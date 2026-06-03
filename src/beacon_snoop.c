#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "beacon_snoop.h"
#include "wifi_oui_attacker.h"

static beacon_ap_t     g_aps[MAX_BEACON_APS];
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── 802.11 beacon parser ────────────────────────────────── */

/* Cipher OUI 00-0F-AC type names (IEEE 802.11 §9.4.2.25.2). */
static const char *cipher_name(uint8_t t) {
    switch (t) {
    case 0:  return "GROUP";
    case 1:  return "WEP-40";
    case 2:  return "TKIP";
    case 4:  return "CCMP";
    case 5:  return "WEP-104";
    case 6:  return "BIP";
    case 8:  return "GCMP";
    case 9:  return "GCMP-256";
    case 10: return "CCMP-256";
    default: return "?";
    }
}

/* AKM OUI 00-0F-AC type names (IEEE 802.11 §9.4.2.25.3). */
static const char *akm_name(uint8_t t) {
    switch (t) {
    case 1:  return "802.1X";
    case 2:  return "PSK";
    case 3:  return "FT-802.1X";
    case 4:  return "FT-PSK";
    case 5:  return "802.1X-SHA256";
    case 6:  return "PSK-SHA256";
    case 8:  return "SAE";
    case 9:  return "FT-SAE";
    case 11: return "Suite-B";
    case 12: return "Suite-B-192";
    case 18: return "OWE";
    case 19: return "FT-PSK-SHA384";
    default: return "?";
    }
}

int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out,
                 beacon_rsn_t *rsn_out)
{
    if (rsn_out) {
        rsn_out->pairwise[0] = '\0';
        rsn_out->group[0]    = '\0';
        rsn_out->akm[0]      = '\0';
        rsn_out->mfp         = 0;
        rsn_out->vendor[0]   = '\0';
        rsn_out->has_wps     = 0;
        rsn_out->wps_state   = 0;
        rsn_out->wps_locked  = 0;
        rsn_out->phy[0]      = '\0';
        rsn_out->neighbor_count = 0;
        memset(rsn_out->neighbors, 0, sizeof(rsn_out->neighbors));
        memset(&rsn_out->fp, 0, sizeof(rsn_out->fp));
    }
    /* FNV-1a 32-bit, seeded with the offset basis. Used below to
     * accumulate a stable hash of every non-Microsoft tag-221 IE
     * body so two same-vendor APs (same firmware, same caps) produce
     * an identical hash, while a rogue mimicking the SSID/cipher but
     * built on different silicon produces a different one. */
    uint32_t vendor_hash = 2166136261u;
    int      vendor_hash_seen = 0;
    int has_ht = 0, has_vht = 0, has_he = 0, has_eht = 0;
    /* Need at least 802.11 header (24) + fixed params (12) = 36 bytes */
    if (len < 36) return 0;

    /* FC byte 0: type=0b00 (management), subtype=0b1000 (beacon) → 0x80 */
    if (dot11[0] != 0x80) return 0;

    /* BSSID at bytes 16-21 */
    memcpy(bssid_out, dot11 + 16, 6);

    /* Beacon interval at bytes 32-33, little-endian TUs (1 TU = 1024 µs) */
    uint32_t bi_tu = (uint32_t)(dot11[32] | ((uint32_t)dot11[33] << 8));
    *beacon_ms_out = (uint16_t)(bi_tu * 1024 / 1000);

    /* Capability Information at bytes 34-35; bit 4 = Privacy */
    uint16_t cap     = (uint16_t)(dot11[34] | ((uint16_t)dot11[35] << 8));
    int      privacy = (cap >> 4) & 1;

    ssid_out[0]  = '\0';
    *channel_out = 0;

    int rsn_found = 0;
    int wpa_found = 0;
    int sae_found = 0;

    /* Walk Information Elements starting at byte 36 */
    const uint8_t *ie     = dot11 + 36;
    int            ie_rem = len - 36;

    while (ie_rem >= 2) {
        uint8_t tag = ie[0];
        uint8_t tln = ie[1];
        if (2 + (int)tln > ie_rem) break;

        if (tag == 0) {
            /* SSID */
            int slen = tln < 32 ? tln : 32;
            memcpy(ssid_out, ie + 2, (size_t)slen);
            ssid_out[slen] = '\0';

        } else if (tag == 45)  { has_ht  = 1;
            if (rsn_out) rsn_out->fp.flags |= AP_FP_FLAG_HT_PRESENT;
        } else if (tag == 191) { has_vht = 1;
            if (rsn_out) rsn_out->fp.flags |= AP_FP_FLAG_VHT_PRESENT;
        } else if (tag == 255 && tln >= 1) {
            uint8_t ext = ie[2];
            if (ext == 35)               { has_he  = 1;
                if (rsn_out) rsn_out->fp.flags |= AP_FP_FLAG_HE_PRESENT;
            }
            if (ext == 81 || ext == 108) has_eht = 1;

        } else if (tag == 201 && tln >= 4 && rsn_out) {
            /* 802.11ax/be Reduced Neighbor Report (RNR).
             * Body is one or more Neighbor AP Info Fields, each:
             *   bytes 0-1  TBTT Information Header (little-endian):
             *     bits  0-1 Type
             *     bit   2   Filtered Neighbor AP
             *     bits  4-7 TBTT Info Count (zero-based: count = N+1)
             *     bits  8-15 TBTT Info Length (per entry, bytes)
             *   byte  2    Operating Class
             *   byte  3    Channel Number
             *   bytes 4+   TBTT Info entries (count * len bytes total)
             *
             * Each TBTT entry (when len >= 7) contains:
             *   byte 0       TBTT Offset
             *   bytes 1-6    BSSID
             *   (more fields when len >= 11)
             *
             * We extract (BSSID, channel) per neighbor — same shape as
             * the 802.11k path so they merge into one neighbor list. */
            const uint8_t *p = ie + 2;
            int rem = tln;
            while (rem >= 4 &&
                   rsn_out->neighbor_count < MAX_AP_NEIGHBORS) {
                uint16_t h     = (uint16_t)(p[0] | (uint16_t)(p[1] << 8));
                int tbtt_count = ((h >> 4) & 0xF) + 1;
                int tbtt_len   = (h >> 8) & 0xFF;
                uint8_t channel = p[3];
                if (tbtt_len <= 0) break;
                int field_len = 4 + tbtt_count * tbtt_len;
                if (field_len > rem) break;
                const uint8_t *tp = p + 4;
                for (int t = 0;
                     t < tbtt_count &&
                     rsn_out->neighbor_count < MAX_AP_NEIGHBORS;
                     t++, tp += tbtt_len) {
                    if (tbtt_len < 7) continue;
                    ap_neighbor_t *n =
                        &rsn_out->neighbors[rsn_out->neighbor_count];
                    memcpy(n->bssid, tp + 1, 6);
                    n->channel  = channel;
                    n->phy_type = 0;       /* RNR doesn't carry PHY type */
                    int dup = 0;
                    for (int k = 0; k < rsn_out->neighbor_count; k++)
                        if (memcmp(rsn_out->neighbors[k].bssid,
                                   n->bssid, 6) == 0) {
                            dup = 1;
                            break;
                        }
                    if (!dup) rsn_out->neighbor_count++;
                }
                p   += field_len;
                rem -= field_len;
            }

        } else if (tag == 52 && tln >= 13 && rsn_out) {
            /* 802.11k Neighbor Report Element.
             *   6 BSSID + 4 BSSID Info + 1 OperClass + 1 Channel +
             *   1 PHY Type [+ subelements].
             * Each tag-52 IE is ONE neighbor. APs that advertise
             * multiple neighbors emit multiple tag-52 IEs. */
            if (rsn_out->neighbor_count < MAX_AP_NEIGHBORS) {
                ap_neighbor_t *n =
                    &rsn_out->neighbors[rsn_out->neighbor_count];
                memcpy(n->bssid, ie + 2, 6);
                n->channel  = ie[2 + 11];   /* offset 11 = channel    */
                n->phy_type = ie[2 + 12];   /* offset 12 = PHY type   */
                /* De-dupe against existing entries — APs sometimes
                 * advertise the same neighbor across re-beacons we'd
                 * accumulate; we want a unique set. */
                int dup = 0;
                for (int k = 0; k < rsn_out->neighbor_count; k++) {
                    if (memcmp(rsn_out->neighbors[k].bssid, n->bssid, 6) == 0) {
                        dup = 1;
                        break;
                    }
                }
                if (!dup) rsn_out->neighbor_count++;
            }

        } else if (tag == 3 && tln == 1) {
            /* DS Parameter Set — channel number */
            *channel_out = ie[2];

        } else if (tag == 48 && tln >= 8) {
            /* RSN (WPA2/WPA3). Layout (after tag+len):
             *   2 ver | 4 group cipher | 2 N pw | 4N pairwise |
             *   2 M akm | 4M akm | 2 RSN capabilities */
            rsn_found = 1;
            int off = 2;                                /* skip version */
            /* Group cipher: 4 bytes OUI(3) + type(1) */
            if (rsn_out && off + 4 <= (int)tln) {
                if (ie[2+off]==0x00 && ie[2+off+1]==0x0f && ie[2+off+2]==0xac) {
                    snprintf(rsn_out->group, sizeof(rsn_out->group),
                             "%s", cipher_name(ie[2+off+3]));
                }
            }
            off += 4;
            if (off + 2 <= (int)tln) {
                uint16_t pw = (uint16_t)(ie[2+off] | ((uint16_t)ie[2+off+1] << 8));
                off += 2;
                /* Pairwise list — record the first suite (most beacons
                 * just advertise one; if more, we still capture the
                 * primary cipher). */
                if (rsn_out && pw > 0 && off + 4 <= (int)tln) {
                    if (ie[2+off]==0x00 && ie[2+off+1]==0x0f && ie[2+off+2]==0xac) {
                        snprintf(rsn_out->pairwise, sizeof(rsn_out->pairwise),
                                 "%s", cipher_name(ie[2+off+3]));
                    }
                }
                off += pw * 4;
                if (off + 2 <= (int)tln) {
                    uint16_t akm = (uint16_t)(ie[2+off] | ((uint16_t)ie[2+off+1] << 8));
                    off += 2;
                    /* AKM list — join up to 3 names. SAE detection
                     * keeps the legacy "WPA3" enc tag working. */
                    int akm_taken = 0;
                    for (int k = 0; k < (int)akm && off + 4 <= (int)tln; k++, off += 4) {
                        if (!(ie[2+off]==0x00 && ie[2+off+1]==0x0f && ie[2+off+2]==0xac))
                            continue;
                        uint8_t t = ie[2+off+3];
                        if (t == 8 || t == 9) sae_found = 1;
                        if (rsn_out && akm_taken < 3) {
                            const char *nm = akm_name(t);
                            int cur = (int)strlen(rsn_out->akm);
                            int sz  = (int)sizeof(rsn_out->akm);
                            int rem = sz - cur - 1;
                            if (rem > 0) {
                                snprintf(rsn_out->akm + cur, rem + 1,
                                         "%s%s", akm_taken ? "," : "", nm);
                                akm_taken++;
                            }
                        }
                    }
                    /* RSN Capabilities: 2 bytes after the AKM list.
                     *   bit 6 = MFPR (required)
                     *   bit 7 = MFPC (capable) */
                    if (rsn_out && off + 2 <= (int)tln) {
                        uint16_t caps = (uint16_t)(ie[2+off] |
                                                   ((uint16_t)ie[2+off+1] << 8));
                        int mfpr = (caps >> 6) & 1;
                        int mfpc = (caps >> 7) & 1;
                        rsn_out->mfp = mfpr ? 2 : (mfpc ? 1 : 0);
                    }
                }
            }

        } else if (tag == 221 && tln >= 4) {
            uint8_t o0 = ie[2], o1 = ie[3], o2 = ie[4];
            uint8_t ty = ie[5];
            int     is_microsoft = (o0==0x00 && o1==0x50 && o2==0xf2);
            /* Microsoft Vendor-Specific OUI 00:50:F2.
             *   type 1 = WPA IE
             *   type 4 = Wi-Fi Protected Setup IE                     */
            if (is_microsoft) {
                if (ty == 0x01) wpa_found = 1;
                if (rsn_out && ty == 0x04) {
                    rsn_out->has_wps = 1;
                    int uuid_e_zero_seen = 0;
                    /* Walk WPS attributes (TLV body after OUI+type).
                     * Each attribute: 2 bytes ID + 2 bytes length +
                     * data, big-endian. */
                    const uint8_t *wp = ie + 6;        /* after OUI+type */
                    int            wrem = (int)tln - 4;
                    while (wrem >= 4) {
                        uint16_t aid = (uint16_t)((wp[0] << 8) | wp[1]);
                        uint16_t alen = (uint16_t)((wp[2] << 8) | wp[3]);
                        if (4 + (int)alen > wrem) break;
                        const uint8_t *adata = wp + 4;
                        if (aid == 0x1044 && alen >= 1) {
                            /* Wi-Fi Protected Setup State */
                            rsn_out->wps_state =
                                (adata[0] == 0x02) ? 2 :
                                (adata[0] == 0x01) ? 1 : 0;
                        } else if (aid == 0x1057 && alen >= 1) {
                            /* AP Setup Locked */
                            rsn_out->wps_locked =
                                (adata[0] == 0x01) ? 2 : 1;
                        } else if (aid == 0x1047 && alen == 16) {
                            /* WPS UUID-E. An all-zero UUID is a known
                             * tell for some Pineapple firmware revisions
                             * — legit APs ship a random / per-device UUID. */
                            int all_zero = 1;
                            for (int z = 0; z < 16; z++)
                                if (adata[z] != 0) { all_zero = 0; break; }
                            if (all_zero) uuid_e_zero_seen = 1;
                        }
                        wp   += 4 + alen;
                        wrem -= 4 + alen;
                    }
                    if (uuid_e_zero_seen)
                        rsn_out->fp.flags |= AP_FP_FLAG_WPS_UUID_ZERO;
                }
            }
            /* Vendor-IE hash — FNV-1a over OUI+type+body of every
             * non-Microsoft tag-221 IE. Order matters and is preserved
             * (same firmware emits IEs in the same order beacon after
             * beacon); a rogue mimicking the same SSID/cipher on
             * different silicon will land a different hash. */
            if (rsn_out && !is_microsoft) {
                int hlen = 2 + (int)tln;   /* tag, len, body */
                for (int b = 0; b < hlen; b++) {
                    vendor_hash ^= (uint32_t)ie[b];
                    vendor_hash *= 16777619u;
                }
                vendor_hash_seen = 1;
            }
            /* AP vendor fingerprint — first non-Microsoft OUI we
             * recognise wins. Lookup table is small (SOHO + enterprise
             * + IoT mostly). */
            if (rsn_out && !rsn_out->vendor[0]) {
                const char *v = NULL;
                if      (o0==0x00 && o1==0x17 && o2==0xf2) v = "Apple";
                else if (o0==0x00 && o1==0x40 && o2==0x96) v = "Cisco";
                else if (o0==0x00 && o1==0x03 && o2==0x7f) v = "Atheros";
                else if (o0==0x00 && o1==0x10 && o2==0x18) v = "Broadcom";
                else if (o0==0x4c && o1==0x5e && o2==0x0c) v = "Mikrotik";
                else if (o0==0x00 && o1==0x15 && o2==0x6d) v = "Ubiquiti";
                else if (o0==0xdc && o1==0x9f && o2==0xdb) v = "Ubiquiti";
                else if (o0==0x24 && o1==0x0a && o2==0xc4) v = "Espressif";
                else if (o0==0x00 && o1==0x0d && o2==0x97) v = "Ruckus";
                else if (o0==0x00 && o1==0x24 && o2==0x6c) v = "Aruba";
                else if (o0==0xc0 && o1==0xc9 && o2==0xe3) v = "TP-Link";
                else if (o0==0x00 && o1==0x09 && o2==0x5b) v = "Netgear";
                else if (o0==0x00 && o1==0x18 && o2==0xe7) v = "D-Link";
                else if (o0==0x00 && o1==0x14 && o2==0x6c) v = "Netgear";
                else if (o0==0x50 && o1==0x6f && o2==0x9a) v = "Wi-Fi Alliance";
                if (v) snprintf(rsn_out->vendor, sizeof(rsn_out->vendor),
                                "%s", v);
            }
        }

        ie     += 2 + tln;
        ie_rem -= 2 + tln;
    }

    if (rsn_out) {
        const char *p = has_eht ? "Wi-Fi 7"
                      : has_he  ? "Wi-Fi 6"
                      : has_vht ? "Wi-Fi 5"
                      : has_ht  ? "Wi-Fi 4" : "legacy";
        snprintf(rsn_out->phy, sizeof(rsn_out->phy), "%s", p);
        rsn_out->fp.beacon_interval_ms = *beacon_ms_out;
        /* Leave fp.vendor_ies_hash at 0 when the beacon had no
         * non-Microsoft tag-221 IE — the alerts code treats 0 on
         * either side as "no signal" and falls through to WARN. */
        rsn_out->fp.vendor_ies_hash = vendor_hash_seen ? vendor_hash : 0u;
    }

    /* Determine encryption, strongest first */
    if (sae_found)
        strncpy(enc_out, "WPA3",  10);
    else if (rsn_found)
        strncpy(enc_out, "WPA2",  10);
    else if (wpa_found)
        strncpy(enc_out, "WPA",   10);
    else if (privacy)
        strncpy(enc_out, "WEP",   10);
    else
        strncpy(enc_out, "OPEN",  10);

    (void)signal;
    return 1;
}

/* ── AP table ────────────────────────────────────────────── */

/* Append `signal` to the AP's RSSI ring, evict samples older than
 * RSSI_WIN_SECS, and re-derive rssi_min/max_60s. The ring is the
 * carrier; the int8_t min/max fields are the projection consumed
 * by the alerts code and views. 0 dBm is impossible for real Wi-Fi
 * (always negative) so 0 doubles as "unseen" in the projection. */
static void rssi_ring_push(beacon_ap_t *ap, int8_t signal, time_t now) {
    rssi_ring_t *r = &ap->rssi_ring;
    r->dbm[r->head] = signal;
    r->ts [r->head] = now;
    r->head = (r->head + 1) % RSSI_WIN_SAMPLES;
    if (r->count < RSSI_WIN_SAMPLES) r->count++;
    int8_t lo = 0, hi = 0;
    int    init = 0;
    for (int k = 0; k < r->count; k++) {
        if (now - r->ts[k] > RSSI_WIN_SECS) continue;
        int8_t v = r->dbm[k];
        if (!init) { lo = v; hi = v; init = 1; }
        else {
            if (v < lo) lo = v;
            if (v > hi) hi = v;
        }
    }
    ap->rssi_min_60s = init ? lo : 0;
    ap->rssi_max_60s = init ? hi : 0;
}

void beacon_record(const uint8_t *bssid, const char *ssid,
                   int8_t signal, int channel,
                   const char *enc, uint16_t beacon_ms,
                   const beacon_rsn_t *rsn)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    /* update existing entry */
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0) {
            g_aps[i].signal_dbm = signal;
            g_aps[i].channel    = channel;
            g_aps[i].beacon_ms  = beacon_ms;
            g_aps[i].last_seen  = now;
            rssi_ring_push(&g_aps[i], signal, now);
            g_aps[i].frame_count++;
            if (ssid[0]) {
                strncpy(g_aps[i].ssid, ssid, 32);
                /* Track distinct SSIDs per BSSID for KARMA/Pineapple
                 * detection. Append if not already present, cap at
                 * MAX_AP_SSID_HISTORY (drops past that). */
                int dup = 0;
                for (int k = 0; k < g_aps[i].ssid_history_n; k++)
                    if (strncmp(g_aps[i].ssid_history[k], ssid, 32) == 0) {
                        dup = 1; break;
                    }
                if (!dup && g_aps[i].ssid_history_n < MAX_AP_SSID_HISTORY) {
                    snprintf(g_aps[i].ssid_history[g_aps[i].ssid_history_n],
                             33, "%s", ssid);
                    g_aps[i].ssid_history_n++;
                }
            }
            if (rsn) {
                snprintf(g_aps[i].pairwise, sizeof(g_aps[i].pairwise),
                         "%s", rsn->pairwise);
                snprintf(g_aps[i].group, sizeof(g_aps[i].group),
                         "%s", rsn->group);
                snprintf(g_aps[i].akm, sizeof(g_aps[i].akm),
                         "%s", rsn->akm);
                g_aps[i].mfp = rsn->mfp;
                /* Vendor IE / WPS — only overwrite if we found new
                 * info; preserve a previously-set vendor on bare
                 * re-records. */
                if (rsn->vendor[0])
                    snprintf(g_aps[i].vendor, sizeof(g_aps[i].vendor),
                             "%s", rsn->vendor);
                if (rsn->has_wps) g_aps[i].has_wps = 1;
                if (rsn->wps_state)  g_aps[i].wps_state  = rsn->wps_state;
                if (rsn->wps_locked) g_aps[i].wps_locked = rsn->wps_locked;
                if (rsn->phy[0])
                    snprintf(g_aps[i].phy, sizeof(g_aps[i].phy),
                             "%s", rsn->phy);
                /* Neighbors — merge new entries by BSSID; cap at the
                 * stored array size. */
                for (int k = 0; k < rsn->neighbor_count; k++) {
                    const ap_neighbor_t *nk = &rsn->neighbors[k];
                    int found = 0;
                    for (int m = 0; m < g_aps[i].neighbor_count; m++)
                        if (memcmp(g_aps[i].neighbors[m].bssid, nk->bssid, 6) == 0) {
                            g_aps[i].neighbors[m] = *nk;
                            found = 1;
                            break;
                        }
                    if (!found && g_aps[i].neighbor_count < MAX_AP_NEIGHBORS)
                        g_aps[i].neighbors[g_aps[i].neighbor_count++] = *nk;
                }
                /* Fingerprint — OR-merge the flag bits (any beacon
                 * that ever showed a capability counts), but overwrite
                 * vendor_ies_hash with the latest non-zero observation.
                 * OUI is stable from BSSID; beacon_interval is stable
                 * from the AP. */
                g_aps[i].fp.flags |= rsn->fp.flags;
                if (rsn->fp.vendor_ies_hash)
                    g_aps[i].fp.vendor_ies_hash = rsn->fp.vendor_ies_hash;
                if (rsn->fp.beacon_interval_ms)
                    g_aps[i].fp.beacon_interval_ms = rsn->fp.beacon_interval_ms;
            }
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }

    /* new entry — evict oldest if full */
    int slot = g_count < MAX_BEACON_APS ? g_count++ : 0;
    if (slot == 0 && g_count == MAX_BEACON_APS) {
        time_t oldest = g_aps[0].last_seen;
        for (int i = 1; i < g_count; i++) {
            if (g_aps[i].last_seen < oldest) {
                oldest = g_aps[i].last_seen;
                slot   = i;
            }
        }
    }

    memset(&g_aps[slot], 0, sizeof(g_aps[slot]));
    memcpy(g_aps[slot].bssid, bssid, 6);
    strncpy(g_aps[slot].ssid,  ssid, 32);
    strncpy(g_aps[slot].enc,   enc,  9);
    g_aps[slot].signal_dbm = signal;
    g_aps[slot].channel    = channel;
    g_aps[slot].beacon_ms  = beacon_ms;
    g_aps[slot].last_seen  = now;
    g_aps[slot].frame_count = 1;
    if (ssid[0]) {
        snprintf(g_aps[slot].ssid_history[0], 33, "%s", ssid);
        g_aps[slot].ssid_history_n = 1;
    }
    if (rsn) {
        snprintf(g_aps[slot].pairwise, sizeof(g_aps[slot].pairwise),
                 "%s", rsn->pairwise);
        snprintf(g_aps[slot].group, sizeof(g_aps[slot].group),
                 "%s", rsn->group);
        snprintf(g_aps[slot].akm, sizeof(g_aps[slot].akm),
                 "%s", rsn->akm);
        g_aps[slot].mfp = rsn->mfp;
        snprintf(g_aps[slot].vendor, sizeof(g_aps[slot].vendor),
                 "%s", rsn->vendor);
        g_aps[slot].has_wps    = rsn->has_wps;
        g_aps[slot].wps_state  = rsn->wps_state;
        g_aps[slot].wps_locked = rsn->wps_locked;
        snprintf(g_aps[slot].phy, sizeof(g_aps[slot].phy),
                 "%s", rsn->phy);
        int nc = rsn->neighbor_count;
        if (nc > MAX_AP_NEIGHBORS) nc = MAX_AP_NEIGHBORS;
        memcpy(g_aps[slot].neighbors, rsn->neighbors,
               (size_t)nc * sizeof(ap_neighbor_t));
        g_aps[slot].neighbor_count = nc;
        g_aps[slot].fp = rsn->fp;
    }
    /* fp.oui mirrors bssid[0..2] — set unconditionally (independent
     * of whether the parser populated rsn). */
    g_aps[slot].fp.oui[0] = bssid[0];
    g_aps[slot].fp.oui[1] = bssid[1];
    g_aps[slot].fp.oui[2] = bssid[2];
    /* Set the attacker-OUI flag bits inline so downstream consumers
     * (JSONL, iOS client, Twins view) see the marker without having
     * to re-run the lookup. The bits never clear — an OUI on the
     * Hak5/Espressif list stays there for the life of the entry. */
    if (oui_is_hak5(g_aps[slot].fp.oui))
        g_aps[slot].fp.flags |= AP_FP_FLAG_HAK5_OUI;
    if (oui_is_espressif(g_aps[slot].fp.oui))
        g_aps[slot].fp.flags |= AP_FP_FLAG_ESPRESSIF_OUI;
    rssi_ring_push(&g_aps[slot], signal, now);

    pthread_mutex_unlock(&g_mu);
}

int beacon_find_ssid(const uint8_t bssid[6], char ssid_out[33])
{
    if (!bssid || !ssid_out) return 0;
    ssid_out[0] = '\0';
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) != 0) continue;
        if (g_aps[i].ssid[0]) {
            snprintf(ssid_out, 33, "%s", g_aps[i].ssid);
            hit = 1;
        }
        break;
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

void beacon_reveal_hidden_ssid(const uint8_t *bssid, const char *ssid)
{
    if (!ssid || !ssid[0]) return;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) != 0) continue;
        if (g_aps[i].ssid[0]) break;     /* already known — leave alone */
        snprintf(g_aps[i].ssid, sizeof(g_aps[i].ssid), "%s", ssid);
        g_aps[i].revealed = 1;
        break;
    }
    pthread_mutex_unlock(&g_mu);
}

static int cmp_signal_desc(const void *a, const void *b) {
    const beacon_ap_t *x = (const beacon_ap_t *)a;
    const beacon_ap_t *y = (const beacon_ap_t *)b;
    return (int)y->signal_dbm - (int)x->signal_dbm;
}

void beacon_snapshot(sloth_state_t *s)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    /* age out stale entries in-place */
    int i = 0;
    while (i < g_count) {
        if (now - g_aps[i].last_seen > BEACON_AGE_SECS)
            g_aps[i] = g_aps[--g_count];
        else
            i++;
    }

    /* sort by signal strength, strongest first */
    qsort(g_aps, (size_t)g_count, sizeof(beacon_ap_t), cmp_signal_desc);

    int n = g_count < MAX_BEACON_APS ? g_count : MAX_BEACON_APS;
    memcpy(s->beacon_aps, g_aps, (size_t)n * sizeof(beacon_ap_t));
    s->beacon_count = n;
    if (s->beacon_sel >= n) s->beacon_sel = n > 0 ? n - 1 : 0;

    pthread_mutex_unlock(&g_mu);
}

void beacon_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
