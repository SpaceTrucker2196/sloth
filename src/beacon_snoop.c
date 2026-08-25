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

/* Ring of timestamps of recently first-seen BSSIDs — the beacon-flood
 * signal (roadmap B4). Written under g_mu from beacon_record's new-entry
 * path; read (with its own lock) by beacon_recent_new_bssids. Sized so a
 * flood well above the alert threshold still fits the window. */
#define BEACON_NEW_TS_RING 256
static time_t g_new_bssid_ts[BEACON_NEW_TS_RING];
static int    g_new_bssid_head;

/* Caller must hold g_mu. */
static void note_new_bssid(time_t now) {
    g_new_bssid_ts[g_new_bssid_head] = now;
    g_new_bssid_head = (g_new_bssid_head + 1) % BEACON_NEW_TS_RING;
}

int beacon_recent_new_bssids(time_t now, int window_s) {
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < BEACON_NEW_TS_RING; i++)
        if (g_new_bssid_ts[i] && now - g_new_bssid_ts[i] <= window_s) n++;
    pthread_mutex_unlock(&g_mu);
    return n;
}

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
    /* WPA3 R3 / 802.11be. Named here because the transition-mode rule
     * treats PSK alongside SAE-EXT-KEY as a downgrade path exactly as
     * it treats PSK alongside plain SAE (#62). */
    case 24: return "SAE-EXT-KEY";
    case 25: return "FT-SAE-EXT-KEY";
    default: return "?";
    }
}

/* Family labels for a suite bitmap. Ordered strongest-lane-first so a
 * transition-mode BSS reads "SAE+PSK" rather than "PSK+SAE" — the
 * stronger lane is the one the client would prefer, and the weaker one
 * is the finding. */
void rsn_akm_label(uint32_t akm_bits, char *out, size_t sz) {
    if (!out || sz == 0) return;
    out[0] = '\0';
    if (akm_bits == 0) { snprintf(out, sz, "open"); return; }

    static const struct { uint32_t mask; const char *name; } fam[] = {
        { RSN_AKM_SAE_FAMILY, "SAE"    },
        { RSN_AKM_PSK_FAMILY, "PSK"    },
        { RSN_AKM_OWE,        "OWE"    },
        { RSN_SUITE_BIT(1) | RSN_SUITE_BIT(3) | RSN_SUITE_BIT(5) |
          RSN_SUITE_BIT(11) | RSN_SUITE_BIT(12),
                              "802.1X" },
    };
    size_t off = 0;
    uint32_t named = 0;
    for (size_t i = 0; i < sizeof(fam) / sizeof(fam[0]); i++) {
        if (!(akm_bits & fam[i].mask)) continue;
        named |= akm_bits & fam[i].mask;
        int n = snprintf(out + off, sz - off, "%s%s",
                         off ? "+" : "", fam[i].name);
        if (n < 0 || (size_t)n >= sz - off) return;
        off += (size_t)n;
    }
    /* Suites this build does not name still have to show up, or a row
     * would silently read "open" for a BSS that is anything but. */
    if (akm_bits & ~named)
        snprintf(out + off, sz - off, "%s?", off ? "+" : "");
}

/* Shared Information-Element walker (roadmap B3b).
 *
 * Split out of beacon_parse() so the managed-mode nl80211 scan path can
 * reach the same parser. Before this, sloth had two Wi-Fi code paths of
 * very different depth — this one with the full RSN/WPS/RNR/11k/QBSS/
 * vendor decode, and src/platform/linux_wifi.c with SSID plus three
 * booleans — so the *same AP reported different detail depending on
 * which interface mode observed it*. That is a correctness
 * inconsistency, not a missing feature.
 *
 * Takes the IE blob rather than a frame because that is what nl80211
 * hands over (NL80211_BSS_INFORMATION_ELEMENTS); the beacon path passes
 * dot11 + 36. `privacy` is the capability field's Privacy bit, which
 * both sources have, and `beacon_ms` only feeds the fingerprint.
 *
 * Returns 1 always — an empty or malformed IE blob still yields a
 * usable enc/ssid, with the malformed-frame counters set. */
int beacon_parse_ies(const uint8_t *ies, int ies_len, int privacy,
                     uint16_t beacon_ms,
                     char ssid_out[33], int *channel_out, char enc_out[10],
                     beacon_rsn_t *rsn_out)
{
    /* One memset rather than a field-by-field reset. The header
     * promises rsn_out is "fully zeroed on entry", but clearing each
     * field by hand makes that a promise the next field addition
     * quietly breaks — which is exactly what happened when akm_bits
     * and pairwise_bits landed (#60). Zeroing the object makes the
     * documented contract structural. */
    if (rsn_out) memset(rsn_out, 0, sizeof(*rsn_out));
    /* FNV-1a 32-bit, seeded with the offset basis. Used below to
     * accumulate a stable hash of every non-Microsoft tag-221 IE
     * body so two same-vendor APs (same firmware, same caps) produce
     * an identical hash, while a rogue mimicking the SSID/cipher but
     * built on different silicon produces a different one. */
    uint32_t vendor_hash = 2166136261u;
    int      vendor_hash_seen = 0;
    int has_ht = 0, has_vht = 0, has_he = 0, has_eht = 0;

    ssid_out[0]  = '\0';
    *channel_out = 0;

    int rsn_found = 0;
    int wpa_found = 0;
    int sae_found = 0;

    const uint8_t *ie     = ies;
    int            ie_rem = ies_len;

    while (ie_rem >= 2) {
        uint8_t tag = ie[0];
        uint8_t tln = ie[1];
        if (2 + (int)tln > ie_rem) {
            /* IE claims a length that runs off the frame end — a
             * malformed-frame signal (mdk4 mode m / crafted injection).
             * Count it and stop; the rest of the frame is untrustworthy. */
            if (rsn_out) rsn_out->ie_overruns++;
            break;
        }
        /* RSN IE present (tag 48) but too short to hold even the version
         * + group-cipher selector — truncated / crafted. The full RSN
         * decoder below requires tln >= 8, so this would otherwise be
         * silently skipped. Independent count; does not alter parse flow. */
        if (tag == 48 && tln < 8 && rsn_out) rsn_out->truncated_rsn++;

        if (tag == 0) {
            /* SSID. Lengths > 32 are invalid per 802.11 — a fuzz signal. */
            if (tln > 32 && rsn_out) rsn_out->oversize_ssid++;
            int slen = tln < 32 ? tln : 32;
            memcpy(ssid_out, ie + 2, (size_t)slen);
            ssid_out[slen] = '\0';

        } else if (tag == 11 && rsn_out && tln >= 3) {
            /* QBSS Load (802.11e): station count (2 bytes LE) + channel
             * utilisation (1 byte, 0..255) + admission capacity (2 bytes).
             * AP-self-reported congestion — no math required. */
            rsn_out->has_qbss       = 1;
            rsn_out->qbss_stations  = ie[2] | (ie[3] << 8);
            rsn_out->qbss_chan_util = ie[4];
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
                /* Pairwise list — the first suite feeds the display
                 * string (most beacons advertise one, and that is the
                 * primary cipher); every suite feeds the bitmap, which
                 * is what "was TKIP also on offer?" needs (#60). Bounds
                 * are rechecked per entry because `pw` comes off the
                 * air and may overstate the list. */
                for (int k = 0; k < (int)pw && off + k*4 + 4 <= (int)tln; k++) {
                    const uint8_t *sel = ie + 2 + off + k*4;
                    if (!(sel[0]==0x00 && sel[1]==0x0f && sel[2]==0xac)) continue;
                    if (!rsn_out) continue;
                    if (k == 0)
                        snprintf(rsn_out->pairwise, sizeof(rsn_out->pairwise),
                                 "%s", cipher_name(sel[3]));
                    if (sel[3] < 32)
                        rsn_out->pairwise_bits |= RSN_SUITE_BIT(sel[3]);
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
                        /* Every suite lands in the bitmap even when the
                         * display string is already full at three — the
                         * fourth AKM is exactly the one a crowded
                         * transition-mode BSS hides (#60, #62). */
                        if (rsn_out && t < 32)
                            rsn_out->akm_bits |= RSN_SUITE_BIT(t);
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
        rsn_out->fp.beacon_interval_ms = beacon_ms;
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

    return 1;
}

int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out,
                 beacon_rsn_t *rsn_out)
{
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

    (void)signal;
    return beacon_parse_ies(dot11 + 36, len - 36, privacy, *beacon_ms_out,
                            ssid_out, channel_out, enc_out, rsn_out);
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

/* Compact FNV-1a fingerprint of a beacon's security/IE posture — the
 * tuple that a legit multi-VAP AP varies per VAP but a PineAP/KARMA
 * radio keeps identical across every SSID it spoofs (#30 ie_uniformity).
 * Never returns 0 for a real beacon, so 0 stays "unknown". */
static uint32_t ap_ie_fingerprint(const char *enc, const beacon_rsn_t *rsn) {
    uint32_t h = 2166136261u;
    #define FP_MIX_STR(str) do { const char *_p = (str); \
        while (_p && *_p) { h ^= (uint8_t)*_p++; h *= 16777619u; } } while (0)
    FP_MIX_STR(enc);
    if (rsn) {
        FP_MIX_STR(rsn->pairwise);
        FP_MIX_STR(rsn->group);
        FP_MIX_STR(rsn->akm);
        h ^= (uint32_t)rsn->mfp;            h *= 16777619u;
        h ^= rsn->fp.vendor_ies_hash;       h *= 16777619u;
    }
    #undef FP_MIX_STR
    return h ? h : 1u;                        /* avoid the "unknown" sentinel */
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
                    int hn = g_aps[i].ssid_history_n;
                    snprintf(g_aps[i].ssid_history[hn], 33, "%s", ssid);
                    g_aps[i].ssid_history_fp[hn] = ap_ie_fingerprint(enc, rsn);
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
                /* QBSS Load — only overwrite when the IE was present so a
                 * bare re-record doesn't wipe a prior occupancy reading. */
                if (rsn->has_qbss) {
                    g_aps[i].has_qbss       = 1;
                    g_aps[i].qbss_stations  = rsn->qbss_stations;
                    g_aps[i].qbss_chan_util = rsn->qbss_chan_util;
                }
                /* Accumulate malformed-IE counts across frames (#33),
                 * saturating rather than wrapping the uint16 counters. */
                if (g_aps[i].fuzz_ie_overruns   < 0xffff)
                    g_aps[i].fuzz_ie_overruns   += (uint16_t)rsn->ie_overruns;
                if (g_aps[i].fuzz_oversize_ssid < 0xffff)
                    g_aps[i].fuzz_oversize_ssid += (uint16_t)rsn->oversize_ssid;
                if (g_aps[i].fuzz_truncated_rsn < 0xffff)
                    g_aps[i].fuzz_truncated_rsn += (uint16_t)rsn->truncated_rsn;
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

    note_new_bssid(now);   /* beacon-flood rate signal (roadmap B4) */
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
        g_aps[slot].ssid_history_fp[0] = ap_ie_fingerprint(enc, rsn);
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
        g_aps[slot].has_qbss       = rsn->has_qbss;
        g_aps[slot].qbss_stations  = rsn->qbss_stations;
        g_aps[slot].qbss_chan_util = rsn->qbss_chan_util;
        g_aps[slot].fuzz_ie_overruns   = (uint16_t)rsn->ie_overruns;
        g_aps[slot].fuzz_oversize_ssid = (uint16_t)rsn->oversize_ssid;
        g_aps[slot].fuzz_truncated_rsn = (uint16_t)rsn->truncated_rsn;
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
    memset(g_new_bssid_ts, 0, sizeof(g_new_bssid_ts));
    g_new_bssid_head = 0;
    pthread_mutex_unlock(&g_mu);
}

/* ── 802.11k topology predicates (#51) ──────────────────────
 * Live here because this file is what parses tag 52 into
 * beacon_ap_t.neighbors[]; the consumers (the evil-twin rule, the
 * twins view) sit above beacon data and would otherwise need a
 * module cycle to share this. Contract in sloth.h. */

int ap_advertises_neighbor(const beacon_ap_t *ap, const uint8_t bssid[6])
{
    if (!ap || !bssid) return 0;
    int n = ap->neighbor_count;
    if (n > MAX_AP_NEIGHBORS) n = MAX_AP_NEIGHBORS;
    for (int i = 0; i < n; i++)
        if (memcmp(ap->neighbors[i].bssid, bssid, 6) == 0) return 1;
    return 0;
}

int ap_infrastructure_peers(const beacon_ap_t *a, const beacon_ap_t *b)
{
    if (!a || !b) return 0;
    /* An AP listing itself is a parse artefact, not a relationship. */
    if (memcmp(a->bssid, b->bssid, 6) == 0) return 0;
    return ap_advertises_neighbor(a, b->bssid) ||
           ap_advertises_neighbor(b, a->bssid);
}
