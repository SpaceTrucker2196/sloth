#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "beacon_snoop.h"

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
    }
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
            /* Vendor-specific: OUI 00:50:F2 type 0x01 = WPA Information Element */
            if (ie[2]==0x00 && ie[3]==0x50 && ie[4]==0xf2 && ie[5]==0x01)
                wpa_found = 1;
        }

        ie     += 2 + tln;
        ie_rem -= 2 + tln;
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
            g_aps[i].frame_count++;
            if (ssid[0]) strncpy(g_aps[i].ssid, ssid, 32);
            if (rsn) {
                snprintf(g_aps[i].pairwise, sizeof(g_aps[i].pairwise),
                         "%s", rsn->pairwise);
                snprintf(g_aps[i].group, sizeof(g_aps[i].group),
                         "%s", rsn->group);
                snprintf(g_aps[i].akm, sizeof(g_aps[i].akm),
                         "%s", rsn->akm);
                g_aps[i].mfp = rsn->mfp;
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
    if (rsn) {
        snprintf(g_aps[slot].pairwise, sizeof(g_aps[slot].pairwise),
                 "%s", rsn->pairwise);
        snprintf(g_aps[slot].group, sizeof(g_aps[slot].group),
                 "%s", rsn->group);
        snprintf(g_aps[slot].akm, sizeof(g_aps[slot].akm),
                 "%s", rsn->akm);
        g_aps[slot].mfp = rsn->mfp;
    }

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
