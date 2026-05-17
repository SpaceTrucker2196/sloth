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

int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out)
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
            /* RSN (WPA2/WPA3) — walk AKM suite list to detect SAE */
            rsn_found = 1;
            int off = 0;
            off += 2;                              /* version */
            off += 4;                              /* group cipher */
            if (off + 2 <= (int)tln) {
                uint16_t pw = (uint16_t)(ie[2+off] | ((uint16_t)ie[2+off+1] << 8));
                off += 2 + pw * 4;                 /* pairwise list */
                if (off + 2 <= (int)tln) {
                    uint16_t akm = (uint16_t)(ie[2+off] | ((uint16_t)ie[2+off+1] << 8));
                    off += 2;
                    for (int k = 0; k < (int)akm && off + 4 <= (int)tln; k++, off += 4) {
                        /* OUI 00-0F-AC type 8 = SAE (WPA3) */
                        if (ie[2+off]==0x00 && ie[2+off+1]==0x0f &&
                            ie[2+off+2]==0xac && ie[2+off+3]==0x08)
                            sae_found = 1;
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
                   const char *enc, uint16_t beacon_ms)
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
