#include <string.h>
#include <pthread.h>

#include "pm_forge.h"
#include "dot11_frame.h"
#include "beacon_snoop.h"
#include "sensor_health.h"

static pm_forge_t      g_tbl[MAX_PM_FORGE_ENTRIES];
static int             g_count;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Caller holds g_mu. */
static pm_forge_t *entry_for(const uint8_t sta[6], time_t now) {
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < MAX_PM_FORGE_ENTRIES; i++) {
        if (g_tbl[i].in_use && memcmp(g_tbl[i].sta, sta, 6) == 0)
            return &g_tbl[i];
        if (!g_tbl[i].in_use && free_slot < 0) free_slot = i;
        if (g_tbl[i].last_seen < g_tbl[oldest].last_seen) oldest = i;
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    if (free_slot < 0) sh_evict_note(SH_EVICT_PM_FORGE);
    else g_count++;
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    memcpy(g_tbl[slot].sta, sta, 6);
    g_tbl[slot].first_seen = now;
    g_tbl[slot].in_use     = 1;
    return &g_tbl[slot];
}

/* The byte entry point stays for the tests and fuzz harnesses written
 * against it (#130); it decodes once and hands the view on. */
void pm_forge_observe(const uint8_t *dot11, int len,
                     time_t now_sec, long now_usec) {
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    pm_forge_observe_frame(&f, now_sec, now_usec);
}

void pm_forge_observe_frame(const dot11_frame_t *f,
                            time_t now_sec, long now_usec) {
    if (!f || !f->p || f->len < 24) return;
    if (f->type != 2) return;                   /* not a data frame */

    /* Only a station transmitting to its AP carries a PwrMgt
     * declaration worth tracking here — the AP never sets this bit,
     * and a WDS/mesh (addr4) frame has no single station to attribute
     * it to. */
    if (!f->to_ds || f->from_ds) return;

    /* STA -> AP (Table 9-26): A1 is the BSSID, A2 the station. Both
     * are inside the 24 octets checked above. */
    const uint8_t *bssid = f->bssid;
    const uint8_t *sta   = f->sa;
    if (!bssid || !sta) return;

    int pm         = f->pwr_mgmt;
    int no_payload = (f->subtype & 0x04) ? 1 : 0;   /* Null / QoS-Null family */
    /* A non-QoS frame has the one implicit queue, TID 0; a QoS Control
     * field cut off by the capture reads as that queue too, as it did
     * when this came from dot11_data_tid(). */
    int tid        = f->has_qos ? f->tid : 0;
    if (tid < 0) tid = 0;

    int64_t now_us = (int64_t)now_sec * 1000000 + (now_usec > 0 ? now_usec : 0);

    pthread_mutex_lock(&g_mu);
    pm_forge_t *e = entry_for(sta, now_sec);
    memcpy(e->bssid, bssid, 6);
    e->last_seen = now_sec;

    if (no_payload) {
        if (pm) {
            e->last_pm1_null_us  = now_us;
            e->last_pm1_null_tid = tid;
        }
    } else if (!pm) {
        /* A contradiction is the station transmitting as awake
         * (PM=0) on a TID distinct from the one its own most recent
         * sleep declaration named, inside the window the AP itself
         * would still honour that declaration for — its advertised
         * beacon interval (IEEE 802.11-2020 §11.1.3). Checked before
         * the PM=0 bookkeeping below is updated, so a frame cannot
         * corroborate itself. */
        if (e->last_pm1_null_us > 0 && tid != e->last_pm1_null_tid &&
            now_us >= e->last_pm1_null_us) {
            int bms = beacon_find_interval_ms(bssid);
            if (bms > 0 && (now_us - e->last_pm1_null_us) <= (int64_t)bms * 1000) {
                e->contradiction_count++;
                e->last_contradiction_ts = now_sec;
            }
        }
        e->last_pm0_data_us  = now_us;
        e->last_pm0_data_tid = tid;
    }
    pthread_mutex_unlock(&g_mu);
}

int pm_forge_lookup(const uint8_t sta[6], pm_forge_t *out) {
    if (!sta || !out) return 0;
    int found = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_PM_FORGE_ENTRIES; i++) {
        if (g_tbl[i].in_use && memcmp(g_tbl[i].sta, sta, 6) == 0) {
            *out = g_tbl[i];
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return found;
}

int pm_forge_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int pm_forge_snapshot(pm_forge_t *out, int max) {
    if (!out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_PM_FORGE_ENTRIES && n < max; i++)
        if (g_tbl[i].in_use) out[n++] = g_tbl[i];
    pthread_mutex_unlock(&g_mu);
    return n;
}

void pm_forge_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_tbl, 0, sizeof(g_tbl));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
