#include "wifi_merge.h"
#include <string.h>

static int popcount16(uint16_t v) {
    int n = 0;
    while (v) { v &= (uint16_t)(v - 1); n++; }
    return n;
}

void wifi_merge_reset(wifi_merge_t *m) {
    if (!m) return;
    m->count = 0;
    m->dropped = 0;
}

wifi_merged_t *wifi_merge_find(wifi_merge_t *m, const uint8_t key[6]) {
    if (!m || !key) return NULL;
    for (int i = 0; i < m->count; i++)
        if (memcmp(m->ents[i].key, key, 6) == 0)
            return &m->ents[i];
    return NULL;
}

wifi_merged_t *wifi_merge_observe(wifi_merge_t *m, int sensor_id,
                                  const uint8_t key[6], int channel,
                                  int freq_mhz, int rssi_dbm, time_t seen_at) {
    if (!m || !key || sensor_id < 0 || sensor_id >= MAX_SENSORS) {
        if (m) m->dropped++;
        return NULL;
    }

    wifi_merged_t *e = wifi_merge_find(m, key);
    if (!e) {
        if (m->count >= MAX_WIFI_MERGED) { m->dropped++; return NULL; }
        e = &m->ents[m->count++];
        memset(e, 0, sizeof(*e));
        memcpy(e->key, key, 6);
        e->first_seen = seen_at;
        e->best_rssi  = 0;   /* 0 = no signal sample yet */
        e->best_sensor = -1;
    }

    e->sensor_mask |= (uint16_t)(1u << sensor_id);
    e->seen_by = popcount16(e->sensor_mask);
    e->observations++;
    e->last_seen = seen_at;
    if (channel)  e->channel  = channel;
    if (freq_mhz) e->freq_mhz = freq_mhz;

    /* RSSI is negative dBm; "best" = strongest = closest to 0. Treat 0 as
     * "unknown" so a missing sample never masquerades as the strongest. */
    if (rssi_dbm < 0 && (e->best_rssi == 0 || rssi_dbm > e->best_rssi)) {
        e->best_rssi   = rssi_dbm;
        e->best_sensor = sensor_id;
    }
    return e;
}

void wifi_merge_from_beacons(sloth_state_t *s, int sensor_id) {
    if (!s) return;
    for (int i = 0; i < s->beacon_count; i++) {
        beacon_ap_t *ap = &s->beacon_aps[i];
        wifi_merge_observe(&s->wifi_merged, sensor_id, ap->bssid,
                           ap->channel, 0, ap->signal_dbm, ap->last_seen);
    }
}
