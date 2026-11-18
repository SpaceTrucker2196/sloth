#include <string.h>
#include "dev_how.h"

/* Read and written on the poll thread only (dev_how_observe from
 * poll.c, dev_how_get from the view the same thread draws), so no lock. */
typedef struct {
    uint8_t  mac[6];
    uint8_t  used;
    long     last_hour;                 /* epoch hour last counted */
    uint16_t present[DEV_HOW_CELLS];
} how_row_t;

static how_row_t g_rows[DEV_HOW_MAX];
static uint16_t  g_watched[DEV_HOW_CELLS];
static long      g_watched_hour = -1;

static int mac_zero(const uint8_t m[6]) {
    static const uint8_t z[6] = {0};
    return memcmp(m, z, 6) == 0;
}

int dev_how_cell(time_t t) {
    struct tm tm;
    if (!localtime_r(&t, &tm)) return 0;
    int day = (tm.tm_wday + 6) % 7;          /* Monday 0 */
    return day * 24 + tm.tm_hour;
}

static how_row_t *row_for(const uint8_t mac[6], int make) {
    how_row_t *free_r = NULL, *old = NULL;
    for (int i = 0; i < DEV_HOW_MAX; i++) {
        how_row_t *r = &g_rows[i];
        if (!r->used) { if (!free_r) free_r = r; continue; }
        if (memcmp(r->mac, mac, 6) == 0) return r;
        if (!old || r->last_hour < old->last_hour) old = r;
    }
    if (!make) return NULL;
    how_row_t *r = free_r ? free_r : old;
    memset(r, 0, sizeof(*r));
    memcpy(r->mac, mac, 6);
    r->used = 1;
    r->last_hour = -1;
    return r;
}

void dev_how_observe(const sloth_state_t *s, time_t now) {
    if (!s || now <= 0) return;
    long hour = (long)(now / 3600);
    int cell = dev_how_cell(now);
    if (hour != g_watched_hour) {
        if (g_watched[cell] < UINT16_MAX) g_watched[cell]++;
        g_watched_hour = hour;
    }
    for (int i = 0; i < s->device_count && i < MAX_DEVICES; i++) {
        const device_t *d = &s->devices[i];
        /* Seen this hour: a record last refreshed in an earlier hour was
         * counted then, if this run was watching. */
        if (mac_zero(d->mac) || d->last_seen <= 0 ||
            (long)(d->last_seen / 3600) != hour)
            continue;
        how_row_t *r = row_for(d->mac, 1);
        if (r->last_hour == hour) continue;
        r->last_hour = hour;
        if (r->present[cell] < UINT16_MAX) r->present[cell]++;
    }
}

int dev_how_get(const uint8_t mac[6], uint16_t present[DEV_HOW_CELLS],
                uint16_t watched[DEV_HOW_CELLS]) {
    memcpy(watched, g_watched, sizeof(g_watched));
    const how_row_t *r = mac_zero(mac) ? NULL : row_for(mac, 0);
    if (!r) { memset(present, 0, sizeof(uint16_t) * DEV_HOW_CELLS); return 0; }
    memcpy(present, r->present, sizeof(r->present));
    return 1;
}

void dev_how_clear(void) {
    memset(g_rows, 0, sizeof(g_rows));
    memset(g_watched, 0, sizeof(g_watched));
    g_watched_hour = -1;
}
