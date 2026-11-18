#include <stdio.h>
#include <string.h>

#include "gps.h"
#include "position_track.h"
#include "tune.h"

/* Contract in position_track.h. Main thread only: the tick and the
 * --db writer both run inside poll_tick(). */

typedef struct {
    uint8_t mac[6];
    int     used;
    time_t  ts;          /* of the last sample, also the LRU clock */
    double  lat, lon;
    int     band;        /* rssi_band() of the last sample */
} last_t;

static int               g_sink;
static last_t            g_last[POSTRACK_MAX_DEVICES];
static postrack_sample_t g_q[POSTRACK_QUEUE];
static int               g_qhead, g_qlen;
static postrack_sensor_t g_sq[POSTRACK_SENSOR_Q];
static int               g_sqhead, g_sqlen;
static int               g_have_sensor;
static postrack_sensor_t g_sensor_last;
static uint64_t          g_dropped;

void postrack_set_sink(int on) { g_sink = on ? 1 : 0; }

static int moved(double llat, double llon, const loc_stamp_t *fix) {
    return gps_distance_m(llat, llon, fix->lat, fix->lon) >=
           (double)tune_val(TUNE_GPS_MIN_MOVE_M);
}

/* The sensor's own track: on a move, or every gps.sample_s. One row a
 * minute at rest by default, which costs nothing. */
static int due(time_t last_ts, double llat, double llon,
               const loc_stamp_t *fix, time_t now) {
    if (now - last_ts >= tune_val(TUNE_GPS_SAMPLE_S)) return 1;
    return moved(llat, llon, fix);
}

/* 10 dB bands of a device's signal, 0 for "no reading". */
static int rssi_band(int dbm) {
    if (dbm == 0) return 0;
    if (dbm > -20) dbm = -20;
    if (dbm < -100) dbm = -100;
    return 1 + (-dbm) / 10;
}

/* A device. On a move, as the sensor's track. At rest (the sensor has
 * moved less than gps.min_move_m since this device's last sample) a
 * repeat row would only restate where the sensor already said it was,
 * so one is written when the device's RSSI band has changed (no sooner
 * than gps.sample_s), or every gps.sample_s x 10 as a keep-alive. A
 * parked sensor hearing 300 devices otherwise wrote 300 rows a minute,
 * ~430k a day, of the same coordinates. */
static int device_due(const last_t *l, int band, const loc_stamp_t *fix,
                      time_t now) {
    if (moved(l->lat, l->lon, fix)) return 1;
    long since = (long)(now - l->ts), every = tune_val(TUNE_GPS_SAMPLE_S);
    if (since >= every * 10) return 1;
    return band != l->band && since >= every;
}

static void push_device(const postrack_sample_t *smp) {
    if (g_qlen == POSTRACK_QUEUE) {
        g_qhead = (g_qhead + 1) % POSTRACK_QUEUE;
        g_qlen--;
        g_dropped++;
    }
    g_q[(g_qhead + g_qlen) % POSTRACK_QUEUE] = *smp;
    g_qlen++;
}

static void push_sensor(const postrack_sensor_t *smp) {
    if (g_sqlen == POSTRACK_SENSOR_Q) {
        g_sqhead = (g_sqhead + 1) % POSTRACK_SENSOR_Q;
        g_sqlen--;
        g_dropped++;
    }
    g_sq[(g_sqhead + g_sqlen) % POSTRACK_SENSOR_Q] = *smp;
    g_sqlen++;
}

static last_t *slot_for(const uint8_t mac[6]) {
    last_t *free_slot = NULL, *oldest = NULL;
    for (int i = 0; i < POSTRACK_MAX_DEVICES; i++) {
        last_t *l = &g_last[i];
        if (!l->used) { if (!free_slot) free_slot = l; continue; }
        if (memcmp(l->mac, mac, 6) == 0) return l;
        if (!oldest || l->ts < oldest->ts) oldest = l;
    }
    /* A forgotten device only means its next sample comes sooner: the
     * table is a rate limiter, not a record, so no tally. */
    last_t *l = free_slot ? free_slot : oldest;
    memset(l, 0, sizeof(*l));
    memcpy(l->mac, mac, 6);
    return l;
}

void postrack_tick(const sloth_state_t *s, time_t now) {
    if (!g_sink || !s) return;
    loc_stamp_t fix;
    if (gps_location_current(&fix, now) != LOC_SRC_GPS) return;

    if (!g_have_sensor ||
        due(g_sensor_last.ts, g_sensor_last.lat, g_sensor_last.lon, &fix, now)) {
        postrack_sensor_t t;
        memset(&t, 0, sizeof(t));
        t.ts = now;
        t.lat = fix.lat;
        t.lon = fix.lon;
        t.has_alt = fix.has_alt;
        t.alt_m = fix.alt_m;
        t.has_acc = fix.has_acc;
        t.acc_m = fix.acc_m;
        t.sats = s->gps.sats;
        t.hdop = s->gps.hdop;
        push_sensor(&t);
        g_sensor_last = t;
        g_have_sensor = 1;
    }

    for (int i = 0; i < s->device_count; i++) {
        const device_t *d = &s->devices[i];
        if (d->last_seen <= 0 || now - d->last_seen > 2) continue;
        last_t *l = slot_for(d->mac);
        int band = rssi_band(d->signal_dbm);
        if (l->used && !device_due(l, band, &fix, now)) continue;
        postrack_sample_t smp;
        memset(&smp, 0, sizeof(smp));
        snprintf(smp.mac, sizeof(smp.mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);
        smp.ts = now;
        smp.lat = fix.lat;
        smp.lon = fix.lon;
        smp.has_acc = fix.has_acc;
        smp.acc_m = fix.acc_m;
        smp.rssi = d->signal_dbm;
        push_device(&smp);
        l->used = 1;
        l->ts = now;
        l->lat = fix.lat;
        l->lon = fix.lon;
        l->band = band;
    }
}

int postrack_drain_devices(postrack_sample_t *out, int max) {
    int n = 0;
    while (g_qlen > 0 && n < max) {
        out[n++] = g_q[g_qhead];
        g_qhead = (g_qhead + 1) % POSTRACK_QUEUE;
        g_qlen--;
    }
    return n;
}

int postrack_drain_sensor(postrack_sensor_t *out, int max) {
    int n = 0;
    while (g_sqlen > 0 && n < max) {
        out[n++] = g_sq[g_sqhead];
        g_sqhead = (g_sqhead + 1) % POSTRACK_SENSOR_Q;
        g_sqlen--;
    }
    return n;
}

uint64_t postrack_dropped(void) { return g_dropped; }

void postrack_clear(void) {
    g_sink = 0;
    memset(g_last, 0, sizeof(g_last));
    g_qhead = g_qlen = 0;
    g_sqhead = g_sqlen = 0;
    g_have_sensor = 0;
    memset(&g_sensor_last, 0, sizeof(g_sensor_last));
    g_dropped = 0;
}
