/* Recurring-transit tracking. Contract in transit.h (#54). */

#include <string.h>

#include "transit.h"

static transit_device_t g_dev[MAX_TRANSIT_DEVICES];
static int              g_count;

static int find_dev(const uint8_t mac[6]) {
    for (int i = 0; i < g_count; i++)
        if (memcmp(g_dev[i].mac, mac, 6) == 0) return i;
    return -1;
}

/* Evict the device whose most recent pass is oldest. A table full of
 * stale one-off passers must not lock out the device that is actually
 * circling right now. */
static int evict_slot(void) {
    int oldest = 0;
    for (int i = 1; i < g_count; i++)
        if (g_dev[i].last_seen < g_dev[oldest].last_seen) oldest = i;
    return oldest;
}

void transit_observe(const uint8_t mac[6], time_t ts, int8_t peak_rssi) {
    if (!mac) return;

    int idx = find_dev(mac);
    if (idx < 0) {
        idx = (g_count < MAX_TRANSIT_DEVICES) ? g_count++ : evict_slot();
        memset(&g_dev[idx], 0, sizeof(g_dev[idx]));
        memcpy(g_dev[idx].mac, mac, 6);
        g_dev[idx].first_seen = ts;
    }
    transit_device_t *d = &g_dev[idx];

    /* Closest approach across every pass. RSSI is negative, so stronger
     * is greater; 0 is the "unknown" sentinel and must not win. */
    if (peak_rssi != 0 && (d->best_rssi == 0 || peak_rssi > d->best_rssi))
        d->best_rssi = peak_rssi;

    if (ts > d->last_seen) d->last_seen = ts;
    if (d->first_seen == 0 || ts < d->first_seen) d->first_seen = ts;

    /* Coalesce: a run of transit verdicts from one slow drive-by is one
     * pass, not several. Counting each observation would manufacture
     * recurrence out of a single event. */
    if (d->pass_n > 0) {
        time_t last = d->pass_ts[d->pass_n - 1];
        long gap = (long)(ts - last);
        if (gap < 0) gap = -gap;
        if (gap < TRANSIT_GAP_SECS) return;
    }

    if (d->pass_n < MAX_TRANSIT_PASSES) {
        d->pass_ts[d->pass_n++] = ts;
    } else {
        /* Full: drop the oldest pass and append. A device with more
         * than MAX_TRANSIT_PASSES recorded is already far past the
         * alert threshold, so losing the earliest changes nothing that
         * matters. */
        memmove(&d->pass_ts[0], &d->pass_ts[1],
                sizeof(d->pass_ts[0]) * (MAX_TRANSIT_PASSES - 1));
        d->pass_ts[MAX_TRANSIT_PASSES - 1] = ts;
    }
}

int transit_pass_count(const uint8_t mac[6], time_t now, int window_secs) {
    if (!mac) return 0;
    int idx = find_dev(mac);
    if (idx < 0) return 0;
    const transit_device_t *d = &g_dev[idx];
    int n = 0;
    for (int i = 0; i < d->pass_n; i++) {
        long age = (long)(now - d->pass_ts[i]);
        if (age < 0) age = 0;              /* clock stepped back */
        if (age <= window_secs) n++;
    }
    return n;
}

void transit_snapshot(sloth_state_t *s, time_t now) {
    if (!s) return;

    /* Drop devices whose most recent pass has left the window. The
     * table is a live picture, not an archive — the durable record is
     * the SQLite sink. */
    int i = 0;
    while (i < g_count) {
        long age = (long)(now - g_dev[i].last_seen);
        if (age > TRANSIT_WINDOW_SECS)
            g_dev[i] = g_dev[--g_count];
        else
            i++;
    }

    int n = g_count < MAX_TRANSIT_DEVICES ? g_count : MAX_TRANSIT_DEVICES;
    memcpy(s->transits, g_dev, (size_t)n * sizeof(transit_device_t));
    s->transit_count = n;
}

void transit_clear(void) {
    g_count = 0;
    memset(g_dev, 0, sizeof(g_dev));
}

void transit_canonical_mac(const sloth_state_t *s, const uint8_t mac[6],
                           uint8_t out[6]) {
    if (!out || !mac) return;
    memcpy(out, mac, 6);
    if (!s) return;

    /* Randomised MACs from one physical radio share a monotonic
     * sequence counter, which seqnum_track correlates into pairs. Pick
     * the numerically smaller address of a pair as canonical so both
     * sides resolve to the same key whichever is seen first — otherwise
     * the same device would accumulate two half-counts and never reach
     * the threshold.
     *
     * One hop only. Chasing transitive chains would need a union-find
     * over a table that is rebuilt every poll, and the correlator
     * already pairs each radio's addresses directly. */
    for (int i = 0; i < s->seqnum_correlation_count; i++) {
        const seqnum_correlation_t *c = &s->seqnum_correlations[i];
        const uint8_t *other = NULL;
        if      (memcmp(c->mac_a, mac, 6) == 0) other = c->mac_b;
        else if (memcmp(c->mac_b, mac, 6) == 0) other = c->mac_a;
        if (!other) continue;
        if (memcmp(other, out, 6) < 0) memcpy(out, other, 6);
    }
}
