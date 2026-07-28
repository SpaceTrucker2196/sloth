/* Presence classification. Contract and reasoning in presence.h (#53). */

#include "presence.h"

/* Copy the ring's live samples into chronological order.
 *
 * rssi_ring_t is circular: `head` is the next slot to be written, so
 * once the ring has wrapped the oldest sample sits at `head`, not at 0.
 * Reading the raw array in index order would scramble the time series
 * and turn a clean rise-peak-fall into noise — which is exactly the
 * shape this module exists to detect.
 *
 * Returns the number of samples written to `out`, oldest first. */
static int ordered_samples(const rssi_ring_t *ring, time_t now,
                           int8_t *out, int max) {
    if (!ring || ring->count <= 0) return 0;
    int count = ring->count;
    if (count > RSSI_WIN_SAMPLES) count = RSSI_WIN_SAMPLES;

    int n = 0;
    for (int k = 0; k < count && n < max; k++) {
        /* Full ring starts at head; a partly-filled one starts at 0. */
        int idx = (count == RSSI_WIN_SAMPLES)
                ? (ring->head + k) % RSSI_WIN_SAMPLES
                : k;
        /* Honour the ring's own window: a stale sample is not evidence
         * about what is happening now. A zero timestamp means the slot
         * was never written. */
        if (ring->ts[idx] == 0) continue;
        if (now - ring->ts[idx] > RSSI_WIN_SECS) continue;
        out[n++] = ring->dbm[idx];
    }
    return n;
}

int presence_has_transit_shape(const rssi_ring_t *ring, time_t now) {
    int8_t s[RSSI_WIN_SAMPLES];
    int n = ordered_samples(ring, now, s, RSSI_WIN_SAMPLES);
    if (n < PRESENCE_MIN_SAMPLES) return 0;

    /* Strongest sample is the closest approach. RSSI is negative, so
     * "strongest" is the greatest value. */
    int peak = 0;
    for (int i = 1; i < n; i++)
        if (s[i] > s[peak]) peak = i;

    /* The peak must be interior. A series that peaks at its first or
     * last sample is still rising or still falling — the device may yet
     * be approaching, or may have simply gone quiet — and calling that
     * a completed pass would be guessing at the half we cannot see.
     *
     * The sided minima below happen to enforce this too (a peak at
     * either end makes that side's swing zero), so this is a statement
     * of the rule rather than the thing implementing it. Kept because
     * the rule is not obvious from the arithmetic. */
    if (peak == 0 || peak == n - 1) return 0;

    /* Measure against the weakest sample on each side rather than the
     * endpoints, so one anomalous reading at the very start or end
     * cannot mask an otherwise clean transit. */
    int8_t before = s[0], after = s[n - 1];
    for (int i = 0; i < peak; i++)      if (s[i] < before) before = s[i];
    for (int i = peak + 1; i < n; i++)  if (s[i] < after)  after  = s[i];

    int rise = s[peak] - before;
    int fall = s[peak] - after;
    return rise >= PRESENCE_SWING_DBM && fall >= PRESENCE_SWING_DBM;
}

presence_class_t presence_classify(const rssi_ring_t *ring,
                                   time_t first_seen, time_t last_seen,
                                   time_t now) {
    long dwell = (long)(last_seen - first_seen);
    if (dwell < 0) dwell = 0;      /* clock stepped back; treat as new */

    /* Transit is the strong claim and is checked first, because a
     * device that demonstrably passed by should not be reported as a
     * visitor merely for having been audible either side of the pass. */
    if (dwell <= PRESENCE_TRANSIENT_MAX_S &&
        presence_has_transit_shape(ring, now))
        return PRESENCE_TRANSIENT;

    if (dwell >= PRESENCE_RESIDENT_MIN_S) return PRESENCE_RESIDENT;
    if (dwell >= PRESENCE_VISITOR_MIN_S)  return PRESENCE_VISITOR;

    /* Short dwell with no transit evidence. It may be a device that
     * just arrived, or one heard once while the radio was hopping —
     * both are "we do not know yet", which is the honest answer. */
    return PRESENCE_UNKNOWN;
}

const char *presence_label(presence_class_t c) {
    switch (c) {
    case PRESENCE_TRANSIENT: return "passing";
    case PRESENCE_VISITOR:   return "visitor";
    case PRESENCE_RESIDENT:  return "resident";
    case PRESENCE_UNKNOWN:
    default:                 return "?";
    }
}
