#ifndef EV_CITE_H
#define EV_CITE_H

#include <stdint.h>
#include <string.h>

/* Bounded evidence-ring citation rings — issue #92 slice 4.
 *
 * A detector that wants its alert to name the frames behind it keeps
 * the evidence-ring event IDs of those frames next to the state it
 * already keeps (a per-pair row, a per-AP record) and hands them to
 * fire_inv()/fire_ev() when it fires. deauth_snoop.c grew the first of
 * these by hand; this is the same ring, written once so the other
 * detector families do not each grow their own copy of the wrap
 * arithmetic.
 *
 * Contract, the same as deauth_snoop.c's:
 *   - 0 is never stored. evidence_ring_note() returns 0 when it retained
 *     nothing, and a citation of 0 can never resolve.
 *   - It keeps the NEWEST ids, not the first ones. The evidence ring is
 *     itself a FIFO, so the oldest frames of a long incident are the
 *     ones already gone from it; citing the newest keeps the citations
 *     retrievable.
 *   - An id already in the ring is not stored again, so one frame that
 *     feeds two observations (the PM=1 Null behind two contradictions)
 *     does not crowd out a second frame.
 *   - Flattened oldest-first, so a consumer reading evidence_ids[] in
 *     order never has to know where the head was.
 *
 * Callers own the storage (`ids[cap]`, `*n`, `*head`) so the ring can
 * sit in an exported struct at whatever size that struct can afford —
 * eight for a per-pair detector row, four on the 256-entry beacon table.
 * `cap` must be at most 255 (the counters are uint8_t). */

static inline void ev_cite_push(uint64_t *ids, int cap,
                                uint8_t *n, uint8_t *head, uint64_t id) {
    if (id == 0 || cap <= 0) return;
    for (int i = 0; i < *n && i < cap; i++)
        if (ids[i] == id) return;
    ids[*head % cap] = id;
    *head = (uint8_t)((*head + 1) % cap);
    if (*n < cap) (*n)++;
}

/* Copies at most `max` ids, oldest first, and returns how many. When the
 * ring holds more than `max`, the NEWEST `max` are the ones copied. */
static inline int ev_cite_flatten(const uint64_t *ids, int cap,
                                  uint8_t n, uint8_t head,
                                  uint64_t *out, int max) {
    if (!out || max <= 0 || cap <= 0) return 0;
    int have = n < cap ? n : cap;
    int skip = have > max ? have - max : 0;
    int k = 0;
    for (int e = skip; e < have; e++) {
        int src = have < cap ? e : (head + e) % cap;
        out[k++] = ids[src];
    }
    return k;
}

/* Append `src[0..sn)` to `dst[*dn..max)`, skipping ids already there.
 * For rules that cite two sources at once (both halves of an evil-twin
 * pair, a twin's beacons plus the deauth flood that chained into it). */
static inline void ev_cite_merge(uint64_t *dst, int *dn, int max,
                                 const uint64_t *src, int sn) {
    for (int i = 0; i < sn && *dn < max; i++) {
        if (src[i] == 0) continue;
        int dup = 0;
        for (int j = 0; j < *dn; j++)
            if (dst[j] == src[i]) { dup = 1; break; }
        if (!dup) dst[(*dn)++] = src[i];
    }
}

/* The flood trackers (auth, assoc, BTM) keep one global timestamped ring
 * rather than per-key rows, so their citation query walks that ring
 * newest first, collecting the ids of the entries its window accepts,
 * and then turns the result round so it reads oldest first like every
 * other citation list. */
static inline void ev_cite_reverse(uint64_t *ids, int k) {
    for (int i = 0; i < k / 2; i++) {
        uint64_t t = ids[i]; ids[i] = ids[k - 1 - i]; ids[k - 1 - i] = t;
    }
}

#endif /* EV_CITE_H */
