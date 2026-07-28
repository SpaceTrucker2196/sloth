/* Recurring-transit tracking — issue #54.
 *
 * One device driving past is traffic. The same device driving past
 * three times in two hours is a person circling the building, and it is
 * the observation a human operator cannot make unaided — nobody
 * remembers which of two hundred MACs they saw forty minutes ago.
 *
 * #53 can say "this emitter passed by". This accumulates those verdicts
 * across a horizon longer than the probe table's, which evicts a client
 * after PROBE_AGE_SECS (120 s) — so without a separate tracker three
 * passes an hour apart are three unrelated entries, two of them already
 * gone.
 *
 * Two things this deliberately does NOT do:
 *
 *  - It does not decide identity. The caller passes whatever key it
 *    considers canonical, so MAC-randomisation handling (resolving
 *    through seqnum correlations) lives at the call site and this
 *    module stays pure bookkeeping over an opaque 6-byte key.
 *  - It does not read the clock. Every timestamp is a parameter, so the
 *    coalescing and windowing logic is testable without waiting. */

#ifndef SLOTH_TRANSIT_H
#define SLOTH_TRANSIT_H

#include "sloth.h"

/* Two observations closer together than this are the same pass. A slow
 * drive-by, or a vehicle stopped at a light inside RF range, produces a
 * run of transit verdicts; counting each as a separate approach would
 * manufacture recurrence out of one event — the exact false positive
 * that would make the alert untrustworthy. */
#define TRANSIT_GAP_SECS      300

/* Recurrence is only interesting if it is recent. Someone who passed
 * twice this morning and once tonight is commuting. */
#define TRANSIT_WINDOW_SECS  7200   /* 2 h */

/* Passes inside the window before it is worth telling anyone. Two is a
 * round trip — going somewhere and coming back is what roads are for.
 * Three is a circuit. */
#define TRANSIT_RECUR_THRESH    3

/* Record a pass. `ts` is when the pass was observed; `peak_rssi` is the
 * closest approach (0 = unknown). Coalesces into the previous pass when
 * within TRANSIT_GAP_SECS, otherwise starts a new one. */
void transit_observe(const uint8_t mac[6], time_t ts, int8_t peak_rssi);

/* Passes recorded for `mac` within `window_secs` of `now`. 0 when the
 * device is unknown. */
int transit_pass_count(const uint8_t mac[6], time_t now, int window_secs);

/* Copy the live table into `s->transits`, dropping devices whose most
 * recent pass has fallen outside the window. Called once per poll. */
void transit_snapshot(sloth_state_t *s, time_t now);

/* Drop everything — tests, and `[c]`-style clears. */
void transit_clear(void);

/* Resolve `mac` to a canonical identity using the seqnum correlation
 * table (#53's randomisation gap). Randomised MACs belonging to one
 * physical radio correlate on a shared monotonic sequence counter; when
 * a correlation links `mac` to another address, the numerically smaller
 * of the pair is chosen as the canonical one so both sides of the pair
 * resolve to the same key regardless of which is seen first.
 *
 * Falls back to `mac` unchanged when nothing links it. Pure — reads
 * state, writes only `out`. */
void transit_canonical_mac(const sloth_state_t *s, const uint8_t mac[6],
                           uint8_t out[6]);

#endif /* SLOTH_TRANSIT_H */
