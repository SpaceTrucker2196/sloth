#ifndef BEACON_DETECT_H
#define BEACON_DETECT_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Periodic-traffic ("C2 beaconing") detector. Distinct from beacon_snoop,
 * which captures 802.11 management beacons — this module tracks regular-
 * interval IP flows and feeds the alerts pipeline. */

#define BD_MAX_TRACKS      128
#define BD_MAX_SAMPLES      16
#define BD_MIN_SAMPLES       5
#define BD_MIN_INTERVAL_S   10   /* drop chatty heartbeats below this */
#define BD_GAP_S             5   /* same-session window for update() */
#define BD_MAX_JITTER_RATIO  0.25 /* v1: stddev/mean must be <= this */

/* v2 thresholds. Robust gap-concentration test: rather than measure
 * stddev/mean (which inflates fast under jitter and rules out the
 * exact beacons we want to catch), compute the *fraction of gaps*
 * within ±30% of the median gap. A periodic signal at any jitter
 * level keeps a median-stable distribution; uniform noise spreads
 * across the whole range.
 *
 * BD_MIN_CONCENTRATION = 0.60 catches up to ~40% additive jitter
 * (covers Cobalt Strike at "interactive" 30% setting and Sliver at
 * default 30% — frameworks documented in CISA's
 * AA22-277A "Cobalt Strike" advisory and the open-source Sliver
 * project). Sliver at 50% jitter is intentionally not caught —
 * with only 16 samples, statistical separation from random gap
 * distributions isn't reliable. The mitigation there is more
 * samples (longer-running flows) feeding v1.
 *
 * BD_MIN_SAMPLES_V2 = 12 keeps the per-flow false-positive rate
 * under 0.1% on uniform-random gap distributions at the 0.60
 * threshold. */
#define BD_MIN_CONCENTRATION 0.60
#define BD_MIN_SAMPLES_V2     12

typedef struct {
    char     remote_ip[46];
    uint16_t remote_port;
    time_t   last_active;
    time_t   samples[BD_MAX_SAMPLES];
    int      sample_count;
    int      head;
} bd_track_t;

void bd_observe(const char *remote_ip, uint16_t port, time_t now);
void bd_update (const sloth_state_t *s, time_t now);
int  bd_stats  (const char *remote_ip, uint16_t port,
                double *mean_s, double *jitter_s);

/* Best-fit period (= median gap) and concentration ratio under the
 * gap-concentration test. Returns sample count examined (≥
 * BD_MIN_SAMPLES_V2 if the search ran), 0 if too few samples.
 * period_s and concentration are zeroed when 0 is returned. */
int  bd_autocorr_stats(const char *remote_ip, uint16_t port,
                       double *period_s, double *concentration);

/* Strength classifier — returns:
 *   0 : not a beacon
 *   1 : v1 hit (classic low-jitter, stddev/mean ≤ BD_MAX_JITTER_RATIO)
 *   2 : v2 hit (autocorrelation; up to ~40% jitter)
 * Callers (alerts.c) treat any non-zero return as fire-worthy; the
 * specific value lets the detail string label which detector matched. */
int  bd_is_strong(const char *remote_ip, uint16_t port);

typedef int (*bd_each_fn)(const bd_track_t *t, void *ud);
void bd_each (bd_each_fn cb, void *ud);
void bd_clear(void);

#endif /* BEACON_DETECT_H */
