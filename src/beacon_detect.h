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
#define BD_MAX_JITTER_RATIO  0.25 /* stddev/mean must be <= this */

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
int  bd_is_strong(const char *remote_ip, uint16_t port);

typedef int (*bd_each_fn)(const bd_track_t *t, void *ud);
void bd_each (bd_each_fn cb, void *ud);
void bd_clear(void);

#endif /* BEACON_DETECT_H */
