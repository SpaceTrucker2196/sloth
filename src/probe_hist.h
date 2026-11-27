#ifndef SLOTH_PROBE_HIST_H
#define SLOTH_PROBE_HIST_H

#include <stdint.h>
#include <time.h>

/* Directed-probe history (2026-11-27, owner request for the Probes
 * tab's waterfall): how many directed probe requests each transmitter
 * address sent for each SSID, counted per PROBE_HIST_BUCKET_S bucket,
 * for sloth.db's probe_history table (src/db.c write_probe_history()).
 *
 * pnl_ssids keeps only the first and last time a (MAC, SSID) pair was
 * heard; this keeps the shape in between. A directed probe is one
 * probe_pnl_observe() takes: a non-empty SSID element. A wildcard probe
 * (zero-length SSID) names no network and is not counted, for the same
 * reason the PNL drops it; the Probes tab never lists it as an SSID.
 *
 * The capture thread counts; the --db writer drains. With no sink
 * attached (no --db, or sloth-rf, which has no capture) nothing is
 * counted. The table holds each key of a bucket until a drain after
 * that bucket has ended, so a drain writes what was counted since the
 * last one and a key stays one row per bucket however often it is
 * drained.
 *
 * Bounded: at most PROBE_HIST_BUCKET_KEYS distinct (MAC, SSID) keys per
 * bucket and PROBE_HIST_SLOTS keys held in all (two buckets' worth, the
 * one closing and the one opening). A burst of randomised addresses
 * past either bound cannot grow the table or the file: a probe that
 * would need a new key past it is dropped, never counted, and noted as
 * SH_EVICT_PROBE_HIST (sensor_health's evict_probe_hist). Probes on a
 * key the table already holds are always counted, so what a flood
 * costs is the rows of its newest addresses in that bucket, not the
 * counts of the devices already there. pnl_clients.probe_count and
 * pnl_ssids are unaffected. */

#define PROBE_HIST_BUCKET_S     600
#define PROBE_HIST_BUCKET_KEYS  2048
#define PROBE_HIST_SLOTS        (2 * PROBE_HIST_BUCKET_KEYS)

typedef struct {
    uint8_t  mac[6];
    char     ssid[33];
    time_t   bucket;      /* start of the bucket, a multiple of PROBE_HIST_BUCKET_S */
    uint32_t count;       /* directed probes since the last drain */
    time_t   first_seen;  /* first and last of those probes */
    time_t   last_seen;
} probe_hist_row_t;

/* Attach (1) or detach (0) the consumer. db_open() attaches. */
void probe_hist_set_sink(int on);

/* One directed probe from `mac` for `ssid` at wall time `now`. An empty
 * or NULL ssid is ignored. Takes the module's own lock. */
void probe_hist_note(const uint8_t mac[6], const char *ssid, time_t now);

/* Copy up to `max` keys with probes counted since the last drain into
 * `out` and zero their counts. Returns the number copied; call until it
 * returns 0. The call that finds nothing left also frees the keys of
 * buckets older than the newest one heard. */
int  probe_hist_drain(probe_hist_row_t *out, int max);

/* Keys held, and probes dropped for want of a key since the last
 * probe_hist_clear() (db_close() clears; the lifetime tally is
 * sh_evict_count(SH_EVICT_PROBE_HIST)). */
int      probe_hist_keys(void);
uint64_t probe_hist_dropped(void);

/* Empty the table and detach the sink. */
void probe_hist_clear(void);

#endif /* SLOTH_PROBE_HIST_H */
