#ifndef SLOTH_COV_TIMELINE_H
#define SLOTH_COV_TIMELINE_H

#include <stdint.h>

/* ── Where the radios were, and what the monitor handle dropped (#246) ──
 *
 * A finding's `complete` (src/alert_quality.h) asks two questions about
 * the window its cited frames span: was a hopping radio away from a
 * channel those frames are on for part of it, and did the monitor
 * handle drop frames inside it. The per-interval coverage record
 * (src/cov_interval.h) answers both per minute, which is too coarse: a
 * window of a few beacons lies inside one dwell or straddles a hop, and
 * a minute holds sixty dwells either way. So this keeps the two
 * histories at the resolution they happen at, bounded:
 *
 *   dwells   one entry per confirmed retune: radio, frequency, the wall
 *            clock in ms when the scheduler confirmed it. A dwell lasts
 *            until the same radio's next entry. Fed by chanhop_service()
 *            (radio 0) and mon_hop_service() (the other sensor radios),
 *            which is every retune there is. COV_TL_DWELLS entries: at
 *            the reference sensor's ~1 s measured dwell (one radio,
 *            2026-11-23) about 17 minutes; at the scheduler's 100 ms
 *            floor on all MON_RADIO_MAX radios, about 25 s.
 *   drops    the monitor handle's pcap_stats() drop total (ps_drop +
 *            ps_ifdrop), one sample a poll tick, from the coverage
 *            sampler (src/cov_interval_capture.c). COV_TL_DROPS samples.
 *            Radio 0's handle only: the further --monitor-iface radios
 *            take no pcap_stats() sample (cov_interval_capture.h).
 *
 * Wall clock, not monotonic, because the windows come from frame capture
 * times, which are the kernel's CLOCK_REALTIME (src/capture/probe.c's
 * clock note). A note older than the one before it (a wall step back)
 * is stored at the previous note's time, so the ring stays ordered.
 *
 * Main thread only: the hop stage, the sampler and alerts_update() all
 * run on the poll loop. Fixed memory, no allocation; nothing here opens
 * a device or retunes anything. sloth-rf feeds it nothing. */

#define COV_TL_DWELLS   1024
#define COV_TL_DROPS    128
/* Radios a dwell can name: MON_RADIO_MAX today, with room. */
#define COV_TL_RADIOS   8
/* Uncovered time up to this is not a hop away. A dwell is stamped when
 * the retune is confirmed, after the driver call returns, so a frame
 * on the new channel can carry a capture time a little before its
 * dwell's start. The scheduler's shortest dwell (min_dwell_ms, 100) is
 * the bound: a gap shorter than one dwell cannot hold a visit to
 * another channel. */
#define COV_TL_SLACK_MS 100

/* A confirmed retune of `radio` to `freq_mhz` at `wall_ms`; freq 0
 * marks the radio gone (dealt out of the hop list, src/mon_radios.c),
 * so its last dwell does not run on. */
void    cov_tl_hop_note(int radio, int freq_mhz, int64_t wall_ms);

/* The ms of [t0_ms, t1_ms] in which no radio is recorded on `freq_mhz`.
 * Time before the oldest dwell the ring holds counts as uncovered: the
 * ring cannot show a radio was there. -1 when no dwell is recorded at
 * all (not hopping, or a test that fed none); 0 for an empty window. */
int64_t cov_tl_uncovered_ms(int freq_mhz, int64_t t0_ms, int64_t t1_ms);

/* One sample of the monitor handle's drop total. */
void    cov_tl_drops_note(int64_t wall_ms, uint64_t total);

/* Whether the total rose between the newest sample at or before t0_ms
 * and the oldest at or after t1_ms (the newest sample when none is that
 * late yet): 1 it rose, 0 it did not, -1 not known (no sample before the
 * window, or none after its start). One poll tick of resolution: a drop
 * in the tick that holds the window's edge counts as inside it. */
int     cov_tl_drops_in(int64_t t0_ms, int64_t t1_ms);

/* Entries held, for the tests. */
int     cov_tl_dwell_count(void);
int     cov_tl_drop_count(void);
/* The newest dwell of `radio`: 1 and its frequency and start, 0 when
 * the ring holds none. For the tests. */
int     cov_tl_radio_last(int radio, int *freq_mhz, int64_t *wall_ms);

void    cov_tl_reset(void);

#endif /* SLOTH_COV_TIMELINE_H */
