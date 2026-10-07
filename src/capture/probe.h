#ifndef CAPTURE_PROBE_H
#define CAPTURE_PROBE_H

#include "sloth.h"

#ifdef WITH_PCAP

/* Find a monitor-mode interface and open it, setting s->probe_iface
   synchronously, WITHOUT starting the probe thread — so startup can
   resolve --monitor-only and decide capture scope before any worker
   runs (#85). Silently does nothing if no monitor interface exists or
   pcap fails. */
void probe_open(sloth_state_t *s);

/* Start the probe thread on the handle probe_open() made; no-op without
   one. */
void probe_run(void);

/* probe_open() + probe_run(). */
void probe_start(sloth_state_t *s);

/* Signal the probe thread to stop and block until it exits; closes a
   handle that was opened but never run. */
void probe_stop(void);

/* Copy the current probe client table into s->probe_clients[],
   ageing out entries older than PROBE_AGE_SECS. Call from poll_data. */
void probe_snapshot(sloth_state_t *s);

/* Copy the captured 802.11 frame ring into s->mon_frames[] (newest first).
   Feeds the dashboard's monitor packets band. Call from poll_data. */
void mon_frame_snapshot(sloth_state_t *s);

/* Cumulative count of 802.11 frames ever seen by the monitor capture —
   the observation count for the Wi-Fi sensor (#28). */
uint64_t mon_frame_total(void);

/* Frames whose capture timestamp was <= 0 — the epoch or before it,
   which no live kernel produces (#92). Nothing is substituted when it
   happens: a frame is stamped with what the capture says. This exists
   so an operator can tell a quiet radio from a capture whose clock is
   broken, and is exported as `mon_bad_clock` in sensor_health. */
uint64_t mon_bad_clock_total(void);

/* Erase all tracked clients from the internal table. */
void probe_clear(void);

/* Stop any running capture and restart on iface.
   Silently does nothing if iface is not radiotap or pcap fails.
   Refuses, before stopping anything, when a non-empty launch-time
   allow-list excludes iface (#85): s->probe_err carries the reason and
   a running radio is left untouched. An empty allow-list admits
   everything, so an unrestricted run is unaffected. */
void probe_set_iface(sloth_state_t *s, const char *iface);

/* Drive the real on_probe_frame() over caller-supplied radiotap+802.11
   frames via an in-memory libpcap savefile — the monitor twin of
   capture_test_dispatch() (#92). No device, no .pcap fixture. ts_secs
   is optional and sets each frame's capture timestamp, which is what
   lets a test pin which clock a record was stamped from. orig_lens is
   optional and sets each record's `len` independently of its caplen —
   the "kernel snapped it" case, and the one that distinguishes a
   callback reading hdr->len from one reading hdr->caplen (the exact
   confusion #92 found in this file on 2026-10-01). Both NULL reproduce
   the pre-existing behaviour: synthetic increasing stamps, len ==
   caplen. Synchronous; returns frames delivered, or -1. */
int probe_test_dispatch(sloth_state_t *s,
                        const uint8_t *const *frames, const int *lens,
                        const int *orig_lens,
                        const uint32_t *ts_secs, int n);

/* Refresh `h` from the monitor-radio handle — liveness, the worker's
   exit classification once it has ended, and one pcap_stats() sample
   (#91 slice 2). The mirror of capture_health_poll() for the radio;
   this is the stream where "quiet channel" and "dead thread" were most
   expensive to confuse. Called once per poll from main(). */
void probe_health_poll(capture_health_t *h);

#else

static inline void probe_open(sloth_state_t *s)                         { (void)s; }
static inline void probe_run(void)                                      {}
static inline void probe_start(sloth_state_t *s)                        { (void)s; }
static inline void probe_stop(void)                                     {}
static inline void probe_snapshot(sloth_state_t *s)                     { (void)s; }
static inline void mon_frame_snapshot(sloth_state_t *s)                 { (void)s; }
static inline uint64_t mon_frame_total(void)                            { return 0; }
static inline uint64_t mon_bad_clock_total(void)                        { return 0; }
static inline void probe_clear(void)                                    {}
static inline void probe_set_iface(sloth_state_t *s, const char *iface) { (void)s; (void)iface; }
static inline void probe_health_poll(capture_health_t *h)
    { if (h) { h->open = 0; h->running = 0; } }

#endif /* WITH_PCAP */

#endif /* CAPTURE_PROBE_H */
