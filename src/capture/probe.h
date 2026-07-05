#ifndef CAPTURE_PROBE_H
#define CAPTURE_PROBE_H

#include "sloth.h"

#ifdef WITH_PCAP

/* Find a monitor-mode interface and start capturing probe requests.
   Silently does nothing if no monitor interface exists or pcap fails. */
void probe_start(sloth_state_t *s);

/* Signal the probe thread to stop and block until it exits. */
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

/* Erase all tracked clients from the internal table. */
void probe_clear(void);

/* Stop any running capture and restart on iface.
   Silently does nothing if iface is not radiotap or pcap fails. */
void probe_set_iface(sloth_state_t *s, const char *iface);

#else

static inline void probe_start(sloth_state_t *s)                        { (void)s; }
static inline void probe_stop(void)                                     {}
static inline void probe_snapshot(sloth_state_t *s)                     { (void)s; }
static inline void mon_frame_snapshot(sloth_state_t *s)                 { (void)s; }
static inline uint64_t mon_frame_total(void)                            { return 0; }
static inline void probe_clear(void)                                    {}
static inline void probe_set_iface(sloth_state_t *s, const char *iface) { (void)s; (void)iface; }

#endif /* WITH_PCAP */

#endif /* CAPTURE_PROBE_H */
