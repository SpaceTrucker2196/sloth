#ifndef CAPTURE_PROBE_H
#define CAPTURE_PROBE_H

#include "ntop.h"

#ifdef WITH_PCAP

/* Find a monitor-mode interface and start capturing probe requests.
   Silently does nothing if no monitor interface exists or pcap fails. */
void probe_start(ntop_state_t *s);

/* Signal the probe thread to stop and block until it exits. */
void probe_stop(void);

/* Copy the current probe client table into s->probe_clients[],
   ageing out entries older than PROBE_AGE_SECS. Call from poll_data. */
void probe_snapshot(ntop_state_t *s);

/* Erase all tracked clients from the internal table. */
void probe_clear(void);

/* Stop any running capture and restart on iface.
   Silently does nothing if iface is not radiotap or pcap fails. */
void probe_set_iface(ntop_state_t *s, const char *iface);

#else

static inline void probe_start(ntop_state_t *s)                        { (void)s; }
static inline void probe_stop(void)                                     {}
static inline void probe_snapshot(ntop_state_t *s)                     { (void)s; }
static inline void probe_clear(void)                                    {}
static inline void probe_set_iface(ntop_state_t *s, const char *iface) { (void)s; (void)iface; }

#endif /* WITH_PCAP */

#endif /* CAPTURE_PROBE_H */
