#ifndef CAPTURE_H
#define CAPTURE_H

#include "ntop.h"

#ifdef WITH_PCAP

/* Start a background pcap capture thread writing into s->packets[].
   No-op when pcap_open_live fails (no root / no devices). */
void capture_start(ntop_state_t *s);

/* Signal the capture thread to stop and block until it exits. */
void capture_stop(void);

/* Compile and apply a BPF filter expression on the live handle.
   Pass "" to accept all packets.  Returns 0 on success, -1 on error
   with a message written into errbuf (may be NULL). */
int capture_set_filter(const char *expr, char *errbuf, int errsz);

#else

static inline void capture_start(ntop_state_t *s)  { (void)s; }
static inline void capture_stop(void)               {}
static inline int  capture_set_filter(const char *e, char *b, int n)
    { (void)e; (void)b; (void)n; return 0; }

#endif /* WITH_PCAP */

#endif /* CAPTURE_H */
