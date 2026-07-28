#ifndef CAPTURE_H
#define CAPTURE_H

#include "sloth.h"

/* Classify a pcap_activate() return code.

   pcap_activate() returns 0 on clean success, a *positive* PCAP_WARNING_*
   code on success-with-caveats, and a negative PCAP_ERROR_* code on
   failure. Only negative is fatal. Treating any non-zero return as fatal
   closed a live SLL2 handle on the "any" device (which warns
   PCAP_WARNING_PROMISC_NOTSUP), silently downgrading capture to SLL v1 —
   no ingress ifindex, so the per-iface allow-list passed everything (#46).

   Declared and compiled without WITH_PCAP so the classification can be
   pinned by the test suite without linking libpcap. */
int capture_activate_failed(int rc);

#ifdef WITH_PCAP

/* Start a background pcap capture thread writing into s->packets[].
   No-op when pcap_open_live fails (no root / no devices). */
void capture_start(sloth_state_t *s);

/* Signal the capture thread to stop and block until it exits. */
void capture_stop(void);

/* Compile and apply a BPF filter expression on the live handle.
   Pass "" to accept all packets.  Returns 0 on success, -1 on error
   with a message written into errbuf (may be NULL). */
int capture_set_filter(const char *expr, char *errbuf, int errsz);

#else

static inline void capture_start(sloth_state_t *s)  { (void)s; }
static inline void capture_stop(void)               {}
static inline int  capture_set_filter(const char *e, char *b, int n)
    { (void)e; (void)b; (void)n; return 0; }

#endif /* WITH_PCAP */

#endif /* CAPTURE_H */
