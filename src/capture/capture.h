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

/* Can frames on this datalink be attributed to an ingress interface?

   Only DLT_LINUX_SLL2 carries sll2_if_index, which is what the
   data-stream election keys on (#17, #35). On SLL v1, EN10MB or anything
   else no frame can be attributed, so --iface / --monitor-only cannot be
   enforced: startup refuses and the callback drops (#85).

   Capture reaches a non-SLL2 datalink by several routes — pcap_set_datalink()
   rejected by an older libpcap or kernel, the pcap_open_live() fallback, or
   capture never starting at all. Callers test this end state rather than
   enumerating causes, so a future route is covered for free (#57).

   Declared and compiled without WITH_PCAP so the classification can be
   pinned by the test suite without linking libpcap. */
int capture_dlt_has_ifindex(int dlt);

/* ── Fail-closed capture scope (#85) ──────────────────────────────

   The launch-time allow-list is an authorisation boundary: an operator
   who scoped sloth to the monitor radio has not authorised the VPN or
   the wired management port. Every "can't tell" case therefore drops.

   capture_ifname_lookup() maps an SLL2 ingress index to a name through
   a small cache. Only successful, non-empty resolutions are cached; a
   failure returns NULL and is asked again on the next packet, so a
   transient if_indextoname() miss is never remembered as an answer.
   The resolver returns 1 and fills name[16] on success. The cache is
   touched only by the capture thread (and reset before it starts).

   capture_frame_in_scope() is the per-packet election the pcap callback
   runs before decode. With a non-empty allow-list it admits a frame only
   when it is SLL2, long enough to carry the index, the index resolves
   to a non-empty name, and that name is allowed and not deselected.
   With no allow-list it applies the runtime [y] deselect as before and
   passes anything it cannot attribute. NULL state admits nothing.

   All three are compiled without WITH_PCAP so the test build can drive
   them with hand-built SLL2 headers and a seeded resolver. */
typedef int (*capture_ifname_fn)(uint32_t ifindex, char name[16]);
void        capture_ifname_cache_reset(void);
const char *capture_ifname_lookup(uint32_t ifindex, capture_ifname_fn resolve);
int         capture_frame_in_scope(const sloth_state_t *s, int dlt,
                                   const uint8_t *frame, int caplen,
                                   capture_ifname_fn resolve);

/* Startup decision: can the requested scope be enforced? (#85)

   Inputs are the end state after the allow-list has been seeded and
   capture opened, but before the capture worker starts:
     iface_args    — number of --iface arguments given
     monitor_only  — --monitor-only given
     monitor_iface — the monitor radio probe_open() found ("" = none)
     allowed_count — entries actually installed in the allow-list
     capture_open  — the data-stream pcap handle exists
     linktype      — its datalink (meaningless when !capture_open)

   A refusing verdict means main() must not start the worker and must
   exit non-zero. NO_CAPTURE is a warning, not a refusal: with no
   data-stream handle nothing out of scope can be collected. */
typedef enum {
    CAPTURE_SCOPE_NONE = 0,          /* no restriction requested */
    CAPTURE_SCOPE_ENFORCED,          /* allow-list active on SLL2 */
    CAPTURE_SCOPE_NO_CAPTURE,        /* requested, but no data stream */
    CAPTURE_SCOPE_REFUSE_NO_MONITOR, /* --monitor-only, no radio found */
    CAPTURE_SCOPE_REFUSE_EMPTY,      /* requested, nothing installed */
    CAPTURE_SCOPE_REFUSE_DATALINK    /* datalink carries no ifindex */
} capture_scope_t;

capture_scope_t capture_scope_verdict(int iface_args, int monitor_only,
                                      const char *monitor_iface,
                                      int allowed_count, int capture_open,
                                      int linktype);
int             capture_scope_refuses(capture_scope_t v);
/* One-line operator-facing reason for a non-NONE/ENFORCED verdict. */
const char     *capture_scope_reason(capture_scope_t v);

#ifdef WITH_PCAP

/* Open the data-stream pcap handle and record s->pkt_linktype, WITHOUT
   starting the capture thread. Silently leaves capture disabled when
   no handle can be opened (no root / no devices). */
void capture_open(sloth_state_t *s);

/* Non-zero iff capture_open() produced a handle. */
int capture_is_open(void);

/* Start the capture thread on the handle capture_open() made. The scope
   policy (s->iface_allowed) must be complete before this call: the
   thread's creation is the synchronisation point that publishes it, and
   the allow-list is never written again (#85). No-op without a handle. */
void capture_run(void);

/* capture_open() + capture_run(), for callers with no scope to install. */
void capture_start(sloth_state_t *s);

/* Signal the capture thread to stop and block until it exits; closes a
   handle that was opened but never run. */
void capture_stop(void);

/* Compile and apply a BPF filter expression on the live handle.
   Pass "" to accept all packets.  Returns 0 on success, -1 on error
   with a message written into errbuf (may be NULL). */
int capture_set_filter(const char *expr, char *errbuf, int errsz);

#else

static inline void capture_open(sloth_state_t *s)   { (void)s; }
static inline int  capture_is_open(void)            { return 0; }
static inline void capture_run(void)                {}
static inline void capture_start(sloth_state_t *s)  { (void)s; }
static inline void capture_stop(void)               {}
static inline int  capture_set_filter(const char *e, char *b, int n)
    { (void)e; (void)b; (void)n; return 0; }

#endif /* WITH_PCAP */

#endif /* CAPTURE_H */
