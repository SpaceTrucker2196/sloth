#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/* Start/stop the background resolver thread. */
void dns_init(void);
void dns_cleanup(void);

/* Non-blocking lookup. Returns the cached hostname, or the original IP
   string if resolution is pending/failed. Safe to call only from the
   main thread. The returned pointer is valid until the next dns_lookup call.

   Retained as the pre-#84 spelling of dns_resolve(); it requests active
   resolution on a cache miss. New code should name the half it means. */
const char *dns_lookup(const char *ip);

/* ── Passive lookup vs. active resolution (#84) ──────────────────────
 *
 * MISSION.md §2.1 says sloth "never resolves hosts it didn't already
 * see". The two halves below make that distinction expressible in the
 * type system of the callers rather than in a comment:
 *
 *   dns_lookup_cached() answers *only* from metadata sloth already
 *   observed — names injected by the DNS/mDNS/NBNS/DHCP/SNI snoopers
 *   via dns_set_resolved(), or a reverse resolve that already
 *   completed. It queues nothing, claims no cache slot, and can never
 *   reach the network. A cold cache costs exactly one table scan.
 *
 *   dns_resolve() is the single choke point for active reverse
 *   resolution: it is the only function in the tree that can hand an
 *   address to the getnameinfo() worker. Gating it gates all of
 *   sloth's name-resolution egress, which is what #84 slice 2 needs.
 *
 * Both return the hostname when one is known and the ip argument
 * unchanged when it is not. The returned pointer is valid until the
 * next call to either function.
 */
const char *dns_lookup_cached(const char *ip);
const char *dns_resolve(const char *ip);

/* Resolver policy. Enabled by default, which preserves the behaviour
   sloth has shipped since the resolver was added — #84 slice 1 builds
   the choke point, it does not decide what flows through it. Whether
   the shipped default flips (and under which flag) is #84 slice 2. */
void dns_resolver_set_enabled(int enabled);
int  dns_resolver_enabled(void);

/* Observability seam for #84's regression requirement ("assert zero
   resolver work"). Counting here rather than in the caller means a
   test can prove a whole code path stayed passive without knowing
   which functions that path happens to call. */
typedef struct {
    uint64_t cached_lookups;     /* dns_lookup_cached() calls           */
    uint64_t resolve_requests;   /* dns_resolve() calls (incl. dns_lookup) */
    uint64_t resolve_enqueued;   /* addresses handed to the worker      */
    uint64_t resolve_suppressed; /* requests refused — resolver disabled */
    uint64_t getnameinfo_calls;  /* actual getnameinfo(3) invocations   */
} dns_resolver_stats_t;

void dns_resolver_stats(dns_resolver_stats_t *out);
void dns_resolver_stats_reset(void);

/* Format "host:port" or "ip:port" into buf (always NUL-terminated). */
void dns_fmt_addr(const char *ip, uint16_t port, char *buf, int sz);

/* Reset all cache and queue state (for testing). */
void dns_reset(void);

/* Inject a resolved entry directly (for testing). */
void dns_set_resolved(const char *ip, const char *host);

#endif /* DNS_H */
