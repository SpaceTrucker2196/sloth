#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>

/* Longest hostname the cache stores, NUL included. A caller that wants
   a name back untruncated sizes its buffer with this. */
#define DNS_NAME_MAX 256

/* Start/stop the background resolver thread.

   dns_init() starts the worker only when active resolution is enabled
   (#84 slice 2), so a strict run never creates the one thread in sloth
   that can call getnameinfo(3). Set the policy — normally from the CLI
   flags — before calling this. Calling it twice does not start a second
   worker; the cache is reset either way. */
void dns_init(void);
void dns_cleanup(void);

/* Non-blocking lookup: the pre-#84 spelling of dns_resolve(), with the
   same caller-owned buffer contract (below). It *requests* active
   resolution on a cache miss, which since slice 2 is granted only under
   --allow-active. New code should name the half it means. */
const char *dns_lookup(const char *ip, char *buf, size_t sz);

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
 * ── Result ownership (#95) ──
 *
 * The caller owns the output. Each function writes the hostname when
 * one is known, or a copy of ip when it is not, into buf (at most sz
 * bytes, always NUL-terminated, truncated to fit) and returns buf. The
 * copy out of the cache happens under the cache lock, so what lands in
 * buf is one entry's name as it stood at one instant — never a mix of
 * two.
 *
 * Until #95 both returned a pointer into one static buffer shared by
 * every caller. dns_lookup_cached() runs on the capture thread
 * (capture_quic_hostname()) while the main thread runs dns_resolve()
 * for top_hosts and the packet detail pane, so the capture thread could
 * read a name the main thread was overwriting: a torn hostname that
 * then went into a QUIC log record. A caller-owned buffer has no
 * second writer.
 *
 * buf must not overlap ip. Size it DNS_NAME_MAX for an untruncated
 * name. A NULL buf or sz == 0 writes nothing and returns ip — the one
 * case where the return is not buf. All three functions are safe to
 * call from any thread.
 */
const char *dns_lookup_cached(const char *ip, char *buf, size_t sz);
const char *dns_resolve(const char *ip, char *buf, size_t sz);

/* ── Resolver policy (#84 slice 2) ───────────────────────────────────
 *
 * Strict observation is the DEFAULT. Without an explicit opt-in sloth
 * originates no reverse-DNS traffic: dns_resolve() suppresses every
 * request and dns_init() never creates the worker. That makes
 * MISSION.md §2.1 ("never resolves hosts it didn't already see") a
 * property of the shipped binary rather than of how it is invoked.
 *
 * --allow-active calls dns_resolver_set_enabled(1) and says so on
 * stderr. --strict calls dns_resolver_lock_strict(), which turns the
 * resolver off and refuses every later enable for the lifetime of the
 * process — so the guarantee holds for the whole run, not until the
 * next call.
 *
 * The lock itself lives in src/observe.h (slice 3), not here and not in
 * the argv parser: the nl80211 scan trigger and the discovery carve-out
 * have to honour the same lock, and neither can depend on this module.
 * The functions below are the resolver's view of that one policy.
 */
#define DNS_RESOLVER_DEFAULT_ENABLED 0

void dns_resolver_set_enabled(int enabled);
int  dns_resolver_enabled(void);

/* Lock strict observation for the run: disables the resolver now and
   makes dns_resolver_set_enabled(1) a refused no-op from here on. */
void dns_resolver_lock_strict(void);
int  dns_resolver_strict_locked(void);

/* Is the resolver worker thread alive? The observable half of the
   worker gate — "the DNS worker was never started" is what #84 asks
   for, and this is how a test proves it. */
int  dns_resolver_worker_running(void);

/* Restore the shipped default and clear the strict lock (for testing). */
void dns_resolver_reset_policy(void);

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
