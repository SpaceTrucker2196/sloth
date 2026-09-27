#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "runner.h"
#include "dns.h"

/* Caller-owned result buffer for the dns.h lookups (#95). */
static char nb_[DNS_NAME_MAX];

/* ── Tests ───────────────────────────────────────────────── */

static void test_cache_miss_returns_ip(void) {
    dns_reset();
    /* Unknown IP: async resolve pending — raw IP returned immediately */
    ASSERT_STR(dns_lookup("192.0.2.1", nb_, sizeof(nb_)), "192.0.2.1");
}

static void test_dedup_pending(void) {
    dns_reset();
    /* Two lookups for same IP must not crash or corrupt queue */
    ASSERT_STR(dns_lookup("198.51.100.1", nb_, sizeof(nb_)), "198.51.100.1");
    ASSERT_STR(dns_lookup("198.51.100.1", nb_, sizeof(nb_)), "198.51.100.1");
}

static void test_inject_resolved(void) {
    dns_reset();
    dns_set_resolved("10.0.0.1", "myhost");
    ASSERT_STR(dns_lookup("10.0.0.1", nb_, sizeof(nb_)), "myhost");
}

static void test_inject_then_fmt_addr(void) {
    dns_reset();
    dns_set_resolved("10.0.0.2", "router");
    char buf[64];
    dns_fmt_addr("10.0.0.2", 80, buf, sizeof(buf));
    ASSERT_STR(buf, "router:http");
}

static void test_fmt_addr_no_entry(void) {
    dns_reset();
    char buf[64];
    dns_fmt_addr("203.0.113.5", 443, buf, sizeof(buf));
    /* Not resolved yet — raw IP, but port resolved to service name */
    ASSERT_STR(buf, "203.0.113.5:https");
}

static void test_reset_clears_cache(void) {
    dns_reset();
    dns_set_resolved("10.1.1.1", "before-reset");
    dns_reset();
    /* After reset the entry is gone — lookup returns raw IP */
    ASSERT_STR(dns_lookup("10.1.1.1", nb_, sizeof(nb_)), "10.1.1.1");
}

static void test_ipv6_miss_returns_ip(void) {
    dns_reset();
    ASSERT_STR(dns_lookup("2001:db8::1", nb_, sizeof(nb_)), "2001:db8::1");
}

static void test_inject_ipv6(void) {
    dns_reset();
    dns_set_resolved("::1", "localhost6");
    ASSERT_STR(dns_lookup("::1", nb_, sizeof(nb_)), "localhost6");
}

static void test_multiple_distinct_ips(void) {
    dns_reset();
    dns_set_resolved("1.1.1.1", "one.one.one.one");
    dns_set_resolved("8.8.8.8", "dns.google");
    ASSERT_STR(dns_lookup("1.1.1.1", nb_, sizeof(nb_)), "one.one.one.one");
    ASSERT_STR(dns_lookup("8.8.8.8", nb_, sizeof(nb_)), "dns.google");
}

/* ── Passive lookup vs. active resolver (#84) ────────────── */

/* Every test below starts from a cold cache AND zeroed counters, so a
 * counter assertion measures only what that test did. */
static void cold(void) {
    dns_reset();
    dns_resolver_reset_policy();   /* clears any --strict lock a test set */
    dns_resolver_set_enabled(1);
    dns_resolver_stats_reset();
}

/* Cold cache under the *shipped* policy rather than an enabled one. */
static void cold_default(void) {
    dns_reset();
    dns_resolver_reset_policy();
    dns_resolver_stats_reset();
}

static dns_resolver_stats_t snap(void) {
    dns_resolver_stats_t st;
    dns_resolver_stats(&st);
    return st;
}

/* The defect #84 names: a display path that only wants a name sloth
 * already saw must not generate DNS egress when it doesn't have one.
 * This is the test that would have caught it. */
static void test_cached_lookup_does_zero_resolver_work(void) {
    cold();
    ASSERT_STR(dns_lookup_cached("203.0.113.9", nb_, sizeof(nb_)), "203.0.113.9");

    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.cached_lookups);
    ASSERT_EQ(0, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);
}

/* A cache miss through the passive half must also leave no PENDING
 * slot behind — otherwise the *next* caller inherits queued work it
 * never asked for, which is the same egress one call later. */
static void test_cached_lookup_leaves_no_pending_slot(void) {
    cold();
    dns_lookup_cached("203.0.113.10", nb_, sizeof(nb_));
    dns_lookup_cached("203.0.113.10", nb_, sizeof(nb_));
    ASSERT_STR(dns_lookup_cached("203.0.113.10", nb_, sizeof(nb_)), "203.0.113.10");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* The passive half still answers from what the snoopers observed —
 * that is the whole point of keeping a cache at all. */
static void test_cached_lookup_returns_observed_name(void) {
    cold();
    dns_set_resolved("198.51.100.7", "observed.example");
    ASSERT_STR(dns_lookup_cached("198.51.100.7", nb_, sizeof(nb_)), "observed.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

static void test_cached_lookup_ipv6_miss_and_hit(void) {
    cold();
    ASSERT_STR(dns_lookup_cached("2001:db8::99", nb_, sizeof(nb_)), "2001:db8::99");
    dns_set_resolved("2001:db8::99", "v6.example");
    ASSERT_STR(dns_lookup_cached("2001:db8::99", nb_, sizeof(nb_)), "v6.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* dns_resolve() is the choke point: one request, one enqueue. */
static void test_resolve_enqueues_on_cold_cache(void) {
    cold();
    ASSERT_STR(dns_resolve("203.0.113.11", nb_, sizeof(nb_)), "203.0.113.11");
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(1, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.resolve_suppressed);
}

/* A second request while the first is PENDING must not re-queue. */
static void test_resolve_dedups_pending(void) {
    cold();
    dns_resolve("203.0.113.12", nb_, sizeof(nb_));
    dns_resolve("203.0.113.12", nb_, sizeof(nb_));
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(2, (int)st.resolve_requests);
    ASSERT_EQ(1, (int)st.resolve_enqueued);
}

/* A known name is served from cache without touching the worker. */
static void test_resolve_hit_does_not_enqueue(void) {
    cold();
    dns_set_resolved("198.51.100.8", "known.example");
    ASSERT_STR(dns_resolve("198.51.100.8", nb_, sizeof(nb_)), "known.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* The gate: with the resolver disabled, no request may reach the
 * worker, and the cache must be left exactly as it was found. */
static void test_disabled_resolver_enqueues_nothing(void) {
    cold();
    dns_resolver_set_enabled(0);
    ASSERT_EQ(0, dns_resolver_enabled());
    ASSERT_STR(dns_resolve("203.0.113.13", nb_, sizeof(nb_)), "203.0.113.13");

    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
    ASSERT_EQ(1, (int)st.resolve_suppressed);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);

    /* No slot was claimed: the passive half still sees a cold cache. */
    ASSERT_STR(dns_lookup_cached("203.0.113.13", nb_, sizeof(nb_)), "203.0.113.13");
    dns_resolver_set_enabled(1);
}

/* Disabling the resolver must not blind the operator to names sloth
 * already observed passively. */
static void test_disabled_resolver_still_serves_cache(void) {
    cold();
    dns_set_resolved("198.51.100.9", "snooped.example");
    dns_resolver_set_enabled(0);
    ASSERT_STR(dns_resolve("198.51.100.9", nb_, sizeof(nb_)), "snooped.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
    dns_resolver_set_enabled(1);
}

/* Slice 2 flips the shipped default: strict observation is what an
 * operator gets without asking. This assertion is the inverted twin of
 * slice 1's test_resolver_enabled_by_default — that one existed to make
 * exactly this flip visible as a deliberate edit rather than drift, and
 * this is that edit. Nothing here is weakened: the shape is identical
 * and only the pinned value moved. */
static void test_resolver_disabled_by_default(void) {
    ASSERT_EQ(0, DNS_RESOLVER_DEFAULT_ENABLED);
    dns_resolver_reset_policy();
    ASSERT_EQ(0, dns_resolver_enabled());
}

/* The default stated as behaviour rather than as a flag read: a cold
 * start that sees an address must produce no resolver work at all. */
static void test_default_policy_enqueues_nothing(void) {
    cold_default();
    ASSERT_STR(dns_resolve("203.0.113.19", nb_, sizeof(nb_)), "203.0.113.19");

    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
    ASSERT_EQ(1, (int)st.resolve_suppressed);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);
}

/* ── Worker-thread gate (#84 slice 2) ────────────────────── */

/* "The DNS worker is never started" is the property #84 asks for, and
 * it is a property of the *process*, not a branch taken per lookup: the
 * worker is the only code in sloth that can call getnameinfo(3), so a
 * strict run that never creates it cannot resolve even by accident. */
static void test_init_starts_no_worker_under_strict(void) {
    dns_cleanup();
    cold_default();
    dns_init();
    ASSERT_EQ(0, dns_resolver_worker_running());
    dns_cleanup();               /* must be safe with no thread to join */
    ASSERT_EQ(0, dns_resolver_worker_running());
}

/* The opt-in half: --allow-active must actually produce a worker, or
 * the flag would be a silent no-op. Nothing is enqueued here, so the
 * thread parks on the condvar and never touches the network. */
static void test_init_starts_worker_when_active(void) {
    dns_cleanup();
    cold();
    dns_init();
    ASSERT_EQ(1, dns_resolver_worker_running());
    dns_cleanup();
    ASSERT_EQ(0, dns_resolver_worker_running());
}

/* Two suites call dns_init() once per test. Without this guard each
 * call overwrote g_thread with a fresh pthread, so every earlier worker
 * became unjoinable. */
static void test_repeated_init_starts_one_worker(void) {
    dns_cleanup();
    cold();
    dns_init();
    dns_init();
    ASSERT_EQ(1, dns_resolver_worker_running());
    dns_cleanup();
    ASSERT_EQ(0, dns_resolver_worker_running());
}

/* ── --strict lock (#84 slice 2) ─────────────────────────── */

/* --strict changes nothing by itself; its value is that it refuses a
 * later enable, so the guarantee holds for the whole run rather than
 * until the next call. Enforced in dns.c so it is a cross-module
 * invariant and not an argv-parsing convention. */
static void test_strict_lock_refuses_later_enable(void) {
    cold_default();
    dns_resolver_lock_strict();
    ASSERT_EQ(1, dns_resolver_strict_locked());

    dns_resolver_set_enabled(1);
    ASSERT_EQ(0, dns_resolver_enabled());

    ASSERT_STR(dns_resolve("203.0.113.20", nb_, sizeof(nb_)), "203.0.113.20");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
    dns_resolver_reset_policy();
}

/* Locking an already-active resolver must turn it off, not merely
 * freeze it: --strict names a guarantee, not a preference. */
static void test_strict_lock_disables_an_active_resolver(void) {
    cold();
    ASSERT_EQ(1, dns_resolver_enabled());
    dns_resolver_lock_strict();
    ASSERT_EQ(0, dns_resolver_enabled());
    dns_resolver_reset_policy();
}

/* A locked run must not start a worker either, whatever order the
 * calls arrive in. */
static void test_strict_lock_keeps_the_worker_unstarted(void) {
    dns_cleanup();
    cold();
    dns_resolver_lock_strict();
    dns_init();
    ASSERT_EQ(0, dns_resolver_worker_running());
    dns_cleanup();
    dns_resolver_reset_policy();
}

static void test_reset_policy_clears_the_lock(void) {
    cold_default();
    dns_resolver_lock_strict();
    dns_resolver_reset_policy();
    ASSERT_EQ(0, dns_resolver_strict_locked());
    dns_resolver_set_enabled(1);
    ASSERT_EQ(1, dns_resolver_enabled());
    dns_resolver_reset_policy();
}

/* The compatibility spelling must keep resolving, or slice 1 has
 * silently changed behaviour for every caller that still uses it. */
static void test_dns_lookup_routes_through_resolver(void) {
    cold();
    ASSERT_STR(dns_lookup("203.0.113.14", nb_, sizeof(nb_)), "203.0.113.14");
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(1, (int)st.resolve_enqueued);
}

static void test_fmt_addr_routes_through_resolver(void) {
    cold();
    char buf[64];
    dns_fmt_addr("203.0.113.15", 443, buf, sizeof(buf));
    ASSERT_STR(buf, "203.0.113.15:https");
    ASSERT_EQ(1, (int)snap().resolve_enqueued);
}

/* An enqueue is an *intent* to resolve; getnameinfo_calls counts the
 * syscall. With no worker thread running the two must diverge — which
 * is what makes the counter usable as proof of real egress. */
static void test_getnameinfo_counter_tracks_the_worker(void) {
    cold();
    dns_resolve("203.0.113.16", nb_, sizeof(nb_));
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);
}

static void test_stats_reset_zeroes_counters(void) {
    cold();
    dns_lookup_cached("203.0.113.17", nb_, sizeof(nb_));
    dns_resolve("203.0.113.17", nb_, sizeof(nb_));
    ASSERT(snap().resolve_requests > 0);

    dns_resolver_stats_reset();
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(0, (int)st.cached_lookups);
    ASSERT_EQ(0, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.resolve_suppressed);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);
}

/* dns_reset() clears cache and queue; counters are a separate seam and
 * must survive it, so a test can measure across a cache reset. */
static void test_dns_reset_preserves_counters(void) {
    cold();
    dns_resolve("203.0.113.18", nb_, sizeof(nb_));
    dns_reset();
    ASSERT_EQ(1, (int)snap().resolve_requests);
}

static void test_stats_null_out_is_safe(void) {
    cold();
    dns_resolver_stats(NULL);   /* must not crash */
    ASSERT_EQ(0, (int)snap().resolve_requests);
}

/* ── Caller-owned result (#95) ───────────────────────────── */

/* Until #95 both halves returned one static buffer, so a second call
 * silently rewrote the first call's answer. Holding two results at once
 * is the single-threaded form of that defect, and fails deterministically
 * against a shared buffer: x would read "second.example". */
static void test_two_results_held_at_once_stay_distinct(void) {
    cold();
    dns_set_resolved("198.51.100.20", "first.example");
    dns_set_resolved("198.51.100.21", "second.example");
    char b1[DNS_NAME_MAX], b2[DNS_NAME_MAX];
    const char *x = dns_lookup_cached("198.51.100.20", b1, sizeof(b1));
    const char *y = dns_resolve("198.51.100.21", b2, sizeof(b2));
    ASSERT(x == b1);
    ASSERT(y == b2);
    ASSERT_STR(x, "first.example");
    ASSERT_STR(y, "second.example");
}

/* A miss hands back a copy of the IP in the caller's buffer, not the
 * argument pointer: the caller can rely on one ownership rule. */
static void test_miss_copies_ip_into_caller_buffer(void) {
    cold_default();
    char b1[DNS_NAME_MAX], b2[DNS_NAME_MAX];
    const char *ip = "203.0.113.30";
    ASSERT(dns_lookup_cached(ip, b1, sizeof(b1)) == b1);
    ASSERT(dns_resolve(ip, b2, sizeof(b2)) == b2);
    ASSERT_STR(b1, ip);
    ASSERT_STR(b2, ip);
}

/* A short buffer truncates and still terminates — the caller's size is
 * the bound, not the cache's. */
static void test_short_buffer_truncates_and_terminates(void) {
    cold();
    dns_set_resolved("198.51.100.22", "truncated.example");
    char b[8];
    memset(b, 'X', sizeof(b));
    ASSERT_STR(dns_lookup_cached("198.51.100.22", b, sizeof(b)), "truncat");
    memset(b, 'X', sizeof(b));
    ASSERT_STR(dns_resolve("198.51.100.22", b, sizeof(b)), "truncat");
    memset(b, 'X', sizeof(b));
    ASSERT_STR(dns_resolve("203.0.113.31", b, sizeof(b)), "203.0.1");
}

/* No buffer means nothing to write into; the ip comes back and the
 * caller's memory is untouched. */
static void test_no_buffer_returns_ip_and_writes_nothing(void) {
    cold();
    dns_set_resolved("198.51.100.23", "unwritten.example");
    const char *ip = "198.51.100.23";
    char b[4] = { 'Q', 'Q', 'Q', 'Q' };
    ASSERT(dns_lookup_cached(ip, NULL, 16) == ip);
    ASSERT(dns_lookup_cached(ip, b, 0) == ip);
    ASSERT(dns_resolve(ip, NULL, 16) == ip);
    ASSERT(dns_resolve(ip, b, 0) == ip);
    ASSERT_EQ('Q', b[0]);
}

/* The race #95 names: capture_quic_hostname() runs dns_lookup_cached()
 * on the capture thread while the main thread runs dns_resolve() for
 * top_hosts and the packet pane. With a shared static result, one
 * thread read a name the other was overwriting and got a torn mix.
 * Each worker checks every result against the one name its address
 * owns; the names differ in every byte, so any interleaving shows. The
 * workers never assert — runner counters are not thread-safe — they
 * count, and the main thread asserts after join. */

#define DNS_RACE_ITERS 200000

typedef struct {
    int          use_resolve;
    const char  *ip;
    const char  *want;
    int          ops;
    int          torn;
} dns_race_arg_t;

static void *dns_race_worker(void *p) {
    dns_race_arg_t *a = p;
    char buf[DNS_NAME_MAX];
    for (int i = 0; i < DNS_RACE_ITERS; i++) {
        const char *r = a->use_resolve
            ? dns_resolve(a->ip, buf, sizeof(buf))
            : dns_lookup_cached(a->ip, buf, sizeof(buf));
        if (strcmp(r, a->want) != 0) a->torn++;
        a->ops++;
    }
    return NULL;
}

static void test_concurrent_lookup_and_resolve_never_tear(void) {
    cold();
    /* Long names widen the copy window; distinct fill bytes make any
     * mix of the two visible at every offset. */
    static char name_a[DNS_NAME_MAX], name_b[DNS_NAME_MAX];
    memset(name_a, 'a', DNS_NAME_MAX - 1); name_a[DNS_NAME_MAX - 1] = '\0';
    memset(name_b, 'b', 100);              name_b[100] = '\0';
    dns_set_resolved("198.51.100.24", name_a);
    dns_set_resolved("198.51.100.25", name_b);
    dns_resolver_stats_reset();

    dns_race_arg_t args[2] = {
        { 0, "198.51.100.24", name_a, 0, 0 },   /* capture thread  */
        { 1, "198.51.100.25", name_b, 0, 0 },   /* main thread     */
    };
    pthread_t th[2];
    for (int i = 0; i < 2; i++)
        ASSERT_EQ(0, pthread_create(&th[i], NULL, dns_race_worker, &args[i]));
    for (int i = 0; i < 2; i++)
        ASSERT_EQ(0, pthread_join(th[i], NULL));

    ASSERT_EQ(DNS_RACE_ITERS, args[0].ops);
    ASSERT_EQ(DNS_RACE_ITERS, args[1].ops);
    ASSERT_EQ(0, args[0].torn);
    ASSERT_EQ(0, args[1].torn);

    /* Both were cache hits throughout: no resolver work, and the
     * counters — also guarded by g_mu — lost no increment. */
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(DNS_RACE_ITERS, (int)st.cached_lookups);
    ASSERT_EQ(DNS_RACE_ITERS, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
}

/* ── Stop flag (#95) ─────────────────────────────────────── */

/* dns_cleanup() read the run flag outside g_mu and cleared it in a
 * second step, so two callers could both pass the check and both
 * pthread_join() the same worker — undefined behaviour — and each check
 * was a data race against the other's locked write. The worker is
 * started with nothing queued, so it parks on the condvar and never
 * reaches getnameinfo(3). */
#define DNS_STOP_ROUNDS 200

static void *dns_cleanup_thread(void *p) {
    (void)p;
    dns_cleanup();
    return NULL;
}

static void test_concurrent_cleanup_joins_worker_once(void) {
    dns_cleanup();
    int started = 0, stopped = 0, created = 0;
    for (int r = 0; r < DNS_STOP_ROUNDS; r++) {
        cold();
        dns_init();
        started += dns_resolver_worker_running();
        pthread_t th[2];
        int ok = 0;
        for (int i = 0; i < 2; i++)
            if (pthread_create(&th[i], NULL, dns_cleanup_thread, NULL) == 0) ok++;
        for (int i = 0; i < ok; i++) pthread_join(th[i], NULL);
        if (ok == 2) created++;
        dns_cleanup();   /* reaps the worker if a create failed */
        stopped += !dns_resolver_worker_running();
    }
    ASSERT_EQ(DNS_STOP_ROUNDS, started);
    ASSERT_EQ(DNS_STOP_ROUNDS, created);
    ASSERT_EQ(DNS_STOP_ROUNDS, stopped);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_dns_tests(void) {
    TEST_SUITE("DNS cache");
    RUN_TEST(test_cache_miss_returns_ip);
    RUN_TEST(test_dedup_pending);
    RUN_TEST(test_inject_resolved);
    RUN_TEST(test_inject_then_fmt_addr);
    RUN_TEST(test_fmt_addr_no_entry);
    RUN_TEST(test_reset_clears_cache);
    RUN_TEST(test_ipv6_miss_returns_ip);
    RUN_TEST(test_inject_ipv6);
    RUN_TEST(test_multiple_distinct_ips);

    TEST_SUITE("DNS passive lookup vs. resolver (#84)");
    RUN_TEST(test_cached_lookup_does_zero_resolver_work);
    RUN_TEST(test_cached_lookup_leaves_no_pending_slot);
    RUN_TEST(test_cached_lookup_returns_observed_name);
    RUN_TEST(test_cached_lookup_ipv6_miss_and_hit);
    RUN_TEST(test_resolve_enqueues_on_cold_cache);
    RUN_TEST(test_resolve_dedups_pending);
    RUN_TEST(test_resolve_hit_does_not_enqueue);
    RUN_TEST(test_disabled_resolver_enqueues_nothing);
    RUN_TEST(test_disabled_resolver_still_serves_cache);
    RUN_TEST(test_resolver_disabled_by_default);
    RUN_TEST(test_default_policy_enqueues_nothing);
    RUN_TEST(test_dns_lookup_routes_through_resolver);
    RUN_TEST(test_fmt_addr_routes_through_resolver);
    RUN_TEST(test_getnameinfo_counter_tracks_the_worker);
    RUN_TEST(test_stats_reset_zeroes_counters);
    RUN_TEST(test_dns_reset_preserves_counters);
    RUN_TEST(test_stats_null_out_is_safe);

    TEST_SUITE("DNS resolver worker gate (#84 slice 2)");
    RUN_TEST(test_init_starts_no_worker_under_strict);
    RUN_TEST(test_init_starts_worker_when_active);
    RUN_TEST(test_repeated_init_starts_one_worker);

    TEST_SUITE("DNS --strict lock (#84 slice 2)");
    RUN_TEST(test_strict_lock_refuses_later_enable);
    RUN_TEST(test_strict_lock_disables_an_active_resolver);
    RUN_TEST(test_strict_lock_keeps_the_worker_unstarted);
    RUN_TEST(test_reset_policy_clears_the_lock);

    TEST_SUITE("DNS caller-owned result (#95)");
    RUN_TEST(test_two_results_held_at_once_stay_distinct);
    RUN_TEST(test_miss_copies_ip_into_caller_buffer);
    RUN_TEST(test_short_buffer_truncates_and_terminates);
    RUN_TEST(test_no_buffer_returns_ip_and_writes_nothing);
    RUN_TEST(test_concurrent_lookup_and_resolve_never_tear);

    TEST_SUITE("DNS worker stop flag (#95)");
    RUN_TEST(test_concurrent_cleanup_joins_worker_once);

    /* Leave the shipped default in place for every suite that follows.
     * test_dhcp_snoop.c and test_nbns_snoop.c call dns_init() per test;
     * handing them an enabled resolver would start a real worker and
     * put `make test` one cache miss away from a genuine PTR query. */
    dns_resolver_reset_policy();
}
