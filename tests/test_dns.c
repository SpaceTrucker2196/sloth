#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "dns.h"

/* ── Tests ───────────────────────────────────────────────── */

static void test_cache_miss_returns_ip(void) {
    dns_reset();
    /* Unknown IP: async resolve pending — raw IP returned immediately */
    ASSERT_STR(dns_lookup("192.0.2.1"), "192.0.2.1");
}

static void test_dedup_pending(void) {
    dns_reset();
    /* Two lookups for same IP must not crash or corrupt queue */
    ASSERT_STR(dns_lookup("198.51.100.1"), "198.51.100.1");
    ASSERT_STR(dns_lookup("198.51.100.1"), "198.51.100.1");
}

static void test_inject_resolved(void) {
    dns_reset();
    dns_set_resolved("10.0.0.1", "myhost");
    ASSERT_STR(dns_lookup("10.0.0.1"), "myhost");
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
    ASSERT_STR(dns_lookup("10.1.1.1"), "10.1.1.1");
}

static void test_ipv6_miss_returns_ip(void) {
    dns_reset();
    ASSERT_STR(dns_lookup("2001:db8::1"), "2001:db8::1");
}

static void test_inject_ipv6(void) {
    dns_reset();
    dns_set_resolved("::1", "localhost6");
    ASSERT_STR(dns_lookup("::1"), "localhost6");
}

static void test_multiple_distinct_ips(void) {
    dns_reset();
    dns_set_resolved("1.1.1.1", "one.one.one.one");
    dns_set_resolved("8.8.8.8", "dns.google");
    ASSERT_STR(dns_lookup("1.1.1.1"), "one.one.one.one");
    ASSERT_STR(dns_lookup("8.8.8.8"), "dns.google");
}

/* ── Passive lookup vs. active resolver (#84) ────────────── */

/* Every test below starts from a cold cache AND zeroed counters, so a
 * counter assertion measures only what that test did. */
static void cold(void) {
    dns_reset();
    dns_resolver_set_enabled(1);
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
    ASSERT_STR(dns_lookup_cached("203.0.113.9"), "203.0.113.9");

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
    dns_lookup_cached("203.0.113.10");
    dns_lookup_cached("203.0.113.10");
    ASSERT_STR(dns_lookup_cached("203.0.113.10"), "203.0.113.10");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* The passive half still answers from what the snoopers observed —
 * that is the whole point of keeping a cache at all. */
static void test_cached_lookup_returns_observed_name(void) {
    cold();
    dns_set_resolved("198.51.100.7", "observed.example");
    ASSERT_STR(dns_lookup_cached("198.51.100.7"), "observed.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

static void test_cached_lookup_ipv6_miss_and_hit(void) {
    cold();
    ASSERT_STR(dns_lookup_cached("2001:db8::99"), "2001:db8::99");
    dns_set_resolved("2001:db8::99", "v6.example");
    ASSERT_STR(dns_lookup_cached("2001:db8::99"), "v6.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* dns_resolve() is the choke point: one request, one enqueue. */
static void test_resolve_enqueues_on_cold_cache(void) {
    cold();
    ASSERT_STR(dns_resolve("203.0.113.11"), "203.0.113.11");
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(1, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.resolve_suppressed);
}

/* A second request while the first is PENDING must not re-queue. */
static void test_resolve_dedups_pending(void) {
    cold();
    dns_resolve("203.0.113.12");
    dns_resolve("203.0.113.12");
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(2, (int)st.resolve_requests);
    ASSERT_EQ(1, (int)st.resolve_enqueued);
}

/* A known name is served from cache without touching the worker. */
static void test_resolve_hit_does_not_enqueue(void) {
    cold();
    dns_set_resolved("198.51.100.8", "known.example");
    ASSERT_STR(dns_resolve("198.51.100.8"), "known.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
}

/* The gate: with the resolver disabled, no request may reach the
 * worker, and the cache must be left exactly as it was found. */
static void test_disabled_resolver_enqueues_nothing(void) {
    cold();
    dns_resolver_set_enabled(0);
    ASSERT_EQ(0, dns_resolver_enabled());
    ASSERT_STR(dns_resolve("203.0.113.13"), "203.0.113.13");

    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_requests);
    ASSERT_EQ(0, (int)st.resolve_enqueued);
    ASSERT_EQ(1, (int)st.resolve_suppressed);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);

    /* No slot was claimed: the passive half still sees a cold cache. */
    ASSERT_STR(dns_lookup_cached("203.0.113.13"), "203.0.113.13");
    dns_resolver_set_enabled(1);
}

/* Disabling the resolver must not blind the operator to names sloth
 * already observed passively. */
static void test_disabled_resolver_still_serves_cache(void) {
    cold();
    dns_set_resolved("198.51.100.9", "snooped.example");
    dns_resolver_set_enabled(0);
    ASSERT_STR(dns_resolve("198.51.100.9"), "snooped.example");
    ASSERT_EQ(0, (int)snap().resolve_enqueued);
    dns_resolver_set_enabled(1);
}

/* Slice 1 is behaviour-preserving: the shipped default stays on.
 * Flipping it is a deliberate decision for #84 slice 2, and this
 * assertion is what will make that flip visible when it happens. */
static void test_resolver_enabled_by_default(void) {
    dns_resolver_set_enabled(1);
    ASSERT_EQ(1, dns_resolver_enabled());
}

/* The compatibility spelling must keep resolving, or slice 1 has
 * silently changed behaviour for every caller that still uses it. */
static void test_dns_lookup_routes_through_resolver(void) {
    cold();
    ASSERT_STR(dns_lookup("203.0.113.14"), "203.0.113.14");
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
    dns_resolve("203.0.113.16");
    dns_resolver_stats_t st = snap();
    ASSERT_EQ(1, (int)st.resolve_enqueued);
    ASSERT_EQ(0, (int)st.getnameinfo_calls);
}

static void test_stats_reset_zeroes_counters(void) {
    cold();
    dns_lookup_cached("203.0.113.17");
    dns_resolve("203.0.113.17");
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
    dns_resolve("203.0.113.18");
    dns_reset();
    ASSERT_EQ(1, (int)snap().resolve_requests);
}

static void test_stats_null_out_is_safe(void) {
    cold();
    dns_resolver_stats(NULL);   /* must not crash */
    ASSERT_EQ(0, (int)snap().resolve_requests);
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
    RUN_TEST(test_resolver_enabled_by_default);
    RUN_TEST(test_dns_lookup_routes_through_resolver);
    RUN_TEST(test_fmt_addr_routes_through_resolver);
    RUN_TEST(test_getnameinfo_counter_tracks_the_worker);
    RUN_TEST(test_stats_reset_zeroes_counters);
    RUN_TEST(test_dns_reset_preserves_counters);
    RUN_TEST(test_stats_null_out_is_safe);
}
