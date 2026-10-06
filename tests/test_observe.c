#include "runner.h"
#include "observe.h"
#include "dns.h"

/* Observation policy (#84 slice 3) — the one owner of "may sloth
 * originate traffic or change kernel state?". */

static void test_strict_observation_is_the_default(void) {
    observe_reset_policy();
    /* The shipped default, pinned so a later flip has to be a deliberate
     * edit rather than drift — same role test_resolver_disabled_by_default
     * plays for the resolver half. */
    ASSERT_EQ(0, observe_active_allowed());
    ASSERT_EQ(0, observe_strict_locked());
}

static void test_allow_active_opts_in(void) {
    observe_reset_policy();
    observe_set_active_allowed(1);
    ASSERT_EQ(1, observe_active_allowed());
    ASSERT_EQ(0, observe_strict_locked());

    observe_set_active_allowed(0);
    ASSERT_EQ(0, observe_active_allowed());
    observe_reset_policy();
}

static void test_lock_disables_and_refuses_every_later_enable(void) {
    observe_reset_policy();
    observe_set_active_allowed(1);
    ASSERT_EQ(1, observe_active_allowed());

    observe_lock_strict();
    ASSERT_EQ(1, observe_strict_locked());
    ASSERT_EQ(0, observe_active_allowed());   /* turned off, not just pinned */

    /* The guarantee holds for the whole run, not until the next call. */
    observe_set_active_allowed(1);
    ASSERT_EQ(0, observe_active_allowed());
    observe_set_active_allowed(1);
    ASSERT_EQ(0, observe_active_allowed());
    observe_reset_policy();
}

static void test_tightening_is_always_allowed(void) {
    observe_reset_policy();
    observe_lock_strict();
    /* Disabling under a lock is a no-op, never an error or a re-enable. */
    observe_set_active_allowed(0);
    ASSERT_EQ(0, observe_active_allowed());
    ASSERT_EQ(1, observe_strict_locked());
    observe_reset_policy();
}

/* ── Discovery tracks the lock, not the opt-in ───────────── */

static void test_discovery_allowed_by_default(void) {
    observe_reset_policy();
    /* The default profile leaves MISSION §2.1's opt-out carve-out alone:
     * discovery already needs a routable data-socket bind, so it cannot
     * fire on a default run, and suppressing it here would break
     * sloth-ios discovery for a deployment that asked for it. */
    ASSERT_EQ(1, observe_discovery_allowed());

    observe_set_active_allowed(1);
    ASSERT_EQ(1, observe_discovery_allowed());
    observe_reset_policy();
}

static void test_strict_suppresses_discovery(void) {
    observe_reset_policy();
    observe_lock_strict();
    ASSERT_EQ(0, observe_discovery_allowed());
    observe_reset_policy();
    ASSERT_EQ(1, observe_discovery_allowed());
}

/* ── The resolver half reads the same lock ───────────────── */

static void test_dns_strict_lock_is_the_shared_lock(void) {
    observe_reset_policy();
    dns_resolver_reset_policy();
    ASSERT_EQ(0, dns_resolver_strict_locked());

    /* Locking through the observe API locks the resolver too — one
     * policy object, not two that have to be kept in step. */
    observe_lock_strict();
    ASSERT_EQ(1, dns_resolver_strict_locked());
    dns_resolver_set_enabled(1);
    ASSERT_EQ(0, dns_resolver_enabled());

    /* ...and locking through the resolver API locks the scan trigger. */
    dns_resolver_reset_policy();
    ASSERT_EQ(0, observe_strict_locked());
    dns_resolver_lock_strict();
    ASSERT_EQ(1, observe_strict_locked());
    ASSERT_EQ(0, observe_discovery_allowed());

    dns_resolver_reset_policy();
    observe_reset_policy();
}

/* ── --strict vs a routable data socket — #84 ────────────────
 *
 * The owner ruled on 2026-10-06 that --strict refuses a ROUTABLE data
 * socket and only a routable one, settling a question README.md and
 * docs/wiki/data-socket-exposure.md had published as open.
 *
 * Pinned as a pure predicate because the composition lives in main(),
 * which sloth_test does not link — the reason an earlier attempt at
 * strict-contract tests resorted to matching source strings and ended
 * up asserting a `return 1;` sixty-eight lines from the one it meant. A
 * one-line policy function is cheaper than that and actually holds. */
static void test_strict_refuses_only_a_routable_socket(void) {
    /* The ruling, in four lines. */
    ASSERT_EQ(observe_strict_refuses_socket(1, 1), 1);   /* strict + routable */
    ASSERT_EQ(observe_strict_refuses_socket(1, 0), 0);   /* strict + loopback */
    ASSERT_EQ(observe_strict_refuses_socket(0, 1), 0);   /* routable, no strict */
    ASSERT_EQ(observe_strict_refuses_socket(0, 0), 0);
}

static void test_strict_socket_refusal_ignores_an_unparseable_spec(void) {
    /* -1 is "cannot parse". Such a spec never binds and
       data_socket_init_ex() rejects it naming the actual typo, so this
       predicate stays quiet rather than blaming --strict for it. */
    ASSERT_EQ(observe_strict_refuses_socket(1, -1), 0);
    ASSERT_EQ(observe_strict_refuses_socket(0, -1), 0);
}

static void test_strict_socket_refusal_is_not_overridable(void) {
    /* --data-socket-allow-remote is how an operator says "expose this";
       --strict is how they say "not on this run". The predicate takes no
       opt-in parameter at all, which is the point: a lock that another
       flag can override is not a lock. The shape of this assertion IS
       the guarantee — if an allow-remote argument is ever threaded in
       here, this test stops compiling and names the decision. */
    ASSERT_EQ(observe_strict_refuses_socket(1, 1), 1);
}

void run_observe_tests(void) {
    TEST_SUITE("observation policy (#84)");
    RUN_TEST(test_strict_observation_is_the_default);
    RUN_TEST(test_allow_active_opts_in);
    RUN_TEST(test_lock_disables_and_refuses_every_later_enable);
    RUN_TEST(test_tightening_is_always_allowed);
    RUN_TEST(test_discovery_allowed_by_default);
    RUN_TEST(test_strict_suppresses_discovery);
    RUN_TEST(test_dns_strict_lock_is_the_shared_lock);
    RUN_TEST(test_strict_refuses_only_a_routable_socket);
    RUN_TEST(test_strict_socket_refusal_ignores_an_unparseable_spec);
    RUN_TEST(test_strict_socket_refusal_is_not_overridable);
}
