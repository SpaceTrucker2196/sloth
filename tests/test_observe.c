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

void run_observe_tests(void) {
    TEST_SUITE("observation policy (#84)");
    RUN_TEST(test_strict_observation_is_the_default);
    RUN_TEST(test_allow_active_opts_in);
    RUN_TEST(test_lock_disables_and_refuses_every_later_enable);
    RUN_TEST(test_tightening_is_always_allowed);
    RUN_TEST(test_discovery_allowed_by_default);
    RUN_TEST(test_strict_suppresses_discovery);
    RUN_TEST(test_dns_strict_lock_is_the_shared_lock);
}
