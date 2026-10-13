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

/* ── The whole-command-line profile resolver — #84 ───────────
 *
 * Three of the five strict-contract clauses used to be decided by the
 * order three blocks sat in main(), which sloth_test does not link. The
 * 2026-10-05 attempt to test them by matching src/main.c source text was
 * held with three majors (a "exits non-zero" clause that matched an
 * unrelated `return 1;` sixty-eight lines downstream, a clause pinned to
 * one exact source line, and a clause that duplicated
 * tests/test_wifi_scan_trigger.c while being strictly weaker). These
 * tests replace all of that: the policy is a pure function now, so the
 * suite asserts the decision itself.
 *
 * None of them calls observe_reset_policy(), and that is the point —
 * observe_resolve_profile() touches no process-global state, so unlike
 * the tests above these cannot leak into each other. */
static observe_profile_t resolve(observe_profile_req_t req) {
    observe_profile_t p;
    observe_resolve_profile(&req, &p);
    return p;
}

static void test_profile_default_is_strict_but_unlocked(void) {
    /* The shipped default: nothing active, and no lock either, so a
       later in-process enable is still possible. Pinned so a flip has
       to be a deliberate edit rather than drift. */
    observe_profile_t p = resolve((observe_profile_req_t){ 0 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(0, p.strict_locked);
    ASSERT_EQ(0, p.active_allowed);
    ASSERT_EQ(0, p.resolver_enabled);
    ASSERT_EQ(0, p.hop_enabled);
}

static void test_profile_allow_active_alone_opts_in(void) {
    observe_profile_t p = resolve((observe_profile_req_t){ .allow_active = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(1, p.active_allowed);
    ASSERT_EQ(1, p.resolver_enabled);   /* both rows of README's table */
    ASSERT_EQ(0, p.strict_locked);
}

static void test_profile_strict_alone_locks_and_allows_nothing(void) {
    observe_profile_t p = resolve((observe_profile_req_t){ .strict = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(1, p.strict_locked);
    ASSERT_EQ(0, p.active_allowed);
    ASSERT_EQ(0, p.resolver_enabled);
}

static void test_profile_strict_plus_allow_active_is_refused(void) {
    /* README.md documents that `--strict --allow-active` exits non-zero
       "in either order". One assertion covers both orders because the
       request struct carries no ordering at all — it records which flags
       were given, never their sequence. THAT is what makes the README
       claim structural; before this resolver it was a property of where
       two blocks happened to sit in main(), and swapping them made
       `--strict --allow-active` exit 0 with active behaviour silently
       off. */
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .allow_active = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT, p.refusal);
    ASSERT_EQ(2, p.exit_code);
    /* Refused values, not enabled ones: a caller that ignored exit_code
       still could not turn anything on. */
    ASSERT_EQ(0, p.active_allowed);
    ASSERT_EQ(0, p.resolver_enabled);
}

static void test_profile_strict_permits_hop(void) {
    /* Asserted positively. --hop is MISSION §2.1's first carve-out and
       --strict does not refuse it; README's WiFi SIGINT section records
       whether it should as an OPEN owner decision. So a future flip is a
       deliberate edit to this assertion, not silent drift. */
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .hop = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(1, p.strict_locked);
    ASSERT_EQ(1, p.hop_enabled);
}

static void test_profile_allow_active_permits_hop(void) {
    observe_profile_t p = resolve((observe_profile_req_t){
        .allow_active = 1, .hop = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(1, p.hop_enabled);
    ASSERT_EQ(1, p.active_allowed);
}

static void test_profile_strict_refuses_a_routable_socket(void) {
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .have_data_socket = 1, .socket_is_remote = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_REFUSE_ROUTABLE_SOCKET_UNDER_STRICT, p.refusal);
    ASSERT_EQ(2, p.exit_code);
}

/* The pass-through itself, which nothing pinned. Review found that
 * hardcoding out->strict_locked to 1 at the socket clause went
 * undetected: every existing case set strict = 1, so a constant and the
 * real value were indistinguishable. A routable socket WITHOUT --strict
 * is the configuration #86 shipped as a documented opt-in, and refusing
 * it would break that. */
static void test_profile_without_strict_permits_a_routable_socket(void) {
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 0, .have_data_socket = 1, .socket_is_remote = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    /* And the lock really is off, so the refusal above was declined on
       the strict flag and not on something incidental. */
    ASSERT_EQ(0, p.strict_locked);
}

static void test_profile_strict_permits_a_local_or_unparseable_socket(void) {
    /* Loopback and unix: do not leave the host, and README has long
       published bare `--strict --data-socket` as usable. */
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .have_data_socket = 1, .socket_is_remote = 0 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);

    /* -1 is "cannot parse", and src/observe.h's reasoning applies
       unchanged here: such a spec never binds, data_socket_init_ex()
       rejects it naming the actual typo, and reporting a strict
       violation for a mistyped host would be precise about the wrong
       thing. */
    p = resolve((observe_profile_req_t){
        .strict = 1, .have_data_socket = 1, .socket_is_remote = -1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
}

static void test_profile_socket_check_is_gated_on_the_flag(void) {
    /* socket_is_remote is meaningless without --data-socket. Pinned so
       a stale 1 left in the request by a future refactor cannot refuse a
       run that asked for no socket at all. */
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .have_data_socket = 0, .socket_is_remote = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_OK, p.refusal);
    ASSERT_EQ(0, p.exit_code);
    ASSERT_EQ(1, p.strict_locked);
}

static void test_profile_allow_active_refusal_beats_the_socket_one(void) {
    /* Both exit 2, so only the message differs — but which message an
       operator gets is worth deciding rather than inheriting from block
       order. The flag pair contradicts the stated intent; the socket is
       a configuration consequence. Pinned deliberately. */
    observe_profile_t p = resolve((observe_profile_req_t){
        .strict = 1, .allow_active = 1,
        .have_data_socket = 1, .socket_is_remote = 1 });
    ASSERT_EQ(OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT, p.refusal);
    ASSERT_EQ(2, p.exit_code);
}

static void test_profile_null_arguments_are_safe(void) {
    observe_profile_t p;
    observe_profile_req_t req = { .strict = 1 };

    p.refusal = OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT;
    p.exit_code = 99;
    observe_resolve_profile(NULL, &p);
    /* A no-op, not a silently permissive default — a NULL request must
       not be able to clear a refusal. */
    ASSERT_EQ(OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT, p.refusal);
    ASSERT_EQ(99, p.exit_code);

    observe_resolve_profile(&req, NULL);   /* must not fault */
    observe_resolve_profile(NULL, NULL);
    ASSERT_EQ(1, req.strict);              /* req is const to the callee */
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
    RUN_TEST(test_profile_default_is_strict_but_unlocked);
    RUN_TEST(test_profile_allow_active_alone_opts_in);
    RUN_TEST(test_profile_strict_alone_locks_and_allows_nothing);
    RUN_TEST(test_profile_strict_plus_allow_active_is_refused);
    RUN_TEST(test_profile_strict_permits_hop);
    RUN_TEST(test_profile_allow_active_permits_hop);
    RUN_TEST(test_profile_strict_refuses_a_routable_socket);
    RUN_TEST(test_profile_without_strict_permits_a_routable_socket);
    RUN_TEST(test_profile_strict_permits_a_local_or_unparseable_socket);
    RUN_TEST(test_profile_socket_check_is_gated_on_the_flag);
    RUN_TEST(test_profile_allow_active_refusal_beats_the_socket_one);
    RUN_TEST(test_profile_null_arguments_are_safe);
}
