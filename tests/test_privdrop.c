#include "runner.h"
#include "privdrop.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#endif

/* Privilege drop (#140; owner ruling 2026-10-15, default ON for root).
 *
 * CI is not root, so the plan is the tested unit: privdrop_resolve() is
 * pure, and every rule the ruling states is pinned on it here. apply is
 * exercised on the one plan a non-root process can carry out — shed
 * what it holds, set no_new_privs — inside a forked child, so the test
 * process itself keeps whatever it had. The root path of apply
 * (setresuid, PR_CAPBSET_DROP, ambient clear under real caps) cannot
 * run in CI; it is the hand checklist on the issue, not a claim here. */

/* Sentinel ids: never a real account's, never 0. */
#define PD_UID 4242u
#define PD_GID 4343u

/* A root run whose default `sloth` account exists, holding the caps a
 * root process holds. Tests adjust from here. */
static privdrop_req_t root_req(void) {
    privdrop_req_t r;
    memset(&r, 0, sizeof(r));
    r.euid_is_root       = 1;
    r.have_cap_setuid    = 1;
    r.have_cap_setpcap   = 1;
    r.have_cap_net_admin = 1;
    r.have_cap_net_raw   = 1;
    r.user_resolved      = 1;
    r.uid                = (uid_t)PD_UID;
    r.gid                = (gid_t)PD_GID;
    return r;
}

static privdrop_req_t unpriv_req(void) {
    privdrop_req_t r;
    memset(&r, 0, sizeof(r));
    return r;
}

static void test_root_with_hop_drops_and_keeps_only_net_admin(void) {
    privdrop_req_t r = root_req();
    r.hop = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_DROP);
    ASSERT_EQ(p.keep_net_admin, 1);
    ASSERT_EQ(p.keep_net_raw, 0);
    ASSERT_EQ(p.set_no_new_privs, 1);
    ASSERT_EQ(p.change_uid, 1);
    ASSERT_EQ(p.shed_caps, 1);
    ASSERT_EQ(p.drop_bounding, 1);
    ASSERT_EQ(p.uid, (uid_t)PD_UID);
    ASSERT_EQ(p.gid, (gid_t)PD_GID);
    ASSERT_EQ(p.exit_code, 0);
}

/* The scan trigger opens a fresh nl80211 socket per call, exactly like
 * a --hop retune, so --allow-active alone also keeps CAP_NET_ADMIN. */
static void test_allow_active_alone_keeps_net_admin(void) {
    privdrop_req_t r = root_req();
    r.allow_active = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_DROP);
    ASSERT_EQ(p.keep_net_admin, 1);
    ASSERT_EQ(p.keep_net_raw, 0);
}

static void test_no_hop_no_active_keeps_nothing(void) {
    privdrop_req_t r = root_req();
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_DROP);
    ASSERT_EQ(p.keep_net_admin, 0);
    ASSERT_EQ(p.keep_net_raw, 0);
    ASSERT_EQ(p.set_no_new_privs, 1);
}

/* capset cannot grant what the permitted set lacks, so the plan never
 * asks for it: the readback would then fail closed on every such run. */
static void test_hop_without_net_admin_held_keeps_nothing(void) {
    privdrop_req_t r = unpriv_req();
    r.hop = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_NONE_UNPRIVILEGED);
    ASSERT_EQ(p.keep_net_admin, 0);
}

/* "keep_net_raw = 0 always" — every action that sheds, across every
 * combination of the inputs that could plausibly tempt it to keep. */
static void test_net_raw_is_never_kept_by_a_shedding_plan(void) {
    int shedding = 0;
    for (int root = 0; root < 2; root++)
    for (int hop = 0; hop < 2; hop++)
    for (int act = 0; act < 2; act++)
    for (int res = 0; res < 2; res++)
    for (int given = 0; given < 2; given++) {
        privdrop_req_t r = root ? root_req() : unpriv_req();
        r.have_cap_net_raw   = 1;
        r.have_cap_net_admin = 1;
        r.hop = hop; r.allow_active = act;
        r.user_resolved = res; r.user_given = given;
        if (!root) r.have_cap_setuid = given;
        privdrop_plan_t p;
        privdrop_resolve(&r, &p);
        if (!p.shed_caps) continue;
        shedding++;
        ASSERT_EQ(p.keep_net_raw, 0);
        ASSERT_EQ(p.set_no_new_privs, 1);
    }
    /* 32 combinations, of which the 8 with --user given and unresolved
     * refuse; the other 24 must all have been checked above. */
    ASSERT_EQ(shedding, 24);
}

static void test_unknown_user_is_refused_with_exit_2(void) {
    privdrop_req_t r = root_req();
    r.user_given    = 1;
    r.user_resolved = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_REFUSE_NO_SUCH_USER);
    ASSERT_EQ(p.exit_code, 2);
    ASSERT(p.reason != NULL);
    ASSERT_EQ(p.shed_caps, 0);
    ASSERT_EQ(p.change_uid, 0);
}

/* Owner ruling: no account → keep the uid, still shed, never silently
 * stay fully root. */
static void test_root_without_account_keeps_uid_but_sheds(void) {
    privdrop_req_t r = root_req();
    r.user_resolved = 0;
    r.uid = 0; r.gid = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_ROOT_KEEP_UID);
    ASSERT_EQ(p.change_uid, 0);
    ASSERT_EQ(p.shed_caps, 1);
    ASSERT_EQ(p.drop_bounding, 1);
    ASSERT_EQ(p.set_no_new_privs, 1);
    ASSERT_EQ(p.keep_net_admin, 0);
    ASSERT_EQ(p.exit_code, 0);
}

/* --user root, or an account that is uid 0 by another name, is not a
 * drop; the plan still sheds rather than announcing a fake one. */
static void test_target_account_at_uid_0_is_not_a_drop(void) {
    privdrop_req_t r = root_req();
    r.user_given = 1;
    r.uid = 0; r.gid = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_ROOT_KEEP_UID);
    ASSERT_EQ(p.change_uid, 0);
    ASSERT_EQ(p.shed_caps, 1);
}

/* Root inside a capability-restricted container: no CAP_SETUID. The
 * implicit default degrades to shedding; an explicit --user refuses. */
static void test_root_without_setuid_cap(void) {
    privdrop_req_t r = root_req();
    r.have_cap_setuid = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_ROOT_KEEP_UID);
    ASSERT_EQ(p.change_uid, 0);

    r.user_given = 1;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_REFUSE_CANNOT);
    ASSERT_EQ(p.exit_code, 2);
    ASSERT(p.reason != NULL);
}

static void test_non_root_is_unprivileged_with_nnp(void) {
    privdrop_req_t r = unpriv_req();
    r.have_cap_net_raw   = 1;   /* the shipped unit's ambient caps */
    r.have_cap_net_admin = 1;
    r.hop = 1;
    /* The default account existing must not tempt a non-root run into
     * switching: it already chose its identity. */
    r.user_resolved = 1;
    r.uid = (uid_t)PD_UID;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_NONE_UNPRIVILEGED);
    ASSERT_EQ(p.set_no_new_privs, 1);
    ASSERT_EQ(p.change_uid, 0);
    ASSERT_EQ(p.shed_caps, 1);
    ASSERT_EQ(p.keep_net_admin, 1);
    ASSERT_EQ(p.keep_net_raw, 0);
    /* No CAP_SETPCAP under the unit: the bounding set is the unit's. */
    ASSERT_EQ(p.drop_bounding, 0);
    ASSERT_EQ(p.exit_code, 0);
}

static void test_non_root_user_request(void) {
    privdrop_req_t r = unpriv_req();
    r.user_given = 1;
    r.user_resolved = 1;
    r.uid = (uid_t)PD_UID; r.gid = (gid_t)PD_GID;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_REFUSE_CANNOT);
    ASSERT_EQ(p.exit_code, 2);

    r.have_cap_setuid = 1;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_DROP);
    ASSERT_EQ(p.change_uid, 1);
    ASSERT_EQ(p.uid, (uid_t)PD_UID);
}

static void test_no_privdrop_is_the_only_way_to_stay_root(void) {
    privdrop_req_t r = root_req();
    r.no_privdrop = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_DISABLED);
    ASSERT_EQ(p.shed_caps, 0);
    ASSERT_EQ(p.change_uid, 0);
    ASSERT_EQ(p.exit_code, 0);
    /* NNP stays on even here: it gets in no dev box's way. */
    ASSERT_EQ(p.set_no_new_privs, 1);

    /* Without the flag, no root input combination leaves caps unshed. */
    for (int res = 0; res < 2; res++)
    for (int su = 0; su < 2; su++) {
        privdrop_req_t q = root_req();
        q.user_resolved = res;
        q.have_cap_setuid = su;
        privdrop_resolve(&q, &p);
        ASSERT_EQ(p.shed_caps, 1);
    }
}

static void test_user_with_no_privdrop_contradicts(void) {
    privdrop_req_t r = root_req();
    r.no_privdrop = 1;
    r.user_given  = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    ASSERT_EQ(p.action, PRIVDROP_REFUSE_CANNOT);
    ASSERT_EQ(p.exit_code, 2);
    ASSERT(p.reason != NULL && strstr(p.reason, "--no-privdrop") != NULL);
}

/* ── The announcement ────────────────────────────────────── */

static void test_describe_names_uid_account_and_kept_cap(void) {
    privdrop_req_t r = root_req();
    r.hop = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    char buf[320];
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "dropped to uid 4242 (sloth)") != NULL);
    ASSERT(strstr(buf, "CAP_NET_ADMIN for --hop") != NULL);
    ASSERT(strstr(buf, "no_new_privs on") != NULL);

    r.hop = 0; r.allow_active = 1;
    privdrop_resolve(&r, &p);
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "CAP_NET_ADMIN for --allow-active") != NULL);

    r.allow_active = 0;
    privdrop_resolve(&r, &p);
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "caps kept: none") != NULL);
}

static void test_describe_is_never_silent_for_root(void) {
    char buf[320];
    privdrop_plan_t p;

    privdrop_req_t r = root_req();
    r.user_resolved = 0;
    privdrop_resolve(&r, &p);
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "staying uid 0") != NULL);
    ASSERT(strstr(buf, "--user NAME") != NULL);

    r = root_req();
    r.no_privdrop = 1;
    privdrop_resolve(&r, &p);
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "--no-privdrop") != NULL);
    ASSERT(strstr(buf, "NOT dropped") != NULL);
}

static void test_describe_quiet_for_an_ordinary_unprivileged_run(void) {
    char buf[320];
    privdrop_plan_t p;
    privdrop_req_t r = unpriv_req();
    privdrop_resolve(&r, &p);
    buf[0] = 'X';
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT_STR(buf, "");

    /* Held something (the shipped unit's ambient caps): say so. */
    r.have_cap_net_raw = 1;
    privdrop_resolve(&r, &p);
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT(strstr(buf, "capabilities dropped") != NULL);
}

/* ── apply ───────────────────────────────────────────────── */

static void test_apply_refuses_a_refusal_plan(void) {
    privdrop_req_t r = root_req();
    r.user_given = 1;
    r.user_resolved = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    char err[160];
    ASSERT_EQ(privdrop_apply(&p, err, sizeof(err)), -1);
    ASSERT(err[0] != '\0');
}

#ifdef __linux__
/* Carries out the NONE_UNPRIVILEGED plan for real, in a child so the
 * suite keeps its own state. The child reports by exit status:
 * 0 ok, 10 apply failed, 11 NNP not set afterwards, 12 caps remain.
 *
 * Seen to fail: with the PR_SET_NO_NEW_PRIVS call removed from apply,
 * this goes red (the readback refuses, status 10). That proof needs a
 * suite whose NNP starts at 0; a runner already under no_new_privs
 * would pass either way, so the starting value is printed, not
 * asserted (host state, not sloth's). */
static void test_apply_unprivileged_plan_sets_nnp_and_sheds(void) {
    int parent_nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    fflush(NULL);
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid < 0) return;
    if (pid == 0) {
        privdrop_req_t r;
        memset(&r, 0, sizeof(r));
        privdrop_probe(&r);
        /* Forced unprivileged: the plan under test is the non-root one,
         * whoever runs the suite. */
        r.euid_is_root = 0;
        privdrop_plan_t p;
        privdrop_resolve(&r, &p);
        if (p.action != PRIVDROP_NONE_UNPRIVILEGED) _exit(9);
        char err[160];
        if (privdrop_apply(&p, err, sizeof(err)) != 0) _exit(10);
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) _exit(11);
        struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
        struct __user_cap_data_struct d[2];
        memset(d, 0, sizeof(d));
        if (syscall(SYS_capget, &h, d) != 0) _exit(12);
        if (d[0].effective || d[0].permitted || d[0].inheritable ||
            d[1].effective || d[1].permitted || d[1].inheritable)
            _exit(12);
        _exit(0);
    }
    int st = 0;
    ASSERT_EQ(waitpid(pid, &st, 0), pid);
    ASSERT(WIFEXITED(st));
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
        fprintf(stderr, "    privdrop child exited %d\n", WEXITSTATUS(st));
    ASSERT_EQ(WEXITSTATUS(st), 0);
    if (parent_nnp != 0)
        fprintf(stderr, "    note: suite already runs under no_new_privs; "
                        "the NNP half of this test cannot discriminate\n");
    /* The isolation the fork exists for: the suite's own NNP is
     * untouched. */
    ASSERT_EQ(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), parent_nnp);
}
#endif

void run_privdrop_tests(void) {
    TEST_SUITE("privdrop (#140)");
    RUN_TEST(test_root_with_hop_drops_and_keeps_only_net_admin);
    RUN_TEST(test_allow_active_alone_keeps_net_admin);
    RUN_TEST(test_no_hop_no_active_keeps_nothing);
    RUN_TEST(test_hop_without_net_admin_held_keeps_nothing);
    RUN_TEST(test_net_raw_is_never_kept_by_a_shedding_plan);
    RUN_TEST(test_unknown_user_is_refused_with_exit_2);
    RUN_TEST(test_root_without_account_keeps_uid_but_sheds);
    RUN_TEST(test_target_account_at_uid_0_is_not_a_drop);
    RUN_TEST(test_root_without_setuid_cap);
    RUN_TEST(test_non_root_is_unprivileged_with_nnp);
    RUN_TEST(test_non_root_user_request);
    RUN_TEST(test_no_privdrop_is_the_only_way_to_stay_root);
    RUN_TEST(test_user_with_no_privdrop_contradicts);
    RUN_TEST(test_describe_names_uid_account_and_kept_cap);
    RUN_TEST(test_describe_is_never_silent_for_root);
    RUN_TEST(test_describe_quiet_for_an_ordinary_unprivileged_run);
    RUN_TEST(test_apply_refuses_a_refusal_plan);
#ifdef __linux__
    RUN_TEST(test_apply_unprivileged_plan_sets_nnp_and_sheds);
#endif
}
