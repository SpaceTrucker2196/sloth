#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "views/procs.h"
#include "tui.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void push(sloth_state_t *s, int pid, const char *proc, int proto) {
    if (s->conn_count >= MAX_CONNS) return;
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    c->pid   = pid;
    c->proto = proto;
    c->state = 1;
    c->remote_port = 80;
    strncpy(c->proc, proc, sizeof(c->proc) - 1);
}

/* ── proc_stat_t field tests ─────────────────────────────── */

static void test_ppid_field_exists(void) {
    proc_stat_t p;
    memset(&p, 0, sizeof(p));
    p.ppid = 42;
    ASSERT_EQ(p.ppid, 42);
}

static void test_depth_field_exists(void) {
    proc_stat_t p;
    memset(&p, 0, sizeof(p));
    p.depth = 2;
    ASSERT_EQ(p.depth, 2);
}

static void test_aggregate_zeros_ppid_depth(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 10, "nginx", PROTO_TCP);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].ppid,  0);
    ASSERT_EQ(out[0].depth, 0);
}

/* ── Draw ─────────────────────────────────────────────────── *
 * ASSERT(1) smoke tests until #116; they read the screen now. The two
 * real-PID cases assert the tree's shape and never a PID, which is the
 * host's. */

static void test_tree_draw_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_procs_draw(&s);
    ASSERT_LINE_HAS(0, "Processes: 0");
    ASSERT_SCREEN_HAS("(no connections)");
}

static void test_tree_draw_single(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 100, "sshd", PROTO_TCP);
    view_procs_draw(&s);
    ASSERT_LINE_HAS(0, "Processes: 1");
    int y = runner_screen_find("sshd");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "  100      1     1     0");
    ASSERT_SCREEN_LACKS("(no connections)");
}

static void test_tree_draw_multiple_roots(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 100, "nginx",  PROTO_TCP);
    push(&s, 200, "sshd",   PROTO_TCP);
    push(&s, 300, "chrome", PROTO_TCP);
    view_procs_draw(&s);
    ASSERT_LINE_HAS(0, "Processes: 3");
    /* Three roots, none indented under another. */
    ASSERT(runner_find_col(runner_screen_find("nginx"), "nginx") == 1);
    ASSERT(runner_find_col(runner_screen_find("sshd"), "sshd") == 1);
    ASSERT(runner_find_col(runner_screen_find("chrome"), "chrome") == 1);
}

static void test_tree_draw_unresolved(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 0, "", PROTO_TCP);
    push(&s, 0, "", PROTO_UDP);
    view_procs_draw(&s);
    /* pid 0 rows fold into one "(unresolved)" row, PID column "-". */
    int y = runner_screen_find("(unresolved)");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "-      2     1     1");
}

/* ── Real parent-child test using getpid()/getppid() ─────── */

static void test_tree_real_parent_child(void) {
    pid_t self   = getpid();
    pid_t parent = getppid();
    ASSERT_NE(self, parent);      /* no process is its own parent */
    if (self == parent) return;

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* parent has more conns → appears first after procs_aggregate sort */
    push(&s, (int)parent, "parent_proc", PROTO_TCP);
    push(&s, (int)parent, "parent_proc", PROTO_TCP);
    push(&s, (int)self,   "child_proc",  PROTO_TCP);

    s.proc_sel = 0;
    view_procs_draw(&s);   /* triggers build_tree → reads real PPIDs */

    /* After tree ordering, parent should come before child (depth=0 → depth=1) */
    proc_stat_t agg[MAX_PROCS];
    int n = procs_aggregate(&s, agg, MAX_PROCS);
    ASSERT(n >= 2);
    /* The child is drawn under the parent, indented one level. */
    int py = runner_screen_find("parent_proc");
    int cy = runner_screen_find("child_proc");
    ASSERT(py >= 0);
    ASSERT_EQ(cy, py + 1);
    ASSERT_LINE_HAS(py, "[-]");
    ASSERT_EQ(runner_find_col(cy, "child_proc"), 3);
}

/* ── Navigation tests ────────────────────────────────────── */

static void test_tree_nav_down(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 10, "a", PROTO_TCP);
    push(&s, 20, "b", PROTO_TCP);
    s.proc_sel = 0;
    view_procs_draw(&s);
    view_procs_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.proc_sel, 1);
}

static void test_tree_nav_up(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 10, "a", PROTO_TCP);
    push(&s, 20, "b", PROTO_TCP);
    s.proc_sel = 1;
    view_procs_draw(&s);
    view_procs_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.proc_sel, 0);
}

static void test_tree_nav_top_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 10, "a", PROTO_TCP);
    s.proc_sel = 0;
    view_procs_draw(&s);
    view_procs_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.proc_sel, 0);
}

static void test_tree_nav_bottom_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 10, "a", PROTO_TCP);
    s.proc_sel = 0;
    view_procs_draw(&s);
    view_procs_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.proc_sel, 0);
}

static void test_tree_nav_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.proc_sel = 0;
    view_procs_draw(&s);
    view_procs_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.proc_sel, 0);
}

/* ── Detail panel: leaf → opens, not-leaf → does not open ── */

static void test_tree_enter_leaf_opens_detail(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 42, "solo", PROTO_TCP);
    s.proc_sel = 0;
    view_procs_draw(&s);     /* one entry, no children */
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 1);
}

static void test_tree_enter_unresolved_no_detail(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 0, "", PROTO_TCP);
    s.proc_sel = 0;
    view_procs_draw(&s);
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 0);
}

static void test_tree_enter_real_child_folds(void) {
    /* With real PIDs getpid()/getppid(), pressing Enter on the parent
       (which has getpid() as a child in the list) should toggle fold. */
    pid_t self   = getpid();
    pid_t parent = getppid();
    ASSERT_NE(self, parent);      /* no process is its own parent */
    if (self == parent) return;

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, (int)parent, "parent", PROTO_TCP);
    push(&s, (int)parent, "parent", PROTO_TCP);  /* 2 conns → sorts first */
    push(&s, (int)self,   "child",  PROTO_TCP);

    s.proc_sel = 0;
    view_procs_draw(&s);  /* tree: parent(depth=0) → child(depth=1) */

    /* proc_sel=0 should be the parent (more conns, root) */
    /* pressing Enter should toggle fold (has child) */
    /* draw to populate g_vis_count */
    view_procs_draw(&s);

    ASSERT_LINE_HAS(runner_screen_find("parent "), "[-]");
    ASSERT_SCREEN_HAS("  child ");

    view_procs_key(&s, '\r');  /* fold/unfold */
    /* now draw again to see new vis_count */
    tui_test_erase();
    view_procs_draw(&s);       /* rebuilds vis */

    /* Folded: the marker flips, the child row is gone, and the header
     * counts visible over total. Seen to fail with the Enter fold toggle
     * removed from view_procs_key(). */
    ASSERT_LINE_HAS(0, "Processes: 1/2");
    ASSERT_LINE_HAS(runner_screen_find("parent "), "[+]");
    ASSERT_SCREEN_LACKS("  child ");
}

/* ── Detail close ────────────────────────────────────────── */

static void test_tree_detail_close_esc(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.proc_detail = 1;
    view_procs_key(&s, '\033');
    ASSERT_EQ(s.proc_detail, 0);
}

static void test_tree_detail_blocks_nav(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push(&s, 1, "a", PROTO_TCP);
    push(&s, 2, "b", PROTO_TCP);
    view_procs_draw(&s);
    s.proc_sel    = 0;
    s.proc_detail = 1;
    view_procs_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.proc_sel, 0);  /* nav consumed by detail mode */
}

/* ── Entry point ─────────────────────────────────────────── */

void run_tree_tests(void) {
    TEST_SUITE("tree/fields");
    RUN_TEST(test_ppid_field_exists);
    RUN_TEST(test_depth_field_exists);
    RUN_TEST(test_aggregate_zeros_ppid_depth);

    TEST_SUITE("tree/draw");
    RUN_TEST(test_tree_draw_empty);
    RUN_TEST(test_tree_draw_single);
    RUN_TEST(test_tree_draw_multiple_roots);
    RUN_TEST(test_tree_draw_unresolved);
    RUN_TEST(test_tree_real_parent_child);

    TEST_SUITE("tree/nav");
    RUN_TEST(test_tree_nav_down);
    RUN_TEST(test_tree_nav_up);
    RUN_TEST(test_tree_nav_top_bound);
    RUN_TEST(test_tree_nav_bottom_bound);
    RUN_TEST(test_tree_nav_empty);

    TEST_SUITE("tree/enter");
    RUN_TEST(test_tree_enter_leaf_opens_detail);
    RUN_TEST(test_tree_enter_unresolved_no_detail);
    RUN_TEST(test_tree_enter_real_child_folds);
    RUN_TEST(test_tree_detail_close_esc);
    RUN_TEST(test_tree_detail_blocks_nav);
}
