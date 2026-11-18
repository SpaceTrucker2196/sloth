#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "fd_guard.h"

/*
 * The suite's file-descriptor leak guard (tests/fd_guard.h, #209).
 *
 * Every case in the run exercises the guard's happy path, the same way
 * every case exercises the tmp guard's. What needs its own test is the
 * part a green run never reaches: that a case which leaks is *caught*
 * and *named*. So these drive fdg_report() directly on a hand-made
 * before/after pair rather than through RUN_TEST — a case that really
 * leaked would fail the run, which is exactly the behaviour under test
 * and therefore not something it can be built on.
 *
 * These cases are themselves measured by the guard, so each closes what
 * it opens; the guard going red on its own test file would be the first
 * thing to look at.
 */

static int msg_has(const char *msg, const char *needle) {
    return strstr(msg, needle) != NULL;
}

/* The claim: a case that leaves a descriptor open is reported, with its
 * own name and the fd in the message. Seen to fail with the delta test
 * in fdg_report() relaxed to `delta > 1`. */
static void test_report_catches_and_names_a_leak(void) {
    fdg_set_t before, after;
    char msg[FDG_MSG_MAX];
    ASSERT(fdg_scan(&before) > 0);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(fd >= 0);
    ASSERT(fdg_scan(&after) > 0);
    msg[0] = '\0';
    ASSERT_EQ(fdg_report(&before, &after, "test_a_leaky_case", msg, sizeof(msg)), 1);
    ASSERT(msg_has(msg, "FDLEAK"));
    ASSERT(msg_has(msg, "test_a_leaky_case"));
    ASSERT(msg_has(msg, "left 1 descriptor(s) open"));
    char want[32];
    snprintf(want, sizeof(want), "fd %d", fd);
    ASSERT(msg_has(msg, want));
    ASSERT(msg_has(msg, "/dev/null"));   /* the readlink, where /proc is there */
    if (fd >= 0) close(fd);
}

/* …and a case that opens and closes is not reported, which is the half
 * that would make the guard useless if it were wrong: a guard that
 * fails everything is as uninformative as one that fails nothing. */
static void test_report_passes_a_clean_case(void) {
    fdg_set_t before, after;
    char msg[FDG_MSG_MAX];
    ASSERT(fdg_scan(&before) > 0);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(fd >= 0);
    if (fd >= 0) close(fd);
    ASSERT(fdg_scan(&after) > 0);
    msg[0] = 'x'; msg[1] = '\0';
    ASSERT_EQ(fdg_report(&before, &after, "test_a_clean_case", msg, sizeof(msg)), 0);
    ASSERT_STR(msg, "x");            /* clean leaves the buffer alone */
}

/* The verdict is the count, not the identity: a case that closes one
 * descriptor and opens another has given back what it borrowed. Holding
 * it to the bitmap instead would fail honest code that reopens a
 * stream, so this pins the deliberate choice. */
static void test_report_ignores_a_descriptor_that_moved(void) {
    fdg_set_t before, after;
    char msg[FDG_MSG_MAX];
    int a = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(a >= 0);
    ASSERT(fdg_scan(&before) > 0);
    if (a >= 0) close(a);
    int b = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(b >= 0);
    ASSERT(fdg_scan(&after) > 0);
    msg[0] = '\0';
    ASSERT_EQ(fdg_report(&before, &after, "test_moved", msg, sizeof(msg)), 0);
    if (b >= 0) close(b);
}

/* The other direction: a case that closed a descriptor it did not open
 * also failed to return the table to its entry value. Reported, with no
 * fd list — there is nothing new to name. */
static void test_report_catches_a_descriptor_closed_not_opened(void) {
    fdg_set_t before, after;
    char msg[FDG_MSG_MAX];
    int held = dup(2);
    ASSERT(held >= 0);
    ASSERT(fdg_scan(&before) > 0);
    if (held >= 0) close(held);
    ASSERT(fdg_scan(&after) > 0);
    msg[0] = '\0';
    ASSERT_EQ(fdg_report(&before, &after, "test_closer", msg, sizeof(msg)), -1);
    ASSERT(msg_has(msg, "test_closer"));
    ASSERT(msg_has(msg, "closed 1 descriptor(s) it did not open"));
    ASSERT(!msg_has(msg, " fd "));
}

/* Several at once are counted, and the list is capped at FDG_NAMED so
 * a case leaking in a loop says it once rather than a thousand times. */
static void test_report_counts_many_and_caps_the_list(void) {
    enum { N = FDG_NAMED + 3 };
    fdg_set_t before, after;
    char msg[FDG_MSG_MAX];
    int fds[N];
    ASSERT(fdg_scan(&before) > 0);
    int opened = 0;
    for (int i = 0; i < N; i++) {
        fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[i] >= 0) opened++;
    }
    ASSERT_EQ(opened, N);
    ASSERT(fdg_scan(&after) > 0);
    msg[0] = '\0';
    ASSERT_EQ(fdg_report(&before, &after, "test_many", msg, sizeof(msg)), N);
    char want[48];
    snprintf(want, sizeof(want), "left %d descriptor(s) open", N);
    ASSERT(msg_has(msg, want));
    int listed = 0;
    for (const char *p = strstr(msg, " fd "); p; p = strstr(p + 1, " fd "))
        listed++;
    ASSERT_EQ(listed, FDG_NAMED);        /* FDG_NAMED entries, not N */
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
}

/* Both scan routes must agree, so the /proc-less fallback is not dead
 * code that only a Darwin or generic-POSIX build ever runs — it would
 * be found broken there, on a host nobody is watching. On a host with
 * /proc the two run against the same table and must count the same.
 *
 * Deliberately NOT asserting that the bitmaps are identical: the probe
 * stops at the soft limit and the /proc scan does not, so on a host
 * whose RLIMIT_NOFILE is below a live descriptor the two legitimately
 * differ. Nothing in this suite opens that high. */
static void test_both_scan_routes_agree(void) {
    fdg_set_t viaproc, viaprobe;
    int p = fdg_scan_proc(&viaproc);
    int q = fdg_scan_probe(&viaprobe);
    ASSERT(q > 0);
    if (p < 0) {
        /* No /proc: the fallback is the only route and fdg_scan takes it */
        fdg_set_t any;
        ASSERT_EQ(fdg_scan(&any), q);
        return;
    }
    ASSERT_EQ(p, q);
    ASSERT_EQ(memcmp(viaproc.bits, viaprobe.bits, sizeof(viaproc.bits)), 0);
}

/* A descriptor the scan found is one fdg_has() reports, and one it did
 * not is not. The bitmap is what names a leak; an off-by-one in the
 * shift would still produce plausible counts. */
static void test_marks_the_descriptor_it_found(void) {
    fdg_set_t s;
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(fd >= 0);
    ASSERT(fdg_scan(&s) > 0);
    ASSERT_EQ(fdg_has(&s, fd), 1);
    ASSERT_EQ(fdg_has(&s, 0), 1);            /* stdin */
    ASSERT_EQ(fdg_has(&s, -1), 0);
    ASSERT_EQ(fdg_has(&s, FDG_MAX_FD), 0);   /* out of the bitmap's range */
    if (fd >= 0) close(fd);
    ASSERT(fdg_scan(&s) > 0);
    ASSERT_EQ(fdg_has(&s, fd), 0);
}

void run_fd_guard_tests(void) {
    TEST_SUITE("fd_guard — the suite's descriptor-leak guard");
    RUN_TEST(test_report_catches_and_names_a_leak);
    RUN_TEST(test_report_passes_a_clean_case);
    RUN_TEST(test_report_ignores_a_descriptor_that_moved);
    RUN_TEST(test_report_catches_a_descriptor_closed_not_opened);
    RUN_TEST(test_report_counts_many_and_caps_the_list);
    RUN_TEST(test_both_scan_routes_agree);
    RUN_TEST(test_marks_the_descriptor_it_found);
}
