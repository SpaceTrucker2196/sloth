#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"

/*
 * The test suite's own temporary-file helpers (tests/tmp_dir.h). The
 * leak guard is exercised by every run; these cover the paths a passing
 * run never takes: a directory a failed refusal test left unreadable,
 * a run directory that cannot be removed, and a runner killed by a
 * signal before atexit().
 */

static int exists(const char *p) {
    struct stat st;
    return lstat(p, &st) == 0;
}

/* Builds "<tmpdir>/tmpdir_t_XXXXXX/sub/f" and returns the top in top. */
static int make_tree(char *top, size_t sz, char *sub, size_t subsz) {
    if (test_tmp_path(top, sz, "tmpdir_t_XXXXXX") != 0 || !mkdtemp(top))
        return -1;
    int n = snprintf(sub, subsz, "%s/sub", top);
    if (n < 0 || (size_t)n >= subsz || mkdir(sub, 0700) != 0) return -1;
    char f[TEST_TMP_MAX + 16];
    n = snprintf(f, sizeof(f), "%s/f", sub);
    if (n < 0 || (size_t)n >= sizeof(f)) return -1;
    FILE *fp = fopen(f, "w");
    if (!fp) return -1;
    fputs("x\n", fp);
    fclose(fp);
    return 0;
}

/* A refusal test that fails before restoring its directory's mode
 * leaves it at 0500; the run directory must still go. */
static void test_rm_tree_removes_a_0500_dir_of_our_own(void) {
    char top[TEST_TMP_MAX], sub[TEST_TMP_MAX + 8];
    ASSERT_EQ(make_tree(top, sizeof(top), sub, sizeof(sub)), 0);
    ASSERT_EQ(chmod(sub, 0500), 0);
    ASSERT_EQ(test_rm_tree(top), 0);
    ASSERT_EQ(exists(top), 0);
    if (exists(sub)) chmod(sub, 0700);
    test_rm_tree(top);
}

static void test_rm_tree_removes_a_0000_dir_of_our_own(void) {
    char top[TEST_TMP_MAX], sub[TEST_TMP_MAX + 8];
    ASSERT_EQ(make_tree(top, sizeof(top), sub, sizeof(sub)), 0);
    ASSERT_EQ(chmod(sub, 0000), 0);
    ASSERT_EQ(test_rm_tree(top), 0);
    ASSERT_EQ(exists(top), 0);
    if (exists(sub)) chmod(sub, 0700);
    test_rm_tree(top);
}

/* tmp_run_dir_close() reports a directory it could not remove, which
 * the runner turns into a failed run. Its parent at 0500 makes rmdir()
 * fail; test_rm_tree() only opens up the directory itself. */
static void test_run_dir_close_reports_what_it_cannot_remove(void) {
    char top[TEST_TMP_MAX], sub[TEST_TMP_MAX + 8];
    ASSERT_EQ(make_tree(top, sizeof(top), sub, sizeof(sub)), 0);
    if (getuid() == 0) {   /* root ignores the mode; nothing to see */
        ASSERT_EQ(test_rm_tree(top), 0);
        return;
    }
    char held[TEST_TMP_MAX + 8];
    memcpy(held, sub, sizeof(held));
    ASSERT_EQ(chmod(top, 0500), 0);
    /* its "could not remove" line is expected here: keep it off the log */
    fflush(stderr);
    int saved = dup(2), null = open("/dev/null", O_WRONLY);
    if (saved >= 0 && null >= 0) dup2(null, 2);
    int rc = tmp_run_dir_close(held, "tmp_dir_test");
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
    if (null >= 0) close(null);
    ASSERT_EQ(rc, -1);
    ASSERT_EQ(held[0], '\0');
    ASSERT_EQ(chmod(top, 0700), 0);
    ASSERT_EQ(test_rm_tree(top), 0);
    ASSERT_EQ(exists(top), 0);
}

static char g_sig_dir[TEST_TMP_MAX];

static void sig_child_handler(int sig) {
    tmp_run_dir_signal_rm(g_sig_dir);
    raise(sig);
}

/* A runner interrupted by SIGINT/SIGTERM never reaches atexit(). The
 * handler removes the tree and the process still dies of the signal,
 * so make and timeout(1) see what happened. */
static void signal_case(int sig) {
    char sub[TEST_TMP_MAX + 8];
    ASSERT_EQ(make_tree(g_sig_dir, sizeof(g_sig_dir), sub, sizeof(sub)), 0);
    fflush(NULL);
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
        tmp_run_dir_trap_signals(sig_child_handler);
        kill(getpid(), sig);
        _exit(3);   /* not reached: the re-raise kills the child */
    }
    int st = 0;
    ASSERT_EQ(waitpid(pid, &st, 0), pid);
    ASSERT(WIFSIGNALED(st));
    ASSERT_EQ(WIFSIGNALED(st) ? WTERMSIG(st) : 0, sig);
    ASSERT_EQ(exists(g_sig_dir), 0);
    test_rm_tree(g_sig_dir);
    g_sig_dir[0] = '\0';
}

static void test_signal_removes_the_run_dir_sigint(void)  { signal_case(SIGINT); }
static void test_signal_removes_the_run_dir_sigterm(void) { signal_case(SIGTERM); }

void run_tmp_dir_tests(void) {
    TEST_SUITE("tmp_dir — the suite's own temporary-file helpers");
    RUN_TEST(test_rm_tree_removes_a_0500_dir_of_our_own);
    RUN_TEST(test_rm_tree_removes_a_0000_dir_of_our_own);
    RUN_TEST(test_run_dir_close_reports_what_it_cannot_remove);
    RUN_TEST(test_signal_removes_the_run_dir_sigint);
    RUN_TEST(test_signal_removes_the_run_dir_sigterm);
}
