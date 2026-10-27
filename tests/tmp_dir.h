/* Temporary files for the test suite.
 *
 * Every file or directory a test creates goes under test_tmpdir(), which
 * is $TMPDIR, falling back to /tmp. main_test.c points $TMPDIR at a
 * private mkdtemp() run directory before the first suite and removes it
 * recursively at exit, after counting what is left in it: anything still
 * there is a leak and fails the run (tmp_run_dir_check below). So a
 * helper that forgets to clean up goes red rather than piling up in a
 * shared /tmp, which on this project's hosts is RAM.
 *
 * The run directory is 0700. A test that needs a shared, world-writable
 * parent (a refusal check) makes a 01777 subdirectory of it rather than
 * writing into the host's /tmp.
 *
 * web/tests/wt_tmp.h is slothweb's copy: web/ includes nothing from
 * tests/, so the two suites can change independently. */
#ifndef SLOTH_TESTS_TMP_DIR_H
#define SLOTH_TESTS_TMP_DIR_H

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* The size of a buffer that holds a test's temporary path. The runner
 * refuses a run directory longer than TEST_TMP_DIR_MAX, which leaves
 * room under this for any template a test uses; and a unix socket
 * under it still fits sun_path (108). Deliberately not PATH_MAX, so a
 * derived "<dir>/<file>" buffer need not be 4 KB to stay
 * -Wformat-truncation clean. */
#define TEST_TMP_MAX     96
/* The Makefile passes its own TEST_TMP_DIR_MAX, which it also uses to
 * pick the outer directory's base (TEST_IN_TMPDIR), so the two cannot
 * disagree about when a $TMPDIR is too long. */
#ifndef TEST_TMP_DIR_MAX
#define TEST_TMP_DIR_MAX 56
#endif

static inline const char *test_tmpdir(void) {
    const char *t = getenv("TMPDIR");
    return (t && *t) ? t : "/tmp";
}

/* "<tmpdir>/<name>" into buf; name is usually an mkstemp()/mkdtemp()
 * template. Returns 0, or -1 when it does not fit. */
static inline int test_tmp_path(char *buf, size_t sz, const char *name) {
    int n = snprintf(buf, sz, "%s/%s", test_tmpdir(), name);
    return (n < 0 || (size_t)n >= sz) ? -1 : 0;
}

/* For a file-scope `static char buf[TEST_TMP_MAX]` template: fills it with
 * "<tmpdir>/<name>" the first time (buf still empty) and returns buf,
 * so `mkstemp(test_tmp_tpl(buf, sizeof(buf), "x_XXXXXX"))` reads the
 * way the old `static char buf[] = "/tmp/x_XXXXXX"` did. A test that
 * puts the XXXXXX back after use and calls it again keeps its path. */
static inline char *test_tmp_tpl(char *buf, size_t sz, const char *name) {
    if (!buf[0] && test_tmp_path(buf, sz, name) != 0) buf[0] = '\0';
    return buf;
}

/* rm -rf without following symlinks. ENOENT is success. Recursion depth
 * is the tree's depth, which in a test is two or three. A directory of
 * our own left at 0500 or 0000 (a refusal test that failed before it
 * restored the mode) is made 0700 first, so it can still be emptied. */
static inline int test_rm_tree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return (unlink(path) == 0 || errno == ENOENT) ? 0 : -1;
    if (st.st_uid == getuid() && (st.st_mode & 0700) != 0700)
        (void)chmod(path, 0700);
    int rc = 0;
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char sub[PATH_MAX];
            int n = snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
            if (n < 0 || (size_t)n >= sizeof(sub)) { rc = -1; continue; }
            if (test_rm_tree(sub) != 0) rc = -1;
        }
        closedir(d);
    }
    if (rmdir(path) != 0 && errno != ENOENT) rc = -1;
    return rc;
}

/* ── The runner's leak guard ─────────────────────────────────────── */

static inline long tmp_run_dir_walk(const char *dir, long *printed, long max) {
    long n = 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char sub[PATH_MAX];
        int w = snprintf(sub, sizeof(sub), "%s/%s", dir, e->d_name);
        if (w < 0 || (size_t)w >= sizeof(sub)) continue;
        n++;
        if (*printed < max) { fprintf(stderr, "LEAK: %s\n", sub); (*printed)++; }
        struct stat st;
        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode))
            n += tmp_run_dir_walk(sub, printed, max);
    }
    closedir(d);
    return n;
}

/* Names (at most 20) and counts what the suites left in the run
 * directory. Returns the number of leftover paths; 0 is clean. */
static inline long tmp_run_dir_check(const char *dir, const char *who) {
    long printed = 0;
    fflush(stdout);   /* the [pass] lines are stdout; keep them apart */
    long n = tmp_run_dir_walk(dir, &printed, 20);
    if (n > printed)
        fprintf(stderr, "LEAK: ...and %ld more\n", n - printed);
    if (n)
        fprintf(stderr, "%s: %ld temporary path(s) left under %s; "
                        "a test must remove what it creates\n", who, n, dir);
    return n;
}

/* Makes the run directory "<tmpdir>/<prefix>.XXXXXX" (0700) into dir
 * and points $TMPDIR at it, so every test_tmp_path() after this, and
 * SQLite's own temporary files, land inside it. A $TMPDIR too long to
 * leave room for the tests' names under TEST_TMP_MAX (base plus
 * "/<prefix>.XXXXXX" over TEST_TMP_DIR_MAX) falls back to /tmp, said on
 * stderr, rather than truncating paths later. Under make that never
 * fires: TEST_IN_TMPDIR picks an outer base short enough for it. Run
 * by hand with a long $TMPDIR, the run directory is in /tmp, and only
 * atexit() and the signal handler (tmp_run_dir_signal_rm) remove it. */
static inline int tmp_run_dir_open(char *dir, size_t sz, const char *prefix,
                                   const char *who) {
    const char *base = test_tmpdir();
    if (strlen(base) + 1 + strlen(prefix) + 7 > TEST_TMP_DIR_MAX) {
        fprintf(stderr, "%s: TMPDIR %s is longer than the suite's paths "
                        "allow; using /tmp\n", who, base);
        base = "/tmp";
    }
    int n = snprintf(dir, sz, "%s/%s.XXXXXX", base, prefix);
    if (n < 0 || (size_t)n >= sz || !mkdtemp(dir)) {
        fprintf(stderr, "%s: cannot make a run directory under %s: %s\n",
                who, base, strerror(errno));
        dir[0] = '\0';
        return -1;
    }
    return setenv("TMPDIR", dir, 1);
}

static inline int tmp_run_dir_keep(void) {
    const char *keep = getenv("SLOTH_TEST_KEEP_TMP");
    return keep && *keep && strcmp(keep, "0") != 0;
}

/* The atexit half: remove the run directory, unless
 * SLOTH_TEST_KEEP_TMP is set (then say where it is). Returns -1 when
 * the directory could not be removed, which the runner turns into a
 * failed run: a passing run that leaves a directory behind is a leak
 * the guard, having run before atexit(), did not see. */
static inline int tmp_run_dir_close(char *dir, const char *who) {
    if (!dir[0]) return 0;
    int rc = 0;
    if (tmp_run_dir_keep()) {
        fprintf(stderr, "%s: kept %s (SLOTH_TEST_KEEP_TMP)\n", who, dir);
    } else if (test_rm_tree(dir) != 0) {
        fprintf(stderr, "%s: could not remove %s\n", who, dir);
        rc = -1;
    }
    dir[0] = '\0';
    return rc;
}

/* The signal half, for SIGINT/SIGTERM/SIGHUP: a runner interrupted by
 * hand never reaches atexit(). Only async-signal-safe calls: opendir()
 * may allocate, so the tree goes to rm(1) in a child rather than to
 * test_rm_tree(). vfork(), not fork(): glibc's fork() runs its atfork
 * handlers and takes the malloc and stdio locks, and a SIGTERM that
 * landed inside malloc() hung there on a futex (seen 2026-10-27, the
 * first version of this). The vfork child only calls execv() and
 * _exit(). The caller re-raises the signal afterwards. */
static inline void tmp_run_dir_signal_rm(const char *dir) {
    if (!dir[0]) return;
    char *argv[] = { "rm", "-rf", "--", (char *)dir, NULL };
    pid_t pid = vfork();
    if (pid == 0) {
        execv("/bin/rm", argv);
        _exit(127);
    }
    if (pid > 0) {
        int st;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    }
}

/* Installs h for the signals that end a run by hand or by a timeout.
 * SA_RESETHAND|SA_NODEFER: the handler runs once, and a second Ctrl-C
 * while it is removing the tree kills the process outright instead of
 * waiting behind it. */
static inline void tmp_run_dir_trap_signals(void (*h)(int)) {
    static const int sigs[] = { SIGINT, SIGTERM, SIGHUP };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = h;
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
}

#endif /* SLOTH_TESTS_TMP_DIR_H */
