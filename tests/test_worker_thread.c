#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include "runner.h"
#include "worker_thread.h"
#include "dns.h"

/* ── src/worker_thread.c — signals stay on the main thread (#95) ──
 *
 * main() installs on_signal() for SIGINT and SIGTERM. POSIX delivers a
 * process-directed signal to any thread that does not block it (XSH
 * 2.4.1), so every worker sloth starts must block both, or a Ctrl-C can
 * land on the capture thread mid-pcap_dispatch() instead of the main
 * loop that acts on it. */

/* ── the helper itself ───────────────────────────────────── */

static int g_saw_int, g_saw_term;

static void *report_mask(void *arg) {
    (void)arg;
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    g_saw_int  = sigismember(&cur, SIGINT);
    g_saw_term = sigismember(&cur, SIGTERM);
    return NULL;
}

/* Run from a creator whose own mask is empty, so the result cannot be
 * inherited from whatever the suite happened to block before. */
static void test_worker_starts_with_int_and_term_blocked(void) {
    sigset_t none, saved;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, &saved);

    g_saw_int = g_saw_term = -1;
    pthread_t t;
    ASSERT_EQ(0, worker_thread_create(&t, report_mask, NULL));
    pthread_join(t, NULL);
    ASSERT_EQ(1, g_saw_int);
    ASSERT_EQ(1, g_saw_term);

    pthread_sigmask(SIG_SETMASK, &saved, NULL);
}

/* The block is for the worker only. The creator is the main thread in
 * sloth, and leaving SIGINT blocked there would make Ctrl-C do nothing
 * at all — so the creator's mask must come back exactly as it was,
 * including a signal it had blocked for its own reasons. */
static void test_creator_mask_is_restored_exactly(void) {
    sigset_t mine, saved, after;
    sigemptyset(&mine);
    sigaddset(&mine, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &mine, &saved);

    pthread_t t;
    ASSERT_EQ(0, worker_thread_create(&t, report_mask, NULL));
    pthread_join(t, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &after);
    ASSERT_EQ(0, sigismember(&after, SIGINT));
    ASSERT_EQ(0, sigismember(&after, SIGTERM));
    ASSERT_EQ(1, sigismember(&after, SIGUSR1));

    pthread_sigmask(SIG_SETMASK, &saved, NULL);
}

static void test_signal_set_is_int_and_term(void) {
    sigset_t s;
    worker_signal_set(&s);
    ASSERT_EQ(1, sigismember(&s, SIGINT));
    ASSERT_EQ(1, sigismember(&s, SIGTERM));
    /* SIGHUP keeps its default action in sloth; nothing handles it. */
    ASSERT_EQ(0, sigismember(&s, SIGHUP));
}

/* ── a real worker, read from the kernel ─────────────────── */

#define MAX_TIDS 256

static int list_tids(long *out, int max) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        out[n++] = strtol(e->d_name, NULL, 10);
    }
    closedir(d);
    return n;
}

static int tid_in(long tid, const long *v, int n) {
    for (int i = 0; i < n; i++) if (v[i] == tid) return 1;
    return 0;
}

/* SigBlk from /proc/self/task/<tid>/status: the kernel's view of that
 * thread's mask, as a hex bitmap where signal N is bit N-1. */
static int read_sigblk(long tid, unsigned long long *mask) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/status", tid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    int found = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SigBlk:", 7) == 0) {
            *mask = strtoull(line + 7, NULL, 16);
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

/* Wait out glibc's thread start. pthread_create() blocks every signal
 * around clone() and the child restores its inherited mask only once it
 * runs, so a SigBlk read straight after creation can see the transient
 * all-blocked mask — which contains SIGINT and SIGTERM and made the
 * first version of this test pass against a bare pthread_create() on
 * one run in two. SIGHUP is in the transient set and in neither
 * possible final mask (the creator's is emptied below), so its bit
 * clearing marks the end of the transient. */
static int read_settled_sigblk(long tid, unsigned long long *mask) {
    const unsigned long long hup = 1ULL << (SIGHUP - 1);
    struct timespec ms = { 0, 1000000 };
    for (int i = 0; i < 2000; i++) {
        if (read_sigblk(tid, mask) != 0) return -1;
        if (!(*mask & hup)) return 0;
        nanosleep(&ms, NULL);
    }
    return -1;
}

/* The DNS worker is the one sloth thread a test can start without a
 * capture handle (the capture and probe workers need a live pcap_t).
 * It is located as the task that appears across dns_init(), so a
 * thread another suite left running cannot be mistaken for it. Under
 * --allow-active with nothing enqueued it parks on its condvar, so the
 * test makes no lookup.
 *
 * The creator's mask is emptied first, so the worker's final mask is
 * exactly what worker_thread_create() added and nothing inherited from
 * however the test binary was started. */
static void test_live_dns_worker_blocks_int_and_term(void) {
    long before[MAX_TIDS], after[MAX_TIDS];
    const unsigned long long want =
        (1ULL << (SIGINT - 1)) | (1ULL << (SIGTERM - 1));
    dns_cleanup();
    dns_reset();
    dns_resolver_reset_policy();
    dns_resolver_set_enabled(1);

    sigset_t none, saved;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, &saved);

    int nb = list_tids(before, MAX_TIDS);
    ASSERT_GT(nb, 0);
    dns_init();
    ASSERT_EQ(1, dns_resolver_worker_running());
    int na = list_tids(after, MAX_TIDS);

    int checked = 0;
    for (int i = 0; i < na; i++) {
        if (tid_in(after[i], before, nb)) continue;
        unsigned long long m = 0;
        ASSERT_EQ(0, read_settled_sigblk(after[i], &m));
        ASSERT(m == want);
        checked++;
    }
    ASSERT_EQ(1, checked);

    pthread_sigmask(SIG_SETMASK, &saved, NULL);
    dns_cleanup();
    dns_resolver_reset_policy();
}

/* ── every creation site goes through the helper ─────────── */

/* The capture and probe workers cannot be started here, so their half
 * of the guarantee is held structurally: no file under src/ other than
 * the helper may call pthread_create() directly. A new worker added
 * with a bare pthread_create() fails this test by name. "pthread_create()"
 * written in a comment is not a call and is skipped. */
static int bare_creates_in(const char *path, int report) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    int n = 0, lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        for (char *p = strstr(line, "pthread_create("); p;
             p = strstr(p + 1, "pthread_create(")) {
            if (p[15] == ')') continue;
            if (report)
                fprintf(stderr, "    bare pthread_create at %s:%d\n", path, lineno);
            n++;
        }
    }
    fclose(f);
    return n;
}

static int walk(const char *dir, int *files) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        size_t len = strlen(e->d_name);
        if (len > 2 && strcmp(e->d_name + len - 2, ".c") == 0) {
            (*files)++;
            if (strcmp(path, "src/worker_thread.c") != 0)
                n += bare_creates_in(path, 1);
        } else if (strchr(e->d_name, '.') == NULL) {
            n += walk(path, files);
        }
    }
    closedir(d);
    return n;
}

static void test_no_bare_pthread_create_under_src(void) {
    int files = 0;
    int bare = walk("src", &files);
    ASSERT_GT(files, 50);          /* the walk actually reached the tree */
    ASSERT_EQ(0, bare);
    /* And the helper is still the one call, so the walk can see one. */
    ASSERT_EQ(1, bare_creates_in("src/worker_thread.c", 0));
}

void run_worker_thread_tests(void) {
    TEST_SUITE("worker_thread — SIGINT/SIGTERM stay on the main thread (#95)");
    RUN_TEST(test_signal_set_is_int_and_term);
    RUN_TEST(test_worker_starts_with_int_and_term_blocked);
    RUN_TEST(test_creator_mask_is_restored_exactly);
    RUN_TEST(test_live_dns_worker_blocks_int_and_term);
    RUN_TEST(test_no_bare_pthread_create_under_src);
}
