/* File-descriptor leak guard for the test suite (#209).
 *
 * The companion to tests/tmp_dir.h's leak guard, for the other shared
 * resource a test case can walk off with. The tmp guard runs once, at
 * the end of the run, because a leftover path is still there to be
 * found; a leaked descriptor is not — all it leaves behind is a smaller
 * fd table, and the failure lands on whatever opens next. Twice in
 * November 2026 that was a test's own mkstemp path being refused:
 * jsonl_open() in test_twin_field.c on CI's ASan job, db_open() in
 * test_jsonl.c on the plain job, both green on the next run of the same
 * code (#209). sfile_open()'s only reachable refusal for a freshly
 * created 0600 file is the openat() itself, and under `ulimit -n 1024`
 * the realistic errno there is EMFILE.
 *
 * So this one samples at every test-case boundary instead: the count of
 * open descriptors when the case starts, the count when it ends, and
 * the names of what is new. A case whose count did not come back fails
 * the suite by its own name, at the leak, rather than ten suites later
 * at somebody else's open().
 *
 * The verdict is the COUNT, deliberately, not the identity of the
 * descriptors: a case that closes fd 3 and opens fd 7 has returned the
 * resource it borrowed, and holding it to the bitmap would fail honest
 * code that reopens a standard stream. The bitmap exists to name what
 * is new once the count has already said something is.
 *
 * Both scan routes are exported so the suite can exercise both on one
 * host: /proc/self/fd where it exists, and a probe of every descriptor
 * up to the limit where it does not (the generic-POSIX and Darwin
 * builds, which have no /proc). */
#ifndef SLOTH_TESTS_FD_GUARD_H
#define SLOTH_TESTS_FD_GUARD_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Descriptors at or above this are counted but not named. 1024 is the
 * limit CI's sanitize job runs under (`ulimit -n 1024`), so in the
 * configuration this guard exists for nothing lands above it. */
#define FDG_MAX_FD  1024
#define FDG_BYTES   (FDG_MAX_FD / 8)
/* How many new descriptors one report lists. A case that leaks in a
 * loop says the same thing six times as it does sixty. */
#define FDG_NAMED   6
/* Enough for the sentence, the counts and FDG_NAMED "fd N -> path"
 * clauses at a tmp path's length (TEST_TMP_MAX is 96). */
#define FDG_MSG_MAX 1024
/* A readlink target in the report. The paths a test case opens are its
 * own temporary files (TEST_TMP_MAX is 96) and the suite's sources; a
 * longer one is truncated rather than growing every stack frame here. */
#define FDG_PATH_MAX 256

typedef struct {
    unsigned char bits[FDG_BYTES];
    int total;          /* every open descriptor, including >= FDG_MAX_FD */
} fdg_set_t;

static inline void fdg_mark(fdg_set_t *s, int fd) {
    if (fd < 0) return;
    s->total++;
    if (fd < FDG_MAX_FD) s->bits[fd / 8] |= (unsigned char)(1u << (fd % 8));
}

static inline int fdg_has(const fdg_set_t *s, int fd) {
    if (fd < 0 || fd >= FDG_MAX_FD) return 0;
    return (s->bits[fd / 8] >> (fd % 8)) & 1;
}

/* The /proc route. Fills `s` and returns its total, or -1 when
 * /proc/self/fd cannot be read. The directory's own descriptor is live
 * for the length of the scan and is not one of ours, so it is skipped;
 * "." and ".." are skipped by the leading-digit test. */
static inline int fdg_scan_proc(fdg_set_t *s) {
    memset(s, 0, sizeof(*s));
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int self = dirfd(d);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        int fd = (int)strtol(e->d_name, NULL, 10);
        if (fd == self) continue;
        fdg_mark(s, fd);
    }
    closedir(d);
    return s->total;
}

/* The portable route, for a host with no /proc: ask every descriptor up
 * to the soft limit whether it exists. Opens nothing, so it cannot
 * perturb what it is measuring — which is also why it is the fallback
 * for a /proc that is there but could not be opened: at the fd limit,
 * the one failure this guard exists to find, opendir() is the call that
 * fails. Bounded by FDG_MAX_FD as well as by the
 * limit, because a host with RLIMIT_NOFILE at 1048576 would otherwise
 * spend a million fcntl() calls per boundary. */
static inline int fdg_scan_probe(fdg_set_t *s) {
    memset(s, 0, sizeof(*s));
    long lim = sysconf(_SC_OPEN_MAX);
    if (lim < 0 || lim > FDG_MAX_FD) lim = FDG_MAX_FD;
    for (int fd = 0; fd < (int)lim; fd++)
        if (fcntl(fd, F_GETFD) >= 0) fdg_mark(s, fd);
    return s->total;
}

static inline int fdg_scan(fdg_set_t *s) {
    int n = fdg_scan_proc(s);
    return n >= 0 ? n : fdg_scan_probe(s);
}

/* What `fd` is, for the report: the readlink of its /proc entry, or ""
 * where that is unavailable. The fd number alone is already enough to
 * find the leak in a single case; the path is what makes it obvious. */
static inline const char *fdg_name(int fd, char *buf, size_t sz) {
    char link[64];
    if (!buf || sz == 0) return "";
    buf[0] = '\0';
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, sz - 1);
    if (n < 0) return "";
    buf[n] = '\0';
    return buf;
}

/* The verdict for one case. Returns `after` minus `before`: 0 is clean,
 * positive is descriptors left open, negative is descriptors the case
 * closed without having opened them (a dup2 onto a standard stream that
 * was not put back — rarer, and just as much a borrowed resource not
 * returned). Non-zero fills `msg` with the diagnostic, naming the case;
 * zero leaves it alone. The caller prints it, which is what lets the
 * guard's own self-test read the message without failing the run. */
static inline int fdg_report(const fdg_set_t *before, const fdg_set_t *after,
                             const char *name, char *msg, size_t msgsz) {
    int delta = after->total - before->total;
    if (delta == 0 || !msg || msgsz == 0) return delta;
    size_t off = 0;
    int n = snprintf(msg, msgsz,
                     delta > 0
                       ? "FDLEAK: %s left %d descriptor(s) open "
                         "(%d at entry, %d at exit)"
                       : "FDLEAK: %s closed %d descriptor(s) it did not open "
                         "(%d at entry, %d at exit)",
                     name ? name : "?", delta > 0 ? delta : -delta,
                     before->total, after->total);
    if (n < 0) { msg[0] = '\0'; return delta; }
    off = (size_t)n < msgsz ? (size_t)n : msgsz - 1;
    if (delta < 0) return delta;
    int named = 0;
    for (int fd = 0; fd < FDG_MAX_FD && named < FDG_NAMED; fd++) {
        if (!fdg_has(after, fd) || fdg_has(before, fd)) continue;
        char path[FDG_PATH_MAX];
        const char *what = fdg_name(fd, path, sizeof(path));
        n = snprintf(msg + off, msgsz - off, "%s fd %d%s%s",
                     named == 0 ? ":" : ",", fd,
                     what[0] ? " -> " : "", what);
        if (n < 0) break;
        off += (size_t)n < msgsz - off ? (size_t)n : msgsz - off - 1;
        named++;
        if (off >= msgsz - 1) break;
    }
    return delta;
}

#endif /* SLOTH_TESTS_FD_GUARD_H */
