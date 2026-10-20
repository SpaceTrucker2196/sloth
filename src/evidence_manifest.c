#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "evidence_manifest.h"
#include "secure_file.h"
#include "sha256.h"
#include "sloth_clock.h"

/* See the header for the format and the design. Everything here runs
 * under g_mu: callers are the capture thread (handshake and hashcat
 * writes, inside the EAPOL module's own lock) and the poll thread (both
 * alert pcaps). Lock order is caller's lock, then g_mu; nothing here
 * calls back out, so the order cannot invert. */

/* One open manifest per directory this session has written into. Four
 * is two sinks with headroom: --pcap-dir and --eapol-dir are the only
 * directories in production, but a directory can be re-pinned at run
 * time and the suite pins hundreds; the least recently used is closed
 * to make room, and reopened under a fresh -N name if it is written to
 * again. */
#define EVM_SLOTS 4
#define EVM_NAME_MAX (EVM_SESSION_MAX + 32)
#define EVM_UNIQUE_MAX 16

typedef struct {
    int      used;
    dev_t    dev;
    ino_t    ino;
    int      fd;
    uint64_t seq;          /* lines written to this manifest          */
    uint64_t touched;      /* LRU stamp                                */
    char     name[EVM_NAME_MAX];
} evm_slot_t;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static evm_slot_t      g_slots[EVM_SLOTS];
static uint64_t        g_clock;            /* LRU counter, not time   */
static char            g_session[EVM_SESSION_MAX];
static int             g_force_on;
static uint64_t        g_force_suffix;
static int             g_fail_next;

static const char *const SINK_NAMES[EVM_SINK_COUNT] = {
    "alert_pcap", "evidence_pcap", "handshake_pcap", "hashcat_22000",
};

const char *evidence_manifest_sink_name(evm_sink_t s) {
    return (unsigned)s < (unsigned)EVM_SINK_COUNT ? SINK_NAMES[s] : "unknown";
}

int evidence_manifest_reconstructed(evm_sink_t s) {
    return s == EVM_SINK_HANDSHAKE_PCAP || s == EVM_SINK_HASHCAT_22000;
}

int evidence_manifest_is_name(const char *name) {
    if (!name) return 0;
    size_t n = strlen(name), p = sizeof(EVM_PREFIX) - 1,
           e = sizeof(EVM_EXT) - 1;
    return n > p + e && strncmp(name, EVM_PREFIX, p) == 0 &&
           strcmp(name + n - e, EVM_EXT) == 0;
}

/* 64 bits from the kernel's CSPRNG. Not for secrecy — the suffix only
 * has to differ between two runs that start in the same wall second,
 * which a restarting RTC-less sensor does — but a pid alone does not:
 * two boots can hand the same pid to sloth at the same saved clock.
 * The fallback mixes pid and the monotonic clock; O_EXCL in
 * open_manifest() is what makes a collision harmless either way. */
static uint64_t session_suffix(void) {
    if (g_force_on) return g_force_suffix;
    uint64_t v = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = read(fd, &v, sizeof(v));
        close(fd);
        if (r == (ssize_t)sizeof(v) && v != 0) return v;
    }
    v = ((uint64_t)(unsigned)getpid() << 32) ^ sloth_mono_ms();
    return v ? v : 1;
}

/* Caller holds g_mu. */
static void begin_locked(time_t start) {
    if (g_session[0]) return;
    struct tm tmv;
    struct tm *t = gmtime_r(&start, &tmv);
    snprintf(g_session, sizeof(g_session),
             "%04d%02d%02dT%02d%02d%02dZ-%016llx",
             t ? t->tm_year + 1900 : 1970, t ? t->tm_mon + 1 : 1,
             t ? t->tm_mday : 1, t ? t->tm_hour : 0,
             t ? t->tm_min : 0, t ? t->tm_sec : 0,
             (unsigned long long)session_suffix());
}

void evidence_manifest_session_begin(time_t start) {
    pthread_mutex_lock(&g_mu);
    begin_locked(start);
    pthread_mutex_unlock(&g_mu);
}

void evidence_manifest_session(char *out, size_t outsz) {
    if (!out || !outsz) return;
    pthread_mutex_lock(&g_mu);
    snprintf(out, outsz, "%s", g_session);
    pthread_mutex_unlock(&g_mu);
}

static void close_slot(evm_slot_t *s) {
    if (s->used && s->fd >= 0) close(s->fd);
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}

void evidence_manifest_reset(void) {
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < EVM_SLOTS; i++) close_slot(&g_slots[i]);
    g_session[0] = '\0';
    g_clock = 0;
    g_fail_next = 0;
    g_force_on = 0;
    g_force_suffix = 0;
    pthread_mutex_unlock(&g_mu);
}

void evidence_manifest_test_force_suffix(int on, uint64_t suffix) {
    pthread_mutex_lock(&g_mu);
    g_force_on = on ? 1 : 0;
    g_force_suffix = suffix;
    pthread_mutex_unlock(&g_mu);
}

void evidence_manifest_test_fail_next(void) {
    pthread_mutex_lock(&g_mu);
    g_fail_next = 1;
    pthread_mutex_unlock(&g_mu);
}

static int bare(const char *n) {
    return n && n[0] && strcmp(n, ".") != 0 && strcmp(n, "..") != 0 &&
           strchr(n, '/') == NULL;
}

/* SHA-256 and length of `name` as it is under `dirfd` now. Read through
 * the pinned descriptor with O_NOFOLLOW and refused unless it is a
 * regular file, so what is hashed is the file the sink committed and
 * not whatever a link would lead to. */
static int hash_file(int dirfd, const char *name, char hex[65],
                     uint64_t *size, char *err, size_t errsz) {
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        snprintf(err, errsz, "%s: cannot reopen to hash: %s",
                 name, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errsz, "%s: not a regular file — not hashed", name);
        close(fd);
        return -1;
    }
    sha256_ctx_t c;
    sha256_init(&c);
    uint8_t buf[8192];
    uint64_t total = 0;
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errsz, "%s: read failed while hashing: %s",
                     name, strerror(errno));
            close(fd);
            return -1;
        }
        if (r == 0) break;
        sha256_update(&c, buf, (size_t)r);
        total += (uint64_t)r;
    }
    close(fd);
    uint8_t d[32];
    sha256_final(&c, d);
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 0xf];
    }
    hex[64] = '\0';
    *size = total;
    return 0;
}

/* Create this session's manifest in `dirfd`: "sloth-manifest-<session>
 * .jsonl", then "-2" ... if that is taken. Taken means a session with
 * the same start second and suffix — only a forced or failed random
 * source makes that happen — or this session's own earlier manifest
 * still present after its slot was evicted. Neither is ever appended
 * to: a manifest is one writer's record, created exclusively. */
static int open_manifest(evm_slot_t *s, int dirfd, char *err, size_t errsz) {
    for (int k = 1; k <= EVM_UNIQUE_MAX; k++) {
        char name[EVM_NAME_MAX];
        if (k == 1)
            snprintf(name, sizeof(name), EVM_PREFIX "%s" EVM_EXT, g_session);
        else
            snprintf(name, sizeof(name), EVM_PREFIX "%s-%d" EVM_EXT,
                     g_session, k);
        int fd = sfile_open(dirfd, name, SFILE_EXCL, err, errsz);
        if (fd >= 0) {
            /* The name has to survive a crash as well as the lines. */
            if (fsync(dirfd) != 0) { /* best effort: see eapol commit */ }
            s->fd = fd;
            s->seq = 0;
            snprintf(s->name, sizeof(s->name), "%s", name);
            return 0;
        }
        if (errno != EEXIST) return -1;
    }
    snprintf(err, errsz, "manifest: %d names for session %s already taken",
             EVM_UNIQUE_MAX, g_session);
    return -1;
}

/* Caller holds g_mu. The slot for `dirfd`'s directory, opening a
 * manifest there if this session has none. */
static evm_slot_t *slot_for(int dirfd, char *err, size_t errsz) {
    struct stat dst;
    if (fstat(dirfd, &dst) != 0) {
        snprintf(err, errsz, "manifest: cannot stat directory: %s",
                 strerror(errno));
        return NULL;
    }
    evm_slot_t *s = NULL;
    for (int i = 0; i < EVM_SLOTS; i++)
        if (g_slots[i].used && g_slots[i].dev == dst.st_dev &&
            g_slots[i].ino == dst.st_ino) { s = &g_slots[i]; break; }
    if (s) {
        /* Unlinked under us: the --eapol-dir retention sweep removes a
         * manifest whose last line is older than the window, which
         * means every file it lists is past the window too. Appending
         * to the unlinked inode would lose every later line, so start
         * a fresh manifest instead. */
        struct stat mst;
        if (fstat(s->fd, &mst) == 0 && mst.st_nlink > 0) {
            s->touched = ++g_clock;
            return s;
        }
        close_slot(s);
    } else {
        evm_slot_t *lru = &g_slots[0];
        for (int i = 0; i < EVM_SLOTS; i++) {
            if (!g_slots[i].used) { lru = &g_slots[i]; break; }
            if (g_slots[i].touched < lru->touched) lru = &g_slots[i];
        }
        s = lru;
        close_slot(s);
    }
    if (open_manifest(s, dirfd, err, errsz) != 0) {
        close_slot(s);
        return NULL;
    }
    s->used = 1;
    s->dev = dst.st_dev;
    s->ino = dst.st_ino;
    s->touched = ++g_clock;
    return s;
}

/* JSON string body: the names here are sloth-built ([A-Za-z0-9_.-]),
 * but this is a file format others parse, so escape regardless. */
static size_t json_str(char *out, size_t cap, const char *s) {
    size_t o = 0;
    for (; *s && o + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20)
            o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        else out[o++] = (char)c;
    }
    out[o] = '\0';
    return o;
}

static int pwrite_all(int fd, const char *buf, size_t n, off_t off) {
    while (n > 0) {
        ssize_t w = pwrite(fd, buf, n, off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) { errno = EIO; return -1; }
        buf += w; n -= (size_t)w; off += w;
    }
    return 0;
}

int evidence_manifest_record(int dirfd, const char *name,
                             const evm_meta_t *meta,
                             char *err, size_t errsz) {
    char ebuf[SFILE_ERR_MAX];
    if (!err || !errsz) { err = ebuf; errsz = sizeof(ebuf); }
    err[0] = '\0';
    if (dirfd < 0 || !bare(name) || !meta) {
        snprintf(err, errsz, "manifest: bad arguments");
        return -1;
    }

    char hex[65];
    uint64_t size = 0;
    if (hash_file(dirfd, name, hex, &size, err, errsz) != 0) return -1;

    char fname[160], inc[80], rule[80];
    json_str(fname, sizeof(fname), name);
    json_str(inc,   sizeof(inc),   meta->incident_id ? meta->incident_id : "");
    json_str(rule,  sizeof(rule),  meta->rule ? meta->rule : "");

    pthread_mutex_lock(&g_mu);
    int rc = -1;
    time_t now = sloth_wall();
    begin_locked(now);
    evm_slot_t *s = slot_for(dirfd, err, errsz);
    if (!s) goto out;

    struct tm tmv;
    struct tm *t = gmtime_r(&now, &tmv);
    char line[1024];
    int n = snprintf(line, sizeof(line),
        "{\"v\":1,\"session\":\"%s\",\"seq\":%llu,\"file\":\"%s\","
        "\"size\":%llu,\"sha256\":\"%s\",\"sink\":\"%s\"",
        g_session, (unsigned long long)(s->seq + 1), fname,
        (unsigned long long)size, hex,
        evidence_manifest_sink_name(meta->sink));
    if (inc[0] && n > 0 && (size_t)n < sizeof(line))
        n += snprintf(line + n, sizeof(line) - (size_t)n,
                      ",\"incident_id\":\"%s\"", inc);
    if (rule[0] && n > 0 && (size_t)n < sizeof(line))
        n += snprintf(line + n, sizeof(line) - (size_t)n,
                      ",\"rule\":\"%s\"", rule);
    if (n > 0 && (size_t)n < sizeof(line))
        n += snprintf(line + n, sizeof(line) - (size_t)n,
            ",\"reconstructed\":%s,"
            "\"written_at\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\","
            "\"written_at_epoch\":%lld}\n",
            evidence_manifest_reconstructed(meta->sink) ? "true" : "false",
            t ? t->tm_year + 1900 : 1970, t ? t->tm_mon + 1 : 1,
            t ? t->tm_mday : 1, t ? t->tm_hour : 0,
            t ? t->tm_min : 0, t ? t->tm_sec : 0, (long long)now);
    if (n <= 0 || (size_t)n >= sizeof(line)) {
        snprintf(err, errsz, "%s: manifest line too long", s->name);
        goto out;
    }

    /* Append at the current end, and on any failure cut back to it:
     * a partial line left in place would glue itself to the front of
     * the next good one and make that one unparseable too. */
    struct stat mst;
    if (fstat(s->fd, &mst) != 0) {
        snprintf(err, errsz, "%s: %s", s->name, strerror(errno));
        goto out;
    }
    off_t end = mst.st_size;
    int bad;
    if (g_fail_next) {
        g_fail_next = 0;
        /* Half a line, as a full disk would leave it, so the rollback
         * below is exercised and not only the error report. */
        (void)pwrite_all(s->fd, line, (size_t)n / 2, end);
        errno = ENOSPC;
        bad = 1;
    } else {
        bad = pwrite_all(s->fd, line, (size_t)n, end) != 0;
    }
    if (bad) {
        snprintf(err, errsz, "%s: write failed: %s", s->name, strerror(errno));
        if (ftruncate(s->fd, end) != 0) { /* reported above already */ }
        goto out;
    }
    if (fsync(s->fd) != 0) {
        /* The line may or may not be durable; say so rather than
         * pretend. It stays: it is complete, and it is true. */
        snprintf(err, errsz, "%s: fsync failed: %s", s->name, strerror(errno));
        s->seq++;
        goto out;
    }
    s->seq++;
    rc = 0;
out:
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int evidence_manifest_name(int dirfd, char *out, size_t outsz) {
    if (!out || !outsz) return -1;
    out[0] = '\0';
    struct stat dst;
    if (dirfd < 0 || fstat(dirfd, &dst) != 0) return -1;
    int rc = -1;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < EVM_SLOTS; i++)
        if (g_slots[i].used && g_slots[i].dev == dst.st_dev &&
            g_slots[i].ino == dst.st_ino) {
            snprintf(out, outsz, "%s", g_slots[i].name);
            rc = 0;
            break;
        }
    pthread_mutex_unlock(&g_mu);
    return rc;
}
