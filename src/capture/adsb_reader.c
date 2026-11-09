#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "adsb.h"
#include "capture/capture.h"     /* capture_run_flag_t */
#include "capture/adsb_reader.h"
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in adsb_reader.h. */

#define ADSB_SLICE_MS 200        /* stop is noticed within this */
#define SBS_BACKOFF_MIN 2        /* s; doubled per failed connect */
#define SBS_BACKOFF_MAX 30
#define SBS_CONNECT_MS  3000

static adsb_spec_t        g_spec;
static char               g_path[256];
static int                g_configured;
static pthread_t          g_thread;
static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
/* The last good read's identity: unchanged means not re-parsed. */
static struct { int valid; dev_t dev; ino_t ino; off_t size;
                time_t mtime; long mtime_ns; } g_last;
/* Worker-owned (or the test's, with no worker): one document and one
 * file at a time. Static, off the worker's stack. */
static char       g_buf[ADSB_MAX_DOC + 1];
static adsb_doc_t g_doc;

int adsb_reader_configure(const char *spec, char *err, size_t errsz) {
    if (adsb_spec_parse(spec, &g_spec, err, errsz) != 0)
        return -1;
    char label[48];
    adsb_spec_label(&g_spec, label, sizeof(label));
    if (g_spec.kind == ADSB_SPEC_SBS) {
        g_path[0] = '\0';
        adsb_set_source_sbs(label);
    } else {
        snprintf(g_path, sizeof(g_path), "%s", g_spec.path);
        adsb_set_source(label);
    }
    memset(&g_last, 0, sizeof(g_last));
    g_configured = 1;
    return 0;
}

int adsb_reader_configured(void) { return g_configured; }

static int fail(const char *what, int e) {
    char why[96];
    snprintf(why, sizeof(why), "%s: %s", what, strerror(e));
    adsb_note_read_error(why);
    g_last.valid = 0;
    return -1;
}

int adsb_reader_poll_once(time_t wall, uint64_t mono_ms) {
    if (!g_configured || g_spec.kind != ADSB_SPEC_FILE) return -1;
    /* O_NONBLOCK: a FIFO put at the path must not hang the worker; it is
     * refused below as not a regular file. */
    int fd = open(g_path, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return fail("open", errno);
    struct stat sb;
    if (fstat(fd, &sb) != 0) { int e = errno; close(fd); return fail("fstat", e); }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        adsb_note_read_error("not a regular file");
        g_last.valid = 0;
        return -1;
    }
    if (sb.st_size < 0 || (uint64_t)sb.st_size > ADSB_MAX_DOC) {
        close(fd);
        char why[96];
        snprintf(why, sizeof(why), "file over %u bytes", (unsigned)ADSB_MAX_DOC);
        adsb_note_read_error(why);
        g_last.valid = 0;
        return -1;
    }
    if (g_last.valid && g_last.dev == sb.st_dev && g_last.ino == sb.st_ino &&
        g_last.size == sb.st_size && g_last.mtime == sb.st_mtim.tv_sec &&
        g_last.mtime_ns == sb.st_mtim.tv_nsec) {
        close(fd);
        return 0;
    }
    /* Read to EOF, not to st_size: the decoder replaces the file by
     * rename, so this inode does not change under the read, but a file
     * written in place by some other tool could; reading one byte past
     * the cap is how an over-cap file is still caught. */
    size_t len = 0;
    for (;;) {
        ssize_t r = read(fd, g_buf + len, ADSB_MAX_DOC + 1 - len);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            return fail("read", e);
        }
        if (r == 0) break;
        len += (size_t)r;
        if (len > ADSB_MAX_DOC) {
            close(fd);
            char why[96];
            snprintf(why, sizeof(why), "file over %u bytes", (unsigned)ADSB_MAX_DOC);
            adsb_note_read_error(why);
            g_last.valid = 0;
            return -1;
        }
    }
    close(fd);
    if (adsb_doc_parse(g_buf, len, &g_doc) != 0) {
        adsb_note_parse_error(len ? "malformed aircraft.json" : "empty file");
        /* Remember it anyway: the same broken file is one parse error,
         * not one a second. */
        g_last.valid = 1;
        g_last.dev = sb.st_dev; g_last.ino = sb.st_ino; g_last.size = sb.st_size;
        g_last.mtime = sb.st_mtim.tv_sec; g_last.mtime_ns = sb.st_mtim.tv_nsec;
        return -1;
    }
    double stamp = (double)sb.st_mtim.tv_sec + sb.st_mtim.tv_nsec / 1e9;
    adsb_feed_doc(&g_doc, stamp, wall, mono_ms);
    g_last.valid = 1;
    g_last.dev = sb.st_dev; g_last.ino = sb.st_ino; g_last.size = sb.st_size;
    g_last.mtime = sb.st_mtim.tv_sec; g_last.mtime_ns = sb.st_mtim.tv_nsec;
    return 1;
}

/* Sleep up to `ms` in ADSB_SLICE_MS slices, returning early on stop. */
static void nap(int ms) {
    for (int i = 0; i < ms / ADSB_SLICE_MS; i++) {
        if (!capture_run_flag_get(&g_running)) return;
        struct timespec ts = { 0, ADSB_SLICE_MS * 1000000L };
        nanosleep(&ts, NULL);
    }
}

static void *adsb_file_thread(void) {
    while (capture_run_flag_get(&g_running)) {
        adsb_reader_poll_once(sloth_wall(), sloth_mono_ms());
        nap(ADSB_POLL_MS);
    }
    return NULL;
}

/* ── sbs:// ────────────────────────────────────────────────────────
 * A TCP client that only reads. connect() is the one thing sent (the
 * handshake); no send(), write() or shutdown() is ever called on the
 * socket, and the decoder's SBS output ignores what a client sends
 * anyway (readsb: READ_MODE_IGNORE). */

static void sbs_err(const char *what, int e) {
    char why[96];
    snprintf(why, sizeof(why), "%s: %s", what, strerror(e));
    adsb_note_read_error(why);
}

/* Non-blocking connect bounded by SBS_CONNECT_MS. -1 with the error
 * counted. */
static int sbs_connect(void) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int fam;
    memset(&ss, 0, sizeof(ss));
    if (strchr(g_spec.host, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)g_spec.port);
        if (inet_pton(AF_INET6, g_spec.host, &a->sin6_addr) != 1) return -1;
        sl = sizeof(*a);
        fam = AF_INET6;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)g_spec.port);
        if (inet_pton(AF_INET, g_spec.host, &a->sin_addr) != 1) return -1;
        sl = sizeof(*a);
        fam = AF_INET;
    }
    int fd = socket(fam, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { sbs_err("socket", errno); return -1; }
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        if (errno != EINPROGRESS) { sbs_err("connect", errno); close(fd); return -1; }
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int r = poll(&pfd, 1, SBS_CONNECT_MS);
        int soerr = 0;
        socklen_t el = sizeof(soerr);
        if (r <= 0) { sbs_err("connect", r == 0 ? ETIMEDOUT : errno); close(fd); return -1; }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &el) != 0 || soerr) {
            sbs_err("connect", soerr ? soerr : errno);
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void *adsb_sbs_thread(void) {
    static adsb_sbs_lines_t lines;   /* the worker's alone */
    static uint8_t buf[4096];
    int backoff = SBS_BACKOFF_MIN;
    while (capture_run_flag_get(&g_running)) {
        int fd = sbs_connect();
        if (fd < 0) {
            nap(backoff * 1000);
            backoff = backoff * 2 > SBS_BACKOFF_MAX ? SBS_BACKOFF_MAX : backoff * 2;
            continue;
        }
        adsb_note_connected();
        backoff = SBS_BACKOFF_MIN;
        adsb_sbs_lines_init(&lines);
        while (capture_run_flag_get(&g_running)) {
            struct pollfd pfd = { fd, POLLIN, 0 };
            int r = poll(&pfd, 1, ADSB_SLICE_MS);
            if (r < 0) {
                if (errno == EINTR) continue;
                sbs_err("poll", errno);
                break;
            }
            if (r == 0) continue;
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;
                sbs_err("read", errno);
                break;
            }
            if (n == 0) {
                adsb_note_read_error("decoder closed the connection");
                break;
            }
            adsb_sbs_lines_feed(&lines, buf, (size_t)n, sloth_wall_ms(),
                                sloth_mono_ms());
        }
        close(fd);
        /* A session that ended is retried after the shortest wait: the
         * decoder restarting is the common case. The rows stand until
         * they expire, as they do when aircraft.json goes missing. */
        nap(backoff * 1000);
    }
    return NULL;
}

static void *adsb_reader_thread(void *arg) {
    (void)arg;
    return g_spec.kind == ADSB_SPEC_SBS ? adsb_sbs_thread() : adsb_file_thread();
}

void adsb_reader_run(void) {
    if (!g_configured || capture_run_flag_get(&g_running)) return;
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, adsb_reader_thread, NULL) != 0) {
        capture_run_flag_set(&g_running, 0);
        adsb_note_read_error("worker thread not started");
    }
}

void adsb_reader_stop(void) {
    if (capture_run_flag_take(&g_running))
        pthread_join(g_thread, NULL);
    g_configured = 0;
    memset(&g_last, 0, sizeof(g_last));
    memset(&g_spec, 0, sizeof(g_spec));
}
