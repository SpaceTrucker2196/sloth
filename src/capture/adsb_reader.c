#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "adsb.h"
#include "capture/capture.h"     /* capture_run_flag_t */
#include "capture/adsb_reader.h"
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in adsb_reader.h. */

#define ADSB_SLICE_MS 200        /* stop is noticed within this */

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
    if (adsb_spec_parse(spec, g_path, sizeof(g_path), err, errsz) != 0)
        return -1;
    char label[48];
    snprintf(label, sizeof(label), "file:%.42s", g_path);
    adsb_set_source(label);
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
    if (!g_configured) return -1;
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

static void *adsb_reader_thread(void *arg) {
    (void)arg;
    while (capture_run_flag_get(&g_running)) {
        adsb_reader_poll_once(sloth_wall(), sloth_mono_ms());
        for (int i = 0; i < ADSB_POLL_MS / ADSB_SLICE_MS; i++) {
            if (!capture_run_flag_get(&g_running)) break;
            struct timespec ts = { 0, ADSB_SLICE_MS * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
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
}
