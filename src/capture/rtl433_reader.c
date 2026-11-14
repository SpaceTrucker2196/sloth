#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rtl433.h"
#include "capture/capture.h"     /* capture_run_flag_t */
#include "capture/rtl433_reader.h"
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in rtl433_reader.h. */

#define RTL433_SLICE_MS 200      /* stop is noticed within this */

static char               g_path[256];
static int                g_configured;
static pthread_t          g_thread;
static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
/* Where the reader is. `known` once any poll has run: before that the
 * first open seeks to the end; after a poll that found no file, the
 * file that appears is read from 0 (ino 0 never names a file). */
static struct { int known; dev_t dev; ino_t ino; off_t off; } g_at;
/* A line not yet ended, and whether the line being read is already
 * over RTL433_MAX_LINE (skipped to its newline, counted once). */
static char   g_part[RTL433_MAX_LINE + 1];
static size_t g_part_n;
static int    g_skip;
/* Worker-owned (or the test's, with no worker). Static, off its stack. */
static char   g_buf[RTL433_POLL_BYTES];

int rtl433_reader_configure(const char *spec, char *err, size_t errsz) {
    if (rtl433_spec_parse(spec, g_path, sizeof(g_path), err, errsz) != 0)
        return -1;
    char label[48];
    snprintf(label, sizeof(label), "file:%.42s", g_path);
    rtl433_set_source(label);
    memset(&g_at, 0, sizeof(g_at));
    g_part_n = 0;
    g_skip = 0;
    g_configured = 1;
    return 0;
}

int rtl433_reader_configured(void) { return g_configured; }

static void restart(void) {
    g_at.off = 0;
    g_part_n = 0;
    g_skip = 0;
}

/* Bytes into lines: each complete one to rtl433_feed_line(), the tail
 * kept in g_part. */
static void take(const char *b, size_t n, time_t wall) {
    size_t i = 0;
    while (i < n) {
        const char *nl = memchr(b + i, '\n', n - i);
        size_t seg = nl ? (size_t)(nl - (b + i)) : n - i;
        if (!g_skip) {
            if (g_part_n + seg > RTL433_MAX_LINE) {
                g_skip = 1;
                g_part_n = 0;
                rtl433_note_bad_line();
            } else {
                memcpy(g_part + g_part_n, b + i, seg);
                g_part_n += seg;
            }
        }
        i += seg;
        if (!nl) break;
        i++;                                     /* the '\n' */
        if (!g_skip) rtl433_feed_line(g_part, g_part_n, wall);
        g_part_n = 0;
        g_skip = 0;
    }
}

long rtl433_reader_poll_once(time_t wall) {
    if (!g_configured) return -1;
    /* O_NONBLOCK: a FIFO put at the path must not hang the worker; it is
     * refused below as not a regular file. */
    int fd = open(g_path, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        if (e == ENOENT) {
            /* Not there (yet): the next file at the path is new. */
            g_at.known = 1;
            g_at.ino = 0;
            restart();
            rtl433_note_missing();
            return -1;
        }
        char why[96];
        snprintf(why, sizeof(why), "open: %s", strerror(e));
        rtl433_note_read_error(why);
        return -1;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        char why[96];
        snprintf(why, sizeof(why), "fstat: %s", strerror(errno));
        close(fd);
        rtl433_note_read_error(why);
        return -1;
    }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        rtl433_note_read_error("not a regular file");
        return -1;
    }
    int rotated = 0, truncated = 0;
    if (!g_at.known) {
        /* The first look: what is already there was written before this
         * run, and is not replayed. */
        g_at.known = 1;
        g_at.dev = sb.st_dev;
        g_at.ino = sb.st_ino;
        g_at.off = sb.st_size;
        g_part_n = 0;
        g_skip = 0;
    } else if (g_at.ino != sb.st_ino || g_at.dev != sb.st_dev) {
        rotated = g_at.ino != 0;     /* not a rotation: the first file */
        g_at.dev = sb.st_dev;
        g_at.ino = sb.st_ino;
        restart();
    } else if (sb.st_size < g_at.off) {
        truncated = 1;               /* copytruncate */
        restart();
    }
    long got = 0;
    if (sb.st_size > g_at.off) {
        size_t want = (size_t)(sb.st_size - g_at.off);
        if (want > sizeof(g_buf)) want = sizeof(g_buf);
        ssize_t r;
        do {
            r = pread(fd, g_buf, want, g_at.off);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            char why[96];
            snprintf(why, sizeof(why), "read: %s", strerror(errno));
            close(fd);
            rtl433_note_read_error(why);
            return -1;
        }
        g_at.off += r;
        got = (long)r;
        take(g_buf, (size_t)r, wall);
    }
    close(fd);
    rtl433_note_read(wall, (uint64_t)got, rotated, truncated);
    return got;
}

static void *rtl433_reader_thread(void *arg) {
    (void)arg;
    while (capture_run_flag_get(&g_running)) {
        rtl433_reader_poll_once(sloth_wall());
        for (int i = 0; i < RTL433_POLL_MS / RTL433_SLICE_MS; i++) {
            if (!capture_run_flag_get(&g_running)) break;
            struct timespec ts = { 0, RTL433_SLICE_MS * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

void rtl433_reader_run(void) {
    if (!g_configured || capture_run_flag_get(&g_running)) return;
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, rtl433_reader_thread, NULL) != 0) {
        capture_run_flag_set(&g_running, 0);
        rtl433_note_read_error("worker thread not started");
    }
}

void rtl433_reader_stop(void) {
    if (capture_run_flag_take(&g_running))
        pthread_join(g_thread, NULL);
    g_configured = 0;
    memset(&g_at, 0, sizeof(g_at));
    g_part_n = 0;
    g_skip = 0;
}
