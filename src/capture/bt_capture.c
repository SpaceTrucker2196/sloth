#ifdef WITH_PCAP

#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sloth.h"
#include "bt_stream.h"
#include "capture/bt_capture.h"
#include "capture/capture.h"     /* capture_run_flag_t */
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in bt_capture.h. The worker owns the descriptor and the
 * framer; everything it learns is published through src/bt_stream.c. */

#define BTCAP_POLL_MS 100

static char               g_path[BT_CAPTURE_PATH_MAX];
static int                g_configured;
static pthread_t          g_thread;
static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
static bt_stream_t        g_stream;   /* the worker's alone while it runs */

static int type_ok(mode_t m) { return S_ISREG(m) || S_ISFIFO(m); }

int bt_capture_configure(const char *path, char *err, size_t errsz) {
    struct stat sb;
    if (!path || !path[0] || strlen(path) >= sizeof(g_path)) {
        if (err && errsz) snprintf(err, errsz, "path empty or too long");
        return -1;
    }
    /* stat, not open: opening a FIFO here would block startup until a
     * writer appeared, and a second open later would be the reopen the
     * contract rules out. */
    if (stat(path, &sb) != 0) {
        if (err && errsz) snprintf(err, errsz, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (!type_ok(sb.st_mode)) {
        if (err && errsz)
            snprintf(err, errsz, "%s: not a regular file or FIFO", path);
        return -1;
    }
    snprintf(g_path, sizeof(g_path), "%s", path);
    g_configured = 1;
    bt_stream_configure();
    return 0;
}

static void fail(const char *what, int e) {
    char why[96];
    snprintf(why, sizeof(why), "%s: %s", what, strerror(e));
    bt_stream_set_state(BT_CAP_ERROR, why);
}

static void *bt_capture_thread(void *arg) {
    (void)arg;
    bt_stream_init(&g_stream);
    /* The one open. O_NONBLOCK so a FIFO with no writer yet does not
     * block here either: poll() below waits for the first data. */
    int fd = open(g_path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) { fail("open", errno); return NULL; }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || !type_ok(sb.st_mode)) {
        /* Swapped for something else since the startup check. */
        bt_stream_set_state(BT_CAP_ERROR, "not a regular file or FIFO");
        close(fd);
        return NULL;
    }
    static uint8_t buf[4096];
    int end_state = BT_CAP_STOPPED;
    while (capture_run_flag_get(&g_running)) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int r = poll(&pfd, 1, BTCAP_POLL_MS);
        if (r < 0) {
            if (errno == EINTR) continue;
            fail("poll", errno);
            end_state = -1;
            break;
        }
        if (r == 0) continue;
        /* Linux reports POLLHUP on a FIFO only once a writer has come
         * and gone, so before the first writer this waits rather than
         * reading the 0 a writerless FIFO returns. */
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            fail("read", errno);
            end_state = -1;
            break;
        }
        if (n == 0) { end_state = BT_CAP_EOF; break; }
        if (!bt_stream_feed(&g_stream, buf, (size_t)n, sloth_wall())) {
            end_state = -1;   /* refused or corrupt: already published */
            break;
        }
    }
    close(fd);
    if (end_state >= 0) bt_stream_set_state(end_state, NULL);
    return NULL;
}

void bt_capture_run(void) {
    if (!g_configured || capture_run_flag_get(&g_running)) return;
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, bt_capture_thread, NULL) != 0) {
        capture_run_flag_set(&g_running, 0);
        bt_stream_set_state(BT_CAP_ERROR, "worker thread not started");
    }
}

void bt_capture_stop(void) {
    if (capture_run_flag_take(&g_running))
        pthread_join(g_thread, NULL);
}

#endif /* WITH_PCAP */
