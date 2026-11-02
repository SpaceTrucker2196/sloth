#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "gps.h"
#include "capture/capture.h"     /* capture_run_flag_t */
#include "capture/gps_reader.h"
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in gps_reader.h. */

#define GPS_POLL_MS      200
#define GPS_BACKOFF_MIN  2
#define GPS_BACKOFF_MAX  30
#define GPS_CONNECT_MS   3000

static gps_spec_t         g_spec;
static int                g_configured;
static int                g_baud = 9600;
static int                g_fd = -1;       /* serial: opened pre-drop */
static pthread_t          g_thread;
static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
static gps_lines_t        g_lines;        /* the worker's alone */

int gps_reader_baud_ok(int baud) {
    return baud == 4800 || baud == 9600 || baud == 19200 ||
           baud == 38400 || baud == 57600 || baud == 115200;
}

static speed_t baud_const(int baud) {
    switch (baud) {
    case 4800:   return B4800;
    case 19200:  return B19200;
    case 38400:  return B38400;
    case 57600:  return B57600;
    case 115200: return B115200;
    default:     return B9600;
    }
}

static void set_err(const char *what, int e) {
    char why[96];
    snprintf(why, sizeof(why), "%s: %s", what, strerror(e));
    gps_location_set_err(why);
}

/* Open the serial device read-only and put it in raw mode. Nothing is
 * written to it. A FIFO is accepted too (a stream piped in by the
 * operator); termios is skipped for it. It is treated as live: a fix is
 * stamped with the time it is read, never the NMEA UTC fields, so a
 * recorded track replayed here stamps as if the sensor were there now
 * (docs/wiki/location.md). */
static int serial_open(char *err, size_t errsz) {
    int fd = open(g_spec.path, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (err && errsz) snprintf(err, errsz, "%s: %s", g_spec.path, strerror(errno));
        return -1;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || !(S_ISCHR(sb.st_mode) || S_ISFIFO(sb.st_mode))) {
        if (err && errsz)
            snprintf(err, errsz, "%s: not a character device or FIFO", g_spec.path);
        close(fd);
        return -1;
    }
    if (isatty(fd)) {
        struct termios t;
        if (tcgetattr(fd, &t) == 0) {
            cfmakeraw(&t);
            t.c_cflag |= CREAD | CLOCAL;
            cfsetispeed(&t, baud_const(g_baud));
            cfsetospeed(&t, baud_const(g_baud));
            if (tcsetattr(fd, TCSANOW, &t) != 0) {
                if (err && errsz)
                    snprintf(err, errsz, "%s: tcsetattr: %s", g_spec.path, strerror(errno));
                close(fd);
                return -1;
            }
        }
    }
    return fd;
}

int gps_reader_configure(const char *spec, int allow_remote, int baud,
                         char *err, size_t errsz) {
    if (gps_spec_parse(spec, &g_spec, err, errsz) != 0) return -1;
    if (gps_spec_is_remote(&g_spec) && !allow_remote) {
        if (err && errsz)
            snprintf(err, errsz, "gpsd at %s is not loopback; pass "
                     "--gps-allow-remote to read a remote gpsd", g_spec.host);
        return -1;
    }
    if (baud) {
        if (!gps_reader_baud_ok(baud)) {
            if (err && errsz) snprintf(err, errsz, "unsupported baud %d", baud);
            return -1;
        }
        g_baud = baud;
    }
    if (g_spec.kind == GPS_SPEC_SERIAL) {
        g_fd = serial_open(err, errsz);
        if (g_fd < 0) return -1;
    }
    char label[48];
    gps_spec_label(&g_spec, label, sizeof(label));
    gps_location_set_gps(label);
    g_configured = 1;
    return 0;
}

int gps_reader_configured(void) { return g_configured; }

/* Non-blocking connect bounded by GPS_CONNECT_MS, then the one ?WATCH
 * line. -1 with the error published. */
static int gpsd_connect(void) {
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    int fam;
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
    if (fd < 0) { set_err("socket", errno); return -1; }
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        if (errno != EINPROGRESS) { set_err("connect", errno); close(fd); return -1; }
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int r = poll(&pfd, 1, GPS_CONNECT_MS);
        int soerr = 0;
        socklen_t el = sizeof(soerr);
        if (r <= 0) { set_err("connect", r == 0 ? ETIMEDOUT : errno); close(fd); return -1; }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &el) != 0 || soerr) {
            set_err("connect", soerr ? soerr : errno);
            close(fd);
            return -1;
        }
    }
    static const char watch[] = "?WATCH={\"enable\":true,\"json\":true}\n";
    size_t off = 0;
    while (off < sizeof(watch) - 1) {
        ssize_t w = send(fd, watch + off, sizeof(watch) - 1 - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                struct pollfd pfd = { fd, POLLOUT, 0 };
                if (poll(&pfd, 1, GPS_CONNECT_MS) > 0) continue;
            }
            set_err("send ?WATCH", errno ? errno : ETIMEDOUT);
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    return fd;
}

/* Sleep up to `secs` in GPS_POLL_MS slices, returning early on stop. */
static void backoff_wait(int secs) {
    for (int i = 0; i < secs * (1000 / GPS_POLL_MS); i++) {
        if (!capture_run_flag_get(&g_running)) return;
        struct timespec ts = { 0, GPS_POLL_MS * 1000000L };
        nanosleep(&ts, NULL);
    }
}

static void *gps_reader_thread(void *arg) {
    (void)arg;
    int kind = g_spec.kind == GPS_SPEC_SERIAL ? GPS_FEED_NMEA : GPS_FEED_GPSD;
    int fd = g_fd;
    g_fd = -1;
    int backoff = GPS_BACKOFF_MIN;
    static uint8_t buf[2048];
    while (capture_run_flag_get(&g_running)) {
        if (fd < 0) {
            char err[96] = "";
            if (kind == GPS_FEED_NMEA) {
                fd = serial_open(err, sizeof(err));
                if (fd < 0) gps_location_set_err(err);
            } else {
                fd = gpsd_connect();
            }
            /* A failed attempt is not a reconnect: a gpsd that was never
             * reachable must not read as a flapping one. It shows in
             * gps_err; gps_reconnects counts sessions lost below. */
            if (fd < 0) {
                backoff_wait(backoff);
                backoff = backoff * 2 > GPS_BACKOFF_MAX ? GPS_BACKOFF_MAX : backoff * 2;
                continue;
            }
            gps_location_set_err("");
            backoff = GPS_BACKOFF_MIN;
        }
        gps_lines_init(&g_lines, kind);
        while (capture_run_flag_get(&g_running)) {
            struct pollfd pfd = { fd, POLLIN, 0 };
            int r = poll(&pfd, 1, GPS_POLL_MS);
            if (r < 0) {
                if (errno == EINTR) continue;
                set_err("poll", errno);
                break;
            }
            if (r == 0) continue;
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;
                set_err("read", errno);
                break;
            }
            if (n == 0) {
                gps_location_set_err(kind == GPS_FEED_NMEA ? "device closed"
                                                           : "gpsd closed the connection");
                break;
            }
            gps_lines_feed(&g_lines, buf, (size_t)n, sloth_wall());
        }
        close(fd);
        fd = -1;
        if (capture_run_flag_get(&g_running)) {
            gps_location_note(0, 0, 0, 1);   /* an open session was lost */
            backoff_wait(backoff);
        }
    }
    if (fd >= 0) close(fd);
    return NULL;
}

void gps_reader_run(void) {
    if (!g_configured || capture_run_flag_get(&g_running)) return;
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, gps_reader_thread, NULL) != 0) {
        capture_run_flag_set(&g_running, 0);
        gps_location_set_err("worker thread not started");
    }
}

void gps_reader_stop(void) {
    if (capture_run_flag_take(&g_running))
        pthread_join(g_thread, NULL);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    g_configured = 0;
}
