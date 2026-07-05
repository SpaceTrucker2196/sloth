#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "event_wake.h"

static int g_rfd = -1;
static int g_wfd = -1;

int event_wake_init(void) {
    if (g_rfd >= 0) return 0;
    int fds[2];
    if (pipe(fds) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl >= 0) fcntl(fds[i], F_SETFL, fl | O_NONBLOCK);
        int fdfl = fcntl(fds[i], F_GETFD, 0);
        if (fdfl >= 0) fcntl(fds[i], F_SETFD, fdfl | FD_CLOEXEC);
    }
    g_rfd = fds[0];
    g_wfd = fds[1];
    return 0;
}

int event_wake_fd(void) {
    return g_rfd;
}

void event_wake_signal(void) {
    if (g_wfd < 0) return;
    /* One byte is enough — the reader drains until the pipe is empty.
     * EAGAIN is fine: the pipe is full, which means at least one
     * wake is already pending. */
    char b = 0;
    ssize_t r;
    do {
        r = write(g_wfd, &b, 1);
    } while (r < 0 && errno == EINTR);
}

void event_wake_drain(void) {
    if (g_rfd < 0) return;
    char buf[64];
    for (;;) {
        ssize_t r = read(g_rfd, buf, sizeof(buf));
        if (r <= 0) break;
    }
}
