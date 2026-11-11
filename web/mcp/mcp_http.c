#include "mcp_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ":PORT" or nothing at p: the port (8770 when absent), or -1. */
static int port_at(const char *p) {
    if (!*p || !strcmp(p, "/")) return 8770;
    if (*p != ':') return -1;
    p++;
    long v = 0;
    int n = 0;
    while (*p >= '0' && *p <= '9' && n < 5) { v = v * 10 + (*p++ - '0'); n++; }
    if (n == 0 || v < 1 || v > 65535) return -1;
    if (*p && strcmp(p, "/")) return -1;
    return (int)v;
}

int mcp_addr_parse(mcp_addr_t *a, const char *url, int allow_remote, const char **why) {
    memset(a, 0, sizeof(*a));
    *why = "bad_url";
    if (!url || strncmp(url, "http://", 7) != 0) return -1;
    const char *h = url + 7;
    char lit[MCP_HOST_MAX];
    const char *rest;
    if (*h == '[') {
        const char *e = strchr(h, ']');
        if (!e || e == h + 1 || (size_t)(e - h - 1) >= sizeof(lit)) return -1;
        memcpy(lit, h + 1, (size_t)(e - h - 1));
        lit[e - h - 1] = '\0';
        if (inet_pton(AF_INET6, lit, a->addr) != 1) return -1;
        a->family = AF_INET6;
        rest = e + 1;
        static const unsigned char one[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        a->loopback = memcmp(a->addr, one, 16) == 0;
    } else {
        size_t n = strcspn(h, ":/");
        if (n == 0 || n >= sizeof(lit)) return -1;
        memcpy(lit, h, n);
        lit[n] = '\0';
        /* Digits and dots only: inet_pton takes nothing else, and a
         * name ("localhost" too) is not resolved here. */
        if (strspn(lit, "0123456789.") != n || inet_pton(AF_INET, lit, a->addr) != 1) return -1;
        a->family = AF_INET;
        rest = h + n;
        a->loopback = a->addr[0] == 127;
    }
    a->port = port_at(rest);
    if (a->port < 0) return -1;
    if (!a->loopback && !allow_remote) { *why = "not_loopback"; return -1; }
    snprintf(a->host, sizeof(a->host), a->family == AF_INET6 ? "[%s]:%d" : "%s:%d", lit, a->port);
    *why = NULL;
    return 0;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait for fd to be ready for events until the deadline: 1, or 0. */
static int wait_fd(int fd, short events, long long deadline) {
    for (;;) {
        long long left = deadline - mono_ms();
        if (left <= 0) return 0;
        struct pollfd p = { fd, events, 0 };
        int r = poll(&p, 1, left > 1000 ? 1000 : (int)left);
        if (r > 0) return 1;
        if (r < 0 && errno != EINTR) return 0;
    }
}

int mcp_http_xfer(void *ctx, const char *req, size_t len, char *resp, size_t cap, size_t *got) {
    const mcp_addr_t *a = ctx;
    *got = 0;
    if (cap) resp[0] = '\0';
    int fd = socket(a->family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    if (a->family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons((unsigned short)a->port);
        memcpy(&s6->sin6_addr, a->addr, 16);
        sl = sizeof(*s6);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons((unsigned short)a->port);
        memcpy(&s4->sin_addr, a->addr, 4);
        sl = sizeof(*s4);
    }
    long long t0 = mono_ms(), deadline = t0 + MCP_HTTP_TOTAL_MS;
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (errno != EINPROGRESS || !wait_fd(fd, POLLOUT, t0 + MCP_HTTP_CONNECT_MS) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, req + off, len - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) &&
            wait_fd(fd, POLLOUT, deadline))
            continue;
        close(fd);
        return -2;
    }
    size_t n = 0;
    int rc = 0;
    for (;;) {
        if (n + 1 >= cap) { rc = -3; break; }
        ssize_t r = recv(fd, resp + n, cap - 1 - n, 0);
        if (r > 0) { n += (size_t)r; continue; }
        if (r == 0) break;
        if ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) && wait_fd(fd, POLLIN, deadline))
            continue;
        /* A reset after the answer was written (slothweb closes at once
         * on a 413) still leaves the answer read. */
        rc = n ? 0 : -2;
        break;
    }
    close(fd);
    resp[n] = '\0';
    *got = n;
    return rc;
}

/* The value of header `name` (lower case, with its colon) in the block
 * [h, end), OWS trimmed, into out; 1 or 0. */
static int header(const char *h, const char *end, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name);
    while (h < end) {
        const char *eol = memchr(h, '\n', (size_t)(end - h));
        if (!eol) eol = end;
        if ((size_t)(eol - h) > nl && strncasecmp(h, name, nl) == 0) {
            const char *v = h + nl, *e = eol;
            while (v < e && (*v == ' ' || *v == '\t')) v++;
            while (e > v && (e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) e--;
            if ((size_t)(e - v) >= cap) return 0;
            memcpy(out, v, (size_t)(e - v));
            out[e - v] = '\0';
            return 1;
        }
        h = eol + 1;
    }
    return 0;
}

int mcp_http_parse(const char *resp, size_t len, mcp_resp_t *out) {
    memset(out, 0, sizeof(*out));
    out->retry_after = -1;
    if (len < 12 || memcmp(resp, "HTTP/1.", 7) != 0 || resp[8] != ' ') return -1;
    int st = 0;
    for (int i = 9; i < 12; i++) {
        if (resp[i] < '0' || resp[i] > '9') return -1;
        st = st * 10 + (resp[i] - '0');
    }
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (!memcmp(resp + i, "\r\n\r\n", 4)) { end = resp + i; break; }
    if (!end) return -1;
    out->status = st;
    out->body = end + 4;
    out->body_len = len - (size_t)(out->body - resp);
    char v[64];
    if (header(resp, end, "content-length:", v, sizeof(v))) {
        size_t cl = 0, d = 0;
        for (; v[d] >= '0' && v[d] <= '9' && d < 9; d++) cl = cl * 10 + (size_t)(v[d] - '0');
        if (d == 0 || v[d] != '\0' || cl != out->body_len) return -1;
    }
    if (header(resp, end, "retry-after:", v, sizeof(v))) {
        int ra = 0, d = 0;
        for (; v[d] >= '0' && v[d] <= '9' && d < 6; d++) ra = ra * 10 + (v[d] - '0');
        if (d > 0 && v[d] == '\0') out->retry_after = ra;
    }
    if (header(resp, end, "content-type:", v, sizeof(v)))
        out->json = strncasecmp(v, "application/json", 16) == 0;
    return 0;
}
