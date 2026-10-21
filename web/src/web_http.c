#include "web_http.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* RFC 9110 §5.6.2 tchar. */
static int is_tchar(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return 1;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL && c != '\0';
}

/* One line, without its LF and any CR before it. Returns 0 when the
 * line contains a bare CR or a NUL, which RFC 9112 §2.2 lets a server
 * reject and which have no business in a request we only classify. */
static int line_clean(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\r' || s[i] == '\0') return 0;
    return 1;
}

/* RFC 9112 §3.2: keep the path of an origin-form or absolute-form
 * target, without its query. Asterisk-form and anything else is kept
 * as written; no route matches it. */
static void keep_path(web_req_t *rq, const char *t, size_t n) {
    if (n > 7 && !strncasecmp(t, "http://", 7)) {
        const char *slash = memchr(t + 7, '/', n - 7);
        size_t al = slash ? (size_t)(slash - (t + 7)) : n - 7;
        rq->target_abs = 1;
        if (al >= sizeof(rq->target_host)) rq->target_host_long = 1;
        else {
            memcpy(rq->target_host, t + 7, al);
            rq->target_host[al] = '\0';
        }
        if (!slash) { t = "/"; n = 1; }
        else { n -= (size_t)(slash - t); t = slash; }
    }
    const char *q = memchr(t, '?', n);
    if (q) n = (size_t)(q - t);
    if (n >= sizeof(rq->path)) { rq->path_long = 1; return; }
    memcpy(rq->path, t, n);
    rq->path[n] = '\0';
}

/* RFC 9112 §3: method SP request-target SP HTTP-version. */
static int classify_request_line(const char *s, size_t n, web_req_t *rq) {
    size_t i = 0;
    while (i < n && is_tchar((unsigned char)s[i])) i++;
    size_t mlen = i;
    if (mlen == 0 || i >= n || s[i] != ' ') return 400;
    i++;

    size_t ts = i;
    while (i < n && s[i] > 0x20 && s[i] < 0x7f) i++;
    if (i == ts || i >= n || s[i] != ' ') return 400;
    i++;

    const char *v = s + i;
    size_t vl = n - i;
    if (vl != 8 || memcmp(v, "HTTP/", 5) != 0 ||
        v[5] < '0' || v[5] > '9' || v[6] != '.' || v[7] < '0' || v[7] > '9')
        return 400;
    if (v[5] != '1') return 505;

    /* Methods are case-sensitive (RFC 9110 §9.1): "get" is not GET. */
    int route = 0;
    if (mlen == 3 && !memcmp(s, "GET", 3))  route = 1;
    if (mlen == 4 && !memcmp(s, "HEAD", 4)) { rq->is_head = 1; route = 1; }
    if (!route) return 405;
    keep_path(rq, s + ts, (i - 1) - ts);
    return WEB_HTTP_ROUTE;
}

/* RFC 9112 §5: field-name ":" ... with no whitespace before the colon,
 * and no obs-fold continuation lines. */
static int header_line_ok(const char *s, size_t n) {
    size_t i = 0;
    while (i < n && is_tchar((unsigned char)s[i])) i++;
    return i > 0 && i < n && s[i] == ':';
}

/* RFC 9110 §5.3: several If-None-Match lines are one comma-separated
 * list. Field names are case-insensitive; OWS around the value goes. */
static void keep_inm(web_req_t *rq, const char *s, size_t n) {
    static const char name[] = "if-none-match:";
    size_t nl = sizeof(name) - 1;
    if (n < nl || strncasecmp(s, name, nl) != 0) return;
    const char *v = s + nl;
    size_t vl = n - nl;
    while (vl && (*v == ' ' || *v == '\t')) { v++; vl--; }
    while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
    size_t have = strlen(rq->inm);
    size_t sep = rq->inm_present ? 2 : 0;
    rq->inm_present = 1;
    if (have + sep + vl >= sizeof(rq->inm)) { rq->inm_long = 1; return; }
    if (sep) memcpy(rq->inm + have, ", ", 2);
    memcpy(rq->inm + have + sep, v, vl);
    rq->inm[have + sep + vl] = '\0';
}

/* RFC 9110 §7.2. Only the count and the value are kept; whether the
 * value is acceptable is the router's decision (web_http_host_ok). */
static void keep_host(web_req_t *rq, const char *s, size_t n) {
    static const char name[] = "host:";
    size_t nl = sizeof(name) - 1;
    if (n < nl || strncasecmp(s, name, nl) != 0) return;
    const char *v = s + nl;
    size_t vl = n - nl;
    while (vl && (*v == ' ' || *v == '\t')) { v++; vl--; }
    while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
    if (rq->host_count++ > 0) return;
    if (vl >= sizeof(rq->host)) { rq->host_long = 1; return; }
    memcpy(rq->host, v, vl);
    rq->host[vl] = '\0';
}

/* An optional ":" port of at most five digits, up to 65535; an empty
 * port is allowed (RFC 3986 §3.2.3). */
static int port_ok(const char *p) {
    if (!*p) return 1;
    if (*p++ != ':') return 0;
    size_t n = strlen(p);
    if (n > 5) return 0;
    long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
        v = v * 10 + (p[i] - '0');
    }
    return v <= 65535;
}

int web_http_host_ok(const char *host) {
    char lit[INET6_ADDRSTRLEN + 1];
    unsigned char a[16];
    const char *end;
    size_t n;
    if (host[0] == '[') {
        end = strchr(host, ']');
        if (!end) return 0;
        n = (size_t)(end - (host + 1));
        if (n == 0 || n >= sizeof(lit)) return 0;
        memcpy(lit, host + 1, n);
        lit[n] = '\0';
        return inet_pton(AF_INET6, lit, a) == 1 && port_ok(end + 1);
    }
    end = strchr(host, ':');
    n = end ? (size_t)(end - host) : strlen(host);
    if (!end) end = host + n;
    if (n == 0 || n >= sizeof(lit)) return 0;
    memcpy(lit, host, n);
    lit[n] = '\0';
    if (strcasecmp(lit, "localhost") != 0 && inet_pton(AF_INET, lit, a) != 1)
        return 0;
    return port_ok(end);
}

int web_http_inm_matches(const char *inm, const char *etag) {
    size_t el = strlen(etag);
    const char *p = inm;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) return 0;
        const char *e = p;
        while (*e && *e != ',') e++;
        size_t n = (size_t)(e - p);
        while (n && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
        if (n == 1 && *p == '*') return 1;
        if (n >= 2 && p[0] == 'W' && p[1] == '/') { p += 2; n -= 2; }
        if (n == el && !memcmp(p, etag, el)) return 1;
        p = e;
    }
}

int web_http_parse(const char *buf, size_t len, web_req_t *rq) {
    size_t pos = 0;
    int    have_rl = 0, status = 0;
    memset(rq, 0, sizeof(*rq));

    for (;;) {
        if (pos >= WEB_HDR_MAX) return 431;
        const char *nl = memchr(buf + pos, '\n', len - pos);
        if (!nl || (size_t)(nl - buf) >= WEB_HDR_MAX)
            return len >= WEB_HDR_MAX ? 431 : 0;

        size_t n = (size_t)(nl - (buf + pos));
        const char *line = buf + pos;
        if (n > 0 && line[n - 1] == '\r') n--;
        pos = (size_t)(nl - buf) + 1;

        if (!have_rl) {
            /* RFC 9112 §2.2: ignore empty lines before the request line. */
            if (n == 0) continue;
            if (!line_clean(line, n)) return 400;
            status = classify_request_line(line, n, rq);
            if (status == 400 || status == 505) return status;
            have_rl = 1;
            continue;
        }
        if (n == 0) return status;               /* end of the header block */
        if (!line_clean(line, n) || !header_line_ok(line, n)) {
            rq->is_head = 0;
            return 400;
        }
        if (status == WEB_HTTP_ROUTE) {
            keep_inm(rq, line, n);
            keep_host(rq, line, n);
        }
    }
}

int web_http_classify(const char *buf, size_t len, int *is_head) {
    web_req_t rq;
    int st = web_http_parse(buf, len, &rq);
    *is_head = rq.is_head;
    return st;
}

const char *web_http_reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 421: return "Misdirected Request";
    case 431: return "Request Header Fields Too Large";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default:  return "Internal Server Error";
    }
}

static const char *body_for(int status) {
    switch (status) {
    case 400: return "bad request\n";
    case 404: return "not found\n";
    case 405: return "method not allowed\n";
    case 408: return "request timeout\n";
    case 421: return "misdirected request\n";
    case 431: return "request header fields too large\n";
    case 503: return "service unavailable\n";
    case 505: return "http version not supported\n";
    default:  return "error\n";
    }
}

size_t web_http_response(int status, int is_head, char *out, size_t outsz) {
    const char *body = body_for(status);
    /* Allow is required on a 405 (RFC 9110 §15.5.6), and states the
     * whole read-only surface: there will never be a third method. */
    const char *allow = status == 405 ? "Allow: GET, HEAD\r\n" : "";
    int n = snprintf(out, outsz,
        "HTTP/1.1 %d %s\r\n"
        "%s"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'none'\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, web_http_reason(status), allow,
        (unsigned)strlen(body), is_head ? "" : body);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}
