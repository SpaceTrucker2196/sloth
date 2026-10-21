#include "web_http.h"

#include <stdio.h>
#include <string.h>

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

/* RFC 9112 §3: method SP request-target SP HTTP-version. */
static int classify_request_line(const char *s, size_t n, int *is_head) {
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
    if (mlen == 3 && !memcmp(s, "GET", 3))  return 404;
    if (mlen == 4 && !memcmp(s, "HEAD", 4)) { *is_head = 1; return 404; }
    return 405;
}

/* RFC 9112 §5: field-name ":" ... with no whitespace before the colon,
 * and no obs-fold continuation lines. */
static int header_line_ok(const char *s, size_t n) {
    size_t i = 0;
    while (i < n && is_tchar((unsigned char)s[i])) i++;
    return i > 0 && i < n && s[i] == ':';
}

int web_http_classify(const char *buf, size_t len, int *is_head) {
    size_t pos = 0;
    int    have_rl = 0, status = 0;
    *is_head = 0;

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
            status = classify_request_line(line, n, is_head);
            if (status == 400 || status == 505) return status;
            have_rl = 1;
            continue;
        }
        if (n == 0) return status;               /* end of the header block */
        if (!line_clean(line, n) || !header_line_ok(line, n)) {
            *is_head = 0;
            return 400;
        }
    }
}

const char *web_http_reason(int status) {
    switch (status) {
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 431: return "Request Header Fields Too Large";
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
    case 431: return "request header fields too large\n";
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
