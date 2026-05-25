#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "http_log.h"
#include "jsonl.h"

static http_log_entry_t g_log[MAX_HTTP_LOG];
static int              g_head  = 0;   /* next write slot */
static int              g_count = 0;   /* entries populated (≤ MAX_HTTP_LOG) */
static pthread_mutex_t  g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── HTTP/1.x request parser ─────────────────────────────── */

static int ci_eq(const char *a, int alen, const char *b, int blen) {
    if (alen != blen) return 0;
    for (int i = 0; i < alen; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return 1;
}

static int is_method(const char *tok, int tlen) {
    static const char *methods[] = {
        "GET","POST","PUT","HEAD","DELETE",
        "OPTIONS","PATCH","CONNECT","TRACE", NULL
    };
    for (int i = 0; methods[i]; i++)
        if (ci_eq(tok, tlen, methods[i], (int)strlen(methods[i]))) return 1;
    return 0;
}

int http_log_parse(const uint8_t *data, int len, const char *src_ip,
                   http_log_entry_t *out)
{
    if (len < 16) return 0;

    const char *p   = (const char *)data;
    int         rem = len < 8192 ? len : 8192;

    /* ── request line: METHOD SP path SP HTTP/x.x ── */
    const char *eol = (const char *)memchr(p, '\n', (size_t)rem);
    if (!eol) return 0;
    int rlen = (int)(eol - p);
    if (rlen > 0 && p[rlen - 1] == '\r') rlen--;

    /* extract method token */
    const char *sp1 = (const char *)memchr(p, ' ', (size_t)rlen);
    if (!sp1) return 0;
    int mlen = (int)(sp1 - p);
    if (!is_method(p, mlen)) return 0;

    /* extract path token */
    const char *path_start = sp1 + 1;
    int path_rem = rlen - mlen - 1;
    if (path_rem <= 0) return 0;
    const char *sp2 = (const char *)memchr(path_start, ' ', (size_t)path_rem);
    int plen = sp2 ? (int)(sp2 - path_start) : path_rem;

    /* ── walk headers for Host + User-Agent ── */
    rem -= (int)(eol - p) + 1;
    p    = eol + 1;
    char host[64] = "";
    char ua[64]   = "";

    while (rem > 0 && (host[0] == '\0' || ua[0] == '\0')) {
        if (*p == '\r' || *p == '\n') break;
        const char *heol = (const char *)memchr(p, '\n', (size_t)rem);
        int hlen = heol ? (int)(heol - p) : rem;
        int vlen = hlen;
        if (vlen > 0 && p[vlen - 1] == '\r') vlen--;

        if (vlen > 5 && ci_eq(p, 5, "host:", 5) && !host[0]) {
            const char *val = p + 5;
            int vrem = vlen - 5;
            while (vrem > 0 && (*val == ' ' || *val == '\t')) { val++; vrem--; }
            while (vrem > 0 && (val[vrem-1]==' '||val[vrem-1]=='\t')) vrem--;
            const char *colon = (const char *)memchr(val, ':', (size_t)vrem);
            if (colon) vrem = (int)(colon - val);
            if (vrem > 0) {
                int hsz = vrem < 63 ? vrem : 63;
                memcpy(host, val, (size_t)hsz);
                host[hsz] = '\0';
            }
        } else if (vlen > 11 && ci_eq(p, 11, "user-agent:", 11) && !ua[0]) {
            const char *val = p + 11;
            int vrem = vlen - 11;
            while (vrem > 0 && (*val == ' ' || *val == '\t')) { val++; vrem--; }
            while (vrem > 0 && (val[vrem-1]==' '||val[vrem-1]=='\t')) vrem--;
            if (vrem > 0) {
                int usz = vrem < 63 ? vrem : 63;
                memcpy(ua, val, (size_t)usz);
                ua[usz] = '\0';
            }
        }
        if (!heol) break;
        rem -= hlen + 1;
        p    = heol + 1;
    }

    /* ── fill output ── */
    memset(out, 0, sizeof(*out));
    if (src_ip) strncpy(out->src, src_ip, sizeof(out->src) - 1);

    int msz = mlen < 9 ? mlen : 9;
    memcpy(out->method, (const char *)data, (size_t)msz);
    out->method[msz] = '\0';

    snprintf(out->host, sizeof(out->host), "%s", host);
    snprintf(out->user_agent, sizeof(out->user_agent), "%s", ua);

    int psz = plen < 127 ? plen : 127;
    memcpy(out->path, path_start, (size_t)psz);
    out->path[psz] = '\0';

    out->ts = time(NULL);
    return 1;
}

/* ── Rolling log ─────────────────────────────────────────── */

void http_log_record(const http_log_entry_t *e)
{
    pthread_mutex_lock(&g_mu);
    g_log[g_head] = *e;
    g_head = (g_head + 1) % MAX_HTTP_LOG;
    if (g_count < MAX_HTTP_LOG) g_count++;
    pthread_mutex_unlock(&g_mu);
    jsonl_emit_http(e);
}

void http_log_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);

    int n = g_count < MAX_HTTP_LOG ? g_count : MAX_HTTP_LOG;

    /* copy in reverse-chronological order: newest first */
    for (int i = 0; i < n; i++) {
        int src_idx = ((g_head - 1 - i) % MAX_HTTP_LOG + MAX_HTTP_LOG) % MAX_HTTP_LOG;
        s->http_log[i] = g_log[src_idx];
    }
    s->http_log_count = n;
    s->http_log_head  = g_head;
    if (s->http_log_sel >= n) s->http_log_sel = n > 0 ? n - 1 : 0;

    pthread_mutex_unlock(&g_mu);
}

void http_log_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head  = 0;
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
