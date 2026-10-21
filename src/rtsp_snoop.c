/* Passive RTSP observer — anonymous stream exposure (#106 slice B).
 *
 * Modelled on src/http_log.c: RTSP borrows HTTP/1.1's message shape
 * (RFC 2326 §4, RFC 7826 §5), so a start line, a header block and a
 * blank line are all there is to read. What this module adds over the
 * HTTP parser is pairing: RTSP responses carry no URI, only the CSeq of
 * the request they answer, and the CSeq series is per direction of one
 * TCP connection (RFC 7826 §18.20). So a DESCRIBE is remembered against
 * (client, client port, server, server port, CSeq) and settled when the
 * response with the same CSeq comes back the other way.
 *
 * The finding is narrow on purpose: a server that answered DESCRIBE
 * 200 to a request with no Authorization header, on a connection where
 * it had not answered 401 first, handed out a stream description with
 * no authentication step sloth could see. That corroborates anonymous
 * stream access; it does not confirm it (the server may authenticate
 * SETUP or PLAY instead, or filter by source address), and the docs say
 * so.
 *
 * Nothing is sent. Nothing about a credential is kept: see the guard
 * comments at has_auth and uri_scan below, and rtsp_snoop.h. */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

#include "rtsp_snoop.h"
#include "sloth_clock.h"
#include "netstr.h"
#include "stab.h"
#include "sensor_health.h"

/* ── Tables ──────────────────────────────────────────────── */

/* DESCRIBEs in flight per connection. A client may pipeline requests
 * (RFC 7826 §12), so a connection holds a few; the slot whose CSeq is
 * oldest is overwritten past that, which loses one pairing on a client
 * pipelining more than four DESCRIBEs and nothing else. */
#define RTSP_PENDING        4
#define RTSP_MAX_EXCHANGES  32

typedef struct {
    uint32_t cseq;
    uint8_t  used;
    uint8_t  has_auth;            /* presence only, see rtsp_msg_t */
    char     path[RTSP_PATH_LEN];
} rtsp_pending_t;

typedef struct {
    char           client[46];
    char           server[46];
    uint16_t       cport;
    uint16_t       sport;
    uint8_t        challenged;    /* a DESCRIBE here was answered 401 */
    int            next;          /* pending slot to overwrite next */
    rtsp_pending_t pend[RTSP_PENDING];
    time_t         last_seen;
} rtsp_exchange_t;

typedef struct {
    const char *client, *server;
    uint16_t    cport, sport;
} ex_key_t;

static int ex_key_eq(const void *row, const void *key) {
    const rtsp_exchange_t *e = row; const ex_key_t *k = key;
    return e->cport == k->cport && e->sport == k->sport &&
           strcmp(e->client, k->client) == 0 &&
           strcmp(e->server, k->server) == 0;
}

typedef struct {
    const char *server, *path;
    uint16_t    port;
} st_key_t;

static int st_key_eq(const void *row, const void *key) {
    const rtsp_stream_t *r = row; const st_key_t *k = key;
    return r->port == k->port && strcmp(r->server, k->server) == 0 &&
           strcmp(r->path, k->path) == 0;
}

/* STAB_OLDEST (#110) for both: client ports and request paths are the
 * remote side's to choose, so a spray of them churns the tables and is
 * tallied rather than refused or allocated. */
STAB_DECL(g_ex, rtsp_exchange_t, RTSP_MAX_EXCHANGES, last_seen, STAB_OLDEST,
          SH_EVICT_RTSP_EXCHANGE, NULL, ex_key_eq);
STAB_DECL(g_st, rtsp_stream_t, MAX_RTSP_STREAMS, last_seen, STAB_OLDEST,
          SH_EVICT_RTSP_STREAM, NULL, st_key_eq);
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── Lexing ──────────────────────────────────────────────── */

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static int ci_eq(const char *a, int alen, const char *b) {
    int blen = (int)strlen(b);
    if (alen != blen) return 0;
    for (int i = 0; i < alen; i++) if (lower(a[i]) != lower(b[i])) return 0;
    return 1;
}

static int ci_prefix(const char *a, int alen, const char *b) {
    int blen = (int)strlen(b);
    if (alen < blen) return 0;
    for (int i = 0; i < blen; i++) if (lower(a[i]) != lower(b[i])) return 0;
    return 1;
}

/* Next complete line of buf[*pos..len). RFC 7826 §5 says lines MUST
 * end in CRLF; RFC 2326 §4 asks receivers to be prepared for a lone LF
 * too, and that tolerance is kept. A lone CR is not taken as a line end
 * (no RTSP stack sloth knows of emits one). A tail with no terminator is
 * not a line: the segment may have cut it mid-value. */
static int next_line(const char *buf, int len, int *pos,
                     const char **lp, int *ln) {
    int i = *pos;
    if (i >= len) return 0;
    const char *nl = memchr(buf + i, '\n', (size_t)(len - i));
    if (!nl) return 0;
    int end = (int)(nl - buf);
    int e = end;
    if (e > i && buf[e - 1] == '\r') e--;
    *lp = buf + i;
    *ln = e - i;
    *pos = end + 1;
    return 1;
}

/* "RTSP/1.0" or "RTSP/2.0" exactly — the two versions RFC 2326 and RFC
 * 7826 define. Anything else on these ports is not ours to read. */
static int parse_version(const char *v, int n) {
    if (n != 8 || memcmp(v, "RTSP/", 5) != 0 || v[6] != '.' || v[7] != '0')
        return 0;
    if (v[5] == '1') return 1;
    if (v[5] == '2') return 2;
    return 0;
}

static int is_method_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '-';
}

/* Query/path parameter names that carry a credential in the URL forms
 * camera firmwares accept in place of an Authorization header:
 * "?user=admin&password=...", Foscam-style "?loginuse=admin&loginpas=...",
 * "?account=...", "?token=...", "?auth=...". A parameter is a name
 * starting at a segment boundary and running to '='; it is credential-
 * shaped when the name begins with one of these stems, so "username",
 * "passwd", "loginpas", "auth_key" and "token_id" all are, while
 * "compass" (stem not at the start) and "users" (no '=') are not. The
 * list errs wide on purpose: it decides what is NOT tracked, so a false
 * match loses one finding and a miss would count an authenticated
 * request anonymous. A URL that matches is never stored, never
 * compared, and never counted as anonymous. */
static const char *const k_cred_stems[] = {
    "user", "usr", "pass", "pwd", "login", "account", "token", "auth", NULL
};

static int cred_token_at(const char *s, int n) {
    int nl = 0;
    while (nl < n && s[nl] != '=' && s[nl] != '/' && s[nl] != '?' &&
           s[nl] != '&' && s[nl] != ';')
        nl++;
    if (nl == 0 || nl == n || s[nl] != '=') return 0;
    for (int t = 0; k_cred_stems[t]; t++)
        if (ci_prefix(s, nl, k_cred_stems[t])) return 1;
    return 0;
}

/* Request-URI → abs_path (RFC 2326 §3.2, RFC 7826 §4.2 / RFC 3986 §3).
 * Absolute "rtsp://", "rtsps://" or "rtspu://" forms have their
 * authority skipped; a relative "/..." form is taken as the path.
 * Query and fragment are dropped from what is stored. Userinfo in the
 * authority ("rtsp://admin:12345@host/") or a credential-shaped
 * parameter anywhere after it sets url_creds and leaves path empty —
 * the guardrail is that the bytes never leave this function. */
static void uri_scan(const char *u, int n, rtsp_msg_t *out) {
    int i;
    out->path[0] = '\0';
    if      (ci_prefix(u, n, "rtsp://"))  i = 7;
    else if (ci_prefix(u, n, "rtsps://")) i = 8;
    else if (ci_prefix(u, n, "rtspu://")) i = 8;
    else if (n > 0 && u[0] == '/')        i = -1;
    else return;                               /* "*" or not a URI */

    int p0 = 0;
    if (i >= 0) {
        int a = i;
        while (a < n && u[a] != '/' && u[a] != '?' && u[a] != '#') a++;
        if (memchr(u + i, '@', (size_t)(a - i))) out->url_creds = 1;
        p0 = a;
    }
    int frag = p0;
    while (frag < n && u[frag] != '#') frag++;
    for (int k = p0; k < frag; k++) {
        int boundary = (k == p0) || u[k - 1] == '/' || u[k - 1] == '?' ||
                       u[k - 1] == '&' || u[k - 1] == ';';
        if (boundary && cred_token_at(u + k, frag - k)) out->url_creds = 1;
    }
    if (out->url_creds) return;

    int pe = p0;
    while (pe < frag && u[pe] != '?') pe++;
    if (pe == p0) {
        snprintf(out->path, sizeof(out->path), "/");
        return;
    }
    netstr_copy(out->path, sizeof(out->path),
                (const uint8_t *)(u + p0), (size_t)(pe - p0));
}

/* CSeq value: 1*DIGIT, optional surrounding whitespace, <= 2^32-1. */
static int parse_cseq(const char *v, int n, uint32_t *out) {
    int i = 0;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    int d0 = i;
    uint64_t acc = 0;
    while (i < n && v[i] >= '0' && v[i] <= '9') {
        acc = acc * 10 + (uint64_t)(v[i] - '0');
        if (acc > 0xffffffffULL) return 0;
        i++;
    }
    if (i == d0) return 0;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    if (i != n) return 0;
    *out = (uint32_t)acc;
    return 1;
}

static void read_header(const char *l, int n, rtsp_msg_t *out) {
    const char *colon = memchr(l, ':', (size_t)n);
    if (!colon) return;                        /* not a header line */
    int nl = (int)(colon - l);
    while (nl > 0 && (l[nl - 1] == ' ' || l[nl - 1] == '\t')) nl--;
    const char *v = colon + 1;
    int vn = n - (int)(v - l);
    while (vn > 0 && (*v == ' ' || *v == '\t')) { v++; vn--; }

    if (ci_eq(l, nl, "CSeq")) {
        uint32_t c;
        if (!out->has_cseq && parse_cseq(v, vn, &c)) {
            out->has_cseq = 1;
            out->cseq = c;
        }
    } else if (ci_eq(l, nl, "Authorization") ||
               ci_eq(l, nl, "Proxy-Authorization")) {
        /* The value is a credential (RFC 7235 §4.2). Its presence is
         * what decides "authenticated"; the value is not read. */
        out->has_auth = 1;
    } else if (ci_eq(l, nl, "Content-Type")) {
        static const char sdp[] = "application/sdp";
        int sl = (int)sizeof(sdp) - 1;
        if (ci_prefix(v, vn, sdp) &&
            (vn == sl || v[sl] == ';' || v[sl] == ' ' || v[sl] == '\t'))
            out->has_sdp = 1;
    } else if (ci_eq(l, nl, "WWW-Authenticate")) {
        /* The server's challenge scheme ("Basic", "Digest"), which is
         * the server's own and not a credential. Token chars only. */
        int k = 0;
        while (k < vn && k < (int)sizeof(out->auth_scheme) - 1 &&
               ((v[k] >= 'A' && v[k] <= 'Z') || (v[k] >= 'a' && v[k] <= 'z') ||
                (v[k] >= '0' && v[k] <= '9') || v[k] == '-'))
            k++;
        memcpy(out->auth_scheme, v, (size_t)k);
        out->auth_scheme[k] = '\0';
    }
}

/* ── Public parse ────────────────────────────────────────── */

int rtsp_parse(const uint8_t *data, int len, rtsp_msg_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!data || len < 12) return 0;
    const char *buf = (const char *)data;
    /* Interleaved binary data (RFC 7826 §14) on the same connection. */
    if (buf[0] == '$') return 0;

    int pos = 0;
    const char *l; int n;
    if (!next_line(buf, len, &pos, &l, &n)) return 0;

    if (n >= 12 && memcmp(l, "RTSP/", 5) == 0) {
        /* Status-Line: RTSP-Version SP Status-Code SP Reason-Phrase. */
        int v = parse_version(l, 8);
        if (!v || l[8] != ' ') return 0;
        const char *c = l + 9;
        if (c[0] < '1' || c[0] > '5' || c[1] < '0' || c[1] > '9' ||
            c[2] < '0' || c[2] > '9')
            return 0;
        if (n > 12 && l[12] != ' ') return 0;
        out->kind    = RTSP_MSG_RESPONSE;
        out->version = v;
        out->status  = (c[0] - '0') * 100 + (c[1] - '0') * 10 + (c[2] - '0');
    } else {
        /* Request-Line: Method SP Request-URI SP RTSP-Version. */
        const char *sp1 = memchr(l, ' ', (size_t)n);
        if (!sp1) return 0;
        int ml = (int)(sp1 - l);
        if (ml < 1 || ml >= (int)sizeof(out->method)) return 0;
        for (int k = 0; k < ml; k++) if (!is_method_char(l[k])) return 0;
        const char *u = sp1 + 1;
        int rest = n - ml - 1;
        const char *sp2 = memchr(u, ' ', (size_t)rest);
        if (!sp2) return 0;
        int ul = (int)(sp2 - u);
        if (ul < 1) return 0;
        int v = parse_version(sp2 + 1, rest - ul - 1);
        if (!v) return 0;
        out->kind    = RTSP_MSG_REQUEST;
        out->version = v;
        memcpy(out->method, l, (size_t)ml);
        out->method[ml] = '\0';
        uri_scan(u, ul, out);
    }

    while (next_line(buf, len, &pos, &l, &n)) {
        if (n == 0) { out->complete = 1; break; }  /* end of headers */
        read_header(l, n, out);
    }
    return 1;
}

/* ── Table helpers (caller holds g_mu) ───────────────────── */

static rtsp_stream_t *stream_get(const char *server, uint16_t port,
                                 const char *path, time_t now) {
    st_key_t key = { server, path, port };
    int created = 0;
    rtsp_stream_t *r = stab_get(&g_st, &key, now, &created);
    if (!r) return NULL;
    if (created) {
        snprintf(r->server, sizeof(r->server), "%s", server);
        snprintf(r->path,   sizeof(r->path),   "%s", path);
        r->port       = port;
        r->first_seen = now;
    }
    r->last_seen = now;
    return r;
}

static void note_describe(const char *client, uint16_t cport,
                          const char *server, uint16_t sport,
                          const rtsp_msg_t *m, time_t now) {
    ex_key_t key = { client, server, cport, sport };
    int created = 0;
    rtsp_exchange_t *e = stab_get(&g_ex, &key, now, &created);
    if (!e) return;
    if (created) {
        snprintf(e->client, sizeof(e->client), "%s", client);
        snprintf(e->server, sizeof(e->server), "%s", server);
        e->cport = cport;
        e->sport = sport;
    }
    e->last_seen = now;
    /* A retransmission carries the same CSeq (RFC 7826 §18.20) and
     * reuses its slot rather than taking a second one. */
    rtsp_pending_t *p = NULL;
    for (int i = 0; i < RTSP_PENDING; i++)
        if (e->pend[i].used && e->pend[i].cseq == m->cseq) p = &e->pend[i];
    if (!p) {
        p = &e->pend[e->next];
        e->next = (e->next + 1) % RTSP_PENDING;
    }
    p->used     = 1;
    p->cseq     = m->cseq;
    p->has_auth = (uint8_t)(m->has_auth != 0);
    snprintf(p->path, sizeof(p->path), "%s", m->path);
}

static int settle(const char *client, uint16_t cport,
                  const char *server, uint16_t sport,
                  const rtsp_msg_t *m, time_t now) {
    ex_key_t key = { client, server, cport, sport };
    rtsp_exchange_t *e = stab_find(&g_ex, &key);
    if (!e) return 0;
    rtsp_pending_t *p = NULL;
    for (int i = 0; i < RTSP_PENDING; i++)
        if (e->pend[i].used && e->pend[i].cseq == m->cseq) p = &e->pend[i];
    if (!p) return 0;
    e->last_seen = now;

    if (m->status == 401) {
        e->challenged = 1;
        rtsp_stream_t *r = stream_get(server, sport, p->path, now);
        if (r) {
            r->challenged++;
            snprintf(r->client, sizeof(r->client), "%s", client);
            if (m->auth_scheme[0])
                snprintf(r->auth_scheme, sizeof(r->auth_scheme), "%s",
                         m->auth_scheme);
        }
    } else if (m->status == 200) {
        rtsp_stream_t *r = stream_get(server, sport, p->path, now);
        if (r) {
            if (!p->has_auth && !e->challenged) r->anon_ok++;
            else                                r->auth_ok++;
            if (m->has_sdp) r->sdp = 1;
            snprintf(r->client, sizeof(r->client), "%s", client);
        }
    }
    /* Any final answer retires the request; other codes (404, 454, a
     * 3xx redirect) say nothing about authentication either way. */
    p->used = 0;
    return 1;
}

/* ── Public API ──────────────────────────────────────────── */

int rtsp_snoop_observe(const char *src, uint16_t sport,
                       const char *dst, uint16_t dport,
                       const uint8_t *data, int len,
                       char *info, int infosz) {
    rtsp_msg_t m;
    if (!src || !dst || !rtsp_parse(data, len, &m)) return 0;

    if (m.kind == RTSP_MSG_REQUEST) {
        /* Tracked only when there is something to pair, a path that is
         * safe to keep, and a whole header block. A URI carrying a
         * credential is neither anonymous nor ours to store. A header
         * block with no empty line in this segment may have its
         * Authorization in the next one (a client writing headers in
         * several send()s, a long Digest value): has_auth is unknown
         * there, so the request is dropped rather than called
         * anonymous. Segments are not reassembled. */
        if (strcmp(m.method, "DESCRIBE") == 0 && m.has_cseq &&
            m.complete && !m.url_creds && m.path[0]) {
            pthread_mutex_lock(&g_mu);
            note_describe(src, sport, dst, dport, &m, sloth_wall());
            pthread_mutex_unlock(&g_mu);
        }
        if (info && infosz > 0)
            snprintf(info, (size_t)infosz, "RTSP %s", m.method);
    } else {
        if (m.has_cseq) {
            pthread_mutex_lock(&g_mu);
            settle(dst, dport, src, sport, &m, sloth_wall());
            pthread_mutex_unlock(&g_mu);
        }
        if (info && infosz > 0)
            snprintf(info, (size_t)infosz, "RTSP %d", m.status);
    }
    return 1;
}

void rtsp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    s->rtsp_stream_count = stab_snapshot(&g_st, s->rtsp_streams,
                                         MAX_RTSP_STREAMS);
    pthread_mutex_unlock(&g_mu);
}

void rtsp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_ex);
    stab_clear(&g_st);
    pthread_mutex_unlock(&g_mu);
}
