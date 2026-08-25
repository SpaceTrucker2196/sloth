#include <stdio.h>
#include <stdlib.h>   /* qsort — JA4H cookie/name sort */
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "http_log.h"
#include "sha256.h"
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

/* ── JA4H helpers (FoxIO spec) ────────────────────────
 * Format: a(10) _ b(12) _ c(12) _ d(12) = 49 chars.
 *   a: method(2) + version(2) + cookie-flag(1) + referer-flag(1) +
 *      numheaders(2) + primary-language(2)
 *   b: first 12 hex chars of sha256(comma-joined header names,
 *      OBSERVED ORDER, excluding Cookie / Referer)
 *   c: first 12 hex chars of sha256(comma-joined sorted cookie names)
 *      — "000000000000" if no cookies
 *   d: first 12 hex chars of sha256(comma-joined sorted name=value
 *      cookie pairs) — "000000000000" if no cookies
 *
 * Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
 */

#define JA4H_MAX_HDRS    64
#define JA4H_MAX_COOKIES 32

static const char *ja4h_method2(const char *method, int mlen) {
    /* First two chars, lowercased. GET → "ge", POST → "po",
     * CONNECT → "co". Only ASCII methods appear in real HTTP. */
    static char buf[3] = { '?', '?', '\0' };
    if (mlen < 2) { buf[0] = 'x'; buf[1] = 'x'; return buf; }
    char a = method[0]; char b = method[1];
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    buf[0] = a; buf[1] = b;
    return buf;
}

static const char *ja4h_version(const char *ver, int vlen) {
    /* Expect "HTTP/1.1" / "HTTP/1.0" / "HTTP/2.0" — take the two
     * digits around the '.'. Malformed input maps to "00". */
    static char buf[3] = { '0', '0', '\0' };
    if (vlen < 8) return buf;   /* "HTTP/x.y" min */
    const char *dot = memchr(ver, '.', (size_t)vlen);
    if (!dot || dot == ver || dot == ver + vlen - 1) return buf;
    char maj = *(dot - 1);
    char min = *(dot + 1);
    if (maj < '0' || maj > '9' || min < '0' || min > '9') return buf;
    buf[0] = maj;
    buf[1] = min;
    return buf;
}

static int u16_str_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* Compare fixed-width slots in the cookie table. */
static int cookie_name_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* ── HTTP/1.x response parser (#71) ───────────────────────── */

/* Case-insensitive header lookup within one header block. Returns a
 * pointer to the value (past the colon and any spaces) and its length,
 * or NULL. */
static const char *hdr_find(const char *hdrs, int hlen,
                            const char *name, int *vlen) {
    int nlen = (int)strlen(name);
    int i = 0;
    while (i < hlen) {
        int line_end = i;
        while (line_end < hlen && hdrs[line_end] != '\r' &&
               hdrs[line_end] != '\n') line_end++;
        int colon = i;
        while (colon < line_end && hdrs[colon] != ':') colon++;
        if (colon < line_end && ci_eq(hdrs + i, colon - i, name, nlen)) {
            int v = colon + 1;
            while (v < line_end && (hdrs[v] == ' ' || hdrs[v] == '\t')) v++;
            if (vlen) *vlen = line_end - v;
            return hdrs + v;
        }
        i = line_end;
        while (i < hlen && (hdrs[i] == '\r' || hdrs[i] == '\n')) i++;
    }
    return NULL;
}

int http_log_parse_response(const uint8_t *data, int len,
                            const char *src_ip, http_log_entry_t *out)
{
    if (!data || !out || len < 12) return 0;
    memset(out, 0, sizeof(*out));
    out->content_length = -1;

    const char *p = (const char *)data;
    /* Status line: "HTTP/1.x SSS reason". Anything else is either a
     * request, a continuation segment, or not HTTP — and a continuation
     * is the important one to reject, because its first bytes are body
     * data that can look like anything. */
    if (strncmp(p, "HTTP/1.", 7) != 0) return 0;
    if (p[7] != '0' && p[7] != '1') return 0;
    if (p[8] != ' ') return 0;
    if (p[9] < '0' || p[9] > '9' ||
        p[10] < '0' || p[10] > '9' ||
        p[11] < '0' || p[11] > '9') return 0;

    out->is_response = 1;
    out->status = (uint16_t)((p[9] - '0') * 100 + (p[10] - '0') * 10 +
                             (p[11] - '0'));
    snprintf(out->src, sizeof(out->src), "%s", src_ip ? src_ip : "");
    out->ts = time(NULL);

    /* Find the header/body boundary. Absent one, the headers ran past
     * this segment and there is no body here to speak of. */
    int body_off = -1;
    for (int i = 0; i + 3 < len; i++) {
        if (p[i] == '\r' && p[i+1] == '\n' &&
            p[i+2] == '\r' && p[i+3] == '\n') { body_off = i + 4; break; }
        /* Bare-LF header terminators exist in the wild, and a rogue
         * portal has no reason to be well-behaved. */
        if (p[i] == '\n' && p[i+1] == '\n') { body_off = i + 2; break; }
    }

    int hdr_len = (body_off > 0) ? body_off : len;
    int vlen = 0;
    const char *v = hdr_find(p, hdr_len, "content-length", &vlen);
    if (v && vlen > 0) {
        int n = 0, ok = 0;
        for (int i = 0; i < vlen && v[i] >= '0' && v[i] <= '9'; i++) {
            n = n * 10 + (v[i] - '0');
            ok = 1;
            if (n > 1 << 24) { ok = 0; break; }   /* absurd; treat as absent */
        }
        if (ok) out->content_length = n;
    }
    v = hdr_find(p, hdr_len, "transfer-encoding", &vlen);
    if (v && vlen >= 7 && ci_eq(v, 7, "chunked", 7)) out->chunked = 1;

    if (body_off < 0) return 1;          /* headers alone in this segment */

    int avail = len - body_off;
    if (avail < 0) avail = 0;
    int take = avail < HTTP_RESP_BODY_MAX ? avail : HTTP_RESP_BODY_MAX;
    memcpy(out->resp_body, p + body_off, (size_t)take);
    out->resp_body_len = take;

    /* Completeness, stated rather than assumed.
     *
     * A 204 has no body by definition, so it is complete the moment the
     * headers end. Otherwise the declared length has to match what
     * arrived, and it has to fit inside the bound — a body longer than
     * HTTP_RESP_BODY_MAX is one sloth deliberately did not keep, which
     * is not the same as one it failed to receive, but for a consumer
     * doing an exact comparison the two are equally unusable.
     *
     * Chunked is never complete: the body is interleaved with chunk
     * sizes and this does not decode them. Saying so is the honest
     * output; pretending the raw bytes are the body would produce a
     * mismatch on a response that is actually correct. */
    if (out->chunked) {
        out->body_complete = 0;
    } else if (out->status == 204 || out->content_length == 0) {
        out->body_complete = 1;
    } else if (out->content_length > 0) {
        out->body_complete = (out->content_length == take);
    } else {
        /* No Content-Length and not chunked: the body runs to
         * connection close, and we cannot know we have all of it. */
        out->body_complete = 0;
    }
    return 1;
}

/* ── Request/response pairing (#71) ────────────────────────
 *
 * One slot per flow, holding the most recent request. Bounded and
 * LRU-evicted like every other table here. */
#define HTTP_FLOW_MAX 64

typedef struct {
    char     cli[46];        /* the request's source */
    char     srv[46];
    uint16_t cli_port;
    uint16_t srv_port;
    char     host[64];
    char     path[128];
    int      in_flight;      /* a request is awaiting its response */
    time_t   ts;
} http_flow_t;

static http_flow_t     g_flow[HTTP_FLOW_MAX];
static int             g_flow_n;
static pthread_mutex_t g_flow_mu = PTHREAD_MUTEX_INITIALIZER;

static void flow_note_request(const http_log_entry_t *req) {
    if (!req || !req->src[0] || !req->dst[0]) return;
    pthread_mutex_lock(&g_flow_mu);
    int idx = -1;
    for (int i = 0; i < g_flow_n; i++)
        if (g_flow[i].cli_port == req->src_port &&
            g_flow[i].srv_port == req->dst_port &&
            strcmp(g_flow[i].cli, req->src) == 0 &&
            strcmp(g_flow[i].srv, req->dst) == 0) { idx = i; break; }
    if (idx < 0) {
        if (g_flow_n < HTTP_FLOW_MAX) {
            idx = g_flow_n++;
        } else {
            idx = 0;
            for (int i = 1; i < HTTP_FLOW_MAX; i++)
                if (g_flow[i].ts < g_flow[idx].ts) idx = i;
        }
        memset(&g_flow[idx], 0, sizeof(g_flow[idx]));
        snprintf(g_flow[idx].cli, sizeof(g_flow[idx].cli), "%s", req->src);
        snprintf(g_flow[idx].srv, sizeof(g_flow[idx].srv), "%s", req->dst);
        g_flow[idx].cli_port = req->src_port;
        g_flow[idx].srv_port = req->dst_port;
    }
    /* A second request before the first was answered is pipelining, and
     * "which one does the next response answer" stops being knowable.
     * Marked unpairable rather than guessed: attributing a response to
     * the wrong URL is worse for a sentinel comparison than not
     * attributing it at all. */
    if (g_flow[idx].in_flight) {
        g_flow[idx].in_flight = -1;      /* ambiguous */
    } else if (g_flow[idx].in_flight == 0) {
        g_flow[idx].in_flight = 1;
        snprintf(g_flow[idx].host, sizeof(g_flow[idx].host), "%s", req->host);
        snprintf(g_flow[idx].path, sizeof(g_flow[idx].path), "%s", req->path);
    }
    g_flow[idx].ts = req->ts;
    pthread_mutex_unlock(&g_flow_mu);
}

int http_log_pair_response(http_log_entry_t *resp) {
    if (!resp || !resp->is_response) return 0;
    int paired = 0;
    pthread_mutex_lock(&g_flow_mu);
    /* The response travels server -> client, so the four-tuple is the
     * request's reversed. */
    for (int i = 0; i < g_flow_n; i++) {
        if (g_flow[i].cli_port != resp->dst_port) continue;
        if (g_flow[i].srv_port != resp->src_port) continue;
        if (strcmp(g_flow[i].cli, resp->dst) != 0) continue;
        if (strcmp(g_flow[i].srv, resp->src) != 0) continue;
        if (g_flow[i].in_flight == 1) {
            snprintf(resp->host, sizeof(resp->host), "%s", g_flow[i].host);
            snprintf(resp->path, sizeof(resp->path), "%s", g_flow[i].path);
            paired = 1;
        }
        g_flow[i].in_flight = 0;         /* answered, ambiguous or not */
        break;
    }
    pthread_mutex_unlock(&g_flow_mu);
    return paired;
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

    /* JA4H needs the HTTP-version token, which comes after the second
     * space on the request line. Optional — malformed / HTTP/0.9
     * requests skip it. */
    const char *ver_start = sp2 ? sp2 + 1 : NULL;
    int ver_len = sp2 ? rlen - mlen - 1 - plen - 1 : 0;
    if (ver_len < 0) ver_len = 0;

    /* ── walk ALL headers — the pre-JA4H code exited early on
     * Host + User-Agent; JA4H needs the full ordered list to hash.  */
    rem -= (int)(eol - p) + 1;
    p    = eol + 1;
    char host[64] = "";
    char ua[64]   = "";

    /* JA4H collectors. */
    char  hdr_names[JA4H_MAX_HDRS][40];   /* header names, observed order */
    int   n_hdrs = 0;
    char  cookies_names [JA4H_MAX_COOKIES][40];
    char  cookies_pairs [JA4H_MAX_COOKIES][80];
    int   n_cookies = 0;
    int   have_cookie = 0, have_referer = 0;
    char  lang2[3] = { '0', '0', '\0' };

    while (rem > 0) {
        if (*p == '\r' || *p == '\n') break;
        const char *heol = (const char *)memchr(p, '\n', (size_t)rem);
        int hlen = heol ? (int)(heol - p) : rem;
        int vlen = hlen;
        if (vlen < 0) vlen = 0;   /* prove non-negative for the memchr bound below */
        if (vlen > 0 && p[vlen - 1] == '\r') vlen--;

        /* Header name terminates at ':'. */
        const char *colon = memchr(p, ':', (size_t)vlen);
        int name_len = colon ? (int)(colon - p) : 0;

        if (name_len > 0 && name_len < 40) {
            int is_cookie  = (name_len == 6  && ci_eq(p, 6,  "cookie",  6));
            int is_referer = (name_len == 7  && ci_eq(p, 7,  "referer", 7));

            /* Extract value (colon+1 .. eol) with whitespace trim. */
            const char *val = colon ? colon + 1 : NULL;
            int         vrem = colon ? vlen - name_len - 1 : 0;
            if (val) {
                while (vrem > 0 && (*val == ' ' || *val == '\t')) { val++; vrem--; }
                while (vrem > 0 && (val[vrem-1]==' '||val[vrem-1]=='\t')) vrem--;
            }

            if (is_cookie) {
                have_cookie = 1;
                /* Cookie: name=value; name2=value2; …
                 * Split on ';' with optional whitespace. */
                int i = 0;
                while (i < vrem && n_cookies < JA4H_MAX_COOKIES) {
                    while (i < vrem && (val[i] == ' ' || val[i] == '\t' ||
                                        val[i] == ';')) i++;
                    if (i >= vrem) break;
                    int pair_start = i;
                    while (i < vrem && val[i] != ';') i++;
                    int pair_end = i;
                    while (pair_end > pair_start
                           && (val[pair_end-1]==' '||val[pair_end-1]=='\t'))
                        pair_end--;
                    if (pair_end > pair_start) {
                        /* Find the first '=' inside this pair. Everything
                         * before is the name (used in JA4H_c); the whole
                         * pair is used in JA4H_d. */
                        int eq = pair_start;
                        while (eq < pair_end && val[eq] != '=') eq++;
                        int name_span = eq - pair_start;
                        int nsz = name_span < 39 ? name_span : 39;
                        memcpy(cookies_names[n_cookies], val + pair_start,
                               (size_t)nsz);
                        cookies_names[n_cookies][nsz] = '\0';
                        int psz = (pair_end - pair_start) < 79 ?
                                  (pair_end - pair_start) : 79;
                        memcpy(cookies_pairs[n_cookies], val + pair_start,
                               (size_t)psz);
                        cookies_pairs[n_cookies][psz] = '\0';
                        n_cookies++;
                    }
                }
            } else if (is_referer) {
                have_referer = 1;
            } else if (n_hdrs < JA4H_MAX_HDRS) {
                int nsz = name_len < 39 ? name_len : 39;
                for (int i = 0; i < nsz; i++) {
                    char c = p[i];
                    if (c >= 'A' && c <= 'Z') c += 32;
                    hdr_names[n_hdrs][i] = c;
                }
                hdr_names[n_hdrs][nsz] = '\0';
                n_hdrs++;
            }

            /* Host + User-Agent capture (unchanged behaviour). */
            if (name_len == 4 && ci_eq(p, 4, "host", 4) && !host[0]) {
                const char *hv = val;
                int hvrem = vrem;
                const char *hcolon = hv ? memchr(hv, ':', (size_t)hvrem) : NULL;
                if (hcolon) hvrem = (int)(hcolon - hv);
                if (hvrem > 0) {
                    int hsz = hvrem < 63 ? hvrem : 63;
                    memcpy(host, hv, (size_t)hsz);
                    host[hsz] = '\0';
                }
            } else if (name_len == 10 && ci_eq(p, 10, "user-agent", 10)
                       && !ua[0]) {
                if (vrem > 0) {
                    int usz = vrem < 63 ? vrem : 63;
                    memcpy(ua, val, (size_t)usz);
                    ua[usz] = '\0';
                }
            } else if (name_len == 15
                       && ci_eq(p, 15, "accept-language", 15)) {
                /* JA4H section-a primary language: first 2 chars of
                 * the first language tag, lowercased. */
                if (vrem >= 2) {
                    char l0 = val[0], l1 = val[1];
                    if (l0 >= 'A' && l0 <= 'Z') l0 += 32;
                    if (l1 >= 'A' && l1 <= 'Z') l1 += 32;
                    lang2[0] = l0;
                    lang2[1] = l1;
                }
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

    /* ── JA4H assembly ──────────────────────────────────
     * Section a is 10 chars, sections b/c/d are 12 hex chars each. */
    char sec_a[16];
    int nh_capped = n_hdrs > 99 ? 99 : n_hdrs;
    snprintf(sec_a, sizeof(sec_a), "%s%s%c%c%02d%s",
             ja4h_method2((const char *)data, mlen),
             ja4h_version(ver_start ? ver_start : "", ver_len),
             have_cookie  ? 'c' : 'n',
             have_referer ? 'r' : 'n',
             nh_capped,
             lang2);

    /* Section b: comma-joined header names in observed order,
     * excluding Cookie/Referer (already excluded during collection). */
    char hdr_buf[JA4H_MAX_HDRS * 41 + 1];
    hdr_buf[0] = '\0';
    int hp = 0;
    for (int i = 0; i < n_hdrs; i++) {
        int nl = (int)strlen(hdr_names[i]);
        int need = nl + (i > 0 ? 1 : 0);
        if (hp + need + 1 >= (int)sizeof(hdr_buf)) break;
        if (i > 0) hdr_buf[hp++] = ',';
        memcpy(hdr_buf + hp, hdr_names[i], (size_t)nl);
        hp += nl;
    }
    hdr_buf[hp] = '\0';
    char sec_b_full[65];
    sha256_hex((const uint8_t *)hdr_buf, strlen(hdr_buf), sec_b_full);

    /* Section c: comma-joined sorted cookie NAMES. */
    char sec_c_hex[13] = "000000000000";
    char sec_d_hex[13] = "000000000000";
    if (n_cookies > 0) {
        qsort(cookies_names, (size_t)n_cookies, sizeof(cookies_names[0]),
              cookie_name_cmp);
        char cnames[JA4H_MAX_COOKIES * 41 + 1];
        int cp = 0; cnames[0] = '\0';
        for (int i = 0; i < n_cookies; i++) {
            int nl = (int)strlen(cookies_names[i]);
            int need = nl + (i > 0 ? 1 : 0);
            if (cp + need + 1 >= (int)sizeof(cnames)) break;
            if (i > 0) cnames[cp++] = ',';
            memcpy(cnames + cp, cookies_names[i], (size_t)nl);
            cp += nl;
        }
        cnames[cp] = '\0';
        char full[65];
        sha256_hex((const uint8_t *)cnames, strlen(cnames), full);
        memcpy(sec_c_hex, full, 12);

        /* Section d: comma-joined sorted cookie name=value PAIRS. */
        qsort(cookies_pairs, (size_t)n_cookies, sizeof(cookies_pairs[0]),
              u16_str_cmp);
        char cpairs[JA4H_MAX_COOKIES * 81 + 1];
        int pp = 0; cpairs[0] = '\0';
        for (int i = 0; i < n_cookies; i++) {
            int pl = (int)strlen(cookies_pairs[i]);
            int need = pl + (i > 0 ? 1 : 0);
            if (pp + need + 1 >= (int)sizeof(cpairs)) break;
            if (i > 0) cpairs[pp++] = ',';
            memcpy(cpairs + pp, cookies_pairs[i], (size_t)pl);
            pp += pl;
        }
        cpairs[pp] = '\0';
        sha256_hex((const uint8_t *)cpairs, strlen(cpairs), full);
        memcpy(sec_d_hex, full, 12);
    }

    snprintf(out->ja4h, sizeof(out->ja4h), "%s_%.12s_%s_%s",
             sec_a, sec_b_full, sec_c_hex, sec_d_hex);

    out->ts = time(NULL);
    return 1;
}

/* ── Rolling log ─────────────────────────────────────────── */

void http_log_record(const http_log_entry_t *e)
{
    /* A request opens the pairing window for its flow (#71). Done here
     * rather than in the parser so a caller that parses without
     * recording — the credential scanner does — cannot open one. */
    if (e && !e->is_response) flow_note_request(e);

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
    pthread_mutex_lock(&g_flow_mu);
    memset(g_flow, 0, sizeof(g_flow));
    g_flow_n = 0;
    pthread_mutex_unlock(&g_flow_mu);
}
