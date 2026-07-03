/* Passive SMTP AUTH observer — roadmap #16 phase 3.2 + follow-up.
 *
 * Handles two SASL mechanisms:
 *
 *   AUTH PLAIN <b64>            single-shot; b64 decodes to
 *                               [authzid]\0authcid\0passwd
 *
 *   AUTH LOGIN                  three-line stateful exchange:
 *     C: AUTH LOGIN
 *     S: 334 VXNlcm5hbWU6       (base64 "Username:")
 *     C: <b64 username>
 *     S: 334 UGFzc3dvcmQ6       (base64 "Password:")
 *     C: <b64 password>
 *     S: 235 ok
 *
 * AUTH PLAIN is parsed inline. AUTH LOGIN needs per-flow scratch
 * state (was the last client verb AUTH LOGIN? did we already see
 * the username line?) — held in a small ring keyed by
 * (client, server, dst_port). The password value is never
 * inspected past "yes, it was on the wire." */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "smtp_snoop.h"
#include "cleartext_creds.h"

static int ci_startswith(const char *s, int slen, const char *prefix, int plen) {
    if (slen < plen) return 0;
    for (int i = 0; i < plen; i++) {
        char a = s[i], b = prefix[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

/* Minimal base64 decoder — same shape as the one in http_snoop.c. */
static int b64_decode(const char *in, int inlen, char *out, int outsz) {
    static const int8_t T[128] = {
        ['A']= 0,['B']= 1,['C']= 2,['D']= 3,['E']= 4,['F']= 5,['G']= 6,['H']= 7,
        ['I']= 8,['J']= 9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
        ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
        ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
        ['8']=60,['9']=61,['+']=62,['/']=63,
    };
    int op = 0;
    int quad_pos = 0;
    uint32_t acc = 0;
    for (int i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        if (c >= 128 || T[c] < 0) return -1;
        acc = (acc << 6) | (uint32_t)T[c];
        quad_pos++;
        if (quad_pos == 4) {
            if (op + 3 >= outsz) return op;
            out[op++] = (char)((acc >> 16) & 0xff);
            out[op++] = (char)((acc >>  8) & 0xff);
            out[op++] = (char) (acc        & 0xff);
            quad_pos = 0;
            acc = 0;
        }
    }
    if (quad_pos == 2) {
        if (op + 1 >= outsz) return op;
        out[op++] = (char)((acc >> 4) & 0xff);
    } else if (quad_pos == 3) {
        if (op + 2 >= outsz) return op;
        out[op++] = (char)((acc >> 10) & 0xff);
        out[op++] = (char)((acc >>  2) & 0xff);
    }
    return op;
}

/* ── AUTH LOGIN flow state ─────────────────────────────
 * Tiny table sized to keep the module self-contained. Keys are
 * client-side tuples; server-side payloads (dst_port not in the
 * SMTP set) are labelled but don't touch state. Entries age out on
 * capacity pressure by oldest last_seen. */

#define SMTP_MAX_FLOWS 16

typedef enum {
    LOGIN_NONE = 0,
    LOGIN_AWAIT_USER,
    LOGIN_AWAIT_PASS,
} login_state_t;

typedef struct {
    char           client[46];
    char           server[46];
    uint16_t       dst_port;
    login_state_t  state;
    time_t         last_seen;
} smtp_flow_t;

static smtp_flow_t     g_flows[SMTP_MAX_FLOWS];
static int             g_flow_count = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* True if `port` is one we treat as the SMTP server side. Used to
 * decide direction — client payloads have this as their dst_port. */
static int is_smtp_port(uint16_t port) {
    return port == 25 || port == 587;
}

static int flow_find(const char *client, const char *server, uint16_t port) {
    for (int i = 0; i < g_flow_count; i++) {
        const smtp_flow_t *f = &g_flows[i];
        if (f->dst_port != port) continue;
        if (strcmp(f->client, client) != 0) continue;
        if (strcmp(f->server, server) != 0) continue;
        return i;
    }
    return -1;
}

static int flow_evict_oldest(void) {
    int oldest = 0;
    for (int i = 1; i < g_flow_count; i++)
        if (g_flows[i].last_seen < g_flows[oldest].last_seen) oldest = i;
    return oldest;
}

static smtp_flow_t *flow_get_or_add(const char *client, const char *server,
                                    uint16_t port)
{
    int idx = flow_find(client, server, port);
    if (idx >= 0) return &g_flows[idx];
    int slot = (g_flow_count < SMTP_MAX_FLOWS) ? g_flow_count++
                                                : flow_evict_oldest();
    smtp_flow_t *f = &g_flows[slot];
    memset(f, 0, sizeof(*f));
    snprintf(f->client, sizeof(f->client), "%s", client);
    snprintf(f->server, sizeof(f->server), "%s", server);
    f->dst_port = port;
    f->state = LOGIN_NONE;
    return f;
}

/* Best-effort: if the line looks like a base64 chunk (only base64
 * chars and possible '=' padding, non-empty) — return 1. Used to
 * decide whether an AWAIT_USER line is really the client's b64
 * response or noise (server prompts start with 3-digit status codes,
 * caught before this). */
static int looks_like_base64(const char *s, int len) {
    if (len < 4) return 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (!ok) return 0;
    }
    return 1;
}

void smtp_snoop_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    pthread_mutex_unlock(&g_mu);
}

int smtp_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port)
{
    if (!data || len < 5 || !src || !dst) return 0;

    const char *p = (const char *)data;
    int rem = len < 1024 ? len : 1024;

    const char *eol = memchr(p, '\n', (size_t)rem);
    if (!eol) return 0;
    int line = (int)(eol - p);
    if (line > 0 && p[line - 1] == '\r') line--;

    /* ── AUTH LOGIN state machine ────────────────────────
     * We only touch state on client-directed payloads (dst_port is
     * the SMTP server port). Server payloads (with src_port on the
     * SMTP set) get labelled but leave state alone. */
    int is_client = is_smtp_port(dst_port);

    if (is_client) {
        pthread_mutex_lock(&g_mu);

        if (ci_startswith(p, line, "AUTH LOGIN", 10)) {
            /* Some clients pipeline the username on the same line:
             *   AUTH LOGIN <b64_user>
             * Handle both forms. */
            int i = 10;
            while (i < line && (p[i] == ' ' || p[i] == '\t')) i++;
            smtp_flow_t *f = flow_get_or_add(src, dst, dst_port);
            if (i < line && looks_like_base64(p + i, line - i)) {
                char raw[128];
                int dl = b64_decode(p + i, line - i, raw, (int)sizeof(raw));
                if (dl > 0) {
                    if (dl >= (int)sizeof(raw)) dl = (int)sizeof(raw) - 1;
                    raw[dl] = '\0';
                    cleartext_creds_record_user(src, dst, dst_port,
                                                "SMTP", raw);
                }
                f->state = LOGIN_AWAIT_PASS;
            } else {
                f->state = LOGIN_AWAIT_USER;
            }
            f->last_seen = time(NULL);
            pthread_mutex_unlock(&g_mu);
            return 1;
        }

        /* Server status codes never appear on a client line, so if the
         * flow's state expects the client's next payload, this must be
         * it. Guard with looks_like_base64 so a client's plaintext
         * QUIT / RSET etc. doesn't get misread. */
        int idx = flow_find(src, dst, dst_port);
        if (idx >= 0 && looks_like_base64(p, line)) {
            smtp_flow_t *f = &g_flows[idx];
            if (f->state == LOGIN_AWAIT_USER) {
                char raw[128];
                int dl = b64_decode(p, line, raw, (int)sizeof(raw));
                if (dl > 0) {
                    if (dl >= (int)sizeof(raw)) dl = (int)sizeof(raw) - 1;
                    raw[dl] = '\0';
                    cleartext_creds_record_user(src, dst, dst_port,
                                                "SMTP", raw);
                }
                f->state = LOGIN_AWAIT_PASS;
                f->last_seen = time(NULL);
                pthread_mutex_unlock(&g_mu);
                return 1;
            }
            if (f->state == LOGIN_AWAIT_PASS) {
                /* Never inspect the payload — just mark the flow. */
                cleartext_creds_mark_password(src, dst, dst_port, "SMTP");
                f->state = LOGIN_NONE;
                f->last_seen = time(NULL);
                pthread_mutex_unlock(&g_mu);
                return 1;
            }
        }
        pthread_mutex_unlock(&g_mu);
    }

    /* AUTH PLAIN <base64> — recognise both cases + trailing whitespace. */
    if (ci_startswith(p, line, "AUTH PLAIN", 10)) {
        int i = 10;
        while (i < line && (p[i] == ' ' || p[i] == '\t')) i++;
        if (i < line) {
            char raw[256];
            int  dl = b64_decode(p + i, line - i, raw, (int)sizeof(raw));
            if (dl >= 3) {
                /* Payload = [authzid] \0 authcid \0 passwd
                 * Find the first \0 that ends authzid; the token
                 * immediately after is the username. */
                int a = 0;
                while (a < dl && raw[a] != '\0') a++;
                if (a < dl - 1) {
                    /* authcid starts at a+1, ends at next \0. */
                    int u = a + 1;
                    int uend = u;
                    while (uend < dl && raw[uend] != '\0') uend++;
                    if (uend > u && uend < dl) {
                        char name[64];
                        int nsz = (uend - u) < 63 ? (uend - u) : 63;
                        memcpy(name, raw + u, (size_t)nsz);
                        name[nsz] = '\0';
                        cleartext_creds_record_user(src, dst, dst_port,
                                                    "SMTP", name);
                        /* If any bytes follow the trailing \0, that's
                         * the password portion — mark, don't inspect. */
                        if (uend + 1 < dl)
                            cleartext_creds_mark_password(src, dst,
                                                          dst_port, "SMTP");
                    }
                }
            }
        }
        return 1;
    }

    /* Other SMTP verbs — recognise so the packet can be labelled. */
    static const char *cmds[] = {
        "HELO","EHLO","MAIL FROM","RCPT TO","DATA","QUIT",
        "RSET","NOOP","VRFY","EXPN","STARTTLS","AUTH ",
        "220","221","250","334","354","421","450","451","452",
        "500","501","502","503","504","530","535","538","550",
        NULL
    };
    for (int i = 0; cmds[i]; i++) {
        int cl = (int)strlen(cmds[i]);
        if (line >= cl && ci_startswith(p, cl, cmds[i], cl))
            return 1;
    }

    return 0;
}
