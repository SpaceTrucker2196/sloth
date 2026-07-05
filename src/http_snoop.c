#include <string.h>
#include "http_snoop.h"
#include "cleartext_creds.h"

/* ── helpers ─────────────────────────────────────────────── */

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

/* ── Public API ──────────────────────────────────────────── */

int http_snoop(const uint8_t *data, int len, char *host, int hostsz) {
    if (len < 16 || hostsz < 2) return 0;

    const char *p   = (const char *)data;
    int         rem = len < 8192 ? len : 8192;  /* cap scan at 8 KiB */

    /* Validate first token is a known HTTP request method.
       Responses (HTTP/1.x ...) don't carry a Host header we care about. */
    static const char *methods[] = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", NULL
    };
    int is_req = 0;
    for (int i = 0; methods[i]; i++) {
        int ml = (int)strlen(methods[i]);
        if (rem >= ml && memcmp(p, methods[i], (size_t)ml) == 0) {
            is_req = 1;
            break;
        }
    }
    if (!is_req) return 0;

    /* skip the request line */
    const char *nl = (const char *)memchr(p, '\n', (size_t)rem);
    if (!nl) return 0;
    rem -= (int)(nl - p) + 1;
    p    = nl + 1;

    /* walk header lines looking for Host: */
    while (rem > 0) {
        /* blank line = end of headers */
        if (*p == '\r' || *p == '\n') break;

        const char *eol = (const char *)memchr(p, '\n', (size_t)rem);
        int linelen = eol ? (int)(eol - p) : rem;
        /* strip trailing \r */
        int vlen = linelen;
        if (vlen > 0 && p[vlen - 1] == '\r') vlen--;

        if (ci_startswith(p, vlen, "host:", 5)) {
            /* extract value after "host:" */
            const char *val = p + 5;
            int vrem = vlen - 5;
            /* skip leading whitespace */
            while (vrem > 0 && (*val == ' ' || *val == '\t')) { val++; vrem--; }
            /* strip trailing whitespace */
            while (vrem > 0 && (val[vrem-1] == ' ' || val[vrem-1] == '\t')) vrem--;
            /* strip :port */
            const char *colon = (const char *)memchr(val, ':', (size_t)vrem);
            if (colon) vrem = (int)(colon - val);
            if (vrem <= 0) return 0;
            /* copy, truncate to buffer */
            if (vrem >= hostsz) vrem = hostsz - 1;
            memcpy(host, val, (size_t)vrem);
            host[vrem] = '\0';
            return 1;
        }

        if (!eol) break;
        rem -= linelen + 1;
        p    = eol + 1;
    }
    return 0;
}

/* ── Cleartext credential scanner (roadmap #16 phase 3) ── */

/* Minimal base64 decoder — only what the Authorization: Basic path
 * needs. Returns number of bytes written to `out` (up to outsz-1), or
 * -1 if the input contains an invalid char. Handles standard '=' pad
 * but doesn't require it. Never touches password bytes: the caller is
 * expected to split on ':' and hand only the username portion onward. */
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
        if (c >= 128 || T[c] < 0)
            return -1;
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
    if (op < outsz) out[op] = '\0';
    return op;
}

void http_snoop_scan_creds(const uint8_t *data, int len,
                           const char *src, const char *dst,
                           uint16_t dst_port)
{
    if (len < 32 || !src || !dst) return;

    const char *p   = (const char *)data;
    int         rem = len < 8192 ? len : 8192;

    /* Must look like an HTTP request, otherwise our header walk is
     * meaningless. Reusing the http_snoop() method sniff would double
     * the work; a fast prefix check is enough. */
    static const char *methods[] = {
        "GET ","POST ","PUT ","HEAD ","DELETE ",
        "OPTIONS ","PATCH ","CONNECT ","TRACE ", NULL
    };
    int is_req = 0;
    for (int i = 0; methods[i]; i++) {
        int ml = (int)strlen(methods[i]);
        if (rem >= ml && memcmp(p, methods[i], (size_t)ml) == 0) {
            is_req = 1; break;
        }
    }
    if (!is_req) return;

    /* skip request line */
    const char *nl = (const char *)memchr(p, '\n', (size_t)rem);
    if (!nl) return;
    rem -= (int)(nl - p) + 1;
    p    = nl + 1;

    while (rem > 0) {
        if (*p == '\r' || *p == '\n') break;
        const char *eol = (const char *)memchr(p, '\n', (size_t)rem);
        int linelen = eol ? (int)(eol - p) : rem;
        int vlen    = linelen;
        if (vlen > 0 && p[vlen - 1] == '\r') vlen--;

        if (ci_startswith(p, vlen, "authorization:", 14)) {
            const char *v = p + 14;
            int vrem = vlen - 14;
            while (vrem > 0 && (*v == ' ' || *v == '\t')) { v++; vrem--; }
            if (ci_startswith(v, vrem, "basic ", 6)) {
                const char *b64 = v + 6;
                int b64len      = vrem - 6;
                while (b64len > 0 && (*b64 == ' ' || *b64 == '\t')) {
                    b64++; b64len--;
                }
                char decoded[128];
                int dl = b64_decode(b64, b64len, decoded, (int)sizeof(decoded));
                if (dl > 0) {
                    /* Split on the first ':'. Username is everything
                     * before it. Password is everything after — we
                     * intentionally never touch that portion beyond
                     * noting "yes, one was on the wire." */
                    char *colon = memchr(decoded, ':', (size_t)dl);
                    if (colon) {
                        *colon = '\0';
                        int has_pw = (colon + 1 < decoded + dl);
                        cleartext_creds_record_user(src, dst, dst_port,
                                                    "HTTP-Basic", decoded);
                        if (has_pw)
                            cleartext_creds_mark_password(src, dst, dst_port,
                                                          "HTTP-Basic");
                    }
                }
            }
            return;   /* one Authorization header per request */
        }

        if (!eol) break;
        rem -= linelen + 1;
        p    = eol + 1;
    }
}
