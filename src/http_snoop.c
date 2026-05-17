#include <string.h>
#include "http_snoop.h"

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
