/* Passive SMTP AUTH observer — roadmap #16 phase 3.2.
 *
 * AUTH PLAIN payload format (RFC 4616):
 *
 *     [authzid] \0 authcid \0 passwd
 *
 * where authzid is optional. We record `authcid` as the username.
 * The passwd portion is deliberately never touched. */

#include <string.h>
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
        "220","221","250","354","421","450","451","452",
        "500","501","502","503","504","530","535",
        NULL
    };
    for (int i = 0; cmds[i]; i++) {
        int cl = (int)strlen(cmds[i]);
        if (line >= cl && ci_startswith(p, cl, cmds[i], cl))
            return 1;
    }

    return 0;
}
