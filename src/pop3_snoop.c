/* Passive POP3 observer — roadmap #16 phase 3.2.
 *
 * Mirrors src/ftp_snoop.c: extract the username from `USER <name>`,
 * mark the flow on `PASS`. Never inspect password bytes.
 *
 * POP3 (RFC 1939) is a line-oriented CRLF protocol. Servers speak
 * status lines starting `+OK` or `-ERR`; clients issue single-word
 * verbs followed by args. We ignore server responses and other
 * verbs (STAT/LIST/RETR/DELE/QUIT) — recognising them so the packet
 * can be labelled, but recording nothing. */

#include <string.h>
#include "pop3_snoop.h"
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

int pop3_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port)
{
    if (!data || len < 5 || !src || !dst) return 0;

    const char *p = (const char *)data;
    int rem = len < 512 ? len : 512;

    const char *eol = memchr(p, '\n', (size_t)rem);
    if (!eol) return 0;
    int line = (int)(eol - p);
    if (line > 0 && p[line - 1] == '\r') line--;

    if (ci_startswith(p, line, "USER ", 5)) {
        const char *u = p + 5;
        int urem = line - 5;
        while (urem > 0 && (*u == ' ' || *u == '\t')) { u++; urem--; }
        while (urem > 0 && (u[urem-1] == ' ' || u[urem-1] == '\t')) urem--;
        if (urem > 0) {
            char name[64];
            int nsz = urem < 63 ? urem : 63;
            memcpy(name, u, (size_t)nsz);
            name[nsz] = '\0';
            cleartext_creds_record_user(src, dst, dst_port, "POP3", name);
        }
        return 1;
    }

    if (ci_startswith(p, line, "PASS ", 5)) {
        cleartext_creds_mark_password(src, dst, dst_port, "POP3");
        return 1;
    }

    /* Other POP3 verbs — recognise but don't record. Includes server
     * greeting bytes ("+OK …" / "-ERR …") so the label is applied on
     * both directions of the flow. */
    static const char *cmds[] = {
        "STAT","LIST","RETR","DELE","NOOP","RSET","QUIT",
        "TOP","UIDL","APOP","CAPA","STLS",
        "+OK","-ERR", NULL
    };
    for (int i = 0; cmds[i]; i++) {
        int cl = (int)strlen(cmds[i]);
        if (line >= cl && ci_startswith(p, cl, cmds[i], cl))
            return 1;
    }

    return 0;
}
