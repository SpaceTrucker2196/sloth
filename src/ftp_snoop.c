/* Passive FTP command-channel observer — roadmap #16 phase 3.
 *
 * FTP (RFC 959) sends control commands in cleartext on TCP/21:
 *   USER <username>\r\n
 *   PASS <password>\r\n
 * plus the rest of the command set. We capture the username; we do
 * not capture, hash, or truncate the password — just record the
 * fact that one was on the wire. */

#include <string.h>
#include "ftp_snoop.h"
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

int ftp_snoop(const uint8_t *data, int len,
              const char *src, const char *dst, uint16_t dst_port)
{
    if (!data || len < 5 || !src || !dst) return 0;

    const char *p = (const char *)data;
    int         rem = len < 512 ? len : 512;

    /* FTP commands terminate with CRLF. We accept a single command per
     * payload; command pipelining is rare on ftp/21. */
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
            cleartext_creds_record_user(src, dst, dst_port, "FTP", name);
        }
        return 1;
    }

    if (ci_startswith(p, line, "PASS ", 5)) {
        /* Never inspect the value — just mark the flow. */
        cleartext_creds_mark_password(src, dst, dst_port, "FTP");
        return 1;
    }

    /* Other FTP verbs (SYST, FEAT, PWD, LIST, ...) — recognise as FTP
     * so the packet can be labelled, but nothing to record. */
    static const char *cmds[] = {
        "QUIT","SYST","FEAT","PWD","CWD","LIST","RETR","STOR",
        "PORT","PASV","EPSV","TYPE","MODE","STRU","HELP","NOOP",
        "AUTH", NULL
    };
    for (int i = 0; cmds[i]; i++) {
        int cl = (int)strlen(cmds[i]);
        if (line >= cl && ci_startswith(p, cl, cmds[i], cl))
            return 1;
    }

    return 0;
}
