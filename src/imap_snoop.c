/* Passive IMAP observer — roadmap #16 phase 3.2.
 *
 * IMAP (RFC 3501) is line-oriented CRLF. Client commands are
 * tagged with an arbitrary alphanumeric label:
 *
 *     a001 LOGIN alice hunter2
 *     a001 LOGIN "alice" "hunter2"
 *     A007 login "user@example" "pass\"with\"quotes"
 *
 * We parse the LOGIN verb (case-insensitive), skip the tag prefix,
 * then extract the username as either a bare word (up to next
 * whitespace) or a double-quoted string. The password is
 * intentionally never read past the "yes, one is on the wire"
 * check — this file has no code path that stores or hashes
 * password bytes. */

#include <string.h>
#include "imap_snoop.h"
#include "cleartext_creds.h"

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

/* Read one whitespace-separated token from `p` (of length `rem`) into
 * out[outsz]. Handles double-quoted strings ("…"). Returns the number
 * of characters consumed from `p` including any surrounding quotes
 * and trailing whitespace, or 0 on parse failure / empty. */
static int read_token(const char *p, int rem, char *out, int outsz) {
    int i = 0;
    int op = 0;
    while (i < rem && (p[i] == ' ' || p[i] == '\t')) i++;
    if (i >= rem) return 0;

    if (p[i] == '"') {
        i++;
        while (i < rem && p[i] != '"' && op + 1 < outsz) {
            /* Backslash escapes are used inside IMAP quoted strings;
             * a full parser handles them, but for a username field
             * that's almost never quoted-with-escapes, treat a
             * backslash as a bail-out — better to drop the token
             * than to store a garbled name. */
            if (p[i] == '\\') return 0;
            out[op++] = p[i++];
        }
        if (i >= rem || p[i] != '"') return 0;
        i++;
    } else {
        while (i < rem && p[i] != ' ' && p[i] != '\t' && p[i] != '\r'
               && p[i] != '\n' && op + 1 < outsz) {
            out[op++] = p[i++];
        }
    }
    out[op] = '\0';
    /* Skip trailing whitespace so the caller can chain read_token. */
    while (i < rem && (p[i] == ' ' || p[i] == '\t')) i++;
    return op > 0 ? i : 0;
}

int imap_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port)
{
    if (!data || len < 8 || !src || !dst) return 0;

    const char *p = (const char *)data;
    int rem = len < 1024 ? len : 1024;

    const char *eol = memchr(p, '\n', (size_t)rem);
    if (!eol) return 0;
    int line = (int)(eol - p);
    if (line > 0 && p[line - 1] == '\r') line--;

    /* IMAP tag: alnum, up to a space. */
    int i = 0;
    while (i < line && p[i] != ' ' && p[i] != '\t') {
        char c = p[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '*' || c == '+';
        if (!ok) return 0;
        i++;
    }
    if (i == 0 || i >= line) return 0;
    while (i < line && (p[i] == ' ' || p[i] == '\t')) i++;

    /* Verb — case-insensitive LOGIN triggers cred capture. */
    int verb_start = i;
    while (i < line && p[i] != ' ' && p[i] != '\t') i++;
    int vlen = i - verb_start;

    /* Recognise other common verbs so we can label the packet even
     * when there's no cred to record. Server responses (untagged
     * `*` or the tag + status) fall through the tag check above and
     * come here — we treat them as valid IMAP lines. */
    static const char *verbs[] = {
        "LOGIN","AUTHENTICATE","CAPABILITY","NOOP","LOGOUT",
        "STARTTLS","SELECT","EXAMINE","LIST","LSUB","STATUS",
        "APPEND","FETCH","STORE","SEARCH","IDLE","OK","NO","BAD",
        "BYE","PREAUTH", NULL
    };
    int is_imap = 0;
    for (int j = 0; verbs[j]; j++)
        if (ci_eq(p + verb_start, vlen, verbs[j], (int)strlen(verbs[j]))) {
            is_imap = 1; break;
        }
    if (!is_imap) return 0;

    if (!ci_eq(p + verb_start, vlen, "LOGIN", 5)) return 1;

    while (i < line && (p[i] == ' ' || p[i] == '\t')) i++;
    char user[64];
    int consumed = read_token(p + i, line - i, user, sizeof(user));
    if (consumed <= 0) return 1;

    cleartext_creds_record_user(src, dst, dst_port, "IMAP", user);

    /* Read past the password token without inspecting it. If a
     * password token exists (whitespace-separated or quoted), mark
     * the flow. */
    i += consumed;
    while (i < line && (p[i] == ' ' || p[i] == '\t')) i++;
    if (i < line)
        cleartext_creds_mark_password(src, dst, dst_port, "IMAP");
    return 1;
}
