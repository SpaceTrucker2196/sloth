/* slothweb JSON writer (#159, M1). Every string that reaches a JSON
 * answer or an event goes through web_jw_str(), whatever its source.
 *
 * The escaping is RFC 8259 plus what keeps the text inert in an HTML
 * context: < > & ' are written as < > & ', so a
 * hostname or SSID carrying markup is never markup in the bytes we
 * send, even if a browser were made to sniff a JSON body as a document.
 * U+2028 / U+2029 are escaped because they end a line in older
 * JavaScript, and DEL and C1 (U+007F..U+009F) because C1 holds CSI.
 * Input should be valid UTF-8 (the stream decoder guarantees it for
 * stream strings); an invalid byte is written as � rather than
 * passed through. */
#ifndef SLOTHWEB_JSON_H
#define SLOTHWEB_JSON_H

#include <stddef.h>

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    int    overflow;    /* set once anything did not fit; sticky */
} web_jw_t;

/* Worst-case growth of one input byte under web_jw_strn(): "<" becomes
 * the six bytes <. Callers size buffers with it. */
#define WEB_JW_EXPAND 6

void web_jw_init(web_jw_t *w, char *buf, size_t cap);
void web_jw_raw(web_jw_t *w, const char *s);
void web_jw_str(web_jw_t *w, const char *s);          /* "..." escaped */
void web_jw_strn(web_jw_t *w, const char *s, size_t n);
void web_jw_int(web_jw_t *w, long long v);
/* "key": with the key escaped like any string. */
void web_jw_key(web_jw_t *w, const char *k);

/* Copy at most max bytes of valid UTF-8 s into out (out holds max + 1),
 * cut back to a code-point boundary so the copy is valid UTF-8 too. */
void web_utf8_copy(char *out, size_t max, const char *s);

/* Length of the well-formed UTF-8 sequence at p (RFC 3629: no
 * overlongs, no surrogates, nothing past U+10FFFF), with its code point
 * in *cp; 0 when p does not start one. Shared with the stream decoder,
 * so the reader and the writer agree on what valid means. */
size_t web_utf8_seq(const unsigned char *p, size_t n, unsigned *cp);

#endif
