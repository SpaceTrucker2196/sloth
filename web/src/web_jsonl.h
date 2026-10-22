/* slothweb JSONL record decoder (#159, M1).
 *
 * Every byte from the data socket is untrusted: sloth may be a
 * different build, the socket may be someone else's, and a record's
 * strings carry whatever was on the air. So one line is decoded by a
 * strict, bounded reader written for this, not by scanning for
 * `"key":` (which would read a field out of a hostile string's
 * contents) and not by research/mcp/json.c, which decodes \u only to
 * Latin-1 and does not check raw UTF-8.
 *
 * What a line must be, or it is refused whole:
 *   - one JSON object (RFC 8259), nothing after it but whitespace;
 *   - at most WEB_JL_MAX_LINE bytes (the framer enforces that), at most
 *     WEB_JL_MAX_FIELDS top-level members, nesting at most
 *     WEB_JL_MAX_DEPTH deep;
 *   - every string well-formed UTF-8 (RFC 3629) both raw and after \u
 *     decoding: no lone surrogate, no overlong, no raw control byte,
 *     and no \u0000, which would cut a C string short;
 *   - no member name twice at the top level (which "type" would win is
 *     exactly what a hostile line would like to choose);
 *   - a string "type" member.
 *
 * Top-level scalar members are kept (strings decoded, integers parsed);
 * nested arrays and objects are checked and skipped. Nothing is
 * allocated: the record holds its own decoded text. */
#ifndef SLOTHWEB_JSONL_H
#define SLOTHWEB_JSONL_H

#include <stddef.h>

/* sloth's own line buffer is 8 KB (src/jsonl.c LINEBUF); twice that
 * leaves room for a newer sloth without letting one line be unbounded. */
#define WEB_JL_MAX_LINE   16384
/* sensor_health, the widest record, has about 250 members. */
#define WEB_JL_MAX_FIELDS 384
#define WEB_JL_MAX_DEPTH  8

enum {
    WEB_J_STR = 1, WEB_J_INT, WEB_J_REAL, WEB_J_BOOL, WEB_J_NULL, WEB_J_NEST
};

enum {
    WEB_JL_OK = 0,
    WEB_JL_ESYNTAX,     /* not JSON, or truncated */
    WEB_JL_EUTF8,       /* ill-formed UTF-8, raw or escaped */
    WEB_JL_EDEPTH,
    WEB_JL_EFIELDS,
    WEB_JL_ENOTOBJ,
    WEB_JL_EDUP,
    WEB_JL_ETYPE,       /* no string "type" */
    WEB_JL_ELONG,       /* over WEB_JL_MAX_LINE (set by the framer) */
    WEB_JL_ECOUNT
};

typedef struct {
    const char *key;      /* NUL-terminated, in the record's text */
    int         kind;     /* WEB_J_* */
    const char *str;      /* WEB_J_STR: NUL-terminated decoded value */
    size_t      slen;
    long long   i;        /* WEB_J_INT, and WEB_J_BOOL as 0/1 */
    /* WEB_J_INT and WEB_J_REAL: the value as a double (M2's gauges are
     * sloth's "%.2f" rates). A number too long to convert, or one that
     * overflows, is NaN, which web_jl_num() refuses. */
    double      d;
} web_jfield_t;

typedef struct {
    int          n;
    web_jfield_t f[WEB_JL_MAX_FIELDS];
    size_t       tlen;
    /* A decoded string plus its NUL is never longer than its source
     * with both quotes, so the line's own size bounds the text. */
    char         text[WEB_JL_MAX_LINE + 1];
} web_jrec_t;

/* Decode one line (no trailing newline needed; one is whitespace).
 * WEB_JL_OK, or the WEB_JL_E* reason. */
int  web_jl_parse(const char *line, size_t len, web_jrec_t *r);

const web_jfield_t *web_jl_get(const web_jrec_t *r, const char *key);
/* The member's string, or NULL when absent or not a string. */
const char *web_jl_str(const web_jrec_t *r, const char *key);
/* The member's integer (or boolean), or def. */
long long   web_jl_int(const web_jrec_t *r, const char *key, long long def);

/* The member's number (integer or real) in *out when it is one and
 * finite: 1, else 0. */
int         web_jl_num(const web_jrec_t *r, const char *key, double *out);

const char *web_jl_error_name(int e);

#endif
