/* slothweb-mcp's JSON: a bounded reader for the JSON-RPC requests it is
 * sent, a bounded appender for what it writes, and a copier that takes
 * slothweb's JSON answer through unchanged but for its bounds.
 *
 * The reader is research/mcp/json.c's design (recursive descent, fixed
 * node and text arrays, depth capped, every cap an error and never a
 * truncation) with one difference that matters here: a \uXXXX escape
 * decodes to UTF-8, surrogate pairs included, where that one stops at
 * Latin-1. A note an agent writes may hold any character, and a client
 * is free to send it escaped. Raw bytes above 0x7f pass through as they
 * came: slothweb decides whether a note is well-formed UTF-8, not this.
 *
 * The copier is not a parser of meaning. slothweb's answer is copied
 * token by token under an explicit stack (no recursion, so a hostile
 * depth cannot reach the C stack), its grammar checked as it goes, each
 * string kept in its escaped form exactly as slothweb wrote it and cut
 * at MCP_STR_MAX bytes on an escape and UTF-8 boundary. Nothing is
 * decoded, so an SSID's display form stays the display form and no
 * escaped byte becomes a raw one. */
#ifndef SLOTHWEB_MCP_JSON_H
#define SLOTHWEB_MCP_JSON_H

#include <stddef.h>

#define MJ_MAX_NODES  128
#define MJ_MAX_TEXT   16384
#define MJ_MAX_DEPTH  12
/* The copier's nesting bound: slothweb's deepest answer is the bundle's
 * (not served here) at about ten. */
#define MJ_COPY_DEPTH 32

typedef enum { MJ_NULL, MJ_BOOL, MJ_NUM, MJ_STR, MJ_ARR, MJ_OBJ } mj_type_t;

typedef struct {
    mj_type_t type;
    int    str;      /* offset into doc->text, for MJ_STR */
    int    slen;     /* its length: a decoded string may hold no NUL, but
                        the length is kept so none is assumed */
    int    key;      /* offset of the member name, or -1 */
    double num;
    int    boolean;
    int    child, next;
} mj_node_t;

typedef struct {
    mj_node_t nodes[MJ_MAX_NODES];
    int       n;
    char      text[MJ_MAX_TEXT];
    int       tlen;
} mj_doc_t;

/* Parse the n bytes of src (no NUL needed) into d. 0, or -1 on any
 * malformed input, any cap exceeded, a NUL (escaped or raw) inside a
 * string, or anything but whitespace after the root value. */
int mj_parse(mj_doc_t *d, const char *src, size_t n);
int mj_get(const mj_doc_t *d, int obj, const char *key);
const char *mj_str(const mj_doc_t *d, int node);
double mj_num(const mj_doc_t *d, int node, double dflt);

/* A bounded appender that latches overflow instead of truncating: the
 * caller checks `over` once at the end. */
typedef struct { char *buf; size_t cap, len; int over; } mj_sb_t;
void mj_sb_init(mj_sb_t *s, char *buf, size_t cap);
void mj_sb_raw(mj_sb_t *s, const char *str);
void mj_sb_rawn(mj_sb_t *s, const char *str, size_t n);
void mj_sb_int(mj_sb_t *s, long long v);
/* str as a JSON string, quotes included: '"', '\\' and every byte below
 * 0x20 escaped, the rest as it is. */
void mj_sb_str(mj_sb_t *s, const char *str);
void mj_sb_strn(mj_sb_t *s, const char *str, size_t n);

/* One JSON value (in, n bytes) appended to o as it is, whitespace
 * dropped, each string cut at strcap bytes of its escaped form with
 * MJ_CUT_MARK after it (*cut counts them). 0; -1 not one well-formed
 * JSON value, or nested past MJ_COPY_DEPTH; -2 it did not fit (o->over
 * is set). */
#define MJ_CUT_MARK "...[cut]"
int mj_copy(const char *in, size_t n, mj_sb_t *o, size_t strcap, int *cut);

#endif
