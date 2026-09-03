#ifndef RESEARCH_MCP_JSON_H
#define RESEARCH_MCP_JSON_H

#include <stddef.h>

/* A minimal JSON reader, for the MCP transport only — issue #73.
 *
 * This tree already has jsonl.c, which *writes* JSON and cannot read it.
 * Speaking JSON-RPC needs a reader, and the alternatives were vendoring
 * a parser into a codebase that has deliberately carried no third-party
 * source, or scanning for `"key":` in the raw text. The scan is what it
 * looks like from far away — cheap and obvious — and it is wrong in a
 * way that matters here: a request whose *arguments* contain the string
 * `"name"` (a search for `alert "name" field`, say) would have its tool
 * name read out of the user's own query. Input arriving over a pipe
 * from something other than us is exactly where that stops being
 * hypothetical.
 *
 * So: a real recursive-descent parser, bounded, no allocation, with the
 * subset MCP needs and nothing else. What it deliberately does not do:
 *
 *   - \u escapes decode only to Latin-1; anything above U+00FF is a
 *     parse error rather than a mangled byte. The alternative is
 *     silently emitting invalid UTF-8.
 *   - No duplicate-key handling: the first wins, which is what
 *     json_obj_get finds. RFC 8259 leaves this to the implementation.
 *   - Numbers are strtod'd. JSON-RPC ids that need bit-exact round-trip
 *     past 2^53 do not survive; nothing generates those.
 *
 * Depth, node count and text are all fixed-cap, and exceeding any of
 * them is an error, never a truncation. A half-parsed request answered
 * as if it were whole is the failure mode worth engineering against. */

#define JSON_MAX_NODES  256
#define JSON_MAX_TEXT   8192
#define JSON_MAX_DEPTH  16

typedef enum {
    JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ
} json_type_t;

typedef struct {
    json_type_t type;
    int    str;      /* offset into doc->text, for JSON_STR */
    int    key;      /* offset into doc->text for the member name, or -1 */
    double num;
    int    boolean;
    int    child;    /* first child node index, or -1 */
    int    next;     /* next sibling node index, or -1 */
} json_node_t;

typedef struct {
    json_node_t nodes[JSON_MAX_NODES];
    int         n;
    char        text[JSON_MAX_TEXT];
    int         tlen;
} json_doc_t;

/* Parse `src` into `d`. Returns 0 on success, -1 on any malformed input,
 * any cap exceeded, or trailing non-whitespace after the root value.
 * On failure `d` must not be read. */
int json_parse(json_doc_t *d, const char *src);

/* Member of an object node by name, or -1. Returns -1 for a non-object,
 * so `json_obj_get(d, json_obj_get(d, 0, "params"), "name")` is safe
 * when `params` is absent. */
int json_obj_get(const json_doc_t *d, int obj, const char *key);

/* The decoded string of a JSON_STR node, or NULL for any other type or
 * for -1. Callers use the NULL to mean "absent or not a string" — the
 * two cases have the same handling everywhere in the dispatcher. */
const char *json_str(const json_doc_t *d, int node);

/* The value of a JSON_NUM node, or `dflt` for any other type or -1. */
double json_num(const json_doc_t *d, int node, double dflt);

/* Append `in` to `out` as a JSON string *including* the surrounding
 * quotes. Returns 0 on success, -1 if it would not fit — the caller
 * must treat that as a failed response, not a short one. */
int json_esc_append(char *out, size_t cap, const char *in);

#endif /* RESEARCH_MCP_JSON_H */
