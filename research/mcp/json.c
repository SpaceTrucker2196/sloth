#include <stdlib.h>
#include <string.h>

#include "json.h"

typedef struct {
    json_doc_t *d;
    const char *p;
    int         depth;
    int         bad;
} jp_t;

static int  parse_value(jp_t *j);

static void skip_ws(jp_t *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')
        j->p++;
}

static int new_node(jp_t *j, json_type_t t) {
    if (j->d->n >= JSON_MAX_NODES) { j->bad = 1; return -1; }
    int i = j->d->n++;
    json_node_t *nd = &j->d->nodes[i];
    nd->type = t;
    nd->str = nd->key = -1;
    nd->num = 0;
    nd->boolean = 0;
    nd->child = nd->next = -1;
    return i;
}

/* Returns the offset of the decoded string in doc->text, or -1. The
 * offset rather than a pointer because the text buffer is inside the
 * doc and nodes are copied around during parsing of arrays. */
static int parse_string(jp_t *j) {
    if (*j->p != '"') { j->bad = 1; return -1; }
    j->p++;
    int start = j->d->tlen;
    for (;;) {
        unsigned char c = (unsigned char)*j->p;
        if (c == '\0') { j->bad = 1; return -1; }
        if (c == '"') { j->p++; break; }
        /* Control characters are not legal raw inside a JSON string
         * (RFC 8259 §7). Accepting them would mean a newline in a tool
         * argument could not be told from the end of a request when the
         * transport is newline-delimited. */
        if (c < 0x20) { j->bad = 1; return -1; }

        int out = -1;              /* single byte, or -1 for a code point */
        unsigned cp = 0;
        if (c == '\\') {
            j->p++;
            switch (*j->p) {
            case '"':  out = '"';  break;
            case '\\': out = '\\'; break;
            case '/':  out = '/';  break;
            case 'b':  out = '\b'; break;
            case 'f':  out = '\f'; break;
            case 'n':  out = '\n'; break;
            case 'r':  out = '\r'; break;
            case 't':  out = '\t'; break;
            case 'u': {
                for (int k = 1; k <= 4; k++) {
                    char h = j->p[k];
                    unsigned v;
                    if      (h >= '0' && h <= '9') v = (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') v = (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') v = (unsigned)(h - 'A' + 10);
                    else { j->bad = 1; return -1; }
                    cp = (cp << 4) | v;
                }
                /* See json.h: above Latin-1 is refused rather than
                 * folded to '?' or split into a bad byte pair. */
                if (cp > 0xFF) { j->bad = 1; return -1; }
                j->p += 4;
                out = (int)cp;
                break;
            }
            default: j->bad = 1; return -1;
            }
            j->p++;
        } else {
            out = c;
            j->p++;
        }
        if (j->d->tlen + 1 >= JSON_MAX_TEXT) { j->bad = 1; return -1; }
        j->d->text[j->d->tlen++] = (char)out;
    }
    if (j->d->tlen + 1 > JSON_MAX_TEXT) { j->bad = 1; return -1; }
    j->d->text[j->d->tlen++] = '\0';
    return start;
}

static int lit(jp_t *j, const char *word) {
    size_t n = strlen(word);
    if (strncmp(j->p, word, n) != 0) { j->bad = 1; return 0; }
    j->p += n;
    return 1;
}

/* Container members share this: parse each element, chain it onto the
 * parent, and enforce the comma/close grammar. `keyed` distinguishes an
 * object (name, colon, value) from an array (value). */
static void parse_members(jp_t *j, int parent, char close, int keyed) {
    j->p++;                                   /* '{' or '[' */
    skip_ws(j);
    if (*j->p == close) { j->p++; return; }

    int last = -1;
    for (;;) {
        int key = -1;
        if (keyed) {
            skip_ws(j);
            key = parse_string(j);
            if (j->bad) return;
            skip_ws(j);
            if (*j->p != ':') { j->bad = 1; return; }
            j->p++;
        }
        int kid = parse_value(j);
        if (j->bad) return;
        j->d->nodes[kid].key = key;
        if (last < 0) j->d->nodes[parent].child = kid;
        else          j->d->nodes[last].next    = kid;
        last = kid;

        skip_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == close) { j->p++; return; }
        j->bad = 1;
        return;
    }
}

static int parse_value(jp_t *j) {
    skip_ws(j);
    if (++j->depth > JSON_MAX_DEPTH) { j->bad = 1; return -1; }

    int idx = -1;
    switch (*j->p) {
    case '{':
        idx = new_node(j, JSON_OBJ);
        if (idx >= 0) parse_members(j, idx, '}', 1);
        break;
    case '[':
        idx = new_node(j, JSON_ARR);
        if (idx >= 0) parse_members(j, idx, ']', 0);
        break;
    case '"': {
        int s = parse_string(j);
        if (j->bad) break;
        idx = new_node(j, JSON_STR);
        if (idx >= 0) j->d->nodes[idx].str = s;
        break;
    }
    case 't':
        if (lit(j, "true"))  { idx = new_node(j, JSON_BOOL);
                               if (idx >= 0) j->d->nodes[idx].boolean = 1; }
        break;
    case 'f':
        if (lit(j, "false")) idx = new_node(j, JSON_BOOL);
        break;
    case 'n':
        if (lit(j, "null"))  idx = new_node(j, JSON_NULL);
        break;
    default: {
        char *end = NULL;
        double v = strtod(j->p, &end);
        /* strtod accepts "inf" and "nan", which JSON does not, and it
         * accepts a leading '+'. Requiring the first character to be a
         * digit or '-' rejects all three without a second parser. */
        const char *q = j->p;
        if (end == q || (*q != '-' && (*q < '0' || *q > '9'))) {
            j->bad = 1;
            break;
        }
        /* Leading zeros are not JSON (RFC 8259 §6) but strtod takes
         * them, so "007" would parse as 7. Refusing matters because it
         * is the shape a hand-written or truncated id arrives in, and a
         * request whose framing is already wrong should not be
         * answered. */
        if (*q == '-') q++;
        if (q[0] == '0' && q[1] >= '0' && q[1] <= '9') { j->bad = 1; break; }
        j->p = end;
        idx = new_node(j, JSON_NUM);
        if (idx >= 0) j->d->nodes[idx].num = v;
        break;
    }
    }
    j->depth--;
    if (idx < 0) j->bad = 1;
    return idx;
}

int json_parse(json_doc_t *d, const char *src) {
    if (!d || !src) return -1;
    d->n = 0;
    d->tlen = 0;

    jp_t j = { d, src, 0, 0 };
    int root = parse_value(&j);
    if (j.bad || root != 0) return -1;
    skip_ws(&j);
    /* Trailing content is an error rather than ignored: over a
     * newline-delimited transport, "{...} {...}" on one line means the
     * framing has already gone wrong upstream. */
    if (*j.p != '\0') return -1;
    return 0;
}

int json_obj_get(const json_doc_t *d, int obj, const char *key) {
    if (!d || !key || obj < 0 || obj >= d->n) return -1;
    if (d->nodes[obj].type != JSON_OBJ) return -1;
    for (int i = d->nodes[obj].child; i >= 0; i = d->nodes[i].next) {
        int k = d->nodes[i].key;
        if (k >= 0 && strcmp(&d->text[k], key) == 0) return i;
    }
    return -1;
}

const char *json_str(const json_doc_t *d, int node) {
    if (!d || node < 0 || node >= d->n) return NULL;
    if (d->nodes[node].type != JSON_STR) return NULL;
    return &d->text[d->nodes[node].str];
}

double json_num(const json_doc_t *d, int node, double dflt) {
    if (!d || node < 0 || node >= d->n) return dflt;
    if (d->nodes[node].type != JSON_NUM) return dflt;
    return d->nodes[node].num;
}

int json_esc_append(char *out, size_t cap, const char *in) {
    if (!out || !in) return -1;
    size_t o = strlen(out);
    /* Every append checks against cap before writing, so a response
     * that would overflow is reported as a failure and the caller
     * abandons it. Truncated JSON is not a smaller answer, it is an
     * unparseable one. */
    if (o + 1 >= cap) return -1;
    out[o++] = '"';
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        char buf[8];
        const char *add = buf;
        size_t n;
        switch (*p) {
        case '"':  memcpy(buf, "\\\"", 2); n = 2; break;
        case '\\': memcpy(buf, "\\\\", 2); n = 2; break;
        case '\n': memcpy(buf, "\\n",  2); n = 2; break;
        case '\r': memcpy(buf, "\\r",  2); n = 2; break;
        case '\t': memcpy(buf, "\\t",  2); n = 2; break;
        case '\b': memcpy(buf, "\\b",  2); n = 2; break;
        case '\f': memcpy(buf, "\\f",  2); n = 2; break;
        default:
            if (*p < 0x20) {
                static const char hex[] = "0123456789abcdef";
                buf[0] = '\\'; buf[1] = 'u'; buf[2] = '0'; buf[3] = '0';
                buf[4] = hex[(*p >> 4) & 0xF];
                buf[5] = hex[*p & 0xF];
                n = 6;
            } else {
                buf[0] = (char)*p;
                n = 1;
            }
            break;
        }
        if (o + n + 2 > cap) { out[o] = '\0'; return -1; }
        memcpy(out + o, add, n);
        o += n;
    }
    if (o + 2 > cap) { out[o] = '\0'; return -1; }
    out[o++] = '"';
    out[o] = '\0';
    return 0;
}
