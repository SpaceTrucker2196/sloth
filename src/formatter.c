#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "formatter.h"

/* Configured format — set once at startup from the --out-format flag,
 * read by emit_line() for every record. No mutex: writes happen at
 * startup before any emitter runs; reads are racy-but-safe (single
 * read of an enum word, no torn values on any sane CPU). */
static out_format_t g_format = OUT_FMT_JSONL;

int formatter_parse_name(const char *name, out_format_t *out) {
    if (!name || !out) return 0;
    if (strcmp(name, "jsonl")  == 0) { *out = OUT_FMT_JSONL;  return 1; }
    if (strcmp(name, "cef")    == 0) { *out = OUT_FMT_CEF;    return 1; }
    if (strcmp(name, "syslog") == 0) { *out = OUT_FMT_SYSLOG; return 1; }
    return 0;
}

out_format_t formatter_get(void)              { return g_format; }
void         formatter_set(out_format_t fmt)  { g_format = fmt; }

/* ── JSON tokeniser ─────────────────────────────────────────
 *
 * Sloth emits a known subset of JSON: top-level is always an object
 * with flat scalar values plus the occasional array of strings or
 * small objects. We only need to walk the top-level keys, so a tiny
 * scanner is enough — no need for a full RFC 8259 parser.
 *
 * State: pointer into the source string. Helpers advance the pointer
 * past whitespace, strings (with backslash escapes), arrays (matching
 * brackets), and objects (matching braces). Each returns the start
 * and end of the token it consumed. */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Consume a JSON string literal starting at `p` (which points to the
 * opening quote). Returns pointer just past the closing quote, or
 * NULL on malformed input. *out_start / *out_end point to the
 * contents (excluding quotes). */
static const char *scan_string(const char *p, const char **out_start,
                                const char **out_end) {
    if (*p != '"') return NULL;
    p++;
    *out_start = p;
    while (*p) {
        if (*p == '\\' && p[1]) { p += 2; continue; }
        if (*p == '"') { *out_end = p; return p + 1; }
        p++;
    }
    return NULL;
}

/* Consume a JSON value (string / number / true / false / null /
 * array / object). Returns pointer just past the end of the value.
 * *out_start / *out_end span the raw value bytes (including any
 * enclosing quotes / brackets). Returns NULL on malformed input. */
static const char *scan_value(const char *p, const char **out_start,
                               const char **out_end) {
    p = skip_ws(p);
    *out_start = p;
    if (*p == '"') {
        const char *s, *e;
        p = scan_string(p, &s, &e);
        if (!p) return NULL;
        *out_end = p;
        return p;
    }
    if (*p == '[' || *p == '{') {
        char open = *p;
        char close = open == '[' ? ']' : '}';
        int depth = 0;
        while (*p) {
            if (*p == '"') {
                const char *s, *e;
                const char *q = scan_string(p, &s, &e);
                if (!q) return NULL;
                p = q;
                continue;
            }
            if (*p == open)  depth++;
            if (*p == close) { depth--; if (depth == 0) { p++; break; } }
            p++;
        }
        if (depth != 0) return NULL;
        *out_end = p;
        return p;
    }
    /* Number / true / false / null — scan until next syntactic delim. */
    while (*p && *p != ',' && *p != '}' && *p != ']'
           && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    *out_end = p;
    return p;
}

/* Walk a flat top-level JSON object, yielding (key, value) byte
 * ranges. Calls `cb(ud, key_start, key_len, val_start, val_len)` for
 * each pair. Returns 1 on success, 0 on malformed input.
 *
 * Caller's cb may stop iteration by returning 0; the walk continues
 * regardless of its return for simplicity (we want all keys). */
typedef int (*kv_cb)(void *ud, const char *k, int klen,
                     const char *v, int vlen);
static int walk_object(const char *json, kv_cb cb, void *ud) {
    const char *p = skip_ws(json);
    if (*p != '{') return 0;
    p = skip_ws(p + 1);
    if (*p == '}') return 1;
    while (*p) {
        const char *ks, *ke;
        p = scan_string(p, &ks, &ke);
        if (!p) return 0;
        p = skip_ws(p);
        if (*p != ':') return 0;
        p = skip_ws(p + 1);
        const char *vs, *ve;
        p = scan_value(p, &vs, &ve);
        if (!p) return 0;
        cb(ud, ks, (int)(ke - ks), vs, (int)(ve - vs));
        p = skip_ws(p);
        if (*p == ',') { p = skip_ws(p + 1); continue; }
        if (*p == '}') return 1;
        return 0;
    }
    return 0;
}

/* ── CEF ────────────────────────────────────────────────────
 *
 * CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extensions
 *
 * Header pipes need backslash-escaping in the named fields; in
 * extensions, `=` and `\` need escaping. Newlines are forbidden in
 * the body — we replace with `\n`. */

static int cef_escape_field(const char *s, int n, char *out, int out_sz) {
    int o = 0;
    for (int i = 0; i < n && o + 2 < out_sz; i++) {
        char c = s[i];
        if (c == '|' || c == '\\') { out[o++] = '\\'; }
        if (c == '\n' || c == '\r') c = ' ';
        out[o++] = c;
    }
    out[o] = '\0';
    return o;
}

static int cef_escape_ext(const char *s, int n, char *out, int out_sz) {
    int o = 0;
    /* CEF extension values may be quoted strings from JSON; strip
     * leading/trailing quote and unescape JSON backslashes. */
    int start = 0, end = n;
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') { start = 1; end = n - 1; }
    for (int i = start; i < end && o + 2 < out_sz; i++) {
        char c = s[i];
        if (c == '\\' && i + 1 < end) {
            char nx = s[i + 1];
            if (nx == 'n') { out[o++] = ' '; i++; continue; }
            if (nx == 'r') { out[o++] = ' '; i++; continue; }
            if (nx == 't') { out[o++] = ' '; i++; continue; }
            if (nx == '"') { out[o++] = '"'; i++; continue; }
            if (nx == '\\'){ out[o++] = '\\'; i++; continue; }
        }
        if (c == '=' || c == '\\') { out[o++] = '\\'; }
        if (c == '\n' || c == '\r') c = ' ';
        out[o++] = c;
    }
    out[o] = '\0';
    return o;
}

struct cef_ctx {
    char *out;
    int   off;
    int   sz;
    int   first;
    /* Extracted by special-cased keys: */
    char type[32];
    int  severity;
};

/* Map sloth alert sev (0=LOW, 1=WARN, 2=CRIT) to CEF severity 0-10. */
static int cef_severity_from_sev(int sev) {
    if (sev <= 0) return 3;
    if (sev == 1) return 6;
    return 9;
}

static int cef_kv_cb(void *ud, const char *k, int kn,
                     const char *v, int vn) {
    struct cef_ctx *cx = (struct cef_ctx *)ud;
    /* Special-case the envelope keys — `type` goes into the header,
     * not the extensions. `sev` (alerts only) maps to severity. */
    if (kn == 4 && memcmp(k, "type", 4) == 0) {
        int start = 0, end = vn;
        if (vn >= 2 && v[0] == '"' && v[vn - 1] == '"') {
            start = 1; end = vn - 1;
        }
        int copy = end - start;
        if (copy > (int)sizeof(cx->type) - 1) copy = sizeof(cx->type) - 1;
        memcpy(cx->type, v + start, (size_t)copy);
        cx->type[copy] = '\0';
        return 1;
    }
    if (kn == 3 && memcmp(k, "sev", 3) == 0) {
        int sev = 0;
        for (int i = 0; i < vn && (v[i] >= '0' && v[i] <= '9'); i++) {
            sev = sev * 10 + (v[i] - '0');
        }
        cx->severity = cef_severity_from_sev(sev);
        return 1;   /* don't duplicate in extensions */
    }
    /* Emit `<space>key=val` (no leading space on first ext). */
    if (cx->off + kn + 2 >= cx->sz) return 1;
    if (cx->first) { cx->first = 0; } else { cx->out[cx->off++] = ' '; }
    memcpy(cx->out + cx->off, k, (size_t)kn);
    cx->off += kn;
    if (cx->off + 2 >= cx->sz) return 1;
    cx->out[cx->off++] = '=';
    /* Reserve room for at least one byte. */
    int wrote = cef_escape_ext(v, vn, cx->out + cx->off, cx->sz - cx->off);
    cx->off += wrote;
    return 1;
}

static int format_cef(const char *jsonl, char *out, int out_sz) {
    /* First pass: extract type + severity so we can lay down the
     * header before the extensions. We accomplish this in a single
     * walk by writing extensions into a scratch buffer and the
     * header inline once both keys have been seen — but simpler:
     * walk twice. The records are short so two passes is fine. */
    char scratch[2048];
    struct cef_ctx cx = {
        .out = scratch, .off = 0, .sz = (int)sizeof(scratch),
        .first = 1, .severity = 3,
    };
    cx.type[0] = '\0';
    if (!walk_object(jsonl, cef_kv_cb, &cx)) return -1;
    if (!cx.type[0]) return -1;

    char name_field[64];
    cef_escape_field(cx.type, (int)strlen(cx.type),
                     name_field, sizeof(name_field));
    int n = snprintf(out, (size_t)out_sz,
                     "CEF:0|sloth-net|sloth|1|%s|%s|%d|%.*s",
                     name_field, name_field, cx.severity,
                     cx.off, scratch);
    if (n < 0 || n >= out_sz) return -1;
    return n;
}

/* ── RFC 5424 syslog ────────────────────────────────────────
 *
 * <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
 *
 * We use PRI=134 (local0.info), VERSION=1, APP-NAME=sloth,
 * PROCID=pid, MSGID=record type. STRUCTURED-DATA is a single SD
 * element [sloth@32473 key1="val1" ...]; MSG is the original JSONL
 * (so a parser can recover full fidelity if it knows about sloth). */

static int syslog_sd_escape(const char *s, int n, char *out, int out_sz) {
    int o = 0;
    int start = 0, end = n;
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') { start = 1; end = n - 1; }
    for (int i = start; i < end && o + 2 < out_sz; i++) {
        char c = s[i];
        if (c == '\\' && i + 1 < end) {
            char nx = s[i + 1];
            if (nx == 'n' || nx == 'r' || nx == 't') {
                out[o++] = ' '; i++; continue;
            }
            if (nx == '"')  { out[o++] = '\\'; out[o++] = '"';  i++; continue; }
            if (nx == '\\') { out[o++] = '\\'; out[o++] = '\\'; i++; continue; }
        }
        if (c == '"' || c == '\\' || c == ']') { out[o++] = '\\'; }
        if (c == '\n' || c == '\r') c = ' ';
        out[o++] = c;
    }
    out[o] = '\0';
    return o;
}

struct syslog_ctx {
    char *out;
    int   off;
    int   sz;
    char  type[32];
};

static int syslog_kv_cb(void *ud, const char *k, int kn,
                        const char *v, int vn) {
    struct syslog_ctx *cx = (struct syslog_ctx *)ud;
    if (kn == 4 && memcmp(k, "type", 4) == 0) {
        int start = 0, end = vn;
        if (vn >= 2 && v[0] == '"' && v[vn - 1] == '"') {
            start = 1; end = vn - 1;
        }
        int copy = end - start;
        if (copy > (int)sizeof(cx->type) - 1) copy = sizeof(cx->type) - 1;
        memcpy(cx->type, v + start, (size_t)copy);
        cx->type[copy] = '\0';
        return 1;
    }
    /* Skip nested arrays/objects in structured-data — RFC 5424
     * doesn't allow them inside SD-PARAM values. Caller still gets
     * the full fidelity via the MSG (which is the original JSON). */
    if (vn > 0 && (v[0] == '[' || v[0] == '{')) return 1;

    if (cx->off + kn + 4 >= cx->sz) return 1;
    cx->out[cx->off++] = ' ';
    memcpy(cx->out + cx->off, k, (size_t)kn);
    cx->off += kn;
    cx->out[cx->off++] = '=';
    cx->out[cx->off++] = '"';
    int wrote = syslog_sd_escape(v, vn,
                                 cx->out + cx->off, cx->sz - cx->off - 2);
    cx->off += wrote;
    if (cx->off + 2 >= cx->sz) return 1;
    cx->out[cx->off++] = '"';
    return 1;
}

static int format_syslog(const char *jsonl, char *out, int out_sz) {
    char hostname[64] = "sloth";
    gethostname(hostname, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    /* Spaces in hostname break the syslog header — replace defensively. */
    for (int i = 0; hostname[i]; i++) {
        if (hostname[i] == ' ' || hostname[i] == '\t') hostname[i] = '-';
    }

    char sd_body[1600];
    struct syslog_ctx cx = {
        .out = sd_body, .off = 0, .sz = (int)sizeof(sd_body),
    };
    cx.type[0] = '\0';
    if (!walk_object(jsonl, syslog_kv_cb, &cx)) return -1;
    if (!cx.type[0]) return -1;
    sd_body[cx.off] = '\0';

    /* RFC 3339 UTC timestamp. */
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    int pid = (int)getpid();
    /* PRI 134 = facility 16 (local0) * 8 + severity 6 (info). */
    int n = snprintf(out, (size_t)out_sz,
                     "<134>1 %s %s sloth %d %s [sloth@32473%s] %s",
                     ts, hostname, pid, cx.type, sd_body, jsonl);
    if (n < 0 || n >= out_sz) return -1;
    return n;
}

int formatter_transform(const char *jsonl, char *out, int out_sz) {
    if (!jsonl || !out || out_sz < 2) return -1;
    switch (g_format) {
    case OUT_FMT_JSONL: {
        int n = (int)strlen(jsonl);
        if (n >= out_sz) return -1;
        memcpy(out, jsonl, (size_t)n);
        out[n] = '\0';
        return n;
    }
    case OUT_FMT_CEF:    return format_cef   (jsonl, out, out_sz);
    case OUT_FMT_SYSLOG: return format_syslog(jsonl, out, out_sz);
    }
    return -1;
}
