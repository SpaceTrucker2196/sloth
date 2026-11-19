/* sloth's intel-pack reader; contract in intel_read.h, format in
 * docs/wiki/pack-schema.md. */
#include "intel_read.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sloth.h"
#include "tool_fingerprint.h"
#include "ble_watchlist.h"

const char *const ir_pack_names[IR_NPACKS] = {
    "attacker-ouis", "ble-watchlist", "camera-vendor",
    "oui-builtin", "surveillance-endpoints", "tool-fingerprints",
};

#define TOOL_NAME(x) { #x, (long)(x) }
const ir_name_t ir_tool_names[] = {
    TOOL_NAME(SLOTH_TOOL_HOSTAPD_MANA),  TOOL_NAME(SLOTH_TOOL_EAPHAMMER),
    TOOL_NAME(SLOTH_TOOL_HCXDUMPTOOL),   TOOL_NAME(SLOTH_TOOL_ESP32_MARAUDER),
    TOOL_NAME(SLOTH_TOOL_WIFI_DUCK),     TOOL_NAME(SLOTH_TOOL_FLIPPER_ZERO),
    TOOL_NAME(SLOTH_TOOL_PINEAPPLE_MK7),
};
const int ir_tool_names_n = (int)(sizeof(ir_tool_names) / sizeof(ir_tool_names[0]));

const ir_name_t ir_flag_names[] = {
    TOOL_NAME(AP_FP_FLAG_WPS_UUID_ZERO), TOOL_NAME(AP_FP_FLAG_HT_PRESENT),
    TOOL_NAME(AP_FP_FLAG_VHT_PRESENT),   TOOL_NAME(AP_FP_FLAG_HE_PRESENT),
    TOOL_NAME(AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS),
    TOOL_NAME(AP_FP_FLAG_HAK5_OUI),      TOOL_NAME(AP_FP_FLAG_ESPRESSIF_OUI),
};
const int ir_flag_names_n = (int)(sizeof(ir_flag_names) / sizeof(ir_flag_names[0]));
#undef TOOL_NAME

const char *const ir_ble_match_names[4] = { NULL, "mfr", "svc_data", "uuid16" };

/* The alert fields a tool row's strings are copied into (engine.c's
 * stamp_signature()): a longer value would arrive cut. */
#define SIG_ID_MAX       (sizeof(((alert_t *)0)->sig_id) - 1)
#define SIG_VERSION_MAX  (sizeof(((alert_t *)0)->sig_version) - 1)
#define SIG_EVIDENCE_MAX (sizeof(((alert_t *)0)->sig_evidence) - 1)

static int seterr(char *err, size_t errsz, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
    return -1;
}

char *ir_slurp(const char *path, long max, size_t *len, char *err, size_t errsz) {
    FILE *f = fopen(path, "rb");
    if (!f) { seterr(err, errsz, "%s: %s", path, strerror(errno)); return NULL; }
    char *b = malloc((size_t)max + 1);
    if (!b) { fclose(f); seterr(err, errsz, "%s: out of memory", path); return NULL; }
    size_t n = fread(b, 1, (size_t)max + 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) { free(b); seterr(err, errsz, "%s: read error", path); return NULL; }
    if (n > (size_t)max) {
        free(b);
        seterr(err, errsz, "%s: longer than %ld bytes", path, max);
        return NULL;
    }
    b[n] = '\0';
    *len = n;
    return b;
}

/* ── Strict JSON for the manifest ─────────────────────────────────── */

typedef enum { JV_NULL, JV_BOOL, JV_INT, JV_STR, JV_ARR, JV_OBJ } jv_kind_t;

typedef struct {
    const char *p, *end;
    char       *err;
    size_t      errsz;
    int         failed;
} jp_t;

static int jfail(jp_t *j, const char *what) {
    if (!j->failed) seterr(j->err, j->errsz, "manifest: %s", what);
    j->failed = 1;
    return -1;
}

static void jws(jp_t *j) {
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' ||
                             *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static int hex4(const char *s, unsigned *v) {
    *v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return -1;
        *v = *v * 16 + (unsigned)d;
    }
    return 0;
}

static int put_utf8(char *out, size_t cap, size_t *n, unsigned cp) {
    unsigned char b[4];
    int k;
    if (cp < 0x80)        { b[0] = (unsigned char)cp; k = 1; }
    else if (cp < 0x800)  { b[0] = (unsigned char)(0xC0 | cp >> 6);
                            b[1] = (unsigned char)(0x80 | (cp & 0x3F)); k = 2; }
    else if (cp < 0x10000){ b[0] = (unsigned char)(0xE0 | cp >> 12);
                            b[1] = (unsigned char)(0x80 | (cp >> 6 & 0x3F));
                            b[2] = (unsigned char)(0x80 | (cp & 0x3F)); k = 3; }
    else                  { b[0] = (unsigned char)(0xF0 | cp >> 18);
                            b[1] = (unsigned char)(0x80 | (cp >> 12 & 0x3F));
                            b[2] = (unsigned char)(0x80 | (cp >> 6 & 0x3F));
                            b[3] = (unsigned char)(0x80 | (cp & 0x3F)); k = 4; }
    if (*n + (size_t)k >= cap) return -1;
    memcpy(out + *n, b, (size_t)k);
    *n += (size_t)k;
    return 0;
}

/* Length of the well-formed UTF-8 sequence at s (n bytes left), or 0. */
static int utf8_len(const unsigned char *s, size_t n) {
    if (s[0] < 0x80) return 1;
    int k; unsigned cp;
    if ((s[0] & 0xE0) == 0xC0)      { k = 2; cp = s[0] & 0x1Fu; }
    else if ((s[0] & 0xF0) == 0xE0) { k = 3; cp = s[0] & 0x0Fu; }
    else if ((s[0] & 0xF8) == 0xF0) { k = 4; cp = s[0] & 0x07u; }
    else return 0;
    if ((size_t)k > n) return 0;
    for (int i = 1; i < k; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = cp << 6 | (s[i] & 0x3Fu);
    }
    if ((k == 2 && cp < 0x80) || (k == 3 && cp < 0x800) || (k == 4 && cp < 0x10000) ||
        cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return k;
}

/* A JSON string into out (cap bytes with the NUL). */
static int jstring(jp_t *j, char *out, size_t cap) {
    if (j->p >= j->end || *j->p != '"') return jfail(j, "expected a string");
    j->p++;
    size_t n = 0;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p;
        if (c < 0x20) return jfail(j, "control character in a string");
        if (c == '\\') {
            if (j->end - j->p < 2) return jfail(j, "truncated escape");
            char e = j->p[1];
            j->p += 2;
            const char *simple = "\"\\/bfnrt", *val = "\"\\/\b\f\n\r\t";
            const char *hit = strchr(simple, e);
            if (e && hit) {
                if (n + 1 >= cap) return jfail(j, "string too long");
                out[n++] = val[hit - simple];
                continue;
            }
            if (e != 'u' || j->end - j->p < 4) return jfail(j, "bad escape");
            unsigned cp;
            if (hex4(j->p, &cp) != 0) return jfail(j, "bad \\u escape");
            j->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                unsigned lo;
                if (j->end - j->p < 6 || j->p[0] != '\\' || j->p[1] != 'u' ||
                    hex4(j->p + 2, &lo) != 0 || lo < 0xDC00 || lo > 0xDFFF)
                    return jfail(j, "unpaired surrogate");
                j->p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return jfail(j, "unpaired surrogate");
            }
            if (cp == 0) return jfail(j, "NUL in a string");
            if (put_utf8(out, cap, &n, cp) != 0) return jfail(j, "string too long");
            continue;
        }
        int k = utf8_len((const unsigned char *)j->p, (size_t)(j->end - j->p));
        if (k == 0) return jfail(j, "invalid UTF-8");
        if (n + (size_t)k >= cap) return jfail(j, "string too long");
        memcpy(out + n, j->p, (size_t)k);
        n += (size_t)k;
        j->p += k;
    }
    if (j->p >= j->end) return jfail(j, "unterminated string");
    j->p++;
    out[n] = '\0';
    return 0;
}

/* Integers only (pack-schema §2): no fraction, no exponent, no '+'. */
static int jint(jp_t *j, long long *v) {
    const char *s = j->p;
    int neg = 0;
    if (s < j->end && *s == '-') { neg = 1; s++; }
    if (s >= j->end || *s < '0' || *s > '9') return jfail(j, "expected an integer");
    if (*s == '0' && s + 1 < j->end && s[1] >= '0' && s[1] <= '9')
        return jfail(j, "leading zero");
    long long x = 0;
    int digits = 0;
    while (s < j->end && *s >= '0' && *s <= '9') {
        if (++digits > 15) return jfail(j, "integer out of range");
        x = x * 10 + (*s - '0');
        s++;
    }
    if (s < j->end && (*s == '.' || *s == 'e' || *s == 'E'))
        return jfail(j, "not an integer");
    j->p = s;
    *v = neg ? -x : x;
    return 0;
}

static int jlit(jp_t *j, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, lit, n) != 0)
        return jfail(j, "bad literal");
    j->p += n;
    return 0;
}

/* What kind of value starts here (without consuming it). */
static int jpeek(jp_t *j, jv_kind_t *k) {
    jws(j);
    if (j->p >= j->end) return jfail(j, "unexpected end");
    switch (*j->p) {
    case 'n': *k = JV_NULL; return 0;
    case 't': case 'f': *k = JV_BOOL; return 0;
    case '"': *k = JV_STR; return 0;
    case '[': *k = JV_ARR; return 0;
    case '{': *k = JV_OBJ; return 0;
    default:
        if (*j->p == '-' || (*j->p >= '0' && *j->p <= '9')) { *k = JV_INT; return 0; }
        return jfail(j, "unexpected character");
    }
}

/* Member names seen in one object, for the duplicate check. */
typedef struct { char name[16][24]; int n; } jseen_t;

static int jseen_add(jp_t *j, jseen_t *s, const char *name) {
    for (int i = 0; i < s->n; i++)
        if (!strcmp(s->name[i], name)) return jfail(j, "duplicate member");
    if (s->n >= 16) return jfail(j, "too many members");
    snprintf(s->name[s->n++], sizeof(s->name[0]), "%s", name);
    return 0;
}

/* A file name directly inside the pack directory, from a small ASCII
 * alphabet. pack-schema §2 allows forward-slash paths; sloth's six
 * packs use none, and taking only a flat name means a listed path can
 * never leave the directory (no '/', so no "..", no absolute path) and
 * the one-level stray-file scan in ir_pack_verify() sees everything a
 * manifest could list. A leading '.' is refused too: ".", ".." and
 * hidden files are never pack data. */
static int path_ok(const char *p) {
    static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-";
    size_t n = strlen(p);
    return n > 0 && n <= IR_PATH_MAX && p[0] != '.' && strspn(p, alphabet) == n;
}

static int hex64_ok(const char *s) {
    if (strlen(s) != 64) return 0;
    for (int i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

static int date_ok(const char *s) {
    if (strlen(s) != 10 || s[4] != '-' || s[7] != '-') return 0;
    for (int i = 0; i < 10; i++)
        if (i != 4 && i != 7 && (s[i] < '0' || s[i] > '9')) return 0;
    int mo = (s[5] - '0') * 10 + (s[6] - '0');
    int d  = (s[8] - '0') * 10 + (s[9] - '0');
    return mo >= 1 && mo <= 12 && d >= 1 && d <= 31;
}

static int rfc3339_ok(const char *s) {
    /* YYYY-MM-DDTHH:MM:SSZ */
    if (strlen(s) != 20 || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z')
        return 0;
    char d[11];
    memcpy(d, s, 10);
    d[10] = '\0';
    if (!date_ok(d)) return 0;
    for (int i = 11; i < 19; i++)
        if (i != 13 && i != 16 && (s[i] < '0' || s[i] > '9')) return 0;
    return 1;
}

int ir_semver_ok(const char *s) {
    int parts = 0;
    const char *p = s;
    for (;;) {
        if (*p < '0' || *p > '9') return 0;
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') return 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') { p++; if (++digits > 9) return 0; }
        parts++;
        if (*p == '\0') return parts == 3;
        if (*p != '.' || parts == 3) return 0;
        p++;
    }
}

static const char *const k_formats[] = {
    "csv-rows", "md-document", "csv-ieee-registry", "csv-value-name",
    "md-vendor-entry", NULL
};

static int jfile(jp_t *j, ir_file_t *f) {
    jws(j);
    if (j->p >= j->end || *j->p != '{') return jfail(j, "a file entry is not an object");
    j->p++;
    jseen_t seen = { .n = 0 };
    int have_path = 0, have_sha = 0, have_bytes = 0, have_url = 0, have_ret = 0,
        have_lic = 0, have_fmt = 0;
    f->rows = -1;
    jws(j);
    if (j->p < j->end && *j->p == '}') return jfail(j, "an empty file entry");
    for (;;) {
        char name[24], sbuf[1024];
        jws(j);
        if (jstring(j, name, sizeof(name)) != 0) return -1;
        if (jseen_add(j, &seen, name) != 0) return -1;
        jws(j);
        if (j->p >= j->end || *j->p != ':') return jfail(j, "expected ':'");
        j->p++;
        jv_kind_t k;
        if (jpeek(j, &k) != 0) return -1;
        if (!strcmp(name, "bytes") || !strcmp(name, "rows")) {
            long long v;
            if (k != JV_INT || jint(j, &v) != 0 || v < 0)
                return jfail(j, "bytes and rows are non-negative integers");
            if (name[0] == 'b') { f->bytes = v; have_bytes = 1; }
            else f->rows = v;
        } else {
            if (k != JV_STR) return jfail(j, "a file field is not a string");
            if (jstring(j, sbuf, sizeof(sbuf)) != 0) return -1;
            if (!strcmp(name, "path")) {
                if (!path_ok(sbuf)) return jfail(j, "a file path is not a plain pack-relative name");
                memcpy(f->path, sbuf, strlen(sbuf) + 1);   /* path_ok() bounds it */
                have_path = 1;
            } else if (!strcmp(name, "sha256")) {
                if (!hex64_ok(sbuf)) return jfail(j, "sha256 is not 64 lowercase hex digits");
                memcpy(f->sha256, sbuf, 65);
                have_sha = 1;
            } else if (!strcmp(name, "source_url")) {
                if (!sbuf[0]) return jfail(j, "empty source_url");
                have_url = 1;
            } else if (!strcmp(name, "retrieved")) {
                if (!date_ok(sbuf)) return jfail(j, "retrieved is not YYYY-MM-DD");
                have_ret = 1;
            } else if (!strcmp(name, "licence")) {
                if (!sbuf[0]) return jfail(j, "empty licence");
                have_lic = 1;
            } else if (!strcmp(name, "format")) {
                int known = 0;
                for (int i = 0; k_formats[i]; i++) if (!strcmp(sbuf, k_formats[i])) known = 1;
                if (!known) return jfail(j, "unknown file format");
                memcpy(f->format, sbuf, strlen(sbuf) + 1);   /* a k_formats entry: short */
                have_fmt = 1;
            } else if (!strcmp(name, "notes")) {
                /* free text */
            } else {
                return jfail(j, "a file field v1 does not define");
            }
        }
        jws(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == '}') { j->p++; break; }
        return jfail(j, "expected ',' or '}'");
    }
    if (!(have_path && have_sha && have_bytes && have_url && have_ret && have_lic && have_fmt))
        return jfail(j, "a file entry lacks a required field");
    if (f->rows >= 0 && strncmp(f->format, "csv-", 4) != 0)
        return jfail(j, "rows on a file that is not a CSV");
    return 0;
}

int ir_manifest_parse(const char *json, size_t len, ir_manifest_t *m,
                      char *err, size_t errsz) {
    memset(m, 0, sizeof(*m));
    jp_t j = { json, json + len, err, errsz, 0 };
    jws(&j);
    if (j.p >= j.end || *j.p != '{') return jfail(&j, "not a JSON object");
    j.p++;
    jseen_t seen = { .n = 0 };
    int have_sv = 0, have_name = 0, have_ver = 0, have_bt = 0, have_files = 0;
    jws(&j);
    if (j.p < j.end && *j.p == '}') return jfail(&j, "empty object");
    for (;;) {
        char name[24], sbuf[4096];
        jws(&j);
        if (jstring(&j, name, sizeof(name)) != 0) return -1;
        if (jseen_add(&j, &seen, name) != 0) return -1;
        jws(&j);
        if (j.p >= j.end || *j.p != ':') return jfail(&j, "expected ':'");
        j.p++;
        jv_kind_t k;
        if (jpeek(&j, &k) != 0) return -1;
        if (!strcmp(name, "schema_version")) {
            long long v;
            if (k != JV_INT || jint(&j, &v) != 0) return jfail(&j, "schema_version is not an integer");
            /* A version this reader does not know is refused, never
             * guessed at (pack-schema §2.1). */
            if (v != IR_SCHEMA_VERSION) return jfail(&j, "unknown schema_version");
            have_sv = 1;
        } else if (!strcmp(name, "pack_name") || !strcmp(name, "pack_version") ||
                   !strcmp(name, "build_time") || !strcmp(name, "notes") ||
                   !strcmp(name, "tier")) {
            if (k != JV_STR) return jfail(&j, "a string field is not a string");
            if (jstring(&j, sbuf, sizeof(sbuf)) != 0) return -1;
            if (!strcmp(name, "pack_name")) {
                size_t n = strlen(sbuf);
                if (n == 0 || n > 63 || sbuf[0] == '-') return jfail(&j, "bad pack_name");
                for (size_t i = 0; i < n; i++)
                    if (!((sbuf[i] >= 'a' && sbuf[i] <= 'z') ||
                          (sbuf[i] >= '0' && sbuf[i] <= '9') || sbuf[i] == '-'))
                        return jfail(&j, "bad pack_name");
                memcpy(m->pack_name, sbuf, n + 1);
                have_name = 1;
            } else if (!strcmp(name, "pack_version")) {
                if (!ir_semver_ok(sbuf)) return jfail(&j, "pack_version is not MAJOR.MINOR.PATCH");
                if (strlen(sbuf) >= sizeof(m->pack_version)) return jfail(&j, "pack_version too long");
                memcpy(m->pack_version, sbuf, strlen(sbuf) + 1);
                have_ver = 1;
            } else if (!strcmp(name, "build_time")) {
                if (!rfc3339_ok(sbuf)) return jfail(&j, "build_time is not YYYY-MM-DDTHH:MM:SSZ");
                have_bt = 1;
            } else if (!strcmp(name, "tier")) {
                /* Only a table-tier pack is compiled into a consumer. */
                if (strcmp(sbuf, "table") != 0) return jfail(&j, "tier is not \"table\"");
            }
        } else if (!strcmp(name, "country")) {
            if (k == JV_NULL) { if (jlit(&j, "null") != 0) return -1; }
            else {
                if (k != JV_STR || jstring(&j, sbuf, sizeof(sbuf)) != 0 ||
                    strlen(sbuf) != 2 || sbuf[0] < 'A' || sbuf[0] > 'Z' ||
                    sbuf[1] < 'A' || sbuf[1] > 'Z')
                    return jfail(&j, "country is not null or an ISO 3166-1 alpha-2 code");
            }
        } else if (!strcmp(name, "pii")) {
            if (k != JV_BOOL) return jfail(&j, "pii is not a boolean");
            if (*j.p == 't') return jfail(&j, "a pack with personal data is never compiled in");
            if (jlit(&j, "false") != 0) return -1;
        } else if (!strcmp(name, "files")) {
            if (k != JV_ARR) return jfail(&j, "files is not an array");
            j.p++;
            jws(&j);
            if (j.p < j.end && *j.p == ']') return jfail(&j, "files is empty");
            for (;;) {
                if (m->nfiles >= IR_MAX_FILES) return jfail(&j, "too many files");
                ir_file_t *f = &m->files[m->nfiles];
                if (jfile(&j, f) != 0) return -1;
                for (int i = 0; i < m->nfiles; i++)
                    if (!strcmp(m->files[i].path, f->path)) return jfail(&j, "a path listed twice");
                if (!strcmp(f->path, "manifest.json")) return jfail(&j, "the manifest lists itself");
                m->nfiles++;
                jws(&j);
                if (j.p < j.end && *j.p == ',') { j.p++; continue; }
                if (j.p < j.end && *j.p == ']') { j.p++; break; }
                return jfail(&j, "expected ',' or ']'");
            }
            have_files = 1;
        } else {
            return jfail(&j, "a field v1 does not define");
        }
        jws(&j);
        if (j.p < j.end && *j.p == ',') { j.p++; continue; }
        if (j.p < j.end && *j.p == '}') { j.p++; break; }
        return jfail(&j, "expected ',' or '}'");
    }
    jws(&j);
    if (j.p != j.end) return jfail(&j, "trailing bytes after the object");
    if (!(have_sv && have_name && have_ver && have_bt && have_files))
        return jfail(&j, "a required field is missing");
    return 0;
}

/* ── CSV (RFC 4180) ───────────────────────────────────────────────── */

void ir_csv_free(ir_csv_t *c) {
    if (!c->cell) return;
    for (size_t i = 0; i < (size_t)c->nrec * (size_t)c->ncol; i++) free(c->cell[i]);
    free(c->cell);
    c->cell = NULL;
}

/* One field at *pp; NUL-terminated copy in *out. Returns the byte after
 * it (',' '\n' or end) through *pp. */
static int csv_field(const char **pp, const char *end, char **out,
                     long rec, char *err, size_t errsz) {
    const char *p = *pp;
    size_t cap = 64, n = 0;
    char *b = malloc(cap);
    if (!b) return seterr(err, errsz, "record %ld: out of memory", rec);
    if (p < end && *p == '"') {
        p++;
        for (;;) {
            if (p >= end) { free(b); return seterr(err, errsz, "record %ld: unterminated quote", rec); }
            if (*p == '"') {
                if (p + 1 < end && p[1] == '"') { p += 2; goto put_quote; }
                p++;
                break;
            }
            if (n + 2 > cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); return seterr(err, errsz, "out of memory"); } b = nb; }
            b[n++] = *p++;
            continue;
        put_quote:
            if (n + 2 > cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); return seterr(err, errsz, "out of memory"); } b = nb; }
            b[n++] = '"';
        }
        if (p < end && *p != ',' && *p != '\n' && !(*p == '\r' && p + 1 < end && p[1] == '\n')) {
            free(b);
            return seterr(err, errsz, "record %ld: bytes after a closing quote", rec);
        }
    } else {
        while (p < end && *p != ',' && *p != '\n') {
            if (*p == '"') { free(b); return seterr(err, errsz, "record %ld: a quote inside an unquoted field", rec); }
            if (*p == '\r') {
                if (p + 1 < end && p[1] == '\n') break;
                free(b);
                return seterr(err, errsz, "record %ld: a bare CR", rec);
            }
            if (n + 2 > cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); return seterr(err, errsz, "out of memory"); } b = nb; }
            b[n++] = *p++;
        }
    }
    if (memchr(b, '\0', n)) { free(b); return seterr(err, errsz, "record %ld: a NUL byte", rec); }
    b[n] = '\0';
    *out = b;
    *pp = p;
    return 0;
}

int ir_csv_parse(const char *buf, size_t len, const char *const *cols,
                 int ncols, ir_csv_t *c, char *err, size_t errsz) {
    memset(c, 0, sizeof(*c));
    c->ncol = ncols;
    const char *p = buf, *end = buf + len;
    size_t cap = 0;
    long rec = 0;
    while (p < end) {
        if (*p == '\n' || (*p == '\r' && p + 1 < end && p[1] == '\n')) {
            ir_csv_free(c);
            return seterr(err, errsz, "record %ld: an empty line", rec);
        }
        if ((size_t)(c->nrec + 1) * (size_t)ncols > cap) {
            size_t nc = cap ? cap * 2 : (size_t)ncols * 64;
            char **ncell = realloc(c->cell, nc * sizeof(*ncell));
            if (!ncell) { ir_csv_free(c); return seterr(err, errsz, "out of memory"); }
            c->cell = ncell;
            cap = nc;
        }
        int k = 0;
        for (;;) {
            char *f = NULL;
            if (csv_field(&p, end, &f, rec, err, errsz) != 0) {
                c->nrec++;   /* free the cells written so far */
                for (int i = k; i < ncols; i++) IR_CELL(c, c->nrec - 1, i) = NULL;
                ir_csv_free(c);
                return -1;
            }
            if (k < ncols) IR_CELL(c, c->nrec, k) = f;
            else free(f);
            k++;
            if (p < end && *p == ',') { p++; continue; }
            break;
        }
        if (k != ncols) {
            c->nrec++;
            for (int i = k; i < ncols; i++) IR_CELL(c, c->nrec - 1, i) = NULL;
            ir_csv_free(c);
            return seterr(err, errsz, "record %ld: %d fields, the header has %d", rec, k, ncols);
        }
        c->nrec++;
        if (p < end && *p == '\r') p++;
        if (p < end) p++;   /* the '\n' */
        if (rec == 0) {
            for (int i = 0; i < ncols; i++)
                if (strcmp(IR_CELL(c, 0, i), cols[i]) != 0) {
                    seterr(err, errsz, "header column %d is \"%.40s\", not \"%s\"",
                           i + 1, IR_CELL(c, 0, i), cols[i]);
                    ir_csv_free(c);
                    return -1;
                }
        }
        rec++;
    }
    if (c->nrec == 0) {
        ir_csv_free(c);
        return seterr(err, errsz, "no header");
    }
    return 0;
}

long ir_csv_count(const char *buf, size_t len) {
    long recs = 0;
    int inq = 0, any = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i];
        if (ch == '"') inq = !inq;
        if (ch == '\n' && !inq) { recs++; any = 0; }
        else if (ch != '\r') any = 1;
    }
    if (any) recs++;
    return recs > 0 ? recs - 1 : 0;
}

/* ── Values against their C types ─────────────────────────────────── */

/* Text that lands in a C string literal: well-formed UTF-8, no control
 * character, within `max` bytes and, unless `may_empty`, not empty. */
static int text_ok(const char *s, size_t max, int may_empty) {
    size_t n = strlen(s);
    if ((!may_empty && n == 0) || n > max) return 0;
    for (size_t i = 0; i < n; ) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F) return 0;
        int k = utf8_len((const unsigned char *)s + i, n - i);
        if (k == 0) return 0;
        i += (size_t)k;
    }
    return 1;
}

/* The value of one digit in `base` (10 or 16, either case), or -1. */
static int digit_in(char c, unsigned base) {
    static const char lower[] = "0123456789abcdef", upper[] = "0123456789ABCDEF";
    const char *hit = c ? strchr(lower, c) : NULL;
    int v = hit ? (int)(hit - lower) : -1;
    if (v < 0 && c && (hit = strchr(upper, c)) != NULL) v = (int)(hit - upper);
    return v >= 0 && (unsigned)v < base ? v : -1;
}

/* An MA-L block as the CSVs spell it, six upper-case hex digits, into
 * its three octets. The I/G and U/L bits of the first octet must both
 * be clear: an IEEE MA-L assignment has neither, and a row with one set
 * could never match what the lookups compare it against. */
static int oui_parse(const char *s, uint8_t o[3]) {
    uint32_t v = 0;
    size_t n = 0;
    for (; s[n]; n++) {
        if (n == 6 || (s[n] >= 'a' && s[n] <= 'f')) return -1;
        int d = digit_in(s[n], 16);
        if (d < 0) return -1;
        v = (v << 4) | (uint32_t)d;
    }
    if (n != 6 || (v & 0x030000u)) return -1;
    o[0] = (uint8_t)(v >> 16);
    o[1] = (uint8_t)(v >> 8);
    o[2] = (uint8_t)v;
    return 0;
}

/* A CSV flag column: exactly "0" or "1". */
static int bit01(const char *s) {
    if (s[0] == '\0' || s[1] != '\0') return -1;
    return s[0] == '1' ? 1 : s[0] == '0' ? 0 : -1;
}

/* An unsigned value within [0, max]: decimal with no leading zero (at
 * most ten digits), or "0x" and one to eight hex digits. */
static int uparse(const char *s, unsigned long max, unsigned long *out) {
    unsigned base = 10;
    size_t width = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        width = 8;
        s += 2;
    } else if (s[0] == '0' && s[1] != '\0') {
        return -1;
    }
    size_t n = strlen(s);
    if (n == 0 || n > width) return -1;
    unsigned long long acc = 0;
    for (size_t i = 0; i < n; i++) {
        int d = digit_in(s[i], base);
        if (d < 0) return -1;
        acc = acc * base + (unsigned)d;
    }
    if (acc > max) return -1;
    *out = (unsigned long)acc;
    return 0;
}

/* Decimal in [lo, hi], '-' allowed. */
static int iparse(const char *s, long lo, long hi, long *out) {
    const char *p = s;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (!*p || strlen(p) > 6 || (p[0] == '0' && p[1])) return -1;
    long v = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
    }
    if (neg) v = -v;
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

static int name_index(const ir_name_t *t, int n, const char *s) {
    for (int i = 0; i < n; i++) if (!strcmp(t[i].name, s)) return i;
    return -1;
}

/* "0", or AP_FP_FLAG_* names joined by '|'. */
static int flags_parse(const char *s, unsigned *bits) {
    *bits = 0;
    if (!strcmp(s, "0")) return 0;
    char tmp[256];
    if (strlen(s) >= sizeof(tmp)) return -1;
    strcpy(tmp, s);
    for (char *tok = tmp; tok; ) {
        char *bar = strchr(tok, '|');
        if (bar) *bar = '\0';
        int i = name_index(ir_flag_names, ir_flag_names_n, tok);
        if (i < 0 || (*bits & (1u << i))) return -1;
        *bits |= 1u << i;
        tok = bar ? bar + 1 : NULL;
    }
    return 0;
}

static int dns_label_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

/* Lower-case LDH labels joined by dots, 2+ labels, at most 253 bytes:
 * what the suffix match compares (case-insensitively) against a host. */
static int domain_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 253 || !strchr(s, '.')) return 0;
    size_t lab = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            if (lab == 0 || lab > 63 || s[i - 1] == '-' || s[i - lab] == '-') return 0;
            lab = 0;
            continue;
        }
        if (!dns_label_char(s[i])) return 0;
        lab++;
    }
    return 1;
}

/* A DNS-SD service label as cam_mdns_service() compares it: '_' then a
 * registered service name (RFC 6335 §5.1: letters, digits, hyphens, at
 * most 15 characters). */
static int service_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 2 || n > 16 || s[0] != '_' || s[1] == '-' || s[n - 1] == '-') return 0;
    for (size_t i = 1; i < n; i++) if (!dns_label_char(s[i])) return 0;
    return 1;
}

/* ── Pack verification ────────────────────────────────────────────── */

int ir_pack_verify(const char *dir, const char *name, ir_manifest_t *m,
                   char man_sha[65], char *err, size_t errsz) {
    char path[4096], e[IR_ERR];
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    size_t ml;
    char *mb = ir_slurp(path, IR_FILE_MAX, &ml, e, sizeof(e));
    if (!mb) return seterr(err, errsz, "%s", e);
    sha256_hex((const uint8_t *)mb, ml, man_sha);
    int rc = ir_manifest_parse(mb, ml, m, e, sizeof(e));
    free(mb);
    if (rc != 0) return seterr(err, errsz, "%s: %s", path, e);
    if (strcmp(m->pack_name, name) != 0)
        return seterr(err, errsz, "%s: pack_name is \"%s\", the directory is \"%s\"",
                      path, m->pack_name, name);
    for (int i = 0; i < m->nfiles; i++) {
        const ir_file_t *f = &m->files[i];
        snprintf(path, sizeof(path), "%s/%s", dir, f->path);
        size_t fl;
        char *fb = ir_slurp(path, IR_FILE_MAX, &fl, e, sizeof(e));
        if (!fb) return seterr(err, errsz, "%s", e);
        char got[65];
        sha256_hex((const uint8_t *)fb, fl, got);
        long rows = f->rows >= 0 ? ir_csv_count(fb, fl) : -1;
        free(fb);
        if ((long long)fl != f->bytes) {
            return seterr(err, errsz, "%s: %zu bytes, the manifest says %lld",
                          path, fl, f->bytes);
        }
        if (strcmp(got, f->sha256) != 0)
            return seterr(err, errsz, "%s: sha256 %s, the manifest says %s",
                          path, got, f->sha256);
        if (f->rows >= 0 && rows != f->rows)
            return seterr(err, errsz, "%s: %ld rows, the manifest says %lld",
                          path, rows, f->rows);
    }
    /* The snapshot is exactly the pack: a file the manifest does not
     * list is something nobody hashed. */
    DIR *d = opendir(dir);
    if (!d) return seterr(err, errsz, "%s: %s", dir, strerror(errno));
    struct dirent *de;
    int stray = 0;
    char sname[256] = "";
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") ||
            !strcmp(de->d_name, "manifest.json"))
            continue;
        int i = 0;
        while (i < m->nfiles && strcmp(m->files[i].path, de->d_name) != 0) i++;
        if (i == m->nfiles && !stray) {
            stray = 1;
            snprintf(sname, sizeof(sname), "%s", de->d_name);
        }
    }
    closedir(d);
    if (stray) return seterr(err, errsz, "%s/%s: not in the pack's manifest", dir, sname);
    return 0;
}

/* Read one listed csv-rows file of a verified pack and parse it. */
static int pack_csv(const char *intel_dir, const ir_manifest_t *m,
                    const char *file, const char *const *cols, int ncols,
                    ir_csv_t *c, char *err, size_t errsz) {
    const ir_file_t *f = NULL;
    for (int i = 0; i < m->nfiles; i++)
        if (!strcmp(m->files[i].path, file)) f = &m->files[i];
    if (!f) return seterr(err, errsz, "%s: %s is not in its manifest", m->pack_name, file);
    if (strcmp(f->format, "csv-rows") != 0)
        return seterr(err, errsz, "%s/%s: format %s, not csv-rows", m->pack_name, file, f->format);
    char path[4096], e[IR_ERR];
    snprintf(path, sizeof(path), "%s/%s/%s", intel_dir, m->pack_name, file);
    size_t len;
    char *b = ir_slurp(path, IR_FILE_MAX, &len, e, sizeof(e));
    if (!b) return seterr(err, errsz, "%s", e);
    int rc = ir_csv_parse(b, len, cols, ncols, c, e, sizeof(e));
    free(b);
    if (rc != 0) return seterr(err, errsz, "%s/%s: %s", m->pack_name, file, e);
    return 0;
}

static char *dup_or_null(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

#define ROWS(c) ((c)->nrec - 1)
#define BAD(what) do { \
        seterr(err, errsz, "%s/%s: record %d: %s (\"%.60s\")", pk, fn, r, (what), val); \
        goto fail; } while (0)
#define DUP(dst, s) do { if (!((dst) = dup_or_null(s))) { val = ""; BAD("out of memory"); } } while (0)

static int load_oui(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                    char *err, size_t errsz) {
    static const char *const cols[] = { "oui", "vendor" };
    const char *pk = m->pack_name, *fn = "oui_builtin.csv", *val = "";
    ir_csv_t c;
    int r = 0;
    if (pack_csv(dir, m, fn, cols, 2, &c, err, errsz) != 0) return -1;
    if (ROWS(&c) < 1) { BAD("no rows: a C array cannot be empty"); }
    s->oui = calloc((size_t)ROWS(&c), sizeof(*s->oui));
    if (!s->oui) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_oui_t *o = &s->oui[r - 1];
        s->n_oui = r;   /* first: a refusal mid-row frees what it holds */
        uint8_t b[3];
        val = IR_CELL(&c, r, 0);
        if (oui_parse(val, b) != 0) BAD("oui is not six upper-case hex digits of an MA-L block");
        o->oui = (uint32_t)b[0] << 16 | (uint32_t)b[1] << 8 | b[2];
        /* oui_lookup() binary-searches: ascending and unique, or a row
         * it should find is missed. */
        if (r > 1 && o->oui <= s->oui[r - 2].oui) BAD("not in ascending order, or repeated");
        val = IR_CELL(&c, r, 1);
        if (!text_ok(val, 63, 0)) BAD("vendor is empty, too long or not text");
        DUP(o->vendor, val);
    }
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

static int load_attacker(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                         char *err, size_t errsz) {
    static const char *const cols[] = { "oui", "family", "note" };
    const char *pk = m->pack_name, *fn = "attacker_ouis.csv", *val = "";
    ir_csv_t c;
    int r = 0, nf[2] = { 0, 0 };
    if (pack_csv(dir, m, fn, cols, 3, &c, err, errsz) != 0) return -1;
    s->att = calloc((size_t)(ROWS(&c) > 0 ? ROWS(&c) : 1), sizeof(*s->att));
    if (!s->att) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_attacker_t *a = &s->att[r - 1];
        s->n_att = r;   /* first: a refusal mid-row frees what it holds */
        val = IR_CELL(&c, r, 0);
        if (oui_parse(val, a->oui) != 0) BAD("oui is not six upper-case hex digits of an MA-L block");
        val = IR_CELL(&c, r, 1);
        if (!strcmp(val, "hak5")) a->family = IR_FAM_HAK5;
        else if (!strcmp(val, "espressif")) a->family = IR_FAM_ESPRESSIF;
        else BAD("family is neither hak5 nor espressif");
        for (int q = 0; q < r - 1; q++)
            if (s->att[q].family == a->family && !memcmp(s->att[q].oui, a->oui, 3))
                BAD("repeated within its family");
        nf[a->family]++;
        val = IR_CELL(&c, r, 2);
        /* Emitted as a C comment beside its row. */
        if (!text_ok(val, 120, 1) || strstr(val, "*/") || strstr(val, "/*"))
            BAD("note is too long, not text or holds a comment delimiter");
        DUP(a->note, val);
    }
    val = "";
    if (nf[IR_FAM_HAK5] == 0) BAD("no hak5 rows: a C array cannot be empty");
    if (nf[IR_FAM_ESPRESSIF] == 0) BAD("no espressif rows: a C array cannot be empty");
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

static int load_camera(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                       char *err, size_t errsz) {
    const char *pk = m->pack_name, *fn, *val = "";
    ir_csv_t c;
    int r = 0;

    static const char *const ocols[] = { "oui", "vendor", "org", "mixed" };
    fn = "camera_vendors.csv";
    if (pack_csv(dir, m, fn, ocols, 4, &c, err, errsz) != 0) return -1;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->cam = calloc((size_t)ROWS(&c), sizeof(*s->cam));
    if (!s->cam) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_cam_oui_t *o = &s->cam[r - 1];
        s->n_cam = r;   /* first: a refusal mid-row frees what it holds */
        val = IR_CELL(&c, r, 0);
        if (oui_parse(val, o->oui) != 0) BAD("oui is not six upper-case hex digits of an MA-L block");
        /* cam_vendor_oui() returns the first match: a repeat is dead. */
        for (int q = 0; q < r - 1; q++)
            if (!memcmp(s->cam[q].oui, o->oui, 3)) BAD("repeated");
        val = IR_CELL(&c, r, 1);
        if (!text_ok(val, 31, 0)) BAD("vendor is empty, too long or not text");
        DUP(o->vendor, val);
        val = IR_CELL(&c, r, 2);
        if (!text_ok(val, 120, 0)) BAD("org is empty, too long or not text");
        DUP(o->org, val);
        val = IR_CELL(&c, r, 3);
        if ((o->mixed = bit01(val)) < 0) BAD("mixed is not 0 or 1");
    }
    ir_csv_free(&c);

    static const char *const bcols[] = { "brand" };
    fn = "camera_server_brands.csv";
    if (pack_csv(dir, m, fn, bcols, 1, &c, err, errsz) != 0) return -1;
    r = 0;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->brand = calloc((size_t)ROWS(&c), sizeof(*s->brand));
    if (!s->brand) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        s->n_brand = r;
        val = IR_CELL(&c, r, 0);
        /* cam_vendor_server() compares it as one SERVER product token. */
        if (!text_ok(val, 31, 0) || strpbrk(val, " \t,/")) BAD("brand is not one product-name token");
        DUP(s->brand[r - 1], val);
    }
    ir_csv_free(&c);

    static const char *const scols[] = { "service", "label", "camera_specific" };
    fn = "camera_services.csv";
    if (pack_csv(dir, m, fn, scols, 3, &c, err, errsz) != 0) return -1;
    r = 0;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->svc = calloc((size_t)ROWS(&c), sizeof(*s->svc));
    if (!s->svc) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_cam_svc_t *v = &s->svc[r - 1];
        s->n_svc = r;   /* first: a refusal mid-row frees what it holds */
        val = IR_CELL(&c, r, 0);
        if (!service_ok(val)) BAD("service is not '_' and an RFC 6335 service name");
        DUP(v->name, val);
        val = IR_CELL(&c, r, 1);
        if (!text_ok(val, 63, 0)) BAD("label is empty, too long or not text");
        DUP(v->label, val);
        val = IR_CELL(&c, r, 2);
        if ((v->camera_specific = bit01(val)) < 0) BAD("camera_specific is not 0 or 1");
    }
    ir_csv_free(&c);

    static const char *const pcols[] = { "prefix", "label", "brand" };
    fn = "camera_setup_ssids.csv";
    if (pack_csv(dir, m, fn, pcols, 3, &c, err, errsz) != 0) return -1;
    r = 0;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->ssid = calloc((size_t)ROWS(&c), sizeof(*s->ssid));
    if (!s->ssid) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_cam_ssid_t *p = &s->ssid[r - 1];
        s->n_ssid = r;   /* first: a refusal mid-row frees what it holds */
        val = IR_CELL(&c, r, 0);
        /* A prefix of an SSID, which is at most 32 octets. */
        if (!text_ok(val, 32, 0)) BAD("prefix is empty, longer than an SSID or not text");
        DUP(p->prefix, val);
        val = IR_CELL(&c, r, 1);
        if (!text_ok(val, 63, 0)) BAD("label is empty, too long or not text");
        DUP(p->label, val);
        val = IR_CELL(&c, r, 2);
        if (!text_ok(val, 31, 0)) BAD("brand is empty, too long or not text");
        DUP(p->brand, val);
    }
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

static int load_endpoints(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                          char *err, size_t errsz) {
    static const char *const cols[] = { "domain", "vendor", "family" };
    const char *pk = m->pack_name, *fn = "surveillance_endpoints.csv", *val = "";
    ir_csv_t c;
    int r = 0;
    if (pack_csv(dir, m, fn, cols, 3, &c, err, errsz) != 0) return -1;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->ep = calloc((size_t)ROWS(&c), sizeof(*s->ep));
    if (!s->ep) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_endpoint_t *e = &s->ep[r - 1];
        s->n_ep = r;   /* first: a refusal mid-row frees what it holds */
        val = IR_CELL(&c, r, 0);
        if (!domain_ok(val)) BAD("domain is not lower-case LDH labels");
        DUP(e->domain, val);
        /* vendor and family go into an akey token and the alert detail. */
        val = IR_CELL(&c, r, 1);
        if (!text_ok(val, 31, 0) || strpbrk(val, " :")) BAD("vendor is not a short token");
        DUP(e->vendor, val);
        val = IR_CELL(&c, r, 2);
        if (!text_ok(val, 31, 0) || strpbrk(val, " :")) BAD("family is not a short token");
        DUP(e->family, val);
    }
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

static int load_tools(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                      char *err, size_t errsz) {
    static const char *const cols[] = {
        "tool", "vendor_ie_hash", "beacon_interval_ms", "supported_rates",
        "require_flags", "forbid_flags", "requires_karma_echo", "requires_pmkid",
        "unverified", "human_label", "evidence", "id", "version" };
    const char *pk = m->pack_name, *fn = "tool_fingerprints.csv", *val = "";
    ir_csv_t c;
    int r = 0;
    if (pack_csv(dir, m, fn, cols, 13, &c, err, errsz) != 0) return -1;
    if (ROWS(&c) < 1) BAD("no rows: a C array cannot be empty");
    s->tool = calloc((size_t)ROWS(&c), sizeof(*s->tool));
    if (!s->tool) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_tool_t *t = &s->tool[r - 1];
        s->n_tool = r;   /* first: a refusal mid-row frees what it holds */
        unsigned long u;
        int b;
        val = IR_CELL(&c, r, 0);
        if ((t->tool = name_index(ir_tool_names, ir_tool_names_n, val)) < 0)
            BAD("tool is not a SLOTH_TOOL_* this build defines");
        val = IR_CELL(&c, r, 1);
        if (uparse(val, 0xFFFFFFFFul, &u) != 0) BAD("vendor_ie_hash is not a uint32_t");
        t->vendor_ie_hash = (uint32_t)u;
        val = IR_CELL(&c, r, 2);
        if (uparse(val, 0xFFFFul, &u) != 0) BAD("beacon_interval_ms is not a uint16_t");
        t->beacon_interval_ms = (uint16_t)u;
        val = IR_CELL(&c, r, 3);
        if (uparse(val, 0xFFFFFFFFul, &u) != 0) BAD("supported_rates is not a uint32_t");
        t->supported_rates = (uint32_t)u;
        val = IR_CELL(&c, r, 4);
        if (flags_parse(val, &t->require_flags) != 0) BAD("require_flags is not 0 or AP_FP_FLAG_* names");
        val = IR_CELL(&c, r, 5);
        if (flags_parse(val, &t->forbid_flags) != 0) BAD("forbid_flags is not 0 or AP_FP_FLAG_* names");
        if (t->require_flags & t->forbid_flags) BAD("a flag both required and forbidden");
        val = IR_CELL(&c, r, 6);
        if ((b = bit01(val)) < 0) BAD("requires_karma_echo is not 0 or 1");
        t->requires_karma_echo = (uint8_t)b;
        val = IR_CELL(&c, r, 7);
        if ((b = bit01(val)) < 0) BAD("requires_pmkid is not 0 or 1");
        t->requires_pmkid = (uint8_t)b;
        val = IR_CELL(&c, r, 8);
        if ((b = bit01(val)) < 0) BAD("unverified is not 0 or 1");
        t->unverified = (uint8_t)b;
        val = IR_CELL(&c, r, 9);
        if (!text_ok(val, 47, 0)) BAD("human_label is empty, too long or not text");
        DUP(t->human_label, val);
        /* The row's provenance (tool_fingerprint.h, #90): required, and
         * an unverified row says so where the operator reads it. */
        val = IR_CELL(&c, r, 10);
        if (!text_ok(val, SIG_EVIDENCE_MAX, 0)) BAD("evidence is empty, too long for sig_evidence or not text");
        if (t->unverified != !strncmp(val, "UNVERIFIED - ", 13))
            BAD("unverified disagrees with the evidence string's UNVERIFIED - prefix");
        DUP(t->evidence, val);
        val = IR_CELL(&c, r, 11);
        if (!text_ok(val, SIG_ID_MAX, 0) || strpbrk(val, " \"")) BAD("id is empty, too long for sig_id or not a token");
        for (int q = 0; q < r - 1; q++)
            if (!strcmp(s->tool[q].id, val)) BAD("id repeated: an id is never reused");
        DUP(t->id, val);
        val = IR_CELL(&c, r, 12);
        if (!text_ok(val, SIG_VERSION_MAX, 0)) BAD("version is empty, too long for sig_version or not text");
        DUP(t->version, val);
    }
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

static int load_ble(const char *dir, const ir_manifest_t *m, ir_snapshot_t *s,
                    char *err, size_t errsz) {
    static const char *const cols[] = {
        "category", "match", "id", "subtype", "min_len", "max_len", "source" };
    const char *pk = m->pack_name, *fn = "ble_watchlist.csv", *val = "";
    ir_csv_t c;
    int r = 0;
    if (pack_csv(dir, m, fn, cols, 7, &c, err, errsz) != 0) return -1;
    /* Zero rows is the shipped table (src/ble_watchlist.c): "no claim". */
    s->ble = calloc((size_t)(ROWS(&c) > 0 ? ROWS(&c) : 1), sizeof(*s->ble));
    if (!s->ble) BAD("out of memory");
    for (r = 1; r < c.nrec; r++) {
        ir_ble_t *w = &s->ble[r - 1];
        s->n_ble = r;   /* first: a refusal mid-row frees what it holds */
        unsigned long u;
        long v;
        /* What ble_watchlist_set_table() refuses, refused here. */
        val = IR_CELL(&c, r, 0);
        if (!text_ok(val, BLE_WL_CATEGORY_MAX, 0)) BAD("category is empty, too long or not text");
        DUP(w->category, val);
        val = IR_CELL(&c, r, 1);
        w->match = 0;
        for (int k = BLE_WL_MFR; k <= BLE_WL_UUID16; k++)
            if (!strcmp(val, ir_ble_match_names[k])) w->match = k;
        if (!w->match) BAD("match is not mfr, svc_data or uuid16");
        val = IR_CELL(&c, r, 2);
        if (strncmp(val, "0x", 2) != 0 || strlen(val) < 3 || strlen(val) > 6 ||
            uparse(val, 0xFFFFul, &u) != 0)
            BAD("id is not 0x and at most four hex digits");
        w->id = (uint16_t)u;
        val = IR_CELL(&c, r, 3);
        if (iparse(val, -1, 255, &v) != 0) BAD("subtype is not -1 or an octet");
        w->subtype = (int16_t)v;
        val = IR_CELL(&c, r, 4);
        if (iparse(val, -1, 32767, &v) != 0) BAD("min_len is not -1 or an int16_t length");
        w->min_len = (int16_t)v;
        val = IR_CELL(&c, r, 5);
        if (iparse(val, -1, 32767, &v) != 0) BAD("max_len is not -1 or an int16_t length");
        w->max_len = (int16_t)v;
        if (w->min_len >= 0 && w->max_len >= 0 && w->min_len > w->max_len)
            BAD("min_len above max_len");
        val = IR_CELL(&c, r, 6);
        if (!text_ok(val, 200, 0)) BAD("source is empty: a row with no source is refused");
        DUP(w->source, val);
    }
    ir_csv_free(&c);
    return 0;
fail:
    ir_csv_free(&c);
    return -1;
}

void ir_snapshot_hash(const char man_sha[IR_NPACKS][65], char out[65]) {
    sha256_ctx_t c;
    sha256_init(&c);
    for (int i = 0; i < IR_NPACKS; i++) {
        sha256_update(&c, (const uint8_t *)ir_pack_names[i], strlen(ir_pack_names[i]));
        sha256_update(&c, (const uint8_t *)" ", 1);
        sha256_update(&c, (const uint8_t *)man_sha[i], 64);
        sha256_update(&c, (const uint8_t *)"\n", 1);
    }
    uint8_t d[32];
    sha256_final(&c, d);
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

int ir_snapshot_load(const char *intel_dir, ir_snapshot_t *s, char *err, size_t errsz) {
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < IR_NPACKS; i++) {
        char dir[4096];
        snprintf(dir, sizeof(dir), "%s/%s", intel_dir, ir_pack_names[i]);
        if (ir_pack_verify(dir, ir_pack_names[i], &s->man[i], s->man_sha[i], err, errsz) != 0)
            return -1;
    }
    ir_snapshot_hash((const char (*)[65])s->man_sha, s->hash);
    int rc = load_attacker(intel_dir, &s->man[0], s, err, errsz);
    if (!rc) rc = load_ble(intel_dir, &s->man[1], s, err, errsz);
    if (!rc) rc = load_camera(intel_dir, &s->man[2], s, err, errsz);
    if (!rc) rc = load_oui(intel_dir, &s->man[3], s, err, errsz);
    if (!rc) rc = load_endpoints(intel_dir, &s->man[4], s, err, errsz);
    if (!rc) rc = load_tools(intel_dir, &s->man[5], s, err, errsz);
    if (rc) ir_snapshot_free(s);
    return rc;
}

void ir_snapshot_free(ir_snapshot_t *s) {
    for (int i = 0; i < s->n_oui; i++) free(s->oui[i].vendor);
    for (int i = 0; i < s->n_att; i++) free(s->att[i].note);
    for (int i = 0; i < s->n_cam; i++) { free(s->cam[i].vendor); free(s->cam[i].org); }
    for (int i = 0; i < s->n_brand; i++) free(s->brand[i]);
    for (int i = 0; i < s->n_svc; i++) { free(s->svc[i].name); free(s->svc[i].label); }
    for (int i = 0; i < s->n_ssid; i++) {
        free(s->ssid[i].prefix); free(s->ssid[i].label); free(s->ssid[i].brand);
    }
    for (int i = 0; i < s->n_ep; i++) {
        free(s->ep[i].domain); free(s->ep[i].vendor); free(s->ep[i].family);
    }
    for (int i = 0; i < s->n_tool; i++) {
        free(s->tool[i].human_label); free(s->tool[i].evidence);
        free(s->tool[i].id); free(s->tool[i].version);
    }
    for (int i = 0; i < s->n_ble; i++) { free(s->ble[i].category); free(s->ble[i].source); }
    free(s->oui); free(s->att); free(s->cam); free(s->brand); free(s->svc);
    free(s->ssid); free(s->ep); free(s->tool); free(s->ble);
    memset(s, 0, sizeof(*s));
}

/* ── intel/LOCK ───────────────────────────────────────────────────── */

int ir_lock_parse(const char *buf, size_t len, ir_lock_t *l, char *err, size_t errsz) {
    memset(l, 0, sizeof(*l));
    int have[4] = { 0, 0, 0, 0 };
    const char *p = buf, *end = buf + len;
    int line = 0;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
        line++;
        char ln[256];
        if (n >= sizeof(ln)) return seterr(err, errsz, "LOCK line %d: too long", line);
        memcpy(ln, p, n);
        ln[n] = '\0';
        p += n + (nl ? 1 : 0);
        if (ln[0] == '#' || ln[0] == '\0') continue;
        char *colon = strstr(ln, ": ");
        if (!colon) return seterr(err, errsz, "LOCK line %d: not \"key: value\"", line);
        *colon = '\0';
        const char *k = ln, *v = colon + 2;
        int idx = !strcmp(k, "pack_version") ? 0 : !strcmp(k, "hash") ? 1 :
                  !strcmp(k, "comint_commit") ? 2 : !strcmp(k, "date") ? 3 : -1;
        if (idx < 0) {
            /* Informational keys are allowed; only these four are read. */
            if (!strcmp(k, "packs") || !strcmp(k, "source")) continue;
            return seterr(err, errsz, "LOCK line %d: unknown key %s", line, k);
        }
        if (have[idx]) return seterr(err, errsz, "LOCK line %d: %s twice", line, k);
        have[idx] = 1;
        if (idx == 0) {
            if (!ir_semver_ok(v) || strlen(v) >= sizeof(l->pack_version))
                return seterr(err, errsz, "LOCK: pack_version is not MAJOR.MINOR.PATCH");
            strcpy(l->pack_version, v);
        } else if (idx == 1) {
            if (!hex64_ok(v)) return seterr(err, errsz, "LOCK: hash is not 64 lowercase hex digits");
            strcpy(l->hash, v);
        } else if (idx == 2) {
            size_t vl = strlen(v);
            if (vl != 40) return seterr(err, errsz, "LOCK: comint_commit is not a 40-digit SHA");
            for (size_t i = 0; i < vl; i++)
                if (!((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f')))
                    return seterr(err, errsz, "LOCK: comint_commit is not a 40-digit SHA");
            strcpy(l->comint_commit, v);
        } else {
            if (!date_ok(v)) return seterr(err, errsz, "LOCK: date is not YYYY-MM-DD");
            strcpy(l->date, v);
        }
    }
    if (!(have[0] && have[1] && have[2] && have[3]))
        return seterr(err, errsz, "LOCK: pack_version, hash, comint_commit and date are all required");
    return 0;
}
