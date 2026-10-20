#ifndef SLOTH_TEST_MANIFEST_CHECK_H
#define SLOTH_TEST_MANIFEST_CHECK_H

/* Reading a #92 slice 3 hashed manifest back, for the tests of every
 * sink that writes one. Parsed with the tree's real JSON reader
 * (research/mcp/json.c), not by scanning for `"key":`, so a line that
 * is not valid JSON fails here the way it would fail a consumer.
 *
 * The independent hash is the embedded SHA-256 over the file as read by
 * stdio, and, where the host has it, sha256sum(1) as a second opinion
 * that shares no code with sloth. */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "sha256.h"
#include "evidence_manifest.h"

typedef struct {
    char      session[EVM_SESSION_MAX];
    long long seq;
    char      file[160];
    long long size;
    char      sha256[65];
    char      sink[32];
    char      incident_id[40];
    char      rule[48];
    int       has_incident, has_rule;
    int       reconstructed;      /* -1 absent / not a bool */
    char      written_at[32];
    long long written_at_epoch;
} mf_line_t;

/* How many manifests are in `dir`; the first one's name in out. */
static inline int mf_count(const char *dir, char *out, size_t outsz) {
    if (out && outsz) out[0] = '\0';
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!evidence_manifest_is_name(e->d_name)) continue;
        if (n == 0 && out && outsz) snprintf(out, outsz, "%s", e->d_name);
        n++;
    }
    closedir(d);
    return n;
}

static inline void mf_copy_str(const json_doc_t *d, const char *key,
                               char *out, size_t outsz, int *has) {
    const char *v = json_str(d, json_obj_get(d, 0, key));
    if (has) *has = v != NULL;
    snprintf(out, outsz, "%s", v ? v : "");
}

/* Parse one line. 0, or -1 if it is not a JSON object. */
static inline int mf_parse_line(const char *line, mf_line_t *o) {
    static json_doc_t d;
    memset(o, 0, sizeof(*o));
    if (json_parse(&d, line) != 0 || d.nodes[0].type != JSON_OBJ) return -1;
    mf_copy_str(&d, "session", o->session, sizeof(o->session), NULL);
    mf_copy_str(&d, "file", o->file, sizeof(o->file), NULL);
    mf_copy_str(&d, "sha256", o->sha256, sizeof(o->sha256), NULL);
    mf_copy_str(&d, "sink", o->sink, sizeof(o->sink), NULL);
    mf_copy_str(&d, "incident_id", o->incident_id, sizeof(o->incident_id),
                &o->has_incident);
    mf_copy_str(&d, "rule", o->rule, sizeof(o->rule), &o->has_rule);
    mf_copy_str(&d, "written_at", o->written_at, sizeof(o->written_at), NULL);
    o->seq  = (long long)json_num(&d, json_obj_get(&d, 0, "seq"), -1);
    o->size = (long long)json_num(&d, json_obj_get(&d, 0, "size"), -1);
    o->written_at_epoch =
        (long long)json_num(&d, json_obj_get(&d, 0, "written_at_epoch"), -1);
    int b = json_obj_get(&d, 0, "reconstructed");
    o->reconstructed = (b >= 0 && d.nodes[b].type == JSON_BOOL)
                     ? d.nodes[b].boolean : -1;
    return 0;
}

/* Every newline-terminated line of `path`, parsed into out[0..max).
 * A trailing fragment with no newline is what a crash mid-append
 * leaves, and is not a line: it is counted in *tail, not parsed.
 * *bad counts complete lines that do not parse. Returns the number of
 * complete lines, or -1 if the file cannot be read. */
static inline int mf_read_path(const char *path, mf_line_t *out, int max,
                               int *bad, int *tail) {
    if (bad) *bad = 0;
    if (tail) *tail = 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    static char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    int lines = 0;
    char *p = buf;
    for (;;) {
        char *nl = strchr(p, '\n');
        if (!nl) { if (*p && tail) *tail = 1; break; }
        *nl = '\0';
        mf_line_t tmp;
        if (mf_parse_line(p, &tmp) != 0) { if (bad) (*bad)++; }
        else if (lines < max && out) out[lines] = tmp;
        lines++;
        p = nl + 1;
    }
    return lines;
}

/* The single manifest in `dir`. -1 if there is not exactly one. */
static inline int mf_read_dir(const char *dir, mf_line_t *out, int max,
                              int *bad) {
    char name[200], path[600];
    if (mf_count(dir, name, sizeof(name)) != 1) return -1;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return mf_read_path(path, out, max, bad, NULL);
}

/* SHA-256 of `path` read through stdio, with its byte count. */
static inline int mf_hash_path(const char *path, char hex[65],
                               long long *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    sha256_ctx_t c;
    sha256_init(&c);
    uint8_t b[4096];
    size_t r;
    long long total = 0;
    while ((r = fread(b, 1, sizeof(b), fp)) > 0) {
        sha256_update(&c, b, r);
        total += (long long)r;
    }
    fclose(fp);
    uint8_t dg[32];
    sha256_final(&c, dg);
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[2 * i] = hx[dg[i] >> 4];
        hex[2 * i + 1] = hx[dg[i] & 0xf];
    }
    hex[64] = '\0';
    if (size) *size = total;
    return 0;
}

/* sha256sum(1)'s digest of `path`: 1 with hex filled, 0 when the host
 * has no sha256sum (the caller skips that cross-check, not the test). */
static inline int mf_sha256sum(const char *path, char hex[65]) {
    char cmd[700];
    if (strchr(path, '\'')) return 0;
    snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    char out[256] = "";
    char *got = fgets(out, sizeof(out), p);
    int rc = pclose(p);
    if (!got || rc != 0) return 0;
    for (int i = 0; i < 64; i++) {
        char c = out[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    memcpy(hex, out, 64);
    hex[64] = '\0';
    return 1;
}

/* The line naming `file`, latest first (a replaced handshake pcap has
 * several). NULL if none. */
static inline const mf_line_t *mf_find(const mf_line_t *l, int n,
                                       const char *file) {
    for (int i = n - 1; i >= 0; i--)
        if (strcmp(l[i].file, file) == 0) return &l[i];
    return NULL;
}

#endif /* SLOTH_TEST_MANIFEST_CHECK_H */
