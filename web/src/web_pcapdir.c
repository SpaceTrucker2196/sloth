#include "web_pcapdir.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../tools/sha256.h"

/* ── the name gate ────────────────────────────────────────────────── */

static int all_digits(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)p[i])) return 0;
    return 1;
}

/* src/alert_pcap.c alert_pcap_is_name(), copied exactly: "alert_" + 8
 * digits + "_" + 6 digits + "_" + [A-Za-z0-9_]* + ".pcap", under 80. */
static int alert_name_ok(const char *name, size_t n) {
    static const char pfx[] = "alert_", ext[] = ".pcap";
    const size_t pn = sizeof(pfx) - 1, en = sizeof(ext) - 1;
    if (n < pn + 8 + 1 + 6 + 1 + en || n >= 80) return 0;
    if (strncmp(name, pfx, pn) != 0) return 0;
    const char *p = name + pn;
    if (!all_digits(p, 8) || p[8] != '_' || !all_digits(p + 9, 6) || p[15] != '_') return 0;
    if (strcmp(name + n - en, ext) != 0) return 0;
    for (const char *c = p + 16; c < name + n - en; c++)
        if (!isalnum((unsigned char)*c) && *c != '_') return 0;
    return 1;
}

/* src/evidence_export.c evidence_export_alert_name(): 16 lowercase hex,
 * "-", the event id (1..20 digits), "-", the rule ([A-Za-z0-9_]{1,47}),
 * an optional "-N" collision suffix (1..2 digits), ".pcap". */
static int evidence_name_ok(const char *name, size_t n) {
    static const char ext[] = ".pcap";
    const size_t en = sizeof(ext) - 1;
    if (n < 16 + 1 + 1 + 1 + 1 + en || n > WEB_PCAP_NAME_MAX) return 0;
    for (int i = 0; i < 16; i++)
        if (!isxdigit((unsigned char)name[i]) || isupper((unsigned char)name[i])) return 0;
    if (name[16] != '-') return 0;
    const char *p = name + 17, *end = name + n - en;
    if (strcmp(end, ext) != 0) return 0;
    size_t d = 0;
    while (p + d < end && isdigit((unsigned char)p[d])) d++;
    if (d < 1 || d > 20 || p + d >= end || p[d] != '-') return 0;
    p += d + 1;
    size_t r = 0;
    while (p + r < end && (isalnum((unsigned char)p[r]) || p[r] == '_')) r++;
    if (r < 1 || r > 47) return 0;
    p += r;
    if (p == end) return 1;
    if (*p != '-') return 0;
    p++;
    size_t s = 0;
    while (p + s < end && isdigit((unsigned char)p[s])) s++;
    return s >= 1 && s <= 2 && p + s == end;
}

int web_pcapdir_name_ok(const char *name) {
    if (!name || !name[0]) return 0;
    size_t n = strlen(name);
    if (n > WEB_PCAP_NAME_MAX || strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, ".."))
        return 0;
    return alert_name_ok(name, n) || evidence_name_ok(name, n);
}

void web_pcapdir_basename(const char *path, char out[WEB_PCAP_NAME_MAX + 1]) {
    out[0] = '\0';
    if (!path) return;
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strlen(b) > WEB_PCAP_NAME_MAX || !web_pcapdir_name_ok(b)) return;
    memcpy(out, b, strlen(b) + 1);
}

static int manifest_name_ok(const char *name) {
    static const char pfx[] = "sloth-manifest-", ext[] = ".jsonl";
    size_t n = strlen(name), p = sizeof(pfx) - 1, e = sizeof(ext) - 1;
    if (n <= p + e || n > WEB_PCAP_NAME_MAX || strchr(name, '/')) return 0;
    return !strncmp(name, pfx, p) && !strcmp(name + n - e, ext);
}

/* ── the directory ────────────────────────────────────────────────── */

int web_pcapdir_init(web_pcapdir_t *p, const char *const *dirs, int n) {
    memset(p, 0, sizeof(*p));
    p->scanned_ms = -1;
    if (n > WEB_PCAP_DIRS) n = WEB_PCAP_DIRS;
    for (int i = 0; i < n; i++) {
        snprintf(p->d[i].path, sizeof(p->d[i].path), "%s", dirs[i]);
        p->d[i].mtime_ns = -1;
    }
    p->ndir = n;
    p->e = calloc(WEB_PCAPDIR_ENTRIES, sizeof(*p->e));
    return p->e ? 0 : -1;
}

void web_pcapdir_destroy(web_pcapdir_t *p) {
    free(p->e);
    p->e = NULL;
    p->n = 0;
}

int web_pcapdir_open_dir(const web_pcapdir_t *p, int dir, int *err) {
    *err = 0;
    if (dir < 0 || dir >= p->ndir) { *err = ENOENT; return -1; }
    int fd = open(p->d[dir].path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { *err = errno; return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        *err = ENOTDIR;
        close(fd);
        return -1;
    }
    return fd;
}

/* The one open: by name through the directory, following nothing. */
static int open_under(int dirfd, const char *name, long long cap, long long *size,
                      const char **why) {
    *size = 0;
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        *why = errno == ENOENT ? "not_found" : errno == ELOOP ? "not_regular" : "unreadable";
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); *why = "unreadable"; return -1; }
    if (!S_ISREG(st.st_mode)) { close(fd); *why = "not_regular"; return -1; }
    if ((long long)st.st_size > cap) { close(fd); *why = "too_large"; return -1; }
    *size = (long long)st.st_size;
    return fd;
}

int web_pcapdir_open_file(int dirfd, const char *name, long long *size, const char **why) {
    *size = 0;
    if (!web_pcapdir_name_ok(name)) { *why = "bad_name"; return -1; }
    return open_under(dirfd, name, (long long)WEB_PCAP_FILE_MAX, size, why);
}

unsigned char *web_pcapdir_slurp(int fd, long long size) {
    if (size < 0 || size > (long long)WEB_PCAP_FILE_MAX) return NULL;
    unsigned char *b = malloc((size_t)size + 1);
    if (!b) return NULL;
    size_t got = 0;
    while (got < (size_t)size) {
        ssize_t r = read(fd, b + got, (size_t)size - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { free(b); return NULL; }
        got += (size_t)r;
    }
    /* A file that grew after its stat is not the file that was gated. */
    char extra;
    if (read(fd, &extra, 1) != 0) { free(b); return NULL; }
    return b;
}

/* ── one manifest line ────────────────────────────────────────────── */

/* A flat JSON object of strings, numbers and literals, as
 * src/evidence_manifest.c writes it. Returns the end of the value at
 * p, with the value's text (a string decoded, up to cap - 1) in out;
 * NULL when malformed. Only the escapes the writer can produce
 * matter; others become '?'. */
static const char *value(const char *p, const char *end, char *out, size_t cap) {
    size_t o = 0;
    if (p < end && *p == '"') {
        p++;
        while (p < end && *p != '"') {
            char c = *p++;
            if (c == '\\') {
                if (p >= end) return NULL;
                char e = *p++;
                if (e == 'u') { if (end - p < 4) return NULL; p += 4; c = '?'; }
                else if (e == '"' || e == '\\' || e == '/') c = e;
                else c = '?';
            }
            if ((unsigned char)c < 0x20) c = '?';
            if (o + 1 < cap) out[o++] = c;
        }
        if (p >= end) return NULL;
        out[o] = '\0';
        return p + 1;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ' ') {
        if (o + 1 < cap) out[o++] = *p;
        p++;
    }
    out[o] = '\0';
    return o ? p : NULL;
}

static int hex_ok(const char *s, size_t n) {
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i])) return 0;
    return 1;
}

static int ll_of(const char *s, long long *out) {
    if (!*s || strlen(s) > 18) return 0;
    long long v = 0;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return 0;
        v = v * 10 + (*s - '0');
    }
    *out = v;
    return 1;
}

int web_pcapdir_parse_line(const char *line, size_t len, web_pcap_entry_t *e) {
    memset(e, 0, sizeof(*e));
    const char *p = line, *end = line + len;
    while (p < end && (*p == ' ' || *p == '\r')) p++;
    if (p >= end || *p != '{') return 0;
    p++;
    int have_v = 0, have_file = 0, have_size = 0, have_hash = 0, have_sink = 0, have_epoch = 0;
    char key[32], val[WEB_PCAP_NAME_MAX * 2 + 8];
    for (int fields = 0; fields < 32; fields++) {
        while (p < end && *p == ' ') p++;
        if (p < end && *p == '}') break;
        if (p >= end || *p != '"') return 0;
        p = value(p, end, key, sizeof(key));
        if (!p || p >= end || *p != ':') return 0;
        p++;
        p = value(p, end, val, sizeof(val));
        if (!p) return 0;
        long long n;
        if (!strcmp(key, "v")) { if (!ll_of(val, &n) || n != 1) return 0; have_v = 1; }
        else if (!strcmp(key, "file")) {
            if (!web_pcapdir_name_ok(val)) return 0;
            memcpy(e->file, val, strlen(val) + 1);
            have_file = 1;
        } else if (!strcmp(key, "size")) { if (!ll_of(val, &n)) return 0; e->size = n; have_size = 1; }
        else if (!strcmp(key, "sha256")) {
            if (!hex_ok(val, 64)) return 0;
            memcpy(e->sha256, val, 65);
            have_hash = 1;
        } else if (!strcmp(key, "sink")) {
            if (strcmp(val, "alert_pcap") && strcmp(val, "evidence_pcap")) return 0;
            memcpy(e->sink, val, strlen(val) + 1);
            have_sink = 1;
        } else if (!strcmp(key, "incident_id")) {
            if (hex_ok(val, 16)) memcpy(e->incident_id, val, 17);
        } else if (!strcmp(key, "rule")) {
            size_t l = strlen(val);
            if (l < sizeof(e->rule)) {
                int ok = l > 0;
                for (size_t i = 0; i < l; i++)
                    if (!isalnum((unsigned char)val[i]) && val[i] != '_') ok = 0;
                if (ok) memcpy(e->rule, val, l + 1);
            }
        } else if (!strcmp(key, "written_at")) {
            if (strlen(val) == 20 && val[19] == 'Z') memcpy(e->written_at, val, 21);
        } else if (!strcmp(key, "written_at_epoch")) {
            if (!ll_of(val, &n)) return 0;
            e->written_at_epoch = n;
            have_epoch = 1;
        }
        while (p < end && *p == ' ') p++;
        if (p < end && *p == ',') p++;
    }
    if (p >= end || *p != '}') return 0;
    if (!(have_v && have_file && have_size && have_hash && have_sink && have_epoch)) return 0;
    /* The --pcap-dir sink's name is the alert_ shape, the evidence
     * sink's the incident shape: a line that crosses them is not one
     * sloth wrote. */
    int alert_shape = !strncmp(e->file, "alert_", 6);
    if (alert_shape != !strcmp(e->sink, "alert_pcap")) return 0;
    return 1;
}

/* ── the scan ─────────────────────────────────────────────────────── */

typedef struct {
    char name[WEB_PCAP_NAME_MAX + 1];
} mname_t;

static int by_name_desc(const void *a, const void *b) {
    return strcmp(((const mname_t *)b)->name, ((const mname_t *)a)->name);
}

static int by_newest(const void *a, const void *b) {
    const web_pcap_entry_t *x = a, *y = b;
    if (x->written_at_epoch != y->written_at_epoch)
        return x->written_at_epoch < y->written_at_epoch ? 1 : -1;
    /* Equal stamps keep the order they were read in (newest manifest
     * first): qsort is not stable, so the read index is the tie-break. */
    return (x->order > y->order) - (x->order < y->order);
}

static void read_manifest(web_pcapdir_t *p, int dirfd, int dir, const char *name) {
    long long size;
    const char *why;
    int fd = open_under(dirfd, name, (long long)WEB_PCAPDIR_MANIFEST_MAX, &size, &why);
    if (fd < 0) { if (!strcmp(why, "too_large")) p->partial = 1; return; }
    unsigned char *b = web_pcapdir_slurp(fd, size);
    close(fd);
    if (!b) return;
    const char *s = (const char *)b, *end = s + size;
    while (s < end) {
        const char *nl = memchr(s, '\n', (size_t)(end - s));
        if (!nl) break;                     /* an unterminated tail: dropped */
        if (p->n >= WEB_PCAPDIR_ENTRIES) { p->partial = 1; break; }
        web_pcap_entry_t e;
        if (web_pcapdir_parse_line(s, (size_t)(nl - s), &e)) {
            e.dir = dir;
            p->e[p->n++] = e;
        }
        s = nl + 1;
    }
    free(b);
}

static long long mtime_ns(const struct stat *st) {
    return (long long)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec;
}

void web_pcapdir_scan(web_pcapdir_t *p, long long now_ms) {
    if (p->ndir == 0 || !p->e) return;
    if (p->scanned_ms >= 0 && now_ms - p->scanned_ms < WEB_PCAPDIR_RESCAN_MS) return;
    p->scanned_ms = now_ms;
    /* Each directory's manifests, newest session first (the stamp is
     * the name), and whether anything moved since the last scan. */
    static mname_t names[WEB_PCAP_DIRS][WEB_PCAPDIR_MANIFESTS];
    int nn[WEB_PCAP_DIRS];
    int changed = p->scans == 0, partial = 0;
    for (int d = 0; d < p->ndir; d++) {
        nn[d] = 0;
        int err;
        int dirfd = web_pcapdir_open_dir(p, d, &err);
        if (dirfd < 0) {
            if (p->d[d].err != err || p->d[d].mtime_ns != -1) changed = 1;
            p->d[d].err = err;
            p->d[d].mtime_ns = -1;
            continue;
        }
        p->d[d].err = 0;
        struct stat st;
        long long mt = fstat(dirfd, &st) == 0 ? mtime_ns(&st) : -1;
        DIR *dh = fdopendir(dup(dirfd));
        if (dh) {
            struct dirent *de;
            int seen = 0;
            while ((de = readdir(dh)) != NULL) {
                if (++seen > WEB_PCAPDIR_READDIR) { partial = 1; break; }
                if (!manifest_name_ok(de->d_name)) continue;
                mname_t m;
                /* manifest_name_ok() held it under sizeof(m.name). */
                memcpy(m.name, de->d_name, strlen(de->d_name) + 1);
                if (nn[d] < WEB_PCAPDIR_MANIFESTS) {
                    names[d][nn[d]++] = m;
                } else {
                    /* Keep the WEB_PCAPDIR_MANIFESTS newest: replace
                     * the oldest held when this one is newer. */
                    int oldest = 0;
                    for (int i = 1; i < nn[d]; i++)
                        if (strcmp(names[d][i].name, names[d][oldest].name) < 0) oldest = i;
                    if (strcmp(m.name, names[d][oldest].name) > 0) names[d][oldest] = m;
                    partial = 1;
                }
            }
            closedir(dh);
        }
        qsort(names[d], (size_t)nn[d], sizeof(mname_t), by_name_desc);
        long long nsize = -1;
        if (nn[d]) {
            struct stat ms;
            if (fstatat(dirfd, names[d][0].name, &ms, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(ms.st_mode))
                nsize = (long long)ms.st_size;
        }
        if (mt != p->d[d].mtime_ns || nsize != p->d[d].newest_size ||
            strcmp(nn[d] ? names[d][0].name : "", p->d[d].newest) != 0)
            changed = 1;
        p->d[d].mtime_ns = mt;
        p->d[d].newest_size = nsize;
        if (nn[d]) memcpy(p->d[d].newest, names[d][0].name, sizeof(p->d[d].newest));
        else p->d[d].newest[0] = '\0';
        close(dirfd);
    }
    p->scans++;
    if (!changed) { p->partial = p->partial || partial; return; }
    p->n = 0;
    p->partial = partial;
    for (int d = 0; d < p->ndir; d++) {
        if (p->d[d].mtime_ns < 0 || !nn[d]) continue;
        int err;
        int dirfd = web_pcapdir_open_dir(p, d, &err);
        if (dirfd < 0) continue;
        for (int i = 0; i < nn[d]; i++) read_manifest(p, dirfd, d, names[d][i].name);
        close(dirfd);
    }
    /* Newest first, read order within a stamp, on a field of its own:
     * the stamp is whatever 18 digits a manifest line held, so nothing
     * is folded into it (a scaled stamp overflowed past 2^47). */
    for (int i = 0; i < p->n; i++) p->e[i].order = i;
    qsort(p->e, (size_t)p->n, sizeof(*p->e), by_newest);
}

/* ── the lookup ───────────────────────────────────────────────────── */

static int has_hit(const web_pcap_hit_t *h, int n, const char *file, int dir) {
    for (int i = 0; i < n; i++)
        if (h[i].dir == dir && !strcmp(h[i].file, file)) return 1;
    return 0;
}

static void take(web_pcap_hit_t *out, int *n, int max, const web_pcap_entry_t *e,
                 const char *file, int dir, const char *by) {
    if (*n >= max || has_hit(out, *n, file, dir)) return;
    web_pcap_hit_t *h = &out[(*n)++];
    h->e = e;
    snprintf(h->file, sizeof(h->file), "%s", file);
    h->dir = dir;
    h->matched_by = by;
    h->withheld = NULL;
    h->unreadable = NULL;
    h->lines = 0;
    h->conflict = 0;
}

/* What the list says of each hit beyond its name: withheld, not a
 * regular file, and how many manifest lines name it. */
static void annotate(const web_pcapdir_t *p, web_pcap_hit_t *out, int n) {
    for (int d = 0; d < p->ndir; d++) {
        int dirfd = -1;
        for (int i = 0; i < n; i++) {
            web_pcap_hit_t *h = &out[i];
            if (h->dir != d) continue;
            /* parse_line() ties the evidence sink to the evidence
             * name, so the name alone says which a record-named file
             * with no line is. */
            if (!p->serve_evidence && strncmp(h->file, "alert_", 6) != 0)
                h->withheld = WEB_PCAP_WITHHELD;
            const web_pcap_entry_t *first = NULL;
            for (int k = 0; k < p->n; k++) {
                const web_pcap_entry_t *e = &p->e[k];
                if (e->dir != d || strcmp(e->file, h->file) != 0) continue;
                h->lines++;
                if (!first) first = e;
                else if (e->size != first->size || strcmp(e->sha256, first->sha256) != 0)
                    h->conflict = 1;
            }
            if (dirfd < 0) {
                int err;
                dirfd = web_pcapdir_open_dir(p, d, &err);
                if (dirfd < 0) break;
            }
            struct stat st;
            if (fstatat(dirfd, h->file, &st, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISREG(st.st_mode))
                h->unreadable = WEB_PCAP_NOT_REG;
        }
        if (dirfd >= 0) close(dirfd);
    }
}

int web_pcapdir_for_alert(web_pcapdir_t *p, long long now_ms, const char *incident_id,
                          const char *pcap_name, const char *rule, long long first_seen,
                          long long last_seen, web_pcap_hit_t *out, int max) {
    int n = 0;
    if (max > WEB_PCAPDIR_HITS) max = WEB_PCAPDIR_HITS;
    if (p->ndir == 0 || !p->e) return 0;
    web_pcapdir_scan(p, now_ms);
    int have_id = incident_id && hex_ok(incident_id, 16);
    int have_name = pcap_name && web_pcapdir_name_ok(pcap_name);
    for (int i = 0; have_id && i < p->n && n < max; i++)
        if (!strcmp(p->e[i].incident_id, incident_id))
            take(out, &n, max, &p->e[i], p->e[i].file, p->e[i].dir, "incident");
    int named = 0;
    for (int i = 0; have_name && i < p->n && n < max; i++)
        if (!strcmp(p->e[i].file, pcap_name)) {
            take(out, &n, max, &p->e[i], p->e[i].file, p->e[i].dir, "record");
            named = 1;
        }
    /* The record named a file no manifest lists (a manifest that could
     * not be written, or one past the index): a hit without a line
     * when the file is there, so the page can still show it, with
     * "no manifest entry" for its hash. */
    for (int d = 0; have_name && !named && d < p->ndir && n < max; d++) {
        int err;
        int dirfd = web_pcapdir_open_dir(p, d, &err);
        if (dirfd < 0) continue;
        long long size;
        const char *why;
        int fd = web_pcapdir_open_file(dirfd, pcap_name, &size, &why);
        if (fd >= 0) { close(fd); take(out, &n, max, NULL, pcap_name, d, "record"); }
        close(dirfd);
    }
    /* Only when neither sloth's id nor its record found a file: the
     * manifest carries no address, so another key's file of the same
     * rule in the window would match too, and the page says how each
     * file was matched. */
    if (n == 0 && rule && rule[0] && first_seen > 0 && last_seen >= first_seen) {
        long long lo = first_seen - 60, hi = last_seen + WEB_PCAPDIR_TIME_SLACK_S;
        for (int i = 0; i < p->n && n < max; i++) {
            const web_pcap_entry_t *e = &p->e[i];
            if (strcmp(e->rule, rule) != 0) continue;
            if (e->written_at_epoch < lo || e->written_at_epoch > hi) continue;
            take(out, &n, max, e, e->file, e->dir, "rule_time");
        }
    }
    annotate(p, out, n);
    return n;
}

const web_pcap_hit_t *web_pcapdir_hit_named(const web_pcap_hit_t *hits, int n, const char *file) {
    if (!file || !web_pcapdir_name_ok(file)) return NULL;
    for (int i = 0; i < n; i++)
        if (!strcmp(hits[i].file, file)) return &hits[i];
    return NULL;
}

const char *web_pcapdir_verify(const unsigned char *buf, size_t n, const web_pcap_entry_t *e) {
    if (!e) return "no_manifest_entry";
    if ((long long)n != e->size) return "MISMATCH";
    uint8_t d[32];
    web_sha256(buf, n, d);
    static const char HEX[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++)
        if (e->sha256[2 * i] != HEX[d[i] >> 4] || e->sha256[2 * i + 1] != HEX[d[i] & 15])
            return "MISMATCH";
    return "verified";
}

const char *web_pcapdir_verify_hit(const web_pcapdir_t *p, const unsigned char *buf, size_t n,
                                   const web_pcap_hit_t *h, const web_pcap_entry_t **match) {
    if (match) *match = h ? h->e : NULL;
    if (!h || !h->e) return "no_manifest_entry";
    /* Any line naming the file that vouches for these bytes, not only
     * the newest: a line's stamp is its own claim, so a later one
     * cannot outvote an earlier one that matches. Hashed once, however
     * many lines name the file. */
    uint8_t d[32];
    char hex[65];
    web_sha256(buf, n, d);
    static const char HEX[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[2 * i] = HEX[d[i] >> 4];
        hex[2 * i + 1] = HEX[d[i] & 15];
    }
    hex[64] = '\0';
    for (int k = 0; p && k < p->n; k++) {
        const web_pcap_entry_t *e = &p->e[k];
        if (e->dir != h->dir || strcmp(e->file, h->file) != 0) continue;
        if ((long long)n == e->size && !strcmp(e->sha256, hex)) {
            if (match) *match = e;
            return "verified";
        }
    }
    return "MISMATCH";
}

const char *web_pcapdir_note(const web_pcapdir_t *p, char *buf, size_t cap) {
    if (p->ndir == 0) return "no --pcap-dir";
    for (int d = 0; d < p->ndir; d++) {
        if (p->d[d].mtime_ns < 0 && p->d[d].err) {
            int e = p->d[d].err;
            snprintf(buf, cap, "directory unreadable: %s",
                     e == ENOENT ? "ENOENT" : e == EACCES ? "EACCES" : e == ENOTDIR ? "ENOTDIR"
                     : e == ELOOP ? "ELOOP" : e == EPERM ? "EPERM" : "error");
            return buf;
        }
    }
    if (p->partial) return "index partial";
    return NULL;
}
