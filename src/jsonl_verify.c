#include "jsonl_chain.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "evidence_manifest.h"

/* sloth --verify PATH (#251): the reader of the chain src/jsonl_chain.c
 * writes, and of the #92 evidence manifests. Apart from the writer so
 * sloth-rf, which writes the chain, links none of it: main.c alone
 * names jc_verify_main(). */

static const char ZERO_HEX[JC_HEX_LEN] =
    "0000000000000000000000000000000000000000000000000000000000000000";
#define CHAIN_PREFIX "{\"type\":\"chain\","

static void ctx_hex(sha256_ctx_t *c, char hex[JC_HEX_LEN]) {
    static const char hx[] = "0123456789abcdef";
    uint8_t d[32];
    sha256_final(c, d);
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 0xf];
    }
    hex[64] = '\0';
}

static void line_hex(const char *rec, size_t n, char hex[JC_HEX_LEN]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)rec, n);
    sha256_update(&c, (const uint8_t *)"\n", 1);
    ctx_hex(&c, hex);
}

/* ── --verify on a JSONL file ──────────────────────────────────────── */

typedef struct {
    long long          ts;
    unsigned           n;
    unsigned long long seq;
    unsigned           lines;
    char               blk[JC_HEX_LEN], prev[JC_HEX_LEN];
} jc_rec_t;

static int is_hex64(const char *s) {
    for (int i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

/* A chain record is read by re-rendering what it parses to and
 * comparing bytes, so a record is either exactly what the writer makes
 * or malformed: no spelling of it a reader might take two ways. */
static int parse_rec(const char *line, size_t n, jc_rec_t *r) {
    char blk[80], prev[80];
    memset(r, 0, sizeof(*r));
    if (sscanf(line, CHAIN_PREFIX "\"ts\":%lld,\"v\":1,\"n\":%u,\"seq\":%llu,"
               "\"lines\":%u,"
               "\"block_sha256\":\"%79[^\"]\",\"prev_sha256\":\"%79[^\"]\"}",
               &r->ts, &r->n, &r->seq, &r->lines, blk, prev) != 6)
        return -1;
    if (r->n == 0 || r->n > JC_MAX_BLOCK) return -1;
    if (strlen(blk) != 64 || strlen(prev) != 64 || !is_hex64(blk) || !is_hex64(prev))
        return -1;
    memcpy(r->blk, blk, JC_HEX_LEN);
    memcpy(r->prev, prev, JC_HEX_LEN);
    char again[JC_RECORD_MAX];
    int m = jc_format(again, sizeof(again), r->ts, r->n, r->seq, r->lines,
                      r->blk, r->prev);
    if (m <= 0 || (size_t)m != n || memcmp(again, line, n) != 0) return -1;
    return 0;
}

static void set_break(jc_verify_t *v, uint64_t seg, uint64_t seq, uint64_t first,
                uint64_t last, uint64_t line, const char *what) {
    v->status = 1;
    v->brk_segment = seg;
    v->brk_seq = seq;
    v->brk_first = first;
    v->brk_last = last;
    v->brk_line = line;
    snprintf(v->brk_what, sizeof(v->brk_what), "%s", what);
}

static const char EMPTY_HEX[JC_HEX_LEN] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/* After a segment's last chain record the writer leaves at most n-1
 * lines (a crash between seals). More is chain records taken out, or a
 * run without the flag appending to a chained file; the file cannot
 * say which, so it is a break and the message names both. */
static int tail_too_long(jc_verify_t *v, uint64_t since, uint64_t first,
                         uint64_t last, uint64_t at) {
    if (since < (uint64_t)v->head_n) return 0;
    char what[240];
    snprintf(what, sizeof(what), "%llu unchained lines after the segment's "
             "last chain record (line %llu), where the writer leaves at most "
             "%u: chain records were removed, or a run without --jsonl-chain "
             "appended to this file", (unsigned long long)since,
             (unsigned long long)v->head_line, v->head_n - 1);
    set_break(v, v->head_segment, 0, first, last, at, what);
    return 1;
}

void jc_verify_stream(FILE *f, jc_verify_t *v) {
    jc_verify_stream_segs(f, v, NULL, NULL);
}

void jc_verify_stream_segs(FILE *f, jc_verify_t *v, jc_seg_head_fn seg_head,
                           void *ctx) {
    memset(v, 0, sizeof(*v));
    if (!f) { v->status = 2; return; }
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int in_chain = 0;
    uint64_t seg = 0;
    char prev[JC_HEX_LEN];
    memcpy(prev, ZERO_HEX, sizeof(prev));
    sha256_ctx_t blk;
    sha256_init(&blk);
    uint64_t since = 0, since_first = 0;    /* lines since the last record */
    const size_t pfx = sizeof(CHAIN_PREFIX) - 1;

    while ((got = getline(&line, &cap, f)) > 0) {
        size_t n = (size_t)got;
        if (line[n - 1] != '\n') { v->fragment = 1; break; }
        v->lines++;
        const uint64_t ln = v->lines;
        if (n - 1 < pfx || memcmp(line, CHAIN_PREFIX, pfx) != 0) {
            sha256_update(&blk, (const uint8_t *)line, n);
            if (!since) since_first = ln;
            since++;
            continue;
        }
        jc_rec_t r;
        if (parse_rec(line, n - 1, &r) != 0) {
            set_break(v, seg, 0, 0, 0, ln, "a chain record is malformed");
            break;
        }
        char got_hex[JC_HEX_LEN], what[240];
        ctx_hex(&blk, got_hex);
        sha256_init(&blk);
        const uint64_t first = since ? since_first : 0;
        const uint64_t last  = since ? ln - 1 : 0;
        if (r.seq == 1 && strcmp(r.prev, ZERO_HEX) == 0) {
            /* A genesis: lines before it belong to no block. */
            if (r.lines != 0 || strcmp(r.blk, EMPTY_HEX) != 0) {
                set_break(v, seg + 1, 1, 0, 0, ln,
                    "a genesis record (seq 1) that claims lines");
                break;
            }
            if (in_chain && tail_too_long(v, since, first, last, ln)) break;
            if (in_chain && seg_head)
                seg_head(ctx, v->head_segment, v->head_seq, v->head_line,
                         v->head_sha);
            if (since) {
                if (!v->uncovered_first) v->uncovered_first = since_first;
                v->uncovered += since;
            }
            seg++;
            v->segments++;
            in_chain = 1;
        } else if (!in_chain) {
            set_break(v, seg, r.seq, first, last, ln,
                "a chain record with no genesis before it");
            break;
        } else if (r.n != v->head_n) {
            snprintf(what, sizeof(what), "n %u where the segment's genesis "
                     "says %u", r.n, v->head_n);
            set_break(v, seg, r.seq, first, last, ln, what);
            break;
        } else if (r.seq != v->head_seq + 1) {
            snprintf(what, sizeof(what), "seq %llu follows seq %llu",
                     (unsigned long long)r.seq, (unsigned long long)v->head_seq);
            set_break(v, seg, r.seq, first, last, ln, what);
            break;
        } else if (strcmp(r.prev, prev) != 0) {
            snprintf(what, sizeof(what), "prev_sha256 is not the SHA-256 of "
                     "the chain record at line %llu",
                     (unsigned long long)v->head_line);
            set_break(v, seg, r.seq, first, last, ln, what);
            break;
        } else if ((uint64_t)r.lines != since || r.lines > r.n) {
            snprintf(what, sizeof(what), "the record covers %u lines (at most "
                     "%u), the file holds %llu", r.lines, r.n,
                     (unsigned long long)since);
            set_break(v, seg, r.seq, first, last, ln, what);
            break;
        } else if (strcmp(r.blk, got_hex) != 0) {
            set_break(v, seg, r.seq, first, last, ln,
                "the lines do not match block_sha256: changed after capture");
            break;
        } else {
            v->blocks++;
        }
        v->records++;
        v->head_n = r.n;
        v->head_segment = seg;
        v->head_seq = r.seq;
        v->head_line = ln;
        line_hex(line, n - 1, prev);
        memcpy(v->head_sha, prev, sizeof(prev));
        since = 0;
    }
    if (ferror(f) && v->status == 0) {
        v->status = 2;
        snprintf(v->brk_what, sizeof(v->brk_what), "read failed");
    }
    free(line);
    if (v->status) return;
    if (in_chain &&
        tail_too_long(v, since, since ? since_first : 0, since ? v->lines : 0,
                      v->lines))
        return;
    v->pending = in_chain ? since : 0;
    if (!in_chain) {
        v->uncovered += since;
        if (since && !v->uncovered_first) v->uncovered_first = since_first;
    }
    if (v->records == 0) {
        v->status = 2;
        snprintf(v->brk_what, sizeof(v->brk_what), "no chain record: the file "
                 "was written without --jsonl-chain");
        return;
    }
    if (seg_head)
        seg_head(ctx, v->head_segment, v->head_seq, v->head_line, v->head_sha);
}

/* ── --verify on an evidence directory ─────────────────────────────── */

typedef struct {
    char     file[160];
    char     sha[JC_HEX_LEN];
    uint64_t size;
} ev_line_t;

/* The value after "key": in a flat manifest line. The keys read here
 * are not names inside the one nested object, `loc`. */
static const char *mf_val(const char *line, const char *key) {
    char pat[40];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    return p ? p + strlen(pat) : NULL;
}

static int mf_str(const char *line, const char *key, char *out, size_t cap) {
    const char *p = mf_val(line, key);
    if (!p || *p != '"') return -1;
    p++;
    size_t i = 0;
    for (; *p && *p != '"'; p++) {
        /* Names sloth writes need no escape; one that has one, or a
         * path separator, names nothing in this directory. */
        if (*p == '\\' || *p == '/' || (unsigned char)*p < 0x20) return -1;
        if (i + 1 >= cap) return -1;
        out[i++] = *p;
    }
    if (*p != '"' || i == 0) return -1;
    out[i] = '\0';
    return 0;
}

static int mf_u64(const char *line, const char *key, uint64_t *out) {
    const char *p = mf_val(line, key);
    if (!p || *p < '0' || *p > '9') return -1;
    uint64_t v = 0;
    for (; *p >= '0' && *p <= '9'; p++) v = v * 10 + (uint64_t)(*p - '0');
    *out = v;
    return 0;
}

static int hash_at(int dfd, const char *name, char hex[JC_HEX_LEN], uint64_t *size) {
    int fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? -1 : -2;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -2; }
    sha256_ctx_t c;
    sha256_init(&c);
    uint8_t buf[8192];
    uint64_t total = 0;
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -2; }
        if (r == 0) break;
        sha256_update(&c, buf, (size_t)r);
        total += (uint64_t)r;
    }
    close(fd);
    ctx_hex(&c, hex);
    *size = total;
    return 0;
}

static int cmp_name(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Each manifest, in name order: every complete line must parse, and
 * seq must run 1, 2, 3 ... with no gap (the manifest's own rule: a gap
 * means a line went missing). A final fragment is a crash tail. */
static int read_manifest(int dfd, const char *name, ev_line_t **lines,
                         size_t *n, size_t *capn, jc_evdir_t *v) {
    int fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *f = fd >= 0 ? fdopen(fd, "r") : NULL;
    if (!f) {
        if (fd >= 0) close(fd);
        snprintf(v->brk_what, sizeof(v->brk_what), "%s: cannot read", name);
        return -2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    uint64_t want = 1, ln = 0;
    int rc = 0;
    while ((got = getline(&line, &cap, f)) > 0) {
        if (line[got - 1] != '\n') break;
        ln++;
        v->lines++;
        ev_line_t e;
        uint64_t seq = 0;
        memset(&e, 0, sizeof(e));
        if (mf_u64(line, "seq", &seq) != 0 ||
            mf_str(line, "file", e.file, sizeof(e.file)) != 0 ||
            mf_u64(line, "size", &e.size) != 0 ||
            mf_str(line, "sha256", e.sha, sizeof(e.sha)) != 0 ||
            strlen(e.sha) != 64 || !is_hex64(e.sha)) {
            snprintf(v->brk_what, sizeof(v->brk_what),
                     "%s line %llu: malformed", name, (unsigned long long)ln);
            rc = -1;
            break;
        }
        if (seq != want) {
            snprintf(v->brk_what, sizeof(v->brk_what),
                     "%s line %llu: seq %llu where %llu was due: a line is "
                     "missing", name, (unsigned long long)ln,
                     (unsigned long long)seq, (unsigned long long)want);
            rc = -1;
            break;
        }
        want++;
        if (*n == *capn) {
            size_t nc = *capn ? *capn * 2 : 64;
            ev_line_t *nl = realloc(*lines, nc * sizeof(**lines));
            if (!nl) {
                snprintf(v->brk_what, sizeof(v->brk_what), "out of memory");
                rc = -2;
                break;
            }
            *lines = nl;
            *capn = nc;
        }
        (*lines)[(*n)++] = e;
    }
    free(line);
    fclose(f);
    return rc;
}

void jc_verify_evidence_dir(const char *dir, jc_evdir_t *v) {
    memset(v, 0, sizeof(*v));
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? fdopendir(dup(dfd)) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        v->status = 2;
        snprintf(v->brk_what, sizeof(v->brk_what), "%s: cannot open: %s",
                 dir, strerror(errno));
        return;
    }
    char **names = NULL;
    size_t nn = 0, capnames = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (nn == capnames) {
            size_t nc = capnames ? capnames * 2 : 64;
            char **x = realloc(names, nc * sizeof(*names));
            if (!x) break;
            names = x;
            capnames = nc;
        }
        names[nn] = strdup(e->d_name);
        if (names[nn]) nn++;
    }
    closedir(d);
    if (nn) qsort(names, nn, sizeof(*names), cmp_name);

    ev_line_t *lines = NULL;
    size_t nl = 0, capl = 0;
    for (size_t i = 0; i < nn && v->status == 0; i++) {
        if (!evidence_manifest_is_name(names[i])) continue;
        v->manifests++;
        int rc = read_manifest(dfd, names[i], &lines, &nl, &capl, v);
        if (rc == -1) v->status = 1;
        else if (rc == -2) v->status = 2;
    }
    if (v->status == 0 && v->manifests == 0) {
        v->status = 2;
        snprintf(v->brk_what, sizeof(v->brk_what), "%s: no sloth-manifest-*.jsonl: "
                 "not a --pcap-dir or --eapol-dir sloth wrote into", dir);
    }
    /* Each name once: it is intact when its bytes match any of its
     * lines. A handshake pcap is replaced and eapol.22000 appended to,
     * so their earlier lines name bytes that are gone by design; an
     * alert or evidence pcap is never rewritten and has one line. */
    for (size_t i = 0; i < nl && v->status == 0; i++) {
        int seen = 0;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(lines[j].file, lines[i].file)) { seen = 1; break; }
        if (seen) continue;
        char hex[JC_HEX_LEN];
        uint64_t size = 0;
        int h = hash_at(dfd, lines[i].file, hex, &size);
        if (h == -1) {
            if (!v->missing)
                snprintf(v->first_missing, sizeof(v->first_missing), "%s",
                         lines[i].file);
            v->missing++;
            continue;
        }
        if (h != 0) {
            v->status = 2;
            snprintf(v->brk_what, sizeof(v->brk_what), "%s: cannot read",
                     lines[i].file);
            break;
        }
        int ok = 0, count = 0;
        for (size_t j = i; j < nl; j++) {
            if (strcmp(lines[j].file, lines[i].file)) continue;
            count++;
            if (lines[j].size == size && !strcmp(lines[j].sha, hex)) ok = 1;
        }
        if (!ok) {
            v->status = 1;
            snprintf(v->brk_what, sizeof(v->brk_what), "%s: its SHA-256 matches "
                     "none of its %d manifest line%s: changed after it was "
                     "written", lines[i].file, count, count == 1 ? "" : "s");
            break;
        }
        v->files_ok++;
    }
    /* Files no manifest lists: reported, not a break (the `w` export and
     * anything an operator put there are not sloth's evidence). */
    for (size_t i = 0; i < nn && v->status == 0; i++) {
        if (evidence_manifest_is_name(names[i])) continue;
        int listed = 0;
        for (size_t j = 0; j < nl; j++)
            if (!strcmp(lines[j].file, names[i])) { listed = 1; break; }
        if (listed) continue;
        if (!v->unlisted)
            snprintf(v->first_unlisted, sizeof(v->first_unlisted), "%s", names[i]);
        v->unlisted++;
    }
    for (size_t i = 0; i < nn; i++) free(names[i]);
    free(names);
    free(lines);
    close(dfd);
}

/* ── sloth --verify PATH ───────────────────────────────────────────── */

/* Each segment's head, kept until the summary is printed under them. */
typedef struct {
    char  *buf;
    size_t len, cap;
} seg_text_t;

static void seg_line(void *ctx, uint64_t segment, uint64_t seq, uint64_t line,
                     const char *sha) {
    seg_text_t *t = ctx;
    char one[200];
    int n = snprintf(one, sizeof(one), "  segment %llu head: seq %llu at line "
                     "%llu, sha256 %s\n", (unsigned long long)segment,
                     (unsigned long long)seq, (unsigned long long)line, sha);
    if (n <= 0 || (size_t)n >= sizeof(one)) return;
    if (t->len + (size_t)n + 1 > t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 1024;
        while (nc < t->len + (size_t)n + 1) nc *= 2;
        char *nb = realloc(t->buf, nc);
        if (!nb) return;
        t->buf = nb;
        t->cap = nc;
    }
    memcpy(t->buf + t->len, one, (size_t)n + 1);
    t->len += (size_t)n;
}

static int verify_jsonl(const char *path, FILE *out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    FILE *f = fd >= 0 ? fdopen(fd, "r") : NULL;
    if (!f) {
        if (fd >= 0) close(fd);
        fprintf(out, "verify: %s: cannot read: %s\n", path, strerror(errno));
        return 2;
    }
    jc_verify_t v;
    seg_text_t segs = { NULL, 0, 0 };
    jc_verify_stream_segs(f, &v, seg_line, &segs);
    fclose(f);
    fprintf(out, "verify: %s: JSONL hash chain (--jsonl-chain)\n", path);
    if (v.status == 2) {
        free(segs.buf);
        fprintf(out, "  cannot verify: %s\n", v.brk_what);
        return 2;
    }
    fprintf(out, "  lines %llu, chain records %llu in %llu segment%s, blocks "
            "checked %llu\n", (unsigned long long)v.lines,
            (unsigned long long)v.records, (unsigned long long)v.segments,
            v.segments == 1 ? "" : "s", (unsigned long long)v.blocks);
    /* One head per run that wrote here: a report written during that
     * run names its segment's head, or a chain record before it. */
    if (segs.buf) fputs(segs.buf, out);
    free(segs.buf);
    if (v.status == 1) {
        fprintf(out, "  BREAK at line %llu: segment %llu", 
                (unsigned long long)v.brk_line, (unsigned long long)v.brk_segment);
        if (v.brk_seq)
            fprintf(out, " block %llu", (unsigned long long)v.brk_seq);
        if (v.brk_first)
            fprintf(out, " (lines %llu-%llu)", (unsigned long long)v.brk_first,
                    (unsigned long long)v.brk_last);
        fprintf(out, ": %s\n", v.brk_what);
        if (v.head_line)
            fprintf(out, "  intact up to the chain record at line %llu "
                    "(segment %llu seq %llu)\n", (unsigned long long)v.head_line,
                    (unsigned long long)v.head_segment,
                    (unsigned long long)v.head_seq);
        fprintf(out, "  result: break\n");
        return 1;
    }
    if (v.uncovered)
        fprintf(out, "  not covered: %llu line%s before a genesis, the first at "
                "line %llu (an earlier run's tail, or a run without the chain)\n",
                (unsigned long long)v.uncovered, v.uncovered == 1 ? "" : "s",
                (unsigned long long)v.uncovered_first);
    fprintf(out, "  head: segment %llu seq %llu at line %llu, sha256 %s\n",
            (unsigned long long)v.head_segment, (unsigned long long)v.head_seq,
            (unsigned long long)v.head_line, v.head_sha);
    if (v.pending || v.fragment)
        fprintf(out, "  pending: %llu line%s after the head not yet chained%s\n",
                (unsigned long long)v.pending, v.pending == 1 ? "" : "s",
                v.fragment ? ", and a final line with no newline" : "");
    fprintf(out, "  compare a report's head with its segment's head above, or "
            "with the chain record of that seq in that segment (sha256 of its "
            "line): lines cut after a chain record, or a whole segment "
            "removed, verify here\n");
    fprintf(out, "  result: intact\n");
    return 0;
}

static int verify_dir(const char *path, FILE *out) {
    jc_evdir_t v;
    jc_verify_evidence_dir(path, &v);
    fprintf(out, "verify: %s: evidence directory (sloth-manifest-*.jsonl)\n", path);
    if (v.status == 2) {
        fprintf(out, "  cannot verify: %s\n", v.brk_what);
        return 2;
    }
    fprintf(out, "  manifests %d, lines %llu, files intact %llu\n", v.manifests,
            (unsigned long long)v.lines, (unsigned long long)v.files_ok);
    if (v.status == 1) {
        fprintf(out, "  BREAK: %s\n  result: break\n", v.brk_what);
        return 1;
    }
    if (v.missing)
        fprintf(out, "  missing: %llu listed file%s not on disk, the first %s "
                "(the retention sweep removes them; so would anyone else)\n",
                (unsigned long long)v.missing, v.missing == 1 ? "" : "s",
                v.first_missing);
    if (v.unlisted)
        fprintf(out, "  unlisted: %llu file%s in no manifest, the first %s\n",
                (unsigned long long)v.unlisted, v.unlisted == 1 ? "" : "s",
                v.first_unlisted);
    fprintf(out, "  the manifests are not chained: a line and its file "
            "changed together verify here; the chained JSONL alert record's "
            "pcap_sha256 is what ties a capture to the chain\n");
    fprintf(out, "  result: intact\n");
    return 0;
}

int jc_verify_main(const char *path, FILE *out) {
    struct stat st;
    if (!path || stat(path, &st) != 0) {
        fprintf(out, "verify: %s: %s\n", path ? path : "", strerror(errno));
        return 2;
    }
    if (S_ISDIR(st.st_mode)) return verify_dir(path, out);
    if (S_ISREG(st.st_mode)) return verify_jsonl(path, out);
    fprintf(out, "verify: %s: neither a file nor a directory\n", path);
    return 2;
}
