#include "sweep_run.h"
#include "wifi_snapshot.h"
#include "secure_file.h"
#include "mon_radios.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The sweep run (#249). Contract: sweep_run.h. Main thread. */

int sweep_label_ok(const char *l) {
    if (!l || !l[0] || l[0] == '.' || l[0] == '-') return 0;
    size_t n = strlen(l);
    if (n > SWEEP_LABEL_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = l[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int sweep_minutes_parse(const char *s, unsigned *out) {
    if (!s || !out) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 1 || v > SWEEP_MINUTES_MAX) return -1;
    *out = (unsigned)v;
    return 0;
}

int sweep_baseline_path(const char *dir, const char *label, char *out, size_t n) {
    int w = snprintf(out, n, "%s/sweep-%s.baseline.tsv", dir, label);
    return w < 0 || (size_t)w >= n ? -1 : 0;
}

int sweep_record_stem(const char *dir, const char *label, time_t start,
                      char *out, size_t n) {
    char st[32] = "";
    struct tm tmv, *tm = gmtime_r(&start, &tmv);
    if (tm) strftime(st, sizeof(st), "%Y%m%dT%H%M%SZ", tm);
    int w = snprintf(out, n, "%s/sweep-%s.%s", dir, label, st);
    return w < 0 || (size_t)w >= n ? -1 : 0;
}

void sweep_run_free(sweep_run_t *r) {
    if (!r) return;
    sweep_inv_free(r->inv);
    sweep_inv_free(r->base);
    r->inv = r->base = NULL;
}

/* ── the shared group ── */

int sweep_group_resolve(const char *name, sweep_group_t *g, char *err,
                        size_t errsz) {
    if (!g || !err || !errsz) return -1;
    memset(g, 0, sizeof(*g));
    if (!name || !name[0] || strlen(name) >= sizeof(g->name)) {
        snprintf(err, errsz, "--sweep-group: a group name or number, 1 to %d "
                 "bytes", SWEEP_GROUP_MAX - 1);
        return -1;
    }
    struct group gr, *res = NULL;
    char buf[4096];
    int rc = getgrnam_r(name, &gr, buf, sizeof(buf), &res);
    if (rc == 0 && !res) {
        /* A number names the group directly, as chgrp takes one. */
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul(name, &end, 10);
        if (!errno && end != name && !*end && name[0] >= '0' && name[0] <= '9' &&
            v < 0x7fffffffUL)
            rc = getgrgid_r((gid_t)v, &gr, buf, sizeof(buf), &res);
    }
    if (rc != 0 || !res) {
        snprintf(err, errsz, "--sweep-group %.64s: %s", name,
                 rc ? strerror(rc) : "no such group");
        return -1;
    }
    g->on = 1;
    g->gid = res->gr_gid;
    snprintf(g->name, sizeof(g->name), "%s", name);
    return 0;
}

/* The group rule over a directory's stat. 0, or -1 with `err`. */
static int group_dir_ok(const struct stat *st, const sweep_group_t *g,
                        const char *dir, char *err, size_t errsz) {
    unsigned mode = (unsigned)(st->st_mode & 07777);
    if (!S_ISDIR(st->st_mode)) {
        snprintf(err, errsz, "--sweep-dir %.200s: not a directory", dir);
        return -1;
    }
    if (st->st_uid != geteuid() && st->st_uid != 0) {
        snprintf(err, errsz, "--sweep-dir %.200s: owned by uid %lu, not this "
                 "account or root", dir, (unsigned long)st->st_uid);
        return -1;
    }
    if (st->st_gid != g->gid) {
        snprintf(err, errsz, "--sweep-dir %.200s: group %lu, not --sweep-group "
                 "%.64s (%lu)", dir, (unsigned long)st->st_gid, g->name,
                 (unsigned long)g->gid);
        return -1;
    }
    if (mode != 0770 && mode != 02770) {
        snprintf(err, errsz, "--sweep-dir %.200s: mode %04o, not 2770 or 0770 "
                 "(the group's, nothing for other)", dir, mode);
        return -1;
    }
    return 0;
}

int sweep_dir_check(const char *dir, const sweep_group_t *g, char *err,
                    size_t errsz) {
    if (!dir || !err || !errsz) return -1;
    struct stat st;
    if (!g || !g->on) {
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            snprintf(err, errsz, "--sweep-dir %.200s: not a directory", dir);
            return -1;
        }
        return 0;
    }
    /* By descriptor, O_NOFOLLOW: a symlink in the last component is
     * refused, not followed into some other directory. */
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* O_DIRECTORY with O_NOFOLLOW reports a symlink as ENOTDIR on
         * Linux, so the reason is read from lstat(). */
        int e = errno;
        struct stat ls;
        int is_link = lstat(dir, &ls) == 0 && S_ISLNK(ls.st_mode);
        snprintf(err, errsz, "--sweep-dir %.200s: %s", dir,
                 is_link ? "a symlink" : strerror(e));
        return -1;
    }
    int rc = fstat(fd, &st) != 0 ? -1 : group_dir_ok(&st, g, dir, err, errsz);
    if (rc != 0 && !err[0]) snprintf(err, errsz, "--sweep-dir %.200s: %s", dir,
                                     strerror(errno));
    close(fd);
    return rc;
}

/* The last component of a path this file built ("<dir>/<name>"). */
static const char *base_name(const char *path) {
    const char *sl = strrchr(path, '/');
    return sl ? sl + 1 : path;
}

/* A per-sweep output, created O_EXCL. Without a group: secure_file's
 * 0600. With one: 0640 and the group's, against the directory's
 * descriptor (checked again here: it is the one the files go into).
 * fchmod sets the mode the umask may have narrowed; it touches only the
 * file this call just created, never an operator path. NULL with `err`
 * filled; a half-made file is removed. */
static FILE *out_create(const sweep_run_t *r, const char *path, char *err,
                        size_t errsz) {
    if (!r->group.on) return sfile_fopen(AT_FDCWD, path, SFILE_EXCL, err, errsz);
    err[0] = '\0';
    int dfd = open(r->dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (dfd < 0 || fstat(dfd, &st) != 0 ||
        group_dir_ok(&st, &r->group, r->dir, err, errsz) != 0) {
        if (!err[0]) snprintf(err, errsz, "%.200s: %s", r->dir, strerror(errno));
        if (dfd >= 0) close(dfd);
        return NULL;
    }
    const char *name = base_name(path);
    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0640);
    if (fd < 0) {
        snprintf(err, errsz, "%.200s: %s", path, strerror(errno));
        close(dfd);
        return NULL;
    }
    if ((fstat(fd, &st) != 0) ||
        (st.st_gid != r->group.gid && fchown(fd, (uid_t)-1, r->group.gid) != 0) ||
        fchmod(fd, 0640) != 0) {
        snprintf(err, errsz, "%.150s: not given group %.32s, 0640 (is this "
                 "account in it?): %s", path, r->group.name, strerror(errno));
        close(fd);
        (void)unlinkat(dfd, name, 0);
        close(dfd);
        return NULL;
    }
    close(dfd);
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        snprintf(err, errsz, "%.200s: %s", path, strerror(errno));
        close(fd);
    }
    return f;
}

/* The baseline under the group rule: O_NOFOLLOW, a regular file with
 * one link and nothing for other, this account's or the group's. 0
 * with *f open, 1 when there is none, -1 with `err`. */
static int open_group_baseline(const char *path, const sweep_group_t *g,
                               FILE **f, char *err, size_t errsz) {
    *f = NULL;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 1;
        snprintf(err, errsz, "%.200s: the baseline cannot be read: %s", path,
                 errno == ELOOP ? "a symlink" : strerror(errno));
        return -1;
    }
    struct stat st;
    const char *why = NULL;
    if (fstat(fd, &st) != 0)                            why = strerror(errno);
    else if (!S_ISREG(st.st_mode))                      why = "not a regular file";
    else if (st.st_nlink != 1)                          why = "more than one link";
    else if (st.st_mode & 0007)                         why = "readable or writable by other";
    else if (st.st_uid != geteuid() && st.st_gid != g->gid)
        why = "neither this account's nor the group's";
    if (why) {
        snprintf(err, errsz, "%.200s: the baseline cannot be read: %s", path, why);
        close(fd);
        return -1;
    }
    *f = fdopen(fd, "r");
    if (!*f) {
        snprintf(err, errsz, "%.200s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    return 0;
}

/* The label's baseline at `path` into *out (allocated; NULL and 0 when
 * there is none). 0, or -1 with `err` filled. */
static int read_baseline(const char *path, const sweep_group_t *g,
                         sw_inv_t **out, int *version, char *err, size_t errsz) {
    *out = NULL;
    if (g && g->on) {
        FILE *f = NULL;
        int o = open_group_baseline(path, g, &f, err, errsz);
        if (o != 0) return o > 0 ? 0 : -1;
        sw_inv_t *b = sweep_inv_new();
        if (!b) { fclose(f); snprintf(err, errsz, "out of memory"); return -1; }
        int rc = wifi_snapshot_read_f(f, b, version);
        fclose(f);
        if (rc != 0) {
            snprintf(err, errsz, "%.200s: the baseline cannot be read", path);
            sweep_inv_free(b);
            return -1;
        }
        *out = b;
        return 0;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) return 0;
        snprintf(err, errsz, "%.200s: %s", path, strerror(errno));
        return -1;
    }
    sw_inv_t *b = sweep_inv_new();
    if (!b) { snprintf(err, errsz, "out of memory"); return -1; }
    if (!S_ISREG(st.st_mode) || wifi_snapshot_read(path, b, version) != 0) {
        snprintf(err, errsz, "%.200s: the baseline cannot be read", path);
        sweep_inv_free(b);
        return -1;
    }
    *out = b;
    return 0;
}

int sweep_baseline_check(const char *dir, const char *label,
                         const sweep_group_t *g, char *err, size_t errsz) {
    char path[SWEEP_PATH_MAX];
    if (!dir || !label || !err || !errsz) return -1;
    if (sweep_baseline_path(dir, label, path, sizeof(path)) != 0) {
        snprintf(err, errsz, "%.200s: path too long", dir);
        return -1;
    }
    sw_inv_t *b = NULL;
    int ver = 0;
    if (read_baseline(path, g, &b, &ver, err, errsz) != 0) return -1;
    int have = b != NULL;
    sweep_inv_free(b);
    return have;
}

int sweep_run_begin(sweep_run_t *r, const char *label, unsigned minutes,
                    const char *dir, const sweep_group_t *g,
                    const chanhop_t *full,
                    uint64_t now_ms, time_t wall, char *err, size_t errsz) {
    if (!r || !label || !dir || !err || !errsz) return -1;
    memset(r, 0, sizeof(*r));
    snprintf(r->label, sizeof(r->label), "%s", label);
    snprintf(r->dir, sizeof(r->dir), "%s", dir);
    if (g && g->on) r->group = *g;
    r->minutes = minutes;
    r->start = wall;
    r->start_ms = now_ms;
    if (sweep_baseline_path(dir, label, r->baseline, sizeof(r->baseline)) != 0) {
        snprintf(err, errsz, "%.200s: path too long", dir);
        return -1;
    }
    r->inv = sweep_inv_new();
    if (!r->inv) { snprintf(err, errsz, "out of memory"); return -1; }
    if (read_baseline(r->baseline, &r->group, &r->base, &r->base_version, err,
                      errsz) != 0) {
        sweep_run_free(r);
        return -1;
    }
    sweep_cov_init(&r->cov, full, now_ms);
    return 0;
}

int sweep_run_tick(sweep_run_t *r, const sloth_state_t *s,
                   const chanhop_t *h0, uint64_t now_ms) {
    if (!r || !r->inv || r->done) return r ? r->done : 0;
    if (s) sweep_inv_observe(r->inv, s);
    int all_done = h0 && h0->count > 0 && h0->sweep_done;
    if (h0) sweep_cov_sample(&r->cov, 0, h0, now_ms);
    for (int k = 1; k < MON_RADIO_MAX && k < SW_COV_RADIOS; k++) {
        const chanhop_t *h = mon_hop_sched(k);
        if (!h) continue;
        sweep_cov_sample(&r->cov, k, h, now_ms);
        if (!h->sweep_done) all_done = 0;
    }
    if (now_ms - r->start_ms >= (uint64_t)r->minutes * 60000u) {
        r->done = 1;
        r->end_why = SW_END_TIME;
    } else if (all_done) {
        r->done = 1;
        r->end_why = SW_END_PASS;
    }
    return r->done;
}

static int write_report(const sweep_run_t *r, const char *path,
                        const sw_report_t *rep, int json, FILE *msg) {
    char err[SFILE_ERR_MAX];
    FILE *f = out_create(r, path, err, sizeof(err));
    if (!f) {
        if (msg) fprintf(msg, "sloth: --sweep report not written: %s\n", err);
        return -1;
    }
    if (json) sweep_report_json(f, rep); else sweep_report_md(f, rep);
    if (sfile_fclose(f, path, err, sizeof(err)) != 0) {
        if (msg) fprintf(msg, "sloth: --sweep report %s\n", err);
        return -1;
    }
    if (msg) fprintf(msg, "sloth: sweep report -> %s\n", path);
    return 0;
}

int sweep_run_finish(sweep_run_t *r, const sloth_state_t *s, int stopped,
                     int ble_configured, time_t wall, FILE *msg) {
    if (!r || !r->inv) return -1;
    if (s) sweep_inv_observe(r->inv, s);
    if (stopped && !r->done) r->end_why = SW_END_STOPPED;
    int rc = 0;
    char stem[SWEEP_PATH_MAX], tsv[SWEEP_PATH_MAX + 8], md[SWEEP_PATH_MAX + 8],
         js[SWEEP_PATH_MAX + 8];
    if (sweep_record_stem(r->dir, r->label, r->start, stem, sizeof(stem)) != 0) {
        if (msg) fprintf(msg, "sloth: --sweep: %.200s: path too long\n", r->dir);
        sweep_run_free(r);
        return -1;
    }
    snprintf(tsv, sizeof(tsv), "%s.tsv", stem);
    snprintf(md, sizeof(md), "%s.md", stem);
    snprintf(js, sizeof(js), "%s.json", stem);

    /* The inventory first and O_EXCL: it is what an accept would make
     * the baseline, and one sweep never replaces another's. */
    const char *cand = NULL;
    {
        char err[SFILE_ERR_MAX];
        FILE *f = out_create(r, tsv, err, sizeof(err));
        if (!f) {
            if (msg) fprintf(msg, "sloth: --sweep inventory not written: %s\n", err);
            rc = -1;
        } else {
            wifi_snapshot_write_inv_f(f, r->inv, r->label, (long)wall);
            if (sfile_fclose(f, tsv, err, sizeof(err)) == 0) {
                cand = tsv;
                if (msg) fprintf(msg, "sloth: sweep inventory -> %s\n", tsv);
            } else {
                if (msg) fprintf(msg, "sloth: --sweep inventory: %s\n", err);
                rc = -1;
            }
        }
    }

    sw_cmp_t cmp;
    if (sweep_compare(r->inv, r->base, &cmp) != 0) {
        if (msg) fprintf(msg, "sloth: --sweep: out of memory for the report\n");
        sweep_run_free(r);
        return -1;
    }
    sw_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.label = r->label;
    rep.start = r->start;
    rep.end = wall;
    rep.minutes = r->minutes;
    rep.end_why = r->end_why;
    rep.cov = &r->cov;
    rep.cmp = &cmp;
    rep.inv = r->inv;
    rep.base_version = r->base ? r->base_version : 0;
    rep.baseline_path = r->baseline;
    rep.candidate_path = cand;
    rep.mon_up = s ? s->mon_health.running : 0;
    rep.ble_configured = ble_configured;
    rep.ble_up = s ? (s->bt_health.running || s->btcap.state == BT_CAP_STREAMING) : 0;
    if (write_report(r, md, &rep, 0, msg) != 0) rc = -1;
    if (write_report(r, js, &rep, 1, msg) != 0) rc = -1;
    sweep_report_emit(&rep);
    if (msg)
        fprintf(msg, "sloth: sweep %s: %d new, %d known, %d missing; %d of %d "
                "channels swept\n", r->label,
                cmp.count[0][SW_ST_NEW] + cmp.count[1][SW_ST_NEW] + cmp.count[2][SW_ST_NEW],
                cmp.count[0][SW_ST_KNOWN] + cmp.count[1][SW_ST_KNOWN] + cmp.count[2][SW_ST_KNOWN],
                cmp.count[0][SW_ST_MISSING] + cmp.count[1][SW_ST_MISSING] +
                    cmp.count[2][SW_ST_MISSING],
                sweep_cov_swept(&r->cov), r->cov.n);
    sweep_cmp_free(&cmp);
    sweep_run_free(r);
    return rc;
}
