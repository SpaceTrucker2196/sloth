#include "sweep_run.h"
#include "wifi_snapshot.h"
#include "secure_file.h"
#include "mon_radios.h"
#include <errno.h>
#include <fcntl.h>
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

/* The label's baseline at `path` into *out (allocated; NULL and 0 when
 * there is none). 0, or -1 with `err` filled. */
static int read_baseline(const char *path, sw_inv_t **out, int *version,
                         char *err, size_t errsz) {
    *out = NULL;
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

int sweep_baseline_check(const char *dir, const char *label, char *err,
                         size_t errsz) {
    char path[SWEEP_PATH_MAX];
    if (!dir || !label || !err || !errsz) return -1;
    if (sweep_baseline_path(dir, label, path, sizeof(path)) != 0) {
        snprintf(err, errsz, "%.200s: path too long", dir);
        return -1;
    }
    sw_inv_t *b = NULL;
    int ver = 0;
    if (read_baseline(path, &b, &ver, err, errsz) != 0) return -1;
    int have = b != NULL;
    sweep_inv_free(b);
    return have;
}

int sweep_run_begin(sweep_run_t *r, const char *label, unsigned minutes,
                    const char *dir, const chanhop_t *full,
                    uint64_t now_ms, time_t wall, char *err, size_t errsz) {
    if (!r || !label || !dir || !err || !errsz) return -1;
    memset(r, 0, sizeof(*r));
    snprintf(r->label, sizeof(r->label), "%s", label);
    snprintf(r->dir, sizeof(r->dir), "%s", dir);
    r->minutes = minutes;
    r->start = wall;
    r->start_ms = now_ms;
    if (sweep_baseline_path(dir, label, r->baseline, sizeof(r->baseline)) != 0) {
        snprintf(err, errsz, "%.200s: path too long", dir);
        return -1;
    }
    r->inv = sweep_inv_new();
    if (!r->inv) { snprintf(err, errsz, "out of memory"); return -1; }
    if (read_baseline(r->baseline, &r->base, &r->base_version, err, errsz) != 0) {
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

static int write_report(const char *path, const sw_report_t *rep, int json,
                        FILE *msg) {
    char err[SFILE_ERR_MAX];
    FILE *f = sfile_fopen(AT_FDCWD, path, SFILE_EXCL, err, sizeof(err));
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
        int fd = sfile_open(AT_FDCWD, tsv, SFILE_EXCL, err, sizeof(err));
        if (fd < 0) {
            if (msg) fprintf(msg, "sloth: --sweep inventory not written: %s\n", err);
            rc = -1;
        } else {
            close(fd);
            if (wifi_snapshot_write_inv(r->inv, tsv, r->label, (long)wall) == 0) {
                cand = tsv;
                if (msg) fprintf(msg, "sloth: sweep inventory -> %s\n", tsv);
            } else {
                if (msg) fprintf(msg, "sloth: --sweep inventory: %s\n",
                                 wifi_snapshot_error());
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
    if (write_report(md, &rep, 0, msg) != 0) rc = -1;
    if (write_report(js, &rep, 1, msg) != 0) rc = -1;
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
