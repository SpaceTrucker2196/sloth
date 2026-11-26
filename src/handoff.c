#include "handoff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cov_interval.h"
#include "intel_pack.h"
#include "interference.h"
#include "inventory.h"
#include "ownership.h"
#include "rule_coverage_live.h"
#include "secure_file.h"
#include "site_db.h"
#include "sloth.h"
#include "wifi_snapshot.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/* What became of each file, for README.txt and the caller's lines. */
#define HO_MAX_FILES 16
typedef struct {
    int      dirfd;
    int      failed;               /* a write failed: exit 2 */
    int      n;
    char     name[HO_MAX_FILES][32];
    char     note[HO_MAX_FILES][200];
    int      written[HO_MAX_FILES];
    char     err[SFILE_ERR_MAX];
} ho_t;

static void note(ho_t *h, const char *name, int written, const char *fmt, ...) {
    if (h->n >= HO_MAX_FILES) return;
    snprintf(h->name[h->n], sizeof(h->name[0]), "%s", name);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(h->note[h->n], sizeof(h->note[0]), fmt, ap);
    va_end(ap);
    h->written[h->n] = written;
    h->n++;
}

static FILE *ho_open(ho_t *h, const char *name) {
    FILE *f = sfile_fopen(h->dirfd, name, SFILE_EXCL, h->err, sizeof(h->err));
    if (!f) h->failed = 1;
    return f;
}

/* Close; 0, or -1 with the failure recorded. */
static int ho_close(ho_t *h, FILE *f, const char *name) {
    if (sfile_fclose(f, name, h->err, sizeof(h->err)) != 0) {
        h->failed = 1;
        return -1;
    }
    return 0;
}

static void mac_str(const uint8_t *m, char *out, size_t n) {
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

#ifdef WITH_SQLITE
static const char *sev_word(int s) {
    return s >= ALERT_SEV_CRIT ? "CRIT" : s == ALERT_SEV_WARN ? "WARN" : "INFO";
}

/* A kind's name from the stored integer; "type N" for one this build
 * does not know (a newer daemon's row, which the version check makes
 * rare but not impossible within one schema version). */
static void kind_of(int type, char *out, size_t n) {
    if (type >= 0 && type < ALERT_TYPE_COUNT)
        snprintf(out, n, "%s", cov_kind_name((alert_type_t)type));
    else
        snprintf(out, n, "type %d", type);
}
#endif /* WITH_SQLITE */

/* ── config.json ─────────────────────────────────────────────────── */

static void j(FILE *f, const char *s) { pf_json_str(f, s); }

static void df_pos_json(FILE *f, const df_pos_t *p) {
    if (p->form == DF_POS_LINE)
        fprintf(f, "{\"along_m\":%.2f}", p->a);
    else if (p->form == DF_POS_XY)
        fprintf(f, "{\"east_m\":%.2f,\"north_m\":%.2f}", p->a, p->b);
    else
        fprintf(f, "null");
}

static void write_config(ho_t *h, const handoff_cfg_t *c, const char *host,
                         const site_db_t *d, int db_ok) {
    FILE *f = ho_open(h, "config.json");
    if (!f) { note(h, "config.json", 0, "not written: %s", h->err); return; }
    char now[32];
    site_db_iso(c->now, now, sizeof(now));
    const pf_config_t *p = c->pf;
    fprintf(f, "{\"handoff\":{\"daemon\":\"sloth-wifi\",\"version\":");
    j(f, SLOTH_VERSION);
    fprintf(f, ",\"host\":");
    j(f, host);
    fprintf(f, ",\"written\":");
    j(f, now);
    fprintf(f, ",\"site_label\":");
    if (c->site_label) j(f, c->site_label); else fprintf(f, "null");
    fprintf(f, "},\"argv\":[");
    for (int i = 0; i < c->argc; i++) {
        if (i) fputc(',', f);
        j(f, c->argv[i]);
    }
    fprintf(f, "],\"radios\":{\"ip\":[");
    for (int i = 0; p && i < p->n_iface; i++) { if (i) fputc(',', f); j(f, p->iface[i]); }
    fprintf(f, "],\"monitor\":[");
    for (int i = 0; p && i < p->n_mon; i++) { if (i) fputc(',', f); j(f, p->mon[i]); }
    fprintf(f, "],\"monitor_only\":%s,\"df\":[", p && p->monitor_only ? "true" : "false");
    for (int i = 0; c->df && i < c->df->n; i++) {
        fprintf(f, "%s{\"iface\":", i ? "," : "");
        j(f, c->df->name[i]);
        fprintf(f, ",\"position\":");
        df_pos_json(f, &c->df->pos[i]);
        fputc('}', f);
    }
    fprintf(f, "]},\"hop\":{\"enabled\":%s,\"plan\":[", p && p->hop ? "true" : "false");
    for (int i = 0; p && i < p->n_hop; i++)
        fprintf(f, "%s{\"freq_mhz\":%d,\"band\":\"%s\"}", i ? "," : "",
                p->hop_mhz[i], cov_ivb_name(cov_ivb_of_mhz(p->hop_mhz[i])));
    fprintf(f, "]},\"positions\":{\"location\":");
    if (c->location) j(f, c->location); else fprintf(f, "null");
    fprintf(f, ",\"df_origin\":");
    if (c->df && c->df->origin_set) df_pos_json(f, &c->df->origin);
    else fprintf(f, "null");
    fprintf(f, "},\"designations\":{\"ssids\":%d,\"bssids\":%d,\"roster\":%d},",
            ownership_ssid_count(), ownership_bssid_count(), ownership_known_count());
    fprintf(f, "\"inventory\":");
    if (inventory_loaded()) {
        fprintf(f, "{\"version\":");
        j(f, inventory_version());
        fprintf(f, ",\"site\":");
        j(f, inventory_site());
        fprintf(f, ",\"hash\":");
        j(f, inventory_hash());
        fprintf(f, ",\"networks\":%d,\"bssids\":%d,\"path\":",
                inventory_network_count(), inventory_bssid_count());
        if (c->inventory) j(f, c->inventory); else fprintf(f, "null");
        fputc('}', f);
    } else {
        fprintf(f, "null");
    }
    fprintf(f, ",\"intel_pack\":{\"version\":");
    j(f, intel_pack_version());
    fprintf(f, ",\"hash\":");
    j(f, intel_pack_hash());
    fprintf(f, ",\"date\":");
    j(f, intel_pack_date());
    fprintf(f, "},\"database\":");
    if (c->db) {
        fprintf(f, "{\"path\":");
        j(f, c->db);
        if (db_ok) fprintf(f, ",\"schema\":%d,\"read_wal\":%s}", d->version,
                           d->wal ? "true" : "false");
        else fprintf(f, "}");
    } else {
        fprintf(f, "null");
    }
    fprintf(f, "}\n");
    if (ho_close(h, f, "config.json") == 0)
        note(h, "config.json", 1, "the command line, radios, hop plan,"
             " positions, designation counts, inventory identity, intel pack"
             " and database");
    else
        note(h, "config.json", 0, "write failed: %s", h->err);
}

/* ── preflight ───────────────────────────────────────────────────── */

static void write_preflight(ho_t *h, const handoff_cfg_t *c, pf_result_t *r) {
    static pf_facts_t facts;
    memset(&facts, 0, sizeof(facts));
    memset(r, 0, sizeof(*r));
    preflight_gather(c->pf, c->ops ? c->ops : preflight_default_ops(), &facts);
    pf_run_checks(c->pf, &facts, r);
    int code = pf_exit_code(r);
    FILE *f = ho_open(h, "preflight.txt");
    if (f) {
        pf_print_text(r, f);
        if (ho_close(h, f, "preflight.txt") == 0)
            note(h, "preflight.txt", 1, "--preflight for this command line,"
                 " exit %d; the rule status counts at its end", code);
        else
            note(h, "preflight.txt", 0, "write failed: %s", h->err);
    } else {
        note(h, "preflight.txt", 0, "not written: %s", h->err);
    }
    f = ho_open(h, "preflight.json");
    if (f) {
        pf_print_json(r, f);
        if (ho_close(h, f, "preflight.json") == 0)
            note(h, "preflight.json", 1, "the same as one JSON object (rules:"
                 " observable, partly, blind and each kind not observable)");
        else
            note(h, "preflight.json", 0, "write failed: %s", h->err);
    } else {
        note(h, "preflight.json", 0, "not written: %s", h->err);
    }
}

/* ── networks.tsv ────────────────────────────────────────────────── */

static void write_networks(ho_t *h, const handoff_cfg_t *c) {
    FILE *f = ho_open(h, "networks.tsv");
    if (!f) { note(h, "networks.tsv", 0, "not written: %s", h->err); return; }
    fprintf(f, "# sloth handoff: designated networks and the roster\n");
    fprintf(f, "# kind\tvalue\n");
    for (int i = 0; i < ownership_ssid_count(); i++) {
        char e[32 * 4 + 1];
        wifi_snapshot_escape(ownership_ssid_at(i), e, sizeof(e));
        fprintf(f, "my-ssid\t%s\n", e);
    }
    for (int i = 0; i < ownership_bssid_count(); i++) {
        char m[20];
        mac_str(ownership_bssid_at(i), m, sizeof(m));
        fprintf(f, "my-bssid\t%s\n", m);
    }
    for (int i = 0; i < ownership_known_count(); i++) {
        char m[20];
        mac_str(ownership_known_at(i), m, sizeof(m));
        fprintf(f, "known-mac\t%s\n", m);
    }
    if (inventory_loaded()) {
        char e[INV_SITE_LEN * 4 + 1], v[INV_VERSION_LEN * 4 + 1];
        wifi_snapshot_escape(inventory_site(), e, sizeof(e));
        wifi_snapshot_escape(inventory_version(), v, sizeof(v));
        fprintf(f, "inventory\thash=%s\tversion=%s\tsite=%s\tnetworks=%d\tbssids=%d\n",
                inventory_hash(), v, e, inventory_network_count(),
                inventory_bssid_count());
    }
    int n = ownership_ssid_count() + ownership_bssid_count() + ownership_known_count();
    if (ho_close(h, f, "networks.tsv") == 0)
        note(h, "networks.tsv", 1, "%d designation%s and roster entr%s%s", n,
             n == 1 ? "" : "s", n == 1 ? "y" : "ies",
             inventory_loaded()
             ? "; the inventory's identity (the --inventory file itself is"
               " not copied: hand it over beside this packet)"
             : (c->inventory ? "" : "; no --inventory"));
    else
        note(h, "networks.tsv", 0, "write failed: %s", h->err);
}

/* ── copies of sloth's own snapshot files ───────────────────────── */

/* Copy `src` into the packet as `name` when its first line is a
 * snapshot's. -1 with the reason in h->err; the file is then not
 * created. */
static int copy_snapshot(ho_t *h, const char *src, const char *name) {
    int fd = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        snprintf(h->err, sizeof(h->err), "%.200s: %s", src, strerror(errno));
        return -1;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size > HANDOFF_COPY_MAX) {
        snprintf(h->err, sizeof(h->err), "%.200s: not a regular file of at most"
                 " %ld bytes", src, HANDOFF_COPY_MAX);
        close(fd);
        return -1;
    }
    FILE *in = fdopen(fd, "r");
    if (!in) { close(fd); snprintf(h->err, sizeof(h->err), "%.200s: fdopen", src); return -1; }
    char line[1024];
    /* v2 (#249) adds client and BLE rows a v1 reader skips. */
    static const char magic[] = "# sloth-snapshot v";
    if (!fgets(line, sizeof(line), in) || strncmp(line, magic, sizeof(magic) - 1) != 0 ||
        (strcmp(line + sizeof(magic) - 1, "1\n") != 0 &&
         strcmp(line + sizeof(magic) - 1, "2\n") != 0)) {
        snprintf(h->err, sizeof(h->err), "%.200s: not a sloth snapshot (no \"%s1\""
                 " or \"%s2\" first line)", src, magic, magic);
        fclose(in);
        return -1;
    }
    FILE *out = ho_open(h, name);
    if (!out) { fclose(in); return -1; }
    fputs(line, out);
    size_t k;
    char buf[8192];
    while ((k = fread(buf, 1, sizeof(buf), in)) > 0)
        if (fwrite(buf, 1, k, out) != k) break;
    int rerr = ferror(in);
    fclose(in);
    if (ho_close(h, out, name) != 0) return -1;
    if (rerr) {
        snprintf(h->err, sizeof(h->err), "%.200s: read failed", src);
        h->failed = 1;
        return -1;
    }
    return 0;
}

#ifdef WITH_SQLITE

/* ── from sloth.db ───────────────────────────────────────────────── */

static void write_snapshot_db(ho_t *h, const handoff_cfg_t *c, const site_db_t *d) {
    long long newest = site_db_scalar(d, "SELECT MAX(last_seen) FROM beacon_aps", 0);
    long long total  = site_db_scalar(d, "SELECT COUNT(*) FROM beacon_aps", 0);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(d->h,
            "SELECT bssid, ssid, enc, channel, akm, mfp, vendor FROM beacon_aps"
            " WHERE last_seen >= ?1 ORDER BY last_seen DESC, bssid LIMIT ?2",
            -1, &st, NULL) != SQLITE_OK) {
        note(h, "snapshot.tsv", 0, "not written: %s", sqlite3_errmsg(d->h));
        return;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)(newest - HANDOFF_SNAPSHOT_WINDOW_S));
    sqlite3_bind_int(st, 2, MAX_BEACON_APS);
    long long in_window = 0;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(d->h, "SELECT COUNT(*) FROM beacon_aps WHERE last_seen >= ?1",
                               -1, &q, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(q, 1, (sqlite3_int64)(newest - HANDOFF_SNAPSHOT_WINDOW_S));
            if (sqlite3_step(q) == SQLITE_ROW) in_window = sqlite3_column_int64(q, 0);
        }
        sqlite3_finalize(q);
    }
    long long rows = in_window < MAX_BEACON_APS ? in_window : MAX_BEACON_APS;
    FILE *f = ho_open(h, "snapshot.tsv");
    if (!f) {
        sqlite3_finalize(st);
        note(h, "snapshot.tsv", 0, "not written: %s", h->err);
        return;
    }
    char lab[256];
    wifi_snapshot_escape(c->site_label, lab, sizeof(lab));
    fprintf(f, "# sloth-snapshot v1\n");
    fprintf(f, "# label\t%s\n", lab);
    fprintf(f, "# ts\t%lld\n", newest);
    fprintf(f, "# source\tsloth.db beacon_aps, heard within %d s of the newest\n",
            HANDOFF_SNAPSHOT_WINDOW_S);
    fprintf(f, "# count\t%lld\n", rows);
    fprintf(f, "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n");
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *ssid = (const char *)sqlite3_column_text(st, 1);
        wifi_snapshot_row(f, (const char *)sqlite3_column_text(st, 0),
                          ssid ? ssid : "",
                          (const char *)sqlite3_column_text(st, 2),
                          sqlite3_column_int(st, 3),
                          (const char *)sqlite3_column_text(st, 4),
                          sqlite3_column_int(st, 5),
                          (const char *)sqlite3_column_text(st, 6));
    }
    sqlite3_finalize(st);
    if (ho_close(h, f, "snapshot.tsv") == 0)
        note(h, "snapshot.tsv", 1, "%lld access point%s heard within a day of"
             " the newest (of %lld in sloth.db)%s; read it with --baseline-in",
             rows, rows == 1 ? "" : "s", total,
             in_window > rows ? "; the most recently heard, to the"
                                " --baseline-in reader's limit" : "");
    else
        note(h, "snapshot.tsv", 0, "write failed: %s", h->err);
}

/* The newest write in the file: an incident or a coverage interval. */
static long long file_newest(const site_db_t *d) {
    long long a = site_db_scalar(d, "SELECT MAX(last_seen) FROM alert_incidents", 0);
    long long b = site_db_has_table(d, "coverage_intervals")
                ? site_db_scalar(d, "SELECT MAX(last_seen) FROM coverage_intervals", 0)
                : 0;
    return a > b ? a : b;
}

static void write_open(ho_t *h, const site_db_t *d) {
    int has_q = d->version >= 19;
    sqlite3_stmt *st = NULL;
    /* alert_incidents.key is not selected: it is alerts.key, which
     * carries a credential's user name (see handoff.h, WITHHELD). */
    if (sqlite3_prepare_v2(d->h, has_q
            ? "SELECT type, sev, peak_sev, first_seen, last_seen, count,"
              " incident_id, complete, complete_why FROM alert_incidents"
              " WHERE closed_at IS NULL ORDER BY peak_sev DESC, first_seen"
            : "SELECT type, sev, peak_sev, first_seen, last_seen, count,"
              " incident_id, NULL, NULL FROM alert_incidents"
              " WHERE closed_at IS NULL ORDER BY peak_sev DESC, first_seen",
            -1, &st, NULL) != SQLITE_OK) {
        note(h, "findings_open.tsv", 0, "not written: %s", sqlite3_errmsg(d->h));
        return;
    }
    FILE *f = ho_open(h, "findings_open.tsv");
    if (!f) {
        sqlite3_finalize(st);
        note(h, "findings_open.tsv", 0, "not written: %s", h->err);
        return;
    }
    long long newest = file_newest(d);
    fprintf(f, "# sloth handoff: incidents with no close recorded in sloth.db\n");
    fprintf(f, "# state: open = evaluated within %d s of the file's newest"
            " write; unclosed = older, so the daemon stopped before it could"
            " close it\n", ALERT_RESOLVE_AFTER_S);
    fprintf(f, "# kind\tseverity\tpeak\tstate\topened\tlast_evaluated"
            "\tevaluations\tcomplete\tincident_id\n");
    int n = 0, open_n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char kind[64], fs[32], ls[32], comp[48];
        kind_of(sqlite3_column_int(st, 0), kind, sizeof(kind));
        long long last = sqlite3_column_int64(st, 4);
        site_db_iso((time_t)sqlite3_column_int64(st, 3), fs, sizeof(fs));
        site_db_iso((time_t)last, ls, sizeof(ls));
        int open = last >= newest - ALERT_RESOLVE_AFTER_S;
        const char *cq = (const char *)sqlite3_column_text(st, 7);
        const char *cw = (const char *)sqlite3_column_text(st, 8);
        snprintf(comp, sizeof(comp), "%s%s%s", cq ? cq : "-",
                 cw ? ":" : "", cw ? cw : "");
        const char *iid = (const char *)sqlite3_column_text(st, 6);
        fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\t%lld\t%s\t%s\n", kind,
                sev_word(sqlite3_column_int(st, 1)),
                sev_word(sqlite3_column_int(st, 2)),
                open ? "open" : "unclosed", fs, ls,
                (long long)sqlite3_column_int64(st, 5), comp, iid ? iid : "-");
        n++;
        open_n += open;
    }
    sqlite3_finalize(st);
    if (ho_close(h, f, "findings_open.tsv") == 0)
        note(h, "findings_open.tsv", 1, "%d incident%s with no close: %d open,"
             " %d unclosed", n, n == 1 ? "" : "s", open_n, n - open_n);
    else
        note(h, "findings_open.tsv", 0, "write failed: %s", h->err);
}

static void write_closed(ho_t *h, const site_db_t *d, time_t now) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(d->h,
            "SELECT type, COUNT(*), SUM(peak_sev >= 2), SUM(peak_sev = 1),"
            " SUM(peak_sev <= 0) FROM alert_incidents"
            " WHERE closed_at IS NOT NULL AND closed_at >= ?1 AND closed_at <= ?2"
            " GROUP BY type ORDER BY COUNT(*) DESC, type", -1, &st, NULL) != SQLITE_OK) {
        note(h, "findings_closed_30d.tsv", 0, "not written: %s", sqlite3_errmsg(d->h));
        return;
    }
    time_t from = now - (time_t)HANDOFF_CLOSED_DAYS * 86400;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)now);
    FILE *f = ho_open(h, "findings_closed_30d.tsv");
    if (!f) {
        sqlite3_finalize(st);
        note(h, "findings_closed_30d.tsv", 0, "not written: %s", h->err);
        return;
    }
    char fs[32], ts[32];
    site_db_iso(from, fs, sizeof(fs));
    site_db_iso(now, ts, sizeof(ts));
    fprintf(f, "# sloth handoff: incidents closed %s to %s, by kind and peak severity\n",
            fs, ts);
    fprintf(f, "# kind\tclosed\tcrit\twarn\tinfo\n");
    long long total = 0;
    int kinds = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char kind[64];
        kind_of(sqlite3_column_int(st, 0), kind, sizeof(kind));
        long long cnt = sqlite3_column_int64(st, 1);
        fprintf(f, "%s\t%lld\t%lld\t%lld\t%lld\n", kind, cnt,
                (long long)sqlite3_column_int64(st, 2),
                (long long)sqlite3_column_int64(st, 3),
                (long long)sqlite3_column_int64(st, 4));
        total += cnt;
        kinds++;
    }
    sqlite3_finalize(st);
    if (ho_close(h, f, "findings_closed_30d.tsv") == 0)
        note(h, "findings_closed_30d.tsv", 1, "%lld incident%s of %d kind%s closed"
             " in the last %d days", total, total == 1 ? "" : "s", kinds,
             kinds == 1 ? "" : "s", HANDOFF_CLOSED_DAYS);
    else
        note(h, "findings_closed_30d.tsv", 0, "write failed: %s", h->err);
}

static void write_interference(ho_t *h, const handoff_cfg_t *c, const site_db_t *d) {
    FILE *f = ho_open(h, "interference.md");
    if (!f) { note(h, "interference.md", 0, "not written: %s", h->err); return; }
    char err[256] = "";
    int n = interference_report(d, c->db, c->now - (time_t)HANDOFF_CLOSED_DAYS * 86400,
                                c->now, c->now, f, err, sizeof(err));
    if (ho_close(h, f, "interference.md") != 0)
        note(h, "interference.md", 0, "write failed: %s", h->err);
    else if (n < 0) {
        h->failed = 1;
        note(h, "interference.md", 0, "incomplete: %s", err);
    } else
        note(h, "interference.md", 1, "--interference-report for the last %d"
             " days: %d episode%s", HANDOFF_CLOSED_DAYS, n, n == 1 ? "" : "s");
}

#endif /* WITH_SQLITE */

static void write_false_positives(ho_t *h) {
    FILE *f = ho_open(h, "false_positives.txt");
    if (!f) { note(h, "false_positives.txt", 0, "not written: %s", h->err); return; }
    fprintf(f, "Known false-positive sources\n\n"
            "None listed. Triage notes (which findings an operator judged\n"
            "benign, and why) are kept by sloth-mesh, the dashboard, and not\n"
            "in sloth.db; sloth has nothing to put here. Export them from\n"
            "the dashboard to hand them over.\n");
    if (ho_close(h, f, "false_positives.txt") == 0)
        note(h, "false_positives.txt", 1, "empty: triage notes are sloth-mesh's");
    else
        note(h, "false_positives.txt", 0, "write failed: %s", h->err);
}

static void write_readme(ho_t *h, const handoff_cfg_t *c, const char *host,
                         const pf_result_t *r) {
    FILE *f = ho_open(h, "README.txt");
    if (!f) return;
    char now[32];
    site_db_iso(c->now, now, sizeof(now));
    fprintf(f, "sloth site handoff packet\n\n");
    fprintf(f, "Host:    %s\n", host);
    fprintf(f, "Written: %s by sloth %s (sloth --handoff)\n", now, SLOTH_VERSION);
    fprintf(f, "Site:    %s\n", c->site_label ? c->site_label : "-");
    fprintf(f, "DB:      %s\n", c->db ? c->db : "none named (--db)");
    if (r->assessed)
        fprintf(f, "Rules:   %d observable, %d partly, %d blind for this"
                " command line (preflight.txt)\n", r->observable, r->partly,
                r->blind);
    else
        fprintf(f, "Rules:   not assessed (a --replay command line)\n");
    fprintf(f, "\nWhat a site's next operator needs to run this sensor as it"
            " was run\n(FM 2-0 4-16). Every file is 0600 and local to this"
            " host; this is\nnot a fleet export.\n\nFiles\n\n");
    for (int i = 0; i < h->n; i++)
        fprintf(f, "  %-24s %s%s\n", h->name[i], h->written[i] ? "" : "[absent] ",
                h->note[i]);
    fprintf(f, "  %-24s this file\n", "README.txt");
    fprintf(f, "\nUsing it\n\n"
            "  The command line is config.json's argv. Run it with --preflight\n"
            "  first. To see what changed since this packet, add\n"
            "  --baseline-in snapshot.tsv (or baseline.tsv): the exit report\n"
            "  lists new, gone and changed access points.\n"
            "\nNot in this packet\n\n"
            "  Credential user names, RDP cookies, MQTT user names and EAP\n"
            "  identities: sloth.db holds some of them (alerts.key and\n"
            "  .detail, cleartext_creds.username, mqtt_flows.last_username,\n"
            "  rdp_flows.last_cookie, rogue_radius.last_identity), and no file\n"
            "  here does. A finding is listed by kind, severity, times and\n"
            "  incident id; its detail is in sloth.db and on the dashboard.\n"
            "  interference.md reads the key and detail of RF_DEGRADED,\n"
            "  RTS_FLOOD and GNSS_JAMMING alone, for the channel number, the\n"
            "  transmitter's address and the rule's figures, and copies\n"
            "  neither text.\n"
            "  The --inventory file is named, not copied.\n");
    ho_close(h, f, "README.txt");
}

int handoff_write(const handoff_cfg_t *c, FILE *msg) {
    site_db_t d;
    memset(&d, 0, sizeof(d));
    int db_ok = 0;
    char err[SFILE_ERR_MAX];
    if (c->db) {
        if (site_db_open(&d, c->db, err, sizeof(err)) != 0) {
            fprintf(msg, "sloth: --handoff: %s\n", err);
            return 2;
        }
        db_ok = 1;
    }
    ho_t *h = calloc(1, sizeof(*h));
    if (!h) { site_db_close(&d); return 2; }
    h->dirfd = sfile_private_dir(c->out_dir, err, sizeof(err));
    if (h->dirfd < 0) {
        fprintf(msg, "sloth: --handoff: %s\n", err);
        site_db_close(&d);
        free(h);
        return 2;
    }
    /* Empty, or refused: a packet never sits beside another's files. */
    {
        int dup_fd = dup(h->dirfd);
        DIR *dir = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
        int other = dir ? 0 : 1;
        struct dirent *e;
        while (dir && (e = readdir(dir)) != NULL)
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { other = 1; break; }
        if (dir) closedir(dir);
        else if (dup_fd >= 0) close(dup_fd);
        if (other) {
            fprintf(msg, "sloth: --handoff: %s is not empty: a packet is written"
                    " into a new or empty directory\n", c->out_dir);
            close(h->dirfd);
            site_db_close(&d);
            free(h);
            return 2;
        }
    }
    char host[256] = "";
    if (gethostname(host, sizeof(host) - 1) != 0 || !host[0])
        snprintf(host, sizeof(host), "unknown");

    static pf_result_t r;
    write_config(h, c, host, &d, db_ok);
    write_preflight(h, c, &r);
    write_networks(h, c);

    if (c->baseline_in) {
        if (copy_snapshot(h, c->baseline_in, "baseline.tsv") == 0)
            note(h, "baseline.tsv", 1, "the --baseline-in file %s", c->baseline_in);
        else
            note(h, "baseline.tsv", 0, "not copied: %s", h->err);
    } else {
        note(h, "baseline.tsv", 0, "no --baseline-in named");
    }
#ifdef WITH_SQLITE
    if (db_ok) {
        write_snapshot_db(h, c, &d);
        write_open(h, &d);
        write_closed(h, &d, c->now);
        write_interference(h, c, &d);
    }
#endif
    if (!db_ok) {
        if (c->snapshot_out && access(c->snapshot_out, F_OK) == 0) {
            if (copy_snapshot(h, c->snapshot_out, "snapshot.tsv") == 0)
                note(h, "snapshot.tsv", 1, "the --snapshot-out file %s (no --db)",
                     c->snapshot_out);
            else
                note(h, "snapshot.tsv", 0, "not copied: %s", h->err);
        } else {
            note(h, "snapshot.tsv", 0, "no --db, and no --snapshot-out file");
        }
#ifdef WITH_SQLITE
        const char *why = "no --db named";
#else
        const char *why = "built without SQLite";
#endif
        note(h, "findings_open.tsv", 0, "%s", why);
        note(h, "findings_closed_30d.tsv", 0, "%s", why);
        note(h, "interference.md", 0, "%s", why);
    }
    write_false_positives(h);
    write_readme(h, c, host, &r);
    site_db_close(&d);

    for (int i = 0; i < h->n; i++)
        fprintf(msg, "sloth: handoff %-24s %s%s\n", h->name[i],
                h->written[i] ? "" : "[absent] ", h->note[i]);
    int rc = h->failed ? 2 : 0;
    if (rc) fprintf(msg, "sloth: --handoff: incomplete: %s\n", h->err);
    else fprintf(msg, "sloth: handoff packet written to %s\n", c->out_dir);
    close(h->dirfd);
    free(h);
    return rc;
}
