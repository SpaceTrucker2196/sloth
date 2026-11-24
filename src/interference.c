#include "interference.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rule_coverage_live.h"
#include "secure_file.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "wifi_snapshot.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>

/* The three kinds, in the order the summary names them. */
static const alert_type_t KINDS[] = {
    ALERT_TYPE_RF_DEGRADED, ALERT_TYPE_RTS_FLOOD, ALERT_TYPE_GNSS_JAMMING
};
#define NKINDS ((int)(sizeof(KINDS) / sizeof(KINDS[0])))

static const char *sev_word(int s) {
    return s >= ALERT_SEV_CRIT ? "CRIT" : s == ALERT_SEV_WARN ? "WARN" : "INFO";
}

/* An SSID for Markdown: the snapshot file's lossless escape, and then
 * each byte Markdown would act on as \xHH, so a name heard on the air
 * cannot format the report. */
static void md_ssid(const char *in, char *out, size_t cap) {
    char esc[32 * 4 + 1];
    wifi_snapshot_escape(in ? in : "", esc, sizeof(esc));
    size_t o = 0;
    for (const char *p = esc; *p && o + 5 < cap; p++) {
        if (strchr("`|<>*_[]#!~&", *p)) {
            o += (size_t)snprintf(out + o, cap - o, "\\x%02x", (unsigned char)*p);
        } else {
            out[o++] = *p;
        }
    }
    out[o] = '\0';
}

/* coverage_interval figures over a window. */
typedef struct {
    int       rows;
    long long dur_ms;              /* the intervals' own lengths, summed */
    long long ctrl, frames_all;    /* every channel */
    long long ch_frames;           /* on the channel asked for */
    long long ch_ms[8];            /* per radio, on that channel */
    int       radios;              /* highest radio index seen + 1 */
    /* For an episode with no channel: the radios' time per channel. */
    int       nch;
    int       ch_no[32];
    long long ch_tot[32];
} cov_sum_t;

/* One "chans" array as the writer writes it (cov_iv_chans_json()). */
static void add_chans(cov_sum_t *c, const char *json, int channel) {
    for (const char *p = json ? strchr(json, '{') : NULL; p; p = strchr(p + 1, '{')) {
        int radio, ch, mhz;
        char band[16];
        unsigned long long ms, fr;
        if (sscanf(p, "{\"radio\":%d,\"ch\":%d,\"freq_mhz\":%d,\"band\":\"%15[^\"]\","
                   "\"ms\":%llu,\"frames\":%llu}",
                   &radio, &ch, &mhz, band, &ms, &fr) != 6)
            continue;
        if (radio >= 0 && radio < 8 && radio + 1 > c->radios) c->radios = radio + 1;
        if (channel > 0 && ch == channel) {
            c->ch_frames += (long long)fr;
            if (radio >= 0 && radio < 8) c->ch_ms[radio] += (long long)ms;
        }
        int k;
        for (k = 0; k < c->nch && c->ch_no[k] != ch; k++) {}
        if (k == c->nch && c->nch < 32) { c->ch_no[k] = ch; c->ch_tot[k] = 0; c->nch++; }
        if (k < c->nch) c->ch_tot[k] += (long long)ms;
    }
}

static int cov_window(const site_db_t *d, time_t a, time_t b, int channel,
                      cov_sum_t *c) {
    memset(c, 0, sizeof(*c));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(d->h,
            "SELECT dur_ms, f_ctrl, f_beacon + f_probe + f_auth + f_assoc +"
            " f_deauth + f_action + f_ctrl + f_data + f_eapol + f_other, chans"
            " FROM coverage_intervals WHERE last_seen >= ?1 AND start <= ?2"
            " ORDER BY start", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)a);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)b);
    while (sqlite3_step(st) == SQLITE_ROW) {
        c->rows++;
        c->dur_ms     += sqlite3_column_int64(st, 0);
        c->ctrl       += sqlite3_column_int64(st, 1);
        c->frames_all += sqlite3_column_int64(st, 2);
        add_chans(c, (const char *)sqlite3_column_text(st, 3), channel);
    }
    sqlite3_finalize(st);
    return 0;
}

static long long per_min(long long n, long long ms) {
    return ms > 0 ? (n * 60000 + ms / 2) / ms : 0;
}

static int pct(long long part, long long whole) {
    if (whole <= 0) return 0;
    long long v = (part * 100 + whole / 2) / whole;
    return v > 100 ? 100 : (int)v;
}

/* The finding's stored detail, when it is this incident's. */
static int detail_of(const site_db_t *d, const char *key, const char *iid,
                     char *out, size_t n) {
    sqlite3_stmt *st = NULL;
    int ok = 0;
    out[0] = '\0';
    if (sqlite3_prepare_v2(d->h, "SELECT detail FROM alerts WHERE key = ?1"
                           " AND incident_id = ?2 AND type IN (?3, ?4, ?5)"
                           " ORDER BY last_seen DESC LIMIT 1",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, iid, -1, SQLITE_STATIC);
        for (int k = 0; k < NKINDS; k++) sqlite3_bind_int(st, 3 + k, (int)KINDS[k]);
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
            snprintf(out, n, "%s", (const char *)sqlite3_column_text(st, 0));
            ok = 1;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* A detail is the rule's own text, but it names addresses and, for an
 * SSID-bearing kind, could carry on-air bytes: keep it on one line and
 * inert in Markdown. */
static void md_line(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 5 < cap; p++) {
        if (*p < 0x20 || *p == 0x7f || strchr("`|<>*_[]#!~&\\", *p))
            o += (size_t)snprintf(out + o, cap - o, "\\x%02x", *p);
        else
            out[o++] = (char)*p;
    }
    out[o] = '\0';
}

static void coverage_lines(FILE *out, const site_db_t *d, time_t f, time_t l,
                           int channel) {
    if (!site_db_has_table(d, "coverage_intervals")) {
        fprintf(out, "- Coverage: not in this file (coverage_intervals arrived"
                " with schema v18; this file is v%d).\n", d->version);
        return;
    }
    long long ep_s = (long long)(l - f) + 1;
    long long before_s = ep_s < IFR_BEFORE_MAX_S ? ep_s : IFR_BEFORE_MAX_S;
    cov_sum_t during, before;
    if (cov_window(d, f, l, channel, &during) != 0 ||
        cov_window(d, f - (time_t)before_s, f - 1, channel, &before) != 0) {
        fprintf(out, "- Coverage: could not be read: %s.\n", sqlite3_errmsg(d->h));
        return;
    }
    if (during.rows == 0) {
        fprintf(out, "- Coverage: no coverage interval overlaps the episode."
                " The radios' time in it is not known, and nothing below about"
                " frames heard applies to it.\n");
        return;
    }
    fprintf(out, "- Coverage: %d one-minute coverage interval%s overlap the"
            " episode (%lld s of radio time for each radio).\n",
            during.rows, during.rows == 1 ? "" : "s", during.dur_ms / 1000);
    if (channel > 0) {
        for (int r = 0; r < during.radios; r++)
            fprintf(out, "- Radio %d spent %d%% of that time on channel %d.\n",
                    r, pct(during.ch_ms[r], during.dur_ms), channel);
        if (during.radios == 0)
            fprintf(out, "- No radio time on any channel was recorded in those"
                    " intervals.\n");
        fprintf(out, "- Frames heard on channel %d per minute of radio time:"
                " %lld during", channel, per_min(during.ch_frames, during.dur_ms));
        if (before.rows)
            fprintf(out, ", %lld in the %lld s before.\n",
                    per_min(before.ch_frames, before.dur_ms), before_s);
        else
            fprintf(out, "; no coverage interval covers the %lld s before.\n",
                    before_s);
    } else if (during.nch > 0) {
        fprintf(out, "- The radios' time in the episode, by channel:");
        for (int k = 0; k < during.nch; k++)
            fprintf(out, "%s channel %d %d%%", k ? "," : "", during.ch_no[k],
                    pct(during.ch_tot[k], during.dur_ms));
        fprintf(out, ". The alert does not record the channel.\n");
    }
    fprintf(out, "- Control frames per minute, every channel heard: %lld during",
            per_min(during.ctrl, during.dur_ms));
    if (before.rows)
        fprintf(out, ", %lld before.\n", per_min(before.ctrl, before.dur_ms));
    else
        fprintf(out, "; before not covered.\n");
}

static void aps_lines(FILE *out, const site_db_t *d, time_t f, time_t l,
                      int channel) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(d->h,
            "SELECT b.bssid, b.ssid, b.has_qbss, b.qbss_chan_util,"
            " (SELECT COUNT(*) FROM assocs s WHERE s.bssid = b.bssid"
            "   AND s.first_seen <= ?3 AND s.last_seen >= ?2)"
            " FROM beacon_aps b WHERE b.channel = ?1"
            " AND b.first_seen <= ?3 AND b.last_seen >= ?2"
            " ORDER BY b.bssid", -1, &st, NULL) != SQLITE_OK) {
        fprintf(out, "- Access points: could not be read: %s.\n", sqlite3_errmsg(d->h));
        return;
    }
    sqlite3_bind_int(st, 1, channel);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)f);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)l);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == 0)
            fprintf(out, "- Access points on channel %d whose sightings span the"
                    " episode (clients: associations seen in it; QBSS load: the"
                    " AP's latest, 0-255, not its value then):\n", channel);
        n++;
        if (n > IFR_MAX_APS) continue;
        char ss[32 * 4 * 4 + 1];
        md_ssid((const char *)sqlite3_column_text(st, 1), ss, sizeof(ss));
        fprintf(out, "  - %s \"%s\", %d client%s",
                sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "-",
                ss, sqlite3_column_int(st, 4),
                sqlite3_column_int(st, 4) == 1 ? "" : "s");
        if (sqlite3_column_int(st, 2) && sqlite3_column_type(st, 3) != SQLITE_NULL)
            fprintf(out, ", QBSS load %d\n", sqlite3_column_int(st, 3));
        else
            fprintf(out, ", no QBSS load advertised\n");
    }
    sqlite3_finalize(st);
    if (n == 0)
        fprintf(out, "- Access points: none recorded on channel %d over the"
                " episode.\n", channel);
    else if (n > IFR_MAX_APS)
        fprintf(out, "  - and %d more\n", n - IFR_MAX_APS);
}

static void one_episode(FILE *out, const site_db_t *d, int idx,
                        sqlite3_stmt *ep) {
    const char *key = (const char *)sqlite3_column_text(ep, 0);
    const char *iid = (const char *)sqlite3_column_text(ep, 1);
    int type        = sqlite3_column_int(ep, 2);
    time_t f        = (time_t)sqlite3_column_int64(ep, 3);
    time_t l        = (time_t)sqlite3_column_int64(ep, 4);
    int sev         = sqlite3_column_int(ep, 5);
    int peak        = sqlite3_column_int(ep, 6);
    long long cnt   = sqlite3_column_int64(ep, 7);
    long long obs   = sqlite3_column_int64(ep, 8);
    int closed      = sqlite3_column_type(ep, 9) != SQLITE_NULL;
    time_t c        = (time_t)sqlite3_column_int64(ep, 9);
    const char *why = (const char *)sqlite3_column_text(ep, 10);
    if (!key) key = "";
    if (!iid) iid = "";

    int channel = 0;
    char tx[20] = "";
    if (type == ALERT_TYPE_RF_DEGRADED) {
        if (sscanf(key, "rfdegraded:%d", &channel) != 1) channel = 0;
    } else if (type == ALERT_TYPE_RTS_FLOOD) {
        if (sscanf(key, "rtsflood:%17[0-9a-fA-F:]", tx) != 1) tx[0] = '\0';
    }

    char fs[32], ls[32], cs[32];
    site_db_iso(f, fs, sizeof(fs));
    site_db_iso(l, ls, sizeof(ls));
    site_db_iso(c, cs, sizeof(cs));
    fprintf(out, "\n## %d. %s", idx, cov_kind_name((alert_type_t)type));
    if (channel) fprintf(out, " on channel %d", channel);
    if (tx[0])   fprintf(out, " from %s", tx);
    fprintf(out, ", %s\n\n", fs);

    fprintf(out, "- Opened %s; last evaluated %s (%lld s).\n", fs, ls,
            (long long)(l - f));
    if (closed)
        fprintf(out, "- Closed %s (%s).\n", cs, why ? why : "no reason recorded");
    else
        fprintf(out, "- No close recorded in this file: the episode was open"
                " when last written.\n");
    fprintf(out, "- Severity %s, peak %s; %lld evaluation%s, %lld evidence"
            " change%s.\n", sev_word(sev), sev_word(peak), cnt,
            cnt == 1 ? "" : "s", obs, obs == 1 ? "" : "s");

    char det[ALERT_DETAIL_LEN + 64], md[(ALERT_DETAIL_LEN + 64) * 4];
    if (detail_of(d, key, iid, det, sizeof(det))) {
        md_line(det, md, sizeof(md));
        fprintf(out, "- Figures the rule recorded at its last evaluation: %s\n", md);
        int ch, retry, fcs;
        unsigned frames;
        if (type == ALERT_TYPE_RF_DEGRADED &&
            sscanf(det, "ch %d: %d%% retries, %d%% bad-FCS over %u frames",
                   &ch, &retry, &fcs, &frames) == 4)
            fprintf(out, "- Retry ratio %d%% and bad-FCS share %d%% over %u"
                    " data frames.\n", retry, fcs, frames);
        int n, dur, nav;
        if (type == ALERT_TYPE_RTS_FLOOD &&
            sscanf(det, "%*17s sent %d RTS over %ds (~%*d/s), max NAV %dus",
                   &n, &dur, &nav) == 3)
            fprintf(out, "- Control-frame volume: %d RTS frames over %d s from"
                    " one transmitter, longest NAV %d us.\n", n, dur, nav);
    } else {
        fprintf(out, "- Figures: not stored for this episode (sloth.db keeps"
                " the figures of a finding's latest episode only).\n");
    }

    if (type == ALERT_TYPE_GNSS_JAMMING) {
        fprintf(out, "- Coverage: the coverage intervals describe the Wi-Fi"
                " radios; the GNSS receiver's own record is gnss_fixes.\n");
    } else {
        coverage_lines(out, d, f, l, channel);
        fprintf(out, "- Channel utilisation: not stored as a history (sloth.db"
                " keeps each access point's latest QBSS load only).\n");
        if (channel) {
            aps_lines(out, d, f, l, channel);
        } else if (tx[0]) {
            fprintf(out, "- Affected access points and clients: not stored (the"
                    " alert records the transmitter, not the channel or the"
                    " stations whose medium it reserved).\n");
        }
    }
    fprintf(out, "- Location: not located. One sensor measures what reaches"
            " it; an estimate needs several sensors (sloth-mesh#19).\n");
}

int interference_report(const site_db_t *d, const char *db_path,
                        time_t from, time_t to, time_t now, FILE *out,
                        char *err, size_t errsz) {
    time_t a = from > 0 ? from : 0;
    time_t b = to > 0 ? to : (time_t)INT64_MAX / 2;
    char ns[32], fs[32], ts[32];
    site_db_iso(now, ns, sizeof(ns));
    site_db_iso(from, fs, sizeof(fs));
    site_db_iso(to, ts, sizeof(ts));
    char host[256] = "";
    if (gethostname(host, sizeof(host) - 1) != 0 || !host[0])
        snprintf(host, sizeof(host), "unknown");

    fprintf(out, "# Interference report\n\n");
    fprintf(out, "- Sensor: %s, sloth %s\n", host, SLOTH_VERSION);
    fprintf(out, "- Database: %s (schema v%d%s)\n", db_path ? db_path : "-",
            d->version, d->wal ? ", read with its -wal" : "");
    fprintf(out, "- Window: %s to %s\n", from > 0 ? fs : "the file's start",
            to > 0 ? ts : "the file's end");
    fprintf(out, "- Written: %s\n\n", ns);
    fprintf(out, "Each figure below is a measurement of what this sensor's"
            " receivers took in. None of them says why. A sustained retry"
            " ratio is what a jammer, a microwave oven, a hidden node and a"
            " client at the edge of range all produce, and a GNSS receiver"
            " cannot tell interference from jamming. The sections state what"
            " was received and when, for whoever can look at the source.\n\n");

    int counts[NKINDS] = { 0 };
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(d->h,
            "SELECT type, COUNT(*) FROM alert_incidents WHERE type IN (?1,?2,?3)"
            " AND last_seen >= ?4 AND first_seen <= ?5 GROUP BY type",
            -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "%s", sqlite3_errmsg(d->h));
        return -1;
    }
    for (int k = 0; k < NKINDS; k++) sqlite3_bind_int(st, 1 + k, (int)KINDS[k]);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)a);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)b);
    while (sqlite3_step(st) == SQLITE_ROW)
        for (int k = 0; k < NKINDS; k++)
            if (sqlite3_column_int(st, 0) == (int)KINDS[k])
                counts[k] = sqlite3_column_int(st, 1);
    sqlite3_finalize(st);

    fprintf(out, "Episodes: RF_DEGRADED %d, RTS_FLOOD %d, GNSS_JAMMING %d.\n\n",
            counts[0], counts[1], counts[2]);
    long long gnss = site_db_has_table(d, "gnss_fixes")
                   ? site_db_scalar(d, "SELECT COUNT(*) FROM gnss_fixes", 0) : 0;
    long long wifi = site_db_scalar(d, "SELECT COUNT(*) FROM beacon_aps", 0) +
                     (site_db_has_table(d, "coverage_intervals")
                      ? site_db_scalar(d, "SELECT COUNT(*) FROM coverage_intervals", 0) : 0);
    fprintf(out, "RF_DEGRADED and RTS_FLOOD are sloth-wifi's alerts and"
            " GNSS_JAMMING is sloth-rf's. Wi-Fi rows in this file: %s; GNSS"
            " rows: %s; so %s.\n",
            wifi ? "yes" : "none", gnss ? "yes" : "none",
            gnss && wifi ? "both daemons wrote to it"
            : gnss ? "only sloth-rf wrote to it"
            : wifi ? "only sloth-wifi wrote to it: GNSS jamming is not reported"
                     " here unless sloth-rf writes to the same file"
                     " (sloth-rf --db the same path)"
            : "neither daemon has written observations to it yet");

    if (sqlite3_prepare_v2(d->h,
            "SELECT key, incident_id, type, first_seen, last_seen, sev, peak_sev,"
            " count, observations, closed_at, reason FROM alert_incidents"
            " WHERE type IN (?1,?2,?3) AND last_seen >= ?4 AND first_seen <= ?5"
            " ORDER BY first_seen, key", -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "%s", sqlite3_errmsg(d->h));
        return -1;
    }
    for (int k = 0; k < NKINDS; k++) sqlite3_bind_int(st, 1 + k, (int)KINDS[k]);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)a);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)b);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW)
        one_episode(out, d, ++n, st);
    sqlite3_finalize(st);
    if (n == 0)
        fprintf(out, "\nNo episode of the three kinds overlaps the window.\n");
    return n;
}

#else /* !WITH_SQLITE */

int interference_report(const site_db_t *d, const char *db_path,
                        time_t from, time_t to, time_t now, FILE *out,
                        char *err, size_t errsz) {
    (void)d; (void)db_path; (void)from; (void)to; (void)now; (void)out;
    snprintf(err, errsz, "built without SQLite");
    return -1;
}

#endif /* WITH_SQLITE */

int interference_main(const char *db, const char *out_path, time_t from,
                      time_t to, FILE *msg) {
    char err[SFILE_ERR_MAX];
    site_db_t d;
    if (site_db_open(&d, db, err, sizeof(err)) != 0) {
        fprintf(msg, "sloth: --interference-report: %s\n", err);
        return 2;
    }
    FILE *out = stdout;
    int to_stdout = !strcmp(out_path, "-");
    if (!to_stdout) {
        out = sfile_fopen(AT_FDCWD, out_path, SFILE_TRUNC, err, sizeof(err));
        if (!out) {
            fprintf(msg, "sloth: --interference-report: %s\n", err);
            site_db_close(&d);
            return 2;
        }
    }
    int n = interference_report(&d, db, from, to, sloth_wall(), out, err,
                                sizeof(err));
    site_db_close(&d);
    int bad = n < 0;
    char cerr[SFILE_ERR_MAX];
    if (to_stdout ? fflush(out) != 0
                  : sfile_fclose(out, out_path, cerr, sizeof(cerr)) != 0) {
        if (!bad) snprintf(err, sizeof(err), "%s",
                           to_stdout ? "write to stdout failed" : cerr);
        bad = 1;
    }
    if (bad) {
        fprintf(msg, "sloth: --interference-report: %s\n", err);
        return 2;
    }
    if (!to_stdout)
        fprintf(msg, "sloth: interference report %s: %d episode%s\n", out_path,
                n, n == 1 ? "" : "s");
    return 0;
}
