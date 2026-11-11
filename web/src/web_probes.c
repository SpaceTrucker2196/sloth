#include "web_probes.h"

#include <math.h>
#include <stdlib.h>

#include "web_metrics.h"
#include "web_probeq.h"
#include "web_series.h"

int web_probe_u(long long n) {
    long long u = n / WEB_PROBE_U_SHARE;
    return u < WEB_PROBE_U_MIN ? WEB_PROBE_U_MIN
         : u > WEB_PROBE_U_MAX ? WEB_PROBE_U_MAX : (int)u;
}

double web_probe_weight(long long n, long long df) {
    if (n < 1 || df < 1 || df >= n) return 0;
    return log((double)n / (double)df);
}

#ifdef WITH_SQLITE

/* days (0 everything, 1..WEB_PROBE_DAYS_MAX) into *days and the first
 * second of the window into *since. */
static int days_of(const web_param_t *p, long long now_s, long long *days,
                   long long *since) {
    *days = WEB_PROBE_DAYS;
    if (p->seen && decimal(p->val, 0, WEB_PROBE_DAYS_MAX, days) != 0) return -1;
    *since = *days ? now_s - *days * 86400 : 0;
    return 0;
}


/* ── /api/probes/clients ─────────────────────────────────────────────── */

typedef struct {
    char      mac[WEB_KEY_MAX + 1];
    char      os[WEB_SDB_TEXT_MAX + 1], phy[WEB_SDB_TEXT_MAX + 1];
    long long frames, directed, signal, channel, first_seen, last_seen, nss;
    int       has_p, has_n, has_signal;
    struct { char mac[WEB_KEY_MAX + 1]; long long gap, dt_ms, frames, first_seen, last_seen; }
              sib[WEB_PROBE_SIBLINGS];
    int       nsib;
} pc_t;

/* One row at its largest: WEB_PROBE_ROW_SSIDS SSIDs in the display
 * form, the siblings, the fixed members. */
#define PC_ROW_MAX (WEB_PROBE_ROW_SSIDS * (WEB_SSID_JSON_MAX(WEB_SDB_TEXT_MAX) + 96) + 1600)

/* Every station of either table in the window, once: the two tables'
 * rows side by side, grouped by MAC, so one pass orders them and counts
 * them (the statement has no LIMIT: the page is cut here, and the rows
 * past it only counted). */
#define CLIENT_SET \
    "(SELECT mac, last_seen AS pl, 0 AS nl, first_seen AS f, frame_count AS fc," \
    " signal_dbm AS sg FROM probe_clients WHERE last_seen >= ?1" \
    " UNION ALL SELECT mac, 0, last_seen, first_seen, 0, NULL FROM pnl_clients" \
    " WHERE last_seen >= ?1) m"

int web_probes_clients_route(const web_m4_t *m, const char *query, long long now_s,
                             char *body, size_t cap, size_t *len, int *status) {
    if (no_db(m)) return NO_DB_ANSWER();
    web_param_t ps[4] = { { "days", "", 0 }, { "sort", "", 0 }, { "limit", "", 0 },
                          { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days, since, limit = WEB_PROBE_LIMIT, offset = 0;
    if (days_of(&ps[0], now_s, &days, &since) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    /* Each order is a constant of this file: the word picks one, and is
     * never part of the statement. */
    static const struct { const char *word, *order; } SORT[] = {
        { "last", "max(max(m.pl), max(m.nl)) DESC, m.mac" },
        { "first", "min(m.f), m.mac" },
        { "ssids", "(SELECT count(*) FROM pnl_ssids s WHERE s.mac = m.mac AND s.ssid <> '')"
                   " DESC, m.mac" },
        { "frames", "max(m.fc) DESC, m.mac" },
        { "signal", "max(m.sg) IS NULL, max(m.sg) DESC, m.mac" },
        { "mac", "m.mac" },
    };
    int sort = 0;
    if (ps[1].seen) {
        sort = -1;
        for (size_t i = 0; i < sizeof(SORT) / sizeof(SORT[0]); i++)
            if (!strcmp(ps[1].val, SORT[i].word)) sort = (int)i;
        if (sort < 0) return answer_error(400, "bad_sort", NULL, body, cap, len, status);
    }
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_PROBE_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, 0, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

    web_sdb_conn_t conn;
    if (open_db(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT m.mac FROM " CLIENT_SET " GROUP BY m.mac ORDER BY %s",
             SORT[sort].order);
    sqlite3_stmt *st = prep(&conn, sql);
    pc_t *rows = calloc((size_t)limit, sizeof(*rows));
    if (!st || !rows) {
        sqlite3_finalize(st);
        free(rows);
        if (!st) return db_failed(&conn, body, cap, len, status);
        web_slothdb_close(&conn);
        return -1;
    }
    sqlite3_bind_int64(st, 1, since);
    int nr = 0, rc;
    long long total = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (total >= offset && nr < limit) {
            if (!cmac(st, 0, rows[nr].mac)) continue;
            nr++;
        }
        total++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        free(rows);
        return db_failed(&conn, body, cap, len, status);
    }
    int show = nr;
    /* Each shown row's own two records and its count of names. */
    sqlite3_stmt *sp = prep(&conn, "SELECT frame_count, signal_dbm, COALESCE(channel,0),"
                                   " first_seen, last_seen FROM probe_clients WHERE mac = ?1");
    sqlite3_stmt *sn = prep(&conn, "SELECT probe_count, COALESCE(os_fp,''), COALESCE(phy,''),"
                                   " first_seen, last_seen FROM pnl_clients WHERE mac = ?1");
    sqlite3_stmt *sc = prep(&conn, "SELECT count(*) FROM pnl_ssids WHERE mac = ?1 AND"
                                   " ssid <> ''");
    for (int i = 0; i < show; i++) {
        pc_t *r = &rows[i];
        long long pf = 0, pl = 0, nf = 0, nl = 0;
        if (sp) {
            sqlite3_reset(sp);
            bind_t(sp, 1, r->mac);
            if (sqlite3_step(sp) == SQLITE_ROW) {
                r->has_p = 1;
                r->frames = sqlite3_column_int64(sp, 0);
                r->has_signal = sqlite3_column_type(sp, 1) != SQLITE_NULL;
                r->signal = sqlite3_column_int64(sp, 1);
                r->channel = sqlite3_column_int64(sp, 2);
                pf = sqlite3_column_int64(sp, 3);
                pl = sqlite3_column_int64(sp, 4);
            }
        }
        if (sn) {
            sqlite3_reset(sn);
            bind_t(sn, 1, r->mac);
            if (sqlite3_step(sn) == SQLITE_ROW) {
                r->has_n = 1;
                r->directed = sqlite3_column_int64(sn, 0);
                ctext(sn, 1, r->os, WEB_SDB_TEXT_MAX);
                ctext(sn, 2, r->phy, WEB_SDB_TEXT_MAX);
                nf = sqlite3_column_int64(sn, 3);
                nl = sqlite3_column_int64(sn, 4);
            }
        }
        if (sc) {
            sqlite3_reset(sc);
            bind_t(sc, 1, r->mac);
            if (sqlite3_step(sc) == SQLITE_ROW) r->nss = sqlite3_column_int64(sc, 0);
        }
        r->first_seen = r->has_p && r->has_n ? (pf < nf ? pf : nf) : r->has_p ? pf : nf;
        r->last_seen = pl > nl ? pl : nl;
    }
    sqlite3_finalize(sp);
    sqlite3_finalize(sn);
    sqlite3_finalize(sc);

    /* sloth's sequence-number correlations naming a row's MAC, in one
     * pass over the table, newest first, at most WEB_PROBE_SEQ_READ rows
     * of it ("seq_read" false past that). */
    int seq_whole = 1;
    st = prep(&conn, "SELECT mac_a, mac_b, gap, dt_ms, a_count + b_count, first_seen,"
                     " last_seen FROM seqnum_correlations ORDER BY last_seen DESC");
    if (st) {
        int read = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (read++ >= WEB_PROBE_SEQ_READ) { seq_whole = 0; break; }
            char a[WEB_KEY_MAX + 1], b[WEB_KEY_MAX + 1];
            if (!cmac(st, 0, a) || !cmac(st, 1, b)) continue;
            for (int i = 0; i < show; i++) {
                const char *other = !strcmp(rows[i].mac, a) ? b
                                  : !strcmp(rows[i].mac, b) ? a : NULL;
                if (!other) continue;
                pc_t *r = &rows[i];
                if (r->nsib < WEB_PROBE_SIBLINGS) {
                    snprintf(r->sib[r->nsib].mac, sizeof(r->sib[0].mac), "%s", other);
                    r->sib[r->nsib].gap = sqlite3_column_int64(st, 2);
                    r->sib[r->nsib].dt_ms = sqlite3_column_int64(st, 3);
                    r->sib[r->nsib].frames = sqlite3_column_int64(st, 4);
                    r->sib[r->nsib].first_seen = sqlite3_column_int64(st, 5);
                    r->sib[r->nsib].last_seen = sqlite3_column_int64(st, 6);
                }
                r->nsib++;
            }
        }
        sqlite3_finalize(st);
    }
    if (conn.timed_out) { free(rows); return db_failed(&conn, body, cap, len, status); }

    char (*macs)[WEB_KEY_MAX + 1] = calloc((size_t)(show ? show : 1), sizeof(*macs));
    unsigned char *bits = calloc((size_t)(show ? show : 1), WEB_DEV_CELLS / 8);
    if (!macs || !bits) {
        free(macs); free(bits); free(rows);
        web_slothdb_close(&conn);
        return -1;
    }
    for (int i = 0; i < show; i++) snprintf(macs[i], sizeof(macs[i]), "%s", rows[i].mac);
    web_dev_strips(m, (const char (*)[WEB_KEY_MAX + 1])macs, show, now_s, bits);
    free(macs);

    /* A wildcard probe names no SSID and has no pnl_ssids row; the
     * empty string is refused here too, so a row something else wrote
     * is never listed as a network. */
    sqlite3_stmt *ss = prep(&conn, "SELECT ssid, first_seen, last_seen FROM pnl_ssids"
                                   " WHERE mac = ?1 AND ssid <> '' ORDER BY last_seen DESC,"
                                   " ssid LIMIT ?2");
    sqlite3_stmt *dv = prep(&conn, "SELECT 1 FROM devices WHERE mac = ?1");
    sqlite3_stmt *as = prep(&conn, "SELECT bssid, COALESCE(ssid,''), last_seen FROM assocs"
                                   " WHERE sta_mac = ?1 ORDER BY last_seen DESC, bssid LIMIT 1");
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");      web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":");     web_jw_int(&w, days);
    web_jw_raw(&w, ",\"sort\":");     web_jw_str(&w, SORT[sort].word);
    web_jw_raw(&w, ",\"limit\":");    web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":");   web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"presence_from\":"); web_jw_int(&w, web_dev_strip_from(now_s));
    web_jw_raw(&w, ",\"seq_read\":"); jw_bool(&w, seq_whole);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = 0; i < show; i++) {
        if (w.len + PC_ROW_MAX + 256 > cap) break;
        const pc_t *r = &rows[i];
        if (shown++) web_jw_raw(&w, ",");
        jw_mac(&w, m, r->mac);
        web_jw_raw(&w, ",\"frames\":");
        if (r->has_p) web_jw_int(&w, r->frames < 0 ? 0 : r->frames); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"directed\":");
        if (r->has_n) web_jw_int(&w, r->directed < 0 ? 0 : r->directed); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"signal\":");     jw_signal(&w, r->has_p && r->has_signal, r->signal);
        web_jw_raw(&w, ",\"channel\":");
        if (r->has_p) web_jw_int(&w, r->channel & 0xffff); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"os\":");         jw_text_or_null(&w, r->os);
        web_jw_raw(&w, ",\"phy\":");        jw_text_or_null(&w, r->phy);
        web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, r->first_seen);
        web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, r->last_seen);
        web_jw_raw(&w, ",\"ssid_count\":"); web_jw_int(&w, r->nss);
        web_jw_raw(&w, ",\"ssids\":[");
        int k = 0;
        if (ss) {
            sqlite3_reset(ss);
            bind_t(ss, 1, r->mac);
            sqlite3_bind_int(ss, 2, WEB_PROBE_ROW_SSIDS);
            while (sqlite3_step(ss) == SQLITE_ROW) {
                char s[WEB_SDB_TEXT_MAX + 1];
                ctext(ss, 0, s, WEB_SDB_TEXT_MAX);
                if (k++) web_jw_raw(&w, ",");
                jw_ssid_obj(&w, s);
                web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, sqlite3_column_int64(ss, 1));
                web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, sqlite3_column_int64(ss, 2));
                web_jw_raw(&w, "}");
            }
        }
        web_jw_raw(&w, "],\"ssids_more\":"); jw_bool(&w, r->nss > k);
        int dev = 0;
        if (dv) {
            sqlite3_reset(dv);
            bind_t(dv, 1, r->mac);
            dev = sqlite3_step(dv) == SQLITE_ROW;
        }
        web_jw_raw(&w, ",\"device\":"); jw_bool(&w, dev);
        web_jw_raw(&w, ",\"assoc\":");
        int have = 0;
        if (as) {
            sqlite3_reset(as);
            bind_t(as, 1, r->mac);
            char ap[WEB_KEY_MAX + 1];
            if (sqlite3_step(as) == SQLITE_ROW && cmac(as, 0, ap)) {
                char s[WEB_SDB_TEXT_MAX + 1];
                ctext(as, 1, s, WEB_SDB_TEXT_MAX);
                have = 1;
                web_jw_raw(&w, "{\"bssid\":");     web_jw_str(&w, ap);
                web_jw_raw(&w, ",\"ssid\":");      web_jw_ssid(&w, s);
                web_jw_ssid_meta(&w, "ssid", s);
                web_jw_raw(&w, ",\"last_seen\":"); web_jw_int(&w, sqlite3_column_int64(as, 2));
                web_jw_raw(&w, "}");
            }
        }
        if (!have) web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"siblings\":[");
        for (int q = 0; q < r->nsib && q < WEB_PROBE_SIBLINGS; q++) {
            if (q) web_jw_raw(&w, ",");
            jw_mac(&w, m, r->sib[q].mac);
            web_jw_raw(&w, ",\"gap\":");        web_jw_int(&w, r->sib[q].gap);
            web_jw_raw(&w, ",\"dt_ms\":");      web_jw_int(&w, r->sib[q].dt_ms);
            web_jw_raw(&w, ",\"frames\":");     web_jw_int(&w, r->sib[q].frames);
            web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, r->sib[q].first_seen);
            web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, r->sib[q].last_seen);
            web_jw_raw(&w, "}");
        }
        web_jw_raw(&w, "],\"siblings_total\":"); web_jw_int(&w, r->nsib);
        char hx[WEB_DEV_CELLS / 4 + 1];
        web_dev_presence_hex(bits + (size_t)i * (WEB_DEV_CELLS / 8), hx);
        web_jw_raw(&w, ",\"presence\":"); web_jw_str(&w, hx);
        web_jw_raw(&w, "}");
    }
    sqlite3_finalize(ss);
    sqlite3_finalize(dv);
    sqlite3_finalize(as);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    free(bits);
    free(rows);
    if (to) return answer_error(503, "sloth_db_timeout", NULL, body, cap, len, status);
    int more = offset + shown < total;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"total\":");    web_jw_int(&w, total);
    web_jw_raw(&w, ",\"more\":");     jw_bool(&w, more);
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/probes/ssids ───────────────────────────────────────────────── */

#define PS_ROW_MAX (WEB_SSID_JSON_MAX(WEB_SDB_TEXT_MAX) + 320)

int web_probes_ssids_route(const web_m4_t *m, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status) {
    if (no_db(m)) return NO_DB_ANSWER();
    web_param_t ps[4] = { { "days", "", 0 }, { "sort", "", 0 }, { "limit", "", 0 },
                          { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days, since, limit = WEB_PROBE_LIMIT, offset = 0;
    if (days_of(&ps[0], now_s, &days, &since) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    static const struct { const char *word, *order; } SORT[] = {
        { "clients", "clients DESC, s.ssid" },
        { "last", "max(s.last_seen) DESC, s.ssid" },
        { "first", "min(s.first_seen), s.ssid" },
        { "ssid", "s.ssid" },
    };
    int sort = 0;
    if (ps[1].seen) {
        sort = -1;
        for (size_t i = 0; i < sizeof(SORT) / sizeof(SORT[0]); i++)
            if (!strcmp(ps[1].val, SORT[i].word)) sort = (int)i;
        if (sort < 0) return answer_error(400, "bad_sort", NULL, body, cap, len, status);
    }
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_PROBE_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, 0, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

    web_sdb_conn_t conn;
    if (open_db(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long clients = one_count(&conn,
        "SELECT count(*) FROM pnl_clients WHERE last_seen >= ?1", NULL, 1, since);
    /* A row per SSID asked for by name: pnl_ssids' key is (mac, ssid),
     * so count(*) is its stations; a MAC whose second hex digit is 2,
     * 6, a or e is locally administered (randomised). No LIMIT: the page
     * is cut here and the rows past it only counted, so one pass gives
     * the whole count too. The APs are beacon_aps rows of exactly that
     * SSID, by its index, read for the shown rows alone. */
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "SELECT s.ssid, count(*) AS clients,"
             " sum(substr(s.mac, 2, 1) IN ('2','6','a','e')),"
             " min(s.first_seen), max(s.last_seen)"
             " FROM pnl_ssids s WHERE s.last_seen >= ?1 AND s.ssid <> ''"
             " GROUP BY s.ssid ORDER BY %s", SORT[sort].order);
    sqlite3_stmt *st = prep(&conn, sql);
    sqlite3_stmt *ap = prep(&conn, "SELECT count(*), max(signal_dbm) FROM beacon_aps"
                                   " WHERE ssid = ?1");
    if (!st || clients < 0) {
        sqlite3_finalize(st);
        sqlite3_finalize(ap);
        return db_failed(&conn, body, cap, len, status);
    }
    sqlite3_bind_int64(st, 1, since);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");      web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":");     web_jw_int(&w, days);
    web_jw_raw(&w, ",\"sort\":");     web_jw_str(&w, SORT[sort].word);
    web_jw_raw(&w, ",\"limit\":");    web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":");   web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"clients\":");  web_jw_int(&w, clients);
    web_jw_raw(&w, ",\"u\":");        web_jw_int(&w, web_probe_u(clients));
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0, rc;
    long long total = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (total++ < offset || shown >= limit || w.len + PS_ROW_MAX + 256 > cap) continue;
        char s[WEB_SDB_TEXT_MAX + 1];
        ctext(st, 0, s, WEB_SDB_TEXT_MAX);
        long long df = sqlite3_column_int64(st, 1), aps = 0, sig = 0;
        int has_sig = 0;
        if (ap) {
            sqlite3_reset(ap);
            bind_t(ap, 1, s);
            if (sqlite3_step(ap) == SQLITE_ROW) {
                aps = sqlite3_column_int64(ap, 0);
                has_sig = sqlite3_column_type(ap, 1) != SQLITE_NULL;
                sig = sqlite3_column_int64(ap, 1);
            }
        }
        if (shown++) web_jw_raw(&w, ",");
        jw_ssid_obj(&w, s);
        web_jw_raw(&w, ",\"clients\":");    web_jw_int(&w, df);
        web_jw_raw(&w, ",\"random\":");     web_jw_int(&w, sqlite3_column_int64(st, 2));
        web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, sqlite3_column_int64(st, 3));
        web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, sqlite3_column_int64(st, 4));
        web_jw_raw(&w, ",\"aps\":");        web_jw_int(&w, aps);
        web_jw_raw(&w, ",\"ap_signal\":");  jw_signal(&w, has_sig, sig);
        web_jw_raw(&w, ",\"uncommon\":");
        jw_bool(&w, df >= 2 && df <= web_probe_u(clients));
        /* sloth's --my-ssid reaches neither sloth.db nor the stream. */
        web_jw_raw(&w, ",\"designated\":null}");
    }
    sqlite3_finalize(st);
    sqlite3_finalize(ap);
    if (rc != SQLITE_DONE) return db_failed(&conn, body, cap, len, status);
    web_slothdb_close(&conn);
    int more = offset + shown < total;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"total\":");    web_jw_int(&w, total);
    web_jw_raw(&w, ",\"more\":");     jw_bool(&w, more);
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── the similarity ──────────────────────────────────────────────────── */

static uint64_t fnv(const char *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 0x100000001b3ULL; }
    return h ? h : 1;
}

/* df(s) for the request, each SSID counted once: an index range of
 * idx_pnl_ssids_ssid. Keyed by a 64-bit hash of the octets; a full
 * table just counts again. */
#define DF_SLOTS 4096
typedef struct {
    sqlite3_stmt *st;
    long long     since;
    uint64_t      key[DF_SLOTS];
    long long     df[DF_SLOTS];
    int           n;
} dfc_t;

static long long df_of(dfc_t *d, const char *ssid) {
    uint64_t h = fnv(ssid);
    unsigned at = (unsigned)(h % DF_SLOTS);
    for (int probe = 0; probe < DF_SLOTS && d->key[at]; probe++) {
        if (d->key[at] == h) return d->df[at];
        at = (at + 1) % DF_SLOTS;
    }
    long long v = 0;
    sqlite3_reset(d->st);
    bind_t(d->st, 1, ssid);
    sqlite3_bind_int64(d->st, 2, d->since);
    if (sqlite3_step(d->st) == SQLITE_ROW) v = sqlite3_column_int64(d->st, 0);
    if (d->n < DF_SLOTS - 1 && !d->key[at]) {
        d->key[at] = h;
        d->df[at] = v;
        d->n++;
    }
    return v;
}

typedef struct {
    char      ssid[WEB_PROBE_SET][WEB_SDB_TEXT_MAX + 1];
    long long df[WEB_PROBE_SET];
    int       n, more;
} pset_t;

/* mac's named SSIDs in the window, the newest WEB_PROBE_SET, with df. */
static void set_read(sqlite3_stmt *st, dfc_t *d, const char *mac, pset_t *s) {
    s->n = 0;
    s->more = 0;
    sqlite3_reset(st);
    bind_t(st, 1, mac);
    sqlite3_bind_int64(st, 2, d->since);
    sqlite3_bind_int(st, 3, WEB_PROBE_SET + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (s->n >= WEB_PROBE_SET) { s->more = 1; break; }
        ctext(st, 0, s->ssid[s->n], WEB_SDB_TEXT_MAX);
        s->n++;
    }
    for (int i = 0; i < s->n; i++) s->df[i] = df_of(d, s->ssid[i]);
}

static int uncommon(long long df, int u) { return df >= 2 && df <= u; }

typedef struct {
    char   mac[WEB_KEY_MAX + 1];
    int    shared_u;          /* uncommon SSIDs shared */
    int    shared, nset, set_more;
    double sim;
    int    which[6];          /* A's SSIDs shared, the rarest first */
    int    nwhich;
} cand_t;

static int by_sim(const void *x, const void *y) {
    const cand_t *a = x, *b = y;
    if (a->sim != b->sim) return a->sim < b->sim ? 1 : -1;
    if (a->shared_u != b->shared_u) return b->shared_u - a->shared_u;
    return strcmp(a->mac, b->mac);
}

static void jw_num3(web_jw_t *w, double v) {
    char b[32];
    if (!isfinite(v) || v < 0) v = 0;
    snprintf(b, sizeof(b), "%.3f", v);
    web_jw_raw(w, b);
}

static void jw_formula(web_jw_t *w, long long n, int u, long long min) {
    web_jw_raw(w, ",\"n_clients\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"u\":");         web_jw_int(w, u);
    web_jw_raw(w, ",\"min\":");       web_jw_int(w, min);
    web_jw_raw(w, ",\"formula\":\"w(s) = ln(N / df(s)); sim = sum of w over the shared "
                  "SSIDs / sum of w over either's; uncommon: 2 <= df <= U\"");
}

int web_probes_shared_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status) {
    if (no_db(m)) return NO_DB_ANSWER();
    web_param_t ps[3] = { { "mac", "", 0 }, { "days", "", 0 }, { "min", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    char mac[WEB_KEY_MAX + 1];
    if (!ps[0].seen) return answer_error(400, "missing_mac", NULL, body, cap, len, status);
    if (web_dev_canon_mac(ps[0].val, mac) != 0)
        return answer_error(400, "bad_mac", NULL, body, cap, len, status);
    long long days, since, min = WEB_PROBE_MIN;
    if (days_of(&ps[1], now_s, &days, &since) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_PROBE_MIN_MAX, &min) != 0)
        return answer_error(400, "bad_min", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

    web_sdb_conn_t conn;
    if (open_db(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long N = one_count(&conn,
        "SELECT count(*) FROM pnl_clients WHERE last_seen >= ?1", NULL, 1, since);
    dfc_t *d = calloc(1, sizeof(*d));
    pset_t *A = calloc(1, sizeof(*A)), *B = calloc(1, sizeof(*B));
    cand_t *cs = calloc(WEB_PROBE_CANDS, sizeof(*cs));
    sqlite3_stmt *sset = prep(&conn, "SELECT ssid FROM pnl_ssids WHERE mac = ?1 AND"
                                     " last_seen >= ?2 AND ssid <> '' ORDER BY last_seen DESC,"
                                     " ssid LIMIT ?3");
    sqlite3_stmt *sdf = prep(&conn, "SELECT count(*) FROM pnl_ssids WHERE ssid = ?1 AND"
                                    " last_seen >= ?2");
    sqlite3_stmt *scand = prep(&conn, "SELECT mac FROM pnl_ssids WHERE ssid = ?1 AND"
                                      " last_seen >= ?2 AND mac <> ?3 LIMIT ?4");
    if (!d || !A || !B || !cs || !sset || !sdf || !scand || N < 0) {
        int mem = !d || !A || !B || !cs;
        sqlite3_finalize(sset); sqlite3_finalize(sdf); sqlite3_finalize(scand);
        free(d); free(A); free(B); free(cs);
        if (mem) { web_slothdb_close(&conn); return -1; }
        return db_failed(&conn, body, cap, len, status);
    }
    d->st = sdf;
    d->since = since;
    int u = web_probe_u(N);
    set_read(sset, d, mac, A);

    /* The candidates: every station asking for one of A's uncommon
     * SSIDs, each of which at most U stations ask for, so at most
     * WEB_PROBE_SET * (U - 1) of them. */
    int nc = 0, capped = 0;
    for (int i = 0; i < A->n; i++) {
        if (!uncommon(A->df[i], u)) continue;
        sqlite3_reset(scand);
        bind_t(scand, 1, A->ssid[i]);
        sqlite3_bind_int64(scand, 2, since);
        bind_t(scand, 3, mac);
        sqlite3_bind_int(scand, 4, WEB_PROBE_U_MAX + 1);
        while (sqlite3_step(scand) == SQLITE_ROW) {
            char o[WEB_KEY_MAX + 1];
            if (!cmac(scand, 0, o) || !strcmp(o, mac)) continue;
            int k = 0;
            while (k < nc && strcmp(cs[k].mac, o)) k++;
            if (k == nc) {
                if (nc >= WEB_PROBE_CANDS) { capped = 1; continue; }
                snprintf(cs[nc].mac, sizeof(cs[nc].mac), "%s", o);
                nc++;
            }
            cs[k].shared_u++;
        }
    }
    /* Each candidate with enough shared uncommon SSIDs, scored. */
    double wa = 0;
    for (int i = 0; i < A->n; i++) wa += web_probe_weight(N, A->df[i]);
    int nk = 0;
    for (int k = 0; k < nc; k++) {
        if (cs[k].shared_u < min) continue;
        cand_t c = cs[k];
        set_read(sset, d, c.mac, B);
        double inter = 0, wb = 0;
        c.shared = 0;
        c.nwhich = 0;
        for (int j = 0; j < B->n; j++) wb += web_probe_weight(N, B->df[j]);
        for (int i = 0; i < A->n; i++) {
            int hit = 0;
            for (int j = 0; j < B->n && !hit; j++) hit = !strcmp(A->ssid[i], B->ssid[j]);
            if (!hit) continue;
            inter += web_probe_weight(N, A->df[i]);
            c.shared++;
            /* The six rarest shared SSIDs are named: by df, then as A
             * lists them. */
            int at;
            if (c.nwhich < 6) at = c.nwhich++;
            else if (A->df[i] < A->df[c.which[5]]) at = 5;
            else continue;
            c.which[at] = i;
            for (int q = at; q > 0 && A->df[c.which[q]] < A->df[c.which[q - 1]]; q--) {
                int t = c.which[q];
                c.which[q] = c.which[q - 1];
                c.which[q - 1] = t;
            }
        }
        double uni = wa + wb - inter;
        c.sim = uni > 0 ? inter / uni : 0;
        c.nset = B->n;
        c.set_more = B->more;
        cs[nk++] = c;
    }
    sqlite3_finalize(sset);
    sqlite3_finalize(sdf);
    sqlite3_finalize(scand);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (to) {
        free(d); free(A); free(B); free(cs);
        return answer_error(503, "sloth_db_timeout", NULL, body, cap, len, status);
    }
    qsort(cs, (size_t)nk, sizeof(*cs), by_sim);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"mac\":");  web_jw_str(&w, mac);
    web_jw_raw(&w, ",\"now\":");  web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    jw_formula(&w, N, u, min);
    web_jw_raw(&w, ",\"ssids\":[");
    for (int i = 0; i < A->n; i++) {
        if (i) web_jw_raw(&w, ",");
        jw_ssid_obj(&w, A->ssid[i]);
        web_jw_raw(&w, ",\"df\":");       web_jw_int(&w, A->df[i]);
        web_jw_raw(&w, ",\"w\":");        jw_num3(&w, web_probe_weight(N, A->df[i]));
        web_jw_raw(&w, ",\"uncommon\":"); jw_bool(&w, uncommon(A->df[i], u));
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"ssids_more\":"); jw_bool(&w, A->more);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int k = 0; k < nk && shown < WEB_PROBE_SHOWN; k++) {
        if (w.len + 6 * (WEB_SSID_JSON_MAX(WEB_SDB_TEXT_MAX) + 64) + 600 > cap) break;
        const cand_t *c = &cs[k];
        if (shown++) web_jw_raw(&w, ",");
        jw_mac(&w, m, c->mac);
        web_jw_raw(&w, ",\"sim\":");             jw_num3(&w, c->sim);
        web_jw_raw(&w, ",\"shared_uncommon\":"); web_jw_int(&w, c->shared_u);
        web_jw_raw(&w, ",\"shared_n\":");        web_jw_int(&w, c->shared);
        web_jw_raw(&w, ",\"ssid_count\":");      web_jw_int(&w, c->nset);
        web_jw_raw(&w, ",\"ssids_more\":");      jw_bool(&w, c->set_more);
        web_jw_raw(&w, ",\"shared\":[");
        for (int q = 0; q < c->nwhich; q++) {
            if (q) web_jw_raw(&w, ",");
            jw_ssid_obj(&w, A->ssid[c->which[q]]);
            web_jw_raw(&w, ",\"df\":"); web_jw_int(&w, A->df[c->which[q]]);
            web_jw_raw(&w, "}");
        }
        web_jw_raw(&w, "]}");
    }
    web_jw_raw(&w, "],\"count\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"total\":");   web_jw_int(&w, nk);
    web_jw_raw(&w, ",\"capped\":");  jw_bool(&w, capped);
    web_jw_raw(&w, "}\n");
    free(d); free(A); free(B); free(cs);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/probes/groups ──────────────────────────────────────────────── */

typedef struct {
    char           ssid[WEB_SDB_TEXT_MAX + 1];
    unsigned char  n;
    unsigned short idx[WEB_PROBE_U_MAX];
} gss_t;

typedef struct {
    char      (*mac)[WEB_KEY_MAX + 1];
    int       *slot;                  /* WEB_PROBE_G_MACS * 2, index + 1 */
    int        nmac;
    gss_t     *ss;
    int        nss;
    uint32_t  *pkey;                  /* WEB_PROBE_G_PAIRS * 2, key + 1 */
    unsigned short *pcnt;
    int        npair;
    int       *parent, *gsize, *gss;
    long long  uncommon_seen;
    int        capped;
} grp_t;

static void grp_free(grp_t *g) {
    free(g->mac); free(g->slot); free(g->ss); free(g->pkey); free(g->pcnt);
    free(g->parent); free(g->gsize); free(g->gss);
}

static int grp_alloc(grp_t *g) {
    memset(g, 0, sizeof(*g));
    g->mac = calloc(WEB_PROBE_G_MACS, sizeof(*g->mac));
    g->slot = calloc(WEB_PROBE_G_MACS * 2, sizeof(*g->slot));
    g->ss = calloc(WEB_PROBE_G_SSIDS, sizeof(*g->ss));
    g->pkey = calloc(WEB_PROBE_G_PAIRS * 2, sizeof(*g->pkey));
    g->pcnt = calloc(WEB_PROBE_G_PAIRS * 2, sizeof(*g->pcnt));
    g->parent = calloc(WEB_PROBE_G_MACS, sizeof(*g->parent));
    g->gsize = calloc(WEB_PROBE_G_MACS, sizeof(*g->gsize));
    g->gss = calloc(WEB_PROBE_G_MACS, sizeof(*g->gss));
    return g->mac && g->slot && g->ss && g->pkey && g->pcnt && g->parent &&
           g->gsize && g->gss ? 0 : -1;
}

/* The station's index, made on first sight; -1 when the table is full. */
static int grp_mac(grp_t *g, const char *mac) {
    unsigned at = (unsigned)(fnv(mac) % (WEB_PROBE_G_MACS * 2));
    while (g->slot[at]) {
        if (!strcmp(g->mac[g->slot[at] - 1], mac)) return g->slot[at] - 1;
        at = (at + 1) % (WEB_PROBE_G_MACS * 2);
    }
    if (g->nmac >= WEB_PROBE_G_MACS) return -1;
    snprintf(g->mac[g->nmac], sizeof(g->mac[0]), "%s", mac);
    g->slot[at] = ++g->nmac;
    return g->nmac - 1;
}

static void grp_pair(grp_t *g, int a, int b) {
    if (a == b) return;
    if (a > b) { int t = a; a = b; b = t; }
    uint32_t key = (uint32_t)a * WEB_PROBE_G_MACS + (uint32_t)b + 1;
    unsigned at = (unsigned)((key * 2654435761u) % (WEB_PROBE_G_PAIRS * 2));
    while (g->pkey[at]) {
        if (g->pkey[at] == key) {
            if (g->pcnt[at] < 0xffff) g->pcnt[at]++;
            return;
        }
        at = (at + 1) % (WEB_PROBE_G_PAIRS * 2);
    }
    if (g->npair >= WEB_PROBE_G_PAIRS) { g->capped = 1; return; }
    g->pkey[at] = key;
    g->pcnt[at] = 1;
    g->npair++;
}

/* One SSID's stations, complete: kept when uncommon. */
static void grp_ssid(grp_t *g, const char *ssid, char (*macs)[WEB_KEY_MAX + 1],
                     int n, int u) {
    if (!uncommon(n, u)) return;
    g->uncommon_seen++;
    if (g->nss >= WEB_PROBE_G_SSIDS) { g->capped = 1; return; }
    gss_t *e = &g->ss[g->nss];
    snprintf(e->ssid, sizeof(e->ssid), "%s", ssid);
    e->n = 0;
    for (int i = 0; i < n; i++) {
        int ix = grp_mac(g, macs[i]);
        if (ix < 0) { g->capped = 1; continue; }
        e->idx[e->n++] = (unsigned short)ix;
    }
    if (e->n < 2) return;
    g->nss++;
    for (int i = 0; i < e->n; i++)
        for (int j = i + 1; j < e->n; j++) grp_pair(g, e->idx[i], e->idx[j]);
}

static int grp_root(grp_t *g, int i) {
    while (g->parent[i] != i) {
        g->parent[i] = g->parent[g->parent[i]];
        i = g->parent[i];
    }
    return i;
}

static grp_t *g_sort;
static int by_group(const void *x, const void *y) {
    int a = *(const int *)x, b = *(const int *)y;
    if (g_sort->gss[a] != g_sort->gss[b]) return g_sort->gss[b] - g_sort->gss[a];
    if (g_sort->gsize[a] != g_sort->gsize[b]) return g_sort->gsize[b] - g_sort->gsize[a];
    return strcmp(g_sort->mac[a], g_sort->mac[b]);
}

int web_probes_groups_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status) {
    if (no_db(m)) return NO_DB_ANSWER();
    web_param_t ps[2] = { { "days", "", 0 }, { "min", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days, since, min = WEB_PROBE_MIN;
    if (days_of(&ps[0], now_s, &days, &since) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_PROBE_MIN_MAX, &min) != 0)
        return answer_error(400, "bad_min", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

    web_sdb_conn_t conn;
    if (open_db(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long N = one_count(&conn,
        "SELECT count(*) FROM pnl_clients WHERE last_seen >= ?1", NULL, 1, since);
    grp_t g;
    /* The window's rows in SSID order (idx_pnl_ssids_ssid): one SSID's
     * stations arrive together, so df is a run's length and only an
     * uncommon SSID's stations are ever held. */
    sqlite3_stmt *st = prep(&conn, "SELECT ssid, mac FROM pnl_ssids WHERE last_seen >= ?1"
                                   " AND ssid <> '' ORDER BY ssid");
    if (grp_alloc(&g) != 0 || !st || N < 0) {
        int mem = !g.mac || !g.gss;
        sqlite3_finalize(st);
        grp_free(&g);
        if (mem) { web_slothdb_close(&conn); return -1; }
        return db_failed(&conn, body, cap, len, status);
    }
    int u = web_probe_u(N);
    sqlite3_bind_int64(st, 1, since);
    char cur[WEB_SDB_TEXT_MAX + 1] = "";
    char macs[WEB_PROBE_U_MAX + 1][WEB_KEY_MAX + 1];
    int run = 0, have = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        char s[WEB_SDB_TEXT_MAX + 1], mac[WEB_KEY_MAX + 1];
        ctext(st, 0, s, WEB_SDB_TEXT_MAX);
        if (!cmac(st, 1, mac)) continue;
        if (!have || strcmp(s, cur)) {
            if (have) grp_ssid(&g, cur, macs, run, u);
            snprintf(cur, sizeof(cur), "%s", s);
            run = 0;
            have = 1;
        }
        if (run <= WEB_PROBE_U_MAX) snprintf(macs[run], sizeof(macs[0]), "%s", mac);
        if (run <= WEB_PROBE_U_MAX) run++;
    }
    if (have) grp_ssid(&g, cur, macs, run, u);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        grp_free(&g);
        return db_failed(&conn, body, cap, len, status);
    }
    web_slothdb_close(&conn);

    /* Two stations are linked when they share at least min uncommon
     * SSIDs; a group is the stations linked to one another, directly
     * or through others. */
    for (int i = 0; i < g.nmac; i++) g.parent[i] = i;
    for (int at = 0; at < WEB_PROBE_G_PAIRS * 2; at++) {
        if (!g.pkey[at] || g.pcnt[at] < min) continue;
        uint32_t key = g.pkey[at] - 1;
        int a = grp_root(&g, (int)(key / WEB_PROBE_G_MACS));
        int b = grp_root(&g, (int)(key % WEB_PROBE_G_MACS));
        if (a != b) g.parent[b] = a;
    }
    for (int i = 0; i < g.nmac; i++) g.gsize[grp_root(&g, i)]++;
    /* A group's SSIDs: the uncommon ones at least two of it ask for. */
    for (int e = 0; e < g.nss; e++) {
        const gss_t *x = &g.ss[e];
        for (int i = 0; i < x->n; i++) {
            int r = grp_root(&g, x->idx[i]), first = 1, twice = 0;
            for (int j = 0; j < i; j++) if (grp_root(&g, x->idx[j]) == r) first = 0;
            if (!first) continue;
            for (int j = i + 1; j < x->n; j++) if (grp_root(&g, x->idx[j]) == r) twice = 1;
            if (twice) g.gss[r]++;
        }
    }
    int *roots = calloc((size_t)(g.nmac ? g.nmac : 1), sizeof(*roots));
    if (!roots) { grp_free(&g); return -1; }
    int ng = 0;
    for (int i = 0; i < g.nmac; i++)
        if (g.parent[i] == i && g.gsize[i] >= 2) roots[ng++] = i;
    g_sort = &g;
    qsort(roots, (size_t)ng, sizeof(*roots), by_group);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");  web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    jw_formula(&w, N, u, min);
    web_jw_raw(&w, ",\"ssids_uncommon\":"); web_jw_int(&w, g.uncommon_seen);
    web_jw_raw(&w, ",\"ssids_read\":");     web_jw_int(&w, g.nss);
    web_jw_raw(&w, ",\"capped\":");         jw_bool(&w, g.capped);
    web_jw_raw(&w, ",\"groups\":[");
    int shown = 0;
    size_t one = WEB_PROBE_G_NAMES * (WEB_SSID_JSON_MAX(WEB_SDB_TEXT_MAX) + 64) +
                 WEB_PROBE_G_MEMBERS * 480 + 400;
    for (int k = 0; k < ng && shown < WEB_PROBE_G_SHOWN; k++) {
        if (w.len + one > cap) break;
        int r = roots[k];
        web_jw_raw(&w, shown++ ? ",{\"clients\":" : "{\"clients\":");
        web_jw_int(&w, g.gsize[r]);
        web_jw_raw(&w, ",\"ssids\":"); web_jw_int(&w, g.gss[r]);
        web_jw_raw(&w, ",\"macs\":[");
        int nm = 0;
        for (int i = 0; i < g.nmac && nm < WEB_PROBE_G_MEMBERS; i++) {
            if (grp_root(&g, i) != r) continue;
            if (nm++) web_jw_raw(&w, ",");
            jw_mac(&w, m, g.mac[i]);
            web_jw_raw(&w, "}");
        }
        web_jw_raw(&w, "],\"names\":[");
        int nn = 0;
        for (int e = 0; e < g.nss && nn < WEB_PROBE_G_NAMES; e++) {
            const gss_t *x = &g.ss[e];
            int in = 0;
            for (int i = 0; i < x->n; i++) if (grp_root(&g, x->idx[i]) == r) in++;
            if (in < 2) continue;
            if (nn++) web_jw_raw(&w, ",");
            jw_ssid_obj(&w, x->ssid);
            web_jw_raw(&w, ",\"df\":");       web_jw_int(&w, x->n);
            web_jw_raw(&w, ",\"in_group\":"); web_jw_int(&w, in);
            web_jw_raw(&w, "}");
        }
        web_jw_raw(&w, "]}");
    }
    web_jw_raw(&w, "],\"count\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"total\":");  web_jw_int(&w, ng);
    web_jw_raw(&w, "}\n");
    free(roots);
    grp_free(&g);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

#else /* !WITH_SQLITE */

/* no_db() is always true here: web_slothdb_available() says so. */
int web_probes_clients_route(const web_m4_t *m, const char *query, long long now_s,
                             char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return NO_DB_ANSWER();
}
int web_probes_ssids_route(const web_m4_t *m, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return NO_DB_ANSWER();
}
int web_probes_shared_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return NO_DB_ANSWER();
}
int web_probes_groups_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return NO_DB_ANSWER();
}

#endif
