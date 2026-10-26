#include "web_devices.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_baseline.h"
#include "web_history.h"
#include "web_metrics.h"
#include "web_query.h"
#include "web_ssid.h"

/* ── parameters ──────────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    size_t      max;          /* decoded bytes */
    int         plus_space;   /* '+' is a space (the q of a form) */
    char        val[WEB_Q_LEN + 1];
    int         seen;
} dparam_t;

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int why(char *err, size_t errsz, const char *w) {
    snprintf(err, errsz, "%s", w);
    return -1;
}

/* As /api/series parses its query (web_series.c): name=value pairs and
 * nothing else, each name once and one of ours, values percent-decoded.
 * A decoded value may hold any byte from 0x20 up but DEL: the query
 * parser (web_query.c) then checks it as text. */
static int dparams(const char *query, dparam_t *ps, int np, char *err,
                   size_t errsz) {
    if (!query || !query[0]) return 0;
    const char *p = query;
    for (;;) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg);
        if (!seg || !eq || eq == p) return why(err, errsz, "bad_query");
        size_t nl = (size_t)(eq - p);
        int which = -1;
        for (int i = 0; i < np; i++)
            if (strlen(ps[i].name) == nl && !memcmp(ps[i].name, p, nl)) which = i;
        if (which < 0) return why(err, errsz, "unknown_parameter");
        if (ps[which].seen) return why(err, errsz, "repeated_parameter");
        ps[which].seen = 1;
        size_t o = 0;
        for (const char *v = eq + 1; v < p + seg; v++) {
            int c = (unsigned char)*v;
            if (c == '%') {
                if ((size_t)(p + seg - v) < 3) return why(err, errsz, "bad_escape");
                int h = hexv((unsigned char)v[1]), l = hexv((unsigned char)v[2]);
                if (h < 0 || l < 0) return why(err, errsz, "bad_escape");
                c = h * 16 + l;
                v += 2;
            } else if (c == '+' && ps[which].plus_space) {
                c = ' ';
            }
            if (c < 0x20 || c == 0x7f) return why(err, errsz, "bad_value");
            if (o >= ps[which].max) return why(err, errsz, "value_too_long");
            ps[which].val[o++] = (char)c;
        }
        ps[which].val[o] = '\0';
        if (!o) return why(err, errsz, "empty_value");
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int decimal(const char *s, long long max, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 6) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v > max) return -1;
    *out = v;
    return 0;
}

/* ── answers ─────────────────────────────────────────────────────────── */

static int answer_error(int status, const char *reason, const char *detail,
                        char *body, size_t cap, size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    if (detail) {
        web_jw_raw(&w, ",\"detail\":");
        web_jw_strn(&w, detail, strnlen(detail, 240));
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

static void jw_text_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

static void jw_real1(web_jw_t *w, double v) {
    char b[32];
    if (!isfinite(v)) { web_jw_raw(w, "null"); return; }
    if (v > 1e6) v = 1e6;
    snprintf(b, sizeof(b), "%.1f", v);
    web_jw_raw(w, b);
}

void web_dev_presence_hex(const unsigned char bits[WEB_DEV_CELLS / 8],
                          char out[WEB_DEV_CELLS / 4 + 1]) {
    static const char hx[] = "0123456789abcdef";
    for (int d = 0; d < WEB_DEV_CELLS / 4; d++) {
        int v = 0;
        for (int k = 0; k < 4; k++) {
            int c = d * 4 + k;
            if (bits[c / 8] & (1u << (c % 8))) v |= 8 >> k;
        }
        out[d] = hx[v];
    }
    out[WEB_DEV_CELLS / 4] = '\0';
}

/* The strip's first cell: 144 cells ending with the one now_s is in. */
static long long strip_from(long long now_s) {
    return now_s - now_s % WEB_DEV_CELL_S - (WEB_DEV_CELLS - 1) * WEB_DEV_CELL_S;
}

/* The strips of n MACs, ncell (at most WEB_DEV_CELLS) cells of cell_s
 * from from, nothing at or past to: the store's minute tier, and its
 * hour tier too when hour is set (cells of whole hours, so an hour row
 * belongs to one cell), then what the ring and the open buckets hold. */
static void strips_at(const web_m4_t *m, const char (*macs)[WEB_KEY_MAX + 1],
                      int n, long long from, long long to, int ncell,
                      int cell_s, int hour, unsigned char *bits) {
    memset(bits, 0, (size_t)n * (WEB_DEV_CELLS / 8));
    if (!m->tsdb) return;
    if (m->tsdb->store && m->tsdb->store->rd)
        for (int i = 0; i < n; i++)
            for (int t = WEB_TIER_MINUTE; t <= (hour ? WEB_TIER_HOUR : WEB_TIER_MINUTE); t++)
                web_store_presence(m->tsdb->store, t, WM_DEV_PRESENT, macs[i],
                                   from, to, ncell, cell_s,
                                   bits + (size_t)i * (WEB_DEV_CELLS / 8));
    web_rollup_presence(m->tsdb->ru, WM_DEV_PRESENT, macs, n, from, to,
                        ncell, cell_s, bits);
}

static void strips(const web_m4_t *m, const char (*macs)[WEB_KEY_MAX + 1],
                   int n, long long now_s, unsigned char *bits) {
    long long from = strip_from(now_s);
    strips_at(m, macs, n, from, from + (long long)WEB_DEV_CELLS * WEB_DEV_CELL_S,
              WEB_DEV_CELLS, WEB_DEV_CELL_S, 0, bits);
}

static const char *vendor_table(const web_m4_t *m) {
    return m->oui && m->oui->source ? m->oui->source : "none";
}

/* The best passive name of a row and its glyph (§8.6): D DHCP, m mDNS,
 * N NBNS from sloth.db; h sloth's own hostname field; p a PTR answer
 * seen on the wire; then the stream's current D, m, N. */
static const char *best_name(const web_m4_t *m, const web_sdb_dev_t *d,
                             long long now_s, char *buf, const char **glyph) {
    if (d->dhcp_name[0]) { *glyph = "D"; return d->dhcp_name; }
    if (d->mdns_name[0]) { *glyph = "m"; return d->mdns_name; }
    if (d->nbns_name[0]) { *glyph = "N"; return d->nbns_name; }
    if (d->hostname[0]) { *glyph = "h"; return d->hostname; }
    if (d->ip[0] && m->ptr && web_ptr_get(m->ptr, d->ip, buf, NULL)) {
        *glyph = "p";
        return buf;
    }
    if (d->ip[0] && m->ident) {
        char mac[WEB_KEY_MAX + 1];
        web_id_name_t nm[WEB_ID_SRC_COUNT];
        static const char *const G[WEB_ID_SRC_COUNT] = { "D", "m", "N" };
        if (web_ident_ip_info(m->ident, d->ip, now_s, mac, nm))
            for (int s = 0; s < WEB_ID_SRC_COUNT; s++)
                if (nm[s].name[0]) {
                    web_utf8_copy(buf, WEB_PTR_NAME_MAX, nm[s].name);
                    *glyph = G[s];
                    return buf;
                }
    }
    *glyph = NULL;
    return NULL;
}

/* One device row (§8.6). At most WEB_DEV_ROW_MAX bytes. */
static void dev_json(web_jw_t *w, const web_m4_t *m, const web_sdb_dev_t *d,
                     const unsigned char *bits, long long now_s) {
    uint8_t mac[6];
    web_oui_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    int ok = web_oui_mac_bytes(d->mac, mac) == 0;
    if (ok) web_oui_lookup(m->oui, mac, &hit);
    web_jw_raw(w, "{\"mac\":");      web_jw_str(w, d->mac);
    web_jw_raw(w, ",\"random\":");   web_jw_raw(w, ok && hit.local ? "true" : "false");
    web_jw_raw(w, ",\"vendor\":");
    if (hit.found) web_jw_str(w, hit.name);
    else jw_text_or_null(w, d->vendor);
    web_jw_raw(w, ",\"vendor_src\":");
    web_jw_raw(w, hit.found ? "\"oui\"" : d->vendor[0] ? "\"sloth\"" : "null");
    web_jw_raw(w, ",\"ip\":");       jw_text_or_null(w, d->ip);
    char nbuf[WEB_PTR_NAME_MAX + 1];
    const char *glyph;
    const char *name = best_name(m, d, now_s, nbuf, &glyph);
    web_jw_raw(w, ",\"name\":");     jw_text_or_null(w, name);
    web_jw_raw(w, ",\"name_src\":"); jw_text_or_null(w, glyph);
    web_jw_raw(w, ",\"ssid\":");     web_jw_ssid(w, d->ssid);
    web_jw_raw(w, ",\"signal\":");
    if (d->has_signal) web_jw_int(w, d->signal_dbm); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"sources\":");  web_jw_int(w, d->sources & 0xffff);
    web_jw_raw(w, ",\"is_ap\":");    web_jw_raw(w, d->is_ap ? "true" : "false");
    web_jw_raw(w, ",\"risk\":");
    web_jw_int(w, d->risk < 0 ? 0 : d->risk > 9 ? 9 : d->risk);
    web_jw_raw(w, ",\"risk_signals\":"); web_jw_int(w, d->risk_signals & 0xffff);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, d->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, d->last_seen);
    double z;
    web_jw_raw(w, ",\"z\":");
    if (m->anomaly && web_anomaly_device_z(m->anomaly, d->mac, now_s, &z))
        jw_real1(w, z);
    else
        web_jw_raw(w, "null");
    web_jw_raw(w, ",\"anomalies\":");
    web_jw_int(w, m->anomaly ? web_anomaly_key_count(m->anomaly, d->mac, -1) : 0);
    web_jw_raw(w, ",\"presence\":");
    if (bits) {
        char hx[WEB_DEV_CELLS / 4 + 1];
        web_dev_presence_hex(bits, hx);
        web_jw_str(w, hx);
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_ssid_meta(w, "ssid", d->ssid);
    web_jw_raw(w, "}");
}

/* ── /api/devices ────────────────────────────────────────────────────── */

typedef struct {
    web_sdb_dev_t *rows;
    int            n, cap;
} collect_t;

static int collect(void *ctx, const web_sdb_dev_t *d) {
    collect_t *c = ctx;
    if (c->n >= c->cap) return 1;
    c->rows[c->n++] = *d;
    return 0;
}

static int sdb_unavailable(const web_m4_t *m, char *body, size_t cap,
                           size_t *len, int *status, const char *err) {
    web_sdb_stats_t st;
    web_slothdb_stats(m->sdb, &st);
    char r[48];
    snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
    return answer_error(503, r, err, body, cap, len, status);
}

int web_devices_route(const web_m4_t *m, const char *query, long long now_s,
                      char *body, size_t cap, size_t *len, int *status) {
    char err[64] = "";
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    dparam_t ps[5] = {
        { "q", WEB_Q_LEN, 1, "", 0 }, { "sort", 8, 0, "", 0 },
        { "limit", 8, 0, "", 0 }, { "offset", 8, 0, "", 0 },
        { "dir", 8, 0, "", 0 },
    };
    if (dparams(query, ps, 5, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    int sort = WEB_QS_LAST, dir = WEB_SORT_DEFAULT;
    if (ps[1].seen && (sort = web_query_sort_find(ps[1].val)) < 0)
        return answer_error(400, "bad_sort", NULL, body, cap, len, status);
    if (ps[4].seen && (dir = web_sort_dir_find(ps[4].val)) < 0)
        return answer_error(400, "bad_dir", NULL, body, cap, len, status);
    long long limit = WEB_DEV_LIMIT, offset = 0;
    if (ps[2].seen && (decimal(ps[2].val, WEB_DEV_LIMIT_MAX, &limit) != 0 ||
                       limit < 1))
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    web_query_t *q = malloc(sizeof(*q));
    if (!q) return -1;
    if (web_query_parse(ps[0].val, now_s, q, err, sizeof(err)) != 0) {
        free(q);
        return answer_error(400, err, NULL, body, cap, len, status);
    }
    collect_t c = { calloc((size_t)limit + 1, sizeof(web_sdb_dev_t)), 0,
                    (int)limit + 1 };
    if (!c.rows) { free(q); return -1; }
    web_sdb_conn_t conn;
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                         sizeof(oerr)) != 0) {
        web_slothdb_close(&conn);
        free(q);
        free(c.rows);
        return sdb_unavailable(m, body, cap, len, status, oerr);
    }
    const char *fail_why = "error";
    int got = web_sdb_devices(&conn, q, WEB_SORT_PACK(sort, dir), limit + 1,
                              offset, collect, &c, &fail_why);
    int schema = conn.schema;
    web_slothdb_close(&conn);      /* before any rendering: no held read */
    free(q);
    if (got < 0) {
        free(c.rows);
        return answer_error(503, !strcmp(fail_why, "timeout")
                                 ? "sloth_db_timeout" : "sloth_db_error",
                            NULL, body, cap, len, status);
    }
    int show = c.n > limit ? (int)limit : c.n;
    char (*macs)[WEB_KEY_MAX + 1] = calloc((size_t)(show ? show : 1), sizeof(*macs));
    unsigned char *bits = calloc((size_t)(show ? show : 1), WEB_DEV_CELLS / 8);
    if (!macs || !bits) { free(macs); free(bits); free(c.rows); return -1; }
    for (int i = 0; i < show; i++)
        snprintf(macs[i], sizeof(macs[i]), "%s", c.rows[i].mac);
    strips(m, (const char (*)[WEB_KEY_MAX + 1])macs, show, now_s, bits);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");     web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"q\":");       web_jw_str(&w, ps[0].val);
    static const char *const SORT[WEB_QS_COUNT] = { "last", "first", "mac",
        "risk", "vendor", "ip", "ssid", "signal", "sources" };
    web_jw_raw(&w, ",\"sort\":");    web_jw_str(&w, SORT[sort]);
    web_jw_raw(&w, ",\"limit\":");   web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":");  web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, schema);
    web_jw_raw(&w, ",\"vendor_table\":"); web_jw_str(&w, vendor_table(m));
    web_jw_raw(&w, ",\"presence_from\":"); web_jw_int(&w, strip_from(now_s));
    web_jw_raw(&w, ",\"presence_cell_s\":"); web_jw_int(&w, WEB_DEV_CELL_S);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = 0; i < show; i++) {
        /* Room for this row and the tail, or stop here with "more". */
        if (w.len + WEB_DEV_ROW_MAX + 96 > cap) break;
        if (i) web_jw_raw(&w, ",");
        dev_json(&w, m, &c.rows[i], bits + (size_t)i * (WEB_DEV_CELLS / 8), now_s);
        shown++;
    }
    int more = shown < c.n;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");     web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    /* Only when asked for: an answer without dir is as it always was. */
    if (dir != WEB_SORT_DEFAULT)
        web_jw_raw(&w, dir == WEB_SORT_ASC ? ",\"dir\":\"asc\"" : ",\"dir\":\"desc\"");
    web_jw_raw(&w, "}\n");
    free(macs);
    free(bits);
    free(c.rows);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/history/devices (M5, #163) ────────────────────────────────── */

int web_history_devices_route(const web_m4_t *m, const char *query,
                              long long now_s, char *body, size_t cap,
                              size_t *len, int *status) {
    char err[64] = "";
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    dparam_t ps[4] = {
        { "from", 11, 0, "", 0 }, { "to", 11, 0, "", 0 },
        { "limit", 8, 0, "", 0 }, { "offset", 8, 0, "", 0 },
    };
    if (dparams(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long from, to;
    const char *why;
    if (web_hist_range(ps[0].seen ? ps[0].val : NULL, ps[1].seen ? ps[1].val : NULL,
                       now_s, &from, &to, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    long long limit = WEB_DEV_LIMIT, offset = 0;
    if (ps[2].seen && (decimal(ps[2].val, WEB_DEV_LIMIT_MAX, &limit) != 0 ||
                       limit < 1))
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    collect_t c = { calloc((size_t)limit + 1, sizeof(web_sdb_dev_t)), 0,
                    (int)limit + 1 };
    if (!c.rows) return -1;
    web_sdb_conn_t conn;
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                         sizeof(oerr)) != 0) {
        web_slothdb_close(&conn);
        free(c.rows);
        return sdb_unavailable(m, body, cap, len, status, oerr);
    }
    int got = web_sdb_devices_between(&conn, from, to, limit + 1, offset,
                                      collect, &c);
    int to_out = conn.timed_out, schema = conn.schema;
    web_slothdb_close(&conn);
    if (got < 0) {
        free(c.rows);
        return answer_error(503, to_out ? "sloth_db_timeout" : "sloth_db_error",
                            NULL, body, cap, len, status);
    }
    /* The strip over the range itself and nothing past it: at most 144
     * cells, each a whole number of the steps of the tier that still
     * holds the range, as /api/wifi/channels chooses one. The minute
     * tier is kept --web-retain-days; a range reaching further back
     * reads the hour tier (kept 400 d) as well, in cells of whole
     * hours. The last cell may be short: it ends at to. */
    int store_on = m->tsdb && m->tsdb->store && m->tsdb->store->rd;
    int hour = store_on && from < now_s - (long long)m->tsdb->retain_days * 86400;
    long long step = hour ? 3600 : 60;
    /* On the hour tier the cells start on the hour: an hour row stands
     * for [t, t+3600), so a strip starting mid-hour would drop the row
     * covering its start (the store keeps r.t >= origin) and file each
     * later row one cell early. The origin is reported as presence_from.
     * Minute cells keep from, as the minute tests pin. */
    long long origin = hour ? from - ((from % 3600) + 3600) % 3600 : from;
    long long span = to - origin;
    long long cell = (span + WEB_DEV_CELLS - 1) / WEB_DEV_CELLS;
    cell = (cell + step - 1) / step * step;
    int ncell = (int)((span + cell - 1) / cell);
    int show = c.n > limit ? (int)limit : c.n;
    char (*macs)[WEB_KEY_MAX + 1] = calloc((size_t)(show ? show : 1), sizeof(*macs));
    unsigned char *bits = calloc((size_t)(show ? show : 1), WEB_DEV_CELLS / 8);
    if (!macs || !bits) { free(macs); free(bits); free(c.rows); return -1; }
    for (int i = 0; i < show; i++)
        snprintf(macs[i], sizeof(macs[i]), "%s", c.rows[i].mac);
    strips_at(m, (const char (*)[WEB_KEY_MAX + 1])macs, show, origin, to, ncell,
              (int)cell, hour, bits);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");     web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"from\":");    web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");      web_jw_int(&w, to);
    web_jw_raw(&w, ",\"limit\":");   web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":");  web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, schema);
    web_jw_raw(&w, ",\"vendor_table\":"); web_jw_str(&w, vendor_table(m));
    web_jw_raw(&w, ",\"presence_from\":"); web_jw_int(&w, origin);
    web_jw_raw(&w, ",\"presence_cell_s\":"); web_jw_int(&w, cell);
    web_jw_raw(&w, ",\"presence_cells\":"); web_jw_int(&w, ncell);
    web_jw_raw(&w, ",\"presence_tier\":"); web_jw_str(&w, hour ? "hour" : "minute");
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = 0; i < show; i++) {
        if (w.len + WEB_DEV_ROW_MAX + 96 > cap) break;
        if (i) web_jw_raw(&w, ",");
        dev_json(&w, m, &c.rows[i], bits + (size_t)i * (WEB_DEV_CELLS / 8), now_s);
        shown++;
    }
    int more = shown < c.n;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");     web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    web_jw_raw(&w, "}\n");
    free(macs);
    free(bits);
    free(c.rows);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/device/{mac} and /api/lookup ───────────────────────────────── */

#define DEV_NAMES   12
#define DEV_SSIDS   24
#define DEV_ASSOCS  12
#define DEV_IPS     8
#define DEV_ANOMS   8
#define DEV_ALERTS  12

typedef struct {
    web_jw_t  *w;
    int        n, max, kind;
    const char *src;      /* names: the source word for stream names */
} emit_t;

enum { EK_SSID, EK_ASSOC, EK_ADDR, EK_NAME, EK_ALERT };

static int emit_item(void *ctx, const web_sdb_item_t *it) {
    emit_t *e = ctx;
    if (e->n >= e->max) return 1;
    web_jw_t *w = e->w;
    if (e->n++) web_jw_raw(w, ",");
    switch (e->kind) {
    case EK_SSID:
        web_jw_raw(w, "{\"ssid\":"); web_jw_ssid(w, it->a);
        web_jw_ssid_meta(w, "ssid", it->a);
        break;
    case EK_ASSOC:
        web_jw_raw(w, "{\"bssid\":"); web_jw_str(w, it->a);
        web_jw_raw(w, ",\"ssid\":");  web_jw_ssid(w, it->b);
        web_jw_raw(w, ",\"source\":"); web_jw_int(w, it->n1 & 0xffff);
        web_jw_raw(w, ",\"channel\":"); web_jw_int(w, it->n2 & 0xffff);
        web_jw_raw(w, ",\"signal\":");
        if (it->has_n3) web_jw_int(w, it->n3 < -200 ? -200 : it->n3 > 50 ? 50 : it->n3);
        else web_jw_raw(w, "null");
        web_jw_ssid_meta(w, "ssid", it->b);
        break;
    case EK_ADDR:
        web_jw_raw(w, "{\"addr\":"); web_jw_str(w, it->a);
        break;
    case EK_NAME:
        web_jw_raw(w, "{\"name\":"); web_jw_str(w, it->a);
        web_jw_raw(w, ",\"src\":");  web_jw_str(w, it->b);
        web_jw_raw(w, ",\"where\":\"sloth.db\"");
        break;
    default:
        web_jw_raw(w, "{\"title\":"); web_jw_str(w, it->a);
        web_jw_raw(w, ",\"type\":");  web_jw_int(w, it->n1 & 0xffff);
        web_jw_raw(w, ",\"sev\":");   web_jw_int(w, it->n2 < 0 ? 0 : it->n2 > 3 ? 3 : it->n2);
        web_jw_raw(w, ",\"count\":"); web_jw_int(w, it->has_n3 && it->n3 > 0 ? it->n3 : 0);
        break;
    }
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, it->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, it->last_seen);
    web_jw_raw(w, "}");
    return 0;
}

/* A list member from a sloth.db read: [] when there is no connection,
 * and "<name>_more":true when the cap cut it. */
static void sdb_list(web_jw_t *w, const char *name, web_sdb_conn_t *c,
                     int kind, int max,
                     int (*rd)(web_sdb_conn_t *, const char *, int,
                               web_sdb_item_fn, void *),
                     const char *arg) {
    web_jw_raw(w, ",");
    web_jw_key(w, name);
    web_jw_raw(w, "[");
    emit_t e = { w, 0, max, kind, NULL };
    int got = c && c->db && arg && arg[0] ? rd(c, arg, max + 1, emit_item, &e) : 0;
    web_jw_raw(w, "]");
    char more[48];
    snprintf(more, sizeof(more), "%s_more", name);
    web_jw_raw(w, ",");
    web_jw_key(w, more);
    web_jw_raw(w, got > max ? "true" : "false");
}

/* The stream's and the PTR cache's names of ip, after sloth.db's. */
static void stream_names(web_jw_t *w, const web_m4_t *m, const char *ip,
                         long long now_s, int *n) {
    if (!ip || !ip[0]) return;
    char mac[WEB_KEY_MAX + 1];
    web_id_name_t nm[WEB_ID_SRC_COUNT];
    if (m->ident && web_ident_ip_info(m->ident, ip, now_s, mac, nm))
        for (int s = 0; s < WEB_ID_SRC_COUNT && *n < DEV_NAMES; s++) {
            if (!nm[s].name[0]) continue;
            if ((*n)++) web_jw_raw(w, ",");
            web_jw_raw(w, "{\"name\":"); web_jw_str(w, nm[s].name);
            web_jw_raw(w, ",\"src\":");  web_jw_str(w, web_ident_src_name(s));
            web_jw_raw(w, ",\"where\":\"stream\",\"first_seen\":null,\"last_seen\":");
            web_jw_int(w, nm[s].t);
            web_jw_raw(w, "}");
        }
    char pn[WEB_PTR_NAME_MAX + 1];
    long long pt;
    if (m->ptr && *n < DEV_NAMES && web_ptr_get(m->ptr, ip, pn, &pt)) {
        if ((*n)++) web_jw_raw(w, ",");
        web_jw_raw(w, "{\"name\":"); web_jw_str(w, pn);
        web_jw_raw(w, ",\"src\":\"ptr\",\"where\":\"wire\",\"first_seen\":null,"
                      "\"last_seen\":");
        web_jw_int(w, pt);
        web_jw_raw(w, "}");
    }
}

static void names_member(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *c,
                         const char *ip, long long now_s) {
    web_jw_raw(w, ",\"names\":[");
    emit_t e = { w, 0, DEV_NAMES, EK_NAME, NULL };
    if (c && c->db && ip && ip[0]) web_sdb_names(c, ip, DEV_NAMES, emit_item, &e);
    int n = e.n;
    stream_names(w, m, ip, now_s, &n);
    web_jw_raw(w, "]");
}

static void oui_member(web_jw_t *w, const web_m4_t *m, const char *mac) {
    uint8_t b[6];
    web_oui_hit_t hit;
    web_jw_raw(w, ",\"oui\":");
    if (web_oui_mac_bytes(mac, b) != 0) { web_jw_raw(w, "null"); return; }
    web_oui_lookup(m->oui, b, &hit);
    static const char *const REG[] = { "MA-L", "MA-M", "MA-S" };
    web_jw_raw(w, "{\"found\":");     web_jw_raw(w, hit.found ? "true" : "false");
    web_jw_raw(w, ",\"vendor\":");    jw_text_or_null(w, hit.found ? hit.name : NULL);
    web_jw_raw(w, ",\"block\":");     jw_text_or_null(w, hit.found ? hit.block : NULL);
    web_jw_raw(w, ",\"bits\":");
    if (hit.found) web_jw_int(w, hit.bits); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"registry\":");
    if (hit.found) web_jw_str(w, REG[hit.cls]); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"private\":");   web_jw_raw(w, hit.private_ ? "true" : "false");
    web_jw_raw(w, ",\"local\":");     web_jw_raw(w, hit.local ? "true" : "false");
    web_jw_raw(w, ",\"multicast\":"); web_jw_raw(w, hit.multicast ? "true" : "false");
    web_jw_raw(w, ",\"table\":");     web_jw_str(w, vendor_table(m));
    web_jw_raw(w, ",\"full\":");      web_jw_raw(w, web_oui_full(m->oui) ? "true" : "false");
    web_jw_raw(w, "}");
}

/* Seconds east of UTC at t (tm_gmtoff is not C99), as web_series.c. */
static long long utc_offset(long long t) {
    time_t tt = (time_t)t;
    struct tm lt, gt;
    if (!localtime_r(&tt, &lt) || !gmtime_r(&tt, &gt)) return 0;
    long long d = lt.tm_yday - gt.tm_yday;
    if (lt.tm_year != gt.tm_year) d = lt.tm_year > gt.tm_year ? 1 : -1;
    return ((d * 24 + (lt.tm_hour - gt.tm_hour)) * 60 +
            (lt.tm_min - gt.tm_min)) * 60 + (lt.tm_sec - gt.tm_sec);
}

/* The 168 hour-of-week cells of dev.present for mac, [share, n] each
 * (the share of weeks it was present in that local hour), or null. */
static void week_member(web_jw_t *w, const web_m4_t *m, const char *mac,
                        long long now_s) {
    web_jw_raw(w, ",\"week\":{\"now_cell\":");
    web_jw_int(w, web_bl_cell_index(now_s - now_s % 3600));
    web_jw_raw(w, ",\"utc_offset_s\":"); web_jw_int(w, utc_offset(now_s));
    web_jw_raw(w, ",\"warm_n\":");       web_jw_int(w, WEB_BL_WARM_N);
    web_jw_raw(w, ",\"cells\":");
    web_baseline_t *bl = m->anomaly ? m->anomaly->cfg.bl : NULL;
    web_bl_cell_t *cells = bl ? malloc(WEB_BL_CELLS * sizeof(*cells)) : NULL;
    if (!cells || web_baseline_cells(bl, WM_DEV_PRESENT, mac, cells) != 0) {
        web_jw_raw(w, "null}");
        free(cells);
        return;
    }
    web_jw_raw(w, "[");
    for (int i = 0; i < WEB_BL_CELLS; i++) {
        web_jw_raw(w, i ? ",[" : "[");
        double v = cells[i].n ? cells[i].mean : 0;
        char b[24];
        snprintf(b, sizeof(b), "%.3f", isfinite(v) ? (v < 0 ? 0 : v > 1 ? 1 : v) : 0);
        web_jw_raw(w, b);
        web_jw_raw(w, ",");
        web_jw_int(w, cells[i].n);
        web_jw_raw(w, "]");
    }
    web_jw_raw(w, "]}");
    free(cells);
}

static int canon_mac(const char *in, char *out) {
    char t[24];
    size_t n = strlen(in);
    if (n != 17) return -1;
    for (size_t i = 0; i < n; i++) t[i] = in[i] == '-' ? ':' : in[i];
    t[n] = '\0';
    return web_key_mac(t, out);
}

int web_device_route(const web_m4_t *m, const char *path_mac,
                     const char *query, long long now_s, char *body,
                     size_t cap, size_t *len, int *status) {
    if (query && query[0])
        return answer_error(400, "unknown_parameter", NULL, body, cap, len, status);
    /* The path segment, percent-decoded (the page sends
     * encodeURIComponent(mac), so ':' arrives as %3A). */
    char raw[24];
    size_t o = 0;
    for (const char *p = path_mac; *p; p++) {
        int c = (unsigned char)*p;
        if (c == '%') {
            int h = hexv((unsigned char)p[1]), l = h >= 0 ? hexv((unsigned char)p[2]) : -1;
            if (h < 0 || l < 0)
                return answer_error(400, "bad_escape", NULL, body, cap, len, status);
            c = h * 16 + l;
            p += 2;
        }
        if (o >= sizeof(raw) - 1)
            return answer_error(400, "bad_mac", NULL, body, cap, len, status);
        raw[o++] = (char)c;
    }
    raw[o] = '\0';
    char mac[WEB_KEY_MAX + 1];
    if (canon_mac(raw, mac) != 0)
        return answer_error(400, "bad_mac", NULL, body, cap, len, status);

    web_sdb_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    char oerr[WEB_SDB_ERR_MAX] = "";
    int have_db = m->sdb && m->sdb->configured &&
                  web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                                   sizeof(oerr)) == 0;
    web_sdb_dev_t d;
    int found = have_db ? web_sdb_device(&conn, mac, &d) : 0;
    if (found < 0) found = 0;
    char sip[WEB_KEY_MAX + 1] = "";
    web_id_name_t sdhcp;
    memset(&sdhcp, 0, sizeof(sdhcp));
    long long sfs = -1;
    if (m->ident) web_ident_mac_info(m->ident, mac, now_s, sip, &sdhcp, &sfs);
    const char *ip = found && d.ip[0] ? d.ip : sip;

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"mac\":");  web_jw_str(&w, mac);
    web_jw_raw(&w, ",\"now\":");  web_jw_int(&w, now_s);
    web_sdb_stats_t sst;
    memset(&sst, 0, sizeof(sst));
    if (m->sdb) web_slothdb_stats(m->sdb, &sst);
    web_jw_raw(&w, ",\"db\":");
    web_jw_str(&w, have_db ? "open" : m->sdb && m->sdb->configured
                   ? web_slothdb_state_word(sst.state) : "none");
    web_jw_raw(&w, ",\"db_error\":");
    jw_text_or_null(&w, have_db ? NULL : oerr);
    oui_member(&w, m, mac);
    web_jw_raw(&w, ",\"record\":");
    if (found) {
        dev_json(&w, m, &d, NULL, now_s);
        web_jw_raw(&w, ",\"detail\":{\"hostname\":");
        jw_text_or_null(&w, d.hostname);
        web_jw_raw(&w, ",\"device_class\":");
        web_jw_int(&w, d.device_class < 0 ? 0 : d.device_class > 9 ? 9 : d.device_class);
        web_jw_raw(&w, ",\"camera_vendor\":"); jw_text_or_null(&w, d.camera_vendor);
        web_jw_raw(&w, ",\"camera_model\":");  jw_text_or_null(&w, d.camera_model);
        web_jw_raw(&w, ",\"dhcp_vci\":");      jw_text_or_null(&w, d.dhcp_vci);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, ",\"stream\":{\"ip\":"); jw_text_or_null(&w, sip);
    web_jw_raw(&w, ",\"first_seen\":");
    if (sfs >= 0) web_jw_int(&w, sfs); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"hostname\":");       jw_text_or_null(&w, sdhcp.name);
    web_jw_raw(&w, "}");
    names_member(&w, m, have_db ? &conn : NULL, ip, now_s);
    sdb_list(&w, "ssids", have_db ? &conn : NULL, EK_SSID, DEV_SSIDS,
             web_sdb_ssids, mac);
    sdb_list(&w, "assocs", have_db ? &conn : NULL, EK_ASSOC, DEV_ASSOCS,
             web_sdb_assocs, mac);
    sdb_list(&w, "ips", have_db ? &conn : NULL, EK_ADDR, DEV_IPS,
             web_sdb_arp_mac, mac);
    web_jw_raw(&w, ",\"alerts\":[");
    emit_t ea = { &w, 0, DEV_ALERTS, EK_ALERT, NULL };
    int ga = have_db ? web_sdb_alerts(&conn, mac, ip, DEV_ALERTS + 1, emit_item, &ea) : 0;
    web_jw_raw(&w, "],\"alerts_more\":");
    web_jw_raw(&w, ga > DEV_ALERTS ? "true" : "false");
    web_slothdb_close(&conn);

    unsigned char bits[WEB_DEV_CELLS / 8];
    char macs[1][WEB_KEY_MAX + 1];
    snprintf(macs[0], sizeof(macs[0]), "%s", mac);
    strips(m, (const char (*)[WEB_KEY_MAX + 1])macs, 1, now_s, bits);
    char hx[WEB_DEV_CELLS / 4 + 1];
    web_dev_presence_hex(bits, hx);
    web_jw_raw(&w, ",\"presence\":");      web_jw_str(&w, hx);
    web_jw_raw(&w, ",\"presence_from\":"); web_jw_int(&w, strip_from(now_s));
    week_member(&w, m, mac, now_s);
    web_jw_raw(&w, ",\"anomalies\":[");
    if (m->anomaly) {
        web_anom_ep_t eps[DEV_ANOMS];
        int ne = web_anomaly_key_list(m->anomaly, mac, eps, DEV_ANOMS);
        for (int i = 0; i < ne; i++) {
            if (i) web_jw_raw(&w, ",");
            web_anomaly_ep_json(&w, &eps[i]);
        }
    }
    web_jw_raw(&w, "]}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

static int first_addr(void *ctx, const web_sdb_item_t *it) {
    char *out = ctx;
    char k[WEB_KEY_MAX + 1];
    if (!out[0] && web_key_mac(it->a, k) == 0) snprintf(out, WEB_KEY_MAX + 1, "%s", k);
    return 1;
}

int web_lookup_route(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status) {
    char err[64] = "";
    dparam_t ps[1] = { { "q", 63, 0, "", 0 } };
    if (dparams(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return answer_error(400, "missing_q", NULL, body, cap, len, status);
    char key[WEB_KEY_MAX + 1];
    int is_mac = canon_mac(ps[0].val, key) == 0;
    if (!is_mac && web_key_ip(ps[0].val, key) != 0)
        return answer_error(400, "bad_lookup", NULL, body, cap, len, status);

    web_sdb_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    char oerr[WEB_SDB_ERR_MAX] = "";
    int have_db = m->sdb && m->sdb->configured &&
                  web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                                   sizeof(oerr)) == 0;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"q\":");     web_jw_str(&w, key);
    web_jw_raw(&w, ",\"kind\":");  web_jw_str(&w, is_mac ? "mac" : "ip");
    web_jw_raw(&w, ",\"now\":");   web_jw_int(&w, now_s);
    web_sdb_stats_t sst;
    memset(&sst, 0, sizeof(sst));
    if (m->sdb) web_slothdb_stats(m->sdb, &sst);
    web_jw_raw(&w, ",\"db\":");
    web_jw_str(&w, have_db ? "open" : m->sdb && m->sdb->configured
                   ? web_slothdb_state_word(sst.state) : "none");
    web_jw_raw(&w, ",\"active\":false");   /* there is no active lookup */

    char mac[WEB_KEY_MAX + 1] = "", ip[WEB_KEY_MAX + 1] = "";
    if (is_mac) {
        snprintf(mac, sizeof(mac), "%s", key);
        oui_member(&w, m, mac);
        sdb_list(&w, "ips", have_db ? &conn : NULL, EK_ADDR, DEV_IPS,
                 web_sdb_arp_mac, mac);
    } else {
        snprintf(ip, sizeof(ip), "%s", key);
        web_jw_raw(&w, ",\"oui\":null");
        sdb_list(&w, "macs", have_db ? &conn : NULL, EK_ADDR, DEV_IPS,
                 web_sdb_arp_ip, ip);
    }
    /* The device: by MAC, or the IP's ARP MAC (sloth.db's, else the
     * stream's binding). */
    web_sdb_dev_t d;
    int found = 0;
    if (!is_mac && have_db)
        web_sdb_arp_ip(&conn, ip, 1, first_addr, mac);
    if (!is_mac && !mac[0]) {
        web_id_name_t nm[WEB_ID_SRC_COUNT];
        char smac[WEB_KEY_MAX + 1] = "";
        if (m->ident) web_ident_ip_info(m->ident, ip, now_s, smac, nm);
        if (smac[0]) snprintf(mac, sizeof(mac), "%s", smac);
    }
    if (have_db && mac[0]) found = web_sdb_device(&conn, mac, &d) == 1;
    if (is_mac && found && d.ip[0]) snprintf(ip, sizeof(ip), "%s", d.ip);
    if (is_mac && !ip[0] && m->ident) {
        web_id_name_t dh;
        long long fs;
        web_ident_mac_info(m->ident, mac, now_s, ip, &dh, &fs);
    }
    names_member(&w, m, have_db ? &conn : NULL, ip, now_s);
    web_slothdb_close(&conn);
    web_jw_raw(&w, ",\"device\":");
    if (found) dev_json(&w, m, &d, NULL, now_s); else web_jw_raw(&w, "null");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── health ──────────────────────────────────────────────────────────── */

void web_m4_health(const web_m4_t *m, long long now_s, web_jw_t *w) {
    web_jw_raw(w, ",\"db\":");
    if (!m || !m->sdb || !m->sdb->configured) {
        web_jw_raw(w, "\"none\",\"db_schema\":null,\"db_rows\":null");
    } else {
        web_slothdb_check(m->sdb, now_s);
        web_sdb_stats_t st;
        web_slothdb_stats(m->sdb, &st);
        web_jw_str(w, web_slothdb_state_word(st.state));
        web_jw_raw(w, ",\"db_schema\":");
        if (st.state == WEB_SDB_OPEN) web_jw_int(w, st.schema); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"db_rows\":");
        if (st.state == WEB_SDB_OPEN && st.rows >= 0) web_jw_int(w, st.rows);
        else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"db_path\":");
        web_jw_strn(w, m->sdb->path, strnlen(m->sdb->path, 256));
        web_jw_raw(w, ",\"db_mode\":"); jw_text_or_null(w, st.mode);
        web_jw_raw(w, ",\"db_error\":"); jw_text_or_null(w, st.err);
        web_jw_raw(w, ",\"db_opens\":"); web_jw_int(w, (long long)st.opens);
        web_jw_raw(w, ",\"db_timeouts\":"); web_jw_int(w, (long long)st.timeouts);
    }
    web_jw_raw(w, ",\"db_supported\":[");
    web_jw_int(w, WEB_SDB_SCHEMA_MIN);
    web_jw_raw(w, ",");
    web_jw_int(w, WEB_SDB_SCHEMA_MAX);
    web_jw_raw(w, "]");
    if (!m) return;
    web_jw_raw(w, ",\"vendor_table\":"); web_jw_str(w, vendor_table(m));
    web_jw_raw(w, ",\"vendor_counts\":{\"ma_l\":");
    web_jw_int(w, m->oui ? m->oui->counts[WEB_OUI_MAL] : 0);
    web_jw_raw(w, ",\"ma_m\":"); web_jw_int(w, m->oui ? m->oui->counts[WEB_OUI_MAM] : 0);
    web_jw_raw(w, ",\"ma_s\":"); web_jw_int(w, m->oui ? m->oui->counts[WEB_OUI_MAS] : 0);
    web_jw_raw(w, "}");
    web_jw_raw(w, ",\"a4\":");
    const char *r = m->anomaly ? web_anomaly_a4_reason(m->anomaly) : "no anomaly engine";
    web_jw_str(w, r ? r : "on");
    web_jw_raw(w, ",\"passive_ptr\":");
    if (!m->ptr) {
        web_jw_raw(w, "null");
    } else {
        web_ptr_stats_t ps;
        web_ptr_stats(m->ptr, &ps);
        web_jw_raw(w, "{\"entries\":");   web_jw_int(w, ps.n);
        web_jw_raw(w, ",\"cap\":");       web_jw_int(w, ps.cap);
        web_jw_raw(w, ",\"seen\":");      web_jw_int(w, (long long)ps.seen);
        web_jw_raw(w, ",\"stored\":");    web_jw_int(w, (long long)ps.stored);
        web_jw_raw(w, ",\"empty\":");     web_jw_int(w, (long long)ps.empty);
        web_jw_raw(w, ",\"refused\":");   web_jw_int(w, (long long)ps.refused);
        web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)ps.evictions);
        web_jw_raw(w, ",\"db_evictions\":"); web_jw_int(w, (long long)ps.db_evictions);
        web_jw_raw(w, ",\"persist_errors\":"); web_jw_int(w, (long long)ps.persist_errors);
        web_jw_raw(w, "}");
    }
}
