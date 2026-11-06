#include "web_rfhist.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "web_gnss.h"
#include "web_gnssmeta.h"
#include "web_json.h"
#include "web_series.h"
#include "web_slothdb.h"

#define DAY_S 86400LL

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

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    if (!s || !*s || strlen(s) > 12) return -1;
    long long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

static void jw_num(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static void jw_int_or_null(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

/* `~`? and six lower-case hex digits: sloth's spelling (web_adsb.h). */
static int hex_ok(const char *s) {
    if (!s) return 0;
    if (*s == '~') s++;
    for (int i = 0; i < 6; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return s[6] == '\0';
}

/* The open, the 503s and the close every route shares. */
static int open_sdb(const web_m4_t *m, web_sdb_conn_t *conn, long long now_s,
                    char *body, size_t cap, size_t *len, int *status) {
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, conn, WEB_SDB_HTTP_MS, now_s, oerr, sizeof(oerr)) != 0) {
        web_slothdb_close(conn);
        web_sdb_stats_t st;
        web_slothdb_stats(m->sdb, &st);
        char r[48];
        snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
        answer_error(503, r, oerr, body, cap, len, status);
        return -1;
    }
    return 0;
}

static int no_db(const web_m4_t *m, char *body, size_t cap, size_t *len, int *status) {
    if (m && m->sdb && m->sdb->configured && web_slothdb_available()) return 0;
    answer_error(503, "no_sloth_db",
                 "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                 body, cap, len, status);
    return 1;
}

/* ── /api/gnss/seen ─────────────────────────────────────────────────── */

typedef struct { web_jw_t *w; int n, limit, cut; } gsat_ctx_t;

static int emit_gsat(void *ctx, const web_sdb_gsat_t *g) {
    gsat_ctx_t *k = ctx;
    if (k->n >= k->limit) { k->cut = 1; return 1; }
    web_jw_t *w = k->w;
    if (k->n++) web_jw_raw(w, ",");
    int gid = g->gnssid >= 0 && g->gnssid <= 7 ? g->gnssid : 8;
    web_jw_raw(w, "{\"gnss\":"); web_jw_str(w, web_gnss_name(gid));
    web_jw_raw(w, ",\"gnssid\":"); web_jw_int(w, g->gnssid);
    web_jw_raw(w, ",\"prn\":"); web_jw_int(w, g->prn);
    web_jw_raw(w, ",\"svid\":"); jw_int_or_null(w, g->svid >= 0, g->svid);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, g->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, g->last_seen);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, g->records);
    web_jw_raw(w, ",\"used_pct\":");
    jw_num(w, g->records > 0, 100.0 * (double)g->used_n / (double)(g->records > 0 ? g->records : 1), 0);
    web_jw_raw(w, ",\"cn0_max\":"); jw_num(w, g->has_cn0, g->cn0_max, 1);
    web_jw_raw(w, ",\"cn0_mean\":");
    jw_num(w, g->cn0_n > 0, g->cn0_sum / (double)(g->cn0_n > 0 ? g->cn0_n : 1), 1);
    web_jw_raw(w, ",\"el_max\":"); jw_int_or_null(w, g->has_el, g->el_max);
    web_gnss_ident_json(w, g->gnssid, g->svid, g->prn, g->last_seen);
    web_jw_raw(w, "}");
    return 0;
}

int web_gnss_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "days", "", 0 }, { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days = 1, limit = WEB_RFHIST_SATS_MAX;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_RFHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_RFHIST_SATS_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - days * DAY_S;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"from\":"); web_jw_int(&w, from);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 10 ? "true" : "false");
    web_jw_raw(&w, ",\"sats\":[");
    gsat_ctx_t k = { &w, 0, (int)limit, 0 };
    int n = web_sdb_gnss_seen(&conn, from, limit + 1, emit_gsat, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, ",\"more\":"); web_jw_raw(&w, k.cut ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/gnss/sat ──────────────────────────────────────────────────── */

typedef struct { web_jw_t *w; int n; } pt_ctx_t;

static int emit_gpt(void *ctx, const web_sdb_gpt_t *p) {
    pt_ctx_t *k = ctx;
    web_jw_t *w = k->w;
    if (k->n++) web_jw_raw(w, ",");
    /* [ts, el, az, cn0, used, health]: compact, the page draws many. */
    web_jw_raw(w, "["); web_jw_int(w, p->ts);
    web_jw_raw(w, ","); jw_int_or_null(w, p->has_el, p->el);
    web_jw_raw(w, ","); jw_int_or_null(w, p->has_az, p->az);
    web_jw_raw(w, ","); jw_num(w, p->has_cn0, p->cn0, 1);
    web_jw_raw(w, ","); web_jw_int(w, p->used != 0);
    web_jw_raw(w, ","); jw_int_or_null(w, p->health >= 0, p->health);
    web_jw_raw(w, "]");
    return 0;
}

int web_gnss_sat_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[3] = { { "gnssid", "", 0 }, { "prn", "", 0 }, { "days", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long gnssid, prn, days = 1;
    if (!ps[0].seen || decimal(ps[0].val, 0, 127, &gnssid) != 0)
        return answer_error(400, "bad_gnssid", NULL, body, cap, len, status);
    if (!ps[1].seen || decimal(ps[1].val, 0, 32767, &prn) != 0)
        return answer_error(400, "bad_prn", NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_RFHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - days * DAY_S;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    int gid = gnssid <= 7 ? (int)gnssid : 8;
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"gnss\":"); web_jw_str(&w, web_gnss_name(gid));
    web_jw_raw(&w, ",\"gnssid\":"); web_jw_int(&w, gnssid);
    web_jw_raw(&w, ",\"prn\":"); web_jw_int(&w, prn);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 10 ? "true" : "false");
    web_jw_raw(&w, ",\"cols\":[\"ts\",\"el\",\"az\",\"cn0\",\"used\",\"health\"],\"points\":[");
    pt_ctx_t k = { &w, 0 };
    int n = web_sdb_gnss_sat(&conn, (int)gnssid, (int)prn, from, WEB_RFHIST_PTS_MAX,
                             emit_gpt, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/gnss/tracks ───────────────────────────────────────────────── */

typedef struct { web_jw_t *w; int n, open, gnssid, prn; } trk_ctx_t;

static int emit_trk(void *ctx, const web_sdb_gtrk_t *t) {
    trk_ctx_t *k = ctx;
    web_jw_t *w = k->w;
    if (!k->open || t->gnssid != k->gnssid || t->prn != k->prn) {
        if (k->open) web_jw_raw(w, "]},");
        k->open = 1;
        k->gnssid = t->gnssid;
        k->prn = t->prn;
        k->n++;
        char id[8];
        web_gnss_rinex_id(t->gnssid, t->svid, t->prn, id);
        web_jw_raw(w, "{\"gnssid\":"); web_jw_int(w, t->gnssid);
        web_jw_raw(w, ",\"prn\":"); web_jw_int(w, t->prn);
        web_jw_raw(w, ",\"id\":"); web_jw_str(w, id);
        web_jw_raw(w, ",\"pts\":[");
    } else {
        web_jw_raw(w, ",");
    }
    /* [ts, el, az]: el may be negative (under the horizon, still listed). */
    web_jw_raw(w, "["); web_jw_int(w, t->ts);
    web_jw_raw(w, ","); web_jw_int(w, t->el < -90 ? -90 : t->el > 90 ? 90 : t->el);
    web_jw_raw(w, ","); web_jw_int(w, ((t->az % 360) + 360) % 360);
    web_jw_raw(w, "]");
    return 0;
}

int web_gnss_tracks_route(const web_m4_t *m, const char *query, long long now_s,
                          char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "hours", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long hours = 6;
    if (ps[0].seen && decimal(ps[0].val, 1, 24, &hours) != 0)
        return answer_error(400, "bad_hours", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - hours * 3600;
    long long bucket = hours * 3600 / WEB_RFHIST_TRK_PTS;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"hours\":"); web_jw_int(&w, hours);
    web_jw_raw(&w, ",\"bucket_s\":"); web_jw_int(&w, bucket);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 10 ? "true" : "false");
    web_jw_raw(&w, ",\"tracks\":[");
    trk_ctx_t k = { &w, 0, 0, 0, 0 };
    int n = web_sdb_gnss_tracks(&conn, from, bucket, WEB_RFHIST_TRK_ROWS, emit_trk, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    if (k.open) web_jw_raw(&w, "]}");
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, ",\"points\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"cut\":"); web_jw_raw(&w, n >= WEB_RFHIST_TRK_ROWS ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/adsb/seen and /api/adsb/aircraft ──────────────────────────── */

static void ac_json(web_jw_t *w, const web_sdb_ac_t *a) {
    web_jw_raw(w, "{\"hex\":"); web_jw_str(w, a->hex);
    web_jw_raw(w, ",\"non_icao\":"); web_jw_int(w, a->non_icao != 0);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, a->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, a->last_seen);
    web_jw_raw(w, ",\"visits\":"); web_jw_int(w, a->visits);
    web_jw_raw(w, ",\"sightings\":"); web_jw_int(w, a->sightings);
    web_jw_raw(w, ",\"flight\":"); web_jw_str(w, a->flight);
    web_jw_raw(w, ",\"squawk\":"); web_jw_str(w, a->squawk);
    web_jw_raw(w, ",\"category\":"); web_jw_str(w, a->category);
    web_jw_raw(w, ",\"source_type\":"); web_jw_str(w, a->source_type);
    web_jw_raw(w, ",\"emergency_seen\":"); web_jw_int(w, a->emergency_seen != 0);
    web_jw_raw(w, ",\"alt_min\":"); jw_int_or_null(w, a->has_alt, a->alt_min);
    web_jw_raw(w, ",\"alt_max\":"); jw_int_or_null(w, a->has_alt, a->alt_max);
    web_jw_raw(w, ",\"gs_max\":"); jw_num(w, a->has_gs, a->gs_max, 1);
    web_jw_raw(w, ",\"rssi_max\":"); jw_num(w, a->has_rssi, a->rssi_max, 1);
    web_jw_raw(w, ",\"messages\":"); jw_int_or_null(w, a->has_messages, a->messages);
    web_jw_raw(w, ",\"pos_seen\":"); web_jw_int(w, a->pos_seen != 0);
    web_jw_raw(w, "}");
}

typedef struct { web_jw_t *w; int n, limit, cut; } ac_ctx_t;

static int emit_ac(void *ctx, const web_sdb_ac_t *a) {
    ac_ctx_t *k = ctx;
    if (k->n >= k->limit) { k->cut = 1; return 1; }
    if (k->n++) web_jw_raw(k->w, ",");
    ac_json(k->w, a);
    return 0;
}

int web_adsb_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[4] = { { "days", "", 0 }, { "limit", "", 0 }, { "q", "", 0 },
                          { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days = 7, limit = WEB_RFHIST_AC_MAX, offset = 0;
    if (ps[3].seen && decimal(ps[3].val, 0, WEB_RFHIST_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_RFHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_RFHIST_AC_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    /* q: a hex or callsign prefix, letters and digits (and a leading
     * ~), never a LIKE wildcard; refused rather than stripped. */
    const char *q = ps[2].seen ? ps[2].val : "";
    size_t ql = strlen(q);
    if (ql > 8) return answer_error(400, "bad_q", NULL, body, cap, len, status);
    for (size_t i = 0; i < ql; i++) {
        char ch = q[i];
        int ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') ||
                 (ch >= 'A' && ch <= 'Z') || (ch == '~' && i == 0);
        if (!ok) return answer_error(400, "bad_q", NULL, body, cap, len, status);
    }
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - days * DAY_S;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"from\":"); web_jw_int(&w, from);
    web_jw_raw(&w, ",\"offset\":"); web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"q\":"); web_jw_str(&w, q);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 12 ? "true" : "false");
    web_jw_raw(&w, ",\"aircraft\":[");
    ac_ctx_t k = { &w, 0, (int)limit, 0 };
    int n = web_sdb_adsb_seen(&conn, from, limit + 1, offset, q, emit_ac, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, ",\"more\":"); web_jw_raw(&w, k.cut ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

static int emit_apt(void *ctx, const web_sdb_apt_t *p) {
    pt_ctx_t *k = ctx;
    web_jw_t *w = k->w;
    if (k->n++) web_jw_raw(w, ",");
    /* A compact row, its names in the answer's "cols": the altitude is
     * barometric, else geometric, -1 on the ground, null unknown. */
    int has_alt = p->on_ground || p->has_alt_baro || p->has_alt_geom;
    int alt = p->on_ground ? -1 : p->has_alt_baro ? p->alt_baro : p->alt_geom;
    web_jw_raw(w, "["); web_jw_int(w, p->ts);
    web_jw_raw(w, ","); jw_int_or_null(w, p->heard > 0, p->heard);
    web_jw_raw(w, ","); jw_int_or_null(w, has_alt, alt);
    web_jw_raw(w, ","); jw_num(w, p->has_pos, p->lat, 5);
    web_jw_raw(w, ","); jw_num(w, p->has_pos, p->lon, 5);
    web_jw_raw(w, ","); jw_num(w, p->has_gs, p->gs, 0);
    web_jw_raw(w, ","); jw_num(w, p->has_track, p->track, 0);
    web_jw_raw(w, ","); jw_int_or_null(w, p->has_rate, p->rate);
    web_jw_raw(w, ","); jw_num(w, p->has_rssi, p->rssi, 1);
    web_jw_raw(w, ","); web_jw_str(w, p->squawk);
    web_jw_raw(w, ","); web_jw_str(w, p->flight);
    web_jw_raw(w, ","); web_jw_str(w, p->emergency);
    web_jw_raw(w, "]");
    return 0;
}

int web_adsb_aircraft_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "hex", "", 0 }, { "days", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days = 7;
    if (!ps[0].seen || !hex_ok(ps[0].val))
        return answer_error(400, "bad_hex", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_RFHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - days * DAY_S;
    web_sdb_ac_t a;
    int found = web_sdb_adsb_one(&conn, ps[0].val, &a);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"hex\":"); web_jw_str(&w, ps[0].val);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 12 ? "true" : "false");
    web_jw_raw(&w, ",\"aircraft\":");
    if (found > 0) ac_json(&w, &a); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"cols\":[\"ts\",\"heard\",\"alt\",\"lat\",\"lon\",\"gs\",\"track\","
                   "\"rate\",\"rssi\",\"squawk\",\"flight\",\"emergency\"],\"sightings\":[");
    pt_ctx_t k = { &w, 0 };
    int n = found < 0 ? -1
          : web_sdb_adsb_track(&conn, ps[0].val, from, WEB_RFHIST_PTS_MAX, emit_apt, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
