#include "web_positions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_history.h"
#include "web_json.h"
#include "web_metrics.h"
#include "web_series.h"

/* Contract in web_positions.h. */

typedef struct {
    long long ts;
    double    lat, lon;
    int       has_acc, has_alt, has_rssi;
    double    acc_m, alt_m;
    int       rssi;
} pos_t;

const char *web_positions_ctype(int format) {
    switch (format) {
    case WEB_POS_GEOJSON: return "application/geo+json";
    case WEB_POS_GPX:     return "application/gpx+xml";
    default:              return "application/json";
    }
}

const char *web_positions_ext(int format) {
    switch (format) {
    case WEB_POS_GEOJSON: return "geojson";
    case WEB_POS_GPX:     return "gpx";
    default:              return "json";
    }
}

/* slothweb never calls setlocale(), so %f's point is '.'. */
static void num(web_jw_t *w, double v, int places) {
    char b[48];
    snprintf(b, sizeof(b), "%.*f", places, v);
    web_jw_raw(w, b);
}

/* ISO 8601 UTC, for GPX's <time>. */
static void iso(web_jw_t *w, long long ts) {
    char b[32];
    time_t t = (time_t)ts;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv)) { web_jw_raw(w, "1970-01-01T00:00:00Z"); return; }
    strftime(b, sizeof(b), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    web_jw_raw(w, b);
}

static int answer(int status, const char *reason, char *body, size_t cap,
                  size_t *len, int *st) {
    return web_hist_error(status, reason, NULL, body, cap, len, st);
}

#ifdef WITH_SQLITE
#include <sqlite3.h>

/* Up to max rows of one statement into out; the count, or -1. */
static int read_rows(web_sdb_conn_t *c, const char *sql, const char *mac,
                     long long since, long long until, int max, int dev,
                     pos_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int k = 1;
    if (mac) sqlite3_bind_text(st, k++, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, k++, since);
    sqlite3_bind_int64(st, k++, until);
    sqlite3_bind_int(st, k, max);
    int rc, n = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < max) {
        pos_t *p = &out[n];
        memset(p, 0, sizeof(*p));
        p->ts = sqlite3_column_int64(st, 0);
        p->lat = sqlite3_column_double(st, 1);
        p->lon = sqlite3_column_double(st, 2);
        if (!(p->lat >= -90.0 && p->lat <= 90.0 && p->lon >= -180.0 && p->lon <= 180.0))
            continue;      /* never serve a value no sloth could have written */
        p->has_acc = sqlite3_column_type(st, 3) != SQLITE_NULL;
        p->acc_m = sqlite3_column_double(st, 3);
        if (dev) {
            p->has_rssi = sqlite3_column_type(st, 4) != SQLITE_NULL;
            p->rssi = sqlite3_column_int(st, 4);
        } else {
            p->has_alt = sqlite3_column_type(st, 4) != SQLITE_NULL;
            p->alt_m = sqlite3_column_double(st, 4);
        }
        n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? n : -1;
}
#endif

static void json_body(web_jw_t *w, const char *mac, const pos_t *d, int nd,
                      const pos_t *t, int nt, int more) {
    web_jw_raw(w, "{\"mac\":");      web_jw_str(w, mac);
    web_jw_raw(w, ",\"note\":");
    web_jw_str(w, "where the sensor was when it heard the device, not where the device is");
    web_jw_raw(w, ",\"positions\":[");
    for (int i = 0; i < nd; i++) {
        web_jw_raw(w, i ? ",{\"ts\":" : "{\"ts\":");
        web_jw_int(w, d[i].ts);
        web_jw_raw(w, ",\"lat\":"); num(w, d[i].lat, 7);
        web_jw_raw(w, ",\"lon\":"); num(w, d[i].lon, 7);
        web_jw_raw(w, ",\"acc_m\":");
        if (d[i].has_acc) num(w, d[i].acc_m, 1); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"rssi\":");
        if (d[i].has_rssi) web_jw_int(w, d[i].rssi); else web_jw_raw(w, "null");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"track\":[");
    for (int i = 0; i < nt; i++) {
        web_jw_raw(w, i ? ",{\"ts\":" : "{\"ts\":");
        web_jw_int(w, t[i].ts);
        web_jw_raw(w, ",\"lat\":"); num(w, t[i].lat, 7);
        web_jw_raw(w, ",\"lon\":"); num(w, t[i].lon, 7);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"more\":");
    web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, "}\n");
}

/* RFC 7946: [lon, lat], WGS84, no "crs" member. "more" and "limit" are
 * foreign members (§6.1): a file cut at WEB_POS_MAX says so, as the
 * JSON answer does, rather than passing for the whole series. */
static void geojson_body(web_jw_t *w, const char *mac, const pos_t *d, int nd,
                         const pos_t *t, int nt, int more) {
    web_jw_raw(w, "{\"type\":\"FeatureCollection\",\"features\":[");
    for (int i = 0; i < nd; i++) {
        web_jw_raw(w, i ? ",{" : "{");
        web_jw_raw(w, "\"type\":\"Feature\",\"geometry\":{\"type\":\"Point\",\"coordinates\":[");
        num(w, d[i].lon, 7);
        web_jw_raw(w, ",");
        num(w, d[i].lat, 7);
        web_jw_raw(w, "]},\"properties\":{\"kind\":\"heard\",\"mac\":");
        web_jw_str(w, mac);
        web_jw_raw(w, ",\"ts\":");  web_jw_int(w, d[i].ts);
        web_jw_raw(w, ",\"acc_m\":");
        if (d[i].has_acc) num(w, d[i].acc_m, 1); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"rssi\":");
        if (d[i].has_rssi) web_jw_int(w, d[i].rssi); else web_jw_raw(w, "null");
        web_jw_raw(w, "}}");
    }
    if (nt >= 2) {
        web_jw_raw(w, nd ? ",{" : "{");
        web_jw_raw(w, "\"type\":\"Feature\",\"geometry\":{\"type\":\"LineString\",\"coordinates\":[");
        /* Oldest first: a track is drawn in the order it was driven. */
        for (int i = nt - 1; i >= 0; i--) {
            web_jw_raw(w, i == nt - 1 ? "[" : ",[");
            num(w, t[i].lon, 7);
            web_jw_raw(w, ",");
            num(w, t[i].lat, 7);
            web_jw_raw(w, "]");
        }
        web_jw_raw(w, "]},\"properties\":{\"kind\":\"sensor_track\",\"from\":");
        web_jw_int(w, t[nt - 1].ts);
        web_jw_raw(w, ",\"to\":");
        web_jw_int(w, t[0].ts);
        web_jw_raw(w, "}}");
    }
    web_jw_raw(w, "],\"more\":");
    web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"limit\":");
    web_jw_int(w, WEB_POS_MAX);
    web_jw_raw(w, "}\n");
}

/* GPX 1.1 (https://www.topografix.com/GPX/1/1/): attributes lat and lon,
 * <time> in UTC, <ele> metres. The MAC is canonical hex and colons, so
 * it needs no XML escaping; nothing else here is text. */
static void gpx_body(web_jw_t *w, const char *mac, const pos_t *d, int nd,
                     const pos_t *t, int nt, int more) {
    web_jw_raw(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                  "<gpx version=\"1.1\" creator=\"slothweb\""
                  " xmlns=\"http://www.topografix.com/GPX/1/1\">\n");
    web_jw_raw(w, "<metadata><desc>where the sensor was when it heard ");
    web_jw_raw(w, mac);
    web_jw_raw(w, ", not where the device is");
    if (more) {
        char b[160];
        snprintf(b, sizeof(b), "; truncated: only the newest %d samples and "
                 "the newest %d track points of their span", WEB_POS_MAX,
                 WEB_POS_MAX);
        web_jw_raw(w, b);
    }
    web_jw_raw(w, "</desc></metadata>\n");
    for (int i = nd - 1; i >= 0; i--) {
        web_jw_raw(w, "<wpt lat=\"");  num(w, d[i].lat, 7);
        web_jw_raw(w, "\" lon=\"");    num(w, d[i].lon, 7);
        web_jw_raw(w, "\"><time>");    iso(w, d[i].ts);
        web_jw_raw(w, "</time><name>");
        web_jw_raw(w, mac);
        web_jw_raw(w, "</name>");
        if (d[i].has_rssi) {
            char b[48];
            snprintf(b, sizeof(b), "<desc>%d dBm</desc>", d[i].rssi);
            web_jw_raw(w, b);
        }
        web_jw_raw(w, "</wpt>\n");
    }
    if (nt > 0) {
        web_jw_raw(w, "<trk><name>sensor</name><trkseg>\n");
        for (int i = nt - 1; i >= 0; i--) {
            web_jw_raw(w, "<trkpt lat=\""); num(w, t[i].lat, 7);
            web_jw_raw(w, "\" lon=\"");     num(w, t[i].lon, 7);
            web_jw_raw(w, "\">");
            if (t[i].has_alt) { web_jw_raw(w, "<ele>"); num(w, t[i].alt_m, 1); web_jw_raw(w, "</ele>"); }
            web_jw_raw(w, "<time>");        iso(w, t[i].ts);
            web_jw_raw(w, "</time></trkpt>\n");
        }
        web_jw_raw(w, "</trkseg></trk>\n");
    }
    web_jw_raw(w, "</gpx>\n");
}

int web_positions_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status,
                        int *format) {
    *format = WEB_POS_JSON;
    web_param_t ps[4] = { { "mac", "", 0 }, { "format", "", 0 },
                          { "since", "", 0 }, { "until", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer(400, err, body, cap, len, status);
    char mac[WEB_KEY_MAX + 1];
    if (!ps[0].seen || strlen(ps[0].val) != 17 || web_key_mac(ps[0].val, mac) != 0)
        return answer(400, "bad_mac", body, cap, len, status);
    int fmt = WEB_POS_JSON;
    if (ps[1].seen) {
        if (!strcmp(ps[1].val, "json"))         fmt = WEB_POS_JSON;
        else if (!strcmp(ps[1].val, "geojson")) fmt = WEB_POS_GEOJSON;
        else if (!strcmp(ps[1].val, "gpx"))     fmt = WEB_POS_GPX;
        else return answer(400, "bad_format", body, cap, len, status);
    }
    long long since = 0, until = now_s;
    if (ps[2].seen && web_param_secs(ps[2].val, &since) != 0)
        return answer(400, "bad_since", body, cap, len, status);
    if (ps[3].seen && web_param_secs(ps[3].val, &until) != 0)
        return answer(400, "bad_until", body, cap, len, status);
    if (since > until) return answer(400, "bad_range", body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);

    pos_t *d = calloc(WEB_POS_MAX + 1, sizeof(*d));
    pos_t *t = calloc(WEB_POS_MAX + 1, sizeof(*t));
    if (!d || !t) { free(d); free(t); return -1; }
    int nd = 0, nt = 0, more = 0;
#ifdef WITH_SQLITE
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) { free(d); free(t); return o > 0 ? 0 : -1; }
    if (c.opt & WEB_SDB_OPT_POS) {
        nd = read_rows(&c, "SELECT last_seen, lat, lon, acc_m, rssi FROM device_positions"
                           " WHERE mac = ? AND last_seen >= ? AND last_seen <= ?"
                           " ORDER BY last_seen DESC LIMIT ?",
                       mac, since, until, WEB_POS_MAX + 1, 1, d);
        if (nd > WEB_POS_MAX) { nd = WEB_POS_MAX; more = 1; }
        /* The track over the span the samples cover. */
        if (nd > 0)
            nt = read_rows(&c, "SELECT last_seen, lat, lon, acc_m, alt_m FROM sensor_positions"
                               " WHERE last_seen >= ? AND last_seen <= ?"
                               " ORDER BY last_seen DESC LIMIT ?",
                           NULL, d[nd - 1].ts, d[0].ts, WEB_POS_MAX + 1, 0, t);
        if (nt > WEB_POS_MAX) { nt = WEB_POS_MAX; more = 1; }
        if (nd < 0 || nt < 0) {
            free(d); free(t);
            return web_hist_read_failed(&c, body, cap, len, status);
        }
    }
    web_slothdb_close(&c);
#endif
    web_jw_t w;
    web_jw_init(&w, body, cap);
    if (fmt == WEB_POS_GEOJSON)  geojson_body(&w, mac, d, nd, t, nt, more);
    else if (fmt == WEB_POS_GPX) gpx_body(&w, mac, d, nd, t, nt, more);
    else                         json_body(&w, mac, d, nd, t, nt, more);
    free(d);
    free(t);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    *format = fmt;
    return 0;
}
