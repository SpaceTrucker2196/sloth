#include "web_routes.h"
#include "web_rfhist.h"
#include "web_aprshist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "web_alerts.h"
#include "web_assets.h"
#include "web_bledev.h"
#include "web_evidence.h"
#include "web_fleet.h"
#include "web_fleetadsb.h"
#include "web_fleetgnss.h"
#include "web_fleetview.h"
#include "web_fleetid.h"
#include "web_locate.h"
#include "web_bundle.h"
#include "web_flows.h"
#include "web_frrs.h"
#include "web_history.h"
#include "web_json.h"
#include "web_recipes.h"
#include "web_scope.h"
#include "web_series.h"
#include "web_wifi.h"
#include "web_positions.h"
#include "web_probes.h"
#include "web_radar.h"
#include "web_allkeys.h"
#include "web_ssidview.h"

static int route_scoped(const web_req_t *rq, const web_health_t *h,
                        int sse_room, char *out, size_t outsz, web_resp_t *r);
static int route_paths(const web_req_t *rq, const web_health_t *h,
                       int sse_room, char *out, size_t outsz, web_resp_t *r);

/* What every answer carries. no-referrer because nothing on the page
 * should tell anyone where it was; nosniff because every type is
 * declared. */
#define COMMON \
    "X-Content-Type-Options: nosniff\r\n" \
    "Referrer-Policy: no-referrer\r\n"

/* A JSON or event-stream answer is never a document: it can load
 * nothing and be framed by nothing. */
#define CSP_NONE "Content-Security-Policy: default-src 'none'; " \
                 "frame-ancestors 'none'\r\n"

/* A query the routes with parameters refuse whole: one that did not fit
 * the request's buffer, or one past the length those routes take. */
static int qlong(const web_req_t *rq) {
    return rq->query_long || strlen(rq->query) >= WEB_QUERY_ROUTE_MAX;
}

static int fit(int n, size_t outsz, size_t *len) {
    if (n < 0 || (size_t)n >= outsz) return -1;
    *len = (size_t)n;
    return 0;
}

/* A request that named a scope gets it back as the body's first member,
 * so an answer says which scope it is (a 400 named none). The body is
 * an object rendered by our own writers: '{' first. One that filled its
 * buffer goes out without it: the page knows what it asked for, and a
 * whole answer is worth more than the echo. */
static void scope_echo(const web_health_t *h, char *body, size_t *bl, size_t cap) {
    if (!h || !h->sc || !h->sc->given || *bl < 2 || body[0] != '{') return;
    char m[40];
    int n = snprintf(m, sizeof(m), "\"scope\":\"%s\"%s",
                     web_scope_word(h->sc->scope), body[1] == '}' ? "" : ",");
    if (n < 0 || (size_t)n >= sizeof(m) || *bl + (size_t)n > cap) return;
    memmove(body + 1 + n, body + 1, *bl - 1);
    memcpy(body + 1, m, (size_t)n);
    *bl += (size_t)n;
}

static int route_page(const web_req_t *rq, char *out, size_t outsz,
                      web_resp_t *r) {
    /* A validator that did not fit is treated as absent: the cost is a
     * 200 where a 304 would have done, never a wrong 304. */
    if (rq->inm_present && !rq->inm_long &&
        web_http_inm_matches(rq->inm, web_page_etag)) {
        r->status = 304;
        /* RFC 9110 §15.4.5: the headers a 200 would have carried that
         * describe caching, no body and no Content-Length. */
        return fit(snprintf(out, outsz,
            "HTTP/1.1 304 Not Modified\r\n"
            "ETag: %s\r\n"
            "Cache-Control: no-cache\r\n"
            COMMON
            "Connection: close\r\n"
            "\r\n", web_page_etag), outsz, &r->out_len);
    }
    r->status = 200;
    if (!rq->is_head) {
        r->body = web_page;
        r->body_len = web_page_len;
    }
    /* no-cache, not immutable: the page has no versioned URL, so the
     * browser revalidates every load and gets a 304 until a rebuild
     * changes the ETag. */
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "ETag: %s\r\n"
        "Cache-Control: no-cache\r\n"
        COMMON
        "Content-Security-Policy: %s\r\n"
        "Connection: close\r\n"
        "\r\n", web_page_len, web_page_etag, web_page_csp),
        outsz, &r->out_len);
}

/* The M2 members: the store and the rollup's bounds. "store" is
 * "none" with no time series at all, "memory" with the rollup but no
 * slothweb.db, "open" with both. */
static void kc_obj(web_jw_t *w, const char *name, const long long v[WEB_KC_COUNT]) {
    web_jw_raw(w, ",");
    web_jw_key(w, name);
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        web_jw_raw(w, c ? "," : "{");
        web_jw_key(w, web_kclass_name(c));
        web_jw_int(w, v[c]);
    }
    web_jw_raw(w, "}");
}

static void tsdb_health(web_tsdb_t *t, web_jw_t *w) {
    if (!t) {
        web_jw_raw(w, "\"store\":\"none\"");
        return;
    }
    web_rollup_stats_t rs;
    web_rollup_stats(t->ru, &rs);
    web_store_stats_t ss;
    memset(&ss, 0, sizeof(ss));
    int open = t->store && t->store->rd;
    if (open) web_store_stats(t->store, &ss);
    web_jw_raw(w, "\"store\":");
    web_jw_str(w, open ? "open" : "memory");
    web_jw_raw(w, ",\"store_path\":");
    /* Operator text, shown cut; the full path is on stderr at start. */
    if (open) web_jw_strn(w, t->store->path, strnlen(t->store->path, 256));
    else      web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_schema\":");
    if (open) web_jw_int(w, ss.schema); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_rows\":");
    if (open) {
        web_jw_raw(w, "{\"fine\":");    web_jw_int(w, ss.rows[WEB_TIER_FINE]);
        web_jw_raw(w, ",\"minute\":");  web_jw_int(w, ss.rows[WEB_TIER_MINUTE]);
        web_jw_raw(w, ",\"hour\":");    web_jw_int(w, ss.rows[WEB_TIER_HOUR]);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"store_bytes\":");     web_jw_int(w, ss.bytes);
    web_jw_raw(w, ",\"store_max_bytes\":"); web_jw_int(w, t->max_bytes);
    web_jw_raw(w, ",\"store_batches\":");   web_jw_int(w, (long long)ss.batches);
    web_jw_raw(w, ",\"store_write_errors\":");
    web_jw_int(w, (long long)ss.write_errors);
    web_jw_raw(w, ",\"store_last_error\":");
    if (ss.last_error[0]) web_jw_str(w, ss.last_error); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"store_compactions\":");
    web_jw_int(w, (long long)ss.compactions);
    web_jw_raw(w, ",\"store_dropped_expired\":");
    web_jw_int(w, (long long)ss.dropped_expired);
    web_jw_raw(w, ",\"store_dropped_ceiling\":");
    web_jw_int(w, (long long)ss.dropped_ceiling);
    web_jw_raw(w, ",\"store_ceiling_runs\":");
    web_jw_int(w, (long long)ss.ceiling_runs);
    web_jw_raw(w, ",\"store_ceiling_raised\":");
    web_jw_int(w, (long long)ss.ceiling_raised);
    web_jw_raw(w, ",\"store_analysis_bytes\":");
    web_jw_int(w, open ? ss.analysis_bytes : -1);
    web_jw_raw(w, ",\"store_baseline_rows_reused\":");
    web_jw_int(w, (long long)ss.bl_rows_reused);
    /* The WiFi view's channel mix (web_chmix.h): what it holds and what
     * its bounds dropped, in memory and in the store. */
    web_jw_raw(w, ",\"chmix\":");
    if (t->mix) {
        web_chmix_stats_t ms;
        web_chmix_stats(t->mix, &ms);
        web_jw_raw(w, "{\"channels\":");     web_jw_int(w, ms.channels);
        web_jw_raw(w, ",\"samples\":");      web_jw_int(w, (long long)ms.samples);
        web_jw_raw(w, ",\"ring_rows\":");    web_jw_int(w, (long long)ms.ring_rows);
        web_jw_raw(w, ",\"ring_overwritten\":");
        web_jw_int(w, (long long)ms.ring_overwritten);
        web_jw_raw(w, ",\"queue_dropped\":");
        web_jw_int(w, (long long)ms.queue_dropped);
        web_jw_raw(w, ",\"folded\":");       web_jw_int(w, (long long)ms.folded);
        web_jw_raw(w, ",\"channel_evictions\":");
        web_jw_int(w, (long long)ms.channel_evictions);
        web_jw_raw(w, ",\"store_rows\":");
        if (open) web_jw_int(w, ss.mix_rows); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"store_dropped_expired\":");
        web_jw_int(w, (long long)ss.mix_dropped_expired);
        web_jw_raw(w, ",\"store_dropped_cap\":");
        web_jw_int(w, (long long)ss.mix_dropped_cap);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"retain_days\":");     web_jw_int(w, t->retain_days);
    long long v[WEB_KC_COUNT];
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = rs.keys[c];
    kc_obj(w, "series_keys", v);
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = rs.caps[c];
    kc_obj(w, "series_key_caps", v);
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = (long long)rs.evictions[c];
    kc_obj(w, "key_evictions", v);
    for (int c = 0; c < WEB_KC_COUNT; c++) v[c] = (long long)rs.ghost_hits[c];
    kc_obj(w, "key_returns", v);
    web_jw_raw(w, ",\"series\":");           web_jw_int(w, (long long)rs.series);
    web_jw_raw(w, ",\"samples\":");          web_jw_int(w, (long long)rs.samples);
    web_jw_raw(w, ",\"ring_rows\":");        web_jw_int(w, (long long)rs.ring_rows);
    web_jw_raw(w, ",\"queue_rows\":");       web_jw_int(w, (long long)rs.queue_rows);
    web_jw_raw(w, ",\"queue_cap\":");        web_jw_int(w, (long long)rs.queue_cap);
    web_jw_raw(w, ",\"queue_dropped\":");    web_jw_int(w, (long long)rs.q_dropped);
    web_jw_raw(w, ",\"churn_dropped\":");  web_jw_int(w, (long long)rs.churn_dropped);
    web_jw_raw(w, ",\"highwater_evictions\":");
    web_jw_int(w, (long long)rs.hw_evictions);
    web_jw_raw(w, ",\"values_clamped\":");   web_jw_int(w, (long long)rs.clamped);
}

/* The M3 members: the baseline table, the episode table and the
 * identity tables, each with its bound and what it has had to drop. */
static void analysis_health(web_anomaly_t *a, web_jw_t *w) {
    web_jw_raw(w, ",\"anomaly\":");
    if (!a) { web_jw_raw(w, "null"); return; }
    web_anom_stats_t s;
    web_anomaly_stats(a, &s);
    web_jw_raw(w, "{\"open\":");              web_jw_int(w, s.open);
    web_jw_raw(w, ",\"building\":");          web_jw_int(w, s.building);
    web_jw_raw(w, ",\"closed_kept\":");       web_jw_int(w, s.closed_kept);
    web_jw_raw(w, ",\"cap\":");               web_jw_int(w, a->cap);
    web_jw_raw(w, ",\"opened\":");            web_jw_int(w, (long long)s.opened);
    web_jw_raw(w, ",\"closed\":");            web_jw_int(w, (long long)s.closed);
    web_jw_raw(w, ",\"dropped\":");           web_jw_int(w, (long long)s.dropped);
    web_jw_raw(w, ",\"evicted_closed\":");    web_jw_int(w, (long long)s.evicted_closed);
    web_jw_raw(w, ",\"candidates_dropped\":"); web_jw_int(w, (long long)s.candidates_dropped);
    web_jw_raw(w, ",\"rows_dropped\":");      web_jw_int(w, (long long)s.rows_dropped);
    web_jw_raw(w, ",\"late_rows\":");         web_jw_int(w, (long long)s.late_rows);
    web_jw_raw(w, ",\"hours_fed\":");         web_jw_int(w, (long long)s.hours_fed);
    web_jw_raw(w, ",\"hours_unobserved\":");  web_jw_int(w, (long long)s.hours_unobserved);
    web_jw_raw(w, ",\"minutes_unobserved\":"); web_jw_int(w, (long long)s.minutes_unobserved);
    web_jw_raw(w, ",\"hours_merged\":");      web_jw_int(w, (long long)s.hours_merged);
    web_jw_raw(w, ",\"mad\":");
    web_jw_raw(w, a->cfg.store ? "true" : "false");
    web_jw_raw(w, ",\"mad_queries\":");       web_jw_int(w, (long long)s.mad_queries);
    web_jw_raw(w, ",\"mad_skipped\":");       web_jw_int(w, (long long)s.mad_skipped);
    web_jw_raw(w, ",\"a9\":");
    web_jw_raw(w, a->cfg.store ? "true" : "false");
    web_jw_raw(w, ",\"a9_queries\":");        web_jw_int(w, (long long)s.a9_queries);
    web_jw_raw(w, ",\"fanout_hosts\":");      web_jw_int(w, s.fanout);
    web_jw_raw(w, ",\"fanout_evictions\":");  web_jw_int(w, (long long)s.fanout_evictions);
    web_jw_raw(w, ",\"reported\":");          web_jw_int(w, s.reported);
    web_jw_raw(w, ",\"reported_evicted\":");  web_jw_int(w, (long long)s.reported_evicted);
    web_jw_raw(w, ",\"known_evictions\":");   web_jw_int(w, (long long)s.known_evictions);
    web_jw_raw(w, ",\"a2_queries\":");        web_jw_int(w, (long long)s.a2_queries);
    web_jw_raw(w, ",\"a2_not_new\":");        web_jw_int(w, (long long)s.a2_not_new);
    web_jw_raw(w, ",\"a2_deferred\":");       web_jw_int(w, (long long)s.a2_deferred);
    web_jw_raw(w, ",\"a2_in_burst\":");       web_jw_int(w, (long long)s.a2_in_burst);
    web_jw_raw(w, ",\"ident_truncated\":");   web_jw_int(w, (long long)s.ident_truncated);
    web_jw_raw(w, ",\"persist_errors\":");    web_jw_int(w, (long long)s.persist_errors);
    web_jw_raw(w, ",\"persisted\":");
    web_jw_raw(w, a->cfg.store ? "true" : "false");
    web_jw_raw(w, "}");
    web_jw_raw(w, ",\"baseline\":");
    if (!a->cfg.bl) {
        web_jw_raw(w, "null");
    } else {
        web_bl_stats_t b;
        web_baseline_stats(a->cfg.bl, &b);
        web_jw_raw(w, "{\"entries\":");     web_jw_int(w, b.entries);
        web_jw_raw(w, ",\"cap\":");         web_jw_int(w, b.cap);
        web_jw_raw(w, ",\"evictions\":");   web_jw_int(w, (long long)b.evictions);
        web_jw_raw(w, ",\"aged_out\":");    web_jw_int(w, (long long)b.aged_out);
        web_jw_raw(w, ",\"fed\":");         web_jw_int(w, (long long)b.fed);
        web_jw_raw(w, ",\"zero_fed\":");    web_jw_int(w, (long long)b.zero_fed);
        web_jw_raw(w, ",\"deletes_lost\":"); web_jw_int(w, (long long)b.del_lost);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, ",\"ident\":");
    if (!a->cfg.ident) {
        web_jw_raw(w, "null");
    } else {
        web_id_stats_t i;
        web_ident_stats(a->cfg.ident, &i);
        web_jw_raw(w, "{\"macs\":");          web_jw_int(w, i.macs);
        web_jw_raw(w, ",\"mac_cap\":");       web_jw_int(w, i.mac_cap);
        web_jw_raw(w, ",\"mac_evictions\":"); web_jw_int(w, (long long)i.mac_evictions);
        web_jw_raw(w, ",\"ips\":");           web_jw_int(w, i.ips);
        web_jw_raw(w, ",\"ip_cap\":");        web_jw_int(w, i.ip_cap);
        web_jw_raw(w, ",\"ip_evictions\":");  web_jw_int(w, (long long)i.ip_evictions);
        web_jw_raw(w, ",\"dns_matched\":");   web_jw_int(w, (long long)i.dns_matched);
        web_jw_raw(w, ",\"dns_unmatched\":"); web_jw_int(w, (long long)i.dns_unmatched);
        web_jw_raw(w, ",\"query_overwrites\":");
        web_jw_int(w, (long long)i.query_overwrites);
        web_jw_raw(w, "}");
    }
}

static size_t health_json(const web_health_t *h, char *out, size_t outsz) {
    web_jw_t w;
    web_jw_init(&w, out, outsz);
    web_jw_raw(&w, "{\"service\":\"slothweb\",\"milestone\":\"M6\",\"uptime_s\":");
    web_jw_int(&w, h->uptime_s);
    /* With no data socket the M0 shape stands: "none" and null. Every
     * stream-derived or operator-given string goes through web_jw_str. */
    if (h->live) web_live_health_members(h->live, &w, h->now_ms);
    else         web_jw_raw(&w, ",\"socket\":\"none\",\"last_record_age_s\":null");
    web_m4_health(h->m4, h->wall_s, &w);
    /* #168: whether the DB-backed views are stale, decided here rather
     * than in the page so the one rule is tested in one place. Only with
     * a --sloth-db: the M0 shape stands without one. */
    if (h->m4 && h->m4->sdb && h->m4->sdb->configured) {
        long long age;
        web_jw_raw(&w, ",\"sloth_db_stale_after_s\":");
        web_jw_int(&w, WEB_SDB_STALE_S);
        web_jw_raw(&w, ",\"sloth_db_stale\":");
        if (web_m4_db_age(h->m4, h->wall_s, &age)) {
            int current = 0;
            if (h->live) {
                web_live_sum_t ls;
                web_live_summary(h->live, &ls, h->now_ms);
                current = ls.sock_state == WEB_SOCK_CONNECTED &&
                          ls.last_record_age_ms >= 0 &&
                          ls.last_record_age_ms <= WEB_SDB_STREAM_CURRENT_S * 1000LL;
            }
            web_jw_raw(&w, web_sdb_is_stale(age, current) ? "true" : "false");
        } else {
            web_jw_raw(&w, "null");
        }
    }
    /* The page shows the SQL box only when this says so. */
    web_jw_raw(&w, ",\"sql\":");
    if (!h->sql || !h->sql->enabled) {
        web_jw_raw(&w, "false");
    } else {
        web_sqlbox_stats_t ss;
        web_sqlbox_stats(h->sql, &ss);
        web_jw_raw(&w, "{\"row_cap\":");     web_jw_int(&w, h->sql->row_cap);
        web_jw_raw(&w, ",\"timeout_ms\":");  web_jw_int(&w, h->sql->timeout_ms);
        web_jw_raw(&w, ",\"queries\":");     web_jw_int(&w, (long long)ss.queries);
        web_jw_raw(&w, ",\"refused\":");     web_jw_int(&w, (long long)ss.refused);
        web_jw_raw(&w, ",\"busy\":");        web_jw_int(&w, (long long)ss.busy);
        web_jw_raw(&w, ",\"timeouts\":");    web_jw_int(&w, (long long)ss.timeouts);
        web_jw_raw(&w, ",\"truncated\":");   web_jw_int(&w, (long long)ss.truncated);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, ",");
    tsdb_health(h->tsdb, &w);
    analysis_health(h->anomaly, &w);
    /* The BLE tables (web_ble.h), only when slothweb keeps them: the
     * M0 shape stands without. */
    if (h->ble) {
        web_jw_raw(&w, ",\"ble\":");
        web_ble_health_json(h->ble, &w);
        if (h->tsdb && h->tsdb->store && h->tsdb->store->rd) {
            web_store_stats_t bs;
            web_store_stats(h->tsdb->store, &bs);
            web_jw_raw(&w, ",\"ble_store\":{\"rows\":");  web_jw_int(&w, bs.ble_rows);
            web_jw_raw(&w, ",\"alert_rows\":");            web_jw_int(&w, bs.ble_alert_rows);
            web_jw_raw(&w, ",\"batches\":");               web_jw_int(&w, (long long)bs.ble_batches);
            web_jw_raw(&w, ",\"dropped_expired\":");       web_jw_int(&w, (long long)bs.ble_dropped_expired);
            web_jw_raw(&w, ",\"dropped_cap\":");           web_jw_int(&w, (long long)bs.ble_dropped_cap);
            web_jw_raw(&w, "}");
        } else {
            web_jw_raw(&w, ",\"ble_store\":null");
        }
    }
    /* The GNSS panel (web_gnss.h), likewise only when kept. */
    if (h->gnss) {
        web_jw_raw(&w, ",\"gnss\":");
        web_gnss_health_json(h->gnss, &w);
    }
    /* The ADS-B panel (web_adsb.h), likewise only when kept. */
    if (h->adsb) {
        web_jw_raw(&w, ",\"adsb\":");
        web_adsb_health_json(h->adsb, &w);
    }
    /* The APRS panel (web_aprs.h), likewise only when kept. */
    if (h->aprs) {
        web_jw_raw(&w, ",\"aprs\":");
        web_aprs_health_json(h->aprs, &w);
    }
    web_jw_raw(&w, ",\"sse_clients\":");
    web_jw_int(&w, h->sse_clients);
    web_jw_raw(&w, ",\"tick_seq\":");
    web_jw_int(&w, (long long)h->tick_seq);
    /* The page header names the host it is looking at, so two sites'
     * pages open side by side cannot be mistaken for each other. */
    {
        char hn[256];
        web_jw_raw(&w, ",\"hostname\":");
        if (gethostname(hn, sizeof(hn)) == 0) {
            hn[sizeof(hn) - 1] = '\0';
            web_jw_str(&w, hn);
        } else {
            web_jw_raw(&w, "null");
        }
    }
    /* Triage and the FRRS record (web_frrs.h): additive, last, and only
     * when the module is attached, so the answer without it is as it
     * was. */
    if (h->m4 && h->m4->frrs) web_frrs_health(h->m4->frrs, &w);
    /* The owner's fleet (web_fleet.h): the export, and each peer pulled
     * with its last good pull's age and its last refusal. Additive and
     * last, only when attached, as triage is. */
    if (h->m4 && h->m4->fleet) {
        web_jw_raw(&w, ",\"fleet\":");
        web_fleet_health_json(h->m4->fleet, &w, h->wall_s);
    }
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

static int route_health(const web_req_t *rq, const web_health_t *h,
                        char *out, size_t outsz, web_resp_t *r) {
    /* 8 KB before the fleet; eight peers, each a last refusal of up to
     * WEB_FLEET_ERR_MAX bytes escaped, take up to another 10 KB. */
    char body[20480];
    size_t bl = health_json(h, body, sizeof(body));
    if (bl == 0) return -1;
    r->status = 200;
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n"
        "%s", bl, rq->is_head ? "" : body), outsz, &r->out_len);
}

static size_t live_body(const web_health_t *h, char *out, size_t cap) {
    if (h->live) {
        size_t n = web_live_json_scoped(h->live, h->sc, out, cap, h->now_ms);
        /* Under a scope the tick's anomalies_open (every scope's) will
         * not do: the scope's own count of open episodes rides here, so
         * the page's 2 s scoped refresh keeps the tile and the strip. */
        if (n >= 2 && h->anomaly && h->sc && h->sc->scope != WEB_SCOPE_HYBRID &&
            out[n - 2] == '}' && out[n - 1] == '\n') {
            char t[48];
            int k = snprintf(t, sizeof(t), ",\"anomalies_open\":%d}\n",
                             web_anomaly_open_count_scoped(h->anomaly, h->sc,
                                                           h->tsdb ? h->tsdb->ru : NULL));
            if (k < 0 || n - 2 + (size_t)k + 1 > cap) return 0;
            memcpy(out + n - 2, t, (size_t)k + 1);
            n = n - 2 + (size_t)k;
        }
        /* The BLE receivers' state (web_ble.h), Monitor's and Hybrid's:
         * the Overview's BLE fact and the Health view's Bluetooth block.
         * Under Local the member is null, as the view is out of scope. */
        if (n >= 2 && h->ble && out[n - 2] == '}' && out[n - 1] == '\n') {
            /* Sized from the worst case: twelve sensor_health strings of
             * WEB_BLE_SH_STR bytes, each byte at most a six-byte \u
             * escape, about 450 bytes of names and a dozen integers.
             * Should it ever not fit, the member is null and the rest of
             * /api/live stands: one block is not the page's feed. */
            char t[12 * WEB_BLE_SH_STR * 6 + 1024];
            web_jw_t w;
            web_jw_init(&w, t, sizeof(t));
            web_jw_raw(&w, ",\"ble\":");
            if (h->sc && h->sc->scope == WEB_SCOPE_LOCAL) web_jw_raw(&w, "null");
            else web_ble_live_json(h->ble, &w, h->wall_s);
            web_jw_raw(&w, "}\n");
            if (w.overflow) {
                web_jw_init(&w, t, sizeof(t));
                web_jw_raw(&w, ",\"ble\":null}\n");
            }
            if (w.overflow || n - 2 + w.len + 1 > cap) return 0;
            memcpy(out + n - 2, t, w.len + 1);
            n = n - 2 + w.len;
        }
        return n;
    }
    static const char none[] =
        "{\"socket\":\"none\",\"devices\":null,\"devices_stale\":true,"
        "\"alerts_open\":null,\"records\":0,\"records_s\":null,"
        "\"sensor\":{\"state\":\"unknown\"},\"alerts\":[],\"recent\":[]}\n";
    if (cap < sizeof(none)) return 0;
    memcpy(out, none, sizeof(none));
    return sizeof(none) - 1;
}

/* The body is rendered straight into out behind room for the header,
 * then the header is written in front of it: one copy, no second 64 KB
 * buffer. */
static int route_live(const web_req_t *rq, const web_health_t *h,
                      char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    /* 64 bytes kept back for the scope's echo. */
    size_t bl = outsz > WEB_LIVE_HDR_RESERVE + 64
              ? live_body(h, body, outsz - WEB_LIVE_HDR_RESERVE - 64) : 0;
    if (bl) scope_echo(h, body, &bl, outsz - WEB_LIVE_HDR_RESERVE);
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", bl), sizeof(hdr), &hl) != 0)
        return -1;
    r->status = 200;
    if (rq->is_head) {
        memcpy(out, hdr, hl);
        r->out_len = hl;
        return 0;
    }
    memmove(out + hl, body, bl);
    memcpy(out, hdr, hl);
    r->out_len = hl + bl;
    return 0;
}

/* A JSON answer whose body was rendered at out + WEB_LIVE_HDR_RESERVE:
 * write the header in front of it. */
static int json_answer(const web_req_t *rq, const web_health_t *h, int status, size_t bl, char *out,
                       size_t outsz, web_resp_t *r) {
    char *body = out + WEB_LIVE_HDR_RESERVE;
    scope_echo(h, body, &bl, outsz - WEB_LIVE_HDR_RESERVE);
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status), bl), sizeof(hdr), &hl) != 0)
        return -1;
    if (hl + bl > outsz) return -1;
    r->status = status;
    if (rq->is_head) {
        memcpy(out, hdr, hl);
        r->out_len = hl;
        return 0;
    }
    memmove(out + hl, body, bl);
    memcpy(out, hdr, hl);
    r->out_len = hl + bl;
    return 0;
}

enum { SR_SERIES, SR_KEYS, SR_METRICS };

/* /api/series, /api/keys, /api/metrics. Every parameter is checked
 * before anything is read (web_series.h); a bad one is a 400 naming the
 * reason in a word of our own, never echoing the value. */
static int route_series(const web_req_t *rq, const web_health_t *h, int which,
                        char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    char why[48] = "";
    size_t bl = 0;
    int status = 200;
    if (!h->tsdb) {
        status = 503;
        bl = web_series_error_json("no_time_series", body, cap);
    } else if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (which == SR_SERIES) {
        web_series_q_t q;
        int store_on = h->tsdb->store && h->tsdb->store->rd;
        if (web_series_parse(rq->query, h->wall_s, h->tsdb->retain_days,
                             store_on, &q, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            q.sc = h->sc;
            bl = web_series_json(h->tsdb, &q, body, cap);
        }
    } else if (which == SR_KEYS) {
        int metric;
        if (web_keys_parse(rq->query, &metric, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            bl = web_keys_json_scoped(h->tsdb, metric, h->sc, body, cap);
        }
    } else {
        if (web_metrics_parse(rq->query, why, sizeof(why)) != 0) {
            status = 400;
            bl = web_series_error_json(why, body, cap);
        } else {
            bl = web_metrics_json_scoped(h->tsdb, h->sc, body, cap);
        }
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/series/all (web_allkeys.h): every key of one metric, each in at
 * most cols cells, a page of keys to an answer. Checked as /api/series
 * is, before anything is read. */
static int route_allkeys(const web_req_t *rq, const web_health_t *h,
                         char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    char why[48] = "";
    size_t bl = 0;
    int status = 200;
    web_allkeys_q_t q;
    if (!h->tsdb) {
        status = 503;
        bl = web_series_error_json("no_time_series", body, cap);
    } else if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (web_allkeys_parse(rq->query, h->wall_s,
                                 h->tsdb->store && h->tsdb->store->rd, &q,
                                 why, sizeof(why)) != 0) {
        status = 400;
        bl = web_series_error_json(why, body, cap);
    } else {
        q.sc = h->sc;
        bl = web_allkeys_json(h->tsdb, &q, body, cap);
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/anomalies?since=&kind= and /api/baseline?metric=&key= (M3).
 * Parameters as strict as the series routes': an unknown, repeated or
 * malformed one is a 400 naming the reason in a word of our own. The
 * anomaly list always fits: it stops with "more":true first. */
static int route_anomalies(const web_req_t *rq, const web_health_t *h,
                           char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    int status = 200;
    size_t bl;
    char why[48] = "";
    long long since;
    int kind;
    if (!h->anomaly) {
        status = 503;
        bl = web_series_error_json("no_anomaly_engine", body, cap);
    } else if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (web_anomalies_parse(rq->query, h->wall_s, &since, &kind, why,
                                   sizeof(why)) != 0) {
        status = 400;
        bl = web_series_error_json(why, body, cap);
    } else {
        bl = web_anomaly_json_scoped(h->anomaly, h->wall_s, since, kind, h->sc,
                                     h->tsdb ? h->tsdb->ru : NULL, body, cap);
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

static int route_baseline(const web_req_t *rq, const web_health_t *h,
                          char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    int status = 200;
    size_t bl;
    char why[48] = "", key[WEB_KEY_MAX + 1];
    int metric;
    if (!h->anomaly || !h->anomaly->cfg.bl) {
        status = 503;
        bl = web_series_error_json("no_anomaly_engine", body, cap);
    } else if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (web_baseline_parse(rq->query, &metric, key, why,
                                  sizeof(why)) != 0) {
        status = 400;
        bl = web_series_error_json(why, body, cap);
    } else {
        /* A series the scope does not hold reads as never fed. */
        int out_of = h->sc && h->sc->scope != WEB_SCOPE_HYBRID &&
                     !web_scope_pass(h->sc->scope,
                                     web_scope_metric_key(metric, key, h->sc));
        bl = web_baseline_json(out_of ? NULL : h->anomaly->cfg.bl, metric, key,
                               h->wall_s, body, cap);
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

enum { M4_DEVICES, M4_DEVICE, M4_LOOKUP };

/* /api/devices, /api/device/{mac}, /api/lookup (M4, web_devices.h):
 * validated whole, answered from sloth.db read-only, the stream and the
 * OUI table. */
static int route_m4(const web_req_t *rq, const web_health_t *h, int which,
                    const char *arg, char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else if (which == M4_DEVICES) {
        rc = web_devices_route(m, rq->query, h->wall_s, body, cap, &bl, &status);
    } else if (which == M4_DEVICE) {
        rc = web_device_route(m, arg, rq->query, h->wall_s, body, cap, &bl,
                              &status);
    } else {
        rc = web_lookup_route(m, rq->query, h->wall_s, body, cap, &bl, &status);
    }
    /* The peers' rows (web_fleetview.h), after the route has answered. */
    if (rc == 0 && bl && which != M4_LOOKUP && h->fleet_merge) {
        web_fv_src_t fs = { m->sdb, h->ble, m->oui, h->adsb };
        if (which == M4_DEVICES && status == 200)
            web_fv_list(m->fleet, &fs, WEB_FV_DEVICES, rq->query, h->wall_s, body, cap, &bl);
        else if (which == M4_DEVICE)
            web_fv_detail(m->fleet, 0, arg, h->wall_s, body, cap, &bl, &status);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

enum { M5_CHANNELS, M5_DEAUTH, M5_APS, M5_OVERVIEW, M5_HDEVICES, M5_HALERTS,
       M5_HFLOWS, M5_SESSIONS, M5_SESSIONS_NEW, M6_FLOWS, M6_GRAPH, M5_WLOCAL,
       M5_CHAIN, RF_GNSS_SEEN, RF_GNSS_SAT, RF_ADSB_SEEN, RF_ADSB_AC, RF_GNSS_TRACKS,
       RF_APRS_SEEN, RF_APRS_STN, RF_APRS_TRK, M5_SSID,
       PR_CLIENTS, PR_SSIDS, PR_SHARED, PR_GROUPS };

/* The WiFi and History routes (M5, web_wifi.h, web_history.h) and the
 * Flows routes (M6, web_flows.h): the same shape as route_m4(). */
static int route_m5(const web_req_t *rq, const web_health_t *h, int which,
                    char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    typedef int (*fn_t)(const web_m4_t *, const char *, long long, char *,
                        size_t, size_t *, int *);
    static const fn_t F[] = {
        web_wifi_channels_route, web_wifi_deauth_route, web_wifi_aps_route,
        web_history_overview_route, web_history_devices_route,
        web_history_alerts_route, web_history_flows_route, web_sessions_route,
        web_sessions_new_route, web_flows_route, web_flows_graph_route,
        web_wifi_local_route, web_wifi_chain_route,
        web_gnss_seen_route, web_gnss_sat_route, web_adsb_seen_route,
        web_adsb_aircraft_route, web_gnss_tracks_route,
        web_aprs_seen_route, web_aprs_station_route, web_aprs_tracks_route,
        web_ssid_route, web_probes_clients_route, web_probes_ssids_route,
        web_probes_shared_route, web_probes_groups_route,
    };
    /* A view a capture scope holds nothing of (web_scope.h): the WiFi
     * view's channels, deauths and APs are the monitor radio's, its card
     * panels (/api/wifi/local) the managed card's own scan and link, the
     * flows all the IP capture's (sloth.db keeps no capture path, so its
     * flow rows are Local's).
     * Said once, here, rather than as an empty answer that looks like a
     * quiet network. The parameters are still checked first, by the
     * route's own parser on a check-only copy that reads nothing. */
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    const char *none_here =
        sc == WEB_SCOPE_LOCAL && (which == M5_CHANNELS || which == M5_DEAUTH ||
                                  which == M5_APS || which == M5_CHAIN)
            ? "the WiFi view's channels, deauths and access points are the passive "
              "monitor radio's; the host's own interfaces carried none of it (the "
              "managed card's own scan and link are /api/wifi/local)"
        : sc == WEB_SCOPE_MONITOR && which == M5_WLOCAL
            ? "the managed Wi-Fi card's own scan and station dump are the host's "
              "own interface's; the monitor radio heard none of it"
        : sc == WEB_SCOPE_MONITOR && (which == M6_FLOWS || which == M6_GRAPH ||
                                      which == M5_HFLOWS)
            ? "flows are the IP capture's (sloth.db keeps no capture path, so "
              "its flow rows count as Local); the monitor radio heard none"
        : sc == WEB_SCOPE_LOCAL && (which == RF_ADSB_SEEN || which == RF_ADSB_AC)
            ? "aircraft are the ADS-B decoder's (--adsb), a passive radio; the "
              "host's own interfaces carried none"
        : sc == WEB_SCOPE_LOCAL && (which == RF_APRS_SEEN || which == RF_APRS_STN ||
                                    which == RF_APRS_TRK)
            ? "APRS stations are the Dire Wolf decoder's (--aprs), a passive "
              "radio; the host's own interfaces carried none"
        : sc == WEB_SCOPE_LOCAL && which >= M5_SSID && which <= PR_GROUPS
            ? "an SSID's beacons and the probe requests asking for it are the "
              "passive monitor radio's; the host's own interfaces carried none "
              "of it"
        : NULL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        web_m4_t mc = *m;
        mc.check_only = none_here != NULL;
        rc = F[which](&mc, rq->query, h->wall_s, body, cap, &bl, &status);
        /* The Probes view's clients and SSIDs merge too; shared and
         * groups are this sensor's similarity and never do. */
        if (rc == 0 && !none_here && status == 200 && h->fleet_merge &&
            (which == M5_APS || which == PR_CLIENTS || which == PR_SSIDS ||
             which == RF_ADSB_SEEN)) {
            web_fv_src_t fs = { m->sdb, h->ble, m->oui, h->adsb };
            web_fv_list(m->fleet, &fs,
                        which == M5_APS ? WEB_FV_APS
                        : which == PR_CLIENTS ? WEB_FV_PROBE_CLIENTS
                        : which == PR_SSIDS ? WEB_FV_PROBE_SSIDS : WEB_FV_ADSB_SEEN,
                        rq->query, h->wall_s, body, cap, &bl);
        }
        /* The aircraft detail names the hosts that heard an address. */
        if (rc == 0 && !none_here && status == 200 && h->fleet_merge && which == RF_ADSB_AC) {
            web_fv_src_t fs = { m->sdb, h->ble, m->oui, h->adsb };
            web_fv_aircraft(m->fleet, &fs, rq->query, h->wall_s, body, cap, &bl, status);
        }
        if (rc == 0 && none_here && status == 200) {
            web_jw_t w;
            web_jw_init(&w, body, cap);
            web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
            web_jw_str(&w, none_here);
            web_jw_raw(&w, "}\n");
            bl = w.overflow ? 0 : w.len;
        }
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/positions (web_positions.h): GET only, as /api/alerts. JSON,
 * GeoJSON or GPX; the two exports are attachments, so a browser saves
 * them rather than rendering an XML document under this origin. */
static int route_positions(const web_req_t *rq, const web_health_t *h,
                           char *out, size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc, fmt = WEB_POS_JSON;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        rc = web_positions_route(m, rq->query, h->wall_s, body, cap, &bl,
                                 &status, &fmt);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (fmt == WEB_POS_JSON || status != 200)
        return json_answer(rq, h, status, bl, out, outsz, r);
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Disposition: attachment; filename=\"sloth-positions.%s\"\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", web_positions_ctype(fmt), web_positions_ext(fmt), bl),
        sizeof(hdr), &hl) != 0)
        return -1;
    if (hl + bl > outsz) return -1;
    r->status = 200;
    memmove(out + hl, body, bl);
    memcpy(out, hdr, hl);
    r->out_len = hl + bl;
    return 0;
}

enum { BLE_DEVICES, BLE_ALERTS, BLE_DEVICE };

/* /api/gnss and /api/gnss/fixes (web_gnss.h): the host's own receiver,
 * sloth's own state, so every scope's; the answer says so itself. */
static int route_gnss(const web_req_t *rq, const web_health_t *h, int fixes,
                      char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else if (fixes) {
        rc = web_gnss_fixes_route(h->gnss, rq->query, h->wall_s, body, cap, &bl, &status);
    } else {
        rc = web_gnss_route(h->gnss, rq->query, h->wall_s, body, cap, &bl, &status);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/adsb (web_adsb.h): the aircraft a local decoder lists. Its SDR
 * is a passive radio, as the BLE receivers are, so Monitor's and
 * Hybrid's; under Local the query is checked, then the one
 * out_of_scope answer. */
static int route_adsb(const web_req_t *rq, const web_health_t *h,
                      char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        /* The open ADSB_EMERGENCY incidents, so a row links its alert
         * (#186); read before the panel's lock, never under it. */
        web_adsb_alert_t al[WEB_ADSB_ALERTS];
        memset(al, 0, sizeof(al));
        int nal = none_here ? 0 : web_adsb_alerts(h->live, al, WEB_ADSB_ALERTS);
        rc = web_adsb_route(h->adsb, rq->query, h->wall_s, none_here, al, nal,
                            body, cap, &bl, &status);
        if (rc == 0 && none_here && status == 200) bl = web_adsb_out_of_scope_json(body, cap);
        /* The peers' aircraft (web_fleetview.h), after the panel's own
         * answer, its counts untouched. */
        if (rc == 0 && !none_here && status == 200 && h->fleet_merge && h->m4) {
            web_fv_src_t fs = { h->m4->sdb, h->ble, h->m4->oui, h->adsb };
            web_fv_list(h->m4->fleet, &fs, WEB_FV_ADSB, rq->query, h->wall_s, body, cap, &bl);
        }
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/sys (web_sysstat.h): the sensor host's status, its sources and
 * the receivers attached to it. sloth's own state, so every scope's. */
static int route_sys(const web_req_t *rq, const web_health_t *h,
                     char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        rc = web_sys_route(h->sys, rq->query, h->wall_s, h->now_ms, body, cap, &bl, &status);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/lures (web_lure.h): the KARMA and key-harvest evidence sloth's
 * rules read. The monitor radio's, so Monitor's and Hybrid's; under
 * Local the query is checked, then the one out_of_scope answer. */
static int route_lures(const web_req_t *rq, const web_health_t *h,
                       char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        rc = web_lure_route(h->lure, rq->query, h->wall_s, h->now_ms, none_here,
                            body, cap, &bl, &status);
        if (rc == 0 && none_here && status == 200) bl = web_lure_out_of_scope_json(body, cap);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/aprs (web_aprs.h): the stations a local Dire Wolf decodes. Its
 * receiver is a passive radio, as the decoder's SDR for ADS-B, so
 * Monitor's and Hybrid's; under Local the query is checked, then the
 * one out_of_scope answer. */
static int route_aprs(const web_req_t *rq, const web_health_t *h,
                      char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        rc = web_aprs_route(h->aprs, rq->query, h->wall_s, none_here, body, cap, &bl, &status);
        if (rc == 0 && none_here && status == 200) bl = web_aprs_out_of_scope_json(body, cap);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/radar (web_radar.h): the Radar view's Wi-Fi and BLE band census,
 * from the BLE tables and the FRRS ledger (h->m4->frrs). Both are
 * passive radio, so Monitor's and Hybrid's; under Local the query is
 * checked, then the one out_of_scope answer. */
static int route_radar(const web_req_t *rq, const web_health_t *h,
                       char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    web_frrs_t *f = h->m4 ? h->m4->frrs : NULL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        rc = web_radar_route(h->ble, f, rq->query, h->wall_s, none_here, body, cap, &bl, &status);
        if (rc == 0 && none_here && status == 200) bl = web_radar_out_of_scope_json(body, cap);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/ble, /api/ble/alerts, /api/ble/{addr} (web_ble.h): slothweb's
 * own BLE tables. The receivers are passive radio, so Monitor and
 * Hybrid serve them and Local is a view that holds nothing of them:
 * said once, as route_m5()'s none_here says it, the query still checked
 * first. */
static int route_ble(const web_req_t *rq, const web_health_t *h, int which,
                     const char *arg, char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        if (which == BLE_DEVICES)
            rc = web_ble_devices_route(h->ble, rq->query, h->wall_s, none_here, body, cap,
                                       &bl, &status);
        else if (which == BLE_ALERTS)
            rc = web_ble_alerts_route(h->ble, rq->query, h->wall_s, none_here, body, cap,
                                      &bl, &status);
        else
            rc = web_ble_device_route(h->ble, arg, rq->query, h->wall_s, none_here, body,
                                      cap, &bl, &status);
        if (rc == 0 && which != BLE_ALERTS && !none_here && h->fleet_merge) {
            web_fleet_t *fl = h->m4 ? h->m4->fleet : NULL;
            web_fv_src_t fs = { h->m4 ? h->m4->sdb : NULL, h->ble, h->m4 ? h->m4->oui : NULL,
                                h->adsb };
            if (which == BLE_DEVICES && status == 200)
                web_fv_list(fl, &fs, WEB_FV_BLE, rq->query, h->wall_s, body, cap, &bl);
            else if (which == BLE_DEVICE)
                web_fv_detail(fl, 1, arg, h->wall_s, body, cap, &bl, &status);
        }
        if (rc == 0 && none_here && status == 200) bl = web_ble_out_of_scope_json(body, cap);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/ble/classes and /api/ble/proximity (web_bledev.h): the BLE
 * Devices view's two panels, over the time series and the BLE tables.
 * Monitor's and Hybrid's as route_ble()'s; under Local the query is
 * checked on a check-only copy, then the one out_of_scope answer. */
static int route_bledev(const web_req_t *rq, const web_health_t *h, int prox,
                        char *out, size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    static const web_m4_t none;
    web_m4_t mc = h->m4 ? *h->m4 : none;
    int sc = h->sc ? h->sc->scope : WEB_SCOPE_HYBRID;
    int none_here = sc == WEB_SCOPE_LOCAL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else {
        mc.check_only = none_here;
        rc = prox ? web_bledev_proximity_route(&mc, h->ble, rq->query, h->wall_s, body,
                                               cap, &bl, &status)
                  : web_bledev_classes_route(&mc, h->ble, rq->query, h->wall_s, body,
                                             cap, &bl, &status);
        if (rc == 0 && none_here && status == 200) bl = web_ble_out_of_scope_json(body, cap);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/alerts and /api/alert (web_alerts.h): GET only. A HEAD has no
 * answer to describe without reading sloth.db, as /api/query's. */
static int route_alerts(const web_req_t *rq, const web_health_t *h, int one,
                        char *out, size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else if (one) {
        rc = web_alert_route(m, h->live, rq->query, h->wall_s, body, cap, &bl, &status);
    } else {
        rc = web_alerts_route(m, h->live, rq->query, h->wall_s, body, cap, &bl, &status);
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/frrs/... (web_frrs.h): a JSON answer with the module's extra
 * header lines (an Allow, a Retry-After), or the export, a body of its
 * own the connection frees once sent. */
static int route_frrs(const web_req_t *rq, const web_health_t *h, char *out, size_t outsz,
                      web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0, biglen = 0;
    int status = 200;
    char extra[160];
    char *big = NULL;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    int rc = web_frrs_route(m, h->live, rq, h->wall_s, h->now_ms, body, cap, &bl, &status,
                            extra, sizeof(extra), &big, &biglen);
    if (rc != 0 || (bl == 0 && !big)) {
        free(big);
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (big) {
        r->status = status;
        if (fit(snprintf(out, outsz,
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: application/x-ndjson; charset=utf-8\r\n"
            "Content-Length: %zu\r\n"
            "Cache-Control: no-store\r\n"
            "%s"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n", status, web_http_reason(status), biglen, extra), outsz, &r->out_len) != 0) {
            free(big);
            return -1;
        }
        if (rq->is_head) {
            free(big);
        } else {
            r->body = (const unsigned char *)big;
            r->body_len = biglen;
            r->body_free = 1;
        }
        return 0;
    }
    scope_echo(h, body, &bl, cap);
    char hdr[WEB_LIVE_HDR_RESERVE];
    size_t hl;
    if (fit(snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "%s"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status), bl, extra), sizeof(hdr), &hl) != 0)
        return -1;
    if (hl + bl > outsz) return -1;
    r->status = status;
    if (rq->is_head) {
        memcpy(out, hdr, hl);
        r->out_len = hl;
        return 0;
    }
    memmove(out + hl, body, bl);
    memcpy(out, hdr, hl);
    r->out_len = hl + bl;
    return 0;
}

/* /api/pcap/frames and /api/pcap (web_evidence.h): GET only, as
 * /api/alert, whose capture they read. The download is the one answer
 * whose body is the route's own heap copy (web_resp_t.body_owned): a
 * pcap is up to WEB_PCAP_FILE_MAX, past any connection buffer. */
static int route_pcap(const web_req_t *rq, const web_health_t *h, int download,
                      char *out, size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    size_t bl = 0;
    int status = 200, rc;
    static const web_m4_t none;
    const web_m4_t *m = h->m4 ? h->m4 : &none;
    unsigned char *data = NULL;
    size_t dn = 0;
    char name[WEB_PCAP_NAME_MAX + 1] = "";
    const char *hash = NULL;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
        rc = bl ? 0 : -1;
    } else if (download) {
        rc = web_pcap_download_route(m, h->live, rq->query, h->wall_s, &data, &dn, name,
                                     sizeof(name), &hash, body, cap, &bl, &status);
    } else {
        rc = web_pcap_frames_route(m, h->live, rq->query, h->wall_s, body, cap, &bl, &status);
    }
    if (rc == 0 && data) {
        /* The name passed sloth's own grammar ([A-Za-z0-9_.-] only,
         * web_pcapdir_name_ok()), so it needs no quoting. */
        if (fit(snprintf(out, outsz,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/vnd.tcpdump.pcap\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %zu\r\n"
            "X-Sloth-SHA256: %s\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n", name, dn, hash ? hash : "no_manifest_entry"), outsz, &r->out_len) != 0) {
            free(data);
            return -1;
        }
        r->status = 200;
        r->body = data;
        r->body_owned = data;
        r->body_len = dn;
        return 0;
    }
    if (rc != 0 || bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/bundle (web_bundle.h): GET only, like /api/alert. The body is
 * the bundle's own heap buffer (it can outgrow out), handed to the
 * server as r->body_owned behind a header built here; the scope echo
 * is the bundle's own first member, so none is spliced in. */
static int route_bundle(const web_req_t *rq, const web_health_t *h, char *out,
                        size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = NULL;
    size_t bl = 0;
    int status = 200;
    if (qlong(rq)) {
        bl = web_series_error_json("query_too_long", out + WEB_LIVE_HDR_RESERVE,
                                   outsz - WEB_LIVE_HDR_RESERVE);
        if (!bl) return -1;
        return json_answer(rq, h, 400, bl, out, outsz, r);
    }
    if (web_bundle_route(h, rq->query, &body, &bl, &status) != 0 || !body || bl == 0) {
        free(body);
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (fit(snprintf(out, outsz,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status), bl), outsz, &r->out_len) != 0) {
        free(body);
        return -1;
    }
    r->status = status;
    r->body = (const unsigned char *)body;
    r->body_owned = (unsigned char *)body;
    r->body_len = bl;
    return 0;
}

/* /api/fleet/export (web_fleet.h): GET only, a heap body as
 * /api/bundle's. Read-only, and served to whatever the allow list
 * admits, as every route is: the peers a fleet names are --web-allow
 * entries. */
static int route_fleet_export(const web_req_t *rq, const web_health_t *h, char *out,
                              size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (qlong(rq)) {
        if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
        size_t bl = web_series_error_json("query_too_long", out + WEB_LIVE_HDR_RESERVE,
                                          outsz - WEB_LIVE_HDR_RESERVE);
        if (!bl) return -1;
        return json_answer(rq, h, 400, bl, out, outsz, r);
    }
    web_fleet_src_t src = {
        h->m4 ? h->m4->sdb : NULL, h->ble, h->gnss, h->m4 ? h->m4->frrs : NULL,
        h->m4 && h->m4->fleet ? h->m4->fleet->own_csv : NULL, h->adsb,
        h->m4 && h->m4->fleet ? &h->m4->fleet->mine : NULL, h->m4 ? h->m4->chain : NULL,
    };
    char *body = NULL;
    size_t bl = 0;
    int status = 200;
    if (web_fleet_export_route(&src, rq->query, h->wall_s, &body, &bl, &status) != 0 ||
        !body || bl == 0) {
        free(body);
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (fit(snprintf(out, outsz,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status),
        status == 200 ? "application/x-ndjson" : "application/json", bl),
        outsz, &r->out_len) != 0) {
        free(body);
        return -1;
    }
    r->status = status;
    r->body = (const unsigned char *)body;
    r->body_owned = (unsigned char *)body;
    r->body_len = bl;
    return 0;
}

/* /api/fleet/peers (web_fleet.h): what each peer last reported. */
static int route_fleet_peers(const web_req_t *rq, const web_health_t *h, char *out,
                             size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE, bl = 0;
    int status = 200;
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (web_fleet_peers_route(h->m4 ? h->m4->fleet : NULL, rq->query, h->wall_s,
                                     body, cap, &bl, &status) != 0) {
        bl = 0;
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/glossary (web_bundle.h): the bundle's glossary alone. */
static int route_glossary(const web_req_t *rq, const web_health_t *h, char *out, size_t outsz,
                          web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    int status = 200;
    size_t bl;
    if (rq->query[0] || rq->query_long) {
        status = 400;
        bl = web_series_error_json("unknown_parameter", body, cap);
    } else {
        bl = web_bundle_glossary_json(body, cap);
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/fleet/overview (web_fleet.h, F2): the sites, their health and
 * the distances between them. */
static int route_fleet_overview(const web_req_t *rq, const web_health_t *h, char *out,
                                size_t outsz, web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE, bl = 0;
    int status = 200;
    web_fleet_src_t src = {
        h->m4 ? h->m4->sdb : NULL, h->ble, h->gnss, h->m4 ? h->m4->frrs : NULL,
        h->m4 && h->m4->fleet ? h->m4->fleet->own_csv : NULL, h->adsb,
        h->m4 && h->m4->fleet ? &h->m4->fleet->mine : NULL, h->m4 ? h->m4->chain : NULL,
    };
    if (qlong(rq)) {
        status = 400;
        bl = web_series_error_json("query_too_long", body, cap);
    } else if (web_fleet_overview_route(h->m4 ? h->m4->fleet : NULL, &src, rq->query,
                                        h->wall_s, body, cap, &bl, &status) != 0) {
        bl = 0;
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/fleet/shared (web_fleet.h, F2): keys seen at this site and at a
 * peer; /api/fleet/locate (web_locate.h, #192 I5): the emitters two or
 * more sites heard, located. GET only, a heap body as /api/fleet/export's. */
typedef int (*fleet_heap_fn)(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                             long long now_s, char **body, size_t *len, int *status);

static int route_fleet_heap(const web_req_t *rq, const web_health_t *h, char *out,
                            size_t outsz, web_resp_t *r, fleet_heap_fn fn) {
    if (rq->is_head) {
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (qlong(rq)) {
        if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
        size_t bl = web_series_error_json("query_too_long", out + WEB_LIVE_HDR_RESERVE,
                                          outsz - WEB_LIVE_HDR_RESERVE);
        if (!bl) return -1;
        return json_answer(rq, h, 400, bl, out, outsz, r);
    }
    web_fleet_src_t src = {
        h->m4 ? h->m4->sdb : NULL, h->ble, h->gnss, h->m4 ? h->m4->frrs : NULL,
        h->m4 && h->m4->fleet ? h->m4->fleet->own_csv : NULL, h->adsb,
        h->m4 && h->m4->fleet ? &h->m4->fleet->mine : NULL, h->m4 ? h->m4->chain : NULL,
    };
    char *body = NULL;
    size_t bl = 0;
    int status = 200;
    if (fn(h->m4 ? h->m4->fleet : NULL, &src, rq->query, h->wall_s,
           &body, &bl, &status) != 0 || !body || bl == 0) {
        free(body);
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    if (fit(snprintf(out, outsz,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        COMMON
        CSP_NONE
        "Connection: close\r\n"
        "\r\n", status, web_http_reason(status), bl), outsz, &r->out_len) != 0) {
        free(body);
        return -1;
    }
    r->status = status;
    r->body = (const unsigned char *)body;
    r->body_owned = (unsigned char *)body;
    r->body_len = bl;
    return 0;
}

/* /api/recipes: docs/wiki/sqlite-schema.md's, as built in. */
static int route_recipes(const web_req_t *rq, const web_health_t *h, char *out, size_t outsz,
                         web_resp_t *r) {
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    int status = 200;
    size_t bl;
    if (rq->query[0] || rq->query_long) {
        status = 400;
        bl = web_series_error_json("unknown_parameter", body, cap);
    } else {
        web_jw_t w;
        web_jw_init(&w, body, cap);
        web_jw_raw(&w, "{\"source\":");  web_jw_str(&w, web_recipes_source);
        web_jw_raw(&w, ",\"recipes\":[");
        for (size_t i = 0; i < web_recipes_n; i++) {
            web_jw_raw(&w, i ? ",{\"title\":" : "{\"title\":");
            web_jw_str(&w, web_recipes[i].title);
            web_jw_raw(&w, ",\"sql\":");
            web_jw_str(&w, web_recipes[i].sql);
            web_jw_raw(&w, "}");
        }
        web_jw_raw(&w, "]}\n");
        bl = w.overflow ? 0 : w.len;
    }
    if (bl == 0) {
        r->status = 503;
        r->out_len = web_http_response(503, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    return json_answer(rq, h, status, bl, out, outsz, r);
}

/* /api/query (web_sqlbox.h). The text is checked here, on the loop's
 * thread, before anything is queued: a malformed or non-SELECT request
 * never reaches the box. What needs the statement prepared (one
 * statement, the authorizer, read-only) is the box thread's. */
static int route_query(const web_req_t *rq, const web_health_t *h, char *out,
                       size_t outsz, web_resp_t *r) {
    if (rq->is_head) {
        /* GET only: there is no answer to describe without running it. */
        r->status = 405;
        return fit(snprintf(out, outsz,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Allow: GET\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            COMMON
            CSP_NONE
            "Connection: close\r\n"
            "\r\n"), outsz, &r->out_len);
    }
    if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
    char *body = out + WEB_LIVE_HDR_RESERVE;
    size_t cap = outsz - WEB_LIVE_HDR_RESERVE;
    char sql[WEB_SQL_MAX_BYTES + 1];
    size_t len = 0;
    const char *why = NULL;
    if (rq->query_long) why = "too_long";
    else if (web_sqlbox_param(rq->query, sql, sizeof(sql), &len, &why) == 0 &&
             web_sqlbox_precheck(sql, len, &why) == 0)
        why = NULL;
    size_t bl;
    if (why) {
        bl = web_series_error_json(why, body, cap);
        if (!bl) return -1;
        return json_answer(rq, h, 400, bl, out, outsz, r);
    }
    if (web_sqlbox_submit(h->sql, sql, len, h->wall_s) != 0) {
        bl = web_series_error_json("busy", body, cap);
        if (!bl) return -1;
        return json_answer(rq, h, 503, bl, out, outsz, r);
    }
    r->kind = WEB_R_SQL;
    r->status = 200;
    r->out_len = 0;
    return 0;
}

static int route_events(const web_req_t *rq, int sse_room, char *out,
                        size_t outsz, web_resp_t *r) {
    if (!rq->is_head && !sse_room) {
        r->status = 503;
        r->out_len = web_http_response(503, 0, out, outsz);
        return r->out_len ? 0 : -1;
    }
    r->status = 200;
    /* HEAD gets the stream's headers and the connection ends: there is
     * no length to promise and nothing to hold open. */
    if (!rq->is_head) r->kind = WEB_R_SSE;
    char retry[32] = "";
    if (!rq->is_head)
        snprintf(retry, sizeof(retry), "retry: %d\n\n", WEB_SSE_RETRY_MS);
    return fit(snprintf(out, outsz,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        COMMON
        CSP_NONE
        "Connection: %s\r\n"
        "\r\n"
        "%s",
        rq->is_head ? "close" : "keep-alive",
        retry), outsz, &r->out_len);
}

int web_route(const web_req_t *rq, const web_health_t *h, int sse_room,
              char *out, size_t outsz, web_resp_t *r) {
    memset(r, 0, sizeof(*r));
    r->kind = WEB_R_ONESHOT;
    /* RFC 9112 §3.2: an HTTP/1.1 request with no Host, or more than
     * one, is a 400. */
    if (rq->host_count != 1) {
        r->status = 400;
        r->out_len = web_http_response(400, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    /* DNS rebinding: the peer is loopback, so the allow list admits it,
     * but the page that sent the request may be another site's whose
     * name now resolves here. Its Host is that name. Refused before the
     * table, so such a page cannot even tell which paths exist. */
    const char *host = rq->target_abs ? rq->target_host : rq->host;
    int host_long = rq->target_abs ? rq->target_host_long : rq->host_long;
    if (host_long || !web_http_host_ok(host)) {
        r->status = 421;
        r->out_len = web_http_response(421, rq->is_head, out, outsz);
        return r->out_len ? 0 : -1;
    }
    /* The capture scope, taken out of the query before a route's own
     * parser sees it. A query that does not name one is routed as it
     * came, so every answer without a scope is as it was. */
    if (!rq->path_long && !strncmp(rq->path, "/api/", 5) &&
        strcmp(rq->path, "/api/health") && strcmp(rq->path, "/api/query") &&
        !qlong(rq) && strstr(rq->query, "scope"))
        return route_scoped(rq, h, sse_room, out, outsz, r);
    return route_paths(rq, h, sse_room, out, outsz, r);
}

enum { MG_DEVICES, MG_DEVICE, MG_APS, MG_BLE, MG_BLEDEV, MG_PRCLIENTS, MG_PRSSIDS,
       MG_ADSB, MG_ADSB_SEEN, MG_ADSB_AC };

/* The merged views (web_fleetview.h): fleet= taken out of the query as
 * scope= is, the route answered as before on the rest, and the peers'
 * rows merged into its answer when the request asks for them (fleet=1
 * or no fleet=), a peer is configured and the request is Hybrid's. */
static int route_merged(const web_req_t *rq, const web_health_t *h, int which,
                        const char *arg, char *out, size_t outsz, web_resp_t *r) {
    web_health_t hh = *h;
    hh.fleet_merge = 0;
    web_req_t *q = NULL;
    const web_req_t *use = rq;
    if (!qlong(rq) && strstr(rq->query, "fleet")) {
        int mode;
        char why[48] = "";
        q = malloc(sizeof(*q));
        if (!q) return -1;
        *q = *rq;
        if (web_fv_take(rq->query, q->query, WEB_QUERY_ROUTE_MAX, &mode, why,
                        sizeof(why)) != 0) {
            free(q);
            if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
            size_t bl = web_series_error_json(why, out + WEB_LIVE_HDR_RESERVE,
                                              outsz - WEB_LIVE_HDR_RESERVE);
            if (!bl) return -1;
            return json_answer(rq, h, 400, bl, out, outsz, r);
        }
        hh.fleet_merge = web_fv_on(h->m4 ? h->m4->fleet : NULL, mode, h->sc);
        use = q;
    } else {
        hh.fleet_merge = web_fv_on(h->m4 ? h->m4->fleet : NULL, WEB_FV_DEFAULT, h->sc);
    }
    int rc;
    switch (which) {
    case MG_DEVICES: rc = route_m4(use, &hh, M4_DEVICES, NULL, out, outsz, r); break;
    case MG_DEVICE:  rc = route_m4(use, &hh, M4_DEVICE, arg, out, outsz, r); break;
    case MG_APS:     rc = route_m5(use, &hh, M5_APS, out, outsz, r); break;
    case MG_BLE:     rc = route_ble(use, &hh, BLE_DEVICES, NULL, out, outsz, r); break;
    case MG_PRCLIENTS: rc = route_m5(use, &hh, PR_CLIENTS, out, outsz, r); break;
    case MG_PRSSIDS: rc = route_m5(use, &hh, PR_SSIDS, out, outsz, r); break;
    case MG_ADSB:    rc = route_adsb(use, &hh, out, outsz, r); break;
    case MG_ADSB_SEEN: rc = route_m5(use, &hh, RF_ADSB_SEEN, out, outsz, r); break;
    case MG_ADSB_AC: rc = route_m5(use, &hh, RF_ADSB_AC, out, outsz, r); break;
    default:         rc = route_ble(use, &hh, BLE_DEVICE, arg, out, outsz, r); break;
    }
    free(q);
    return rc;
}

static int route_scoped(const web_req_t *rq, const web_health_t *h,
                        int sse_room, char *out, size_t outsz, web_resp_t *r) {
    static const web_m4_t none;
    web_scope_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    char why[48] = "";
    web_req_t *q = malloc(sizeof(*q));
    if (!q) return -1;
    *q = *rq;
    if (web_scope_take(rq->query, q->query, WEB_QUERY_ROUTE_MAX, &sc.scope,
                       &sc.given, why, sizeof(why)) != 0) {
        free(q);
        if (outsz <= WEB_LIVE_HDR_RESERVE) return -1;
        size_t bl = web_series_error_json(why, out + WEB_LIVE_HDR_RESERVE,
                                          outsz - WEB_LIVE_HDR_RESERVE);
        if (!bl) return -1;
        return json_answer(rq, h, 400, bl, out, outsz, r);
    }
    if (h->live) web_live_scope_ctx(h->live, &sc);
    web_health_t hh = *h;
    web_m4_t mm = h->m4 ? *h->m4 : none;
    mm.sc = &sc;
    hh.sc = &sc;
    hh.m4 = &mm;
    int rc = route_paths(q, &hh, sse_room, out, outsz, r);
    free(q);
    return rc;
}

static int route_paths(const web_req_t *rq, const web_health_t *h,
                       int sse_room, char *out, size_t outsz, web_resp_t *r) {
    if (!rq->path_long) {
        if (!strcmp(rq->path, "/"))
            return route_page(rq, out, outsz, r);
        if (!strcmp(rq->path, "/api/health"))
            return route_health(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/live"))
            return route_live(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/events"))
            return route_events(rq, sse_room, out, outsz, r);
        if (!strcmp(rq->path, "/api/series"))
            return route_series(rq, h, SR_SERIES, out, outsz, r);
        if (!strcmp(rq->path, "/api/keys"))
            return route_series(rq, h, SR_KEYS, out, outsz, r);
        if (!strcmp(rq->path, "/api/series/all"))
            return route_allkeys(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/metrics"))
            return route_series(rq, h, SR_METRICS, out, outsz, r);
        if (!strcmp(rq->path, "/api/anomalies"))
            return route_anomalies(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/baseline"))
            return route_baseline(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/devices"))
            return route_merged(rq, h, MG_DEVICES, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/lookup"))
            return route_m4(rq, h, M4_LOOKUP, NULL, out, outsz, r);
        if (!strncmp(rq->path, "/api/device/", 12) && rq->path[12] &&
            !strchr(rq->path + 12, '/'))
            return route_merged(rq, h, MG_DEVICE, rq->path + 12, out, outsz, r);
        if (!strcmp(rq->path, "/api/wifi/aps"))
            return route_merged(rq, h, MG_APS, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/probes/clients"))
            return route_merged(rq, h, MG_PRCLIENTS, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/probes/ssids"))
            return route_merged(rq, h, MG_PRSSIDS, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/adsb/seen"))
            return route_merged(rq, h, MG_ADSB_SEEN, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/adsb/aircraft"))
            return route_merged(rq, h, MG_ADSB_AC, NULL, out, outsz, r);
        static const struct { const char *path; int which; } M5[] = {
            { "/api/wifi/channels", M5_CHANNELS },
            { "/api/wifi/deauth", M5_DEAUTH },
            { "/api/wifi/chain", M5_CHAIN },
            /* GNSS and ADS-B history (web_rfhist.h): sloth.db's. */
            { "/api/gnss/seen", RF_GNSS_SEEN },
            { "/api/gnss/sat", RF_GNSS_SAT },
            { "/api/gnss/tracks", RF_GNSS_TRACKS },
            /* APRS history (web_aprshist.h): sloth.db's. */
            { "/api/aprs/seen", RF_APRS_SEEN },
            { "/api/aprs/station", RF_APRS_STN },
            { "/api/aprs/tracks", RF_APRS_TRK },
            { "/api/wifi/local", M5_WLOCAL },
            { "/api/history/overview", M5_OVERVIEW },
            { "/api/history/devices", M5_HDEVICES },
            { "/api/history/alerts", M5_HALERTS },
            { "/api/history/flows", M5_HFLOWS },
            { "/api/sessions", M5_SESSIONS },
            { "/api/sessions/new", M5_SESSIONS_NEW },
            { "/api/flows", M6_FLOWS },
            { "/api/flows/graph", M6_GRAPH },
            /* One SSID's detail (web_ssidview.h). */
            { "/api/wifi/ssid", M5_SSID },
            /* The Probes view (web_probes.h). */
            { "/api/probes/shared", PR_SHARED },
            { "/api/probes/groups", PR_GROUPS },
        };
        for (size_t i = 0; i < sizeof(M5) / sizeof(M5[0]); i++)
            if (!strcmp(rq->path, M5[i].path))
                return route_m5(rq, h, M5[i].which, out, outsz, r);
        if (!strcmp(rq->path, "/api/alerts"))
            return route_alerts(rq, h, 0, out, outsz, r);
        if (!strcmp(rq->path, "/api/alert"))
            return route_alerts(rq, h, 1, out, outsz, r);
        if (!strncmp(rq->path, "/api/frrs/", 10) && web_frrs_path(rq->path))
            return route_frrs(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/gnss"))
            return route_gnss(rq, h, 0, out, outsz, r);
        if (!strcmp(rq->path, "/api/gnss/fixes"))
            return route_gnss(rq, h, 1, out, outsz, r);
        if (!strcmp(rq->path, "/api/adsb"))
            return route_merged(rq, h, MG_ADSB, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/aprs"))
            return route_aprs(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/sys"))
            return route_sys(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/lures"))
            return route_lures(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/radar"))
            return route_radar(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/ble"))
            return route_merged(rq, h, MG_BLE, NULL, out, outsz, r);
        if (!strcmp(rq->path, "/api/ble/alerts"))
            return route_ble(rq, h, BLE_ALERTS, NULL, out, outsz, r);
        /* Before the address branch below, which would read either as a
         * bad address. */
        if (!strcmp(rq->path, "/api/ble/classes"))
            return route_bledev(rq, h, 0, out, outsz, r);
        if (!strcmp(rq->path, "/api/ble/proximity"))
            return route_bledev(rq, h, 1, out, outsz, r);
        if (!strncmp(rq->path, "/api/ble/", 9) && rq->path[9] &&
            !strchr(rq->path + 9, '/'))
            return route_merged(rq, h, MG_BLEDEV, rq->path + 9, out, outsz, r);
        if (!strcmp(rq->path, "/api/pcap/frames"))
            return route_pcap(rq, h, 0, out, outsz, r);
        if (!strcmp(rq->path, "/api/pcap"))
            return route_pcap(rq, h, 1, out, outsz, r);
        if (!strcmp(rq->path, "/api/bundle"))
            return route_bundle(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/positions"))
            return route_positions(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/fleet/export"))
            return route_fleet_export(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/fleet/peers"))
            return route_fleet_peers(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/glossary"))
            return route_glossary(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/fleet/overview"))
            return route_fleet_overview(rq, h, out, outsz, r);
        if (!strcmp(rq->path, "/api/fleet/shared"))
            return route_fleet_heap(rq, h, out, outsz, r, web_fleet_shared_route);
        if (!strcmp(rq->path, "/api/fleet/locate"))
            return route_fleet_heap(rq, h, out, outsz, r, web_fleet_locate_route);
        if (!strcmp(rq->path, "/api/fleet/gnss"))
            return route_fleet_heap(rq, h, out, outsz, r, web_fleet_gnss_route);
        if (!strcmp(rq->path, "/api/fleet/aircraft"))
            return route_fleet_heap(rq, h, out, outsz, r, web_fleet_aircraft_route);
        if (!strcmp(rq->path, "/api/fleet/findings"))
            return route_fleet_heap(rq, h, out, outsz, r, web_fleet_findings_route);
        /* Without --web-allow-sql neither exists: a 404 like any path. */
        if (h->sql && h->sql->enabled) {
            if (!strcmp(rq->path, "/api/query"))
                return route_query(rq, h, out, outsz, r);
            if (!strcmp(rq->path, "/api/recipes"))
                return route_recipes(rq, h, out, outsz, r);
        }
    }
    r->status = 404;
    r->out_len = web_http_response(404, rq->is_head, out, outsz);
    return r->out_len ? 0 : -1;
}

size_t web_sse_tick(char *out, size_t outsz, unsigned long seq, long long ts,
                    const web_health_t *h) {
    char data[512];
    web_jw_t w;
    web_jw_init(&w, data, sizeof(data));
    web_jw_raw(&w, "{\"seq\":");        web_jw_int(&w, (long long)seq);
    web_jw_raw(&w, ",\"ts\":");         web_jw_int(&w, ts);
    web_jw_raw(&w, ",\"uptime_s\":");   web_jw_int(&w, h->uptime_s);
    web_jw_raw(&w, ",\"sse_clients\":"); web_jw_int(&w, h->sse_clients);
    if (h->live) {
        web_live_sum_t s;
        char r10[32];
        web_live_summary(h->live, &s, h->now_ms);
        web_jw_raw(&w, ",\"socket\":"); web_jw_str(&w, web_live_sock_word(s.sock_state));
        web_jw_raw(&w, ",\"devices\":");
        if (s.dev_known) web_jw_int(&w, s.devices); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"devices_stale\":"); web_jw_raw(&w, s.dev_stale ? "true" : "false");
        web_jw_raw(&w, ",\"alerts_open\":[");
        web_jw_int(&w, (long long)s.alerts[0]); web_jw_raw(&w, ",");
        web_jw_int(&w, (long long)s.alerts[1]); web_jw_raw(&w, ",");
        web_jw_int(&w, (long long)s.alerts[2]); web_jw_raw(&w, "]");
        snprintf(r10, sizeof(r10), "%ld.%ld", s.rate10 / 10, s.rate10 % 10);
        web_jw_raw(&w, ",\"records_s\":"); web_jw_raw(&w, r10);
        web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)s.records);
        web_jw_raw(&w, ",\"sensor\":"); web_jw_str(&w, s.sensor);
    }
    if (h->anomaly) {
        web_jw_raw(&w, ",\"anomalies_open\":");
        web_jw_int(&w, web_anomaly_open_count(h->anomaly));
    }
    web_jw_raw(&w, "}");
    if (w.overflow) return 0;
    int n = snprintf(out, outsz, "id: %lu\nevent: tick\ndata: %s\n\n", seq, data);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_record(char *out, size_t outsz, const web_live_rec_t *e) {
    /* The escaped JSON holds no raw CR or LF (web_jw_strn escapes both),
     * so it is one SSE data line whatever the record said. */
    char data[(WEB_LIVE_TYPE_MAX + 2 * WEB_LIVE_TEXT_MAX) * WEB_JW_EXPAND + 160];
    web_jw_t w;
    web_jw_init(&w, data, sizeof(data));
    web_jw_raw(&w, "{\"seq\":");  web_jw_int(&w, (long long)e->seq);
    web_jw_raw(&w, ",\"type\":"); web_jw_str(&w, e->type);
    web_jw_raw(&w, ",\"ts\":");   web_jw_int(&w, e->ts);
    web_jw_raw(&w, ",\"text\":"); web_jw_str(&w, e->text);
    /* Its capture-scope tag (web_scope.h): the page's ticker keeps the
     * records of the scope it shows. */
    web_jw_raw(&w, ",\"sc\":");   web_jw_int(&w, e->sc);
    /* A device row's Monitor line (web_live_rec_t), which the page shows
     * in place of text under Monitor. The stream goes to every page
     * whatever its scope, so both lines travel; the scope is a view of
     * one viewer's data, not a boundary between viewers. */
    if (!strcmp(e->type, "device")) {
        web_jw_raw(&w, ",\"text_m\":"); web_jw_str(&w, e->text_m);
    }
    web_jw_raw(&w, "}");
    if (w.overflow) return 0;
    int n = snprintf(out, outsz, "event: record\ndata: %s\n\n", data);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_anomaly(char *out, size_t outsz, const web_anom_ep_t *e) {
    char data[WEB_ANOM_EP_JSON_MAX + 64];
    web_jw_t w;
    web_jw_init(&w, data, sizeof(data));
    web_anomaly_ep_json(&w, e);
    if (w.overflow) return 0;
    /* One data line: web_jw_str escapes CR and LF. */
    int n = snprintf(out, outsz, "event: anomaly\ndata: %s\n\n", data);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return (size_t)n;
}

size_t web_sse_ping(char *out, size_t outsz) {
    static const char ping[] = ": ping\n\n";
    if (outsz < sizeof(ping)) return 0;
    memcpy(out, ping, sizeof(ping));
    return sizeof(ping) - 1;
}
