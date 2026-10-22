#include "web_anomaly.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"

static const char *kind_name(int kind) {
    switch (kind) {
    case WEB_ANOM_A1_RATE:   return "rate";
    case WEB_ANOM_A3_HOURS:  return "hours";
    case WEB_ANOM_A8_DNS:    return "dns";
    case WEB_ANOM_A9_PROTO:  return "proto";
    case WEB_ANOM_A10_SENSOR:return "sensor";
    default:                 return "unknown";
    }
}

static int req_streak(int kind) {
    return kind == WEB_ANOM_A1_RATE ? WEB_ANOM_STREAK_MIN : 1;
}

int web_anomaly_init(web_anomaly_t *a, int cap) {
    memset(a, 0, sizeof(*a));
    if (cap < 1) cap = 1;
    a->cap = cap;
    a->last_minute = -1;
    a->last_hour = -1;
    pthread_mutex_init(&a->mu, NULL);
    a->ep = calloc((size_t)cap, sizeof(*a->ep));
    return a->ep ? 0 : -1;
}

void web_anomaly_destroy(web_anomaly_t *a) {
    free(a->ep);
    a->ep = NULL;
}

/* The slot to reuse for a new episode when the table is full: an
 * unused one if there is one (there never is once the table has
 * filled once), else the closed one with the oldest last_seen, else
 * the open one with the oldest last_seen. */
static int find_slot_locked(web_anomaly_t *a) {
    int free_i = -1, closed_i = -1, open_i = -1;
    for (int i = 0; i < a->cap; i++) {
        if (!a->ep[i].used) { free_i = i; break; }
        if (!a->ep[i].open) {
            if (closed_i < 0 || a->ep[i].last_seen < a->ep[closed_i].last_seen)
                closed_i = i;
        } else {
            if (open_i < 0 || a->ep[i].last_seen < a->ep[open_i].last_seen)
                open_i = i;
        }
    }
    if (free_i >= 0) return free_i;
    if (closed_i >= 0) return closed_i;
    return open_i;
}

static int find_ep_locked(web_anomaly_t *a, int kind, int metric,
                          const char *key) {
    for (int i = 0; i < a->cap; i++)
        if (a->ep[i].used && a->ep[i].kind == kind &&
            a->ep[i].metric == metric && !strcmp(a->ep[i].key, key))
            return i;
    return -1;
}

/* One condition held this minute for (kind, metric, key): advance its
 * episode (creating it if this is the first time) and open it once it
 * has held for req_streak(kind) consecutive minutes. */
static void touch_locked(web_anomaly_t *a, int kind, int metric,
                         const char *key, double score, const char *evidence,
                         long long now_s) {
    int i = find_ep_locked(a, kind, metric, key);
    if (i < 0) {
        i = find_slot_locked(a);
        if (i < 0) return;
        if (a->ep[i].used && a->ep[i].open) a->closed++;
        memset(&a->ep[i], 0, sizeof(a->ep[i]));
        a->ep[i].used = 1;
        a->ep[i].kind = kind;
        a->ep[i].metric = metric;
        snprintf(a->ep[i].key, sizeof(a->ep[i].key), "%s", key);
        a->ep[i].first_seen = now_s;
        a->ep[i].hit_streak = 0;
    }
    web_anom_ep_t *e = &a->ep[i];
    e->hit_streak++;
    e->clear_streak = 0;
    e->last_seen = now_s;
    if (score > e->score) e->score = score;
    snprintf(e->evidence, sizeof(e->evidence), "%s", evidence);
    if (!e->open && e->hit_streak >= req_streak(kind)) {
        e->open = 1;
        a->opened++;
    }
}

static double z_score(double z) {
    double s = fabs(z) * 20.0;
    return s > 100.0 ? 100.0 : s;
}

static void scan_a1(web_anomaly_t *a, web_baseline_t *bl, web_rollup_t *ru,
                    web_store_t *store, long long now_s) {
    web_keyinfo_t keys[WEB_ANOM_SCAN_MAX];
    for (int m = 0; m < WM_COUNT; m++) {
        if (web_metric_defs[m].kind == WEB_MK_PRESENCE) continue;
        int total;
        int got = web_rollup_keys(ru, m, keys, WEB_ANOM_SCAN_MAX, &total);
        for (int k = 0; k < got; k++) {
            web_point_t pt;
            int more;
            if (web_store_query(store, WEB_TIER_MINUTE, m, keys[k].key,
                                now_s - 120, now_s, &pt, 1, &more) != 1)
                continue;
            double v = web_point_value(m, &pt);
            double scaled = web_metric_defs[m].kind == WEB_MK_COUNTER
                           ? v * 60.0 : v;
            web_bl_score_t sc;
            if (web_baseline_score(bl, m, keys[k].key, now_s, scaled,
                                   &sc) != 0 || sc.warming)
                continue;
            if (fabs(sc.z) < WEB_ANOM_Z_THRESHOLD) continue;
            char ev[WEB_ANOM_EVIDENCE_MAX];
            snprintf(ev, sizeof(ev),
                    "%.31s%s%.47s z=%.1f value=%.3g baseline=%.3g\xc2\xb1%.3g",
                    web_metric_defs[m].name, keys[k].key[0] ? "[" : "",
                    keys[k].key, sc.z, scaled, sc.mean, sc.sd);
            touch_locked(a, WEB_ANOM_A1_RATE, m, keys[k].key,
                        z_score(sc.z), ev, now_s);
        }
    }
}

static void scan_a3(web_anomaly_t *a, web_baseline_t *bl, web_rollup_t *ru,
                    web_store_t *store, long long now_s) {
    web_keyinfo_t keys[WEB_ANOM_SCAN_MAX];
    int total;
    int got = web_rollup_keys(ru, WM_DEV_PRESENT, keys, WEB_ANOM_SCAN_MAX, &total);
    for (int k = 0; k < got; k++) {
        web_point_t pt;
        int more;
        if (web_store_query(store, WEB_TIER_MINUTE, WM_DEV_PRESENT,
                            keys[k].key, now_s - 120, now_s, &pt, 1,
                            &more) != 1)
            continue;
        if (web_point_value(WM_DEV_PRESENT, &pt) < 0.5) continue;
        web_bl_score_t sc;
        if (web_baseline_score(bl, WM_DEV_PRESENT, keys[k].key, now_s, 1.0,
                               &sc) != 0 || sc.warming)
            continue;
        if (sc.n < WEB_ANOM_A3_MIN_N || sc.mean >= WEB_ANOM_A3_MEAN_MAX)
            continue;
        char ev[WEB_ANOM_EVIDENCE_MAX];
        snprintf(ev, sizeof(ev),
                "dev.present[%.47s] present now; this hour of the week is "
                "normally absent (baseline=%.3f over %d weeks)",
                keys[k].key, sc.mean, sc.n);
        touch_locked(a, WEB_ANOM_A3_HOURS, WM_DEV_PRESENT, keys[k].key,
                    70.0, ev, now_s);
    }
}

static void scan_a8(web_anomaly_t *a, web_rollup_t *ru, web_store_t *store,
                    long long now_s) {
    web_keyinfo_t keys[WEB_ANOM_SCAN_MAX];
    int total;
    int got = web_rollup_keys(ru, WM_DNS_QUERIES, keys, WEB_ANOM_SCAN_MAX, &total);
    for (int k = 0; k < got; k++) {
        web_point_t q[WEB_ANOM_A8_WINDOW_S / 60 + 1];
        web_point_t nx[WEB_ANOM_A8_WINDOW_S / 60 + 1];
        int more;
        int qn = web_store_query(store, WEB_TIER_MINUTE, WM_DNS_QUERIES,
                                 keys[k].key, now_s - WEB_ANOM_A8_WINDOW_S,
                                 now_s, q, (int)(sizeof(q) / sizeof(q[0])),
                                 &more);
        int xn = web_store_query(store, WEB_TIER_MINUTE, WM_DNS_NXDOMAIN,
                                 keys[k].key, now_s - WEB_ANOM_A8_WINDOW_S,
                                 now_s, nx, (int)(sizeof(nx) / sizeof(nx[0])),
                                 &more);
        if (qn < 0) qn = 0;
        if (xn < 0) xn = 0;
        double totalq = 0, totalnx = 0;
        for (int i = 0; i < qn; i++)
            totalq += web_point_value(WM_DNS_QUERIES, &q[i]);
        for (int i = 0; i < xn; i++)
            totalnx += web_point_value(WM_DNS_NXDOMAIN, &nx[i]);
        if (totalq < WEB_ANOM_A8_MIN_Q) continue;
        double share = totalnx / totalq;
        if (share <= WEB_ANOM_A8_NX_SHARE) continue;
        char ev[WEB_ANOM_EVIDENCE_MAX];
        snprintf(ev, sizeof(ev),
                "dns.nxdomain[%.47s] %.0f%% of %.0f queries over %ds NXDOMAIN",
                keys[k].key, share * 100.0, totalq, WEB_ANOM_A8_WINDOW_S);
        touch_locked(a, WEB_ANOM_A8_DNS, WM_DNS_QUERIES, keys[k].key,
                    60.0, ev, now_s);
    }
}

static void scan_a9(web_anomaly_t *a, web_baseline_t *bl, web_rollup_t *ru,
                    web_store_t *store, long long now_s) {
    static const int flows[] = {
        WM_FLOW_SSH, WM_FLOW_RDP, WM_FLOW_SMB, WM_FLOW_SNMP, WM_FLOW_MQTT
    };
    web_keyinfo_t keys[WEB_ANOM_SCAN_MAX];
    for (size_t f = 0; f < sizeof(flows) / sizeof(flows[0]); f++) {
        int m = flows[f];
        int total;
        int got = web_rollup_keys(ru, m, keys, WEB_ANOM_SCAN_MAX, &total);
        for (int k = 0; k < got; k++) {
            web_point_t pt;
            int more;
            if (web_store_query(store, WEB_TIER_MINUTE, m, keys[k].key,
                                now_s - 120, now_s, &pt, 1, &more) != 1)
                continue;
            if (web_point_value(m, &pt) <= 0) continue;
            web_bl_score_t sc;
            /* A baseline entry already exists: this key has had an
             * hour close for this metric before, so it is not the
             * first time. Only "never fed" (-1) counts as first use. */
            if (web_baseline_score(bl, m, keys[k].key, now_s, 0, &sc) == 0)
                continue;
            char ev[WEB_ANOM_EVIDENCE_MAX];
            snprintf(ev, sizeof(ev),
                    "%.31s[%.47s] first use seen", web_metric_defs[m].name,
                    keys[k].key);
            touch_locked(a, WEB_ANOM_A9_PROTO, m, keys[k].key, 50.0, ev,
                        now_s);
        }
    }
}

static void scan_a10(web_anomaly_t *a, web_live_t *live, long long now_s,
                     long long now_ms) {
    if (!live) return;
    web_live_sum_t sum;
    web_live_summary(live, &sum, now_ms);
    if (sum.sock_state != WEB_SOCK_CONNECTED) return;
    if (sum.last_record_age_ms < 0) return;
    if (sum.last_record_age_ms < (long long)WEB_ANOM_A10_SILENCE_S * 1000)
        return;
    char ev[WEB_ANOM_EVIDENCE_MAX];
    snprintf(ev, sizeof(ev),
            "no record for %lld ms while the socket is connected",
            sum.last_record_age_ms);
    touch_locked(a, WEB_ANOM_A10_SENSOR, -1, "", 80.0, ev, now_s);
}

void web_anomaly_step(web_anomaly_t *a, web_baseline_t *bl, web_rollup_t *ru,
                      web_store_t *store, web_live_t *live, long long now_s,
                      long long now_ms) {
    long long hour = now_s / 3600;
    long long minute = now_s / 60;

    pthread_mutex_lock(&a->mu);
    int do_hour = hour != a->last_hour;
    int do_minute = minute != a->last_minute;
    if (do_hour) a->last_hour = hour;
    if (do_minute) a->last_minute = minute;
    pthread_mutex_unlock(&a->mu);

    if (store && do_hour) {
        /* The hour that just closed started one hour before this one. */
        long long closed_start = (hour - 1) * 3600;
        long long closed_end = hour * 3600;
        web_keyinfo_t keys[WEB_ANOM_SCAN_MAX];
        for (int m = 0; m < WM_COUNT; m++) {
            int total;
            int got = web_rollup_keys(ru, m, keys, WEB_ANOM_SCAN_MAX, &total);
            for (int k = 0; k < got; k++) {
                web_point_t pt;
                int more;
                if (web_store_query(store, WEB_TIER_HOUR, m, keys[k].key,
                                    closed_start, closed_end, &pt, 1,
                                    &more) != 1)
                    continue;
                web_baseline_feed(bl, m, keys[k].key, closed_start,
                                  web_point_value(m, &pt));
            }
        }
    }

    if (!do_minute) return;
    pthread_mutex_lock(&a->mu);
    /* A1, A3, A8 and A9 all read the minute or hour tier through
     * store: without one (WITH_SQLITE=0, or none opened) they have
     * nothing to score. A10 needs only the live state, so it still
     * runs. */
    if (store) {
        scan_a1(a, bl, ru, store, now_s);
        scan_a3(a, bl, ru, store, now_s);
        scan_a8(a, ru, store, now_s);
        scan_a9(a, bl, ru, store, now_s);
    }
    scan_a10(a, live, now_s, now_ms);
    /* Anything open or building that was not touched this minute (its
     * last_seen still lags now_s) is quiet: advance it toward closing,
     * or drop a never-opened builder outright. */
    for (int i = 0; i < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if (!e->used || e->last_seen == now_s) continue;
        if (e->open) {
            if (++e->clear_streak >= WEB_ANOM_CLEAR_TICKS) {
                e->open = 0;
                a->closed++;
            }
        } else {
            e->used = 0;
        }
    }
    pthread_mutex_unlock(&a->mu);
}

size_t web_anomaly_json(web_anomaly_t *a, long long now_s, char *out,
                        size_t cap) {
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"anomalies\":[");
    pthread_mutex_lock(&a->mu);
    int first = 1;
    for (int i = 0; i < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if (!e->used) continue;
        if (!e->open && now_s - e->last_seen > WEB_ANOM_RECENT_S) continue;
        if (!first) web_jw_raw(&w, ",");
        first = 0;
        web_jw_raw(&w, "{\"kind\":\"");
        web_jw_raw(&w, kind_name(e->kind));
        web_jw_raw(&w, "\",\"key\":");
        web_jw_str(&w, e->key);
        web_jw_raw(&w, ",\"score\":");
        web_jw_int(&w, (long long)(e->score + 0.5));
        web_jw_raw(&w, ",\"evidence\":");
        web_jw_str(&w, e->evidence);
        web_jw_raw(&w, ",\"first_seen\":");
        web_jw_int(&w, e->first_seen);
        web_jw_raw(&w, ",\"last_seen\":");
        web_jw_int(&w, e->last_seen);
        web_jw_raw(&w, ",\"open\":");
        web_jw_raw(&w, e->open ? "true" : "false");
        web_jw_raw(&w, "}");
    }
    pthread_mutex_unlock(&a->mu);
    web_jw_raw(&w, "]}\n");
    return w.overflow ? 0 : w.len;
}
