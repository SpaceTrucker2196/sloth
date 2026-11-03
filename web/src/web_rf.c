#include "web_rf.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_frrs.h"

long long web_rf_from(long long now_s) {
    long long last = now_s - ((now_s % WEB_RF_CELL_S) + WEB_RF_CELL_S) % WEB_RF_CELL_S;
    return last - (long long)(WEB_RF_CELLS - 1) * WEB_RF_CELL_S;
}

static int count_cells(const web_agg_t *c) {
    int n = 0;
    for (int i = 0; i < WEB_RF_CELLS; i++) if (c[i].n) n++;
    return n;
}

void web_rf_trails(web_rollup_t *ru, const web_scope_ctx_t *sc,
                   const char (*macs)[WEB_KEY_MAX + 1], const int *is_ap,
                   int n, long long now_s, web_rf_trail_t *out) {
    for (int k = 0; k < n; k++) {
        memset(&out[k], 0, sizeof(out[k]));
        out[k].metric = -1;
    }
    if (!ru || n <= 0 || !web_scope_ok(sc, web_scope_metric(WM_RF_RSSI_STA)))
        return;
    long long from = web_rf_from(now_s), until = from + (long long)WEB_RF_CELLS * WEB_RF_CELL_S;
    web_agg_t *sta = calloc((size_t)n * WEB_RF_CELLS, sizeof(*sta));
    web_agg_t *bss = calloc((size_t)n * WEB_RF_CELLS, sizeof(*bss));
    if (!sta || !bss) { free(sta); free(bss); return; }
    web_rollup_trail(ru, WM_RF_RSSI_STA, macs, n, from, until, WEB_RF_CELLS,
                     WEB_RF_CELL_S, sta);
    web_rollup_trail(ru, WM_RF_RSSI_BSSID, macs, n, from, until, WEB_RF_CELLS,
                     WEB_RF_CELL_S, bss);
    for (int k = 0; k < n; k++) {
        const web_agg_t *a = (is_ap && is_ap[k] ? bss : sta) + (size_t)k * WEB_RF_CELLS;
        const web_agg_t *b = (is_ap && is_ap[k] ? sta : bss) + (size_t)k * WEB_RF_CELLS;
        int am = is_ap && is_ap[k] ? WM_RF_RSSI_BSSID : WM_RF_RSSI_STA;
        int na = count_cells(a), nb = na ? 0 : count_cells(b);
        const web_agg_t *use = nb ? b : a;
        out[k].metric = nb ? (am == WM_RF_RSSI_STA ? WM_RF_RSSI_BSSID : WM_RF_RSSI_STA) : am;
        out[k].n = nb ? nb : na;
        memcpy(out[k].cell, use, sizeof(out[k].cell));
    }
    free(sta);
    free(bss);
}

static long long dbm(double v) { return (long long)floor(v + 0.5); }

void web_rf_json(web_jw_t *w, const web_rf_trail_t *t, struct web_frrs *frrs,
                 const char *mac, long long now_s) {
    web_jw_raw(w, ",\"rf\":");
    if (!t || t->metric < 0) { web_jw_raw(w, "null"); return; }
    long long from = web_rf_from(now_s);
    int bssid = t->metric == WM_RF_RSSI_BSSID;
    web_jw_raw(w, "{\"metric\":"); web_jw_str(w, web_metric_defs[t->metric].name);
    web_jw_raw(w, ",\"from\":");   web_jw_int(w, from);
    web_jw_raw(w, ",\"cell_s\":"); web_jw_int(w, WEB_RF_CELL_S);
    web_jw_raw(w, ",\"cells\":[");
    int last = -1;
    for (int i = 0; t->n && i < WEB_RF_CELLS; i++) {
        if (i) web_jw_raw(w, ",");
        if (!t->cell[i].n) { web_jw_raw(w, "null"); continue; }
        double v = t->cell[i].sum / (double)t->cell[i].n;
        web_jw_int(w, dbm(v < -127 ? -127 : v > 20 ? 20 : v));
        last = i;
    }
    web_jw_raw(w, "],\"n\":"); web_jw_int(w, t->n);
    web_frrs_rf_t fr;
    int led = frrs && web_frrs_rf(frrs, bssid, mac, &fr);
    web_jw_raw(w, ",\"whisker\":");
    const char *wsrc = NULL;
    /* The beacon's range is the whisker only when that beacon is in
     * the minute the last value is: the whisker is drawn at the last
     * value, and an assoc (the AP's frames too) can be the later
     * sample, or a snapshot re-sent long after the last one taken. */
    long long lt = from + (long long)last * WEB_RF_CELL_S;
    if (led && bssid && fr.have_range && last >= 0 && fr.ts >= lt &&
        fr.ts < lt + WEB_RF_CELL_S) {
        web_jw_raw(w, "[");  web_jw_int(w, fr.rmin);
        web_jw_raw(w, ",");  web_jw_int(w, fr.rmax);
        web_jw_raw(w, "]");
        wsrc = "beacon";
    } else if (last >= 0) {
        double lo = t->cell[last].min, hi = t->cell[last].max;
        web_jw_raw(w, "[");  web_jw_int(w, dbm(lo < -127 ? -127 : lo));
        web_jw_raw(w, ",");  web_jw_int(w, dbm(hi > 20 ? 20 : hi));
        web_jw_raw(w, "]");
        wsrc = "samples";
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"whisker_src\":");
    if (wsrc) web_jw_str(w, wsrc); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"band\":");
    if (led && fr.band[0]) web_jw_str(w, fr.band); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"trend\":");
    if (led && fr.trend[0]) web_jw_str(w, fr.trend); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"est_src\":");
    if (led && (fr.band[0] || fr.trend[0])) web_jw_str(w, bssid ? "beacon" : "probe_client");
    else web_jw_raw(w, "null");
    web_jw_raw(w, "}");
}
