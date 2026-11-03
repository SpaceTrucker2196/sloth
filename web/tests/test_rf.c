/* G2's data (web/src/web_rf.h, #171 slice V2): the trail of an
 * emitter's rf.rssi.* gauge over the last hour, a minute a cell, and
 * the words sloth's own distance estimate gives it through the FRRS
 * ledger, so the page's range sparkline never says a nearness of its
 * own. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_frrs.h"
#include "web_jsonl.h"
#include "web_rf.h"
#include "web_rollup.h"
#include "web_scope.h"
#include "wtest.h"

/* A minute boundary, so cell arithmetic reads plainly. */
#define T0 1700000040LL

static void ru_up(web_rollup_t *ru) {
    char err[128];
    WT_EQ(web_rollup_init(ru, 64, 0, err, sizeof(err)), 0);
}

static void feed(web_frrs_t *f, const char *line) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_frrs_record(f, &r);
}

static int json_of(const web_rf_trail_t *t, web_frrs_t *f, const char *mac,
                   long long now, char *buf, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, buf, cap);
    web_rf_json(&w, t, f, mac, now);
    return w.overflow ? -1 : (int)w.len;
}

/* The window: WEB_RF_CELLS minutes, the last the one now is in. */
static void test_rf_window(void) {
    WT_EQ(web_rf_from(T0), T0 - (WEB_RF_CELLS - 1) * WEB_RF_CELL_S);
    WT_EQ(web_rf_from(T0 + 59), T0 - (WEB_RF_CELLS - 1) * WEB_RF_CELL_S);
    WT_EQ(web_rf_from(T0 + 60), T0 + 60 - (WEB_RF_CELLS - 1) * WEB_RF_CELL_S);
}

/* web_rollup_trail(): every fine bucket of a key's series, closed or
 * still open, merged into the cell it starts in; another key's, and a
 * bucket before the window, are not. Seen red with the open bucket
 * left out (the last cell's n 1, not 2), and with the window's lower
 * bound dropped (the early sample landed in cell 0). */
static void test_rollup_trail(void) {
    static web_rollup_t ru;
    ru_up(&ru);
    const char *a = "02:00:00:00:00:0a", *b = "02:00:00:00:00:0b";
    long long from = T0 - 120;
    web_rollup_add(&ru, WM_RF_RSSI_STA, a, -80, from - 30);   /* before the window */
    web_rollup_add(&ru, WM_RF_RSSI_STA, a, -70, from + 5);    /* cell 0 */
    web_rollup_add(&ru, WM_RF_RSSI_STA, a, -60, from + 15);   /* cell 0, next bucket */
    web_rollup_add(&ru, WM_RF_RSSI_STA, b, -40, from + 15);   /* the other key */
    web_rollup_add(&ru, WM_RF_RSSI_STA, a, -50, from + 125);  /* cell 2 */
    web_rollup_close_due(&ru, from + 130);
    web_rollup_add(&ru, WM_RF_RSSI_STA, a, -54, from + 135);  /* cell 2, still open */
    char keys[2][WEB_KEY_MAX + 1];
    snprintf(keys[0], sizeof(keys[0]), "%s", a);
    snprintf(keys[1], sizeof(keys[1]), "02:00:00:00:00:0c");  /* no series */
    web_agg_t out[2 * 3];
    web_rollup_trail(&ru, WM_RF_RSSI_STA, (const char (*)[WEB_KEY_MAX + 1])keys, 2,
                     from, from + 180, 3, 60, out);
    WT_EQ(out[0].n, 2);
    WT_EQ(out[0].t, from);
    WT_ASSERT(out[0].sum == -130 && out[0].min == -70 && out[0].max == -60);
    WT_EQ(out[1].n, 0);
    WT_EQ(out[1].t, -1);
    WT_EQ(out[2].n, 2);
    WT_ASSERT(out[2].min == -54 && out[2].max == -50);
    for (int i = 3; i < 6; i++) WT_EQ(out[i].n, 0);
    /* The other metric of the same key has nothing. */
    web_rollup_trail(&ru, WM_RF_RSSI_BSSID, (const char (*)[WEB_KEY_MAX + 1])keys, 1,
                     from, from + 180, 3, 60, out);
    WT_EQ(out[0].n + out[1].n + out[2].n, 0);
    web_rollup_destroy(&ru);
}

/* web_rf_trails(): an AP's series first, a station's otherwise, and the
 * other when the first has nothing in the window; under Local, where
 * the monitor radio's series are not shown, no trail at all. The
 * fallback was seen red with it taken out (metric stayed bssid, n 0),
 * and the scope's absence with the web_scope_ok() guard removed. */
static void test_rf_trails_pick_and_scope(void) {
    static web_rollup_t ru;
    ru_up(&ru);
    const char *ap = "02:00:00:00:00:a1", *sta = "02:00:00:00:00:51";
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -45, T0 - 30);
    web_rollup_add(&ru, WM_RF_RSSI_STA, ap, -90, T0 - 30);
    web_rollup_add(&ru, WM_RF_RSSI_STA, sta, -62, T0 - 30);
    char keys[3][WEB_KEY_MAX + 1];
    snprintf(keys[0], sizeof(keys[0]), "%s", ap);
    snprintf(keys[1], sizeof(keys[1]), "%s", sta);
    snprintf(keys[2], sizeof(keys[2]), "02:00:00:00:00:ff");
    int isap[3] = { 1, 1, 0 };
    web_rf_trail_t t[3];
    web_rf_trails(&ru, NULL, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 3, T0, t);
    WT_EQ(t[0].metric, WM_RF_RSSI_BSSID);
    WT_EQ(t[0].n, 1);
    WT_ASSERT(t[0].cell[WEB_RF_CELLS - 2].n == 1 && t[0].cell[WEB_RF_CELLS - 2].sum == -45);
    WT_EQ(t[1].metric, WM_RF_RSSI_STA);       /* asked as an AP, heard as a station */
    WT_EQ(t[1].n, 1);
    WT_EQ(t[2].metric, WM_RF_RSSI_STA);       /* nothing: the asked series, empty */
    WT_EQ(t[2].n, 0);
    web_scope_ctx_t loc;
    memset(&loc, 0, sizeof(loc));
    loc.scope = WEB_SCOPE_LOCAL;
    web_rf_trails(&ru, &loc, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 3, T0, t);
    for (int i = 0; i < 3; i++) WT_EQ(t[i].metric, -1);
    char buf[1024];
    WT_ASSERT(json_of(&t[0], NULL, ap, T0, buf, sizeof(buf)) > 0);
    WT_ASSERT(!strcmp(buf, ",\"rf\":null"));
    web_scope_ctx_t mon = loc;
    mon.scope = WEB_SCOPE_MONITOR;
    web_rf_trails(&ru, &mon, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 3, T0, t);
    WT_EQ(t[0].metric, WM_RF_RSSI_BSSID);
    /* No rollup (no tsdb): no trail. */
    web_rf_trails(NULL, NULL, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 3, T0, t);
    WT_EQ(t[0].metric, -1);
    web_rollup_destroy(&ru);
}

/* The member: the cells as integer dBm, null where none fell; the
 * beacon's own 60 s range as the whisker; sloth's band and trend from
 * the latest beacon, so "approaching" is sloth's word, not a slope the
 * page fits. A station has no beacon range: the whisker is its last
 * cell's sample range. */
static void test_rf_json_agrees_with_sloth(void) {
    static web_rollup_t ru;
    static web_frrs_t f;
    char err[256];
    ru_up(&ru);
    WT_EQ(web_frrs_init(&f, NULL, NULL, 0, err, sizeof(err)), 0);
    const char *ap = "02:00:00:00:00:a1", *sta = "02:00:00:00:00:51";
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -61, T0 - 300);
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -50, T0 - 5);
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -47, T0 + 5);
    web_rollup_add(&ru, WM_RF_RSSI_STA, sta, -70, T0 + 1);
    web_rollup_add(&ru, WM_RF_RSSI_STA, sta, -66, T0 + 2);
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"beacon\",\"ts\":%lld,\"bssid\":\"02:00:00:00:00:A1\",\"ssid\":\"x\","
             "\"signal_dbm\":-47,\"rssi_min_60s\":-58,\"rssi_max_60s\":-44,"
             "\"est_dist_m\":4.5,\"est_dist_band\":\"room\",\"est_dist_trend\":\"approaching\","
             "\"est_ptx_source\":\"assumed\"}", T0 + 5);
    feed(&f, line);
    snprintf(line, sizeof(line),
             "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:51\","
             "\"signal_dbm\":-66,\"est_dist_m\":12,\"est_dist_band\":\"building\","
             "\"est_dist_trend\":\"leaving\",\"est_ptx_source\":\"assumed\"}", T0 + 2);
    feed(&f, line);
    char keys[2][WEB_KEY_MAX + 1];
    snprintf(keys[0], sizeof(keys[0]), "%s", ap);
    snprintf(keys[1], sizeof(keys[1]), "%s", sta);
    int isap[2] = { 1, 0 };
    web_rf_trail_t t[2];
    web_rf_trails(&ru, NULL, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 2, T0 + 10, t);
    char buf[1024];
    WT_ASSERT(json_of(&t[0], &f, ap, T0 + 10, buf, sizeof(buf)) > 0);
    char want[160];
    snprintf(want, sizeof(want), ",\"rf\":{\"metric\":\"rf.rssi.bssid\",\"from\":%lld,"
             "\"cell_s\":60,\"cells\":[null,", web_rf_from(T0 + 10));
    WT_HAS(buf, want);
    /* Five minutes back, then the minute before now (-50), and now's
     * open bucket (-47). */
    WT_HAS(buf, ",-61,null,null,null,-50,-47],\"n\":3,");
    WT_HAS(buf, "\"whisker\":[-58,-44],\"whisker_src\":\"beacon\","
                "\"band\":\"room\",\"trend\":\"approaching\",\"est_src\":\"beacon\"}");
    WT_ASSERT(json_of(&t[1], &f, sta, T0 + 10, buf, sizeof(buf)) > 0);
    WT_HAS(buf, "\"metric\":\"rf.rssi.sta\"");
    WT_HAS(buf, ",-68],\"n\":1,\"whisker\":[-70,-66],\"whisker_src\":\"samples\","
                "\"band\":\"building\",\"trend\":\"leaving\",\"est_src\":\"probe_client\"}");
    /* With no ledger there is no word of sloth's to say, so none. */
    WT_ASSERT(json_of(&t[0], NULL, ap, T0 + 10, buf, sizeof(buf)) > 0);
    WT_HAS(buf, "\"whisker_src\":\"samples\",\"band\":null,\"trend\":null,\"est_src\":null}");
    web_frrs_destroy(&f);
    web_rollup_destroy(&ru);
}

/* The beacon's range is the whisker only for the minute it was in: the
 * whisker is drawn at the last value, and that value can be a later
 * assoc's (the AP's frames too), or the beacon a snapshot re-sent after
 * the last sample was taken. Either way the whisker is the last cell's
 * own samples. Seen red with the gate back at "the latest beacon is
 * inside the hour" (both cases drew [-70,-55] from the beacon). */
static void test_rf_whisker_is_the_last_values_minute(void) {
    static web_rollup_t ru;
    static web_frrs_t f;
    char err[256];
    ru_up(&ru);
    WT_EQ(web_frrs_init(&f, NULL, NULL, 0, err, sizeof(err)), 0);
    const char *ap = "02:00:00:00:00:a4", *bp = "02:00:00:00:00:a5";
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -61, T0 - 300);  /* the beacon's */
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -50, T0 + 5);    /* a later assoc's */
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, bp, -64, T0 - 300);  /* the only sample */
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"beacon\",\"ts\":%lld,\"bssid\":\"%s\",\"signal_dbm\":-61,"
             "\"rssi_min_60s\":-70,\"rssi_max_60s\":-55,\"est_dist_m\":9,"
             "\"est_dist_band\":\"room\",\"est_dist_trend\":\"steady\","
             "\"est_ptx_source\":\"assumed\"}", T0 - 300, ap);
    feed(&f, line);
    snprintf(line, sizeof(line),
             "{\"type\":\"beacon\",\"ts\":%lld,\"bssid\":\"%s\",\"signal_dbm\":-64,"
             "\"rssi_min_60s\":-70,\"rssi_max_60s\":-55,\"est_dist_m\":9,"
             "\"est_dist_band\":\"room\",\"est_dist_trend\":\"steady\","
             "\"est_ptx_source\":\"assumed\"}", T0 + 5, bp);
    feed(&f, line);
    char keys[2][WEB_KEY_MAX + 1];
    snprintf(keys[0], sizeof(keys[0]), "%s", ap);
    snprintf(keys[1], sizeof(keys[1]), "%s", bp);
    int isap[2] = { 1, 1 };
    web_rf_trail_t t[2];
    web_rf_trails(&ru, NULL, (const char (*)[WEB_KEY_MAX + 1])keys, isap, 2, T0 + 10, t);
    char buf[1024];
    WT_ASSERT(json_of(&t[0], &f, ap, T0 + 10, buf, sizeof(buf)) > 0);
    WT_HAS(buf, "\"whisker\":[-50,-50],\"whisker_src\":\"samples\",\"band\":\"room\"");
    WT_ASSERT(json_of(&t[1], &f, bp, T0 + 10, buf, sizeof(buf)) > 0);
    WT_HAS(buf, "\"whisker\":[-64,-64],\"whisker_src\":\"samples\",\"band\":\"room\"");
    WT_LACKS(buf, "-55");
    web_frrs_destroy(&f);
    web_rollup_destroy(&ru);
}

/* A record's band or trend that is not one of sloth's words is not
 * passed on: the ledger's strings came off the stream. And a beacon
 * range out of order or out of a reading's bounds is no whisker. Seen
 * red with web_frrs_rf()'s word check taken out (the trend "<b>x</b>"
 * reached the member, escaped) and with the range's order check
 * dropped. */
static void test_rf_refuses_other_words(void) {
    static web_rollup_t ru;
    static web_frrs_t f;
    char err[256];
    ru_up(&ru);
    WT_EQ(web_frrs_init(&f, NULL, NULL, 0, err, sizeof(err)), 0);
    const char *ap = "02:00:00:00:00:a2";
    web_rollup_add(&ru, WM_RF_RSSI_BSSID, ap, -50, T0 + 1);
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"beacon\",\"ts\":%lld,\"bssid\":\"02:00:00:00:00:a2\","
             "\"signal_dbm\":-50,\"rssi_min_60s\":-40,\"rssi_max_60s\":-60,"
             "\"est_dist_m\":4.5,\"est_dist_band\":\"next door\",\"est_dist_trend\":\"<b>x</b>\","
             "\"est_ptx_source\":\"assumed\"}", T0 + 1);
    feed(&f, line);
    web_frrs_rf_t fr;
    WT_EQ(web_frrs_rf(&f, 1, ap, &fr), 1);
    WT_ASSERT(!fr.band[0] && !fr.trend[0]);
    WT_EQ(fr.have_range, 0);
    WT_EQ(web_frrs_rf(&f, 0, ap, &fr), 0);    /* not a station's */
    char keys[1][WEB_KEY_MAX + 1];
    snprintf(keys[0], sizeof(keys[0]), "%s", ap);
    int isap = 1;
    web_rf_trail_t t;
    web_rf_trails(&ru, NULL, (const char (*)[WEB_KEY_MAX + 1])keys, &isap, 1, T0 + 2, &t);
    char buf[1024];
    WT_ASSERT(json_of(&t, &f, ap, T0 + 2, buf, sizeof(buf)) > 0);
    WT_LACKS(buf, "next door");
    WT_LACKS(buf, "\\u003cb");
    WT_HAS(buf, "\"whisker\":[-50,-50],\"whisker_src\":\"samples\",\"band\":null,"
                "\"trend\":null,\"est_src\":null}");
    web_frrs_destroy(&f);
    web_rollup_destroy(&ru);
}

/* WEB_RF_JSON_MAX holds the longest member: every cell at -127, the
 * longest words, a ten-digit clock. */
static void test_rf_json_bound(void) {
    web_rf_trail_t t;
    memset(&t, 0, sizeof(t));
    t.metric = WM_RF_RSSI_BSSID;
    t.n = WEB_RF_CELLS;
    for (int i = 0; i < WEB_RF_CELLS; i++) {
        t.cell[i].t = 0;
        t.cell[i].sum = -127;
        t.cell[i].min = -127;
        t.cell[i].max = -127;
        t.cell[i].n = 1;
    }
    char buf[2048];
    int n = json_of(&t, NULL, "02:00:00:00:00:a3", 9999999999LL, buf, sizeof(buf));
    fprintf(stderr, "    longest rf member: %d bytes of %d\n", n, WEB_RF_JSON_MAX);
    /* The ledger's longest words add these over the nulls. */
    int words = (int)(strlen("\"immediate\"") + strlen("\"approaching\"") +
                      strlen("\"probe_client\"") - 3 * strlen("null"));
    WT_ASSERT(n > 0 && n + words <= WEB_RF_JSON_MAX);
    WT_ASSERT(n + words > WEB_RF_JSON_MAX * 3 / 4);
}

void run_rf_tests(void) {
    WT_RUN(test_rf_window);
    WT_RUN(test_rollup_trail);
    WT_RUN(test_rf_trails_pick_and_scope);
    WT_RUN(test_rf_json_agrees_with_sloth);
    WT_RUN(test_rf_whisker_is_the_last_values_minute);
    WT_RUN(test_rf_refuses_other_words);
    WT_RUN(test_rf_json_bound);
}
