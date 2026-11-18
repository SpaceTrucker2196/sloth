/* One slothweb, two daemons (#214, ADR 0010): --rf-socket and --rf-db.
 *
 * The framer is driven without a socket (web_feed_bytes()), with every
 * consumer set on BOTH feeds, so what a consumer sees is decided by the
 * feed's role and by nothing main.c happened to leave unset. Records
 * are the emitters' shapes (src/jsonl.c, src/jsonl_rf.c) with invented
 * values; positions are invented (10/20 and 11/21 degrees).
 *
 * Absence assertions, each seen red under the named mutation and
 * restored:
 *   - the rtl_433 tab surviving sloth's sensor_health: with
 *     split_line()'s `if (rf_type || health)` block also run for
 *     WEB_FEED_WIFI (the block was cleared, "sensor":null);
 *   - sloth's copies of the RF records feeding nothing: with
 *     `if (rf_type) return;` removed and the RF consumers called on the
 *     Wi-Fi feed (the decoy aircraft, station and device were listed);
 *   - the wrong-daemon guard: with wrong_daemon() returning 0 (sloth-rf's
 *     sensor_health on --socket set sloth.db's limit and cleared the
 *     capture state; sloth's on --rf-socket cleared the rtl_433 block);
 *   - the RF stream never reaching the metrics or the lures: with
 *     web_metrics_record() and web_lure_record() called in the
 *     WEB_FEED_RF branch (have_first_ts set, the lure version moved);
 *   - the one-stream incident list keeping its order (by change, not
 *     by last_ts): with the no-peer path sorted by by_last_desc();
 *     sloth-rf's incidents in the open counts: with peer_alerts()
 *     dropped from web_live_summary() (present, seen red the same way);
 *   - an RF alert's page reading sloth-rf.db: with web_alert_route()'s
 *     `e->rf` test made false (sloth.db's row of the same key served);
 *   - each store's limit from its own daemon: with sloth-rf's
 *     sensor_health given to sloth.db's slot;
 *   - the host batch having one writer: with web_sys_record_from()'s
 *     `if (y->host_wifi) applied = 0;` removed (sloth-rf's rss replaced
 *     sloth's);
 *   - sloth's source rows of sloth-rf's sources: with
 *     web_sys_record_from()'s owner test made false (sloth's
 *     "not_configured" adsb row replaced sloth-rf's "ok"), and the gnss
 *     row's with `if (y->gnss_rf) applied = 0;` made false;
 *   - the position's precedence: with the Wi-Fi feed calling
 *     web_gnss_record() in place of web_gnss_record_fallback() (sloth's
 *     sensor_health without loc_* cleared sloth-rf's position);
 *   - the answers without the flags: with health_json()'s
 *     `h->live->peer` test dropped ("daemons" in a one-stream answer),
 *     the tick's likewise ("rf"), /api/sys's `y->split` test made true
 *     ("host_from") and its `i == WEB_SYS_DB_RF && !path[0]` skip
 *     removed (a third storage row; test_sysstat.c's whole-answer pin
 *     went red on that one too);
 *   - the RF history's file: with web_m4_rfdb() returning m->sdb
 *     (sloth.db's decoy aircraft listed, sloth-rf.db's not).
 * The review's (#214): one occurrence two daemons raise, the two
 * databases' findings of one key, an RF alert's ids, its triage
 * subject, the bundle's rf_db and the sloth-rf sys.db_mb series each
 * name their mutation at the assertion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_adsb.h"
#include "web_aprs.h"
#include "web_assets.h"
#include "web_devices.h"
#include "web_gnss.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_lure.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_rtl433.h"
#include "web_sysstat.h"
#include "web_victron.h"
#include "web_alertkb.h"
#include "wt_world.h"

#define T 1800000000LL

static long long fixed_clock(void *ctx) { (void)ctx; return T; }

typedef struct {
    int           split;
    web_live_t    live, live_rf;
    web_gnss_t    gnss;
    web_adsb_t    adsb;
    web_aprs_t    aprs;
    web_rtl433_t  rtl433;
    web_victron_t victron;
    web_sys_t     sys;
    web_lure_t    lure;
    web_rollup_t  ru;
    web_metrics_t met;
    web_feed_t   *fw, *fr;      /* fw is the one feed of a one-stream world */
    web_m4_t      m4;
    web_health_t  h;
    long long     ms;
} tw_t;

static char g_out[262144];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    for (const char *q = strstr(s, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

static void consumers(tw_t *w, web_feed_t *f) {
    f->metrics = &w->met;
    f->gnss = &w->gnss;
    f->adsb = &w->adsb;
    f->aprs = &w->aprs;
    f->rtl433 = &w->rtl433;
    f->victron = &w->victron;
    f->sys = &w->sys;
    f->lure = &w->lure;
}

static void tw_up(tw_t *w, int split) {
    char err[256];
    memset(w, 0, sizeof(*w));
    w->split = split;
    web_live_init(&w->live, "unix:/demo/sloth.sock");
    web_live_sock_connected(&w->live, 0);
    WT_EQ(web_gnss_init(&w->gnss), 0);
    WT_EQ(web_adsb_init(&w->adsb), 0);
    WT_EQ(web_aprs_init(&w->aprs), 0);
    WT_EQ(web_rtl433_init(&w->rtl433), 0);
    WT_EQ(web_victron_init(&w->victron), 0);
    WT_EQ(web_sys_init(&w->sys), 0);
    WT_EQ(web_lure_init(&w->lure), 0);
    WT_EQ(web_rollup_init(&w->ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&w->met, &w->ru, fixed_clock, NULL), 0);
    w->fw = calloc(1, sizeof(*w->fw));
    w->fr = calloc(1, sizeof(*w->fr));
    WT_ASSERT(w->fw && w->fr);
    if (!w->fw || !w->fr) return;
    consumers(w, w->fw);
    if (split) {
        web_live_init(&w->live_rf, "unix:/demo/sloth-rf.sock");
        web_live_sock_connected(&w->live_rf, 0);
        web_live_set_role(&w->live, WEB_LIVE_WIFI);
        web_live_set_role(&w->live_rf, WEB_LIVE_RF);
        web_live_set_peer(&w->live, &w->live_rf);
        web_sys_set_split(&w->sys);
        w->fw->role = WEB_FEED_WIFI;
        consumers(w, w->fr);
        w->fr->role = WEB_FEED_RF;
        w->fr->rf_ru = &w->ru;
        w->fr->rf_clock = fixed_clock;
    }
    w->h.live = &w->live;
    w->h.gnss = &w->gnss;
    w->h.adsb = &w->adsb;
    w->h.aprs = &w->aprs;
    w->h.rtl433 = &w->rtl433;
    w->h.victron = &w->victron;
    w->h.sys = &w->sys;
    w->h.lure = &w->lure;
    w->h.m4 = &w->m4;
    w->h.wall_s = T;
    w->h.now_ms = 5000;
    w->ms = 1000;
}

static void tw_down(tw_t *w) {
    free(w->fw);
    free(w->fr);
    web_metrics_destroy(&w->met);
    web_rollup_destroy(&w->ru);
    web_lure_destroy(&w->lure);
    web_sys_destroy(&w->sys);
    web_victron_destroy(&w->victron);
    web_rtl433_destroy(&w->rtl433);
    web_aprs_destroy(&w->aprs);
    web_adsb_destroy(&w->adsb);
    web_gnss_destroy(&w->gnss);
    if (w->split) web_live_destroy(&w->live_rf);
    web_live_destroy(&w->live);
}

/* One line on sloth's socket ('w') or sloth-rf's ('r'). A one-stream
 * world has the one socket: both go to it. */
static void put(tw_t *w, int which, const char *line) {
    web_feed_t *f = w->split && which == 'r' ? w->fr : w->fw;
    web_live_t *l = w->split && which == 'r' ? &w->live_rf : &w->live;
    if (!f) return;
    web_feed_bytes(f, l, line, strlen(line), w->ms);
    web_feed_bytes(f, l, "\n", 1, w->ms);
    w->ms += 10;
}

static int get(tw_t *w, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    memset(&r, 0, sizeof(r));
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, &w->h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    size_t n = r.out_len < sizeof(g_out) - 1 ? r.out_len : sizeof(g_out) - 1;
    if (r.body && r.body_len && n + r.body_len < sizeof(g_out) - 1) {
        memcpy(g_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    g_out[n] = '\0';
    if (r.body_owned) free(r.body_owned);
    else if (r.body_free) free((void *)r.body);
    return r.status;
}

/* A route's body, copied: two worlds' answers are compared. */
static char *body_dup(tw_t *w, const char *path, const char *query) {
    if (get(w, path, query) != 200) return NULL;
    const char *b = body_of(g_out);
    char *c = malloc(strlen(b) + 1);
    if (c) memcpy(c, b, strlen(b) + 1);
    return c;
}

/* ── the records ──────────────────────────────────────────────────── */

/* sloth-rf's blocks of sensor_health, in jsonl_emit_sensor_health_rf()'s
 * order: the receiver and the position, ADS-B, APRS, rtl_433. */
#define RF_BLOCKS \
    "\"gps_state\":\"fix\",\"gps_src\":\"gpsd:127.0.0.1:2947\",\"gps_fix_age_s\":0," \
    "\"gps_quality\":3,\"gps_sats\":2,\"gps_hdop\":0.8,\"gps_sentences\":2," \
    "\"gps_bad_checksum\":0,\"gps_parse_errors\":0,\"gps_reconnects\":0," \
    "\"gps_positions_dropped\":0,\"gps_err\":\"\",\"gnss_sats_in_view\":4," \
    "\"gnss_sats_used\":2,\"gnss_cn0_mean\":31.3,\"gnss_time_offset_ms\":250,\"gnss_jam\":12," \
    "\"loc_lat\":10.00000,\"loc_lon\":20.00000,\"loc_alt_m\":30.0,\"loc_src\":\"gps\"," \
    "\"adsb_state\":\"live\",\"adsb_src\":\"file:/run/readsb/aircraft.json\"," \
    "\"aprs_state\":\"live\",\"aprs_src\":\"file:/var/lib/direwolf/aprs.log\"," \
    "\"rtl433_state\":\"live\",\"rtl433_src\":\"file:/var/lib/rtl_433/events.jsonl\"," \
    "\"rtl433_missing\":0,\"rtl433_last_read\":1799999999,\"rtl433_last_msg\":1799999960," \
    "\"rtl433_devices\":1,\"rtl433_bytes\":4096,\"rtl433_lines\":12,\"rtl433_msgs\":10," \
    "\"rtl433_bad_lines\":2,\"rtl433_err\":\"\""

/* sloth's own: the capture and the monitor radio. */
#define WIFI_BLOCKS \
    "\"capture_iface\":\"eth0\",\"capture_open\":1,\"capture_running\":1," \
    "\"monitor_iface\":\"wlan1mon\",\"monitor_open\":1,\"monitor_running\":1,\"scope\":\"lan\""

/* `sloth` before the split: everything in one record. */
static const char SH_ONE[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS "," RF_BLOCKS
    ",\"db_max_mb\":512,\"jsonl_version\":\"1.9.0\"}";
/* sloth-wifi after it: its capture, no decoder block, no position. */
static const char SH_WIFI[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS
    ",\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"1.9.0\"}";
/* sloth-wifi with a GPS of its own (it keeps GNSS health and loc_*). */
static const char SH_WIFI_GPS[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS
    ",\"gps_state\":\"fix\",\"gps_src\":\"gpsd:127.0.0.1:2947\",\"gnss_sats_in_view\":9,"
    "\"gnss_sats_used\":7,\"gnss_cn0_mean\":40.0,\"gnss_jam\":3,"
    "\"loc_lat\":11.00000,\"loc_lon\":21.00000,\"loc_src\":\"gps\","
    "\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"1.9.0\"}";
static const char SH_RF[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," RF_BLOCKS
    ",\"daemon\":\"rf\",\"db_max_mb\":256,\"jsonl_version\":\"1.9.0\"}";
/* sloth-rf with no decoder and no receiver configured. */
static const char SH_RF_BARE[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000001,\"daemon\":\"rf\",\"db_max_mb\":256,"
    "\"jsonl_version\":\"1.9.0\"}";

static const char FIX[] =
    "{\"type\":\"gnss_fix\",\"ts\":1800000000,\"src\":\"gpsd:127.0.0.1:2947\","
    "\"fix_ts\":1800000000,\"mode\":3,\"status\":2,\"nsat\":4,\"usat\":2,"
    "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"lat\":10.00000,\"lon\":20.00000,"
    "\"alt_m\":30.0,\"eph\":6.2,\"epv\":9.1,\"speed_mps\":0.30,\"track_deg\":12.5,"
    "\"time_off_ms\":250,\"leap\":18,\"jam\":12,\"tpv_count\":1}";
static const char SKY[] =
    "{\"type\":\"gnss_sky\",\"ts\":1800000000,\"src\":\"gpsd:127.0.0.1:2947\","
    "\"sky_ts\":1800000000,\"nsat\":4,\"usat\":2,\"rows\":4,\"overflow\":0,"
    "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"gdop\":2.0,\"tdop\":0.9,"
    "\"cn0_mean\":31.3,\"cn0_max\":41.0,\"cn0_sd\":7.6,\"cn0_n\":3,\"passes\":1}";
static const char SAT[] =
    "{\"type\":\"gnss_sat\",\"ts\":1800000000,\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":5,"
    "\"prn\":5,\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":41.0,\"used\":1,\"health\":1,"
    "\"sky_ts\":1800000000}";
static const char AC[] =
    "{\"type\":\"adsb_aircraft\",\"ts\":1800000000,\"hex\":\"a1b2c3\",\"non_icao\":0,"
    "\"state\":\"live\",\"flight\":\"FLT-MARK\",\"first_seen\":1799999940,"
    "\"last_seen\":1800000000}";
static const char STN[] =
    "{\"type\":\"aprs_station\",\"ts\":1800000000,\"call\":\"N0TEST-5\",\"state\":\"live\","
    "\"src\":\"file:/var/lib/direwolf/aprs.log\",\"first_seen\":1799999940,"
    "\"last_seen\":1800000000,\"packets\":1,\"via\":\"N0TEST-5\",\"direct\":1,"
    "\"heard_direct\":1,\"level\":50,\"best_level\":50,\"dti\":\"!\",\"symbol\":\"/#\","
    "\"comment\":\"APRS-COMMENT-MARK\"}";
static const char DEV[] =
    "{\"type\":\"rtl433_device\",\"ts\":1800000000,\"src\":\"file:/var/lib/rtl_433/events.jsonl\","
    "\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\",\"first_seen\":1799999990,"
    "\"last_seen\":1799999990,\"msgs\":1,\"dev_type\":\"TPMS\",\"mic\":\"CHECKSUM\","
    "\"mod\":\"FSK\",\"protocol\":60,\"freq_mhz\":433.918,\"temperature_C\":21.0,"
    "\"other_keys\":3}";
/* What a sloth that still has the RF flags writes beside sloth-rf: its
 * own copies, with other values. */
static const char AC_DECOY[] =
    "{\"type\":\"adsb_aircraft\",\"ts\":1800000000,\"hex\":\"dec0de\",\"non_icao\":0,"
    "\"state\":\"live\",\"flight\":\"DECOY-AC\",\"first_seen\":1799999940,"
    "\"last_seen\":1800000000}";
static const char STN_DECOY[] =
    "{\"type\":\"aprs_station\",\"ts\":1800000000,\"call\":\"D3COY-1\",\"state\":\"live\","
    "\"src\":\"file:/x\",\"first_seen\":1799999940,\"last_seen\":1800000000,\"packets\":1,"
    "\"via\":\"D3COY-1\",\"direct\":1,\"heard_direct\":1,\"level\":50,\"best_level\":50,"
    "\"dti\":\"!\",\"symbol\":\"/#\",\"comment\":\"DECOY-STN\"}";
static const char DEV_DECOY[] =
    "{\"type\":\"rtl433_device\",\"ts\":1800000000,\"src\":\"file:/x\","
    "\"model\":\"Decoy-DV01\",\"id\":\"777\",\"first_seen\":1799999990,"
    "\"last_seen\":1799999990,\"msgs\":1,\"other_keys\":0}";
static const char FIX_DECOY[] =
    "{\"type\":\"gnss_fix\",\"ts\":1800000000,\"src\":\"gpsd:127.0.0.1:2947\","
    "\"fix_ts\":1800000000,\"mode\":2,\"status\":1,\"nsat\":9,\"usat\":7,\"hdop\":9.9,"
    "\"lat\":11.00000,\"lon\":21.00000,\"tpv_count\":77}";

static const char STATUS_WIFI[] =
    "{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":2,\"interval_s\":60,\"cpu_pct\":15.0,"
    "\"cpu_iowait_pct\":10.0,\"cpu_band\":\"low\",\"mem_total_kb\":3884328,"
    "\"mem_avail_kb\":2913246,\"mem_band\":\"ok\",\"uptime_s\":350735,\"rss_kb\":12276,"
    "\"temps\":1,\"temp_max_c\":51.0,\"temp_max_id\":\"thermal_zone0\",\"temp_band\":\"ok\","
    "\"volts\":0,\"undervolt\":0,\"power\":0,\"sources\":9,\"receivers\":0}";
static const char STATUS_RF[] =
    "{\"type\":\"sys_status\",\"ts\":1800000061,\"seq\":7,\"interval_s\":60,\"cpu_pct\":16.0,"
    "\"cpu_iowait_pct\":10.0,\"cpu_band\":\"low\",\"mem_total_kb\":3884328,"
    "\"mem_avail_kb\":2913246,\"mem_band\":\"ok\",\"uptime_s\":350736,\"rss_kb\":4321,"
    "\"temps\":1,\"temp_max_c\":51.0,\"temp_max_id\":\"thermal_zone0\",\"temp_band\":\"ok\","
    "\"volts\":0,\"undervolt\":0,\"power\":0,\"sources\":5,\"receivers\":0}";
static const char TEMP_WIFI[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"temp\","
    "\"id\":\"thermal_zone0\",\"label\":\"cpu-thermal\",\"c\":48.3}";
static const char TEMP_RF[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000061,\"seq\":7,\"class\":\"temp\","
    "\"id\":\"thermal_zone9\",\"label\":\"rf-side\",\"c\":49.9}";

#define SRC(name, state, detail) \
    "{\"type\":\"source_status\",\"ts\":1800000060,\"seq\":2,\"name\":\"" name "\"," \
    "\"kind\":\"" name "\",\"flag\":\"--x\",\"state\":\"" state "\",\"detail\":\"" detail "\"," \
    "\"endpoint\":\"\"}"

/* ── the tabs ─────────────────────────────────────────────────────── */

/* An RF tab's answer without its last member, "rf_stream" (#216): the
 * tab's own data, which is what one stream or two must not change.
 * "rf_stream" says where the data came from, and differs by design;
 * the tests of it are at the end of this file. Cuts in place; returns
 * the member's text, or NULL when the answer has none. */
static const char *cut_rf_stream(char *body) {
    char *m = body ? strstr(body, ",\"rf_stream\":{") : NULL;
    if (!m) return NULL;
    *m = '\0';
    return m + 1;
}

/* The same records, one stream or two: the five RF tabs answer the same
 * bytes. sloth's stream in the two-daemon world also carries sloth's own
 * copies of the RF records (a sloth that still has the RF flags) and a
 * sensor_health with no decoder block; neither reaches a tab. */
static void test_tabs_same_with_one_stream_or_two(void) {
    static tw_t one, two;
    tw_up(&one, 0);
    tw_up(&two, 1);
    put(&one, 'w', FIX); put(&one, 'w', SKY); put(&one, 'w', SAT);
    put(&one, 'w', AC); put(&one, 'w', STN); put(&one, 'w', DEV);
    put(&one, 'w', SH_ONE);

    put(&two, 'w', FIX_DECOY); put(&two, 'w', AC_DECOY); put(&two, 'w', STN_DECOY);
    put(&two, 'w', DEV_DECOY);
    put(&two, 'r', FIX); put(&two, 'r', SKY); put(&two, 'r', SAT);
    put(&two, 'r', AC); put(&two, 'r', STN); put(&two, 'r', DEV);
    put(&two, 'r', SH_RF);
    /* sloth's sensor_health after sloth-rf's: no decoder block in it. */
    put(&two, 'w', SH_WIFI);
    put(&two, 'w', AC_DECOY);

    static const char *const paths[] = { "/api/rtl433", "/api/adsb", "/api/aprs", "/api/gnss",
                                         "/api/gnss/fixes", "/api/victron" };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char *a = body_dup(&one, paths[i], ""), *b = body_dup(&two, paths[i], "");
        WT_ASSERT(a && b);
        if (a && b) {
            /* The data is the same; where it came from is not (#216). */
            const char *sa = cut_rf_stream(a), *sb = cut_rf_stream(b);
            if (strcmp(paths[i], "/api/gnss/fixes")) {
                WT_ASSERT(sa && strstr(sa, "\"rf_stream\":{\"state\":\"sensor_stream\",") == sa);
                WT_ASSERT(sb && strstr(sb, "\"rf_stream\":{\"state\":\"rf_socket\",") == sb);
            } else {
                WT_ASSERT(!sa && !sb);     /* the page takes it from /api/gnss */
            }
            if (strcmp(a, b)) fprintf(stderr, "    %s differs:\n    one: %s\n    two: %s\n",
                                      paths[i], a, b);
            WT_ASSERT(!strcmp(a, b));
            /* And it is an answer with something in it. */
            WT_LACKS(b, "DECOY");
            WT_LACKS(b, "dec0de");
            WT_LACKS(b, "D3COY");
            WT_LACKS(b, "Decoy-DV01");
        }
        free(a);
        free(b);
    }
    WT_EQ(get(&two, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "Testco-TP01");
    WT_HAS(body_of(g_out), "\"state\":\"live\"");
    WT_EQ(get(&two, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "FLT-MARK");
    WT_EQ(get(&two, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "APRS-COMMENT-MARK");
    WT_EQ(get(&two, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"tpv_count\":1}");
    WT_LACKS(body_of(g_out), "\"tpv_count\":77");
    /* sloth's stream still counted what it sent. */
    WT_EQ(two.live.records, 6);
    WT_EQ(two.live_rf.records, 7);
    tw_down(&one);
    tw_down(&two);
}

/* The hazard the split was routed around (web_rtl433.c sh_apply()): a
 * sensor_health without the rtl433 block clears the tab's block. With
 * two streams sloth's record cannot; with one it still does, as today. */
static void test_rtl433_block_and_sloths_sensor_health(void) {
    static tw_t w;
    tw_up(&w, 1);
    put(&w, 'r', DEV);
    put(&w, 'r', SH_RF);
    WT_EQ(w.rtl433.sh.seen, 1);
    char *before = body_dup(&w, "/api/rtl433", "");
    put(&w, 'w', SH_WIFI);
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.rtl433.sh.seen, 1);
    char *after = body_dup(&w, "/api/rtl433", "");
    /* Less "rf_stream", which names --socket's version and daemon and
     * so does follow sloth's sensor_health. */
    cut_rf_stream(before);
    cut_rf_stream(after);
    WT_ASSERT(before && after && !strcmp(before, after));
    if (after) WT_HAS(after, "\"sensor\":{");
    free(before);
    free(after);
    /* sloth-rf's own record without the block is the decoder gone, and
     * does clear it. */
    put(&w, 'r', SH_RF_BARE);
    WT_EQ(w.rtl433.sh.seen, 0);
    tw_down(&w);

    /* One stream, today's way: cleared. */
    tw_up(&w, 0);
    put(&w, 'w', DEV);
    put(&w, 'w', SH_ONE);
    WT_EQ(w.rtl433.sh.seen, 1);
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.rtl433.sh.seen, 0);
    tw_down(&w);
}

/* ── the wrong daemon ─────────────────────────────────────────────── */

/* --socket pointed at sloth-rf, or --rf-socket at sloth: the
 * sensor_health that says so is counted once and applied to nothing,
 * and so is what follows it on that connection. */
static void test_wrong_daemon_is_not_applied(void) {
    static tw_t w;
    tw_up(&w, 1);
    /* Each socket right first. */
    put(&w, 'w', SH_WIFI);
    put(&w, 'r', DEV);
    put(&w, 'r', SH_RF);
    WT_EQ(w.live.cap_open, 1);
    WT_EQ(w.sys.sloth_max_mb, 512);
    WT_EQ(w.sys.rf_max_mb, 256);
    WT_EQ(w.live.wrong_health, 0);
    WT_EQ(w.live_rf.wrong_health, 0);
    WT_ASSERT(!strcmp(w.live.sh_daemon, "wifi") && !strcmp(w.live_rf.sh_daemon, "rf"));

    /* sloth-rf's record on --socket. */
    unsigned long long rec0 = w.live.records;
    put(&w, 'w', SH_RF);
    WT_EQ(w.live.wrong_health, 1);
    WT_ASSERT(!strcmp(w.live.wrong_now, "rf"));
    WT_EQ(w.live.records, rec0 + 1);            /* counted as a record */
    WT_EQ(w.live.cap_open, 1);                  /* not "no capture" */
    WT_ASSERT(!strcmp(w.live.cap_iface, "eth0"));
    WT_EQ(w.sys.sloth_max_mb, 512);             /* not sloth-rf's 256 */
    /* What follows on that connection is passed over too. */
    put(&w, 'w', STATUS_RF);
    WT_EQ(w.live.wrong_records, 2);
    WT_EQ(w.sys.seen, 0);
    /* A connect is a new stream; a right record ends it as well. */
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.live.wrong_now[0], '\0');
    WT_EQ(w.live.wrong_health, 1);
    put(&w, 'w', STATUS_WIFI);
    WT_EQ(w.sys.seen, 1);
    WT_EQ(w.live.wrong_records, 2);

    /* sloth's record on --rf-socket: with its word, and with none (an
     * older sloth). */
    put(&w, 'r', SH_WIFI);
    WT_EQ(w.live_rf.wrong_health, 1);
    WT_ASSERT(!strcmp(w.live_rf.wrong_now, "wifi"));
    WT_EQ(w.rtl433.sh.seen, 1);                 /* not cleared by it */
    WT_EQ(w.sys.rf_max_mb, 256);
    put(&w, 'r', DEV_DECOY);
    WT_EQ(w.live_rf.wrong_records, 2);
    WT_EQ(get(&w, "/api/rtl433", ""), 200);
    WT_LACKS(body_of(g_out), "Decoy-DV01");
    put(&w, 'r', SH_ONE);
    WT_EQ(w.live_rf.wrong_health, 2);
    WT_ASSERT(!strcmp(w.live_rf.wrong_now, "other"));
    WT_EQ(w.rtl433.sh.seen, 1);
    /* /api/health says it, per daemon. */
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"wrong_daemon\":\"other\",\"wrong_health\":2,\"wrong_records\":3}");
    WT_HAS(body_of(g_out), "\"wrong_daemon\":null,\"wrong_health\":1,\"wrong_records\":2}");
    /* A reconnect clears the word, not the count. */
    web_feed_reset(w.fr);
    web_live_sock_connected(&w.live_rf, w.ms);
    put(&w, 'r', DEV);
    WT_EQ(w.live_rf.wrong_now[0], '\0');
    WT_EQ(w.live_rf.wrong_records, 3);
    tw_down(&w);

    /* One stream: no guard, whatever the word (a host that runs
     * sloth-rf alone and points --socket at it, as before the flags). */
    tw_up(&w, 0);
    put(&w, 'w', SH_RF);
    WT_EQ(w.live.wrong_health, 0);
    WT_EQ(w.live.sh_seen, 1);
    WT_EQ(w.rtl433.sh.seen, 1);
    WT_EQ(w.sys.sloth_max_mb, 256);
    tw_down(&w);
}

/* ── one writer each ──────────────────────────────────────────────── */

/* sloth-rf's stream never reaches the metrics (one thread's alone) or
 * the lures; its series go to the rollup, which locks. */
static void test_rf_stream_feeds_the_rollup_not_the_metrics(void) {
    static tw_t w;
    tw_up(&w, 1);
    web_rollup_stats_t st;
    web_rollup_stats(&w.ru, &st);
    WT_EQ(st.samples, 0);
    put(&w, 'r', FIX);
    put(&w, 'r', SKY);
    put(&w, 'r', SH_RF);
    put(&w, 'r', SRC("adsb", "ok", ""));
    WT_EQ(w.met.have_first_ts, 0);
    WT_EQ(w.lure.ver[0] + w.lure.ver[1] + w.lure.ver[2], 0);
    WT_EQ(w.lure.ver_seen, 0);
    web_rollup_stats(&w.ru, &st);
    /* Three figures of the fix, one of the sky, source.up for the row;
     * no records.rate or records.total, which are sloth's stream's. */
    WT_EQ(st.samples, 3 + 1 + 1);
    /* An alert sloth-rf fires now reaches alerts.fired (#218), but not
     * by a direct write from this thread: it queues (web_rollup_queue_add())
     * and waits for close_where() -- the tsdb thread's alone -- to
     * apply it, so a type both daemons can fire (SENSOR_SOURCE_DOWN)
     * never gets two writers on one series (slothweb.md, "Alerts").
     * Seen red by reverting web_metrics_rf_sample()'s "alert" branch
     * to call web_rollup_add() directly: the queued-not-applied
     * assertion below would pass immediately instead of waiting for
     * the drain. */
    {
        char line[256], tyk[16];
        snprintf(tyk, sizeof(tyk), "%d", web_akb_find("GNSS_JAMMING"));
        snprintf(line, sizeof(line), "{\"type\":\"alert\",\"ts\":1800000000,\"sev\":2,\"ty\":%s,"
                 "\"title\":\"GNSS jamming\",\"detail\":\"d\"}", tyk);
        put(&w, 'r', line);
        WT_EQ(web_rollup_has(&w.ru, WM_ALERTS_FIRED, tyk), 0);
        web_rollup_stats(&w.ru, &st);
        WT_EQ(st.samples, 5);
        web_rollup_close_all(&w.ru);
        WT_EQ(web_rollup_has(&w.ru, WM_ALERTS_FIRED, tyk), 1);
        web_rollup_stats(&w.ru, &st);
        WT_EQ(st.samples, 6);
    }
    /* sloth's stream is the metrics' writer still, and its copies of
     * the RF records and of sloth-rf's source rows sample nothing. */
    put(&w, 'w', FIX_DECOY);
    put(&w, 'w', SRC("adsb", "not_configured", ""));
    web_rollup_stats(&w.ru, &st);
    WT_EQ(st.samples, 6);
    WT_EQ(w.met.have_first_ts, 0);
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.met.have_first_ts, 1);
    WT_EQ(w.lure.ver_seen, 1);
    tw_down(&w);
}

/* The host batch, the source rows and the two stores' limits. */
static void test_sysstat_has_one_writer_per_part(void) {
    static tw_t w;
    tw_up(&w, 1);
    /* sloth-rf alone so far: its batch is the host's. */
    put(&w, 'r', STATUS_RF);
    put(&w, 'r', TEMP_RF);
    WT_EQ(w.sys.seen, 1);
    WT_EQ(w.sys.rss_kb, 4321);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"host_from\":\"rf\"");
    WT_HAS(body_of(g_out), "\"id\":\"thermal_zone9\"");
    /* sloth reports: the host is sloth's from here on, and sloth-rf's
     * rows of the batch it took over from are gone. */
    put(&w, 'w', STATUS_WIFI);
    put(&w, 'w', TEMP_WIFI);
    WT_EQ(w.sys.rss_kb, 12276);
    put(&w, 'r', STATUS_RF);
    put(&w, 'r', TEMP_RF);
    WT_EQ(w.sys.rss_kb, 12276);
    WT_EQ(w.sys.seq, 2);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"host_from\":\"wifi\"");
    WT_HAS(body_of(g_out), "\"id\":\"thermal_zone0\"");
    WT_LACKS(body_of(g_out), "thermal_zone9");

    /* The source rows, by name. */
    put(&w, 'r', SRC("adsb", "ok", "rf-adsb"));
    put(&w, 'w', SRC("adsb", "not_configured", "wifi-adsb"));
    put(&w, 'w', SRC("monitor", "ok", "wifi-monitor"));
    put(&w, 'r', SRC("monitor", "not_configured", "rf-monitor"));
    put(&w, 'w', SRC("rtl433", "down", "wifi-rtl433"));
    put(&w, 'w', SRC("victron", "down", "wifi-victron"));
    put(&w, 'w', SRC("aprs", "down", "wifi-aprs"));
    WT_EQ(get(&w, "/api/sys", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"name\":\"adsb\",\"kind\":\"adsb\",\"flag\":\"--x\",\"state\":\"ok\",\"detail\":\"rf-adsb\"");
    WT_HAS(b, "\"name\":\"monitor\",\"kind\":\"monitor\",\"flag\":\"--x\",\"state\":\"ok\",\"detail\":\"wifi-monitor\"");
    WT_LACKS(b, "wifi-adsb");
    WT_LACKS(b, "rf-monitor");
    WT_LACKS(b, "wifi-rtl433");
    WT_LACKS(b, "wifi-victron");
    WT_LACKS(b, "wifi-aprs");

    /* gnss, which both report: sloth's until sloth-rf reports one that
     * is configured, sloth-rf's from then on. */
    put(&w, 'r', SRC("gnss", "not_configured", "rf-none"));
    put(&w, 'w', SRC("gnss", "ok", "wifi-gps"));
    put(&w, 'r', SRC("gnss", "not_configured", "rf-none"));
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"detail\":\"wifi-gps\"");
    WT_LACKS(body_of(g_out), "rf-none");
    put(&w, 'r', SRC("gnss", "ok", "rf-gps"));
    put(&w, 'w', SRC("gnss", "ok", "wifi-gps"));
    put(&w, 'w', SRC("gnss", "stale", "wifi-gps-2"));
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"detail\":\"rf-gps\"");
    WT_LACKS(body_of(g_out), "wifi-gps");
    /* A name this slothweb does not know is its sender's. */
    put(&w, 'r', SRC("meshtastic", "ok", "rf-mesh"));
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"detail\":\"rf-mesh\"");

    /* Each daemon's sensor_health is its own store's limit. */
    put(&w, 'w', SH_WIFI);
    put(&w, 'r', SH_RF);
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.sys.sloth_max_mb, 512);
    WT_EQ(w.sys.rf_max_mb, 256);
    WT_EQ(w.sys.sloth_lim, WEB_SYS_LIM_SAID);
    WT_EQ(w.sys.rf_lim, WEB_SYS_LIM_SAID);
    tw_down(&w);

    /* One stream: every row is the one daemon's, as before. */
    tw_up(&w, 0);
    put(&w, 'w', STATUS_WIFI);
    put(&w, 'w', SRC("adsb", "ok", "one-adsb"));
    put(&w, 'w', SRC("adsb", "not_configured", "one-adsb-2"));
    put(&w, 'w', SRC("monitor", "ok", "one-monitor"));
    put(&w, 'w', SRC("gnss", "not_configured", "one-gnss"));
    put(&w, 'w', STATUS_RF);
    WT_EQ(w.sys.rss_kb, 4321);
    WT_EQ(w.sys.not_owned, 0);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "one-adsb-2");
    WT_HAS(body_of(g_out), "one-monitor");
    WT_HAS(body_of(g_out), "one-gnss");
    WT_LACKS(body_of(g_out), "host_from");
    WT_LACKS(body_of(g_out), "not_owned");
    tw_down(&w);
}

/* GNSS (ADR 0010, ruled 2026-11-15): both daemons report the health and
 * the position; sloth-rf's is served when it has given one, sloth's
 * otherwise, and neither clears the other's. */
static void test_gnss_position_and_health_precedence(void) {
    static tw_t w;
    tw_up(&w, 1);
    /* sloth alone has a GPS (sloth-rf masked, or not started yet). */
    put(&w, 'w', SH_WIFI_GPS);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":11.0000000,\"lon\":21.0000000,");
    WT_HAS(body_of(g_out), "\"sats_in_view\":9,");
    /* sloth-rf reports its own: served from then on. */
    put(&w, 'r', SH_RF);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":10.0000000,\"lon\":20.0000000,\"alt_m\":30.0,");
    WT_HAS(body_of(g_out), "\"sats_in_view\":4,");
    /* sloth's record with no position (it has no --gps) clears nothing
     * of sloth-rf's, nor does its record with another one replace it. */
    put(&w, 'w', SH_WIFI);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":10.0000000,\"lon\":20.0000000,\"alt_m\":30.0,");
    WT_HAS(body_of(g_out), "\"sats_in_view\":4,");
    put(&w, 'w', SH_WIFI_GPS);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":10.0000000,\"lon\":20.0000000,\"alt_m\":30.0,");
    WT_LACKS(body_of(g_out), "11.0000000");
    /* The fleet's site reads the same. */
    web_loc_t loc;
    web_gnss_sh_t sh;
    web_gnss_site(&w.gnss, &loc, &sh);
    WT_EQ(loc.has, 1);
    WT_ASSERT(loc.lat > 9.99 && loc.lat < 10.01);
    WT_EQ(sh.sats_in_view, 4);
    /* sloth-rf loses its position: sloth's is served, not none. */
    put(&w, 'r', SH_RF_BARE);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":{\"lat\":11.0000000,\"lon\":21.0000000,");
    /* Neither has one. */
    put(&w, 'w', SH_WIFI);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":null");
    tw_down(&w);

    /* One stream, today's way: a record without loc_* clears it. */
    tw_up(&w, 0);
    put(&w, 'w', SH_ONE);
    WT_EQ(w.gnss.loc.has, 1);
    put(&w, 'w', SH_WIFI);
    WT_EQ(w.gnss.loc.has, 0);
    WT_EQ(w.gnss.loc_fb.has, 0);
    WT_EQ(w.gnss.sh_fb.seen, 0);
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"loc\":null");
    tw_down(&w);
}

/* ── alerts ───────────────────────────────────────────────────────── */

#define ALERT(ev, id, sev, ty, title, ts) \
    "{\"type\":\"alert." ev "\",\"ts\":" ts ",\"incident_id\":\"" id "\",\"sev\":" sev "," \
    "\"ty\":" ty ",\"title\":\"" title "\",\"detail\":\"d\",\"key\":\"k:" id "\"," \
    "\"first_seen\":" ts ",\"last_seen\":" ts ",\"count\":1}"

/* An alert sloth-rf raised is on the list, in the counts and behind its
 * handle with sloth's; sloth's reconnect drops sloth's open incidents
 * and leaves sloth-rf's. */
static void test_rf_alerts_are_listed_with_sloths(void) {
    static tw_t w;
    tw_up(&w, 1);
    put(&w, 'w', ALERT("create", "w1", "1", "10", "WIFI-ONE", "1800000010"));
    put(&w, 'r', ALERT("create", "r1", "2", "11", "RF-ONE", "1800000020"));
    put(&w, 'w', ALERT("create", "w2", "0", "12", "WIFI-TWO", "1800000030"));
    put(&w, 'r', ALERT("create", "r2", "1", "13", "RF-CLOSED", "1800000005"));
    put(&w, 'r', ALERT("resolve", "r2", "1", "13", "RF-CLOSED", "1800000006"));
    web_live_inc_t *inc = calloc(64, sizeof(*inc));
    WT_ASSERT(inc != NULL);
    if (!inc) { tw_down(&w); return; }
    int nopen = 0, n = web_live_incidents(&w.live, inc, 64, &nopen);
    WT_EQ(n, 4);
    WT_EQ(nopen, 3);
    /* Open first, the newest change first, across the two. */
    WT_ASSERT(!strcmp(inc[0].title, "WIFI-TWO") && inc[0].rf == 0);
    WT_ASSERT(!strcmp(inc[1].title, "RF-ONE") && inc[1].rf == 1);
    WT_ASSERT(!strcmp(inc[2].title, "WIFI-ONE") && inc[2].rf == 0);
    WT_ASSERT(!strcmp(inc[3].title, "RF-CLOSED") && inc[3].rf == 1);
    /* The handles are apart, and one lookup finds either. */
    WT_ASSERT(strcmp(inc[0].hid, inc[1].hid) != 0);
    WT_ASSERT(strncmp(inc[0].hid, inc[1].hid, 8) != 0);
    web_live_inc_t one;
    WT_EQ(web_live_incident(&w.live, inc[1].hid, &one), 1);
    WT_ASSERT(!strcmp(one.title, "RF-ONE") && one.rf == 1);
    WT_EQ(web_live_incident(&w.live, inc[2].hid, &one), 1);
    WT_ASSERT(!strcmp(one.title, "WIFI-ONE") && one.rf == 0);
    WT_EQ(web_live_incident(&w.live, "00000000ffff", &one), 0);
    /* The counts: the tick's and /api/live's. */
    web_live_sum_t s;
    web_live_summary(&w.live, &s, w.ms);
    WT_EQ(s.alerts[0], 1);
    WT_EQ(s.alerts[1], 1);
    WT_EQ(s.alerts[2], 1);
    char tick[2048];
    WT_ASSERT(web_sse_tick(tick, sizeof(tick), 1, T, &w.h) > 0);
    WT_HAS(tick, "\"alerts_open\":[1,1,1]");
    WT_EQ(get(&w, "/api/live", ""), 200);
    WT_HAS(body_of(g_out), "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":1");
    WT_EQ(get(&w, "/api/alerts", "limit=100"), 200);
    WT_HAS(body_of(g_out), "RF-ONE");
    WT_HAS(body_of(g_out), "WIFI-ONE");
    WT_HAS(body_of(g_out), "RF-CLOSED");

    /* sloth reconnects: its open incidents go, sloth-rf's stay. */
    web_live_sock_connected(&w.live, w.ms);
    n = web_live_incidents(&w.live, inc, 64, &nopen);
    WT_EQ(nopen, 1);
    WT_ASSERT(!strcmp(inc[0].title, "RF-ONE"));
    /* And the other way. */
    put(&w, 'w', ALERT("create", "w3", "1", "10", "WIFI-THREE", "1800000040"));
    web_live_sock_connected(&w.live_rf, w.ms);
    n = web_live_incidents(&w.live, inc, 64, &nopen);
    WT_EQ(nopen, 1);
    WT_ASSERT(!strcmp(inc[0].title, "WIFI-THREE"));
    tw_down(&w);

    /* One stream: its own incidents, in its own order, none marked. */
    tw_up(&w, 0);
    put(&w, 'w', ALERT("create", "a", "1", "10", "A-OLD-TS", "1800000090"));
    put(&w, 'w', ALERT("create", "b", "1", "11", "B-NEW-CHANGE", "1800000010"));
    n = web_live_incidents(&w.live, inc, 64, &nopen);
    WT_EQ(n, 2);
    /* By the order they changed, not by last_ts: as before. */
    WT_ASSERT(!strcmp(inc[0].title, "B-NEW-CHANGE") && inc[0].rf == 0);
    WT_ASSERT(!strcmp(inc[1].title, "A-OLD-TS") && inc[1].rf == 0);
    free(inc);
    tw_down(&w);
}

/* An incident with its own key and span. */
#define ALERTK(ev, id, sev, ty, title, key, first, ts) \
    "{\"type\":\"alert." ev "\",\"ts\":" ts ",\"incident_id\":\"" id "\",\"sev\":" sev "," \
    "\"ty\":" ty ",\"title\":\"" title "\",\"detail\":\"d\",\"key\":\"" key "\"," \
    "\"first_seen\":" first ",\"last_seen\":" ts ",\"count\":3}"

/* One occurrence both daemons raise (the shared gpsd reader; a sloth
 * that still runs the RF rules, until #216) is one incident: listed
 * once, as sloth's, and counted once. Seen red with peer_dup()
 * returning 0: two in the open counts, the tick and /api/live, and
 * the list row's count the two daemons' sum (6). The same key over
 * spans that do not meet is two incidents (seen red with inc_meet()
 * returning 1: sloth-rf's later one was dropped). */
static void test_same_key_from_both_daemons_is_one(void) {
    static tw_t w;
    tw_up(&w, 1);
    put(&w, 'w', ALERTK("create", "wg", "1", "20", "SRC-DOWN", "srcdown:gnss",
                        "1800000100", "1800000100"));
    put(&w, 'r', ALERTK("create", "rg", "1", "20", "SRC-DOWN", "srcdown:gnss",
                        "1800000102", "1800000102"));
    put(&w, 'r', ALERT("create", "r1", "2", "11", "RF-ONE", "1800000020"));
    web_live_inc_t *inc = calloc(WEB_LIVE_INC_ALL, sizeof(*inc));
    WT_ASSERT(inc != NULL);
    if (!inc) { tw_down(&w); return; }
    int nopen = 0, n = web_live_incidents(&w.live, inc, WEB_LIVE_INC_ALL, &nopen);
    WT_EQ(n, 2);
    WT_EQ(nopen, 2);
    WT_ASSERT(!strcmp(inc[0].title, "SRC-DOWN") && inc[0].rf == 0);
    WT_ASSERT(!strcmp(inc[1].title, "RF-ONE") && inc[1].rf == 1);
    web_live_sum_t s;
    web_live_summary(&w.live, &s, w.ms);
    WT_EQ(s.alerts[0], 0);
    WT_EQ(s.alerts[1], 1);
    WT_EQ(s.alerts[2], 1);
    char tick[2048];
    WT_ASSERT(web_sse_tick(tick, sizeof(tick), 1, T, &w.h) > 0);
    WT_HAS(tick, "\"alerts_open\":[0,1,1]");
    WT_EQ(get(&w, "/api/live", ""), 200);
    WT_HAS(body_of(g_out), "\"alerts_open\":{\"low\":0,\"warn\":1,\"crit\":1");
    WT_EQ(get(&w, "/api/alerts", "limit=100"), 200);
    WT_EQ(count_of(body_of(g_out), "\"title\":\"SRC-DOWN\""), 1);
    WT_HAS(body_of(g_out), "\"count\":3,\"incidents\":1,");
    WT_LACKS(body_of(g_out), "\"count\":6,");
    WT_HAS(body_of(g_out), "\"open\":2,");
    /* sloth-rf's copy is still behind its own handle. */
    web_live_inc_t own, one;
    WT_EQ(web_live_incidents(&w.live_rf, &own, 1, NULL), 1);
    WT_ASSERT(!strcmp(own.title, "SRC-DOWN"));
    WT_EQ(web_live_incident(&w.live, own.hid, &one), 1);
    WT_EQ(one.rf, 1);

    /* The same key, another occurrence: sloth's closed long before
     * sloth-rf's opened. Both are listed. */
    put(&w, 'w', ALERTK("create", "wj", "2", "21", "JAM-THEN", "gnssjam",
                        "1800000000", "1800000000"));
    put(&w, 'w', ALERTK("resolve", "wj", "2", "21", "JAM-THEN", "gnssjam",
                        "1800000000", "1800000010"));
    put(&w, 'r', ALERTK("create", "rj", "2", "21", "JAM-NOW", "gnssjam",
                        "1800000500", "1800000500"));
    n = web_live_incidents(&w.live, inc, WEB_LIVE_INC_ALL, &nopen);
    WT_EQ(n, 4);
    WT_EQ(nopen, 3);
    WT_ASSERT(!strcmp(inc[0].title, "JAM-NOW") && inc[0].rf == 1);
    WT_ASSERT(!strcmp(inc[3].title, "JAM-THEN") && inc[3].rf == 0);
    web_live_summary(&w.live, &s, w.ms);
    WT_EQ(s.alerts[2], 2);
    free(inc);
    tw_down(&w);
}

/* A busy sensor: more open incidents across the two daemons than one
 * state's list holds. Every one is listed and the list agrees with the
 * open counts (seen red with WEB_LIVE_INC_ALL the one state's 320: 320
 * listed against 400 counted, the last 80 of sloth-rf's cut). */
static void test_both_daemons_open_incidents_all_listed(void) {
    static tw_t w;
    tw_up(&w, 1);
    char line[512];
    for (int i = 0; i < 200; i++) {
        for (int d = 0; d < 2; d++) {
            snprintf(line, sizeof(line),
                     "{\"type\":\"alert.create\",\"ts\":%d,\"incident_id\":\"%c%d\",\"sev\":1,"
                     "\"ty\":10,\"title\":\"%s\",\"detail\":\"d\",\"key\":\"k:%c%d\","
                     "\"first_seen\":%d,\"last_seen\":%d,\"count\":1}",
                     1800000000 + i, d ? 'r' : 'w', i, d ? "RF-MANY" : "WIFI-MANY",
                     d ? 'r' : 'w', i, 1800000000 + i, 1800000000 + i);
            put(&w, d ? 'r' : 'w', line);
        }
    }
    web_live_inc_t *inc = calloc(WEB_LIVE_INC_ALL, sizeof(*inc));
    WT_ASSERT(inc != NULL);
    if (!inc) { tw_down(&w); return; }
    int nopen = 0, n = web_live_incidents(&w.live, inc, WEB_LIVE_INC_ALL, &nopen), nrf = 0;
    for (int i = 0; i < n; i++) nrf += inc[i].rf;
    WT_EQ(nopen, 400);
    WT_EQ(nrf, 200);
    web_live_sum_t s;
    web_live_summary(&w.live, &s, w.ms);
    WT_EQ(s.alerts[1], 400);
    WT_EQ(get(&w, "/api/alerts", "state=open&limit=1"), 200);
    WT_HAS(body_of(g_out), "\"open\":400,");
    free(inc);
    tw_down(&w);
}

/* ── /api/health, /api/sys and the tick ───────────────────────────── */

/* Without the flags the three answers carry none of the new members;
 * with them, both daemons, each on its own. */
static void test_health_one_stream_or_two(void) {
    static tw_t w;
    char tick[2048];
    tw_up(&w, 0);
    put(&w, 'w', SH_ONE);
    put(&w, 'w', STATUS_WIFI);
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_LACKS(body_of(g_out), "\"daemons\"");
    WT_LACKS(body_of(g_out), "\"rf_db\"");
    WT_LACKS(body_of(g_out), "wrong_daemon");
    /* The daemons' own member; "rf_stream" (#216) has
     * sensor_jsonl_version, in every answer with a data socket. */
    WT_LACKS(body_of(g_out), "\"jsonl_version\"");
    WT_EQ(count_of(body_of(g_out), "\"socket_spec\":"), 1);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_LACKS(body_of(g_out), "host_from");
    WT_LACKS(body_of(g_out), "sloth-rf");
    WT_EQ(count_of(body_of(g_out), "{\"key\":\"sloth"), 2);
    WT_HAS(body_of(g_out), "\"storage\":[{\"key\":\"sloth\",\"configured\":false,");
    WT_ASSERT(web_sse_tick(tick, sizeof(tick), 1, T, &w.h) > 0);
    WT_LACKS(tick, "\"rf\":");
    WT_HAS(tick, ",\"sensor\":\"ok\"}");
    tw_down(&w);

    tw_up(&w, 1);
    put(&w, 'w', SH_WIFI);
    put(&w, 'r', SH_RF);
    w.h.now_ms = w.ms + 4000;
    WT_EQ(get(&w, "/api/health", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, ",\"daemons\":[{\"role\":\"wifi\",\"socket\":\"connected\","
              "\"socket_spec\":\"unix:/demo/sloth.sock\",");
    WT_HAS(b, "},{\"role\":\"rf\",\"socket\":\"connected\","
              "\"socket_spec\":\"unix:/demo/sloth-rf.sock\",");
    WT_HAS(b, ",\"sensor\":\"ok\",\"health_age_s\":4,\"health_ts\":1800000000,"
              "\"jsonl_version\":\"1.9.0\",\"daemon\":\"rf\",\"wrong_daemon\":null,"
              "\"wrong_health\":0,\"wrong_records\":0}]");
    WT_HAS(b, "\"jsonl_version\":\"1.9.0\",\"daemon\":\"wifi\",\"wrong_daemon\":null,");
    /* The first socket's members stand where they stood. */
    WT_HAS(b, "\"uptime_s\":0,\"socket\":\"connected\",\"socket_spec\":\"unix:/demo/sloth.sock\",");
    WT_EQ(count_of(b, "\"socket_spec\":"), 3);
    /* No --rf-db: no "rf_db". */
    WT_LACKS(b, "\"rf_db\"");
    WT_ASSERT(web_sse_tick(tick, sizeof(tick), 1, T, &w.h) > 0);
    WT_HAS(tick, ",\"sensor\":\"ok\",\"rf\":{\"socket\":\"connected\",\"sensor\":\"ok\","
                 "\"records\":1}}");
    /* sloth-rf silent past the heartbeat: stale; sloth's word is its own. */
    w.h.now_ms = w.ms + WEB_LIVE_SH_STALE_MS + 1000;
    put(&w, 'w', SH_WIFI);
    w.live.sh_ms = w.h.now_ms;
    WT_ASSERT(web_sse_tick(tick, sizeof(tick), 1, T, &w.h) > 0);
    WT_HAS(tick, ",\"sensor\":\"ok\",\"rf\":{\"socket\":\"connected\",\"sensor\":\"stale\",");
    /* sloth-rf has no capture: never "not_observing" or "degraded". */
    WT_ASSERT(strcmp(web_live_sensor_word(&w.live_rf, w.ms), "ok") == 0);
    /* A stream that is not there yet. */
    web_live_sock_failed(&w.live_rf, "connect: No such file or directory", 250, w.ms);
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "{\"role\":\"rf\",\"socket\":\"retrying\",");
    WT_HAS(body_of(g_out), "\"socket_last_error\":\"connect: No such file or directory\"");
    tw_down(&w);
}

/* The store slot: listed, measured and sampled only when --rf-db names
 * it. */
static void test_rf_store_slot(void) {
    static tw_t w;
    char dir[TEST_TMP_MAX], path[TEST_TMP_MAX + 32];
    snprintf(dir, sizeof(dir), "%s/slothweb-twod-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/sloth-rf.db", dir);
    FILE *f = fopen(path, "wb");
    WT_ASSERT(f != NULL);
    if (f) {
        static char block[4096];
        for (int i = 0; i < 256; i++) fwrite(block, 1, sizeof(block), f);   /* 1 MiB */
        fclose(f);
    }
    tw_up(&w, 1);
    web_sys_set_rf_db(&w.sys, path);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), ",{\"key\":\"sloth-rf\",\"configured\":true,\"file\":\"sloth-rf.db\","
                           "\"present\":true,\"mb\":1.0,");
    WT_HAS(body_of(g_out), "\"limit_mb\":null,\"limit_state\":\"unknown\",\"limit_from\":null,");
    put(&w, 'r', SH_RF);
    put(&w, 'w', SH_WIFI);
    WT_EQ(get(&w, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"key\":\"sloth-rf\",\"configured\":true,\"file\":\"sloth-rf.db\","
                           "\"present\":true,\"mb\":1.0,\"main_bytes\":1048576,\"wal_bytes\":0,"
                           "\"limit_mb\":256,\"limit_state\":\"set\",\"limit_from\":\"sensor_health\",");
    /* sys.db_mb for it, on the RF daemon's own sys_status: the series
     * of its own key, not the host batch's samples of the same record
     * (seen red with DB_KEY[2] made "sloth"). */
    WT_EQ(web_rollup_has(&w.ru, WM_SYS_DB_MB, "sloth-rf"), 0);
    put(&w, 'r', STATUS_RF);
    WT_EQ(web_rollup_has(&w.ru, WM_SYS_DB_MB, "sloth-rf"), 1);
    tw_down(&w);
    unlink(path);
    rmdir(dir);
    /* Without --rf-db the same record samples no such series (seen red
     * with web_sys_db_metrics() adding a row whose size read failed). */
    tw_up(&w, 1);
    put(&w, 'r', SH_RF);
    put(&w, 'r', STATUS_RF);
    WT_EQ(web_rollup_has(&w.ru, WM_SYS_CPU, ""), 1);
    WT_EQ(web_rollup_has(&w.ru, WM_SYS_DB_MB, "sloth-rf"), 0);
    tw_down(&w);
}

#ifdef WITH_SQLITE
/* ── --rf-db ──────────────────────────────────────────────────────── */

static void ac_row(const char *db, const char *hex, const char *flight) {
    char sql[640];
    snprintf(sql, sizeof(sql),
        "INSERT INTO adsb_aircraft (hex,non_icao,first_seen,last_seen,visit_first,visits,"
        "sightings,flight,squawk,category,source_type,messages,pos_seen) VALUES"
        " ('%s',0,%lld,%lld,%lld,1,1,'%s','4175','A3','adsb_icao',307,0);",
        hex, (long long)SDB_NOW - 900, (long long)SDB_NOW - 100, (long long)SDB_NOW - 900, flight);
    WT_EQ(sdb_exec(db, sql), 0);
}

/* The RF history is read from --rf-db when it is given, else from
 * --sloth-db; /api/health describes it; the Devices route is sloth.db's
 * either way. */
static void test_rf_history_reads_the_rf_db(void) {
    static tw_t w;
    char dir[TEST_TMP_MAX], wdb[TEST_TMP_MAX + 32], rdb[TEST_TMP_MAX + 32];
    snprintf(dir, sizeof(dir), "%s/slothweb-twod-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(dir) != NULL);
    snprintf(wdb, sizeof(wdb), "%s/sloth.db", dir);
    snprintf(rdb, sizeof(rdb), "%s/sloth-rf.db", dir);
    WT_EQ(sdb_make(wdb, db_schema_version(), 0), 0);
    WT_EQ(sdb_make(rdb, db_schema_version(), 0), 0);
    ac_row(wdb, "aaa111", "WIFIDB1");
    ac_row(rdb, "bbb222", "RFDB22");
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,sources,risk_signals,first_seen,last_seen)"
        " VALUES ('0e:5f:00:00:00:0a','InWifiDb',0,16,0,%lld,%lld);",
        (long long)SDB_NOW - 900, (long long)SDB_NOW - 60);
    WT_EQ(sdb_exec(wdb, sql), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,sources,risk_signals,first_seen,last_seen)"
        " VALUES ('0e:5f:00:00:00:0b','InRfDb',0,16,0,%lld,%lld);",
        (long long)SDB_NOW - 900, (long long)SDB_NOW - 60);
    WT_EQ(sdb_exec(rdb, sql), 0);
    static web_slothdb_t S1, S2;
    web_slothdb_init(&S1, wdb, NULL);
    web_slothdb_init(&S2, rdb, NULL);

    tw_up(&w, 1);
    w.h.wall_s = SDB_NOW;
    w.m4.sdb = &S1;
    /* No --rf-db: sloth.db, as before the flags. */
    WT_EQ(get(&w, "/api/adsb/seen", "days=1"), 200);
    WT_HAS(body_of(g_out), "aaa111");
    WT_LACKS(body_of(g_out), "bbb222");
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_LACKS(body_of(g_out), "\"rf_db\"");
    /* With it. */
    w.m4.sdb_rf = &S2;
    WT_EQ(get(&w, "/api/adsb/seen", "days=1"), 200);
    WT_HAS(body_of(g_out), "bbb222");
    WT_HAS(body_of(g_out), "RFDB22");
    WT_LACKS(body_of(g_out), "aaa111");
    WT_EQ(get(&w, "/api/adsb/aircraft", "hex=bbb222&days=1"), 200);
    WT_HAS(body_of(g_out), "RFDB22");
    WT_EQ(get(&w, "/api/adsb/aircraft", "hex=aaa111&days=1"), 200);
    WT_LACKS(body_of(g_out), "WIFIDB1");
    WT_EQ(get(&w, "/api/gnss/seen", "days=1"), 200);
    WT_EQ(get(&w, "/api/aprs/seen", "days=1"), 200);
    /* The Wi-Fi tables stay on sloth.db. */
    WT_EQ(get(&w, "/api/devices", "limit=10&offset=0&sort=last"), 200);
    WT_HAS(body_of(g_out), "InWifiDb");
    WT_LACKS(body_of(g_out), "InRfDb");
    /* /api/health: sloth.db's members where they stood, sloth-rf.db's
     * in "rf_db". */
    WT_EQ(get(&w, "/api/health", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, ",\"db\":\"open\",");
    WT_HAS(b, ",\"rf_db\":{\"state\":\"open\",\"schema\":");
    WT_HAS(b, "/sloth-rf.db\",\"mode\":");
    WT_HAS(b, ",\"stale_after_s\":");
    WT_HAS(b, ",\"error\":null,\"opens\":");
    /* Only --rf-db (a host that runs sloth-rf alone): the RF history
     * answers, the Devices view says there is no sloth.db. */
    w.m4.sdb = NULL;
    WT_EQ(get(&w, "/api/adsb/seen", "days=1"), 200);
    WT_HAS(body_of(g_out), "bbb222");
    WT_EQ(get(&w, "/api/devices", "limit=10&offset=0&sort=last"), 503);
    /* --rf-db named and not there: the RF history says so, and does not
     * fall back to another daemon's file. */
    static web_slothdb_t S3;
    char gone[TEST_TMP_MAX + 32];
    snprintf(gone, sizeof(gone), "%s/absent.db", dir);
    web_slothdb_init(&S3, gone, NULL);
    w.m4.sdb = &S1;
    w.m4.sdb_rf = &S3;
    WT_EQ(get(&w, "/api/adsb/seen", "days=1"), 503);
    WT_HAS(body_of(g_out), "sloth_db_missing");
    WT_LACKS(body_of(g_out), "aaa111");
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), ",\"rf_db\":{\"state\":\"missing\",\"schema\":null,");
    WT_EQ(get(&w, "/api/devices", "limit=10&offset=0&sort=last"), 200);
    tw_down(&w);
    web_slothdb_destroy(&S3);
    web_slothdb_destroy(&S2);
    web_slothdb_destroy(&S1);
    /* slothweb wrote neither file nor a side file of either. */
    char listing[1024];
    sdb_listing(dir, listing, sizeof(listing));
    WT_LACKS(listing, "-journal");
    WT_LACKS(listing, "absent.db");
    static const char *const names[] = { "sloth.db", "sloth.db-wal", "sloth.db-shm",
                                         "sloth-rf.db", "sloth-rf.db-wal", "sloth-rf.db-shm" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[TEST_TMP_MAX + 48];
        snprintf(p, sizeof(p), "%s/%s", dir, names[i]);
        unlink(p);
    }
    rmdir(dir);
}

/* The list row of id in an /api/alerts body: from its "id" to the end
 * of the object. 1 found. */
static int row_seg(const char *body, const char *id, char *out, size_t cap) {
    char want[80];
    snprintf(want, sizeof(want), "{\"id\":\"%s\",", id);
    const char *b = strstr(body, want);
    if (!b) return 0;
    const char *e = strstr(b + 1, "{\"id\":\"");
    size_t n = e ? (size_t)(e - b) : strlen(b);
    if (n >= cap) n = cap - 1;
    memcpy(out, b, n);
    out[n] = '\0';
    return 1;
}

/* An alert sloth-rf raised, in the shared world with the optional RF
 * stream and database (wt_world.h w_rf_up()): it is on /api/alerts by
 * its handle, and its page reads the finding's history from
 * sloth-rf.db, not from a row of the same key in sloth.db. */
static void test_rf_alert_page_reads_the_rf_db(void) {
    w_open(1);
    w_rf_up();
    if (!W.have_db || !W.have_rf_db) { w_close(); return; }
    int ty = web_akb_find("GNSS_JAMMING");
    WT_ASSERT(ty > 0);
    char sql[1024], line[512], id[64];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES ('gnssjam',%lld,%lld,%d,2,'GNSS jamming','',"
        "'T1464',NULL,NULL,7);", (long long)W_T - 5000, (long long)W_T - 40, ty);
    WT_EQ(sdb_exec(W.rf_path, sql), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES ('gnssjam',%lld,%lld,%d,2,'GNSS jamming','',"
        "'T1464',NULL,NULL,99);", (long long)W_T - 7777, (long long)W_T - 50, ty);
    WT_EQ(sdb_exec(W.sdb_path, sql), 0);
    snprintf(line, sizeof(line),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"j1\",\"sev\":2,\"ty\":%d,"
        "\"title\":\"GNSS jamming\",\"detail\":\"d\",\"key\":\"gnssjam\",\"first_seen\":%lld,"
        "\"last_seen\":%lld,\"count\":1}", (long long)W_T - 40, ty, (long long)W_T - 40,
        (long long)W_T - 40);
    web_live_sum_t s0;
    web_live_summary(&W.live, &s0, W.h.now_ms);
    w_rf_line(line);
    WT_EQ(w_alert_id("GNSS_JAMMING", id, sizeof(id)), 1);
    WT_EQ(id[0], 's');
    char q[96], want[64];
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(w_get("/api/alert", q), 200);
    snprintf(want, sizeof(want), "%lld", (long long)W_T - 5000);
    WT_HAS(w_body(), want);
    snprintf(want, sizeof(want), "%lld", (long long)W_T - 7777);
    WT_LACKS(w_body(), want);
    /* sloth-rf.db's rowids are never given as "d" ids, which every
     * route resolves in sloth.db: the page names its file, and neither
     * db_id nor a run carries one (seen red with from_rf made 0 after
     * the file was chosen: a "d" db_id and a "d" run id of sloth-rf.db's
     * rowid came back). */
    WT_HAS(w_body(), "\"db\":\"open\",\"state\":\"open\",\"source\":\"both\",");
    WT_HAS(w_body(), ",\"db_file\":\"sloth-rf.db\",\"db_id\":null,");
    WT_HAS(w_body(), ",\"incidents\":1,\"sev\":2,\"count\":7,\"id\":null}],\"more\":false}");
    WT_LACKS(w_body(), "\"id\":\"d");
    /* The open count the tiles show includes it. */
    WT_EQ(w_get("/api/live", ""), 200);
    web_live_sum_t s;
    web_live_summary(&W.live, &s, W.h.now_ms);
    WT_EQ(s.alerts[2], s0.alerts[2] + 1);
    /* The list row shows what the page shows: sloth-rf.db's figures of
     * the key (7), not sloth.db's (99). sloth.db's finding of the same
     * key is no part of that row and is listed as itself (seen red with
     * web_alert_rf_apart() returning 0: the stream row counted 99 and
     * the sloth.db row was gone). */
    char row[1024], drow[1024];
    WT_EQ(w_get("/api/alerts", "limit=100&window=2592000"), 200);
    WT_EQ(row_seg(w_body(), id, row, sizeof(row)), 1);
    WT_HAS(row, "\"state\":\"open\",\"source\":\"both\",");
    WT_HAS(row, ",\"count\":7,\"incidents\":1,");
    char did[32] = "";
    const char *dp = strstr(w_body(), "\"state\":\"recorded\",\"source\":\"sloth.db\",\"type\":");
    for (; dp; dp = strstr(dp + 1, "\"state\":\"recorded\",\"source\":\"sloth.db\",\"type\":")) {
        const char *tn = strstr(dp, "\"type_name\":\"");
        if (!tn || strncmp(tn + 13, "GNSS_JAMMING\"", 13) != 0) continue;
        const char *b = dp;
        while (b > w_body() && strncmp(b, "{\"id\":\"", 7) != 0) b--;
        const char *e = strchr(b + 7, '"');
        if (e && (size_t)(e - b - 7) < sizeof(did)) {
            memcpy(did, b + 7, (size_t)(e - b - 7));
            did[e - b - 7] = '\0';
        }
        break;
    }
    WT_EQ(did[0], 'd');
    WT_EQ(row_seg(w_body(), did, drow, sizeof(drow)), 1);
    WT_HAS(drow, ",\"count\":99,\"incidents\":1,");
    /* And sloth.db's finding is not given sloth-rf's live incident of
     * the same key as its state (seen red with the web_alert_rf_apart()
     * test dropped from the "d" page's stream match: "open", and
     * sloth-rf's handle as its stream_id). */
    char dq[48];
    snprintf(dq, sizeof(dq), "id=%s", did);
    WT_EQ(w_get("/api/alert", dq), 200);
    WT_HAS(w_body(), "\"state\":\"recorded\",\"source\":\"sloth.db\",\"stream_id\":null,");
    WT_LACKS(w_body(), "\"db_file\"");

    /* A verdict on sloth-rf's alert is the stream incident's own, never
     * recorded against sloth.db's finding of the same key (seen red
     * with `apart` made 0 in frrs_resolve_alert(): sloth.db's row came
     * back "noise" too). */
    if (W.have_store) {
        char b[160];
        snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"by\":\"op\"}", id);
        WT_EQ(w_post("/api/frrs/triage", b), 200);
        WT_EQ(w_get("/api/alerts", "limit=100&window=2592000&triage=any"), 200);
        WT_EQ(row_seg(w_body(), id, row, sizeof(row)), 1);
        WT_HAS(row, "\"triage\":{\"state\":\"noise\"");
        WT_EQ(row_seg(w_body(), did, drow, sizeof(drow)), 1);
        WT_HAS(drow, "\"triage\":{\"state\":\"untriaged\"");
        WT_LACKS(drow, "\"noise\"");
    }

    /* The bundle of it says which file its page was read from, and
     * that file's state beside sloth.db's. */
    snprintf(q, sizeof(q), "kind=alert&id=%s", id);
    WT_EQ(w_get("/api/bundle", q), 200);
    WT_HAS(w_body(), ",\"sloth_db\":{\"state\":\"open\",\"schema\":");
    WT_HAS(w_body(), ",\"rf_db\":{\"state\":\"open\",\"schema\":");
    WT_HAS(w_body(), ",\"db_file\":\"sloth-rf.db\",\"db_id\":null,");
    /* Without --rf-db the bundle has no such member (seen red with the
     * block written for --sloth-db's file when --rf-db is not given). */
    W.m4.sdb_rf = NULL;
    WT_EQ(w_get("/api/bundle", q), 200);
    WT_HAS(w_body(), ",\"sloth_db\":{\"state\":\"open\",\"schema\":");
    WT_LACKS(w_body(), "\"rf_db\"");
    WT_LACKS(w_body(), "\"db_file\"");
    w_close();
}
#endif

/* ── the page ─────────────────────────────────────────────────────── */

/* The health view's two additions and the tile's, each pinned whole
 * (presence checks; no absence is claimed). */
static void test_two_daemon_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function rfWord(rf) { return rf.socket === \"connected\" ? String(rf.sensor) : String(rf.socket); }\n"
              "  function rfKpi(t) {\n"
              "    if (!t.rf || typeof t.sensor !== \"string\") return;\n"
              "    var w = rfWord(t.rf);\n"
              "    // The worse of the two words colours the tile: anything but ok or\n"
              "    // unknown is bad, whichever daemon says it.\n"
              "    var bad = function (x) { return x !== \"ok\" && x !== \"unknown\"; };\n"
              "    var cls = bad(t.sensor) || bad(w) ? \"bad\" : t.sensor === \"ok\" && w === \"ok\" ? \"ok\" : \"unknown\";\n"
              "    set(\"k-sensor\", t.sensor + \" \\u00b7 rf \" + w);\n"
              "    $(\"k-sensor\").className = \"kpi health-\" + cls;\n"
              "  }\n");
    /* Both of kpis()'s callers hand it sloth-rf's word, in every scope:
     * the tick keeps it, a scoped tick and /api/live's answer (which
     * has none) pass the kept one. */
    WT_HAS(p, "  var lastRf = null;\n"
              "  function rfWord(rf) {");
    WT_HAS(p, "        kpis({ socket: l.socket, devices: l.devices,\n"
              "               devices_stale: l.devices_stale, records: l.records,\n"
              "               records_s: l.records_s,\n"
              "               sensor: l.sensor ? l.sensor.state : undefined,\n"
              "               rf: lastRf,\n"
              "               alerts_open: l.alerts_open\n"
              "                 ? [l.alerts_open.low, l.alerts_open.warn, l.alerts_open.crit]\n"
              "                 : null });\n");
    WT_HAS(p, "      lastRf = t.rf || null;\n"
              "      kpis(SCOPE === \"hybrid\" ? t : { socket: t.socket, sensor: t.sensor, rf: lastRf });\n"
              "      // Under a scope the tiles are /api/live's: asked again every 2 s.\n"
              "      if (SCOPE !== \"hybrid\" && Date.now() - lastLive >= 2000) live();\n");
    /* An RF alert's runs carry no id and its page names its file. */
    WT_HAS(p, "      if (r.id && r.id !== AD.runsOf) alertLink(li, r.id);\n");
    WT_HAS(p, "    var dbFile = j.db_file || \"sloth.db\";\n"
              "    AD.runsNone = j.db === \"open\" ? \"no \" + dbFile + \" row yet\" : dbFile + \" is \" + j.db;\n");
    WT_HAS(p, "        (t.sensor === \"ok\" ? \"ok\" : t.sensor === \"unknown\" ? \"unknown\" : \"bad\");\n"
              "    }\n"
              "    rfKpi(t);\n");
    WT_HAS(p, "  var DAEMON_NAME = { \"wifi\": \"sloth (--socket)\", \"rf\": \"sloth-rf (--rf-socket)\" };\n"
              "  function daemonRows(box, h) {\n"
              "    (h.daemons || []).forEach(function (d) {\n"
              "      var word = el(\"span\", \"health-\" + (d.sensor === \"ok\" ? \"ok\" : d.sensor === \"unknown\" ? \"unknown\" : \"bad\"),\n"
              "                    String(d.sensor));\n"
              "      box.appendChild(el(\"div\", \"label\", \"daemon: \" + (DAEMON_NAME[d.role] || String(d.role))));\n"
              "      kvList(box, [[\"socket\", d.socket + (d.socket_spec ? \", \" + d.socket_spec : \"\")],\n"
              "                   [\"sensor_health\", word],\n"
              "                   [\"report\", num(d.health_age_s) ? dur(d.health_age_s) + \" ago\" : \"no sensor_health yet\"],\n"
              "                   [\"stream version\", d.jsonl_version],\n"
              "                   [\"last record\", num(d.last_record_age_s) ? dur(d.last_record_age_s) + \" ago\" : \"none yet\"],\n"
              "                   [\"records\", String(d.socket_records)], [\"decode errors\", String(d.socket_decode_errors)],\n"
              "                   [\"gaps\", String(d.socket_gaps)], [\"reconnects\", String(d.socket_reconnects)],\n"
              "                   [\"last error\", d.socket_last_error],\n"
              "                   [\"wrong daemon\", d.wrong_daemon ? \"this socket is sending \" + d.wrong_daemon + \"'s sensor_health: nothing from it is applied (\" +\n"
              "                                                     d.wrong_records + \" records passed over); check the socket flags\"\n"
              "                                                   : d.wrong_records ? d.wrong_records + \" records passed over earlier, none now\" : null]]);\n"
              "    });\n"
              "  }\n");
    WT_HAS(p, "  function rfDbRows(box, h) {\n"
              "    var d = h.rf_db;\n"
              "    if (!d) return;\n"
              "    box.appendChild(el(\"div\", \"label\", \"sloth-rf.db\"));\n"
              "    kvList(box, [[\"db\", String(d.state) + (d.mode ? \", \" + d.mode : \"\")],\n"
              "                 [\"schema\", num(d.schema) ? \"v\" + d.schema : null],\n"
              "                 [\"freshness\", num(d.age_s) ? \"written \" + dur(d.age_s) + \" ago\" + (d.stale === true ? \", stale: sloth-rf's stream is current and the file is not\" : \"\")\n"
              "                                            : \"nothing to read yet\"],\n"
              "                 [\"error\", d.error]]);\n"
              "  }\n");
    WT_HAS(p, "        kvList(box, [[\"store\", String(h.store)], [\"path\", h.store_path]]);\n"
              "        daemonRows(box, h);\n"
              "        rfStreamRows(box, h);\n"
              "        rfDbRows(box, h);\n"
              "        set(\"hl-note\", \"the tile's word is the state above\");\n");
    WT_HAS(p, "  var DB_NAME = { \"sloth\": \"sloth.db\", \"slothweb\": \"slothweb.db\", \"sloth-rf\": \"sloth-rf.db\" };");
    WT_HAS(p, "  function rssName(j) { return j.host_from === \"rf\" ? \"sloth-rf rss\" : \"sloth rss\"; }\n");
    WT_HAS(p, "      { g: \"host\", name: rssName(j), metric: \"sys.rss\", key: \"\", unit: \"kB\", eps: 1024 },");
}

/* ── where the RF tabs' records come from (#216, JSONL 2.0.0) ─────── */

/* sloth-wifi since the cutover: its capture, the receiver's health, no
 * decoder block, and the 2.0.0 contract. */
static const char SH_WIFI_2X[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS
    ",\"gps_state\":\"fix\",\"gps_src\":\"gpsd:127.0.0.1:2947\",\"gnss_sats_in_view\":9,"
    "\"gnss_sats_used\":7,\"loc_lat\":11.00000,\"loc_lon\":21.00000,\"loc_src\":\"gps\","
    "\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"2.0.0\"}";
static const char SH_RF_2X[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," RF_BLOCKS
    ",\"daemon\":\"rf\",\"db_max_mb\":256,\"jsonl_version\":\"2.0.0\"}";
/* A stream from before the version field (before JSONL 1.0.0). */
static const char SH_PRE10[] =
    "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS "," RF_BLOCKS "}";

static const char *const RF_TABS[] = { "/api/adsb", "/api/aprs", "/api/rtl433", "/api/victron" };
#define RF_TAB_N ((int)(sizeof(RF_TABS) / sizeof(RF_TABS[0])))

#define RFS_NOT_CONFIGURED \
    ",\"rf_stream\":{\"state\":\"not_configured\",\"reading\":\"2.x\"," \
    "\"sensor_jsonl_version\":\"2.0.0\",\"sensor_daemon\":\"wifi\",\"rf_socket\":false}}"

/* A 2.x sloth-wifi on --socket and no --rf-socket: every RF tab and
 * /api/health say the RF daemon's stream is not configured, as the last
 * member of the answer, and the tabs are empty for that stated reason.
 * Before any sensor_health the state is "unknown", never
 * "not_configured": slothweb does not yet know what it is reading.
 *
 * Seen red (2026-11-15) with rf_stream_locked()'s `>= 2` made `>= 3`
 * (every tab and /api/health read "sensor_stream"), and the
 * out-of-scope absence with the `!none_here` test taken off
 * route_adsb()'s rf_stream_member() call (the out-of-scope answer ends
 * in a newline, which the splice keeps last, so only that test holds
 * the member off it). */
static void test_2x_wifi_alone_says_rf_not_configured(void) {
    static tw_t w;
    tw_up(&w, 0);
    for (int i = 0; i < RF_TAB_N; i++) {
        WT_EQ(get(&w, RF_TABS[i], ""), 200);
        WT_HAS(body_of(g_out), ",\"rf_stream\":{\"state\":\"unknown\",\"reading\":null,"
                               "\"sensor_jsonl_version\":null,\"sensor_daemon\":null,"
                               "\"rf_socket\":false}}");
        WT_LACKS(body_of(g_out), "not_configured");
    }
    put(&w, 'w', SH_WIFI_2X);
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_NOT_CONFIGURED);
    for (int i = 0; i < RF_TAB_N; i++) {
        WT_EQ(get(&w, RF_TABS[i], ""), 200);
        const char *b = body_of(g_out);
        WT_HAS(b, RFS_NOT_CONFIGURED);
        /* The last member, once, and the answer still an object. */
        WT_EQ(count_of(b, "\"rf_stream\":"), 1);
        WT_ASSERT(strlen(b) > strlen(RFS_NOT_CONFIGURED) &&
                  !strcmp(b + strlen(b) - strlen(RFS_NOT_CONFIGURED), RFS_NOT_CONFIGURED));
        WT_ASSERT(b[0] == '{');
        /* Empty, and for no other stated reason. */
        WT_HAS(b, "\"sensor\":null");
    }
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"total\":0,");
    WT_EQ(get(&w, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "\"devices\":[]");
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), ",\"rf_stream\":{\"state\":\"not_configured\",\"reading\":\"2.x\","
                           "\"sensor_jsonl_version\":\"2.0.0\",\"sensor_daemon\":\"wifi\","
                           "\"rf_socket\":false}");
    WT_EQ(count_of(body_of(g_out), "\"rf_stream\":"), 1);
    WT_LACKS(body_of(g_out), "\"daemons\"");
    /* The receiver's health is sloth-wifi's too and still read, so the
     * GNSS tab's header draws; its fix, sky and satellite records are
     * sloth-rf's alone, so the answer carries the same reason and the
     * page says why those are empty (#216 review; seen red with the
     * rf_stream_member() call taken out of route_gnss()). */
    WT_EQ(get(&w, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"lat\":11.00000");
    WT_HAS(body_of(g_out), "\"fix\":null");
    WT_HAS(body_of(g_out), RFS_NOT_CONFIGURED);
    WT_EQ(count_of(body_of(g_out), "\"rf_stream\":"), 1);
    WT_EQ(get(&w, "/api/gnss/fixes", ""), 200);
    WT_LACKS(body_of(g_out), "rf_stream");
    /* The out-of-scope answer is the scope's, not this sensor's: no
     * member. */
    WT_EQ(get(&w, "/api/adsb", "scope=local"), 200);
    WT_HAS(body_of(g_out), "out_of_scope");
    WT_LACKS(body_of(g_out), "rf_stream");
    tw_down(&w);

    /* No data socket at all: the M0 shape, no member anywhere. */
    tw_up(&w, 0);
    w.h.live = NULL;
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_LACKS(body_of(g_out), "rf_stream");
    WT_EQ(get(&w, "/api/rtl433", ""), 200);
    WT_LACKS(body_of(g_out), "rf_stream");
    w.h.live = &w.live;
    tw_down(&w);
}

/* A 1.x stream alone (an unsplit, older sensor): read as it always was.
 * Its own stream has the decoders' records and blocks, they fill the RF
 * tabs, and the state says "sensor_stream" and which contract it is
 * reading - 1.x, or "before 1.0.0" for a stream with no version at all.
 * Never "not_configured".
 *
 * Seen red (2026-11-15) with rf_stream_locked() returning
 * NOT_CONFIGURED for every one-socket stream that is not sloth-rf's. */
static void test_1x_stream_alone_still_fills_the_rf_tabs(void) {
    static tw_t w;
    static const struct { const char *sh, *reading, *ver; } old[] = {
        { SH_ONE,   "\"reading\":\"1.x\"",          "\"sensor_jsonl_version\":\"1.9.0\"" },
        { SH_PRE10, "\"reading\":\"before 1.0.0\"", "\"sensor_jsonl_version\":null" },
    };
    for (int k = 0; k < 2; k++) {
        tw_up(&w, 0);
        put(&w, 'w', AC); put(&w, 'w', STN); put(&w, 'w', DEV);
        put(&w, 'w', old[k].sh);
        WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_SENSOR_1X);
        for (int i = 0; i < RF_TAB_N; i++) {
            WT_EQ(get(&w, RF_TABS[i], ""), 200);
            const char *b = body_of(g_out);
            WT_HAS(b, ",\"rf_stream\":{\"state\":\"sensor_stream\",");
            WT_HAS(b, old[k].reading);
            WT_HAS(b, old[k].ver);
            WT_HAS(b, "\"sensor_daemon\":null,\"rf_socket\":false}}");
            WT_LACKS(b, "not_configured");
        }
        WT_EQ(get(&w, "/api/adsb", ""), 200);
        WT_HAS(body_of(g_out), "FLT-MARK");
        WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
        WT_EQ(get(&w, "/api/aprs", ""), 200);
        WT_HAS(body_of(g_out), "APRS-COMMENT-MARK");
        WT_EQ(get(&w, "/api/rtl433", ""), 200);
        WT_HAS(body_of(g_out), "Testco-TP01");
        WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
        WT_EQ(get(&w, "/api/health", ""), 200);
        WT_HAS(body_of(g_out), ",\"rf_stream\":{\"state\":\"sensor_stream\",");
        tw_down(&w);
    }
    /* A 1.10.0 is 1.x, not "10": the MAJOR is read, not a prefix. */
    tw_up(&w, 0);
    put(&w, 'w', "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS
                 ",\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"1.10.0\"}");
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_SENSOR_1X);
    put(&w, 'w', "{\"type\":\"sensor_health\",\"ts\":1800000001," WIFI_BLOCKS
                 ",\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"10.0.0\"}");
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_NOT_CONFIGURED);
    tw_down(&w);
}

/* A 2.x sloth-wifi and sloth-rf, each on its socket: the RF tabs are
 * filled from sloth-rf's stream and say so; nothing on sloth-wifi's
 * socket feeds them (its stream has none, and a decoy there is passed
 * over as before). And sloth-rf alone on --socket, which a host with
 * only SDRs may do: filled from it, and named for what it is.
 *
 * Seen red (2026-11-15), the first half, with the Wi-Fi feed's
 * `if (rf_type) return;` removed and the four RF consumers called on
 * that feed (the decoys were listed). */
static void test_2x_wifi_and_rf_fill_the_tabs_from_the_rf_stream(void) {
    static tw_t w;
    tw_up(&w, 1);
    put(&w, 'w', SH_WIFI_2X);
    put(&w, 'w', AC_DECOY); put(&w, 'w', STN_DECOY); put(&w, 'w', DEV_DECOY);
    put(&w, 'r', AC); put(&w, 'r', STN); put(&w, 'r', DEV);
    put(&w, 'r', SH_RF_2X);
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_RF_SOCKET);
    for (int i = 0; i < RF_TAB_N; i++) {
        WT_EQ(get(&w, RF_TABS[i], ""), 200);
        const char *b = body_of(g_out);
        WT_HAS(b, ",\"rf_stream\":{\"state\":\"rf_socket\",\"reading\":\"2.x\","
                  "\"sensor_jsonl_version\":\"2.0.0\",\"sensor_daemon\":\"wifi\","
                  "\"rf_socket\":true}}");
        WT_LACKS(b, "not_configured");
        WT_LACKS(b, "DECOY");
        WT_LACKS(b, "dec0de");
        WT_LACKS(b, "D3COY");
        WT_LACKS(b, "Decoy-DV01");
    }
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "FLT-MARK");
    WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
    WT_EQ(get(&w, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "APRS-COMMENT-MARK");
    WT_EQ(get(&w, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "Testco-TP01");
    WT_EQ(get(&w, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), ",\"rf_stream\":{\"state\":\"rf_socket\",");
    WT_HAS(body_of(g_out), "\"jsonl_version\":\"2.0.0\",\"daemon\":\"rf\",\"wrong_daemon\":null,");
    WT_HAS(body_of(g_out), "\"jsonl_version\":\"2.0.0\",\"daemon\":\"wifi\",\"wrong_daemon\":null,");
    /* The lures read sloth-wifi's 2.x stream and say which. */
    WT_EQ(web_lure_reported(&w.lure), 1);
    WT_EQ(get(&w, "/api/lures", ""), 200);
    WT_HAS(body_of(g_out), "\"reported\":true,\"jsonl_version\":\"2.0.0\"");
    tw_down(&w);

    tw_up(&w, 0);
    put(&w, 'w', AC); put(&w, 'w', DEV);
    put(&w, 'w', SH_RF_2X);
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_RF_DAEMON);
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "FLT-MARK");
    WT_HAS(body_of(g_out), ",\"rf_stream\":{\"state\":\"rf_daemon_on_socket\",\"reading\":\"2.x\","
                           "\"sensor_jsonl_version\":\"2.0.0\",\"sensor_daemon\":\"rf\","
                           "\"rf_socket\":false}}");
    WT_EQ(get(&w, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "Testco-TP01");
    WT_LACKS(body_of(g_out), "not_configured");
    tw_down(&w);

    /* The words, each once. */
    WT_ASSERT(!strcmp(web_live_rf_stream_word(WEB_RF_STREAM_UNKNOWN), "unknown"));
    WT_ASSERT(!strcmp(web_live_rf_stream_word(WEB_RF_STREAM_RF_SOCKET), "rf_socket"));
    WT_ASSERT(!strcmp(web_live_rf_stream_word(WEB_RF_STREAM_SENSOR_1X), "sensor_stream"));
    WT_ASSERT(!strcmp(web_live_rf_stream_word(WEB_RF_STREAM_RF_DAEMON), "rf_daemon_on_socket"));
    WT_ASSERT(!strcmp(web_live_rf_stream_word(WEB_RF_STREAM_NOT_CONFIGURED), "not_configured"));
    WT_ASSERT(!strcmp(web_live_rf_stream_word(99), "unknown"));
    WT_EQ(web_live_rf_stream(NULL), WEB_RF_STREAM_UNKNOWN);
}

/* An unsplit 1.x sensor upgraded under a slothweb that stays up: the
 * decoder blocks its stream carried are not kept once a sensor_health
 * arrives without them. The ADS-B and APRS stores used to keep the last
 * block for ever (rtl_433 and Victron always cleared theirs), so the
 * tab read "decoder live" over a stream that has no decoder, and the
 * page, which asks for the reason only when there is no block, never
 * said the RF daemon is not configured. The same clears a block when
 * sloth-rf is restarted without the flag.
 *
 * Seen red (2026-11-15) with web_adsb.c's and web_aprs.c's sh_apply()
 * returning on a blockless sensor_health as they did: both answers kept
 * "sensor":{...,"state":"live"}. */
static void test_1x_then_2x_drops_the_decoder_blocks(void) {
    static tw_t w;
    tw_up(&w, 0);
    put(&w, 'w', SH_ONE);
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
    WT_EQ(get(&w, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"state\":\"live\"");
    WT_LACKS(body_of(g_out), "\"sensor\":null");
    put(&w, 'w', SH_WIFI_2X);
    WT_EQ(web_live_rf_stream(&w.live), WEB_RF_STREAM_NOT_CONFIGURED);
    for (int i = 0; i < RF_TAB_N; i++) {
        WT_EQ(get(&w, RF_TABS[i], ""), 200);
        WT_HAS(body_of(g_out), "\"sensor\":null");
        WT_LACKS(body_of(g_out), "\"state\":\"live\"");
        WT_HAS(body_of(g_out), RFS_NOT_CONFIGURED);
    }
    tw_down(&w);

    /* sloth-rf restarted with no decoder, on its own socket. */
    tw_up(&w, 1);
    put(&w, 'w', SH_WIFI_2X);
    put(&w, 'r', SH_RF_2X);
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
    put(&w, 'r', SH_RF_BARE);
    for (int i = 0; i < RF_TAB_N; i++) {
        WT_EQ(get(&w, RF_TABS[i], ""), 200);
        WT_HAS(body_of(g_out), "\"sensor\":null");
    }
    /* sloth-wifi's own sensor_health never clears sloth-rf's blocks. */
    put(&w, 'r', SH_RF_2X);
    put(&w, 'w', SH_WIFI_2X);
    WT_EQ(get(&w, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"ts\":1800000000,\"state\":\"live\"");
    WT_EQ(get(&w, "/api/aprs", ""), 200);
    WT_LACKS(body_of(g_out), "\"sensor\":null");
    tw_down(&w);
}

/* The contract is named for what the stream says, never rounded to one
 * slothweb knows: a 3.0.0 reads "3.x" and a 0.9.0 "0.x", and the page
 * says it does not know that MAJOR (rfstream.js readingText()). Such a
 * stream used to be reported as "2.x" (and 0.x as "1.x").
 *
 * Seen red (2026-11-15) with the reading written as
 * `ver_major() >= 2 ? "2.x" : "1.x"`. */
static void test_reading_names_the_streams_own_major(void) {
    static tw_t w;
    static const struct { const char *ver, *reading; int state; } v[] = {
        { "3.0.0",  "\"reading\":\"3.x\",\"sensor_jsonl_version\":\"3.0.0\"",   WEB_RF_STREAM_NOT_CONFIGURED },
        { "10.0.0", "\"reading\":\"10.x\",\"sensor_jsonl_version\":\"10.0.0\"", WEB_RF_STREAM_NOT_CONFIGURED },
        { "0.9.0",  "\"reading\":\"0.x\",\"sensor_jsonl_version\":\"0.9.0\"",   WEB_RF_STREAM_SENSOR_1X },
        { "2.4.1",  "\"reading\":\"2.x\",\"sensor_jsonl_version\":\"2.4.1\"",   WEB_RF_STREAM_NOT_CONFIGURED },
        { "1.10.0", "\"reading\":\"1.x\",\"sensor_jsonl_version\":\"1.10.0\"",  WEB_RF_STREAM_SENSOR_1X },
    };
    for (size_t k = 0; k < sizeof(v) / sizeof(v[0]); k++) {
        char line[1024];
        tw_up(&w, 0);
        snprintf(line, sizeof(line), "{\"type\":\"sensor_health\",\"ts\":1800000000," WIFI_BLOCKS
                 ",\"daemon\":\"wifi\",\"db_max_mb\":512,\"jsonl_version\":\"%s\"}", v[k].ver);
        put(&w, 'w', line);
        WT_EQ(web_live_rf_stream(&w.live), v[k].state);
        WT_EQ(get(&w, "/api/health", ""), 200);
        WT_HAS(body_of(g_out), v[k].reading);
        tw_down(&w);
    }
}

/* The page's one wording of it (web/ui/rfstream.js), whole functions,
 * and the one call each tab and the health view make. Every string
 * reaches the DOM through textContent or el(): none is HTML. */
static void test_rf_stream_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function notConfigured(j) {\n"
              "    return !!(j && j.rf_stream && j.rf_stream.state === \"not_configured\");\n"
              "  }\n");
    WT_HAS(p, "  function text(j, what) {\n"
              "    if (!notConfigured(j)) return \"\";\n"
              "    var v = j.rf_stream.sensor_jsonl_version;\n"
              "    return \"RF daemon not configured: this slothweb reads sloth-wifi's stream\" +\n"
              "      (v ? \" (JSONL \" + v + \")\" : \"\") + \", which has carried no \" + what +\n"
              "      \" records since the sloth-wifi / sloth-rf split (JSONL 2.0.0). They are sloth-rf's: \" +\n"
              "      \"start slothweb with --rf-socket (and --rf-db) pointing at it, docs/wiki/deployment.md section 11\";\n"
              "  }\n");
    WT_HAS(p, "  function sourceText(r) {\n"
              "    if (!r) return null;\n"
              "    var v = r.sensor_jsonl_version ? \"JSONL \" + r.sensor_jsonl_version : r.reading || \"no version yet\";\n"
              "    if (r.state === \"rf_socket\") return \"sloth-rf's stream (--rf-socket)\";\n"
              "    if (r.state === \"sensor_stream\")\n"
              "      return \"the sensor's own stream (\" + v + \", an unsplit sensor: its decoders' records are on --socket)\";\n"
              "    if (r.state === \"rf_daemon_on_socket\") return \"sloth-rf's stream, on --socket (\" + v + \")\";\n"
              "    if (r.state === \"not_configured\")\n"
              "      return \"NOT CONFIGURED: --socket is sloth-wifi's stream (\" + v +\n"
              "        \"), which has no ADS-B, APRS, rtl_433 or Victron records; give slothweb --rf-socket (and --rf-db) for sloth-rf\";\n"
              "    return \"not known: no sensor_health on --socket yet\";\n"
              "  }\n");
    WT_HAS(p, "  function readingText(r) {\n"
              "    var rd = r && r.reading;\n"
              "    if (!rd) return null;\n"
              "    if (rd === \"1.x\" || rd === \"2.x\" || rd === \"before 1.0.0\") return rd;\n"
              "    return rd + \" (a JSONL MAJOR this slothweb does not know; it reads 1.x and 2.x, so what it shows of this stream may be wrong: upgrade slothweb)\";\n"
              "  }\n");
    WT_HAS(p, "  window.SlothRfStream = { notConfigured: notConfigured, text: text, sourceText: sourceText, readingText: readingText };\n");
    /* The health view. */
    WT_HAS(p, "  function rfStreamRows(box, h) {\n"
              "    var t = window.SlothRfStream && h.rf_stream ? window.SlothRfStream.sourceText(h.rf_stream) : null;\n"
              "    if (!t) return;\n"
              "    box.appendChild(el(\"div\", \"label\", \"RF daemon (ADS-B, APRS, rtl_433, Victron)\"));\n"
              "    var rd = window.SlothRfStream.readingText(h.rf_stream);\n"
              "    kvList(box, [[\"records from\", el(\"span\", h.rf_stream.state === \"not_configured\" ? \"health-bad\" : \"\", t)],\n"
              "                 [\"--socket is\", rd && rd !== h.rf_stream.reading ? el(\"span\", \"health-bad\", rd) : rd]]);\n"
              "  }\n");
    /* The GNSS tab: the receiver's health is sloth-wifi's, the fix, sky
     * and satellite records sloth-rf's, so it gives the same reason. */
    WT_HAS(p, "  function rfWhy(j) {\n"
              "    return window.SlothRfStream ? window.SlothRfStream.text(j, \"gnss_fix, gnss_sky or gnss_sat\") : \"\";\n"
              "  }\n");
    WT_HAS(p, "    if (!rows || !rows.length) { set(\"gnss-fix-note\", rfWhy(last) || \"no gnss_fix records yet\"); return; }\n");
    /* The two state lines name the daemon that takes the flag. */
    WT_HAS(p, "    if (!s) return \"no decoder: the sensor has not reported --rtl433 on this connection (the flag is sloth-rf's)\";\n");
    WT_HAS(p, "    if (!s) return \"no reader: the sensor has not reported --victron on this connection (the flag is sloth-rf's)\";\n");
    WT_LACKS(p, "sloth has not reported --");
    /* The four tabs: the reason outranks "no decoder". */
    WT_HAS(p, "    if (!s && !j.total) {\n"
              "      // #216: with a 2.x sloth-wifi and no --rf-socket the tab is empty\n"
              "      // because the RF daemon's stream is not configured; say that.\n"
              "      var rf = window.SlothRfStream ? window.SlothRfStream.text(j, \"ADS-B\") : \"\";\n"
              "      h.appendChild(el(\"span\", \"\", rf ? \"ADS-B: RF daemon not configured\" : \"ADS-B: no decoder\"));\n"
              "      var e = $(\"adsb-empty\");\n"
              "      e.hidden = false;\n"
              "      e.textContent = rf || \"no adsb records yet: sloth-rf needs --adsb /run/readsb/aircraft.json (or another readsb / dump1090-fa aircraft.json), docs/wiki/adsb.md\";\n");
    WT_HAS(p, "    if (!s && !j.total) {\n"
              "      // #216: as the ADS-B tab; the RF daemon's stream not configured\n"
              "      // is a reason of its own.\n"
              "      var rf = window.SlothRfStream ? window.SlothRfStream.text(j, \"APRS\") : \"\";\n"
              "      h.appendChild(el(\"span\", \"\", rf ? \"APRS: RF daemon not configured\" : \"APRS: no decoder\"));\n"
              "      var e = $(\"aprs-empty\");\n"
              "      e.hidden = false;\n"
              "      e.textContent = rf || \"no aprs records yet: sloth-rf needs --aprs /var/lib/direwolf/aprs.log (Dire Wolf's -L packet log), docs/wiki/aprs.md\";\n");
    WT_HAS(p, "  function draw(j) {\n"
              "    var st = $(\"r4-state\");\n"
              "    // #216: the RF daemon's stream not configured outranks \"no decoder\".\n"
              "    var rf = window.SlothRfStream ? window.SlothRfStream.text(j, \"rtl_433\") : \"\";\n"
              "    if (st) st.textContent = rf || stateText(j);\n"
              "    table((j && !j.out_of_scope && j.devices) || []);\n"
              "  }\n");
    WT_HAS(p, "  function draw(j) {\n"
              "    var st = $(\"vc-state\");\n"
              "    // #216: the RF daemon's stream not configured outranks \"no reader\".\n"
              "    var rf = window.SlothRfStream ? window.SlothRfStream.text(j, \"Victron\") : \"\";\n"
              "    if (st) st.textContent = rf || stateText(j);\n");
}

void run_twodaemon_tests(void) {
    WT_RUN(test_tabs_same_with_one_stream_or_two);
    WT_RUN(test_rtl433_block_and_sloths_sensor_health);
    WT_RUN(test_wrong_daemon_is_not_applied);
    WT_RUN(test_rf_stream_feeds_the_rollup_not_the_metrics);
    WT_RUN(test_sysstat_has_one_writer_per_part);
    WT_RUN(test_gnss_position_and_health_precedence);
    WT_RUN(test_rf_alerts_are_listed_with_sloths);
    WT_RUN(test_same_key_from_both_daemons_is_one);
    WT_RUN(test_both_daemons_open_incidents_all_listed);
    WT_RUN(test_health_one_stream_or_two);
    WT_RUN(test_rf_store_slot);
#ifdef WITH_SQLITE
    WT_RUN(test_rf_history_reads_the_rf_db);
    WT_RUN(test_rf_alert_page_reads_the_rf_db);
#endif
    WT_RUN(test_two_daemon_page);
    WT_RUN(test_2x_wifi_alone_says_rf_not_configured);
    WT_RUN(test_1x_stream_alone_still_fills_the_rf_tabs);
    WT_RUN(test_2x_wifi_and_rf_fill_the_tabs_from_the_rf_stream);
    WT_RUN(test_1x_then_2x_drops_the_decoder_blocks);
    WT_RUN(test_reading_names_the_streams_own_major);
    WT_RUN(test_rf_stream_page);
}
