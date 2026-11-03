/* The GNSS panel (web_gnss.h): the receiver's sky and clock kept by
 * slothweb from hand-built records in the emitter's exact shape
 * (src/jsonl.c jsonl_emit_gnss(); the lines below are the ones
 * tests/test_gps.c asserts sloth writes), the two routes through the
 * route table under every scope, the four global metrics, and the
 * names held to sloth's own table.
 *
 * Absence assertions, each seen red under a named mutation and restored:
 * the every-scope answer with route_gnss() given route_ble()'s Local
 * out_of_scope branch (a Local answer carried no rows); the range
 * checks with sat_apply()'s el bound widened to 180 (95 landed on the
 * row); the ring bound with fix_apply()'s wrap removed (ASan). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_gnss.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"

#define T 1793059200LL

static web_gnss_t G;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_gnss_record(&G, &R, 1000);
}

/* The four records as sloth writes them for tests/test_gps.c's SKY4 /
 * TPV_FULL pair, ts T. */
static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1793059200,\"capture_iface\":\"any\","
    "\"gps_state\":\"fix\",\"gps_src\":\"gpsd:127.0.0.1:2947\",\"gps_fix_age_s\":0,"
    "\"gps_quality\":3,\"gps_sats\":2,\"gps_hdop\":0.8,\"gps_sentences\":2,"
    "\"gps_bad_checksum\":0,\"gps_parse_errors\":0,\"gps_reconnects\":0,"
    "\"gps_positions_dropped\":0,\"gps_err\":\"\",\"gnss_sats_in_view\":4,"
    "\"gnss_sats_used\":2,\"gnss_cn0_mean\":31.3,\"gnss_time_offset_ms\":250,\"gnss_jam\":12}";
static const char FIX[] =
    "{\"type\":\"gnss_fix\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\","
    "\"fix_ts\":1793059200,\"mode\":3,\"status\":2,\"nsat\":4,\"usat\":2,"
    "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"lat\":51.50074,\"lon\":-0.12469,"
    "\"alt_m\":11.6,\"eph\":6.2,\"epv\":9.1,\"speed_mps\":0.30,"
    "\"track_deg\":12.5,\"rx_time_ms\":1793059200250,\"time_off_ms\":250,"
    "\"leap\":18,\"jam\":12,\"tpv_count\":1}";
static const char SKY[] =
    "{\"type\":\"gnss_sky\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\","
    "\"sky_ts\":1793059200,\"nsat\":4,\"usat\":2,\"rows\":4,\"overflow\":0,"
    "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"gdop\":2.0,\"tdop\":0.9,"
    "\"cn0_mean\":31.3,\"cn0_max\":41.0,\"cn0_sd\":7.6,\"cn0_n\":3,\"passes\":1}";
static const char SAT5[] =
    "{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
    "\"svid\":5,\"prn\":5,\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":41.0,"
    "\"used\":1,\"health\":1,\"sky_ts\":1793059200}";
static const char SAT7[] =
    "{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
    "\"svid\":7,\"prn\":7,\"sigid\":-1,\"cn0\":22.5,"
    "\"used\":0,\"health\":1,\"sky_ts\":1793059200}";
static const char SAT73[] =
    "{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GLONASS\",\"gnssid\":6,"
    "\"svid\":9,\"prn\":73,\"sigid\":-1,\"el\":30,\"az\":300,\"cn0\":30.5,"
    "\"used\":1,\"health\":1,\"sky_ts\":1793059200}";
static const char SAT131[] =
    "{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"SBAS\",\"gnssid\":1,"
    "\"svid\":131,\"prn\":131,\"sigid\":-1,\"el\":10,\"az\":200,"
    "\"used\":0,\"health\":0,\"sky_ts\":1793059200}";

static char g_out[131072];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static void fresh(void) {
    web_gnss_destroy(&G);
    WT_EQ(web_gnss_init(&G), 0);
}

static void seed(void) {
    feed(SH); feed(SKY); feed(FIX);
    feed(SAT5); feed(SAT7); feed(SAT73); feed(SAT131);
}

/* The four records land where the page reads them: the sensor block,
 * the fix, the sky, four rows sorted by C/N0 with the untracked SBAS
 * row last and its cn0 null, each row's points. */
static void test_gnss_ingest_and_route(void) {
    fresh();
    seed();
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.gnss = &G;
    H.wall_s = T + 5;
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793059205,\"scope_note\":\"every scope: the host's own receiver\","
              "\"src\":\"gpsd:127.0.0.1:2947\",\"records\":6,\"evictions\":0,\"aged\":0,"
              "\"rejected\":0,\"sensor\":{\"ts\":1793059200,\"state\":\"fix\","
              "\"sats_in_view\":4,\"sats_used\":2,\"cn0_mean\":31.3,\"time_off_ms\":250,"
              "\"jam\":12},\"fix\":{\"ts\":1793059200,\"fix_ts\":1793059200,\"mode\":3,"
              "\"status\":2,\"nsat\":4,\"usat\":2,\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,"
              "\"lat\":51.50074,\"lon\":-0.12469,\"alt_m\":11.6,\"eph\":6.2,\"epv\":9.1,"
              "\"speed_mps\":0.30,\"track_deg\":12.5,\"time_off_ms\":250,\"leap\":18,"
              "\"jam\":12,\"tpv_count\":1},\"fixes\":1,\"sky\":{\"ts\":1793059200,"
              "\"sky_ts\":1793059200,\"nsat\":4,\"usat\":2,\"rows\":4,\"overflow\":0,"
              "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"gdop\":2.0,\"tdop\":0.9,"
              "\"cn0_mean\":31.3,\"cn0_max\":41.0,\"cn0_sd\":7.6,\"cn0_n\":3,\"passes\":1},"
              "\"total\":4,\"sats\":[{\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":5,\"prn\":5,"
              "\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":41.0,\"used\":1,\"health\":1,"
              "\"ts\":1793059200,\"first_ts\":1793059200,\"sky_ts\":1793059200,\"records\":1,"
              "\"points\":[[1793059200,41.0]]},{\"gnss\":\"GLONASS\"");
    const char *g1 = strstr(b, "\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":5");
    const char *g2 = strstr(b, "\"gnss\":\"GLONASS\"");
    const char *g3 = strstr(b, "\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":7");
    const char *g4 = strstr(b, "\"gnss\":\"SBAS\"");
    WT_ASSERT(g1 && g2 && g3 && g4 && g1 < g2 && g2 < g3 && g3 < g4);
    /* The emitter's -1 is null here, an el / az it did not write is
     * null (never -1: that is a real elevation), and an absent cn0 is
     * null with no point. */
    WT_HAS(b, "\"svid\":7,\"prn\":7,\"sigid\":null,\"el\":null,\"az\":null,\"cn0\":22.5");
    WT_HAS(b, "\"svid\":131,\"prn\":131,\"sigid\":null,\"el\":10,\"az\":200,\"cn0\":null,"
              "\"used\":0,\"health\":0,\"ts\":1793059200,\"first_ts\":1793059200,"
              "\"sky_ts\":1793059200,\"records\":1,\"points\":[]}");
    /* A later record of a row appends a point and keeps first_ts. */
    static char line[512];
    snprintf(line, sizeof(line), "%s", SAT5);
    char *p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059261", 15);
    p = strstr(line, "\"cn0\":41.0");
    memcpy(p, "\"cn0\":47.5", 10);
    feed(line);
    WT_EQ(route(&H, "/api/gnss", "limit=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total\":4,\"sats\":[{\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":5,\"prn\":5,"
              "\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":47.5,\"used\":1,\"health\":1,"
              "\"ts\":1793059261,\"first_ts\":1793059200,\"sky_ts\":1793059200,\"records\":2,"
              "\"points\":[[1793059200,41.0],[1793059261,47.5]]}]}");
    /* The health member. */
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"gnss\":{\"sats\":4,\"fixes\":1,\"records\":7,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* Nothing yet: nulls, not zeros. */
    fresh();
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"src\":\"\",\"records\":0,\"evictions\":0,\"aged\":0,\"rejected\":0,"
                           "\"sensor\":null,\"fix\":null,\"fixes\":0,\"sky\":null,\"total\":0,\"sats\":[]}");
    /* A sensor_health without the block (a sloth with no --gps) leaves
     * the sensor null. */
    feed("{\"type\":\"sensor_health\",\"ts\":1793059200,\"capture_iface\":\"any\","
         "\"gps_state\":\"fixed\",\"gps_src\":\"fixed\"}");
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":null");
}

/* Every figure is range checked and anything outside is absent, never
 * clamped; a constellation sloth does not name is "other"; a satellite
 * with no PRN and a fix with no mode are rejected and counted; the
 * query refusals never echo the value. */
static void test_gnss_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"?\",\"gnssid\":12,"
         "\"svid\":40000,\"prn\":9,\"sigid\":200,\"el\":95,\"az\":361,\"cn0\":150,"
         "\"used\":3,\"health\":7,\"sky_ts\":1793059200}");
    feed("{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
         "\"svid\":5,\"used\":1}");
    feed("{\"type\":\"gnss_fix\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\",\"mode\":7}");
    feed("{\"type\":\"gnss_fix\",\"ts\":1793059201,\"src\":\"g\\u0001psd\",\"mode\":2,"
         "\"lat\":91,\"lon\":0,\"eph\":-1,\"speed_mps\":1e9,\"time_off_ms\":5}");
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.gnss = &G;
    H.wall_s = T;
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"src\":\"\"");                       /* not printable ASCII */
    WT_HAS(b, "\"records\":4,\"evictions\":0,\"aged\":0,\"rejected\":2");
    WT_HAS(b, "\"fix\":{\"ts\":1793059201,\"fix_ts\":0,\"mode\":2,\"status\":null,\"nsat\":null,"
              "\"usat\":null,\"hdop\":null,\"vdop\":null,\"pdop\":null,\"lat\":null,\"lon\":null,"
              "\"alt_m\":null,\"eph\":null,\"epv\":null,\"speed_mps\":null,\"track_deg\":null,"
              "\"time_off_ms\":5,\"leap\":null,\"jam\":null,\"tpv_count\":0}");
    WT_HAS(b, "\"total\":1,\"sats\":[{\"gnss\":\"other\",\"gnssid\":8,\"svid\":null,\"prn\":9,"
              "\"sigid\":null,\"el\":null,\"az\":null,\"cn0\":null,\"used\":0,\"health\":null");
    /* A negative elevation is a satellite under the horizon that gpsd
     * still lists, kept as itself; -91 is out of range. Seen red with
     * sat_apply()'s el floor back at 0 (the -3 read null). */
    feed("{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
         "\"svid\":9,\"prn\":9,\"el\":-3,\"az\":0,\"used\":0,\"sky_ts\":1793059200}");
    feed("{\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
         "\"svid\":10,\"prn\":10,\"el\":-91,\"az\":-1,\"used\":0,\"sky_ts\":1793059200}");
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"svid\":9,\"prn\":9,\"sigid\":null,\"el\":-3,\"az\":0,");
    WT_HAS(b, "\"svid\":10,\"prn\":10,\"sigid\":null,\"el\":null,\"az\":null,");
    WT_EQ(route(&H, "/api/gnss", "limit=0"), 400);
    WT_HAS(body_of(g_out), "bad_limit");
    WT_EQ(route(&H, "/api/gnss", "limit=65"), 400);
    WT_EQ(route(&H, "/api/gnss", "sort=cn0"), 400);
    WT_EQ(route(&H, "/api/gnss/fixes", "since=x"), 400);
    WT_HAS(body_of(g_out), "bad_since");
    WT_LACKS(body_of(g_out), "since=x");
    WT_EQ(route(&H, "/api/gnss/fixes", "limit=129"), 400);
    /* No panel: 503 with a reason, as the BLE routes answer. */
    H.gnss = NULL;
    WT_EQ(route(&H, "/api/gnss", ""), 503);
}

/* WEB_GNSS_SATS rows, the least recently reported evicted and counted;
 * a row quiet past the TTL dropped and counted at the next record. */
static void test_gnss_eviction_and_age(void) {
    fresh();
    static char line[512];
    for (int i = 0; i < WEB_GNSS_SATS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"gnss_sat\",\"ts\":%lld,\"gnss\":\"GPS\",\"gnssid\":%d,"
                 "\"svid\":%d,\"prn\":%d,\"sigid\":-1,\"el\":10,\"az\":10,\"cn0\":%d.0,"
                 "\"used\":0,\"health\":1,\"sky_ts\":%lld}",
                 T + i, i % 8, i, i + 1, 20 + i % 30, T);
        feed(line);
    }
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.gnss = &G;
    H.wall_s = T + 100;
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,\"aged\":0");
    WT_HAS(b, "\"total\":64,");
    WT_LACKS(b, "\"prn\":1,");                 /* the oldest (ts T) is gone */
    WT_HAS(b, "\"prn\":65,");
    /* A gnss_sky far later ages every row out. */
    snprintf(line, sizeof(line), "%s", SKY);
    char *p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793060000", 15);        /* 800 s on: past the TTL */
    feed(line);
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,\"aged\":64");
    WT_HAS(b, "\"total\":0,\"sats\":[]");
}

/* The fix ring: WEB_GNSS_FIXES records, oldest overwritten; the fixes
 * route lists them oldest first after `since`, up to `limit`. */
static void test_gnss_fix_ring(void) {
    fresh();
    static char line[512];
    for (int i = 0; i < WEB_GNSS_FIXES + 8; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"gnss_fix\",\"ts\":%lld,\"src\":\"gpsd:127.0.0.1:2947\","
                 "\"fix_ts\":%lld,\"mode\":%d,\"status\":-1,\"nsat\":-1,\"usat\":%d,"
                 "\"hdop\":1.%d,\"vdop\":0,\"pdop\":0,\"leap\":-1,\"jam\":-1,\"tpv_count\":%d}",
                 T + i, T + i, 1 + i % 3, i % 12, i % 10, i + 1);
        feed(line);
    }
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.gnss = &G;
    H.wall_s = T + 1000;
    WT_EQ(route(&H, "/api/gnss/fixes", ""), 200);
    const char *b = body_of(g_out);
    /* A page: the oldest kept first, WEB_GNSS_LIMIT_MAX of them. */
    WT_HAS(b, "\"since\":0,\"total\":512,\"rows\":[{\"ts\":1793059208,");
    WT_HAS(b, "\"matched\":128}");
    WT_LACKS(b, "\"ts\":1793059207,");
    WT_HAS(b, "{\"ts\":1793059335,");
    WT_LACKS(b, "{\"ts\":1793059336,");
    /* The emitter's -1 / 0 read as null; the newest is the ring's last. */
    WT_EQ(route(&H, "/api/gnss/fixes", "since=1793059718"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"rows\":[{\"ts\":1793059719,\"fix_ts\":1793059719,\"mode\":1,\"status\":null,"
              "\"nsat\":null,\"usat\":3,\"hdop\":1.9,\"vdop\":null,\"pdop\":null");
    WT_HAS(b, "\"matched\":1}");
    WT_EQ(route(&H, "/api/gnss/fixes", "since=1793059717&limit=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total\":512,\"rows\":[{\"ts\":1793059718,");
    WT_HAS(b, "\"matched\":1}");
    WT_EQ(route(&H, "/api/gnss/fixes", "since=1793059719"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[],\"matched\":0}");
    /* /api/gnss reports the newest fix and the ring's size. */
    WT_EQ(route(&H, "/api/gnss", ""), 200);
    WT_HAS(body_of(g_out), "\"fix\":{\"ts\":1793059719,");
    WT_HAS(body_of(g_out), "\"fixes\":512,");
}

/* The receiver is the host's own: the records are META (sloth's own
 * state), listed as poll-thread types, and the routes answer under
 * Local as under Monitor, with no out_of_scope body. */
static void test_gnss_every_scope(void) {
    fresh();
    seed();
    WT_EQ(web_scope_record("gnss_fix"), WEB_SC_META);
    WT_EQ(web_scope_record("gnss_sky"), WEB_SC_META);
    WT_EQ(web_scope_record("gnss_sat"), WEB_SC_META);
    WT_ASSERT(web_live_is_poll_type("gnss_fix"));
    WT_ASSERT(web_live_is_poll_type("gnss_sky"));
    WT_ASSERT(web_live_is_poll_type("gnss_sat"));
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.gnss = &G;
    H.wall_s = T;
    static const char *const scopes[] = { "scope=local", "scope=monitor", "scope=hybrid" };
    for (size_t i = 0; i < 3; i++) {
        WT_EQ(route(&H, "/api/gnss", scopes[i]), 200);
        const char *b = body_of(g_out);
        WT_HAS(b, "\"scope_note\":\"every scope: the host's own receiver\"");
        WT_HAS(b, "\"total\":4,");
        WT_LACKS(b, "out_of_scope");
        WT_EQ(route(&H, "/api/gnss/fixes", scopes[i]), 200);
        WT_HAS(body_of(g_out), "\"matched\":1}");
    }
}

/* The four global gauges, sampled from the change-only records only
 * when the record carries a figure in range. */
static long long g_clock = T;
static long long clock_fn(void *ctx) { (void)ctx; return g_clock; }

static void test_gnss_metrics(void) {
    web_rollup_t ru;
    web_metrics_t m;
    char err[128];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    WT_EQ(web_jl_parse(FIX, strlen(FIX), &R), WEB_JL_OK);
    web_metrics_record(&m, &R);
    WT_EQ(web_jl_parse(SKY, strlen(SKY), &R), WEB_JL_OK);
    web_metrics_record(&m, &R);
    WT_ASSERT(web_rollup_has(&ru, WM_GNSS_SATS_USED, ""));
    WT_ASSERT(web_rollup_has(&ru, WM_GNSS_HDOP, ""));
    WT_ASSERT(web_rollup_has(&ru, WM_GNSS_TIME_OFF_MS, ""));
    WT_ASSERT(web_rollup_has(&ru, WM_GNSS_CN0_MEAN, ""));
    WT_ASSERT(!strcmp(web_metric_defs[WM_GNSS_SATS_USED].name, "gnss.sats_used"));
    WT_ASSERT(!strcmp(web_metric_defs[WM_GNSS_HDOP].name, "gnss.hdop"));
    WT_ASSERT(!strcmp(web_metric_defs[WM_GNSS_TIME_OFF_MS].name, "gnss.time_off_ms"));
    WT_ASSERT(!strcmp(web_metric_defs[WM_GNSS_CN0_MEAN].name, "gnss.cn0_mean"));
    WT_EQ(web_metric_defs[WM_GNSS_HDOP].kclass, WEB_KC_GLOBAL);
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);
    /* A fix with no sky yet (usat -1, hdop 0) and no time: nothing
     * sampled. Seen red with the usat >= 0 test removed (a -1 sample). */
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    static const char bare[] =
        "{\"type\":\"gnss_fix\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\","
        "\"fix_ts\":1793059200,\"mode\":1,\"status\":-1,\"nsat\":-1,\"usat\":-1,"
        "\"hdop\":0,\"vdop\":0,\"pdop\":0,\"leap\":-1,\"jam\":-1,\"tpv_count\":1}";
    WT_EQ(web_jl_parse(bare, strlen(bare), &R), WEB_JL_OK);
    web_metrics_record(&m, &R);
    WT_ASSERT(!web_rollup_has(&ru, WM_GNSS_SATS_USED, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_GNSS_HDOP, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_GNSS_TIME_OFF_MS, ""));
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);
}

/* The constellation names are sloth's (src/gps.c gnss_name()). */
static void test_gnss_names_are_sloths(void) {
    FILE *f = fopen("src/gps.c", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char src[1 << 17];
    size_t n = fread(src, 1, sizeof(src) - 1, f);
    src[n] = '\0';
    fclose(f);
    for (int i = 0; i <= 7; i++) {
        char lit[32];
        snprintf(lit, sizeof(lit), "case %d: return \"%s\";", i, web_gnss_name(i));
        if (!strstr(src, lit)) fprintf(stderr, "    src/gps.c lacks %s\n", lit);
        WT_ASSERT(strstr(src, lit) != NULL);
    }
    WT_ASSERT(!strcmp(web_gnss_name(8), "other"));
    WT_ASSERT(!strcmp(web_gnss_name(-1), "?"));
}

/* The page's half (the pattern test_ble.c::test_page uses): the
 * satellites table is app.js's one DataTable, not a hand-rolled
 * <table>; the fix strip walks /api/gnss/fixes with since= from the
 * last row's ts while a page comes back full, so it reaches the newest
 * record once the 512-entry ring holds more than one 128-row page (a
 * single request showed the oldest 128 for ever). The route's own
 * paging is test_gnss_fix_ring's. */
static void test_gnss_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "    T = window.SlothTables.make({ id: \"gnss\", label: \"satellites in view\", box: $(\"gnss-box\"),\n"
              "      head: $(\"gnss-thead\"), reset: $(\"gnss-tools\"), redraw: drawRows, cols: COLS });");
    WT_HAS(p, "<div class=\"hscroll\" id=\"gnss-box\"><div class=\"gnssrow dhead\" id=\"gnss-thead\"></div><div id=\"gnss-rows\"></div></div>");
    WT_HAS(p, "<span class=\"dt-tools\" id=\"gnss-tools\"></span>");
    WT_LACKS(p, "class=\"gnss-table\"");
    WT_LACKS(p, ".gnss-table th");
    /* The row: bright in the solution, dim unhealthy, the TUI's. */
    WT_HAS(p, "    var cls = s.health === 2 ? \"d-dim\" : s.used ? \"d-bright\" : \"d-normal\";\n"
              "    var r = el(\"div\", \"gnssrow dt-row \" + cls + (on ? \" on\" : \"\"));");
    WT_HAS(p, "    var ordered = t ? t.sort(rows, true) : rows.slice();");
    /* The walk. */
    WT_HAS(p, "  var FIX_PAGE = 128, FIX_PAGES = 8;");
    WT_HAS(p, "    return getJSON(\"/api/gnss/fixes?since=\" + since).then(function (f) {");
    WT_HAS(p, "      if (got.length >= FIX_PAGE && pages + 1 < FIX_PAGES && num(lastTs) && lastTs > since)\n"
              "        return fixes(lastTs, acc, pages + 1);");
    WT_HAS(p, "      return fixes(0, [], 0).then(function (f) {");
    WT_LACKS(p, "getJSON(\"/api/gnss/fixes\")");
}

/* The tab's label (owner request 2026-11-02, "a GPS Sat and BLE Devices
 * tab"): the words changed, the id and the view did not. */
static void test_gnss_tab_label(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-gnss\">GPS Sat</button></li>");
    WT_LACKS(p, "id=\"nav-gnss\">GNSS</button>");
    WT_HAS(p, "  $(\"nav-gnss\").addEventListener(\"click\", function () { show(\"gnss\"); });");
    WT_HAS(p, "<div id=\"v-gnss\" hidden>");
}

void run_gnss_tests(void) {
    WT_RUN(test_gnss_tab_label);
    WT_RUN(test_gnss_ingest_and_route);
    WT_RUN(test_gnss_ranges_and_refusals);
    WT_RUN(test_gnss_eviction_and_age);
    WT_RUN(test_gnss_fix_ring);
    WT_RUN(test_gnss_every_scope);
    WT_RUN(test_gnss_metrics);
    WT_RUN(test_gnss_names_are_sloths);
    WT_RUN(test_gnss_page);
    WT_RUN(test_gnss_tab_label);
    web_gnss_destroy(&G);
}
