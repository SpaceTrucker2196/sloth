/* The sensor's host status (web_sysstat.h): sloth's four records, in
 * the shape src/sys_status.c writes them (the lines below are the ones
 * tests/test_sys_status.c asserts sloth writes), kept by slothweb,
 * answered by /api/sys under every scope, sampled into the eight
 * series; and the page's half, the words a series is given (the trend
 * and the up/down strip), as a C port of syshealth.js's pure functions
 * with the JS pinned verbatim out of the served page, the way
 * test_glyph.c holds glyph.js.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored (the mutation is named at the assertion). */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_sysstat.h"
#include "wtest.h"

#define T 1800000060LL

static web_sys_t Y;
static web_jrec_t R;

/* slothweb's monotonic clock when the records arrive: nothing like
 * the wall clock, as on a real host (milliseconds since boot). */
#define MONO0 777000LL

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_sys_record(&Y, &R, MONO0);
}

static void fresh(void) {
    web_sys_destroy(&Y);
    WT_EQ(web_sys_init(&Y), 0);
}

static const char STATUS[] =
    "{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":2,\"interval_s\":60,\"cpu_pct\":15.0,"
    "\"cpu_iowait_pct\":10.0,\"cpu_band\":\"low\",\"load1\":0.20,\"load5\":0.18,\"load15\":0.12,"
    "\"mem_total_kb\":3884328,\"mem_avail_kb\":2913246,\"mem_band\":\"ok\",\"uptime_s\":350735,"
    "\"rss_kb\":12276,\"disk_for\":\"db\",\"disk_free_mb\":21840,\"disk_total_mb\":29500,"
    "\"disk_band\":\"ok\",\"temps\":2,\"temp_max_c\":51.0,\"temp_max_id\":\"hwmon3/temp1\","
    "\"temp_band\":\"ok\",\"volts\":2,\"undervolt\":0,\"power\":1,\"sources\":7,"
    "\"sources_configured\":2,\"sources_ok\":1,\"sources_down\":0,\"receivers\":2}";
static const char TEMP0[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"temp\","
    "\"id\":\"thermal_zone0\",\"label\":\"cpu-thermal\",\"c\":48.3}";
static const char TEMP1[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"temp\","
    "\"id\":\"hwmon3/temp1\",\"label\":\"rp1_adc\",\"c\":51.0}";
static const char VOLT_ALARM[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"volt\","
    "\"id\":\"hwmon1/in0\",\"label\":\"rpi_volt\",\"alarm\":0}";
static const char VOLT1[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"volt\","
    "\"id\":\"hwmon3/in1\",\"label\":\"rp1_adc VBUS\",\"v\":5.103}";
static const char BAT[] =
    "{\"type\":\"sys_sensor\",\"ts\":1800000060,\"seq\":2,\"class\":\"power\",\"id\":\"BAT0\","
    "\"label\":\"Battery\",\"v\":12.011,\"capacity\":87,\"status\":\"Discharging\"}";
static const char SRC_MON[] =
    "{\"type\":\"source_status\",\"ts\":1800000060,\"seq\":2,\"name\":\"monitor\","
    "\"kind\":\"wifi-monitor\",\"flag\":\"a monitor-mode interface\",\"state\":\"ok\","
    "\"detail\":\"\",\"endpoint\":\"wlan1mon\",\"hw\":\"usb:1-1.4\","
    "\"desc\":\"Realtek RTL8812AU 802.11ac\",\"driver\":\"rtl88XXau\",\"age_s\":0,"
    "\"age_band\":\"fresh\",\"unit\":\"frames\",\"count\":184220,\"rate\":51.30,\"errors\":0}";
static const char SRC_GNSS[] =
    "{\"type\":\"source_status\",\"ts\":1800000060,\"seq\":2,\"name\":\"gnss\",\"kind\":\"gnss\","
    "\"flag\":\"--gps\",\"state\":\"stale\",\"detail\":\"searching\","
    "\"endpoint\":\"gpsd:127.0.0.1:2947\",\"age_s\":75,\"age_band\":\"stale\","
    "\"unit\":\"sentences\",\"count\":40,\"errors\":2,\"reconnects\":3}";
static const char SRC_APRS[] =
    "{\"type\":\"source_status\",\"ts\":1800000060,\"seq\":2,\"name\":\"aprs\",\"kind\":\"aprs\","
    "\"flag\":\"--aprs\",\"state\":\"not_configured\",\"detail\":\"\",\"endpoint\":\"\"}";
static const char HW_SDR[] =
    "{\"type\":\"receiver_hw\",\"ts\":1800000060,\"seq\":2,\"key\":\"usb:1-1.2\",\"kind\":\"sdr\","
    "\"bus\":\"usb\",\"id\":\"0bda:2838\",\"known\":1,"
    "\"desc\":\"Realtek RTL2838 DVB-T (RTL-SDR)\",\"vendor\":\"Realtek\","
    "\"product\":\"RTL2838UHIDIR\",\"driver\":\"dvb_usb_rtl28xxu\",\"ifaces\":\"\"}";
static const char HW_WLAN[] =
    "{\"type\":\"receiver_hw\",\"ts\":1800000060,\"seq\":2,\"key\":\"net:wlan0\",\"kind\":\"wifi\","
    "\"bus\":\"sdio\",\"id\":\"02d0:a9a6\",\"known\":0,\"desc\":\"\",\"vendor\":\"\","
    "\"product\":\"\",\"driver\":\"brcmfmac\",\"ifaces\":\"wlan0\"}";

static void seed(void) {
    feed(STATUS);
    feed(TEMP0); feed(TEMP1); feed(VOLT_ALARM); feed(VOLT1); feed(BAT);
    feed(SRC_MON); feed(SRC_GNSS); feed(SRC_APRS);
    feed(HW_SDR); feed(HW_WLAN);
}

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

/* A request at wall-clock `now`, the records having arrived at T + 1. */
static void health(web_health_t *h, long long now) {
    memset(h, 0, sizeof(*h));
    h->sys = &Y;
    h->wall_s = now;
    h->now_ms = MONO0 + (now - (T + 1)) * 1000;
}

/* ── keys and kept strings ───────────────────────────────────────── */

static void test_sys_key(void) {
    char k[WEB_KEY_MAX + 1];
    WT_EQ(web_key_sys("hwmon1/temp2", k), 0);
    WT_ASSERT(!strcmp(k, "hwmon1.temp2"));
    WT_EQ(web_key_sys("BAT0", k), 0);
    WT_ASSERT(!strcmp(k, "bat0"));
    WT_EQ(web_key_sys("thermal_zone0", k), 0);
    WT_EQ(web_key_sys("capture", k), 0);
    WT_ASSERT(web_key_sys("", k) != 0);
    WT_ASSERT(web_key_sys(NULL, k) != 0);
    WT_ASSERT(web_key_sys("a b", k) != 0);
    WT_ASSERT(web_key_sys("x<y", k) != 0);
    WT_ASSERT(web_key_sys("caf\xc3\xa9", k) != 0);
    WT_ASSERT(web_key_sys("0123456789012345678901234567890123456789012345678", k) != 0);
    /* Through the route's canonicaliser: a keyed metric takes the kind,
     * a global one no key at all. */
    WT_EQ(web_key_canon(WM_SYS_TEMP, "Hwmon1/Temp2", k), 0);
    WT_ASSERT(!strcmp(k, "hwmon1.temp2"));
    WT_EQ(web_key_canon(WM_SRC_UP, "monitor", k), 0);
    WT_ASSERT(web_key_canon(WM_SYS_CPU, "x", k) != 0);
    WT_ASSERT(web_key_canon(WM_SYS_VOLT, "", k) != 0);
    WT_ASSERT(!strcmp(web_kclass_name(WEB_KC_SYS), "sys"));
    WT_EQ(web_metric_defs[WM_SYS_CPU].kclass, WEB_KC_GLOBAL);
    WT_EQ(web_metric_defs[WM_SYS_TEMP].kclass, WEB_KC_SYS);
    WT_EQ(web_metric_defs[WM_SRC_UP].kclass, WEB_KC_SYS);
    WT_EQ(web_metric_find("sys.cpu"), WM_SYS_CPU);
    WT_EQ(web_metric_find("sys.mem_used"), WM_SYS_MEM_USED);
    WT_EQ(web_metric_find("sys.rss"), WM_SYS_RSS);
    WT_EQ(web_metric_find("sys.undervolt"), WM_SYS_UNDERVOLT);
    WT_EQ(web_metric_find("sys.temp"), WM_SYS_TEMP);
    WT_EQ(web_metric_find("sys.volt"), WM_SYS_VOLT);
    WT_EQ(web_metric_find("source.rate"), WM_SRC_RATE);
    WT_EQ(web_metric_find("source.up"), WM_SRC_UP);
}

/* A kept string is bounded by what it costs to write, not by its
 * length: thirty '<' are 180 bytes of JSON. */
static void test_sys_keep(void) {
    char o[13];
    web_sys_keep(o, sizeof(o), "abc");
    WT_ASSERT(!strcmp(o, "abc"));
    web_sys_keep(o, sizeof(o), "0123456789abcdef");
    WT_ASSERT(!strcmp(o, "0123456789ab"));
    web_sys_keep(o, sizeof(o), "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
    WT_ASSERT(!strcmp(o, "<<"));                    /* 2 x 6 of a budget of 12 */
    web_sys_keep(o, sizeof(o), "\"\"\"\"\"\"\"\"\"\"");
    WT_ASSERT(!strcmp(o, "\"\"\"\"\"\""));          /* 6 x 2 */
    web_sys_keep(o, sizeof(o), "a<b");
    WT_ASSERT(!strcmp(o, "a<b"));
    /* Never half a UTF-8 sequence. */
    web_sys_keep(o, sizeof(o), "\xc3\xa9\xc3\xa9");
    WT_ASSERT(!strcmp(o, "\xc3\xa9"));
    char s[8];
    web_sys_keep(s, sizeof(s), "\xc3\xa9");         /* 12 does not fit 7 */
    WT_ASSERT(!strcmp(s, ""));
    web_sys_keep(o, sizeof(o), NULL);
    WT_ASSERT(!strcmp(o, ""));
}

/* ── ingest and /api/sys ─────────────────────────────────────────── */

/* Before any record, and with no live stream at all (slothweb reading
 * a copied sloth.db): the answer says so, and carries no figure. */
static void test_sys_nothing_yet(void) {
    fresh();
    web_health_t H;
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1800000065,\"scope_note\":\"every scope: sloth's own state\",\"seen\":false,"
              "\"ts\":null,\"age_s\":null,\"seq\":null,\"interval_s\":null,\"stale\":false,"
              "\"system\":null,\"sensors\":[],\"sources\":[],\"receivers\":[],"
              "\"records\":0,\"rejected\":0,\"overflow\":0}");
    /* No module at all is a 503, not an empty answer. */
    H.sys = NULL;
    WT_EQ(route(&H, "/api/sys", ""), 503);
    WT_HAS(body_of(g_out), "no_sys");
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", "limit=3"), 400);
    WT_HAS(body_of(g_out), "unknown_parameter");
}

static void test_sys_ingest_and_route(void) {
    fresh();
    seed();
    web_health_t H;
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"seen\":true,\"ts\":1800000060,\"age_s\":4,\"seq\":2,\"interval_s\":60,"
              "\"stale\":false,\"system\":{\"cpu_pct\":15.0,\"cpu_iowait_pct\":10.0,"
              "\"cpu_band\":\"low\",\"load1\":0.20,\"load5\":0.18,\"load15\":0.12,"
              "\"mem_total_kb\":3884328,\"mem_avail_kb\":2913246,\"mem_band\":\"ok\","
              "\"uptime_s\":350735,\"rss_kb\":12276,\"disk_for\":\"db\",\"disk_free_mb\":21840,"
              "\"disk_total_mb\":29500,\"disk_band\":\"ok\",\"temp_max_c\":51.0,"
              "\"temp_max_id\":\"hwmon3/temp1\",\"temp_band\":\"ok\",\"undervolt\":0}");
    WT_HAS(b, "\"sensors\":[{\"class\":\"temp\",\"id\":\"thermal_zone0\",\"key\":\"thermal_zone0\","
              "\"label\":\"cpu-thermal\",\"c\":48.3,\"alarm\":null,\"capacity\":null,\"status\":null},");
    WT_HAS(b, "{\"class\":\"temp\",\"id\":\"hwmon3/temp1\",\"key\":\"hwmon3.temp1\",");
    /* An alarm with no reading: v is null, not 0.000. */
    WT_HAS(b, "{\"class\":\"volt\",\"id\":\"hwmon1/in0\",\"key\":\"hwmon1.in0\",\"label\":\"rpi_volt\","
              "\"v\":null,\"alarm\":0,\"capacity\":null,\"status\":null}");
    WT_HAS(b, "{\"class\":\"power\",\"id\":\"BAT0\",\"key\":\"bat0\",\"label\":\"Battery\","
              "\"v\":12.011,\"alarm\":null,\"capacity\":87,\"status\":\"Discharging\"}]");
    WT_HAS(b, "\"sources\":[{\"name\":\"monitor\",\"kind\":\"wifi-monitor\","
              "\"flag\":\"a monitor-mode interface\",\"state\":\"ok\",\"detail\":null,"
              "\"endpoint\":\"wlan1mon\",\"hw\":\"usb:1-1.4\","
              "\"desc\":\"Realtek RTL8812AU 802.11ac\",\"driver\":\"rtl88XXau\",\"age_s\":0,"
              "\"age_band\":\"fresh\",\"unit\":\"frames\",\"count\":184220,\"rate\":51.30,"
              "\"errors\":0,\"reconnects\":null,\"ts\":1800000060,\"report_age_s\":4},");
    /* A source with no receiver tied and no rate yet: null, never a
     * guess and never 0.00. */
    WT_HAS(b, "{\"name\":\"gnss\",\"kind\":\"gnss\",\"flag\":\"--gps\",\"state\":\"stale\","
              "\"detail\":\"searching\",\"endpoint\":\"gpsd:127.0.0.1:2947\",\"hw\":null,"
              "\"desc\":null,\"driver\":null,\"age_s\":75,\"age_band\":\"stale\","
              "\"unit\":\"sentences\",\"count\":40,\"rate\":null,\"errors\":2,\"reconnects\":3,");
    /* Not configured is listed, with nothing measured. */
    WT_HAS(b, "{\"name\":\"aprs\",\"kind\":\"aprs\",\"flag\":\"--aprs\",\"state\":\"not_configured\","
              "\"detail\":null,\"endpoint\":null,\"hw\":null,\"desc\":null,\"driver\":null,"
              "\"age_s\":null,\"age_band\":null,\"unit\":null,\"count\":null,\"rate\":null,"
              "\"errors\":null,\"reconnects\":null,");
    WT_HAS(b, "\"receivers\":[{\"key\":\"usb:1-1.2\",\"kind\":\"sdr\",\"bus\":\"usb\","
              "\"id\":\"0bda:2838\",\"known\":1,\"desc\":\"Realtek RTL2838 DVB-T (RTL-SDR)\","
              "\"vendor\":\"Realtek\",\"product\":\"RTL2838UHIDIR\","
              "\"driver\":\"dvb_usb_rtl28xxu\",\"ifaces\":null},"
              "{\"key\":\"net:wlan0\",\"kind\":\"wifi\",\"bus\":\"sdio\",\"id\":\"02d0:a9a6\","
              "\"known\":0,\"desc\":null,\"vendor\":null,\"product\":null,"
              "\"driver\":\"brcmfmac\",\"ifaces\":\"wlan0\"}],"
              "\"records\":11,\"rejected\":0,\"overflow\":0}");
}

/* A host with neither /proc nor /sys reports no figure, and slothweb
 * shows none: null, which the page words "not reported by this host".
 * Seen red with status_apply()'s has_cpu forced to 1 (a 0.0 % CPU
 * nobody measured). */
static void test_sys_absent_is_null(void) {
    fresh();
    feed("{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":1,\"interval_s\":60,\"temps\":0,"
         "\"volts\":0,\"power\":0,\"sources\":7,\"sources_configured\":0,\"sources_ok\":0,"
         "\"sources_down\":0,\"receivers\":0}");
    web_health_t H;
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out),
           "\"system\":{\"cpu_pct\":null,\"cpu_iowait_pct\":null,\"cpu_band\":null,"
           "\"load1\":null,\"load5\":null,\"load15\":null,\"mem_total_kb\":null,"
           "\"mem_avail_kb\":null,\"mem_band\":null,\"uptime_s\":null,\"rss_kb\":null,"
           "\"disk_for\":null,\"disk_free_mb\":null,\"disk_total_mb\":null,\"disk_band\":null,"
           "\"temp_max_c\":null,\"temp_max_id\":null,\"temp_band\":null,\"undervolt\":null},"
           "\"sensors\":[],\"sources\":[],\"receivers\":[]");
}

/* A sensor or receiver that is not in the newest batch is gone; a
 * source's row is updated in place, between batches too. */
static void test_sys_batch_replaces(void) {
    fresh();
    seed();
    web_health_t H;
    health(&H, T + 70);
    /* Batch 3: one temperature left, no receivers. */
    feed("{\"type\":\"sys_status\",\"ts\":1800000120,\"seq\":3,\"interval_s\":60,\"temps\":1,"
         "\"temp_max_c\":49.0,\"temp_max_id\":\"thermal_zone0\",\"temp_band\":\"ok\",\"volts\":0,"
         "\"power\":0,\"sources\":7,\"receivers\":0}");
    WT_EQ(route(&H, "/api/sys", ""), 200);
    /* Until its first row arrives the last batch's sensors still show;
     * the receivers, which this batch says it has none of, do not.
     * Seen red with status_apply()'s receivers == 0 clear removed. */
    WT_HAS(body_of(g_out), "\"receivers\":[],");
    WT_HAS(body_of(g_out), "\"id\":\"BAT0\"");
    feed("{\"type\":\"sys_sensor\",\"ts\":1800000120,\"seq\":3,\"class\":\"temp\","
         "\"id\":\"thermal_zone0\",\"label\":\"cpu-thermal\",\"c\":49.0}");
    WT_EQ(route(&H, "/api/sys", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"sensors\":[{\"class\":\"temp\",\"id\":\"thermal_zone0\",\"key\":\"thermal_zone0\","
              "\"label\":\"cpu-thermal\",\"c\":49.0,\"alarm\":null,\"capacity\":null,"
              "\"status\":null}],");
    /* Seen red with sensor_apply()'s seq != sensor_seq clear removed. */
    WT_LACKS(b, "\"id\":\"BAT0\"");
    WT_LACKS(b, "hwmon3");
    /* The sources are still there, and one changes on its own. */
    WT_HAS(b, "\"name\":\"monitor\"");
    feed("{\"type\":\"source_status\",\"ts\":1800000125,\"seq\":3,\"name\":\"monitor\","
         "\"kind\":\"wifi-monitor\",\"flag\":\"a monitor-mode interface\",\"state\":\"down\","
         "\"detail\":\"exit: iface_gone: No such device\",\"endpoint\":\"wlan1mon\",\"age_s\":5,"
         "\"age_band\":\"fresh\",\"unit\":\"frames\",\"count\":184300,\"rate\":16.00,\"errors\":0}");
    WT_EQ(route(&H, "/api/sys", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"name\":\"monitor\",\"kind\":\"wifi-monitor\",\"flag\":\"a monitor-mode interface\","
              "\"state\":\"down\",\"detail\":\"exit: iface_gone: No such device\","
              "\"endpoint\":\"wlan1mon\",\"hw\":null,");
    WT_HAS(b, "\"name\":\"gnss\"");
    /* A batch that says it has no sensors clears them without a row. */
    feed("{\"type\":\"sys_status\",\"ts\":1800000180,\"seq\":4,\"interval_s\":60,\"temps\":0,"
         "\"volts\":0,\"power\":0,\"sources\":7,\"receivers\":0}");
    WT_EQ(route(&H, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"sensors\":[],");
}

/* A sensor that stopped reporting shows its age, and the answer says
 * stale past three of its own intervals. The age is slothweb's
 * monotonic clock against itself: seen red (an age of 57 years, stale
 * from the first second) with the route subtracting the arrival's
 * monotonic reading from the wall clock, which is what the first run
 * against a real sloth showed. */
static void test_sys_stale(void) {
    fresh();
    seed();
    web_health_t H;
    health(&H, T + 1 + 180);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"age_s\":180,\"seq\":2,\"interval_s\":60,\"stale\":false,");
    health(&H, T + 1 + 181);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"age_s\":181,\"seq\":2,\"interval_s\":60,\"stale\":true,");
    WT_HAS(body_of(g_out), "\"report_age_s\":181}");
}

/* sloth's own state: META, poll-thread types, and the same answer
 * under every scope. */
static void test_sys_every_scope(void) {
    fresh();
    seed();
    static const char *const types[] = { "sys_status", "sys_sensor", "source_status",
                                         "receiver_hw" };
    for (size_t i = 0; i < 4; i++) {
        WT_EQ(web_scope_record(types[i]), WEB_SC_META);
        WT_ASSERT(web_live_is_poll_type(types[i]));
    }
    for (int m = WM_SYS_CPU; m <= WM_SRC_UP; m++) WT_EQ(web_scope_metric(m), 0);
    web_health_t H;
    health(&H, T + 5);
    static const char *const scopes[] = { "scope=local", "scope=monitor", "scope=hybrid" };
    for (size_t i = 0; i < 3; i++) {
        WT_EQ(route(&H, "/api/sys", scopes[i]), 200);
        WT_HAS(body_of(g_out), "\"scope_note\":\"every scope: sloth's own state\",\"seen\":true,");
        /* The scoped answer's own "scope" member, once: a second one
         * of this route's would be a duplicate key. Seen red with the
         * note named "scope". */
        if (i < 2) {
            const char *a = strstr(body_of(g_out), "\"scope\":");
            WT_ASSERT(a != NULL && strstr(a + 1, "\"scope\":") == NULL);
        }
        WT_HAS(body_of(g_out), "\"name\":\"monitor\"");
        WT_LACKS(body_of(g_out), "out_of_scope");
    }
}

/* The socket may be someone else's: refusals, ranges, and the bounds. */
static void test_sys_hostile(void) {
    fresh();
    /* No seq, an unknown class, an empty id, a name that is not a
     * word, a state that is not one of the four, a receiver with no
     * key: each refused whole. */
    feed("{\"type\":\"sys_status\",\"ts\":1,\"interval_s\":60}");
    feed("{\"type\":\"sys_status\",\"ts\":1,\"seq\":-4}");
    feed("{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"fan\",\"id\":\"x\",\"c\":1.0}");
    feed("{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"temp\",\"id\":\"\",\"c\":1.0}");
    feed("{\"type\":\"source_status\",\"ts\":1,\"seq\":1,\"name\":\"<b>\",\"state\":\"ok\"}");
    feed("{\"type\":\"source_status\",\"ts\":1,\"seq\":1,\"name\":\"adsb\",\"state\":\"great\"}");
    feed("{\"type\":\"receiver_hw\",\"ts\":1,\"seq\":1,\"kind\":\"sdr\"}");
    WT_EQ((int)Y.rejected, 7);
    WT_EQ(Y.seen, 0);
    /* Figures out of range are not figures. */
    feed("{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":1,\"cpu_pct\":250.0,"
         "\"mem_total_kb\":100,\"mem_avail_kb\":900,\"temp_max_c\":9999.0,\"undervolt\":7,"
         "\"uptime_s\":-5,\"rss_kb\":-1,\"disk_free_mb\":50,\"disk_total_mb\":10}");
    feed("{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"temp\",\"id\":\"z\",\"c\":-500.0}");
    feed("{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"power\",\"id\":\"b\","
         "\"capacity\":250,\"v\":1e9}");
    web_health_t H;
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"cpu_pct\":null,");
    WT_HAS(b, "\"mem_total_kb\":null,\"mem_avail_kb\":null,");
    WT_HAS(b, "\"uptime_s\":null,\"rss_kb\":null,");
    WT_HAS(b, "\"disk_free_mb\":null,\"disk_total_mb\":null,");
    WT_HAS(b, "\"temp_max_c\":null,");
    WT_HAS(b, "\"undervolt\":null}");
    WT_HAS(b, "{\"class\":\"temp\",\"id\":\"z\",\"key\":\"z\",\"label\":null,\"c\":null,");
    WT_HAS(b, "{\"class\":\"power\",\"id\":\"b\",\"key\":\"b\",\"label\":null,\"v\":null,"
              "\"alarm\":null,\"capacity\":null,");
    /* Markup in a device string reaches the page escaped. */
    feed("{\"type\":\"receiver_hw\",\"ts\":1,\"seq\":1,\"key\":\"usb:9-9\",\"kind\":\"sdr\","
         "\"product\":\"<img src=x onerror=alert(1)>\"}");
    WT_EQ(route(&H, "/api/sys", ""), 200);
    WT_HAS(body_of(g_out), "\"product\":\"\\u003cimg src=x onerror=alert(1)\\u003e\"");
    WT_LACKS(body_of(g_out), "<img");

    /* Every slot full of the costliest strings the decoder lets
     * through: the tables hold their caps and count the rest, and the
     * answer still fits the connection's buffer. */
    fresh();
    char lt[101], line[2048];
    memset(lt, '<', sizeof(lt) - 1);
    lt[sizeof(lt) - 1] = '\0';
    feed("{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":9,\"interval_s\":60,\"temps\":40,"
         "\"volts\":0,\"power\":0,\"receivers\":20}");
    for (int i = 0; i < WEB_SYS_SENSORS + 4; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":9,"
                 "\"class\":\"power\",\"id\":\"s%d\",\"label\":\"%s\",\"status\":\"%s\","
                 "\"v\":-99.999,\"capacity\":100}", i, lt, lt);
        feed(line);
    }
    static const char *const names[] = { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j" };
    for (int i = 0; i < WEB_SYS_SOURCES + 2; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"source_status\",\"ts\":1800000060,\"seq\":9,"
                 "\"name\":\"%s\",\"kind\":\"%s\",\"flag\":\"%s\",\"state\":\"not_configured\","
                 "\"detail\":\"%s\",\"endpoint\":\"%s\",\"hw\":\"%s\",\"desc\":\"%s\","
                 "\"driver\":\"%s\",\"age_band\":\"%s\",\"unit\":\"%s\",\"age_s\":1099511627776,"
                 "\"count\":4611686018427387904,\"errors\":4611686018427387904,"
                 "\"rate\":999999999.99,\"reconnects\":4611686018427387904}",
                 names[i], lt, lt, lt, lt, lt, lt, lt, lt, lt);
        feed(line);
    }
    for (int i = 0; i < WEB_SYS_HW + 3; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"receiver_hw\",\"ts\":1,\"seq\":9,"
                 "\"key\":\"k%d\",\"kind\":\"%s\",\"bus\":\"%s\",\"id\":\"%s\",\"known\":1,"
                 "\"desc\":\"%s\",\"vendor\":\"%s\",\"product\":\"%s\",\"driver\":\"%s\","
                 "\"ifaces\":\"%s\"}", i, lt, lt, lt, lt, lt, lt, lt, lt);
        feed(line);
    }
    WT_EQ((int)Y.overflow, 4 + 2 + 3);
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/sys", ""), 200);
    size_t bl = strlen(body_of(g_out));
    fprintf(stderr, "    /api/sys worst case: %zu bytes of body (the buffer holds %d)\n",
            bl, 65536 - WEB_LIVE_HDR_RESERVE);
    WT_ASSERT(bl > 12000 && bl < 65536 - WEB_LIVE_HDR_RESERVE);
    WT_HAS(body_of(g_out), "\"overflow\":9}");
}

/* ── the series ──────────────────────────────────────────────────── */

static long long g_clock = T;
static long long clock_fn(void *ctx) { (void)ctx; return g_clock; }

/* The newest fine bucket of (metric, key), open one included. */
static int point(web_rollup_t *ru, int metric, const char *key, web_point_t *p) {
    int more = 0;
    return web_rollup_fine(ru, metric, key, T - 3600, T + 3600, 1, p, 1, &more);
}

static void mrec(web_metrics_t *m, const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_metrics_record(m, &R);
}

static void test_sys_metrics(void) {
    web_rollup_t ru;
    web_metrics_t m;
    web_point_t p;
    char err[128];
    g_clock = T;
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    mrec(&m, STATUS);
    mrec(&m, TEMP0); mrec(&m, TEMP1); mrec(&m, VOLT_ALARM); mrec(&m, VOLT1); mrec(&m, BAT);
    mrec(&m, SRC_MON); mrec(&m, SRC_GNSS); mrec(&m, SRC_APRS);
    mrec(&m, HW_SDR);
    WT_EQ(point(&ru, WM_SYS_CPU, "", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_CPU, &p) - 15.0) < 1e-9);
    WT_EQ(point(&ru, WM_SYS_MEM_USED, "", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_MEM_USED, &p) -
                   (100.0 - 100.0 * 2913246.0 / 3884328.0)) < 1e-9);
    WT_EQ(point(&ru, WM_SYS_RSS, "", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_RSS, &p) - 12276.0) < 1e-9);
    WT_EQ(point(&ru, WM_SYS_UNDERVOLT, "", &p), 1);
    WT_ASSERT(web_point_value(WM_SYS_UNDERVOLT, &p) == 0.0);
    WT_EQ(point(&ru, WM_SYS_TEMP, "hottest", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_TEMP, &p) - 51.0) < 1e-9);
    WT_EQ(point(&ru, WM_SYS_TEMP, "thermal_zone0", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_TEMP, &p) - 48.3) < 1e-9);
    WT_ASSERT(web_rollup_has(&ru, WM_SYS_TEMP, "hwmon3.temp1"));
    WT_EQ(point(&ru, WM_SYS_VOLT, "hwmon3.in1", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SYS_VOLT, &p) - 5.103) < 1e-9);
    WT_ASSERT(web_rollup_has(&ru, WM_SYS_VOLT, "bat0"));
    /* An alarm with no reading is not a voltage of zero. Seen red with
     * web_sys_metrics() sampling v as 0 when the member is absent. */
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_VOLT, "hwmon1.in0"));
    WT_EQ(point(&ru, WM_SRC_UP, "monitor", &p), 1);
    WT_ASSERT(web_point_value(WM_SRC_UP, &p) == 1.0);
    WT_EQ(point(&ru, WM_SRC_RATE, "monitor", &p), 1);
    WT_ASSERT(fabs(web_point_value(WM_SRC_RATE, &p) - 51.30) < 1e-9);
    /* Stale is not up; and no rate was measured, so none is sampled. */
    WT_EQ(point(&ru, WM_SRC_UP, "gnss", &p), 1);
    WT_ASSERT(web_point_value(WM_SRC_UP, &p) == 0.0);
    WT_ASSERT(!web_rollup_has(&ru, WM_SRC_RATE, "gnss"));
    /* A source nobody configured has no up or down to chart. Seen red
     * with the not_configured return removed (a flat "down" series for
     * a source that was never asked for). */
    WT_ASSERT(!web_rollup_has(&ru, WM_SRC_UP, "aprs"));
    WT_ASSERT(!web_rollup_has(&ru, WM_SRC_RATE, "aprs"));
    /* An outage inside a bucket is in its min, whatever its mean. */
    mrec(&m, "{\"type\":\"source_status\",\"ts\":1800000061,\"seq\":2,\"name\":\"monitor\","
             "\"kind\":\"wifi-monitor\",\"state\":\"down\",\"detail\":\"not open\"}");
    WT_EQ(point(&ru, WM_SRC_UP, "monitor", &p), 1);
    WT_ASSERT(p.min == 0.0 && p.max == 1.0 && p.n == 2);
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);

    /* Absent or out of range is not sampled, and a sys_sensor cannot
     * write the "hottest" key. */
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    mrec(&m, "{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":1,\"interval_s\":60,\"temps\":0,"
             "\"volts\":0,\"power\":0,\"receivers\":0}");
    mrec(&m, "{\"type\":\"sys_status\",\"ts\":1800000060,\"seq\":1,\"cpu_pct\":250.0,"
             "\"mem_total_kb\":100,\"mem_avail_kb\":900,\"temp_max_c\":9999.0,\"undervolt\":7,"
             "\"rss_kb\":-1}");
    mrec(&m, "{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"temp\",\"id\":\"hottest\","
             "\"c\":20.0}");
    mrec(&m, "{\"type\":\"sys_sensor\",\"ts\":1,\"seq\":1,\"class\":\"temp\",\"id\":\"a b\","
             "\"c\":20.0}");
    mrec(&m, "{\"type\":\"source_status\",\"ts\":1,\"seq\":1,\"name\":\"<b>\",\"state\":\"ok\","
             "\"rate\":1.00}");
    mrec(&m, "{\"type\":\"source_status\",\"ts\":1,\"seq\":1,\"name\":\"adsb\",\"state\":\"ok\","
             "\"rate\":-4.00}");
    /* Seen red with web_sys_metrics() sampling cpu_pct without its
     * range (a 250 % bucket). */
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_CPU, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_MEM_USED, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_RSS, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_UNDERVOLT, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_SYS_TEMP, "hottest"));
    WT_ASSERT(web_rollup_has(&ru, WM_SRC_UP, "adsb"));
    WT_ASSERT(!web_rollup_has(&ru, WM_SRC_RATE, "adsb"));
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_SYS], 1);          /* "adsb" alone */
    WT_EQ(st.caps[WEB_KC_SYS], WEB_SYS_KEYS);
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);
}

/* ── the page's words: syshealth.js's pure half, ported ──────────── */

#define CELLS 96
#define MIN_N 12

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

/* median(): the JS sorts a copy and takes the middle, or the mean of
 * the two middles. */
static double median(const double *a, int n) {
    double s[512];
    if (n <= 0 || n > 512) return NAN;
    memcpy(s, a, (size_t)n * sizeof(double));
    qsort(s, (size_t)n, sizeof(double), cmp_d);
    int m = n >> 1;
    return n & 1 ? s[m] : (s[m - 1] + s[m]) / 2;
}

typedef struct { const char *word; double d, spread; int n; } trend_t;

/* trendOf(), line for line. pts are [t, v]. */
static trend_t trend_of(double (*pts)[2], int n, double from, double to, double eps) {
    trend_t r = { "warming", NAN, NAN, n };
    if (n < MIN_N || !(to > from) || pts[n - 1][0] - pts[0][0] < (to - from) / 2) return r;
    double v[512], dev[512];
    int i, k = n / 3;
    for (i = 0; i < n; i++) v[i] = pts[i][1];
    double med = median(v, n);
    for (i = 0; i < n; i++) dev[i] = fabs(v[i] - med);
    double spread = 1.4826 * median(dev, n);
    double d = median(v + (n - k), k) - median(v, k);
    double bar = spread > (eps > 0 ? eps : 0) ? spread : (eps > 0 ? eps : 0);
    r.word = d > bar ? "rising" : d < -bar ? "falling" : "steady";
    r.d = d;
    r.spread = spread;
    return r;
}

typedef struct { int cells[CELLS]; int seen, on, drops; } strip_t;

/* stripOf(), line for line. pts are [t, mean, min, max, n]; the JS
 * falls back to the mean for a point with no min or max, which no
 * /api/series point is. */
static strip_t strip_of(double (*pts)[5], int n, double from, double to, int worst) {
    strip_t s;
    double span = to - from;
    int i, prev = -1;
    s.seen = s.on = s.drops = 0;
    for (i = 0; i < CELLS; i++) s.cells[i] = -1;
    for (i = 0; i < n; i++) {
        int c = (int)floor((pts[i][0] - from) / span * CELLS);
        if (!(span > 0) || c < 0 || c >= CELLS) continue;
        double m = worst ? pts[i][3] : pts[i][2];
        int v = m >= 0.5 ? 1 : 0;
        if (s.cells[c] < 0) s.cells[c] = v;
        else if (worst) s.cells[c] = s.cells[c] || v;
        else s.cells[c] = s.cells[c] && v;
        s.seen++;
        s.on += v;
        if (prev == 1 && v == 0) s.drops++;
        prev = v;
    }
    return s;
}

/* The JS these port, as the page serves it. */
static void test_sys_page_pure_half_is_pinned(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  var POLL_MS = 15000, TREND_MS = 300000, CELLS = 96, MIN_N = 12;\n");
/*PINS*/
    WT_HAS(p, "  function median(a) {\n"
              "    if (!a.length) return NaN;\n"
              "    var s = a.slice().sort(function (x, y) { return x - y; }), m = s.length >> 1;\n"
              "    return s.length & 1 ? s[m] : (s[m - 1] + s[m]) / 2;\n"
              "  }\n");
    WT_HAS(p, "  function trendOf(pts, from, to, eps) {\n"
              "    var n = pts ? pts.length : 0;\n"
              "    if (n < MIN_N || !(to > from) || pts[n - 1][0] - pts[0][0] < (to - from) / 2)\n"
              "      return { word: \"warming\", d: NaN, spread: NaN, n: n };\n"
              "    var v = [], i, k = Math.floor(n / 3);\n"
              "    for (i = 0; i < n; i++) v.push(pts[i][1]);\n"
              "    var med = median(v), dev = [];\n"
              "    for (i = 0; i < n; i++) dev.push(Math.abs(v[i] - med));\n"
              "    var spread = 1.4826 * median(dev);\n"
              "    var d = median(v.slice(n - k)) - median(v.slice(0, k));\n"
              "    var bar = Math.max(spread, eps > 0 ? eps : 0);\n"
              "    return { word: d > bar ? \"rising\" : d < -bar ? \"falling\" : \"steady\", d: d, spread: spread, n: n };\n"
              "  }\n");
    WT_HAS(p, "  function stripOf(pts, from, to, worst) {\n"
              "    var cells = [], i, span = to - from, on = 0, seen = 0, drops = 0, prev = -1;\n"
              "    for (i = 0; i < CELLS; i++) cells.push(-1);\n"
              "    for (i = 0; pts && i < pts.length; i++) {\n"
              "      var c = Math.floor((pts[i][0] - from) / span * CELLS);\n"
              "      if (!(span > 0) || c < 0 || c >= CELLS) continue;\n"
              "      var m = worst ? pts[i][3] : pts[i][2];\n"
              "      var v = (num(m) ? m : pts[i][1]) >= 0.5 ? 1 : 0;\n"
              "      if (cells[c] < 0) cells[c] = v;\n"
              "      else if (worst) cells[c] = cells[c] || v;\n"
              "      else cells[c] = cells[c] && v;\n"
              "      seen++;\n"
              "      on += v;\n"
              "      if (prev === 1 && v === 0) drops++;\n"
              "      prev = v;\n"
              "    }\n"
              "    return { cells: cells, seen: seen, on: on, drops: drops };\n"
              "  }\n");
}

static int fill(double (*pts)[2], int n, double t0, double step) {
    for (int i = 0; i < n; i++) { pts[i][0] = t0 + i * step; pts[i][1] = 0; }
    return n;
}

/* The trend's rule: no word on too little data, and medians against
 * the series' own spread and the unit's smallest change. */
static void test_sys_trend_rule(void) {
    double pts[64][2];
    /* Eleven samples, however steep: warming. */
    int n = fill(pts, 11, 0, 3600);
    for (int i = 0; i < n; i++) pts[i][1] = i * 10.0;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "warming"));
    /* Twelve samples in the last quarter of the window: warming. Seen
     * red with trendOf()'s half-the-window test removed (and its port's)
     * - a day's trend claimed from its last hours. */
    n = fill(pts, 12, 64800, 1800);
    for (int i = 0; i < n; i++) pts[i][1] = i * 10.0;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "warming"));
    /* Flat, and flat with noise about a level: steady. */
    n = fill(pts, 24, 0, 3600);
    for (int i = 0; i < n; i++) pts[i][1] = 50;
    trend_t t = trend_of(pts, n, 0, 86400, 1);
    WT_ASSERT(!strcmp(t.word, "steady") && t.d == 0 && t.spread == 0 && t.n == 24);
    for (int i = 0; i < n; i++) pts[i][1] = (i & 1) ? 51 : 49;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "steady"));
    /* A ramp from 40 to 63: the thirds' medians differ by 16, more
     * than its spread (1.4826 x 6 = 8.9). */
    for (int i = 0; i < n; i++) pts[i][1] = 40.0 + i;
    t = trend_of(pts, n, 0, 86400, 1);
    WT_ASSERT(!strcmp(t.word, "rising"));
    WT_ASSERT(fabs(t.d - 16.0) < 1e-9);
    WT_ASSERT(fabs(t.spread - 1.4826 * 6.0) < 1e-9);
    for (int i = 0; i < n; i++) pts[i][1] = 63.0 - i;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "falling"));
    /* One spike moves no median. */
    for (int i = 0; i < n; i++) pts[i][1] = 50;
    pts[20][1] = 95;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "steady"));
    /* A step in the last third: its spread is 0 (two thirds sit on the
     * median), so the unit's smallest change is the bar. */
    for (int i = 0; i < n; i++) pts[i][1] = i < 16 ? 50 : 60;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "rising"));
    /* A drift smaller than the unit's smallest change is not a trend:
     * 48.0 to 48.46 C is steady at 1 C, and rising only with no floor.
     * Seen red with eps dropped from the bar. */
    for (int i = 0; i < n; i++) pts[i][1] = 48.0 + i * 0.02;
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 1).word, "steady"));
    WT_ASSERT(!strcmp(trend_of(pts, n, 0, 86400, 0).word, "rising"));
}

/* The up/down strip: an outage is never averaged away, a missing
 * report is a gap and not a "down". */
static void test_sys_strip_rule(void) {
    double pts[8][5];
    memset(pts, 0, sizeof(pts));
    /* 96 cells over 96 minutes: a cell a minute. Buckets at minutes 0,
     * 1, 2 (up), 3 (an outage inside it: mean 0.5, min 0), 5 (up), and
     * two in minute 7 - one up, one down. Minute 4 and 6: no report. */
    double from = 6000, to = from + 96 * 60;
    static const double at[7] = { 30, 90, 150, 210, 330, 450, 470 };
    static const double mean[7] = { 1, 1, 1, 0.5, 1, 1, 0 };
    static const double lo[7] = { 1, 1, 1, 0, 1, 1, 0 };
    static const double hi[7] = { 1, 1, 1, 1, 1, 1, 0 };
    for (int i = 0; i < 7; i++) {
        pts[i][0] = from + at[i]; pts[i][1] = mean[i]; pts[i][2] = lo[i]; pts[i][3] = hi[i];
        pts[i][4] = 1;
    }
    strip_t s = strip_of(pts, 7, from, to, 0);
    WT_EQ(s.cells[0], 1);
    WT_EQ(s.cells[2], 1);
    /* Seen red with stripOf() reading the bucket's mean (and its port):
     * an outage inside a bucket drawn as up. */
    WT_EQ(s.cells[3], 0);
    WT_EQ(s.cells[4], -1);                 /* not reported: a gap, not down */
    WT_EQ(s.cells[5], 1);
    WT_EQ(s.cells[6], -1);
    WT_EQ(s.cells[7], 0);                  /* up and down in one cell: down */
    WT_EQ(s.cells[8], -1);
    WT_EQ(s.seen, 7);
    WT_EQ(s.on, 5);
    WT_EQ(s.drops, 2);
    /* The same buckets as an alarm: set at any time in a bucket (its
     * max), and a cell is set when any bucket in it was. */
    s = strip_of(pts, 7, from, to, 1);
    WT_EQ(s.cells[3], 1);
    WT_EQ(s.cells[7], 1);
    WT_EQ(s.on, 6);
    /* A point outside the window is not in it. */
    pts[7][0] = to + 600; pts[7][1] = pts[7][2] = pts[7][3] = 1;
    s = strip_of(pts, 8, from, to, 0);
    WT_EQ(s.seen, 7);
    /* No points: every cell a gap. */
    s = strip_of(pts, 0, from, to, 0);
    WT_EQ(s.seen, 0);
    for (int i = 0; i < CELLS; i++) WT_EQ(s.cells[i], -1);
}

/* ── the page ────────────────────────────────────────────────────── */

static char *module_text(void) {
    const char *p = (const char *)web_page;
    const char *a = strstr(p, "// slothweb: the sensor's host status on the Sensor health view\n");
    const char *b = a ? strstr(a, "  window.SlothSysHealth = { init: init, show: show };\n})();") : NULL;
    WT_ASSERT(a != NULL && b != NULL);
    if (!a || !b) return NULL;
    size_t n = (size_t)(b - a);
    char *m = malloc(n + 1);
    if (!m) return NULL;
    memcpy(m, a, n);
    m[n] = '\0';
    return m;
}

static void test_sys_page(void) {
    const char *p = (const char *)web_page;
    /* The containers, in the health view, ahead of the older panel. */
    const char *v = strstr(p, "<div id=\"v-health\" hidden>");
    const char *old = v ? strstr(v, "<div id=\"hl-rows\"></div>") : NULL;
    const char *mine = v ? strstr(v, "<div class=\"hscroll\" id=\"sy-src-box\"><div class=\"syrow dhead\" "
                                     "id=\"sy-src-thead\"></div><div id=\"sy-src-rows\"></div></div>") : NULL;
    WT_ASSERT(v && old && mine && mine < old);
    WT_HAS(p, "<div class=\"hscroll\" id=\"sy-hw-box\"><div class=\"syrow dhead\" id=\"sy-hw-thead\">"
              "</div><div id=\"sy-hw-rows\"></div></div>");
    WT_HAS(p, "<div class=\"kpis\" id=\"sy-tiles\"></div>");
    WT_HAS(p, "<div id=\"sy-trends\"></div>");
    WT_HAS(p, "<option value=\"86400\" selected>24 h</option>\n        <option value=\"604800\">7 d</option>\n"
              "        <option value=\"2592000\">30 d</option>\n      </select></label></div>");
    /* app.js's two hooks, and nothing else of this module's in it. */
    WT_HAS(p, "    if (v === \"health\" && window.SlothSysHealth) SlothSysHealth.show();\n");
    WT_HAS(p, "  if (window.SlothSysHealth) SlothSysHealth.init({ fmt: fmt, dur: dur, tok: tok, bands: bands,\n"
              "    sens: function () { return sens; }, storeOn: function () { return A.storeOn; },\n"
              "    prefGet: prefGet, prefSet: prefSet });\n");
    char *m = module_text();
    if (!m) return;
    /* No sink that parses markup and no attribute written from a
     * value: every string here is a device's. Seen red with
     * `box.innerHTML = \"\"` added to clear() in syshealth.js. */
    static const char *const SINK[] = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "setAttribute(",
        "eval(", "new Function", ".href =", ".src =", "createElement(\"input\")",
    };
    for (size_t i = 0; i < sizeof(SINK) / sizeof(SINK[0]); i++) WT_LACKS(m, SINK[i]);
    /* Same-origin relative reads, and unscoped on purpose: sloth's own
     * state is read as Hybrid's under every scope. */
    WT_HAS(m, "    return fetch(path, { credentials: \"same-origin\", cache: \"no-store\" }).then(function (r) {");
    WT_HAS(m, "    getJSON(\"/api/sys\").then(function (j) {");
    WT_LACKS(m, "scope=");
    WT_LACKS(m, "http://");
    WT_LACKS(m, "https://");
    /* The two tables are the page's one DataTable. */
    WT_HAS(m, "      ST = window.SlothTables.make({ id: \"sy-src\", label: \"sources\", box: $(\"sy-src-box\"),\n"
              "        head: $(\"sy-src-thead\"), reset: $(\"sy-src-tools\"), redraw: drawSources, cols: SRC_COLS });");
    WT_HAS(m, "      HT = window.SlothTables.make({ id: \"sy-hw\", label: \"attached receivers\", box: $(\"sy-hw-box\"),\n"
              "        head: $(\"sy-hw-thead\"), reset: $(\"sy-hw-tools\"), redraw: drawHw, cols: HW_COLS });");
    /* A state is a shape and a word (R10), four of them. */
    WT_HAS(m, "  var MARK = { \"ok\": \"\\u25cf ok\", \"stale\": \"\\u25d0 stale\", \"down\": \"\\u2715 down\",\n"
              "               \"not_configured\": \"\\u00b7 not configured\" };");
    /* A reading the host does not have is said, never drawn as zero. */
    WT_HAS(m, "  var ABSENT = \"not reported by this host\";");
    WT_HAS(m, "    t.appendChild(el(\"div\", \"sub\", value === null ? ABSENT : sub || \"\"));");
    /* The state strip is G5, called; the series G1 on a kept scale. */
    WT_HAS(m, "    glyph.paint(ui.c, glyph.g5(st.cells, { w: ui.c.clientWidth, h: ui.c.clientHeight, first: -1 }), H.tok);");
    WT_HAS(m, "    S.scale[id] = w.fixed ? w.fixed : shared || glyph.scale(pts, bd, S.scale[id] || null);");
    WT_HAS(m, "            var sh = temps.length ? glyph.shared(sets, S.scale.temp || null) : null;");
    /* With no report at all, the page says what that means. */
    WT_HAS(m, "or slothweb is reading a copied sloth.db with no live stream: sloth.db holds none of this, ");
    /* Past 24 h needs the store's hour tier, and says so without one. */
    WT_HAS(m, "    if (win > 86400) return H.storeOn() ? \"hour\" : null;");
    free(m);
}

void run_sysstat_tests(void) {
    WT_RUN(test_sys_key);
    WT_RUN(test_sys_keep);
    WT_RUN(test_sys_nothing_yet);
    WT_RUN(test_sys_ingest_and_route);
    WT_RUN(test_sys_absent_is_null);
    WT_RUN(test_sys_batch_replaces);
    WT_RUN(test_sys_stale);
    WT_RUN(test_sys_every_scope);
    WT_RUN(test_sys_hostile);
    WT_RUN(test_sys_metrics);
    WT_RUN(test_sys_page_pure_half_is_pinned);
    WT_RUN(test_sys_trend_rule);
    WT_RUN(test_sys_strip_rule);
    WT_RUN(test_sys_page);
    web_sys_destroy(&Y);
}
