/* The rtl_433 tab (web_rtl433.h, #208): the devices kept by slothweb
 * from hand-built records in the emitter's exact shape (src/jsonl.c
 * emit_rtl433_device() and the rtl433_* block of
 * jsonl_emit_sensor_health(); tests/test_rtl433.c pins those), the
 * route through the route table under each scope, the health member,
 * and the page's half. Models, ids and readings are invented.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the Local answer with route_rtl433()'s none_here forced to
 * 0 (a Local answer carried devices); the range checks with
 * device_apply()'s temperature bound widened to 1e6 (the 900.0 landed
 * on the row); the two-unit refusal with junit()'s `hits != 1` made
 * `hits < 1` (a pressure was kept from an ambiguous record); the aging
 * with age_out()'s TTL test removed (the silent row stayed). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_rtl433.h"
#include "web_scope.h"
#include "wtest.h"

#define T 1794654600LL

static web_rtl433_t A;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_rtl433_record(&A, &R, 1000);
}

/* sensor_health's rtl433_* block, in jsonl_emit_sensor_health()'s order. */
static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1794654600,\"capture_iface\":\"any\","
    "\"rtl433_state\":\"live\",\"rtl433_src\":\"file:/var/lib/rtl_433/events.jsonl\","
    "\"rtl433_missing\":0,\"rtl433_last_read\":1794654599,\"rtl433_last_msg\":1794654560,"
    "\"rtl433_devices\":2,\"rtl433_bytes\":4096,\"rtl433_lines\":12,\"rtl433_msgs\":10,"
    "\"rtl433_bad_lines\":2,\"rtl433_rej_oversize\":0,\"rtl433_rej_not_object\":1,"
    "\"rtl433_rej_malformed\":0,\"rtl433_rej_no_model\":0,\"rtl433_rej_no_id\":1,"
    "\"rtl433_bad_values\":3,\"rtl433_other_keys\":9,\"rtl433_evicted\":0,"
    "\"rtl433_truncations\":1,\"rtl433_rotations\":0,\"rtl433_read_errors\":0,"
    "\"rtl433_err\":\"\",\"db_max_mb\":-1,\"jsonl_version\":\"1.8.0\"}";
/* A TPMS sensor (FSK, so freq and freq2), as emit_rtl433_device() writes it. */
static const char D1[] =
    "{\"type\":\"rtl433_device\",\"ts\":1794654501,\"src\":\"file:/var/lib/rtl_433/events.jsonl\","
    "\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\",\"first_seen\":1794654500,"
    "\"last_seen\":1794654500,\"msgs\":1,\"dev_type\":\"TPMS\",\"mic\":\"CHECKSUM\","
    "\"mod\":\"FSK\",\"protocol\":60,\"freq_mhz\":433.918,\"freq2_mhz\":433.952,"
    "\"rssi\":-0.2,\"snr\":22.4,\"noise\":-22.6,\"temperature_C\":21.0,"
    "\"pressure_kPa\":241.4,\"other_keys\":3}";
/* A weather sensor (ASK), a string channel, hPa and battery. */
static const char D2[] =
    "{\"type\":\"rtl433_device\",\"ts\":1794654561,\"src\":\"file:/var/lib/rtl_433/events.jsonl\","
    "\"model\":\"Testco-WX9\",\"id\":\"205\",\"first_seen\":1794654000,"
    "\"last_seen\":1794654560,\"msgs\":19,\"channel\":\"2\",\"mic\":\"CRC\",\"mod\":\"ASK\","
    "\"freq_mhz\":433.902,\"rssi\":-10.2,\"snr\":7.1,\"noise\":-17.3,\"battery_ok\":1.0,"
    "\"temperature_F\":70.5,\"humidity\":63.0,\"pressure_hPa\":1013.2,\"other_keys\":0}";

static char g_out[262144];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, 65536, &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static void fresh(void) {
    web_rtl433_destroy(&A);
    WT_EQ(web_rtl433_init(&A), 0);
}

static void health(web_health_t *H, long long now) {
    memset(H, 0, sizeof(*H));
    H->rtl433 = &A;
    H->wall_s = now;
}

/* The records land where the page reads them: the sensor block, the
 * devices most recently heard first, each reading in its own unit,
 * absent ones null or "". */
static void test_rtl433_ingest_and_route(void) {
    fresh();
    feed(D1); feed(D2); feed(SH);
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1794654600,\"src\":\"file:/var/lib/rtl_433/events.jsonl\",\"records\":2,"
              "\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor\":{\"ts\":1794654600,"
              "\"state\":\"live\",\"src\":\"file:/var/lib/rtl_433/events.jsonl\",\"missing\":0,"
              "\"last_read\":1794654599,\"last_msg\":1794654560,\"devices\":2,\"bytes\":4096,"
              "\"lines\":12,\"msgs\":10,\"bad_lines\":2,\"rej\":{\"oversize\":0,"
              "\"not_object\":1,\"malformed\":0,\"no_model\":0,\"no_id\":1},\"bad_values\":3,"
              "\"other_keys\":9,\"evicted\":0,\"truncations\":1,\"rotations\":0,"
              "\"read_errors\":0,\"err\":\"\"},\"total\":2,\"devices\":["
              "{\"model\":\"Testco-WX9\",\"id\":\"205\",\"first_seen\":1794654000,"
              "\"last_seen\":1794654560,\"msgs\":19,\"dev_type\":\"\",\"subtype\":\"\","
              "\"channel\":\"2\",\"mic\":\"CRC\",\"mod\":\"ASK\",\"protocol\":null,"
              "\"freq_mhz\":433.902,\"freq2_mhz\":null,\"rssi\":-10.2,\"snr\":7.1,"
              "\"noise\":-17.3,\"battery_ok\":1.0,\"temperature\":70.5,\"temp_unit\":\"F\","
              "\"humidity\":63.0,\"pressure\":1013.2,\"pres_unit\":\"hPa\",\"other_keys\":0,"
              "\"ts\":1794654561,\"records\":1},"
              "{\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\",\"first_seen\":1794654500,"
              "\"last_seen\":1794654500,\"msgs\":1,\"dev_type\":\"TPMS\",\"subtype\":\"\","
              "\"channel\":\"\",\"mic\":\"CHECKSUM\",\"mod\":\"FSK\",\"protocol\":60,"
              "\"freq_mhz\":433.918,\"freq2_mhz\":433.952,\"rssi\":-0.2,\"snr\":22.4,"
              "\"noise\":-22.6,\"battery_ok\":null,\"temperature\":21.0,\"temp_unit\":\"C\","
              "\"humidity\":null,\"pressure\":241.4,\"pres_unit\":\"kPa\",\"other_keys\":3,"
              "\"ts\":1794654501,\"records\":1}],\"shown\":2,\"cut\":false}");
    WT_EQ(route(&H, "/api/rtl433", "limit=1"), 200);
    WT_HAS(body_of(g_out), "],\"shown\":1,\"cut\":false}");
    WT_LACKS(body_of(g_out), "1a2b3c");
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"rtl433\":{\"rows\":2,\"records\":2,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* A later record for the same key replaces the row: sloth's merge
     * is sticky, so what a record omits sloth no longer has. */
    feed("{\"type\":\"rtl433_device\",\"ts\":1794654700,\"src\":\"file:/x\","
         "\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\",\"first_seen\":1794654500,"
         "\"last_seen\":1794654690,\"msgs\":7,\"rssi\":-6.1,\"other_keys\":4}");
    WT_EQ(route(&H, "/api/rtl433", "limit=1"), 200);
    WT_HAS(body_of(g_out), "{\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\",\"first_seen\":1794654500,"
                           "\"last_seen\":1794654690,\"msgs\":7,");
    WT_HAS(body_of(g_out), "\"rssi\":-6.1,");
    WT_HAS(body_of(g_out), "\"records\":2}");
    /* A sensor_health without the block (no --rtl433): the sensor null. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1794654600,\"capture_iface\":\"any\"}");
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "\"src\":\"\",\"records\":0,\"evictions\":0,\"aged\":0,"
                           "\"rejected\":0,\"sensor\":null,\"total\":0,"
                           "\"devices\":[],\"shown\":0,\"cut\":false}");
}

/* Hostile strings and numbers: a record with no usable model, id or
 * first_seen is rejected; a reading out of range, or a reading in two
 * units at once, is null; a word off its list is "". */
static void test_rtl433_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"id\":\"1\",\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"id\":\"a\\\"b\",\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"id\":\"1\"}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\\u0001\",\"id\":\"1\",\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"id\":\"12345678901234567\",\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"id\":1,\"first_seen\":1}");
    feed("{\"type\":\"rtl433_device\",\"ts\":1,\"model\":\"X\",\"id\":\"1\",\"first_seen\":1,"
         "\"temperature_C\":900.0e3,\"humidity\":101.0,\"battery_ok\":2.0,\"rssi\":-999.0,"
         "\"freq_mhz\":0.0,\"protocol\":70000,\"pressure_kPa\":200.0,\"pressure_psi\":29.0,"
         "\"mic\":\"MD5\",\"mod\":\"OOK\",\"dev_type\":\"<script>alert(1)</script>\"}");
    web_health_t H;
    health(&H, 10);
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"rejected\":7,");
    WT_HAS(b, "\"total\":1,");
    WT_HAS(b, "\"dev_type\":\"\",");
    WT_HAS(b, "\"mic\":\"\",\"mod\":\"\",\"protocol\":null,\"freq_mhz\":null,");
    WT_HAS(b, "\"rssi\":null,");
    WT_HAS(b, "\"battery_ok\":null,\"temperature\":null,\"temp_unit\":\"\","
              "\"humidity\":null,\"pressure\":null,\"pres_unit\":\"\",");
    WT_LACKS(b, "900");
    WT_LACKS(b, "200.0");
    WT_LACKS(b, "script");
    WT_EQ(route(&H, "/api/rtl433", "limit=0"), 400);
    WT_EQ(route(&H, "/api/rtl433", "limit=513"), 400);
    WT_EQ(route(&H, "/api/rtl433", "call=X"), 400);
}

/* A row with no record for WEB_RTL433_TTL_S is one sloth evicted:
 * dropped and counted; a record with a new first_seen is sloth's new
 * row for the key. */
static void test_rtl433_age(void) {
    fresh();
    feed(D1); feed(D2);
    /* 660 s after D1's record: still kept. */
    feed("{\"type\":\"sensor_health\",\"ts\":1794655161}");
    web_health_t H;
    health(&H, 1794655161);
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    /* Past it for D1, not yet for D2. */
    feed("{\"type\":\"sensor_health\",\"ts\":1794655162}");
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"aged\":1,");
    WT_HAS(b, "\"total\":1,");
    WT_LACKS(b, "1a2b3c");
    /* Back with a new first_seen: a fresh row, its own count. */
    feed(D2);
    feed("{\"type\":\"rtl433_device\",\"ts\":1794655200,\"model\":\"Testco-WX9\","
         "\"id\":\"205\",\"first_seen\":1794655190,\"last_seen\":1794655190,\"msgs\":1,"
         "\"other_keys\":0}");
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_HAS(body_of(g_out), "\"first_seen\":1794655190,\"last_seen\":1794655190,\"msgs\":1,");
    WT_HAS(body_of(g_out), "\"records\":1}");
}

static void test_rtl433_eviction(void) {
    fresh();
    static char line[512];
    for (int i = 0; i < WEB_RTL433_ROWS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"rtl433_device\",\"ts\":%lld,\"model\":\"Testco-TP01\","
                 "\"id\":\"%06x\",\"first_seen\":%lld,\"last_seen\":%lld,\"msgs\":1,"
                 "\"other_keys\":0}", T + i, i, T, T + i);
        feed(line);
    }
    web_health_t H;
    health(&H, T + 600);
    WT_EQ(route(&H, "/api/rtl433", "limit=1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,");
    WT_HAS(b, "\"total\":512,");
    WT_EQ(route(&H, "/api/rtl433", ""), 200);
    WT_LACKS(body_of(g_out), "\"id\":\"000000\"");
    WT_HAS(body_of(g_out), "\"id\":\"000200\"");
}

/* The decoder's SDR is passive radio: Monitor's record and a poll
 * type; Monitor and Hybrid answer devices, Local the one out_of_scope
 * body (its query still checked). */
static void test_rtl433_scope(void) {
    fresh();
    feed(SH); feed(D1);
    WT_EQ(web_scope_record("rtl433_device"), WEB_SC_M);
    WT_ASSERT(web_live_is_poll_type("rtl433_device"));
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/rtl433", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/rtl433", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/rtl433", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"rtl_433 devices are the rtl_433 decoder");
    WT_LACKS(body_of(g_out), "1a2b3c");
    WT_LACKS(body_of(g_out), "\"devices\"");
    WT_EQ(route(&H, "/api/rtl433", "scope=local&limit=0"), 400);
    /* No table: 503. */
    health(&H, T);
    H.rtl433 = NULL;
    WT_EQ(route(&H, "/api/rtl433", ""), 503);
}

/* The page's half: the tab after Spectrum, the view, the module's hooks;
 * every remote string through textContent (el()), no markup sink. */
static void test_rtl433_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-spectrum\">Spectrum</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-rtl433\">rtl_433</button></li>");
    WT_HAS(p, "  VIEWS.push(\"rtl433\");");
    WT_HAS(p, "  $(\"nav-rtl433\").addEventListener(\"click\", function () { show(\"rtl433\"); });");
    WT_HAS(p, "    if (v === \"rtl433\" && window.SlothRtl433) SlothRtl433.show();");
    WT_HAS(p, "  if (window.SlothRtl433) SlothRtl433.init({ getJSON: getJSON, errText: errText, shortStamp: shortStamp });");
    WT_HAS(p, "<div id=\"v-rtl433\" hidden>");
    WT_HAS(p, "<table class=\"qt\" id=\"r4-rows\"");
    WT_HAS(p, "    H.getJSON(\"/api/rtl433\").then(function (j) {");
    WT_HAS(p, "  function el(tag, cls, text) {\n"
              "    var e = document.createElement(tag);\n"
              "    if (cls) e.className = cls;\n"
              "    if (text !== undefined && text !== null) e.textContent = String(text);\n"
              "    return e;\n"
              "  }");
    /* The readings keep the unit they arrived in: the page reads the
     * route's unit members and converts nothing. */
    WT_HAS(p, "  function reading(v, unit) { return num(v) ? v.toFixed(1) + (unit ? \" \" + unit : \"\") : \"-\"; }");
    WT_HAS(p, "reading(r.temperature, r.temp_unit)");
    WT_HAS(p, "reading(r.pressure, r.pres_unit)");
    const char *s = strstr(p, "// slothweb: the rtl_433 tab");
    const char *m = strstr(p, "stateText: stateText, cells: cells, reading: reading");
    WT_ASSERT(s && m && s < m);
    if (s && m) {
        size_t n = (size_t)(m - s);
        char *mod = malloc(n + 1);
        WT_ASSERT(mod != NULL);
        if (mod) {
            memcpy(mod, s, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "insertAdjacentHTML");
            WT_LACKS(mod, "http://");
            WT_LACKS(mod, "https://");
            free(mod);
        }
    }
}

void run_rtl433_tests(void) {
    WT_RUN(test_rtl433_ingest_and_route);
    WT_RUN(test_rtl433_ranges_and_refusals);
    WT_RUN(test_rtl433_age);
    WT_RUN(test_rtl433_eviction);
    WT_RUN(test_rtl433_scope);
    WT_RUN(test_rtl433_page);
    web_rtl433_destroy(&A);
}
