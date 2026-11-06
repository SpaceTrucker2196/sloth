/* The Radar view (2026-11-06): /api/radar (web_radar.h), the Wi-Fi and
 * BLE distance-band census from the BLE tables and the FRRS ledger,
 * seeded from hand-built records in the emitters' shapes (test_ble.c's
 * ble_device line, test_rf.c's beacon and probe_client lines); and the
 * page's half, web/ui/radar.js, pinned by whole functions as #171 V1's
 * review asked: the projection, the painters, the kept camera, the
 * scope and estimate sentences, the nav's place, the three select()
 * hooks the dome's panel calls.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the Local out_of_scope answer with route_radar()'s
 * none_here forced to 0 (a Local answer carried addresses); the devs
 * cap with band_take()'s `if (at >= WEB_RADAR_DEVS) return;` removed
 * and the list unbounded (nine addresses in one band); the none count
 * with census_take()'s has_rssi test dropped (a row without a reading
 * counted as none); the page's R8 bans with a `createLinearGradient(`
 * line added to radar.js; the divide-by-depth ban with `/ depth` put
 * into project(); the control census with `<select id="radar-x">`
 * added to v-radar; the scoped-out ban with a `$("v-radar")` toggle
 * added to scopeUI(); the `radar.sel` ban with a prefSet of it added;
 * the recent lists' cap with recent_take()'s bound widened to 2048 (60
 * listed); the estimate rule with recent_take() moved from the band
 * branch to the none branch (unestimated rows listed); Local's devs with
 * route_radar()'s none_here forced 0; the one-fillText rule with a
 * second fillText added to draw(); put()'s overlap refusal with its
 * boxHit() test dropped (the drawLabels pin). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_ble.h"
#include "web_devices.h"
#include "web_frrs.h"
#include "web_jsonl.h"
#include "web_radar.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"

#define T 1793100000LL

static web_ble_t B;
static web_frrs_t F;
static web_m4_t M;
static web_jrec_t R;
static char g_out[262144];

static void feed_ble(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_ble_record(&B, &R, 1000);
}
static void feed_rf(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_frrs_record(&F, &R);
}

/* One ble_device line as the emitter writes it (test_ble.c dev_line's
 * shape, the members this census reads varied): rssi 0 is no reading;
 * band "" is no estimate. */
static const char *ble_line(const char *addr, int type, const char *name, int rssi,
                            const char *band) {
    static char buf[1024];
    char est[160] = "";
    if (band && band[0])
        snprintf(est, sizeof(est), ",\"est_dist_m\":2.5,\"est_dist_band\":\"%s\","
                 "\"est_dist_trend\":\"steady\",\"est_ptx_source\":\"assumed\"", band);
    snprintf(buf, sizeof(buf),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":%d,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"adapter\":0,\"sampled\":0,"
             "\"channel\":-1,\"last_pdu\":\"ADV_IND\",\"pdu_mask\":1,\"name\":\"%s\","
             "\"name_complete\":1,\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"tx_power\":-128,"
             "\"flags\":-1,\"has_rssi\":%d,\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":3,"
             "\"watch_category\":\"\",\"ext_adv\":0,\"primary_phy\":0,\"secondary_phy\":0,"
             "\"adv_sid\":-1,\"first_seen\":%lld,\"last_seen\":%lld%s}",
             T, addr, type, name, rssi != 0, rssi, rssi != 0 ? rssi + 5 : 0, T - 60, T, est);
    return buf;
}

/* A beacon (ap) or probe_client (sta) line with its signal and sloth's
 * estimate, as test_rf.c feeds the ledger. */
static const char *rf_line(int ap, const char *mac, const char *ssid, int dbm, const char *band) {
    static char buf[1024];
    char est[160] = "";
    if (band && band[0])
        snprintf(est, sizeof(est), ",\"est_dist_m\":6.0,\"est_dist_band\":\"%s\","
                 "\"est_dist_trend\":\"steady\",\"est_ptx_source\":\"assumed\"", band);
    if (ap)
        snprintf(buf, sizeof(buf), "{\"type\":\"beacon\",\"ts\":%lld,\"bssid\":\"%s\",\"ssid\":\"%s\","
                 "\"channel\":6,\"signal_dbm\":%d%s}", T, mac, ssid, dbm, est);
    else
        snprintf(buf, sizeof(buf), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"%s\","
                 "\"signal_dbm\":%d,\"frame_count\":3%s}", T, mac, dbm, est);
    return buf;
}

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
static int count(const char *s, const char *needle) {
    int n = 0;
    for (const char *h = strstr(s, needle); h; h = strstr(h + 1, needle)) n++;
    return n;
}

static void fresh(void) {
    char err[256];
    web_ble_destroy(&B);
    web_frrs_destroy(&F);
    WT_EQ(web_ble_init(&B, 0), 0);
    WT_EQ(web_frrs_init(&F, NULL, NULL, 0, err, sizeof(err)), 0);
    memset(&M, 0, sizeof(M));
    M.frrs = &F;
}
static void health(web_health_t *H) {
    memset(H, 0, sizeof(*H));
    H->ble = &B;
    H->m4 = &M;
    H->wall_s = T + 5;
}

/* Both censuses from seeded rows: every row in total, the banded ones
 * in their band nearest-RSSI first, a row with a reading and no
 * estimate in none (and nowhere else), a row with neither only in
 * total; the Wi-Fi rows by kind, the AP with its SSID. */
static void test_radar_census(void) {
    fresh();
    feed_ble(ble_line("02:de:00:00:00:01", 0, "far one", -45, "immediate"));
    feed_ble(ble_line("02:de:00:00:00:02", 1, "", -40, "immediate"));
    feed_ble(ble_line("02:de:00:00:00:03", 0, "third", -50, "immediate"));
    feed_ble(ble_line("02:de:00:00:00:04", 0, "", -70, "room"));
    feed_ble(ble_line("02:de:00:00:00:05", 0, "", -72, "room"));
    feed_ble(ble_line("02:de:00:00:00:06", 0, "noest", -80, ""));     /* a reading, no band */
    feed_ble(ble_line("00:00:00:00:00:00", 255, "", 0, ""));           /* anonymous, nothing */
    feed_rf(rf_line(1, "02:00:00:00:00:a1", "home", -47, "room"));
    feed_rf(rf_line(1, "02:00:00:00:00:a2", "", -61, "room"));
    feed_rf(rf_line(0, "02:00:00:00:00:51", "", -66, "building"));
    feed_rf(rf_line(1, "02:00:00:00:00:a3", "nx", -55, ""));          /* a reading, no band */
    feed_rf(rf_line(0, "02:00:00:00:00:52", "", 0, ""));              /* neither */
    web_health_t H;
    health(&H);
    WT_EQ(route(&H, "/api/radar", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793100005,\"ble\":{\"total\":7,\"estimated\":5,\"none\":1,\"bands\":{"
              "\"immediate\":{\"n\":3,\"devs\":["
              "{\"addr\":\"02:de:00:00:00:02\",\"addr_type\":1,\"iface\":\"bluetooth-monitor\",\"name\":\"\",\"rssi\":-40,\"last_seen\":1793100000},"
              "{\"addr\":\"02:de:00:00:00:01\",\"addr_type\":0,\"iface\":\"bluetooth-monitor\",\"name\":\"far one\",\"rssi\":-45,\"last_seen\":1793100000},"
              "{\"addr\":\"02:de:00:00:00:03\",\"addr_type\":0,\"iface\":\"bluetooth-monitor\",\"name\":\"third\",\"rssi\":-50,\"last_seen\":1793100000}]},"
              "\"near\":{\"n\":0,\"devs\":[]},"
              "\"room\":{\"n\":2,\"devs\":[{\"addr\":\"02:de:00:00:00:04\"");
    WT_HAS(b, "\"building\":{\"n\":0,\"devs\":[]},\"far\":{\"n\":0,\"devs\":[]}}}");
    WT_LACKS(b, "02:de:00:00:00:06");            /* none: counted, never listed */
    WT_LACKS(b, "00:00:00:00:00:00");
    WT_HAS(b, "\"wifi\":{\"total\":5,\"estimated\":3,\"none\":1,\"bands\":{"
              "\"immediate\":{\"n\":0,\"devs\":[]},\"near\":{\"n\":0,\"devs\":[]},"
              "\"room\":{\"n\":2,\"devs\":["
              "{\"mac\":\"02:00:00:00:00:a1\",\"kind\":\"ap\",\"ssid\":\"home\",\"rssi\":-47,\"ts\":1793100000},"
              "{\"mac\":\"02:00:00:00:00:a2\",\"kind\":\"ap\",\"ssid\":\"\",\"rssi\":-61,\"ts\":1793100000}]},"
              "\"building\":{\"n\":1,\"devs\":[{\"mac\":\"02:00:00:00:00:51\",\"kind\":\"sta\",\"ssid\":\"\",\"rssi\":-66,\"ts\":1793100000}]},"
              "\"far\":{\"n\":0,\"devs\":[]}}},\"devs\":{\"ble\":[");
    WT_LACKS(b, "02:00:00:00:00:a3");
    /* A word that is not sloth's is no band: counted as none when it
     * has a reading (seen red with the band_index() lookup replaced by
     * "any non-empty word is far"). */
    feed_rf(rf_line(1, "02:00:00:00:00:a4", "odd", -50, "next door"));
    WT_EQ(route(&H, "/api/radar", ""), 200);
    WT_HAS(body_of(g_out), "\"wifi\":{\"total\":6,\"estimated\":3,\"none\":2,");
    /* No tables attached: each half null, still a 200. */
    H.ble = NULL;
    H.m4 = NULL;
    WT_EQ(route(&H, "/api/radar", ""), 200);
    WT_HAS(body_of(g_out), "{\"now\":1793100005,\"ble\":null,\"wifi\":null,\"devs\":{\"ble\":[],\"wifi\":[]}}");
}

/* Eight listed of twelve in one band, the strongest eight, in order;
 * n says twelve. Seen red with band_take()'s cap removed. */
static void test_radar_cap(void) {
    fresh();
    for (int i = 0; i < 12; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "02:de:00:00:01:%02x", i);
        /* Strength scrambled, so the order is the sort's, not the feed's. */
        feed_ble(ble_line(addr, 0, "", -40 - ((i * 7) % 12) * 3, "near"));
    }
    web_health_t H;
    health(&H);
    WT_EQ(route(&H, "/api/radar", ""), 200);
    const char *b = body_of(g_out);
    const char *near = strstr(b, "\"near\":{\"n\":12,\"devs\":[");
    WT_ASSERT(near != NULL);
    if (!near) return;
    const char *end = strstr(near, "]}");
    WT_ASSERT(end != NULL);
    if (!end) return;
    char seg[4096];
    snprintf(seg, sizeof(seg), "%.*s", (int)(end - near), near);
    WT_EQ(count(seg, "\"addr\":"), WEB_RADAR_DEVS);
    /* -40 (i 0), -43 (i 7), -46 (i 2), -49 (i 9), ... the weakest four
     * (-64 .. -73) are left out. */
    WT_HAS(seg, "\"addr\":\"02:de:00:00:01:00\",\"addr_type\":0,\"iface\":\"bluetooth-monitor\",\"name\":\"\",\"rssi\":-40,");
    const char *p1 = strstr(seg, "\"rssi\":-40,"), *p2 = strstr(seg, "\"rssi\":-43,"), *p3 = strstr(seg, "\"rssi\":-61,");
    WT_ASSERT(p1 && p2 && p3 && p1 < p2 && p2 < p3);
    WT_LACKS(seg, "\"rssi\":-64,");
    WT_LACKS(seg, "\"rssi\":-73,");
    /* A row without a reading sorts after every reading, and a band of
     * them lists the first eight fed. */
    fresh();
    for (int i = 0; i < 3; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "02:de:00:00:02:%02x", i);
        feed_ble(ble_line(addr, 0, "", 0, "far"));
    }
    feed_ble(ble_line("02:de:00:00:02:ff", 0, "heard", -90, "far"));
    WT_EQ(route(&H, "/api/radar", ""), 200);
    WT_HAS(body_of(g_out), "\"far\":{\"n\":4,\"devs\":[{\"addr\":\"02:de:00:00:02:ff\",\"addr_type\":0,"
                           "\"iface\":\"bluetooth-monitor\",\"name\":\"heard\",\"rssi\":-90,\"last_seen\":1793100000},"
                           "{\"addr\":\"02:de:00:00:02:00\",\"addr_type\":0,\"iface\":\"bluetooth-monitor\","
                           "\"name\":\"\",\"rssi\":null,");
    /* The BLE half counts no estimate without a reading as neither. */
    WT_HAS(body_of(g_out), "\"ble\":{\"total\":4,\"estimated\":4,\"none\":0,");
}

/* The receivers are passive radio: Monitor and Hybrid answer the
 * census, Local the one out_of_scope body with the query still
 * checked; a parameter of any name is a 400 that never echoes it. */
static void test_radar_scope_and_params(void) {
    fresh();
    feed_ble(ble_line("02:de:00:00:00:01", 0, "", -45, "immediate"));
    feed_rf(rf_line(1, "02:00:00:00:00:a1", "home", -47, "room"));
    web_health_t H;
    health(&H);
    WT_EQ(route(&H, "/api/radar", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"monitor\",\"now\":1793100005,\"ble\":{\"total\":1,");
    WT_HAS(body_of(g_out), "02:00:00:00:00:a1");
    WT_EQ(route(&H, "/api/radar", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"ble\":{\"total\":1,");
    WT_EQ(route(&H, "/api/radar", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"the Wi-Fi and BLE distance bands are the passive monitor radio");
    WT_LACKS(body_of(g_out), "02:de:00:00:00:01");
    WT_LACKS(body_of(g_out), "02:00:00:00:00:a1");
    WT_LACKS(body_of(g_out), "\"bands\"");
    WT_EQ(route(&H, "/api/radar", "scope=local&limit=1"), 400);
    WT_EQ(route(&H, "/api/radar", "limit=1"), 400);
    WT_HAS(body_of(g_out), "unknown_parameter");
    WT_EQ(route(&H, "/api/radar", "sort=rssi"), 400);
    WT_LACKS(body_of(g_out), "sort");
    WT_EQ(route(&H, "/api/radar", "scope=nowhere"), 400);
    WT_HAS(body_of(g_out), "bad_scope");
    /* HEAD answers the same status with no body. */
    web_req_t *rq = calloc(1, sizeof(*rq));
    WT_ASSERT(rq != NULL);
    if (rq) {
        web_resp_t r;
        snprintf(rq->path, sizeof(rq->path), "/api/radar");
        snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
        rq->host_count = 1;
        rq->is_head = 1;
        WT_EQ(web_route(rq, &H, 1, g_out, sizeof(g_out), &r), 0);
        WT_EQ(r.status, 200);
        g_out[r.out_len] = '\0';
        WT_LACKS(body_of(g_out), "\"ble\"");
        free(rq);
    }
}

/* The answer stays small whatever the tables hold. The bands alone:
 * every BLE row the table has (WEB_BLE_DEVICES) under 8 KB without the
 * recent list's names. The worst case: every BLE row and a full ledger
 * (WEB_FRRS_LEDGER_BSSID beacons, WEB_FRRS_LEDGER_STA probes), every
 * name and SSID 32 '<' (cut to 24, each escaped to six bytes), measured
 * and held under 48 KB, inside the 63 KB a body has behind its header.
 * The name cut keeps a long peer name to its first WEB_RADAR_NAME_MAX
 * octets on a code-point boundary. */
static void test_radar_size(void) {
    fresh();
    static const char *const BANDS[] = { "immediate", "near", "room", "building", "far" };
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "%02x:%02x:00:00:%02x:%02x", 0x02 + (i >> 14), (i >> 8) & 0xff, (i >> 8) & 0xff, i & 0xff);
        feed_ble(ble_line(addr, i & 1, "a name of some length here, thirty-two", -30 - i % 70, BANDS[i % 5]));
    }
    web_health_t H;
    health(&H);
    WT_EQ(route(&H, "/api/radar", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"ble\":{\"total\":1024,\"estimated\":1024,\"none\":0,");
    const char *dv = strstr(b, ",\"devs\":{\"ble\":[");
    WT_ASSERT(dv != NULL);
    if (dv) {
        fprintf(stderr, "    /api/radar bands with 1024 BLE rows: %zu bytes\n", (size_t)(dv - b));
        WT_ASSERT((size_t)(dv - b) < 8192);
        WT_EQ(count(dv, "\"addr\":"), WEB_RADAR_RECENT);
    }
    WT_HAS(b, "\"name\":\"a name of some length he\"");
    /* The worst case. */
    fresh();
    char lt[33];
    memset(lt, '<', 32);
    lt[32] = '\0';
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "02:%02x:00:00:00:%02x", i >> 8, i & 0xff);
        feed_ble(ble_line(addr, 0, lt, -30 - i % 70, BANDS[i % 5]));
    }
    for (int i = 0; i < WEB_FRRS_LEDGER_BSSID; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "02:00:00:01:%02x:%02x", i >> 8, i & 0xff);
        feed_rf(rf_line(1, mac, lt, -40 - i % 50, BANDS[i % 5]));
    }
    for (int i = 0; i < WEB_FRRS_LEDGER_STA; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "02:00:00:02:%02x:%02x", i >> 8, i & 0xff);
        feed_rf(rf_line(0, mac, "", -40 - i % 50, BANDS[i % 5]));
    }
    WT_EQ(route(&H, "/api/radar", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"ble\":{\"total\":1024,\"estimated\":1024,\"none\":0,");
    WT_HAS(b, "\"wifi\":{\"total\":1536,\"estimated\":1536,\"none\":0,");
    fprintf(stderr, "    /api/radar worst case (1024 BLE, a full ledger, names escaped): %zu bytes\n", strlen(b));
    WT_ASSERT(strlen(b) < 49152);
    WT_EQ(count(b, "\"addr\":"), 5 * WEB_RADAR_DEVS + WEB_RADAR_RECENT);
    WT_EQ(count(b, "\"mac\":"), 5 * WEB_RADAR_DEVS + WEB_RADAR_RECENT);
    WT_HAS(b, "\"name\":\"\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c"
              "\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\\u003c\",");
    WT_LACKS(b, "<");
    /* The cut is on a code-point boundary: a two-byte character at the
     * edge is dropped whole, never split. */
    fresh();
    feed_ble(ble_line("02:de:00:00:00:01", 0, "abcdefghijklmnopqrstuvw\xc3\xa9", -45, "near"));
    WT_EQ(route(&H, "/api/radar", ""), 200);
    WT_HAS(body_of(g_out), "\"name\":\"abcdefghijklmnopqrstuvw\"");
}

/* devs (owner request 2026-11-06): each family's WEB_RADAR_RECENT most
 * recently heard rows with an estimate, newest first, with sloth's
 * metres, band and trend; a row without an estimate never listed;
 * Local still out_of_scope. Seen red with recent_take()'s cap removed
 * (sixty listed) and with census_take()'s recent_take() moved outside
 * the band test (the unestimated rows listed). */
static void test_radar_recent(void) {
    fresh();
    char line[1024];
    /* Sixty BLE rows, each heard a second later than the last; the
     * table keeps the record's last_seen. */
    for (int i = 0; i < 60; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "02:de:00:00:03:%02x", i);
        snprintf(line, sizeof(line), "%s", ble_line(addr, 1, i == 59 ? "newest" : "", -40 - i % 30, "room"));
        char *p = strstr(line, "\"last_seen\":1793100000");
        char ts[32];
        snprintf(ts, sizeof(ts), "\"last_seen\":%lld", T - 100 + i);
        if (p) memcpy(p, ts, strlen(ts));
        feed_ble(line);
    }
    /* Newer than all of them but no estimate: never listed. */
    snprintf(line, sizeof(line), "%s", ble_line("02:de:00:00:04:01", 0, "noest", -41, ""));
    feed_ble(line);
    /* Wi-Fi: an AP with metres and a trend, a station whose trend word
     * is not sloth's, an AP without an estimate. */
    feed_rf(rf_line(1, "02:00:00:00:00:b1", "lab", -52, "room"));
    snprintf(line, sizeof(line), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:b2\","
             "\"signal_dbm\":-70,\"frame_count\":3,\"est_dist_m\":22.25,\"est_dist_band\":\"building\","
             "\"est_dist_trend\":\"wobbling\",\"est_ptx_source\":\"assumed\"}", T + 9);
    feed_rf(line);
    feed_rf(rf_line(1, "02:00:00:00:00:b3", "none", -45, ""));
    web_health_t H;
    health(&H);
    WT_EQ(route(&H, "/api/radar", ""), 200);
    const char *b = body_of(g_out);
    const char *dv = strstr(b, "\"devs\":{\"ble\":[");
    WT_ASSERT(dv != NULL);
    if (!dv) return;
    const char *wf = strstr(dv, "],\"wifi\":[");
    WT_ASSERT(wf != NULL);
    if (!wf) return;
    char seg[16384];
    snprintf(seg, sizeof(seg), "%.*s", (int)(wf - dv), dv);
    WT_EQ(count(seg, "\"addr\":"), WEB_RADAR_RECENT);
    /* Newest first: the row heard at T-41 leads, the oldest kept is
     * T-90 (rows T-100..T-91 fell off). The estimate as the table keeps
     * it: est_dist_dm 25 -> 2.5 m, sloth's trend word. */
    WT_HAS(seg, "\"devs\":{\"ble\":[{\"addr\":\"02:de:00:00:03:3b\",\"addr_type\":1,\"iface\":\"bluetooth-monitor\","
                "\"name\":\"newest\",\"m\":2.5,\"band\":\"room\",\"trend\":\"steady\",\"rssi\":-69,\"last_seen\":1793099959},"
                "{\"addr\":\"02:de:00:00:03:3a\",");
    WT_HAS(seg, "\"last_seen\":1793099910}");
    WT_LACKS(seg, "\"last_seen\":1793099909}");
    WT_LACKS(seg, "02:de:00:00:03:09\"");
    WT_LACKS(seg, "noest");
    WT_HAS(wf, "],\"wifi\":[{\"mac\":\"02:00:00:00:00:b2\",\"kind\":\"sta\",\"ssid\":\"\",\"m\":22.2,\"band\":\"building\","
               "\"trend\":\"\",\"rssi\":-70,\"ts\":1793100009},"
               "{\"mac\":\"02:00:00:00:00:b1\",\"kind\":\"ap\",\"ssid\":\"lab\",\"m\":6.0,\"band\":\"room\","
               "\"trend\":\"steady\",\"rssi\":-52,\"ts\":1793100000}]}}");
    WT_LACKS(wf, "02:00:00:00:00:b3");
    /* Local: the query checked, no row. */
    WT_EQ(route(&H, "/api/radar", "scope=local"), 200);
    WT_LACKS(body_of(g_out), "\"devs\"");
    WT_LACKS(body_of(g_out), "02:de:00:00:03:3b");
}

/* ── the page ─────────────────────────────────────────────────────── */

/* The module's text, from its banner to its export. */
static char *module(const char *p) {
    const char *s = strstr(p, "// slothweb: the Radar view");
    const char *m = strstr(p, "window.SlothRadar = { init: init, show: show, redraw: dirty };");
    if (!s || !m || s >= m) return NULL;
    size_t n = (size_t)(m - s);
    char *mod = malloc(n + 1);
    if (!mod) return NULL;
    memcpy(mod, s, n);
    mod[n] = '\0';
    return mod;
}

/* The tab after APRS and before TACDB, its click, show()'s hook, the
 * init line with the helpers lent, the view and its ids; no scoped-out
 * toggle (the satellites are every scope's), no control in the view
 * (test_prefs.c's census). */
static void test_radar_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-aprs\">APRS</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-radar\">Radar</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-tacdb\">TACDB</button></li>");
    WT_HAS(p, "  $(\"nav-radar\").addEventListener(\"click\", function () { show(\"radar\"); });");
    WT_HAS(p, "    if (v === \"radar\" && window.SlothRadar) SlothRadar.show();");
    WT_HAS(p, "  if (window.SlothRadar) SlothRadar.init({ el: el, set: set, getJSON: getJSON, theme: theme, tok: tok,\n"
              "    heat: heat, sizeCanvas: sizeCanvas, prefGet: prefGet, prefSet: prefSet, show: show,\n"
              "    openDrawer: openDrawer, openBleDrawer: openBleDrawer, scope: function () { return SCOPE; } });");
    WT_HAS(p, "               \"lookup\", \"tacdb\", \"ble\", \"gnss\", \"adsb\", \"aprs\", \"radar\"];");
    WT_HAS(p, "<div id=\"v-radar\" hidden>");
    WT_HAS(p, "<canvas id=\"radar-dome\" aria-label=");
    static const char *const ids[] = {
        "radar-head", "radar-note", "radar-cam", "radar-reset", "radar-north", "radar-top",
        "radar-zin", "radar-zout", "radar-side", "radar-side-name", "radar-side-kv",
        "radar-side-list", "radar-open", "radar-side-close", "radar-cap", "radar-full",
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        if (!strcmp(ids[i], "radar-note")) continue;     /* static text: not looked up */
        snprintf(want, sizeof(want), "\"%s\"", ids[i]);
        /* Looked up by the module, as $("id") or set("id", ...). */
        char *mod = module(p);
        WT_ASSERT(mod && strstr(mod, want));
        free(mod);
    }
    WT_HAS(p, "<dl class=\"radar-kv\" id=\"radar-side-kv\"></dl>");
    WT_HAS(p, "<div class=\"sub radar-ov radar-bl\" id=\"radar-cap\"></div>");
    /* The dome is the page (owner request 2026-11-06): the stage holds
     * the canvas full size and the rest floats over it; fit() gives the
     * stage the window below its top. */
    WT_HAS(p, "<section class=\"panel radar-stage\" id=\"radar-stage\">\n"
              "      <canvas id=\"radar-dome\"");
    WT_HAS(p, ".radar-stage { position: relative; padding: 0; overflow: hidden; height: 70vh; min-height: 320px; }");
    WT_HAS(p, "#radar-dome { position: absolute; inset: 0; display: block; width: 100%; height: 100%; touch-action: none; cursor: grab; }");
    WT_HAS(p, ".radar-ov { position: absolute; z-index: 1; background: var(--panel); border: 1px solid var(--rule); padding: 6px 8px; font-size: 12px; }");
    WT_HAS(p, "<div class=\"radar-ov radar-tr\" id=\"radar-side\" hidden>");
    WT_HAS(p, "<details class=\"radar-about\"><summary>about this view</summary><span class=\"sub\" id=\"radar-note\">");
    WT_HAS(p, "  function fit() {\n"
              "    var st = $(\"radar-stage\");\n"
              "    if (!st || full()) return;\n"
              "    var top = st.getBoundingClientRect().top + (window.scrollY || 0);\n"
              "    var h = Math.max(320, Math.floor(window.innerHeight - top - 12)) + \"px\";\n"
              "    if (st.style.height !== h) st.style.height = h;\n"
              "  }");
    WT_HAS(p, "    if (!cv || !H) return;\n    fit();\n");
    /* Full screen, the dome alone (owner request 2026-11-06): the stage
     * through the Fullscreen API, every panel over it hidden there, f or
     * the button toggles, fit() stands aside while it is up. */
    WT_HAS(p, "          <button type=\"button\" id=\"radar-full\">full screen</button>\n");
    WT_HAS(p, "  function full() { return document.fullscreenElement === $(\"radar-stage\"); }\n"
              "  function toggleFull() {\n"
              "    var st = $(\"radar-stage\");\n"
              "    if (!st || !document.fullscreenEnabled) return;\n"
              "    if (full()) document.exitFullscreen();\n"
              "    else st.requestFullscreen().then(function () { $(\"radar-dome\").focus(); }, function () {});\n"
              "  }");
    WT_HAS(p, "    if (!st || full()) return;");
    WT_HAS(p, "      else if (k === \"f\") toggleFull();");
    WT_HAS(p, ".radar-stage:fullscreen .radar-ov { display: none; }");
    WT_HAS(p, ".radar-stage:fullscreen { height: 100% !important; width: 100%; border: 0; background: var(--bg); }");
    /* The two includes in their places: the CSS after bledev's, the
     * script after bledev.js (after app.js). */
    const char *bcss = strstr(p, "canvas.wfall.bledev-classes"), *rcss = strstr(p, ".radar-stage { position: relative;");
    WT_ASSERT(bcss && rcss && bcss < rcss);
    const char *bjs = strstr(p, "window.SlothBleDev = {"), *rjs = strstr(p, "// slothweb: the Radar view");
    const char *ajs = strstr(p, "window.SlothRadar) SlothRadar.init(");
    WT_ASSERT(bjs && rjs && ajs && ajs < bjs && bjs < rjs);
    /* No scoped-out toggle for the view, and the comment saying why. */
    WT_LACKS(p, "$(\"v-radar\").classList.toggle(\"scoped-out\"");
    WT_HAS(p, "    // No scoped-out toggle for v-radar: the satellites it draws are the\n");
    /* No control inside the view: its five buttons carry no ARIA state. */
    const char *v = strstr(p, "<div id=\"v-radar\" hidden>"), *vend = v ? strstr(v, "<div id=\"v-wifi\" hidden>") : NULL;
    WT_ASSERT(v && vend);
    if (v && vend) {
        size_t n = (size_t)(vend - v);
        char *view = malloc(n + 1);
        WT_ASSERT(view != NULL);
        if (view) {
            memcpy(view, v, n);
            view[n] = '\0';
            /* One control (owner request 2026-11-06, "a setting that
             * defaults to one hour for APRS objects"): the APRS window,
             * kept by keepCtl (test_prefs.c's census lists it). No other:
             * the camera is kept by its prefs, not by controls. Seen red
             * with a second <select id="radar-x"> added. */
            WT_EQ(count(view, "<select"), 1);
            WT_HAS(view, "<select id=\"radar-aprs-win\">");
            WT_LACKS(view, "<input");
            WT_LACKS(view, "<textarea");
            WT_LACKS(view, "aria-pressed");
            WT_LACKS(view, "aria-checked");
            WT_EQ(count(view, "<button type=\"button\" id=\"radar-"), 8);   /* + full screen */
            WT_EQ(count(view, "<canvas"), 1);
            free(view);
        }
    }
}

/* The projection, whole: the log range with its 0.3 m floor and 300 km
 * ceiling, the haversine range and forward azimuth, the placement at
 * the true (az, el) with the compressed slant range, the orthographic
 * camera (no divide by depth: equal ranges stay equal on screen), the
 * ring's ellipse distance. */
static void test_radar_projection_js(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  var R_MIN = 0.3, R_MAX = 300000;\n"
              "  var LOG_MIN = Math.log(R_MIN) / Math.LN10, LOG_SPAN = Math.log(R_MAX) / Math.LN10 - LOG_MIN;\n"
              "  var RINGS = [1, 10, 100, 1000, 10000, 100000];\n"
              "  var EARTH_M = 6371008.8, FT_M = 0.3048, ALT_SPAN_FT = 45000, CN0_SPAN = 50;\n"
              "  var PITCH_MIN = 10, PITCH_MAX = 90, PITCH_DFLT = 55, ZOOM_MIN = 0.5, ZOOM_MAX = 4, ZOOM_STEP = 1.1;\n");
    WT_HAS(p, "  function rn(m) {\n"
              "    if (!(m > 0)) return 0;\n"
              "    var f = (Math.log(m) / Math.LN10 - LOG_MIN) / LOG_SPAN;\n"
              "    return f < 0 ? 0 : f > 1 ? 1 : f;\n"
              "  }");
    WT_HAS(p, "  function geo(lat0, lon0, lat, lon) {\n"
              "    var d = Math.PI / 180, p0 = lat0 * d, p1 = lat * d, dl = (lon - lon0) * d, dp = p1 - p0;\n"
              "    var a = Math.sin(dp / 2) * Math.sin(dp / 2) + Math.cos(p0) * Math.cos(p1) * Math.sin(dl / 2) * Math.sin(dl / 2);\n"
              "    var range = 2 * EARTH_M * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));\n"
              "    var y = Math.sin(dl) * Math.cos(p1), x = Math.cos(p0) * Math.sin(p1) - Math.sin(p0) * Math.cos(p1) * Math.cos(dl);\n"
              "    var az = Math.atan2(y, x) / d;\n"
              "    return { range: range, az: (az + 360) % 360 };\n"
              "  }");
    WT_HAS(p, "  function place(az, el, m) {\n"
              "    var d = Math.PI / 180, r = rn(m), a = az * d, e = el * d;\n"
              "    return [r * Math.cos(e) * Math.sin(a), r * Math.cos(e) * Math.cos(a), r * Math.sin(e)];\n"
              "  }");
    WT_HAS(p, "  function project(p, cam) {\n"
              "    var d = Math.PI / 180, cy = Math.cos(cam.yaw * d), sy = Math.sin(cam.yaw * d);\n"
              "    var sp = Math.sin(cam.pitch * d), cp = Math.cos(cam.pitch * d);\n"
              "    var xr = p[0] * cy - p[1] * sy, yr = p[0] * sy + p[1] * cy;\n"
              "    return { x: cam.cx + cam.S * xr, y: cam.cy - cam.S * (yr * sp + p[2] * cp), depth: yr * cp - p[2] * sp };\n"
              "  }");
    WT_HAS(p, "  function ringDist(x, y, r, cam) {\n"
              "    var a = cam.S * r, b = a * Math.sin(cam.pitch * Math.PI / 180);\n"
              "    var dx = x - cam.cx, dy = y - cam.cy;\n"
              "    if (!(a > 0) || !(b > 0)) return Math.sqrt(dx * dx + dy * dy);\n"
              "    var t = Math.atan2(dy / b, dx / a);\n"
              "    var ex = a * Math.cos(t), ey = b * Math.sin(t);\n"
              "    return Math.sqrt((dx - ex) * (dx - ex) + (dy - ey) * (dy - ey));\n"
              "  }");
    /* Orthographic: nothing in project() divides by the depth. */
    const char *pj = strstr(p, "  function project(p, cam) {");
    const char *pe = pj ? strstr(pj, "\n  }\n") : NULL;
    WT_ASSERT(pj && pe);
    if (pj && pe) {
        size_t n = (size_t)(pe - pj);
        char *fn = malloc(n + 1);
        WT_ASSERT(fn != NULL);
        if (fn) {
            memcpy(fn, pj, n);
            fn[n] = '\0';
            WT_LACKS(fn, "/ depth");
            WT_LACKS(fn, "/ (");
            WT_LACKS(fn, "/ p[");
            free(fn);
        }
    }
    /* Every family through the one rule: satellites at R_MAX, aircraft
     * and stations through locate(), the rings through rn(). */
    WT_HAS(p, "      var p = project(place(s.az, Math.max(0, s.el), R_MAX), cam);");
    WT_HAS(p, "    return { az: gr.az, range: gr.range, h: h, el: el, slant: slant,\n"
              "             p: place(gr.az, el, slant), foot: place(gr.az, 0, gr.range) };");
    WT_HAS(p, "        var r = rn(BAND_R[i]), on = isSel(\"ring\", { fam: fam[0], band: i });");
    WT_HAS(p, "  var BAND_R = [1, 3, 10, 30, 100];");
}

/* The marks are shapes drawn as paths (R1, R10), the rings translucent
 * lines (Wi-Fi solid, BLE dashed) labelled with the family word and
 * the count; nothing in the module uses a gradient or a shadow (R8). */
static void test_radar_marks_are_shapes(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function diamond(g, x, y, s, fill) {\n"
              "    g.beginPath();\n"
              "    g.moveTo(x, y - s); g.lineTo(x + s, y); g.lineTo(x, y + s); g.lineTo(x - s, y);\n"
              "    g.closePath();\n"
              "    if (fill) g.fill(); else g.stroke();\n"
              "  }");
    WT_HAS(p, "  function tri(g, x, y, s, heading, fill) {\n"
              "    var a = (heading - 90) * Math.PI / 180, c = Math.cos(a), sn = Math.sin(a);\n"
              "    g.beginPath();\n"
              "    g.moveTo(x + s * c, y + s * sn);\n"
              "    g.lineTo(x + s * (-0.6 * c - 0.6 * sn), y + s * (-0.6 * sn + 0.6 * c));\n"
              "    g.lineTo(x + s * (-0.6 * c + 0.6 * sn), y + s * (-0.6 * sn - 0.6 * c));\n"
              "    g.closePath();\n"
              "    if (fill) g.fill(); else g.stroke();\n"
              "  }");
    WT_HAS(p, "  function ring(g, x, y, s) {\n"
              "    g.beginPath();\n"
              "    g.arc(x, y, s, 0, Math.PI * 2);\n"
              "    g.stroke();\n"
              "  }");
    WT_HAS(p, "        if (fam[0] === \"ble\") g.setLineDash([6, 4]); else g.setLineDash([]);\n"
              "        g.lineWidth = on ? 2 * dpr : 1;\n"
              "        g.globalAlpha = on ? 1 : 0.09;\n"
              "        g.strokeStyle = on ? T.signal : T.normal;\n"
              "        groundPath(g, cam, r, 0);\n"
              "        g.stroke();");
    WT_HAS(p, "    [[\"wifi\", \"Wi-Fi \"], [\"ble\", \"BLE \"]].forEach(function (fam) {");
    WT_HAS(p, "        var txt = fam[1] + BANDS[i] + \" \" + band.n, ble = fam[0] === \"ble\";\n"
              "        want.push({ x: cam.cx + (ble ? -1 : 1) * R * r, y: cam.cy, text: txt, left: ble,\n"
              "                    pri: on ? PRI.sel : PRI.band, color: on ? T.signal : T.muted, alpha: 1 });");
    /* The selection is the one accent; gone or stale is 0.35. */
    WT_HAS(p, "      var col = on ? T.signal : num(s.cn0) ? H.heat(s.cn0 / CN0_SPAN) : T.dim;");
    WT_HAS(p, "      var alpha = gone ? 0.35 : L.range > R_MAX ? 0.5 : 1;");
    WT_HAS(p, "      if (stale(s.ts, now)) alpha = 0.35;");
    WT_HAS(p, "      diamond(g, p.x, p.y, (s.used ? 5 : 4) * dpr, !!s.used);");
    WT_HAS(p, "      tri(g, p.x, p.y, 6 * dpr, dir ? Math.atan2(dir.dy, dir.dx) / d + 90 : 0, true);");
    WT_HAS(p, "      if (e.kind === \"object\") cross(g, p.x, p.y, 4 * dpr); else ring(g, p.x, p.y, 5 * dpr);");
    char *mod = module(p);
    WT_ASSERT(mod != NULL);
    if (mod) {
        WT_LACKS(mod, "createLinearGradient");
        WT_LACKS(mod, "createRadialGradient");
        WT_LACKS(mod, "createPattern");
        WT_LACKS(mod, "shadowBlur");
        WT_LACKS(mod, "shadowColor");
        /* No markup from a string, no attribute write, no absolute
         * address, no timer from a string (test_routes.c's bans, held
         * here on the module alone so a mutation is named). */
        WT_LACKS(mod, "innerHTML");
        WT_LACKS(mod, "insertAdjacentHTML");
        WT_LACKS(mod, "setAttribute(");
        WT_LACKS(mod, "http:");
        WT_LACKS(mod, "https:");
        WT_LACKS(mod, "setTimeout(");
        /* Every DOM string through textContent (H.el / H.set); the
         * canvas's peer strings through fillText. */
        WT_HAS(mod, "    b.textContent = label ? \"open in \" + label : \"\";");
        WT_HAS(mod, "H.el(\"dd\", \"\", p[1])");
        WT_LACKS(mod, "el(\"select\"");
        WT_LACKS(mod, "el(\"input\"");
        free(mod);
    }
}

/* The camera's kept state: three prefs, validated on read (a number in
 * range, else the default) and cleared, not zeroed, on reset; the
 * selection is never kept. */
static void test_radar_prefs(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function prefNum(name, lo, hi, dflt) {\n"
              "    var v = H.prefGet(name);\n"
              "    return typeof v === \"number\" && isFinite(v) && v >= lo && v <= hi ? v : dflt;\n"
              "  }");
    WT_HAS(p, "  function savePrefs() {\n"
              "    H.prefSet(\"radar.yaw\", S.yaw);\n"
              "    H.prefSet(\"radar.pitch\", S.pitch);\n"
              "    H.prefSet(\"radar.zoom\", S.zoom);\n"
              "  }");
    WT_HAS(p, "  function resetCam() {\n"
              "    S.yaw = 0; S.pitch = PITCH_DFLT; S.zoom = 1;\n"
              "    H.prefSet(\"radar.yaw\", null);\n"
              "    H.prefSet(\"radar.pitch\", null);\n"
              "    H.prefSet(\"radar.zoom\", null);\n"
              "    dirty();\n"
              "  }");
    WT_HAS(p, "    S.yaw = prefNum(\"radar.yaw\", 0, 360, 0);\n"
              "    S.pitch = prefNum(\"radar.pitch\", PITCH_MIN, PITCH_MAX, PITCH_DFLT);\n"
              "    S.zoom = prefNum(\"radar.zoom\", ZOOM_MIN, ZOOM_MAX, 1);");
    WT_LACKS(p, "prefSet(\"radar.sel\"");
    /* Drawn only when dirty, through one requestAnimationFrame. */
    WT_HAS(p, "  function dirty() {\n"
              "    if (S.raf || !visible()) return;\n"
              "    S.raf = window.requestAnimationFrame(draw);\n"
              "  }");
    char *mod = module(p);
    WT_ASSERT(mod != NULL);
    if (mod) {
        WT_EQ(count(mod, "requestAnimationFrame("), 1);
        WT_EQ(count(mod, "setInterval("), 1);
        /* The pointer and wheel rules: capture, the tap threshold, the
         * non-passive wheel, the canvas focusable for its keys. */
        WT_HAS(mod, "      if (cv.setPointerCapture) cv.setPointerCapture(ev.pointerId);");
        WT_HAS(mod, "    }, { passive: false });");
        WT_HAS(mod, "    cv.tabIndex = 0;");
        WT_HAS(mod, "  var STALE_S = 600, FIX_FRESH_S = 60, PICK_PX = 8, TAP_PX = 4, LABEL_ZOOM = 0.7;");
        free(mod);
    }
}

/* The Local sentence and the estimate sentences verbatim; the centre
 * rule (a fresh fix, else loc, else none); the ring loader's
 * out_of_scope handling and the three passive fetches skipped under
 * Local; every fetch through the lent (scoped) getJSON. */
static void test_radar_scope_and_caption(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "\"Local: only the host's own receiver (satellites). Aircraft, APRS, Wi-Fi monitor and BLE are "
              "the passive radios' \xe2\x80\x94 switch to Monitor or Hybrid\"");
    WT_HAS(p, "    parts.push(\"range log 0.3 m\xe2\x80\x93" "300 km; height is true elevation angle\");");
    WT_HAS(p, "      parts.push(\"distance from signal strength is an estimate; a ring is where the device may be, not where it is\");");
    WT_HAS(p, "\" Wi-Fi, \" + (rd.ble ? rd.ble.none : 0) + \" BLE without a distance estimate\"");
    WT_HAS(p, "      h.appendChild(H.el(\"b\", \"h2\", \"no sensor position: aircraft and APRS not placed\"));");
    WT_HAS(p, "    if (f && num(f.mode) && f.mode >= 2 && num(f.lat) && num(f.lon) && num(f.ts) && now - f.ts <= FIX_FRESH_S)\n"
              "      return { lat: f.lat, lon: f.lon, alt: num(f.alt_m) ? f.alt_m : null, from: \"gps fix\", age: now - f.ts };\n"
              "    if (l && num(l.lat) && num(l.lon))\n"
              "      return { lat: l.lat, lon: l.lon, alt: num(l.alt_m) ? l.alt_m : null,\n"
              "               from: l[\"src\"] === \"gps\" ? \"last gps fix\" : \"--location\", age: num(l.ts) ? now - l.ts : null };\n"
              "    return null;");
    WT_HAS(p, "        if (j.out_of_scope) { S.radar = null; after(); return; }");
    WT_HAS(p, "    if (local) {\n"
              "      S.adsb = S.aprs = S.radar = S.atrk = null;\n"
              "      S.radarAt = S.atrkAt = 0;\n"
              "      after();\n"
              "      return;\n"
              "    }");
    char *mod = module(p);
    WT_ASSERT(mod != NULL);
    if (mod) {
        /* Every fetch is the page's scoped getJSON; the module has no
         * fetch of its own. */
        WT_LACKS(mod, "fetch(");
        WT_EQ(count(mod, "H.getJSON(\"/api/gnss\")"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/adsb\")"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/aprs\")"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/radar\")"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/gnss/tracks?hours=\" + TRAIL_H)"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/aprs?call=\" + encodeURIComponent(call))"), 1);
        WT_EQ(count(mod, "H.getJSON(\"/api/aprs/tracks?hours=\" + ATRK_H)"), 1);
        WT_EQ(count(mod, "H.getJSON("), 7);
        WT_HAS(mod, "  var POLL_MS = 5000, RADAR_MS = 10000, TRAIL_MS = 60000, TRAIL_H = 6;");
        free(mod);
    }
}

/* The three select() hooks the dome's "open in" calls: each module
 * exports it beside show(), each applies a row it already has and
 * leaves one it does not for the next load. */
static void test_select_hooks(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  window.SlothAdsb = { show: show, select: select };");
    WT_HAS(p, "  window.SlothGnss = { show: show, select: select };");
    WT_HAS(p, "  window.SlothAprs = { show: show, select: select };");
    WT_HAS(p, "  function select(hex) {\n"
              "    if (typeof hex !== \"string\" || !/^~?[0-9a-f]{6}$/.test(hex)) return;\n"
              "    sel = hex;\n"
              "    var cur = rows.filter(function (a) { return a.hex === hex; })[0];\n"
              "    if (cur) detail(cur, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));\n"
              "    drawRows();\n"
              "    histLoad(hex);\n"
              "    if (last) plot(last);\n"
              "  }");
    WT_HAS(p, "  function select(gnssid, prn) {\n"
              "    if (!num(gnssid) || !num(prn)) return;\n"
              "    sel = { gnssid: gnssid, prn: prn };\n"
              "    var cur = rows.filter(function (s) { return s.gnssid === gnssid && s.prn === prn; })[0];\n"
              "    if (cur) {\n"
              "      detail(cur, num(last && last.now) ? last.now : Math.floor(Date.now() / 1000));\n"
              "      hist(gnssid, prn, (cur.id || cur.gnss + \" PRN \" + cur.prn) + (cur.veh ? \" \" + cur.veh.name : \"\"));\n"
              "    }\n"
              "    drawRows();\n"
              "    if (last) sky(last);\n"
              "  }");
    WT_HAS(p, "  function select(call) {\n"
              "    if (typeof call !== \"string\" || !call) return;\n"
              "    sel = call;\n"
              "    selLive = null;");
    /* The dome's side: the tab first, then the family's own pick. */
    WT_HAS(p, "    if (s.kind === \"sat\") { H.show(\"gnss\"); if (window.SlothGnss && SlothGnss.select) SlothGnss.select(ref.gnssid, ref.prn); }\n"
              "    else if (s.kind === \"adsb\") { H.show(\"adsb\"); if (window.SlothAdsb && SlothAdsb.select) SlothAdsb.select(ref.hex); }\n"
              "    else if (s.kind === \"aprs\") { H.show(\"aprs\"); if (window.SlothAprs && SlothAprs.select) SlothAprs.select(ref.kind === \"object\" ? ref.via : ref.key); }\n"
              "    else if (s.kind === \"ring\") H.show(s.key.fam === \"ble\" ? \"ble\" : \"devices\");");
    WT_HAS(p, "          if (ble) { H.show(\"ble\"); H.openBleDrawer(dv.addr, dv.addr_type, dv.iface); }\n"
              "          else { H.show(\"devices\"); H.openDrawer(dv.mac); }");
}

/* The devices on the north axis, the label layout and the velocity
 * tick (owner request 2026-11-06), whole: the layout's four functions,
 * the tick's four, the device helpers and painters, the device, aircraft
 * and APRS draw blocks, picking a stacked label first, "open in".
 *
 * What the pins prove and what they do not: a C test cannot run the
 * script, so "no label ever overlaps another" is held by construction
 * and pinned, not executed: put() is the only fillText in the module
 * (counted: one), and put() refuses a box that is off the canvas or hits
 * any placed box (boxHit, pinned whole), so whatever order or offsets
 * the placers propose, a drawn label never touches another. The pins do
 * not prove the layout is good (how many labels find room): that was
 * measured by hand with a stub canvas (50 + 50 devices, 67 of the
 * labels drawn on an 800 x 440 canvas, 0 overlapping). Seen red with a
 * second fillText added to draw() (the count) and with put()'s boxHit
 * test dropped (the drawLabels pin). */
static void test_radar_devices_js(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function boxHit(b, boxes) {\n"
              "    for (var k = 0; k < boxes.length; k++) {\n"
              "      var o = boxes[k];\n"
              "      if (b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0) return true;\n"
              "    }\n"
              "    return false;\n"
              "  }");
    WT_HAS(p, "  function stackColumn(ys, h, gap, top, bottom) {\n"
              "    var out = [], n = ys.length, step = h + gap, i;\n"
              "    for (i = 0; i < n; i++) out.push(Math.max(ys[i], top, i ? out[i - 1] + step : top));\n"
              "    if (n && out[n - 1] > bottom) {\n"
              "      out[n - 1] = bottom;\n"
              "      for (i = n - 2; i >= 0; i--) out[i] = Math.min(out[i], out[i + 1] - step);\n"
              "    }\n"
              "    return out;\n"
              "  }");
    WT_HAS(p, "  function candidates(x, y, w, h, r, left) {\n"
              "    var D = left ? [[-1, -1], [-1, 1], [-1, 0], [1, -1], [1, 1], [1, 0], [0, -1], [0, 1]]\n"
              "                 : [[1, -1], [1, 1], [1, 0], [-1, -1], [-1, 1], [-1, 0], [0, -1], [0, 1]];\n"
              "    return D.map(function (d) {\n"
              "      var x0 = d[0] > 0 ? x + r : d[0] < 0 ? x - r - w : x - w / 2;\n"
              "      var y0 = d[1] > 0 ? y + r : d[1] < 0 ? y - r - h : y - h / 2;\n"
              "      return { x0: x0, y0: y0, x1: x0 + w, y1: y0 + h };\n"
              "    });\n"
              "  }");
    WT_HAS(p, "  function drawLabels(g, want, dpr, W, Hh, T, blocked) {\n"
              "    var boxes = (blocked || []).slice(), h = 12 * dpr, gap = 2 * dpr;\n"
              "    g.textAlign = \"left\";\n"
              "    g.textBaseline = \"top\";\n"
              "    want.forEach(function (w) { w.w = g.measureText(w.text).width; });\n"
              "    want.sort(function (a, b) { return a.pri - b.pri; });\n"
              "    function put(w, b, lead) {\n"
              "      if (b.x0 < 0 || b.y0 < 0 || b.x1 > W || b.y1 > Hh || boxHit(b, boxes)) return false;\n"
              "      boxes.push(b);\n"
              "      g.globalAlpha = w.alpha;\n"
              "      if (lead) {\n"
              "        g.strokeStyle = T.rule;\n"
              "        g.lineWidth = dpr;\n"
              "        g.setLineDash([]);\n"
              "        polyline(g, [{ x: w.x, y: w.y }, { x: w.x < b.x0 ? b.x0 : w.x > b.x1 ? b.x1 : (b.x0 + b.x1) / 2, y: (b.y0 + b.y1) / 2 }]);\n"
              "      }\n"
              "      g.fillStyle = w.color;\n"
              "      g.fillText(w.text, b.x0, b.y0 + dpr);\n"
              "      g.globalAlpha = 1;\n"
              "      if (w.pick) S.labelPicks.push({ box: b, pick: w.pick });\n"
              "      return true;\n"
              "    }\n"
              "    function greedy(w) {\n"
              "      var radii = [6 * dpr, 16 * dpr], cs, i, k;\n"
              "      for (i = 0; i < radii.length; i++) {\n"
              "        cs = candidates(w.x, w.y, w.w, h, radii[i], w.left);\n"
              "        for (k = 0; k < cs.length; k++) if (put(w, cs[k], false)) return;\n"
              "      }\n"
              "      // No room for the long form: the short one, from the start.\n"
              "      if (w.alt) {\n"
              "        w.text = w.alt;\n"
              "        w.alt = null;\n"
              "        w.w = g.measureText(w.text).width;\n"
              "        greedy(w);\n"
              "        return;\n"
              "      }\n"
              "      if (w.pri > PRI.aprs) return;\n"
              "      cs = candidates(w.x, w.y, w.w, h, 30 * dpr, w.left);\n"
              "      for (k = 0; k < cs.length; k++) if (put(w, cs[k], true)) return;\n"
              "    }\n"
              "    function column(items, right) {\n"
              "      if (!items.length) return;\n"
              "      items.sort(function (a, b) { return a.y - b.y; });\n"
              "      var xs = items.map(function (w) { return w.x; }), ws = items.map(function (w) { return w.w; });\n"
              "      var maxw = Math.max.apply(null, ws);\n"
              "      var cx = right ? Math.min(Math.max.apply(null, xs) + 10 * dpr, W - maxw - 2 * dpr)\n"
              "                     : Math.max(Math.min.apply(null, xs) - 10 * dpr, maxw + 2 * dpr);\n"
              "      var ys = stackColumn(items.map(function (w) { return w.y + h / 2; }), h, gap, h, Hh);\n"
              "      items.forEach(function (w, i) {\n"
              "        put(w, { x0: right ? cx : cx - w.w, x1: right ? cx + w.w : cx, y0: ys[i] - h, y1: ys[i] }, true);\n"
              "      });\n"
              "    }\n"
              "    want.filter(function (w) { return w.fixed; }).forEach(function (w) {\n"
              "      put(w, { x0: w.x - w.w / 2, y0: w.y - h / 2, x1: w.x + w.w / 2, y1: w.y + h / 2 }, false);\n"
              "    });\n"
              "    want.filter(function (w) { return !w.fixed && !w.col && w.pri <= PRI.aprs; }).forEach(greedy);\n"
              "    column(want.filter(function (w) { return w.col === \"R\"; }), true);\n"
              "    column(want.filter(function (w) { return w.col === \"L\"; }), false);\n"
              "    want.filter(function (w) { return !w.fixed && !w.col && w.pri > PRI.aprs; }).forEach(greedy);\n"
              "  }");
    WT_HAS(p, "  function tickDir(az, m, hdg, cam) {\n"
              "    var d = Math.PI / 180, s = Math.max(1, m * 0.02);\n"
              "    var e = m * Math.sin(az * d), n = m * Math.cos(az * d);\n"
              "    var e2 = e + s * Math.sin(hdg * d), n2 = n + s * Math.cos(hdg * d);\n"
              "    var a = project(place(az, 0, m), cam);\n"
              "    var b = project(place(Math.atan2(e2, n2) / d, 0, Math.sqrt(e2 * e2 + n2 * n2)), cam);\n"
              "    var dx = b.x - a.x, dy = b.y - a.y, l = Math.sqrt(dx * dx + dy * dy);\n"
              "    return l > 1e-6 ? { dx: dx / l, dy: dy / l } : null;\n"
              "  }");
    WT_HAS(p, "  function tickLen(kt) {\n"
              "    return Math.min(30, 6 + 14 * Math.log(1 + kt / 10) / Math.LN10);\n"
              "  }");
    WT_HAS(p, "  function velTick(g, p, dir, kt, dpr) {\n"
              "    var l = tickLen(kt) * dpr;\n"
              "    g.beginPath();\n"
              "    g.moveTo(p.x, p.y);\n"
              "    g.lineTo(p.x + dir.dx * l, p.y + dir.dy * l);\n"
              "    g.stroke();\n"
              "  }");
    WT_HAS(p, "  function velText(kt, hdg) {\n"
              "    var h = String(Math.round(hdg) % 360);\n"
              "    while (h.length < 3) h = \"0\" + h;\n"
              "    return Math.round(kt) + \" kt \" + h + \"\\u00b0\";\n"
              "  }");
    WT_HAS(p, "  function devM(dv) {\n"
              "    if (num(dv.m)) return dv.m;\n"
              "    var i = BANDS.indexOf(dv.band);\n"
              "    return i >= 0 ? BAND_R[i] : null;\n"
              "  }");
    WT_HAS(p, "  function devKey(fam, dv) { return fam === \"ble\" ? dv.addr + \"/\" + dv.addr_type + \"/\" + dv.iface : dv.mac; }\n"
              "  function trendGlyph(t) { return Object.prototype.hasOwnProperty.call(TREND_GLYPH, t) ? TREND_GLYPH[t] : \"\"; }\n"
              "  // Compact: a name or SSID cut to 12, else the address's last three\n"
              "  // octets; the distance and sloth's trend glyph.\n"
              "  function devLabel(fam, dv) {\n"
              "    var nm = fam === \"ble\" ? dv.name : dv.ssid, ad = String((fam === \"ble\" ? dv.addr : dv.mac) || \"\");\n"
              "    var id = nm ? (nm.length > 12 ? nm.slice(0, 11) + \"\\u2026\" : nm) : ad.slice(-8), gl = trendGlyph(dv.trend);\n"
              "    return id + \" ~\" + metres(devM(dv)) + (gl ? \" \" + gl : \"\");\n"
              "  }");
    WT_HAS(p, "  function overlayBoxes(cv) {\n"
              "    var cb = cv.getBoundingClientRect(), sx = cv.width / Math.max(1, cb.width), sy = cv.height / Math.max(1, cb.height);\n"
              "    var out = [], ov = document.querySelectorAll(\"#radar-stage .radar-ov\");\n"
              "    for (var i = 0; i < ov.length; i++) {\n"
              "      if (ov[i].hidden || !ov[i].offsetParent) continue;\n"
              "      var r = ov[i].getBoundingClientRect();\n"
              "      out.push({ x0: (r.left - cb.left) * sx, y0: (r.top - cb.top) * sy, x1: (r.right - cb.left) * sx, y1: (r.bottom - cb.top) * sy });\n"
              "    }\n"
              "    return out;\n"
              "  }");
    WT_HAS(p, "  function square(g, x, y, s) {\n"
              "    g.beginPath();\n"
              "    g.rect(x - s, y - s, 2 * s, 2 * s);\n"
              "    g.fill();\n"
              "  }");
    WT_HAS(p, "  function dot(g, x, y, s) {\n"
              "    g.beginPath();\n"
              "    g.arc(x, y, s, 0, Math.PI * 2);\n"
              "    g.fill();\n"
              "  }");
    WT_HAS(p, "    var shown = { ble: 0, wifi: 0 };\n"
              "    [[\"wifi\", \"R\"], [\"ble\", \"L\"]].forEach(function (fam) {\n"
              "      var list = (S.radar && S.radar.devs && S.radar.devs[fam[0]]) || [];\n"
              "      list.forEach(function (dv, idx) {\n"
              "        var m = devM(dv);\n"
              "        if (!num(m)) return;\n"
              "        shown[fam[0]]++;\n"
              "        var key = devKey(fam[0], dv), on = isSel(fam[0], key), ble = fam[0] === \"ble\";\n"
              "        var hov = !!S.hover && S.hover.kind === fam[0] && S.hover.key === key;\n"
              "        var old = stale(ble ? dv.last_seen : dv.ts, now), col = on ? T.signal : T.normal;\n"
              "        if (ble) g.setLineDash([6, 4]); else g.setLineDash([]);\n"
              "        g.lineWidth = 1;\n"
              "        g.globalAlpha = on ? 0.6 : old ? 0.06 : 0.15;\n"
              "        g.strokeStyle = col;\n"
              "        groundPath(g, cam, rn(m), 0);\n"
              "        g.stroke();\n"
              "        g.setLineDash([]);\n"
              "        var p = project(place(0, 0, m), cam);\n"
              "        g.globalAlpha = old ? 0.35 : 1;\n"
              "        g.fillStyle = col;\n"
              "        if (ble) dot(g, p.x, p.y, 3 * dpr); else square(g, p.x, p.y, 3 * dpr);\n"
              "        g.globalAlpha = 1;\n"
              "        S.marks.push({ x: p.x, y: p.y, kind: fam[0], key: key, ref: dv });\n"
              "        if (idx < LABEL_N || on || hov)\n"
              "          want.push({ x: p.x, y: p.y, col: fam[1], text: devLabel(fam[0], dv), pri: on || hov ? PRI.sel : PRI.dev,\n"
              "                      color: on ? T.signal : hov ? T.ink : T.muted, alpha: old && !hov ? 0.35 : 1,\n"
              "                      pick: { kind: fam[0], key: key } });\n"
              "      });\n"
              "    });\n"
              "    g.lineWidth = dpr;\n"
              "");
    WT_HAS(p, "      var mv = num(a.gs) && a.gs > 0 && num(a.track);\n"
              "      var dir = num(a.track) ? tickDir(L.az, L.range, a.track, cam) : null;\n"
              "      tri(g, p.x, p.y, 6 * dpr, dir ? Math.atan2(dir.dy, dir.dx) / d + 90 : 0, true);\n"
              "      if (mv && dir) velTick(g, p, dir, a.gs, dpr);");
    WT_HAS(p, "      var mv = num(e.speed_kt) && e.speed_kt > 0 && num(e.course);\n"
              "      var dir = mv ? tickDir(L.az, L.range, e.course, cam) : null;\n"
              "      if (dir) velTick(g, p, dir, e.speed_kt, dpr);");
    WT_HAS(p, "    // A device's stacked label is its handle where dots crowd the axis.\n"
              "    for (var i = 0; i < S.labelPicks.length; i++) {\n"
              "      var b = S.labelPicks[i].box;\n"
              "      if (px >= b.x0 && px <= b.x1 && py >= b.y0 && py <= b.y1) return S.labelPicks[i].pick;\n"
              "    }\n"
              "    S.marks.forEach");
    WT_HAS(p, "    else if (s.kind === \"ble\") { H.show(\"ble\"); H.openBleDrawer(ref.addr, ref.addr_type, ref.iface); }\n"
              "    else if (s.kind === \"wifi\") { H.show(\"devices\"); H.openDrawer(ref.mac); }");
    WT_HAS(p, "  var TREND_GLYPH = { approaching: \"\\u2198\", steady: \"\\u2192\", leaving: \"\\u2197\" };");
    WT_HAS(p, "  var PRI = { sel: 0, air: 1, aprs: 2, dev: 3, satUsed: 4, sat: 5, band: 6, range: 7 };");
    WT_HAS(p, "    drawLabels(g, want, dpr, W, Hh, T, overlayBoxes(cv));\n");
    /* Device labels (owner ruling 2026-11-06): the 10 most recent of each
     * family labelled, any other while hovered or selected; no label
     * under a floating panel (overlayBoxes seeds the placer). */
    WT_HAS(p, "  var LABEL_N = 10;");
    WT_HAS(p, "      if (!dr) {\n"
              "        // Hover: a device dot under the pointer shows its label.\n"
              "        var pt = canvasPoint(ev, cv), pk = pickAt(pt[0], pt[1]);\n"
              "        var hv = pk && (pk.kind === \"ble\" || pk.kind === \"wifi\") ? pk : null;\n"
              "        var was = S.hover ? S.hover.kind + \"|\" + S.hover.key : \"\", now = hv ? hv.kind + \"|\" + hv.key : \"\";\n"
              "        if (was !== now) { S.hover = hv; dirty(); }\n"
              "        return;\n"
              "      }");
    WT_HAS(p, "    cv.addEventListener(\"pointerleave\", function () { if (S.hover) { S.hover = null; dirty(); } });");
    WT_HAS(p, "                  [\"placement\", \"distance from signal strength; no bearing: drawn on the north axis\"]]);");
    WT_HAS(p, "                   (rd.wifi ? rd.wifi.estimated : 0) + \" Wi-Fi shown (most recent), on the north axis: no bearing\");");
    WT_HAS(p, "      parts.push(\"ticks are speed and heading (aircraft gs/track, APRS speed/course); Wi-Fi and BLE have neither, \" +\n"
              "                 \"their arrow is sloth's trend (\\u2198 approaching, \\u2192 steady, \\u2197 leaving)\");");
    char *mod = module(p);
    WT_ASSERT(mod != NULL);
    if (mod) {
        WT_EQ(count(mod, "fillText("), 1);
        WT_EQ(count(mod, "strokeText("), 0);
        WT_LACKS(mod, "function labels(");
        free(mod);
    }
}

/* The APRS window and trails (owner request 2026-11-06: "a setting that
 * defaults to one hour for APRS objects and show trails if they are
 * moving for the last 24 hours"; "objects will update status regularly
 * but remain up to one hour before clearing after no transmission"),
 * whole: the window select (1 h selected) and its keepCtl entry; the
 * merge of sloth.db's entities with the live stations and the window
 * filter on the newest packet of any kind; the trail; the object's ✕;
 * the label with its status suffix and the short form the placer falls
 * back to; the 60 s loader; the panel's rows; the caption. Seen red
 * with aprsEntities()'s filter made `now - e.pos_ts` (a status-only
 * packet no longer kept an entity: the pin and the LACKS) and with the
 * trail's gap test dropped (the pin). */
static void test_radar_aprs_js(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<label class=\"sub\">APRS for <select id=\"radar-aprs-win\"><option value=\"900\">15 min</option>"
              "<option value=\"3600\" selected>1 h</option><option value=\"10800\">3 h</option>"
              "<option value=\"21600\">6 h</option><option value=\"86400\">24 h</option></select></label></div>");
    WT_HAS(p, "   \"aprs-seen-days\", \"aprs-seen-q\", \"radar-aprs-win\"].forEach(keepCtl);");
    WT_HAS(p, "  var APRS_WINS = [900, 3600, 10800, 21600, 86400], APRS_WIN_DFLT = 3600;");
    WT_HAS(p, "  var ATRK_H = 24, ATRK_MS = 60000;");
    WT_HAS(p, "    $(\"radar-aprs-win\").addEventListener(\"change\", function () { S.atrkAt = 0; load(); dirty(); });");
    WT_HAS(p, "    if (s.kind === \"aprs\") return S.aents.filter(function (x) { return x.id === s.key; })[0] || null;");
    WT_HAS(p, "  function aprsWin() {\n"
              "    var el = $(\"radar-aprs-win\"), v = el ? Number(el.value) : NaN;\n"
              "    return APRS_WINS.indexOf(v) >= 0 ? v : APRS_WIN_DFLT;\n"
              "  }");
    WT_HAS(p, "  function winText(s) { return s < 3600 ? Math.round(s / 60) + \" min\" : Math.round(s / 3600) + \" h\"; }\n"
              "  // sloth.db's entities (/api/aprs/tracks: stations by source call,\n"
              "  // objects and items by their own name, each with its newest packet's\n"
              "  // time, its newest position, status, comment and a moving one's 24 h\n"
              "  // trail) merged with the live table's stations (/api/aprs), keyed by\n"
              "  // kind and key: the live row wins for the latest position, the newer\n"
              "  // last_seen of the two counts. Then the window: an entity is shown\n"
              "  // while now - last_seen <= win, last_seen being its newest packet of\n"
              "  // any kind, so a status-only packet keeps it (at its last position).\n"
              "  function aprsEntities(now, win) {\n"
              "    var by = Object.create(null), out = [];\n"
              "    function get(kind, key) {\n"
              "      var id = kind + \"|\" + key;\n"
              "      if (!by[id]) {\n"
              "        by[id] = { id: id, kind: kind, key: key, via: \"\", symbol: \"\", last_seen: 0, moving: false,\n"
              "                   status: \"\", comment: \"\", pts: [], bucket_s: 0, live: null };\n"
              "        out.push(by[id]);\n"
              "      }\n"
              "      return by[id];\n"
              "    }\n"
              "    var t = S.atrk, cols = t && Array.isArray(t.cols) ? t.cols : [];\n"
              "    ((t && t.entities) || []).forEach(function (r) {\n"
              "      if (!Array.isArray(r)) return;\n"
              "      var o = {};\n"
              "      cols.forEach(function (c, i) { o[c] = r[i]; });\n"
              "      if (typeof o.key !== \"string\" || !o.key) return;\n"
              "      var e = get(o.object ? \"object\" : \"station\", o.key);\n"
              "      e.via = typeof o.via === \"string\" ? o.via : \"\";\n"
              "      e.symbol = typeof o.symbol === \"string\" ? o.symbol : \"\";\n"
              "      e.last_seen = num(o.last_seen) ? o.last_seen : 0;\n"
              "      e.lat = o.lat; e.lon = o.lon; e.alt_m = o.alt_m; e.speed_kt = o.speed_kt; e.course = o.course;\n"
              "      e.moving = !!o.moving;\n"
              "      e.status = typeof o.status === \"string\" ? o.status : \"\";\n"
              "      e.comment = typeof o.comment === \"string\" ? o.comment : \"\";\n"
              "      e.pts = Array.isArray(o.pts) ? o.pts : [];\n"
              "      e.bucket_s = num(t.bucket_s) ? t.bucket_s : 1800;\n"
              "    });\n"
              "    ((S.aprs && S.aprs.stations) || []).forEach(function (a) {\n"
              "      if (typeof a.call !== \"string\" || !a.call) return;\n"
              "      var e = get(\"station\", a.call);\n"
              "      e.live = a;\n"
              "      if (num(a.lat) && num(a.lon)) {\n"
              "        e.lat = a.lat; e.lon = a.lon; e.alt_m = a.alt_m; e.speed_kt = a.speed_kt; e.course = a.course;\n"
              "      }\n"
              "      if (num(a.last_seen) && a.last_seen > e.last_seen) e.last_seen = a.last_seen;\n"
              "      if (a.status) e.status = a.status;\n"
              "      if (a.comment) e.comment = a.comment;\n"
              "      if (!e.symbol && typeof a.symbol === \"string\") e.symbol = a.symbol;\n"
              "    });\n"
              "    return out.filter(function (e) { return now - e.last_seen <= win; });\n"
              "  }");
    WT_HAS(p, "  function aprsEntities(now, win) {\n"
              "    var by = Object.create(null), out = [];\n"
              "    function get(kind, key) {\n"
              "      var id = kind + \"|\" + key;\n"
              "      if (!by[id]) {\n"
              "        by[id] = { id: id, kind: kind, key: key, via: \"\", symbol: \"\", last_seen: 0, moving: false,\n"
              "                   status: \"\", comment: \"\", pts: [], bucket_s: 0, live: null };\n"
              "        out.push(by[id]);\n"
              "      }\n"
              "      return by[id];\n"
              "    }\n"
              "    var t = S.atrk, cols = t && Array.isArray(t.cols) ? t.cols : [];\n"
              "    ((t && t.entities) || []).forEach(function (r) {\n"
              "      if (!Array.isArray(r)) return;\n"
              "      var o = {};\n"
              "      cols.forEach(function (c, i) { o[c] = r[i]; });\n"
              "      if (typeof o.key !== \"string\" || !o.key) return;\n"
              "      var e = get(o.object ? \"object\" : \"station\", o.key);\n"
              "      e.via = typeof o.via === \"string\" ? o.via : \"\";\n"
              "      e.symbol = typeof o.symbol === \"string\" ? o.symbol : \"\";\n"
              "      e.last_seen = num(o.last_seen) ? o.last_seen : 0;\n"
              "      e.lat = o.lat; e.lon = o.lon; e.alt_m = o.alt_m; e.speed_kt = o.speed_kt; e.course = o.course;\n"
              "      e.moving = !!o.moving;\n"
              "      e.status = typeof o.status === \"string\" ? o.status : \"\";\n"
              "      e.comment = typeof o.comment === \"string\" ? o.comment : \"\";\n"
              "      e.pts = Array.isArray(o.pts) ? o.pts : [];\n"
              "      e.bucket_s = num(t.bucket_s) ? t.bucket_s : 1800;\n"
              "    });\n"
              "    ((S.aprs && S.aprs.stations) || []).forEach(function (a) {\n"
              "      if (typeof a.call !== \"string\" || !a.call) return;\n"
              "      var e = get(\"station\", a.call);\n"
              "      e.live = a;\n"
              "      if (num(a.lat) && num(a.lon)) {\n"
              "        e.lat = a.lat; e.lon = a.lon; e.alt_m = a.alt_m; e.speed_kt = a.speed_kt; e.course = a.course;\n"
              "      }\n"
              "      if (num(a.last_seen) && a.last_seen > e.last_seen) e.last_seen = a.last_seen;\n"
              "      if (a.status) e.status = a.status;\n"
              "      if (a.comment) e.comment = a.comment;\n"
              "      if (!e.symbol && typeof a.symbol === \"string\") e.symbol = a.symbol;\n"
              "    });\n"
              "    return out.filter(function (e) { return now - e.last_seen <= win; });\n"
              "  }");
    WT_HAS(p, "  function trail(g, pts, bucket, c, cam, col, dpr) {\n"
              "    if (!Array.isArray(pts) || pts.length < 2) return;\n"
              "    var t0 = pts[0][0], span = Math.max(1, pts[pts.length - 1][0] - t0), prev = null;\n"
              "    g.strokeStyle = col;\n"
              "    g.lineWidth = dpr;\n"
              "    for (var i = 0; i < pts.length; i++) {\n"
              "      var q = pts[i];\n"
              "      if (!Array.isArray(q) || !num(q[0]) || !num(q[1]) || !num(q[2])) { prev = null; continue; }\n"
              "      var pt = project(locate(c, q[1], q[2], null).p, cam);\n"
              "      if (prev && q[0] - prev.ts <= 2 * bucket) {\n"
              "        g.globalAlpha = 0.15 + 0.45 * (q[0] - t0) / span;\n"
              "        polyline(g, [prev.p, pt]);\n"
              "      }\n"
              "      prev = { p: pt, ts: q[0] };\n"
              "    }\n"
              "    g.globalAlpha = 1;\n"
              "  }");
    WT_HAS(p, "  function aprsLabel(e, mv, far) {\n"
              "    var base = (e.kind === \"object\" ? e.key + \" (obj via \" + (e.via || \"?\") + \")\" : e.key) +\n"
              "               (mv ? \" \" + velText(e.speed_kt, e.course) : \"\") + (far ? \" \" + far : \"\");\n"
              "    var note = e.status || e.comment;\n"
              "    if (!note) return { text: base, alt: null };\n"
              "    return { text: base + \" \\u00b7 \" + (note.length > 16 ? note.slice(0, 15) + \"\\u2026\" : note), alt: base };\n"
              "  }");
    WT_HAS(p, "  function cross(g, x, y, s) {\n"
              "    g.beginPath();\n"
              "    g.moveTo(x - s, y - s); g.lineTo(x + s, y + s);\n"
              "    g.moveTo(x + s, y - s); g.lineTo(x - s, y + s);\n"
              "    g.stroke();\n"
              "  }");
    WT_HAS(p, "    var awin = aprsWin(), ents = aprsEntities(now, awin);\n"
              "    S.aents = ents;\n"
              "    ents.forEach(function (e) {\n"
              "      placed.aprsN++;\n"
              "      if (e.moving) placed.aprsMoving++;\n"
              "      if (e.kind === \"object\") placed.aprsObj++;\n"
              "      if (!c || !num(e.lat) || !num(e.lon)) { placed.aprsNo++; return; }\n"
              "      placed.aprs++;\n"
              "      var a = e.live, L = locate(c, e.lat, e.lon, num(e.alt_m) ? e.alt_m : null);\n"
              "      var on = isSel(\"aprs\", e.id), gone = (a && a.state === \"gone\") || stale(e.last_seen, now);\n"
              "      var col = on ? T.signal : e.kind === \"object\" ? T.normal : a && a.heard_direct ? H.tok(\"--heat-2\") : T.dim;\n"
              "      var alpha = gone ? 0.35 : L.range > R_MAX ? 0.5 : 1;\n"
              "      if (e.moving) trail(g, e.pts, e.bucket_s, c, cam, on ? T.signal : T.muted, dpr);\n"
              "      g.globalAlpha = alpha;\n"
              "      g.lineWidth = on ? 2 * dpr : dpr;\n"
              "      if (on && !e.moving && S.selTrack) {\n"
              "        g.strokeStyle = T.signal;\n"
              "        polyline(g, S.selTrack.filter(function (q) { return num(q[1]) && num(q[2]); }).map(function (q) {\n"
              "          return project(locate(c, q[1], q[2], null).p, cam);\n"
              "        }));\n"
              "      }\n"
              "      var p = project(L.p, cam);\n"
              "      if (L.h !== 0) { g.strokeStyle = T.faint; polyline(g, [p, project(L.foot, cam)]); }\n"
              "      g.strokeStyle = col;\n"
              "      if (e.kind === \"object\") cross(g, p.x, p.y, 4 * dpr); else ring(g, p.x, p.y, 5 * dpr);\n"
              "      var mv = num(e.speed_kt) && e.speed_kt > 0 && num(e.course);\n"
              "      var dir = mv ? tickDir(L.az, L.range, e.course, cam) : null;\n"
              "      if (dir) velTick(g, p, dir, e.speed_kt, dpr);\n"
              "      g.globalAlpha = 1;\n"
              "      S.marks.push({ x: p.x, y: p.y, kind: \"aprs\", key: e.id, ref: e });\n"
              "      var lb = aprsLabel(e, mv, L.range > R_MAX ? metres(L.range) : \"\");\n"
              "      want.push({ x: p.x, y: p.y, pri: on ? PRI.sel : PRI.aprs, color: on ? T.signal : T.ink, alpha: alpha,\n"
              "                  text: lb.text, alt: lb.alt });\n"
              "    });");
    WT_HAS(p, "    if (Date.now() - S.atrkAt > ATRK_MS) {\n"
              "      S.atrkAt = Date.now();\n"
              "      var ag = ++S.agen;\n"
              "      H.getJSON(\"/api/aprs/tracks?hours=\" + ATRK_H).then(function (j) {\n"
              "        if (ag !== S.agen) return;\n"
              "        S.atrk = j.out_of_scope ? null : j;\n"
              "        S.atrkErr = j.have === false ? \"no APRS tables yet\" : \"\";\n"
              "        after();\n"
              "      }).catch(function (e) {\n"
              "        if (ag !== S.agen) return;\n"
              "        S.atrk = null;\n"
              "        S.atrkErr = msg(e) === \"no_sloth_db\" ? \"trails need --sloth-db\" : msg(e);\n"
              "        after();\n"
              "      });\n"
              "    }");
    WT_HAS(p, "      parts.push(\"APRS: \" + (p.aprsN || 0) + \" in the last \" + winText(aprsWin()) + \" (\" + (p.aprsMoving || 0) +\n"
              "                 \" moving, trails 24 h), \" + (p.aprsObj || 0) + \" objects\" + (p.aprsNo ? \", \" + p.aprsNo + \" unplaced\" : \"\") +\n"
              "                 (S.atrkErr ? \" (sloth.db: \" + S.atrkErr + \")\" : \"\"));");
    WT_HAS(p, "                  [\"status\", ref.status || null],\n"
              "                  [\"comment\", ref.comment || null],\n"
              "                  [\"trail\", np + \" points over \" + (span / 3600).toFixed(1) + \" h, \" + (ref.moving ? \"moving\" : \"stationary\")],");
    WT_HAS(p, "      // No room for the long form: the short one, from the start.\n"
              "      if (w.alt) {\n"
              "        w.text = w.alt;\n"
              "        w.alt = null;\n"
              "        w.w = g.measureText(w.text).width;\n"
              "        greedy(w);\n"
              "        return;\n"
              "      }");
    char *mod = module(p);
    WT_ASSERT(mod != NULL);
    if (mod) {
        /* The window is the newest packet's age, never the position's. */
        WT_LACKS(mod, "pos_ts <= win");
        WT_EQ(count(mod, "cross(g, p.x, p.y, 4 * dpr)"), 1);   /* objects only */
        free(mod);
    }
}

void run_radar_tests(void) {
    WT_RUN(test_radar_census);
    WT_RUN(test_radar_cap);
    WT_RUN(test_radar_scope_and_params);
    WT_RUN(test_radar_size);
    WT_RUN(test_radar_recent);
    WT_RUN(test_radar_page);
    WT_RUN(test_radar_projection_js);
    WT_RUN(test_radar_devices_js);
    WT_RUN(test_radar_aprs_js);
    WT_RUN(test_radar_marks_are_shapes);
    WT_RUN(test_radar_prefs);
    WT_RUN(test_radar_scope_and_caption);
    WT_RUN(test_select_hooks);
    web_ble_destroy(&B);
    web_frrs_destroy(&F);
}
