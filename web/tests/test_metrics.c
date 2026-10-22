/* Metric derivation (#160, M2): hand-written lines in the shapes
 * src/jsonl.c writes, through the strict decoder, into the rollup, on a
 * pinned clock. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_jsonl.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "wtest.h"

static web_rollup_t  ru;
static web_metrics_t mx;
static web_jrec_t    rec;
static long long     g_now;

static long long pinned(void *ctx) { (void)ctx; return g_now; }

static void fresh(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&mx, &ru, pinned, NULL), 0);
    g_now = 1792627200;
}

static void done(void) {
    web_metrics_destroy(&mx);
    web_rollup_destroy(&ru);
}

static void line(const char *s) {
    int e = web_jl_parse(s, strlen(s), &rec);
    WT_EQ(e, WEB_JL_OK);
    if (e == WEB_JL_OK) web_metrics_record(&mx, &rec);
}

/* The bucket being filled now, for (metric, key): its point, or n 0. */
static web_point_t cur(int m, const char *k) {
    web_point_t p[4];
    memset(p, 0, sizeof(p));
    int more;
    int n = web_rollup_fine(&ru, m, k, g_now - g_now % 10, g_now - g_now % 10 + 10,
                            1, p, 4, &more);
    if (n != 1) memset(&p[0], 0, sizeof(p[0]));
    return p[0];
}

static int has_series(int m, const char *k) {
    web_keyinfo_t ki[64];
    int total;
    int n = web_rollup_keys(&ru, m, ki, 64, &total);
    for (int i = 0; i < n; i++) if (!strcmp(ki[i].key, k)) return 1;
    return 0;
}

static void test_key_canonicalisers(void) {
    char o[WEB_KEY_MAX + 1];
    WT_EQ(web_key_mac("AA:bb:0C:dd:EE:01", o), 0);
    WT_ASSERT(!strcmp(o, "aa:bb:0c:dd:ee:01"));
    WT_EQ(web_key_mac("aa:bb:cc:dd:ee", o), -1);
    WT_EQ(web_key_mac("aa-bb-cc-dd-ee-ff", o), -1);
    WT_EQ(web_key_mac("aa:bb:cc:dd:ee:fg", o), -1);
    WT_EQ(web_key_mac("00:00:00:00:00:00", o), -1);
    WT_EQ(web_key_mac("", o), -1);
    WT_EQ(web_key_mac(NULL, o), -1);
    WT_EQ(web_key_ip("10.0.0.5", o), 0);
    WT_ASSERT(!strcmp(o, "10.0.0.5"));
    WT_EQ(web_key_ip("2001:DB8:0:0:0:0:0:1", o), 0);
    WT_ASSERT(!strcmp(o, "2001:db8::1"));
    WT_EQ(web_key_ip("010.0.0.5", o), -1);
    WT_EQ(web_key_ip("10.0.0.5 ", o), -1);
    WT_EQ(web_key_ip("<b>x</b>", o), -1);
    WT_EQ(web_key_ip("example.com", o), -1);
    WT_EQ(web_key_iface("wlan0mon", o), 0);
    WT_EQ(web_key_iface("br-lan.10@x", o), 0);
    WT_EQ(web_key_iface("eth0<script>", o), -1);
    WT_EQ(web_key_iface("abcdefghijklmnop", o), -1);   /* 16 > IFNAMSIZ-1 */
    WT_EQ(web_key_iface("", o), -1);
    WT_EQ(web_key_channel(37, "6 GHz", o), 0);
    WT_ASSERT(!strcmp(o, "6g37"));
    WT_EQ(web_key_channel(37, "5 GHz", o), 0);
    WT_ASSERT(!strcmp(o, "37"));
    WT_EQ(web_key_channel(0, "?", o), -1);
    WT_EQ(web_key_channel(234, "5 GHz", o), -1);
    WT_EQ(web_key_channel_text("6g1", o), 0);
    WT_ASSERT(!strcmp(o, "6g1"));
    WT_EQ(web_key_channel_text("06", o), -1);
    WT_EQ(web_key_channel_text("6g", o), -1);
    WT_EQ(web_key_alert_type(17, o), 0);
    WT_ASSERT(!strcmp(o, "17"));
    WT_EQ(web_key_alert_type(-1, o), -1);
    WT_EQ(web_key_canon(WM_CONNS_TOTAL, "", o), 0);
    WT_EQ(web_key_canon(WM_CONNS_TOTAL, "x", o), -1);
    WT_EQ(web_key_canon(WM_ALERTS_FIRED, "12", o), 0);
    WT_EQ(web_key_canon(WM_ALERTS_FIRED, "12a", o), -1);
    WT_EQ(web_key_canon(WM_DEV_FRAMES, "AA:BB:CC:DD:EE:FF", o), 0);
    WT_ASSERT(!strcmp(o, "aa:bb:cc:dd:ee:ff"));
}

/* iface and top_host rates are sloth's "%.2f" reals. */
static void test_gauges(void) {
    fresh();
    line("{\"type\":\"iface\",\"ts\":1792627200,\"name\":\"eth0\",\"rx_bytes\":1,"
         "\"tx_bytes\":2,\"rx_rate\":1500.25,\"tx_rate\":20.50,\"mtu\":1500}");
    g_now += 1;
    line("{\"type\":\"iface\",\"ts\":1792627201,\"name\":\"eth0\",\"rx_rate\":500.75,"
         "\"tx_rate\":0.00}");
    web_point_t p = cur(WM_IFACE_RX, "eth0");
    WT_EQ(p.n, 2);
    WT_ASSERT(fabs(p.sum - 2001.0) < 1e-9);
    WT_ASSERT(p.min == 500.75 && p.max == 1500.25);
    p = cur(WM_IFACE_TX, "eth0");
    WT_ASSERT(p.n == 2 && fabs(p.sum - 20.5) < 1e-9);
    line("{\"type\":\"top_host\",\"ts\":1792627201,\"ip\":\"192.168.1.20\","
         "\"hostname\":\"nas\",\"conn_count\":7,\"rx_rate\":10.00,\"tx_rate\":5.00}");
    WT_ASSERT(cur(WM_HOST_CONNS, "192.168.1.20").sum == 7);
    WT_ASSERT(cur(WM_HOST_RX, "192.168.1.20").sum == 10);
    /* A rate that is a string, or absent, is no sample. */
    line("{\"type\":\"top_host\",\"ts\":1792627201,\"ip\":\"192.168.1.21\","
         "\"rx_rate\":\"10\"}");
    WT_EQ(has_series(WM_HOST_RX, "192.168.1.21"), 0);
    done();
}

/* Untrusted keys never become keys: markup in the ip, a bad name, a
 * name too long. Seen red with web_key_ip() replaced by a plain copy. */
static void test_hostile_keys_refused(void) {
    fresh();
    line("{\"type\":\"top_host\",\"ts\":1,\"ip\":\"<img onerror=x>\",\"conn_count\":1}");
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.1'; DROP TABLE fine;--\","
         "\"qname\":\"x\",\"is_resp\":0}");
    line("{\"type\":\"iface\",\"ts\":1,\"name\":\"eth0\\u2028\",\"rx_rate\":1}");
    line("{\"type\":\"probe_client\",\"ts\":1,\"mac\":\"aa:bb:cc:dd:ee:ff<\","
         "\"frame_count\":5}");
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.samples, 0);
    WT_EQ(st.series, 0);
    done();
}

static void test_event_counters(void) {
    fresh();
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.5\",\"qname\":\"a.example\","
         "\"qtype\":\"A\",\"answer\":\"\",\"is_resp\":0}");
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.5\",\"qname\":\"b.example\","
         "\"qtype\":\"A\",\"answer\":\"\",\"is_resp\":0}");
    /* A response with an answer is neither; NXDOMAIN counts against the
     * responder, the record's src. */
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.1\",\"qname\":\"a.example\","
         "\"qtype\":\"A\",\"answer\":\"93.184.216.34\",\"is_resp\":1}");
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.1\",\"qname\":\"nx.example\","
         "\"qtype\":\"A\",\"answer\":\"NXDOMAIN\",\"is_resp\":1}");
    WT_ASSERT(cur(WM_DNS_QUERIES, "10.0.0.5").sum == 2);
    WT_EQ(has_series(WM_DNS_QUERIES, "10.0.0.1"), 0);
    WT_ASSERT(cur(WM_DNS_NXDOMAIN, "10.0.0.1").sum == 1);
    WT_EQ(has_series(WM_DNS_NXDOMAIN, "10.0.0.5"), 0);
    line("{\"type\":\"tls\",\"ts\":1,\"src\":\"10.0.0.5\",\"dst\":\"1.1.1.1\","
         "\"host\":\"x\",\"ver\":\"1.3\",\"ja3\":\"abc\"}");
    WT_ASSERT(cur(WM_TLS_HANDSHAKES, "10.0.0.5").sum == 1);
    line("{\"type\":\"http\",\"ts\":1,\"src\":\"10.0.0.5\",\"host\":\"h\","
         "\"method\":\"GET\",\"path\":\"/\"}");
    line("{\"type\":\"http\",\"ts\":1,\"src\":\"10.0.0.9\",\"host\":\"h\","
         "\"method\":\"\",\"path\":\"\",\"status\":200,\"content_length\":3}");
    WT_ASSERT(cur(WM_HTTP_REQUESTS, "10.0.0.5").sum == 1);
    WT_EQ(has_series(WM_HTTP_REQUESTS, "10.0.0.9"), 0);
    line("{\"type\":\"alert\",\"ts\":1,\"title\":\"t\",\"detail\":\"d\",\"key\":\"k\","
         "\"sev\":2,\"ty\":14,\"count\":1}");
    line("{\"type\":\"alert.create\",\"ts\":1,\"title\":\"t\",\"sev\":2,\"ty\":14}");
    WT_ASSERT(cur(WM_ALERTS_FIRED, "14").sum == 1);   /* the legacy record only */
    done();
}

/* High-water counters become deltas floored at zero (§5.1); first sight
 * on a connection is a baseline unless the row was born after the
 * connection's first record. */
static void test_highwater_deltas(void) {
    fresh();
    /* first record on the stream: ts 1000 */
    line("{\"type\":\"probe_client\",\"ts\":1000,\"mac\":\"02:00:00:00:00:01\","
         "\"first_seen\":900,\"last_seen\":1000,\"frame_count\":500}");
    WT_EQ(has_series(WM_DEV_FRAMES, "02:00:00:00:00:01"), 0);   /* baseline */
    line("{\"type\":\"probe_client\",\"ts\":1001,\"mac\":\"02:00:00:00:00:01\","
         "\"first_seen\":900,\"last_seen\":1001,\"frame_count\":503}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:01").sum == 3);
    /* sloth evicted the row and made it again: the total restarts. Not
     * a negative burst; the next rise counts from the new total. Two
     * guards hold this (hw_delta()'s floor and count()'s d > 0); seen
     * red with both removed, green with either one alone. */
    line("{\"type\":\"probe_client\",\"ts\":1002,\"mac\":\"02:00:00:00:00:01\","
         "\"first_seen\":1002,\"last_seen\":1002,\"frame_count\":2}");
    web_point_t p = cur(WM_DEV_FRAMES, "02:00:00:00:00:01");
    WT_ASSERT(p.sum == 3 && p.min >= 0);
    line("{\"type\":\"probe_client\",\"ts\":1003,\"mac\":\"02:00:00:00:00:01\","
         "\"first_seen\":1002,\"last_seen\":1003,\"frame_count\":6}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:01").sum == 7);
    /* Born after we started listening: its whole total is new. */
    line("{\"type\":\"probe_client\",\"ts\":1003,\"mac\":\"02:00:00:00:00:02\","
         "\"first_seen\":1003,\"last_seen\":1003,\"frame_count\":4}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:02").sum == 4);
    /* assoc counts against the station; seqnum_client (no first_seen)
     * is always a baseline on first sight. */
    line("{\"type\":\"assoc\",\"ts\":1003,\"bssid\":\"02:00:00:00:aa:01\","
         "\"sta_mac\":\"02:00:00:00:00:02\",\"first_seen\":1003,\"frame_count\":1}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:02").sum == 5);
    line("{\"type\":\"seqnum_client\",\"ts\":1003,\"mac\":\"02:00:00:00:00:03\","
         "\"mac_random\":1,\"last_seen\":1003,\"frame_count\":90,\"hist\":[1,2]}");
    WT_EQ(has_series(WM_DEV_FRAMES, "02:00:00:00:00:03"), 0);
    line("{\"type\":\"seqnum_client\",\"ts\":1004,\"mac\":\"02:00:00:00:00:03\","
         "\"mac_random\":1,\"last_seen\":1004,\"frame_count\":95,\"hist\":[1,2]}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:03").sum == 5);

    /* deauth: per (src, dst, bssid, subtype), summed into the bssid. */
    line("{\"type\":\"deauth\",\"ts\":1004,\"src\":\"02:00:00:00:aa:01\","
         "\"dst\":\"ff:ff:ff:ff:ff:ff\",\"bssid\":\"02:00:00:00:aa:01\","
         "\"subtype\":12,\"first_seen\":1004,\"count\":10}");
    line("{\"type\":\"deauth\",\"ts\":1004,\"src\":\"02:00:00:00:aa:01\","
         "\"dst\":\"02:00:00:00:00:02\",\"bssid\":\"02:00:00:00:aa:01\","
         "\"subtype\":12,\"first_seen\":1004,\"count\":2}");
    WT_ASSERT(cur(WM_WIFI_DEAUTH, "02:00:00:00:aa:01").sum == 12);

    /* A new connection is a new stream: rows it re-sends at their full
     * totals are baselines again, not a burst. Seen red with
     * web_metrics_stream() not clearing the table (the old mark made
     * the re-sent 9 a delta of 3). */
    web_metrics_stream(&mx);
    g_now += 100;
    line("{\"type\":\"probe_client\",\"ts\":1200,\"mac\":\"02:00:00:00:00:01\","
         "\"first_seen\":1002,\"last_seen\":1200,\"frame_count\":9}");
    WT_EQ(cur(WM_DEV_FRAMES, "02:00:00:00:00:01").n, 0);
    done();
}

/* Flows: the running total per (src, dst), summed into src. */
static void test_flow_counters(void) {
    fresh();
    line("{\"type\":\"ssh_flow\",\"ts\":10,\"src_ip\":\"10.0.0.7\","
         "\"dst_ip\":\"10.0.0.1\",\"banner_count\":1,\"first_seen\":10}");
    line("{\"type\":\"rdp_flow\",\"ts\":10,\"src_ip\":\"10.0.0.7\","
         "\"dst_ip\":\"10.0.0.2\",\"connect_req_count\":2,\"first_seen\":10}");
    line("{\"type\":\"smb_session\",\"ts\":10,\"client_ip\":\"10.0.0.7\","
         "\"server_ip\":\"10.0.0.3\",\"server_port\":445,\"first_seen\":10,\"count\":4}");
    line("{\"type\":\"snmp_flow\",\"ts\":10,\"src_ip\":\"10.0.0.7\","
         "\"dst_ip\":\"10.0.0.4\",\"get_count\":1,\"getnext_count\":2,"
         "\"getbulk_count\":3,\"set_count\":0,\"response_count\":4,\"trap_count\":0,"
         "\"community_count\":1,\"last_community\":\"public\",\"first_seen\":10}");
    line("{\"type\":\"mqtt_flow\",\"ts\":10,\"src_ip\":\"10.0.0.7\","
         "\"dst_ip\":\"10.0.0.5\",\"connect_count\":1,\"connack_fail_count\":9,"
         "\"subscribe_count\":2,\"publish_count\":3,\"last_username\":\"u\","
         "\"first_seen\":10}");
    WT_ASSERT(cur(WM_FLOW_SSH, "10.0.0.7").sum == 1);
    WT_ASSERT(cur(WM_FLOW_RDP, "10.0.0.7").sum == 2);
    WT_ASSERT(cur(WM_FLOW_SMB, "10.0.0.7").sum == 4);
    WT_ASSERT(cur(WM_FLOW_SNMP, "10.0.0.7").sum == 10);
    WT_ASSERT(cur(WM_FLOW_MQTT, "10.0.0.7").sum == 6);
    line("{\"type\":\"ssh_flow\",\"ts\":11,\"src_ip\":\"10.0.0.7\","
         "\"dst_ip\":\"10.0.0.1\",\"banner_count\":3,\"first_seen\":10}");
    WT_ASSERT(cur(WM_FLOW_SSH, "10.0.0.7").sum == 3);
    done();
}

/* channel_summary: ap_count a gauge, ctrl_total a running total. */
static void test_channels(void) {
    fresh();
    line("{\"type\":\"channel_summary\",\"ts\":5,\"channel\":37,\"band\":\"6 GHz\","
         "\"ap_count\":3,\"ctrl_total\":100}");
    line("{\"type\":\"channel_summary\",\"ts\":5,\"channel\":37,\"band\":\"5 GHz\","
         "\"ap_count\":1,\"ctrl_total\":7}");
    WT_ASSERT(cur(WM_WIFI_AP_COUNT, "6g37").sum == 3);
    WT_ASSERT(cur(WM_WIFI_AP_COUNT, "37").sum == 1);
    WT_EQ(has_series(WM_WIFI_CTRL_TOTAL, "6g37"), 0);
    line("{\"type\":\"channel_summary\",\"ts\":6,\"channel\":37,\"band\":\"6 GHz\","
         "\"ap_count\":3,\"ctrl_total\":130}");
    WT_ASSERT(cur(WM_WIFI_CTRL_TOTAL, "6g37").sum == 30);
    done();
}

/* dev.present: any record with a mac or sta_mac heard within the last
 * fine bucket; a row sloth keeps re-sending after it went quiet is not
 * presence. */
static void test_presence(void) {
    fresh();
    line("{\"type\":\"device\",\"ts\":100,\"mac\":\"02:00:00:00:00:0a\",\"ip\":\"\","
         "\"last_seen\":95}");
    line("{\"type\":\"device\",\"ts\":100,\"mac\":\"02:00:00:00:00:0b\",\"ip\":\"\","
         "\"last_seen\":80}");
    line("{\"type\":\"arp\",\"ts\":100,\"ip\":\"10.0.0.9\",\"mac\":\"02:00:00:00:00:0c\"}");
    line("{\"type\":\"device\",\"ts\":100,\"mac\":\"\",\"ip\":\"10.0.0.8\"}");
    WT_ASSERT(cur(WM_DEV_PRESENT, "02:00:00:00:00:0a").max == 1);
    WT_EQ(has_series(WM_DEV_PRESENT, "02:00:00:00:00:0b"), 0);
    WT_ASSERT(cur(WM_DEV_PRESENT, "02:00:00:00:00:0c").max == 1);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_DEV], 2);
    done();
}

static void batch(int probes, int conns, long long ts) {
    char b[256];
    for (int i = 0; i < conns; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"connections\",\"ts\":%lld,\"src\":"
                 "\"10.0.0.1:%d\",\"dst\":\"1.1.1.1:443\",\"proto\":\"tcp\"}", ts, i);
        line(b);
    }
    snprintf(b, sizeof(b), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"lo\","
             "\"rx_rate\":0.00,\"tx_rate\":0.00}", ts);
    line(b);
    snprintf(b, sizeof(b), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\","
             "\"rx_rate\":0.00,\"tx_rate\":0.00}", ts);
    line(b);
    /* A capture-thread record inside the batch steers nothing. */
    snprintf(b, sizeof(b), "{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.2\","
             "\"qname\":\"x\",\"is_resp\":0}", ts);
    line(b);
    for (int i = 0; i < probes; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":"
                 "\"02:00:00:00:01:%02x\",\"last_seen\":%lld,\"frame_count\":1}",
                 ts, i, ts);
        line(b);
    }
    snprintf(b, sizeof(b), "{\"type\":\"sensor_health\",\"ts\":%lld}", ts);
    line(b);
}

/* Rows per pass: the window that closes at a batch start holds that
 * tick's connections and the previous tick's probe clients. The partial
 * window a connection opens in is not sampled, nor is one a gap or an
 * undecodable line cut. */
static void test_pass_gauges(void) {
    fresh();
    batch(4, 6, 1);                 /* partial: nothing published */
    web_point_t p = cur(WM_CONNS_TOTAL, "");
    WT_EQ(p.n, 0);
    g_now += 1;
    batch(5, 7, 2);
    p = cur(WM_CONNS_TOTAL, "");
    WT_EQ(p.n, 1);
    WT_ASSERT(p.sum == 7);
    p = cur(WM_WIFI_PROBE_CLIENTS, "");
    WT_EQ(p.n, 1);
    WT_ASSERT(p.sum == 4);
    /* A tick with no connections and no probe clients publishes 0. */
    g_now += 1;
    batch(0, 0, 3);
    p = cur(WM_CONNS_TOTAL, "");
    WT_ASSERT(p.n == 2 && p.sum == 7 && p.min == 0);
    g_now += 1;
    batch(0, 0, 4);
    p = cur(WM_WIFI_PROBE_CLIENTS, "");
    WT_ASSERT(p.n == 3 && p.sum == 9 && p.min == 0);   /* 4, 5, 0 */
    /* A gap inside a window: that window is not sampled. Seen red with
     * the taint check removed from batch_start(). */
    g_now += 1;
    line("{\"type\":\"socket_gap\",\"ts\":5,\"dropped\":3}");
    batch(2, 2, 5);
    p = cur(WM_CONNS_TOTAL, "");
    WT_EQ(p.n, 3);
    web_metrics_taint(&mx);          /* an undecodable line, likewise */
    g_now += 1;
    batch(2, 2, 6);
    WT_EQ(cur(WM_CONNS_TOTAL, "").n, 3);
    g_now += 1;
    batch(2, 2, 7);
    WT_EQ(cur(WM_CONNS_TOTAL, "").n, 4);
    done();
}

/* The high-water table is bounded; its evictions are counted. */
static void test_highwater_table_bounded(void) {
    fresh();
    char b[256];
    for (int i = 0; i < WEB_HW_ROWS + 10; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"seqnum_client\",\"ts\":1,\"mac\":"
                 "\"02:00:00:%02x:%02x:%02x\",\"frame_count\":1}",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        line(b);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.hw_evictions, 10);
    WT_EQ(mx.hw_n, WEB_HW_ROWS);
    done();
}

void run_metrics_tests(void) {
    WT_RUN(test_key_canonicalisers);
    WT_RUN(test_gauges);
    WT_RUN(test_hostile_keys_refused);
    WT_RUN(test_event_counters);
    WT_RUN(test_highwater_deltas);
    WT_RUN(test_flow_counters);
    WT_RUN(test_channels);
    WT_RUN(test_presence);
    WT_RUN(test_pass_gauges);
    WT_RUN(test_highwater_table_bounded);
}
