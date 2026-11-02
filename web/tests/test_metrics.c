/* Metric derivation (#160, M2): hand-written lines in the shapes
 * src/jsonl.c writes, through the strict decoder, into the rollup, on a
 * pinned clock. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_scope.h"
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
    WT_EQ(web_key_rectype("dns", o), 0);
    WT_ASSERT(!strcmp(o, "dns"));
    WT_EQ(web_key_rectype("alert.create", o), 0);
    WT_EQ(web_key_rectype("DNS", o), -1);          /* upper case */
    WT_EQ(web_key_rectype("dns<script>", o), -1);
    WT_EQ(web_key_rectype("", o), -1);
    WT_EQ(web_key_rectype(NULL, o), -1);
    WT_EQ(web_key_rectype("twelve_characters_too_long_for_this", o), -1);
    WT_EQ(web_key_canon(WM_RECORDS_RATE, "dns", o), 0);
    WT_EQ(web_key_canon(WM_RECORDS_RATE, "DNS", o), -1);
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
 * name too long. Seen red with web_key_ip() replaced by a plain copy.
 * records.rate is the one metric every valid-typed line still feeds
 * (its key is the type, never the hostile field), so the overall
 * sample/series counts below are 4, not 0 -- asserted per metric
 * instead of in aggregate so that stays true without this test caring
 * how many other metrics a future record type might add. */
static void test_hostile_keys_refused(void) {
    fresh();
    line("{\"type\":\"top_host\",\"ts\":1,\"ip\":\"<img onerror=x>\",\"conn_count\":1}");
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.1'; DROP TABLE fine;--\","
         "\"qname\":\"x\",\"is_resp\":0}");
    line("{\"type\":\"iface\",\"ts\":1,\"name\":\"eth0\\u2028\",\"rx_rate\":1}");
    line("{\"type\":\"probe_client\",\"ts\":1,\"mac\":\"aa:bb:cc:dd:ee:ff<\","
         "\"frame_count\":5}");
    web_keyinfo_t ki[4];
    int total;
    WT_EQ(web_rollup_keys(&ru, WM_HOST_CONNS, ki, 4, &total), 0);
    WT_EQ(total, 0);
    WT_EQ(web_rollup_keys(&ru, WM_DNS_QUERIES, ki, 4, &total), 0);
    WT_EQ(total, 0);
    WT_EQ(web_rollup_keys(&ru, WM_IFACE_RX, ki, 4, &total), 0);
    WT_EQ(total, 0);
    WT_EQ(web_rollup_keys(&ru, WM_DEV_FRAMES, ki, 4, &total), 0);
    WT_EQ(total, 0);
    WT_ASSERT(cur(WM_RECORDS_RATE, "top_host").sum == 1);
    WT_ASSERT(cur(WM_RECORDS_RATE, "dns").sum == 1);
    WT_ASSERT(cur(WM_RECORDS_RATE, "iface").sum == 1);
    WT_ASSERT(cur(WM_RECORDS_RATE, "probe_client").sum == 1);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.samples, 4);
    WT_EQ(st.series, 4);
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
    /* assoc counts against the station. */
    line("{\"type\":\"assoc\",\"ts\":1003,\"bssid\":\"02:00:00:00:aa:01\","
         "\"sta_mac\":\"02:00:00:00:00:02\",\"first_seen\":1003,\"frame_count\":1}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:00:00:02").sum == 5);
    /* seqnum_client counts the same probe requests as probe_client
     * (sloth's capture adds each one to both tables), so it is not a
     * source: the same advance of 5 in both records is 5 frames, not
     * 10. Seen red with the seqnum_client branch restored (sum 10). */
    line("{\"type\":\"probe_client\",\"ts\":1003,\"mac\":\"02:00:00:00:00:03\","
         "\"first_seen\":900,\"last_seen\":1003,\"frame_count\":90}");
    line("{\"type\":\"seqnum_client\",\"ts\":1003,\"mac\":\"02:00:00:00:00:03\","
         "\"mac_random\":1,\"last_seen\":1003,\"frame_count\":90,\"hist\":[1,2]}");
    line("{\"type\":\"probe_client\",\"ts\":1004,\"mac\":\"02:00:00:00:00:03\","
         "\"first_seen\":900,\"last_seen\":1004,\"frame_count\":95}");
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

/* records.rate (docs/web-visual-spec.md §7): every decoded record
 * bumps its own type's counter, by one, regardless of whether the type
 * steers anything else here. socket_gap is the one exception: it taints
 * rather than counting as content. */
static void test_records_rate(void) {
    fresh();
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.5\",\"qname\":\"a.example\","
         "\"qtype\":\"A\",\"answer\":\"\",\"is_resp\":0}");
    line("{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.6\",\"qname\":\"b.example\","
         "\"qtype\":\"A\",\"answer\":\"\",\"is_resp\":0}");
    line("{\"type\":\"tls\",\"ts\":1,\"src\":\"10.0.0.5\",\"dst\":\"1.1.1.1\","
         "\"host\":\"x\",\"ver\":\"1.3\",\"ja3\":\"abc\"}");
    line("{\"type\":\"alert.create\",\"ts\":1,\"title\":\"t\",\"sev\":2,\"ty\":14}");
    WT_ASSERT(cur(WM_RECORDS_RATE, "dns").sum == 2);
    WT_ASSERT(cur(WM_RECORDS_RATE, "tls").sum == 1);
    WT_ASSERT(cur(WM_RECORDS_RATE, "alert.create").sum == 1);
    WT_EQ(has_series(WM_RECORDS_RATE, "alert"), 0);
    line("{\"type\":\"socket_gap\",\"ts\":1,\"dropped\":1}");
    WT_EQ(has_series(WM_RECORDS_RATE, "socket_gap"), 0);
    done();
}

/* sensor.drops (docs/web-visual-spec.md §7): the four delta fields
 * summed, every tick -- a tick with none of them present (an older
 * sloth, or simply nothing to report) still samples, at 0, so the
 * series reads as a flat line rather than a gap when the sensor is
 * healthy. Seen red by gating the sample on the sum being positive. */
static void test_sensor_drops(void) {
    fresh();
    line("{\"type\":\"sensor_health\",\"ts\":1,\"capture_drop_delta\":3,"
         "\"capture_ifdrop_delta\":1,\"monitor_drop_delta\":2,"
         "\"monitor_ifdrop_delta\":0}");
    web_point_t p = cur(WM_SENSOR_DROPS, "");
    WT_EQ(p.n, 1);
    WT_ASSERT(p.sum == 6);
    line("{\"type\":\"sensor_health\",\"ts\":1}");
    p = cur(WM_SENSOR_DROPS, "");
    WT_EQ(p.n, 2);
    WT_ASSERT(p.sum == 6 && p.min == 0);
    done();
}

/* live.devices, live.alerts_open, live.anomalies_open (docs/
 * web-visual-spec.md §7): sampled once a snapshot batch, at its first
 * iface record, from whatever web_live_t and web_anomaly_t already
 * hold. Mirrors web_ingest.c's one_line(): web_live_apply() then
 * web_metrics_record() on the same record. */
static web_live_t      g_live;
static web_anomaly_t   g_anom;
static web_baseline_t  g_bl;

static void live_fresh(void) {
    fresh();
    web_live_init(&g_live, NULL);
    web_anom_cfg_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    WT_EQ(web_baseline_init(&g_bl, 32), 0);
    acfg.bl = &g_bl;
    WT_EQ(web_anomaly_init(&g_anom, 8, &acfg), 0);
    web_metrics_set_live(&mx, &g_live);
    web_metrics_set_anomaly(&mx, &g_anom);
}

static void live_done(void) {
    web_anomaly_destroy(&g_anom);
    web_baseline_destroy(&g_bl);
    web_live_destroy(&g_live);
    done();
}

static void live_line(const char *s) {
    int e = web_jl_parse(s, strlen(s), &rec);
    WT_EQ(e, WEB_JL_OK);
    if (e != WEB_JL_OK) return;
    web_live_apply(&g_live, &rec, g_now * 1000);
    web_metrics_record(&mx, &rec);
}

static void test_live_sampling(void) {
    live_fresh();
    /* Pass 1: one device, closed by the beacon that follows it. Not yet
     * sampled: the first batch_start() has nothing prior to report, the
     * same way wifi.probe_clients and conns.total report nothing on it
     * (test_pass_gauges). */
    live_line("{\"type\":\"iface\",\"ts\":1,\"name\":\"eth0\",\"rx_rate\":0,"
              "\"tx_rate\":0}");
    live_line("{\"type\":\"device\",\"ts\":1,\"mac\":\"02:00:00:00:00:01\","
              "\"ip\":\"\"}");
    live_line("{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"02:00:00:00:aa:01\","
              "\"frame_count\":1}");
    live_line("{\"type\":\"alert.create\",\"ts\":1,\"incident_id\":\"i1\","
              "\"sev\":1,\"ty\":1,\"title\":\"t\"}");
    WT_EQ(has_series(WM_LIVE_DEVICES, ""), 0);
    WT_EQ(has_series(WM_LIVE_ALERTS_OPEN, ""), 0);
    WT_EQ(has_series(WM_LIVE_ANOMALIES_OPEN, ""), 0);
    /* One open episode, poked directly: the rules that open one for
     * real are test_anomaly.c's job, not this file's. */
    g_anom.ep[0].state = WEB_EP_OPEN;

    /* Pass 2's first iface record is the next batch's batch_start():
     * it samples pass 1's published count, the open alert and the
     * open episode. */
    g_now += 1;
    live_line("{\"type\":\"iface\",\"ts\":2,\"name\":\"eth0\",\"rx_rate\":0,"
              "\"tx_rate\":0}");
    WT_ASSERT(cur(WM_LIVE_DEVICES, "").sum == 1);
    WT_ASSERT(cur(WM_LIVE_ALERTS_OPEN, "").sum == 1);
    WT_ASSERT(cur(WM_LIVE_ANOMALIES_OPEN, "").sum == 1);
    live_line("{\"type\":\"device\",\"ts\":2,\"mac\":\"02:00:00:00:00:02\","
              "\"ip\":\"\"}");
    live_line("{\"type\":\"beacon\",\"ts\":2,\"bssid\":\"02:00:00:00:aa:01\","
              "\"frame_count\":2}");
    /* Pass 2 published 1 device too; close the open alert and episode,
     * open nothing new, and confirm the next batch samples 0, not a
     * stale 1 -- seen red with sample_live() skipped under a 0 value. */
    live_line("{\"type\":\"alert.resolve\",\"ts\":2,\"incident_id\":\"i1\","
              "\"sev\":1,\"ty\":1,\"title\":\"t\",\"reason\":\"r\"}");
    g_anom.ep[0].state = WEB_EP_CLOSED;
    g_now += 1;
    live_line("{\"type\":\"iface\",\"ts\":3,\"name\":\"eth0\",\"rx_rate\":0,"
              "\"tx_rate\":0}");
    web_point_t p = cur(WM_LIVE_ALERTS_OPEN, "");
    WT_EQ(p.n, 2);
    WT_ASSERT(p.sum == 1 && p.min == 0);
    p = cur(WM_LIVE_ANOMALIES_OPEN, "");
    WT_EQ(p.n, 2);
    WT_ASSERT(p.sum == 1 && p.min == 0);
    live_done();
}

/* With neither wired (the default), nothing is sampled: existing
 * callers of web_metrics_init() that never call web_metrics_set_live()
 * or web_metrics_set_anomaly() are unaffected. */
static void test_live_sampling_unwired_is_a_noop(void) {
    fresh();
    line("{\"type\":\"iface\",\"ts\":1,\"name\":\"eth0\",\"rx_rate\":0,"
         "\"tx_rate\":0}");
    g_now += 1;
    line("{\"type\":\"iface\",\"ts\":2,\"name\":\"eth0\",\"rx_rate\":0,"
         "\"tx_rate\":0}");
    WT_EQ(has_series(WM_LIVE_DEVICES, ""), 0);
    WT_EQ(has_series(WM_LIVE_ALERTS_OPEN, ""), 0);
    WT_EQ(has_series(WM_LIVE_ANOMALIES_OPEN, ""), 0);
    done();
}

/* The high-water table is bounded; its evictions are counted. */
static void test_highwater_table_bounded(void) {
    fresh();
    char b[256];
    for (int i = 0; i < WEB_HW_ROWS + 10; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":1,\"mac\":"
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

/* A row born while listening, evicted from the high-water table and
 * then seen again on the same connection, is a baseline the second
 * time: its total up to the eviction was counted when it was born, and
 * counting it again would be a spurious burst. A row never evicted and
 * born later still counts in full. Seen red with gone_maybe() left out
 * of hw_delta()'s born test (the re-sent row counted its 5 again). */
static void test_highwater_evicted_row_not_recounted(void) {
    fresh();
    char b[256];
    /* The fillers are older on slothweb's clock than what follows, so
     * the rollup's own LRU evicts one of them, not the row under test. */
    g_now -= 100;
    line("{\"type\":\"probe_client\",\"ts\":1000,\"mac\":\"02:00:00:ff:ff:ff\","
         "\"first_seen\":1000,\"last_seen\":1000,\"frame_count\":5}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:ff").sum == 5);
    int fed = 0;
    for (int i = 0; i < WEB_HW_ROWS; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":1000,\"mac\":"
                 "\"02:00:00:%02x:%02x:%02x\",\"first_seen\":1000,"
                 "\"last_seen\":1000,\"frame_count\":1}",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        if (web_jl_parse(b, strlen(b), &rec) == WEB_JL_OK) {
            web_metrics_record(&mx, &rec);
            fed++;
        }
    }
    WT_EQ(fed, WEB_HW_ROWS);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.hw_evictions, 1);
    g_now += 100;
    /* The rollup's own device class (64 keys) has long since evicted
     * the MAC too, so any sample now would make a new series. */
    WT_EQ(has_series(WM_DEV_FRAMES, "02:00:00:ff:ff:ff"), 0);
    line("{\"type\":\"probe_client\",\"ts\":1001,\"mac\":\"02:00:00:ff:ff:ff\","
         "\"first_seen\":1000,\"last_seen\":1001,\"frame_count\":5}");
    WT_EQ(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:ff").n, 0);
    line("{\"type\":\"probe_client\",\"ts\":1002,\"mac\":\"02:00:00:ff:ff:ff\","
         "\"first_seen\":1000,\"last_seen\":1002,\"frame_count\":8}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:ff").sum == 3);
    /* The control: born now, never evicted, counted in full. */
    line("{\"type\":\"probe_client\",\"ts\":1002,\"mac\":\"02:00:00:fe:fe:fe\","
         "\"first_seen\":1002,\"last_seen\":1002,\"frame_count\":7}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:fe:fe:fe").sum == 7);
    /* A new connection forgets the filter with the table: born on it,
     * the row counts in full (3 before, 4 now, one bucket). */
    web_metrics_stream(&mx);
    line("{\"type\":\"probe_client\",\"ts\":2000,\"mac\":\"02:00:00:ff:ff:ff\","
         "\"first_seen\":2000,\"last_seen\":2000,\"frame_count\":4}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:ff").sum == 7);
    done();
}

/* One line, unchecked: for the thousands of filler rows, whose own
 * parse is not under test. */
static int feed(const char *s) {
    if (web_jl_parse(s, strlen(s), &rec) != WEB_JL_OK) return 0;
    web_metrics_record(&mx, &rec);
    return 1;
}

static int fill_rows(int from, int count) {
    char b[256];
    int fed = 0;
    for (int i = from; i < from + count; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":1000,\"mac\":"
                 "\"02:00:00:%02x:%02x:%02x\",\"first_seen\":1000,"
                 "\"last_seen\":1000,\"frame_count\":1}",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        fed += feed(b);
    }
    return fed;
}

/* The evicted-id filter is two generations of WEB_HW_GONE_ROTATE ids,
 * so it is bounded rather than filling up over a long connection. X
 * and Y are the first two rows evicted. After 8191 evictions in all X
 * is still in the older generation: seen again, a baseline. The next
 * eviction (8193rd, X's own re-sighting being the 8192nd) fills the
 * newer generation and clears the older, so Y, seen again then, is
 * forgotten and counts its total in full: the residual the header
 * states, an id is remembered across at least WEB_HW_GONE_ROTATE
 * later evictions, not forever. Seen red with the rotation removed
 * from gone_set() (Y stayed a baseline) and with gone_maybe() reading
 * only the current generation (X counted its 5 again). */
static void test_highwater_gone_filter_rotates(void) {
    fresh();
    g_now -= 100;
    line("{\"type\":\"probe_client\",\"ts\":1000,\"mac\":\"02:00:00:ff:ff:01\","
         "\"first_seen\":1000,\"last_seen\":1000,\"frame_count\":5}");
    line("{\"type\":\"probe_client\",\"ts\":1000,\"mac\":\"02:00:00:ff:ff:02\","
         "\"first_seen\":1000,\"last_seen\":1000,\"frame_count\":5}");
    /* 4094 fill the table; then 8191 evictions, X and Y the first two. */
    WT_EQ(fill_rows(0, WEB_HW_ROWS - 2 + 8191), WEB_HW_ROWS - 2 + 8191);
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.hw_evictions, 8191);
    WT_EQ(2 * WEB_HW_GONE_ROTATE, 8192);
    g_now += 100;
    line("{\"type\":\"probe_client\",\"ts\":1001,\"mac\":\"02:00:00:ff:ff:01\","
         "\"first_seen\":1000,\"last_seen\":1001,\"frame_count\":5}");
    WT_EQ(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:01").n, 0);
    line("{\"type\":\"probe_client\",\"ts\":1001,\"mac\":\"02:00:00:ff:ff:02\","
         "\"first_seen\":1000,\"last_seen\":1001,\"frame_count\":6}");
    WT_ASSERT(cur(WM_DEV_FRAMES, "02:00:00:ff:ff:02").sum == 6);
    web_rollup_stats(&ru, &st);
    WT_EQ(st.hw_evictions, 8193);
    WT_EQ(mx.hw_gone_n, 1);
    done();
}

/* rf.rssi.* (docs/web-frrs-spec.md Q7, owner ruling 2026-11-02): the
 * signal sloth last heard, from hand-built records in src/jsonl.c's
 * shapes, each into its emitter kind's own series. */
static void test_rssi_series(void) {
    fresh();
    /* A station's probes, by its MAC: a gauge, mean min and max. */
    line("{\"type\":\"probe_client\",\"ts\":100,\"mac\":\"02:00:00:00:00:51\",\"ssid\":\"x\","
         "\"signal_dbm\":-61,\"channel\":6,\"first_seen\":90,\"last_seen\":100,\"frame_count\":3}");
    line("{\"type\":\"probe_client\",\"ts\":101,\"mac\":\"02:00:00:00:00:51\",\"ssid\":\"x\","
         "\"signal_dbm\":-55,\"channel\":6,\"first_seen\":90,\"last_seen\":101,\"frame_count\":4}");
    web_point_t p = cur(WM_RF_RSSI_STA, "02:00:00:00:00:51");
    WT_EQ(p.n, 2);
    WT_ASSERT(p.min == -61 && p.max == -55);
    WT_ASSERT(web_point_value(WM_RF_RSSI_STA, &p) == -58);
    /* An AP's beacon, by bssid (canonicalised), with no channel mix
     * wired: the sample does not wait on the mix. Seen red with the
     * beacon branch's `if (!m->mix) return;` moved back above it. */
    line("{\"type\":\"beacon\",\"ts\":100,\"ssid\":\"x\",\"bssid\":\"02:00:00:00:00:A1\","
         "\"signal_dbm\":-50,\"channel\":6,\"last_seen\":100,\"frame_count\":10}");
    p = cur(WM_RF_RSSI_BSSID, "02:00:00:00:00:a1");
    WT_EQ(p.n, 1);
    WT_ASSERT(p.sum == -50);
    /* An assoc row's signal is the AP's frames: the BSSID's series, and
     * never the station's. Seen red with the assoc branch sampling
     * WM_RF_RSSI_STA under the station's key k. */
    line("{\"type\":\"assoc\",\"ts\":101,\"bssid\":\"02:00:00:00:00:a1\",\"sta_mac\":"
         "\"02:00:00:00:00:52\",\"ssid\":\"x\",\"sta_random\":0,\"source\":1,\"channel\":6,"
         "\"signal_dbm\":-48,\"first_seen\":95,\"last_seen\":101,\"frame_count\":2}");
    p = cur(WM_RF_RSSI_BSSID, "02:00:00:00:00:a1");
    WT_EQ(p.n, 2);
    WT_ASSERT(p.max == -48);
    WT_ASSERT(!has_series(WM_RF_RSSI_STA, "02:00:00:00:00:52"));
    /* A row re-sent long after its last frame is no reading: its signal
     * is the old one. Seen red with the `ts - ls > WEB_FINE_S` test
     * taken out of rssi(). */
    line("{\"type\":\"beacon\",\"ts\":200,\"ssid\":\"y\",\"bssid\":\"02:00:00:00:00:a2\","
         "\"signal_dbm\":-40,\"channel\":1,\"last_seen\":150,\"frame_count\":10}");
    WT_ASSERT(!has_series(WM_RF_RSSI_BSSID, "02:00:00:00:00:a2"));
    /* sloth's 0 is "no signal", not 0 dBm. Seen red with rssi()'s Wi-Fi
     * upper bound -1 made 0. */
    line("{\"type\":\"probe_client\",\"ts\":100,\"mac\":\"02:00:00:00:00:53\",\"ssid\":\"x\","
         "\"signal_dbm\":0,\"channel\":6,\"first_seen\":90,\"last_seen\":100,\"frame_count\":1}");
    WT_ASSERT(!has_series(WM_RF_RSSI_STA, "02:00:00:00:00:53"));
    WT_ASSERT(has_series(WM_DEV_PRESENT, "02:00:00:00:00:53"));
    /* An advertiser, by its address: has_rssi 0 says there is no
     * reading, whatever rssi holds. Seen red with the has_rssi test
     * taken out of the ble_device branch. */
    line("{\"type\":\"ble_device\",\"ts\":100,\"addr\":\"c6:00:00:00:00:b1\",\"addr_type\":1,"
         "\"has_rssi\":0,\"rssi\":-70,\"rssi_best\":0,\"last_seen\":100}");
    WT_ASSERT(!has_series(WM_RF_RSSI_BLE, "c6:00:00:00:00:b1"));
    line("{\"type\":\"ble_device\",\"ts\":101,\"addr\":\"c6:00:00:00:00:b1\",\"addr_type\":1,"
         "\"has_rssi\":1,\"rssi\":-70,\"rssi_best\":-66,\"last_seen\":101}");
    p = cur(WM_RF_RSSI_BLE, "c6:00:00:00:00:b1");
    WT_EQ(p.n, 1);
    WT_ASSERT(p.sum == -70);
    /* No kind's series holds another kind's emitter. */
    WT_ASSERT(!has_series(WM_RF_RSSI_STA, "c6:00:00:00:00:b1"));
    WT_ASSERT(!has_series(WM_RF_RSSI_BSSID, "02:00:00:00:00:51"));
    /* The catalogue: gauges of the device class, keyed by MAC, in dBm,
     * the monitor radio's (and the BLE receivers'). */
    static const int M[3] = { WM_RF_RSSI_STA, WM_RF_RSSI_BSSID, WM_RF_RSSI_BLE };
    static const char *const NAME[3] = { "rf.rssi.sta", "rf.rssi.bssid", "rf.rssi.ble" };
    for (int i = 0; i < 3; i++) {
        WT_EQ(web_metric_find(NAME[i]), M[i]);
        WT_EQ(web_metric_defs[M[i]].kind, WEB_MK_GAUGE);
        WT_EQ(web_metric_defs[M[i]].kclass, WEB_KC_DEV);
        WT_ASSERT(!strcmp(web_metric_defs[M[i]].keykind, "mac"));
        WT_ASSERT(!strcmp(web_metric_defs[M[i]].unit, "dBm"));
        WT_ASSERT(strstr(web_metric_defs[M[i]].source, "not calibrated") != NULL);
        WT_EQ(web_scope_metric(M[i]), WEB_SC_M);
        WT_ASSERT(web_metric_is_rssi(M[i]));
    }
    WT_ASSERT(!web_metric_is_rssi(WM_DEV_PRESENT));
    done();
}

/* The device class's cap bounds rf.rssi.* as it bounds every device
 * metric: at --web-max-keys 16 the 17th BSSID evicts the least
 * recently seen, flushed and counted. The first gone was seen red with
 * web_rollup_init()'s device cap doubled. */
static void test_rssi_key_cap(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, WEB_MAX_KEYS_MIN, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&mx, &ru, pinned, NULL), 0);
    g_now = 1792627200;
    for (int i = 0; i <= WEB_MAX_KEYS_MIN; i++) {
        char l[256];
        g_now++;
        snprintf(l, sizeof(l), "{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"x\",\"bssid\":"
                 "\"02:00:00:00:01:%02x\",\"signal_dbm\":%d,\"channel\":6,\"last_seen\":%lld,"
                 "\"frame_count\":1}", g_now, i, -40 - i, g_now);
        line(l);
    }
    web_rollup_stats_t st;
    web_rollup_stats(&ru, &st);
    WT_EQ(st.keys[WEB_KC_DEV], WEB_MAX_KEYS_MIN);
    WT_EQ(st.caps[WEB_KC_DEV], WEB_MAX_KEYS_MIN);
    WT_EQ(st.evictions[WEB_KC_DEV], 1);
    WT_ASSERT(!web_rollup_has(&ru, WM_RF_RSSI_BSSID, "02:00:00:00:01:00"));
    WT_ASSERT(web_rollup_has(&ru, WM_RF_RSSI_BSSID, "02:00:00:00:01:01"));
    WT_ASSERT(web_rollup_has(&ru, WM_RF_RSSI_BSSID, "02:00:00:00:01:10"));
    done();
}

void run_metrics_tests(void) {
    WT_RUN(test_rssi_series);
    WT_RUN(test_rssi_key_cap);
    WT_RUN(test_key_canonicalisers);
    WT_RUN(test_gauges);
    WT_RUN(test_hostile_keys_refused);
    WT_RUN(test_event_counters);
    WT_RUN(test_highwater_deltas);
    WT_RUN(test_flow_counters);
    WT_RUN(test_channels);
    WT_RUN(test_presence);
    WT_RUN(test_pass_gauges);
    WT_RUN(test_records_rate);
    WT_RUN(test_sensor_drops);
    WT_RUN(test_live_sampling);
    WT_RUN(test_live_sampling_unwired_is_a_noop);
    WT_RUN(test_highwater_table_bounded);
    WT_RUN(test_highwater_evicted_row_not_recounted);
    WT_RUN(test_highwater_gone_filter_rotates);
}
