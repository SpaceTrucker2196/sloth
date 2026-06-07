#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "mqtt_snoop.h"

/* MQTT Control Packet type constants — kept here so the test file
 * doesn't depend on the .c file's #defines. Values match the spec. */
#define MQTT_CONNECT   0x10
#define MQTT_CONNACK   0x20
#define MQTT_PUBLISH   0x30
#define MQTT_SUBSCRIBE 0x80

/* MQTT v3.1.1 CONNECT (variable header + payload) per the OASIS
 * MQTT 3.1.1 spec §3.1. The variable header is:
 *
 *   00 04 "MQTT"        -- Protocol Name UTF-8 string
 *   04                  -- Protocol Level (v3.1.1)
 *   <flags>             -- Connect Flags
 *   00 3C               -- Keep Alive (60s)
 *
 * Then the payload, in order:
 *   ClientID  UTF-8 string
 *   WillTopic UTF-8 string  (if WillFlag)
 *   WillMsg   UTF-8 string  (if WillFlag)
 *   Username  UTF-8 string  (if UsernameFlag)
 *   Password  binary       (if PasswordFlag) */

static int put_str(uint8_t *out, const char *s) {
    int n = (int)strlen(s);
    out[0] = (uint8_t)((n >> 8) & 0xFF);
    out[1] = (uint8_t)(n & 0xFF);
    memcpy(out + 2, s, (size_t)n);
    return 2 + n;
}

/* Build a CONNECT with optional username/password. Returns total
 * MQTT-packet length (including fixed header). Buffer must be
 * large enough. Remaining length stays <= 127 so we use a single
 * varint byte. */
static int build_connect(uint8_t *out, const char *client_id,
                         const char *username) {
    uint8_t flags = 0x02;     /* CleanSession bit */
    if (username) flags |= 0x80;

    uint8_t var[64]; int v = 0;
    /* Protocol Name = "MQTT" */
    v += put_str(var + v, "MQTT");
    var[v++] = 0x04;          /* Protocol Level v3.1.1 */
    var[v++] = flags;
    var[v++] = 0x00; var[v++] = 0x3C;       /* Keep Alive */
    /* Payload: ClientID, [Username] */
    v += put_str(var + v, client_id);
    if (username) v += put_str(var + v, username);

    int o = 0;
    out[o++] = MQTT_CONNECT;
    out[o++] = (uint8_t)v;
    memcpy(out + o, var, (size_t)v);
    o += v;
    return o;
}

/* Build a CONNACK with a given reason code. */
static int build_connack(uint8_t *out, uint8_t code) {
    int o = 0;
    out[o++] = MQTT_CONNACK;
    out[o++] = 0x02;          /* Remaining Length */
    out[o++] = 0x00;          /* Acknowledge Flags (SP=0) */
    out[o++] = code;
    return o;
}

/* Build a SUBSCRIBE (variable header packet identifier + 1 topic
 * filter UTF-8 + 1-byte QoS). */
static int build_subscribe(uint8_t *out, const char *topic) {
    int o = 0;
    out[o++] = MQTT_SUBSCRIBE | 0x02;            /* reserved 0010 */
    int tn = (int)strlen(topic);
    out[o++] = (uint8_t)(2 + 2 + tn + 1);        /* RL */
    out[o++] = 0x00; out[o++] = 0x01;            /* Packet Identifier */
    o += put_str(out + o, topic);
    out[o++] = 0x00;                              /* QoS 0 */
    return o;
}

static int build_publish(uint8_t *out, const char *topic) {
    int o = 0;
    out[o++] = MQTT_PUBLISH;
    int tn = (int)strlen(topic);
    out[o++] = (uint8_t)(2 + tn + 1);
    o += put_str(out + o, topic);
    out[o++] = 'x';                               /* tiny payload */
    return o;
}

/* ── Packet-type detection ──────────────────────────────── */

static void test_detects_connect(void) {
    mqtt_snoop_clear();
    uint8_t buf[128];
    int n = build_connect(buf, "iot-device-01", NULL);
    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883,
                                  buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flow_count, 1);
    ASSERT_EQ(s.mqtt_flows[0].connect_count, 1);
    ASSERT_EQ(s.mqtt_flows[0].proto_level, 4);
}

static void test_extracts_username(void) {
    mqtt_snoop_clear();
    uint8_t buf[128];
    int n = build_connect(buf, "client-01", "iot-user");
    mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_STR(s.mqtt_flows[0].last_username, "iot-user");
}

static void test_detects_subscribe(void) {
    mqtt_snoop_clear();
    uint8_t buf[64];
    int n = build_subscribe(buf, "sensors/+/temp");
    mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flows[0].subscribe_count, 1);
}

static void test_detects_publish(void) {
    mqtt_snoop_clear();
    uint8_t buf[64];
    int n = build_publish(buf, "home/livingroom");
    mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flows[0].publish_count, 1);
}

/* ── CONNACK failure tracking ────────────────────────────── */

/* CONNACK code 4 = bad credentials (v3.1.1 §3.2.2.3). The flow
 * attributes back to the client (src_ip on the response is the
 * broker). */
static void test_connack_bad_creds_counts_as_failure(void) {
    mqtt_snoop_clear();
    uint8_t buf[16];
    int n = build_connack(buf, 4);
    mqtt_snoop_observe("10.0.0.10", 1883, "10.0.0.5", 49152, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_STR(s.mqtt_flows[0].src_ip, "10.0.0.5");   /* client */
    ASSERT_EQ(s.mqtt_flows[0].connack_fail_count, 1);
}

static void test_connack_success_not_counted(void) {
    mqtt_snoop_clear();
    uint8_t buf[16];
    int n = build_connack(buf, 0);
    mqtt_snoop_observe("10.0.0.10", 1883, "10.0.0.5", 49152, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flows[0].connack_fail_count, 0);
}

/* ── Aggregation ────────────────────────────────────────── */

static void test_repeated_connects_accumulate(void) {
    mqtt_snoop_clear();
    uint8_t buf[128];
    int n = build_connect(buf, "spammer", "admin");
    for (int i = 0; i < 12; i++)
        mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flow_count, 1);
    ASSERT_EQ(s.mqtt_flows[0].connect_count, 12);
}

static void test_two_clients_tracked_separately(void) {
    mqtt_snoop_clear();
    uint8_t buf[128];
    int n = build_connect(buf, "a", NULL);
    mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883, buf, n);
    mqtt_snoop_observe("10.0.0.6", 49152, "10.0.0.10", 1883, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flow_count, 2);
}

/* ── Port gating ───────────────────────────────────────── */

static void test_non_mqtt_port_rejected(void) {
    mqtt_snoop_clear();
    uint8_t buf[128];
    int n = build_connect(buf, "a", NULL);
    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1884,
                                  buf, n), 0);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_non_mqtt_payload_rejected(void) {
    mqtt_snoop_clear();
    static const uint8_t HTTP[] = "GET / HTTP/1.1\r\n";
    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883,
                                  HTTP, (int)sizeof(HTTP) - 1), 0);
}

static void test_unknown_type_rejected(void) {
    mqtt_snoop_clear();
    /* Type byte 0xF0 = AUTH (v5) — not tracked by Tier 1. The
     * parser should reject the packet entirely rather than count
     * it as something else. */
    uint8_t buf[8] = { 0xF0, 0x00 };
    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883,
                                  buf, (int)sizeof(buf)), 0);
}

static void test_truncated_rejected(void) {
    mqtt_snoop_clear();
    /* Remaining length says 50 but the packet is only 4 bytes. */
    uint8_t buf[4] = { MQTT_CONNECT, 0x32, 0x00, 0x04 };
    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883,
                                  buf, (int)sizeof(buf)), 0);
}

/* Username field containing a non-printable byte must drop the
 * username (preventing JSONL injection) but the CONNECT itself
 * still counts. */
static void test_username_non_printable_dropped(void) {
    mqtt_snoop_clear();
    uint8_t buf[128]; int o = 0;
    uint8_t var[64]; int v = 0;
    v += put_str(var + v, "MQTT");
    var[v++] = 0x04;
    var[v++] = 0x82;                              /* CleanSession + Username */
    var[v++] = 0x00; var[v++] = 0x3C;             /* Keep Alive */
    v += put_str(var + v, "c");                   /* ClientID  */
    /* Username field: length 5, content "ad\x01in" — has 0x01. */
    var[v++] = 0x00; var[v++] = 0x05;
    var[v++] = 'a'; var[v++] = 'd'; var[v++] = 0x01;
    var[v++] = 'i'; var[v++] = 'n';

    buf[o++] = MQTT_CONNECT;
    buf[o++] = (uint8_t)v;
    memcpy(buf + o, var, (size_t)v); o += v;

    ASSERT_EQ(mqtt_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 1883,
                                  buf, o), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    mqtt_snoop_snapshot(&s);
    ASSERT_EQ(s.mqtt_flows[0].connect_count, 1);
    ASSERT_STR(s.mqtt_flows[0].last_username, "");
}

/* ── Suite ──────────────────────────────────────────────── */

void run_mqtt_snoop_tests(void) {
    TEST_SUITE("mqtt_snoop: packet-type detection");
    RUN_TEST(test_detects_connect);
    RUN_TEST(test_extracts_username);
    RUN_TEST(test_detects_subscribe);
    RUN_TEST(test_detects_publish);

    TEST_SUITE("mqtt_snoop: CONNACK failure tracking");
    RUN_TEST(test_connack_bad_creds_counts_as_failure);
    RUN_TEST(test_connack_success_not_counted);

    TEST_SUITE("mqtt_snoop: aggregation");
    RUN_TEST(test_repeated_connects_accumulate);
    RUN_TEST(test_two_clients_tracked_separately);

    TEST_SUITE("mqtt_snoop: port gating");
    RUN_TEST(test_non_mqtt_port_rejected);

    TEST_SUITE("mqtt_snoop: negative cases");
    RUN_TEST(test_non_mqtt_payload_rejected);
    RUN_TEST(test_unknown_type_rejected);
    RUN_TEST(test_truncated_rejected);
    RUN_TEST(test_username_non_printable_dropped);
}
