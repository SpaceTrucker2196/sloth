#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "sloth.h"
#include "onvif_discovery.h"

/* Hand-built WS-Discovery / ONVIF SOAP bodies (OASIS WS-Discovery 1.1,
 * 2009-07-01; ONVIF Core Specification, discovery). No pcap fixtures,
 * per agents/AGENTS.md — every byte here is written from the spec. */

static const uint8_t *to_u8(const char *s) { return (const uint8_t *)s; }

static const char *hello_camera =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<e:Header>"
    "<w:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</w:MessageID>"
    "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</w:Action>"
    "</e:Header>"
    "<e:Body><d:Hello>"
    "<w:EndpointReference><w:Address>urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77</w:Address></w:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/IPCAM onvif://www.onvif.org/name/IPCamera</d:Scopes>"
    "<d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:Hello></e:Body></e:Envelope>";

static const char *bye_camera =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
    "<e:Header>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye</w:Action>"
    "</e:Header>"
    "<e:Body><d:Bye>"
    "<w:EndpointReference><w:Address>urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77</w:Address></w:EndpointReference>"
    "</d:Bye></e:Body></e:Envelope>";

static const char *probematches_camera =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<e:Header>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</w:Action>"
    "</e:Header>"
    "<e:Body><d:ProbeMatches><d:ProbeMatch>"
    "<w:EndpointReference><w:Address>urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77</w:Address></w:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/name/IPCamera</d:Scopes>"
    "<d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>";

static const char *plain_probe =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
    "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>"
    "</e:Envelope>";

/* A Windows/printer-class WSD Hello: no ONVIF camera type. */
static const char *hello_printer =
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:devprof=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">"
    "<e:Body><d:Hello>"
    "<w:EndpointReference><w:Address>urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</w:Address></w:EndpointReference>"
    "<d:Types>devprof:Device</d:Types>"
    "<d:XAddrs>http://192.168.1.60:5357/wsd</d:XAddrs>"
    "</d:Hello></e:Body></e:Envelope>";

/* No EndpointReference at all — exercises the ip-fallback dedup key. */
static const char *hello_no_uuid =
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<e:Body><d:Hello>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:XAddrs>http://10.0.0.5/onvif/device_service</d:XAddrs>"
    "</d:Hello></e:Body></e:Envelope>";

/* Unprefixed elements — some embedded stacks skip namespace prefixes
 * entirely. Pretty-printed with indentation to exercise trim(). */
static const char *hello_unprefixed_pretty =
    "<Envelope>\n"
    "  <Body>\n"
    "    <Hello>\n"
    "      <EndpointReference><Address>urn:uuid:99999999-8888-7777-6666-555555555555</Address></EndpointReference>\n"
    "      <Types>\n        dn:NetworkVideoTransmitter\n      </Types>\n"
    "      <XAddrs>\n        http://192.168.1.70/onvif/device_service\n      </XAddrs>\n"
    "    </Hello>\n"
    "  </Body>\n"
    "</Envelope>\n";

/* ── Detection tests ─────────────────────────────────────── */

static void test_hello_detected(void) {
    onvif_clear();
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                                     (int)strlen(hello_camera), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_bye_detected(void) {
    onvif_clear();
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("192.168.1.50", to_u8(bye_camera),
                                     (int)strlen(bye_camera), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_probematches_detected(void) {
    onvif_clear();
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("192.168.1.50", to_u8(probematches_camera),
                                     (int)strlen(probematches_camera), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_plain_probe_not_detected(void) {
    /* A client's own query carries no XAddrs/Types of its own and is
     * not a device announcement — deliberately not recognised. */
    onvif_clear();
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("192.168.1.5", to_u8(plain_probe),
                                     (int)strlen(plain_probe), info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_unrelated_payload_rejected(void) {
    onvif_clear();
    const char *bad = "GET / HTTP/1.1\r\nHost: foo\r\n\r\n";
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("10.0.0.1", to_u8(bad), (int)strlen(bad),
                                     info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_too_short_rejected(void) {
    onvif_clear();
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("10.0.0.1", to_u8("<Hello/>"), 8,
                                     info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_no_angle_bracket_rejected(void) {
    onvif_clear();
    const char *noise = "the quick brown fox jumps over 12345";
    char info[64] = "";
    int r = onvif_ws_discovery_snoop("10.0.0.1", to_u8(noise), (int)strlen(noise),
                                     info, sizeof(info));
    ASSERT_EQ(r, 0);
}

/* ── Field extraction tests ──────────────────────────────── */

static void test_camera_hello_fields(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_STR(s.onvif_devices[0].ip, "192.168.1.50");
    ASSERT_STR(s.onvif_devices[0].kind, "Hello");
    ASSERT_EQ(s.onvif_devices[0].is_camera, 1);
    ASSERT_STR(s.onvif_devices[0].uuid, "urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77");
    ASSERT(strstr(s.onvif_devices[0].types, "NetworkVideoTransmitter") != NULL);
    ASSERT(strstr(s.onvif_devices[0].scopes, "onvif://www.onvif.org/name/IPCamera") != NULL);
    ASSERT_STR(s.onvif_devices[0].xaddrs, "http://192.168.1.50/onvif/device_service");
}

static void test_printer_hello_is_not_a_camera(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.60", to_u8(hello_printer),
                             (int)strlen(hello_printer), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_EQ(s.onvif_devices[0].is_camera, 0);
}

static void test_unprefixed_pretty_printed_extracted(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.70", to_u8(hello_unprefixed_pretty),
                             (int)strlen(hello_unprefixed_pretty), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_EQ(s.onvif_devices[0].is_camera, 1);
    /* trim() must strip the indentation/newlines pretty-printing adds. */
    ASSERT_STR(s.onvif_devices[0].types,  "dn:NetworkVideoTransmitter");
    ASSERT_STR(s.onvif_devices[0].xaddrs, "http://192.168.1.70/onvif/device_service");
}

/* ── Dedup / table tests ─────────────────────────────────── */

static void test_dedup_by_uuid(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);
    /* Same device, DHCP handed it a new address — same uuid. */
    onvif_ws_discovery_snoop("192.168.1.51", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_STR(s.onvif_devices[0].ip, "192.168.1.51");
}

static void test_different_uuid_different_slot(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);
    onvif_ws_discovery_snoop("192.168.1.60", to_u8(hello_printer),
                             (int)strlen(hello_printer), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 2);
}

static void test_dedup_by_ip_when_no_uuid(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("10.0.0.5", to_u8(hello_no_uuid),
                             (int)strlen(hello_no_uuid), NULL, 0);
    onvif_ws_discovery_snoop("10.0.0.5", to_u8(hello_no_uuid),
                             (int)strlen(hello_no_uuid), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_STR(s.onvif_devices[0].uuid, "");
}

static void test_bye_does_not_erase_camera_fields(void) {
    /* The defect this guards against: a Bye carries only the
     * EndpointReference (OASIS WS-Discovery 1.1 §4.2) — overwriting
     * types/scopes/xaddrs with the message's empty fields would make
     * a departed camera's last-known record read as "never was one". */
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(bye_camera),
                             (int)strlen(bye_camera), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 1);
    ASSERT_EQ(s.onvif_devices[0].is_camera, 1);
    ASSERT_STR(s.onvif_devices[0].kind, "Bye");
    ASSERT(strstr(s.onvif_devices[0].types, "NetworkVideoTransmitter") != NULL);
    ASSERT_STR(s.onvif_devices[0].xaddrs, "http://192.168.1.50/onvif/device_service");
}

/* ── Info string tests ───────────────────────────────────── */

static void test_info_string_names_kind_and_camera(void) {
    onvif_clear();
    char info[64] = "";
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), info, sizeof(info));
    ASSERT(strstr(info, "WSD") != NULL);
    ASSERT(strstr(info, "Hello") != NULL);
    ASSERT(strstr(info, "cam") != NULL);
}

static void test_info_string_no_camera_marker_for_printer(void) {
    onvif_clear();
    char info[64] = "";
    onvif_ws_discovery_snoop("192.168.1.60", to_u8(hello_printer),
                             (int)strlen(hello_printer), info, sizeof(info));
    ASSERT(strstr(info, "cam") == NULL);
}

static void test_info_null_ok(void) {
    onvif_clear();
    int r = onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                                     (int)strlen(hello_camera), NULL, 0);
    ASSERT_EQ(r, 1);
}

/* ── Clear test ──────────────────────────────────────────── */

static void test_clear_resets_count(void) {
    onvif_clear();
    onvif_ws_discovery_snoop("192.168.1.50", to_u8(hello_camera),
                             (int)strlen(hello_camera), NULL, 0);
    onvif_clear();

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    onvif_snapshot(&s);
    ASSERT_EQ(s.onvif_count, 0);
}

/* ── Pure-parse unit tests ───────────────────────────────── */

static void test_parse_rejects_null_data(void) {
    onvif_msg_t m;
    int r = onvif_ws_discovery_parse(NULL, 0, &m);
    ASSERT_EQ(r, 0);
}

static void test_parse_rejects_null_out(void) {
    int r = onvif_ws_discovery_parse(to_u8(hello_camera),
                                     (int)strlen(hello_camera), NULL);
    ASSERT_EQ(r, 0);
}

static void test_parse_truncated_hello_does_not_crash(void) {
    /* Cut mid-way through the Types element's closing tag. No crash,
     * and no field is reported that was not actually present. */
    size_t cut = strstr(hello_camera, "</d:Types>") - hello_camera + 3;
    onvif_msg_t m;
    int r = onvif_ws_discovery_parse(to_u8(hello_camera), (int)cut, &m);
    ASSERT_EQ(r, 1);          /* "Hello" tag itself is well before the cut */
    ASSERT_STR(m.kind, "Hello");
}

void run_onvif_discovery_tests(void) {
    TEST_SUITE("onvif/ws-discovery detection");
    RUN_TEST(test_hello_detected);
    RUN_TEST(test_bye_detected);
    RUN_TEST(test_probematches_detected);
    RUN_TEST(test_plain_probe_not_detected);
    RUN_TEST(test_unrelated_payload_rejected);
    RUN_TEST(test_too_short_rejected);
    RUN_TEST(test_no_angle_bracket_rejected);

    TEST_SUITE("onvif/ws-discovery field extraction");
    RUN_TEST(test_camera_hello_fields);
    RUN_TEST(test_printer_hello_is_not_a_camera);
    RUN_TEST(test_unprefixed_pretty_printed_extracted);

    TEST_SUITE("onvif/ws-discovery dedup");
    RUN_TEST(test_dedup_by_uuid);
    RUN_TEST(test_different_uuid_different_slot);
    RUN_TEST(test_dedup_by_ip_when_no_uuid);
    RUN_TEST(test_bye_does_not_erase_camera_fields);

    TEST_SUITE("onvif/ws-discovery info string");
    RUN_TEST(test_info_string_names_kind_and_camera);
    RUN_TEST(test_info_string_no_camera_marker_for_printer);
    RUN_TEST(test_info_null_ok);

    TEST_SUITE("onvif/ws-discovery clear");
    RUN_TEST(test_clear_resets_count);

    TEST_SUITE("onvif/ws-discovery pure parse");
    RUN_TEST(test_parse_rejects_null_data);
    RUN_TEST(test_parse_rejects_null_out);
    RUN_TEST(test_parse_truncated_hello_does_not_crash);
}
