#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "ownership.h"
#include "oui.h"

/* Roadmap #16 phase 4 — device risk scoring.
 * Verifies each signal contributes independently, the score → bucket
 * mapping, and the compound-signal cases where high-weight signals
 * push a device from MED to HIGH/CRIT on their own. */

static device_t make_dev(const uint8_t mac[6], const char *vendor,
                          const char *hostname, const char *ip)
{
    device_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.mac, mac, 6);
    if (vendor)   snprintf(d.vendor,   sizeof(d.vendor),   "%s", vendor);
    if (hostname) snprintf(d.hostname, sizeof(d.hostname), "%s", hostname);
    if (ip)       snprintf(d.ip,       sizeof(d.ip),       "%s", ip);
    return d;
}

static void test_risk_low_when_everything_known(void) {
    /* Universally-administered MAC, known vendor, known hostname, not
     * probe-only, no alerts, no cleartext creds → LOW. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };  /* Cisco-like */
    device_t d = make_dev(mac, "Cisco", "printer.local", "10.0.0.20");
    d.sources = DEV_SRC_ARP | DEV_SRC_DHCP;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_LOW);
    ASSERT_EQ(signals, 0);
}

static void test_risk_randomised_mac_flag(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };  /* LA bit set */
    device_t d = make_dev(mac, "Apple", "iphone.local", "10.0.0.5");
    d.sources = DEV_SRC_STA;
    int signals = 0;
    device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_RANDOM_MAC);
}

static void test_risk_unknown_vendor_flag(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "", "known.local", "10.0.0.6");
    d.sources = DEV_SRC_ARP;
    int signals = 0;
    device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_UNKNOWN_VENDOR);
}

static void test_risk_probe_only_flag(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Apple", "iphone.local", "");
    d.sources = DEV_SRC_PROBE;   /* no STA, no BEACON */
    int signals = 0;
    device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_PROBE_ONLY);
}

static void test_risk_no_hostname_flag(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Cisco", "", "10.0.0.7");
    d.sources = DEV_SRC_ARP;
    int signals = 0;
    device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_NO_HOSTNAME);
}

static void test_risk_cleartext_cred_pushes_to_high(void) {
    /* Cleartext cred is a 3-point signal; even a fully-identified
     * device jumps to HIGH when it appears in the cred exposure list. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* Seed one cleartext cred whose src matches our device IP. */
    snprintf(s.cleartext_creds[0].src, sizeof(s.cleartext_creds[0].src),
             "10.0.0.20");
    snprintf(s.cleartext_creds[0].dst, sizeof(s.cleartext_creds[0].dst),
             "192.0.2.10");
    snprintf(s.cleartext_creds[0].protocol,
             sizeof(s.cleartext_creds[0].protocol), "HTTP-Basic");
    snprintf(s.cleartext_creds[0].username,
             sizeof(s.cleartext_creds[0].username), "alice");
    s.cleartext_cred_count = 1;

    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Cisco", "printer.local", "10.0.0.20");
    d.sources = DEV_SRC_ARP;

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_CLEARTEXT_CRED);
    ASSERT_EQ((int)lvl, (int)DEV_RISK_HIGH);
}

static void test_risk_alert_tagged_pushes_to_high(void) {
    /* An active alert whose match_ip == device IP is a 3-point signal
     * — one signal, HIGH bucket. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.alert_count = 1;
    snprintf(s.alerts[0].match_ip, sizeof(s.alerts[0].match_ip), "10.0.0.99");
    s.alerts[0].type = ALERT_TYPE_PORT_SCAN;

    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Cisco", "scanner.local", "10.0.0.99");
    d.sources = DEV_SRC_ARP;

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_ALERT_TAGGED);
    ASSERT_EQ((int)lvl, (int)DEV_RISK_HIGH);
}

static void test_risk_crit_at_five_points(void) {
    /* CRIT threshold is 5 points. Cleartext (3) + Alert-tagged (3) = 6. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.cleartext_creds[0].src, sizeof(s.cleartext_creds[0].src),
             "10.0.0.20");
    snprintf(s.cleartext_creds[0].protocol,
             sizeof(s.cleartext_creds[0].protocol), "FTP");
    snprintf(s.cleartext_creds[0].username,
             sizeof(s.cleartext_creds[0].username), "bob");
    s.cleartext_cred_count = 1;
    s.alert_count = 1;
    snprintf(s.alerts[0].match_ip, sizeof(s.alerts[0].match_ip), "10.0.0.20");

    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Cisco", "victim.local", "10.0.0.20");
    d.sources = DEV_SRC_ARP;

    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_CRIT);
}

static void test_risk_label_maps_bucket(void) {
    ASSERT_STR(device_risk_label(DEV_RISK_LOW),  "LOW");
    ASSERT_STR(device_risk_label(DEV_RISK_MED),  "MED");
    ASSERT_STR(device_risk_label(DEV_RISK_HIGH), "HIGH");
    ASSERT_STR(device_risk_label(DEV_RISK_CRIT), "CRIT");
}

/* ── #191: anonymity is one point, not four ─────────────────── */

static void test_risk_random_probe_only_phone_is_med(void) {
    /* The row that was 28,775 of a field sensor's 29,316 HIGH devices:
     * a phone walking past. Randomised MAC, no hostname, probes without
     * associating - 0xd, three facts about one thing. */
    ownership_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0xda, 0xa1, 0x19, 0x33, 0x44, 0x55 };
    device_t d = make_dev(mac, "Randomized", "", "");
    d.sources = DEV_SRC_PROBE;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_MED);
    ASSERT_EQ(signals, DEV_RISK_RANDOM_MAC | DEV_RISK_NO_HOSTNAME
                       | DEV_RISK_PROBE_ONLY);
}

static void test_risk_unknown_vendor_probe_only_is_med(void) {
    /* The other 541: 0xe, a registered OUI the small table lacks. */
    ownership_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "", "", "");
    d.sources = DEV_SRC_PROBE;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_MED);
    ASSERT_EQ(signals, DEV_RISK_UNKNOWN_VENDOR | DEV_RISK_NO_HOSTNAME
                       | DEV_RISK_PROBE_ONLY);
}

static void test_risk_random_mac_is_not_unknown_vendor(void) {
    /* A locally-administered address has no OUI, so an empty vendor on
     * one is not a second signal. */
    ownership_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    device_t d = make_dev(mac, "", "iphone.local", "10.0.0.5");
    d.sources = DEV_SRC_STA;
    int signals = 0;
    device_risk_score(&d, &s, &signals);
    ASSERT_EQ(signals, DEV_RISK_RANDOM_MAC);
}

static void test_risk_anonymous_with_one_evidence_is_high_not_crit(void) {
    /* All four anonymity signals plus a cleartext credential used to
     * be 7 points; CRIT now takes both evidence signals. */
    ownership_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.cleartext_creds[0].src, sizeof(s.cleartext_creds[0].src),
             "10.0.0.9");
    s.cleartext_cred_count = 1;
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "", "", "10.0.0.9");
    d.sources = DEV_SRC_PROBE;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_HIGH);
    ASSERT(signals & DEV_RISK_CLEARTEXT_CRED);
}

static void test_risk_own_interface_is_low_self(void) {
    /* The sensor's own uplink adapter as the field report had it: no
     * vendor, no hostname, probe-only. Rostered from the iface records
     * (#183), it is LOW and says why. */
    ownership_clear();
    uint8_t mac[] = { 0x00, 0xc0, 0xca, 0x11, 0x22, 0x05 };
    ASSERT_EQ(ownership_self_add(mac), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    device_t d = make_dev(mac, "", "", "");
    d.sources = DEV_SRC_PROBE;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_LOW);
    ASSERT_EQ(signals, DEV_RISK_SELF);

    /* The same device unrostered is the 0xe row. */
    ownership_clear();
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_MED);
    ASSERT(!(signals & DEV_RISK_SELF));
}

static void test_risk_rostered_device_is_low_self(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_known_mac("02:11:22:33:44:55"), 1);
    uint8_t mac[] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    sloth_state_t s; memset(&s, 0, sizeof(s));
    device_t d = make_dev(mac, "", "", "");
    d.sources = DEV_SRC_PROBE;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_LOW);
    ASSERT_EQ(signals, DEV_RISK_SELF);
    ownership_clear();
}

static void test_risk_own_device_still_scores_evidence(void) {
    /* SELF replaces the anonymity signals, never the evidence: a host
     * of ours leaking a credential is the finding the report is for. */
    ownership_clear();
    uint8_t mac[] = { 0x00, 0xc0, 0xca, 0x11, 0x22, 0x05 };
    ASSERT_EQ(ownership_self_add(mac), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snprintf(s.cleartext_creds[0].src, sizeof(s.cleartext_creds[0].src),
             "10.0.0.2");
    s.cleartext_cred_count = 1;
    device_t d = make_dev(mac, "", "", "10.0.0.2");
    d.sources = DEV_SRC_ARP;
    int signals = 0;
    ASSERT_EQ((int)device_risk_score(&d, &s, &signals), (int)DEV_RISK_HIGH);
    ASSERT_EQ(signals, DEV_RISK_SELF | DEV_RISK_CLEARTEXT_CRED);
    ownership_clear();
}

static void test_oui_alfa_resolves(void) {
    /* 00:c0:ca is ALFA's registered block; the adapter above read as
     * UNKNOWN_VENDOR while tool_fingerprint.c knew the prefix. */
    uint8_t mac[] = { 0x00, 0xc0, 0xca, 0x11, 0x22, 0x05 };
    ASSERT_STR(oui_lookup(mac), "ALFA");

    /* The table is binary-searched, so a row out of order hides its
     * neighbours: the entries either side of the new one still resolve. */
    uint8_t before[] = { 0x00, 0x90, 0x4c, 0x01, 0x02, 0x03 };
    uint8_t after[]  = { 0x04, 0x0c, 0xce, 0x01, 0x02, 0x03 };
    ASSERT_STR(oui_lookup(before), "Broadcom");
    ASSERT_STR(oui_lookup(after),  "Apple");
}

void run_device_risk_tests(void) {
    ownership_clear();
    TEST_SUITE("device risk — signals");
    RUN_TEST(test_risk_low_when_everything_known);
    RUN_TEST(test_risk_randomised_mac_flag);
    RUN_TEST(test_risk_unknown_vendor_flag);
    RUN_TEST(test_risk_probe_only_flag);
    RUN_TEST(test_risk_no_hostname_flag);

    TEST_SUITE("device risk — buckets");
    RUN_TEST(test_risk_cleartext_cred_pushes_to_high);
    RUN_TEST(test_risk_alert_tagged_pushes_to_high);
    RUN_TEST(test_risk_crit_at_five_points);
    RUN_TEST(test_risk_label_maps_bucket);

    TEST_SUITE("device risk — anonymity family and self (#191)");
    RUN_TEST(test_risk_random_probe_only_phone_is_med);
    RUN_TEST(test_risk_unknown_vendor_probe_only_is_med);
    RUN_TEST(test_risk_random_mac_is_not_unknown_vendor);
    RUN_TEST(test_risk_anonymous_with_one_evidence_is_high_not_crit);
    RUN_TEST(test_risk_own_interface_is_low_self);
    RUN_TEST(test_risk_rostered_device_is_low_self);
    RUN_TEST(test_risk_own_device_still_scores_evidence);
    RUN_TEST(test_oui_alfa_resolves);
}
