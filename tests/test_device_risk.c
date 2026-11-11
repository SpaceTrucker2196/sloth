#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "ownership.h"

/* Roadmap #16 phase 4 — device risk scoring.
 * Verifies each signal contributes independently, the score → bucket
 * mapping, and the compound-signal cases where high-weight signals
 * push a device from MED to HIGH/CRIT on their own.
 *
 * #191 added two more properties: the four 1-point signals must never
 * stack past MED on their own (no has_strong signal present), and a
 * device on the ownership roster is forced to LOW regardless of what
 * it would otherwise have scored. */

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

/* #191: a randomised, vendor-less, hostname-less, probe-only phone —
 * every modern handset walking past a passive sensor — stacks all
 * four weak signals (score 4) but has no evidence-bearing signal.
 * That must cap at MED, not HIGH: the bug this issue reports was
 * exactly this case reaching score >= 3 and being read as HIGH. */
static void test_risk_weak_signals_cap_at_med(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };  /* LA bit set */
    device_t d = make_dev(mac, "", "", "");
    d.sources = DEV_SRC_PROBE;   /* no STA, no BEACON */

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ASSERT_EQ(signals, DEV_RISK_RANDOM_MAC | DEV_RISK_UNKNOWN_VENDOR
                      | DEV_RISK_NO_HOSTNAME | DEV_RISK_PROBE_ONLY);
    ASSERT_EQ((int)lvl, (int)DEV_RISK_MED);
}

/* An evidence-bearing signal must still reach HIGH even stacked on top
 * of every weak signal at once — the cap above must not swallow it. */
static void test_risk_alert_tagged_still_high_with_weak_signals(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.alert_count = 1;
    snprintf(s.alerts[0].match_ip, sizeof(s.alerts[0].match_ip), "10.0.0.50");
    s.alerts[0].type = ALERT_TYPE_PORT_SCAN;

    uint8_t mac[] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    device_t d = make_dev(mac, "", "", "10.0.0.50");
    d.sources = DEV_SRC_PROBE;

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ASSERT(signals & DEV_RISK_ALERT_TAGGED);
    ASSERT(signals & DEV_RISK_RANDOM_MAC);
    ASSERT_EQ((int)lvl, (int)DEV_RISK_HIGH);
}

/* #191: the sensor's own radio (or anything on the operator's known-
 * device roster) is forced to LOW and tagged DEV_RISK_SELF, even
 * though it would otherwise look exactly like the noisy-phone case
 * above — every other signal still reported in the mask. */
static void test_risk_own_device_forced_low(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t mac[] = { 0x00, 0xc0, 0xca, 0x11, 0x22, 0x33 };  /* not LA */
    ownership_add_known_mac("00:c0:ca:11:22:33");

    device_t d = make_dev(mac, "", "", "");
    d.sources = DEV_SRC_PROBE;

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ownership_clear();

    ASSERT(signals & DEV_RISK_SELF);
    ASSERT(signals & DEV_RISK_UNKNOWN_VENDOR);  /* still reported, not hidden */
    ASSERT_EQ((int)lvl, (int)DEV_RISK_LOW);
}

/* A device not on any roster is unaffected by the own-device check. */
static void test_risk_non_own_device_unaffected(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ownership_clear();
    uint8_t mac[] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    device_t d = make_dev(mac, "Cisco", "printer.local", "10.0.0.20");
    d.sources = DEV_SRC_ARP;

    int signals = 0;
    device_risk_level_t lvl = device_risk_score(&d, &s, &signals);
    ASSERT(!(signals & DEV_RISK_SELF));
    ASSERT_EQ((int)lvl, (int)DEV_RISK_LOW);
}

void run_device_risk_tests(void) {
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

    TEST_SUITE("device risk — #191 weak-signal cap and self exemption");
    RUN_TEST(test_risk_weak_signals_cap_at_med);
    RUN_TEST(test_risk_alert_tagged_still_high_with_weak_signals);
    RUN_TEST(test_risk_own_device_forced_low);
    RUN_TEST(test_risk_non_own_device_unaffected);
}
