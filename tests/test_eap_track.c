#include "runner.h"
#include "sloth.h"
#include "eap_track.h"
#include "eap_parse.h"
#include <string.h>

static const uint8_t BSSID[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};

/* Build an EAP Request offering method `type`. */
static int req(uint8_t *f, int type) {
    f[0] = 0x01; f[1] = 0x01; f[2] = 0x00; f[3] = 0x05; f[4] = (uint8_t)type;
    return 5;
}

/* Build an EAP Response/Identity carrying `user`. */
static int resp_id(uint8_t *f, const char *user) {
    int ul = (int)strlen(user);
    f[0] = 0x02; f[1] = 0x02; f[2] = 0x00; f[3] = (uint8_t)(5 + ul);
    f[4] = EAP_TYPE_IDENTITY;
    memcpy(f + 5, user, (size_t)ul);
    return 5 + ul;
}

static void test_weak_method_recorded(void) {
    eap_track_clear();
    uint8_t f[16];
    int n = req(f, EAP_TYPE_MD5);
    eap_track_observe(BSSID, f, n, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 1);
    ASSERT_EQ(s.rogue_radius[0].weak_method, 1);
    ASSERT(s.rogue_radius[0].eap_types_seen & (1u << EAP_TYPE_MD5));
}

static void test_strong_method_not_weak(void) {
    eap_track_clear();
    uint8_t f[16];
    eap_track_observe(BSSID, f, req(f, EAP_TYPE_PEAP), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 1);
    ASSERT_EQ(s.rogue_radius[0].weak_method, 0);
}

static void test_real_identity_leak_counted(void) {
    eap_track_clear();
    uint8_t f[80];
    eap_track_observe(BSSID, f, resp_id(f, "alice@corp.example"), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].identity_leaks, 1);
    ASSERT_STR(s.rogue_radius[0].last_identity, "alice@corp.example");
}

static void test_anonymous_identity_not_leak(void) {
    eap_track_clear();
    uint8_t f[80];
    eap_track_observe(BSSID, f, resp_id(f, "anonymous@corp.example"), 1000);
    eap_track_observe(BSSID, f, resp_id(f, "@corp.example"), 1001);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].identity_leaks, 0);
}

static void test_per_bssid_separation(void) {
    eap_track_clear();
    uint8_t other[6] = {0xde,0xad,0xbe,0xef,0x00,0x02};
    uint8_t f[16];
    eap_track_observe(BSSID, f, req(f, EAP_TYPE_MD5),  1000);
    eap_track_observe(other, f, req(f, EAP_TYPE_PEAP), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 2);
}

void run_eap_track_tests(void) {
    TEST_SUITE("EAP method tracking (#31)");
    RUN_TEST(test_weak_method_recorded);
    RUN_TEST(test_strong_method_not_weak);
    RUN_TEST(test_real_identity_leak_counted);
    RUN_TEST(test_anonymous_identity_not_leak);
    RUN_TEST(test_per_bssid_separation);
}
