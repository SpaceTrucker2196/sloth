#include "runner.h"
#include "sloth.h"
#include "eap_track.h"
#include "eap_parse.h"
#include <string.h>

static const uint8_t BSSID[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
static const uint8_t STA[6]   = {0x12,0x22,0x33,0x44,0x55,0x66};

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
    eap_track_observe(BSSID, STA, 1, f, n, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 1);
    ASSERT_EQ(s.rogue_radius[0].weak_method, 1);
    ASSERT(s.rogue_radius[0].eap_types_seen & (1u << EAP_TYPE_MD5));
}

static void test_strong_method_not_weak(void) {
    eap_track_clear();
    uint8_t f[16];
    eap_track_observe(BSSID, STA, 1, f, req(f, EAP_TYPE_PEAP), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 1);
    ASSERT_EQ(s.rogue_radius[0].weak_method, 0);
}

static void test_real_identity_leak_counted(void) {
    eap_track_clear();
    uint8_t f[80];
    eap_track_observe(BSSID, STA, 1, f, resp_id(f, "alice@corp.example"), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].identity_leaks, 1);
    ASSERT_STR(s.rogue_radius[0].last_identity, "alice@corp.example");
}

static void test_anonymous_identity_not_leak(void) {
    eap_track_clear();
    uint8_t f[80];
    eap_track_observe(BSSID, STA, 1, f, resp_id(f, "anonymous@corp.example"), 1000);
    eap_track_observe(BSSID, STA, 1, f, resp_id(f, "@corp.example"), 1001);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].identity_leaks, 0);
}

static void test_per_bssid_separation(void) {
    eap_track_clear();
    uint8_t other[6] = {0xde,0xad,0xbe,0xef,0x00,0x02};
    uint8_t f[16];
    eap_track_observe(BSSID, STA, 1, f, req(f, EAP_TYPE_MD5),  1000);
    eap_track_observe(other, STA, 1, f, req(f, EAP_TYPE_PEAP), 1000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 2);
}


/* ── CVE-2023-52160: TLS-in-EAP with no server cert (#65) ─── */

/* Build an EAP-Request of a TLS-based method carrying `tls_len` bytes
 * of TLS record data. Flags octet is 0 (no length, no fragment). */
static int tls_req(uint8_t *f, int type, const uint8_t *tls, int tls_len) {
    f[0] = 0x01; f[1] = 0x03;
    f[2] = 0x00; f[3] = (uint8_t)(6 + tls_len);
    f[4] = (uint8_t)type;
    f[5] = 0x00;                      /* flags */
    if (tls_len > 0) memcpy(f + 6, tls, (size_t)tls_len);
    return 6 + tls_len;
}

static int eap_success(uint8_t *f) {
    f[0] = 0x03; f[1] = 0x04; f[2] = 0x00; f[3] = 0x04;
    return 4;
}

/* One TLS handshake record holding the given handshake message types,
 * each with a 4-byte body so the length walk has something to skip. */
static int tls_record(uint8_t *b, const uint8_t *hs_types, int n) {
    int body = n * (4 + 4);
    b[0] = 22;                              /* ContentType: Handshake */
    b[1] = 0x03; b[2] = 0x03;               /* TLS 1.2 */
    b[3] = (uint8_t)(body >> 8); b[4] = (uint8_t)(body & 0xff);
    int o = 5;
    for (int i = 0; i < n; i++) {
        b[o++] = hs_types[i];
        b[o++] = 0x00; b[o++] = 0x00; b[o++] = 0x04;   /* body length 4 */
        b[o++] = 0xaa; b[o++] = 0xbb; b[o++] = 0xcc; b[o++] = 0xdd;
    }
    return o;
}

static void test_tls_scan_finds_both_messages(void) {
    uint8_t rec[64];
    uint8_t hs[2] = { 2, 11 };            /* ServerHello, Certificate */
    int n = tls_record(rec, hs, 2);
    int sh = 0, cert = 0;
    ASSERT_EQ(tls_scan_handshake(rec, n, &sh, &cert), 1);
    ASSERT_EQ(sh, 1);
    ASSERT_EQ(cert, 1);
}

static void test_tls_scan_rejects_a_continuation_fragment(void) {
    /* Mid-certificate bytes carry no record header. Reading them as one
     * invents handshake types out of certificate data — which for this
     * detector produces a false *negative* dressed as evidence. */
    uint8_t junk[32];
    memset(junk, 0x30, sizeof(junk));     /* DER SEQUENCE bytes */
    int sh = 1, cert = 1;
    ASSERT_EQ(tls_scan_handshake(junk, (int)sizeof(junk), &sh, &cert), 0);
    ASSERT_EQ(sh, 0);
    ASSERT_EQ(cert, 0);
}

static void test_tls_scan_ignores_non_handshake_records(void) {
    uint8_t rec[16];
    rec[0] = 23;                          /* ApplicationData */
    rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = 0x00; rec[4] = 0x04;
    rec[5] = 2; rec[6] = 0; rec[7] = 0; rec[8] = 0;
    int sh = 0, cert = 0;
    tls_scan_handshake(rec, 9, &sh, &cert);
    ASSERT_EQ(sh, 0);
}

static void test_peap_clean_handshake_does_not_flag(void) {
    eap_track_clear();
    uint8_t rec[64], f[128];
    uint8_t hs[2] = { 2, 11 };
    int rn = tls_record(rec, hs, 2);
    eap_track_observe(BSSID, STA, 1, f, tls_req(f, EAP_TYPE_PEAP, rec, rn), 1000);
    eap_track_observe(BSSID, STA, 1, f, eap_success(f), 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius_count, 1);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 0);
}

static void test_peap_no_server_hello_flags(void) {
    /* The rogue-AP shape: PEAP started, no TLS handshake ever presented,
     * client accepted anyway. */
    eap_track_clear();
    uint8_t f[128];
    eap_track_observe(BSSID, STA, 1, f, tls_req(f, EAP_TYPE_PEAP, NULL, 0), 1000);
    eap_track_observe(BSSID, STA, 1, f, eap_success(f), 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 1);
    ASSERT_EQ(s.rogue_radius[0].nocert_no_hello, 1);
    ASSERT_EQ(memcmp(s.rogue_radius[0].last_nocert_sta, STA, 6), 0);
}

static void test_peap_hello_without_certificate_flags(void) {
    eap_track_clear();
    uint8_t rec[64], f[128];
    uint8_t hs[1] = { 2 };                /* ServerHello only */
    int rn = tls_record(rec, hs, 1);
    eap_track_observe(BSSID, STA, 1, f, tls_req(f, EAP_TYPE_PEAP, rec, rn), 1000);
    eap_track_observe(BSSID, STA, 1, f, eap_success(f), 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 1);
    /* A ServerHello *was* seen, so the weaker wording applies. */
    ASSERT_EQ(s.rogue_radius[0].nocert_no_hello, 0);
}

static void test_peap_certificate_from_the_client_does_not_count(void) {
    /* A Certificate travelling STA->AP is the *client* authenticating.
     * Counting it would let a client with a cert mask an AP with none. */
    eap_track_clear();
    uint8_t rec[64], f[128];
    uint8_t hs[2] = { 2, 11 };
    int rn = tls_record(rec, hs, 2);
    eap_track_observe(BSSID, STA, 0 /* STA->AP */, f,
                      tls_req(f, EAP_TYPE_PEAP, rec, rn), 1000);
    eap_track_observe(BSSID, STA, 1, f, eap_success(f), 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 1);
    ASSERT_EQ(s.rogue_radius[0].nocert_no_hello, 1);
}

static void test_eap_failure_is_not_a_finding(void) {
    /* The client refused. That is the supplicant behaving correctly,
     * and alerting on the safe outcome would be exactly backwards. */
    eap_track_clear();
    uint8_t f[128];
    eap_track_observe(BSSID, STA, 1, f, tls_req(f, EAP_TYPE_PEAP, NULL, 0), 1000);
    f[0] = 0x04; f[1] = 0x04; f[2] = 0x00; f[3] = 0x04;   /* EAP-Failure */
    eap_track_observe(BSSID, STA, 1, f, 4, 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 0);
}

static void test_non_tls_method_is_not_tracked(void) {
    /* EAP-MD5 has no TLS layer to be missing. The weak-method rule
     * covers it; counting it here would double-report. */
    eap_track_clear();
    uint8_t f[64];
    eap_track_observe(BSSID, STA, 1, f, req(f, EAP_TYPE_MD5), 1000);
    eap_track_observe(BSSID, STA, 1, f, eap_success(f), 1001);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 0);
}

static void test_sessions_are_per_client(void) {
    /* One client's clean handshake must not exonerate another's. */
    eap_track_clear();
    static const uint8_t STA2[6] = {0x12,0x22,0x33,0x44,0x55,0x77};
    uint8_t rec[64], f[128];
    uint8_t hs[2] = { 2, 11 };
    int rn = tls_record(rec, hs, 2);
    eap_track_observe(BSSID, STA,  1, f, tls_req(f, EAP_TYPE_PEAP, rec, rn), 1000);
    eap_track_observe(BSSID, STA2, 1, f, tls_req(f, EAP_TYPE_PEAP, NULL, 0), 1000);
    eap_track_observe(BSSID, STA,  1, f, eap_success(f), 1001);
    eap_track_observe(BSSID, STA2, 1, f, eap_success(f), 1001);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eap_track_snapshot(&s);
    ASSERT_EQ(s.rogue_radius[0].nocert_sessions, 1);
    ASSERT_EQ(memcmp(s.rogue_radius[0].last_nocert_sta, STA2, 6), 0);
}

void run_eap_track_tests(void) {
    TEST_SUITE("EAP method tracking (#31)");
    RUN_TEST(test_weak_method_recorded);
    RUN_TEST(test_strong_method_not_weak);
    RUN_TEST(test_real_identity_leak_counted);
    RUN_TEST(test_anonymous_identity_not_leak);
    RUN_TEST(test_per_bssid_separation);
    TEST_SUITE("TLS-in-EAP no-server-cert (#65, CVE-2023-52160)");
    RUN_TEST(test_tls_scan_finds_both_messages);
    RUN_TEST(test_tls_scan_rejects_a_continuation_fragment);
    RUN_TEST(test_tls_scan_ignores_non_handshake_records);
    RUN_TEST(test_peap_clean_handshake_does_not_flag);
    RUN_TEST(test_peap_no_server_hello_flags);
    RUN_TEST(test_peap_hello_without_certificate_flags);
    RUN_TEST(test_peap_certificate_from_the_client_does_not_count);
    RUN_TEST(test_eap_failure_is_not_a_finding);
    RUN_TEST(test_non_tls_method_is_not_tracked);
    RUN_TEST(test_sessions_are_per_client);
}
