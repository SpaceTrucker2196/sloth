/* Operator-designated networks (#52).
 *
 * The parser is the security-relevant half here: a typo'd --my-bssid
 * that silently designates nothing would leave the operator believing
 * their own AP is recognised while every rule treats it as a stranger.
 * So malformed input must be rejected loudly, never partially accepted. */

#include <string.h>
#include "runner.h"
#include <stdio.h>
#include <unistd.h>
#include "ownership.h"

/* ── SSID designation ────────────────────────────────────── */

static void test_ssid_add_and_match(void) {
    ownership_clear();
    ASSERT_EQ(ownership_any(), 0);
    ASSERT_EQ(ownership_add_ssid("CorpWiFi"), 1);
    ASSERT_EQ(ownership_is_my_ssid("CorpWiFi"), 1);
    ASSERT_EQ(ownership_is_my_ssid("CorpWiFi-Guest"), 0);
    ASSERT_EQ(ownership_any(), 1);
    ASSERT_EQ(ownership_ssid_count(), 1);
}

/* SSIDs are opaque octet strings on the air — two that differ only in
 * case are two different networks, so matching must not fold case. */
static void test_ssid_match_is_case_sensitive(void) {
    ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ASSERT_EQ(ownership_is_my_ssid("corpwifi"), 0);
    ASSERT_EQ(ownership_is_my_ssid("CORPWIFI"), 0);
}

static void test_ssid_repeatable_and_idempotent(void) {
    ownership_clear();
    ownership_add_ssid("A");
    ownership_add_ssid("B");
    ASSERT_EQ(ownership_ssid_count(), 2);
    /* Same value twice must not burn a second slot. */
    ASSERT_EQ(ownership_add_ssid("A"), 1);
    ASSERT_EQ(ownership_ssid_count(), 2);
    ASSERT_EQ(ownership_is_my_ssid("A"), 1);
    ASSERT_EQ(ownership_is_my_ssid("B"), 1);
}

static void test_ssid_rejects_empty_and_oversize(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_ssid(NULL), 0);
    ASSERT_EQ(ownership_add_ssid(""),   0);
    /* 32 octets is the 802.11 maximum — accept it, reject 33. */
    char ok33[34];  memset(ok33, 'x', 32); ok33[32] = '\0';
    ASSERT_EQ(ownership_add_ssid(ok33), 1);
    char big[40];   memset(big, 'y', 33);  big[33] = '\0';
    ASSERT_EQ(ownership_add_ssid(big), 0);
    ASSERT_EQ(ownership_ssid_count(), 1);
}

static void test_ssid_table_full(void) {
    ownership_clear();
    char buf[16];
    for (int i = 0; i < MAX_MY_SSIDS; i++) {
        snprintf(buf, sizeof(buf), "net%d", i);
        ASSERT_EQ(ownership_add_ssid(buf), 1);
    }
    ASSERT_EQ(ownership_ssid_count(), MAX_MY_SSIDS);
    ASSERT_EQ(ownership_add_ssid("overflow"), 0);
    ASSERT_EQ(ownership_ssid_count(), MAX_MY_SSIDS);
    ASSERT_EQ(ownership_is_my_ssid("overflow"), 0);
}

/* ── BSSID designation ───────────────────────────────────── */

static void test_bssid_add_and_match(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:dd:ee:ff"), 1);
    uint8_t want[6]  = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t other[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xfe};
    ASSERT_EQ(ownership_is_my_bssid(want),  1);
    ASSERT_EQ(ownership_is_my_bssid(other), 0);
    ASSERT_EQ(ownership_bssid_count(), 1);
}

static void test_bssid_accepts_uppercase_and_dashes(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_bssid("AA:BB:CC:00:11:22"), 1);
    ASSERT_EQ(ownership_add_bssid("de-ad-be-ef-00-01"), 1);
    uint8_t upper[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};
    uint8_t dashed[6]= {0xde,0xad,0xbe,0xef,0x00,0x01};
    ASSERT_EQ(ownership_is_my_bssid(upper),  1);
    ASSERT_EQ(ownership_is_my_bssid(dashed), 1);
}

/* Every one of these would otherwise designate nothing while looking
 * like it worked. */
static void test_bssid_rejects_malformed(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_bssid(NULL),                  0);
    ASSERT_EQ(ownership_add_bssid(""),                    0);
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:dd:ee"),      0);  /* short */
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:dd:ee:ff:00"),0);  /* long */
    ASSERT_EQ(ownership_add_bssid("aabbccddeeff"),        0);  /* no seps */
    ASSERT_EQ(ownership_add_bssid("gg:bb:cc:dd:ee:ff"),   0);  /* non-hex */
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:dd:ee:fg"),   0);  /* non-hex tail */
    ASSERT_EQ(ownership_add_bssid("aa.bb.cc.dd.ee.ff"),   0);  /* wrong sep */
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:dd:ee:f"),    0);  /* half octet */
    ASSERT_EQ(ownership_bssid_count(), 0);
}

static void test_bssid_repeatable_and_idempotent(void) {
    ownership_clear();
    ownership_add_bssid("aa:bb:cc:00:00:01");
    ownership_add_bssid("aa:bb:cc:00:00:02");
    ASSERT_EQ(ownership_bssid_count(), 2);
    ASSERT_EQ(ownership_add_bssid("aa:bb:cc:00:00:01"), 1);
    ASSERT_EQ(ownership_bssid_count(), 2);
}

static void test_bssid_table_full(void) {
    ownership_clear();
    char buf[24];
    for (int i = 0; i < MAX_MY_BSSIDS; i++) {
        snprintf(buf, sizeof(buf), "aa:bb:cc:00:00:%02x", i);
        ASSERT_EQ(ownership_add_bssid(buf), 1);
    }
    ASSERT_EQ(ownership_add_bssid("ff:ff:ff:ff:ff:ff"), 0);
    ASSERT_EQ(ownership_bssid_count(), MAX_MY_BSSIDS);
}

/* ── unconfigured default ────────────────────────────────── */

/* With nothing designated every predicate is false, so every consumer
 * degrades to pre-#52 behaviour without needing its own guard. */
static void test_unconfigured_matches_nothing(void) {
    ownership_clear();
    uint8_t any[6] = {0,0,0,0,0,0};
    ASSERT_EQ(ownership_any(), 0);
    ASSERT_EQ(ownership_is_my_ssid("anything"), 0);
    ASSERT_EQ(ownership_is_my_bssid(any), 0);
    ASSERT_EQ(ownership_ssid_count(), 0);
    ASSERT_EQ(ownership_bssid_count(), 0);
}

static void test_null_and_empty_lookups_safe(void) {
    ownership_clear();
    ownership_add_ssid("X");
    ownership_add_bssid("aa:bb:cc:dd:ee:ff");
    ASSERT_EQ(ownership_is_my_ssid(NULL), 0);
    ASSERT_EQ(ownership_is_my_ssid(""),   0);
    ASSERT_EQ(ownership_is_my_bssid(NULL), 0);
}

static void test_clear_resets_both_tables(void) {
    ownership_clear();
    ownership_add_ssid("X");
    ownership_add_bssid("aa:bb:cc:dd:ee:ff");
    ASSERT_EQ(ownership_any(), 1);
    ownership_clear();
    ASSERT_EQ(ownership_any(), 0);
    ASSERT_EQ(ownership_is_my_ssid("X"), 0);
}


/* ── known-device roster (#55) ───────────────────────────── */

static void test_known_mac_add_and_match(void) {
    ownership_clear();
    ASSERT_EQ(ownership_known_count(), 0);
    ASSERT_EQ(ownership_add_known_mac("aa:bb:cc:dd:ee:ff"), 1);
    uint8_t known[6]   = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t unknown[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    ASSERT_EQ(ownership_is_known_device(known),   1);
    ASSERT_EQ(ownership_is_known_device(unknown), 0);
    ASSERT_EQ(ownership_known_count(), 1);
}

/* Same strictness as --my-bssid: a typo must be rejected loudly, not
 * silently roster nothing. */
static void test_known_mac_rejects_malformed(void) {
    ownership_clear();
    ASSERT_EQ(ownership_add_known_mac(NULL),                0);
    ASSERT_EQ(ownership_add_known_mac(""),                  0);
    ASSERT_EQ(ownership_add_known_mac("aa:bb:cc:dd:ee"),    0);
    ASSERT_EQ(ownership_add_known_mac("zz:bb:cc:dd:ee:ff"), 0);
    ASSERT_EQ(ownership_add_known_mac("aabbccddeeff"),      0);
    ASSERT_EQ(ownership_known_count(), 0);
}

static void test_known_mac_idempotent(void) {
    ownership_clear();
    ownership_add_known_mac("aa:bb:cc:dd:ee:ff");
    ownership_add_known_mac("AA-BB-CC-DD-EE-FF");   /* same, other spelling */
    ASSERT_EQ(ownership_known_count(), 1);
}

/* The roster is independent of the network designations — clearing or
 * filling one must not disturb the other. */
static void test_roster_independent_of_designations(void) {
    ownership_clear();
    ownership_add_ssid("CorpWiFi");
    ownership_add_known_mac("aa:bb:cc:dd:ee:ff");
    ASSERT_EQ(ownership_ssid_count(),  1);
    ASSERT_EQ(ownership_known_count(), 1);
    /* ownership_any() describes network designations only; a roster on
     * its own does not make the recon rules fire. */
    ASSERT_EQ(ownership_any(), 1);
    ownership_clear();
    ASSERT_EQ(ownership_known_count(), 0);
    ASSERT_EQ(ownership_any(), 0);
}

/* ── roster file ─────────────────────────────────────────── */

static void write_roster(const char *path, const char *body) {
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fputs(body, fp);
    fclose(fp);
}

static void test_roster_file_parses(void) {
    ownership_clear();
    const char *path = "/tmp/sloth_roster_ok.txt";
    write_roster(path,
        "# office laptops\n"
        "aa:bb:cc:00:00:01\n"
        "AA-BB-CC-00-00-02   # trailing comment, dashes, upper case\n"
        "\n"
        "   aa:bb:cc:00:00:03   \n"     /* leading/trailing whitespace */
        "\t\n");
    ASSERT_EQ(ownership_load_known_macs(path), 3);
    ASSERT_EQ(ownership_known_count(), 3);
    uint8_t m2[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x02};
    ASSERT_EQ(ownership_is_known_device(m2), 1);
    unlink(path);
}

/* A malformed line is skipped, not fatal — one typo must not discard a
 * roster of 200 good entries. The good ones still load. */
static void test_roster_file_skips_bad_lines(void) {
    ownership_clear();
    const char *path = "/tmp/sloth_roster_bad.txt";
    write_roster(path,
        "aa:bb:cc:00:00:01\n"
        "not-a-mac\n"
        "aa:bb:cc:00:00:02\n"
        "zz:zz:zz:zz:zz:zz\n"
        "aa:bb:cc:00:00:03\n");
    ASSERT_EQ(ownership_load_known_macs(path), 3);
    ASSERT_EQ(ownership_known_count(), 3);
    unlink(path);
}

static void test_roster_file_missing_is_error(void) {
    ownership_clear();
    ASSERT_EQ(ownership_load_known_macs("/no/such/roster.txt"), -1);
    ASSERT_EQ(ownership_load_known_macs(NULL), -1);
    ASSERT_EQ(ownership_load_known_macs(""),   -1);
    ASSERT_EQ(ownership_known_count(), 0);
}

/* An empty or comment-only roster loads cleanly as zero entries — that
 * is a valid roster, distinct from a missing file. */
static void test_roster_file_empty_is_zero_not_error(void) {
    ownership_clear();
    const char *path = "/tmp/sloth_roster_empty.txt";
    write_roster(path, "# nothing yet\n\n   \n");
    ASSERT_EQ(ownership_load_known_macs(path), 0);
    ASSERT_EQ(ownership_known_count(), 0);
    unlink(path);
}

/* Loading twice must not double-count — reruns and repeated flags are
 * both normal. */
static void test_roster_file_load_is_idempotent(void) {
    ownership_clear();
    const char *path = "/tmp/sloth_roster_twice.txt";
    write_roster(path, "aa:bb:cc:00:00:01\naa:bb:cc:00:00:02\n");
    ownership_load_known_macs(path);
    ownership_load_known_macs(path);
    ASSERT_EQ(ownership_known_count(), 2);
    unlink(path);
}

static void test_roster_is_bounded(void) {
    ownership_clear();
    char buf[32];
    for (int i = 0; i < MAX_KNOWN_MACS; i++) {
        snprintf(buf, sizeof(buf), "02:00:%02x:%02x:%02x:%02x",
                 (i >> 24) & 0xff, (i >> 16) & 0xff,
                 (i >> 8) & 0xff, i & 0xff);
        ASSERT_EQ(ownership_add_known_mac(buf), 1);
    }
    ASSERT_EQ(ownership_known_count(), MAX_KNOWN_MACS);
    ASSERT_EQ(ownership_add_known_mac("ff:ff:ff:ff:ff:ff"), 0);
    ASSERT_EQ(ownership_known_count(), MAX_KNOWN_MACS);
}

static void test_unconfigured_roster_knows_nothing(void) {
    ownership_clear();
    uint8_t any[6] = {0,0,0,0,0,0};
    ASSERT_EQ(ownership_is_known_device(any),  0);
    ASSERT_EQ(ownership_is_known_device(NULL), 0);
    ASSERT_EQ(ownership_known_count(), 0);
}

void run_ownership_tests(void) {
    TEST_SUITE("ownership: SSID designation");
    RUN_TEST(test_ssid_add_and_match);
    RUN_TEST(test_ssid_match_is_case_sensitive);
    RUN_TEST(test_ssid_repeatable_and_idempotent);
    RUN_TEST(test_ssid_rejects_empty_and_oversize);
    RUN_TEST(test_ssid_table_full);

    TEST_SUITE("ownership: BSSID designation");
    RUN_TEST(test_bssid_add_and_match);
    RUN_TEST(test_bssid_accepts_uppercase_and_dashes);
    RUN_TEST(test_bssid_rejects_malformed);
    RUN_TEST(test_bssid_repeatable_and_idempotent);
    RUN_TEST(test_bssid_table_full);

    TEST_SUITE("ownership: unconfigured default");
    RUN_TEST(test_unconfigured_matches_nothing);
    RUN_TEST(test_null_and_empty_lookups_safe);
    RUN_TEST(test_clear_resets_both_tables);

    TEST_SUITE("ownership: known-device roster (#55)");
    RUN_TEST(test_known_mac_add_and_match);
    RUN_TEST(test_known_mac_rejects_malformed);
    RUN_TEST(test_known_mac_idempotent);
    RUN_TEST(test_roster_independent_of_designations);
    RUN_TEST(test_roster_file_parses);
    RUN_TEST(test_roster_file_skips_bad_lines);
    RUN_TEST(test_roster_file_missing_is_error);
    RUN_TEST(test_roster_file_empty_is_zero_not_error);
    RUN_TEST(test_roster_file_load_is_idempotent);
    RUN_TEST(test_roster_is_bounded);
    RUN_TEST(test_unconfigured_roster_knows_nothing);
}
