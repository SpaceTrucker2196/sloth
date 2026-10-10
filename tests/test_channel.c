#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/channel.h"

static void seed_beacon(sloth_state_t *s, const uint8_t *bssid,
                         const char *ssid, int channel, int8_t sig) {
    if (s->beacon_count >= MAX_BEACON_APS) return;
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->bssid, bssid, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    a->channel    = channel;
    a->signal_dbm = sig;
    a->last_seen  = 1700000000;
}

static void seed_assoc(sloth_state_t *s, const uint8_t *bssid,
                        const uint8_t *sta, int channel) {
    if (s->assoc_count >= MAX_ASSOC_ENTRIES) return;
    assoc_t *a = &s->assocs[s->assoc_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->bssid,   bssid, 6);
    memcpy(a->sta_mac, sta,   6);
    a->channel   = channel;
    a->last_seen = 1700000000;
}

static void test_empty_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 0);
}

static void test_two_aps_one_channel(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b1[6] = {0xaa,0,0,0,0,1};
    uint8_t b2[6] = {0xaa,0,0,0,0,2};
    seed_beacon(&s, b1, "HomeNet", 6, -55);
    seed_beacon(&s, b2, "Other",   6, -40);   /* stronger */
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].channel,    6);
    ASSERT_EQ(s.channels[0].ap_count,   2);
    ASSERT_EQ((int)s.channels[0].best_signal, -40);
    ASSERT_STR(s.channels[0].top_ssid, "Other");
}

static void test_multiple_channels_sorted_by_activity(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b6[6]  = {0xaa,0,0,0,0, 6};
    uint8_t b11[6] = {0xaa,0,0,0,0,11};
    uint8_t b36[6] = {0xaa,0,0,0,0,36};
    seed_beacon(&s, b6,  "a", 6,  -50);
    seed_beacon(&s, b11, "b", 11, -50);
    seed_beacon(&s, b11, "c", 11, -50);   /* 11 has 2 APs */
    seed_beacon(&s, b36, "d", 36, -50);
    seed_beacon(&s, b36, "e", 36, -50);
    seed_beacon(&s, b36, "f", 36, -50);   /* 36 has 3 APs */
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 3);
    /* Sort: 36 (3), 11 (2), 6 (1). */
    ASSERT_EQ(s.channels[0].channel, 36);
    ASSERT_EQ(s.channels[1].channel, 11);
    ASSERT_EQ(s.channels[2].channel,  6);
}

static void test_associations_add_to_client_count(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b[6]  = {0xaa,0,0,0,0,1};
    uint8_t s1[6] = {0x11,0,0,0,0,1};
    uint8_t s2[6] = {0x11,0,0,0,0,2};
    seed_beacon(&s, b, "HomeNet", 6, -50);
    seed_assoc(&s, b, s1, 6);
    seed_assoc(&s, b, s2, 6);
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].assoc_count, 2);
}

static void test_channels_without_data_ignored(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b[6] = {0xaa,0,0,0,0,1};
    seed_beacon(&s, b, "HomeNet", 0, -50);   /* channel 0 = unknown */
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 0);
}

/* channel_source (#91): 37 is a valid number in both 5 GHz and 6 GHz,
 * so the row's band is only correct if this field is carried through. */
static void test_6ghz_source_is_carried_onto_the_row(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b[6] = {0xaa,0,0,0,0,1};
    seed_beacon(&s, b, "SixGAp", 37, -50);
    s.beacon_aps[0].channel_source = CH_SRC_HE_6GHZ;
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].channel_source, CH_SRC_HE_6GHZ);
}

static void test_no_6ghz_source_leaves_the_row_unmarked(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b[6] = {0xaa,0,0,0,0,1};
    seed_beacon(&s, b, "FiveGAp", 37, -50);
    s.beacon_aps[0].channel_source = CH_SRC_DS_PARAM;
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].channel_source, CH_SRC_DS_PARAM);
}

/* Promote-only, in both orders: once a 6 GHz AP has marked this channel
 * *number*, a later AP sharing the number with no 6 GHz source of its
 * own must not erase that mark back to unknown. */
static void test_6ghz_mark_survives_a_later_unsourced_ap_same_number(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b1[6] = {0xaa,0,0,0,0,1};
    uint8_t b2[6] = {0xaa,0,0,0,0,2};
    seed_beacon(&s, b1, "SixGAp",  37, -50);
    s.beacon_aps[0].channel_source = CH_SRC_HE_6GHZ;
    seed_beacon(&s, b2, "Unknown", 37, -60);
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].ap_count, 2);
    ASSERT_EQ(s.channels[0].channel_source, CH_SRC_HE_6GHZ);
}

static void test_6ghz_mark_set_by_a_later_ap_same_number(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b1[6] = {0xaa,0,0,0,0,1};
    uint8_t b2[6] = {0xaa,0,0,0,0,2};
    seed_beacon(&s, b1, "Unknown", 37, -60);
    seed_beacon(&s, b2, "SixGAp",  37, -50);
    s.beacon_aps[1].channel_source = CH_SRC_HE_6GHZ;
    channel_summary_update(&s);
    ASSERT_EQ(s.channel_count, 1);
    ASSERT_EQ(s.channels[0].channel_source, CH_SRC_HE_6GHZ);
}

void run_channel_tests(void) {
    TEST_SUITE("channel summary");
    RUN_TEST(test_empty_state);
    RUN_TEST(test_two_aps_one_channel);
    RUN_TEST(test_multiple_channels_sorted_by_activity);
    RUN_TEST(test_associations_add_to_client_count);
    RUN_TEST(test_channels_without_data_ignored);
    RUN_TEST(test_6ghz_source_is_carried_onto_the_row);
    RUN_TEST(test_no_6ghz_source_leaves_the_row_unmarked);
    RUN_TEST(test_6ghz_mark_survives_a_later_unsourced_ap_same_number);
    RUN_TEST(test_6ghz_mark_set_by_a_later_ap_same_number);
}
