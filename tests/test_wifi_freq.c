/* The shared 802.11 band plan (#167).
 *
 * Every value below is hand-computed from IEEE 802.11-2020 Annex E
 * Table E-4 (2.4 / 5 GHz) and 802.11ax-2021 §27.3.23.2 with its 6 GHz
 * rows — never from the converter's own output, which would pass just
 * as happily with the band plan wrong in both directions.
 *
 * The issue this file ships with had three defects: two reverse
 * converters accepting different 5 GHz ranges, a test comment claiming
 * they were shared when they were copy-pasted, and a scheduler whose
 * API could not express a 6 GHz channel at all. The first two are the
 * reason the agreement test below compares two live entry points
 * instead of trusting a comment. */

#include "runner.h"
#include "wifi_freq.h"
#include "radiotap.h"
#include "wifi_chanhop.h"
#include "reg_obs.h"
#include "sloth.h"

/* ── The two entry points really are one converter ───────────
 *
 * radiotap_freq_to_channel() is what the monitor-capture path calls
 * (src/radiotap.c's parser, then src/capture/probe.c);
 * wifi_freq_channel() is what the managed-mode nl80211 scan path calls
 * since #167 deleted its private copy in src/platform/linux_wifi.c.
 * That copy is static in a Linux-only translation unit and so was never
 * reachable from a test — which is exactly how it drifted to a
 * different 5 GHz range while tests/test_radiotap.c asserted in prose
 * that the mapping was shared.
 *
 * The frequencies include both sides of both disputed bounds, so this
 * fails if either path reverts to its own range rather than merely
 * disagreeing somewhere unexercised. */
static const int AGREE_MHZ[] = {
    /* 2.4 GHz, including the off-grid Japan channel */
    2400, 2412, 2437, 2472, 2477, 2484,
    /* 5 GHz, with the disputed floor (radiotap took 5160, nl80211 5180)
     * and the disputed ceiling (radiotap 5895, nl80211 5900) */
    5000, 5155, 5160, 5165, 5170, 5175, 5180, 5745, 5825,
    5880, 5885, 5890, 5895, 5900, 5905,
    /* 6 GHz, including the out-of-order channel 2 and the frequency the
     * datum arithmetic would steal from it */
    5935, 5950, 5955, 5960, 5965, 6175, 7115, 7120,
    /* nothing 802.11 at all */
    0, 900, 9000,
};

static void test_monitor_and_shared_converter_agree_across_bands(void) {
    for (unsigned i = 0; i < sizeof(AGREE_MHZ) / sizeof(AGREE_MHZ[0]); i++) {
        int mhz = AGREE_MHZ[i];
        ASSERT_EQ(radiotap_freq_to_channel(mhz), wifi_freq_channel(mhz, NULL));
        ASSERT_EQ(radiotap_freq_to_band(mhz),    wifi_freq_band(mhz));
    }
}

/* ── The reconciled 5 GHz range (#167's "pick one and say why") ───
 *
 * Neither old bound survives, because neither was a band-plan feature.
 * The floor is channel 32 at 5160 MHz, the lowest 20 MHz centre Annex E
 * assigns; nl80211's 5180 floor answered channel 0 for an AP on 5160 or
 * on 5170 (channel 34, the 802.11j legacy centre). The ceiling is
 * channel 177 at 5885 MHz, the highest centre the table assigns —
 * U-NII-4's top 20 MHz channel, spanning 5875-5895 — so radiotap's 5895
 * and nl80211's 5900 were band EDGES, and both answered with channel
 * numbers (179 and 180) that no 802.11 device can report. */
static void test_five_ghz_span_is_the_assignable_centres(void) {
    ASSERT_EQ(wifi_freq_channel(5160, NULL), 32);   /* lowest assigned */
    ASSERT_EQ(wifi_freq_channel(5170, NULL), 34);   /* 802.11j legacy */
    ASSERT_EQ(wifi_freq_channel(5180, NULL), 36);
    ASSERT_EQ(wifi_freq_channel(5825, NULL), 165);
    ASSERT_EQ(wifi_freq_channel(5885, NULL), 177);  /* highest assigned */
}

/* The claim of absence this slice turns on: the frequencies the two old
 * ceilings accepted name no channel now, and the frequency below the
 * floor still names none. Mutation-proven by widening the 5 GHz row's
 * hi_ch in src/wifi_freq.c — the three ceiling assertions go red
 * together, because each of 5890/5895/5900 then answers with the
 * unassignable number its old converter gave it. */
static void test_five_ghz_edges_outside_the_span_are_not_channels(void) {
    ASSERT_EQ(wifi_freq_channel(5155, NULL), 0);   /* below channel 32 */
    ASSERT_EQ(wifi_freq_channel(5890, NULL), 0);   /* radiotap said 178 */
    ASSERT_EQ(wifi_freq_channel(5895, NULL), 0);   /* radiotap said 179 */
    ASSERT_EQ(wifi_freq_channel(5900, NULL), 0);   /* nl80211 said 180 */
}

/* ── Band and channel are separate questions ─────────────────
 *
 * Channel 149 exists in both 5 and 6 GHz, 25 MHz apart in name and
 * 430 MHz apart on the air, so the number alone cannot identify a
 * transmission and the band travels with it (#149). */
static void test_band_disambiguates_colliding_channel_numbers(void) {
    wifi_band_t band = WIFI_BAND_UNKNOWN;

    ASSERT_EQ(wifi_freq_channel(2412, &band), 1);
    ASSERT_EQ(band, WIFI_BAND_2GHZ);
    ASSERT_EQ(wifi_freq_channel(5955, &band), 1);    /* channel 1 again */
    ASSERT_EQ(band, WIFI_BAND_6GHZ);

    ASSERT_EQ(wifi_freq_channel(5745, &band), 149);
    ASSERT_EQ(band, WIFI_BAND_5GHZ);
    ASSERT_EQ(wifi_freq_channel(6695, &band), 149);  /* channel 149 again */
    ASSERT_EQ(band, WIFI_BAND_6GHZ);
}

/* 6 GHz channel 2 is assigned out of order at 5935 MHz, below channel
 * 1's 5955 (802.11ax §27.3.23.2). So 5960 — where the datum arithmetic
 * would put channel 2 — must name no channel while still being inside
 * the 6 GHz band: "which band" and "which channel" are different facts
 * and a frequency can have an answer to only the first. */
static void test_6ghz_channel_two_is_off_grid_and_does_not_steal_5960(void) {
    wifi_band_t band = WIFI_BAND_UNKNOWN;

    ASSERT_EQ(wifi_freq_channel(5935, &band), 2);
    ASSERT_EQ(band, WIFI_BAND_6GHZ);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_6GHZ, 2), 5935);

    ASSERT_EQ(wifi_freq_channel(5960, &band), 0);
    ASSERT_EQ(band, WIFI_BAND_6GHZ);   /* in band, not a centre */
}

static void test_unmapped_frequencies_have_no_band_and_no_channel(void) {
    const int off[] = { 0, 900, 2400, 5000, 5950, 7120, 9000 };
    for (unsigned i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
        wifi_band_t band = WIFI_BAND_2GHZ;   /* poisoned, not pre-cleared */
        ASSERT_EQ(wifi_freq_channel(off[i], &band), 0);
        ASSERT_EQ(band, WIFI_BAND_UNKNOWN);
    }
}

/* ── Forward direction, and the round trip ───────────────────── */

static void test_channel_to_frequency_across_bands(void) {
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_2GHZ, 1),    2412);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_2GHZ, 13),   2472);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_2GHZ, 14),   2484);   /* off grid */
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 32),   5160);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 36),   5180);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 177),  5885);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_6GHZ, 1),    5955);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_6GHZ, 2),    5935);   /* off grid */
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_6GHZ, 233),  7115);
}

static void test_channel_to_frequency_rejects_out_of_band_numbers(void) {
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_2GHZ, 15),      0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 31),      0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 178),     0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_6GHZ, 234),     0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_UNKNOWN, 36),   0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, 0),       0);
    ASSERT_EQ(wifi_freq_mhz(WIFI_BAND_5GHZ, -36),     0);
}

/* Every assignable channel in every band survives the round trip. This
 * is the property the two directions drifting apart destroyed, and it
 * is checked by enumeration rather than at sampled points so a future
 * one-sided edit cannot hide between them. */
static void test_every_channel_round_trips_through_both_directions(void) {
    static const struct { wifi_band_t band; int lo, hi; } SPANS[] = {
        { WIFI_BAND_2GHZ,  1,  14 },
        { WIFI_BAND_5GHZ, 32, 177 },
        { WIFI_BAND_6GHZ,  1, 233 },
    };
    int seen = 0;
    for (unsigned s = 0; s < sizeof(SPANS) / sizeof(SPANS[0]); s++) {
        for (int ch = SPANS[s].lo; ch <= SPANS[s].hi; ch++) {
            int mhz = wifi_freq_mhz(SPANS[s].band, ch);
            if (!mhz) continue;          /* gaps in the number space */
            wifi_band_t back_band = WIFI_BAND_UNKNOWN;
            int back_ch = wifi_freq_channel(mhz, &back_band);
            ASSERT_EQ(back_ch,   ch);
            ASSERT_EQ(back_band, SPANS[s].band);
            seen++;
        }
    }
    /* Guards the loop itself: a band plan that mapped nothing would
     * otherwise satisfy every assertion above by running none. */
    ASSERT_GT(seen, 350);
}

/* ── Inferring a band from a bare number ─────────────────────
 *
 * Claim of absence: 6 GHz is never inferred. Mutation-proven by
 * dropping the `continue` that skips the 6 GHz row in
 * wifi_freq_infer_band() — channel 1 then infers 6 GHz (the row is
 * matched first for 1-13) and this test goes red. */
static void test_infer_band_never_answers_6ghz(void) {
    for (int ch = 1; ch <= 233; ch++)
        ASSERT_NE(wifi_freq_infer_band(ch), WIFI_BAND_6GHZ);
}

static void test_infer_band_splits_2_4_from_5(void) {
    ASSERT_EQ(wifi_freq_infer_band(1),   WIFI_BAND_2GHZ);
    ASSERT_EQ(wifi_freq_infer_band(13),  WIFI_BAND_2GHZ);
    ASSERT_EQ(wifi_freq_infer_band(14),  WIFI_BAND_2GHZ);   /* off grid */
    ASSERT_EQ(wifi_freq_infer_band(32),  WIFI_BAND_5GHZ);
    ASSERT_EQ(wifi_freq_infer_band(177), WIFI_BAND_5GHZ);
    ASSERT_EQ(wifi_freq_infer_band(15),  WIFI_BAND_UNKNOWN);  /* the gap */
    ASSERT_EQ(wifi_freq_infer_band(178), WIFI_BAND_UNKNOWN);
    ASSERT_EQ(wifi_freq_infer_band(0),   WIFI_BAND_UNKNOWN);
    ASSERT_EQ(wifi_freq_infer_band(-1),  WIFI_BAND_UNKNOWN);
}

/* ── The scheduler can now hold a 6 GHz channel ──────────────
 *
 * #167's third defect: chanhop_freq() took a bare channel number, and a
 * bare number cannot mean a 6 GHz channel because 1-233 collides with
 * every 2.4 and 5 GHz number. 5955 MHz was unreachable through the
 * whole hop path — not merely unmapped, inexpressible. */
static void test_chanhop_band_freq_expresses_6ghz(void) {
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_6GHZ, 1),   5955);
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_6GHZ, 2),   5935);
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_6GHZ, 233), 7115);
    /* The same number in the other two bands, to show the band is what
     * carries the difference rather than the channel. */
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_2GHZ, 1),   2412);
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_5GHZ, 36),  5180);
    ASSERT_EQ(chanhop_band_freq(WIFI_BAND_6GHZ, 36),  6130);
}

/* A 6 GHz slot survives into the rotation and is what the platform
 * would be asked to tune to — the retune argument is the frequency, so
 * this is the whole path from "expressible" to "schedulable". Nothing
 * here touches a radio: the scheduler is pure logic and no retune is
 * issued, only proposed. */
static void test_chanhop_rotation_holds_a_6ghz_channel_at_5955(void) {
    static const chanhop_chan_t CHANS[] = {
        { WIFI_BAND_2GHZ, 6 },
        { WIFI_BAND_6GHZ, 1 },
    };
    chanhop_t h;
    ASSERT_EQ(chanhop_init_bands(&h, CHANS, 2), 2);

    ASSERT_EQ(h.slots[0].freq_mhz, 2437);
    ASSERT_EQ(h.slots[0].band,     WIFI_BAND_2GHZ);
    ASSERT_EQ(h.slots[1].channel,  1);
    ASSERT_EQ(h.slots[1].band,     WIFI_BAND_6GHZ);
    ASSERT_EQ(h.slots[1].freq_mhz, 5955);

    /* Two slots that would be the same channel number without the band:
     * the rotation reaches 5955 and reports which band it is on. */
    ASSERT_EQ(chanhop_tick(&h, 1000), 1);
    chanhop_confirm_retune(&h, 1, 1000);
    ASSERT_EQ(chanhop_current_freq(&h), 2437);
    ASSERT_EQ(chanhop_current_band(&h), WIFI_BAND_2GHZ);

    ASSERT_EQ(chanhop_tick(&h, 9000), 1);
    ASSERT_EQ(chanhop_target_freq(&h), 5955);
    ASSERT_EQ(chanhop_target_band(&h), WIFI_BAND_6GHZ);
    chanhop_confirm_retune(&h, 1, 9000);
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    ASSERT_EQ(chanhop_current_freq(&h),    5955);
    ASSERT_EQ(chanhop_current_band(&h),    WIFI_BAND_6GHZ);
}

/* The bare-number initialiser still means what every pre-#167 caller
 * meant by it. Claim of absence: it can never produce a 6 GHz slot, so
 * a --hop list cannot wander into 6 GHz by accident — mutation-proven
 * with the same infer_band mutation as above. */
static void test_chanhop_init_from_bare_numbers_is_never_6ghz(void) {
    int chans[233];
    for (int i = 0; i < 233; i++) chans[i] = i + 1;
    chanhop_t h;
    int n = chanhop_init(&h, chans, 233);
    ASSERT_GT(n, 0);
    for (int i = 0; i < n; i++)
        ASSERT_NE(h.slots[i].band, WIFI_BAND_6GHZ);
}

/* #167 is explicit that DEFAULT_CHANNELS is out of scope: adding 6 GHz
 * or DFS to the shipped hop list changes which frequencies the radio
 * retunes to, which is an owner call. 6 GHz is expressible, not
 * enabled, and this pins the distinction.
 *
 * What the mutation run proved, precisely: editing DEFAULT_CHANNELS
 * (161 → 165) reddens this test, so the shipped list really is pinned
 * here. The no-6-GHz half is NOT independently provable — widening
 * wifi_freq_infer_band() to answer 6 GHz leaves this test green,
 * because every entry in the default list matches the 2.4 or 5 GHz row
 * first. That half holds by construction (the list is bare numbers and
 * chanhop_init() infers) and is proven by
 * test_chanhop_init_from_bare_numbers_is_never_6ghz instead. Stated
 * rather than claimed, per agents/converge.md step 5. */
static void test_default_rotation_stays_2_4_and_5_ghz(void) {
    chanhop_t h;
    int n = chanhop_init_default(&h);
    ASSERT_EQ(n, 11);
    for (int i = 0; i < n; i++) {
        ASSERT_NE(h.slots[i].band, WIFI_BAND_6GHZ);
        ASSERT_NE(h.slots[i].band, WIFI_BAND_UNKNOWN);
        ASSERT_GT(h.slots[i].freq_mhz, 0);
        ASSERT_LT(h.slots[i].freq_mhz, 5925);   /* below the 6 GHz edge */
    }
    ASSERT_EQ(h.slots[0].channel,  1);
    ASSERT_EQ(h.slots[0].freq_mhz, 2412);
    ASSERT_EQ(h.slots[n - 1].channel,  161);
    ASSERT_EQ(h.slots[n - 1].freq_mhz, 5805);
}

/* ── The other two callers of the band plan ──────────────────
 *
 * reg_obs_freq_mhz() and ap_band_label() each carried their own copy of
 * the channel-number ranges and now read the shared table. These pin
 * the behaviour that must NOT have changed when they were converted —
 * both reach operator-visible output (the [m] view, the beacon view and
 * the JSONL wifi_ap record), so a silent shift here would be a schema
 * change dressed as a refactor. */
static void test_reg_obs_freq_matches_the_shared_plan(void) {
    ASSERT_EQ(reg_obs_freq_mhz(1,   CH_SRC_DS_PARAM), 2412);
    ASSERT_EQ(reg_obs_freq_mhz(14,  CH_SRC_DS_PARAM), 2484);
    ASSERT_EQ(reg_obs_freq_mhz(36,  CH_SRC_HT_OPER),  5180);
    ASSERT_EQ(reg_obs_freq_mhz(177, CH_SRC_DS_PARAM), 5885);
    /* The IE is the only band knowledge this path has, and it is the
     * one way 6 GHz gets in: the same number without it is 5 GHz. */
    ASSERT_EQ(reg_obs_freq_mhz(37,  CH_SRC_HE_6GHZ),  6135);
    ASSERT_EQ(reg_obs_freq_mhz(37,  CH_SRC_DS_PARAM), 5185);
    ASSERT_EQ(reg_obs_freq_mhz(2,   CH_SRC_HE_6GHZ),  5935);
    ASSERT_EQ(reg_obs_freq_mhz(2,   CH_SRC_DS_PARAM), 2417);
    ASSERT_EQ(reg_obs_freq_mhz(20,  CH_SRC_DS_PARAM), 0);
    ASSERT_EQ(reg_obs_freq_mhz(234, CH_SRC_HE_6GHZ),  0);
}

static void test_band_label_matches_the_shared_plan(void) {
    ASSERT_STR(ap_band_label(1,   CH_SRC_DS_PARAM), "2.4 GHz");
    ASSERT_STR(ap_band_label(14,  CH_SRC_DS_PARAM), "2.4 GHz");
    ASSERT_STR(ap_band_label(32,  CH_SRC_DS_PARAM), "5 GHz");
    ASSERT_STR(ap_band_label(177, CH_SRC_DS_PARAM), "5 GHz");
    ASSERT_STR(ap_band_label(37,  CH_SRC_HE_6GHZ),  "6 GHz");
    ASSERT_STR(ap_band_label(15,  CH_SRC_DS_PARAM), "?");
    ASSERT_STR(ap_band_label(178, CH_SRC_DS_PARAM), "?");
    ASSERT_STR(ap_band_label(0,   CH_SRC_HE_6GHZ),  "?");
}

void run_wifi_freq_tests(void) {
    TEST_SUITE("wifi band plan: one converter, both directions (#167)");
    RUN_TEST(test_monitor_and_shared_converter_agree_across_bands);
    RUN_TEST(test_five_ghz_span_is_the_assignable_centres);
    RUN_TEST(test_five_ghz_edges_outside_the_span_are_not_channels);
    RUN_TEST(test_band_disambiguates_colliding_channel_numbers);
    RUN_TEST(test_6ghz_channel_two_is_off_grid_and_does_not_steal_5960);
    RUN_TEST(test_unmapped_frequencies_have_no_band_and_no_channel);
    RUN_TEST(test_channel_to_frequency_across_bands);
    RUN_TEST(test_channel_to_frequency_rejects_out_of_band_numbers);
    RUN_TEST(test_every_channel_round_trips_through_both_directions);
    RUN_TEST(test_infer_band_never_answers_6ghz);
    RUN_TEST(test_infer_band_splits_2_4_from_5);

    TEST_SUITE("wifi band plan: 6 GHz is expressible in the hop path (#167)");
    RUN_TEST(test_chanhop_band_freq_expresses_6ghz);
    RUN_TEST(test_chanhop_rotation_holds_a_6ghz_channel_at_5955);
    RUN_TEST(test_chanhop_init_from_bare_numbers_is_never_6ghz);
    RUN_TEST(test_default_rotation_stays_2_4_and_5_ghz);

    TEST_SUITE("wifi band plan: converted callers keep their behaviour (#167)");
    RUN_TEST(test_reg_obs_freq_matches_the_shared_plan);
    RUN_TEST(test_band_label_matches_the_shared_plan);
}
