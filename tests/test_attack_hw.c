#include <string.h>
#include <time.h>
#include "runner.h"
#include "attack_hw.h"
#include "beacon_snoop.h"

/*
 * Attack-hardware fingerprints (#151): the known-stack table, the
 * Pineapple setup-AP pairing, the verdict layer. The stack table ships
 * empty (no capture exists for any row), so its matcher is driven with
 * synthetic rows through hw_stack_match_table(); the synthetic rows
 * live here, never in the table.
 */

static const char SHA_OK[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static hw_stack_row_t good_row(void) {
    hw_stack_row_t r = { 0x1234abcdu, 8, SLOTH_TOOL_UNKNOWN,
                         "Synthetic stack", "test rig, synthetic", SHA_OK,
                         "test-01" };
    return r;
}

/* ── stack table ── */

static void test_stack_table_ships_empty(void) {
    /* Deliberate: no row has a capture behind it (#151). A row added
     * without bumping this has skipped the test step in attack_hw.c. */
    ASSERT_EQ(hw_stack_count(), 0);
    ASSERT(hw_stack_at(0) == NULL);
    ASSERT(hw_stack_at(-1) == NULL);
    ASSERT(hw_stack_match(0x1234abcdu, 8, NULL) == NULL);
}

static void test_every_shipped_stack_row_carries_a_capture(void) {
    /* The loop is vacuous while the table is empty, so the count is
     * asserted beside it; the validator it calls is proven on synthetic
     * rows below, so the first real row meets a guard that has been
     * seen to refuse. */
    ASSERT(hw_stack_count() >= 0);
    for (int i = 0; i < hw_stack_count(); i++)
        ASSERT(hw_stack_row_valid(hw_stack_at(i)));
}

static void test_stack_row_validator(void) {
    hw_stack_row_t r = good_row();
    ASSERT(hw_stack_row_valid(&r));
    ASSERT(!hw_stack_row_valid(NULL));

    r = good_row(); r.ie_order_hash = 0;   ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.ie_order_count = 0;  ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.stack = "";          ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.id = NULL;           ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.evidence = "";       ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.evidence = NULL;     ASSERT(!hw_stack_row_valid(&r));
    /* Unlike TOOL_SIGNATURES, a research row is refused outright. */
    r = good_row(); r.evidence = "UNVERIFIED - vendor docs";
    ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.capture_sha256 = NULL;  ASSERT(!hw_stack_row_valid(&r));
    r = good_row(); r.capture_sha256 = "abc"; ASSERT(!hw_stack_row_valid(&r));
    r = good_row();
    r.capture_sha256 =
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
    ASSERT(!hw_stack_row_valid(&r));
    r = good_row();
    r.capture_sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
    ASSERT(!hw_stack_row_valid(&r));
}

static void test_stack_match_pins_hash_and_count(void) {
    hw_stack_row_t rows[2] = { good_row(), good_row() };
    rows[1].ie_order_hash = 0x55555555u;
    rows[1].id = "test-02";
    int amb = -1;
    ASSERT(hw_stack_match_table(rows, 2, 0x1234abcdu, 8, &amb) == &rows[0]);
    ASSERT_EQ(amb, 0);
    ASSERT(hw_stack_match_table(rows, 2, 0x55555555u, 8, NULL) == &rows[1]);
    /* Same hash, different element count: a different stack. */
    ASSERT(hw_stack_match_table(rows, 2, 0x1234abcdu, 9, &amb) == NULL);
    ASSERT_EQ(amb, 0);
    /* 0 is "not decoded", never a value, even against a row of 0. */
    hw_stack_row_t zero = good_row();
    zero.ie_order_hash = 0;
    ASSERT(hw_stack_match_table(&zero, 1, 0, 8, NULL) == NULL);
    ASSERT(hw_stack_match_table(NULL, 0, 0x1234abcdu, 8, &amb) == NULL);
}

static void test_stack_collision_is_reported_not_resolved(void) {
    /* #151: a collision arrives as a second row with its own capture.
     * The matcher must then say "ambiguous", not let row order pick. */
    hw_stack_row_t rows[2] = { good_row(), good_row() };
    rows[1].tool = SLOTH_TOOL_PINEAPPLE_MK7;
    rows[1].id = "test-02";
    int amb = 0;
    ASSERT(hw_stack_match_table(rows, 2, 0x1234abcdu, 8, &amb) == NULL);
    ASSERT_EQ(amb, 1);
}

static int put_ie(uint8_t *buf, int off, uint8_t tag,
                  const uint8_t *body, int blen) {
    buf[off++] = tag;
    buf[off++] = (uint8_t)blen;
    if (blen > 0) memcpy(buf + off, body, (size_t)blen);
    return off + blen;
}

static void test_stack_answer_survives_transient_elements(void) {
    /* #151 acceptance: a hash taken while a transient element (CSA,
     * Quiet) is present must not produce a different stack. beacon_snoop
     * leaves those elements out of the hash, so the busy beacon reaches
     * the same row as the steady one, and nothing else. */
    static const uint8_t rates[] = { 0x82, 0x84, 0x8b, 0x96 };
    static const uint8_t tim[]   = { 0x00, 0x01, 0x00, 0x00 };
    static const uint8_t csa[]   = { 1, 11, 5 };
    static const uint8_t quiet[] = { 1, 1, 10, 0, 0, 0 };
    uint8_t ds[1] = { 6 };
    uint8_t steady[64], busy[96];
    int ns = 0, nb = 0;
    ns = put_ie(steady, ns, 0, (const uint8_t *)"Lab", 3);
    ns = put_ie(steady, ns, 1, rates, sizeof(rates));
    ns = put_ie(steady, ns, 3, ds, 1);
    ns = put_ie(steady, ns, 5, tim, sizeof(tim));
    nb = put_ie(busy, nb, 0, (const uint8_t *)"Lab", 3);
    nb = put_ie(busy, nb, 1, rates, sizeof(rates));
    nb = put_ie(busy, nb, 3, ds, 1);
    nb = put_ie(busy, nb, 37, csa, sizeof(csa));
    nb = put_ie(busy, nb, 5, tim, sizeof(tim));
    nb = put_ie(busy, nb, 40, quiet, sizeof(quiet));

    char ssid[33]; char enc[10]; int ch = 0;
    beacon_rsn_t rs, rb;
    beacon_parse_ies(steady, ns, 0, 102, ssid, &ch, enc, &rs, NULL);
    beacon_parse_ies(busy,   nb, 0, 102, ssid, &ch, enc, &rb, NULL);
    ASSERT(rs.fp.ie_order_hash != 0);

    hw_stack_row_t row = good_row();
    row.ie_order_hash  = rs.fp.ie_order_hash;
    row.ie_order_count = rs.fp.ie_order_count;
    ASSERT(hw_stack_match_table(&row, 1, rb.fp.ie_order_hash,
                                rb.fp.ie_order_count, NULL) == &row);
}

/* ── Pineapple setup SSID / pairing ── */

static void test_setup_ssid_shape(void) {
    uint16_t v = 0;
    ASSERT(hw_pineapple_setup_ssid("Pineapple_1a2B", &v));
    ASSERT_EQ(v, 0x1a2b);
    ASSERT(hw_pineapple_setup_ssid("Pineapple_0000", NULL));
    ASSERT(!hw_pineapple_setup_ssid("Pineapple_Guest", NULL));
    ASSERT(!hw_pineapple_setup_ssid("Pineapple_12345", NULL));
    ASSERT(!hw_pineapple_setup_ssid("Pineapple_123", NULL));
    ASSERT(!hw_pineapple_setup_ssid("pineapple_1234", NULL));
    ASSERT(!hw_pineapple_setup_ssid("Pineapple-1234", NULL));
    ASSERT(!hw_pineapple_setup_ssid("", NULL));
    ASSERT(!hw_pineapple_setup_ssid(NULL, NULL));
}

static sloth_state_t g_s;

static beacon_ap_t *add_ap(const uint8_t bssid[6], const char *ssid,
                           int channel, time_t seen) {
    beacon_ap_t *b = &g_s.beacon_aps[g_s.beacon_count++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, bssid, 6);
    snprintf(b->ssid, sizeof(b->ssid), "%s", ssid);
    b->channel   = channel;
    b->last_seen = seen;
    return b;
}

static void test_pairing_finds_the_setup_ap(void) {
    time_t now = 1000000;
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t lure[6]  = { 0x00, 0x13, 0x37, 0xa1, 0x00, 0x01 };
    static const uint8_t setup[6] = { 0x00, 0x13, 0x37, 0xa1, 0x1a, 0x2b };
    beacon_ap_t *k = add_ap(lure, "Starbucks", 6, now);
    add_ap(setup, "Pineapple_1A2B", 11, now - 5);
    hw_pine_pair_t p;
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 1);
    ASSERT_EQ(p.found, 1);
    ASSERT(memcmp(p.bssid, setup, 6) == 0);
    ASSERT_STR(p.ssid, "Pineapple_1A2B");
    ASSERT_EQ(p.channel, 11);
    ASSERT_EQ(p.suffix_matches, 1);

    /* Suffix naming neither BSSID: still a pairing, recorded as such. */
    snprintf(g_s.beacon_aps[1].ssid, 33, "%s", "Pineapple_ffff");
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 1);
    ASSERT_EQ(p.suffix_matches, 0);
    /* ...and the KARMA BSSID's own low bits count too. */
    snprintf(g_s.beacon_aps[1].ssid, 33, "%s", "Pineapple_0001");
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 1);
    ASSERT_EQ(p.suffix_matches, 1);
}

static void test_dual_band_enterprise_ap_does_not_pair(void) {
    /* #151 acceptance: a legitimate dual-radio AP, one BSSID per band,
     * adjacent MACs, one SSID, must not pair. */
    time_t now = 1000000;
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t b24[6] = { 0x00, 0x3a, 0x7d, 0x10, 0x20, 0x30 };
    static const uint8_t b5[6]  = { 0x00, 0x3a, 0x7d, 0x10, 0x20, 0x31 };
    beacon_ap_t *k = add_ap(b24, "CorpNet", 6, now);
    add_ap(b5, "CorpNet", 36, now);
    hw_pine_pair_t p;
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 0);
    ASSERT_EQ(p.found, 0);
    hw_verdict_t v;
    char note[96];
    hw_karma_context(&g_s, k, NULL, now, &v, note, sizeof(note));
    ASSERT_EQ((int)v.tier, (int)HW_TIER_NONE);
    ASSERT_STR(note, "");
}

static void test_pairing_refuses_self_stale_and_lookalikes(void) {
    time_t now = 1000000;
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t lure[6] = { 0x00, 0x13, 0x37, 0x00, 0x00, 0x01 };
    static const uint8_t oth[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    /* The KARMA BSSID itself beaconing the setup name: one radio. */
    beacon_ap_t *k = add_ap(lure, "Pineapple_0001", 6, now);
    hw_pine_pair_t p;
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 0);
    /* A stale setup AP: aged past BEACON_AGE_SECS. */
    add_ap(oth, "Pineapple_0002", 6, now - BEACON_AGE_SECS - 1);
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 0);
    /* The boundary itself is still live. */
    g_s.beacon_aps[1].last_seen = now - BEACON_AGE_SECS;
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 1);
    /* A cafe called Pineapple_Guest is not a setup AP. */
    snprintf(g_s.beacon_aps[1].ssid, 33, "%s", "Pineapple_Guest");
    ASSERT_EQ(hw_pineapple_pair(&g_s, k, now, &p), 0);
    ASSERT_EQ(hw_pineapple_pair(NULL, k, now, &p), 0);
    ASSERT_EQ(hw_pineapple_pair(&g_s, NULL, now, &p), 0);
}

/* ── verdict ── */

static const uint8_t OUI_HAK5[3]  = { 0x00, 0x13, 0x37 };
static const uint8_t OUI_ESP[3]   = { 0x24, 0x6f, 0x28 };
static const uint8_t OUI_OTHER[3] = { 0x00, 0x3a, 0x7d };

static const sloth_tool_sig_t *shipped(sloth_tool_id_t t) {
    for (int i = 0; i < tool_signature_count(); i++)
        if (tool_signature_at(i)->tool == t) return tool_signature_at(i);
    return NULL;
}

static void test_verdict_none_without_inputs(void) {
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_OTHER, 3);
    hw_verdict_t v;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_NONE);
    ASSERT_STR(v.label, "");
    ASSERT_STR(v.names, "");
    /* An Espressif OUI says "some ESP32", not a device. */
    memcpy(in.oui, OUI_ESP, 3);
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_NONE);
    hw_verdict_eval(NULL, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_NONE);
}

static void test_verdict_hak5_oui_alone_is_suspected(void) {
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_HAK5, 3);
    hw_verdict_t v;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);
    ASSERT_EQ((int)v.device, (int)SLOTH_TOOL_PINEAPPLE_MK7);
    ASSERT_STR(v.label, "suspected-pineapple-mk7");
    ASSERT_STR(v.names, "oui");
}

static void test_verdict_does_not_count_the_oui_twice(void) {
    /* The shipped Pineapple row IS the Hak5 OUI. Row + OUI is one
     * observation; it must read as one class, not two. */
    const sloth_tool_sig_t *row = shipped(SLOTH_TOOL_PINEAPPLE_MK7);
    ASSERT(row != NULL);
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_HAK5, 3);
    in.tool_row = row;
    hw_verdict_t v;
    hw_verdict_eval(&in, &v);
    ASSERT_STR(v.names, "tool");
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);
}

static void test_verdict_unbacked_signals_stay_suspected(void) {
    /* Tool row (UNVERIFIED) + pairing (docs, no capture): two classes,
     * neither capture-backed. #151's standard caps that at suspected. */
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_HAK5, 3);
    in.tool_row  = shipped(SLOTH_TOOL_PINEAPPLE_MK7);
    in.pine_pair = 1;
    hw_verdict_t v;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);
    ASSERT_STR(v.names, "tool+pair");
    ASSERT_EQ(v.backed, 0);
}

static void test_verdict_corroborates_with_a_backed_input(void) {
    sloth_tool_sig_t verified = *shipped(SLOTH_TOOL_PINEAPPLE_MK7);
    verified.unverified = 0;
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_HAK5, 3);
    in.tool_row  = &verified;
    in.pine_pair = 1;
    hw_verdict_t v;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_CORROBORATED);
    ASSERT_STR(v.label, "corroborated-pineapple-mk7");
    ASSERT_EQ(v.backed, HW_SIG_TOOL);
    /* One backed class alone is still one signal. */
    in.pine_pair = 0;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);

    /* A capture-backed stack row + the pairing. */
    hw_stack_row_t st = good_row();
    st.tool = SLOTH_TOOL_PINEAPPLE_MK7;
    memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_OTHER, 3);
    in.stack_row = &st;
    in.pine_pair = 1;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_CORROBORATED);
    ASSERT_STR(v.names, "stack+pair");
}

static void test_verdict_conflicts_cap_or_void(void) {
    hw_verdict_t v;
    /* A production stack recognised: the IE emitter is not attack
     * hardware, so nothing corroborates, whatever else agrees. */
    sloth_tool_sig_t verified = *shipped(SLOTH_TOOL_PINEAPPLE_MK7);
    verified.unverified = 0;
    hw_stack_row_t prod = good_row();   /* tool UNKNOWN = production */
    hw_inputs_t in; memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_HAK5, 3);
    in.tool_row  = &verified;
    in.pine_pair = 1;
    in.stack_row = &prod;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);
    ASSERT_EQ(v.conflict, 1);

    /* Two devices one signal each: no answer, conflict reported. */
    sloth_tool_sig_t mar = *shipped(SLOTH_TOOL_ESP32_MARAUDER);
    mar.unverified = 0;
    memset(&in, 0, sizeof(in));
    memcpy(in.oui, OUI_ESP, 3);
    in.tool_row  = &mar;
    in.pine_pair = 1;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_NONE);
    ASSERT_EQ(v.conflict, 1);
    ASSERT_STR(v.label, "");

    /* Majority wins but cannot corroborate past a dissent. */
    hw_stack_row_t ps = good_row();
    ps.tool = SLOTH_TOOL_PINEAPPLE_MK7;
    in.stack_row = &ps;
    hw_verdict_eval(&in, &v);
    ASSERT_EQ((int)v.device, (int)SLOTH_TOOL_PINEAPPLE_MK7);
    ASSERT_EQ((int)v.tier, (int)HW_TIER_SUSPECTED);
}

static void test_every_tool_has_a_slug(void) {
    ASSERT_STR(hw_device_slug(SLOTH_TOOL_UNKNOWN), "");
    for (int t = SLOTH_TOOL_UNKNOWN + 1; t < SLOTH_TOOL_COUNT; t++) {
        const char *sl = hw_device_slug((sloth_tool_id_t)t);
        ASSERT(sl[0] != '\0');
        /* "corroborated-" + slug must fit the label and alert_t field. */
        ASSERT(strlen(sl) + 13 < sizeof(((hw_verdict_t *)0)->label));
    }
}

static void test_verdict_format_round_trips(void) {
    char l[40], n[32];
    hw_verdict_format(HW_TIER_CORROBORATED, SLOTH_TOOL_ESP32_MARAUDER,
                      HW_SIG_TOOL | HW_SIG_STACK | HW_SIG_PAIR | HW_SIG_OUI,
                      l, sizeof(l), n, sizeof(n));
    ASSERT_STR(l, "corroborated-esp32-marauder");
    ASSERT_STR(n, "tool+stack+pair+oui");
    hw_verdict_format(HW_TIER_NONE, SLOTH_TOOL_PINEAPPLE_MK7, HW_SIG_OUI,
                      l, sizeof(l), n, sizeof(n));
    ASSERT_STR(l, ""); ASSERT_STR(n, "");
    hw_verdict_format(HW_TIER_SUSPECTED, SLOTH_TOOL_UNKNOWN, HW_SIG_OUI,
                      l, sizeof(l), n, sizeof(n));
    ASSERT_STR(l, "");
    hw_verdict_format(HW_TIER_SUSPECTED, SLOTH_TOOL_COUNT, HW_SIG_OUI,
                      l, sizeof(l), n, sizeof(n));
    ASSERT_STR(l, "");
    hw_verdict_format(7, SLOTH_TOOL_PINEAPPLE_MK7, HW_SIG_OUI,
                      l, sizeof(l), n, sizeof(n));
    ASSERT_STR(l, "");
}

static void test_karma_context_note(void) {
    time_t now = 1000000;
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t lure[6]  = { 0x00, 0x13, 0x37, 0xa1, 0x00, 0x01 };
    static const uint8_t setup[6] = { 0x00, 0x13, 0x37, 0xa1, 0x1a, 0x2b };
    beacon_ap_t *k = add_ap(lure, "Starbucks", 6, now);
    add_ap(setup, "Pineapple_1a2b", 11, now);
    hw_verdict_t v;
    char note[96];
    hw_karma_context(&g_s, k, NULL, now, &v, note, sizeof(note));
    ASSERT_STR(note, " +setup-AP Pineapple_1a2b@00:13:37:a1:1a:2b"
                     " hw:suspected-pineapple-mk7");
    ASSERT_STR(v.names, "pair+oui");
}

void run_attack_hw_tests(void) {
    TEST_SUITE("attack-hardware stack table (#151)");
    RUN_TEST(test_stack_table_ships_empty);
    RUN_TEST(test_every_shipped_stack_row_carries_a_capture);
    RUN_TEST(test_stack_row_validator);
    RUN_TEST(test_stack_match_pins_hash_and_count);
    RUN_TEST(test_stack_collision_is_reported_not_resolved);
    RUN_TEST(test_stack_answer_survives_transient_elements);

    TEST_SUITE("Pineapple setup-AP pairing (#151)");
    RUN_TEST(test_setup_ssid_shape);
    RUN_TEST(test_pairing_finds_the_setup_ap);
    RUN_TEST(test_dual_band_enterprise_ap_does_not_pair);
    RUN_TEST(test_pairing_refuses_self_stale_and_lookalikes);

    TEST_SUITE("attack-hardware verdict (#151)");
    RUN_TEST(test_verdict_none_without_inputs);
    RUN_TEST(test_verdict_hak5_oui_alone_is_suspected);
    RUN_TEST(test_verdict_does_not_count_the_oui_twice);
    RUN_TEST(test_verdict_unbacked_signals_stay_suspected);
    RUN_TEST(test_verdict_corroborates_with_a_backed_input);
    RUN_TEST(test_verdict_conflicts_cap_or_void);
    RUN_TEST(test_every_tool_has_a_slug);
    RUN_TEST(test_verdict_format_round_trips);
    RUN_TEST(test_karma_context_note);
}
