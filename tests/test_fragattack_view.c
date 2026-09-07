#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "fragattack.h"
#include "views/fragattack.h"

/*
 * FragAttacks tracker view — issue #75 slice 5.
 *
 * fragattack.c's own detector logic (the seven counters, the ordering
 * gate, the CVE-specific arithmetic) is exhaustively covered by
 * tests/test_fragattack.c. This file covers the layer slice 5 adds:
 * frag_snapshot()'s mirror into frag_bss_row_t (sort order, selection
 * clamp, the protected_frames-is-not-a-finding exclusion) and the view
 * that renders it. Frames are still hand-built per IEEE 802.11-2020,
 * not captures — a real detector hit is what exercises the mirror
 * honestly, rather than poking counters that could never occur
 * together in the shipped code.
 */

#define FC1_FROMDS    0x02
#define FC1_PROTECTED 0x40

static const uint8_t BSSID_A[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x01 };
static const uint8_t BSSID_B[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x02 };
static const uint8_t STA_A[6]   = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x10 };
static const uint8_t STA_B[6]   = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x20 };

/* One downlink (FromDS) data frame: addr1 = DA, addr2 = BSSID,
 * addr3 = SA. Protected frames carry no LLC header — same shape
 * test_fragattack.c's build() uses. */
static int build(uint8_t *f, uint8_t fc1, const uint8_t *da,
                 const uint8_t *bssid, const uint8_t *sa) {
    memset(f, 0, 64);
    f[0] = (uint8_t)(2 << 2);
    f[1] = (uint8_t)(fc1 | FC1_FROMDS);
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, bssid, 6);
    memcpy(f + 16, sa,    6);
    if (fc1 & FC1_PROTECTED) return 24 + 16;
    f[24] = 0xaa; f[25] = 0xaa; f[26] = 0x03;   /* LLC/SNAP */
    f[30] = 0x08; f[31] = 0x00;                 /* EtherType IPv4 */
    f[32] = 0x45;
    return 36;
}

/* Witnesses a key install (encrypted frame) on (bssid, sta), then a
 * plaintext data frame from the same station — the exact sequence
 * FRAG_PLAINTEXT fires on (CVE-2020-26140/-26143). Bumps
 * plaintext_unicast by exactly one and protected_frames by exactly one. */
static void fire_one_plaintext_finding(const uint8_t *bssid,
                                       const uint8_t *sta, time_t now) {
    uint8_t f[64];
    int n = build(f, FC1_PROTECTED, STA_B, bssid, sta);
    frag_observe(f, n, now);
    n = build(f, 0, STA_B, bssid, sta);
    frag_observe(f, n, now + 1);
}

static void capture_draw(const sloth_state_t *s, char *buf, int sz) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    view_fragattack_draw(s);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

static void setup(void) { frag_clear(); }

/* ── empty state ────────────────────────────────────────────────────── */

static void test_empty_state_renders_without_crash(void) {
    setup();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 0);

    char buf[4096];
    capture_draw(&s, buf, sizeof(buf));
    ASSERT(strstr(buf, "no FragAttacks activity") != NULL);
}

static void test_null_state_is_safe(void) {
    setup();
    frag_snapshot(NULL);
    ASSERT(1);
}

/* ── mirroring ──────────────────────────────────────────────────────── */

static void test_snapshot_mirrors_a_real_finding(void) {
    setup();
    fire_one_plaintext_finding(BSSID_A, STA_A, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 1);
    ASSERT_EQ(memcmp(s.frag_rows[0].bssid, BSSID_A, 6), 0);
    ASSERT_EQ((int)s.frag_rows[0].plaintext_unicast, 1);
    ASSERT_EQ((int)s.frag_rows[0].protected_frames, 1);
    /* The other six counters must stay at zero — this sequence fires
     * exactly one of the seven rules. */
    ASSERT_EQ((int)s.frag_rows[0].plaintext_bcast_frag, 0);
    ASSERT_EQ((int)s.frag_rows[0].cache_poison, 0);
    ASSERT_EQ((int)s.frag_rows[0].mixed_protect, 0);
    ASSERT_EQ((int)s.frag_rows[0].amsdu_flip, 0);
    ASSERT_EQ((int)s.frag_rows[0].amsdu_eapol_spoof, 0);
    ASSERT_EQ((int)s.frag_rows[0].mixed_key, 0);
    ASSERT_EQ(memcmp(s.frag_rows[0].last_sa, STA_A, 6), 0);
}

static void test_protected_frames_alone_is_not_a_finding(void) {
    /* A BSS with stations that installed keys and nothing else wrong
     * must render as zero findings — protected_frames is the gate's
     * own evidence counter, not a rule firing. Summing it in would
     * make an ordinary encrypted network look attacked. */
    setup();
    uint8_t f[64];
    int n = build(f, FC1_PROTECTED, STA_B, BSSID_A, STA_A);
    frag_observe(f, n, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 1);
    ASSERT(s.frag_rows[0].protected_frames > 0);

    char buf[4096];
    capture_draw(&s, buf, sizeof(buf));
    /* "0 findings" must appear somewhere in the summary line; a stray
     * "1" from protected_frames leaking into the total would fail this. */
    ASSERT(strstr(buf, " 0 findings") != NULL);
}

static void test_rows_sort_by_last_hit_descending(void) {
    setup();
    fire_one_plaintext_finding(BSSID_A, STA_A, 1000);
    fire_one_plaintext_finding(BSSID_B, STA_A, 2000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 2);
    /* BSSID_B fired later, so it belongs at the top. */
    ASSERT_EQ(memcmp(s.frag_rows[0].bssid, BSSID_B, 6), 0);
    ASSERT_EQ(memcmp(s.frag_rows[1].bssid, BSSID_A, 6), 0);
}

static void test_selection_is_clamped(void) {
    setup();
    fire_one_plaintext_finding(BSSID_A, STA_A, 1000);
    fire_one_plaintext_finding(BSSID_B, STA_A, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 2);
    s.frag_sel = 1;

    setup();
    frag_snapshot(&s);
    ASSERT_EQ(s.frag_row_count, 0);
    ASSERT_EQ(s.frag_sel, 0);
}

/* ── populated render ──────────────────────────────────────────────── */

static void test_populated_render_names_the_firing_cve(void) {
    setup();
    fire_one_plaintext_finding(BSSID_A, STA_A, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    frag_snapshot(&s);
    char buf[4096];
    capture_draw(&s, buf, sizeof(buf));

    /* Exact rows, not just substring presence — a mutant that swapped
     * which counter feeds which title (FRAG_PLAINTEXT's count landing
     * on FRAG_BCAST's row, say) would still pass a bare strstr for
     * "FRAG_PLAINTEXT" and "CVE-2020-26140/-26143" since both strings
     * are literals either way; tying the count to the row is what
     * catches that. */
    char fired[128], quiet[128];
    snprintf(fired, sizeof(fired), "  %-18s %-24s %6u\n",
             "FRAG_PLAINTEXT", "CVE-2020-26140/-26143", 1u);
    ASSERT(strstr(buf, fired) != NULL);

    /* A rule that never fired for this BSSID still gets a row — same
     * "uncited rows are the feature" argument VIEW_RESEARCH makes. */
    snprintf(quiet, sizeof(quiet), "  %-18s %-24s %6u\n",
             "FRAG_MIXKEY", "CVE-2020-24587", 0u);
    ASSERT(strstr(buf, quiet) != NULL);
}

/* ── navigation ────────────────────────────────────────────────────── */

static void test_nav_moves_within_bounds(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.frag_row_count = 3;
    s.frag_sel = 0;

    view_fragattack_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.frag_sel, 0);           /* already at top */

    view_fragattack_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.frag_sel, 1);
    view_fragattack_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.frag_sel, 2);
    view_fragattack_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.frag_sel, 2);           /* already at bottom */

    view_fragattack_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.frag_sel, 1);
}

static void test_nav_on_empty_table_is_a_no_op(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_fragattack_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.frag_sel, 0);
    view_fragattack_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.frag_sel, 0);
}

void run_fragattack_view_tests(void);
void run_fragattack_view_tests(void) {
    TEST_SUITE("fragattack view: snapshot mirroring (#75 slice 5)");
    RUN_TEST(test_empty_state_renders_without_crash);
    RUN_TEST(test_null_state_is_safe);
    RUN_TEST(test_snapshot_mirrors_a_real_finding);
    RUN_TEST(test_protected_frames_alone_is_not_a_finding);
    RUN_TEST(test_rows_sort_by_last_hit_descending);
    RUN_TEST(test_selection_is_clamped);

    TEST_SUITE("fragattack view: render + nav (#75 slice 5)");
    RUN_TEST(test_populated_render_names_the_firing_cve);
    RUN_TEST(test_nav_moves_within_bounds);
    RUN_TEST(test_nav_on_empty_table_is_a_no_op);
}
