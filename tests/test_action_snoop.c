#include <string.h>
#include "runner.h"
#include "action_snoop.h"

/*
 * Action frames (management subtype 13) — issue #59.
 *
 * Frames are built byte by byte from IEEE 802.11-2020 rather than
 * replayed from a capture, per AGENTS.md ("parsers are tested with raw
 * byte arrays built from first principles per RFC"). That is also the
 * only option here: tests/ carries no pcap fixtures and the repo has no
 * attack radio. Same tradeoff test_beacon_snoop.c made for the #33
 * malformed-IE detector.
 *
 * 802.11 management header (24 bytes):
 *   [0]     FC byte 0: (subtype<<4)|(type<<2)|proto
 *   [1]     FC byte 1
 *   [2-3]   Duration
 *   [4-9]   addr1 = DA   — the STA being steered
 *   [10-15] addr2 = SA
 *   [16-21] addr3 = BSSID
 *   [22-23] Sequence control
 *   [24+]   frame body
 *
 * Action FC0 = (13<<4)|(0<<2)|0 = 0xD0.
 *
 * BTM Request body (§9.6.14.9), in fixed order:
 *   Category(1)=10  Action(1)=7  DialogToken(1)  RequestMode(1)
 *   DisassocTimer(2, LE)  ValidityInterval(1)
 *   [BSS Termination Duration(12)]   present iff RequestMode B3
 *   [Session Information URL(1+n)]   present iff RequestMode B4
 *   [Neighbor Report elements...]    the candidate list
 */

#define HDR 24

static const uint8_t AP_A[6]   = {0xaa,0xbb,0xcc,0x11,0x22,0x33};
static const uint8_t STA_A[6]  = {0x11,0x22,0x33,0x44,0x55,0x66};
static const uint8_t CAND_1[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
static const uint8_t CAND_2[6] = {0xde,0xad,0xbe,0xef,0x00,0x02};

static void fill_hdr(uint8_t *f, uint8_t fc0,
                     const uint8_t da[6], const uint8_t bssid[6]) {
    memset(f, 0, HDR);
    f[0] = fc0;
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, bssid, 6);   /* SA — the AP transmits its own steer */
    memcpy(f + 16, bssid, 6);
}

/* Write the six fixed BTM Request body bytes. Returns the next offset. */
static int put_btm_fixed(uint8_t *f, uint8_t token, uint8_t mode,
                         uint16_t disassoc_timer, uint8_t validity) {
    int off = HDR;
    f[off++] = ACTION_CAT_WNM;
    f[off++] = WNM_ACT_BTM_REQUEST;
    f[off++] = token;
    f[off++] = mode;
    f[off++] = (uint8_t)(disassoc_timer & 0xff);
    f[off++] = (uint8_t)(disassoc_timer >> 8);
    f[off++] = validity;
    return off;
}

/* Append one Neighbor Report element (tag 52) carrying `bssid`. */
static int put_candidate(uint8_t *f, int off, const uint8_t bssid[6]) {
    f[off++] = 52;    /* Neighbor Report */
    f[off++] = 13;    /* BSSID(6) + info(4) + opclass(1) + chan(1) + phy(1) */
    memcpy(f + off, bssid, 6); off += 6;
    f[off++] = 0x00; f[off++] = 0x00; f[off++] = 0x00; f[off++] = 0x00;
    f[off++] = 81;    /* operating class */
    f[off++] = 6;     /* channel */
    f[off++] = 7;     /* PHY type */
    return off;
}

/* ── category demux ──────────────────────────────────────── */

static void test_category_read(void) {
    uint8_t f[HDR + 2];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    f[HDR]     = ACTION_CAT_WNM;
    f[HDR + 1] = WNM_ACT_BTM_REQUEST;
    uint8_t act = 0;
    ASSERT_EQ(action_parse_category(f, (int)sizeof(f), &act), ACTION_CAT_WNM);
    ASSERT_EQ(act, WNM_ACT_BTM_REQUEST);
}

static void test_category_rejects_other_subtypes(void) {
    /* Deauth (0xC0), beacon (0x80), probe req (0x40) must not parse as
     * Action — the same negative-case discipline test_deauth_snoop.c uses. */
    uint8_t f[HDR + 2];
    fill_hdr(f, 0xC0, STA_A, AP_A);
    ASSERT_EQ(action_parse_category(f, (int)sizeof(f), NULL), -1);
    fill_hdr(f, 0x80, STA_A, AP_A);
    ASSERT_EQ(action_parse_category(f, (int)sizeof(f), NULL), -1);
    fill_hdr(f, 0x40, STA_A, AP_A);
    ASSERT_EQ(action_parse_category(f, (int)sizeof(f), NULL), -1);
}

static void test_category_rejects_short_frame(void) {
    uint8_t f[HDR + 1];              /* category present, action byte missing */
    fill_hdr(f, 0xD0, STA_A, AP_A);
    f[HDR] = ACTION_CAT_WNM;
    ASSERT_EQ(action_parse_category(f, (int)sizeof(f), NULL), -1);
    ASSERT_EQ(action_parse_category(f, HDR, NULL), -1);
    ASSERT_EQ(action_parse_category(NULL, 99, NULL), -1);
}

/* ── BTM Request parse ───────────────────────────────────── */

static void test_btm_minimal_no_candidates(void) {
    /* A bare "leave now" steer carries no candidate list. Legal, and
     * must parse rather than being mistaken for a truncated frame. */
    uint8_t f[HDR + 7];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    put_btm_fixed(f, 0x42, BTM_REQ_DISASSOC_IMM, 100, 255);

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, (int)sizeof(f), &r), 1);
    ASSERT_EQ(r.dialog_token, 0x42);
    ASSERT_EQ(r.disassoc_timer, 100);
    ASSERT_EQ(r.validity_interval, 255);
    ASSERT_EQ(r.candidate_count, 0);
    ASSERT(r.request_mode & BTM_REQ_DISASSOC_IMM);
    ASSERT_EQ(memcmp(r.target_sta, STA_A, 6), 0);
    ASSERT_EQ(memcmp(r.bssid,      AP_A,  6), 0);
}

static void test_btm_candidate_list(void) {
    uint8_t f[HDR + 7 + 2 * 15];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, BTM_REQ_PREF_CANDIDATE, 0, 0);
    off = put_candidate(f, off, CAND_1);
    off = put_candidate(f, off, CAND_2);

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, 2);
    ASSERT_EQ(memcmp(r.candidate_bssids[0], CAND_1, 6), 0);
    ASSERT_EQ(memcmp(r.candidate_bssids[1], CAND_2, 6), 0);
    ASSERT_EQ(r.candidates_truncated, 0);
}

static void test_btm_disassoc_imminent_is_bit2(void) {
    /* The bit that matters: Disassociation Imminent is B2 (0x04) per
     * Figure 9-924. Issue #59 calls it "bit 3"; read literally that is
     * 0x08 = BSS Termination Included, a different field. This pins the
     * spec reading so a future edit can't quietly shift it. */
    ASSERT_EQ(BTM_REQ_DISASSOC_IMM,  0x04);
    ASSERT_EQ(BTM_REQ_BSS_TERM_INCL, 0x08);

    uint8_t f[HDR + 7];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    put_btm_fixed(f, 1, 0x08, 0, 0);      /* BSS Termination, NOT disassoc */

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, HDR + 7, &r), 0);  /* needs the 12 bytes */
}

static void test_btm_skips_bss_termination_duration(void) {
    /* B3 inserts 12 bytes before the candidate list. Miscounting them
     * shifts every candidate BSSID that follows, so the candidate must
     * still come back intact. */
    uint8_t f[HDR + 7 + 12 + 15];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, BTM_REQ_BSS_TERM_INCL, 0, 0);
    memset(f + off, 0xEE, 12); off += 12;      /* BSS Termination Duration */
    off = put_candidate(f, off, CAND_1);

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, 1);
    ASSERT_EQ(memcmp(r.candidate_bssids[0], CAND_1, 6), 0);
}

static void test_btm_skips_session_url(void) {
    /* B4 inserts a length-prefixed URL. Same hazard as above. */
    const char *url = "https://example.invalid/captive";
    int ulen = (int)strlen(url);
    uint8_t f[HDR + 7 + 1 + 64 + 15];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, BTM_REQ_ESS_DISASSOC, 0, 0);
    f[off++] = (uint8_t)ulen;
    memcpy(f + off, url, (size_t)ulen); off += ulen;
    off = put_candidate(f, off, CAND_2);

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, 1);
    ASSERT_EQ(memcmp(r.candidate_bssids[0], CAND_2, 6), 0);
}

static void test_btm_both_optional_fields(void) {
    /* Both present at once — the ordering B3-then-B4 is what the
     * standard fixes, and getting it backwards still "parses". */
    uint8_t f[HDR + 7 + 12 + 1 + 8 + 15];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 9,
                            BTM_REQ_BSS_TERM_INCL | BTM_REQ_ESS_DISASSOC, 0, 0);
    memset(f + off, 0xEE, 12); off += 12;
    f[off++] = 8; memcpy(f + off, "http://x", 8); off += 8;
    off = put_candidate(f, off, CAND_1);

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.dialog_token, 9);
    ASSERT_EQ(r.candidate_count, 1);
    ASSERT_EQ(memcmp(r.candidate_bssids[0], CAND_1, 6), 0);
}

static void test_btm_rejects_wrong_category_and_action(void) {
    uint8_t f[HDR + 7];
    sloth_btm_req_t r;

    fill_hdr(f, 0xD0, STA_A, AP_A);
    put_btm_fixed(f, 1, 0, 0, 0);
    f[HDR] = ACTION_CAT_RRM;                    /* right action, wrong category */
    ASSERT_EQ(action_parse_btm_req(f, (int)sizeof(f), &r), 0);

    fill_hdr(f, 0xD0, STA_A, AP_A);
    put_btm_fixed(f, 1, 0, 0, 0);
    f[HDR + 1] = WNM_ACT_BTM_RESPONSE;          /* right category, wrong action */
    ASSERT_EQ(action_parse_btm_req(f, (int)sizeof(f), &r), 0);
}

static void test_btm_truncated_fixed_fields(void) {
    uint8_t f[HDR + 4];                          /* stops mid disassoc timer */
    fill_hdr(f, 0xD0, STA_A, AP_A);
    f[HDR] = ACTION_CAT_WNM; f[HDR+1] = WNM_ACT_BTM_REQUEST;
    f[HDR+2] = 1; f[HDR+3] = 0;
    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, (int)sizeof(f), &r), 0);
}

static void test_btm_truncated_candidate_ignored(void) {
    /* An element claiming more length than the frame holds must be
     * dropped, not read past — the #33 IE-overrun hazard in a new place. */
    uint8_t f[HDR + 7 + 4];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, 0, 0, 0);
    f[off++] = 52;      /* Neighbor Report */
    f[off++] = 200;     /* claims 200 bytes; 2 remain */
    f[off++] = 0xAA; f[off++] = 0xBB;

    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, 0);
}

static void test_btm_candidate_overflow_flagged(void) {
    /* More candidates than the bound: keep the first N, and say so
     * rather than silently dropping the rest. */
    uint8_t f[HDR + 7 + 15 * (SLOTH_BTM_MAX_CANDIDATES + 3)];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, 0, 0, 0);
    for (int i = 0; i < SLOTH_BTM_MAX_CANDIDATES + 3; i++) {
        uint8_t b[6] = {0x02,0x00,0x00,0x00,0x00,(uint8_t)i};
        off = put_candidate(f, off, b);
    }
    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, SLOTH_BTM_MAX_CANDIDATES);
    ASSERT_EQ(r.candidates_truncated, 1);
}

static void test_btm_output_zeroed_on_reject(void) {
    /* A failed parse must not leave a previous frame's candidates
     * visible to the caller. */
    uint8_t f[HDR + 7 + 15];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    int off = put_btm_fixed(f, 1, 0, 0, 0);
    off = put_candidate(f, off, CAND_1);
    sloth_btm_req_t r;
    ASSERT_EQ(action_parse_btm_req(f, off, &r), 1);
    ASSERT_EQ(r.candidate_count, 1);

    uint8_t bad[HDR + 2];
    fill_hdr(bad, 0xC0, STA_A, AP_A);            /* deauth, not action */
    ASSERT_EQ(action_parse_btm_req(bad, (int)sizeof(bad), &r), 0);
    ASSERT_EQ(r.candidate_count, 0);
    ASSERT_EQ(r.dialog_token, 0);
}

/* ── per-category counting ───────────────────────────────── */

static void test_observe_counts_by_category(void) {
    action_clear();
    uint8_t f[HDR + 2];

    fill_hdr(f, 0xD0, STA_A, AP_A);
    f[HDR] = ACTION_CAT_WNM;  action_observe(f, (int)sizeof(f), 0);
    f[HDR] = ACTION_CAT_WNM;  action_observe(f, (int)sizeof(f), 0);
    f[HDR] = ACTION_CAT_RRM;  action_observe(f, (int)sizeof(f), 0);
    f[HDR] = ACTION_CAT_FT;   action_observe(f, (int)sizeof(f), 0);

    ASSERT_EQ(action_category_count(ACTION_CAT_WNM), 2);
    ASSERT_EQ(action_category_count(ACTION_CAT_RRM), 1);
    ASSERT_EQ(action_category_count(ACTION_CAT_FT),  1);
    ASSERT_EQ(action_category_count(ACTION_CAT_VENDOR), 0);
    ASSERT_EQ(action_total_count(), 4);
    action_clear();
    ASSERT_EQ(action_total_count(), 0);
}

static void test_observe_counts_unhandled_categories(void) {
    /* A category with no handler is still counted — otherwise a new
     * management surface appearing on the air is invisible, which is
     * the exact hole #59 exists to close. */
    action_clear();
    uint8_t f[HDR + 2];
    fill_hdr(f, 0xD0, STA_A, AP_A);
    f[HDR] = ACTION_CAT_VENDOR;  action_observe(f, (int)sizeof(f), 0);
    f[HDR] = 200;                action_observe(f, (int)sizeof(f), 0);
    ASSERT_EQ(action_category_count(ACTION_CAT_VENDOR), 1);
    ASSERT_EQ(action_category_count(200), 1);
    ASSERT_EQ(action_total_count(), 2);
    action_clear();
}

static void test_observe_ignores_non_action(void) {
    action_clear();
    uint8_t f[HDR + 2];
    fill_hdr(f, 0xC0, STA_A, AP_A);      /* deauth */
    action_observe(f, (int)sizeof(f), 0);
    fill_hdr(f, 0x80, STA_A, AP_A);      /* beacon */
    action_observe(f, (int)sizeof(f), 0);
    ASSERT_EQ(action_total_count(), 0);
    action_clear();
}

void run_action_snoop_tests(void) {
    TEST_SUITE("action frame category demux (#59)");
    RUN_TEST(test_category_read);
    RUN_TEST(test_category_rejects_other_subtypes);
    RUN_TEST(test_category_rejects_short_frame);

    TEST_SUITE("BTM Request parse (#59)");
    RUN_TEST(test_btm_minimal_no_candidates);
    RUN_TEST(test_btm_candidate_list);
    RUN_TEST(test_btm_disassoc_imminent_is_bit2);
    RUN_TEST(test_btm_skips_bss_termination_duration);
    RUN_TEST(test_btm_skips_session_url);
    RUN_TEST(test_btm_both_optional_fields);
    RUN_TEST(test_btm_rejects_wrong_category_and_action);
    RUN_TEST(test_btm_truncated_fixed_fields);
    RUN_TEST(test_btm_truncated_candidate_ignored);
    RUN_TEST(test_btm_candidate_overflow_flagged);
    RUN_TEST(test_btm_output_zeroed_on_reject);

    TEST_SUITE("action frame counting (#59)");
    RUN_TEST(test_observe_counts_by_category);
    RUN_TEST(test_observe_counts_unhandled_categories);
    RUN_TEST(test_observe_ignores_non_action);
}
