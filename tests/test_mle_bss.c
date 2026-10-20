#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "mle.h"
#include "alerts.h"
#include "beacon_snoop.h"
#include "dot11_frame.h"
#include "sloth_clock.h"
#include "frame_build.h"

/*
 * Per-BSSID Multi-Link advertisement — #104 slice 6:
 * MLE_RECONFIG_NO_MLO and MLE_PR_BEACON_DIFF.
 *
 * Every frame is built here from the clause layout, not captured:
 *
 *   Beacon / Probe Response (IEEE 802.11-2020 §9.3.3.2 / §9.3.3.10)
 *     MAC header(24): FC, Duration, A1=DA, A2=SA, A3=BSSID, SeqCtl
 *     Timestamp(8) Beacon Interval(2) Capability(2)
 *     elements...
 *
 *   Multi-Link element (IEEE 802.11be-2024 §9.4.2.322), as an Element
 *   ID Extension: 255, Length, ExtID 107, then
 *     Multi-Link Control(2)  bits 0-2 Type: 0 Basic, 2 Reconfiguration
 *                            Basic Presence Bitmap, as bits of the word:
 *                            0x0010 Link ID Info, 0x0020 BSS Parameters
 *                            Change Count, 0x0080 EML Capabilities,
 *                            0x0100 MLD Capabilities, 0x0200 AP MLD ID
 *     Common Info: Length(1) MLD MAC(6) [Link ID Info(1)] [BPCC(1)]
 *                  [EML Capa(2)] [MLD Capa(2)] [AP MLD ID(1)]
 *     Link Info: Per-STA Profile subelements (ID 0)
 *
 * Bit values and field order are hostapd src/common/ieee802_11_defs.h
 * and hostapd_eid_eht_basic_ml_common() / hostapd_eid_eht_reconf_ml()
 * in src/ap/ieee802_11_eht.c; Wireshark's packet-ieee80211.c dissects
 * the same layout. The builders below emit exactly what those two
 * hostapd functions emit, so "conformant" in a test name means "what
 * hostapd sends", which is the strongest public statement of it.
 */

static const uint8_t BSSID[6]  = { 0x02, 0xbb, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t BSSID2[6] = { 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t BCAST[6]  = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t STA[6]    = { 0x02, 0xcc, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t MLD_A[6]  = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t MLD_B[6]  = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t MLD_X[6]  = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x77 };
static const uint8_t LNK1[6]   = { 0x02, 0xaa, 0x00, 0x00, 0x01, 0x01 };
static const uint8_t LNK2[6]   = { 0x02, 0xaa, 0x00, 0x00, 0x01, 0x02 };

#define T0 ((time_t)1700000000)

/* Basic MLE as hostapd_eid_eht_basic_ml_common() builds it: Link ID
 * Info (when link_id >= 0), BSS Parameters Change Count, EML
 * Capabilities and MLD Capabilities always; AP MLD ID only when
 * ap_mld_id >= 0. Then `nprof` Complete Per-STA Profiles, the shape a
 * multi-link Probe Response carries for the other affiliated APs:
 *   ID 0, Length 11,
 *   STA Control(2) = link_id | 0x0010 Complete | 0x0020 MAC Present,
 *   STA Info Length(1) = 7 (itself + MAC), STA MAC(6),
 *   STA Profile: Capability Information(2). */
static void put_basic_mle(fb_t *b, const uint8_t mld[6], int link_id,
                          int ap_mld_id, uint8_t bpcc,
                          const uint8_t (*prof_mac)[6], const int *prof_link,
                          int nprof) {
    uint8_t e[128];
    int n = 0;
    uint16_t ctl = 0x0000 | 0x0020 | 0x0080 | 0x0100;
    if (link_id >= 0)   ctl |= 0x0010;
    if (ap_mld_id >= 0) ctl |= 0x0200;
    e[n++] = (uint8_t)(ctl & 0xff);
    e[n++] = (uint8_t)(ctl >> 8);
    int cil = 1 + 6 + (link_id >= 0) + 1 + 2 + 2 + (ap_mld_id >= 0);
    e[n++] = (uint8_t)cil;
    memcpy(e + n, mld, 6); n += 6;
    if (link_id >= 0) e[n++] = (uint8_t)(link_id & 0x0f);
    e[n++] = bpcc;
    e[n++] = 0x00; e[n++] = 0x00;          /* EML Capabilities */
    e[n++] = 0x01; e[n++] = 0x00;          /* MLD Capabilities: max 2 links */
    if (ap_mld_id >= 0) e[n++] = (uint8_t)ap_mld_id;
    for (int i = 0; i < nprof; i++) {
        e[n++] = 0;                         /* Per-STA Profile */
        e[n++] = 11;
        uint16_t sc = (uint16_t)((prof_link[i] & 0x0f) | 0x0010 | 0x0020);
        e[n++] = (uint8_t)(sc & 0xff);
        e[n++] = (uint8_t)(sc >> 8);
        e[n++] = 7;                         /* STA Info Length */
        memcpy(e + n, prof_mac[i], 6); n += 6;
        e[n++] = 0x11; e[n++] = 0x00;       /* Capability: ESS | Privacy */
    }
    fb_ie_ext(b, MLE_EXT_ID, e, n);
}

/* Reconfiguration MLE as hostapd_eid_eht_reconf_ml() builds it:
 * Control = Type 2 with an empty Presence Bitmap, Common Info Length 1
 * (itself only), then one Per-STA Profile announcing removal of
 * `link_id`: ID 0, Length 5, STA Control(2) = link_id | 0x0040 AP
 * Removal Timer Present, STA Info Length(1) = 3, AP Removal Timer(2). */
static void put_reconf_mle(fb_t *b, int link_id, uint16_t timer) {
    uint8_t e[16];
    int n = 0;
    e[n++] = 0x02; e[n++] = 0x00;          /* Type 2, no presence bits */
    e[n++] = 1;                            /* Common Info Length */
    e[n++] = 0; e[n++] = 5;                /* Per-STA Profile, length 5 */
    uint16_t sc = (uint16_t)((link_id & 0x0f) | 0x0040);
    e[n++] = (uint8_t)(sc & 0xff);
    e[n++] = (uint8_t)(sc >> 8);
    e[n++] = 3;                            /* STA Info Length */
    e[n++] = (uint8_t)(timer & 0xff);
    e[n++] = (uint8_t)(timer >> 8);
    fb_ie_ext(b, MLE_EXT_ID, e, n);
}

/* Header + fixed fields + SSID for a Beacon (subtype 8, to broadcast)
 * or a Probe Response (subtype 5, to STA). */
static void put_head(fb_t *b, int subtype, const uint8_t bssid[6]) {
    fb_mgmt(b, (uint8_t)subtype, 0, subtype == 8 ? BCAST : STA,
            bssid, bssid, 0x0010, 0);
    fb_beacon_fixed(b, 0x1122334455ull, 100, 0x0011);
    fb_ssid(b, "mlo-lab");
}

static void observe(const fb_t *b, time_t now, uint64_t ev) {
    dot11_frame_t f;
    ASSERT(fb_ok(b));
    dot11_frame_decode(b->buf, b->len, NULL, &f);
    f.event_id = ev;
    mle_bss_observe_frame(&f, now);
}

static sloth_state_t g_s;

static const sloth_mle_bss_t *row(const uint8_t bssid[6]) {
    mle_snapshot(&g_s);
    for (int i = 0; i < g_s.mle_bss_count; i++)
        if (memcmp(g_s.mle_bss[i].bssid, bssid, 6) == 0)
            return &g_s.mle_bss[i];
    return NULL;
}

/* Beacon carrying only the hostapd Basic MLE for MLD_A, link 1. */
static void beacon_basic(const uint8_t bssid[6], const uint8_t mld[6],
                         int link_id, time_t now, uint64_t ev) {
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, bssid);
    put_basic_mle(&b, mld, link_id, -1, 0, NULL, NULL, 0);
    observe(&b, now, ev);
}

/* ── MLE_RECONFIG_NO_MLO ─────────────────────────────────────────── */

static void test_reconfig_mle_without_any_basic_mle_is_flagged(void) {
    mle_clear();
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 41);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 1);
    ASSERT_EQ((int)r->reconfig_no_mlo_subtype, 8);
    ASSERT_EQ((long)r->reconfig_no_mlo_last_seen, (long)T0);
    ASSERT_EQ((int)r->reconfig_no_mlo_ev, 41);
    ASSERT_EQ((int)r->basic_mle_seen, 0);
}

/* The hostapd shape: hostapd_eid_eht_ml_beacon() emits the Basic MLE
 * and then the Reconfiguration MLE, in the same Beacon. A conformant AP
 * MLD removing a link, heard for the first time. Seen to fail by moving
 * the `basic_mle_seen` store after the reconfiguration check: red. */
static void test_reconfig_alongside_basic_in_one_frame_not_flagged(void) {
    mle_clear();
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_basic_mle(&b, MLD_A, 1, -1, 3, NULL, NULL, 0);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->basic_mle_seen, 1);
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 0);
}

/* History counts: a BSSID that advertised a Basic MLE earlier and then
 * sends a frame with only the Reconfiguration MLE is not "never MLO".
 * Seen to fail by testing only the frame's own Basic MLE: red. */
static void test_reconfig_after_an_earlier_basic_mle_not_flagged(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_reconf_mle(&b, 2, 40);
    observe(&b, T0 + 5, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 0);
}

static void test_reconfig_in_a_probe_response_is_flagged_as_one(void) {
    mle_clear();
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 5, BSSID);
    put_reconf_mle(&b, 0, 10);
    observe(&b, T0, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 1);
    ASSERT_EQ((int)r->reconfig_no_mlo_subtype, 5);
}

/* A Basic MLE whose Common Info Length cannot hold the MLD MAC is
 * MLE_COMMON_INFO_LEN_BAD's finding. It is still the BSS claiming AP
 * MLD membership, so it suppresses this rule rather than adding to it.
 * Seen to fail by setting `basic` only for a well-formed element: red. */
static void test_a_malformed_basic_mle_still_counts_as_advertised(void) {
    mle_clear();
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    static const uint8_t bad[] = {
        0x00, 0x00,                        /* Basic, empty bitmap */
        0x03,                              /* Common Info Length < 7 */
        0x02, 0xaa, 0x00, 0x00, 0x00, 0x01
    };
    fb_ie_ext(&b, MLE_EXT_ID, bad, (int)sizeof bad);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->basic_mle_seen, 1);
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 0);
}

/* Sticky, like the sibling MLE rules: a Basic MLE heard afterwards does
 * not un-send the frame that had none. */
static void test_reconfig_finding_persists_across_later_basic_frames(void) {
    mle_clear();
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 0);
    for (int i = 1; i <= 3; i++) beacon_basic(BSSID, MLD_A, 1, T0 + i, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->reconfig_no_mlo_total, 1);
    ASSERT_EQ((int)r->basic_mle_seen, 1);
}

/* No Multi-Link element of any variant: no row, so the 64-row table is
 * never spent on legacy APs. Seen to fail by removing the early return
 * on `!basic && !reconf`: red. */
static void test_a_legacy_beacon_creates_no_row(void) {
    mle_clear();
    uint8_t buf[128]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    observe(&b, T0, 0);
    ASSERT_EQ(mle_bss_count(), 0);
}

/* Only Beacons and Probe Responses describe the BSS. A Reconfiguration
 * MLE in an Association Response (subtype 1) is not this rule's frame.
 * Seen to fail by dropping the subtype filter: red. */
static void test_other_subtypes_are_ignored(void) {
    mle_clear();
    uint8_t buf[128]; fb_t b; fb_init(&b, buf, sizeof buf);
    fb_mgmt(&b, 1, 0, STA, BSSID, BSSID, 0x0010, 0);
    fb_assoc_resp_fixed(&b, 0x0011, 0, 1);
    /* Six fixed octets, not twelve: pad so a parser that wrongly skipped
     * twelve would still find the element. */
    for (int i = 0; i < 6; i++) fb_u8(&b, 0xdd);
    fb_u8(&b, 0); fb_u8(&b, 0);           /* empty SSID, 2 bytes */
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 0);
    ASSERT_EQ(mle_bss_count(), 0);
}

/* ── MLE_PR_BEACON_DIFF ──────────────────────────────────────────── */

/* Probe Response from the hostapd ML probe path with `mld`/`link_id`
 * as its own identity, after an AP-MLD-ID-bearing Basic MLE for
 * `other_mld` (the requested MLD of a multiple-BSSID set) carrying
 * Complete Per-STA Profiles for links 2 and 3. */
static void probe_resp(const uint8_t bssid[6], const uint8_t mld[6],
                       int link_id, int with_other, time_t now,
                       uint64_t ev) {
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 5, bssid);
    if (with_other) {
        const uint8_t pm[2][6] = {
            { 0x02, 0xaa, 0x00, 0x00, 0x07, 0x02 },
            { 0x02, 0xaa, 0x00, 0x00, 0x07, 0x03 } };
        const int pl[2] = { 2, 3 };
        put_basic_mle(&b, MLD_X, 0, 1, 9, pm, pl, 2);
    }
    put_basic_mle(&b, mld, link_id, -1, 0, NULL, NULL, 0);
    observe(&b, now, ev);
}

static void test_probe_response_naming_another_mld_is_flagged(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 101);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + 2, 102);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 1);
    ASSERT_EQ((int)r->diff_mld_mac, 1);
    ASSERT_EQ((int)r->diff_link_id, 0);
    ASSERT_EQ(memcmp(r->diff_beacon_mld_mac, MLD_A, 6), 0);
    ASSERT_EQ(memcmp(r->diff_pr_mld_mac, MLD_B, 6), 0);
    ASSERT_EQ((int)r->diff_beacon_ev, 101);
    ASSERT_EQ((int)r->diff_pr_ev, 102);
    ASSERT_EQ((long)r->pr_beacon_diff_last_seen, (long)(T0 + 2));
}

static void test_probe_response_naming_another_link_id_is_flagged(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_A, 4, 0, T0 + 1, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 1);
    ASSERT_EQ((int)r->diff_mld_mac, 0);
    ASSERT_EQ((int)r->diff_link_id, 1);
    ASSERT_EQ((int)r->diff_beacon_link_id, 1);
    ASSERT_EQ((int)r->diff_pr_link_id, 4);
}

/* The case the rule's shape exists for. hostapd's multi-link Probe
 * Response (hostapd_probe_resp_fill_elems) carries the requested AP
 * MLD's Basic MLE first — AP MLD ID present, a different MLD MAC,
 * Complete Per-STA Profiles for links the Beacon never lists, another
 * BSS Parameters Change Count — and then this BSS's own, which matches
 * its Beacon. Nothing fires.
 *
 * Seen to fail by removing the AP MLD ID skip in mle_frame_scan(): the
 * first element becomes the identity and the rule reports MLD_X. The
 * link-set and change-count differences are not compared at all, so no
 * mutation of a comparison can isolate them; they are present to show
 * the frame is the realistic one. */
static void test_conformant_ml_probe_response_does_not_fire(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_A, 1, 1, T0 + 1, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* A Probe Response whose own Basic MLE carries Complete Per-STA
 * Profiles (a link set the Beacon does not) and the same identity. */
static void test_per_sta_profiles_in_own_mle_do_not_fire(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 5, BSSID);
    uint8_t m[2][6];
    memcpy(m[0], LNK1, 6); memcpy(m[1], LNK2, 6);
    const int pl[2] = { 0, 2 };
    put_basic_mle(&b, MLD_A, 1, -1, 7, (const uint8_t (*)[6])m, pl, 2);
    observe(&b, T0 + 1, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* Link ID is compared only when BOTH frames carry Link ID Info. Here
 * the Probe Response leaves bit 4 clear (its link_id field reads 0) and
 * the Beacon says link 1. Seen to fail by dropping `sc.has_link_id &&`
 * from the comparison: red. */
static void test_link_id_compared_only_when_both_carry_it(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_A, -1, 0, T0 + 1, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* MLE_PR_BEACON_WIN_SECS is inclusive: 30 s old compares, 31 s does
 * not. Seen to fail by `<` for `<=` (the first assert) and by dropping
 * the age test (the second): red each. */
static void test_window_is_inclusive_and_bounded(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + MLE_PR_BEACON_WIN_SECS, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 1);

    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + MLE_PR_BEACON_WIN_SECS + 1, 0);
    r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* A capture timestamp that steps backwards is compared by distance, not
 * by an unsigned-looking subtraction. */
static void test_beacon_from_the_future_is_still_aged(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0 + 100, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* Without a Beacon there is nothing both frames carry to compare.
 *
 * Stamped 10 s after the epoch on purpose. At a realistic stamp the
 * unset baseline time (0) is decades old, so the age test alone keeps
 * this quiet and dropping the `e->beacon_ident` guard leaves it green —
 * measured, which is why the stamp is here. A sensor with no RTC (a Pi
 * before NTP) does stamp frames near 1970, and then only the guard stops
 * a comparison against an all-zero MLD MAC. Seen to fail by dropping
 * the guard: red. */
static void test_probe_response_before_any_beacon_not_flagged(void) {
    mle_clear();
    probe_resp(BSSID, MLD_B, 1, 0, (time_t)10, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
    ASSERT_EQ((int)r->basic_mle_seen, 1);
}

/* The comparison is per BSSID: two APs of one site in different AP
 * MLDs are two rows that never meet. */
static void test_rows_are_per_bssid(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    beacon_basic(BSSID2, MLD_B, 1, T0, 0);
    probe_resp(BSSID, MLD_A, 1, 0, T0 + 1, 0);
    probe_resp(BSSID2, MLD_B, 1, 0, T0 + 1, 0);
    ASSERT_EQ(mle_bss_count(), 2);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL && r->pr_beacon_diff_total == 0);
    r = row(BSSID2);
    ASSERT(r != NULL && r->pr_beacon_diff_total == 0);
}

/* The newest Beacon is the comparison's baseline, so an AP MLD that was
 * reconfigured to a new MLD MAC is compared against what it says now. */
static void test_newest_beacon_is_the_baseline(void) {
    mle_clear();
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    beacon_basic(BSSID, MLD_B, 1, T0 + 1, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + 2, 0);
    const sloth_mle_bss_t *r = row(BSSID);
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ((int)r->pr_beacon_diff_total, 0);
}

/* ── the Beacon roster keeps its Basic MLE beside a Reconfiguration MLE ─ */

/* Before this slice beacon_parse_ies() kept the LAST ext-107 element, so
 * in hostapd's removal-window Beacon (Basic, then Reconfiguration) it
 * handed mle_parse() the Reconfiguration MLE, which mle_parse() refuses,
 * and the AP MLD fell out of the roster. Seen to fail by restoring the
 * unconditional assignment: red. */
static void test_beacon_parse_keeps_the_basic_mle_before_a_reconfig(void) {
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_basic_mle(&b, MLD_A, 1, -1, 3, NULL, NULL, 0);
    put_reconf_mle(&b, 2, 50);
    ASSERT(fb_ok(&b));
    char ssid[33], enc[10]; uint8_t bssid[6]; int ch; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(buf, b.len, -40, ssid, bssid, &ch, enc, &bms,
                           &rsn), 1);
    ASSERT(rsn.mle_body != NULL);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(rsn.mle_body, rsn.mle_len, &m), 1);
    ASSERT_EQ(memcmp(m.mld_mac, MLD_A, 6), 0);
}

/* ── through the alert engine ──────────────────────────────────── */

static time_t g_wall;
static time_t pinned_wall(void) { return g_wall; }

static int find_alert(alert_type_t t) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == t) return i;
    return -1;
}

static void run_engine(void) {
    g_wall = T0 + 3;
    sloth_clock_test_set(NULL, pinned_wall);
    mle_snapshot(&g_s);
    alerts_update(&g_s);
    sloth_clock_test_set(NULL, NULL);
}

static void test_reconfig_no_mlo_fires_warn_with_its_frame_cited(void) {
    alerts_clear(); mle_clear();
    memset(&g_s, 0, sizeof g_s);
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 77);
    run_engine();
    int i = find_alert(ALERT_TYPE_MLE_RECONFIG_NO_MLO);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(g_s.alerts[i].detail, "02:bb:00:00:00:01") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "corroborates") != NULL);
    ASSERT_EQ((int)g_s.alerts[i].evidence_id_count, 1);
    ASSERT_EQ((int)g_s.alerts[i].evidence_ids[0], 77);
    alerts_clear(); mle_clear();
}

/* Seen to fail by gutting the rule's `!reconfig_no_mlo_total` guard. */
static void test_reconfig_no_mlo_quiet_for_a_conformant_ap_mld(void) {
    alerts_clear(); mle_clear();
    memset(&g_s, 0, sizeof g_s);
    uint8_t buf[256]; fb_t b; fb_init(&b, buf, sizeof buf);
    put_head(&b, 8, BSSID);
    put_basic_mle(&b, MLD_A, 1, -1, 3, NULL, NULL, 0);
    put_reconf_mle(&b, 2, 50);
    observe(&b, T0, 0);
    run_engine();
    ASSERT_EQ(find_alert(ALERT_TYPE_MLE_RECONFIG_NO_MLO), -1);
    alerts_clear(); mle_clear();
}

static void test_pr_beacon_diff_fires_warn_citing_both_frames(void) {
    alerts_clear(); mle_clear();
    memset(&g_s, 0, sizeof g_s);
    beacon_basic(BSSID, MLD_A, 1, T0, 501);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + 1, 502);
    run_engine();
    int i = find_alert(ALERT_TYPE_MLE_PR_BEACON_DIFF);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(g_s.alerts[i].detail, "02:aa:00:00:00:01") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "02:aa:00:00:00:02") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "not which one is genuine") != NULL);
    ASSERT_EQ((int)g_s.alerts[i].evidence_id_count, 2);
    ASSERT_EQ((int)g_s.alerts[i].evidence_ids[0], 501);
    ASSERT_EQ((int)g_s.alerts[i].evidence_ids[1], 502);
    alerts_clear(); mle_clear();
}

/* Seen to fail by gutting the rule's `!pr_beacon_diff_total` guard. */
static void test_pr_beacon_diff_quiet_for_a_conformant_ml_probe(void) {
    alerts_clear(); mle_clear();
    memset(&g_s, 0, sizeof g_s);
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    probe_resp(BSSID, MLD_A, 1, 1, T0 + 1, 0);
    run_engine();
    ASSERT_EQ(find_alert(ALERT_TYPE_MLE_PR_BEACON_DIFF), -1);
    alerts_clear(); mle_clear();
}

/* One alert per BSSID, keyed by it: two disagreeing BSSIDs are two. */
static void test_pr_beacon_diff_is_one_alert_per_bssid(void) {
    alerts_clear(); mle_clear();
    memset(&g_s, 0, sizeof g_s);
    beacon_basic(BSSID, MLD_A, 1, T0, 0);
    beacon_basic(BSSID2, MLD_A, 2, T0, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + 1, 0);
    probe_resp(BSSID, MLD_B, 1, 0, T0 + 2, 0);
    probe_resp(BSSID2, MLD_B, 2, 0, T0 + 1, 0);
    run_engine();
    int n = 0;
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ALERT_TYPE_MLE_PR_BEACON_DIFF) n++;
    ASSERT_EQ(n, 2);
    alerts_clear(); mle_clear();
}

void run_mle_bss_tests(void);
void run_mle_bss_tests(void) {
    TEST_SUITE("MLE_RECONFIG_NO_MLO (#104 slice 6)");
    RUN_TEST(test_reconfig_mle_without_any_basic_mle_is_flagged);
    RUN_TEST(test_reconfig_alongside_basic_in_one_frame_not_flagged);
    RUN_TEST(test_reconfig_after_an_earlier_basic_mle_not_flagged);
    RUN_TEST(test_reconfig_in_a_probe_response_is_flagged_as_one);
    RUN_TEST(test_a_malformed_basic_mle_still_counts_as_advertised);
    RUN_TEST(test_reconfig_finding_persists_across_later_basic_frames);
    RUN_TEST(test_a_legacy_beacon_creates_no_row);
    RUN_TEST(test_other_subtypes_are_ignored);

    TEST_SUITE("MLE_PR_BEACON_DIFF (#104 slice 6)");
    RUN_TEST(test_probe_response_naming_another_mld_is_flagged);
    RUN_TEST(test_probe_response_naming_another_link_id_is_flagged);
    RUN_TEST(test_conformant_ml_probe_response_does_not_fire);
    RUN_TEST(test_per_sta_profiles_in_own_mle_do_not_fire);
    RUN_TEST(test_link_id_compared_only_when_both_carry_it);
    RUN_TEST(test_window_is_inclusive_and_bounded);
    RUN_TEST(test_beacon_from_the_future_is_still_aged);
    RUN_TEST(test_probe_response_before_any_beacon_not_flagged);
    RUN_TEST(test_rows_are_per_bssid);
    RUN_TEST(test_newest_beacon_is_the_baseline);

    TEST_SUITE("Beacon MLE selection beside a Reconfiguration MLE (#104 slice 6)");
    RUN_TEST(test_beacon_parse_keeps_the_basic_mle_before_a_reconfig);

    TEST_SUITE("MLE per-BSSID rules through the engine (#104 slice 6)");
    RUN_TEST(test_reconfig_no_mlo_fires_warn_with_its_frame_cited);
    RUN_TEST(test_reconfig_no_mlo_quiet_for_a_conformant_ap_mld);
    RUN_TEST(test_pr_beacon_diff_fires_warn_citing_both_frames);
    RUN_TEST(test_pr_beacon_diff_quiet_for_a_conformant_ml_probe);
    RUN_TEST(test_pr_beacon_diff_is_one_alert_per_bssid);
}
