#include <string.h>
#include "runner.h"
#include "fragattack.h"
#include "dot11_data.h"

/*
 * FragAttacks slice 1 — issue #75.
 *
 * Frames are hand-built uint8_t arrays per IEEE 802.11-2020 §9.2, not
 * captures. See agents/AGENTS.md § Discipline: a capture proves the
 * parser against one lab rig; a built frame reaches the truncated,
 * four-address and mid-association cases that decide whether this fires
 * on real traffic.
 *
 * Frame Control byte 0 = (subtype << 4) | (type << 2) | version.
 * Byte 1: bit0 ToDS, bit1 FromDS, bit2 MoreFrag, bit6 Protected.
 *
 * The address table is the whole reason dot11_data_addrs exists — see
 * its comment. These tests build downlink (FromDS) frames unless they
 * are testing the table itself, because a downlink frame is the one
 * where reading addr3 as the BSSID goes wrong.
 */

#define FC1_TODS      0x01
#define FC1_FROMDS    0x02
#define FC1_MOREFRAG  0x04
#define FC1_PROTECTED 0x40

static const uint8_t BSSID[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x01 };
static const uint8_t STA_A[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x10 };
static const uint8_t STA_B[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x20 };
/* Group-addressed: the I/G bit is the low bit of octet 0. STA_A above
 * is unicast precisely because 0x02 has it clear — the trap #60 slice 2
 * and #59 both hit with a 0x11-prefixed constant. */
static const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* One downlink (FromDS) data frame: addr1 = DA, addr2 = BSSID,
 * addr3 = SA. `sub` selects QoS via bit 3. Returns the length. */
static int build(uint8_t *f, int sub, uint8_t fc1,
                 const uint8_t *da, const uint8_t *bssid, const uint8_t *sa,
                 int frag_num, uint16_t ethertype) {
    memset(f, 0, 128);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = (uint8_t)(fc1 | FC1_FROMDS);
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, bssid, 6);
    memcpy(f + 16, sa,    6);
    f[22] = (uint8_t)(frag_num & 0x0f);

    int hdr = 24 + ((sub & 0x08) ? 2 : 0);
    /* A protected frame's body is ciphertext, so no LLC header is
     * written — reading one out of it is exactly the mistake the
     * Protected check exists to prevent. */
    if (fc1 & FC1_PROTECTED) return hdr + 16;

    f[hdr + 0] = 0xaa; f[hdr + 1] = 0xaa; f[hdr + 2] = 0x03;
    f[hdr + 6] = (uint8_t)(ethertype >> 8);
    f[hdr + 7] = (uint8_t)(ethertype & 0xff);
    f[hdr + 8] = 0x45;                      /* a plausible IPv4 first byte */
    return hdr + 12;
}

/* The station's key install, witnessed. Every plaintext test needs this
 * first — that ordering is the detector's entire false-positive
 * defence, so it is stated at each call site rather than hidden. */
static void witness_key_install(const uint8_t *sa, time_t now) {
    uint8_t f[128];
    int n = build(f, 0, FC1_PROTECTED, STA_B, BSSID, sa, 0, 0);
    frag_observe(f, n, now);
}

static const frag_bss_t *bss(void) {
    int i = frag_find(BSSID);
    return i >= 0 ? frag_bss_at(i) : NULL;
}

/* ── dot11_data_addrs: the table ────────────────────────────────────── */

static void test_addrs_follow_the_ds_bits(void) {
    uint8_t f[128], b[6], s[6], d[6];
    memset(f, 0, sizeof(f));
    f[0] = 2 << 2;
    memcpy(f + 4, "\x01\x01\x01\x01\x01\x01", 6);   /* addr1 */
    memcpy(f + 10, "\x02\x02\x02\x02\x02\x02", 6);  /* addr2 */
    memcpy(f + 16, "\x03\x03\x03\x03\x03\x03", 6);  /* addr3 */

    /* IBSS: DA, SA, BSSID */
    f[1] = 0;
    ASSERT_EQ(dot11_data_addrs(f, 30, b, s, d), 1);
    ASSERT_EQ(d[0], 0x01); ASSERT_EQ(s[0], 0x02); ASSERT_EQ(b[0], 0x03);

    /* AP -> STA: DA, BSSID, SA. Reading addr3 as the BSSID here — the
     * shape that works for a beacon — would attribute the frame to the
     * sending station and merge every client into one bogus BSS. */
    f[1] = FC1_FROMDS;
    ASSERT_EQ(dot11_data_addrs(f, 30, b, s, d), 1);
    ASSERT_EQ(d[0], 0x01); ASSERT_EQ(b[0], 0x02); ASSERT_EQ(s[0], 0x03);

    /* STA -> AP: BSSID, SA, DA */
    f[1] = FC1_TODS;
    ASSERT_EQ(dot11_data_addrs(f, 30, b, s, d), 1);
    ASSERT_EQ(b[0], 0x01); ASSERT_EQ(s[0], 0x02); ASSERT_EQ(d[0], 0x03);
}

static void test_four_address_has_no_bssid(void) {
    uint8_t f[128], b[6], s[6], d[6];
    memset(f, 0, sizeof(f));
    f[0] = 2 << 2;
    f[1] = FC1_TODS | FC1_FROMDS;
    memcpy(f + 16, "\x03\x03\x03\x03\x03\x03", 6);  /* addr3 = DA */
    memcpy(f + 24, "\x04\x04\x04\x04\x04\x04", 6);  /* addr4 = SA */
    memset(b, 0xee, 6);
    ASSERT_EQ(dot11_data_addrs(f, 34, b, s, d), DOT11_ADDRS_NO_BSSID);
    ASSERT_EQ(d[0], 0x03);
    ASSERT_EQ(s[0], 0x04);
    /* bssid untouched: a WDS frame crosses two of them and inventing
     * one is worse than reporting that there is none. */
    ASSERT_EQ(b[0], 0xee);

    /* addr4 needs 30 bytes; a truncated WDS frame must not read past. */
    ASSERT_EQ(dot11_data_addrs(f, 28, b, s, d), 0);
}

static void test_addrs_reject_non_data_and_short(void) {
    uint8_t f[128];
    memset(f, 0, sizeof(f));
    f[0] = 0;                                   /* management */
    ASSERT_EQ(dot11_data_addrs(f, 30, NULL, NULL, NULL), 0);
    f[0] = 2 << 2;
    ASSERT_EQ(dot11_data_addrs(f, 23, NULL, NULL, NULL), 0);
}

static void test_group_addr_and_frag_helpers(void) {
    ASSERT_EQ(dot11_is_group_addr(BCAST), 1);
    ASSERT_EQ(dot11_is_group_addr(STA_A), 0);

    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 3, 0x0800);
    ASSERT_EQ(dot11_frag_num(f, n), 3);
    ASSERT_EQ(dot11_more_frags(f, n), 0);
    n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    ASSERT_EQ(dot11_frag_num(f, n), 0);
    ASSERT_EQ(dot11_more_frags(f, n), 1);
    ASSERT_EQ(dot11_frag_num(f, 20), -1);
}

/* ── the gate ───────────────────────────────────────────────────────── */

static void test_plaintext_without_witnessed_key_is_silent(void) {
    /* An open network. Every frame is unprotected and none of it is an
     * attack — this is the case that decides whether the detector is
     * usable at all. */
    frag_clear();
    uint8_t f[128];
    for (int i = 0; i < 20; i++) {
        int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
        frag_observe(f, n, 1000 + i);
    }
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_ordering_is_load_bearing(void) {
    /* Protection must be witnessed *before* the plaintext frame, not
     * merely somewhere in the capture. A client that finishes
     * associating after we saw its pre-association traffic is the
     * ordinary case, and must not read as an attack retroactively. */
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);                    /* plaintext first */
    witness_key_install(STA_B, 1001);            /* key install after */
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_gate_is_per_station(void) {
    /* STA_B installed a key; STA_A has not. STA_A's plaintext is a
     * client mid-association, not an injection. Sharing one per-BSS
     * flag would make every open client on a mixed BSS an alert. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_B, BSSID, STA_A, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

/* ── CVE-2020-26140 / -26143 ────────────────────────────────────────── */

static void test_plaintext_after_key_install_fires(void) {
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (!bss()) return;
    ASSERT_EQ(bss()->plaintext_unicast, 1u);
    ASSERT_EQ(bss()->last_sa[5], STA_B[5]);
    ASSERT_EQ(bss()->last_da[5], STA_A[5]);
    ASSERT_EQ(bss()->last_hit, (time_t)1001);
}

static void test_first_fragment_counts(void) {
    /* CVE-2020-26143 is the fragmented variant, and the first fragment
     * still carries its LLC header — so it is both detectable and
     * distinguishable from EAPOL. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 1u);
}

static void test_later_fragment_is_not_counted(void) {
    /* A continuation fragment has no LLC header, so there is no way to
     * tell a plaintext EAPOL continuation from a plaintext data one.
     * Counting it anyway would be a guess dressed as a detection. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 2, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_eapol_is_exempt(void) {
    /* EAPOL is legitimately unprotected after key install — that is how
     * rekeying works. Without this exemption every rekey on the network
     * is a CRIT. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x888E);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_null_frames_are_exempt(void) {
    /* Null and QoS-Null carry no body and are sent unprotected as a
     * matter of course — they are how a station signals power-save
     * state. Counting them fires on every idle client. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 4, 0, STA_A, BSSID, STA_B, 0, 0x0800);   /* Null */
    frag_observe(f, n, 1001);
    n = build(f, 12, 0, STA_A, BSSID, STA_B, 0, 0x0800);      /* QoS Null */
    frag_observe(f, n, 1002);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_non_snap_is_not_counted(void) {
    /* Bare LLC has its protocol identifier somewhere else, so an
     * EtherType read out of it is invented — and an invented EtherType
     * that happens not to be 0x888E would make every IPX frame a CRIT. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    f[24] = 0xe0; f[25] = 0xe0;                  /* IPX, not AA AA 03 */
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_qos_frames_find_their_llc(void) {
    /* The QoS Control field shifts the LLC header by two bytes. Getting
     * this wrong reads 0x0300 as the EtherType — not EAPOL, so the
     * frame would be counted, and the detector would fire on every QoS
     * data frame on the network. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 8, 0, STA_A, BSSID, STA_B, 0, 0x888E);   /* QoS EAPOL */
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);

    n = build(f, 8, 0, STA_A, BSSID, STA_B, 0, 0x0800);       /* QoS IPv4 */
    frag_observe(f, n, 1002);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 1u);
}

/* ── CVE-2020-26145 ─────────────────────────────────────────────────── */

static void test_plaintext_broadcast_fragment_fires(void) {
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, BCAST, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (!bss()) return;
    ASSERT_EQ(bss()->plaintext_bcast_frag, 1u);
    /* It is a broadcast, not a unicast: the two counters must not both
     * move, or the alert names the wrong CVE. */
    ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

static void test_later_broadcast_fragment_also_fires(void) {
    /* Unlike the unicast rule, this one does not need the LLC header:
     * fragmentation itself is the violation, and broadcast EAPOL does
     * not exist, so there is nothing to exempt. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, BCAST, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_bcast_frag, 1u);
}

static void test_unfragmented_broadcast_is_ordinary(void) {
    /* An unfragmented plaintext broadcast is not -26145. It is ARP on
     * an open network, and on a protected one it would be counted by
     * the unicast rule if it were a violation at all. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, BCAST, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_bcast_frag, 0u);
}

static void test_protected_broadcast_fragment_is_ordinary(void) {
    /* -26145 is about *plaintext* broadcast fragments. A protected one
     * is what a conforming AP sends. */
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, FC1_PROTECTED | FC1_MOREFRAG,
                  BCAST, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_bcast_frag, 0u);
}

/* ── table behaviour ────────────────────────────────────────────────── */

static void test_bsses_are_tracked_separately(void) {
    frag_clear();
    uint8_t other[6] = { 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x02 };
    uint8_t f[128];
    witness_key_install(STA_B, 1000);
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    /* Same station, different BSS, no key install witnessed there. */
    n = build(f, 0, 0, STA_A, other, STA_B, 0, 0x0800);
    frag_observe(f, n, 1002);

    ASSERT_EQ(frag_bss_count(), 2);
    ASSERT(bss() && bss()->plaintext_unicast == 1u);
    int j = frag_find(other);
    ASSERT(j >= 0);
    if (j >= 0) ASSERT_EQ(frag_bss_at(j)->plaintext_unicast, 0u);
}

static void test_table_full_evicts_stalest(void) {
    /* A table that stops learning after 64 BSSes is worse on a hopping
     * radio than one that forgets the BSS it has not heard from in
     * longest. */
    frag_clear();
    uint8_t f[128], b[6] = { 0x02, 0, 0, 0, 0, 0 };
    for (int i = 0; i < FRAG_MAX_BSS; i++) {
        b[5] = (uint8_t)i;
        int n = build(f, 0, FC1_PROTECTED, STA_A, b, STA_B, 0, 0);
        frag_observe(f, n, 2000 + i);            /* index 0 is stalest */
    }
    ASSERT_EQ(frag_bss_count(), FRAG_MAX_BSS);
    uint8_t fresh[6] = { 0x02, 0, 0, 0, 0, 0xfe };
    int n = build(f, 0, FC1_PROTECTED, STA_A, fresh, STA_B, 0, 0);
    frag_observe(f, n, 9000);
    ASSERT_EQ(frag_bss_count(), FRAG_MAX_BSS);
    ASSERT(frag_find(fresh) >= 0);
    b[5] = 0;
    ASSERT_EQ(frag_find(b), -1);
}

static void test_four_address_frames_are_skipped(void) {
    /* No single BSSID, so no attribution — and creating a table row
     * keyed on a guessed BSSID is worse than seeing nothing. */
    frag_clear();
    uint8_t f[128];
    memset(f, 0, sizeof(f));
    f[0] = 2 << 2;
    f[1] = FC1_TODS | FC1_FROMDS;
    frag_observe(f, 40, 1000);
    ASSERT_EQ(frag_bss_count(), 0);
}

static void test_malformed_and_short_are_safe(void) {
    frag_clear();
    uint8_t f[128];
    memset(f, 0, sizeof(f));
    f[0] = 2 << 2;
    frag_observe(NULL, 100, 1000);
    for (int n = 0; n < 24; n++) frag_observe(f, n, 1000);
    ASSERT_EQ(frag_bss_count(), 0);

    /* A management frame is not our business. */
    f[0] = 0x80;
    frag_observe(f, 60, 1000);
    ASSERT_EQ(frag_bss_count(), 0);

    /* Every truncation of a real frame must be safe, not just the
     * short ones — the header additions are what run off the end. */
    int n = build(f, 8, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    for (int cut = 0; cut <= n; cut++) {
        frag_clear();
        witness_key_install(STA_B, 1000);
        frag_observe(f, cut, 1001);
    }
    ASSERT(1);                                   /* no crash is the assertion */
}

static void test_clear_empties_everything(void) {
    frag_clear();
    witness_key_install(STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(frag_bss_count() > 0);
    frag_clear();
    ASSERT_EQ(frag_bss_count(), 0);
    ASSERT(frag_bss_at(0) == NULL);
    ASSERT_EQ(frag_find(BSSID), -1);

    /* And the per-station gate must clear too, or the next capture
     * starts with a key install it never witnessed. */
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1002);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->plaintext_unicast, 0u);
}

/* ── slice 2: fragment sessions ─────────────────────────────────────── */
/*
 * All frames below use sub=0 (non-QoS), so dot11_data_tid() is always 0
 * and every session in these tests shares one TID — the interesting
 * variable is the association timing and the Protected bit, not TID
 * bucketing (dot11_data_tid has its own tests in test_dot11_data.c).
 */

/* CVE-2020-24586. */

static void test_cache_poison_fires_when_completion_straddles_assoc(void) {
    frag_clear();
    uint8_t f[128];
    /* Fragment 0, unprotected — deliberately *not* preceded by a
     * witnessed key install, to show this detector does not depend on
     * slice 1's gate: the fragment cache exists before decryption. */
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    frag_note_association(BSSID, STA_B, 1005);   /* straddles */
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1010);

    ASSERT(bss() != NULL);
    if (!bss()) return;
    ASSERT_EQ(bss()->cache_poison, 1u);
    ASSERT_EQ(bss()->last_sa[5], STA_B[5]);
    ASSERT_EQ(bss()->last_da[5], STA_A[5]);
}

static void test_cache_poison_silent_without_an_association_event(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    /* No frag_note_association call at all. */
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1010);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 0u);
}

static void test_cache_poison_silent_when_assoc_precedes_the_session(void) {
    /* The station associated a while ago and has been sending
     * fragmented traffic since — ordinary operation, not a straddle. */
    frag_clear();
    frag_note_association(BSSID, STA_B, 900);
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1010);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 0u);
}

static void test_cache_poison_checks_both_endpoints(void) {
    /* The association event is recorded against DA here, not SA — a
     * downlink completion straddling the *destination* station's
     * association is the same bug from the other side of the link. */
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    frag_note_association(BSSID, STA_A, 1005);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1010);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 1u);
}

static void test_cache_poison_same_second_is_not_a_straddle(void) {
    /* Second-resolution clock: an association landing in the same
     * second as the fragment that opened the session cannot be shown
     * to be *after* it, so it is not reported as a straddle. */
    frag_clear();
    frag_note_association(BSSID, STA_B, 1000);
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 0u);
}

static void test_continuation_with_no_open_session_is_silent(void) {
    /* sloth joined the capture mid-reassembly (a hopped-away-and-back
     * radio). There is nothing on file to compare it against. */
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, 0, STA_A, BSSID, STA_B, 2, 0x0800);
    frag_observe(f, n, 1000);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 0u);
    ASSERT_EQ(frag_session_count(), 0);
}

/* CVE-2020-26147. */

static void test_mixed_protect_fires_encrypted_then_plaintext(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_PROTECTED | FC1_MOREFRAG,
                 STA_A, BSSID, STA_B, 0, 0);
    frag_observe(f, n, 1000);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->mixed_protect, 1u);
}

static void test_mixed_protect_fires_plaintext_then_encrypted(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, FC1_PROTECTED, STA_A, BSSID, STA_B, 1, 0);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->mixed_protect, 1u);
}

static void test_mixed_protect_silent_when_consistent(void) {
    frag_clear();
    uint8_t f[128];
    /* All-encrypted sequence. */
    int n = build(f, 0, FC1_PROTECTED | FC1_MOREFRAG,
                 STA_A, BSSID, STA_B, 0, 0);
    frag_observe(f, n, 1000);
    n = build(f, 0, FC1_PROTECTED, STA_A, BSSID, STA_B, 1, 0);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->mixed_protect, 0u);

    /* All-plaintext sequence, different DA so it is a fresh session. */
    frag_clear();
    n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1001);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->mixed_protect, 0u);
}

/* ── session lifecycle ──────────────────────────────────────────────── */

static void test_session_closes_on_completing_fragment(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    ASSERT_EQ(frag_session_count(), 1);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);   /* MoreFrag=0 */
    frag_observe(f, n, 1001);
    ASSERT_EQ(frag_session_count(), 0);
}

static void test_session_stays_open_across_a_middle_fragment(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1001);                    /* still More Frag */
    ASSERT_EQ(frag_session_count(), 1);
}

static void test_new_fragment_zero_replaces_an_abandoned_session(void) {
    /* An unfinished reassembly is not itself evidence. A second
     * fragment 0 under the same key must reset start_seen/protected
     * rather than merge with the first — otherwise a stale abandoned
     * session's Protected bit would falsely mark a later, entirely
     * consistent reassembly as mixed. */
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);                    /* plaintext, abandoned */
    n = build(f, 0, FC1_PROTECTED | FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0);
    frag_observe(f, n, 2000);                    /* fresh start, encrypted */
    n = build(f, 0, FC1_PROTECTED, STA_A, BSSID, STA_B, 1, 0);
    frag_observe(f, n, 2001);                    /* consistent completion */
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->mixed_protect, 0u);
}

static void test_sessions_are_cleared(void) {
    frag_clear();
    uint8_t f[128];
    int n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    frag_note_association(BSSID, STA_B, 1005);
    ASSERT_EQ(frag_session_count(), 1);

    frag_clear();
    ASSERT_EQ(frag_session_count(), 0);

    /* And the association table: replaying only the completion after a
     * clear must not still see the pre-clear association. */
    n = build(f, 0, FC1_MOREFRAG, STA_A, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 1000);
    n = build(f, 0, 0, STA_A, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 1010);
    ASSERT(bss() != NULL);
    if (bss()) ASSERT_EQ(bss()->cache_poison, 0u);
}

static void test_session_table_full_evicts_stalest(void) {
    frag_clear();
    uint8_t f[128];
    for (int i = 0; i < FRAG_MAX_SESSIONS; i++) {
        uint8_t da[6] = { 0x02, 0, 0, 0, 0, (uint8_t)i };
        int n = build(f, 0, FC1_MOREFRAG, da, BSSID, STA_B, 0, 0x0800);
        frag_observe(f, n, 2000 + i);             /* index 0 is stalest */
    }
    ASSERT_EQ(frag_session_count(), FRAG_MAX_SESSIONS);

    uint8_t fresh_da[6] = { 0x02, 0, 0, 0, 0, 0xfe };
    int n = build(f, 0, FC1_MOREFRAG, fresh_da, BSSID, STA_B, 0, 0x0800);
    frag_observe(f, n, 9000);
    ASSERT_EQ(frag_session_count(), FRAG_MAX_SESSIONS);

    /* The evicted (stalest) session no longer straddles anything: a
     * completion for it now looks like an unopened session. */
    uint8_t evicted_da[6] = { 0x02, 0, 0, 0, 0, 0 };
    n = build(f, 0, 0, evicted_da, BSSID, STA_B, 1, 0x0800);
    frag_observe(f, n, 9001);
    ASSERT_EQ(frag_session_count(), FRAG_MAX_SESSIONS);
}

void run_fragattack_tests(void);
void run_fragattack_tests(void) {
    TEST_SUITE("802.11 addressing (#75)");
    RUN_TEST(test_addrs_follow_the_ds_bits);
    RUN_TEST(test_four_address_has_no_bssid);
    RUN_TEST(test_addrs_reject_non_data_and_short);
    RUN_TEST(test_group_addr_and_frag_helpers);

    TEST_SUITE("fragattacks: the key-install gate (#75)");
    RUN_TEST(test_plaintext_without_witnessed_key_is_silent);
    RUN_TEST(test_ordering_is_load_bearing);
    RUN_TEST(test_gate_is_per_station);

    TEST_SUITE("fragattacks: plaintext in RSN, CVE-2020-26140/-26143");
    RUN_TEST(test_plaintext_after_key_install_fires);
    RUN_TEST(test_first_fragment_counts);
    RUN_TEST(test_later_fragment_is_not_counted);
    RUN_TEST(test_eapol_is_exempt);
    RUN_TEST(test_null_frames_are_exempt);
    RUN_TEST(test_non_snap_is_not_counted);
    RUN_TEST(test_qos_frames_find_their_llc);

    TEST_SUITE("fragattacks: broadcast fragments, CVE-2020-26145");
    RUN_TEST(test_plaintext_broadcast_fragment_fires);
    RUN_TEST(test_later_broadcast_fragment_also_fires);
    RUN_TEST(test_unfragmented_broadcast_is_ordinary);
    RUN_TEST(test_protected_broadcast_fragment_is_ordinary);

    TEST_SUITE("fragattacks: table behaviour (#75)");
    RUN_TEST(test_bsses_are_tracked_separately);
    RUN_TEST(test_table_full_evicts_stalest);
    RUN_TEST(test_four_address_frames_are_skipped);
    RUN_TEST(test_malformed_and_short_are_safe);
    RUN_TEST(test_clear_empties_everything);

    TEST_SUITE("fragattacks: fragment cache poison, CVE-2020-24586 (#75 slice 2)");
    RUN_TEST(test_cache_poison_fires_when_completion_straddles_assoc);
    RUN_TEST(test_cache_poison_silent_without_an_association_event);
    RUN_TEST(test_cache_poison_silent_when_assoc_precedes_the_session);
    RUN_TEST(test_cache_poison_checks_both_endpoints);
    RUN_TEST(test_cache_poison_same_second_is_not_a_straddle);
    RUN_TEST(test_continuation_with_no_open_session_is_silent);

    TEST_SUITE("fragattacks: mixed reassembly, CVE-2020-26147 (#75 slice 2)");
    RUN_TEST(test_mixed_protect_fires_encrypted_then_plaintext);
    RUN_TEST(test_mixed_protect_fires_plaintext_then_encrypted);
    RUN_TEST(test_mixed_protect_silent_when_consistent);

    TEST_SUITE("fragattacks: session lifecycle (#75 slice 2)");
    RUN_TEST(test_session_closes_on_completing_fragment);
    RUN_TEST(test_session_stays_open_across_a_middle_fragment);
    RUN_TEST(test_new_fragment_zero_replaces_an_abandoned_session);
    RUN_TEST(test_sessions_are_cleared);
    RUN_TEST(test_session_table_full_evicts_stalest);
}
