#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "eapol_log.h"

/* Build a synthetic 802.11 data frame (FromDS=1) carrying an EAPOL-Key
 * frame. We construct the lot from byte arrays — no parser feeding its
 * own output back. */

#define BSSID  {0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
#define STA    {0x10, 0x20, 0x30, 0x40, 0x50, 0x60}

/* Build a complete dot11 + LLC + EAPOL frame.
 *   out      : destination buffer
 *   eapol    : raw EAPOL bytes (starts with version byte)
 *   eapol_n  : length of eapol[]
 *   from_ds  : 1 = AP->STA (M1/M3), 0 = STA->AP (M2/M4)
 * Returns total length written. */
static int build_frame(uint8_t *out, const uint8_t *eapol, int eapol_n,
                       int from_ds) {
    static const uint8_t bssid[6] = BSSID;
    static const uint8_t sta[6]   = STA;
    int p = 0;
    /* FC: type=2 data, subtype=0 data */
    out[p++] = 0x08;
    /* FC byte 1: ToDS / FromDS bits */
    out[p++] = (uint8_t)(from_ds ? 0x02 : 0x01);
    /* Duration */
    out[p++] = 0; out[p++] = 0;
    /* Addr1, Addr2, Addr3 — direction-aware */
    const uint8_t *a1, *a2;
    if (from_ds) { a1 = sta;   a2 = bssid; }
    else         { a1 = bssid; a2 = sta;   }
    memcpy(out + p, a1, 6); p += 6;
    memcpy(out + p, a2, 6); p += 6;
    memcpy(out + p, bssid, 6); p += 6;
    /* SeqCtl */
    out[p++] = 0; out[p++] = 0;
    /* LLC SNAP: AA AA 03 00 00 00 + 0x888E */
    out[p++] = 0xAA; out[p++] = 0xAA; out[p++] = 0x03;
    out[p++] = 0x00; out[p++] = 0x00; out[p++] = 0x00;
    out[p++] = 0x88; out[p++] = 0x8E;
    /* EAPOL payload */
    memcpy(out + p, eapol, eapol_n);
    p += eapol_n;
    return p;
}

/* Build an EAPOL-Key body. ki = Key Information (big-endian 16-bit).
 * nonce32 may be NULL (zeroed). pmkid16 may be NULL (no PMKID KDE).
 * mic16   may be NULL (zeroed MIC). */
static int build_eapol_key(uint8_t *out, uint16_t ki,
                            const uint8_t *nonce32,
                            const uint8_t *mic16,
                            const uint8_t *pmkid16) {
    int p = 0;
    out[p++] = 0x02;            /* version */
    out[p++] = 0x03;            /* type = EAPOL-Key */
    out[p++] = 0; out[p++] = 0; /* length — patched at end */
    out[p++] = 0x02;            /* Descriptor: RSN */
    out[p++] = (uint8_t)(ki >> 8);
    out[p++] = (uint8_t)(ki & 0xff);
    out[p++] = 0x00; out[p++] = 0x10; /* Key Length = 16 (just a value) */
    for (int i = 0; i < 8; i++) out[p++] = 0;   /* Replay counter */
    if (nonce32) memcpy(out + p, nonce32, 32); else memset(out + p, 0, 32);
    p += 32;
    memset(out + p, 0, 16); p += 16;   /* Key IV */
    memset(out + p, 0, 8);  p += 8;    /* Key RSC */
    memset(out + p, 0, 8);  p += 8;    /* Reserved */
    if (mic16) memcpy(out + p, mic16, 16); else memset(out + p, 0, 16);
    p += 16;
    /* Key Data Length + Key Data */
    int kdl = pmkid16 ? 22 : 0;
    out[p++] = (uint8_t)(kdl >> 8);
    out[p++] = (uint8_t)(kdl & 0xff);
    if (pmkid16) {
        out[p++] = 0xDD;
        out[p++] = 0x14;
        out[p++] = 0x00; out[p++] = 0x0F; out[p++] = 0xAC; out[p++] = 0x04;
        memcpy(out + p, pmkid16, 16);
        p += 16;
    }
    /* Length field: total length minus 4 (version+type+length itself) */
    int body = p - 4;
    out[2] = (uint8_t)(body >> 8);
    out[3] = (uint8_t)(body & 0xff);
    return p;
}

static const uint8_t ANONCE[32] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
};
static const uint8_t SNONCE[32] = {
    0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
    0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,
    0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
};
static const uint8_t M2_MIC[16] = {
    0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,
    0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
};
static const uint8_t PMKID[16] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
};

/* ── Tests ───────────────────────────────────────────────── */

static void test_non_eapol_data_frame_ignored(void) {
    eapol_clear();
    /* Build a data frame whose ethertype isn't 0x888E. */
    uint8_t frame[64];
    int p = 0;
    frame[p++] = 0x08; frame[p++] = 0x01;
    frame[p++] = 0; frame[p++] = 0;
    for (int i = 0; i < 6; i++) frame[p++] = 0;
    for (int i = 0; i < 6; i++) frame[p++] = 0;
    for (int i = 0; i < 6; i++) frame[p++] = 0;
    frame[p++] = 0; frame[p++] = 0;
    /* LLC: ethertype 0x0800 (IPv4), not EAPOL */
    frame[p++] = 0xAA; frame[p++] = 0xAA; frame[p++] = 0x03;
    frame[p++] = 0x00; frame[p++] = 0x00; frame[p++] = 0x00;
    frame[p++] = 0x08; frame[p++] = 0x00;
    int r = eapol_observe_dot11(frame, p, -60, 6);
    ASSERT_EQ(r, 0);
    ASSERT_EQ(eapol_event_count(), 0);
}

static void test_m1_with_pmkid_extracted(void) {
    eapol_clear();
    uint8_t eapol[128];
    /* M1: KeyACK=1 (bit 7 of MSB byte = bit 15 of Key Info), MIC=0,
     *     Install=0, Secure=0. Bits 0..2 = key descriptor version (2). */
    uint16_t ki = (1 << 7) | (1 << 3) | 0x02;   /* KeyType=pairwise, version=2 */
    int en = build_eapol_key(eapol, ki, ANONCE, NULL, PMKID);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    int r = eapol_observe_dot11(frame, fn, -50, 6);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(eapol_event_count(), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    ASSERT_EQ(s.eapol_events[0].msg_num, 1);
    ASSERT_EQ(s.eapol_events[0].has_pmkid, 1);
    ASSERT_EQ(memcmp(s.eapol_events[0].pmkid, PMKID, 16), 0);
    ASSERT_EQ(memcmp(s.eapol_events[0].anonce, ANONCE, 32), 0);
}

static void test_m1_without_pmkid(void) {
    eapol_clear();
    uint8_t eapol[128];
    uint16_t ki = (1 << 7) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, ANONCE, NULL, NULL);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -55, 11);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    ASSERT_EQ(s.eapol_events[0].msg_num, 1);
    ASSERT_EQ(s.eapol_events[0].has_pmkid, 0);
}

static void test_full_handshake_m1_then_m2(void) {
    eapol_clear();
    /* M1 */
    {
        uint8_t eapol[128];
        uint16_t ki = (1 << 7) | (1 << 3) | 0x02;
        int en = build_eapol_key(eapol, ki, ANONCE, NULL, NULL);
        uint8_t frame[256];
        int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
        eapol_observe_dot11(frame, fn, -45, 6);
    }
    /* M2: KeyACK=0, MIC=1 (bit 8), Install=0, Secure=0. */
    {
        uint8_t eapol[128];
        uint16_t ki = (1 << 8) | (1 << 3) | 0x02;
        int en = build_eapol_key(eapol, ki, SNONCE, M2_MIC, NULL);
        uint8_t frame[256];
        int fn = build_frame(frame, eapol, en, /*from_ds=*/0);
        eapol_observe_dot11(frame, fn, -45, 6);
    }

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 2);
    /* Snapshot is newest-first — index 0 = M2. */
    ASSERT_EQ(s.eapol_events[0].msg_num, 2);
    ASSERT_EQ(s.eapol_events[0].handshake_complete, 1);
    ASSERT_EQ(memcmp(s.eapol_events[0].anonce, ANONCE, 32), 0);
    ASSERT_EQ(memcmp(s.eapol_events[0].snonce, SNONCE, 32), 0);
    ASSERT_EQ(memcmp(s.eapol_events[0].mic,    M2_MIC, 16), 0);
}

static void test_m2_without_m1_is_not_complete(void) {
    eapol_clear();
    uint8_t eapol[128];
    uint16_t ki = (1 << 8) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, SNONCE, M2_MIC, NULL);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/0);
    eapol_observe_dot11(frame, fn, -55, 6);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    ASSERT_EQ(s.eapol_events[0].msg_num, 2);
    ASSERT_EQ(s.eapol_events[0].handshake_complete, 0);
}

static void test_clear_resets_state(void) {
    eapol_clear();
    uint8_t eapol[128];
    uint16_t ki = (1 << 7) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, ANONCE, NULL, PMKID);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -50, 6);
    ASSERT_EQ(eapol_event_count(), 1);
    eapol_clear();
    ASSERT_EQ(eapol_event_count(), 0);
}

void run_eapol_log_tests(void) {
    TEST_SUITE("eapol_log");
    RUN_TEST(test_non_eapol_data_frame_ignored);
    RUN_TEST(test_m1_with_pmkid_extracted);
    RUN_TEST(test_m1_without_pmkid);
    RUN_TEST(test_full_handshake_m1_then_m2);
    RUN_TEST(test_m2_without_m1_is_not_complete);
    RUN_TEST(test_clear_resets_state);
}
