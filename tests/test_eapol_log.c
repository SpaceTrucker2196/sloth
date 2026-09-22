#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include "runner.h"
#include "sloth.h"
#include "eapol_log.h"
#include "alerts.h"
#include "assoc_track.h"

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

/* Captured PMKID with --eapol-dir set should produce both the
 * eapol.22000 line AND a per-handshake pcap file under the dir. */
static void test_pmkid_emits_pcap_when_eapol_dir_set(void) {
    eapol_clear();
    /* Pick a deterministic temp dir, recreate it. */
    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/sloth_test_eapol_%d", (int)getpid());
    /* best-effort cleanup of prior file */
    char pcap_path[160];
    snprintf(pcap_path, sizeof(pcap_path),
             "%s/00aabbccddee_102030405060.pcap", dir);
    unlink(pcap_path);
    rmdir(dir);
    mkdir(dir, 0700);   /* private: a permissive dir is refused (#87) */
    eapol_set_output_dir(dir);

    /* Feed M1 with PMKID (same as test_m1_with_pmkid_extracted). */
    uint8_t eapol[128];
    uint16_t ki = (1 << 7) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, ANONCE, NULL, PMKID);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -50, 6);

    /* pcap file exists and has the magic header. */
    FILE *f = fopen(pcap_path, "rb");
    ASSERT(f != NULL);
    if (f) {
        uint8_t hdr[4];
        size_t r = fread(hdr, 1, 4, f);
        ASSERT_EQ(r, (size_t)4);
        /* Little-endian magic 0xa1b2c3d4 = bytes d4 c3 b2 a1. */
        ASSERT_EQ((int)hdr[0], 0xd4);
        ASSERT_EQ((int)hdr[1], 0xc3);
        ASSERT_EQ((int)hdr[2], 0xb2);
        ASSERT_EQ((int)hdr[3], 0xa1);
        fclose(f);
    }

    /* Cleanup. */
    eapol_set_output_dir(NULL);
    unlink(pcap_path);
    char eapol22[128];
    snprintf(eapol22, sizeof(eapol22), "%s/eapol.22000", dir);
    unlink(eapol22);
    rmdir(dir);
}

/* Helper for the provenance tests: drive a PMKID-bearing M1 against
 * the test fixture's BSSID into a fresh temp dir, then return the
 * full contents of eapol.22000. Caller frees nothing — the buffer is
 * a static fixed-size slurp. The temp dir is rebuilt every call. */
static const uint8_t TAINT_BSSID[6] = BSSID;   /* 00:AA:BB:CC:DD:EE */

static int slurp_file(const char *path, char *buf, int sz) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = (int)fread(buf, 1, (size_t)(sz - 1), f);
    if (n < 0) n = 0;
    buf[n] = '\0';
    fclose(f);
    return n;
}

/* Drive a PMKID-carrying M1 against the fixture BSSID with eapol.22000
 * output enabled in a fresh per-test temp dir. Returns the eapol.22000
 * body via *out_buf. dir_out is filled with the temp dir path so the
 * caller can clean up. */
static void drive_pmkid_m1(char *out_buf, int out_sz,
                           char *dir_out, int dir_sz) {
    snprintf(dir_out, dir_sz, "/tmp/sloth_test_taint_%d", (int)getpid());
    /* rebuild the dir so prior runs don't bleed in */
    char pcap_path[160], txt_path[160];
    snprintf(pcap_path, sizeof(pcap_path),
             "%s/00aabbccddee_102030405060.pcap", dir_out);
    snprintf(txt_path, sizeof(txt_path), "%s/eapol.22000", dir_out);
    unlink(pcap_path);
    unlink(txt_path);
    rmdir(dir_out);
    mkdir(dir_out, 0700);
    eapol_set_output_dir(dir_out);

    uint8_t eapol[128];
    uint16_t ki = (1 << 7) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, ANONCE, NULL, PMKID);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -50, 6);

    slurp_file(txt_path, out_buf, out_sz);
    eapol_set_output_dir(NULL);
    /* leave files in place — caller asserts then cleans */
}

static void cleanup_taint_dir(const char *dir) {
    char p[160];
    snprintf(p, sizeof(p), "%s/00aabbccddee_102030405060.pcap", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/eapol.22000", dir);
    unlink(p);
    rmdir(dir);
}

/* When the EAPOL handshake's BSSID is currently tainted, the .22000
 * line gets a "# provenance=tainted-evil-twin bssid=…" comment line
 * prepended — Phase 4 provenance marker. */
static void test_eapol_tainted_bssid_emits_provenance_comment(void) {
    eapol_clear();
    evil_twin_taint_clear();
    evil_twin_taint_mark_for_test(TAINT_BSSID);
    ASSERT_EQ(evil_twin_bssid_is_tainted(TAINT_BSSID), 1);

    char body[4096], dir[80];
    drive_pmkid_m1(body, sizeof(body), dir, sizeof(dir));

    ASSERT(strstr(body, "# provenance=tainted-evil-twin") != NULL);
    /* The comment carries the BSSID in lowercase hex, colon-separated. */
    ASSERT(strstr(body, "bssid=00:aa:bb:cc:dd:ee")        != NULL);
    /* The hash line still lands — the comment is additive, not a substitute. */
    ASSERT(strstr(body, "WPA*01*")                        != NULL);

    cleanup_taint_dir(dir);
    evil_twin_taint_clear();
}

/* Symmetric: a clean BSSID writes the WPA*01* line WITHOUT a comment
 * line. Defends against accidentally tagging every handshake. */
static void test_eapol_clean_bssid_no_provenance_comment(void) {
    eapol_clear();
    evil_twin_taint_clear();
    ASSERT_EQ(evil_twin_bssid_is_tainted(TAINT_BSSID), 0);

    char body[4096], dir[80];
    drive_pmkid_m1(body, sizeof(body), dir, sizeof(dir));

    ASSERT(strstr(body, "WPA*01*")                  != NULL);
    ASSERT(strstr(body, "provenance=tainted-evil-twin") == NULL);

    cleanup_taint_dir(dir);
}

/* ── PTK generation, #75 slice 4 (CVE-2020-24587) ──────────────────── */

static const uint8_t ANONCE2[32] = {
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
};

static const uint8_t GEN_BSSID[6] = BSSID;
static const uint8_t GEN_STA[6]   = STA;

/* M3: KeyACK=1, MIC=1, Install=1 (802.11-2016 §12.7.6, Table 12-8). */
static int drive_m3(const uint8_t *anonce) {
    uint8_t eapol[128];
    uint16_t ki = (1 << 8) | (1 << 7) | (1 << 6) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki, anonce, M2_MIC, NULL);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    return eapol_observe_dot11(frame, fn, -50, 6);
}

static void test_generation_zero_for_unknown_pair(void) {
    eapol_clear();
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 0);
}

static void test_generation_bumps_on_first_m3(void) {
    eapol_clear();
    ASSERT_EQ(drive_m3(ANONCE), 1);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 1);
}

static void test_generation_ignores_a_retransmitted_m3(void) {
    /* An AP resends M3 verbatim — same ANonce — when M4 is lost. Every
     * retry counting as a new generation would make ordinary handshake
     * loss look like a rekey storm. */
    eapol_clear();
    drive_m3(ANONCE);
    drive_m3(ANONCE);
    drive_m3(ANONCE);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 1);
}

static void test_generation_bumps_on_a_new_anonce(void) {
    /* A genuine rekey — periodic PTK refresh or a fresh association —
     * draws a new ANonce, which is exactly what distinguishes it from a
     * retry above. */
    eapol_clear();
    drive_m3(ANONCE);
    drive_m3(ANONCE2);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 2);
    drive_m3(ANONCE);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 3);
}

static void test_generation_bumps_on_first_m3_even_with_a_zero_anonce(void) {
    /* installed_anonce starts zeroed. Without has_installed to say
     * whether anything has actually been recorded yet, a first M3 whose
     * ANonce happens to be all-zero would read as "no change" against
     * that zeroed buffer and never bump — has_installed is what tells
     * the two states apart. */
    eapol_clear();
    ASSERT_EQ(drive_m3(NULL), 1);      /* NULL -> build_eapol_key zeroes it */
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 1);
}

static void test_generation_is_per_pair(void) {
    eapol_clear();
    uint8_t other_sta[6] = { 0x11, 0x21, 0x31, 0x41, 0x51, 0x61 };
    drive_m3(ANONCE);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA),  1);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, other_sta), 0);
}

static void test_generation_cleared(void) {
    eapol_clear();
    drive_m3(ANONCE);
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 1);
    eapol_clear();
    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 0);
}

static void test_generation_not_bumped_by_m1_or_m2(void) {
    /* Only Install=1 (M3) says a key is being installed. M1/M2 exchange
     * nonces but install nothing yet. */
    eapol_clear();
    uint8_t eapol[128];
    uint16_t ki1 = (1 << 7) | (1 << 3) | 0x02;
    int en = build_eapol_key(eapol, ki1, ANONCE, NULL, NULL);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -45, 6);

    uint16_t ki2 = (1 << 8) | (1 << 3) | 0x02;
    en = build_eapol_key(eapol, ki2, SNONCE, M2_MIC, NULL);
    fn = build_frame(frame, eapol, en, /*from_ds=*/0);
    eapol_observe_dot11(frame, fn, -45, 6);

    ASSERT_EQ(eapol_key_generation(GEN_BSSID, GEN_STA), 0);
}

/* ── EAPOL-Key bounds, #83 ─────────────────────────────────────────── */

/* Every frame in this section is fed from an EXACT-sized heap block:
 * malloc(dot11 hdr + LLC + n), nothing more. An oversized backing
 * array with a shorter logical length would hide an over-read from
 * ASan — the bytes past the span would be ours, not the allocator's
 * redzone. */
#define DOT11_LLC_LEN 32   /* 24-byte data header + 8-byte LLC/SNAP */

static int feed_exact(const uint8_t *eapol, int n, int from_ds) {
    uint8_t *frame = malloc((size_t)(DOT11_LLC_LEN + n));
    if (!frame) return -1;
    int fn = build_frame(frame, eapol, n, from_ds);
    int r = eapol_observe_dot11(frame, fn, -50, 6);
    free(frame);
    return r;
}

static void set_body_len(uint8_t *eapol, int body) {
    eapol[2] = (uint8_t)(body >> 8);
    eapol[3] = (uint8_t)(body & 0xff);
}

static void set_kdl(uint8_t *eapol, int kdl) {
    eapol[97] = (uint8_t)(kdl >> 8);
    eapol[98] = (uint8_t)(kdl & 0xff);
}

#define KI_M1 ((1 << 7) | (1 << 3) | 0x02)
#define KI_M2 ((1 << 8) | (1 << 3) | 0x02)

static char g_bounds_dir[64];

static void bounds_path(char *out, size_t sz, const char *leaf) {
    snprintf(out, sz, "%s/%s", g_bounds_dir, leaf);
}

static void bounds_reset(void) {
    char p[160];
    bounds_path(p, sizeof(p), "eapol.22000");
    unlink(p);
    bounds_path(p, sizeof(p), "00aabbccddee_102030405060.pcap");
    unlink(p);
    eapol_clear();
    assoc_clear();
}

static int bounds_file_exists(const char *leaf) {
    char p[160];
    bounds_path(p, sizeof(p), leaf);
    struct stat st;
    return stat(p, &st) == 0;
}

static void bounds_setup(void) {
    snprintf(g_bounds_dir, sizeof(g_bounds_dir),
             "/tmp/sloth_test_eapol83_%d", (int)getpid());
    mkdir(g_bounds_dir, 0700);
    eapol_set_output_dir(g_bounds_dir);
}

static void bounds_teardown(void) {
    bounds_reset();
    eapol_set_output_dir(NULL);
    rmdir(g_bounds_dir);
}

/* Seed a valid M1 (no PMKID, so no export on its own), then feed the
 * candidate M2 from an exact allocation. Returns 1 iff the M2 had any
 * observable effect: a second event, an association, or a hashcat /
 * pcap export. */
static int m2_side_effects(const uint8_t *m2, int n) {
    bounds_reset();
    uint8_t m1[128];
    int m1n = build_eapol_key(m1, KI_M1, ANONCE, NULL, NULL);
    feed_exact(m1, m1n, /*from_ds=*/1);
    if (eapol_event_count() != 1 || assoc_count() != 0) return -1;

    feed_exact(m2, n, /*from_ds=*/0);
    return eapol_event_count() != 1
        || assoc_count() != 0
        || bounds_file_exists("eapol.22000")
        || bounds_file_exists("00aabbccddee_102030405060.pcap");
}

/* The issue's table: 95..98 passed the old `len < 95` guard and read
 * the MIC tail / Key Data Length past the span. Sweep 0..100 with the
 * declared body left at the full-frame value (a capture cut short). */
static void test_key_lengths_0_to_100_truncated_capture(void) {
    bounds_setup();
    uint8_t full[100];
    int fulln = build_eapol_key(full, KI_M2, SNONCE, M2_MIC, NULL);
    ASSERT_EQ(fulln, 99);
    full[99] = 0x00;   /* one trailing byte for n == 100 */

    int bad = 0;
    for (int n = 0; n <= 100; n++) {
        uint8_t *m2 = malloc((size_t)(n ? n : 1));
        memcpy(m2, full, (size_t)n);
        int fx = m2_side_effects(m2, n);
        int want = n >= 99;
        /* Every short capture is an EAPOL-Key the dispatcher hands
         * over (n >= 4) whose body claims 95 bytes it doesn't have. */
        int want_trunc = n >= 4 && n < 99;
        if (fx != want
            || eapol_reject_count(EAPOL_REJECT_TRUNCATED) != want_trunc
            || eapol_reject_count(EAPOL_REJECT_MALFORMED) != 0) {
            fprintf(stderr, "    len %d: side effects %d, want %d\n",
                    n, fx, want);
            bad++;
        }
        free(m2);
    }
    ASSERT_EQ(bad, 0);
    bounds_teardown();
}

/* Same sweep, but the declared body length agrees with the capture —
 * a self-consistent frame too short to hold the fixed key header. */
static void test_key_lengths_0_to_100_consistent_short_body(void) {
    bounds_setup();
    uint8_t full[100];
    build_eapol_key(full, KI_M2, SNONCE, M2_MIC, NULL);
    full[99] = 0x00;

    int bad = 0;
    for (int n = 0; n <= 100; n++) {
        uint8_t *m2 = malloc((size_t)(n ? n : 1));
        memcpy(m2, full, (size_t)n);
        if (n >= 4) set_body_len(m2, n - 4);
        int fx = m2_side_effects(m2, n);
        int want = n >= 99;
        int want_bad = n >= 4 && n < 99;
        if (fx != want
            || eapol_reject_count(EAPOL_REJECT_MALFORMED) != want_bad
            || eapol_reject_count(EAPOL_REJECT_TRUNCATED) != 0) {
            fprintf(stderr, "    len %d: side effects %d, want %d\n",
                    n, fx, want);
            bad++;
        }
        free(m2);
    }
    ASSERT_EQ(bad, 0);
    bounds_teardown();
}

/* A valid 99-byte fixed header parses: M2 completes the handshake,
 * lands the association, and exports. */
static void test_key_exact_99_byte_header_parses(void) {
    bounds_setup();
    uint8_t m2[99];
    int n = build_eapol_key(m2, KI_M2, SNONCE, M2_MIC, NULL);
    ASSERT_EQ(n, 99);
    ASSERT_EQ(m2_side_effects(m2, n), 1);
    ASSERT_EQ(eapol_event_count(), 2);
    ASSERT_EQ(assoc_count(), 1);
    ASSERT(bounds_file_exists("eapol.22000"));
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_events[0].handshake_complete, 1);
    ASSERT_EQ(memcmp(s.eapol_events[0].mic, M2_MIC, 16), 0);
    bounds_teardown();
}

/* Declared body says the frame is longer than what was captured. */
static void test_key_declared_body_exceeds_capture_rejected(void) {
    bounds_setup();
    uint8_t m2[99];
    build_eapol_key(m2, KI_M2, SNONCE, M2_MIC, NULL);
    set_body_len(m2, 96);
    ASSERT_EQ(m2_side_effects(m2, 99), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 1);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 0);
    set_body_len(m2, 0xffff);
    ASSERT_EQ(m2_side_effects(m2, 99), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 1);
    bounds_teardown();
}

/* Declared body too short to hold the 95-byte key descriptor, even
 * though enough bytes were captured. The extra captured bytes are
 * padding, not EAPOL. */
static void test_key_declared_body_short_of_header_rejected(void) {
    bounds_setup();
    uint8_t m2[104];
    build_eapol_key(m2, KI_M2, SNONCE, M2_MIC, NULL);
    memset(m2 + 99, 0, 5);
    set_body_len(m2, 94);
    ASSERT_EQ(m2_side_effects(m2, 99), 0);
    ASSERT_EQ(m2_side_effects(m2, 104), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 1);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 0);
    set_body_len(m2, 0);
    ASSERT_EQ(m2_side_effects(m2, 104), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 1);
    bounds_teardown();
}

/* Key Data Length larger than the declared body leaves room for.
 * The old parser treated this as "no key data" and kept the frame. */
static void test_key_data_len_exceeds_declared_body_rejected(void) {
    bounds_setup();
    uint8_t m1[128];
    int n = build_eapol_key(m1, KI_M1, ANONCE, NULL, PMKID);
    ASSERT_EQ(n, 121);
    set_kdl(m1, 23);
    bounds_reset();
    ASSERT_EQ(feed_exact(m1, n, 1), 0);
    ASSERT_EQ(eapol_event_count(), 0);
    set_kdl(m1, 0xffff);
    ASSERT_EQ(feed_exact(m1, n, 1), 0);
    ASSERT_EQ(eapol_event_count(), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 2);
    ASSERT(!bounds_file_exists("eapol.22000"));
    bounds_teardown();
}

/* Key Data fits the capture but not the declared body: the PMKID sits
 * in bytes the frame itself says are not EAPOL. Must not be extracted
 * — the whole frame is inconsistent and is dropped. */
static void test_key_data_beyond_declared_body_not_parsed(void) {
    bounds_setup();
    uint8_t m1[128];
    int n = build_eapol_key(m1, KI_M1, ANONCE, NULL, PMKID);
    set_body_len(m1, 95 + 10);   /* declares 10 bytes of key data, kdl says 22 */
    bounds_reset();
    ASSERT_EQ(feed_exact(m1, n, 1), 0);
    ASSERT_EQ(eapol_event_count(), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 1);
    ASSERT(!bounds_file_exists("eapol.22000"));
    bounds_teardown();
}

/* Key Data Length smaller than the declared body: the tail of the body
 * is unparsed but inside the frame's own span. Tolerated — the fixed
 * fields are sound — but nothing past kdl is read as a KDE. */
static void test_key_data_len_short_of_body_tolerated(void) {
    eapol_clear();
    uint8_t m1[128];
    int n = build_eapol_key(m1, KI_M1, ANONCE, NULL, PMKID);
    set_kdl(m1, 0);
    ASSERT_EQ(feed_exact(m1, n, 1), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    ASSERT_EQ(s.eapol_events[0].has_pmkid, 0);
}

/* A KDE whose own length overruns Key Data stops the walk: the frame
 * is kept (ANonce is sound) but no PMKID is invented from it. */
static void test_kde_len_overrun_extracts_nothing(void) {
    eapol_clear();
    uint8_t m1[128];
    int n = build_eapol_key(m1, KI_M1, ANONCE, NULL, PMKID);
    m1[100] = 0x30;   /* KDE length 48 inside 22 bytes of key data */
    ASSERT_EQ(feed_exact(m1, n, 1), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    ASSERT_EQ(s.eapol_events[0].has_pmkid, 0);
}

/* Trailing capture bytes (FCS, padding) after the declared EAPOL span
 * are not EAPOL content: the hashcat MP=02 EAPOL field is exactly the
 * declared frame, 99 bytes = 198 hex chars. */
static void test_key_trailing_bytes_not_exported(void) {
    bounds_setup();
    bounds_reset();
    uint8_t m1[128];
    int m1n = build_eapol_key(m1, KI_M1, ANONCE, NULL, NULL);
    feed_exact(m1, m1n, 1);
    uint8_t m2[103];
    build_eapol_key(m2, KI_M2, SNONCE, M2_MIC, NULL);
    m2[99] = 0xde; m2[100] = 0xad; m2[101] = 0xbe; m2[102] = 0xef;
    ASSERT_EQ(feed_exact(m2, 103, 0), 1);
    ASSERT_EQ(eapol_event_count(), 2);

    char body[4096], p[160];
    bounds_path(p, sizeof(p), "eapol.22000");
    ASSERT(slurp_file(p, body, sizeof(body)) > 0);
    ASSERT(strstr(body, "WPA*02*") != NULL);
    ASSERT(strstr(body, "deadbeef") == NULL);
    /* Fields: WPA*02*mic*bssid*sta*essid*anonce*eapol*02 — take the
     * 8th '*'-separated field and measure it. */
    char *f = body;
    for (int i = 0; i < 7 && f; i++) {
        f = strchr(f, '*');
        if (f) f++;
    }
    ASSERT(f != NULL);
    if (f) {
        char *end = strchr(f, '*');
        ASSERT(end != NULL);
        if (end) ASSERT_EQ((int)(end - f), 198);
    }
    bounds_teardown();
}

/* The health counts cover only EAPOL-Key frames we would otherwise
 * parse: a short frame with a descriptor we don't handle (legacy RC4,
 * type 1) is not "malformed", just not ours. eapol_clear() zeroes. */
static void test_key_reject_counts_scoped_and_cleared(void) {
    eapol_clear();
    uint8_t k[99];
    build_eapol_key(k, KI_M2, SNONCE, M2_MIC, NULL);
    k[4] = 0x01;              /* RC4 descriptor */
    set_body_len(k, 44);
    ASSERT_EQ(feed_exact(k, 48, 0), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 0);

    k[4] = 0x02;
    ASSERT_EQ(feed_exact(k, 48, 0), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 1);
    set_body_len(k, 95);
    ASSERT_EQ(feed_exact(k, 98, 0), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 1);
    ASSERT_EQ(eapol_event_count(), 0);

    eapol_clear();
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_MALFORMED), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_TRUNCATED), 0);
    ASSERT_EQ(eapol_reject_count(EAPOL_REJECT_COUNT), 0);
}


/* ── Export file permissions, #87 ──────────────────────────────────── */

/* A PMKID or a 4-way handshake is offline-crackable material. Its
 * export must be private whatever the umask, and anything odd already
 * at the path — permissive, symlinked, foreign — is refused and
 * reported, never silently used or chmod'ed. Tests that depend on the
 * umask set it and restore the runner's afterwards. */

#define HS_PCAP "00aabbccddee_102030405060.pcap"

static char g_perm_dir[80];

static void perm_path(char *out, size_t sz, const char *leaf) {
    snprintf(out, sz, "%s/%s", g_perm_dir, leaf);
}

/* Remove everything the tests below may leave, then the dir itself. */
static void perm_cleanup(void) {
    eapol_set_output_dir(NULL);
    DIR *d = opendir(g_perm_dir);
    if (d) {
        struct dirent *e;
        char p[400];
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof(p), "%s/%s", g_perm_dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    unlink(g_perm_dir);          /* in case the test left a symlink here */
    rmdir(g_perm_dir);
    eapol_clear();
}

static void perm_setup(void) {
    snprintf(g_perm_dir, sizeof(g_perm_dir),
             "/tmp/sloth_test_eapol87_%d", (int)getpid());
    perm_cleanup();
}

static void drive_pmkid(void) {
    uint8_t eapol[128];
    int en = build_eapol_key(eapol, KI_M1, ANONCE, NULL, PMKID);
    uint8_t frame[256];
    int fn = build_frame(frame, eapol, en, /*from_ds=*/1);
    eapol_observe_dot11(frame, fn, -50, 6);
}

static int mode_of(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

static long size_of(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

static int dir_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}

/* Under a 022 umask the old code produced a 0755 dir and 0644 files. */
static void test_export_private_under_permissive_umask(void) {
    perm_setup();
    mode_t old = umask(022);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), 0);
    ASSERT_EQ(mode_of(g_perm_dir), 0700);
    drive_pmkid();
    char p[160];
    perm_path(p, sizeof(p), "eapol.22000");
    ASSERT_EQ(mode_of(p), 0600);
    ASSERT_GT(size_of(p), 0);
    perm_path(p, sizeof(p), HS_PCAP);
    ASSERT_EQ(mode_of(p), 0600);
    ASSERT_GT(size_of(p), 0);
    ASSERT_EQ(eapol_export_failures(), 0);
    umask(old);
    perm_cleanup();
}

/* An existing group/world-readable dir is refused, not tightened. */
static void test_export_refuses_permissive_existing_dir(void) {
    perm_setup();
    mkdir(g_perm_dir, 0700);
    chmod(g_perm_dir, 0755);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), -1);
    ASSERT(strstr(eapol_export_error(), "0755") != NULL);
    ASSERT_EQ(mode_of(g_perm_dir), 0755);          /* not chmod'ed */
    drive_pmkid();
    ASSERT_EQ(dir_entries(g_perm_dir), 0);         /* nothing written */
    perm_cleanup();
}

/* A symlink at the export path is refused even when it points at a
 * perfectly private directory — the link itself is the problem. */
static void test_export_refuses_symlinked_dir(void) {
    perm_setup();
    char target[120];
    snprintf(target, sizeof(target), "%s_target", g_perm_dir);
    rmdir(target);
    mkdir(target, 0700);
    ASSERT_EQ(symlink(target, g_perm_dir), 0);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), -1);
    ASSERT(strstr(eapol_export_error(), "symbolic link") != NULL);
    drive_pmkid();
    ASSERT_EQ(dir_entries(target), 0);
    rmdir(target);
    perm_cleanup();
}

/* A dir that cannot be created is reported, not ignored. */
static void test_export_dir_creation_failure_reported(void) {
    char bad[120];
    snprintf(bad, sizeof(bad), "/tmp/sloth_no_parent_%d/eapol", (int)getpid());
    ASSERT_EQ(eapol_set_output_dir(bad), -1);
    ASSERT(strstr(eapol_export_error(), "could not create") != NULL);
    eapol_set_output_dir(NULL);
}

/* A pre-existing permissive eapol.22000 is not appended to (nor
 * chmod'ed); the refusal is counted and its reason kept. */
static void test_export_refuses_permissive_existing_22000(void) {
    perm_setup();
    mkdir(g_perm_dir, 0700);
    char p[160];
    perm_path(p, sizeof(p), "eapol.22000");
    FILE *f = fopen(p, "w");
    if (f) fclose(f);
    chmod(p, 0644);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), 0);
    drive_pmkid();
    ASSERT_EQ(size_of(p), 0);
    ASSERT_EQ(mode_of(p), 0644);
    ASSERT_GE(eapol_export_failures(), 1);
    ASSERT(strstr(eapol_export_error(), "eapol.22000") != NULL);
    perm_cleanup();
}

/* A symlink planted as eapol.22000 is not written through. */
static void test_export_refuses_symlinked_22000(void) {
    perm_setup();
    mkdir(g_perm_dir, 0700);
    char victim[120], p[160];
    snprintf(victim, sizeof(victim), "%s_victim", g_perm_dir);
    FILE *f = fopen(victim, "w");
    if (f) fclose(f);
    perm_path(p, sizeof(p), "eapol.22000");
    ASSERT_EQ(symlink(victim, p), 0);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), 0);
    drive_pmkid();
    ASSERT_EQ(size_of(victim), 0);
    ASSERT_GE(eapol_export_failures(), 1);
    unlink(victim);
    perm_cleanup();
}

/* The per-handshake pcap is replaced atomically: a symlink at its name
 * is replaced by a private regular file, and the link's target is
 * never written. */
static void test_export_pcap_replace_does_not_follow_symlink(void) {
    perm_setup();
    mkdir(g_perm_dir, 0700);
    char victim[120], p[160];
    snprintf(victim, sizeof(victim), "%s_victim", g_perm_dir);
    FILE *f = fopen(victim, "w");
    if (f) fclose(f);
    perm_path(p, sizeof(p), HS_PCAP);
    ASSERT_EQ(symlink(victim, p), 0);
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), 0);
    drive_pmkid();
    ASSERT_EQ(size_of(victim), 0);
    struct stat st;
    ASSERT_EQ(lstat(p, &st), 0);
    ASSERT(S_ISREG(st.st_mode));
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);
    unlink(victim);
    perm_cleanup();
}

/* A write that fails (RLIMIT_FSIZE here, standing in for a full disk
 * without needing one) is counted and reported, and the previous
 * per-handshake pcap survives intact — no truncated replacement, no
 * leftover temp file. */
static void test_export_write_failure_visible(void) {
    perm_setup();
    ASSERT_EQ(eapol_set_output_dir(g_perm_dir), 0);
    drive_pmkid();
    char pcap[160], log22[160];
    perm_path(pcap, sizeof(pcap), HS_PCAP);
    perm_path(log22, sizeof(log22), "eapol.22000");
    long pcap_before = size_of(pcap), log_before = size_of(log22);
    ASSERT_GT(pcap_before, 0);
    ASSERT_EQ(eapol_export_failures(), 0);

    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    eapol_clear();
    setrlimit(RLIMIT_FSIZE, &lim);
    drive_pmkid();
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    ASSERT_GE(eapol_export_failures(), 2);   /* 22000 append + pcap */
    ASSERT(strstr(eapol_export_error(), "write failed") != NULL);
    /* ... and reaches the view's state, not only stderr. */
    static sloth_state_t st;
    memset(&st, 0, sizeof(st));
    eapol_snapshot(&st);
    ASSERT_GE(st.eapol_export_failures, 2);
    ASSERT(strstr(st.eapol_export_err, "write failed") != NULL);
    ASSERT_EQ(size_of(pcap), pcap_before);
    ASSERT_EQ(size_of(log22), log_before);
    ASSERT_EQ(dir_entries(g_perm_dir), 2);
    perm_cleanup();
}

void run_eapol_log_tests(void) {
    TEST_SUITE("eapol_log");
    RUN_TEST(test_non_eapol_data_frame_ignored);
    RUN_TEST(test_m1_with_pmkid_extracted);
    RUN_TEST(test_m1_without_pmkid);
    RUN_TEST(test_full_handshake_m1_then_m2);
    RUN_TEST(test_m2_without_m1_is_not_complete);
    RUN_TEST(test_clear_resets_state);
    RUN_TEST(test_pmkid_emits_pcap_when_eapol_dir_set);
    RUN_TEST(test_eapol_tainted_bssid_emits_provenance_comment);
    RUN_TEST(test_eapol_clean_bssid_no_provenance_comment);

    TEST_SUITE("eapol_log: PTK generation, CVE-2020-24587 (#75 slice 4)");
    RUN_TEST(test_generation_zero_for_unknown_pair);
    RUN_TEST(test_generation_bumps_on_first_m3);
    RUN_TEST(test_generation_bumps_on_first_m3_even_with_a_zero_anonce);
    RUN_TEST(test_generation_ignores_a_retransmitted_m3);
    RUN_TEST(test_generation_bumps_on_a_new_anonce);
    RUN_TEST(test_generation_is_per_pair);
    RUN_TEST(test_generation_cleared);
    RUN_TEST(test_generation_not_bumped_by_m1_or_m2);

    TEST_SUITE("eapol_log: EAPOL-Key bounds (#83)");
    RUN_TEST(test_key_lengths_0_to_100_truncated_capture);
    RUN_TEST(test_key_lengths_0_to_100_consistent_short_body);
    RUN_TEST(test_key_exact_99_byte_header_parses);
    RUN_TEST(test_key_declared_body_exceeds_capture_rejected);
    RUN_TEST(test_key_declared_body_short_of_header_rejected);
    RUN_TEST(test_key_data_len_exceeds_declared_body_rejected);
    RUN_TEST(test_key_data_beyond_declared_body_not_parsed);
    RUN_TEST(test_key_data_len_short_of_body_tolerated);
    RUN_TEST(test_kde_len_overrun_extracts_nothing);
    RUN_TEST(test_key_trailing_bytes_not_exported);
    RUN_TEST(test_key_reject_counts_scoped_and_cleared);

    /* #87 export permissions + failure reporting */
    RUN_TEST(test_export_private_under_permissive_umask);
    RUN_TEST(test_export_refuses_permissive_existing_dir);
    RUN_TEST(test_export_refuses_symlinked_dir);
    RUN_TEST(test_export_dir_creation_failure_reported);
    RUN_TEST(test_export_refuses_permissive_existing_22000);
    RUN_TEST(test_export_refuses_symlinked_22000);
    RUN_TEST(test_export_pcap_replace_does_not_follow_symlink);
    RUN_TEST(test_export_write_failure_visible);
}
