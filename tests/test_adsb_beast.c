#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <sys/socket.h>
#include <unistd.h>

#include "runner.h"
#include "sloth.h"
#include "adsb.h"
#include "adsb_beast.h"
#include "alerts.h"
#include "capture/adsb_reader.h"
#include "sloth_clock.h"
#include "tune.h"

/* --adsb beast:// (#186, 2026-11-09).
 *
 * Two kinds of input, neither from a receiver capture:
 *
 *  - The published example messages of J. Sun, "The 1090 Megahertz
 *    Riddle" (2nd ed., mode-s.org), with the answers that book gives:
 *    8D406B902015A678D4D220AA4BDA (CRC remainder 0, parity AA4BDA),
 *    8D4840D6202CC371C32CE0576098 (KLM1023), the CPR pair
 *    8D40621D58C382D690C8AC2863A7 / 8D40621D58C386435CC412692AD6
 *    (52.2572, 3.91937, 38000 ft; the even one is the newer), the
 *    velocity messages 8D485020994409940838175B284F (subtype 1, 159 kt,
 *    182.88 deg, -832 ft/min GNSS) and 8DA05F219B06B6AF189400CBC33F
 *    (subtype 3, -2304 ft/min barometric), and the surveillance replies
 *    2000171806A983 (DF4, 36000 ft) and 2A00516D492B80 (DF5, 0356).
 *
 *  - Frames built here field by field from the same chapters and from
 *    readsb's mode_s.c / net_io.c layouts. Their parity comes from
 *    ref_crc() below, a separate bit-at-a-time long division written
 *    from the Riddle's description ("append 24 zeros, XOR the 25-bit
 *    generator 1FFF409 under every 1"), not from the decoder's CRC; the
 *    two agree on the Riddle's AA4BDA, which is what pins both.
 *
 * Beast framing per readsb net_io.c modesSendBeastOutput() /
 * netTimestamp(): 0x1A, type, 6-byte timestamp, signal, payload, every
 * later 0x1A doubled. */

/* ── helpers ───────────────────────────────────────────────────── */

static int hexb(const char *h, uint8_t *out) {
    int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v = 0;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static int getbit(const uint8_t *b, int i) {          /* 0-based */
    return (b[i / 8] >> (7 - i % 8)) & 1;
}

/* Bits first..last (1-based, inclusive) of buf set to v. */
static void put(uint8_t *buf, int first, int last, unsigned v) {
    for (int i = last; i >= first; i--, v >>= 1) {
        int k = i - 1;
        if (v & 1) buf[k / 8] |= (uint8_t)(0x80 >> (k % 8));
        else       buf[k / 8] &= (uint8_t)~(0x80 >> (k % 8));
    }
}

/* The Riddle's CRC, bit by bit: data bits (nbits - 24) followed by 24
 * zeros, divided by 1 1111 1111 1111 1010 0000 0100 1. */
static uint32_t ref_crc(const uint8_t *msg, int nbits) {
    static const char gen[] = "1111111111111010000001001";
    int b[112];
    int nd = nbits - 24;
    for (int i = 0; i < nbits; i++) b[i] = i < nd ? getbit(msg, i) : 0;
    for (int i = 0; i < nd; i++)
        if (b[i])
            for (int k = 0; k < 25; k++) b[i + k] ^= gen[k] - '0';
    uint32_t r = 0;
    for (int i = nd; i < nbits; i++) r = (r << 1) | (uint32_t)b[i];
    return r;
}

/* A 112-bit DF17/18 frame: DF, CA/CF, address, ME, parity. */
static void mk_es(uint8_t f[14], int df, int ca, uint32_t addr, const uint8_t me[7]) {
    memset(f, 0, 14);
    put(f, 1, 5, (unsigned)df);
    put(f, 6, 8, (unsigned)ca);
    put(f, 9, 32, addr);
    memcpy(f + 4, me, 7);
    uint32_t p = ref_crc(f, 112);
    f[11] = (uint8_t)(p >> 16); f[12] = (uint8_t)(p >> 8); f[13] = (uint8_t)p;
}

/* A 56-bit DF4/5 reply: the 13-bit field at 20-32 and AP = parity xor
 * address (the Riddle, Mode S surveillance; address/parity). */
static void mk_ap(uint8_t f[7], int df, unsigned field13, uint32_t addr) {
    memset(f, 0, 7);
    put(f, 1, 5, (unsigned)df);
    put(f, 20, 32, field13);
    uint32_t p = ref_crc(f, 56) ^ addr;
    f[4] = (uint8_t)(p >> 16); f[5] = (uint8_t)(p >> 8); f[6] = (uint8_t)p;
}

/* A DF11 all-call reply with II = 0: parity is the plain CRC. */
static void mk_df11(uint8_t f[7], uint32_t addr) {
    memset(f, 0, 7);
    put(f, 1, 5, 11);
    put(f, 6, 8, 5);
    put(f, 9, 32, addr);
    uint32_t p = ref_crc(f, 56);
    f[4] = (uint8_t)(p >> 16); f[5] = (uint8_t)(p >> 8); f[6] = (uint8_t)p;
}

/* The 13-bit identity for four octal digits, in the order the Riddle
 * gives: C1 A1 C2 A2 C4 A4 X B1 D1 B2 D2 B4 D4. */
static unsigned id13(const char *sq) {
    int a = sq[0] - '0', b = sq[1] - '0', c = sq[2] - '0', d = sq[3] - '0';
    int bitv[13] = { c & 1, a & 1, (c >> 1) & 1, (a >> 1) & 1, (c >> 2) & 1,
                     (a >> 2) & 1, 0, b & 1, d & 1, (b >> 1) & 1, (d >> 1) & 1,
                     (b >> 2) & 1, (d >> 2) & 1 };
    unsigned v = 0;
    for (int i = 0; i < 13; i++) v = (v << 1) | (unsigned)bitv[i];
    return v;
}

/* One Beast frame around a payload, 0x1A doubled after the type. */
static size_t wrap(uint8_t *out, uint8_t type, uint64_t ts, uint8_t sig,
                   const uint8_t *p, int n) {
    size_t o = 0;
    uint8_t raw[6 + 1 + 14];
    int rn = 0;
    for (int i = 5; i >= 0; i--) raw[rn++] = (uint8_t)(ts >> (8 * i));
    raw[rn++] = sig;
    for (int i = 0; i < n; i++) raw[rn++] = p[i];
    out[o++] = 0x1A;
    out[o++] = type;
    for (int i = 0; i < rn; i++) {
        out[o++] = raw[i];
        if (raw[i] == 0x1A) out[o++] = 0x1A;
    }
    return o;
}

static adsb_beast_t g_b;            /* ~140 KB: off the stack */
static sloth_state_t g_s;

#define WALL_MS 1800000000000LL
static uint64_t g_mono;

static void begin(void) {
    adsb_reset();
    adsb_set_source_sbs("beast:127.0.0.1:30005");
    adsb_beast_init(&g_b);
    memset(&g_s, 0, sizeof(g_s));
    g_mono = 5000000;
}

/* Feed one payload as a '2'/'3' frame at the current mono, signal sig. */
static void feed(const uint8_t *p, int n, uint8_t sig) {
    uint8_t buf[64];
    size_t l = wrap(buf, n == 7 ? '2' : '3', 0x000102030405ULL, sig, p, n);
    adsb_beast_feed(&g_b, buf, l, WALL_MS + (int64_t)(g_mono - 5000000), g_mono);
}
static void feed_hex(const char *h, uint8_t sig) {
    uint8_t m[14];
    int n = hexb(h, m);
    feed(m, n, sig);
}
static void poll_now(void) {
    adsb_health_poll(&g_s, (time_t)(WALL_MS / 1000 + (int64_t)(g_mono - 5000000) / 1000), g_mono);
}
static const adsb_aircraft_t *row(uint32_t icao, int non_icao) {
    for (int i = 0; i < g_s.adsb_count; i++)
        if (g_s.adsb_rows[i].icao == icao && g_s.adsb_rows[i].non_icao == non_icao)
            return &g_s.adsb_rows[i];
    return NULL;
}

/* ── CRC ───────────────────────────────────────────────────────── */

static void test_crc_known_answers(void) {
    uint8_t m[14];
    hexb("8D406B902015A678D4D220AA4BDA", m);
    ASSERT_EQ(adsb_modes_crc(m, 112), 0u);
    /* The parity the Riddle derives for this data, from both divisions. */
    m[11] = m[12] = m[13] = 0;
    ASSERT_EQ(adsb_modes_crc(m, 112), 0xAA4BDAu);
    ASSERT_EQ(ref_crc(m, 112), 0xAA4BDAu);
    /* The Riddle's corrupted example. */
    hexb("8D4CA251204994B1C36E60A5343D", m);
    ASSERT(adsb_modes_crc(m, 112) != 0u);
    /* Every published ES example in this file is intact. */
    static const char *const ok[] = {
        "8D4840D6202CC371C32CE0576098", "8D40621D58C382D690C8AC2863A7",
        "8D40621D58C386435CC412692AD6", "8D485020994409940838175B284F",
        "8DA05F219B06B6AF189400CBC33F",
    };
    for (int i = 0; i < 5; i++) {
        hexb(ok[i], m);
        ASSERT_EQ(adsb_modes_crc(m, 112), 0u);
    }
    /* One flipped bit anywhere is caught (no correction is attempted). */
    hexb("8D4840D6202CC371C32CE0576098", m);
    for (int bit = 0; bit < 112; bit++) {
        m[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
        ASSERT(adsb_modes_crc(m, 112) != 0u);
        m[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
    }
}

/* A DF17 with one bit flipped is refused and makes no row, while the
 * intact one does. Seen red with the `rem != 0` test for DF17/18 in
 * adsb_beast_decode() removed: the flipped frame made row 4840d6. */
static void test_crc_bad_frame_refused(void) {
    begin();
    uint8_t m[14];
    hexb("8D4840D6202CC371C32CE0576098", m);
    m[6] ^= 0x04;
    feed(m, 14, 100);
    poll_now();
    ASSERT_EQ(g_s.adsb_count, 0);
    ASSERT_EQ(g_b.crc_bad, 1u);
    ASSERT_EQ(g_s.adsb.bad_entries, 1u);
    ASSERT_EQ(g_s.adsb.state, ADSB_LIVE);      /* the stream is alive */
    m[6] ^= 0x04;
    feed(m, 14, 100);
    poll_now();
    ASSERT_EQ(g_s.adsb_count, 1);
    adsb_reset();
}

/* ── field decoders ────────────────────────────────────────────── */

static void test_fields_known_answers(void) {
    uint8_t m[7];
    int alt = 0;
    char sq[5] = { 0 };
    /* DF4 2000171806A983: AC is bits 20-32. */
    hexb("2000171806A983", m);
    unsigned ac = (unsigned)(((m[2] & 0x1F) << 8) | m[3]);
    ASSERT_EQ(adsb_modes_ac13(ac, &alt), 0);
    ASSERT_EQ(alt, 36000);
    /* DF5 2A00516D492B80: ID is bits 20-32. */
    hexb("2A00516D492B80", m);
    unsigned id = (unsigned)(((m[2] & 0x1F) << 8) | m[3]);
    ASSERT_EQ(adsb_modes_id13(id, sq), 0);
    ASSERT_STR(sq, "0356");
    /* The emergency codes through the Riddle's bit order. */
    ASSERT_EQ(adsb_modes_id13(id13("7500"), sq), 0); ASSERT_STR(sq, "7500");
    ASSERT_EQ(adsb_modes_id13(id13("7600"), sq), 0); ASSERT_STR(sq, "7600");
    ASSERT_EQ(adsb_modes_id13(id13("7700"), sq), 0); ASSERT_STR(sq, "7700");
    ASSERT_EQ(adsb_modes_id13(id13("1234"), sq), 0); ASSERT_STR(sq, "1234");
    ASSERT_EQ(adsb_modes_id13(0, sq), -1);
    /* AC13: Q = 0 (Gillham) and M = 1 (metres) are not decoded. */
    ASSERT_EQ(adsb_modes_ac13(ac & ~0x10u, &alt), -1);
    ASSERT_EQ(adsb_modes_ac13(ac | 0x40u, &alt), -1);
    ASSERT_EQ(adsb_modes_ac13(0, &alt), -1);
    /* AC12 of the Riddle's position example: 110000111000 = 38000 ft. */
    ASSERT_EQ(adsb_modes_ac12(0xC38, &alt), 0);
    ASSERT_EQ(alt, 38000);
    ASSERT_EQ(adsb_modes_ac12(0xC38 & ~0x10u, &alt), -1);
}

/* ── CPR ───────────────────────────────────────────────────────── */

/* NL against the closed form's published points and readsb's table
 * (cpr.c cprNLFunction(), from 1090-WP-9-14) on either side of three
 * of its edges. */
static void test_cpr_nl(void) {
    ASSERT_EQ(adsb_cpr_nl(0.0), 59);
    ASSERT_EQ(adsb_cpr_nl(52.2572), 36);
    ASSERT_EQ(adsb_cpr_nl(87.0), 2);
    ASSERT_EQ(adsb_cpr_nl(-87.0), 2);
    ASSERT_EQ(adsb_cpr_nl(88.0), 1);
    ASSERT_EQ(adsb_cpr_nl(10.4704), 59);
    ASSERT_EQ(adsb_cpr_nl(10.4706), 58);
    ASSERT_EQ(adsb_cpr_nl(59.9545), 30);
    ASSERT_EQ(adsb_cpr_nl(59.9547), 29);
    ASSERT_EQ(adsb_cpr_nl(86.5353), 3);
    ASSERT_EQ(adsb_cpr_nl(86.5354), 2);
    ASSERT_EQ(adsb_cpr_nl(-33.2), adsb_cpr_nl(33.2));
}

static void test_cpr_known_answers(void) {
    double la = 0, lo = 0;
    /* The Riddle's raw values: even 93000/51372, odd 74158/50194. */
    ASSERT_EQ(adsb_cpr_global(93000, 51372, 74158, 50194, 0, &la, &lo), 0);
    ASSERT_NEAR(la, 52.25720214843750, 1e-9);
    ASSERT_NEAR(lo, 3.91937255859375, 1e-9);
    /* Local, against the Riddle's reference (52.258, 3.918). */
    la = lo = 0;
    ASSERT_EQ(adsb_cpr_local(52.258, 3.918, 93000, 51372, 0, &la, &lo), 0);
    ASSERT_NEAR(la, 52.2572021484375, 1e-9);
    ASSERT_NEAR(lo, 3.91937255859375, 1e-9);
}

/* CPR encoding (the inverse the Riddle's decode undoes), for frames
 * that put an aircraft where a test wants it. */
static void cpr_enc(double lat, double lon, int odd, unsigned *yz, unsigned *xz) {
    double dlat = 360.0 / (odd ? 59 : 60);
    double y = floor(131072.0 * fmod(fmod(lat, dlat) + dlat, dlat) / dlat + 0.5);
    double rlat = dlat * (y / 131072.0 + floor(lat / dlat));
    int nl = adsb_cpr_nl(rlat) - odd;
    double dlon = 360.0 / (nl > 1 ? nl : 1);
    double x = floor(131072.0 * fmod(fmod(lon, dlon) + dlon, dlon) / dlon + 0.5);
    *yz = (unsigned)y & 0x1FFFF;
    *xz = (unsigned)x & 0x1FFFF;
}

/* An airborne-position DF17 at lat/lon, 25 ft Q-coded altitude. */
static void mk_pos(uint8_t f[14], uint32_t addr, int tc, int alt_ft,
                   double lat, double lon, int odd) {
    uint8_t me[7] = { 0 };
    unsigned yz = 0, xz = 0;
    cpr_enc(lat, lon, odd, &yz, &xz);
    unsigned n = (unsigned)((alt_ft + 1000) / 25);
    unsigned ac12 = ((n & 0x7F0) << 1) | 0x10 | (n & 0x0F);
    put(me, 1, 5, (unsigned)tc);
    put(me, 9, 20, ac12);
    put(me, 22, 22, (unsigned)odd);
    put(me, 23, 39, yz);
    put(me, 40, 56, xz);
    mk_es(f, 17, 5, addr, me);
}

/* The Riddle's pair as frames, odd first (t1 = t0 - 2 s): one row at
 * the even (newer) message's position with 38000 ft. */
static void test_cpr_pair_frames(void) {
    begin();
    feed_hex("8D40621D58C386435CC412692AD6", 0x40);
    poll_now();
    const adsb_aircraft_t *a = row(0x40621D, 0);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->has_pos, 0);              /* half a pair */
        ASSERT_EQ(a->has_alt_baro, 1);
        ASSERT_EQ(a->alt_baro, 38000);
    }
    g_mono += 2000;
    feed_hex("8D40621D58C382D690C8AC2863A7", 0x40);
    poll_now();
    a = row(0x40621D, 0);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->has_pos, 1);
        ASSERT_NEAR(a->lat, 52.2572021484375, 1e-9);
        ASSERT_NEAR(a->lon, 3.91937255859375, 1e-9);
        ASSERT_STR(a->type, "adsb_icao");
        ASSERT_EQ(a->messages, 2u);
    }
    ASSERT_EQ(g_b.cpr_rejected, 0u);
    adsb_reset();
}

/* Refusals. (1) A pair whose latitudes straddle an NL edge (10.465 deg,
 * NL 59; 10.476 deg, NL 58: 1.2 km apart, an aircraft crossing it)
 * decodes to nothing; seen red with the NL
 * comparison in adsb_cpr_global() removed (a position was produced).
 * (2) Halves 11 s apart are not a pair; seen red with the
 * ADSB_BEAST_CPR_PAIR_MS bound removed. (3) A position 200 km from the
 * aircraft's own fix 1 s earlier is refused and the fix stands; seen
 * red with the distance check in position() removed. */
static void test_cpr_refusals(void) {
    double la = 0, lo = 0;
    unsigned ye = 0, xe = 0, yo = 0, xo = 0;
    cpr_enc(10.465, 20.0, 0, &ye, &xe);
    cpr_enc(10.476, 20.0, 1, &yo, &xo);
    ASSERT_EQ(adsb_cpr_global((int)ye, (int)xe, (int)yo, (int)xo, 1, &la, &lo), -1);
    /* Control: both halves at 10.465 decode. */
    cpr_enc(10.465, 20.0, 1, &yo, &xo);
    ASSERT_EQ(adsb_cpr_global((int)ye, (int)xe, (int)yo, (int)xo, 1, &la, &lo), 0);
    ASSERT_NEAR(la, 10.465, 1e-3);
    ASSERT_NEAR(lo, 20.0, 1e-3);

    uint8_t f[14];
    begin();
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.30, -111.80, 0);
    feed(f, 14, 50);
    g_mono += 11000;
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.30, -111.80, 1);
    feed(f, 14, 50);
    poll_now();
    const adsb_aircraft_t *a = row(0xA1B2C3, 0);
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->has_pos, 0);
    g_mono += 1000;                       /* a fresh pair now */
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.30, -111.80, 0);
    feed(f, 14, 50);
    poll_now();
    a = row(0xA1B2C3, 0);
    if (a) {
        ASSERT_EQ(a->has_pos, 1);
        ASSERT_NEAR(a->lat, 33.30, 1e-3);
        ASSERT_NEAR(a->lon, -111.80, 1e-3);
    }
    adsb_reset();

    /* Local decode against that fix: a 1.4 km move one half at a time
     * is taken; a 200 km jump is refused and the fix stands. */
    begin();
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.30, -111.80, 0);
    feed(f, 14, 50);
    g_mono += 1000;
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.30, -111.80, 1);
    feed(f, 14, 50);
    g_mono += 1000;
    mk_pos(f, 0xA1B2C3, 11, 30000, 33.31, -111.79, 0);   /* a 1.4 km move */
    feed(f, 14, 50);
    poll_now();
    a = row(0xA1B2C3, 0);
    if (a) {
        ASSERT_NEAR(a->lat, 33.31, 1e-3);
        ASSERT_NEAR(a->lon, -111.79, 1e-3);
    }
    ASSERT_EQ(g_b.cpr_rejected, 0u);
    g_mono += 1000;
    mk_pos(f, 0xA1B2C3, 11, 30000, 35.10, -111.79, 1);   /* 200 km north */
    feed(f, 14, 50);
    poll_now();
    a = row(0xA1B2C3, 0);
    ASSERT_EQ(g_b.cpr_rejected, 1u);
    if (a) {
        ASSERT_NEAR(a->lat, 33.31, 1e-3);
        ASSERT_EQ(a->messages, 4u);              /* the frame still counts */
    }
    adsb_reset();
}

/* ── ES messages ───────────────────────────────────────────────── */

static void test_ident_klm1023(void) {
    begin();
    feed_hex("8D4840D6202CC371C32CE0576098", 0x80);
    poll_now();
    const adsb_aircraft_t *a = row(0x4840D6, 0);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_STR(a->flight, "KLM1023");
        ASSERT_STR(a->category, "A0");     /* TC 4, CA 0 */
        ASSERT_STR(a->type, "adsb_icao");
        ASSERT_EQ(a->emergency, ADSB_EMERG_ABSENT);
        /* rssi: readsb's 10 log10((b/255)^2 + 1.125e-5), b = 0x80. */
        ASSERT_EQ(a->has_rssi, 1);
        ASSERT_NEAR(a->rssi, 10.0 * log10((128.0 / 255.0) * (128.0 / 255.0) + 1.125e-5), 1e-9);
    }
    adsb_reset();
}

/* A character outside letters, digits and space (a '#' code in the
 * Riddle's table) leaves the callsign absent; the category stands.
 * Seen red with the charset test in es_ident() guarded `if (0)`: the
 * callsign read "SYN@1". */
static void test_ident_bad_char(void) {
    begin();
    uint8_t me[7] = { 0 }, f[14];
    put(me, 1, 5, 4);
    put(me, 6, 8, 3);
    static const unsigned cs[8] = { 19, 25, 14, 0, 49, 32, 32, 32 };  /* S Y N @ 1 */
    for (int i = 0; i < 8; i++) put(me, 9 + 6 * i, 14 + 6 * i, cs[i]);
    mk_es(f, 17, 5, 0x0ABCDE, me);
    feed(f, 14, 10);
    put(me, 9 + 18, 14 + 18, 48);                                     /* '@' -> '0' */
    mk_es(f, 17, 5, 0x0ABCDF, me);
    feed(f, 14, 10);
    poll_now();
    const adsb_aircraft_t *a = row(0x0ABCDE, 0), *b = row(0x0ABCDF, 0);
    ASSERT(a && b);
    if (a) { ASSERT_STR(a->flight, ""); ASSERT_STR(a->category, "A3"); }
    if (b) ASSERT_STR(b->flight, "SYN01");
    adsb_reset();
}

static void test_velocity_known_answers(void) {
    begin();
    feed_hex("8D485020994409940838175B284F", 0x30);
    feed_hex("8DA05F219B06B6AF189400CBC33F", 0x30);
    poll_now();
    const adsb_aircraft_t *a = row(0x485020, 0), *b = row(0xA05F21, 0);
    ASSERT(a && b);
    if (a) {
        ASSERT_EQ(a->has_gs, 1);
        ASSERT_NEAR(a->gs, 159.2, 0.05);         /* the Riddle: 159 kt */
        ASSERT_NEAR(a->track, 182.88, 0.01);
        ASSERT_EQ(a->has_geom_rate, 1);          /* VrSrc 0: GNSS */
        ASSERT_EQ(a->geom_rate, -832);
        ASSERT_EQ(a->has_baro_rate, 0);
    }
    if (b) {
        ASSERT_EQ(b->has_gs, 0);                 /* airspeed, not ground speed */
        ASSERT_EQ(b->has_track, 0);
        ASSERT_EQ(b->has_baro_rate, 1);
        ASSERT_EQ(b->baro_rate, -2304);
    }
    adsb_reset();
}

/* TC 20-22 altitude is geometric; TC 5-8 is a surface report. */
static void test_gnss_alt_and_surface(void) {
    begin();
    uint8_t f[14], me[7] = { 0 };
    mk_pos(f, 0x111111, 20, 12000, 33.3, -111.8, 0);
    feed(f, 14, 10);
    put(me, 1, 5, 6);
    mk_es(f, 17, 4, 0x222222, me);
    feed(f, 14, 10);
    poll_now();
    const adsb_aircraft_t *a = row(0x111111, 0), *b = row(0x222222, 0);
    if (a) {
        ASSERT_EQ(a->has_alt_geom, 1);
        ASSERT_EQ(a->alt_geom, 12000);
        ASSERT_EQ(a->has_alt_baro, 0);
    }
    if (b) ASSERT_EQ(b->on_ground, 1);
    ASSERT(a && b);
    adsb_reset();
}

/* TC 28 subtype 1: the emergency word and the Mode A code. */
static void mk_status(uint8_t f[14], uint32_t addr, int emerg, const char *sq) {
    uint8_t me[7] = { 0 };
    put(me, 1, 5, 28);
    put(me, 6, 8, 1);
    put(me, 9, 11, (unsigned)emerg);
    put(me, 12, 24, id13(sq));
    mk_es(f, 17, 5, addr, me);
}

static void test_status_tc28(void) {
    begin();
    uint8_t f[14];
    mk_status(f, 0x333333, 5, "7500");
    feed(f, 14, 10);
    poll_now();
    const adsb_aircraft_t *a = row(0x333333, 0);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->emergency, ADSB_EMERG_UNLAWFUL);
        ASSERT_STR(adsb_emergency_name(a->emergency), "unlawful");
        ASSERT_STR(a->squawk, "7500");
    }
    mk_status(f, 0x333333, 0, "1200");     /* cleared */
    feed(f, 14, 10);
    poll_now();
    a = row(0x333333, 0);
    if (a) { ASSERT_EQ(a->emergency, ADSB_EMERG_NONE); ASSERT_STR(a->squawk, "1200"); }
    adsb_reset();
}

/* DF18: CF 1 is a non-ICAO address, its own row beside the same 24
 * bits from a DF17; CF 0 is an ICAO address; CF 3 is not decoded. */
static void test_df18_address_spaces(void) {
    begin();
    uint8_t f[14], me[7] = { 0 };
    put(me, 1, 5, 4);
    mk_es(f, 17, 5, 0x444444, me);
    feed(f, 14, 10);
    mk_es(f, 18, 1, 0x444444, me);
    feed(f, 14, 10);
    mk_es(f, 18, 0, 0x555555, me);
    feed(f, 14, 10);
    mk_es(f, 18, 3, 0x666666, me);
    feed(f, 14, 10);
    poll_now();
    ASSERT_EQ(g_s.adsb_count, 3);
    const adsb_aircraft_t *a = row(0x444444, 1), *b = row(0x555555, 0);
    ASSERT(row(0x444444, 0) != NULL);
    if (a) ASSERT_STR(a->type, "adsb_other");
    if (b) ASSERT_STR(b->type, "adsb_icao_nt");
    ASSERT(a && b);
    ASSERT_EQ(g_b.ignored, 1u);
    adsb_reset();
}

/* ── Address/parity replies ────────────────────────────────────── */

/* The Riddle's DF4 and DF5 replies: their address is whatever the
 * remainder says; unconfirmed they are ghosts, confirmed by a clean DF17
 * from that address they decode (36000 ft, 0356). The ghost refusal was
 * seen red with the `!confirmed()` guard in adsb_beast_decode() replaced
 * by taking a track for any address: both made rows. */
static void test_ap_needs_confirmation(void) {
    begin();
    uint8_t m4[7], m5[7], f[14], me[7] = { 0 };
    hexb("2000171806A983", m4);
    hexb("2A00516D492B80", m5);
    uint32_t a4 = adsb_modes_crc(m4, 56), a5 = adsb_modes_crc(m5, 56);
    ASSERT_EQ(a4, ref_crc(m4, 56) ^ (((uint32_t)m4[4] << 16) | ((uint32_t)m4[5] << 8) | m4[6]));
    feed(m4, 7, 10);
    feed(m5, 7, 10);
    poll_now();
    ASSERT_EQ(g_s.adsb_count, 0);
    ASSERT_EQ(g_b.ghosts, 2u);
    put(me, 1, 5, 4);
    mk_es(f, 17, 5, a4, me);
    feed(f, 14, 10);
    mk_es(f, 17, 5, a5, me);
    feed(f, 14, 10);
    g_mono += 1000;
    feed(m4, 7, 10);
    feed(m5, 7, 10);
    poll_now();
    const adsb_aircraft_t *r4 = row(a4, 0), *r5 = row(a5, 0);
    ASSERT(r4 && r5);
    if (r4) { ASSERT_EQ(r4->has_alt_baro, 1); ASSERT_EQ(r4->alt_baro, 36000);
              ASSERT_STR(r4->type, "adsb_icao"); }   /* ADS-B stays the type */
    if (r5) ASSERT_STR(r5->squawk, "0356");
    ASSERT_EQ(g_b.ghosts, 2u);
    adsb_reset();
}

/* DF18 does not vouch (readsb: a DF18 transmitter need not have a
 * Mode S transponder); a DF11 with remainder 0 does, and its address
 * then reads as mode_s. A confirmation lapses after
 * ADSB_BEAST_CONFIRM_MS. The DF18 refusal was seen red with DF18 also
 * setting confirmed_mono; the lapse with the age bound in confirmed()
 * removed. */
static void test_confirmation_sources_and_lapse(void) {
    begin();
    uint8_t f[14], s[7], me[7] = { 0 };
    put(me, 1, 5, 4);
    mk_es(f, 18, 0, 0x777777, me);
    feed(f, 14, 10);
    mk_ap(s, 5, id13("7700"), 0x777777);
    feed(s, 7, 10);
    ASSERT_EQ(g_b.ghosts, 1u);
    mk_df11(s, 0x888888);
    feed(s, 7, 10);
    mk_ap(s, 4, 0x0C38 | 0, 0x888888);      /* M 0, Q 1 */
    feed(s, 7, 10);
    poll_now();
    const adsb_aircraft_t *a = row(0x888888, 0);
    ASSERT(a != NULL);
    if (a) ASSERT_STR(a->type, "mode_s");
    ASSERT_EQ(g_b.ghosts, 1u);
    g_mono += ADSB_BEAST_CONFIRM_MS + 1000;
    mk_ap(s, 4, 0x0C38, 0x888888);
    feed(s, 7, 10);
    ASSERT_EQ(g_b.ghosts, 2u);
    adsb_reset();
}

/* DF11 replying to a radar with interrogator code 5 (remainder 5, the
 * code in its low 7 bits) is neither a CRC failure nor a confirmation;
 * a remainder above those bits is a CRC failure. Found on the live
 * smoke run (one `bad` per such reply); seen red before the fix with
 * crc_bad 1 for the II = 5 reply. */
static void test_df11_interrogator_code(void) {
    begin();
    uint8_t s[7];
    mk_df11(s, 0x999999);
    s[6] ^= 0x05;                       /* parity xor II 5 */
    feed(s, 7, 10);
    ASSERT_EQ(g_b.crc_bad, 0u);
    ASSERT_EQ(g_b.ignored, 1u);
    mk_ap(s, 5, id13("1200"), 0x999999);
    feed(s, 7, 10);
    ASSERT_EQ(g_b.ghosts, 1u);          /* II != 0 did not vouch */
    mk_df11(s, 0x999999);
    s[4] ^= 0x01;                       /* a bit above the II field */
    feed(s, 7, 10);
    ASSERT_EQ(g_b.crc_bad, 1u);
    poll_now();
    ASSERT_EQ(g_s.adsb.bad_entries, 1u);
    ASSERT_EQ(g_s.adsb_count, 0);
    adsb_reset();
}

/* ── The framer ────────────────────────────────────────────────── */

/* Build the stream used by the framing tests: a heartbeat, the KLM
 * identification with a timestamp and signal that both carry 0x1A, and
 * the Riddle's odd position. */
static size_t stream(uint8_t *out) {
    uint8_t m[14], zero[2] = { 0, 0 };
    size_t o = wrap(out, '1', 0, 0, zero, 2);
    hexb("8D4840D6202CC371C32CE0576098", m);
    o += wrap(out + o, '3', 0x1A001A1A0001ULL, 0x1A, m, 14);
    hexb("8D40621D58C386435CC412692AD6", m);
    o += wrap(out + o, '3', 0x000000000002ULL, 0x40, m, 14);
    return o;
}

static void test_framer_escapes_and_splits(void) {
    uint8_t buf[128];
    size_t n = stream(buf);
    ASSERT(n > 11 + 2 * 23);                    /* the doubled bytes are there */
    for (size_t cut = 0; cut <= n; cut++) {
        begin();
        adsb_beast_feed(&g_b, buf, cut, WALL_MS, g_mono);
        adsb_beast_feed(&g_b, buf + cut, n - cut, WALL_MS, g_mono);
        poll_now();
        ASSERT_EQ(g_b.parse_errors, 0u);
        ASSERT_EQ(g_b.frames, 3u);
        ASSERT_EQ(g_b.modeac, 1u);
        ASSERT_EQ(g_s.adsb_count, 2);
        const adsb_aircraft_t *a = row(0x4840D6, 0);
        if (a) {
            ASSERT_STR(a->flight, "KLM1023");
            ASSERT_NEAR(a->rssi, 10.0 * log10((26.0 / 255) * (26.0 / 255) + 1.125e-5), 1e-9);
        }
    }
    /* Byte at a time. */
    begin();
    for (size_t i = 0; i < n; i++) adsb_beast_feed(&g_b, buf + i, 1, WALL_MS, g_mono);
    poll_now();
    ASSERT_EQ(g_s.adsb_count, 2);
    ASSERT_EQ(g_b.parse_errors, 0u);
    adsb_reset();
}

/* Garbage before a frame is one parse error, then the frame decodes; a
 * frame cut short by a lone 0x1A is one parse error and the frame that
 * 0x1A starts decodes; an unknown type is one parse error; a receiver
 * id (0xE3) and a Radarcape position ('5') are skipped, not errors; a
 * heartbeat alone keeps the source live with no row. */
static void test_framer_resync(void) {
    uint8_t buf[256], m[14];
    size_t o = 0;
    static const uint8_t junk[] = { 0x00, 0x33, 0xFF, '3', 0x12 };
    memcpy(buf, junk, sizeof(junk));
    o += sizeof(junk);
    hexb("8D4840D6202CC371C32CE0576098", m);
    o += wrap(buf + o, '3', 1, 10, m, 14);
    /* A cut frame: header and 5 bytes, then a whole new frame. */
    size_t cut = wrap(buf + o, '3', 2, 10, m, 14);
    o += 2 + 5;
    (void)cut;
    hexb("8D485020994409940838175B284F", m);
    o += wrap(buf + o, '3', 3, 10, m, 14);
    buf[o++] = 0x1A; buf[o++] = '9';           /* unknown type */
    buf[o++] = 0x1A; buf[o++] = 0xE3;          /* receiver id, one 0x1A inside */
    static const uint8_t rid[] = { 1, 2, 0x1A, 0x1A, 4, 5, 6, 7, 8 };
    memcpy(buf + o, rid, sizeof(rid));
    o += sizeof(rid);
    buf[o++] = 0x1A; buf[o++] = '5';
    memset(buf + o, 0x11, 21);
    o += 21;
    hexb("8DA05F219B06B6AF189400CBC33F", m);
    o += wrap(buf + o, '3', 4, 10, m, 14);
    begin();
    adsb_beast_feed(&g_b, buf, o, WALL_MS, g_mono);
    poll_now();
    ASSERT_EQ(g_b.parse_errors, 3u);
    ASSERT_EQ(g_s.adsb.parse_errors, 3u);
    ASSERT_EQ(g_b.skipped, 2u);
    ASSERT_EQ(g_s.adsb_count, 3);
    ASSERT(row(0x4840D6, 0) && row(0x485020, 0) && row(0xA05F21, 0));
    adsb_reset();

    begin();
    uint8_t hb[16], zero[2] = { 0, 0 };
    size_t hn = wrap(hb, '1', 0, 0, zero, 2);
    adsb_beast_feed(&g_b, hb, hn, WALL_MS, g_mono);
    poll_now();
    ASSERT_EQ(g_s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(g_s.adsb_count, 0);
    ASSERT_EQ(g_s.adsb.parse_errors, 0u);
    /* ...and goes stale past the window with nothing more. */
    g_mono += (uint64_t)(ADSB_SBS_STALE_S + 1) * 1000u;
    poll_now();
    ASSERT_EQ(g_s.adsb.state, ADSB_STALE);
    adsb_reset();
}

/* ── The spec ──────────────────────────────────────────────────── */

static void test_spec_parse_beast(void) {
    adsb_spec_t sp;
    char e[200], lab[48];
    ASSERT_EQ(adsb_spec_parse("beast://", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.kind, ADSB_SPEC_BEAST);
    ASSERT_STR(sp.host, "127.0.0.1");
    ASSERT_EQ(sp.port, 30005);
    adsb_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "beast:127.0.0.1:30005");
    ASSERT_EQ(adsb_spec_parse("beast://[::1]:31005", &sp, e, sizeof(e)), 0);
    adsb_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "beast:[::1]:31005");
    ASSERT_EQ(adsb_spec_parse("beast://127.0.0.9", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.port, 30005);
    e[0] = '\0';
    ASSERT_EQ(adsb_spec_parse("beast://192.0.2.1:30005", &sp, e, sizeof(e)), -1);
    ASSERT(strstr(e, "beast:// reads a decoder on this host") != NULL);
    ASSERT_EQ(adsb_spec_parse("beast://[::ffff:127.0.0.1]:30005", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("beast://localhost", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("beast://127.0.0.1:0", &sp, e, sizeof(e)), -1);
    /* sbs:// keeps its own default. */
    ASSERT_EQ(adsb_spec_parse("sbs://", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.port, 30003);
}

/* ── ADSB_EMERGENCY from Beast rows ────────────────────────────── */

static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return (time_t)(WALL_MS / 1000 + (int64_t)(g_mono - 5000000) / 1000); }

static const alert_t *alert_by_key(const char *key) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ALERT_TYPE_ADSB_EMERGENCY &&
            strcmp(g_s.alerts[i].key, key) == 0)
            return &g_s.alerts[i];
    return NULL;
}

static void emerg_begin(void) {
    begin();
    sloth_clock_test_set(pin_mono, pin_wall);
    tune_reset();
    alerts_clear();
}
static void emerg_tick(void) {
    poll_now();
    alerts_update(&g_s);
}
static void emerg_end(void) {
    alerts_clear();
    adsb_reset();
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

/* From a DF5 squawk (address confirmed by a DF17), from a TC 28 Mode A
 * code, and from a TC 28 emergency word with an ordinary squawk. */
static void test_emergency_alert_from_beast(void) {
    uint8_t f[14], s[7], me[7] = { 0 };
    emerg_begin();
    put(me, 1, 5, 4);
    mk_es(f, 17, 5, 0xABC001, me);
    feed(f, 14, 10);
    mk_ap(s, 5, id13("7700"), 0xABC001);
    feed(s, 7, 10);
    emerg_tick();
    ASSERT_EQ(g_s.adsb.state, ADSB_LIVE);
    ASSERT(alert_by_key("adsbemerg:abc001:icao:7700") != NULL);
    emerg_end();

    emerg_begin();
    mk_status(f, 0xABC002, 4, "7600");     /* nordo, 7600 */
    feed(f, 14, 10);
    emerg_tick();
    ASSERT(alert_by_key("adsbemerg:abc002:icao:7600") != NULL);
    emerg_end();

    emerg_begin();
    mk_status(f, 0xABC003, 2, "1200");     /* lifeguard */
    feed(f, 14, 10);
    emerg_tick();
    const alert_t *a = alert_by_key("adsbemerg:abc003:icao:lifeguard");
    ASSERT(a != NULL);
    if (a) ASSERT(strstr(a->detail, "squawk 1200 emergency lifeguard") != NULL);
    emerg_end();

    /* A ghost 7700 (unconfirmed DF5) raises nothing. Seen red with the
     * same mutation as test_ap_needs_confirmation (a row and an alert). */
    emerg_begin();
    mk_ap(s, 5, id13("7700"), 0xABC004);
    feed(s, 7, 10);
    emerg_tick();
    ASSERT_EQ(g_s.adsb_count, 0);
    ASSERT(alert_by_key("adsbemerg:abc004:icao:7700") == NULL);
    emerg_end();
}

/* ── The socket ────────────────────────────────────────────────── */

static int listener(int *port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &al) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static void nap_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* A session through the reader: the frames arrive split across writes
 * and become rows; sloth writes nothing to the socket. The "writes
 * nothing" assertion was seen red with a one-byte write() added after
 * adsb_note_connected() in the reader's stream thread. */
static void test_beast_reader_session(void) {
    char err[200], spec[64];
    int port = 0;
    int lfd = listener(&port);
    ASSERT(lfd >= 0);
    if (lfd < 0) return;
    adsb_reset();
    snprintf(spec, sizeof(spec), "beast://127.0.0.1:%d", port);
    ASSERT_EQ(adsb_reader_configure(spec, err, sizeof(err)), 0);
    adsb_reader_run();
    struct pollfd pfd = { lfd, POLLIN, 0 };
    ASSERT_EQ(poll(&pfd, 1, 5000), 1);
    int c = accept(lfd, NULL, NULL);
    ASSERT(c >= 0);
    if (c < 0) { adsb_reader_stop(); close(lfd); adsb_reset(); return; }
    uint8_t buf[128];
    size_t n = stream(buf);
    size_t cuts[] = { 0, 7, 30, n };
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(write(c, buf + cuts[i], cuts[i + 1] - cuts[i]),
                  (ssize_t)(cuts[i + 1] - cuts[i]));
        nap_ms(30);
    }
    sloth_state_t *s = &g_s;
    for (int i = 0; i < 100; i++) {
        memset(s, 0, sizeof(*s));
        adsb_health_poll(s, sloth_wall(), sloth_mono_ms());
        if (s->adsb_count >= 2) break;
        nap_ms(20);
    }
    ASSERT_EQ(s->adsb_count, 2);
    ASSERT_EQ(s->adsb.parse_errors, 0u);
    char want[48];
    snprintf(want, sizeof(want), "beast:127.0.0.1:%d", port);
    ASSERT_STR(s->adsb.src, want);
    char got[16];
    struct pollfd cp = { c, POLLIN, 0 };
    ASSERT_EQ(poll(&cp, 1, 300), 0);
    ASSERT_EQ(recv(c, got, sizeof(got), MSG_DONTWAIT), (ssize_t)-1);
    close(c);
    adsb_reader_stop();
    close(lfd);
    adsb_reset();
}

void run_adsb_beast_tests(void) {
    RUN_TEST(test_crc_known_answers);
    RUN_TEST(test_crc_bad_frame_refused);
    RUN_TEST(test_fields_known_answers);
    RUN_TEST(test_cpr_nl);
    RUN_TEST(test_cpr_known_answers);
    RUN_TEST(test_cpr_pair_frames);
    RUN_TEST(test_cpr_refusals);
    RUN_TEST(test_ident_klm1023);
    RUN_TEST(test_ident_bad_char);
    RUN_TEST(test_velocity_known_answers);
    RUN_TEST(test_gnss_alt_and_surface);
    RUN_TEST(test_status_tc28);
    RUN_TEST(test_df18_address_spaces);
    RUN_TEST(test_ap_needs_confirmation);
    RUN_TEST(test_confirmation_sources_and_lapse);
    RUN_TEST(test_df11_interrogator_code);
    RUN_TEST(test_framer_escapes_and_splits);
    RUN_TEST(test_framer_resync);
    RUN_TEST(test_spec_parse_beast);
    RUN_TEST(test_emergency_alert_from_beast);
    RUN_TEST(test_beast_reader_session);
}
