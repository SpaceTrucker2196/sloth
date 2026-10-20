#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "tls_log.h"
#include "views/tls.h"

/* ── Hand-crafted TLS ClientHello frames ─────────────────────
   TLS record:   16 03 01 <rec_len:2>
   Handshake:    01 <ch_len:3>
   ClientHello:  <legacy_version:2> <random:32> <sid_len:1>
                 <cs_len:2> <cs:2> <cm_len:1> <cm:1>
                 <ext_len:2> [extensions...]
   ──────────────────────────────────────────────────────────── */

/*
 * TLS 1.3 ClientHello with SNI "example.com" (79 bytes)
 * Contains: SNI ext (0x0000) + supported_versions ext (0x002b = TLS 1.3)
 */
static const uint8_t tls13_sni[] = {
    /* TLS record header */
    0x16, 0x03, 0x01, 0x00, 0x4a,   /* type=handshake, ver=3.1, len=74 */
    /* Handshake header */
    0x01, 0x00, 0x00, 0x46,         /* ClientHello, ch_len=70 */
    /* ClientHello */
    0x03, 0x03,                     /* legacy_version = TLS 1.2 */
    /* random (32 bytes) */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,                           /* session_id_len = 0 */
    0x00, 0x02,                     /* cipher_suites_len = 2 */
    0x00, 0x2f,                     /* TLS_RSA_WITH_AES_128_CBC_SHA */
    0x01,                           /* compression_methods_len = 1 */
    0x00,                           /* no compression */
    0x00, 0x1b,                     /* extensions_len = 27 */
    /* SNI extension (type=0x0000, len=16) */
    0x00, 0x00, 0x00, 0x10,
    0x00, 0x0e,                     /* list_len = 14 */
    0x00,                           /* name_type = host_name */
    0x00, 0x0b,                     /* name_len = 11 */
    'e','x','a','m','p','l','e','.','c','o','m',
    /* supported_versions extension (type=0x002b, len=3) */
    0x00, 0x2b, 0x00, 0x03,
    0x02,                           /* versions_list_len = 2 */
    0x03, 0x04,                     /* TLS 1.3 */
};

/*
 * TLS 1.2 ClientHello, no SNI, no supported_versions (52 bytes)
 * uses legacy_version 0x0303 → "TLS 1.2"
 */
static const uint8_t tls12_nosni[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x2b,
    0x03, 0x03,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x00,                     /* extensions_len = 0 */
};

/*
 * TLS 1.1 ClientHello, legacy_version 0x0302 (52 bytes)
 */
static const uint8_t tls11_legacy[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x2b,
    0x03, 0x02,                     /* legacy_version = TLS 1.1 */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x00,
};

/* ── tls_log_parse tests ─────────────────────────────────── */

static void test_parse_tls13_sni(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls13_sni, (int)sizeof(tls13_sni),
                          "192.168.1.5", "93.184.216.34", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.3");
    ASSERT_STR(e.host,    "example.com");
    ASSERT_STR(e.src,     "192.168.1.5");
    ASSERT_STR(e.dst,     "93.184.216.34");
}

static void test_parse_tls12_nosni(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls12_nosni, (int)sizeof(tls12_nosni),
                          "10.0.0.1", "8.8.8.8", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.2");
    ASSERT_EQ((int)e.host[0], 0);   /* no SNI */
}

static void test_parse_tls11_legacy(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls11_legacy, (int)sizeof(tls11_legacy),
                          "10.0.0.2", "10.0.0.1", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.1");
}

static void test_parse_rejects_wrong_type(void) {
    /* record type 0x17 (application data), not handshake */
    uint8_t buf[sizeof(tls12_nosni)];
    memcpy(buf, tls12_nosni, sizeof(buf));
    buf[0] = 0x17;
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(buf, (int)sizeof(buf), "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_server_hello(void) {
    /* handshake type 0x02 (ServerHello), not ClientHello */
    uint8_t buf[sizeof(tls12_nosni)];
    memcpy(buf, tls12_nosni, sizeof(buf));
    buf[5] = 0x02;
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(buf, (int)sizeof(buf), "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_short(void) {
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(tls12_nosni, 8, "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_truncated(void) {
    /* partial frame — len in header says 74 but data is only 20 bytes */
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(tls13_sni, 20, "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_null_ips_ok(void) {
    /* NULL IPs should not crash */
    tls_log_entry_t e;
    int r = tls_log_parse(tls12_nosni, (int)sizeof(tls12_nosni), NULL, NULL, &e);
    ASSERT_EQ(r, 1);
    ASSERT_EQ((int)e.src[0], 0);
    ASSERT_EQ((int)e.dst[0], 0);
}

/*
 * TLS 1.3 ClientHello where the supported_versions list is
 * [GREASE 0x7a7a, TLS 1.3 0x0304]. Real Chrome/Firefox put a GREASE
 * value first (RFC 8701); if the parser doesn't skip GREASE, best_ver
 * becomes 0x7a7a and ver_string() falls through to "TLS".
 *
 * Length fields (vs tls13_sni):
 *   supported_versions body:  1 (list_len) + 2 (GREASE) + 2 (TLS 1.3) = 5
 *   extension:                2 (type) + 2 (len) + 5 (body) = 9
 *   extensions_len:           20 (SNI) + 9 = 29 = 0x1d
 *   ch body:                  2+32+1+2+2+1+1+2+29 = 72 = 0x48
 *   rec body:                 4 (hs hdr) + 72 = 76 = 0x4c
 */
static const uint8_t tls13_sni_grease_versions[] = {
    /* TLS record */
    0x16, 0x03, 0x01, 0x00, 0x4c,
    /* Handshake */
    0x01, 0x00, 0x00, 0x48,
    /* legacy_version = TLS 1.2 */
    0x03, 0x03,
    /* random */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    /* extensions_len = 29 */
    0x00, 0x1d,
    /* SNI ext */
    0x00, 0x00, 0x00, 0x10,
    0x00, 0x0e,
    0x00,
    0x00, 0x0b,
    'e','x','a','m','p','l','e','.','c','o','m',
    /* supported_versions ext: len=5, list_len=4, [GREASE 7a7a, TLS 1.3] */
    0x00, 0x2b, 0x00, 0x05,
    0x04,
    0x7a, 0x7a,
    0x03, 0x04,
};

static void test_parse_tls13_supported_versions_skips_grease(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls13_sni_grease_versions,
                          (int)sizeof(tls13_sni_grease_versions),
                          "192.168.1.5", "93.184.216.34", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.3");
    ASSERT_STR(e.host,    "example.com");
}

/* ── uint16 list walks stop at the extension boundary ──────────────
 *
 * supported_versions, supported_groups and signature_algorithms are
 * lists of 16-bit values. Each walk read a pair at index i while checking
 * only i + 1 <= elen, so an odd-length extension let the last read take
 * one byte from whatever follows - the next extension's type, or past the
 * buffer when the extension is last (found by fuzz_tls_log_parse in CI on
 * 48e3dfe: heap-buffer-overflow in be16, tls_log.c:291). Each case below
 * lays the next extension's first byte where a straddling read would
 * pick it up, so the bug shows in a plain build too, not only under ASan.
 */
static int tls_build_hello(uint8_t *out, int cap, const uint8_t *ext, int ext_len) {
    static const uint8_t head[] = {
        0x03, 0x03,                                     /* legacy_version */
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,               /* random */
        0x00,                                           /* session id */
        0x00, 0x02, 0x00, 0x2f,                         /* one cipher */
        0x01, 0x00,                                     /* null compression */
    };
    int ch_len = (int)sizeof(head) + 2 + ext_len;
    int total  = 5 + 4 + ch_len;
    if (total > cap) return -1;
    uint8_t *p = out;
    *p++ = 0x16; *p++ = 0x03; *p++ = 0x01;
    *p++ = (uint8_t)((ch_len + 4) >> 8); *p++ = (uint8_t)(ch_len + 4);
    *p++ = 0x01; *p++ = 0x00;
    *p++ = (uint8_t)(ch_len >> 8); *p++ = (uint8_t)ch_len;
    memcpy(p, head, sizeof(head)); p += sizeof(head);
    *p++ = (uint8_t)(ext_len >> 8); *p++ = (uint8_t)ext_len;
    memcpy(p, ext, (size_t)ext_len);
    return total;
}

static void test_supported_versions_walk_stops_at_the_extension(void) {
    /* supported_versions, elen 4: list_len 4 claims two versions, but only
     * 0x0303 and a lone 0x03 are inside; the next extension's type starts
     * with 0x04. A straddling read sees 0x0304 and reports TLS 1.3. */
    static const uint8_t ext[] = {
        0x00, 0x2b, 0x00, 0x04,   0x04, 0x03, 0x03, 0x03,
        0x04, 0x00, 0x00, 0x00,                 /* unknown ext 0x0400, empty */
    };
    uint8_t buf[128]; tls_log_entry_t e;
    int n = tls_build_hello(buf, (int)sizeof(buf), ext, (int)sizeof(ext));
    ASSERT(n > 0);
    ASSERT_EQ(tls_log_parse(buf, n, NULL, NULL, &e), 1);
    ASSERT_STR(e.tls_ver, "TLS 1.2");
}

static void test_supported_versions_last_extension_stays_in_bounds(void) {
    /* The same odd tail as the LAST bytes of the buffer, in an exactly
     * sized heap copy, so ASan sees any read past it - the CI crash shape. */
    static const uint8_t ext[] = { 0x00, 0x2b, 0x00, 0x04, 0x04, 0x03, 0x03, 0x03 };
    uint8_t tmp[128]; tls_log_entry_t e;
    int n = tls_build_hello(tmp, (int)sizeof(tmp), ext, (int)sizeof(ext));
    ASSERT(n > 0);
    uint8_t *exact = malloc((size_t)n);
    ASSERT(exact != NULL);
    if (!exact) return;
    memcpy(exact, tmp, (size_t)n);
    ASSERT_EQ(tls_log_parse(exact, n, NULL, NULL, &e), 1);
    ASSERT_STR(e.tls_ver, "TLS 1.2");
    free(exact);
}

/* For the two lists that only reach the JA3/JA4 hashes, compare a
 * straddling hello with an honest twin that lists the in-bounds values
 * only: the fingerprints must agree. */
static void test_groups_and_sigalgs_walks_stop_at_the_extension(void) {
    /* supported_groups, elen 5: list_len 4, 0x001d, then a lone 0x00 and
     * the next extension's 0x17 - a straddling read adds curve 0x0017. */
    static const uint8_t groups_bad[] = {
        0x00, 0x0a, 0x00, 0x05,   0x00, 0x04, 0x00, 0x1d, 0x00,
        0x17, 0x00, 0x00, 0x00,
    };
    static const uint8_t groups_ok[] = {
        0x00, 0x0a, 0x00, 0x05,   0x00, 0x02, 0x00, 0x1d, 0x00,
        0x17, 0x00, 0x00, 0x00,
    };
    /* signature_algorithms, same shape: 0x0403, then 0x05 + next 0x01. */
    static const uint8_t sigs_bad[] = {
        0x00, 0x0d, 0x00, 0x05,   0x00, 0x04, 0x04, 0x03, 0x05,
        0x01, 0x00, 0x00, 0x00,
    };
    static const uint8_t sigs_ok[] = {
        0x00, 0x0d, 0x00, 0x05,   0x00, 0x02, 0x04, 0x03, 0x05,
        0x01, 0x00, 0x00, 0x00,
    };
    uint8_t a[128], b[128]; tls_log_entry_t ea, eb;
    int na = tls_build_hello(a, (int)sizeof(a), groups_bad, (int)sizeof(groups_bad));
    int nb = tls_build_hello(b, (int)sizeof(b), groups_ok,  (int)sizeof(groups_ok));
    ASSERT(na > 0 && nb > 0);
    ASSERT_EQ(tls_log_parse(a, na, NULL, NULL, &ea), 1);
    ASSERT_EQ(tls_log_parse(b, nb, NULL, NULL, &eb), 1);
    ASSERT(ea.ja3[0] != '\0');
    ASSERT_STR(ea.ja3, eb.ja3);
    na = tls_build_hello(a, (int)sizeof(a), sigs_bad, (int)sizeof(sigs_bad));
    nb = tls_build_hello(b, (int)sizeof(b), sigs_ok,  (int)sizeof(sigs_ok));
    ASSERT(na > 0 && nb > 0);
    ASSERT_EQ(tls_log_parse(a, na, NULL, NULL, &ea), 1);
    ASSERT_EQ(tls_log_parse(b, nb, NULL, NULL, &eb), 1);
    ASSERT(ea.ja4[0] != '\0');
    ASSERT_STR(ea.ja4, eb.ja4);
}

/* ── JA3 fingerprint tests ───────────────────────────────── */

/* A ClientHello with cipher 0x003c, ext SNI + supported_versions, supported
 * groups [0x001d, 0x0017], and ec_point_formats [0x00]. Exercises all five
 * JA3 sections.
 *
 * Length fields:
 *   extensions body: 4 (SNI) + 10 (groups) + 6 (formats) + 7 (versions) = 27 = 0x1b
 *   ch body: 2+32+1+2+2+1+1+2+27 = 70 = 0x46
 *   rec body: 4 (hs hdr) + 70 = 74 = 0x4a
 */
static const uint8_t ja3_clienthello[] = {
    /* TLS record */
    0x16, 0x03, 0x01, 0x00, 0x4a,
    /* Handshake */
    0x01, 0x00, 0x00, 0x46,
    /* legacy_version = TLS 1.2 */
    0x03, 0x03,
    /* random */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* session_id_len */
    0x00,
    /* cipher_suites len + entry 0x003c */
    0x00, 0x02, 0x00, 0x3c,
    /* compression_methods */
    0x01, 0x00,
    /* extensions_len = 27 */
    0x00, 0x1b,
    /* SNI ext (type 0x0000, len 0) */
    0x00, 0x00, 0x00, 0x00,
    /* supported_groups (0x000a) — list_len(2)=4 + two uint16 */
    0x00, 0x0a, 0x00, 0x06,
    0x00, 0x04,
    0x00, 0x1d, 0x00, 0x17,
    /* ec_point_formats (0x000b) — fmt_list_len(1)=1 + one byte */
    0x00, 0x0b, 0x00, 0x02,
    0x01,
    0x00,
    /* supported_versions (0x002b) — list_len(1)=2 + TLS1.3 */
    0x00, 0x2b, 0x00, 0x03,
    0x02,
    0x03, 0x04,
};

static void test_parse_emits_ja3(void) {
    tls_log_entry_t e;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "1.1.1.1", "2.2.2.2", &e));
    /* JA3 is the lowercase-hex MD5 — exactly 32 characters. */
    ASSERT_EQ((int)strlen(e.ja3), 32);
    for (int i = 0; i < 32; i++) {
        char c = e.ja3[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        ASSERT(ok);
    }
}

static void test_ja3_is_deterministic(void) {
    tls_log_entry_t a, b;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &a));
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "p", "q", &b));
    ASSERT_STR(a.ja3, b.ja3);
}

static void test_ja3_differs_for_different_ciphers(void) {
    /* Same as ja3_clienthello but cipher_suite changed from 0x003c → 0x0035. */
    uint8_t alt[sizeof(ja3_clienthello)];
    memcpy(alt, ja3_clienthello, sizeof(alt));
    /* offset of cipher_suite bytes inside the buffer: 5 (record) +
       4 (handshake) + 2 (legacy_version) + 32 (random) + 1 (sid_len) +
       2 (cipher_suites_len) = 46, then the suite itself spans 46..47. */
    alt[46] = 0x00;
    alt[47] = 0x35;

    tls_log_entry_t e1, e2;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &e1));
    ASSERT(tls_log_parse(alt, (int)sizeof(alt), "x", "y", &e2));
    ASSERT(strcmp(e1.ja3, e2.ja3) != 0);
}

/* ── JA4 client fingerprint tests (roadmap #16 phase 2) ──── */

static int is_lower_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static void test_ja4_shape_matches_foxio_spec(void) {
    /* FoxIO JA4 format: a(10) _ b(12) _ c(12) = 36 chars. Section a
     * starts with 't' for TCP ClientHello + a 2-char version + 1-char
     * SNI flag + 6 alnum. Sections b and c are lowercase-hex. */
    tls_log_entry_t e;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "1.1.1.1", "2.2.2.2", &e));
    ASSERT_EQ((int)strlen(e.ja4), 36);
    ASSERT_EQ((int)e.ja4[0],  (int)'t');
    ASSERT_EQ((int)e.ja4[10], (int)'_');
    ASSERT_EQ((int)e.ja4[23], (int)'_');
    for (int i = 11; i < 23; i++) ASSERT(is_lower_hex(e.ja4[i]));
    for (int i = 24; i < 36; i++) ASSERT(is_lower_hex(e.ja4[i]));
}

static void test_ja4_is_deterministic(void) {
    tls_log_entry_t a, b;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &a));
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "p", "q", &b));
    ASSERT_STR(a.ja4, b.ja4);
}

static void test_ja4_stable_across_extension_reorder(void) {
    /* The whole point of JA4 vs JA3: shuffling extension order in the
     * ClientHello (which Chrome/Firefox now do) produces the *same*
     * JA4 because sections b + c hash sorted lists. JA3 would change.
     *
     * ja3_clienthello ext order in the buffer:
     *   SNI (00 00 00 00)         at offset ext_start+0..3
     *   supported_groups          at offset ext_start+4..13   (10 bytes)
     *   ec_point_formats          at offset ext_start+14..18  ( 5 bytes)
     *   supported_versions        at offset ext_start+19..26  ( 8 bytes)
     *
     * Swap supported_groups (10) with ec_point_formats (5) + supported_versions (8=1?)
     * — simpler: swap the last two exts (supported_versions and
     *  ec_point_formats). Total ext bytes preserved so length fields
     *  don't need re-fixing. */
    uint8_t shuffled[sizeof(ja3_clienthello)];
    memcpy(shuffled, ja3_clienthello, sizeof(shuffled));

    int ext_start = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2;  /* just past extensions_len */
    int off_sni = ext_start + 0;   /* 4 bytes  (SNI header only, len 0) */
    int off_grp = ext_start + 4;   /* 10 bytes */
    int off_fmt = ext_start + 14;  /* 6 bytes  (0x000b 0x0002 0x01 0x00) */
    int off_ver = ext_start + 20;  /* 7 bytes  (0x002b 0x0003 0x02 0x03 0x04) */

    /* Move supported_versions before ec_point_formats. Both copies read
     * from the pristine fixture: the two ranges are adjacent, so
     * copying within `shuffled` overlaps (7-byte move over a 6-byte
     * gap), which memcpy leaves undefined — ASan flagged it (#95). */
    memcpy(shuffled + off_fmt, ja3_clienthello + off_ver, 7);
    memcpy(shuffled + off_fmt + 7, ja3_clienthello + off_fmt, 6);

    (void)off_sni; (void)off_grp;   /* not touched — silence -Wunused */

    tls_log_entry_t base, shuf;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &base));
    ASSERT(tls_log_parse(shuffled, (int)sizeof(shuffled),
                         "x", "y", &shuf));

    /* JA4 must survive extension reordering. JA3 does *not* — that's
     * a corollary check confirming we haven't accidentally made JA4
     * order-independent by removing the JA3 ordering. */
    ASSERT_STR(base.ja4, shuf.ja4);
    ASSERT(strcmp(base.ja3, shuf.ja3) != 0);
}

static void test_ja4_differs_when_ciphers_change(void) {
    /* Same shape ClientHello, cipher swapped 0x003c → 0x0035. JA4_b
     * (the cipher-hash section) must change; the sha256 truncation
     * makes accidental collisions vanishingly unlikely. */
    uint8_t alt[sizeof(ja3_clienthello)];
    memcpy(alt, ja3_clienthello, sizeof(alt));
    alt[46] = 0x00;
    alt[47] = 0x35;

    tls_log_entry_t base, changed;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &base));
    ASSERT(tls_log_parse(alt, (int)sizeof(alt), "x", "y", &changed));
    ASSERT(strcmp(base.ja4, changed.ja4) != 0);
}

static void test_ja3_skips_grease(void) {
    /* Insert GREASE cipher 0x0a0a alongside 0x003c. Since GREASE is filtered,
     * JA3 should equal that of the cipher-only ja3_clienthello. */
    uint8_t with_grease[sizeof(ja3_clienthello) + 2];
    /* Splice in: bump cipher_suites_len from 2 → 4 and prepend 0a 0a. */
    int prefix = 5 + 4 + 2 + 32 + 1;  /* up to and including sid_len */
    memcpy(with_grease, ja3_clienthello, prefix);
    /* cipher_suites_len */
    with_grease[prefix + 0] = 0x00;
    with_grease[prefix + 1] = 0x04;
    /* the two cipher entries: 0a 0a (GREASE) then 00 3c */
    with_grease[prefix + 2] = 0x0a;
    with_grease[prefix + 3] = 0x0a;
    with_grease[prefix + 4] = 0x00;
    with_grease[prefix + 5] = 0x3c;
    /* rest of the buffer follows. Source offset is prefix+4 (we kept
       cipher_suites_len of size 2 + cipher of size 2 = 4 bytes there). */
    int rest_src = prefix + 4;
    int rest_dst = prefix + 6;
    int rest_len = (int)sizeof(ja3_clienthello) - rest_src;
    memcpy(with_grease + rest_dst, ja3_clienthello + rest_src, (size_t)rest_len);

    /* Fix up the lengths: TLS record length +2, handshake length +2. */
    int new_rec_len = (with_grease[3] << 8 | with_grease[4]) + 2;
    with_grease[3] = (uint8_t)(new_rec_len >> 8);
    with_grease[4] = (uint8_t)(new_rec_len & 0xff);
    int new_ch_len = ((with_grease[6] << 16) | (with_grease[7] << 8) | with_grease[8]) + 2;
    with_grease[6] = (uint8_t)((new_ch_len >> 16) & 0xff);
    with_grease[7] = (uint8_t)((new_ch_len >>  8) & 0xff);
    with_grease[8] = (uint8_t)( new_ch_len        & 0xff);

    tls_log_entry_t base, greased;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &base));
    ASSERT(tls_log_parse(with_grease, (int)sizeof(with_grease),
                         "x", "y", &greased));
    ASSERT_STR(base.ja3, greased.ja3);
}

/* ── tls_log_record / tls_log_snapshot tests ─────────────── */

static tls_log_entry_t make_tls_entry(const char *src, const char *dst,
                                      const char *host, const char *ver)
{
    tls_log_entry_t e;
    memset(&e, 0, sizeof(e));
    if (src) strncpy(e.src,     src,  sizeof(e.src)     - 1);
    if (dst) strncpy(e.dst,     dst,  sizeof(e.dst)     - 1);
    if (host)strncpy(e.host,    host, sizeof(e.host)    - 1);
    if (ver) strncpy(e.tls_ver, ver,  sizeof(e.tls_ver) - 1);
    e.ts = 1000;
    return e;
}

static void test_record_and_snapshot(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("192.168.1.5", "93.184.216.34",
                                       "example.com", "TLS 1.3");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);

    ASSERT_EQ(s.tls_log_count, 1);
    ASSERT_STR(s.tls_log[0].host,    "example.com");
    ASSERT_STR(s.tls_log[0].tls_ver, "TLS 1.3");
}

static void test_snapshot_newest_first(void) {
    tls_log_clear();
    tls_log_entry_t a = make_tls_entry("1.1.1.1", "8.8.8.8", "first.com",  "TLS 1.2");
    tls_log_entry_t b = make_tls_entry("1.1.1.2", "8.8.8.8", "second.com", "TLS 1.3");
    tls_log_record(&a);
    tls_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);

    ASSERT_EQ(s.tls_log_count, 2);
    ASSERT_STR(s.tls_log[0].host, "second.com");   /* newest first */
    ASSERT_STR(s.tls_log[1].host, "first.com");
}

static void test_clear_empties_log(void) {
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "x.com", "TLS 1.2");
    tls_log_record(&e);
    tls_log_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.2");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.tls_log_sel = 99;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);
}

/* Boundary at sel == n + empty-log clamp tests. */
static void test_snapshot_clamps_sel_at_boundary_and_empty(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.2");
    tls_log_record(&e);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.tls_log_sel = 1;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);

    tls_log_clear();
    memset(&s, 0, sizeof(s));
    s.tls_log_sel = 5;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);
}

/* ── view_tls_draw ────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_tls_draw(&s);
    ASSERT_LINE_HAS(0, "TLS connections: 0");
    ASSERT_SCREEN_HAS("(no TLS ClientHello frames seen");
}

static void test_view_draw_populated(void) {
    tls_log_clear();
    tls_log_entry_t e1 = make_tls_entry("192.168.1.5",  "93.184.216.34", "example.com",  "TLS 1.3");
    tls_log_entry_t e2 = make_tls_entry("192.168.1.10", "142.250.80.46", "google.com",   "TLS 1.2");
    tls_log_record(&e1);
    tls_log_record(&e2);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    view_tls_draw(&s);
    ASSERT_LINE_HAS(0, "TLS connections: 2");
    int g = runner_screen_find("google.com");
    int e = runner_screen_find("example.com");
    ASSERT(g >= 0 && g < e);                  /* newest first */
    ASSERT_LINE_HAS(g, "TLS 1.2");
    ASSERT_LINE_HAS(g, "142.250.80.46");
    ASSERT_LINE_HAS(e, "TLS 1.3");
    ASSERT_LINE_HAS(e, "93.184.216.34");
}

/* ── view_tls_key tests ──────────────────────────────────── */

static void test_view_key_nav(void) {
    tls_log_clear();
    tls_log_entry_t a = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.3");
    tls_log_entry_t b = make_tls_entry("1.1.1.2", "2.2.2.2", "b.com", "TLS 1.2");
    tls_log_record(&a);
    tls_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    s.tls_log_sel = 0;

    view_tls_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.tls_log_sel, 1);

    view_tls_key(&s, SLOTH_KEY_DOWN);  /* at end */
    ASSERT_EQ(s.tls_log_sel, 1);

    view_tls_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.tls_log_sel, 0);

    view_tls_key(&s, SLOTH_KEY_UP);    /* at top */
    ASSERT_EQ(s.tls_log_sel, 0);
}

static void test_view_key_clear(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "x.com", "TLS 1.3");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_count, 1);

    view_tls_key(&s, 'c');
    ASSERT_EQ(s.tls_log_count, 0);
    ASSERT_EQ(s.tls_log_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

/* #138: SNI host_name octets (RFC 6066 §3) are stored through
 * netstr_copy(). The fixture's "example.com" is edited in a copy.
 * Mutation-proved: the memcpy restored in tls_log.c reddens it. */
static void test_parse_sni_control_octets_marked(void) {
    uint8_t f[sizeof tls13_sni];
    memcpy(f, tls13_sni, sizeof f);
    int at = -1;
    for (int i = 0; i + 11 <= (int)sizeof f; i++)
        if (memcmp(f + i, "example.com", 11) == 0) { at = i; break; }
    ASSERT(at > 0);
    if (at <= 0) return;
    f[at + 2] = 0x0a;          /* "ex\nm\x1ble.com" */
    f[at + 4] = 0x1b;
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(f, (int)sizeof f, "192.168.1.5", "93.184.216.34", &e), 1);
    ASSERT_STR(e.host, "ex?m?le.com");
}

/* A TLS 1.3 ClientHello carrying `name` (nlen octets) as its one
 * server_name entry, laid out per RFC 8446 §4.1.2 and RFC 6066 §3
 * exactly as tls13_sni above, with every length computed from nlen. */
static int build_ch_sni(uint8_t *f, int fsz, const uint8_t *name, int nlen) {
    int exts = 4 + 5 + nlen + 7;           /* SNI ext + supported_versions */
    int body = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + exts;
    int need = 5 + 4 + body;
    if (need > fsz) return 0;
    int o = 0;
    f[o++] = 0x16; f[o++] = 0x03; f[o++] = 0x01;
    f[o++] = (uint8_t)((4 + body) >> 8); f[o++] = (uint8_t)(4 + body);
    f[o++] = 0x01; f[o++] = 0x00;
    f[o++] = (uint8_t)(body >> 8); f[o++] = (uint8_t)body;
    f[o++] = 0x03; f[o++] = 0x03;                 /* legacy_version */
    memset(f + o, 0, 32); o += 32;                /* random */
    f[o++] = 0x00;                                /* session_id_len */
    f[o++] = 0x00; f[o++] = 0x02; f[o++] = 0x00; f[o++] = 0x2f;
    f[o++] = 0x01; f[o++] = 0x00;                 /* null compression */
    f[o++] = (uint8_t)(exts >> 8); f[o++] = (uint8_t)exts;
    f[o++] = 0x00; f[o++] = 0x00;                 /* server_name */
    f[o++] = (uint8_t)((5 + nlen) >> 8); f[o++] = (uint8_t)(5 + nlen);
    f[o++] = (uint8_t)((3 + nlen) >> 8); f[o++] = (uint8_t)(3 + nlen);
    f[o++] = 0x00;                                /* host_name */
    f[o++] = (uint8_t)(nlen >> 8); f[o++] = (uint8_t)nlen;
    memcpy(f + o, name, (size_t)nlen); o += nlen;
    f[o++] = 0x00; f[o++] = 0x2b; f[o++] = 0x00; f[o++] = 0x03;
    f[o++] = 0x02; f[o++] = 0x03; f[o++] = 0x04;  /* TLS 1.3 */
    return o;
}

/* #105 review: host holds the SNI's first 63 bytes, so a longer name
 * is stored as a prefix that can end on a watchlist suffix
 * ("<44 x a>.evidence.com" from "...evidence.com.evil.example").
 * host_trunc is what lets SURV_CLOUD_SNI refuse to match it. */
static void test_parse_sni_over_63_sets_host_trunc(void) {
    uint8_t name[96];
    const char *tail = ".evidence.com.evil.example";
    int pad = 63 - 13;                     /* 13 = strlen(".evidence.com") */
    memset(name, 'a', (size_t)pad);
    memcpy(name + pad, tail, strlen(tail));
    int nlen = pad + (int)strlen(tail);
    uint8_t f[192];
    int len = build_ch_sni(f, (int)sizeof f, name, nlen);
    ASSERT(len > 0);
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(f, len, "10.0.0.5", "203.0.113.9", &e), 1);
    ASSERT_EQ((int)strlen(e.host), 63);
    ASSERT(strstr(e.host, ".evidence.com") != NULL);
    ASSERT_EQ((int)e.host_trunc, 1);
}

static void test_parse_sni_of_exactly_63_is_whole(void) {
    uint8_t name[63];
    memset(name, 'a', sizeof name - 13);
    memcpy(name + sizeof name - 13, ".evidence.com", 13);
    uint8_t f[160];
    int len = build_ch_sni(f, (int)sizeof f, name, (int)sizeof name);
    ASSERT(len > 0);
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(f, len, "10.0.0.5", "203.0.113.9", &e), 1);
    ASSERT_EQ((int)strlen(e.host), 63);
    ASSERT_EQ((int)e.host_trunc, 0);
}

static void test_parse_sni_with_nul_octet_sets_host_trunc(void) {
    /* RFC 6066 §3 forbids a NUL in host_name; netstr_copy stops at
     * one, so the stored host is again a prefix of the wire value. */
    static const uint8_t name[] = {
        'e','v','i','d','e','n','c','e','.','c','o','m',
        0x00, '.','e','v','i','l'
    };
    uint8_t f[128];
    int len = build_ch_sni(f, (int)sizeof f, name, (int)sizeof name);
    ASSERT(len > 0);
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(f, len, "10.0.0.5", "203.0.113.9", &e), 1);
    ASSERT_STR(e.host, "evidence.com");
    ASSERT_EQ((int)e.host_trunc, 1);
}

static void test_parse_short_sni_is_whole(void) {
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(tls13_sni, (int)sizeof(tls13_sni),
                            "192.168.1.5", "93.184.216.34", &e), 1);
    ASSERT_EQ((int)e.host_trunc, 0);
}

void run_tls_log_tests(void) {
    TEST_SUITE("tls_log parse");
    RUN_TEST(test_parse_tls13_sni);
    RUN_TEST(test_parse_tls12_nosni);
    RUN_TEST(test_parse_tls11_legacy);
    RUN_TEST(test_parse_rejects_wrong_type);
    RUN_TEST(test_parse_rejects_server_hello);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_truncated);
    RUN_TEST(test_parse_null_ips_ok);
    RUN_TEST(test_parse_tls13_supported_versions_skips_grease);
    RUN_TEST(test_supported_versions_walk_stops_at_the_extension);
    RUN_TEST(test_supported_versions_last_extension_stays_in_bounds);
    RUN_TEST(test_groups_and_sigalgs_walks_stop_at_the_extension);
    RUN_TEST(test_ja4_shape_matches_foxio_spec);
    RUN_TEST(test_ja4_is_deterministic);
    RUN_TEST(test_ja4_stable_across_extension_reorder);
    RUN_TEST(test_ja4_differs_when_ciphers_change);

    TEST_SUITE("tls_log JA3 fingerprint");
    RUN_TEST(test_parse_emits_ja3);
    RUN_TEST(test_ja3_is_deterministic);
    RUN_TEST(test_ja3_differs_for_different_ciphers);
    RUN_TEST(test_ja3_skips_grease);

    TEST_SUITE("tls_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_boundary_and_empty);

    TEST_SUITE("view_tls draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_tls key");
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
    RUN_TEST(test_parse_sni_control_octets_marked);
    RUN_TEST(test_parse_sni_over_63_sets_host_trunc);
    RUN_TEST(test_parse_sni_of_exactly_63_is_whole);
    RUN_TEST(test_parse_sni_with_nul_octet_sets_host_trunc);
    RUN_TEST(test_parse_short_sni_is_whole);
}
