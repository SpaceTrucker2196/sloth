#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "va/va_aes.h"
#include "va/va_conf.h"
#include "va/va_victron.h"

/*
 * sloth-va's pure half (src/va/: AES-128/CTR, Victron Instant Readout,
 * the 6597 GATT values, the two secret-file parsers, the JSONL record)
 * and the helper's boundaries (docs/wiki/victron.md, ADR 0011).
 *
 * Where each expected value comes from, never from the code under test:
 *   - AES: FIPS-197 Appendix C.1 and NIST SP 800-38A F.5.1;
 *   - Instant Readout, published vectors: keshavdv/victron-ble's own
 *     test advertisements and their expected readings (cited in
 *     research/victron/README.md); the decrypted bytes were checked
 *     independently with `openssl enc -d -aes-128-ctr`;
 *   - Instant Readout, hand-built: payloads packed bit by bit here from
 *     the "Extra manufacturer data" tables (the packing is worked in the
 *     comments), encrypted with `openssl enc -aes-128-ctr` (key
 *     0123456789abcdeffedcba9876543210, counter block 3412 then zeros),
 *     the ciphertext pasted in;
 *   - GATT: the characteristic table Victron staff posted (mvader,
 *     2021-07-02).
 *
 * Absence assertions, each seen red under the named mutation and then
 * restored (docs/wiki/log.md, the 2026-11-15 sloth-va entry):
 *   - test_wrong_key_refused: the key-check comparison in
 *     va_readout_decode() removed (the mismatched key decoded garbage);
 *   - test_truncated_fields_absent: `if (va_bits(...) != 0) return 0;`
 *     in field() dropped, reading zeros past the end;
 *   - test_soc_out_of_range_absent: `&& v <= 1000` dropped;
 *   - test_diag_never_carries_the_line: VA_CE_PIN's reason text made a
 *     format ("PIN %s is not exactly 6 digits"), the shape a reason
 *     takes the moment someone wants it to quote the line;
 *   - test_helper_is_not_linked_into_sloth:
 *     src/va/va_victron.c appended to CORE_COMMON_SRCS.
 */

static size_t unhex(const char *h, uint8_t *out, size_t max) {
    size_t n = 0;
    while (h[0] && h[1] && n < max) {
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static const va_value_t *val(const va_readout_t *r, const char *name) {
    for (int i = 0; i < r->nvals; i++)
        if (!strcmp(r->vals[i].name, name)) return &r->vals[i];
    return NULL;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    if (b) b[n] = '\0';
    fclose(f);
    return b;
}

/* ── AES ── */

static void test_aes_fips197_c1(void) {
    uint8_t k[16], p[16], c[16], want[16];
    unhex("000102030405060708090a0b0c0d0e0f", k, 16);
    unhex("00112233445566778899aabbccddeeff", p, 16);
    unhex("69c4e0d86a7b0430d8cdb78070b4c55a", want, 16);
    va_aes128_t a;
    va_aes128_init(&a, k);
    va_aes128_encrypt_block(&a, p, c);
    ASSERT(memcmp(c, want, 16) == 0);
}

/* SP 800-38A F.5.1 CTR-AES128.Encrypt: four blocks, and the counter
 * block's last bytes roll fefe..ff -> ff00 across them, which pins the
 * big-endian increment. */
static void test_aes_ctr_sp800_38a(void) {
    uint8_t k[16], ctr[16], p[64], c[64], want[64];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", k, 16);
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);
    unhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710", p, 64);
    unhex("874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff"
          "5ae4df3edbd5d35e5b4f09020db03eab" "1e031dda2fbe03d1792170a0f3009cee", want, 64);
    va_aes128_t a;
    va_aes128_init(&a, k);
    va_aes128_ctr(&a, ctr, p, c, 64);
    ASSERT(memcmp(c, want, 64) == 0);
    /* In place, and back: CTR is its own inverse. */
    va_aes128_ctr(&a, ctr, c, c, 64);
    ASSERT(memcmp(c, p, 64) == 0);
    /* A partial last block. */
    va_aes128_ctr(&a, ctr, p, c, 20);
    ASSERT(memcmp(c, want, 20) == 0);
    /* The caller's counter block is untouched. */
    ASSERT(ctr[15] == 0xff);
}

/* ── Instant Readout ── */

static void test_bits(void) {
    const uint8_t b[3] = { 0xA5, 0x0F, 0x80 };
    uint32_t v;
    ASSERT(va_bits(b, 3, 0, 8, &v) == 0 && v == 0xA5);
    ASSERT(va_bits(b, 3, 4, 8, &v) == 0 && v == 0xFA);     /* 0xA5>>4 | 0x0F<<4 */
    ASSERT(va_bits(b, 3, 23, 1, &v) == 0 && v == 1);
    ASSERT(va_bits(b, 3, 17, 8, &v) == -1);                 /* one bit past the end */
    ASSERT(va_bits(b, 3, 0, 0, &v) == -1);
    ASSERT(va_bits(b, 3, 0, 33, &v) == -1);
}

/* victron-ble tests/test_battery_monitor.py, test_end_to_end_parse:
 * a SmartShunt at 12.53 V, 0 A, -50.0 Ah, 50.0 %, aux off, no TTG. */
static void test_published_battery_monitor(void) {
    uint8_t md[32], key[16];
    size_t n = unhex("100289a302b040af925d09a4d89aa0128bdef48c6298a9", md, sizeof(md));
    unhex("aff4d0995b7d1e176c0c33ecb9e70dcd", key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    ASSERT_EQ(r.model_id, 0xA389);
    ASSERT_STR(va_model_name(r.model_id), "SmartShunt 500A/50mV");
    ASSERT_EQ(r.record_type, VA_REC_BATTERY_MONITOR);
    ASSERT_EQ(r.nonce, 0x40B0);
    ASSERT_EQ(r.plain_len, 15);
    const va_value_t *v;
    ASSERT((v = val(&r, "voltage_v")) && v->v > 12.5299 && v->v < 12.5301);
    ASSERT((v = val(&r, "current_a")) && v->v == 0.0);
    ASSERT((v = val(&r, "consumed_ah")) && v->v > -50.0001 && v->v < -49.9999);
    ASSERT((v = val(&r, "soc_pct")) && v->v > 49.9999 && v->v < 50.0001);
    ASSERT((v = val(&r, "alarm_reason")) && v->v == 0);
    ASSERT((v = val(&r, "aux_input")) && v->v == 3 && !strcmp(v->text, "none"));
    ASSERT(val(&r, "ttg_min") == NULL);                  /* 0xFFFF = NA */
    ASSERT(val(&r, "aux_voltage_v") == NULL);
    ASSERT(val(&r, "temperature_c") == NULL);
}

/* victron-ble tests/test_dcdc_converter.py, test_end_to_end_parse: an
 * Orion Smart off on engine shutdown (OR 0x80), 13.15 V in, output NA. */
static void test_published_dcdc(void) {
    uint8_t md[32], key[16];
    size_t n = unhex("1000c0a304121d64ca8d442b90bbdf6a8cba", md, sizeof(md));
    unhex("64ba49f1a8562e45197a8e1fe50d7658", key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    ASSERT_EQ(r.model_id, 0xA3C0);
    ASSERT_EQ(r.record_type, VA_REC_DCDC);
    const va_value_t *v;
    ASSERT((v = val(&r, "device_state")) && v->v == 0 && !strcmp(v->text, "off"));
    ASSERT((v = val(&r, "charger_error")) && v->v == 0);
    ASSERT((v = val(&r, "input_v")) && v->v > 13.1499 && v->v < 13.1501);
    ASSERT(val(&r, "output_v") == NULL);                 /* 0x7FFF = NA */
    ASSERT((v = val(&r, "off_reason")) && v->v == 0x80);
}

/* Hand-built Battery Monitor payload, by the "Extra manufacturer data"
 * table (record bit = payload bit + 32):
 *   TTG 600 min          bits 32..47   0x0258        58 02
 *   voltage 13.20 V      48..63        1320 = 0x0528 28 05
 *   alarm 0              64..79                      00 00
 *   aux 298.15 K         80..95        29815 = 0x7477 77 74
 *   aux input 2 (temp)   96..97  \
 *   current -1.500 A     98..119 /     -1500 in 22 bits = 0x3FFA24;
 *                        (0x3FFA24 << 2) | 2 = 0xFFE892  92 E8 FF
 *   consumed 12.3 Ah     120..139      123 = 0x7B
 *   SOC 87.5 %           140..149      875 = 0x36B
 *   unused, set          150..159      0x3FF
 *     0x7B | 0x36B << 20 | 0x3FF << 30 = 0xFFF6B0007B  7B 00 B0 F6 FF
 * Payload 58 02 28 05 00 00 77 74 92 E8 FF 7B 00 B0 F6 FF; record type
 * 0x02, nonce 0x1234, model 0xA381 (BMV-712 Smart). */
static const char *const BMV_HAND =
    "1000" "81a3" "02" "3412" "01" "1714bbd9f76a7003688eb687971f48ef";
static const char *const HAND_KEY = "0123456789abcdeffedcba9876543210";

static void test_hand_built_battery_monitor(void) {
    uint8_t md[32], key[16];
    size_t n = unhex(BMV_HAND, md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    ASSERT_STR(va_model_name(r.model_id), "BMV-712 Smart");
    const va_value_t *v;
    ASSERT((v = val(&r, "ttg_min")) && v->v == 600 && v->integer);
    ASSERT((v = val(&r, "voltage_v")) && v->v > 13.1999 && v->v < 13.2001);
    ASSERT((v = val(&r, "aux_input")) && v->v == 2 && !strcmp(v->text, "temperature"));
    ASSERT((v = val(&r, "temperature_c")) && v->v > 24.9999 && v->v < 25.0001);
    ASSERT((v = val(&r, "current_a")) && v->v > -1.5001 && v->v < -1.4999);
    ASSERT((v = val(&r, "consumed_ah")) && v->v > -12.3001 && v->v < -12.2999);
    ASSERT((v = val(&r, "soc_pct")) && v->v > 87.4999 && v->v < 87.5001);
    ASSERT(val(&r, "aux_voltage_v") == NULL && val(&r, "mid_voltage_v") == NULL);
}

/* Hand-built DC/DC payload: state 3 (bulk), error 0, input 14.40 V
 * (0x05A0), output 13.80 V (0x0564), off reason 0, 48 unused bits set:
 * 03 00 A0 05 64 05 00 00 00 00 FF FF FF FF FF FF. */
static void test_hand_built_dcdc(void) {
    uint8_t md[32], key[16];
    size_t n = unhex("1000" "c0a3" "04" "3412" "01" "4c1633d9936f0777fa66b603685041ef", md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    const va_value_t *v;
    ASSERT((v = val(&r, "device_state")) && v->v == 3 && !strcmp(v->text, "bulk"));
    ASSERT((v = val(&r, "input_v")) && v->v > 14.3999 && v->v < 14.4001);
    ASSERT((v = val(&r, "output_v")) && v->v > 13.7999 && v->v < 13.8001);
    ASSERT((v = val(&r, "off_reason")) && v->v == 0);
}

/* Hand-built Inverter payload, by the "Extra manufacturer data" table
 * (victron-ble's devices/inverter.py reads the same widths):
 *   state 9 (inverting)   bits 32..39                 09
 *   alarm 0               40..55                      00 00
 *   battery 12.80 V       56..71        1280 = 0x0500 00 05
 *   apparent 120 VA       72..87        0x0078        78 00
 *   AC 120.05 V           88..102  \    12005 = 0x2EE5
 *   AC 1.0 A              103..113 |    10
 *   unused, set           114..119 /    0x3F
 *     0x2EE5 | 10 << 15 | 0x3F << 26 = 0xFC052EE5     E5 2E 05 FC
 * then 40 unused bits set; model 0xA259. */
static void test_hand_built_inverter(void) {
    uint8_t md[32], key[16];
    size_t n = unhex("1000" "59a2" "03" "3412" "01" "461693dcf2120792d463b503685041ef", md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    ASSERT_EQ(r.record_type, VA_REC_INVERTER);
    ASSERT_STR(va_model_name(r.model_id), "Phoenix Inverter 12V 500VA 120V");
    const va_value_t *v;
    ASSERT((v = val(&r, "device_state")) && v->v == 9 && !strcmp(v->text, "inverting"));
    ASSERT((v = val(&r, "alarm_reason")) && v->v == 0);
    ASSERT((v = val(&r, "voltage_v")) && v->v > 12.7999 && v->v < 12.8001);
    ASSERT((v = val(&r, "ac_apparent_va")) && v->v == 120 && v->integer);
    ASSERT((v = val(&r, "ac_voltage_v")) && v->v > 120.0499 && v->v < 120.0501);
    ASSERT((v = val(&r, "ac_current_a")) && v->v > 0.9999 && v->v < 1.0001);
    ASSERT_EQ(r.nvals, 6);
}

/* The same record with every figure at its NA code (state 1, alarm 0,
 * then 0x7FFF, 0xFFFF, 0x7FFF, 0x7FF): only the state and the alarm
 * are written, and a record cut short after the alarm gives the same. */
static void test_inverter_na_and_short(void) {
    uint8_t md[32], key[16];
    size_t n = unhex("1000" "59a2" "03" "3412" "01" "4e1693238895f8880599b603685041ef", md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_OK);
    const va_value_t *v;
    ASSERT((v = val(&r, "device_state")) && v->v == 1 && !strcmp(v->text, "low_power"));
    ASSERT((v = val(&r, "alarm_reason")) && v->v == 0);
    ASSERT(val(&r, "voltage_v") == NULL && val(&r, "ac_apparent_va") == NULL);
    ASSERT(val(&r, "ac_voltage_v") == NULL && val(&r, "ac_current_a") == NULL);
    ASSERT_EQ(r.nvals, 2);
    ASSERT_EQ(va_readout_decode(md, 8 + 3, key, &r), VA_RO_OK);
    ASSERT_EQ(r.nvals, 2);
}

/* A record type with no layout here is decrypted and named, never
 * guessed at: no values. */
static void test_unknown_record_type(void) {
    uint8_t md[32], key[16];
    size_t n = unhex(BMV_HAND, md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    md[4] = 0x0E;
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_UNDECODED);
    ASSERT_EQ(r.nvals, 0);
    ASSERT_STR(va_record_type_name(0x0E), "unknown");
    md[4] = VA_REC_SOLAR;              /* listed in [EMD], not decoded here */
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_UNDECODED);
    ASSERT_STR(va_record_type_name(r.record_type), "solar_charger");
}

/* [EMD]: when the key's first byte does not match, stop decoding. */
static void test_wrong_key_refused(void) {
    uint8_t md[32], key[16];
    /* victron-ble test_key_mismatch: key byte 0xaf, key all 0xff. */
    size_t n = unhex("100289a302bb01af129087600b9b97bc2c32867c8238da", md, sizeof(md));
    memset(key, 0xff, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_KEY_MISMATCH);
    ASSERT_EQ(r.nvals, 0);
    ASSERT_EQ(r.plain_len, 0);
    /* The hand-built record under a key that differs only after byte 0
     * passes the check (that is all the byte promises) and decodes
     * garbage; one differing in byte 0 is refused. */
    n = unhex(BMV_HAND, md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    key[0] ^= 0x80;
    ASSERT_EQ(va_readout_decode(md, n, key, &r), VA_RO_KEY_MISMATCH);
    ASSERT_EQ(r.nvals, 0);
}

static void test_not_product_ad_and_truncated(void) {
    uint8_t md[32], key[16];
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    /* The VE.Direct dongle's 0x02-first advertisement is not Instant
     * Readout. */
    const uint8_t other[] = { 0x02, 0x00, 0x82, 0xa1, 0x01, 0x02, 0x03, 0x04, 0x05 };
    ASSERT_EQ(va_readout_decode(other, sizeof(other), key, &r), VA_RO_NOT_PRODUCT_AD);
    ASSERT_EQ(va_readout_decode(other, 0, key, &r), VA_RO_TRUNCATED);
    size_t n = unhex(BMV_HAND, md, sizeof(md));
    ASSERT_EQ(va_readout_decode(md, 8, key, &r), VA_RO_TRUNCATED);   /* no ciphertext */
    ASSERT_EQ(va_readout_decode(md, 5, key, &r), VA_RO_TRUNCATED);
    (void)n;
}

/* [EMD]: "a length check should be performed for all items". A record
 * cut after four ciphertext bytes has TTG and voltage, nothing else. */
static void test_truncated_fields_absent(void) {
    uint8_t md[32], key[16];
    unhex(BMV_HAND, md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, 8 + 4, key, &r), VA_RO_OK);
    ASSERT_EQ(r.plain_len, 4);
    ASSERT(val(&r, "ttg_min") != NULL);
    ASSERT(val(&r, "voltage_v") != NULL);
    ASSERT(val(&r, "alarm_reason") == NULL);
    ASSERT(val(&r, "current_a") == NULL);
    ASSERT(val(&r, "soc_pct") == NULL);
    ASSERT_EQ(r.nvals, 2);
    /* Consumed Ah ends at payload bit 107 (14 bytes), SOC at 117 (15). */
    ASSERT_EQ(va_readout_decode(md, 8 + 13, key, &r), VA_RO_OK);
    ASSERT(val(&r, "current_a") != NULL);
    ASSERT(val(&r, "consumed_ah") == NULL);
    ASSERT_EQ(va_readout_decode(md, 8 + 14, key, &r), VA_RO_OK);
    ASSERT(val(&r, "consumed_ah") != NULL);
    ASSERT(val(&r, "soc_pct") == NULL);
    ASSERT_EQ(va_readout_decode(md, 8 + 15, key, &r), VA_RO_OK);
    ASSERT(val(&r, "soc_pct") != NULL);
}

/* SOC's range is 0..100.0 %: raw 1001 is out of range and absent, not
 * clamped. Built by flipping the plaintext through the keystream: the
 * SOC bits are payload bits 108..117 (bytes 13-14). */
static void test_soc_out_of_range_absent(void) {
    uint8_t md[32], key[16];
    unhex(BMV_HAND, md, sizeof(md));
    unhex(HAND_KEY, key, 16);
    /* plaintext bytes 13..14 are B0 F6: SOC 875 = 0x36B. XOR to 1001
     * (0x3E9): delta 0x36B ^ 0x3E9 = 0x082, at bit 4 of byte 13: 0x0820
     * over bytes 13..14 -> byte 13 ^= 0x20, byte 14 ^= 0x08. */
    md[8 + 13] ^= 0x20;
    md[8 + 14] ^= 0x08;
    va_readout_t r;
    ASSERT_EQ(va_readout_decode(md, 24, key, &r), VA_RO_OK);
    ASSERT(val(&r, "soc_pct") == NULL);
    ASSERT(val(&r, "voltage_v") != NULL);
    /* And 1000 exactly is in range: delta 0x36B ^ 0x3E8 = 0x083. */
    md[8 + 13] ^= 0x20; md[8 + 14] ^= 0x08;      /* back to 875 */
    md[8 + 13] ^= 0x30; md[8 + 14] ^= 0x08;
    ASSERT_EQ(va_readout_decode(md, 24, key, &r), VA_RO_OK);
    const va_value_t *v = val(&r, "soc_pct");
    ASSERT(v && v->v > 99.9999 && v->v < 100.0001);
}

/* ── GATT ── */

static void test_gatt_values(void) {
    double v;
    const va_gatt_char_t *c = va_gatt_find("6597ED8D-4BDA-4C1E-AF4B-551C4CF74769");
    ASSERT(c && !strcmp(c->name, "voltage_v"));
    const uint8_t volt[2] = { 0x28, 0x05 };
    ASSERT(c && va_gatt_decode(c, volt, 2, &v) == 1 && v > 13.1999 && v < 13.2001);
    const uint8_t na[2] = { 0xff, 0x7f };
    ASSERT(c && va_gatt_decode(c, na, 2, &v) == 0);
    ASSERT(c && va_gatt_decode(c, volt, 3, &v) == -1);
    c = va_gatt_find("6597ed8c-4bda-4c1e-af4b-551c4cf74769");
    const uint8_t cur[4] = { 0x24, 0xfa, 0xff, 0xff };     /* -1500 mA */
    ASSERT(c && va_gatt_decode(c, cur, 4, &v) == 1 && v > -1.5001 && v < -1.4999);
    c = va_gatt_find("65970fff-4bda-4c1e-af4b-551c4cf74769");
    const uint8_t soc[2] = { 0x10, 0x27 };                 /* 10000 * 0.01 */
    ASSERT(c && va_gatt_decode(c, soc, 2, &v) == 1 && v > 99.999 && v < 100.001);
    c = va_gatt_find("6597eeff-4bda-4c1e-af4b-551c4cf74769");
    const uint8_t ah[4] = { 0x85, 0xff, 0xff, 0xff };      /* -123 * 0.1 */
    ASSERT(c && va_gatt_decode(c, ah, 4, &v) == 1 && v > -12.3001 && v < -12.2999);
    ASSERT(va_gatt_find(VA_GATT_KEEPALIVE_UUID) == NULL);   /* never read as a value */
    ASSERT(va_gatt_find("00002a00-0000-1000-8000-00805f9b34fb") == NULL);
    uint8_t ka[2];
    ASSERT(va_gatt_keepalive(30000, ka) == 0 && ka[0] == 0x30 && ka[1] == 0x75);
    ASSERT(va_gatt_keepalive(0xFFFF, ka) == -1);           /* "forever": refused */
    ASSERT(va_gatt_keepalive(0, ka) == -1);
}

/* ── the secret files ── */

typedef struct { int n; int line[16]; va_conf_err_t why[16]; char text[1024]; } diag_log_t;

static void collect(void *ctx, int line, va_conf_err_t why) {
    diag_log_t *d = ctx;
    if (d->n < 16) { d->line[d->n] = line; d->why[d->n] = why; }
    d->n++;
    size_t o = strlen(d->text);
    snprintf(d->text + o, sizeof(d->text) - o, "line %d: %s\n", line, va_conf_err_name(why));
}

static void test_conf_devices(void) {
    const char *text =
        "# owner's devices\n"
        "HQ2501YV9FU 314159   # BMV-712\n"
        "\n"
        "HQ2515QP3RX 271828\r\n"
        "HQ25232KEJG 161803 e4:b9:aa:47:57:1f  # dongle\n"
        "HQ0000BAD1 12345\n"            /* 5 digits */
        "HQ0000BAD2 1234567\n"          /* 7 digits */
        "HQ0000BAD3 12a456\n"
        "HQ-BAD 123456\n"               /* serial with '-' */
        "HQ0000BAD4 123456 zz:00\n"
        "HQ0000BAD5\n"
        "hq2501yv9fu 000000\n"          /* duplicate, any case */
        "HQ0000BAD6 123456 e4:b9:aa:47:57:1f\n"   /* duplicate address */
        "A B C D E\n";
    va_dev_conf_t d[VA_MAX_DEVICES];
    diag_log_t log;
    memset(&log, 0, sizeof(log));
    int n = va_conf_parse_devices(text, d, VA_MAX_DEVICES, collect, &log);
    ASSERT_EQ(n, 3);
    ASSERT_STR(d[0].serial, "HQ2501YV9FU");
    ASSERT_EQ(d[0].pin, 314159u);
    ASSERT_EQ(d[0].has_mac, 0);
    ASSERT_STR(d[1].serial, "HQ2515QP3RX");
    ASSERT_EQ(d[1].pin, 271828u);
    ASSERT_EQ(d[2].has_mac, 1);
    ASSERT(d[2].mac[0] == 0xe4 && d[2].mac[5] == 0x1f);
    ASSERT_EQ(log.n, 9);
    ASSERT(log.line[0] == 6 && log.why[0] == VA_CE_PIN);
    ASSERT(log.line[1] == 7 && log.why[1] == VA_CE_PIN);
    ASSERT(log.line[2] == 8 && log.why[2] == VA_CE_PIN);
    ASSERT(log.line[3] == 9 && log.why[3] == VA_CE_SERIAL);
    ASSERT(log.line[4] == 10 && log.why[4] == VA_CE_MAC);
    ASSERT(log.line[5] == 11 && log.why[5] == VA_CE_FIELDS);
    ASSERT(log.line[6] == 12 && log.why[6] == VA_CE_DUPLICATE);
    ASSERT(log.line[7] == 13 && log.why[7] == VA_CE_DUPLICATE);
    ASSERT(log.line[8] == 14 && log.why[8] == VA_CE_FIELDS);
    /* Too many: the cap holds and is reported. */
    char big[4096] = "";
    for (int i = 0; i < VA_MAX_DEVICES + 2; i++) {
        size_t o = strlen(big);
        snprintf(big + o, sizeof(big) - o, "HQ%08d 123456\n", i);
    }
    memset(&log, 0, sizeof(log));
    ASSERT_EQ(va_conf_parse_devices(big, d, VA_MAX_DEVICES, collect, &log), VA_MAX_DEVICES);
    ASSERT(log.n == 2 && log.why[0] == VA_CE_TOO_MANY);
}

/* No diagnostic carries any part of a line: the PINs and the keys, good
 * or malformed, are nowhere in the text a caller could log. */
static void test_diag_never_carries_the_line(void) {
    const char *dev =
        "HQ2501YV9FU 314159\n"
        "HQ2515QP3RX 27182x\n"
        "HQ2515QP3RY 2718281\n"
        "HQ2515QP3RZ 271828 not-a-mac\n";
    const char *keys =
        "c7:fe:23:b1:1c:5f aff4d0995b7d1e176c0c33ecb9e70dcd\n"
        "f5:d8:0c:b6:31:cf aff4d0995b7d1e176c0c33ecb9e70dcz\n"
        "f5:d8:0c:b6:31:ce 64ba49f1a8562e45197a8e1fe50d76\n"
        "f5:d8:0c:b6:31:cf\n";
    va_dev_conf_t d[VA_MAX_DEVICES];
    va_key_t k[VA_MAX_DEVICES];
    diag_log_t log;
    memset(&log, 0, sizeof(log));
    ASSERT_EQ(va_conf_parse_devices(dev, d, VA_MAX_DEVICES, collect, &log), 1);
    ASSERT_EQ(va_conf_parse_keys(keys, k, VA_MAX_DEVICES, collect, &log), 1);
    ASSERT_EQ(log.n, 6);
    static const char *const secret[] = { "314159", "27182", "2718281", "not-a-mac",
                                          "aff4d099", "dcz", "64ba49f1", "HQ2515", "c7:fe", "f5:d8" };
    for (size_t i = 0; i < sizeof(secret) / sizeof(secret[0]); i++) {
        if (strstr(log.text, secret[i])) fprintf(stderr, "    diag carries %s\n", secret[i]);
        ASSERT(strstr(log.text, secret[i]) == NULL);
    }
    for (int i = 0; i <= VA_CE_LONG_LINE; i++) {
        const char *s = va_conf_err_name((va_conf_err_t)i);
        ASSERT(s && strchr(s, '%') == NULL);
    }
}

static void test_conf_keys(void) {
    const char *text =
        "C7:FE:23:B1:1C:5F AFF4D0995B7D1E176C0C33ECB9E70DCD  # BMV\n"
        "f5:d8:0c:b6:31:cf 64ba49f1a8562e45197a8e1fe50d7658\n"
        "c7:fe:23:b1:1c:5f 64ba49f1a8562e45197a8e1fe50d7658\n"   /* duplicate address */
        "c7_fe_23_b1_1c_50 64ba49f1a8562e45197a8e1fe50d7658\n"   /* not the owner's form */
        "c7:fe:23:b1:1c:51 64ba49f1a8562e45197a8e1fe50d7658 extra\n";
    va_key_t k[VA_MAX_DEVICES];
    diag_log_t log;
    memset(&log, 0, sizeof(log));
    ASSERT_EQ(va_conf_parse_keys(text, k, VA_MAX_DEVICES, collect, &log), 2);
    ASSERT(k[0].mac[0] == 0xc7 && k[0].key[0] == 0xaf && k[0].key[15] == 0xcd);
    ASSERT(k[1].mac[5] == 0xcf && k[1].key[0] == 0x64);
    ASSERT(log.n == 3 && log.why[0] == VA_CE_DUPLICATE && log.why[1] == VA_CE_MAC
           && log.why[2] == VA_CE_FIELDS);
    /* An over-long line is refused whole. */
    char longl[400];
    memset(longl, 'a', sizeof(longl) - 2);
    longl[sizeof(longl) - 2] = '\n';
    longl[sizeof(longl) - 1] = '\0';
    memset(&log, 0, sizeof(log));
    ASSERT_EQ(va_conf_parse_keys(longl, k, VA_MAX_DEVICES, collect, &log), 0);
    ASSERT(log.n == 1 && log.why[0] == VA_CE_LONG_LINE);
}

/* The helper logs through logf_(); no call names a PIN, a key, or the
 * secret buffers. A text scan, because the PIN reaches only two places
 * in main.c, both D-Bus replies. */
static void test_helper_never_logs_a_secret(void) {
    char *s = slurp("src/va/main.c");
    ASSERT(s != NULL);
    if (!s) return;
    int calls = 0;
    for (char *p = strstr(s, "logf_("); p; p = strstr(p + 1, "logf_(")) {
        char *end = strstr(p, ");");
        if (!end) break;
        char call[600];
        size_t n = (size_t)(end - p) < sizeof(call) - 1 ? (size_t)(end - p) : sizeof(call) - 1;
        memcpy(call, p, n);
        call[n] = '\0';
        calls++;
        if (strstr(call, "pin") || strstr(call, ".key") || strstr(call, "key[")) {
            fprintf(stderr, "    logs a secret: %s\n", call);
            ASSERT(0);
        }
    }
    ASSERT_GT(calls, 10);
    /* Never the default agent; refuses a world-readable secret. */
    ASSERT(strstr(s, "\"RequestDefaultAgent\"") == NULL);
    ASSERT(strstr(s, "S_IROTH") != NULL);
    /* Discovery is active scanning; the helper must not start it. */
    ASSERT(strstr(s, "\"StartDiscovery\"") == NULL);
    free(s);
}

/* ── the record ── */

static void test_record_jsonl(void) {
    va_value_t vals[2] = {
        { "voltage_v", "V", 13.2, 0, NULL },
        { "device_state", "", 3, 1, "bulk" },
    };
    va_record_t r;
    memset(&r, 0, sizeof(r));
    r.source = "readout";
    r.t = 1763200000;
    const uint8_t mac[6] = { 0xc7, 0xfe, 0x23, 0xb1, 0x1c, 0x5f };
    memcpy(r.mac, mac, 6);
    r.serial = "HQ2501YV9FU";
    r.label = "BMV \"712\"\n\xc3\xa9";       /* hostile: quote, newline, UTF-8 */
    r.has_model = 1;
    r.model_id = 0xA381;
    r.record_type = VA_REC_BATTERY_MONITOR;
    r.has_rssi = 1;
    r.rssi = -71;
    r.nvals = 2;
    r.vals = vals;
    char buf[1024];
    int n = va_record_jsonl(&r, buf, sizeof(buf));
    ASSERT(n > 0);
    ASSERT_STR(buf,
        "{\"type\":\"victron\",\"t\":1763200000,\"source\":\"readout\",\"mac\":\"c7:fe:23:b1:1c:5f\","
        "\"serial\":\"HQ2501YV9FU\",\"label\":\"BMV \\\"712\\\"\\u000a\\u00c3\\u00a9\","
        "\"model_id\":\"0xa381\",\"model\":\"BMV-712 Smart\",\"record\":\"battery_monitor\","
        "\"rssi\":-71,\"values\":{\"voltage_v\":13.200,\"device_state\":3,"
        "\"device_state_name\":\"bulk\"}}\n");
    ASSERT_EQ((size_t)n, strlen(buf));
    /* One newline, at the end. */
    ASSERT(strchr(buf, '\n') == buf + n - 1);
    /* Too small: nothing partial. */
    ASSERT_EQ(va_record_jsonl(&r, buf, 40), -1);
    ASSERT_EQ(buf[0], '\0');
    /* A GATT session record: no serial known, services listed. */
    memset(&r, 0, sizeof(r));
    r.source = "gatt";
    r.t = 5;
    r.record_type = -1;
    r.session = "no_supported_service";
    r.services = "306b0001-b081-4037-83dc-e59fcc3cdfd0";
    n = va_record_jsonl(&r, buf, sizeof(buf));
    ASSERT_STR(buf,
        "{\"type\":\"victron\",\"t\":5,\"source\":\"gatt\",\"mac\":\"00:00:00:00:00:00\","
        "\"serial\":null,\"session\":\"no_supported_service\","
        "\"services\":\"306b0001-b081-4037-83dc-e59fcc3cdfd0\",\"values\":{}}\n");
}

static void test_names_and_macs(void) {
    ASSERT(va_name_has_serial("BMV-712 HQ2501YV9FU", "HQ2501YV9FU"));
    ASSERT(va_name_has_serial("hq2501yv9fu", "HQ2501YV9FU"));
    ASSERT(va_name_has_serial("Orion HQ2515QP3RX (van)", "HQ2515QP3RX"));
    ASSERT(!va_name_has_serial("XHQ2501YV9FU", "HQ2501YV9FU"));
    ASSERT(!va_name_has_serial("HQ2501YV9FU1", "HQ2501YV9FU"));
    ASSERT(!va_name_has_serial("My battery", "HQ2501YV9FU"));
    ASSERT(!va_name_has_serial(NULL, "HQ2501YV9FU"));
    uint8_t m[6];
    char s[18];
    ASSERT(va_mac_parse("dev_C7_FE_23_B1_1C_5F", m) == 0);
    va_mac_str(m, s);
    ASSERT_STR(s, "c7:fe:23:b1:1c:5f");
    ASSERT(va_mac_parse("C7:FE:23:B1:1C:5F", m) == 0 && m[5] == 0x5f);
    ASSERT(va_mac_parse("C7:FE:23:B1:1C", m) == -1);
    ASSERT(va_mac_parse("C7:FE:23:B1:1C:5F:00", m) == -1);
    ASSERT(va_mac_parse("G7:FE:23:B1:1C:5F", m) == -1);
}

/* ── boundaries ── */

/* sloth transmits nothing: src/va/ is named only by the helper's own
 * lists and the test build's, and nothing in src/ names its symbols.
 * (slothweb, which transmits nothing either, is sloth-mesh's since
 * #235, and so is the check that it never includes the helper.) */
static void test_helper_is_not_linked_into_sloth(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    int named = 0, ok = 1, prev_test_only = 0;
    for (char *l = mk; l && *l; ) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        if (strstr(l, "src/va/") && l[0] != '#') {
            named++;
            int allowed = !strncmp(l, "VA_SRCS", 7) || !strncmp(l, "VA_HDRS", 7) ||
                          (prev_test_only && (l[0] == ' ' || l[0] == '\t'));
            if (!allowed) {
                fprintf(stderr, "    Makefile names src/va/ elsewhere: %s\n", l);
                ok = 0;
            }
        }
        /* The continuation lines of TEST_ONLY_SRCS stay allowed. */
        if (!strncmp(l, "TEST_ONLY_SRCS", 14)) prev_test_only = 1;
        else if (!(prev_test_only && (l[0] == ' ' || l[0] == '\t'))) prev_test_only = 0;
        l = nl ? nl + 1 : NULL;
    }
    ASSERT(ok);
    ASSERT_GE(named, 3);
    free(mk);
    static const char *const dirs[] = { "src" };
    for (size_t di = 0; di < sizeof(dirs) / sizeof(dirs[0]); di++) {
        DIR *d = opendir(dirs[di]);
        ASSERT(d != NULL);
        if (!d) continue;
        struct dirent *e;
        int clean = 1, seen = 0;
        while ((e = readdir(d))) {
            size_t n = strlen(e->d_name);
            if (n < 3 || (strcmp(e->d_name + n - 2, ".c") && strcmp(e->d_name + n - 2, ".h"))) continue;
            char path[300];
            snprintf(path, sizeof(path), "%s/%s", dirs[di], e->d_name);
            char *s = slurp(path);
            if (!s) continue;
            seen++;
            if (strstr(s, "va/va_") || strstr(s, "sd-bus.h")) {
                fprintf(stderr, "    %s names sloth-va or sd-bus\n", path);
                clean = 0;
            }
            free(s);
        }
        closedir(d);
        ASSERT(clean);
        ASSERT_GT(seen, 10);
    }
}

/* The unit: its own account, no capability, D-Bus only, the secrets as
 * credentials, installed but never enabled by make. */
static void test_unit(void) {
    char *svc = slurp("packaging/systemd/sloth-va.service");
    char *mk = slurp("Makefile");
    ASSERT(svc && mk);
    if (!svc || !mk) { free(svc); free(mk); return; }
    ASSERT(strstr(svc, "\nUser=sloth-va\n") != NULL);
    ASSERT(strstr(svc, "\nDynamicUser") == NULL);
    ASSERT(strstr(svc, "\nCapabilityBoundingSet=\n") != NULL);
    ASSERT(strstr(svc, "\nAmbientCapabilities=\n") != NULL);
    ASSERT(strstr(svc, "\nNoNewPrivileges=true\n") != NULL);
    ASSERT(strstr(svc, "\nRestrictAddressFamilies=AF_UNIX\n") != NULL);
    ASSERT(strstr(svc, "AF_BLUETOOTH") == NULL);
    ASSERT(strstr(svc, "\nLoadCredential=victron-va.conf:/etc/sloth/victron-va.conf\n") != NULL);
    ASSERT(strstr(svc, "\nLoadCredential=victron.keys:/etc/sloth/victron.keys\n") != NULL);
    ASSERT(strstr(svc, "\nStateDirectory=sloth-va\n") != NULL);
    ASSERT(strstr(svc, "\nRequires=bluetooth.service\n") != NULL);
    ASSERT(strstr(svc, "\nExecStart=/usr/local/sbin/sloth-va\n") != NULL);
    ASSERT(strstr(mk, "packaging/systemd/sloth-va.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sloth-va.conf") != NULL);
    ASSERT(strstr(mk, "enable --now sloth-va") != NULL);    /* only in an @echo */
    ASSERT(strstr(mk, "\tsystemctl enable") == NULL);
    free(svc); free(mk);
}

void run_va_tests(void) {
    TEST_SUITE("sloth-va (Victron reader helper, pure half)");
    RUN_TEST(test_aes_fips197_c1);
    RUN_TEST(test_aes_ctr_sp800_38a);
    RUN_TEST(test_bits);
    RUN_TEST(test_published_battery_monitor);
    RUN_TEST(test_published_dcdc);
    RUN_TEST(test_hand_built_battery_monitor);
    RUN_TEST(test_hand_built_dcdc);
    RUN_TEST(test_hand_built_inverter);
    RUN_TEST(test_inverter_na_and_short);
    RUN_TEST(test_unknown_record_type);
    RUN_TEST(test_wrong_key_refused);
    RUN_TEST(test_not_product_ad_and_truncated);
    RUN_TEST(test_truncated_fields_absent);
    RUN_TEST(test_soc_out_of_range_absent);
    RUN_TEST(test_gatt_values);
    RUN_TEST(test_conf_devices);
    RUN_TEST(test_diag_never_carries_the_line);
    RUN_TEST(test_conf_keys);
    RUN_TEST(test_helper_never_logs_a_secret);
    RUN_TEST(test_record_jsonl);
    RUN_TEST(test_names_and_macs);
    RUN_TEST(test_helper_is_not_linked_into_sloth);
    RUN_TEST(test_unit);
}
