#include <string.h>
#include "runner.h"
#include "reg_ie.h"
#include "beacon_snoop.h"

/*
 * Regulatory information elements — issue #101 slice 1.
 *
 * Three elements, all built here from the clause text rather than from a
 * capture (agents/AGENTS.md "no pcap fixtures"): the parser is proved
 * against the specification, and a hand-built blob reaches the
 * truncated and adversarial lengths a capture cannot.
 *
 * Country element, tag 7 — IEEE 802.11-2020 §9.4.2.8:
 *   Country String(3)   octets 1-2 ISO 3166-1 alpha-2, octet 3 the
 *                       environment / operating-class-table selector
 *   then zero or more 3-octet triplets:
 *     Subband Triplet    First Channel(1) Num Channels(1)
 *                        Max TX Power(1, signed dBm)
 *     Operating Triplet  Operating Extension Identifier(1, >= 201)
 *                        Operating Class(1) Coverage Class(1)
 *   optionally one zero Pad octet (802.11-2007 §7.3.2.9) so the element
 *   length stays even.
 *
 * Power Constraint element, tag 32 — §9.4.2.13:
 *   Local Power Constraint(1), unsigned dB below the regulatory maximum
 *
 * TPC Report element, tag 35 — §9.4.2.16:
 *   Transmit Power(1, signed dBm)  Link Margin(1, signed dB)
 */

/* ── blob builders ───────────────────────────────────────── */

static int put_ie(uint8_t *b, int off, uint8_t tag,
                  const uint8_t *body, int len) {
    b[off++] = tag;
    b[off++] = (uint8_t)len;
    memcpy(b + off, body, (size_t)len);
    return off + len;
}

/* A Country element body: 2-letter code, environment octet, then the
 * caller's already-assembled triplet bytes. */
static int country_body(uint8_t *b, const char *cc, uint8_t env,
                        const uint8_t *triplets, int tlen) {
    b[0] = (uint8_t)cc[0];
    b[1] = (uint8_t)cc[1];
    b[2] = env;
    if (tlen) memcpy(b + 3, triplets, (size_t)tlen);
    return 3 + tlen;
}

/* ── Country element ─────────────────────────────────────── */

static void test_country_code_environment_and_subband_triplets(void) {
    /* US, all environments, the 2.4 GHz plan plus UNII-1. */
    const uint8_t trip[] = {
        1,  11, 20,        /* ch 1, 11 channels, 20 dBm */
        36, 4,  23,        /* ch 36, 4 channels, 23 dBm */
    };
    uint8_t body[64];
    int n = country_body(body, "US", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.country_present, 1);
    ASSERT_STR(r.country, "US");
    ASSERT_EQ((int)r.env, REG_ENV_ANY);
    ASSERT_EQ((int)r.env_raw, ' ');
    ASSERT_EQ((int)r.triplet_count, 2);
    ASSERT_EQ((int)r.triplets_truncated, 0);

    ASSERT_EQ((int)r.triplets[0].is_operating, 0);
    ASSERT_EQ((int)r.triplets[0].first_channel, 1);
    ASSERT_EQ((int)r.triplets[0].num_channels, 11);
    ASSERT_EQ((int)r.triplets[0].max_tx_power_dbm, 20);

    ASSERT_EQ((int)r.triplets[1].first_channel, 36);
    ASSERT_EQ((int)r.triplets[1].num_channels, 4);
    ASSERT_EQ((int)r.triplets[1].max_tx_power_dbm, 23);
    ASSERT_EQ((int)r.malformed_country, 0);
}

static void test_country_element_with_no_triplets_is_well_formed(void) {
    /* Boundary: the shortest legal body is the 3-octet country string. */
    uint8_t body[8];
    int n = country_body(body, "JP", 'I', NULL, 0);
    ASSERT_EQ(n, 3);

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.country_present, 1);
    ASSERT_STR(r.country, "JP");
    ASSERT_EQ((int)r.triplet_count, 0);
    ASSERT_EQ((int)r.malformed_country, 0);
}

static void test_operating_extension_identifier_marks_an_operating_triplet(void) {
    /* First octet >= 201 means the three octets are (ext id, operating
     * class, coverage class) — read as a subband triplet they would
     * claim "channel 201, 81 channels, 3 dBm", which is a plausible
     * enough lie to pass unnoticed. That is why this branch exists. */
    const uint8_t trip[] = {
        201, 81, 3,        /* operating triplet: global class 81, cov 3 */
    };
    uint8_t body[64];
    int n = country_body(body, "DE", 'O', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.triplet_count, 1);
    ASSERT_EQ((int)r.triplets[0].is_operating, 1);
    ASSERT_EQ((int)r.triplets[0].ext_id, 201);
    ASSERT_EQ((int)r.triplets[0].operating_class, 81);
    ASSERT_EQ((int)r.triplets[0].coverage_class, 3);
    /* The subband fields must stay zero — a caller that reads the wrong
     * union half gets an obvious 0, not a fabricated channel. */
    ASSERT_EQ((int)r.triplets[0].first_channel, 0);
    ASSERT_EQ((int)r.triplets[0].num_channels, 0);
    ASSERT_EQ((int)r.triplets[0].max_tx_power_dbm, 0);
}

static void test_triplet_kind_is_decided_per_triplet(void) {
    /* Mixed element: the boundary is 201, so 200 is still a subband
     * first-channel and 255 is still an operating extension id. */
    const uint8_t trip[] = {
        36,  4,  23,       /* subband   */
        200, 8,  17,       /* subband — 200 is below the boundary */
        201, 115, 0,       /* operating */
        255, 125, 9,       /* operating — top of the range */
    };
    uint8_t body[64];
    int n = country_body(body, "GB", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.triplet_count, 4);
    ASSERT_EQ((int)r.triplets[0].is_operating, 0);
    ASSERT_EQ((int)r.triplets[1].is_operating, 0);
    ASSERT_EQ((int)r.triplets[1].first_channel, 200);
    ASSERT_EQ((int)r.triplets[1].num_channels, 8);
    ASSERT_EQ((int)r.triplets[2].is_operating, 1);
    ASSERT_EQ((int)r.triplets[2].operating_class, 115);
    ASSERT_EQ((int)r.triplets[3].is_operating, 1);
    ASSERT_EQ((int)r.triplets[3].ext_id, 255);
    ASSERT_EQ((int)r.triplets[3].coverage_class, 9);
}

static void test_maximum_transmit_power_level_is_signed(void) {
    /* §9.4.2.8 makes Max TX Power a signed dBm value. Sub-1 mW caps are
     * real (6 GHz VLP, some indoor-only subbands), and reading the
     * octet unsigned turns -2 dBm into 254 dBm. */
    const uint8_t trip[] = { 149, 4, 0xfe };   /* -2 dBm */
    uint8_t body[64];
    int n = country_body(body, "US", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.triplets[0].max_tx_power_dbm, -2);
}

static void test_environment_octet_in_each_valid_form(void) {
    struct { uint8_t raw; int env; } cases[] = {
        { ' ',  REG_ENV_ANY },            /* all environments        */
        { 'I',  REG_ENV_INDOOR },
        { 'O',  REG_ENV_OUTDOOR },
        { 'X',  REG_ENV_NON_COUNTRY },    /* non-country entity      */
        { 0x04, REG_ENV_OPCLASS_TABLE },  /* Annex E table number 4  */
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t body[8];
        int n = country_body(body, "XX", cases[i].raw, NULL, 0);
        reg_ie_t r;
        reg_ie_reset(&r);
        ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
        ASSERT_EQ((int)r.env, cases[i].env);
        ASSERT_EQ((int)r.env_raw, (int)cases[i].raw);
    }
}

static void test_unrecognised_environment_octet_is_not_guessed(void) {
    /* 'Z' is none of the four ASCII forms and is not a plausible
     * operating-class table number. Reporting it as "any" would invent
     * a regulatory claim the AP never made. */
    uint8_t body[8];
    int n = country_body(body, "US", 'Z', NULL, 0);
    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.env, REG_ENV_UNKNOWN);
    ASSERT_EQ((int)r.env_raw, 'Z');
    ASSERT_EQ((int)r.country_present, 1);
}

static void test_country_element_shorter_than_three_octets_rejected(void) {
    const uint8_t body[3] = { 'U', 'S', ' ' };
    for (int len = 0; len < 3; len++) {
        reg_ie_t r;
        reg_ie_reset(&r);
        ASSERT_EQ(reg_ie_element(&r, 7, body, len), 0);
        ASSERT_EQ((int)r.country_present, 0);
        ASSERT_STR(r.country, "");
        ASSERT_EQ((int)r.env, REG_ENV_ABSENT);
        ASSERT_EQ((int)r.malformed_country, 1);
    }
}

static void test_trailing_pad_octet_is_accepted(void) {
    /* Two triplets make the element length 9 — odd — so a conforming
     * 802.11-2007 encoder appends one zero Pad octet. The leftover
     * octet is not a broken triplet. */
    const uint8_t trip[] = {
        1,  11, 20,
        36, 4,  23,
        0,                 /* Pad */
    };
    uint8_t body[64];
    int n = country_body(body, "US", ' ', trip, (int)sizeof(trip));
    ASSERT_EQ(n, 10);

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.triplet_count, 2);
    ASSERT_EQ((int)r.malformed_country, 0);
}

static void test_two_leftover_octets_do_not_match_the_triplet_structure(void) {
    /* One triplet plus two octets: no encoding produces this. The
     * triplet that did parse is kept — it was fully present — and the
     * element is flagged. */
    const uint8_t trip[] = { 1, 11, 20, 36, 4 };
    uint8_t body[64];
    int n = country_body(body, "US", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 0);
    ASSERT_EQ((int)r.country_present, 1);
    ASSERT_EQ((int)r.triplet_count, 1);
    ASSERT_EQ((int)r.triplets[0].first_channel, 1);
    ASSERT_EQ((int)r.malformed_country, 1);
}

static void test_declared_length_bounds_the_triplet_walk(void) {
    /* The body buffer holds a second triplet the declared length does
     * not cover. Reading it would report a UNII-1 subband the AP never
     * advertised, and off the end of a real frame would be an
     * over-read. The canary triplet must not appear. */
    const uint8_t trip[] = {
        1,  11, 20,        /* covered by the declared length */
        36, 4,  23,        /* canary — past it */
    };
    uint8_t body[64];
    (void)country_body(body, "US", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, 3 + 3), 1);
    ASSERT_EQ((int)r.triplet_count, 1);
    ASSERT_EQ((int)r.triplets[0].first_channel, 1);
    ASSERT_EQ((int)r.triplets[1].first_channel, 0);
}

static void test_triplet_overflow_is_bounded_and_reported(void) {
    /* A hostile Country element can claim up to 84 triplets. The store
     * is fixed, so the surplus is dropped and said to have been
     * dropped — a silently clipped list reads as a short list. */
    uint8_t trip[3 * (REG_MAX_COUNTRY_TRIPLETS + 4)];
    int total = REG_MAX_COUNTRY_TRIPLETS + 4;
    for (int i = 0; i < total; i++) {
        trip[i * 3 + 0] = (uint8_t)(1 + i);
        trip[i * 3 + 1] = 1;
        trip[i * 3 + 2] = 20;
    }
    uint8_t body[3 + sizeof(trip)];
    int n = country_body(body, "US", ' ', trip, (int)sizeof(trip));

    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 7, body, n), 1);
    ASSERT_EQ((int)r.triplet_count, REG_MAX_COUNTRY_TRIPLETS);
    ASSERT_EQ((int)r.triplets_truncated, 1);
    ASSERT_EQ((int)r.triplets[REG_MAX_COUNTRY_TRIPLETS - 1].first_channel,
              REG_MAX_COUNTRY_TRIPLETS);
}

/* ── Power Constraint element ────────────────────────────── */

static void test_power_constraint_is_one_octet_of_db(void) {
    const uint8_t body[1] = { 6 };
    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 32, body, 1), 1);
    ASSERT_EQ((int)r.power_constraint_present, 1);
    ASSERT_EQ((int)r.power_constraint_db, 6);
    ASSERT_EQ((int)r.malformed_power_constraint, 0);
}

static void test_power_constraint_full_range_is_unsigned(void) {
    /* The Local Power Constraint field is a reduction in dB, so it has
     * no negative form: 200 dB is absurd but it is not -56. */
    const uint8_t body[1] = { 200 };
    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 32, body, 1), 1);
    ASSERT_EQ((int)r.power_constraint_db, 200);
}

static void test_power_constraint_wrong_length_rejected(void) {
    const uint8_t body[4] = { 6, 7, 8, 9 };
    int lens[] = { 0, 2, 3 };
    for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        reg_ie_t r;
        reg_ie_reset(&r);
        ASSERT_EQ(reg_ie_element(&r, 32, body, lens[i]), 0);
        ASSERT_EQ((int)r.power_constraint_present, 0);
        ASSERT_EQ((int)r.power_constraint_db, 0);
        ASSERT_EQ((int)r.malformed_power_constraint, 1);
    }
}

/* ── TPC Report element ──────────────────────────────────── */

static void test_tpc_report_transmit_power_and_link_margin(void) {
    const uint8_t body[2] = { 17, 12 };
    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 35, body, 2), 1);
    ASSERT_EQ((int)r.tpc_present, 1);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, 17);
    ASSERT_EQ((int)r.tpc_link_margin_db, 12);
    ASSERT_EQ((int)r.malformed_tpc, 0);
}

static void test_tpc_report_fields_are_signed(void) {
    /* Both fields are signed in §9.4.2.16. A 6 GHz VLP radio reporting
     * -5 dBm and a margin of -3 dB is the case that separates a signed
     * read from an unsigned one: unsigned turns them into 251 and 253,
     * which is a stronger AP than any regulation allows. */
    const uint8_t body[2] = { 0xfb, 0xfd };   /* -5 dBm, -3 dB */
    reg_ie_t r;
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 35, body, 2), 1);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, -5);
    ASSERT_EQ((int)r.tpc_link_margin_db, -3);

    const uint8_t extreme[2] = { 0x80, 0x7f };   /* -128 dBm, +127 dB */
    reg_ie_reset(&r);
    ASSERT_EQ(reg_ie_element(&r, 35, extreme, 2), 1);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, -128);
    ASSERT_EQ((int)r.tpc_link_margin_db, 127);
}

static void test_tpc_report_wrong_length_rejected(void) {
    const uint8_t body[4] = { 0xfb, 0xfd, 1, 2 };
    int lens[] = { 0, 1, 3 };
    for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        reg_ie_t r;
        reg_ie_reset(&r);
        ASSERT_EQ(reg_ie_element(&r, 35, body, lens[i]), 0);
        ASSERT_EQ((int)r.tpc_present, 0);
        ASSERT_EQ((int)r.tpc_tx_power_dbm, 0);
        ASSERT_EQ((int)r.tpc_link_margin_db, 0);
        ASSERT_EQ((int)r.malformed_tpc, 1);
    }
}

static void test_non_regulatory_tags_are_not_claimed(void) {
    const uint8_t body[4] = { 1, 2, 3, 4 };
    uint8_t tags[] = { 0, 3, 11, 33, 34, 36, 37, 48, 221 };
    for (unsigned i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        reg_ie_t r;
        reg_ie_reset(&r);
        ASSERT_EQ(reg_ie_element(&r, tags[i], body, 4), 0);
        ASSERT_EQ((int)r.country_present, 0);
        ASSERT_EQ((int)r.power_constraint_present, 0);
        ASSERT_EQ((int)r.tpc_present, 0);
        ASSERT_EQ((int)r.malformed_country, 0);
        ASSERT_EQ((int)r.malformed_power_constraint, 0);
        ASSERT_EQ((int)r.malformed_tpc, 0);
    }
}

/* ── through the unified beacon_parse_ies seam ───────────── */

/* The blob nl80211 hands over and the blob the monitor path passes at
 * dot11+36 are the same thing, so this is the only seam the parser
 * needs (#66 / B3b). */
static int build_blob(uint8_t *b, int with_reg) {
    int off = 0;
    const uint8_t ssid[4] = { 'l', 'a', 'b', '1' };
    off = put_ie(b, off, 0, ssid, 4);
    const uint8_t ds[1] = { 36 };
    off = put_ie(b, off, 3, ds, 1);
    if (with_reg) {
        const uint8_t trip[] = { 36, 8, 23 };
        uint8_t cb[16];
        int cn = country_body(cb, "NL", 'I', trip, (int)sizeof(trip));
        off = put_ie(b, off, 7, cb, cn);
        const uint8_t pc[1] = { 3 };
        off = put_ie(b, off, 32, pc, 1);
        const uint8_t tpc[2] = { 0xf6, 0x00 };   /* -10 dBm, 0 dB */
        off = put_ie(b, off, 35, tpc, 2);
    }
    return off;
}

static void test_regulatory_elements_reach_the_unified_parser(void) {
    uint8_t ies[128];
    int n = build_blob(ies, 1);

    char ssid[33]; int ch = 0; char enc[10];
    reg_ie_t r;
    ASSERT_EQ(beacon_parse_ies(ies, n, 0, 0, ssid, &ch, enc, NULL, &r), 1);
    ASSERT_STR(ssid, "lab1");
    ASSERT_EQ(ch, 36);
    ASSERT_EQ((int)r.country_present, 1);
    ASSERT_STR(r.country, "NL");
    ASSERT_EQ((int)r.env, REG_ENV_INDOOR);
    ASSERT_EQ((int)r.triplet_count, 1);
    ASSERT_EQ((int)r.triplets[0].max_tx_power_dbm, 23);
    ASSERT_EQ((int)r.power_constraint_present, 1);
    ASSERT_EQ((int)r.power_constraint_db, 3);
    ASSERT_EQ((int)r.tpc_present, 1);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, -10);
    ASSERT_EQ((int)r.tpc_link_margin_db, 0);
}

static void test_absent_regulatory_elements_leave_the_struct_absent(void) {
    uint8_t ies[128];
    int n = build_blob(ies, 0);

    char ssid[33]; int ch = 0; char enc[10];
    reg_ie_t r;
    /* Pre-dirtied: the out-parameter must be zeroed on entry the way
     * rsn_out is, or "absent" reads as whatever the last AP said. */
    memset(&r, 0xa5, sizeof(r));
    ASSERT_EQ(beacon_parse_ies(ies, n, 0, 0, ssid, &ch, enc, NULL, &r), 1);
    ASSERT_EQ((int)r.country_present, 0);
    ASSERT_STR(r.country, "");
    ASSERT_EQ((int)r.env, REG_ENV_ABSENT);
    ASSERT_EQ((int)r.env_raw, 0);
    ASSERT_EQ((int)r.triplet_count, 0);
    ASSERT_EQ((int)r.power_constraint_present, 0);
    ASSERT_EQ((int)r.power_constraint_db, 0);
    ASSERT_EQ((int)r.tpc_present, 0);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, 0);
    ASSERT_EQ((int)r.tpc_link_margin_db, 0);
    ASSERT_EQ((int)r.malformed_country, 0);
    ASSERT_EQ((int)r.malformed_power_constraint, 0);
    ASSERT_EQ((int)r.malformed_tpc, 0);
}

static void test_the_out_parameter_is_optional(void) {
    /* Every pre-#101 caller passes NULL. Behaviour must be identical. */
    uint8_t ies[128];
    int n = build_blob(ies, 1);

    char ssid_a[33], ssid_b[33]; int ch_a = 0, ch_b = 0;
    char enc_a[10], enc_b[10];
    beacon_rsn_t rsn_a, rsn_b;
    reg_ie_t r;
    ASSERT_EQ(beacon_parse_ies(ies, n, 1, 100, ssid_a, &ch_a, enc_a,
                               &rsn_a, NULL), 1);
    ASSERT_EQ(beacon_parse_ies(ies, n, 1, 100, ssid_b, &ch_b, enc_b,
                               &rsn_b, &r), 1);
    ASSERT_STR(ssid_a, ssid_b);
    ASSERT_EQ(ch_a, ch_b);
    ASSERT_STR(enc_a, enc_b);
    /* The regulatory elements must not perturb the fingerprint the
     * existing detectors key on. */
    ASSERT_EQ(rsn_a.fp.ie_order_hash, rsn_b.fp.ie_order_hash);
    ASSERT_EQ((int)rsn_a.fp.ie_order_count, (int)rsn_b.fp.ie_order_count);
}

static void test_element_length_past_the_blob_end_is_not_read(void) {
    /* A Country element claiming 40 octets inside a blob that holds 6.
     * The existing walk already refuses to step past the end; this
     * pins that the regulatory parser inherits the refusal rather than
     * reading the six bytes as a short country string. */
    uint8_t ies[16];
    int off = 0;
    ies[off++] = 7;
    ies[off++] = 40;
    memcpy(ies + off, "US \x01\x0b\x14", 6);
    off += 6;

    char ssid[33]; int ch = 0; char enc[10];
    reg_ie_t r;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse_ies(ies, off, 0, 0, ssid, &ch, enc, &rsn, &r), 1);
    ASSERT_EQ((int)r.country_present, 0);
    ASSERT_EQ((int)r.triplet_count, 0);
    ASSERT_EQ(rsn.ie_overruns, 1);
}

static void test_zero_length_regulatory_elements_are_rejected(void) {
    /* tag/len with no body at all — legal IE framing, illegal for all
     * three of these elements. */
    uint8_t ies[16];
    int off = 0;
    ies[off++] = 7;  ies[off++] = 0;
    ies[off++] = 32; ies[off++] = 0;
    ies[off++] = 35; ies[off++] = 0;

    char ssid[33]; int ch = 0; char enc[10];
    reg_ie_t r;
    ASSERT_EQ(beacon_parse_ies(ies, off, 0, 0, ssid, &ch, enc, NULL, &r), 1);
    ASSERT_EQ((int)r.country_present, 0);
    ASSERT_EQ((int)r.power_constraint_present, 0);
    ASSERT_EQ((int)r.tpc_present, 0);
    ASSERT_EQ((int)r.malformed_country, 1);
    ASSERT_EQ((int)r.malformed_power_constraint, 1);
    ASSERT_EQ((int)r.malformed_tpc, 1);
}

static void test_repeated_elements_count_and_last_one_wins(void) {
    /* Two TPC Reports in one beacon is malformed-adjacent but parseable;
     * the counters are per-element so a repeat is visible. */
    uint8_t ies[32];
    int off = 0;
    const uint8_t t1[2] = { 20, 5 };
    const uint8_t t2[2] = { 0xf6, 0xfe };
    off = put_ie(ies, off, 35, t1, 2);
    off = put_ie(ies, off, 35, t2, 2);
    const uint8_t bad[3] = { 1, 2, 3 };
    off = put_ie(ies, off, 32, bad, 3);
    off = put_ie(ies, off, 32, bad, 3);

    char ssid[33]; int ch = 0; char enc[10];
    reg_ie_t r;
    ASSERT_EQ(beacon_parse_ies(ies, off, 0, 0, ssid, &ch, enc, NULL, &r), 1);
    ASSERT_EQ((int)r.tpc_present, 1);
    ASSERT_EQ((int)r.tpc_tx_power_dbm, -10);
    ASSERT_EQ((int)r.tpc_link_margin_db, -2);
    ASSERT_EQ(r.malformed_power_constraint, 2);
    ASSERT_EQ((int)r.power_constraint_present, 0);
}

void run_reg_ie_tests(void) {
    TEST_SUITE("Country element parse (#101, 802.11-2020 §9.4.2.8)");
    RUN_TEST(test_country_code_environment_and_subband_triplets);
    RUN_TEST(test_country_element_with_no_triplets_is_well_formed);
    RUN_TEST(test_operating_extension_identifier_marks_an_operating_triplet);
    RUN_TEST(test_triplet_kind_is_decided_per_triplet);
    RUN_TEST(test_maximum_transmit_power_level_is_signed);
    RUN_TEST(test_environment_octet_in_each_valid_form);
    RUN_TEST(test_unrecognised_environment_octet_is_not_guessed);
    RUN_TEST(test_country_element_shorter_than_three_octets_rejected);
    RUN_TEST(test_trailing_pad_octet_is_accepted);
    RUN_TEST(test_two_leftover_octets_do_not_match_the_triplet_structure);
    RUN_TEST(test_declared_length_bounds_the_triplet_walk);
    RUN_TEST(test_triplet_overflow_is_bounded_and_reported);

    TEST_SUITE("Power Constraint and TPC Report parse (#101, §9.4.2.13/16)");
    RUN_TEST(test_power_constraint_is_one_octet_of_db);
    RUN_TEST(test_power_constraint_full_range_is_unsigned);
    RUN_TEST(test_power_constraint_wrong_length_rejected);
    RUN_TEST(test_tpc_report_transmit_power_and_link_margin);
    RUN_TEST(test_tpc_report_fields_are_signed);
    RUN_TEST(test_tpc_report_wrong_length_rejected);
    RUN_TEST(test_non_regulatory_tags_are_not_claimed);

    TEST_SUITE("Regulatory elements through beacon_parse_ies (#101)");
    RUN_TEST(test_regulatory_elements_reach_the_unified_parser);
    RUN_TEST(test_absent_regulatory_elements_leave_the_struct_absent);
    RUN_TEST(test_the_out_parameter_is_optional);
    RUN_TEST(test_element_length_past_the_blob_end_is_not_read);
    RUN_TEST(test_zero_length_regulatory_elements_are_rejected);
    RUN_TEST(test_repeated_elements_count_and_last_one_wins);
}
