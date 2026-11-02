#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>   /* not <poll.h>: -Isrc puts src/poll.h first */
#include <sys/socket.h>
#include <time.h>

#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "alerts.h"
#include "gps.h"
#include "capture/gps_reader.h"
#include "jsonl.h"
#include "position_track.h"
#include "sloth_clock.h"
#include "tune.h"
#include "tui.h"
#include "views/alerts.h"

/* --location / --gps (2026-10-27).
 *
 * Every NMEA sentence here is hand-built per NMEA 0183 as gpsd documents
 * it (https://gpsd.gitlab.io/gpsd/NMEA.html). The three "$GP..." spec
 * examples carry their published checksums (*47, *6A, *39); the rest were
 * checksummed by hand as the XOR of the bytes between '$' and '*'. The
 * gpsd objects follow https://gpsd.gitlab.io/gpsd/gpsd_json.html. No
 * capture, no device. */

#define S(lit) lit, sizeof(lit) - 1

static const char GGA_SPEC[] =
    "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
static const char RMC_SPEC[] =
    "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A";
static const char GSA_SPEC[] =
    "$GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39";

/* ── checksum ──────────────────────────────────────────────── */

static void test_nmea_checksum_spec_examples(void) {
    ASSERT_EQ(nmea_checksum_ok(S(GGA_SPEC)), 1);
    ASSERT_EQ(nmea_checksum_ok(S(RMC_SPEC)), 1);
    ASSERT_EQ(nmea_checksum_ok(S(GSA_SPEC)), 1);
    /* A trailing CRLF is the line end, not part of the sum. */
    ASSERT_EQ(nmea_checksum_ok(S("$GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39\r\n")), 1);
    /* Lower-case hex digits are accepted. */
    ASSERT_EQ(nmea_checksum_ok(S("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6a")), 1);
}

static void test_nmea_checksum_refusals(void) {
    /* One digit off, one payload byte off, no '*', no '$', non-hex. */
    ASSERT_EQ(nmea_checksum_ok(S("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48")), 0);
    ASSERT_EQ(nmea_checksum_ok(S("$GPGGA,123519,4807.039,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47")), 0);
    ASSERT_EQ(nmea_checksum_ok(S("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,47")), 0);
    ASSERT_EQ(nmea_checksum_ok(S("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47")), 0);
    ASSERT_EQ(nmea_checksum_ok(S("$GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*3G")), 0);
    ASSERT_EQ(nmea_checksum_ok(S("$*00")), 0);
    ASSERT_EQ(nmea_checksum_ok(NULL, 0), 0);
}

/* ── GGA / RMC / GSA ───────────────────────────────────────── */

static void test_nmea_gga_spec_example(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    ASSERT_EQ(f.valid_lat_lon, 1);
    /* 48 deg 07.038' N, 11 deg 31.000' E */
    ASSERT_NEAR(f.lat, 48.0 + 7.038 / 60.0, 1e-9);
    ASSERT_NEAR(f.lon, 11.0 + 31.0 / 60.0, 1e-9);
    ASSERT_EQ(f.quality, 1);
    ASSERT_EQ(f.sats, 8);
    ASSERT_EQ(f.has_hdop, 1);
    ASSERT_NEAR(f.hdop, 0.9, 1e-9);
    ASSERT_EQ(f.has_alt, 1);
    ASSERT_NEAR(f.alt_m, 545.4, 1e-9);
    ASSERT_EQ(f.utc_hms, 123519L);
    ASSERT_EQ(nmea_fix_usable(&f), 1);
    ASSERT_NEAR(nmea_acc_m(f.hdop), 4.5, 1e-9);
}

static void test_nmea_rmc_spec_example(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(RMC_SPEC), &f), 1);
    ASSERT_EQ(f.rmc_status, 'A');
    ASSERT_NEAR(f.lat, 48.1173, 1e-9);
    ASSERT_NEAR(f.lon, 11.0 + 31.0 / 60.0, 1e-9);
    ASSERT_EQ(f.utc_dmy, 230394L);
    ASSERT_EQ(f.quality, -1);              /* no GGA seen */
    ASSERT_EQ(nmea_fix_usable(&f), 1);     /* status A stands in */
}

static void test_nmea_gsa_spec_example(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(GSA_SPEC), &f), 1);
    ASSERT_EQ(f.gsa_mode, 3);
    ASSERT_NEAR(f.hdop, 1.3, 1e-9);
    ASSERT_EQ(f.valid_lat_lon, 0);         /* GSA carries no position */
    ASSERT_EQ(nmea_fix_usable(&f), 0);
}

/* GN (multi-constellation) talker, four decimal-minute digits, W. */
static void test_nmea_gn_talker_and_west(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S("$GNGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*68\r\n"), &f), 1);
    ASSERT_NEAR(f.lat, 53.0 + 21.6802 / 60.0, 1e-9);
    ASSERT_NEAR(f.lon, -(6.0 + 30.3372 / 60.0), 1e-9);
    ASSERT_EQ(f.utc_hms, 92750L);
    ASSERT_EQ(nmea_fix_usable(&f), 1);
}

/* Quality 6 (dead reckoning) and 8 (simulation) parse but never fix;
 * quality 2 (DGPS) does, with a negative altitude. */
static void test_nmea_quality_gates_the_fix(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,3345.678,S,07012.345,W,6,05,1.2,10.0,M,0.0,M,,*4E"), &f), 1);
    ASSERT_EQ(f.quality, 6);
    ASSERT_EQ(f.valid_lat_lon, 1);
    ASSERT_EQ(nmea_fix_usable(&f), 0);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,3345.678,S,07012.345,W,8,05,1.2,10.0,M,0.0,M,,*40"), &f), 1);
    ASSERT_EQ(nmea_fix_usable(&f), 0);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,3345.678,S,07012.345,W,2,05,1.2,-12.5,M,0.0,M,,*60"), &f), 1);
    ASSERT_EQ(nmea_fix_usable(&f), 1);
    ASSERT_NEAR(f.lat, -(33.0 + 45.678 / 60.0), 1e-9);
    ASSERT_NEAR(f.lon, -(70.0 + 12.345 / 60.0), 1e-9);
    ASSERT_NEAR(f.alt_m, -12.5, 1e-9);
}

/* A receiver saying "no fix" clears the position it said before. Seen
 * red with each of the three clears removed from nmea_parse() in turn
 * (GGA quality 0, RMC status V, GSA mode 1): valid_lat_lon stays 1. */
static void test_nmea_no_fix_sentences_clear_the_position(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,,,,,0,00,,,M,,M,,*6B"), &f), 1);
    ASSERT_EQ(f.quality, 0);
    ASSERT_EQ(f.valid_lat_lon, 0);
    ASSERT_EQ(nmea_fix_usable(&f), 0);

    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(RMC_SPEC), &f), 1);
    ASSERT_EQ(nmea_parse(S("$GPRMC,123519,V,,,,,,,230394,,*33"), &f), 1);
    ASSERT_EQ(f.rmc_status, 'V');
    ASSERT_EQ(f.valid_lat_lon, 0);

    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(RMC_SPEC), &f), 1);
    ASSERT_EQ(nmea_parse(S("$GPGSA,A,1,,,,,,,,,,,,,,,*1E"), &f), 1);
    ASSERT_EQ(f.gsa_mode, 1);
    ASSERT_EQ(f.valid_lat_lon, 0);
}

/* A malformed sentence returns -1 and changes nothing already merged.
 * Seen red with `*f = t;` inserted ahead of the GGA coordinate parse
 * (the quality, satellites and HDOP of the bad line are kept). */
static void test_nmea_malformed_changes_nothing(void) {
    nmea_fix_t f, before;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    before = f;
    /* Bad checksum. */
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48"), &f), -1);
    /* Minutes 67 and latitude 91 degrees, both correctly checksummed,
     * with a time, quality, satellite count and HDOP of their own that
     * a partial merge would leave behind. */
    ASSERT_EQ(nmea_parse(S("$GPGGA,123520,4867.038,N,01131.000,E,2,09,1.0,545.4,M,46.9,M,,*41"), &f), -1);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123520,9100.000,N,01131.000,E,2,09,1.0,545.4,M,46.9,M,,*4F"), &f), -1);
    ASSERT_EQ(memcmp(&f, &before, sizeof(f)), 0);
    ASSERT_NEAR(f.lat, 48.1173, 1e-9);
}

/* 82 bytes "$" to CRLF is the spec's ceiling; one more is refused before
 * the checksum is even looked at. */
static void test_nmea_length_ceiling(void) {
    char line[128];
    nmea_fix_t f;
    nmea_fix_init(&f);
    /* A GSV padded with a long field: build to exactly 83 bytes with CRLF. */
    const char *body = "GPXXX,";
    size_t pad = 83 - 2 /* CRLF */ - 1 /* $ */ - 3 /* *hh */ - strlen(body);
    char payload[100];
    snprintf(payload, sizeof(payload), "%s", body);
    memset(payload + strlen(body), 'A', pad);
    payload[strlen(body) + pad] = '\0';
    unsigned x = 0;
    for (const char *p = payload; *p; p++) x ^= (unsigned char)*p;
    snprintf(line, sizeof(line), "$%s*%02X\r\n", payload, x);
    ASSERT_EQ(strlen(line), 83u);
    ASSERT_EQ(nmea_checksum_ok(line, strlen(line)), 1);
    ASSERT_EQ(nmea_parse(line, strlen(line), &f), -1);
    /* One byte shorter is a well-formed sentence of an unknown type. */
    payload[strlen(payload) - 1] = '\0';
    x = 0;
    for (const char *p = payload; *p; p++) x ^= (unsigned char)*p;
    snprintf(line, sizeof(line), "$%s*%02X\r\n", payload, x);
    ASSERT_EQ(strlen(line), 82u);
    ASSERT_EQ(nmea_parse(line, strlen(line), &f), 0);
}

static void test_nmea_other_sentences_ignored(void) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S("$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74"), &f), 0);
    ASSERT_EQ(f.quality, -1);
    ASSERT_EQ(nmea_parse(S(""), &f), -1);
    ASSERT_EQ(nmea_parse(NULL, 0, &f), -1);
}

/* ── gpsd JSON ─────────────────────────────────────────────── */

static void test_gpsd_tpv_3d(void) {
    gpsd_msg_t m;
    static const char tpv[] =
        "{\"class\":\"TPV\",\"device\":\"/dev/ttyACM0\",\"mode\":3,"
        "\"time\":\"2026-10-27T12:00:00.000Z\",\"ept\":0.005,"
        "\"lat\":51.500740,\"lon\":-0.124690,\"altHAE\":57.3,"
        "\"altMSL\":11.6,\"epx\":3.0,\"epy\":4.0,\"eph\":6.2,"
        "\"track\":12.5,\"speed\":0.1}";
    ASSERT_EQ(gpsd_json_parse(S(tpv), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_TPV);
    ASSERT_EQ(m.mode, 3);
    ASSERT_NEAR(m.lat, 51.50074, 1e-9);
    ASSERT_NEAR(m.lon, -0.12469, 1e-9);
    ASSERT_EQ(m.has_alt, 1);
    ASSERT_NEAR(m.alt_m, 11.6, 1e-9);      /* MSL preferred over HAE */
    ASSERT_NEAR(m.eph, 6.2, 1e-9);
    ASSERT_STR(m.time, "2026-10-27T12:00:00.000Z");
}

/* Key order is gpsd's business; altHAE stands in without altMSL; an
 * exponent and surrounding whitespace parse. */
static void test_gpsd_tpv_reordered(void) {
    gpsd_msg_t m;
    static const char tpv[] =
        "  { \"lon\" : 1.5e1 , \"mode\" : 2, \"lat\":-3.25E0,"
        "\"altHAE\":100.0,\"class\":\"TPV\" }\r\n";
    ASSERT_EQ(gpsd_json_parse(S(tpv), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_TPV);
    ASSERT_EQ(m.mode, 2);
    ASSERT_NEAR(m.lon, 15.0, 1e-9);
    ASSERT_NEAR(m.lat, -3.25, 1e-9);
    ASSERT_NEAR(m.alt_m, 100.0, 1e-9);
}

/* SKY's satellites array is nested objects; a bracket inside a string
 * must not end the skip. */
static void test_gpsd_sky_skips_nested(void) {
    gpsd_msg_t m;
    static const char sky[] =
        "{\"class\":\"SKY\",\"device\":\"/dev/x]}\",\"hdop\":0.8,"
        "\"satellites\":[{\"PRN\":5,\"used\":true,\"el\":45},"
        "{\"PRN\":7,\"used\":false,\"x\":[1,{\"y\":\"}]\"}]}],"
        "\"nSat\":12,\"uSat\":9}";
    ASSERT_EQ(gpsd_json_parse(S(sky), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_SKY);
    ASSERT_EQ(m.has_usat, 1);
    ASSERT_EQ(m.usat, 9);
    ASSERT_NEAR(m.hdop, 0.8, 1e-9);
}

static void test_gpsd_other_and_malformed(void) {
    gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"VERSION\",\"release\":\"3.25\",\"proto_major\":3}"), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_VERSION);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"WATCH\",\"enable\":true,\"json\":true}"), &m), 0);
    ASSERT_EQ(gpsd_json_parse(S("{}"), &m), 0);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3"), &m), -1);   /* unbalanced */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\"} x"), &m), -1);           /* trailing */
    ASSERT_EQ(gpsd_json_parse(S("[\"TPV\"]"), &m), -1);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":TPV}"), &m), -1);
    ASSERT_EQ(gpsd_json_parse(S("{\"lat\":-}"), &m), -1);
    ASSERT_EQ(gpsd_json_parse(S(""), &m), -1);
}

/* ── --gps SPEC ────────────────────────────────────────────── */

static void test_gps_spec_serial_and_gpsd(void) {
    gps_spec_t sp;
    char err[160], lab[64];
    ASSERT_EQ(gps_spec_parse("/dev/ttyUSB0", &sp, err, sizeof(err)), 0);
    ASSERT_EQ(sp.kind, GPS_SPEC_SERIAL);
    ASSERT_EQ(gps_spec_is_remote(&sp), 0);
    gps_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "nmea:/dev/ttyUSB0");

    ASSERT_EQ(gps_spec_parse("gpsd://", &sp, err, sizeof(err)), 0);
    ASSERT_EQ(sp.kind, GPS_SPEC_GPSD);
    ASSERT_STR(sp.host, "127.0.0.1");
    ASSERT_EQ(sp.port, 2947);
    ASSERT_EQ(gps_spec_is_remote(&sp), 0);
    gps_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "gpsd:127.0.0.1:2947");

    ASSERT_EQ(gps_spec_parse("gpsd://127.0.0.2:3000", &sp, err, sizeof(err)), 0);
    ASSERT_EQ(sp.port, 3000);
    ASSERT_EQ(gps_spec_is_remote(&sp), 0);

    ASSERT_EQ(gps_spec_parse("gpsd://[::1]:2948", &sp, err, sizeof(err)), 0);
    ASSERT_STR(sp.host, "::1");
    ASSERT_EQ(gps_spec_is_remote(&sp), 0);
    gps_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "gpsd:[::1]:2948");

    ASSERT_EQ(gps_spec_parse("gpsd://192.0.2.7", &sp, err, sizeof(err)), 0);
    ASSERT_EQ(gps_spec_is_remote(&sp), 1);
    ASSERT_EQ(gps_spec_parse("gpsd://[2001:db8::1]", &sp, err, sizeof(err)), 0);
    ASSERT_EQ(gps_spec_is_remote(&sp), 1);
}

/* gpsd has no Unix data socket, so there is no path form; a host name
 * would need a resolver; a port outside 1..65535 is a typo. */
static void test_gps_spec_refusals(void) {
    gps_spec_t sp;
    char err[160];
    ASSERT_EQ(gps_spec_parse("gpsd:///run/gpsd.sock", &sp, err, sizeof(err)), -1);
    ASSERT(strstr(err, "numeric") != NULL);
    ASSERT_EQ(gps_spec_parse("gpsd://localhost", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("gpsd://127.0.0.1:0", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("gpsd://127.0.0.1:65536", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("gpsd://127.0.0.1:", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("gpsd://[::1", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("tcp:127.0.0.1:2947", &sp, err, sizeof(err)), -1);
    ASSERT(strstr(err, "Unix") != NULL);
    ASSERT_EQ(gps_spec_parse("ttyUSB0", &sp, err, sizeof(err)), -1);
    ASSERT_EQ(gps_spec_parse("", &sp, err, sizeof(err)), -1);
}

/* ── --location ────────────────────────────────────────────── */

static void test_location_parse_fixed(void) {
    char err[160];
    loc_stamp_t l;
    ASSERT_EQ(gps_location_parse_fixed("51.50074,-0.12469,12", err, sizeof(err)), 0);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_FIXED);
    ASSERT_NEAR(l.lat, 51.50074, 1e-9);
    ASSERT_NEAR(l.lon, -0.12469, 1e-9);
    ASSERT_EQ(l.has_alt, 1);
    ASSERT_NEAR(l.alt_m, 12.0, 1e-9);
    ASSERT_EQ(l.has_acc, 0);
    ASSERT_EQ((long long)l.ts, 1800000000LL);
    ASSERT_EQ(gps_location_parse_fixed("-90,180", err, sizeof(err)), 0);
    ASSERT_EQ(gps_location_current(&l, 1), LOC_SRC_FIXED);
    ASSERT_EQ(l.has_alt, 0);
}

static void test_location_parse_refusals(void) {
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("91,0", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("0,180.5", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("0,0,30000", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("1", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("1,2,3,4", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("a,b", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("51,5,", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("1e1,2", err, sizeof(err)), -1);
    ASSERT_EQ(gps_location_parse_fixed("", err, sizeof(err)), -1);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1), LOC_SRC_NONE);
}

/* ── arbitration ───────────────────────────────────────────── */

static nmea_fix_t feed_gga(time_t wall) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    nmea_parse(S(GGA_SPEC), &f);
    gps_location_feed_nmea(&f, wall);
    return f;
}

static void test_nothing_configured_stamps_nothing(void) {
    loc_stamp_t l;
    memset(&l, 0x5a, sizeof(l));
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_NONE);
    ASSERT_EQ(l.src, LOC_SRC_NONE);
    ASSERT_EQ(l.lat, 0.0);   /* zeroed, not left as it was */
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.configured, 0);
    ASSERT_EQ(s.gps.state, GPS_NONE);
}

/* A fresh fix wins over --location; the stamp carries the fix's own
 * time and the HDOP x 5 m accuracy estimate. */
static void test_gps_fix_wins_over_fixed(void) {
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    feed_gga(1800000000);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000005), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 48.1173, 1e-9);
    ASSERT_EQ(l.has_acc, 1);
    ASSERT_NEAR(l.acc_m, 4.5, 1e-9);
    ASSERT_EQ((long long)l.ts, 1800000000LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000005);
    ASSERT_EQ(s.gps.state, GPS_FIX);
    ASSERT_EQ(s.gps.sats, 8);
    ASSERT_EQ(s.gps.fix_age_s, 5);
    ASSERT_STR(s.gps.src, "nmea:/dev/ttyUSB0");
}

/* The age guard, both sides of gps.max_fix_age_s (30 by default): at
 * the limit the fix stamps, one second past it it does not, and the
 * fixed position stands in. */
static void test_fix_age_boundary_falls_back_to_fixed(void) {
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    feed_gga(1800000000);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000030), LOC_SRC_GPS);
    ASSERT_EQ(gps_location_current(&l, 1800000031), LOC_SRC_FIXED);
    ASSERT_NEAR(l.lat, 10.0, 1e-9);
    ASSERT_EQ((long long)l.ts, 1800000031LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000031);
    ASSERT_EQ(s.gps.state, GPS_STALE);
    ASSERT_EQ(s.gps.fix_age_s, 31);
}

/* The owner's rule: a fix older than gps.max_fix_age_s stamps NOTHING
 * when there is no --location. Seen red with fix_fresh()'s age guard
 * inverted (`age > max`): the stale fix is stamped as GPS. */
static void test_stale_fix_without_fixed_stamps_nothing(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    feed_gga(1800000000);
    ASSERT_EQ(tune_set("gps.max_fix_age_s=10", NULL, 0), 0);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000010), LOC_SRC_GPS);
    ASSERT_EQ(gps_location_current(&l, 1800000011), LOC_SRC_NONE);
    ASSERT_EQ(l.src, LOC_SRC_NONE);
    ASSERT_EQ(l.lat, 0.0);
    /* The raw fix is still there for the sampler and the tests. */
    ASSERT_EQ(gps_location_last_fix(&l), 1);
    ASSERT_NEAR(l.lat, 48.1173, 1e-9);
}

/* A receiver that says "no fix" stops stamping at once, not after
 * gps.max_fix_age_s. Seen red with the fix_live clear in
 * gps_location_feed_nmea() removed. */
static void test_receiver_no_fix_stops_stamping(void) {
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    nmea_fix_t f = feed_gga(1800000000);
    ASSERT_EQ(nmea_parse(S("$GPGGA,123519,,,,,0,00,,,M,,M,,*6B"), &f), 1);
    gps_location_feed_nmea(&f, 1800000001);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000001), LOC_SRC_NONE);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000001);
    ASSERT_EQ(s.gps.state, GPS_SEARCHING);
    ASSERT_EQ(s.gps.quality, 0);
}

/* The startup line names what is dialled. Seen red with the gpsd branch
 * of gps_spec_announce() printing "" in place of the parsed label, which
 * is what main.c's old `gps_arg + 7` printed for a bare "gpsd://"
 * ("connecting to gpsd at  over TCP"). */
static void test_gps_announce_names_what_it_dials(void) {
    gps_spec_t sp;
    char out[400];
    ASSERT_EQ(gps_spec_parse("gpsd://", &sp, NULL, 0), 0);
    gps_spec_announce(&sp, out, sizeof(out));
    ASSERT(strstr(out, "gpsd at 127.0.0.1:2947 over TCP") != NULL);
    ASSERT_EQ(gps_spec_parse("gpsd://[::1]:3000", &sp, NULL, 0), 0);
    gps_spec_announce(&sp, out, sizeof(out));
    ASSERT(strstr(out, "gpsd at [::1]:3000 over TCP") != NULL);
    ASSERT_EQ(gps_spec_parse("/dev/ttyUSB0", &sp, NULL, 0), 0);
    gps_spec_announce(&sp, out, sizeof(out));
    ASSERT(strstr(out, "NMEA 0183 from /dev/ttyUSB0 (receive-only") != NULL);
}

/* A GSA carries no position, so it must not renew an older GGA's one.
 * One GGA, then a 3D GSA every second past gps.max_fix_age_s: the GGA's
 * position ages out and nothing stamps. Seen red with the pos_new test
 * in gps_location_feed_nmea() removed (take_fix on every usable merge):
 * the ten-minute-old position came back as a fresh GPS fix aged 0. */
static void test_gsa_does_not_restamp_an_old_position(void) {
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    nmea_fix_t f = feed_gga(1800000000);
    for (time_t t = 1800000001; t <= 1800000600; t++) {
        ASSERT_EQ(nmea_parse(S(GSA_SPEC), &f), 1);
        gps_location_feed_nmea(&f, t);
    }
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000600), LOC_SRC_NONE);
    ASSERT_EQ(gps_location_last_fix(&l), 1);
    ASSERT_EQ((long long)l.ts, 1800000000LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000600);
    ASSERT_EQ(s.gps.fix_age_s, 600);
    ASSERT_EQ(s.gps.state, GPS_STALE);
    /* A new GGA (with a position) still stamps at its own receipt. */
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    gps_location_feed_nmea(&f, 1800000601);
    ASSERT_EQ(gps_location_current(&l, 1800000601), LOC_SRC_GPS);
    ASSERT_EQ((long long)l.ts, 1800000601LL);
}

/* Before any sentence, gps_quality is -1 ("none yet"), not GGA's 0
 * ("no fix"). Seen red with g_loc's `.quality = -1` initialiser and the
 * reset's re-arm both removed: the poll reported 0. */
static void test_quality_is_minus_one_before_any_sentence(void) {
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.quality, -1);
    feed_gga(1800000000);
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.quality, 1);
}

/* gpsd: a 2D TPV stamps without altitude; mode 1 does not stamp; eph
 * is the accuracy, and SKY supplies satellites and HDOP. */
static void test_gpsd_feed(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"hdop\":1.1,\"uSat\":7}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":1,\"lat\":1.0,\"lon\":2.0}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_NONE);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,"
                                "\"lon\":2.5,\"altMSL\":40,\"epx\":3,\"epy\":4}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000001);
    ASSERT_EQ(gps_location_current(&l, 1800000001), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 1.5, 1e-9);
    ASSERT_EQ(l.has_alt, 0);               /* 2D */
    ASSERT_NEAR(l.acc_m, 5.0, 1e-9);       /* hypot(epx, epy) */
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000001);
    ASSERT_EQ(s.gps.sats, 7);
    ASSERT_NEAR(s.gps.hdop, 1.1, 1e-9);
    ASSERT_EQ(s.gps.quality, 2);
}

/* ── the reader's reconnect counter ────────────────────────── */

static int loopback_listener(int *port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &al) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint64_t reconnects_now(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    return s.gps.reconnects;
}

/* gps_reconnects counts sessions lost after opening, not failed
 * attempts: a gpsd that was never reachable reads 0 (and says why in
 * gps_err), one that accepted and then hung up reads 1. The first half
 * seen red with gps_location_note(0, 0, 0, 1) restored on the failed
 * connect in gps_reader_thread(): it read 1 before any session existed.
 * Loopback only; the "gpsd" is this test's own listener. */
static void test_reconnects_count_lost_sessions_only(void) {
    char err[160], spec[64];
    int port = 0;
    int lfd = loopback_listener(&port);
    ASSERT(lfd >= 0);
    close(lfd);                       /* nothing listens on port now */
    snprintf(spec, sizeof(spec), "gpsd://127.0.0.1:%d", port);
    ASSERT_EQ(gps_reader_configure(spec, 0, 0, err, sizeof(err)), 0);
    gps_reader_run();
    nap_ms(400);
    gps_reader_stop();
    ASSERT_EQ(reconnects_now(), 0u);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT(strstr(s.gps.err, "connect") != NULL);

    lfd = loopback_listener(&port);
    ASSERT(lfd >= 0);
    snprintf(spec, sizeof(spec), "gpsd://127.0.0.1:%d", port);
    ASSERT_EQ(gps_reader_configure(spec, 0, 0, err, sizeof(err)), 0);
    gps_reader_run();
    struct pollfd pfd = { lfd, POLLIN, 0 };
    ASSERT_EQ(poll(&pfd, 1, 5000), 1);
    int c = accept(lfd, NULL, NULL);
    ASSERT(c >= 0);
    char watch[64];
    struct pollfd cp = { c, POLLIN, 0 };
    if (poll(&cp, 1, 5000) == 1) (void)!read(c, watch, sizeof(watch));
    close(c);                         /* the session is lost */
    uint64_t r = 0;
    for (int i = 0; i < 100 && (r = reconnects_now()) == 0; i++) nap_ms(50);
    gps_reader_stop();
    close(lfd);
    ASSERT_EQ(r, 1u);
}

/* ── line framing and counters ─────────────────────────────── */

static void test_lines_feed_counts(void) {
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    static gps_lines_t L;
    gps_lines_init(&L, GPS_FEED_NMEA);
    char buf[512];
    snprintf(buf, sizeof(buf), "%s\r\n%s\r\n%s\r\n\r\n",
             RMC_SPEC,
             "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48",
             GGA_SPEC);
    /* Split mid-sentence: framing must not depend on read boundaries. */
    size_t n = strlen(buf);
    gps_lines_feed(&L, (const uint8_t *)buf, 17, 1800000000);
    gps_lines_feed(&L, (const uint8_t *)buf + 17, n - 17, 1800000000);
    /* An overlong line is one parse error, then framing recovers. */
    char longl[200];
    memset(longl, 'X', sizeof(longl));
    gps_lines_feed(&L, (const uint8_t *)longl, sizeof(longl), 1800000000);
    gps_lines_feed(&L, (const uint8_t *)"\n", 1, 1800000000);
    gps_lines_feed(&L, (const uint8_t *)"$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74\n",
                   strlen("$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74\n"),
                   1800000000);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.sentences, 3u);        /* RMC, GGA, GSV */
    ASSERT_EQ(s.gps.bad_checksum, 1u);
    ASSERT_EQ(s.gps.parse_errors, 1u);
    ASSERT_EQ(s.gps.state, GPS_FIX);
}

static void test_lines_feed_gpsd(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    static gps_lines_t L;
    gps_lines_init(&L, GPS_FEED_GPSD);
    static const char stream[] =
        "{\"class\":\"VERSION\",\"release\":\"3.25\"}\n"
        "{\"class\":\"DEVICES\",\"devices\":[{\"path\":\"/dev/ttyACM0\"}]}\n"
        "{\"class\":\"TPV\",\"mode\":3,\"lat\":-33.9,\"lon\":151.2,\"eph\":8.5,\"altMSL\":20}\n"
        "not json\n";
    gps_lines_feed(&L, (const uint8_t *)stream, sizeof(stream) - 1, 1800000000);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.sentences, 3u);
    ASSERT_EQ(s.gps.parse_errors, 1u);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.acc_m, 8.5, 1e-9);
    ASSERT_NEAR(l.alt_m, 20.0, 1e-9);
}

/* ── formatting ────────────────────────────────────────────── */

static void test_fmt_fixed(void) {
    char b[32];
    gps_fmt_fixed(b, sizeof(b), -0.12469, 7);
    ASSERT_STR(b, "-0.1246900");
    gps_fmt_fixed(b, sizeof(b), 51.50074, 7);
    ASSERT_STR(b, "51.5007400");
    gps_fmt_fixed(b, sizeof(b), 4.55, 1);
    ASSERT_STR(b, "4.6");
    gps_fmt_fixed(b, sizeof(b), -0.00000001, 7);
    ASSERT_STR(b, "0.0000000");                /* no "-0" */
    gps_fmt_fixed(b, sizeof(b), 12.0, 0);
    ASSERT_STR(b, "12");
}

static void test_loc_json(void) {
    loc_stamp_t l;
    memset(&l, 0, sizeof(l));
    l.src = LOC_SRC_GPS;
    l.lat = 51.50074; l.lon = -0.12469;
    l.has_alt = 1; l.alt_m = 11.6;
    l.has_acc = 1; l.acc_m = 4.5;
    l.ts = 1800000000;
    char b[256];
    ASSERT(gps_loc_json(&l, b, sizeof(b)) > 0);
    ASSERT_STR(b, "\"loc\":{\"lat\":51.5007400,\"lon\":-0.1246900,"
                  "\"alt_m\":11.6,\"acc_m\":4.5,\"src\":\"gps\",\"ts\":1800000000}");
    l.src = LOC_SRC_FIXED;
    l.has_alt = 0; l.has_acc = 0;
    ASSERT(gps_loc_json(&l, b, sizeof(b)) > 0);
    ASSERT_STR(b, "\"loc\":{\"lat\":51.5007400,\"lon\":-0.1246900,"
                  "\"src\":\"fixed\",\"ts\":1800000000}");
    char t[160];
    gps_loc_text(&l, 1800000000, t, sizeof(t));
    ASSERT_STR(t, "51.5007400, -0.1246900  (fixed)");
}

/* An unstamped alert writes no `loc` at all. Seen red with gps_loc_json()'s
 * LOC_SRC_NONE return removed (a "loc" with src "" is written). */
static void test_loc_json_absent_when_unstamped(void) {
    loc_stamp_t l;
    memset(&l, 0, sizeof(l));
    char b[256] = "junk";
    ASSERT_EQ(gps_loc_json(&l, b, sizeof(b)), 0);
    ASSERT_STR(b, "");
    ASSERT_EQ(gps_loc_json(NULL, b, sizeof(b)), 0);
    char t[64] = "junk";
    gps_loc_text(&l, 0, t, sizeof(t));
    ASSERT_STR(t, "");
}

static void test_distance(void) {
    /* One arc-minute of latitude on the mean sphere: 1853.25 m. */
    ASSERT_NEAR(gps_distance_m(48.0, 11.0, 48.0 + 1.0 / 60.0, 11.0), 1853.25, 0.5);
    ASSERT_NEAR(gps_distance_m(0, 0, 0, 0), 0.0, 1e-9);
    /* Antipodes: half the circumference. */
    ASSERT_NEAR(gps_distance_m(0, 0, 0, 180), 3.14159265358979 * 6371008.8, 1.0);
}

/* ── the engine stamps a new incident ──────────────────────── */

static char g_jl[TEST_TMP_MAX];

static char *read_all(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_gps_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jl);
    ASSERT(jsonl_open(g_jl));
}

static time_t g_wall;

static int scan_alert(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (!strcmp(s->alerts[i].key, "scan:192.0.2.9")) return i;
    return -1;
}
static time_t gw_wall(void) { return g_wall; }
static uint64_t gw_mono(void) { return (uint64_t)g_wall * 1000u; }

/* The stamp is taken where the incident opens, and both JSONL records
 * of that opening carry it. */
static void test_engine_stamps_new_incident(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(gw_mono, gw_wall);
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("51.50074,-0.12469", err, sizeof(err)), 0);
    jl_open();
    alerts_clear();
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN,
                         "scan:192.0.2.9", "d", "192.0.2.9", 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    alerts_update(&s);
    int k = scan_alert(&s);
    ASSERT(k >= 0);
    if (k < 0) return;
    ASSERT_EQ(s.alerts[k].loc.src, LOC_SRC_FIXED);
    ASSERT_NEAR(s.alerts[k].loc.lat, 51.50074, 1e-9);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        const char *want = "\"loc\":{\"lat\":51.5007400,\"lon\":-0.1246900,"
                           "\"src\":\"fixed\",\"ts\":1800000000}";
        const char *a1 = strstr(b, "\"type\":\"alert\"");
        const char *a2 = strstr(b, "\"type\":\"alert.create\"");
        ASSERT(a1 != NULL);
        ASSERT(a2 != NULL);
        const char *l1 = strstr(b, want);
        ASSERT(l1 != NULL);
        if (l1) ASSERT(strstr(l1 + 1, want) != NULL);   /* on both */
    }
    unlink(g_jl);
    alerts_clear();
    sloth_clock_test_set(NULL, NULL);
}

/* Without --location or a fresh fix nothing is stamped and no record
 * carries `loc`. Seen red with the gps_location_current() in fire_inv()
 * replaced by an unconditional LOC_SRC_FIXED stamp at 0,0. */
static void test_engine_unstamped_without_location(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(gw_mono, gw_wall);
    jl_open();
    alerts_clear();
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN,
                         "scan:192.0.2.9", "d", "192.0.2.9", 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    alerts_update(&s);
    int k = scan_alert(&s);
    ASSERT(k >= 0);
    if (k < 0) return;
    ASSERT_EQ(s.alerts[k].loc.src, LOC_SRC_NONE);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"type\":\"alert.create\"") != NULL);
        ASSERT(strstr(b, "\"loc\"") == NULL);
    }
    unlink(g_jl);
    alerts_clear();
    sloth_clock_test_set(NULL, NULL);
}

/* The stamp is where the finding was MADE: a fix arriving later does not
 * move an open incident's stamp. Seen red with a second
 * gps_location_current() added to fire_inv()'s re-evaluation branch. */
static void test_engine_stamp_not_refreshed_on_reevaluation(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(gw_mono, gw_wall);
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    alerts_clear();
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN,
                         "scan:192.0.2.9", "d", "192.0.2.9", 0);
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    g_wall += 5;
    feed_gga(g_wall);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN,
                         "scan:192.0.2.9", "d2", "192.0.2.9", 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    alerts_update(&s);
    int k = scan_alert(&s);
    ASSERT(k >= 0);
    if (k < 0) return;
    ASSERT_EQ(s.alerts[k].loc.src, LOC_SRC_FIXED);
    ASSERT_NEAR(s.alerts[k].loc.lat, 10.0, 1e-9);
    alerts_clear();
    sloth_clock_test_set(NULL, NULL);
}

/* ── sensor_health ─────────────────────────────────────────── */

/* The gps block is written only while --location or --gps is given, so
 * a run with neither writes what it wrote before. Seen red with the
 * `if (s->gps.configured)` guard removed (gps_state appears). */
static void test_sensor_health_gps_block_only_when_configured(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(gw_mono, gw_wall);
    jl_open();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"type\":\"sensor_health\"") != NULL);
        ASSERT(strstr(b, "\"gps_") == NULL);
    }
    unlink(g_jl);

    jl_open();
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    feed_gga(g_wall);
    gps_location_note(5, 1, 0, 0);
    gps_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"gps_state\":\"fix\"") != NULL);
        ASSERT(strstr(b, "\"gps_src\":\"nmea:/dev/ttyUSB0\"") != NULL);
        ASSERT(strstr(b, "\"gps_sats\":8") != NULL);
        ASSERT(strstr(b, "\"gps_hdop\":0.9") != NULL);
        ASSERT(strstr(b, "\"gps_fix_age_s\":0") != NULL);
        ASSERT(strstr(b, "\"gps_sentences\":5") != NULL);
        ASSERT(strstr(b, "\"gps_bad_checksum\":1") != NULL);
        ASSERT(strstr(b, "\"gps_err\":\"\"") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

static int count_type(const char *b, const char *type) {
    int n = 0;
    for (const char *p = b; (p = strstr(p, type)) != NULL; p++) n++;
    return n;
}

/* The fix's age enters the change-only signature as its bucket: ten
 * seconds of a ticking age inside gps.max_fix_age_s write nothing, the
 * crossing to stale writes one line. Seen red with the raw fix_age_s
 * signed instead of the bucket (every tick writes a line). */
static void test_sensor_health_fix_age_is_bucketed(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(gw_mono, gw_wall);
    jl_open();
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    feed_gga(g_wall);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);                     /* 1: first line */
    for (int i = 0; i < 10; i++) {
        g_wall += 1;
        gps_health_poll(&s, g_wall);
        jsonl_emit_sensor_health(&s);                 /* suppressed */
    }
    g_wall += 25;                                     /* age 35 > 30 */
    gps_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);                     /* 2: fix -> stale */
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_type(b, "\"type\":\"sensor_health\""), 2);
        ASSERT(strstr(b, "\"gps_state\":\"stale\"") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* ── per-device position samples ───────────────────────────── */

static void add_dev(sloth_state_t *s, uint8_t last, time_t seen, int8_t dbm) {
    device_t *d = &s->devices[s->device_count++];
    memset(d, 0, sizeof(*d));
    uint8_t mac[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, last };
    memcpy(d->mac, mac, 6);
    d->last_seen = seen;
    d->signal_dbm = dbm;
}

/* Feed a GPS fix at lat (lon fixed) through gpsd's TPV path. */
static void fix_at(double lat, time_t wall) {
    gpsd_msg_t m;
    memset(&m, 0, sizeof(m));
    m.cls = GPSD_CLS_TPV;
    m.mode = 2;
    m.has_lat = m.has_lon = 1;
    m.lat = lat;
    m.lon = 11.0;
    gps_location_feed_gpsd(&m, wall);
}

/* One metre of latitude, in degrees, on the sphere gps_distance_m uses. */
#define DEG_PER_M (1.0 / 111195.08)

/* The sampling rule: first sight samples; a 4 m move at rest does not;
 * a 6 m move does; gps.sample_s at rest does. Seen red with due()'s
 * distance test turned to `>= 0` (the 4 m move samples). */
static void test_postrack_samples_on_move_or_interval(void) {
    postrack_set_sink(1);
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t t = 1800000000;
    add_dev(&s, 1, t, -60);
    fix_at(48.0, t);
    postrack_tick(&s, t);
    static postrack_sample_t out[16];
    static postrack_sensor_t so[16];
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
    ASSERT_STR(out[0].mac, "02:00:5e:00:53:01");
    ASSERT_EQ(out[0].rssi, -60);
    ASSERT_NEAR(out[0].lat, 48.0, 1e-9);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 1);

    t += 1;
    s.devices[0].last_seen = t;
    fix_at(48.0 + 4 * DEG_PER_M, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 0);

    t += 1;
    s.devices[0].last_seen = t;
    fix_at(48.0 + 6 * DEG_PER_M, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 1);

    t += 60;                                         /* gps.sample_s */
    s.devices[0].last_seen = t;
    fix_at(48.0 + 6 * DEG_PER_M, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
}

/* No series from a fixed sensor, from a stale fix, from a device not
 * heard lately, or with no consumer attached. Each seen red on its own
 * guard: the LOC_SRC_GPS check (a --location samples), the last_seen
 * window (the silent device samples), the g_sink check. */
static void test_postrack_samples_nothing_without_a_moving_fix(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t t = 1800000000;
    static postrack_sample_t out[16];
    char err[160];

    postrack_set_sink(1);
    ASSERT_EQ(gps_location_parse_fixed("48,11", err, sizeof(err)), 0);
    add_dev(&s, 1, t, -50);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    gps_location_set_gps("gpsd:127.0.0.1:2947");
    fix_at(48.0, t - 100);                           /* stale */
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    fix_at(48.0, t);
    s.devices[0].last_seen = t - 10;                 /* not heard lately */
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    s.devices[0].last_seen = t;
    postrack_set_sink(0);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    postrack_set_sink(1);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
}

/* A queue nobody drains keeps its newest POSTRACK_QUEUE samples and
 * counts what it dropped. */
static void test_postrack_queue_drops_oldest_and_counts(void) {
    postrack_set_sink(1);
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t t = 1800000000;
    for (int i = 0; i < 200; i++) add_dev(&s, (uint8_t)i, t, -70);
    for (int k = 0; k < 11; k++) {
        t += 60;
        for (int i = 0; i < s.device_count; i++) s.devices[i].last_seen = t;
        fix_at(48.0, t);
        postrack_tick(&s, t);
    }
    /* 2200 samples into 2048 slots. */
    ASSERT_EQ(postrack_dropped(), 2200u - POSTRACK_QUEUE);
    static postrack_sample_t out[POSTRACK_QUEUE + 8];
    ASSERT_EQ(postrack_drain_devices(out, POSTRACK_QUEUE + 8), POSTRACK_QUEUE);
    ASSERT_EQ((long long)out[POSTRACK_QUEUE - 1].ts, (long long)t);
}

/* ── TUI ───────────────────────────────────────────────────── */

/* The alert detail's Location line: the stamp as gps_loc_text() writes
 * it, and an unstamped incident saying so when a source is configured.
 * Without either flag the line is absent. Seen red with the
 * `a->loc.src != LOC_SRC_NONE || s->gps.configured` guard turned to `1`
 * (the line appears with neither flag). */
static void test_view_detail_location_line(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    alert_t *a = &s.alerts[0];
    a->sev = ALERT_SEV_WARN;
    snprintf(a->title, sizeof(a->title), "located");
    a->first_seen = a->first_detected = (time_t)1700000000;
    a->last_seen = a->first_seen + 10;
    a->count = 1;
    a->loc.src = LOC_SRC_GPS;
    a->loc.lat = 51.50074; a->loc.lon = -0.12469;
    a->loc.has_acc = 1; a->loc.acc_m = 4.5;
    a->loc.has_alt = 1; a->loc.alt_m = 12.0;
    a->loc.ts = a->first_detected - 3;
    s.alert_count = 1;
    s.alert_sel = 0;
    s.alert_detail = 1;
    static char buf[16384];
    tui_test_erase();
    view_alerts_draw(&s);
    tui_test_screen(buf, sizeof(buf));
    ASSERT(strstr(buf, "Location:   51.5007400, -0.1246900  +/-5 m  alt 12 m  "
                       "(gps, fix 3 s before)") != NULL);

    memset(&a->loc, 0, sizeof(a->loc));
    tui_test_erase();
    view_alerts_draw(&s);
    tui_test_screen(buf, sizeof(buf));
    ASSERT(strstr(buf, "Location:") == NULL);

    s.gps.configured = 1;
    tui_test_erase();
    view_alerts_draw(&s);
    tui_test_screen(buf, sizeof(buf));
    ASSERT(strstr(buf, "Location:   (not stamped") != NULL);
}

/* The health strip's gps token: present whenever a source is
 * configured, absent otherwise (a default run's strip is unchanged). */
static void test_health_strip_gps_token(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char buf[512];
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "gps") == NULL);
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    feed_gga(1800000000);
    gps_health_poll(&s, 1800000002);
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  gps fix 8sat") != NULL);
    gps_health_poll(&s, 1800000100);
    gps_location_set_err("read: Input/output error");
    gps_health_poll(&s, 1800000100);
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  gps stale 100s (using --location) err read: Input/output error") != NULL);
}

void run_gps_tests(void) {
    TEST_SUITE("gps: NMEA 0183");
    RUN_TEST(test_nmea_checksum_spec_examples);
    RUN_TEST(test_nmea_checksum_refusals);
    RUN_TEST(test_nmea_gga_spec_example);
    RUN_TEST(test_nmea_rmc_spec_example);
    RUN_TEST(test_nmea_gsa_spec_example);
    RUN_TEST(test_nmea_gn_talker_and_west);
    RUN_TEST(test_nmea_quality_gates_the_fix);
    RUN_TEST(test_nmea_no_fix_sentences_clear_the_position);
    RUN_TEST(test_nmea_malformed_changes_nothing);
    RUN_TEST(test_nmea_length_ceiling);
    RUN_TEST(test_nmea_other_sentences_ignored);
    TEST_SUITE("gps: gpsd JSON");
    RUN_TEST(test_gpsd_tpv_3d);
    RUN_TEST(test_gpsd_tpv_reordered);
    RUN_TEST(test_gpsd_sky_skips_nested);
    RUN_TEST(test_gpsd_other_and_malformed);
    TEST_SUITE("gps: --gps SPEC and --location");
    RUN_TEST(test_gps_spec_serial_and_gpsd);
    RUN_TEST(test_gps_spec_refusals);
    RUN_TEST(test_location_parse_fixed);
    RUN_TEST(test_location_parse_refusals);
    TEST_SUITE("gps: arbitration");
    RUN_TEST(test_nothing_configured_stamps_nothing);
    RUN_TEST(test_gps_fix_wins_over_fixed);
    RUN_TEST(test_fix_age_boundary_falls_back_to_fixed);
    RUN_TEST(test_stale_fix_without_fixed_stamps_nothing);
    RUN_TEST(test_receiver_no_fix_stops_stamping);
    RUN_TEST(test_gps_announce_names_what_it_dials);
    RUN_TEST(test_gsa_does_not_restamp_an_old_position);
    RUN_TEST(test_quality_is_minus_one_before_any_sentence);
    RUN_TEST(test_gpsd_feed);
    RUN_TEST(test_reconnects_count_lost_sessions_only);
    RUN_TEST(test_lines_feed_counts);
    RUN_TEST(test_lines_feed_gpsd);
    TEST_SUITE("gps: formatting");
    RUN_TEST(test_fmt_fixed);
    RUN_TEST(test_loc_json);
    RUN_TEST(test_loc_json_absent_when_unstamped);
    RUN_TEST(test_distance);
    TEST_SUITE("gps: alert stamp and sensor_health");
    RUN_TEST(test_engine_stamps_new_incident);
    RUN_TEST(test_engine_unstamped_without_location);
    RUN_TEST(test_engine_stamp_not_refreshed_on_reevaluation);
    RUN_TEST(test_sensor_health_gps_block_only_when_configured);
    RUN_TEST(test_sensor_health_fix_age_is_bucketed);
    TEST_SUITE("gps: device position samples");
    RUN_TEST(test_postrack_samples_on_move_or_interval);
    RUN_TEST(test_postrack_samples_nothing_without_a_moving_fix);
    RUN_TEST(test_postrack_queue_drops_oldest_and_counts);
    TEST_SUITE("gps: TUI");
    RUN_TEST(test_view_detail_location_line);
    RUN_TEST(test_health_strip_gps_token);
}
