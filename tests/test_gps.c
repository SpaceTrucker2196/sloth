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
#include "poll.h"
#include "position_track.h"
#include "sensors.h"
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
 * red with each of the two clears removed from nmea_parse() in turn
 * (GGA quality 0, RMC status V): valid_lat_lon stays 1. A GSA mode 1
 * does not clear it: test_multi_gnss_gsa_mode1_keeps_the_fix. */
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
    ASSERT_EQ(f.valid_lat_lon, 1);
    ASSERT_EQ(nmea_fix_usable(&f), 1);   /* RMC A still says "fix" */
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
    /* 2026-11-02: the array is read now; the nested value inside the
     * second satellite is still skipped, and the line still balances. */
    ASSERT_EQ(m.nsats, 2);
    ASSERT_EQ(m.sats[0].prn, 5);
    ASSERT_EQ(m.sats[0].used, 1);
    ASSERT_EQ(m.sats[0].has_el, 1);
    ASSERT_EQ(m.sats[1].prn, 7);
    ASSERT_EQ(m.sats[1].used, 0);
    ASSERT_EQ(m.sats[1].has_el, 0);
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

/* A fix's age is monotonic (sloth_mono_ms at receipt), so every test
 * that ages one drives both clocks through the seam: wall g_wall, and
 * monotonic following it in step. */
static time_t g_wall;
static time_t gw_wall(void) { return g_wall; }
static uint64_t gw_mono(void) { return (uint64_t)g_wall * 1000u; }
static void clk(time_t w) {
    g_wall = w;
    sloth_clock_test_set(gw_mono, gw_wall);
}
static int cur_at(loc_stamp_t *l, time_t w) {
    clk(w);
    return gps_location_current(l, w);
}
static void poll_at(sloth_state_t *s, time_t w) {
    clk(w);
    gps_health_poll(s, w);
}

static nmea_fix_t feed_gga(time_t wall) {
    nmea_fix_t f;
    nmea_fix_init(&f);
    nmea_parse(S(GGA_SPEC), &f);
    clk(wall);
    gps_location_feed_nmea(&f, wall);
    return f;
}

static void test_nothing_configured_stamps_nothing(void) {
    loc_stamp_t l;
    memset(&l, 0x5a, sizeof(l));
    ASSERT_EQ(cur_at(&l, 1800000000), LOC_SRC_NONE);
    ASSERT_EQ(l.src, LOC_SRC_NONE);
    ASSERT_EQ(l.lat, 0.0);   /* zeroed, not left as it was */
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000000);
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
    ASSERT_EQ(cur_at(&l, 1800000005), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 48.1173, 1e-9);
    ASSERT_EQ(l.has_acc, 1);
    ASSERT_NEAR(l.acc_m, 4.5, 1e-9);
    ASSERT_EQ((long long)l.ts, 1800000000LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000005);
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
    ASSERT_EQ(cur_at(&l, 1800000030), LOC_SRC_GPS);
    ASSERT_EQ(cur_at(&l, 1800000031), LOC_SRC_FIXED);
    ASSERT_NEAR(l.lat, 10.0, 1e-9);
    ASSERT_EQ((long long)l.ts, 1800000031LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000031);
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
    ASSERT_EQ(cur_at(&l, 1800000010), LOC_SRC_GPS);
    ASSERT_EQ(cur_at(&l, 1800000011), LOC_SRC_NONE);
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
    ASSERT_EQ(cur_at(&l, 1800000001), LOC_SRC_NONE);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000001);
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
    ASSERT_EQ(cur_at(&l, 1800000600), LOC_SRC_NONE);
    ASSERT_EQ(gps_location_last_fix(&l), 1);
    ASSERT_EQ((long long)l.ts, 1800000000LL);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000600);
    ASSERT_EQ(s.gps.fix_age_s, 600);
    ASSERT_EQ(s.gps.state, GPS_STALE);
    /* A new GGA (with a position) still stamps at its own receipt. */
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    gps_location_feed_nmea(&f, 1800000601);
    ASSERT_EQ(cur_at(&l, 1800000601), LOC_SRC_GPS);
    ASSERT_EQ((long long)l.ts, 1800000601LL);
}

/* Before any sentence, gps_quality is -1 ("none yet"), not GGA's 0
 * ("no fix"). Seen red with g_loc's `.quality = -1` initialiser and the
 * reset's re-arm both removed: the poll reported 0. */
static void test_quality_is_minus_one_before_any_sentence(void) {
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000000);
    ASSERT_EQ(s.gps.quality, -1);
    feed_gga(1800000000);
    poll_at(&s, 1800000000);
    ASSERT_EQ(s.gps.quality, 1);
}

/* A multi-GNSS receiver (NMEA 4.10) sends one GSA per constellation
 * inside an epoch, the system ID in field 18: here GPS (1) at mode 3 and
 * GLONASS (2) at mode 1, contributing nothing, while the combined GN fix
 * is 3D. The fix holds through every sentence of two epochs. Seen red
 * with `if (mode == 1) t.valid_lat_lon = 0;` restored in nmea_parse()'s
 * GSA branch: the state flips to searching after each GLONASS GSA. */
static void test_multi_gnss_gsa_mode1_keeps_the_fix(void) {
    static const char *const epoch[] = {
        "$GNGGA,123519,4807.038,N,01131.000,E,1,14,0.8,545.4,M,46.9,M,,*55",
        "$GNRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*74",
        "$GNGSA,A,3,04,05,09,12,24,,,,,,,,1.6,0.8,1.4,1*36",
        "$GNGSA,A,1,,,,,,,,,,,,,,,,2*1E",
    };
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    nmea_fix_t f;
    nmea_fix_init(&f);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    loc_stamp_t l;
    for (time_t t = 1800000000; t < 1800000002; t++) {
        clk(t);
        for (size_t i = 0; i < sizeof(epoch) / sizeof(epoch[0]); i++) {
            ASSERT_EQ(nmea_parse(epoch[i], strlen(epoch[i]), &f), 1);
            gps_location_feed_nmea(&f, t);
            ASSERT_EQ(gps_location_current(&l, t), LOC_SRC_GPS);
            gps_health_poll(&s, t);
            ASSERT_EQ(s.gps.state, GPS_FIX);
        }
    }
    ASSERT_EQ(f.gsa_mode, 1);
    ASSERT_EQ(f.valid_lat_lon, 1);
}

/* gpsd's numbers may carry any exponent. Out-of-range or non-finite
 * accuracy and altitude are dropped from the fix, not recorded; a
 * non-finite or out-of-range position is not a fix at all. Each line
 * hand-built per gpsd_json.html's TPV/SKY. Seen red with take_fix()'s
 * acc_ok()/alt_ok() checks removed (acc_m inf, alt_m 1e300, acc_m -50
 * kept), with range_ok()'s isfinite() and bounds turned to `1` (the
 * 1e400 latitude stamps), and with SKY's hdop_ok() removed (hdop inf). */
static void test_gpsd_out_of_range_figures_are_dropped(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gpsd_msg_t m;
    loc_stamp_t l;
    clk(1800000000);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":51.5,"
                                "\"lon\":-0.1,\"altMSL\":1e300,\"eph\":1e400}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 51.5, 1e-9);
    ASSERT_EQ(l.has_acc, 0);
    ASSERT_EQ(l.has_alt, 0);
    char js[256];
    ASSERT(gps_loc_json(&l, js, sizeof(js)) > 0);
    ASSERT(strstr(js, "acc_m") == NULL);
    ASSERT(strstr(js, "alt_m") == NULL);

    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":51.6,"
                                "\"lon\":-0.1,\"altMSL\":-1001,\"eph\":-50}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 51.6, 1e-9);
    ASSERT_EQ(l.has_acc, 0);
    ASSERT_EQ(l.has_alt, 0);

    /* In range on both sides: kept. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":51.7,"
                                "\"lon\":-0.1,\"altMSL\":20000,\"eph\":1e5}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_EQ(l.has_acc, 1);
    ASSERT_NEAR(l.acc_m, 1e5, 1e-6);
    ASSERT_EQ(l.has_alt, 1);
    ASSERT_NEAR(l.alt_m, 20000.0, 1e-9);

    /* A non-finite or out-of-range position is ignored entirely: the
     * 51.7 fix stands. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":1e400,"
                                "\"lon\":-0.1}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":51.5,"
                                "\"lon\":-1e400}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":90.5,"
                                "\"lon\":-0.1}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 51.7, 1e-9);

    /* SKY: a non-finite or negative HDOP is not recorded, and so never
     * becomes a TPV's accuracy estimate. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"hdop\":1e400}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"hdop\":-2}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.hdop, 0.0);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":2,\"lat\":51.8,"
                                "\"lon\":-0.1}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 51.8, 1e-9);
    ASSERT_EQ(l.has_acc, 0);
}

/* NMEA's HDOP is digits, so never inf, but HDOP 99999 x 5 is past
 * 1e5 m and no accuracy, and a GGA altitude past 20000 m is none. Seen
 * red with feed_nmea's hdop_ok() turned to `1` and take_fix()'s checks
 * removed (acc_m 499995 and alt_m 30000 kept). */
static void test_nmea_out_of_range_figures_are_dropped(void) {
    static const char *const gga =
        "$GPGGA,123519,4807.038,N,01131.000,E,1,08,99999,30000.0,M,46.9,M,,*5A";
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(gga, strlen(gga), &f), 1);
    ASSERT_EQ(f.has_hdop, 1);
    clk(1800000000);
    gps_location_feed_nmea(&f, 1800000000);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, 1800000000), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 48.1173, 1e-9);
    ASSERT_EQ(l.has_acc, 0);
    ASSERT_EQ(l.has_alt, 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, 1800000000);
    ASSERT_EQ(s.gps.hdop, 0.0);
}

/* Freshness is monotonic. The fix arrives at wall 5000; the wall clock
 * then steps BACK to 1000 (NTP correcting a fake-hwclock Pi) while 31 s
 * pass on the monotonic clock: the fix is stale, and the stamp, while
 * it was fresh, reported its own wall receipt time. Seen red with
 * fix_fresh() testing `now - g_loc.fix.ts` against gps.max_fix_age_s
 * (the old wall rule): a negative age read as fresh and the 31 s old
 * fix stamped as GPS. */
static time_t g_bw_wall;
static uint64_t g_bw_mono;
static time_t bw_wall(void) { return g_bw_wall; }
static uint64_t bw_mono(void) { return g_bw_mono; }
static void test_fix_age_is_monotonic_across_a_wall_step_back(void) {
    g_bw_wall = 5000;
    g_bw_mono = 777000;
    sloth_clock_test_set(bw_mono, bw_wall);
    gps_location_set_gps("nmea:/dev/ttyUSB0");
    nmea_fix_t f;
    nmea_fix_init(&f);
    ASSERT_EQ(nmea_parse(S(GGA_SPEC), &f), 1);
    gps_location_feed_nmea(&f, g_bw_wall);
    loc_stamp_t l;
    g_bw_wall = 1000;                       /* the step back */
    g_bw_mono += 30000;
    ASSERT_EQ(gps_location_current(&l, g_bw_wall), LOC_SRC_GPS);
    ASSERT_EQ((long long)l.ts, 5000LL);     /* loc_ts: wall at receipt */
    g_bw_mono += 1000;                      /* 31 s on */
    ASSERT_EQ(gps_location_current(&l, g_bw_wall), LOC_SRC_NONE);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    gps_health_poll(&s, g_bw_wall);
    ASSERT_EQ(s.gps.state, GPS_STALE);
    ASSERT_EQ(s.gps.fix_age_s, 31);
    /* And a step FORWARD does not age a new fix. */
    gps_location_feed_nmea(&f, g_bw_wall);
    g_bw_wall += 3600;
    ASSERT_EQ(gps_location_current(&l, g_bw_wall), LOC_SRC_GPS);
    sloth_clock_test_set(NULL, NULL);
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
    ASSERT_EQ(cur_at(&l, 1800000000), LOC_SRC_NONE);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,"
                                "\"lon\":2.5,\"altMSL\":40,\"epx\":3,\"epy\":4}"), &m), 1);
    gps_location_feed_gpsd(&m, 1800000001);
    ASSERT_EQ(cur_at(&l, 1800000001), LOC_SRC_GPS);
    ASSERT_NEAR(l.lat, 1.5, 1e-9);
    ASSERT_EQ(l.has_alt, 0);               /* 2D */
    ASSERT_NEAR(l.acc_m, 5.0, 1e-9);       /* hypot(epx, epy) */
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1800000001);
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

/* A source that goes away ends the fix at once, not gps.max_fix_age_s
 * later: gpsd sends a 3D TPV, the fix stamps, gpsd hangs up, and by the
 * time the lost session is counted nothing stamps. Seen red with the
 * gps_location_source_lost() call removed from gps_reader_thread(): the
 * seconds-old fix kept stamping as GPS after the hang-up. Loopback only;
 * the "gpsd" is this test's own listener. Real clocks: the reader thread
 * runs, so the seam is not swapped. */
static void test_reader_eof_ends_the_fix(void) {
    char err[160], spec[64];
    int port = 0;
    int lfd = loopback_listener(&port);
    ASSERT(lfd >= 0);
    if (lfd < 0) return;
    snprintf(spec, sizeof(spec), "gpsd://127.0.0.1:%d", port);
    ASSERT_EQ(gps_reader_configure(spec, 0, 0, err, sizeof(err)), 0);
    gps_reader_run();
    struct pollfd pfd = { lfd, POLLIN, 0 };
    ASSERT_EQ(poll(&pfd, 1, 5000), 1);
    int c = accept(lfd, NULL, NULL);
    ASSERT(c >= 0);
    static const char tpv[] =
        "{\"class\":\"TPV\",\"mode\":3,\"lat\":51.5,\"lon\":-0.1,\"eph\":8}\n";
    ASSERT_EQ(write(c, tpv, sizeof(tpv) - 1), (ssize_t)(sizeof(tpv) - 1));
    loc_stamp_t l;
    int src = LOC_SRC_NONE;
    for (int i = 0; i < 100; i++) {
        if ((src = gps_location_current(&l, time(NULL))) == LOC_SRC_GPS) break;
        nap_ms(50);
    }
    ASSERT_EQ(src, LOC_SRC_GPS);
    close(c);                         /* gpsd goes away */
    uint64_t r = 0;
    for (int i = 0; i < 100 && (r = reconnects_now()) == 0; i++) nap_ms(50);
    ASSERT_EQ(r, 1u);
    ASSERT_EQ(gps_location_current(&l, time(NULL)), LOC_SRC_NONE);
    gps_reader_stop();
    close(lfd);
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

static int scan_alert(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (!strcmp(s->alerts[i].key, "scan:192.0.2.9")) return i;
    return -1;
}

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
    clk(wall);
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
    clk(t);
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
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 0);

    t += 1;
    s.devices[0].last_seen = t;
    fix_at(48.0 + 6 * DEG_PER_M, t);
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 1);

    /* At rest, gps.sample_s on: the sensor's own track samples; the
     * device, unchanged in band, waits (test_postrack_at_rest_...). */
    t += 60;                                         /* gps.sample_s */
    s.devices[0].last_seen = t;
    fix_at(48.0 + 6 * DEG_PER_M, t);
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    ASSERT_EQ(postrack_drain_sensor(so, 16), 1);
}

/* A parked sensor: the device's row is not restated every gps.sample_s.
 * At rest a sample is written when the device's RSSI 10 dB band changes
 * (no sooner than gps.sample_s), or at gps.sample_s x 10. Seen red with
 * device_due() replaced by the sensor's due() (the old rule: a row every
 * gps.sample_s, so the 60 s and 120 s ticks below each sample). */
static void test_postrack_at_rest_samples_on_band_change_or_long_interval(void) {
    postrack_set_sink(1);
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t t0 = 1800000000, t = t0;
    static postrack_sample_t out[16];
    add_dev(&s, 1, t, -62);
    fix_at(48.0, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);   /* first sight */

    for (t = t0 + 60; t < t0 + 600; t += 60) {       /* same band, -62..-68 */
        s.devices[0].last_seen = t;
        s.devices[0].signal_dbm = (int8_t)(t == t0 + 120 ? -68 : -62);
        fix_at(48.0 + 2 * DEG_PER_M, t);             /* jitter, not a move */
        postrack_tick(&s, t);
        ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    }
    t = t0 + 600;                                     /* gps.sample_s x 10 */
    s.devices[0].last_seen = t;
    fix_at(48.0, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);

    /* A band change 30 s on waits for gps.sample_s, then samples. */
    t += 30;
    s.devices[0].last_seen = t;
    s.devices[0].signal_dbm = -45;
    fix_at(48.0, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    t += 30;
    s.devices[0].last_seen = t;
    fix_at(48.0, t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 1);
    ASSERT_EQ(out[0].rssi, -45);
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
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    gps_location_set_gps("gpsd:127.0.0.1:2947");
    fix_at(48.0, t - 100);                           /* stale */
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    fix_at(48.0, t);
    s.devices[0].last_seen = t - 10;                 /* not heard lately */
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);

    s.devices[0].last_seen = t;
    postrack_set_sink(0);
    clk(t);
    postrack_tick(&s, t);
    ASSERT_EQ(postrack_drain_devices(out, 16), 0);
    postrack_set_sink(1);
    clk(t);
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
        fix_at(48.0 + k * 0.001, t);                  /* ~111 m a tick */
        clk(t);
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
    poll_at(&s, 1800000002);
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  gps fix 8sat") != NULL);
    poll_at(&s, 1800000100);
    gps_location_set_err("read: Input/output error");
    poll_at(&s, 1800000100);
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  gps stale 100s (using --location) err read: Input/output error") != NULL);
}


/* ── GNSS observation (2026-11-02) ─────────────────────────── */

/* A SKY as gpsd's u-blox driver writes one (gpsd_json.html: PRN always;
 * gnssid / svid / sigid, el, az, ss in dBHz, used, health), four
 * satellites across three constellations, one with no C/N0 (an SBAS
 * bird the receiver lists but does not track), one with no el / az. */
static const char SKY4[] =
    "{\"class\":\"SKY\",\"device\":\"/dev/ttyACM0\","
    "\"time\":\"2026-10-27T00:00:01.000Z\",\"xdop\":0.6,\"ydop\":0.5,"
    "\"vdop\":1.2,\"tdop\":0.9,\"hdop\":0.8,\"gdop\":2.0,\"pdop\":1.5,"
    "\"nSat\":4,\"uSat\":2,\"satellites\":["
    "{\"PRN\":5,\"gnssid\":0,\"svid\":5,\"sigid\":0,\"el\":45.0,\"az\":120.0,"
    "\"ss\":41.0,\"used\":true,\"health\":1},"
    "{\"PRN\":7,\"gnssid\":0,\"svid\":7,\"ss\":22.5,\"used\":false,\"health\":1,"
    "\"x\":[1,{\"y\":\"}]\"}]},"
    "{\"PRN\":73,\"gnssid\":6,\"svid\":9,\"freqid\":3,\"el\":30.0,\"az\":300.0,"
    "\"ss\":30.5,\"used\":true,\"health\":1},"
    "{\"PRN\":131,\"gnssid\":1,\"svid\":131,\"el\":10.0,\"az\":200.0,"
    "\"used\":false,\"health\":0}]}";

static const char TPV_FULL[] =
    "{\"class\":\"TPV\",\"device\":\"/dev/ttyACM0\",\"status\":2,\"mode\":3,"
    "\"time\":\"2026-10-27T00:00:01.250Z\",\"leapseconds\":18,\"ept\":0.005,"
    "\"lat\":51.500740,\"lon\":-0.124690,\"altHAE\":57.3,\"altMSL\":11.6,"
    "\"epx\":3.0,\"epy\":4.0,\"epv\":9.1,\"track\":12.5,\"speed\":0.3,"
    "\"climb\":-0.1,\"eph\":6.2,\"jam\":12}";

static void test_gpsd_sky_satellites(void) {
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S(SKY4), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_SKY);
    ASSERT_EQ(m.has_nsat, 1);  ASSERT_EQ(m.nsat, 4);
    ASSERT_EQ(m.has_usat, 1);  ASSERT_EQ(m.usat, 2);
    ASSERT_EQ(m.has_pdop, 1);  ASSERT_NEAR(m.pdop, 1.5, 1e-9);
    ASSERT_EQ(m.has_vdop, 1);  ASSERT_NEAR(m.vdop, 1.2, 1e-9);
    ASSERT_EQ(m.has_gdop, 1);  ASSERT_NEAR(m.gdop, 2.0, 1e-9);
    ASSERT_EQ(m.has_tdop, 1);  ASSERT_NEAR(m.tdop, 0.9, 1e-9);
    ASSERT_STR(m.time, "2026-10-27T00:00:01.000Z");
    ASSERT_EQ(m.nsats, 4);
    ASSERT_EQ(m.has_sats, 1);
    ASSERT_EQ(m.sats_overflow, 0);
    ASSERT_EQ(m.sats[0].prn, 5);
    ASSERT_EQ(m.sats[0].gnssid, 0);
    ASSERT_EQ(m.sats[0].svid, 5);
    ASSERT_EQ(m.sats[0].sigid, 0);
    ASSERT_EQ(m.sats[0].has_el, 1); ASSERT_NEAR(m.sats[0].el, 45.0, 1e-9);
    ASSERT_EQ(m.sats[0].has_az, 1); ASSERT_NEAR(m.sats[0].az, 120.0, 1e-9);
    ASSERT_EQ(m.sats[0].has_cn0, 1); ASSERT_NEAR(m.sats[0].cn0, 41.0, 1e-9);
    ASSERT_EQ(m.sats[0].used, 1);
    ASSERT_EQ(m.sats[0].health, 1);
    /* used:false is a boolean, not a number; the nested x is skipped. */
    ASSERT_EQ(m.sats[1].prn, 7);
    ASSERT_EQ(m.sats[1].used, 0);
    ASSERT_EQ(m.sats[1].has_el, 0);
    ASSERT_EQ(m.sats[1].has_az, 0);
    ASSERT_EQ(m.sats[1].sigid, -1);
    ASSERT_NEAR(m.sats[1].cn0, 22.5, 1e-9);
    /* GLONASS: gpsd's PRN 65+slot, svid the slot. */
    ASSERT_EQ(m.sats[2].prn, 73);
    ASSERT_EQ(m.sats[2].gnssid, 6);
    ASSERT_EQ(m.sats[2].svid, 9);
    ASSERT_EQ(m.sats[2].used, 1);
    /* Listed, not tracked: no ss. */
    ASSERT_EQ(m.sats[3].prn, 131);
    ASSERT_EQ(m.sats[3].gnssid, 1);
    ASSERT_EQ(m.sats[3].has_cn0, 0);
    ASSERT_EQ(m.sats[3].health, 0);
    ASSERT_EQ(m.sats[3].used, 0);
    /* A satellite with no PRN is not one; an out-of-range el is dropped,
     * the row kept. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"satellites\":[{\"used\":true},"
                                "{\"PRN\":9,\"el\":95}]}"), &m), 1);
    ASSERT_EQ(m.nsats, 1);
    ASSERT_EQ(m.sats[0].prn, 9);
    ASSERT_EQ(m.sats[0].has_el, 0);
    /* An unbalanced array is a parse error, as an unbalanced object is. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"satellites\":[{\"PRN\":1}"), &m), -1);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"satellites\":[{\"PRN\":1,\"used\":yes}]}"), &m), -1);
    /* A satellites member that is not an array is skipped like any
     * unknown value. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"satellites\":7,\"uSat\":3}"), &m), 1);
    ASSERT_EQ(m.nsats, 0);
    ASSERT_EQ(m.usat, 3);
}

/* Past GPSD_MAX_SATS the rest are parsed and counted, not kept: a
 * multi-GNSS receiver listing 50 objects is still one well-formed line.
 * Seen red with parse_sats()'s bound check removed (ASan: sats[48]). */
static void test_gpsd_sky_overflow_counted(void) {
    static char line[GPSD_MAX_LINE];
    int off = snprintf(line, sizeof(line), "{\"class\":\"SKY\",\"satellites\":[");
    for (int i = 0; i < 50; i++)
        off += snprintf(line + off, sizeof(line) - (size_t)off,
                        "%s{\"PRN\":%d,\"ss\":%d,\"used\":%s}", i ? "," : "",
                        i + 1, 20 + i % 30, i % 2 ? "true" : "false");
    off += snprintf(line + off, sizeof(line) - (size_t)off, "]}");
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(line, (size_t)off, &m), 1);
    ASSERT_EQ(m.nsats, GPSD_MAX_SATS);
    ASSERT_EQ(m.sats_overflow, 2);
    ASSERT_EQ(m.sats[GPSD_MAX_SATS - 1].prn, 48);
    /* The state keeps the 48 and reports nSat as all 50. */
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gps_location_feed_gpsd(&m, 1800000000);
    gnss_sky_t k;
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, GPSD_MAX_SATS);
    ASSERT_EQ(k.overflow, 2);
    ASSERT_EQ(k.nsat, 50);
}

static void test_gpsd_tpv_extras(void) {
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S(TPV_FULL), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_TPV);
    ASSERT_EQ(m.status, 2);
    ASSERT_EQ(m.leap, 18);
    ASSERT_EQ(m.jam, 12);
    ASSERT_EQ(m.has_speed, 1); ASSERT_NEAR(m.speed, 0.3, 1e-9);
    ASSERT_EQ(m.has_track, 1); ASSERT_NEAR(m.track, 12.5, 1e-9);
    ASSERT_EQ(m.has_climb, 1); ASSERT_NEAR(m.climb, -0.1, 1e-9);
    ASSERT_EQ(m.has_epv, 1);   ASSERT_NEAR(m.epv, 9.1, 1e-9);
    /* Absent reads -1, not 0: a status 0 is "unknown", -1 "not said". */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":1}"), &m), 1);
    ASSERT_EQ(m.status, -1);
    ASSERT_EQ(m.jam, -1);
    ASSERT_EQ(m.leap, -1);
    ASSERT_EQ(m.has_speed, 0);
    /* A fractional or negative status / jam is not one. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":1,\"status\":2.5,\"jam\":-3}"), &m), 1);
    ASSERT_EQ(m.status, -1);
    ASSERT_EQ(m.jam, -1);
}

/* GST (gpsd_json.html): pseudorange noise statistics; its lat / lon /
 * alt are standard deviations in metres and must never read as a
 * position. Seen red with the GST branch's has_lat clearing removed
 * (the TPV path would then take a 2.1 m sigma as a latitude). */
static void test_gpsd_gst(void) {
    static gpsd_msg_t m;
    static const char gst[] =
        "{\"class\":\"GST\",\"device\":\"/dev/ttyACM0\","
        "\"time\":\"2026-10-27T00:00:01.000Z\",\"rms\":1.57,\"major\":2.5,"
        "\"minor\":1.1,\"orient\":40.0,\"lat\":2.1,\"lon\":1.3,\"alt\":4.9}";
    ASSERT_EQ(gpsd_json_parse(S(gst), &m), 1);
    ASSERT_EQ(m.cls, GPSD_CLS_GST);
    ASSERT_NEAR(m.gst_rms, 1.57, 1e-9);
    ASSERT_NEAR(m.gst_major, 2.5, 1e-9);
    ASSERT_NEAR(m.gst_minor, 1.1, 1e-9);
    ASSERT_NEAR(m.gst_orient, 40.0, 1e-9);
    ASSERT_NEAR(m.gst_lat, 2.1, 1e-9);
    ASSERT_NEAR(m.gst_lon, 1.3, 1e-9);
    ASSERT_NEAR(m.gst_alt, 4.9, 1e-9);
    ASSERT_EQ(m.has_lat, 0);
    ASSERT_EQ(m.has_lon, 0);
    ASSERT_EQ(m.has_alt, 0);
    /* Through the state: the sigmas ride the fix and outlive a TPV. */
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gps_location_feed_gpsd(&m, 1800000000);
    ASSERT_EQ(gpsd_json_parse(S(TPV_FULL), &m), 1);
    gps_location_feed_gpsd(&m, 1800000000);
    gnss_fix_t f;
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.has_gst, 1);
    ASSERT_NEAR(f.gst_rms, 1.57, 1e-9);
    ASSERT_NEAR(f.gst_lat_sd, 2.1, 1e-9);
    ASSERT_NEAR(f.lat, 51.50074, 1e-9);
    loc_stamp_t l;
    ASSERT_EQ(gps_location_last_fix(&l), 1);
    ASSERT_NEAR(l.lat, 51.50074, 1e-9);   /* never the sigma */
}

/* gpsd's time is ISO 8601 UTC with a millisecond fraction; the parser
 * takes exactly that form. 1793059200 is 2026-10-27T00:00:00Z. */
static void test_gpsd_time_parse(void) {
    int64_t ms = 0;
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00.000Z", &ms), 0);
    ASSERT_EQ(ms, 1793059200000LL);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T12:00:00Z", &ms), 0);
    ASSERT_EQ(ms, 1793102400000LL);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:01.250Z", &ms), 0);
    ASSERT_EQ(ms, 1793059201250LL);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00.5Z", &ms), 0);
    ASSERT_EQ(ms, 1793059200500LL);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00.123456Z", &ms), 0);
    ASSERT_EQ(ms, 1793059200123LL);       /* truncated, not rounded */
    ASSERT_EQ(gpsd_time_parse("2000-02-29T23:59:59Z", &ms), 0);
    ASSERT_EQ(ms, 951868799000LL);
    ASSERT_EQ(gpsd_time_parse("1970-01-01T00:00:00Z", &ms), 0);
    ASSERT_EQ(ms, 0);
    /* Refused: no Z, an offset, a space, out-of-range fields, an
     * impossible date, a bare fraction, a year before the epoch. */
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00+00:00", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-10-27 00:00:00Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-13-01T00:00:00Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-02-30T00:00:00Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-02-29T00:00:00Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T24:00:00Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:00.Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("1969-12-31T23:59:59Z", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("", &ms), -1);
    ASSERT_EQ(gpsd_time_parse("2026-10-27T00:00:0xZ", &ms), -1);
    ASSERT_EQ(gpsd_time_parse(NULL, &ms), -1);
}

/* The clock offset is the receiver's stamp minus the host's wall clock
 * in milliseconds as the line was framed: through the framer the host
 * side is sloth_wall_ms() (the seam), through the _ms feed the caller's
 * figure. Seen red with take_tpv() computing rx - wall x 1000 (the
 * 700 ms case reads 1250). */
static int64_t g_wall_ms_stub;
static int64_t gw_wall_ms(void) { return g_wall_ms_stub; }

static void test_clock_offset_against_host_ms(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    clk(1793059200);                                   /* 2026-10-27T00:00:00Z */
    static gps_lines_t L;
    gps_lines_init(&L, GPS_FEED_GPSD);
    static char line[512];
    int n = snprintf(line, sizeof(line), "%s\n", TPV_FULL);
    gps_lines_feed(&L, (const uint8_t *)line, (size_t)n, 1793059200);
    gnss_fix_t f;
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.valid, 1);
    ASSERT_EQ(f.has_rx_time, 1);
    ASSERT_EQ(f.rx_time_ms, 1793059201250LL);
    ASSERT_EQ(f.has_time_off, 1);
    ASSERT_EQ(f.time_off_ms, 1250LL);
    ASSERT_EQ(f.ts, (time_t)1793059200);
    /* A finer host stub. */
    g_wall_ms_stub = 1793059200700LL;
    sloth_clock_test_set_wall_ms(gw_wall_ms);
    gps_lines_feed(&L, (const uint8_t *)line, (size_t)n, 1793059200);
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.time_off_ms, 550LL);
    sloth_clock_test_set_wall_ms(NULL);
    /* The _ms feed, directly, with a negative result. */
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S(TPV_FULL), &m), 1);
    gps_location_feed_gpsd_ms(&m, 1793059203000LL);
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.time_off_ms, -1750LL);
    ASSERT_EQ(f.ts, (time_t)1793059203);
    /* No time on the TPV: no offset, and the previous one does not
     * linger on the new fix. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":1,\"lon\":2}"), &m), 1);
    gps_location_feed_gpsd(&m, 1793059204);
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.has_time_off, 0);
    ASSERT_EQ(f.has_rx_time, 0);
    /* A TPV whose time does not parse: a TPV still, offset unknown. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"time\":\"soon\"}"), &m), 1);
    gps_location_feed_gpsd(&m, 1793059205);
    gps_fix_snapshot(&f);
    ASSERT_EQ(f.valid, 1);
    ASSERT_EQ(f.has_time_off, 0);
    ASSERT_EQ(f.count, 5u);
    sloth_clock_test_set(NULL, NULL);
}

/* Feed SKY4 and TPV_FULL at wall w, through the framer. */
static void feed_sky_tpv(time_t w) {
    static gps_lines_t L;
    static int init;
    if (!init) { gps_lines_init(&L, GPS_FEED_GPSD); init = 1; }
    static char line[2048];
    int n = snprintf(line, sizeof(line), "%s\n%s\n", SKY4, TPV_FULL);
    /* The TPV's time follows w (same day), 250 ms ahead of the host, so
     * a run of passes keeps its clock-offset band. */
    char *t = strstr(line, "T00:00:01.250Z");
    ASSERT(t != NULL);
    /* And PRN 5's C/N0 wanders inside its 6 dB band (41.0 .. 41.9), so
     * a run of passes proves the band, not an unchanged figure. */
    char *ss = strstr(line, "\"ss\":41.0");
    ASSERT(ss != NULL);
    if (ss) ss[8] = (char)('0' + (int)((w - 1793059200) % 10));
    if (t) {
        int d = (int)(w - 1793059200) % 86400;
        char stamp[24];
        snprintf(stamp, sizeof(stamp), "T%02d:%02d:%02d.250Z",
                 d / 3600, (d / 60) % 60, d % 60);
        memcpy(t, stamp, 14);
    }
    clk(w);
    gps_lines_feed(&L, (const uint8_t *)line, (size_t)n, w);
}

/* The sky state, its statistics and the copy on sloth_state_t. */
static void test_sky_state_and_snapshot(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    feed_sky_tpv(1793059200);
    gnss_sky_t k;
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.valid, 1);
    ASSERT_EQ(k.ts, (time_t)1793059200);
    ASSERT_EQ(k.n, 4);
    ASSERT_EQ(k.nsat, 4);
    ASSERT_EQ(k.usat, 2);
    ASSERT_EQ(k.cn0_n, 3);
    ASSERT_NEAR(k.cn0_mean, (41.0 + 22.5 + 30.5) / 3.0, 1e-9);
    ASSERT_NEAR(k.cn0_max, 41.0, 1e-9);
    ASSERT(k.cn0_sd > 7.0 && k.cn0_sd < 8.0);
    ASSERT_NEAR(k.hdop, 0.8, 1e-9);
    ASSERT_NEAR(k.pdop, 1.5, 1e-9);
    ASSERT_NEAR(k.vdop, 1.2, 1e-9);
    ASSERT_NEAR(k.gdop, 2.0, 1e-9);
    ASSERT_NEAR(k.tdop, 0.9, 1e-9);
    ASSERT_EQ(k.passes, 1u);
    ASSERT_EQ(k.sats[0].prn, 5);
    ASSERT_EQ(k.sats[0].cn0_x10, 410);
    ASSERT_EQ(k.sats[0].el, 45);
    ASSERT_EQ(k.sats[0].az, 120);
    ASSERT_EQ(k.sats[1].has_el, 0);
    ASSERT_EQ(k.sats[1].has_az, 0);
    ASSERT_EQ(k.sats[3].has_cn0, 0);
    ASSERT_EQ(k.sats[2].gnssid, 6);
    ASSERT_STR(gnss_name(k.sats[2].gnssid), "GLONASS");
    ASSERT_STR(gnss_name(-1), "?");

    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1793059200);
    ASSERT_EQ(s.gnss_sky.n, 4);
    ASSERT_EQ(s.gnss_fix.valid, 1);
    ASSERT_EQ(s.gnss_fix.mode, 3);
    ASSERT_EQ(s.gnss_fix.status, 2);
    ASSERT_EQ(s.gnss_fix.jam, 12);
    ASSERT_EQ(s.gnss_fix.leap, 18);
    ASSERT_EQ(s.gnss_fix.has_pos, 1);
    ASSERT_EQ(s.gnss_fix.has_speed, 1);
    ASSERT_EQ(s.gnss_fix.has_epv, 1);
    ASSERT_NEAR(s.gnss_fix.alt_m, 11.6, 1e-9);
    ASSERT_EQ(s.gnss_fix.time_off_ms, 250LL);
    ASSERT_EQ(s.gps.sats_in_view, 4);
    ASSERT_EQ(s.gps.sats_used, 2);
    ASSERT_NEAR(s.gps.cn0_mean, (41.0 + 22.5 + 30.5) / 3.0, 1e-9);
    ASSERT_NEAR(s.gps.cn0_max, 41.0, 1e-9);
    ASSERT_EQ(s.gps.has_time_off, 1);
    ASSERT_EQ(s.gps.time_off_ms, 250LL);
    ASSERT_NEAR(s.gps.pdop, 1.5, 1e-9);
    ASSERT_EQ(s.gps.status, 2);
    ASSERT_EQ(s.gps.jam, 12);
    /* A SKY carrying DOPs alone updates them and keeps the rows. */
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"hdop\":1.9,\"pdop\":3.0}"), &m), 1);
    gps_location_feed_gpsd(&m, 1793059201);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 4);
    ASSERT_NEAR(k.hdop, 1.9, 1e-9);
    ASSERT_NEAR(k.pdop, 3.0, 1e-9);
    ASSERT_EQ(k.passes, 1u);
    /* Before any receiver: nothing valid, nothing in s->gps. */
    gps_location_reset();
    memset(&s, 0, sizeof(s));
    poll_at(&s, 1793059202);
    ASSERT_EQ(s.gnss_sky.valid, 0);
    ASSERT_EQ(s.gnss_fix.valid, 0);
    ASSERT_EQ(s.gps.sats_in_view, 0);
    ASSERT_EQ(s.gps.status, -1);
    ASSERT_EQ(s.gps.jam, -1);
    sloth_clock_test_set(NULL, NULL);
}

/* The rings kept for the detector slice: 64 positioned fixes, 300 one-
 * second points, oldest overwritten; a TPV without a position keeps the
 * fix ring but still makes a second's point. */
static void test_gnss_history_rings_wrap(void) {
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S(SKY4), &m), 1);
    gps_location_feed_gpsd(&m, 1793059200);
    for (int i = 0; i < 70; i++) {
        static char line[256];
        int n = snprintf(line, sizeof(line),
                         "{\"class\":\"TPV\",\"mode\":3,\"lat\":%d.5,\"lon\":2,\"eph\":%d}",
                         i % 80, i);
        ASSERT_EQ(gpsd_json_parse(line, (size_t)n, &m), 1);
        gps_location_feed_gpsd(&m, 1793059200 + i);
    }
    static gnss_hist_t h;
    gps_gnss_history(&h);
    ASSERT_EQ(h.fix_n, GNSS_FIX_HIST);
    ASSERT_EQ(h.fix_head, 70 % GNSS_FIX_HIST);
    /* The newest point sits before head; the oldest kept is fix 6. */
    int newest = (h.fix_head + GNSS_FIX_HIST - 1) % GNSS_FIX_HIST;
    ASSERT_NEAR(h.fixes[newest].eph, 69.0, 1e-9);
    ASSERT_NEAR(h.fixes[h.fix_head].eph, 6.0, 1e-9);
    ASSERT_EQ(h.fixes[newest].usat, 2);
    ASSERT_EQ(h.sec_n, 70);
    ASSERT_EQ(h.secs[(h.sec_head + GNSS_SERIES_S - 1) % GNSS_SERIES_S].ts,
              (time_t)1793059269);
    ASSERT_EQ(h.secs[0].nsat, 4);
    /* Two TPVs in one second are one point; 400 seconds are 300. */
    for (int i = 70; i < 400; i++) {
        ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":1}"), &m), 1);
        gps_location_feed_gpsd(&m, 1793059200 + i);
        gps_location_feed_gpsd(&m, 1793059200 + i);
    }
    gps_gnss_history(&h);
    ASSERT_EQ(h.sec_n, GNSS_SERIES_S);
    ASSERT_EQ(h.fix_n, GNSS_FIX_HIST);          /* mode 1 adds no fix */
    ASSERT_EQ(h.secs[(h.sec_head + GNSS_SERIES_S - 1) % GNSS_SERIES_S].ts,
              (time_t)1793059599);
    ASSERT_EQ(h.secs[h.sec_head].ts, (time_t)1793059300);
}

/* The three records are change-only on bands: sixty identical passes
 * are one record each (and four gnss_sat), one satellite crossing a
 * 6 dB C/N0 band is one more gnss_sat and nothing else. Seen red with
 * gps_gnss_sat_sig() signing cn0_x10 itself (every pass wrote four
 * gnss_sat lines) and with the 60-pass loop's `== 4` turned to `>= 4`
 * after that mutation (the absence claim needs the exact count). */
static void test_gnss_records_change_only(void) {
    jl_open();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t w = 1793059200;
    feed_sky_tpv(w);
    poll_at(&s, w);
    jsonl_emit_gnss(&s);
    for (int i = 1; i <= 60; i++) {
        feed_sky_tpv(w + i);
        poll_at(&s, w + i);
        jsonl_emit_gnss(&s);
    }
    /* One sink throughout: jsonl_open() resets the change cache, so a
     * reopen would make every phase's first pass a full re-emission. */
    /* uSat wobbling by one (2 -> 3, the same used-count band) writes
     * nothing: neither gnss_fix nor gnss_sky signs the raw count. Seen
     * red with gps_gnss_fix_sig() / gps_gnss_sky_sig() signing k->usat
     * itself (one more of each). */
    static gps_lines_t L;
    gps_lines_init(&L, GPS_FEED_GPSD);
    static char line[2048];
    snprintf(line, sizeof(line), "%s\n", SKY4);
    char *p = strstr(line, "\"uSat\":2");
    ASSERT(p != NULL);
    if (p) memcpy(p, "\"uSat\":3", 8);
    clk(w + 61);
    gps_lines_feed(&L, (const uint8_t *)line, strlen(line), w + 61);
    poll_at(&s, w + 61);
    jsonl_emit_gnss(&s);
    /* One satellite's C/N0 crosses a band (41.0 -> 47.5: 6 dB bucket 6
     * to 7); the sky's mean band and the fix's bands do not move. */
    snprintf(line, sizeof(line), "%s\n", SKY4);
    p = strstr(line, "\"ss\":41.0");
    ASSERT(p != NULL);
    if (p) memcpy(p, "\"ss\":47.5", 9);
    clk(w + 62);
    gps_lines_feed(&L, (const uint8_t *)line, strlen(line), w + 62);
    poll_at(&s, w + 62);
    jsonl_emit_gnss(&s);
    /* The receiver dropping to no fix is a gnss_fix (mode band). */
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":1}"), &m), 1);
    clk(w + 63);
    gps_location_feed_gpsd(&m, w + 63);
    poll_at(&s, w + 63);
    jsonl_emit_gnss(&s);
    /* Nothing without a --gps reader: --location alone has no sky. */
    gps_location_reset();
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    memset(&s, 0, sizeof(s));
    poll_at(&s, w + 64);
    jsonl_emit_gnss(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        /* 60 identical passes: one of each; the crossing: one gnss_sat;
         * the lost fix: one gnss_fix; --location: nothing. */
        ASSERT_EQ(count_type(b, "\"type\":\"gnss_fix\""), 2);
        ASSERT_EQ(count_type(b, "\"type\":\"gnss_sky\""), 1);
        ASSERT_EQ(count_type(b, "\"type\":\"gnss_sat\""), 5);
        ASSERT(strstr(b, "\"ts\":1793059261") == NULL);          /* the uSat wobble */
        ASSERT(strstr(b, "\"type\":\"gnss_sat\",\"ts\":1793059262,\"gnss\":\"GPS\",\"gnssid\":0,"
                         "\"svid\":5,\"prn\":5,\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":47.5") != NULL);
        ASSERT(strstr(b, "\"type\":\"gnss_fix\",\"ts\":1793059263,\"src\":\"gpsd:127.0.0.1:2947\","
                         "\"fix_ts\":1793059263,\"mode\":1,\"status\":-1") != NULL);
        ASSERT(strstr(b, "\"ts\":1793059264") == NULL);
        /* The row gpsd sent no el / az for carries neither key. */
        ASSERT(strstr(b, "\"svid\":7,\"prn\":7,\"sigid\":-1,\"cn0\":22.5,\"used\":0") != NULL);
        ASSERT(strstr(b, "\"type\":\"gnss_fix\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\","
                         "\"fix_ts\":1793059200,\"mode\":3,\"status\":2,\"nsat\":4,\"usat\":2,"
                         "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"lat\":51.50074,\"lon\":-0.12469,"
                         "\"alt_m\":11.6,\"eph\":6.2,\"epv\":9.1,\"speed_mps\":0.30,"
                         "\"track_deg\":12.5,\"rx_time_ms\":1793059200250,\"time_off_ms\":250,"
                         "\"leap\":18,\"jam\":12,\"tpv_count\":1}") != NULL);
        ASSERT(strstr(b, "\"type\":\"gnss_sky\",\"ts\":1793059200,\"src\":\"gpsd:127.0.0.1:2947\","
                         "\"sky_ts\":1793059200,\"nsat\":4,\"usat\":2,\"rows\":4,\"overflow\":0,"
                         "\"hdop\":0.8,\"vdop\":1.2,\"pdop\":1.5,\"gdop\":2.0,\"tdop\":0.9,"
                         "\"cn0_mean\":31.3,\"cn0_max\":41.0,\"cn0_sd\":7.6,\"cn0_n\":3,"
                         "\"passes\":1}") != NULL);
        ASSERT(strstr(b, "\"type\":\"gnss_sat\",\"ts\":1793059200,\"gnss\":\"GPS\",\"gnssid\":0,"
                         "\"svid\":5,\"prn\":5,\"sigid\":0,\"el\":45,\"az\":120,\"cn0\":41.0,"
                         "\"used\":1,\"health\":1,\"sky_ts\":1793059200}") != NULL);
        ASSERT(strstr(b, "\"gnss\":\"GLONASS\",\"gnssid\":6,\"svid\":9,\"prn\":73") != NULL);
        /* The untracked SBAS row carries no cn0 key at all. */
        ASSERT(strstr(b, "\"prn\":131,\"sigid\":-1,\"el\":10,\"az\":200,\"used\":0,\"health\":0") != NULL);
        /* The lost-fix record has no position. */
        const char *nf = strstr(b, "\"fix_ts\":1793059263");
        ASSERT(nf && strstr(nf, "\"lat\"") == NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* The sensor_health appends: present only with a --gps reader (a
 * --location run and a run with neither write no gnss_ key, so their
 * lines are what they were before this slice), the offset key only once
 * a TPV carried a time; and the bands, not the figures, sign the line:
 * a C/N0 wandering inside its band writes nothing, the clock offset
 * crossing 2 s writes one line. Seen red with sig.gnss_time_off_band
 * replaced by the raw offset (every tick wrote a line). */
static void test_sensor_health_gnss_block(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char err[160];
    /* --location alone. */
    jl_open();
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    poll_at(&s, 1793059200);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"gps_state\":\"fixed\"") != NULL);
        ASSERT(strstr(b, "\"gnss_") == NULL);
    }
    unlink(g_jl);
    /* --gps, before any time: counts and jam, no offset key. */
    gps_location_reset();
    jsonl_dedup_reset();
    jl_open();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    static gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(S(SKY4), &m), 1);
    clk(1793059200);
    gps_location_feed_gpsd(&m, 1793059200);
    poll_at(&s, 1793059200);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"gps_err\":\"\",\"gnss_sats_in_view\":4,\"gnss_sats_used\":2,"
                         "\"gnss_cn0_mean\":31.3,\"gnss_jam\":-1}") != NULL);
        ASSERT(strstr(b, "gnss_time_offset_ms") == NULL);
    }
    unlink(g_jl);
    /* With the TPV: the offset and jam appear; sixty ticks of a C/N0
     * wandering in its band and an offset wandering under 500 ms write
     * nothing; the offset crossing 2 s writes one. */
    jl_open();
    feed_sky_tpv(1793059201);
    poll_at(&s, 1793059201);
    jsonl_emit_sensor_health(&s);
    for (int i = 2; i < 62; i++) {
        static char line[2048];
        /* C/N0 41.0 -> 41.x, offset 250 -> 250 + i ms. */
        int n = snprintf(line, sizeof(line),
                         "{\"class\":\"SKY\",\"nSat\":4,\"uSat\":2,\"satellites\":["
                         "{\"PRN\":5,\"ss\":41.%d,\"used\":true},{\"PRN\":7,\"ss\":22.5,\"used\":false},"
                         "{\"PRN\":73,\"ss\":30.5,\"used\":true},{\"PRN\":131,\"used\":false}]}\n"
                         "{\"class\":\"TPV\",\"mode\":3,\"lat\":51.5,\"lon\":-0.1,"
                         "\"time\":\"2026-10-27T00:%02d:%02d.%03dZ\",\"jam\":12}\n",
                         i % 10, i / 60, i % 60, 250 + i);
        static gps_lines_t L;
        gps_lines_init(&L, GPS_FEED_GPSD);
        clk(1793059200 + i);
        gps_lines_feed(&L, (const uint8_t *)line, (size_t)n, 1793059200 + i);
        poll_at(&s, 1793059200 + i);
        jsonl_emit_sensor_health(&s);
    }
    /* Same sink (a reopen resets the change cache): the crossing. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"TPV\",\"mode\":3,\"lat\":51.5,\"lon\":-0.1,"
                                "\"time\":\"2026-10-27T00:01:05.000Z\",\"jam\":12}"), &m), 1);
    clk(1793059262);
    gps_location_feed_gpsd(&m, 1793059262);             /* receiver 3 s ahead */
    poll_at(&s, 1793059262);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_type(b, "\"type\":\"sensor_health\""), 2);
        ASSERT(strstr(b, "\"gnss_time_offset_ms\":250,\"gnss_jam\":12}") != NULL);
        ASSERT(strstr(b, "\"gnss_time_offset_ms\":3000,\"gnss_jam\":12}") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* The receiver registers as the `gps` sensor (kind name "gps", iface
 * its source label, observed its parsed objects), after the radios;
 * --location alone registers nothing. */
static void test_sensor_registry_gps(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char err[160];
    ASSERT_EQ(gps_location_parse_fixed("10,20", err, sizeof(err)), 0);
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    for (int i = 0; i < s.sensor_count; i++) ASSERT_NE(s.sensors[i].kind, SENSOR_GPS);
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    feed_sky_tpv(1793059200);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    int found = -1;
    for (int i = 0; i < s.sensor_count; i++)
        if (s.sensors[i].kind == SENSOR_GPS) found = i;
    ASSERT(found >= 0);
    if (found >= 0) {
        ASSERT_STR(s.sensors[found].iface, "gpsd:127.0.0.1:2947");
        ASSERT_STR(s.sensors[found].name, "GNSS receiver");
        ASSERT_EQ(s.sensors[found].observed, 2u);
        ASSERT_EQ(s.sensors[found].state, SENSOR_STATE_ACTIVE);
        ASSERT_STR(sensor_kind_name(s.sensors[found].kind), "gps");
    }
    jl_open();
    jsonl_emit_sensors(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b)
        ASSERT(strstr(b, "\"type\":\"sensor\",\"ts\":1793059200,\"kind\":\"gps\",\"state\":\"active\","
                         "\"name\":\"GNSS receiver\",\"iface\":\"gpsd:127.0.0.1:2947\","
                         "\"observed\":2") != NULL);
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* The banded signatures move only across a band edge. */
static void test_gnss_signature_bands(void) {
    ASSERT_EQ(gps_cn0_band(0), -1);
    ASSERT_EQ(gps_cn0_band(24.9), 0);
    ASSERT_EQ(gps_cn0_band(25.0), 1);
    ASSERT_EQ(gps_cn0_band(35.0), 2);
    ASSERT_EQ(gps_time_off_band(0, 0), -1);
    ASSERT_EQ(gps_time_off_band(1, -499), 0);
    ASSERT_EQ(gps_time_off_band(1, 500), 1);
    ASSERT_EQ(gps_time_off_band(1, -1999), 1);
    ASSERT_EQ(gps_time_off_band(1, 2000), 2);
    ASSERT_EQ(gps_time_off_band(1, 10000), 3);
    ASSERT_EQ(gps_jam_band(-1), -1);
    ASSERT_EQ(gps_jam_band(0), 0);
    ASSERT_EQ(gps_jam_band(63), 1);
    ASSERT_EQ(gps_jam_band(64), 2);
    ASSERT_EQ(gps_jam_band(128), 3);
    ASSERT_EQ(gps_usat_band(-1), -1);
    ASSERT_EQ(gps_usat_band(0), 0);
    ASSERT_EQ(gps_usat_band(3), 1);
    ASSERT_EQ(gps_usat_band(4), 2);
    ASSERT_EQ(gps_usat_band(5), 2);
    ASSERT_EQ(gps_usat_band(7), 3);
    ASSERT_EQ(gps_usat_band(8), 4);
    ASSERT_EQ(gps_usat_band(14), 4);
    gnss_sat_t a;
    memset(&a, 0, sizeof(a));
    a.prn = 5; a.gnssid = 0; a.svid = 5; a.has_cn0 = 1; a.cn0_x10 = 410;
    a.has_el = a.has_az = 1; a.el = 45; a.az = 120; a.used = 1; a.health = 1;
    uint64_t h0 = gps_gnss_sat_sig(&a);
    a.cn0_x10 = 419;  ASSERT_EQ(gps_gnss_sat_sig(&a), h0);     /* 41.9: same 6 dB band */
    a.el = 59;        ASSERT_EQ(gps_gnss_sat_sig(&a), h0);     /* same 15 degree band */
    a.cn0_x10 = 420;  ASSERT_NE(gps_gnss_sat_sig(&a), h0);     /* 42.0: next band */
    a.cn0_x10 = 419; a.used = 0;  ASSERT_NE(gps_gnss_sat_sig(&a), h0);
    a.used = 1; a.el = 60;        ASSERT_NE(gps_gnss_sat_sig(&a), h0);
    /* Absent is its own band, not -1 degrees; -15..-1 is one band
     * under the horizon (the edges are multiples of 15 from -90),
     * -16 the next. */
    a.el = 45; a.has_el = 0;      ASSERT_NE(gps_gnss_sat_sig(&a), h0);
    a.has_el = 1; a.el = -1;
    uint64_t hm = gps_gnss_sat_sig(&a);
    ASSERT_NE(hm, h0);
    a.el = -15;  ASSERT_EQ(gps_gnss_sat_sig(&a), hm);
    a.el = -16;  ASSERT_NE(gps_gnss_sat_sig(&a), hm);
    gnss_fix_t f; gnss_sky_t k;
    memset(&f, 0, sizeof(f)); memset(&k, 0, sizeof(k));
    f.valid = 1; f.mode = 3; f.has_pos = 1; f.has_speed = 1; f.speed = 0.1;
    f.has_time_off = 1; f.time_off_ms = 100; f.time_off_band = 0;
    k.valid = 1; k.usat = 8; k.nsat = 12; k.hdop = 1.1;
    uint64_t g0 = gps_gnss_fix_sig(&f, &k);
    uint64_t s0 = gps_gnss_sky_sig(&k);
    /* The signatures take the held band, never the figure. */
    f.time_off_ms = 4000; f.speed = 0.4; k.nsat = 15; k.hdop = 1.9;
    ASSERT_EQ(gps_gnss_fix_sig(&f, &k), g0);
    f.time_off_band = 1;  ASSERT_NE(gps_gnss_fix_sig(&f, &k), g0);
    f.time_off_band = 0;
    /* uSat 8 -> 9 is one band; 8 -> 7 crosses one, in both signatures. */
    k.usat = 9;  ASSERT_EQ(gps_gnss_fix_sig(&f, &k), g0);  ASSERT_EQ(gps_gnss_sky_sig(&k), s0);
    k.usat = 7;  ASSERT_NE(gps_gnss_fix_sig(&f, &k), g0);  ASSERT_NE(gps_gnss_sky_sig(&k), s0);
    k.usat = 8;  k.nsat = 16;  ASSERT_NE(gps_gnss_sky_sig(&k), s0);   /* nsat/4 */
}

/* A TPV with a `time` whose receiver clock is `off_ms` ahead of the
 * host's at w (2026-10-27, as the fixtures), TPV_FULL's mode, status
 * and speed (so the fix signature's other bands stand), plus `extra`
 * members. */
static void feed_tpv_off(time_t w, long off_ms, const char *extra) {
    static gps_lines_t L;
    static int init;
    if (!init) { gps_lines_init(&L, GPS_FEED_GPSD); init = 1; }
    long long ms = ((long long)(w - 1793059200) % 86400) * 1000 + off_ms;
    long long sec = ms / 1000, frac = ms % 1000;
    static char line[512];
    int n = snprintf(line, sizeof(line),
                     "{\"class\":\"TPV\",\"mode\":3,\"status\":2,\"speed\":0.3,"
                     "\"lat\":51.5,\"lon\":-0.1,"
                     "\"time\":\"2026-10-27T%02lld:%02lld:%02lld.%03lldZ\"%s%s}\n",
                     sec / 3600, (sec / 60) % 60, sec % 60, frac,
                     extra && extra[0] ? "," : "", extra ? extra : "");
    clk(w);
    gps_lines_feed(&L, (const uint8_t *)line, (size_t)n, w);
}

/* gpsd attaches `jam` only to the TPV after a UBX-MON-HW poll (two of
 * fourteen in eight seconds on the reference u-blox 7). A TPV without
 * it keeps the last value for GNSS_JAM_HOLD_TPVS TPVs: the fix
 * signature, the sensor_health line and the one-second series hold;
 * past the hold it is absent again, and a new reading takes over.
 * Seen red with take_tpv() back to `f->jam = m->jam` (the second TPV
 * read jam -1, the fix signature moved, sensor_health wrote 11 lines,
 * the series point said -1). */
static void test_jam_is_sticky_across_tpvs(void) {
    jl_open();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t w = 1793059200;
    feed_sky_tpv(w);                              /* TPV_FULL: jam 12 */
    poll_at(&s, w);
    jsonl_emit_sensor_health(&s);
    uint64_t sig0 = gps_gnss_fix_sig(&s.gnss_fix, &s.gnss_sky);
    ASSERT_EQ(s.gnss_fix.jam, 12);
    for (int i = 1; i <= GNSS_JAM_HOLD_TPVS; i++) {
        feed_tpv_off(w + i, 250, "");             /* no jam member */
        poll_at(&s, w + i);
        jsonl_emit_sensor_health(&s);
        ASSERT_EQ(s.gnss_fix.jam, 12);
        ASSERT_EQ(s.gps.jam, 12);
        ASSERT_EQ(gps_gnss_fix_sig(&s.gnss_fix, &s.gnss_sky), sig0);
    }
    static gnss_hist_t h;
    gps_gnss_history(&h);
    ASSERT_EQ(h.secs[(h.sec_head + GNSS_SERIES_S - 1) % GNSS_SERIES_S].jam, 12);
    /* The eleventh without it: absent. */
    feed_tpv_off(w + GNSS_JAM_HOLD_TPVS + 1, 250, "");
    poll_at(&s, w + GNSS_JAM_HOLD_TPVS + 1);
    jsonl_emit_sensor_health(&s);
    ASSERT_EQ(s.gnss_fix.jam, -1);
    ASSERT_NE(gps_gnss_fix_sig(&s.gnss_fix, &s.gnss_sky), sig0);
    gps_gnss_history(&h);
    ASSERT_EQ(h.secs[(h.sec_head + GNSS_SERIES_S - 1) % GNSS_SERIES_S].jam, -1);
    /* A new reading, then one omission: the new one holds. */
    feed_tpv_off(w + GNSS_JAM_HOLD_TPVS + 2, 250, "\"jam\":70");
    feed_tpv_off(w + GNSS_JAM_HOLD_TPVS + 3, 250, "");
    poll_at(&s, w + GNSS_JAM_HOLD_TPVS + 3);
    jsonl_emit_sensor_health(&s);
    ASSERT_EQ(s.gnss_fix.jam, 70);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        /* First line, the hold expiring (jam band -1), 70 (band 2). */
        ASSERT_EQ(count_type(b, "\"type\":\"sensor_health\""), 3);
        ASSERT(strstr(b, "\"gnss_jam\":12}") != NULL);
        ASSERT(strstr(b, "\"gnss_jam\":-1}") != NULL);
        ASSERT(strstr(b, "\"gnss_jam\":70}") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* The clock-offset band has hysteresis: with a 9600-baud receiver
 * through gpsd and no PPS the offset sits 200..700 ms behind the host
 * and jitters across the 500 ms edge, so the raw band flipped 0 <-> 1
 * TPV by TPV and each flip was a gnss_fix line, a sensor_health line
 * and a gnss_fixes row. An offset wandering 400 <-> 600 ms writes
 * nothing; 700 (a quarter past the edge) moves the band once; 550 on
 * the way back does not; 300 (a quarter under) does; the same at the
 * 2 s and 10 s edges. Exact counts. Seen red with take_tpv() taking
 * gps_time_off_band() raw (every alternation wrote both lines). */
static void test_time_off_band_hysteresis(void) {
    jl_open();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t w = 1793059200;
    feed_sky_tpv(w);                              /* offset 250: band 0 */
    poll_at(&s, w);
    jsonl_emit_gnss(&s);
    jsonl_emit_sensor_health(&s);
    ASSERT_EQ(s.gnss_fix.time_off_band, 0);
    ASSERT_EQ(s.gps.time_off_band, 0);
    int i = 1;
    for (; i <= 20; i++) {
        feed_tpv_off(w + i, (i & 1) ? 600 : 400, "\"jam\":12");
        poll_at(&s, w + i);
        jsonl_emit_gnss(&s);
        jsonl_emit_sensor_health(&s);
        ASSERT_EQ(s.gnss_fix.time_off_band, 0);
    }
    static const struct { long off; int band; } steps[] = {
        { 700, 1 }, { 550, 1 }, { 620, 1 }, { 300, 0 }, { 1900, 1 }, { 2400, 1 },
        { 2600, 2 }, { 1600, 2 }, { 1400, 1 }, { 9000, 2 }, { 12600, 3 }, { 8000, 3 },
        { 7400, 2 },
    };
    for (size_t j = 0; j < sizeof(steps) / sizeof(steps[0]); j++, i++) {
        feed_tpv_off(w + i, steps[j].off, "\"jam\":12");
        poll_at(&s, w + i);
        jsonl_emit_gnss(&s);
        jsonl_emit_sensor_health(&s);
        ASSERT_EQ(s.gnss_fix.time_off_band, steps[j].band);
        ASSERT_EQ(s.gnss_fix.time_off_ms, (long long)steps[j].off);   /* the figure is exact */
    }
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        /* The first, then each band move: 700, 300, 1900, 2600, 1400,
         * 9000, 12600, 7400 - eight. */
        ASSERT_EQ(count_type(b, "\"type\":\"gnss_fix\""), 9);
        ASSERT_EQ(count_type(b, "\"type\":\"sensor_health\""), 9);
        ASSERT(strstr(b, "\"time_off_ms\":700,") != NULL);
        ASSERT(strstr(b, "\"time_off_ms\":550,") == NULL);
        ASSERT(strstr(b, "\"time_off_ms\":600,") == NULL);
        ASSERT(strstr(b, "\"gnss_time_offset_ms\":12600,") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* A SKY whose satellite set is present but empty (nSat 0, or the key
 * alone) empties the rows - the antenna is gone - where a DOP-only SKY
 * keeps them; the following jsonl_emit_gnss() writes no gnss_sat. And
 * el / az are carried with flags, not a -1 sentinel: a bird one degree
 * under the horizon is -1 with has_el, written as itself; one gpsd
 * sent no el for has none and no key. Seen red with take_sky()'s
 * DOP-only test back on `m->nsats == 0` (the key-alone SKY kept four
 * rows) and with the emitter writing el unconditionally. */
static void test_sky_empty_set_and_elevation_flags(void) {
    jl_open();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    time_t w = 1793059200;
    feed_sky_tpv(w);
    poll_at(&s, w);
    jsonl_emit_gnss(&s);
    gnss_sky_t k;
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 4);
    ASSERT_EQ(k.sats[0].has_el, 1); ASSERT_EQ(k.sats[0].el, 45);
    ASSERT_EQ(k.sats[1].has_el, 0); ASSERT_EQ(k.sats[1].has_az, 0);
    static gpsd_msg_t m;
    /* The empty set as gpsd writes it. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"nSat\":0,\"uSat\":0,\"satellites\":[]}"), &m), 1);
    ASSERT_EQ(m.has_sats, 1);
    clk(w + 1);
    gps_location_feed_gpsd(&m, w + 1);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.valid, 1);
    ASSERT_EQ(k.n, 0);
    ASSERT_EQ(k.nsat, 0);
    ASSERT_EQ(k.usat, 0);
    ASSERT_EQ(k.cn0_n, 0);
    ASSERT_EQ(k.passes, 2u);
    poll_at(&s, w + 1);
    jsonl_emit_gnss(&s);
    ASSERT_EQ(s.gps.sats_in_view, 0);
    /* Back, then the key alone with no nSat / uSat: still an empty sky. */
    feed_sky_tpv(w + 2);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 4);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"satellites\":[]}"), &m), 1);
    gps_location_feed_gpsd(&m, w + 3);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 0);
    ASSERT_EQ(k.nsat, -1);
    /* A DOP-only SKY has no satellites key and keeps the rows. */
    feed_sky_tpv(w + 4);
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"hdop\":1.9}"), &m), 1);
    ASSERT_EQ(m.has_sats, 0);
    gps_location_feed_gpsd(&m, w + 5);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 4);
    ASSERT_NEAR(k.hdop, 1.9, 1e-9);
    /* A bird under the horizon. */
    ASSERT_EQ(gpsd_json_parse(S("{\"class\":\"SKY\",\"nSat\":1,\"uSat\":0,\"satellites\":["
                                "{\"PRN\":9,\"gnssid\":0,\"svid\":9,\"el\":-1.0,\"az\":0.0,"
                                "\"used\":false}]}"), &m), 1);
    clk(w + 6);
    gps_location_feed_gpsd(&m, w + 6);
    gps_sky_snapshot(&k);
    ASSERT_EQ(k.n, 1);
    ASSERT_EQ(k.sats[0].has_el, 1);
    ASSERT_EQ(k.sats[0].el, -1);
    ASSERT_EQ(k.sats[0].has_az, 1);
    ASSERT_EQ(k.sats[0].az, 0);
    ASSERT_NEAR(k.hdop, 0.0, 1e-9);              /* a full SKY's DOPs are its own */
    poll_at(&s, w + 6);
    jsonl_emit_gnss(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        /* Four rows at w, none at w+1 (an emptied sky writes no gnss_sat
         * line), one at w+6 with its negative elevation as itself. */
        ASSERT_EQ(count_type(b, "\"type\":\"gnss_sat\""), 5);
        ASSERT(strstr(b, "\"type\":\"gnss_sat\",\"ts\":1793059201") == NULL);
        ASSERT(strstr(b, "\"type\":\"gnss_sky\",\"ts\":1793059201,\"src\":\"gpsd:127.0.0.1:2947\","
                         "\"sky_ts\":1793059201,\"nsat\":0,\"usat\":0,\"rows\":0,") != NULL);
        ASSERT(strstr(b, "\"svid\":9,\"prn\":9,\"sigid\":-1,\"el\":-1,\"az\":0,\"used\":0") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
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
    RUN_TEST(test_multi_gnss_gsa_mode1_keeps_the_fix);
    RUN_TEST(test_gpsd_out_of_range_figures_are_dropped);
    RUN_TEST(test_nmea_out_of_range_figures_are_dropped);
    RUN_TEST(test_fix_age_is_monotonic_across_a_wall_step_back);
    RUN_TEST(test_gpsd_feed);
    RUN_TEST(test_reconnects_count_lost_sessions_only);
    RUN_TEST(test_reader_eof_ends_the_fix);
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
    RUN_TEST(test_postrack_at_rest_samples_on_band_change_or_long_interval);
    RUN_TEST(test_postrack_samples_nothing_without_a_moving_fix);
    RUN_TEST(test_postrack_queue_drops_oldest_and_counts);
    TEST_SUITE("gps: TUI");
    RUN_TEST(test_view_detail_location_line);
    RUN_TEST(test_health_strip_gps_token);

    TEST_SUITE("gps: GNSS observation (2026-11-02)");
    RUN_TEST(test_gpsd_sky_satellites);
    RUN_TEST(test_gpsd_sky_overflow_counted);
    RUN_TEST(test_gpsd_tpv_extras);
    RUN_TEST(test_gpsd_gst);
    RUN_TEST(test_gpsd_time_parse);
    RUN_TEST(test_clock_offset_against_host_ms);
    RUN_TEST(test_sky_state_and_snapshot);
    RUN_TEST(test_gnss_history_rings_wrap);
    RUN_TEST(test_gnss_records_change_only);
    RUN_TEST(test_sensor_health_gnss_block);
    RUN_TEST(test_sensor_registry_gps);
    RUN_TEST(test_gnss_signature_bands);
    RUN_TEST(test_jam_is_sticky_across_tpvs);
    RUN_TEST(test_time_off_band_hysteresis);
    RUN_TEST(test_sky_empty_set_and_elevation_flags);
}
