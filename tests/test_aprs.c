#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "aprs.h"
#include "capture/aprs_reader.h"
#include "jsonl.h"
#include "poll.h"
#include "sensors.h"
#include "sloth_clock.h"

/* --aprs (2026-11-05).
 *
 * Every line here is written by hand to the shape Dire Wolf 1.7's
 * src/log.c log_write() gives a record: 22 comma-separated fields in
 * the header's order, quote_for_csv() on the text fields (quoted only
 * when they hold ',' or '"', an inner '"' doubled), speed in knots,
 * altitude in metres, "%.6f" coordinates, an empty field for anything
 * unknown. The data type indicators and symbols are APRS101.pdf's. The
 * callsigns (N0TEST-n, N0CALL) and the positions are invented; none is
 * from a receiver, and no parser output is fed back in. */

#define HDR "chan,utime,isotime,source,heard,level,error,dti,name,symbol," \
            "latitude,longitude,speed,course,altitude,frequency,offset,tone," \
            "system,status,telemetry,comment"
#define L_FIXED  "0,1793930035,2026-11-06T01:53:55Z,N0TEST-5,N0TEST-5,50(14/14),0,!," \
                 "N0TEST-5,/#,10.000000,-20.000000,,,,,,,\"DireWolf, WB2OSZ\",,,Test station"
#define L_MOVING "0,1793930035,2026-11-06T01:53:55Z,N0TEST-9,N0TEST-9,50(14/14),0,=," \
                 "N0TEST-9,/>,10.205667,-20.535000,45.0,90.0,376.1,,,," \
                 "\"Generic, (obsolete. Digis should use APNxxx instead)\",,, moving"
#define L_MSG    "0,1793930035,2026-11-06T01:53:55Z,N0TEST-1,N0TEST-1,50(14/14),0,:," \
                 "N0TEST-1,/ ,,,,,,,,,\"Generic, (obsolete. Digis should use APNxxx " \
                 "instead)\",,,hello"

static aprs_packet_t g_p;

static int parse(const char *s) { return aprs_line_parse(s, strlen(s), &g_p); }

/* ── One line ──────────────────────────────────────────────────── */

static void test_fixed_station_line(void) {
    ASSERT_EQ(parse(L_FIXED), 1);
    ASSERT_EQ(g_p.chan, 0);
    ASSERT_EQ((long long)g_p.utime, 1793930035LL);
    ASSERT_STR(g_p.source, "N0TEST-5");
    ASSERT_STR(g_p.heard, "N0TEST-5");
    ASSERT_EQ(g_p.level, 50);
    ASSERT_EQ(g_p.error, 0);
    ASSERT_EQ(g_p.dti, '!');
    ASSERT_STR(g_p.name, "N0TEST-5");
    ASSERT_STR(g_p.symbol, "/#");
    ASSERT_EQ(g_p.has_pos, 1);
    ASSERT_NEAR(g_p.lat, 10.0, 1e-9);
    ASSERT_NEAR(g_p.lon, -20.0, 1e-9);
    ASSERT_EQ(g_p.has_speed + g_p.has_course + g_p.has_alt, 0);
    ASSERT_STR(g_p.system, "DireWolf, WB2OSZ");   /* quoted: holds a ',' */
    ASSERT_STR(g_p.status, "");
    ASSERT_STR(g_p.comment, "Test station");
}

/* 45 kt, 90 degrees, 376.1 m: log.c's conversions of 52 mph and
 * 1234 ft. The comment's leading space is Dire Wolf's, kept. */
static void test_moving_station_line(void) {
    ASSERT_EQ(parse(L_MOVING), 1);
    ASSERT_EQ(g_p.dti, '=');
    ASSERT_STR(g_p.symbol, "/>");
    ASSERT_NEAR(g_p.lat, 10.205667, 1e-9);
    ASSERT_NEAR(g_p.lon, -20.535, 1e-9);
    ASSERT_EQ(g_p.has_speed, 1);
    ASSERT_NEAR(g_p.speed_kt, 45.0, 1e-9);
    ASSERT_NEAR(g_p.course, 90.0, 1e-9);
    ASSERT_NEAR(g_p.alt_m, 376.1, 1e-9);
    ASSERT_STR(g_p.system, "Generic, (obsolete. Digis should use APNxxx instead)");
    ASSERT_STR(g_p.comment, " moving");
}

/* A message (dti ':') has no position; the symbol "/ " is two bytes,
 * the second a space. */
static void test_message_line_no_position(void) {
    ASSERT_EQ(parse(L_MSG), 1);
    ASSERT_EQ(g_p.dti, ':');
    ASSERT_STR(g_p.symbol, "/ ");
    ASSERT_EQ(g_p.has_pos, 0);
    ASSERT_STR(g_p.comment, "hello");
}

/* quote_for_csv(): a '"' inside doubled, the whole field quoted; a
 * symbol whose code is ',' is quoted too; a heard digipeater differs
 * from the source; the other fields log.c can fill. */
static void test_quoting_and_digipeated(void) {
    ASSERT_EQ(parse("1,1793930100,2026-11-06T01:55:00Z,N0TEST-7,N0CALL-1,7(4/3),2,;,"
                    "TESTOBJ,\"/,\",10.500000,-20.500000,0.0,360.0,-12.5,146.520,+600,"
                    "D023,\"say \"\"hi\"\"\",\"En Route\",\"seq 7, a1\","
                    "\"a, \"\"quoted\"\" comment\""), 1);
    ASSERT_EQ(g_p.chan, 1);
    ASSERT_STR(g_p.source, "N0TEST-7");
    ASSERT_STR(g_p.heard, "N0CALL-1");
    ASSERT_EQ(g_p.level, 7);
    ASSERT_EQ(g_p.error, 2);
    ASSERT_EQ(g_p.dti, ';');
    ASSERT_STR(g_p.name, "TESTOBJ");
    ASSERT_STR(g_p.symbol, "/,");
    ASSERT_NEAR(g_p.speed_kt, 0.0, 1e-9);
    ASSERT_EQ(g_p.has_speed, 1);
    ASSERT_NEAR(g_p.course, 360.0, 1e-9);
    ASSERT_NEAR(g_p.alt_m, -12.5, 1e-9);
    ASSERT_STR(g_p.freq, "146.520");
    ASSERT_STR(g_p.offset, "+600");
    ASSERT_STR(g_p.tone, "D023");
    ASSERT_STR(g_p.system, "say \"hi\"");
    ASSERT_STR(g_p.status, "En Route");
    ASSERT_STR(g_p.telemetry, "seq 7, a1");
    ASSERT_STR(g_p.comment, "a, \"quoted\" comment");
    /* A dti that is itself a quote is quoted and doubled. */
    ASSERT_EQ(parse("0,1793930035,x,N0TEST,N0TEST,,,\"\"\"\",,,,,,,,,,,,,,"), 1);
    ASSERT_EQ(g_p.dti, '"');
    ASSERT_EQ(g_p.level, -1);      /* empty: absent, never 0 */
    ASSERT_EQ(g_p.error, -1);
    ASSERT_STR(g_p.heard, "N0TEST");
}

static void test_header_and_blank_skipped(void) {
    ASSERT_EQ(parse(HDR), 0);
    ASSERT_EQ(parse(""), 0);
    ASSERT_EQ(parse("   \r"), 0);
    /* A trailing CR is not part of the comment. */
    ASSERT_EQ(parse(L_FIXED "\r"), 1);
    ASSERT_STR(g_p.comment, "Test station");
}

/* Each of these is not a record Dire Wolf writes, and is refused whole. */
static void test_bad_lines_refused(void) {
    static const char *const bad[] = {
        /* 21 fields */
        "0,1793930035,x,N0TEST,N0TEST,50,0,!,N0TEST,/#,10.0,-20.0,,,,,,,,,",
        /* 23 fields */
        "0,1793930035,x,N0TEST,N0TEST,50,0,!,N0TEST,/#,10.0,-20.0,,,,,,,,,,,extra",
        /* a lower-case source, a 7-character base, a 3-character SSID, */
        "0,1793930035,x,n0test,,,,!,,,,,,,,,,,,,,",
        "0,1793930035,x,N0TESTX,,,,!,,,,,,,,,,,,,,",
        "0,1793930035,x,N0TEST-123,,,,!,,,,,,,,,,,,,,",
        /* an empty source, a bad heard, */
        "0,1793930035,x,,,,,!,,,,,,,,,,,,,,",
        "0,1793930035,x,N0TEST,WIDE1 1,,,!,,,,,,,,,,,,,,",
        /* utime out of range or not a number, a channel out of range, */
        "0,99,x,N0TEST,,,,!,,,,,,,,,,,,,,",
        "0,17939300x5,x,N0TEST,,,,!,,,,,,,,,,,,,,",
        "256,1793930035,x,N0TEST,,,,!,,,,,,,,,,,,,,",
        "-1,1793930035,x,N0TEST,,,,!,,,,,,,,,,,,,,",
        /* a quote not closed, a bare quote, text after a closing quote. */
        "0,1793930035,x,N0TEST,,,,!,,,,,,,,,,,,,,\"open",
        "0,1793930035,x,N0TEST,,,,!,,,,,,,,,,,,,,say \"hi\"",
        "0,1793930035,x,N0TEST,,,,!,,,,,,,,,,,,,,\"a\"b",
        /* The tail of a record a CR/LF in its comment split. */
        "split here\",,,",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ(parse(bad[i]), -1);
    /* Over APRS_MAX_LINE. */
    static char longl[APRS_MAX_LINE + 64];
    snprintf(longl, sizeof(longl), "%s", L_FIXED);
    size_t l = strlen(longl);
    memset(longl + l, 'x', sizeof(longl) - l - 1);
    longl[sizeof(longl) - 1] = '\0';
    ASSERT_EQ(parse(longl), -1);
}

/* A present field out of range or malformed is absent; the line stands. */
static void test_fields_out_of_range_absent(void) {
    ASSERT_EQ(parse("0,1793930035,x,N0TEST,N0TEST,500(1/1),1000,!!,LONGOBJECTNAME,/,"
                    "91.000000,-20.000000,2000.1,360.5,100000.1,14x,600,88.5Hz,,,,"), 1);
    ASSERT_EQ(g_p.level, 500);
    ASSERT_EQ(g_p.error, -1);
    ASSERT_EQ(g_p.dti, 0);
    ASSERT_STR(g_p.name, "");
    ASSERT_STR(g_p.symbol, "");
    ASSERT_EQ(g_p.has_pos, 0);
    ASSERT_EQ(g_p.has_speed, 0);
    ASSERT_EQ(g_p.has_course, 0);
    ASSERT_EQ(g_p.has_alt, 0);
    ASSERT_STR(g_p.freq, "");
    ASSERT_STR(g_p.tone, "");
    ASSERT_STR(g_p.offset, "600");
    /* lat without lon; numbers no "%f" writes (an exponent, two points). */
    ASSERT_EQ(parse("0,1793930035,x,N0TEST,,5x,,!,,/#,10.0,,1e2,1.2.3,-1000.1,,,,,,,"), 1);
    ASSERT_EQ(g_p.level, -1);
    ASSERT_EQ(g_p.has_pos, 0);
    ASSERT_EQ(g_p.has_speed, 0);
    ASSERT_EQ(g_p.has_course, 0);
    ASSERT_EQ(g_p.has_alt, 0);
    /* The edges themselves are kept. */
    ASSERT_EQ(parse("0,1793930035,x,N0TEST,,,,!,,/#,-90.000000,180.000000,2000.0,0.0,"
                    "-1000.0,,,,,,,"), 1);
    ASSERT_EQ(g_p.has_pos, 1);
    ASSERT_NEAR(g_p.lon, 180.0, 1e-9);
    ASSERT_EQ(g_p.has_speed + g_p.has_course + g_p.has_alt, 3);
}

/* Free text keeps printable ASCII; any other byte is '?'; cut at the
 * cap. The object name's trailing spaces (APRS101's 9-byte field) go. */
static void test_text_cleaned_and_capped(void) {
    char line[700], cm[300];
    memset(cm, 'c', 200);
    cm[200] = '\0';
    cm[0] = '\x01';
    cm[1] = (char)0xc2;
    cm[2] = (char)0xb0;
    snprintf(line, sizeof(line), "0,1793930035,x,N0TEST,,,,;,OBJ1     ,/#,,,,,,,,,"
             "%s,,,%s", "sys\ttab", cm);
    ASSERT_EQ(parse(line), 1);
    ASSERT_STR(g_p.name, "OBJ1");
    ASSERT_STR(g_p.system, "sys?tab");
    ASSERT_EQ((int)strlen(g_p.comment), APRS_COMMENT_MAX);
    ASSERT_EQ(g_p.comment[0], '?');
    ASSERT_EQ(g_p.comment[1], '?');
    ASSERT_EQ(g_p.comment[2], '?');
    ASSERT_EQ(g_p.comment[3], 'c');
}

static void test_call_rules(void) {
    ASSERT(aprs_call_ok("N0TEST"));
    ASSERT(aprs_call_ok("N0TEST-15"));
    ASSERT(aprs_call_ok("A"));
    ASSERT(aprs_call_ok("N0CALL-AB"));
    ASSERT(!aprs_call_ok(""));
    ASSERT(!aprs_call_ok("N0TEST-"));
    ASSERT(!aprs_call_ok("-5"));
    ASSERT(!aprs_call_ok("N0TEST-5-1"));
    ASSERT(!aprs_call_ok("N0TEST*"));
    ASSERT(!aprs_call_ok("WIDE1 1"));
    ASSERT(!aprs_call_ok(NULL));
}

static void test_spec_parse(void) {
    char p[256], e[200];
    ASSERT_EQ(aprs_spec_parse("/var/lib/direwolf/aprs.log", p, sizeof(p), e, sizeof(e)), 0);
    ASSERT_STR(p, "/var/lib/direwolf/aprs.log");
    ASSERT_EQ(aprs_spec_parse("file:///var/lib/direwolf/aprs.log", p, sizeof(p), e, sizeof(e)), 0);
    ASSERT_STR(p, "/var/lib/direwolf/aprs.log");
    ASSERT_EQ(aprs_spec_parse("file://host/aprs.log", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(aprs_spec_parse("kiss://127.0.0.1:8001", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT(strstr(e, "unsupported scheme") != NULL);
    ASSERT_EQ(aprs_spec_parse("aprs.log", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(aprs_spec_parse("", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(aprs_spec_parse("/var/lib/direwolf/", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(aprs_spec_parse("/a/b.log", p, 5, e, sizeof(e)), -1);   /* too long */
}

/* ── The table ─────────────────────────────────────────────────── */

static void feed(const char *line, uint64_t mono) {
    ASSERT_EQ(aprs_feed_line(line, strlen(line), 1793930035, mono), 1);
}

/* Keyed by source; a packet without a position keeps the old one; a
 * digipeated packet keeps heard_direct (ever) while via moves; the best
 * level is kept; an object moves neither the sender's position nor its
 * symbol or comment. Seen red with merge()'s object test removed (the
 * sender took the object's position). */
static void test_table_sticky_merge(void) {
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    feed(L_FIXED, 1000);
    feed("0,1793930040,x,N0TEST-5,N0CALL-1,30(1/1),0,>,N0TEST-5,,,,,,,,,,,,,on the air", 2000);
    feed("0,1793930050,x,N0TEST-5,N0CALL-1,20(1/1),0,;,TESTOBJ,/r,11.000000,-21.000000,"
         ",,,,,,,,,object note", 3000);
    aprs_health_poll(&s, 1793930050, 3000);
    ASSERT_EQ(s.aprs_count, 1);
    const aprs_station_t *a = &s.aprs_rows[0];
    ASSERT_STR(a->call, "N0TEST-5");
    ASSERT_EQ(a->packets, 3u);
    ASSERT_EQ((long long)a->first_seen, 1793930035LL);
    ASSERT_EQ((long long)a->last_seen, 1793930050LL);
    ASSERT_EQ(a->has_pos, 1);
    ASSERT_NEAR(a->lat, 10.0, 1e-9);
    ASSERT_NEAR(a->lon, -20.0, 1e-9);
    ASSERT_EQ((long long)a->pos_ts, 1793930035LL);
    ASSERT_STR(a->symbol, "/#");
    ASSERT_STR(a->comment, "on the air");
    ASSERT_STR(a->system, "DireWolf, WB2OSZ");
    ASSERT_STR(a->via, "N0CALL-1");
    ASSERT_EQ(a->last_direct, 0);
    ASSERT_EQ(a->heard_direct, 1);
    ASSERT_EQ(a->best_level, 50);
    ASSERT_EQ(a->level, 20);
    ASSERT_EQ(a->dti, ';');
    /* The ring: three packets, oldest first, seq 1..3, each with the
     * station's first_seen. */
    ASSERT_EQ(s.aprs_pkt_count, 3);
    ASSERT_EQ(s.aprs_pkts[0].seq, 1u);
    ASSERT_EQ(s.aprs_pkts[2].seq, 3u);
    ASSERT_STR(s.aprs_pkts[2].name, "TESTOBJ");
    ASSERT_EQ((long long)s.aprs_pkts[2].stn_first_seen, 1793930035LL);
    ASSERT_EQ(s.aprs.packets, 3u);
    ASSERT_EQ(s.aprs.lines, 3u);
    ASSERT_EQ((long long)s.aprs.last_packet, 1793930050LL);
    /* A new position replaces the speed, course and altitude with the
     * ones it came with, absent included. */
    feed(L_MOVING, 4000);
    feed("0,1793930060,x,N0TEST-9,N0TEST-9,,,!,N0TEST-9,/>,10.300000,-20.600000,,,,,,,,,,", 5000);
    aprs_health_poll(&s, 1793930060, 5000);
    ASSERT_EQ(s.aprs_count, 2);
    for (int i = 0; i < s.aprs_count; i++) {
        if (strcmp(s.aprs_rows[i].call, "N0TEST-9")) continue;
        ASSERT_NEAR(s.aprs_rows[i].lat, 10.3, 1e-9);
        ASSERT_EQ(s.aprs_rows[i].has_speed, 0);
        ASSERT_EQ(s.aprs_rows[i].has_alt, 0);
        ASSERT_STR(s.aprs_rows[i].comment, " moving");
    }
}

/* The ring keeps the newest APRS_PKT_RING packets, oldest first. */
static void test_packet_ring_bounded(void) {
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < APRS_PKT_RING + 10; i++) feed(L_FIXED, 1000 + (uint64_t)i);
    aprs_health_poll(&s, 1793930035, 2000);
    ASSERT_EQ(s.aprs_pkt_count, APRS_PKT_RING);
    ASSERT_EQ(s.aprs_pkts[0].seq, 11u);
    ASSERT_EQ(s.aprs_pkts[APRS_PKT_RING - 1].seq, (uint64_t)APRS_PKT_RING + 10);
}

/* A new call past APRS_MAX_STATIONS is refused and counted; its packet
 * still reaches the ring. */
static void test_station_cap(void) {
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char line[200];
    for (int i = 0; i < APRS_MAX_STATIONS + 3; i++) {
        snprintf(line, sizeof(line), "0,1793930035,x,N%dT,,,,!,,/#,,,,,,,,,,,,", i);
        feed(line, 1000);
    }
    aprs_health_poll(&s, 1793930035, 1000);
    ASSERT_EQ(s.aprs_count, APRS_MAX_STATIONS);
    ASSERT_EQ(s.aprs.overflow, 3u);
    ASSERT_EQ(s.aprs.stations, APRS_MAX_STATIONS);
    ASSERT_EQ(s.aprs_pkts[s.aprs_pkt_count - 1].stn_first_seen, 0);
}

/* A station unheard for APRS_EXPIRE_S (monotonic) is retired once, in
 * s->aprs_gone of that one poll; heard again it is a new visit. */
static void test_station_expires(void) {
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    feed(L_FIXED, 1000);
    aprs_health_poll(&s, 0, 1000 + (uint64_t)(APRS_EXPIRE_S - 1) * 1000u);
    ASSERT_EQ(s.aprs_count, 1);
    ASSERT_EQ(s.aprs_gone_count, 0);
    aprs_health_poll(&s, 0, 1000 + (uint64_t)APRS_EXPIRE_S * 1000u);
    ASSERT_EQ(s.aprs_count, 0);
    ASSERT_EQ(s.aprs_gone_count, 1);
    ASSERT_STR(s.aprs_gone[0].call, "N0TEST-5");
    ASSERT_EQ(s.aprs.expired, 1u);
    aprs_health_poll(&s, 0, 2000 + (uint64_t)APRS_EXPIRE_S * 1000u);
    ASSERT_EQ(s.aprs_gone_count, 0);
    feed("0,1793940000,x,N0TEST-5,N0TEST-5,,,!,,/#,,,,,,,,,,,,", 5000000);
    aprs_health_poll(&s, 0, 5000000);
    ASSERT_EQ((long long)s.aprs_rows[0].first_seen, 1793940000LL);
    ASSERT_EQ(s.aprs_rows[0].packets, 1u);
}

/* Not configured, waiting (never read, or the file missing), live,
 * error; a quiet hour is still live. */
static void test_states(void) {
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    aprs_health_poll(&s, 0, 0);
    ASSERT_EQ(s.aprs.state, APRS_NONE);
    aprs_set_source("file:/x");
    aprs_health_poll(&s, 0, 0);
    ASSERT_EQ(s.aprs.state, APRS_WAITING);
    aprs_note_missing();
    aprs_health_poll(&s, 0, 0);
    ASSERT_EQ(s.aprs.state, APRS_WAITING);
    ASSERT_EQ(s.aprs.missing, 1);
    ASSERT_EQ(s.aprs.read_errors, 0u);
    aprs_note_read(1793930000, 10, 0, 0);
    aprs_health_poll(&s, 1793930000, 1000);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    ASSERT_EQ(s.aprs.missing, 0);
    aprs_health_poll(&s, 1793933600, 3601000);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    aprs_note_read_error("read: Input/output error");
    aprs_health_poll(&s, 0, 0);
    ASSERT_EQ(s.aprs.state, APRS_ERROR);
    ASSERT_EQ(s.aprs.read_errors, 1u);
    aprs_note_read(1793930001, 0, 1, 0);
    aprs_health_poll(&s, 0, 0);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    ASSERT_STR(s.aprs.err, "");
    ASSERT_EQ(s.aprs.rotations, 1u);
}

/* The held cell: a wiggle inside the cell or across its edge by less
 * than APRS_CELL_HYST_DEG keeps the signature; a real move, a symbol
 * change and the first direct packet each change it; the packet count,
 * level and comment never do. Seen red with the raw latitude signed in
 * place of the cell, and with the hysteresis set to 0. */
static void test_signature_bands(void) {
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char l[256];
#define AT(lat, lon, sym, heard, cm) do { \
        snprintf(l, sizeof(l), "0,1793930035,x,N0TEST-9,%s,40,,!,,%s,%.6f,%.6f,,,,,,,,,,%s", \
                 heard, sym, lat, lon, cm); \
        feed(l, 1000); aprs_health_poll(&s, 0, 1000); } while (0)
    AT(10.0550, 20.0550, "/>", "N0CALL-1", "a");
    uint64_t s0 = aprs_station_sig(&s.aprs_rows[0]);
    AT(10.0551, 20.0558, "/>", "N0CALL-1", "b");      /* inside the cell */
    ASSERT_EQ(aprs_station_sig(&s.aprs_rows[0]), s0);
    AT(10.0605, 20.0550, "/>", "N0CALL-2", "c");      /* over the edge by < 0.001 */
    ASSERT_EQ(aprs_station_sig(&s.aprs_rows[0]), s0);
    AT(10.0595, 20.0550, "/>", "N0CALL-1", "d");      /* and back */
    ASSERT_EQ(aprs_station_sig(&s.aprs_rows[0]), s0);
    AT(10.0625, 20.0550, "/>", "N0CALL-1", "e");      /* a new cell */
    uint64_t s1 = aprs_station_sig(&s.aprs_rows[0]);
    ASSERT(s1 != s0);
    AT(10.0625, 20.0550, "/k", "N0CALL-1", "e");      /* a new symbol */
    uint64_t s2 = aprs_station_sig(&s.aprs_rows[0]);
    ASSERT(s2 != s1);
    AT(10.0625, 20.0550, "/k", "N0TEST-9", "e");      /* heard direct */
    ASSERT(aprs_station_sig(&s.aprs_rows[0]) != s2);
#undef AT
}

/* ── The reader against a real file ────────────────────────────── */

static char g_dir[TEST_TMP_MAX];
static char g_file[TEST_TMP_MAX + 32];

static void append(const char *path, const char *body) {
    FILE *fp = fopen(path, "a");     /* what Dire Wolf does */
    ASSERT(fp != NULL);
    if (!fp) return;
    fputs(body, fp);
    fclose(fp);
}

static int configure(void) {
    char spec[TEST_TMP_MAX + 48], err[200];
    snprintf(spec, sizeof(spec), "file://%s", g_file);
    aprs_reset();
    return aprs_reader_configure(spec, err, sizeof(err));
}

/* The first look at a file Dire Wolf already wrote skips its history;
 * then new lines, a partial line held for the next poll, blank lines,
 * an overlong line skipped to its newline and counted once, copytruncate
 * (size below the offset: from 0) and a rename rotation (a new inode:
 * from 0, the header skipped). Seen red with the seek-to-end removed
 * (the old line became a station) and with the truncation branch
 * removed (the shrunk file read nothing). */
static void test_reader_tails_a_file(void) {
    g_dir[0] = '\0';
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_aprs_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/aprs.log", g_dir);
    append(g_file, HDR "\n" L_FIXED "\n");
    ASSERT_EQ(configure(), 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));

    ASSERT_EQ(aprs_reader_poll_once(1793930100, 1000), 0);   /* at the end */
    aprs_health_poll(&s, 1793930100, 1000);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    ASSERT_EQ(s.aprs_count, 0);
    ASSERT_EQ(s.aprs.lines, 0u);

    append(g_file, "\n" L_MOVING "\n0,1793930040,x,N0TEST-1,N0TEST-1,,,!,,/#,10.");
    ASSERT(aprs_reader_poll_once(1793930101, 2000) > 0);
    aprs_health_poll(&s, 1793930101, 2000);
    ASSERT_EQ(s.aprs_count, 1);
    ASSERT_STR(s.aprs_rows[0].call, "N0TEST-9");
    ASSERT_EQ(s.aprs.lines, 1u);                  /* the blank line is none */
    append(g_file, "100000,-20.000000,,,,,,,,,,\n");
    ASSERT(aprs_reader_poll_once(1793930102, 3000) > 0);
    aprs_health_poll(&s, 1793930102, 3000);
    ASSERT_EQ(s.aprs_count, 2);
    ASSERT_EQ(s.aprs.packets, 2u);
    ASSERT_EQ(s.aprs.bad_lines, 0u);
    ASSERT_EQ(aprs_reader_poll_once(1793930103, 4000), 0);

    /* An overlong line, in two appends, then a good one. */
    static char big[APRS_MAX_LINE + 200];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    append(g_file, big);
    ASSERT(aprs_reader_poll_once(1793930104, 5000) > 0);
    append(g_file, big);
    append(g_file, "\n" L_MSG "\n");
    ASSERT(aprs_reader_poll_once(1793930105, 6000) > 0);
    aprs_health_poll(&s, 1793930105, 6000);
    ASSERT_EQ(s.aprs.bad_lines, 1u);
    ASSERT_EQ(s.aprs.packets, 3u);

    /* copytruncate: logrotate empties the file in place and Dire Wolf's
     * "a" stream writes on at the new end. */
    ASSERT_EQ(truncate(g_file, 0), 0);
    append(g_file, L_FIXED "\n");
    ASSERT(aprs_reader_poll_once(1793930106, 7000) > 0);
    aprs_health_poll(&s, 1793930106, 7000);
    ASSERT_EQ(s.aprs.truncations, 1u);
    ASSERT_EQ(s.aprs.packets, 4u);

    /* A rename rotation: a new file at the path, header first. */
    char old[TEST_TMP_MAX + 48];
    snprintf(old, sizeof(old), "%s.1", g_file);
    ASSERT_EQ(rename(g_file, old), 0);
    append(g_file, HDR "\n" L_MOVING "\n");
    ASSERT(aprs_reader_poll_once(1793930107, 8000) > 0);
    aprs_health_poll(&s, 1793930107, 8000);
    ASSERT_EQ(s.aprs.rotations, 1u);
    ASSERT_EQ(s.aprs.packets, 5u);
    ASSERT_EQ(s.aprs.bad_lines, 1u);
    unlink(old);

    /* Missing: waiting, nothing counted; the file that appears is new
     * and read from its start. */
    unlink(g_file);
    ASSERT_EQ(aprs_reader_poll_once(1793930108, 9000), -1);
    aprs_health_poll(&s, 1793930108, 9000);
    ASSERT_EQ(s.aprs.state, APRS_WAITING);
    ASSERT_EQ(s.aprs.read_errors, 0u);
    append(g_file, HDR "\n" L_MSG "\n");
    ASSERT(aprs_reader_poll_once(1793930109, 10000) > 0);
    aprs_health_poll(&s, 1793930109, 10000);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    ASSERT_EQ(s.aprs.packets, 6u);
    ASSERT_EQ(s.aprs.rotations, 1u);              /* appearing is no rotation */

    /* A directory where the file should be: an error, counted. */
    unlink(g_file);
    ASSERT_EQ(mkdir(g_file, 0700), 0);
    ASSERT_EQ(aprs_reader_poll_once(1793930110, 11000), -1);
    aprs_health_poll(&s, 1793930110, 11000);
    ASSERT_EQ(s.aprs.state, APRS_ERROR);
    ASSERT_STR(s.aprs.err, "not a regular file");
    ASSERT_EQ(s.aprs.read_errors, 1u);
    rmdir(g_file);
    aprs_reader_stop();
    rmdir(g_dir);
}

/* A file that is not there at the first poll is read from 0 when it
 * appears (Dire Wolf creates it with its first packet), and a backlog
 * over APRS_POLL_BYTES takes more than one poll. */
static void test_reader_new_file_and_cap(void) {
    g_dir[0] = '\0';
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_aprs_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/aprs.log", g_dir);
    ASSERT_EQ(configure(), 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(aprs_reader_poll_once(1793930100, 1000), -1);
    FILE *fp = fopen(g_file, "a");
    ASSERT(fp != NULL);
    if (!fp) return;
    fputs(HDR "\n", fp);
    int lines = 0;
    for (long b = 0; b < (long)APRS_POLL_BYTES + 4096; b += (long)sizeof(L_MOVING)) {
        fputs(L_MOVING "\n", fp);
        lines++;
    }
    fclose(fp);
    ASSERT_EQ(aprs_reader_poll_once(1793930101, 2000), (long)APRS_POLL_BYTES);
    ASSERT(aprs_reader_poll_once(1793930102, 3000) > 0);
    ASSERT_EQ(aprs_reader_poll_once(1793930103, 4000), 0);
    aprs_health_poll(&s, 1793930103, 4000);
    ASSERT_EQ(s.aprs.packets, (uint64_t)lines);
    ASSERT_EQ(s.aprs.bad_lines, 0u);
    ASSERT_EQ(s.aprs_count, 1);
    ASSERT_EQ(s.aprs_rows[0].packets, (uint32_t)lines);
    aprs_reader_stop();
    unlink(g_file);
    rmdir(g_dir);
}

/* ── The sensor registry ───────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t t_mono(void) { return g_mono; }
static time_t   t_wall(void) { return g_wall; }

static int find_sensor(const sloth_state_t *s) {
    for (int i = 0; i < s->sensor_count; i++)
        if (s->sensors[i].kind == SENSOR_APRS) return i;
    return -1;
}

static void test_sensor_registry_aprs(void) {
    g_wall = 1793930000; g_mono = 1000000;
    sloth_clock_test_set(t_mono, t_wall);
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(find_sensor(&s), -1);           /* nothing without --aprs */

    aprs_set_source("file:/var/lib/direwolf/aprs.log");
    aprs_note_missing();
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    int k = find_sensor(&s);
    ASSERT(k >= 0);
    if (k < 0) { sloth_clock_test_set(NULL, NULL); return; }
    ASSERT_STR(sensor_kind_name(s.sensors[k].kind), "aprs");
    ASSERT_STR(s.sensors[k].iface, "file:/var/lib/direwolf/aprs.log");
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_PRESENT);   /* missing is no error */

    aprs_note_read(g_wall, 0, 0, 0);
    feed(L_FIXED, g_mono);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    ASSERT_EQ(s.sensors[k].observed, 1u);

    aprs_note_read_error("open: Permission denied");
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ERROR);
    aprs_note_read(g_wall, 0, 0, 0);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    sloth_clock_test_set(NULL, NULL);
    aprs_reset();
}

/* ── JSONL ─────────────────────────────────────────────────────── */

static char g_jl[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_aprs_jl_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jl);
    ASSERT(jsonl_open(g_jl));
}

static char *read_all(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int count_of(const char *b, const char *needle) {
    int n = 0;
    for (const char *p = b; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

static void tick(sloth_state_t *s) {
    g_wall++; g_mono += 1000;
    aprs_health_poll(s, g_wall, g_mono);
    jsonl_emit_aprs(s);
}

/* aprs_packet: one record per packet, each once however many ticks
 * pass, every absent field omitted (no "lat":0, no "comment":"").
 * aprs_station: change-only - a station heard ten times from one spot
 * is one record; a move to a new cell is one more; expiry is one
 * "gone". Seen red with the packet cursor not advanced (each packet
 * once per tick) and with the packet count signed in
 * aprs_station_sig() (a record per packet). */
static void test_jsonl_packets_and_stations(void) {
    g_wall = 1793930000; g_mono = 2000000;
    sloth_clock_test_set(t_mono, t_wall);
    aprs_reset();
    aprs_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    feed(L_MSG, g_mono);
    tick(&s);
    tick(&s);
    for (int i = 0; i < 10; i++) { feed(L_FIXED, g_mono); tick(&s); }
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_packet\""), 11);
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_station\""), 2);
        ASSERT(strstr(b, "\"src\":\"file:/x\",\"seq\":1,\"chan\":0,\"utime\":1793930035,"
                         "\"source\":\"N0TEST-1\",\"heard\":\"N0TEST-1\",\"direct\":1,"
                         "\"level\":50,\"error\":0,\"dti\":\":\",\"name\":\"N0TEST-1\","
                         "\"symbol\":\"/ \",\"system\":\"Generic, (obsolete. Digis should "
                         "use APNxxx instead)\",\"comment\":\"hello\"}") != NULL);
        ASSERT(strstr(b, "\"lat\":10.000000,\"lon\":-20.000000,\"system\":"
                         "\"DireWolf, WB2OSZ\",\"comment\":\"Test station\"}") != NULL);
        ASSERT(strstr(b, "\"lat\":0") == NULL);
        ASSERT(strstr(b, "\"speed_kt\"") == NULL);
        ASSERT(strstr(b, "\"status\"") == NULL);
        ASSERT(strstr(b, "\"call\":\"N0TEST-5\",\"state\":\"live\",\"src\":\"file:/x\","
                         "\"first_seen\":1793930035,\"last_seen\":1793930035,"
                         "\"packets\":1,\"via\":\"N0TEST-5\",\"direct\":1,"
                         "\"heard_direct\":1,\"level\":50,\"best_level\":50,"
                         "\"dti\":\"!\",\"symbol\":\"/#\",\"lat\":10.000000,"
                         "\"lon\":-20.000000,\"pos_ts\":1793930035,") != NULL);
    }
    unlink(g_jl);

    jl_open();   /* a fresh sink re-baselines the stations, no old packets */
    tick(&s);
    feed("0,1793930100,x,N0TEST-5,N0TEST-5,,,!,,/#,10.500000,-20.000000,,,,,,,,,,", g_mono);
    tick(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_packet\""), 1);
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_station\""), 3);
        ASSERT_EQ(count_of(b, "\"lat\":10.500000"), 2);
    }
    unlink(g_jl);

    /* Unheard: nothing until APRS_EXPIRE_S, then one "gone" each. */
    jl_open();
    g_wall += APRS_EXPIRE_S; g_mono += (uint64_t)APRS_EXPIRE_S * 1000u;
    tick(&s);
    tick(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_station\""), 2);
        ASSERT_EQ(count_of(b, "\"state\":\"gone\""), 2);
        ASSERT_EQ(count_of(b, "\"type\":\"aprs_packet\""), 0);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    aprs_reset();
}

/* sensor_health carries aprs_* only with --aprs, and signs the state and
 * none/some bands, never the counters: ten seconds of packets and reads
 * are no line, a read error is one. Seen red with aprs_packets signed
 * raw (a line per packet). */
static void test_sensor_health_aprs_block(void) {
    g_wall = 1793930000; g_mono = 3000000;
    sloth_clock_test_set(t_mono, t_wall);
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    aprs_health_poll(&s, g_wall, g_mono);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"type\":\"sensor_health\"") != NULL);
        ASSERT(strstr(b, "\"aprs_") == NULL);
    }
    unlink(g_jl);

    aprs_set_source("file:/x");
    jl_open();
    for (int i = 0; i < 10; i++) {
        g_wall++; g_mono += 1000;
        aprs_note_read(g_wall, 100, 0, 0);
        feed(L_FIXED, g_mono);
        aprs_health_poll(&s, g_wall, g_mono);
        jsonl_emit_sensor_health(&s);
    }
    g_wall++; g_mono += 1000;
    aprs_note_read_error("read: Input/output error");
    aprs_health_poll(&s, g_wall, g_mono);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"sensor_health\""), 2);
        ASSERT(strstr(b, "\"aprs_state\":\"live\",\"aprs_src\":\"file:/x\","
                         "\"aprs_missing\":0,\"aprs_last_read\":1793930001,"
                         "\"aprs_last_packet\":1793930035,\"aprs_stations\":1,"
                         "\"aprs_bytes\":100,\"aprs_lines\":1,\"aprs_packets\":1,"
                         "\"aprs_bad_lines\":0,\"aprs_overflow\":0,\"aprs_expired\":0,"
                         "\"aprs_truncations\":0,\"aprs_rotations\":0,"
                         "\"aprs_read_errors\":0,\"aprs_err\":\"\"") != NULL);
        ASSERT(strstr(b, "\"aprs_state\":\"error\"") != NULL);
        ASSERT(strstr(b, "\"aprs_err\":\"read: Input/output error\"") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    aprs_reset();
}

/* ── The region, the declared frequency, the silent decoder (#204) ──
 *
 * The points are city centres and open sea picked to sit inside a
 * region or on either side of a box edge; none is a sensor's position.
 * An edge is inclusive, so each edge is tested on it and 0.01 degree
 * outside.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the no-fix case with aprs_region_of()'s !has_fix test
 * removed (a stale 0,0 or an old position read as a region); silent
 * outside live with the APRS_LIVE term dropped (an error read as
 * silent); the position kept out of the sensor_health block with a
 * loc_lat member added to it. */

#define R(lat, lon) aprs_region_of(1, (lat), (lon))

static void test_region_no_fix(void) {
    ASSERT_EQ(aprs_region_of(0, 41.9, -87.6), APRS_REGION_NONE);
    ASSERT_EQ(aprs_region_of(0, 0.0, 0.0), APRS_REGION_NONE);
    ASSERT_EQ(R(NAN, -87.6), APRS_REGION_NONE);
    ASSERT_EQ(R(90.01, 0.0), APRS_REGION_NONE);
    ASSERT_EQ(R(0.0, -180.01), APRS_REGION_NONE);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_NONE), 0u);
    ASSERT_STR(aprs_region_name(APRS_REGION_NONE), "none");
    ASSERT_STR(aprs_region_name(99), "none");
    /* A position in no box: no default frequency. */
    ASSERT_EQ(R(39.9, 116.4), APRS_REGION_UNKNOWN);      /* Beijing */
    ASSERT_EQ(R(28.6, 77.2), APRS_REGION_UNKNOWN);       /* Delhi */
    ASSERT_EQ(R(0.0, -150.0), APRS_REGION_UNKNOWN);      /* mid-Pacific */
    ASSERT_EQ(aprs_region_hz(APRS_REGION_UNKNOWN), 0u);
    ASSERT_STR(aprs_region_name(APRS_REGION_UNKNOWN), "unknown");
}

static void test_region_table(void) {
    ASSERT_EQ(aprs_region_hz(APRS_REGION_NA), 144390000u);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_IARU1), 144800000u);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_AU), 145175000u);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_NZ), 144575000u);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_JP), 144640000u);
    ASSERT_EQ(aprs_region_hz(APRS_REGION_BR), 145570000u);
    ASSERT_STR(aprs_region_name(APRS_REGION_NA), "north-america");
    ASSERT_STR(aprs_region_name(APRS_REGION_IARU1), "iaru-r1");
    ASSERT_STR(aprs_region_name(APRS_REGION_AU), "australia");
    ASSERT_STR(aprs_region_name(APRS_REGION_NZ), "new-zealand");
    ASSERT_STR(aprs_region_name(APRS_REGION_JP), "japan");
    ASSERT_STR(aprs_region_name(APRS_REGION_BR), "brazil");
}

static void test_region_north_america(void) {
    ASSERT_EQ(R(41.9, -87.6), APRS_REGION_NA);           /* Chicago */
    ASSERT_EQ(R(21.3, -157.8), APRS_REGION_NA);          /* Honolulu */
    ASSERT_EQ(R(61.2, -149.9), APRS_REGION_NA);          /* Anchorage */
    ASSERT_EQ(R(19.4, -99.1), APRS_REGION_NA);           /* Mexico City */
    ASSERT_EQ(R(14.0, -90.0), APRS_REGION_NA);           /* the south edge */
    ASSERT_EQ(R(13.99, -90.0), APRS_REGION_UNKNOWN);
    ASSERT_EQ(R(47.5, -50.0), APRS_REGION_NA);           /* the east edge */
    ASSERT_EQ(R(47.5, -49.99), APRS_REGION_UNKNOWN);
    ASSERT_EQ(R(72.0, -100.0), APRS_REGION_NA);          /* the north edge */
    ASSERT_EQ(R(72.01, -100.0), APRS_REGION_UNKNOWN);
}

static void test_region_iaru1(void) {
    ASSERT_EQ(R(51.5, -0.1), APRS_REGION_IARU1);         /* London */
    ASSERT_EQ(R(-26.2, 28.0), APRS_REGION_IARU1);        /* Johannesburg */
    ASSERT_EQ(R(55.75, 37.6), APRS_REGION_IARU1);        /* Moscow */
    ASSERT_EQ(R(55.0, 82.9), APRS_REGION_IARU1);         /* Novosibirsk */
    ASSERT_EQ(R(37.74, -25.67), APRS_REGION_IARU1);      /* Ponta Delgada */
    ASSERT_EQ(R(0.0, -25.0), APRS_REGION_IARU1);         /* the west edge */
    ASSERT_EQ(R(0.0, -25.01), APRS_REGION_UNKNOWN);
    ASSERT_EQ(R(-35.0, 20.0), APRS_REGION_IARU1);        /* the south edge */
    ASSERT_EQ(R(-35.01, 20.0), APRS_REGION_UNKNOWN);
    ASSERT_EQ(R(45.0, 60.0), APRS_REGION_IARU1);         /* the east edge */
    ASSERT_EQ(R(45.0, 60.01), APRS_REGION_UNKNOWN);      /* under the Russia box */
    ASSERT_EQ(R(50.0, 100.0), APRS_REGION_IARU1);        /* the Russia box's edge */
    ASSERT_EQ(R(49.99, 100.0), APRS_REGION_UNKNOWN);
}

static void test_region_australia_nz(void) {
    ASSERT_EQ(R(-33.87, 151.2), APRS_REGION_AU);         /* Sydney */
    ASSERT_EQ(R(-31.95, 115.86), APRS_REGION_AU);        /* Perth */
    ASSERT_EQ(R(-42.9, 147.3), APRS_REGION_AU);          /* Hobart */
    ASSERT_EQ(R(-10.0, 142.0), APRS_REGION_AU);          /* Cape York */
    ASSERT_EQ(R(-9.99, 142.0), APRS_REGION_UNKNOWN);     /* Torres Strait, PNG side */
    ASSERT_EQ(R(-40.0, 160.0), APRS_REGION_AU);          /* the east edge */
    ASSERT_EQ(R(-40.0, 160.01), APRS_REGION_UNKNOWN);    /* the Tasman Sea */
    ASSERT_EQ(R(-41.29, 174.78), APRS_REGION_NZ);        /* Wellington */
    ASSERT_EQ(R(-36.85, 174.76), APRS_REGION_NZ);        /* Auckland */
    ASSERT_EQ(R(-43.95, -176.55), APRS_REGION_NZ);       /* the Chathams */
    ASSERT_EQ(R(-40.0, 165.0), APRS_REGION_NZ);          /* the west edge */
    ASSERT_EQ(R(-40.0, 164.99), APRS_REGION_UNKNOWN);
    ASSERT_EQ(R(-40.0, -175.0), APRS_REGION_NZ);         /* past the antimeridian */
    ASSERT_EQ(R(-40.0, -174.99), APRS_REGION_UNKNOWN);
}

static void test_region_japan(void) {
    ASSERT_EQ(R(35.68, 139.69), APRS_REGION_JP);         /* Tokyo */
    ASSERT_EQ(R(43.06, 141.35), APRS_REGION_JP);         /* Sapporo */
    ASSERT_EQ(R(45.4, 141.7), APRS_REGION_JP);           /* Wakkanai */
    ASSERT_EQ(R(33.59, 130.40), APRS_REGION_JP);         /* Fukuoka */
    ASSERT_EQ(R(26.21, 127.68), APRS_REGION_JP);         /* Naha */
    ASSERT_EQ(R(37.57, 126.98), APRS_REGION_UNKNOWN);    /* Seoul */
    ASSERT_EQ(R(35.18, 129.08), APRS_REGION_UNKNOWN);    /* Busan */
    ASSERT_EQ(R(43.12, 131.89), APRS_REGION_UNKNOWN);    /* Vladivostok */
    ASSERT_EQ(R(25.03, 121.56), APRS_REGION_UNKNOWN);    /* Taipei */
    ASSERT_EQ(R(24.4, 122.9), APRS_REGION_JP);           /* the Ryukyus' west edge */
    ASSERT_EQ(R(24.4, 122.89), APRS_REGION_UNKNOWN);
}

static void test_region_brazil(void) {
    ASSERT_EQ(R(-23.55, -46.63), APRS_REGION_BR);        /* Sao Paulo */
    ASSERT_EQ(R(-15.79, -47.88), APRS_REGION_BR);        /* Brasilia */
    ASSERT_EQ(R(-3.12, -60.02), APRS_REGION_BR);         /* Manaus */
    ASSERT_EQ(R(-30.03, -51.23), APRS_REGION_BR);        /* Porto Alegre */
    ASSERT_EQ(R(-8.05, -34.9), APRS_REGION_BR);          /* Recife */
    ASSERT_EQ(R(-8.05, -34.69), APRS_REGION_UNKNOWN);    /* the Atlantic */
    ASSERT_EQ(R(-34.6, -58.4), APRS_REGION_UNKNOWN);     /* Buenos Aires */
    ASSERT_EQ(R(-33.45, -70.67), APRS_REGION_UNKNOWN);   /* Santiago */
    ASSERT_EQ(R(-12.05, -77.04), APRS_REGION_UNKNOWN);   /* Lima */
    ASSERT_EQ(R(-34.0, -50.0), APRS_REGION_BR);          /* the south edge */
    ASSERT_EQ(R(-34.01, -50.0), APRS_REGION_UNKNOWN);
}

#undef R

static void test_freq_parse_and_mismatch(void) {
    uint32_t f = 0;
    ASSERT_EQ(aprs_freq_parse("144390000", &f), 0);
    ASSERT_EQ(f, 144390000u);
    ASSERT_EQ(aprs_freq_parse("144000000", &f), 0);
    ASSERT_EQ(aprs_freq_parse("148000000", &f), 0);
    ASSERT_EQ(aprs_freq_parse("143999999", &f), -1);
    ASSERT_EQ(aprs_freq_parse("148000001", &f), -1);
    ASSERT_EQ(aprs_freq_parse("144.390", &f), -1);       /* Hz, not MHz */
    ASSERT_EQ(aprs_freq_parse("144390000 ", &f), -1);
    ASSERT_EQ(aprs_freq_parse("+144390000", &f), -1);
    ASSERT_EQ(aprs_freq_parse("", &f), -1);
    ASSERT_EQ(aprs_freq_parse("99999999999", &f), -1);
    ASSERT_EQ(aprs_freq_parse(NULL, &f), -1);
    ASSERT_EQ(f, 148000000u);                            /* refusals leave it */

    ASSERT_EQ(aprs_freq_mismatch(0, 144390000u), 0);     /* not declared */
    ASSERT_EQ(aprs_freq_mismatch(144390000u, 0), 0);     /* no region */
    ASSERT_EQ(aprs_freq_mismatch(144390000u, 144390000u), 0);
    ASSERT_EQ(aprs_freq_mismatch(144390000u + APRS_FREQ_TOL_HZ, 144390000u), 0);
    ASSERT_EQ(aprs_freq_mismatch(144390000u - APRS_FREQ_TOL_HZ, 144390000u), 0);
    ASSERT_EQ(aprs_freq_mismatch(144390000u + APRS_FREQ_TOL_HZ + 1, 144390000u), 1);
    ASSERT_EQ(aprs_freq_mismatch(144390000u - APRS_FREQ_TOL_HZ - 1, 144390000u), 1);
    ASSERT_EQ(aprs_freq_mismatch(144800000u, 144390000u), 1);
    /* rx_fm's hardware tune (fs/4 above) is not what this compares. */
    ASSERT_EQ(aprs_freq_mismatch(144894000u, 144390000u), 1);
}

/* The region follows this tick's position and is held through a loss
 * of it; only the region and its Hz reach the health. A declared
 * frequency off the region's channel is a mismatch. */
static void test_health_region_and_mismatch(void) {
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    aprs_set_source("file:/x");
    aprs_set_expect(144800000u, APRS_SILENT_S_DEFAULT);
    aprs_health_poll(&s, 1793930000, 1000);
    ASSERT_EQ(s.aprs.region, APRS_REGION_NONE);
    ASSERT_EQ(s.aprs.region_hz, 0u);
    ASSERT_EQ(s.aprs.freq_hz, 144800000u);
    ASSERT_EQ(s.aprs.freq_mismatch, 0);                  /* nothing to judge */

    s.gps.has_loc = 1; s.gps.loc_lat = 41.9; s.gps.loc_lon = -87.6;
    aprs_health_poll(&s, 1793930001, 2000);
    ASSERT_EQ(s.aprs.region, APRS_REGION_NA);
    ASSERT_EQ(s.aprs.region_hz, 144390000u);
    ASSERT_EQ(s.aprs.freq_mismatch, 1);

    s.gps.has_loc = 0;                                   /* the fix is lost */
    aprs_health_poll(&s, 1793930002, 3000);
    ASSERT_EQ(s.aprs.region, APRS_REGION_NA);            /* held */
    ASSERT_EQ(s.aprs.freq_mismatch, 1);

    s.gps.has_loc = 1; s.gps.loc_lat = 51.5; s.gps.loc_lon = -0.1;
    aprs_health_poll(&s, 1793930003, 4000);
    ASSERT_EQ(s.aprs.region, APRS_REGION_IARU1);
    ASSERT_EQ(s.aprs.freq_mismatch, 0);

    aprs_set_expect(0, APRS_SILENT_S_DEFAULT);           /* none declared */
    aprs_health_poll(&s, 1793930004, 5000);
    ASSERT_EQ(s.aprs.freq_hz, 0u);
    ASSERT_EQ(s.aprs.freq_mismatch, 0);

    aprs_reset();                                        /* forgets the region */
    s.gps.has_loc = 0;
    aprs_health_poll(&s, 1793930005, 6000);
    ASSERT_EQ(s.aprs.region, APRS_REGION_NONE);
    ASSERT_EQ(s.aprs.silent_after_s, APRS_SILENT_S_DEFAULT);
}

/* Silent: live, and no packet for the threshold, counted from the
 * newest packet or this run's first read, whichever is later. Never
 * while waiting or in error, never with the threshold 0. */
static void test_health_silent(void) {
    const time_t t0 = 1793930000;
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    aprs_set_source("file:/x");
    aprs_health_poll(&s, t0 + 7 * 3600, 1000);
    ASSERT_EQ(s.aprs.state, APRS_WAITING);
    ASSERT_EQ(s.aprs.silent, 0);                         /* never read */
    ASSERT_EQ((long long)s.aprs.quiet_since, 0LL);

    aprs_note_read(t0, 0, 0, 0);                         /* an empty log */
    aprs_health_poll(&s, t0 + APRS_SILENT_S_DEFAULT - 1, 2000);
    ASSERT_EQ(s.aprs.state, APRS_LIVE);
    ASSERT_EQ((long long)s.aprs.quiet_since, (long long)t0);
    ASSERT_EQ(s.aprs.silent, 0);
    aprs_health_poll(&s, t0 + APRS_SILENT_S_DEFAULT, 3000);
    ASSERT_EQ(s.aprs.silent, 1);

    /* A packet re-arms it from its own time. */
    aprs_packet_t p;
    ASSERT_EQ(aprs_line_parse(L_FIXED, strlen(L_FIXED), &p), 1);
    p.utime = t0 + APRS_SILENT_S_DEFAULT;
    aprs_feed_packet(&p, p.utime, 4000);
    aprs_health_poll(&s, t0 + APRS_SILENT_S_DEFAULT + 60, 5000);
    ASSERT_EQ((long long)s.aprs.quiet_since, (long long)p.utime);
    ASSERT_EQ(s.aprs.silent, 0);
    aprs_health_poll(&s, p.utime + APRS_SILENT_S_DEFAULT, 6000);
    ASSERT_EQ(s.aprs.silent, 1);

    /* An error is said by the state, not by silent. */
    aprs_note_read_error("read: Input/output error");
    aprs_health_poll(&s, p.utime + APRS_SILENT_S_DEFAULT, 7000);
    ASSERT_EQ(s.aprs.state, APRS_ERROR);
    ASSERT_EQ(s.aprs.silent, 0);
    aprs_note_read(p.utime + 1, 0, 0, 0);

    /* The threshold is the flag's; 0 turns it off. */
    aprs_set_expect(0, 3600);
    aprs_health_poll(&s, p.utime + 3600, 8000);
    ASSERT_EQ(s.aprs.silent_after_s, 3600);
    ASSERT_EQ(s.aprs.silent, 1);
    aprs_set_expect(0, 0);
    aprs_health_poll(&s, p.utime + 30 * 86400, 9000);
    ASSERT_EQ(s.aprs.silent_after_s, 0);
    ASSERT_EQ(s.aprs.silent, 0);

    /* A decoder clock ahead of the host is not quiet yet. */
    aprs_set_expect(0, 3600);
    p.utime = t0 + 40 * 86400;
    aprs_feed_packet(&p, p.utime, 10000);
    aprs_health_poll(&s, t0 + 39 * 86400, 11000);
    ASSERT_EQ(s.aprs.silent, 0);
    aprs_reset();
}

/* The additive sensor_health fields: region and Hz, the declared
 * frequency, the two findings, the threshold and quiet_since, after the
 * twin193 block and before db_max_mb. Never the position in them; a
 * silent flip is a line of its own (it is signed), quiet_since is not. */
static void test_sensor_health_region_fields(void) {
    g_wall = 1793930000; g_mono = 3000000;
    sloth_clock_test_set(t_mono, t_wall);
    aprs_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    aprs_set_source("file:/x");
    aprs_set_expect(144800000u, 3600);
    s.gps.has_loc = 1; s.gps.loc_lat = 41.9; s.gps.loc_lon = -87.6;
    jl_open();
    aprs_note_read(g_wall, 0, 0, 0);
    aprs_health_poll(&s, g_wall, g_mono);
    jsonl_emit_sensor_health(&s);
    for (int i = 0; i < 3601; i++) {                     /* one quiet hour */
        g_wall++; g_mono += 1000;
        aprs_note_read(g_wall, 0, 0, 0);
        aprs_health_poll(&s, g_wall, g_mono);
        jsonl_emit_sensor_health(&s);
    }
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        /* The first line, then the silent flip; the 300 s heartbeat
         * lines between them. */
        ASSERT(strstr(b, "\"aprs_region\":\"north-america\","
                         "\"aprs_region_hz\":144390000,"
                         "\"aprs_freq_hz\":144800000,"
                         "\"aprs_freq_mismatch\":1,\"aprs_silent\":0,"
                         "\"aprs_silent_after_s\":3600,"
                         "\"aprs_quiet_since\":1793930000,\"db_max_mb\":") != NULL);
        ASSERT(strstr(b, "\"aprs_silent\":1,\"aprs_silent_after_s\":3600,"
                         "\"aprs_quiet_since\":1793930000,") != NULL);
        ASSERT(strstr(b, "\"twin193_excl_any\":0,\"aprs_region\":") != NULL);
        ASSERT(count_of(b, "\"type\":\"sensor_health\"") <= 3601 / 300 + 2);
        /* The block carries no position of its own. */
        const char *rg = strstr(b, "\"aprs_region\"");
        const char *end = rg ? strstr(rg, "\"db_max_mb\"") : NULL;
        ASSERT(rg && end);
        if (rg && end) {
            char blk[512];
            size_t n = (size_t)(end - rg) < sizeof(blk) - 1 ? (size_t)(end - rg)
                                                            : sizeof(blk) - 1;
            memcpy(blk, rg, n);
            blk[n] = '\0';
            ASSERT(strstr(blk, "lat") == NULL);
            ASSERT(strstr(blk, "lon") == NULL);
            ASSERT(strstr(blk, "41.9") == NULL);
        }
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    aprs_reset();
}

void run_aprs_tests(void) {
    TEST_SUITE("aprs — Dire Wolf's packet log (2026-11-05)");
    RUN_TEST(test_fixed_station_line);
    RUN_TEST(test_moving_station_line);
    RUN_TEST(test_message_line_no_position);
    RUN_TEST(test_quoting_and_digipeated);
    RUN_TEST(test_header_and_blank_skipped);
    RUN_TEST(test_bad_lines_refused);
    RUN_TEST(test_fields_out_of_range_absent);
    RUN_TEST(test_text_cleaned_and_capped);
    RUN_TEST(test_call_rules);
    RUN_TEST(test_spec_parse);
    RUN_TEST(test_table_sticky_merge);
    RUN_TEST(test_packet_ring_bounded);
    RUN_TEST(test_station_cap);
    RUN_TEST(test_station_expires);
    RUN_TEST(test_states);
    RUN_TEST(test_signature_bands);
    RUN_TEST(test_reader_tails_a_file);
    RUN_TEST(test_reader_new_file_and_cap);
    RUN_TEST(test_sensor_registry_aprs);
    RUN_TEST(test_jsonl_packets_and_stations);
    RUN_TEST(test_sensor_health_aprs_block);
    RUN_TEST(test_region_no_fix);
    RUN_TEST(test_region_table);
    RUN_TEST(test_region_north_america);
    RUN_TEST(test_region_iaru1);
    RUN_TEST(test_region_australia_nz);
    RUN_TEST(test_region_japan);
    RUN_TEST(test_region_brazil);
    RUN_TEST(test_freq_parse_and_mismatch);
    RUN_TEST(test_health_region_and_mismatch);
    RUN_TEST(test_health_silent);
    RUN_TEST(test_sensor_health_region_fields);
}
