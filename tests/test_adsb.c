#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "adsb.h"
#include "capture/adsb_reader.h"
#include "jsonl.h"
#include "poll.h"
#include "sensors.h"
#include "sloth_clock.h"

/* --adsb (#26 slice 1, 2026-11-05).
 *
 * Every document here is written by hand from readsb's README-json.md
 * (the aircraft.json section: "now", "messages", "aircraft", and the
 * per-aircraft keys, which "will be omitted if data is not available").
 * The addresses, callsigns, squawks and positions are invented; none
 * is from a receiver. No capture, no decoder, no parser output fed back
 * in. */

#define S(lit) lit, sizeof(lit) - 1

static adsb_doc_t g_doc;   /* ~50 KB: off the stack */

static int parse(const char *s) { return adsb_doc_parse(s, strlen(s), &g_doc); }

/* ── The document ──────────────────────────────────────────────── */

static void test_minimal_hex_only(void) {
    ASSERT_EQ(parse("{\"now\":1800000000.5,\"messages\":1234,"
                    "\"aircraft\":[{\"hex\":\"a0b1c2\"}]}"), 0);
    ASSERT_EQ(g_doc.has_now, 1);
    ASSERT_NEAR(g_doc.now, 1800000000.5, 1e-3);
    ASSERT_EQ(g_doc.has_messages, 1);
    ASSERT_EQ(g_doc.messages, 1234u);
    ASSERT_EQ(g_doc.n, 1);
    ASSERT_EQ(g_doc.bad, 0);
    const adsb_aircraft_t *a = &g_doc.ac[0];
    ASSERT_EQ(a->icao, 0xa0b1c2u);
    ASSERT_EQ(a->non_icao, 0);
    ASSERT_STR(a->type, "");
    ASSERT_STR(a->flight, "");
    ASSERT_STR(a->squawk, "");
    ASSERT_EQ(a->emergency, ADSB_EMERG_ABSENT);
    ASSERT_EQ(a->has_alt_baro + a->has_alt_geom + a->has_gs + a->has_track +
              a->has_pos + a->has_rssi + a->has_seen + a->on_ground, 0);
}

/* Every key the slice keeps, in the README's units, among keys it does
 * not keep (ias, mach, nav_modes, nic, ...). */
static void test_full_position_and_velocity(void) {
    ASSERT_EQ(parse(
        "{ \"now\" : 1800000001.0,\n"
        "  \"messages\" : 987654,\n"
        "  \"aircraft\" : [\n"
        "{\"hex\":\"C0FFEE\",\"type\":\"adsb_icao\",\"flight\":\"SYN001  \","
        "\"alt_baro\":35000,\"alt_geom\":35675,\"gs\":451.3,\"ias\":270,"
        "\"mach\":0.792,\"track\":87.25,\"baro_rate\":-64,\"geom_rate\":32,"
        "\"squawk\":\"2741\",\"emergency\":\"none\",\"category\":\"A3\","
        "\"nav_modes\":[\"autopilot\",\"vnav\"],\"lat\":10.054321,"
        "\"lon\":-20.012345,\"nic\":8,\"rc\":186,\"seen_pos\":0.4,"
        "\"version\":2,\"mlat\":[],\"tisb\":[],\"messages\":512,"
        "\"seen\":0.1,\"rssi\":-12.7}\n"
        "  ]\n}\n"), 0);
    ASSERT_EQ(g_doc.n, 1);
    const adsb_aircraft_t *a = &g_doc.ac[0];
    ASSERT_EQ(a->icao, 0xc0ffeeu);
    ASSERT_STR(a->type, "adsb_icao");
    ASSERT_STR(a->flight, "SYN001");
    ASSERT_EQ(a->has_alt_baro, 1);
    ASSERT_EQ(a->alt_baro, 35000);
    ASSERT_EQ(a->alt_geom, 35675);
    ASSERT_NEAR(a->gs, 451.3, 1e-9);
    ASSERT_NEAR(a->track, 87.25, 1e-9);
    ASSERT_EQ(a->baro_rate, -64);
    ASSERT_EQ(a->geom_rate, 32);
    ASSERT_STR(a->squawk, "2741");
    ASSERT_EQ(a->emergency, ADSB_EMERG_NONE);
    ASSERT_STR(a->category, "A3");
    ASSERT_EQ(a->has_pos, 1);
    ASSERT_NEAR(a->lat, 10.054321, 1e-9);
    ASSERT_NEAR(a->lon, -20.012345, 1e-9);
    ASSERT_NEAR(a->seen_pos, 0.4, 1e-9);
    ASSERT_NEAR(a->seen, 0.1, 1e-9);
    ASSERT_NEAR(a->rssi, -12.7, 1e-9);
    ASSERT_EQ(a->messages, 512u);
    ASSERT_EQ(a->on_ground, 0);
}

static void test_missing_and_null_fields(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",\"flight\":null,"
                    "\"alt_baro\":null,\"gs\":null,\"squawk\":null,"
                    "\"lat\":null,\"lon\":-20.5,\"emergency\":null}]}"), 0);
    ASSERT_EQ(g_doc.has_now, 0);
    ASSERT_EQ(g_doc.has_messages, 0);
    ASSERT_EQ(g_doc.n, 1);
    const adsb_aircraft_t *a = &g_doc.ac[0];
    ASSERT_STR(a->flight, "");
    ASSERT_EQ(a->has_alt_baro, 0);
    ASSERT_EQ(a->has_gs, 0);
    ASSERT_STR(a->squawk, "");
    ASSERT_EQ(a->has_pos, 0);    /* lon without lat is no position */
    ASSERT_EQ(a->emergency, ADSB_EMERG_ABSENT);
    /* A value of the wrong type is absent too: a number for squawk, a
     * string for gs, a boolean for alt_geom. */
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",\"squawk\":7700,"
                    "\"gs\":\"fast\",\"alt_geom\":true}]}"), 0);
    ASSERT_STR(g_doc.ac[0].squawk, "");
    ASSERT_EQ(g_doc.ac[0].has_gs, 0);
    ASSERT_EQ(g_doc.ac[0].has_alt_geom, 0);
    /* An empty document and an empty list are documents. */
    ASSERT_EQ(parse("{}"), 0);
    ASSERT_EQ(g_doc.n, 0);
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[]}"), 0);
    ASSERT_EQ(g_doc.n, 0);
}

static void test_alt_baro_ground(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",\"alt_baro\":\"ground\","
                    "\"gs\":12.0}]}"), 0);
    ASSERT_EQ(g_doc.ac[0].on_ground, 1);
    ASSERT_EQ(g_doc.ac[0].has_alt_baro, 0);
    /* Any other string is not an altitude. */
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",\"alt_baro\":\"high\"}]}"), 0);
    ASSERT_EQ(g_doc.ac[0].on_ground, 0);
    ASSERT_EQ(g_doc.ac[0].has_alt_baro, 0);
    ASSERT_EQ(adsb_alt_band(1, 0, 0), -2);
}

static void test_non_icao_hex(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"~0f1e2d\",\"type\":\"tisb_other\"},"
                    "{\"hex\":\"0f1e2d\",\"type\":\"adsb_icao\"}]}"), 0);
    ASSERT_EQ(g_doc.n, 2);
    ASSERT_EQ(g_doc.ac[0].icao, 0x0f1e2du);
    ASSERT_EQ(g_doc.ac[0].non_icao, 1);
    ASSERT_STR(g_doc.ac[0].type, "tisb_other");
    ASSERT_EQ(g_doc.ac[1].icao, 0x0f1e2du);
    ASSERT_EQ(g_doc.ac[1].non_icao, 0);
    uint32_t v; int ni;
    ASSERT_EQ(adsb_hex_parse("~ABCDEF", &v, &ni), 0);
    ASSERT_EQ(v, 0xabcdefu);
    ASSERT_EQ(ni, 1);
    ASSERT_EQ(adsb_hex_parse("abcde", &v, &ni), -1);
    ASSERT_EQ(adsb_hex_parse("abcdef0", &v, &ni), -1);
    ASSERT_EQ(adsb_hex_parse("~~abcdef", &v, &ni), -1);
    ASSERT_EQ(adsb_hex_parse("abcdeg", &v, &ni), -1);
}

static void test_callsign_trimmed(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",\"flight\":\"TEST12  \"},"
                    "{\"hex\":\"a0b1c3\",\"flight\":\"        \"},"
                    "{\"hex\":\"a0b1c4\",\"flight\":\"TOOLONG12\"},"
                    "{\"hex\":\"a0b1c5\",\"flight\":\"N123AB\"}]}"), 0);
    ASSERT_EQ(g_doc.n, 4);
    ASSERT_STR(g_doc.ac[0].flight, "TEST12");
    ASSERT_STR(g_doc.ac[1].flight, "");      /* all padding: absent */
    ASSERT_STR(g_doc.ac[2].flight, "");      /* over 8 characters */
    ASSERT_STR(g_doc.ac[3].flight, "N123AB");
}

static void test_position_out_of_range(void) {
    ASSERT_EQ(parse("{\"aircraft\":["
                    "{\"hex\":\"a0b1c1\",\"lat\":90.0001,\"lon\":20.0},"
                    "{\"hex\":\"a0b1c2\",\"lat\":10.0,\"lon\":-180.5},"
                    "{\"hex\":\"a0b1c3\",\"lat\":-90.0,\"lon\":180.0},"
                    "{\"hex\":\"a0b1c4\",\"lat\":10.0},"
                    "{\"hex\":\"a0b1c5\",\"lat\":1e3,\"lon\":0}]}"), 0);
    ASSERT_EQ(g_doc.n, 5);
    ASSERT_EQ(g_doc.ac[0].has_pos, 0);
    ASSERT_EQ(g_doc.ac[1].has_pos, 0);
    ASSERT_EQ(g_doc.ac[2].has_pos, 1);       /* the edges are in range */
    ASSERT_EQ(g_doc.ac[3].has_pos, 0);
    ASSERT_EQ(g_doc.ac[4].has_pos, 0);
}

/* Squawk is four octal digits; emergency one of the README's eight
 * names; category A0..D7. */
static void test_squawk_emergency_category(void) {
    ASSERT_EQ(parse("{\"aircraft\":["
                    "{\"hex\":\"a0b1c1\",\"squawk\":\"7700\",\"emergency\":\"general\",\"category\":\"D7\"},"
                    "{\"hex\":\"a0b1c2\",\"squawk\":\"7800\",\"emergency\":\"panic\",\"category\":\"E1\"},"
                    "{\"hex\":\"a0b1c3\",\"squawk\":\"770\",\"emergency\":\"unlawful\",\"category\":\"A8\"},"
                    "{\"hex\":\"a0b1c4\",\"emergency\":\"downed\"}]}"), 0);
    ASSERT_STR(g_doc.ac[0].squawk, "7700");
    ASSERT_EQ(g_doc.ac[0].emergency, ADSB_EMERG_GENERAL);
    ASSERT_STR(g_doc.ac[0].category, "D7");
    ASSERT_STR(g_doc.ac[1].squawk, "");
    ASSERT_EQ(g_doc.ac[1].emergency, ADSB_EMERG_ABSENT);
    ASSERT_STR(g_doc.ac[1].category, "");
    ASSERT_STR(g_doc.ac[2].squawk, "");
    ASSERT_EQ(g_doc.ac[2].emergency, ADSB_EMERG_UNLAWFUL);
    ASSERT_STR(g_doc.ac[2].category, "");
    ASSERT_EQ(g_doc.ac[3].emergency, ADSB_EMERG_DOWNED);
    ASSERT_STR(adsb_emergency_name(ADSB_EMERG_LIFEGUARD), "lifeguard");
    ASSERT_STR(adsb_emergency_name(ADSB_EMERG_MINFUEL), "minfuel");
    ASSERT_STR(adsb_emergency_name(ADSB_EMERG_NORDO), "nordo");
    ASSERT_STR(adsb_emergency_name(ADSB_EMERG_RESERVED), "reserved");
    ASSERT_STR(adsb_emergency_name(ADSB_EMERG_ABSENT), "");
}

/* Nested values are skipped by depth, a bracket inside a string does
 * not count, and a position inside a nested object (lastPosition) is
 * not the aircraft's position. */
static void test_nested_values_skipped(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\","
                    "\"acas_ra\":{\"advisory\":\"[{\",\"bytes\":[1,[2,{\"x\":3}]]},"
                    "\"lastPosition\":{\"lat\":10.0,\"lon\":20.0,\"seen_pos\":61.0},"
                    "\"mlat\":[\"lat\",\"lon\"],\"r\":\"N-ABC\",\"dbFlags\":0,"
                    "\"alt_baro\":-150,\"gs\":3.5e1}],"
                    "\"extra\":{\"aircraft\":[{\"hex\":\"a0b1c3\"}]}}"), 0);
    ASSERT_EQ(g_doc.n, 1);
    ASSERT_EQ(g_doc.ac[0].has_pos, 0);
    ASSERT_EQ(g_doc.ac[0].alt_baro, -150);
    ASSERT_NEAR(g_doc.ac[0].gs, 35.0, 1e-9);
}

/* An entry with no hex, a bad hex, or that is not an object is refused
 * and counted; the rest of the list stands. */
static void test_bad_entries_counted(void) {
    ASSERT_EQ(parse("{\"aircraft\":[{\"flight\":\"NOHEX\"},{\"hex\":\"xyz123\"},"
                    "42,\"str\",{\"hex\":\"a0b1c2\"}]}"), 0);
    ASSERT_EQ(g_doc.n, 1);
    ASSERT_EQ(g_doc.bad, 4);
    ASSERT_EQ(g_doc.ac[0].icao, 0xa0b1c2u);
}

static void test_malformed_refused(void) {
    /* Truncated in the middle of an aircraft, of the list, of the
     * document; trailing bytes after it; not an object; empty. */
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[{\"hex\":\"a0b1c2\",\"alt_ba"), -1);
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[{\"hex\":\"a0b1c2\"}"), -1);
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[]"), -1);
    ASSERT_EQ(parse("{\"now\":1800000000} x"), -1);
    ASSERT_EQ(parse("[{\"hex\":\"a0b1c2\"}]"), -1);
    ASSERT_EQ(parse(""), -1);
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\",}]}"), -1);
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\" \"a0b1c2\"}]}"), -1);
    ASSERT_EQ(parse("{\"aircraft\":[{\"hex\":\"a0b1c2\"}],\"now\":1e}"), -1);
    /* Over the cap, whatever it holds. */
    ASSERT_EQ(adsb_doc_parse("{}", ADSB_MAX_DOC + 1, &g_doc), -1);
}

/* N hand-templated aircraft with distinct synthetic addresses. */
static char *list_doc(int n, double now) {
    size_t cap = 64 + (size_t)n * 64;
    char *b = malloc(cap);
    if (!b) return NULL;
    size_t off = (size_t)snprintf(b, cap, "{\"now\":%.1f,\"aircraft\":[", now);
    for (int i = 0; i < n; i++)
        off += (size_t)snprintf(b + off, cap - off, "%s{\"hex\":\"%06x\",\"seen\":0}",
                                i ? "," : "", 0x100000 + i);
    snprintf(b + off, cap - off, "]}");
    return b;
}

/* Past ADSB_MAX_AIRCRAFT the entries are still parsed (the document
 * must balance) and counted, not kept; the table refuses a new address
 * once full and counts that too. */
static void test_aircraft_cap(void) {
    char *b = list_doc(ADSB_MAX_AIRCRAFT + 5, 1800000000.0);
    ASSERT(b != NULL);
    if (!b) return;
    ASSERT_EQ(adsb_doc_parse(b, strlen(b), &g_doc), 0);
    ASSERT_EQ(g_doc.n, ADSB_MAX_AIRCRAFT);
    ASSERT_EQ(g_doc.overflow, 5);
    ASSERT_EQ(g_doc.ac[ADSB_MAX_AIRCRAFT - 1].icao, 0x100000u + ADSB_MAX_AIRCRAFT - 1);
    free(b);

    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    adsb_feed_doc(&g_doc, 0, 1800000000, 1000000);
    ASSERT_EQ(parse("{\"now\":1800000001,\"aircraft\":[{\"hex\":\"a0b1c2\"},"
                    "{\"hex\":\"100000\"}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000001, 1001000);
    adsb_health_poll(&s, 1800000001, 1001000);
    ASSERT_EQ(s.adsb_count, ADSB_MAX_AIRCRAFT);
    ASSERT_EQ(s.adsb.overflow, 6u);          /* 5 in the list + 1 table-full */
    ASSERT_EQ(s.adsb.aircraft, ADSB_MAX_AIRCRAFT);
}

/* ── The table ─────────────────────────────────────────────────── */

static const adsb_aircraft_t *row(const sloth_state_t *s, uint32_t icao, int ni) {
    for (int i = 0; i < s->adsb_count; i++)
        if (s->adsb_rows[i].icao == icao && s->adsb_rows[i].non_icao == ni)
            return &s->adsb_rows[i];
    return NULL;
}

/* The ICAO and the non-ICAO address with the same 24 bits are two
 * rows; absent keys keep the last value (sticky merge). */
static void test_table_keys_and_sticky_merge(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[{\"hex\":\"0f1e2d\","
                    "\"flight\":\"TEST12\",\"squawk\":\"1200\",\"alt_baro\":4500},"
                    "{\"hex\":\"~0f1e2d\"}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000000, 5000000);
    ASSERT_EQ(parse("{\"now\":1800000001,\"aircraft\":[{\"hex\":\"0f1e2d\","
                    "\"alt_baro\":\"ground\"}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000001, 5001000);
    adsb_health_poll(&s, 1800000001, 5001000);
    ASSERT_EQ(s.adsb_count, 2);
    const adsb_aircraft_t *a = row(&s, 0x0f1e2d, 0);
    ASSERT(a != NULL);
    if (!a) return;
    ASSERT_STR(a->flight, "TEST12");
    ASSERT_STR(a->squawk, "1200");
    ASSERT_EQ(a->on_ground, 1);
    ASSERT_EQ(a->has_alt_baro, 0);
    ASSERT_EQ(a->alt_band, -2);
    ASSERT_EQ(a->first_seen, (time_t)1800000000);
    ASSERT_EQ(a->last_seen, (time_t)1800000001);
    ASSERT(row(&s, 0x0f1e2d, 1) != NULL);
}

/* An aircraft that drops out of the document is retired ADSB_EXPIRE_S
 * after the decoder last heard it, by the monotonic clock; one the
 * decoder still lists but reports `seen` 50 s ago is that much older
 * already. The retired rows are this poll's adsb_gone, once. */
static void test_aircraft_expires(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    const uint64_t t0 = 10000000;
    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[{\"hex\":\"a0b1c1\",\"seen\":0},"
                    "{\"hex\":\"a0b1c2\",\"seen\":0},{\"hex\":\"a0b1c3\",\"seen\":50}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000000, t0);
    adsb_health_poll(&s, 1800000009, t0 + 9999);
    ASSERT_EQ(s.adsb_count, 3);
    ASSERT_EQ(s.adsb_gone_count, 0);
    const adsb_aircraft_t *c3 = row(&s, 0xa0b1c3, 0);
    ASSERT(c3 != NULL);
    if (c3) ASSERT_EQ(c3->last_seen, (time_t)1799999950);
    /* Heard 50 s before t0, so 60 s unheard at t0 + 10 s. */
    adsb_health_poll(&s, 1800000010, t0 + 10000);
    ASSERT_EQ(s.adsb_gone_count, 1);
    if (s.adsb_gone_count == 1) ASSERT_EQ(s.adsb_gone[0].icao, 0xa0b1c3u);
    ASSERT_EQ(s.adsb_count, 2);
    /* Thirty seconds on, only a0b1c1 is still listed. */
    ASSERT_EQ(parse("{\"now\":1800000030,\"aircraft\":[{\"hex\":\"a0b1c1\",\"seen\":0}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000030, t0 + 30000);
    adsb_health_poll(&s, 1800000059, t0 + 59999);
    ASSERT_EQ(s.adsb_gone_count, 0);         /* c3 reported once */
    ASSERT_EQ(s.adsb_count, 2);
    adsb_health_poll(&s, 1800000060, t0 + 60000);
    ASSERT_EQ(s.adsb_gone_count, 1);
    if (s.adsb_gone_count == 1) ASSERT_EQ(s.adsb_gone[0].icao, 0xa0b1c2u);
    ASSERT_EQ(s.adsb_count, 1);
    ASSERT(row(&s, 0xa0b1c1, 0) != NULL);
    adsb_health_poll(&s, 1800000089, t0 + 89999);
    ASSERT_EQ(s.adsb_count, 1);
    adsb_health_poll(&s, 1800000090, t0 + 90000);
    ASSERT_EQ(s.adsb_count, 0);
    ASSERT_EQ(s.adsb.expired, 3u);
}

/* WAITING before any document, LIVE while the decoder's clock moves,
 * STALE once it has not for ADSB_STALE_S, ERROR on a failure, back to
 * LIVE when a fresh document parses. */
static void test_freshness_states(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_health_poll(&s, 1800000000, 1000);
    ASSERT_EQ(s.adsb.configured, 0);
    ASSERT_EQ(s.adsb.state, ADSB_NONE);
    adsb_set_source("file:/x");
    adsb_health_poll(&s, 1800000000, 1000);
    ASSERT_EQ(s.adsb.state, ADSB_WAITING);
    ASSERT_EQ(s.adsb.fresh_bucket, -1);
    ASSERT_EQ(parse("{\"now\":1800000000,\"messages\":7,\"aircraft\":[]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000000, 1000);
    adsb_health_poll(&s, 1800000000, 1000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.messages, 7u);
    /* The same "now" again: the decoder is not writing. */
    adsb_feed_doc(&g_doc, 0, 1800000005, 6000);
    adsb_health_poll(&s, 1800000010, 1000 + ADSB_STALE_S * 1000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    adsb_health_poll(&s, 1800000011, 1000 + ADSB_STALE_S * 1000 + 1000);
    ASSERT_EQ(s.adsb.state, ADSB_STALE);
    ASSERT_EQ(s.adsb.fresh_bucket, 1);
    ASSERT_EQ(s.adsb.age_s, ADSB_STALE_S + 1);
    adsb_note_read_error("open: No such file or directory");
    adsb_health_poll(&s, 1800000012, 13000);
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT_STR(s.adsb.err, "open: No such file or directory");
    ASSERT_EQ(s.adsb.read_errors, 1u);
    ASSERT_EQ(parse("{\"now\":1800000013,\"aircraft\":[]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000013, 14000);
    adsb_health_poll(&s, 1800000013, 14000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_STR(s.adsb.err, "");
    /* No "now" at all: the file's mtime is the decoder's clock. */
    ASSERT_EQ(parse("{\"aircraft\":[]}"), 0);
    adsb_feed_doc(&g_doc, 1800000100.0, 1800000030, 31000);
    adsb_health_poll(&s, 1800000030, 31000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.age_s, 0);
}

/* A decoder that hung (stopped writing, file left in place) before
 * sloth started leaves an aircraft.json whose clock is already old, and
 * an unchanged file is never re-read. Its aircraft were heard then, not
 * now: the first document whose clock is more than ADSB_STALE_S behind
 * the host's reads stale, and its rows are not taken - else each would
 * be written as a "live" adsb_aircraft with last_seen = now - seen and
 * "gone" a minute later. When the decoder writes again it is live and
 * the rows come in. A first document ADSB_STALE_S old is still live. */
static void test_stale_file_at_startup(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    ASSERT_EQ(parse("{\"now\":1799996400,\"aircraft\":[{\"hex\":\"a0b1c2\",\"seen\":1}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000000, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.state, ADSB_STALE);
    ASSERT_EQ(s.adsb.fresh_bucket, 1);
    ASSERT_EQ(s.adsb.age_s, -1);
    ASSERT_EQ(s.adsb.reads, 1u);
    ASSERT_EQ(s.adsb_count, 0);
    ASSERT_EQ(parse("{\"now\":1800000001,\"aircraft\":[{\"hex\":\"a0b1c2\",\"seen\":0}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000001, 1001000);
    adsb_health_poll(&s, 1800000001, 1001000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.age_s, 0);
    ASSERT_EQ(s.adsb_count, 1);
    if (s.adsb_count == 1) ASSERT_EQ(s.adsb_rows[0].first_seen, (time_t)1800000001);

    adsb_reset();
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    ASSERT_EQ(parse("{\"now\":1799999990,\"aircraft\":[{\"hex\":\"a0b1c2\"}]}"), 0);
    adsb_feed_doc(&g_doc, 0, 1800000000, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb_count, 1);
}

/* ── Bands ─────────────────────────────────────────────────────── */

static void test_alt_bands(void) {
    ASSERT_EQ(adsb_alt_band(0, 0, 0), -1);
    ASSERT_EQ(adsb_alt_band(0, 1, -1000), 0);
    ASSERT_EQ(adsb_alt_band(0, 1, 0), 0);
    ASSERT_EQ(adsb_alt_band(0, 1, 749), 0);
    ASSERT_EQ(adsb_alt_band(0, 1, 750), 1);
    ASSERT_EQ(adsb_alt_band(0, 1, 5000), 5);
    ASSERT_EQ(adsb_alt_band(0, 1, 5500), 5);
    ASSERT_EQ(adsb_alt_band(0, 1, 5749), 5);
    ASSERT_EQ(adsb_alt_band(0, 1, 5750), 6);
    ASSERT_EQ(adsb_alt_band(0, 1, 9749), 9);
    ASSERT_EQ(adsb_alt_band(0, 1, 9750), 10);
    ASSERT_EQ(adsb_alt_band(0, 1, 13749), 10);
    ASSERT_EQ(adsb_alt_band(0, 1, 13750), 11);
    ASSERT_EQ(adsb_alt_band(0, 1, 37000), 16);
    /* Held: an altitude must clear the edge by ADSB_ALT_HYST_FT. */
    ASSERT_EQ(adsb_alt_band_held(5, 0, 1, 5800), 5);
    ASSERT_EQ(adsb_alt_band_held(5, 0, 1, 5850), 6);
    ASSERT_EQ(adsb_alt_band_held(6, 0, 1, 5700), 6);
    ASSERT_EQ(adsb_alt_band_held(6, 0, 1, 5649), 5);
    ASSERT_EQ(adsb_alt_band_held(10, 0, 1, 13800), 10);
    ASSERT_EQ(adsb_alt_band_held(10, 0, 1, 13850), 11);
    ASSERT_EQ(adsb_alt_band_held(5, 0, 1, 12000), 10);   /* a jump moves at once */
    ASSERT_EQ(adsb_alt_band_held(5, 1, 0, 0), -2);       /* ground at once */
    ASSERT_EQ(adsb_alt_band_held(-2, 0, 1, 1200), 1);    /* off the ground at once */
    ASSERT_EQ(adsb_alt_band_held(INT16_MIN, 0, 1, 1200), 1);
}

/* ── The --adsb SPEC ───────────────────────────────────────────── */

static void test_spec_parse(void) {
    adsb_spec_t sp;
    char e[200], lab[64];
    ASSERT_EQ(adsb_spec_parse("/run/readsb/aircraft.json", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.kind, ADSB_SPEC_FILE);
    ASSERT_STR(sp.path, "/run/readsb/aircraft.json");
    adsb_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "file:/run/readsb/aircraft.json");
    ASSERT_EQ(adsb_spec_parse("file:///run/dump1090-fa/aircraft.json", &sp, e, sizeof(e)), 0);
    ASSERT_STR(sp.path, "/run/dump1090-fa/aircraft.json");
    /* beast:// is a source since 2026-11-09: tests/test_adsb_beast.c ::
     * test_spec_parse_beast. */
    ASSERT_EQ(adsb_spec_parse("file://host/aircraft.json", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("http://127.0.0.1/data/aircraft.json", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("aircraft.json", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("/run/readsb/", &sp, e, sizeof(e)), -1);
    char longp[300];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[0] = '/';
    longp[sizeof(longp) - 1] = '\0';
    ASSERT_EQ(adsb_spec_parse(longp, &sp, e, sizeof(e)), -1);   /* too long */
}

/* sbs:// (2026-11-09): numeric loopback HOST, PORT 1..65535, default
 * 127.0.0.1:30003 (readsb's --net-sbs-port default). The refusals of a
 * routable address were seen red with the loopback test in
 * sbs_spec_parse() forced to 1: 192.0.2.1 and 2001:db8::1 parsed. */
static void test_spec_parse_sbs(void) {
    adsb_spec_t sp;
    char e[200], lab[64];
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.1:30003", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.kind, ADSB_SPEC_SBS);
    ASSERT_STR(sp.host, "127.0.0.1");
    ASSERT_EQ(sp.port, 30003);
    adsb_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "sbs:127.0.0.1:30003");
    ASSERT_EQ(adsb_spec_parse("sbs://", &sp, e, sizeof(e)), 0);
    ASSERT_STR(sp.host, "127.0.0.1");
    ASSERT_EQ(sp.port, 30003);
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.2", &sp, e, sizeof(e)), 0);
    ASSERT_EQ(sp.port, 30003);
    ASSERT_EQ(adsb_spec_parse("sbs://[::1]:31003", &sp, e, sizeof(e)), 0);
    ASSERT_STR(sp.host, "::1");
    ASSERT_EQ(sp.port, 31003);
    adsb_spec_label(&sp, lab, sizeof(lab));
    ASSERT_STR(lab, "sbs:[::1]:31003");
    e[0] = '\0';
    ASSERT_EQ(adsb_spec_parse("sbs://192.0.2.1:30003", &sp, e, sizeof(e)), -1);
    ASSERT(strstr(e, "not loopback") != NULL);
    ASSERT_EQ(adsb_spec_parse("sbs://[2001:db8::1]:30003", &sp, e, sizeof(e)), -1);
    ASSERT(strstr(e, "not loopback") != NULL);
    ASSERT_EQ(adsb_spec_parse("sbs://localhost:30003", &sp, e, sizeof(e)), -1);  /* a name */
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.1:0", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.1:65536", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.1:30003x", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("sbs://127.0.0.1:", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("sbs://[::1", &sp, e, sizeof(e)), -1);
    ASSERT_EQ(adsb_spec_parse("sbs://[::1]x", &sp, e, sizeof(e)), -1);
    /* The longest spelling of ::1 is stored canonical, so the label
     * fits sensor_health's 48 bytes with its port whole. Seen red
     * before the inet_ntop() (label "sbs:[0000:...:0001]:3000"). */
    ASSERT_EQ(adsb_spec_parse("sbs://[0000:0000:0000:0000:0000:0000:0000:0001]:30003",
                              &sp, e, sizeof(e)), 0);
    ASSERT_STR(sp.host, "::1");
    char lab48[48];
    adsb_spec_label(&sp, lab48, sizeof(lab48));
    ASSERT_STR(lab48, "sbs:[::1]:30003");
}

/* ── SBS / BaseStation lines ───────────────────────────────────────
 *
 * Every line here is written by hand from readsb's
 * modesSendSBSOutput() (net_io.c, wiedehopf/readsb bf8f8fd): 22 comma
 * separated fields, CRLF, fields left empty when the message did not
 * carry them, readsb's choice of which fields each transmission type
 * fills (1 callsign; 2 surface position; 3 airborne position; 4
 * velocity; 5 surveillance altitude; 6 surveillance identity / squawk;
 * 7 air-to-air; 8 all-call). Addresses, callsigns and positions are
 * invented. The wall clock 1800000000 is 2027/01/15 08:00:00 UTC. */

#define SBS_T "2027/01/15,08:00:00.000,2027/01/15,08:00:00.010"
#define SBS_WALL_MS 1800000000000LL

static adsb_sbs_msg_t g_m;

static int sbs(const char *line) { return adsb_sbs_parse(line, strlen(line), &g_m); }

static void test_sbs_parse_each_type(void) {
    const adsb_aircraft_t *a = &g_m.ac;
    /* 1: identification */
    ASSERT_EQ(sbs("MSG,1,1,1,A1B2C3,1," SBS_T ",SYN510  ,,,,,,,,,,,0\r"), 1);
    ASSERT_EQ(g_m.type, 1);
    ASSERT_EQ(a->icao, 0xa1b2c3u);
    ASSERT_EQ(a->non_icao, 0);
    ASSERT_STR(a->flight, "SYN510");
    ASSERT_EQ(a->has_alt_baro + a->has_pos + a->has_gs + a->squawk[0], 0);
    ASSERT_EQ(a->emergency, ADSB_EMERG_ABSENT);
    /* The generated date and time, fields 6 and 7, as unix ms. */
    ASSERT_EQ(g_m.has_time, 1);
    ASSERT_EQ(g_m.time_ms, SBS_WALL_MS);
    /* 2: surface position: speed, track, position, on the ground. */
    ASSERT_EQ(sbs("MSG,2,1,1,A1B2C3,1," SBS_T ",,,12,271,33.1,-111.9,,,,,,-1"), 1);
    ASSERT_EQ(a->on_ground, 1);
    ASSERT_EQ(a->has_gs, 1);
    ASSERT_NEAR(a->gs, 12.0, 1e-9);
    ASSERT_NEAR(a->track, 271.0, 1e-9);
    ASSERT_EQ(a->has_pos, 1);
    ASSERT_NEAR(a->lat, 33.1, 1e-9);
    ASSERT_NEAR(a->lon, -111.9, 1e-9);
    /* 3: airborne position */
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,33.273972,-111.845380,,,0,,0,0"), 1);
    ASSERT_EQ(a->has_alt_baro, 1);
    ASSERT_EQ(a->alt_baro, 3000);
    ASSERT_EQ(a->on_ground, 0);
    ASSERT_NEAR(a->lat, 33.273972, 1e-9);
    ASSERT_NEAR(a->lon, -111.845380, 1e-9);
    /* 4: velocity, with a negative vertical rate */
    ASSERT_EQ(sbs("MSG,4,1,1,A1B2C3,1," SBS_T ",,,118,232,,,-448,,,,,0"), 1);
    ASSERT_NEAR(a->gs, 118.0, 1e-9);
    ASSERT_NEAR(a->track, 232.0, 1e-9);
    ASSERT_EQ(a->has_baro_rate, 1);
    ASSERT_EQ(a->baro_rate, -448);
    ASSERT_EQ(a->has_alt_baro + a->has_pos, 0);
    /* 5: surveillance altitude */
    ASSERT_EQ(sbs("MSG,5,1,1,A1B2C3,1," SBS_T ",,14375,,,,,,,0,,0,0"), 1);
    ASSERT_EQ(a->alt_baro, 14375);
    /* 6: surveillance identity */
    ASSERT_EQ(sbs("MSG,6,1,1,A1B2C3,1," SBS_T ",,,,,,,,1200,0,0,0,0"), 1);
    ASSERT_STR(a->squawk, "1200");
    /* 7: air-to-air */
    ASSERT_EQ(sbs("MSG,7,1,1,A1B2C3,1," SBS_T ",,14375,,,,,,,,,,"), 1);
    ASSERT_EQ(a->alt_baro, 14375);
    /* 8: all-call: the address and nothing else */
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1," SBS_T ",,,,,,,,,,,,0"), 1);
    ASSERT_EQ(g_m.type, 8);
    ASSERT_EQ(a->has_alt_baro + a->has_alt_geom + a->has_gs + a->has_pos + a->flight[0], 0);
}

/* readsb's variants: a trailing 'H' on altitude and vertical rate is
 * GNSS (geometric); a ground flag drops a barometric altitude as
 * aircraft.json's "ground" does; --sbs-extra-fields adds RSSI and the
 * category; '~' is a non-ICAO address. */
static void test_sbs_parse_variants(void) {
    const adsb_aircraft_t *a = &g_m.ac;
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3125H,,,33.2,-111.8,,,0,,0,0"), 1);
    ASSERT_EQ(a->has_alt_geom, 1);
    ASSERT_EQ(a->alt_geom, 3125);
    ASSERT_EQ(a->has_alt_baro, 0);
    ASSERT_EQ(sbs("MSG,4,1,1,A1B2C3,1," SBS_T ",,,300,90,,,640H,,,,,0"), 1);
    ASSERT_EQ(a->has_geom_rate, 1);
    ASSERT_EQ(a->geom_rate, 640);
    ASSERT_EQ(a->has_baro_rate, 0);
    ASSERT_EQ(sbs("MSG,5,1,1,A1B2C3,1," SBS_T ",,25,,,,,,,0,,0,-1"), 1);
    ASSERT_EQ(a->on_ground, 1);
    ASSERT_EQ(a->has_alt_baro, 0);
    ASSERT_EQ(sbs("MSG,1,1,1,A1B2C3,1," SBS_T ",SYN1    ,,,,,,,,,,,0,-23.5,A3\r"), 1);
    ASSERT_EQ(a->has_rssi, 1);
    ASSERT_NEAR(a->rssi, -23.5, 1e-9);
    ASSERT_STR(a->category, "A3");
    ASSERT_EQ(sbs("MSG,1,1,1,A1B2C3,1," SBS_T ",SYN1    ,,,,,,,,,,,0,,"), 1);
    ASSERT_EQ(a->has_rssi, 0);
    ASSERT_STR(a->category, "");
    ASSERT_EQ(sbs("MSG,8,1,1,~0B0C0D,1," SBS_T ",,,,,,,,,,,,"), 1);
    ASSERT_EQ(a->icao, 0x0b0c0du);
    ASSERT_EQ(a->non_icao, 1);
    /* A time without milliseconds is taken; date and time empty is no
     * time, not an error. */
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,2027/01/15,08:00:01,,,,,,,,,,,,,,"), 1);
    ASSERT_EQ(g_m.time_ms, SBS_WALL_MS + 1000);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,,,,,,,,,,,,,,,,"), 1);
    ASSERT_EQ(g_m.has_time, 0);
}

/* Well-formed values out of range leave their field absent, as in
 * aircraft.json; the line is still taken. Seen red with the squawk's
 * octal check removed (7800 was kept) and the latitude bound removed
 * (has_pos 1 at 91). */
static void test_sbs_parse_out_of_range(void) {
    const adsb_aircraft_t *a = &g_m.ac;
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,91.0,10.0,,,0,,0,0"), 1);
    ASSERT_EQ(a->has_pos, 0);
    ASSERT_EQ(a->has_alt_baro, 1);
    ASSERT_EQ(sbs("MSG,6,1,1,A1B2C3,1," SBS_T ",,,,,,,,7800,0,0,0,0"), 1);
    ASSERT_STR(a->squawk, "");
    ASSERT_EQ(sbs("MSG,6,1,1,A1B2C3,1," SBS_T ",,,,,,,,770,0,0,0,0"), 1);
    ASSERT_STR(a->squawk, "");
    ASSERT_EQ(sbs("MSG,1,1,1,A1B2C3,1," SBS_T ",SYN123456,,,,,,,,,,,0"), 1);  /* 9 chars */
    ASSERT_STR(a->flight, "");
    ASSERT_EQ(sbs("MSG,1,1,1,A1B2C3,1," SBS_T ",        ,,,,,,,,,,,0"), 1);   /* blank */
    ASSERT_STR(a->flight, "");
    ASSERT_EQ(sbs("MSG,4,1,1,A1B2C3,1," SBS_T ",,,5000,400,,,,,,,,0"), 1);
    ASSERT_EQ(a->has_gs, 0);
    ASSERT_EQ(a->has_track, 0);
}

/* Malformed lines are -1 (a parse error), a line that carries nothing
 * for the table is 0. */
static void test_sbs_parse_malformed(void) {
    ASSERT_EQ(sbs(""), 0);                 /* readsb's heartbeat, CR stripped */
    ASSERT_EQ(sbs("\r"), 0);
    ASSERT_EQ(sbs("SEL,,496,2286,4CA4E5,27215,2010/02/19,18:06:07.710,2010/02/19,18:06:07.710,RYR1427"), 0);
    ASSERT_EQ(sbs("CLK,,496,-1,,-1,2010/02/19,18:18:19.036,2010/02/19,18:18:19.036"), 0);
    ASSERT_EQ(sbs("hello"), -1);
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1,2027/01/15"), -1);                       /* truncated */
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,33.2,-111.8,,,0,,0"), -1);   /* 21 fields */
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,33.2,-111.8,,,0,,0,0,,,"), -1); /* 25 */
    ASSERT_EQ(sbs("MSG,9,1,1,A1B2C3,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,0,1,1,A1B2C3,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,,1,1,A1B2C3,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2CZ,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,,1," SBS_T ",,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,5,1,1,A1B2C3,1," SBS_T ",,12a00,,,,,,,0,,0,0"), -1);
    ASSERT_EQ(sbs("MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,33.2,,,,0,,0,0"), -1);   /* lat alone */
    ASSERT_EQ(sbs("MSG,4,1,1,A1B2C3,1," SBS_T ",,,1.2.3,90,,,,,,,,0"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,2027-01-15,08:00:00.000,,,,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,2027/13/15,08:00:00.000,,,,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,2027/01/15,08:00:00.1234,,,,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1,2027/01/15,,,,,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1," SBS_T ",SYN\x01,,,,,,,,,,,"), -1);
    ASSERT_EQ(sbs("MSG,8,1,1,A1B2C3,1," SBS_T ",\xc3\xa9,,,,,,,,,,,"), -1);
}

/* An MSG,3 position and an MSG,1 callsign for one address merge into
 * one row (#186's test list), sticky: the later line's empty fields do
 * not clear the earlier one's. A second address is a second row, and
 * the same 24 bits with '~' a third. messages counts the lines. */
static void test_sbs_merge_across_types(void) {
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_lines_t *l = calloc(1, sizeof(*l));
    ASSERT(l != NULL);
    if (!l) return;
    adsb_sbs_lines_init(l);
    static const char feed[] =
        "MSG,3,1,1,A1B2C3,1," SBS_T ",,3000,,,33.273972,-111.845380,,,0,,0,0\r\n"
        "MSG,1,1,1,A1B2C3,1," SBS_T ",SYN510  ,,,,,,,,,,,0\r\n"
        "MSG,4,1,1,A1B2C3,1," SBS_T ",,,118,232,,,448,,,,,0\r\n"
        "MSG,6,1,1,A1B2C3,1," SBS_T ",,,,,,,,1200,0,0,0,0\r\n"
        "MSG,8,1,1,0ABCDE,1," SBS_T ",,,,,,,,,,,,0\r\n"
        "MSG,8,1,1,~A1B2C3,1," SBS_T ",,,,,,,,,,,,\r\n";
    adsb_sbs_lines_feed(l, (const uint8_t *)feed, sizeof(feed) - 1,
                        SBS_WALL_MS, 1000000);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_STR(s.adsb.src, "sbs:127.0.0.1:30003");
    ASSERT_EQ(s.adsb_count, 3);
    ASSERT_EQ(s.adsb.reads, 6u);
    ASSERT_EQ(s.adsb.messages, 6u);
    ASSERT_EQ(s.adsb.parse_errors, 0u);
    const adsb_aircraft_t *a = NULL;
    for (int i = 0; i < s.adsb_count; i++)
        if (s.adsb_rows[i].icao == 0xa1b2c3u && !s.adsb_rows[i].non_icao) a = &s.adsb_rows[i];
    ASSERT(a != NULL);
    if (a) {
        ASSERT_STR(a->flight, "SYN510");
        ASSERT_EQ(a->has_pos, 1);
        ASSERT_NEAR(a->lat, 33.273972, 1e-9);
        ASSERT_EQ(a->has_alt_baro, 1);
        ASSERT_EQ(a->alt_baro, 3000);
        ASSERT_NEAR(a->gs, 118.0, 1e-9);
        ASSERT_EQ(a->baro_rate, 448);
        ASSERT_STR(a->squawk, "1200");
        ASSERT_EQ(a->messages, 4u);
        ASSERT_EQ(a->emergency, ADSB_EMERG_ABSENT);
        ASSERT_EQ(a->first_seen, (time_t)1800000000);
    }
    free(l);
    adsb_reset();
}

/* The framer: one byte per read, CRLF, a partial line held until its
 * newline, a garbage line and an over-cap line each one parse error
 * that does not stop the next line. The held-partial assertion was seen
 * red with adsb_sbs_lines_feed() parsing what it held at the end of
 * every read (the half line was a parse error and no row); the
 * one-error-per-over-cap-line assertions with the overlong flag never
 * set (the line's tail was cut into more lines, each another error). */
static void test_sbs_lines_framing(void) {
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_lines_t *l = calloc(1, sizeof(*l));
    ASSERT(l != NULL);
    if (!l) return;
    adsb_sbs_lines_init(l);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    static const char one[] = "MSG,1,1,1,A1B2C3,1," SBS_T ",SYN510  ,,,,,,,,,,,0\r\n";
    for (size_t i = 0; i < sizeof(one) - 3; i++)
        adsb_sbs_lines_feed(l, (const uint8_t *)one + i, 1, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb_count, 0);               /* no newline yet */
    ASSERT_EQ(s.adsb.parse_errors, 0u);
    ASSERT_EQ(s.adsb.state, ADSB_WAITING);
    adsb_sbs_lines_feed(l, (const uint8_t *)one + sizeof(one) - 3, 2, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb_count, 1);
    if (s.adsb_count == 1) ASSERT_STR(s.adsb_rows[0].flight, "SYN510");

    /* Garbage, then a good line in the same read. */
    static const char junk[] = "\x7f\x01garbage,,,\r\nMSG,8,1,1,0ABCDE,1," SBS_T ",,,,,,,,,,,,0\r\n";
    adsb_sbs_lines_feed(l, (const uint8_t *)junk, sizeof(junk) - 1, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.parse_errors, 1u);
    ASSERT_EQ(s.adsb_count, 2);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);       /* the good line cleared it */

    /* A line over the cap: one parse error, discarded to its newline,
     * however many reads it spans; the next line is taken. */
    char big[ADSB_SBS_MAX_LINE * 3];
    memset(big, 'M', sizeof(big));
    for (int k = 0; k < 3; k++)
        adsb_sbs_lines_feed(l, (const uint8_t *)big, sizeof(big), SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.parse_errors, 2u);
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT(strstr(s.adsb.err, "over") != NULL);
    static const char tail[] = "MMMM,1,2,3\r\nMSG,8,1,1,0BCDEF,1," SBS_T ",,,,,,,,,,,,0\n";
    adsb_sbs_lines_feed(l, (const uint8_t *)tail, sizeof(tail) - 1, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.parse_errors, 2u);       /* the tail was the big line's */
    ASSERT_EQ(s.adsb_count, 3);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);

    /* Exactly the cap, CR excluded, is a line (a BaseStation SEL
     * record padded out: no error); one byte more is not. */
    char exact[ADSB_SBS_MAX_LINE + 3];
    memset(exact, ' ', sizeof(exact));
    memcpy(exact, "SEL,", 4);
    exact[ADSB_SBS_MAX_LINE] = '\r';
    exact[ADSB_SBS_MAX_LINE + 1] = '\n';
    adsb_sbs_lines_feed(l, (const uint8_t *)exact, ADSB_SBS_MAX_LINE + 2, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.parse_errors, 2u);
    exact[ADSB_SBS_MAX_LINE] = ' ';
    exact[ADSB_SBS_MAX_LINE + 1] = '\r';
    exact[ADSB_SBS_MAX_LINE + 2] = '\n';
    adsb_sbs_lines_feed(l, (const uint8_t *)exact, ADSB_SBS_MAX_LINE + 3, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb.parse_errors, 3u);
    free(l);
    adsb_reset();
}

/* The row's clock is the line's generated time, as aircraft.json's is
 * its seen: a message stamped 5 s before the read is 5 s old, and one
 * stamped 61 s before is retired by the next poll's expiry. A stamp
 * after the read is 0 s, never negative. Seen red with adsb_feed_sbs()
 * ignoring the line's time (seen 0): last_seen was the read time and
 * nothing expired. */
static void test_sbs_seen_from_message_time(void) {
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_msg_t m;
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(adsb_sbs_parse(S("MSG,8,1,1,A1B2C3,1,2027/01/15,07:59:55.000,,,,,,,,,,,,,,"), &m), 1);
    adsb_feed_sbs(&m, SBS_WALL_MS, 1000000);
    ASSERT_EQ(adsb_sbs_parse(S("MSG,8,1,1,0ABCDE,1,2027/01/15,07:58:59.000,,,,,,,,,,,,,,"), &m), 1);
    adsb_feed_sbs(&m, SBS_WALL_MS, 1000000);
    ASSERT_EQ(adsb_sbs_parse(S("MSG,8,1,1,0BCDEF,1,2027/01/15,08:00:03.000,,,,,,,,,,,,,,"), &m), 1);
    adsb_feed_sbs(&m, SBS_WALL_MS, 1000000);
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb_count, 2);
    ASSERT_EQ(s.adsb_gone_count, 1);
    if (s.adsb_gone_count == 1) ASSERT_EQ(s.adsb_gone[0].icao, 0x0abcdeu);
    for (int i = 0; i < s.adsb_count; i++) {
        const adsb_aircraft_t *a = &s.adsb_rows[i];
        if (a->icao == 0xa1b2c3u) {
            ASSERT_EQ(a->last_seen, (time_t)1799999995);
            ASSERT_EQ(a->last_mono_ms, 995000u);
        } else {
            ASSERT_EQ(a->last_seen, (time_t)1800000000);
            ASSERT_EQ(a->last_mono_ms, 1000000u);
        }
    }
    adsb_reset();
}

/* Freshness on a stream is a line arriving, any line: a quiet sky with
 * only readsb's heartbeats stays live. Live past ADSB_STALE_S (a
 * document clock's 10 s) and stale only past ADSB_SBS_STALE_S. The
 * live-at-11-s assertion was seen red with adsb_health_poll() using
 * ADSB_STALE_S for a stream. */
static void test_sbs_freshness(void) {
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_lines_t *l = calloc(1, sizeof(*l));
    ASSERT(l != NULL);
    if (!l) return;
    adsb_sbs_lines_init(l);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_health_poll(&s, 1800000000, 1000);
    ASSERT_EQ(s.adsb.state, ADSB_WAITING);
    static const char msg[] = "MSG,8,1,1,A1B2C3,1," SBS_T ",,,,,,,,,,,,0\r\n";
    adsb_sbs_lines_feed(l, (const uint8_t *)msg, sizeof(msg) - 1, SBS_WALL_MS, 1000);
    adsb_health_poll(&s, 1800000000, 1000 + (ADSB_STALE_S + 1) * 1000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.age_s, ADSB_STALE_S + 1);
    adsb_health_poll(&s, 1800000000, 1000 + (ADSB_SBS_STALE_S + 1) * 1000);
    ASSERT_EQ(s.adsb.state, ADSB_STALE);
    /* The heartbeat alone. */
    adsb_sbs_lines_feed(l, (const uint8_t *)"\r\n", 2, SBS_WALL_MS + 140000,
                        1000 + 140000);
    adsb_health_poll(&s, 1800000140, 1000 + 140000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.reads, 1u);              /* a heartbeat is not a read */
    /* A failure is an error until the next line. */
    adsb_note_read_error("decoder closed the connection");
    adsb_health_poll(&s, 1800000140, 1000 + 140000);
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    adsb_note_connected();
    adsb_health_poll(&s, 1800000140, 1000 + 140000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    /* A file source declared after the stream (configure, stop,
     * configure) is back on the document's 10 s window. Seen red with
     * adsb_set_source() leaving the stream flag set. */
    adsb_set_source("file:/run/readsb/aircraft.json");
    adsb_health_poll(&s, 1800000140, 1000 + 140000 + (ADSB_STALE_S + 1) * 1000);
    ASSERT_EQ(s.adsb.state, ADSB_STALE);
    free(l);
    adsb_reset();
}

/* The table cap holds for a stream: 256 addresses fill it, the 257th
 * is refused and counted, and a known address still merges. */
static void test_sbs_cap(void) {
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_msg_t m;
    char line[160];
    for (int i = 0; i <= ADSB_MAX_AIRCRAFT; i++) {
        snprintf(line, sizeof(line), "MSG,8,1,1,%06X,1," SBS_T ",,,,,,,,,,,,0", 0x100000 + i);
        ASSERT_EQ(adsb_sbs_parse(line, strlen(line), &m), 1);
        adsb_feed_sbs(&m, SBS_WALL_MS, 1000000);
    }
    ASSERT_EQ(adsb_sbs_parse(S("MSG,1,1,1,100000,1," SBS_T ",SYN1    ,,,,,,,,,,,0"), &m), 1);
    adsb_feed_sbs(&m, SBS_WALL_MS, 1000000);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_health_poll(&s, 1800000000, 1000000);
    ASSERT_EQ(s.adsb_count, ADSB_MAX_AIRCRAFT);
    ASSERT_EQ(s.adsb.overflow, 1u);
    int named = 0;
    for (int i = 0; i < s.adsb_count; i++)
        if (s.adsb_rows[i].icao == 0x100000u && strcmp(s.adsb_rows[i].flight, "SYN1") == 0) named = 1;
    ASSERT_EQ(named, 1);
    adsb_reset();
}

/* ── The reader against a real file ────────────────────────────── */

static char g_dir[TEST_TMP_MAX];
static char g_file[TEST_TMP_MAX + 32];

static int write_file(const char *path, const char *body) {
    char tmp[TEST_TMP_MAX + 48];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return -1;
    fputs(body, fp);
    fclose(fp);
    return rename(tmp, path);   /* what the decoder does */
}

static void test_reader_polls_a_file(void) {
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_adsb_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/aircraft.json", g_dir);
    char spec[TEST_TMP_MAX + 48], err[200];
    snprintf(spec, sizeof(spec), "file://%s", g_file);
    ASSERT_EQ(adsb_reader_configure(spec, err, sizeof(err)), 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));

    /* Not there yet: an error state and a count, no crash. */
    ASSERT_EQ(adsb_reader_poll_once(1800000000, 1000), -1);
    adsb_health_poll(&s, 1800000000, 1000);
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT_EQ(s.adsb.read_errors, 1u);
    ASSERT(strstr(s.adsb.err, "open") != NULL);

    ASSERT_EQ(write_file(g_file, "{\"now\":1800000001.0,\"messages\":5,"
                         "\"aircraft\":[{\"hex\":\"a0b1c2\",\"seen\":0.5}]}"), 0);
    ASSERT_EQ(adsb_reader_poll_once(1800000001, 2000), 1);
    ASSERT_EQ(adsb_reader_poll_once(1800000001, 2500), 0);   /* unchanged */
    adsb_health_poll(&s, 1800000001, 2500);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb.reads, 1u);
    ASSERT_EQ(s.adsb_count, 1);

    /* A broken document is one parse error, however often it is polled. */
    ASSERT_EQ(write_file(g_file, "{\"now\":1800000002.0,\"aircraft\":[{\"hex\""), 0);
    ASSERT_EQ(adsb_reader_poll_once(1800000002, 3000), -1);
    ASSERT_EQ(adsb_reader_poll_once(1800000002, 4000), 0);
    adsb_health_poll(&s, 1800000002, 4000);
    ASSERT_EQ(s.adsb.parse_errors, 1u);
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT_EQ(s.adsb_count, 1);               /* the table stands */

    /* Over the size cap (sparse: nothing is written). */
    int fd = open(g_file, O_WRONLY | O_TRUNC);
    ASSERT(fd >= 0);
    if (fd >= 0) {
        ASSERT_EQ(ftruncate(fd, (off_t)ADSB_MAX_DOC + 1), 0);
        close(fd);
    }
    ASSERT_EQ(adsb_reader_poll_once(1800000003, 5000), -1);
    adsb_health_poll(&s, 1800000003, 5000);
    ASSERT(strstr(s.adsb.err, "over") != NULL);

    /* A directory where the file should be. */
    unlink(g_file);
    ASSERT_EQ(mkdir(g_file, 0700), 0);
    ASSERT_EQ(adsb_reader_poll_once(1800000004, 6000), -1);
    adsb_health_poll(&s, 1800000004, 6000);
    ASSERT_STR(s.adsb.err, "not a regular file");
    rmdir(g_file);

    ASSERT_EQ(write_file(g_file, "{\"now\":1800000005.0,\"aircraft\":[]}"), 0);
    ASSERT_EQ(adsb_reader_poll_once(1800000005, 7000), 1);
    adsb_health_poll(&s, 1800000005, 7000);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    adsb_reader_stop();
    unlink(g_file);
    rmdir(g_dir);
}

/* ── The sbs:// reader against a loopback socket ───────────────────
 * The "decoder" is this test's own listener on 127.0.0.1; no network.
 * Real clocks: the reader thread runs. */

static int sbs_listener(int *port) {
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

static void sbs_poll_now(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    adsb_health_poll(s, sloth_wall(), sloth_mono_ms());
}

/* Nothing listening: an error naming the connect, no crash, no rows. */
static void test_sbs_reader_connect_refused(void) {
    char err[200], spec[64];
    int port = 0;
    int lfd = sbs_listener(&port);
    ASSERT(lfd >= 0);
    if (lfd < 0) return;
    close(lfd);
    snprintf(spec, sizeof(spec), "sbs://127.0.0.1:%d", port);
    ASSERT_EQ(adsb_reader_configure(spec, err, sizeof(err)), 0);
    ASSERT_EQ(adsb_reader_poll_once(1800000000, 1000), -1);   /* not a file */
    adsb_reader_run();
    TEST_STATE(s);
    for (int i = 0; i < 100; i++) {
        sbs_poll_now(&s);
        if (s.adsb.read_errors > 0) break;
        nap_ms(20);
    }
    adsb_reader_stop();
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT(strstr(s.adsb.err, "connect") != NULL);
    ASSERT_EQ(s.adsb_count, 0);
    adsb_reset();
}

/* A session: two lines split across three writes with CRLF become one
 * row; sloth writes nothing to the socket; the decoder hanging up is a
 * read error, and the reader dials again. The "writes nothing"
 * assertion was seen red with a one-byte send() added after the connect
 * in sbs_connect(). */
static void test_sbs_reader_session(void) {
    char err[200], spec[64];
    int port = 0;
    int lfd = sbs_listener(&port);
    ASSERT(lfd >= 0);
    if (lfd < 0) return;
    snprintf(spec, sizeof(spec), "sbs://127.0.0.1:%d", port);
    ASSERT_EQ(adsb_reader_configure(spec, err, sizeof(err)), 0);
    adsb_reader_run();
    struct pollfd pfd = { lfd, POLLIN, 0 };
    ASSERT_EQ(poll(&pfd, 1, 5000), 1);
    int c = accept(lfd, NULL, NULL);
    ASSERT(c >= 0);
    if (c < 0) { adsb_reader_stop(); close(lfd); return; }
    static const char *const parts[] = {
        "MSG,3,1,1,A1B2C3,1,2027/01/15,08:00:00.000,2027/01/15,08:00:00.010,,3000,,,33.27",
        "3972,-111.845380,,,0,,0,0\r\nMSG,1,1,1,A1B2C3,1,2027/01/15,08:00:00.000,",
        "2027/01/15,08:00:00.010,SYN510  ,,,,,,,,,,,0\r\n",
    };
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(write(c, parts[i], strlen(parts[i])), (ssize_t)strlen(parts[i]));
        nap_ms(30);
    }
    TEST_STATE(s);
    for (int i = 0; i < 100; i++) {
        sbs_poll_now(&s);
        if (s.adsb.reads >= 2) break;
        nap_ms(20);
    }
    ASSERT_EQ(s.adsb.reads, 2u);
    ASSERT_EQ(s.adsb.parse_errors, 0u);
    /* The rows are stamped by the 2027 message time, read now: the row
     * stands until polled past it, which this test does not need. */
    ASSERT_EQ(s.adsb_count + s.adsb_gone_count, 1);
    const adsb_aircraft_t *a = s.adsb_count ? &s.adsb_rows[0]
                             : s.adsb_gone_count ? &s.adsb_gone[0] : NULL;
    if (a) {
        ASSERT_STR(a->flight, "SYN510");
        ASSERT_EQ(a->has_pos, 1);
        ASSERT_NEAR(a->lat, 33.273972, 1e-9);
    }
    /* sloth sent nothing. */
    char got[16];
    struct pollfd cp = { c, POLLIN, 0 };
    ASSERT_EQ(poll(&cp, 1, 300), 0);
    ASSERT_EQ(recv(c, got, sizeof(got), MSG_DONTWAIT), (ssize_t)-1);

    close(c);                                 /* the decoder hangs up */
    for (int i = 0; i < 100; i++) {
        sbs_poll_now(&s);
        if (s.adsb.read_errors > 0) break;
        nap_ms(20);
    }
    ASSERT_EQ(s.adsb.state, ADSB_ERROR);
    ASSERT_STR(s.adsb.err, "decoder closed the connection");
    /* ... and is dialled again after the 2 s wait. */
    pfd.revents = 0;
    ASSERT_EQ(poll(&pfd, 1, 5000), 1);
    c = accept(lfd, NULL, NULL);
    ASSERT(c >= 0);
    for (int i = 0; i < 100; i++) {
        sbs_poll_now(&s);
        if (s.adsb.state != ADSB_ERROR) break;
        nap_ms(20);
    }
    ASSERT(s.adsb.state != ADSB_ERROR);      /* the connect cleared it */
    if (c >= 0) close(c);
    adsb_reader_stop();
    close(lfd);
    adsb_reset();
}

/* ── The sensor registry ───────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t t_mono(void) { return g_mono; }
static time_t   t_wall(void) { return g_wall; }

static int find_sensor(const sloth_state_t *s) {
    for (int i = 0; i < s->sensor_count; i++)
        if (s->sensors[i].kind == SENSOR_ADSB) return i;
    return -1;
}

static void test_sensor_registry_adsb(void) {
    g_wall = 1800000000; g_mono = 1000000;
    sloth_clock_test_set(t_mono, t_wall);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(find_sensor(&s), -1);           /* nothing without --adsb */

    adsb_set_source("file:/run/readsb/aircraft.json");
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    int k = find_sensor(&s);
    ASSERT(k >= 0);
    if (k < 0) { sloth_clock_test_set(NULL, NULL); return; }
    ASSERT_STR(sensor_kind_name(s.sensors[k].kind), "adsb");
    ASSERT_STR(s.sensors[k].iface, "file:/run/readsb/aircraft.json");
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_PRESENT);

    ASSERT_EQ(parse("{\"now\":1800000000,\"aircraft\":[{\"hex\":\"a0b1c2\"}]}"), 0);
    adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    ASSERT_EQ(s.sensors[k].observed, 1u);

    g_wall += ADSB_STALE_S + 1; g_mono += (ADSB_STALE_S + 1) * 1000u;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ERROR);   /* stale */

    ASSERT_EQ(parse("{\"now\":1800000020,\"aircraft\":[]}"), 0);
    adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    sloth_clock_test_set(NULL, NULL);
}

/* ── JSONL ─────────────────────────────────────────────────────── */

static char g_jl[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_adsb_jl_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jl);
    ASSERT(jsonl_open(g_jl));
}

static char *read_all(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[65536];
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

/* One poll: a document for the one synthetic aircraft, then the poll
 * and the emit, one second after the last. */
static void step(sloth_state_t *s, int alt, const char *squawk,
                 const char *emerg, double lat, double lon) {
    char b[512];
    g_wall++; g_mono += 1000;
    snprintf(b, sizeof(b),
             "{\"now\":%lld.0,\"messages\":%lld,\"aircraft\":[{\"hex\":\"c0ffee\","
             "\"type\":\"adsb_icao\",\"flight\":\"SYN001  \",\"alt_baro\":%d,"
             "\"gs\":%d.5,\"track\":%d.0,\"squawk\":\"%s\",\"emergency\":\"%s\","
             "\"lat\":%.4f,\"lon\":%.4f,\"seen_pos\":0.2,\"seen\":0.1,"
             "\"rssi\":-%d.5,\"messages\":%lld}]}",
             (long long)g_wall, (long long)g_wall * 3, alt,
             (int)(200 + g_wall % 7), (int)(g_wall % 360), squawk, emerg,
             lat, lon, (int)(10 + g_wall % 9), (long long)g_wall % 1000);
    ASSERT_EQ(adsb_doc_parse(b, strlen(b), &g_doc), 0);
    adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
    adsb_health_poll(s, g_wall, g_mono);
    jsonl_emit_adsb(s);
}

/* Change-only: an unchanged aircraft is one record however many
 * documents list it, even while its speed, track, RSSI, message count
 * and the decoder's clock move every second; a wiggle inside the
 * altitude band (or across its edge but inside the hysteresis) and a
 * move inside the position cell are none; a band crossing, a new cell,
 * a squawk change and an emergency change are one each; expiry is one
 * "gone". Seen red with the raw altitude, then the raw latitude, signed
 * in adsb_row_sig() instead of the bands (a record per step), and with
 * either hysteresis set to 0 (a record on the edge). */
static void test_jsonl_change_only(void) {
    g_wall = 1800000000; g_mono = 2000000;
    sloth_clock_test_set(t_mono, t_wall);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    adsb_set_source("file:/x");
    jl_open();
    step(&s, 5000, "2741", "none", 10.0512, 20.0512);
    step(&s, 5000, "2741", "none", 10.0512, 20.0512);   /* unchanged */
    step(&s, 5025, "2741", "none", 10.0514, 20.0518);   /* wiggle, same cell */
    step(&s, 4975, "2741", "none", 10.0590, 20.0590);
    step(&s, 5800, "2741", "none", 10.0512, 20.0512);   /* past 5750 by < 100 */
    step(&s, 5000, "2741", "none", 10.1005, 20.0512);   /* over the cell edge by */
    step(&s, 5000, "2741", "none", 10.0995, 19.9995);   /* < 0.01 degree, and back */
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"adsb_aircraft\""), 1);
        ASSERT(strstr(b, "\"hex\":\"c0ffee\",\"non_icao\":0,\"state\":\"live\","
                         "\"src\":\"file:/x\",\"source_type\":\"adsb_icao\","
                         "\"flight\":\"SYN001\",\"squawk\":\"2741\",\"category\":\"\","
                         "\"emergency\":\"none\",\"on_ground\":0,\"alt_baro\":5000,"
                         "\"alt_band\":5,") != NULL);
        ASSERT(strstr(b, "\"lat\":10.05120,\"lon\":20.05120,") != NULL);
    }
    unlink(g_jl);

    jl_open();   /* a fresh sink re-baselines: one record */
    step(&s, 5800, "2741", "none", 10.0512, 20.0512);
    step(&s, 5900, "2741", "none", 10.0512, 20.0512);   /* band 6 */
    step(&s, 5900, "2741", "none", 10.1612, 20.0512);   /* new cell */
    step(&s, 5900, "7700", "none", 10.1612, 20.0512);   /* squawk */
    step(&s, 5900, "7700", "general", 10.1612, 20.0512);/* emergency */
    step(&s, 5900, "7700", "general", 10.1612, 20.0512);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"adsb_aircraft\""), 5);
        ASSERT_EQ(count_of(b, "\"alt_band\":6"), 4);
        ASSERT_EQ(count_of(b, "\"squawk\":\"7700\""), 2);
        ASSERT_EQ(count_of(b, "\"emergency\":\"general\""), 1);
    }
    unlink(g_jl);

    /* The decoder stops listing it: nothing until ADSB_EXPIRE_S after
     * its last message, then one "gone", then nothing. The fresh sink
     * re-baselines the still-listed row first (one "live"). */
    jl_open();
    for (int i = 0; i < ADSB_EXPIRE_S + 5; i++) {
        g_wall++; g_mono += 1000;
        ASSERT_EQ(parse("{\"now\":1900000000,\"aircraft\":[]}"), 0);
        adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
        adsb_health_poll(&s, g_wall, g_mono);
        jsonl_emit_adsb(&s);
    }
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"adsb_aircraft\""), 2);
        ASSERT_EQ(count_of(b, "\"state\":\"live\""), 1);
        ASSERT_EQ(count_of(b, "\"state\":\"gone\""), 1);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

/* sensor_health carries adsb_* only with --adsb, and signs the state
 * and none/some bands, never the counters: ten live seconds of a
 * decoder writing are no line, going stale is one. Seen red with
 * adsb_reads signed raw (a line per second). */
static void test_sensor_health_adsb_block(void) {
    g_wall = 1800000000; g_mono = 3000000;
    sloth_clock_test_set(t_mono, t_wall);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    adsb_health_poll(&s, g_wall, g_mono);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"type\":\"sensor_health\"") != NULL);
        ASSERT(strstr(b, "\"adsb_") == NULL);
    }
    unlink(g_jl);

    adsb_set_source("file:/x");
    jl_open();
    for (int i = 0; i < 10; i++) {
        g_wall++; g_mono += 1000;
        char d[160];
        snprintf(d, sizeof(d), "{\"now\":%lld,\"messages\":%d,\"aircraft\":"
                 "[{\"hex\":\"a0b1c2\"}]}", (long long)g_wall, 100 + i * 17);
        ASSERT_EQ(parse(d), 0);
        adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
        adsb_health_poll(&s, g_wall, g_mono);
        jsonl_emit_sensor_health(&s);
    }
    b = NULL;
    for (int i = 0; i < ADSB_STALE_S + 2; i++) {
        g_wall++; g_mono += 1000;
        adsb_health_poll(&s, g_wall, g_mono);
        jsonl_emit_sensor_health(&s);
    }
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"sensor_health\""), 2);
        ASSERT(strstr(b, "\"adsb_state\":\"live\",\"adsb_src\":\"file:/x\","
                         "\"adsb_age_s\":0,") != NULL);
        ASSERT(strstr(b, "\"adsb_state\":\"stale\"") != NULL);
        ASSERT(strstr(b, "\"adsb_aircraft\":1,\"adsb_messages\":100,"
                         "\"adsb_reads\":1,\"adsb_read_errors\":0,"
                         "\"adsb_parse_errors\":0,\"adsb_overflow\":0,"
                         "\"adsb_bad_entries\":0,\"adsb_expired\":0,"
                         "\"adsb_err\":\"\"") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
}

void run_adsb_tests(void) {
    TEST_SUITE("adsb — aircraft.json from a local decoder (#26 slice 1)");
    RUN_TEST(test_minimal_hex_only);
    RUN_TEST(test_full_position_and_velocity);
    RUN_TEST(test_missing_and_null_fields);
    RUN_TEST(test_alt_baro_ground);
    RUN_TEST(test_non_icao_hex);
    RUN_TEST(test_callsign_trimmed);
    RUN_TEST(test_position_out_of_range);
    RUN_TEST(test_squawk_emergency_category);
    RUN_TEST(test_nested_values_skipped);
    RUN_TEST(test_bad_entries_counted);
    RUN_TEST(test_malformed_refused);
    RUN_TEST(test_aircraft_cap);
    RUN_TEST(test_table_keys_and_sticky_merge);
    RUN_TEST(test_aircraft_expires);
    RUN_TEST(test_freshness_states);
    RUN_TEST(test_stale_file_at_startup);
    RUN_TEST(test_alt_bands);
    RUN_TEST(test_spec_parse);
    RUN_TEST(test_spec_parse_sbs);
    RUN_TEST(test_sbs_parse_each_type);
    RUN_TEST(test_sbs_parse_variants);
    RUN_TEST(test_sbs_parse_out_of_range);
    RUN_TEST(test_sbs_parse_malformed);
    RUN_TEST(test_sbs_merge_across_types);
    RUN_TEST(test_sbs_lines_framing);
    RUN_TEST(test_sbs_seen_from_message_time);
    RUN_TEST(test_sbs_freshness);
    RUN_TEST(test_sbs_cap);
    RUN_TEST(test_reader_polls_a_file);
    RUN_TEST(test_sbs_reader_connect_refused);
    RUN_TEST(test_sbs_reader_session);
    RUN_TEST(test_sensor_registry_adsb);
    RUN_TEST(test_jsonl_change_only);
    RUN_TEST(test_sensor_health_adsb_block);
}
