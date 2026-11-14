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
#include "rtl433.h"
#include "capture/rtl433_reader.h"
#include "jsonl.h"
#include "poll.h"
#include "sensors.h"
#include "sensor_health.h"
#include "sloth_clock.h"

/* --rtl433 (#208, 2026-11-14).
 *
 * Every line here is written BY HAND to the shape rtl_433's
 * src/output_file.c gives a `-F json` record: one JSON object per line,
 * doubles printed "%.3f" and integers "%d", strings escaped for `"`,
 * `\`, CR, LF and TAB and nothing else, no whitespace between tokens.
 * The field order is the order r_api.c assembles it: `time` prepended,
 * then `protocol` (with -M protocol), the decoder's own fields, then
 * the -M level block.
 *
 * The models, ids and readings are INVENTED — no line here came off a
 * receiver, and no parser output is fed back in. "Testco-TP01" follows
 * DATA_FORMAT.md's `<Manufacturer>-<Model>` syntax; the TPMS field set
 * is the documented one plus the per-model keys the issue observed,
 * which this slice deliberately counts rather than stores. */

/* A TPMS line: FSK, so r_api.c's freq1 / freq2 branch, with the
 * per-model keys (`state`, `flags`, `code`) that are NOT stored. */
#define L_TPMS \
  "{\"time\":\"2026-11-14 10:00:00\",\"protocol\":60,\"model\":\"Testco-TP01\"," \
  "\"type\":\"TPMS\",\"id\":\"1a2b3c\",\"state\":\"closed\",\"flags\":3," \
  "\"pressure_kPa\":241.400,\"temperature_C\":21.000,\"code\":\"0f1e2d\"," \
  "\"mic\":\"CHECKSUM\",\"mod\":\"FSK\",\"freq1\":433.918,\"freq2\":433.952," \
  "\"rssi\":-0.158,\"snr\":22.431,\"noise\":-22.589}"

/* A weather station: ASK, so the single `freq`, an integer id, and the
 * documented common fields. */
#define L_WX \
  "{\"time\":\"2026-11-14 10:00:01\",\"protocol\":12,\"model\":\"Testco-WX9\"," \
  "\"id\":205,\"channel\":2,\"battery_ok\":1.000,\"temperature_C\":-4.500," \
  "\"humidity\":63.000,\"pressure_hPa\":1013.200,\"mic\":\"CRC\"," \
  "\"mod\":\"ASK\",\"freq\":433.942,\"rssi\":-11.100,\"snr\":9.800," \
  "\"noise\":-20.900}"

/* Fahrenheit and psi: the other unit of each pair DATA_FORMAT.md
 * documents, kept as written rather than converted. */
#define L_US \
  "{\"model\":\"Testco-TP02\",\"id\":7,\"temperature_F\":69.800," \
  "\"pressure_PSI\":35.000,\"mod\":\"FSK\",\"freq1\":315.012,\"rssi\":-5.000}"

static rtl433_msg_t g_m;
static int          g_why;

static int parse(const char *s) {
    g_why = -1;
    return rtl433_line_parse(s, strlen(s), &g_m, &g_why);
}

/* ── One line ──────────────────────────────────────────────────── */

static void test_tpms_line(void) {
    ASSERT_EQ(parse(L_TPMS), 1);
    ASSERT_STR(g_m.model, "Testco-TP01");
    ASSERT_STR(g_m.id, "1a2b3c");
    ASSERT_STR(g_m.type, "TPMS");
    ASSERT_STR(g_m.subtype, "");
    ASSERT_STR(g_m.mic, "CHECKSUM");
    ASSERT_STR(g_m.mod, "FSK");
    ASSERT_EQ(g_m.protocol, 60);
    ASSERT_EQ(g_m.has_freq, 1);
    ASSERT_NEAR(g_m.freq_mhz, 433.918, 1e-9);     /* freq1 is THE frequency */
    ASSERT_EQ(g_m.has_freq2, 1);
    ASSERT_NEAR(g_m.freq2_mhz, 433.952, 1e-9);
    ASSERT_EQ(g_m.has_rssi + g_m.has_snr + g_m.has_noise, 3);
    ASSERT_NEAR(g_m.rssi_db, -0.158, 1e-9);
    ASSERT_NEAR(g_m.snr_db, 22.431, 1e-9);
    ASSERT_NEAR(g_m.noise_db, -22.589, 1e-9);
    ASSERT_EQ(g_m.has_temp, 1);
    ASSERT_NEAR(g_m.temp, 21.0, 1e-9);
    ASSERT_EQ(g_m.temp_unit, RTL433_TEMP_C);
    ASSERT_EQ(g_m.has_pressure, 1);
    ASSERT_NEAR(g_m.pressure, 241.4, 1e-9);
    ASSERT_EQ(g_m.pres_unit, RTL433_PRES_KPA);
    /* No battery, humidity or channel on this line: absent, not 0. */
    ASSERT_EQ(g_m.has_battery + g_m.has_humidity, 0);
    ASSERT_STR(g_m.channel, "");
    /* `state`, `flags` and `code` are counted, never stored; `time` is
     * recognised and not counted (rtl433.h). */
    ASSERT_EQ(g_m.other_keys, 3);
    ASSERT_EQ(g_m.bad_values, 0);
}

static void test_weather_line_ask_and_integer_id(void) {
    ASSERT_EQ(parse(L_WX), 1);
    ASSERT_STR(g_m.model, "Testco-WX9");
    ASSERT_STR(g_m.id, "205");          /* a number id, as written */
    ASSERT_STR(g_m.channel, "2");
    ASSERT_STR(g_m.mod, "ASK");
    ASSERT_EQ(g_m.has_freq, 1);
    ASSERT_NEAR(g_m.freq_mhz, 433.942, 1e-9);
    ASSERT_EQ(g_m.has_freq2, 0);        /* an ASK decode has one frequency */
    ASSERT_EQ(g_m.has_battery, 1);
    ASSERT_NEAR(g_m.battery_ok, 1.0, 1e-9);
    ASSERT_NEAR(g_m.temp, -4.5, 1e-9);
    ASSERT_EQ(g_m.temp_unit, RTL433_TEMP_C);
    ASSERT_EQ(g_m.has_humidity, 1);
    ASSERT_NEAR(g_m.humidity, 63.0, 1e-9);
    ASSERT_NEAR(g_m.pressure, 1013.2, 1e-9);
    ASSERT_EQ(g_m.pres_unit, RTL433_PRES_HPA);
    ASSERT_EQ(g_m.other_keys, 0);
}

/* The unit travels with the value; nothing is converted. */
static void test_units_are_the_keys_own(void) {
    ASSERT_EQ(parse(L_US), 1);
    ASSERT_EQ(g_m.temp_unit, RTL433_TEMP_F);
    ASSERT_NEAR(g_m.temp, 69.8, 1e-9);      /* not 21 C */
    ASSERT_EQ(g_m.pres_unit, RTL433_PRES_PSI);
    ASSERT_NEAR(g_m.pressure, 35.0, 1e-9);  /* not 241 kPa */
    ASSERT_STR(rtl433_temp_unit_name(RTL433_TEMP_C), "C");
    ASSERT_STR(rtl433_temp_unit_name(RTL433_TEMP_F), "F");
    ASSERT_STR(rtl433_temp_unit_name(RTL433_TEMP_NONE), "");
    ASSERT_STR(rtl433_pres_unit_name(RTL433_PRES_KPA), "kPa");
    ASSERT_STR(rtl433_pres_unit_name(RTL433_PRES_HPA), "hPa");
    ASSERT_STR(rtl433_pres_unit_name(RTL433_PRES_PSI), "psi");
    ASSERT_STR(rtl433_pres_unit_name(99), "");
    /* `pressure_psi` lower case, DATA_FORMAT.md's own spelling, reads
     * the same unit as tpms_toyota.c's `pressure_PSI`. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP02\",\"id\":7,\"pressure_psi\":35.000}"), 1);
    ASSERT_EQ(g_m.pres_unit, RTL433_PRES_PSI);
}

static void test_blank_lines_skipped(void) {
    ASSERT_EQ(parse(""), 0);
    ASSERT_EQ(parse("   "), 0);
    ASSERT_EQ(parse("\t"), 0);
    ASSERT_EQ(parse("\r"), 0);
}

/* Each refusal reports WHICH refusal: the counters are per reason, so a
 * decoder writing unkeyable objects and a decoder writing garbage are
 * told apart. */
static void test_bad_lines_refused_by_reason(void) {
    /* Not an object. */
    ASSERT_EQ(parse("[{\"model\":\"Testco-TP01\",\"id\":1}]"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NOT_OBJECT);
    ASSERT_EQ(parse("Nov 14 10:00:00 rtl_433: Testco-TP01"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NOT_OBJECT);
    ASSERT_EQ(parse("null"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NOT_OBJECT);
    /* An object followed by anything is not one object per line. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1} {\"model\":\"x\"}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NOT_OBJECT);
    ASSERT_EQ(parse("{}x"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NOT_OBJECT);

    /* Truncated: the writer flushes per record, but a poll can land
     * mid-write and a crashed decoder leaves a partial last line
     * behind a rotation. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":\"1a2"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\""), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\":"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\","), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"rssi\":-}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\" \"Testco-TP01\"}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\" \"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);
    ASSERT_EQ(parse("{\"model\":tru}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_MALFORMED);

    /* No model. An empty object has neither, and model is reported
     * first because a row cannot be named without it. */
    ASSERT_EQ(parse("{}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    ASSERT_EQ(parse("{\"id\":\"1a2b3c\",\"rssi\":-5.000}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    ASSERT_EQ(parse("{\"model\":\"\",\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    ASSERT_EQ(parse("{\"model\":null,\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    ASSERT_EQ(parse("{\"model\":42,\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);

    /* No id: the table is keyed (model, id), so a line sloth cannot key
     * is refused rather than kept under an invented id. DATA_FORMAT.md
     * calls id optional; see the slice report. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"rssi\":-5.000}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_ID);
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":\"\"}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_ID);
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":null}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_ID);
    /* A fractional id is not an integer and not a string: no key. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1.5}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_ID);
    /* id 0 IS a key: an integer id of zero is a device, not an absence. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":0}"), 1);
    ASSERT_STR(g_m.id, "0");
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":-12}"), 1);
    ASSERT_STR(g_m.id, "-12");

    ASSERT_STR(rtl433_reject_name(RTL433_REJ_OVERSIZE), "oversize");
    ASSERT_STR(rtl433_reject_name(RTL433_REJ_NOT_OBJECT), "not_object");
    ASSERT_STR(rtl433_reject_name(RTL433_REJ_MALFORMED), "malformed");
    ASSERT_STR(rtl433_reject_name(RTL433_REJ_NO_MODEL), "no_model");
    ASSERT_STR(rtl433_reject_name(RTL433_REJ_NO_ID), "no_id");
    ASSERT_STR(rtl433_reject_name(RTL433_REJ_COUNT), "");
    ASSERT_STR(rtl433_reject_name(-1), "");
}

/* A line over RTL433_MAX_LINE is refused whole, by length, before any
 * of it is parsed — the bound is the point, not what is inside it. */
static void test_oversize_line_refused(void) {
    static char big[RTL433_MAX_LINE + 64];
    int n = snprintf(big, sizeof(big), "{\"model\":\"Testco-TP01\",\"id\":1,\"mod\":\"");
    while (n < (int)sizeof(big) - 4) big[n++] = 'A';
    big[n++] = '"';
    big[n++] = '}';
    big[n] = '\0';
    ASSERT((size_t)n > RTL433_MAX_LINE);
    ASSERT_EQ(rtl433_line_parse(big, (size_t)n, &g_m, &g_why), -1);
    ASSERT_EQ(g_why, RTL433_REJ_OVERSIZE);
    /* Exactly at the bound is still a line. */
    char ok[RTL433_MAX_LINE + 1];
    int k = snprintf(ok, sizeof(ok), "{\"model\":\"Testco-TP01\",\"id\":1,\"junk\":\"");
    while (k < (int)RTL433_MAX_LINE - 2) ok[k++] = 'A';
    ok[k++] = '"';
    ok[k++] = '}';
    ok[k] = '\0';
    ASSERT_EQ(k, (int)RTL433_MAX_LINE);
    ASSERT_EQ(rtl433_line_parse(ok, (size_t)k, &g_m, &g_why), 1);
}

/* A value present but out of range leaves its field ABSENT and is
 * counted; it is never clamped, and it does not refuse a line whose
 * key and signal metadata are still a real observation. */
static void test_out_of_range_values_absent_not_clamped(void) {
    ASSERT_EQ(parse("{\"model\":\"Testco-WX9\",\"id\":1,\"humidity\":180.000,"
                    "\"battery_ok\":4.000,\"temperature_C\":-400.000,"
                    "\"rssi\":-9000.000,\"freq\":-433.942,\"protocol\":70000,"
                    "\"pressure_hPa\":-1.000,\"snr\":9.800}"), 1);
    ASSERT_EQ(g_m.has_humidity, 0);
    ASSERT_NEAR(g_m.humidity, 0.0, 1e-9);        /* not 100 */
    ASSERT_EQ(g_m.has_battery, 0);
    ASSERT_NEAR(g_m.battery_ok, 0.0, 1e-9);      /* not 1 */
    ASSERT_EQ(g_m.has_temp, 0);
    ASSERT_EQ(g_m.temp_unit, RTL433_TEMP_NONE);
    ASSERT_EQ(g_m.has_rssi, 0);
    ASSERT_EQ(g_m.has_freq, 0);
    ASSERT_EQ(g_m.has_pressure, 0);
    ASSERT_EQ(g_m.protocol, -1);
    ASSERT_EQ(g_m.bad_values, 7);
    /* The good field on the same line survived. */
    ASSERT_EQ(g_m.has_snr, 1);
    ASSERT_NEAR(g_m.snr_db, 9.8, 1e-9);
    /* A closed value set: `mic` outside DATA_FORMAT.md's three and
     * `mod` outside r_api.c's three are absent, not stored raw. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1,\"mic\":\"MD5\","
                    "\"mod\":\"OOK\"}"), 1);
    ASSERT_STR(g_m.mic, "");
    ASSERT_STR(g_m.mod, "");
    ASSERT_EQ(g_m.bad_values, 2);
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1,\"mic\":\"PARITY\"}"), 1);
    ASSERT_STR(g_m.mic, "PARITY");
}

/* Strings are cleaned, and a model or id too long for its documented
 * bound is refused rather than cut: a truncated key would merge two
 * devices into one row. output_file.c escapes only `"`, `\`, CR, LF and
 * TAB, so a control byte reaches sloth raw and must not reach a
 * terminal (the CWE-150 lesson of #77). */
static void test_strings_cleaned_and_bounded(void) {
    /* 33 characters: one past DATA_FORMAT.md's "less than 32". */
    ASSERT_EQ(parse("{\"model\":\"Testco-AAAAAAAAAAAAAAAAAAAAAAAAAA\",\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    /* Exactly 32 is kept. */
    ASSERT_EQ(parse("{\"model\":\"Testco-AAAAAAAAAAAAAAAAAAAAAAAAA\",\"id\":1}"), 1);
    ASSERT_EQ((int)strlen(g_m.model), 32);
    /* 17 characters of id: one past "less than 16". */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":\"12345678901234567\"}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_ID);
    /* A raw control byte in the model: not a model. */
    ASSERT_EQ(parse("{\"model\":\"Test\x01co\",\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    /* An escaped quote or backslash would re-escape on the way out, so
     * it is not kept either. */
    ASSERT_EQ(parse("{\"model\":\"Test\\\"co\",\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    ASSERT_EQ(parse("{\"model\":\"Test\\\\co\",\"id\":1}"), -1);
    ASSERT_EQ(g_why, RTL433_REJ_NO_MODEL);
    /* A long type or channel is absent; the line is still keyable. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1,"
                    "\"type\":\"AAAAAAAAAAAAAAAAA\",\"subtype\":\"keyfob\"}"), 1);
    ASSERT_STR(g_m.type, "");
    ASSERT_STR(g_m.subtype, "keyfob");
    ASSERT_EQ(g_m.bad_values, 1);
}

/* A nested object or array under a key — output_file.c prints an
 * embedded JSON object verbatim — is stepped over as one unknown key,
 * not a malformed line. */
static void test_nested_values_counted_not_fatal(void) {
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1,"
                    "\"extra\":{\"a\":[1,2,{\"b\":\"}\"}]},\"rows\":[],"
                    "\"ok\":true,\"none\":null,\"rssi\":-5.000}"), 1);
    ASSERT_EQ(g_m.other_keys, 4);
    ASSERT_EQ(g_m.has_rssi, 1);
    /* A key longer than the parser's key buffer is on no list, so it is
     * an unknown key and never a silent match. */
    ASSERT_EQ(parse("{\"model\":\"Testco-TP01\",\"id\":1,"
                    "\"a_very_long_key_name_well_past_the_cap\":1}"), 1);
    ASSERT_EQ(g_m.other_keys, 1);
}

static void test_spec_parse(void) {
    char p[256], err[200];
    ASSERT_EQ(rtl433_spec_parse("/var/lib/rtl_433/events.jsonl", p, sizeof(p),
                                err, sizeof(err)), 0);
    ASSERT_STR(p, "/var/lib/rtl_433/events.jsonl");
    ASSERT_EQ(rtl433_spec_parse("file:///var/lib/rtl_433/events.jsonl", p,
                                sizeof(p), err, sizeof(err)), 0);
    ASSERT_STR(p, "/var/lib/rtl_433/events.jsonl");
    /* Refused: a relative path, a directory, a host in the file URL,
     * another scheme, nothing at all. */
    ASSERT_EQ(rtl433_spec_parse("events.jsonl", p, sizeof(p), err, sizeof(err)), -1);
    ASSERT(strstr(err, "absolute") != NULL);
    ASSERT_EQ(rtl433_spec_parse("./events.jsonl", p, sizeof(p), err, sizeof(err)), -1);
    ASSERT_EQ(rtl433_spec_parse("/var/lib/rtl_433/", p, sizeof(p), err, sizeof(err)), -1);
    ASSERT(strstr(err, "directory") != NULL);
    ASSERT_EQ(rtl433_spec_parse("file://host/events.jsonl", p, sizeof(p),
                                err, sizeof(err)), -1);
    ASSERT(strstr(err, "not a host") != NULL);
    ASSERT_EQ(rtl433_spec_parse("http://host/events.jsonl", p, sizeof(p),
                                err, sizeof(err)), -1);
    ASSERT(strstr(err, "scheme") != NULL);
    ASSERT_EQ(rtl433_spec_parse("tcp://127.0.0.1:1234", p, sizeof(p),
                                err, sizeof(err)), -1);
    ASSERT_EQ(rtl433_spec_parse("", p, sizeof(p), err, sizeof(err)), -1);
    ASSERT_EQ(rtl433_spec_parse(NULL, p, sizeof(p), err, sizeof(err)), -1);
    /* A path longer than the caller's buffer is refused, not cut. */
    char longp[300];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[0] = '/';
    longp[sizeof(longp) - 1] = '\0';
    char small[64];
    ASSERT_EQ(rtl433_spec_parse(longp, small, sizeof(small), err, sizeof(err)), -1);
    ASSERT(strstr(err, "too long") != NULL);
}

/* ── The table ─────────────────────────────────────────────────── */

static int feed(const char *s, time_t wall) {
    return rtl433_feed_line(s, strlen(s), wall);
}

/* Keyed (model, id): one model's two ids are two rows, two models'
 * same id are two rows. Sticky merge: a line with no temperature does
 * not erase the temperature of the line before it. */
static void test_table_keyed_and_sticky(void) {
    rtl433_reset();
    rtl433_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(feed(L_TPMS, 1000), 1);
    ASSERT_EQ(feed(L_WX, 1001), 1);
    rtl433_health_poll(&s, 1001);
    ASSERT_EQ(s.rtl433_count, 2);
    ASSERT_EQ(s.rtl433.devices, 2);
    ASSERT_EQ(s.rtl433.msgs, 2u);
    ASSERT_EQ(s.rtl433.lines, 2u);
    ASSERT_EQ(s.rtl433.bad_lines, 0u);
    ASSERT_EQ(s.rtl433.other_keys, 3u);     /* state, flags, code */
    ASSERT_EQ((long long)s.rtl433.last_msg, 1001LL);

    /* Same model, another id. */
    ASSERT_EQ(feed("{\"model\":\"Testco-TP01\",\"id\":\"9z8y7x\"}", 1002), 1);
    /* Another model, the first one's id. */
    ASSERT_EQ(feed("{\"model\":\"Testco-TP09\",\"id\":\"1a2b3c\"}", 1003), 1);
    rtl433_health_poll(&s, 1003);
    ASSERT_EQ(s.rtl433_count, 4);

    /* A second line for the first row, carrying only a new pressure. */
    ASSERT_EQ(feed("{\"model\":\"Testco-TP01\",\"id\":\"1a2b3c\","
                   "\"pressure_kPa\":250.000}", 1010), 1);
    rtl433_health_poll(&s, 1010);
    ASSERT_EQ(s.rtl433_count, 4);
    int k = -1;
    for (int i = 0; i < s.rtl433_count; i++)
        if (!strcmp(s.rtl433_rows[i].model, "Testco-TP01") &&
            !strcmp(s.rtl433_rows[i].id, "1a2b3c")) k = i;
    ASSERT(k >= 0);
    if (k < 0) return;
    const rtl433_device_t *d = &s.rtl433_rows[k];
    ASSERT_EQ(d->msgs, 2u);
    ASSERT_EQ((long long)d->first_seen, 1000LL);
    ASSERT_EQ((long long)d->last_seen, 1010LL);
    ASSERT_NEAR(d->pressure, 250.0, 1e-9);      /* replaced */
    ASSERT_EQ(d->has_temp, 1);
    ASSERT_NEAR(d->temp, 21.0, 1e-9);           /* kept: sticky */
    ASSERT_STR(d->type, "TPMS");
    ASSERT_STR(d->mod, "FSK");
    ASSERT_EQ(d->protocol, 60);
    ASSERT_EQ(d->other_keys, 3u);
    /* A row that never carried a protocol says -1, not 0. */
    for (int i = 0; i < s.rtl433_count; i++)
        if (!strcmp(s.rtl433_rows[i].model, "Testco-TP09"))
            ASSERT_EQ(s.rtl433_rows[i].protocol, -1);
    rtl433_reset();
}

/* The table is bounded: a new (model, id) past RTL433_MAX_DEVICES
 * displaces the least recently heard, and the loss is tallied both in
 * the source's own counter and in the process-wide `evict_rtl433`. */
static void test_table_bounded_and_eviction_tallied(void) {
    rtl433_reset();
    sh_evict_reset();
    rtl433_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char line[160];
    for (int i = 0; i < RTL433_MAX_DEVICES; i++) {
        snprintf(line, sizeof(line),
                 "{\"model\":\"Testco-TP01\",\"id\":%d}", i);
        /* Staggered, so "least recently heard" is id 0 and not a tie. */
        ASSERT_EQ(feed(line, 1000 + i), 1);
    }
    rtl433_health_poll(&s, 2000);
    ASSERT_EQ(s.rtl433_count, RTL433_MAX_DEVICES);
    ASSERT_EQ(s.rtl433.evicted, 0u);
    ASSERT_EQ(sh_evict_count(SH_EVICT_RTL433), 0u);

    for (int i = 0; i < 3; i++) {
        snprintf(line, sizeof(line),
                 "{\"model\":\"Testco-TP01\",\"id\":\"n%d\"}", i);
        ASSERT_EQ(feed(line, 3000 + i), 1);
    }
    rtl433_health_poll(&s, 3000);
    ASSERT_EQ(s.rtl433_count, RTL433_MAX_DEVICES);     /* still bounded */
    ASSERT_EQ(s.rtl433.devices, RTL433_MAX_DEVICES);
    ASSERT_EQ(s.rtl433.evicted, 3u);
    ASSERT_EQ(sh_evict_count(SH_EVICT_RTL433), 3u);
    ASSERT_STR(sh_evict_name(SH_EVICT_RTL433), "rtl433");
    /* The three oldest went; the three newest are there. */
    int gone = 0, fresh = 0;
    for (int i = 0; i < s.rtl433_count; i++) {
        const char *id = s.rtl433_rows[i].id;
        if (!strcmp(id, "0") || !strcmp(id, "1") || !strcmp(id, "2")) gone++;
        if (id[0] == 'n') fresh++;
    }
    ASSERT_EQ(gone, 0);
    ASSERT_EQ(fresh, 3);
    /* Every message still counted, evicted or not. */
    ASSERT_EQ(s.rtl433.msgs, (uint64_t)RTL433_MAX_DEVICES + 3u);
    rtl433_reset();
    sh_evict_reset();
}

/* Not configured, waiting (never read, or the file missing), live,
 * error; a quiet band is still live. */
static void test_states(void) {
    rtl433_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    rtl433_health_poll(&s, 0);
    ASSERT_EQ(s.rtl433.state, RTL433_NONE);
    rtl433_set_source("file:/x");
    rtl433_health_poll(&s, 0);
    ASSERT_EQ(s.rtl433.state, RTL433_WAITING);
    rtl433_note_missing();
    rtl433_health_poll(&s, 0);
    ASSERT_EQ(s.rtl433.state, RTL433_WAITING);
    ASSERT_EQ(s.rtl433.missing, 1);
    ASSERT_EQ(s.rtl433.read_errors, 0u);
    rtl433_note_read(1793930000, 10, 0, 0);
    rtl433_health_poll(&s, 1793930000);
    ASSERT_EQ(s.rtl433.state, RTL433_LIVE);
    ASSERT_EQ(s.rtl433.missing, 0);
    /* An hour with no decode: the file is fine, so the state is. */
    rtl433_health_poll(&s, 1793933600);
    ASSERT_EQ(s.rtl433.state, RTL433_LIVE);
    rtl433_note_read_error("read: Input/output error");
    rtl433_health_poll(&s, 0);
    ASSERT_EQ(s.rtl433.state, RTL433_ERROR);
    ASSERT_EQ(s.rtl433.read_errors, 1u);
    rtl433_note_read(1793930001, 0, 1, 0);
    rtl433_health_poll(&s, 0);
    ASSERT_EQ(s.rtl433.state, RTL433_LIVE);
    ASSERT_STR(s.rtl433.err, "");
    ASSERT_EQ(s.rtl433.rotations, 1u);
    ASSERT_STR(rtl433_state_name(RTL433_NONE), "none");
    ASSERT_STR(rtl433_state_name(RTL433_WAITING), "waiting");
    ASSERT_STR(rtl433_state_name(RTL433_LIVE), "live");
    ASSERT_STR(rtl433_state_name(RTL433_ERROR), "error");
    ASSERT_STR(rtl433_state_name(99), "none");
    rtl433_reset();
}

/* Every refusal reaches its own counter, and a refused line's own
 * tallies still count. */
static void test_reject_counters(void) {
    rtl433_reset();
    rtl433_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(feed("not json", 1000), -1);
    ASSERT_EQ(feed("{\"model\":\"Testco-TP01\"", 1000), -1);
    ASSERT_EQ(feed("{\"id\":1}", 1000), -1);
    ASSERT_EQ(feed("{\"model\":\"Testco-TP01\",\"state\":\"open\"}", 1000), -1);
    rtl433_note_bad_line();
    ASSERT_EQ(feed("", 1000), 0);            /* blank: not a line, not bad */
    rtl433_health_poll(&s, 1000);
    ASSERT_EQ(s.rtl433.lines, 5u);
    ASSERT_EQ(s.rtl433.bad_lines, 5u);
    ASSERT_EQ(s.rtl433.msgs, 0u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_NOT_OBJECT], 1u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_MALFORMED], 1u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_NO_MODEL], 1u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_NO_ID], 1u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_OVERSIZE], 1u);
    /* The sum is the bad-line count: no refusal escapes the breakout. */
    uint64_t sum = 0;
    for (int i = 0; i < RTL433_REJ_COUNT; i++) sum += s.rtl433.rej[i];
    ASSERT_EQ(sum, s.rtl433.bad_lines);
    /* The refused no-id line's `state` key was still counted. */
    ASSERT_EQ(s.rtl433.other_keys, 1u);
    ASSERT_EQ(s.rtl433_count, 0);
    rtl433_reset();
}

/* ── The change signature ──────────────────────────────────────── *
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the message count out of the signature with d->msgs mixed
 * into rtl433_device_sig(); the rssi band with the raw rssi signed in
 * place of its band; the frequency band with the raw freq_mhz signed. */
static void test_signature_bands(void) {
    rtl433_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.model, sizeof(d.model), "Testco-TP01");
    snprintf(d.id, sizeof(d.id), "1a2b3c");
    d.first_seen = 1000;
    d.protocol = 60;
    uint64_t base = rtl433_device_sig(&d);
    ASSERT(base != 0);
    ASSERT_EQ(rtl433_device_sig(NULL), 0xcbf29ce484222325ULL);

    /* The counters and the clock are not in it. */
    d.msgs = 9999;
    d.last_seen = 99999;
    d.other_keys = 1234;
    ASSERT_EQ(rtl433_device_sig(&d), base);
    /* snr and noise: their presence counts, their value does not. */
    d.has_snr = 1; d.snr_db = 22.4;
    uint64_t with_snr = rtl433_device_sig(&d);
    ASSERT(with_snr != base);
    d.snr_db = 3.1;
    ASSERT_EQ(rtl433_device_sig(&d), with_snr);
    d.has_noise = 1; d.noise_db = -22.5;
    uint64_t with_noise = rtl433_device_sig(&d);
    ASSERT(with_noise != with_snr);
    d.noise_db = -40.0;
    ASSERT_EQ(rtl433_device_sig(&d), with_noise);

    /* rssi in RTL433_RSSI_STEP_DB steps: inside one step is no change,
     * the next step is. */
    d.has_rssi = 1; d.rssi_db = -10.0;
    uint64_t r0 = rtl433_device_sig(&d);
    d.rssi_db = -11.9;
    ASSERT_EQ(rtl433_device_sig(&d), r0);        /* same 3 dB step */
    ASSERT_EQ(rtl433_rssi_band(-10.0), rtl433_rssi_band(-11.9));
    d.rssi_db = -12.1;
    ASSERT(rtl433_device_sig(&d) != r0);
    ASSERT_EQ(rtl433_rssi_band(-12.1), rtl433_rssi_band(-10.0) - 1);

    /* The frequency as whole MHz: the estimator's per-decode wobble is
     * no change, another band is. */
    d.has_freq = 1; d.freq_mhz = 433.918;
    uint64_t f0 = rtl433_device_sig(&d);
    d.freq_mhz = 433.952;
    ASSERT_EQ(rtl433_device_sig(&d), f0);
    d.freq_mhz = 868.300;
    ASSERT(rtl433_device_sig(&d) != f0);
    ASSERT_EQ(rtl433_freq_band(433.918), 433);
    ASSERT_EQ(rtl433_freq_band(868.300), 868);
    /* freq2 is the other half of the FSK pair: present or not only. */
    d.freq_mhz = 433.918;
    d.has_freq2 = 1; d.freq2_mhz = 433.952;
    uint64_t g0 = rtl433_device_sig(&d);
    ASSERT(g0 != f0);
    d.freq2_mhz = 868.000;
    ASSERT_EQ(rtl433_device_sig(&d), g0);

    /* The readings, each to one unit. */
    d.has_temp = 1; d.temp_unit = RTL433_TEMP_C; d.temp = 21.1;
    uint64_t t0 = rtl433_device_sig(&d);
    d.temp = 21.4;
    ASSERT_EQ(rtl433_device_sig(&d), t0);
    d.temp = 22.0;
    ASSERT(rtl433_device_sig(&d) != t0);
    /* The same number in the other unit is a different reading. */
    d.temp = 21.1;
    d.temp_unit = RTL433_TEMP_F;
    ASSERT(rtl433_device_sig(&d) != t0);
    d.temp_unit = RTL433_TEMP_C;

    d.has_pressure = 1; d.pres_unit = RTL433_PRES_KPA; d.pressure = 241.4;
    uint64_t p0 = rtl433_device_sig(&d);
    d.pressure = 241.1;
    ASSERT_EQ(rtl433_device_sig(&d), p0);
    d.pressure = 250.0;
    ASSERT(rtl433_device_sig(&d) != p0);
    d.pressure = 241.4;
    d.pres_unit = RTL433_PRES_PSI;
    ASSERT(rtl433_device_sig(&d) != p0);
    d.pres_unit = RTL433_PRES_KPA;

    d.has_humidity = 1; d.humidity = 63.1;
    uint64_t h0 = rtl433_device_sig(&d);
    d.humidity = 63.4;
    ASSERT_EQ(rtl433_device_sig(&d), h0);
    d.humidity = 65.0;
    ASSERT(rtl433_device_sig(&d) != h0);
    d.humidity = 63.1;

    d.has_battery = 1; d.battery_ok = 1.0;
    uint64_t b1 = rtl433_device_sig(&d);
    d.battery_ok = 0.0;
    ASSERT(rtl433_device_sig(&d) != b1);

    /* An absent value is not the same as zero. */
    rtl433_device_t z;
    memset(&z, 0, sizeof(z));
    snprintf(z.model, sizeof(z.model), "Testco-TP01");
    snprintf(z.id, sizeof(z.id), "1a2b3c");
    z.first_seen = 1000;
    z.protocol = 60;
    z.has_temp = 1; z.temp_unit = RTL433_TEMP_C; z.temp = 0.0;
    ASSERT(rtl433_device_sig(&z) != base);

    /* The discrete facts each move it. */
    rtl433_device_t e = z;
    e.has_temp = 0; e.temp_unit = RTL433_TEMP_NONE; e.temp = 0;
    ASSERT_EQ(rtl433_device_sig(&e), base);
    snprintf(e.type, sizeof(e.type), "TPMS");
    uint64_t y0 = rtl433_device_sig(&e);
    ASSERT(y0 != base);
    snprintf(e.subtype, sizeof(e.subtype), "keyfob");
    uint64_t y1 = rtl433_device_sig(&e);
    ASSERT(y1 != y0);
    snprintf(e.channel, sizeof(e.channel), "2");
    uint64_t y2 = rtl433_device_sig(&e);
    ASSERT(y2 != y1);
    snprintf(e.mic, sizeof(e.mic), "CRC");
    uint64_t y3 = rtl433_device_sig(&e);
    ASSERT(y3 != y2);
    snprintf(e.mod, sizeof(e.mod), "FSK");
    uint64_t y4 = rtl433_device_sig(&e);
    ASSERT(y4 != y3);
    e.protocol = 12;
    uint64_t y5 = rtl433_device_sig(&e);
    ASSERT(y5 != y4);
    /* A row evicted and heard again is a new row, not the old one. */
    e.first_seen = 5000;
    ASSERT(rtl433_device_sig(&e) != y5);
    /* The key is both halves. */
    rtl433_device_t k1 = e, k2 = e;
    snprintf(k2.id, sizeof(k2.id), "9z8y7x");
    ASSERT(rtl433_device_sig(&k1) != rtl433_device_sig(&k2));
    snprintf(k2.id, sizeof(k2.id), "1a2b3c");
    snprintf(k2.model, sizeof(k2.model), "Testco-TP09");
    ASSERT(rtl433_device_sig(&k1) != rtl433_device_sig(&k2));
}

/* ── The reader against a real file ────────────────────────────── */

static char g_dir[TEST_TMP_MAX];
static char g_file[TEST_TMP_MAX + 32];

static void append(const char *path, const char *body) {
    FILE *fp = fopen(path, "a");     /* what rtl_433 does */
    ASSERT(fp != NULL);
    if (!fp) return;
    fputs(body, fp);
    fclose(fp);
}

static int configure(void) {
    char spec[TEST_TMP_MAX + 48], err[200];
    snprintf(spec, sizeof(spec), "file://%s", g_file);
    rtl433_reset();
    return rtl433_reader_configure(spec, err, sizeof(err));
}

/* The first look at a file rtl_433 already wrote skips its history;
 * then new lines, a partial line held for the next poll, blank lines,
 * an overlong line skipped to its newline and counted once,
 * copytruncate (size below the offset: from 0) and a rename rotation (a
 * new inode: from 0).
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the seek-to-end with `g_at.off = sb.st_size` replaced by
 * `= 0` (the pre-run line became a device); the truncation branch with
 * its `sb.st_size < g_at.off` test removed (the shrunk file read
 * nothing); the partial-line hold with take()'s `if (!nl) break`
 * feeding the fragment (the half line became a bad line). */
static void test_reader_tails_a_file(void) {
    g_dir[0] = '\0';
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_rtl433_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/events.jsonl", g_dir);
    append(g_file, L_TPMS "\n");
    ASSERT_EQ(configure(), 0);
    ASSERT_EQ(rtl433_reader_configured(), 1);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));

    ASSERT_EQ(rtl433_reader_poll_once(1000), 0);      /* at the end */
    rtl433_health_poll(&s, 1000);
    ASSERT_EQ(s.rtl433.state, RTL433_LIVE);
    ASSERT_EQ(s.rtl433_count, 0);                     /* history not replayed */
    ASSERT_EQ(s.rtl433.lines, 0u);
    /* The label is "file:" and the path, cut to the health field's
     * width — the tmp path here is longer than it. */
    ASSERT_EQ(strncmp(s.rtl433.src, "file:/", 6), 0);

    /* New lines, a blank one, and a last line cut mid-write. */
    append(g_file, "\n" L_WX "\n{\"model\":\"Testco-TP01\",\"id\":\"9z8y");
    ASSERT(rtl433_reader_poll_once(1001) > 0);
    rtl433_health_poll(&s, 1001);
    ASSERT_EQ(s.rtl433_count, 1);
    ASSERT_STR(s.rtl433_rows[0].model, "Testco-WX9");
    ASSERT_EQ(s.rtl433.lines, 1u);          /* the blank line is none */
    ASSERT_EQ(s.rtl433.bad_lines, 0u);      /* the fragment is not yet a line */

    append(g_file, "7x\"}\n");
    ASSERT(rtl433_reader_poll_once(1002) > 0);
    rtl433_health_poll(&s, 1002);
    ASSERT_EQ(s.rtl433_count, 2);
    ASSERT_EQ(s.rtl433.msgs, 2u);
    ASSERT_EQ(s.rtl433.bad_lines, 0u);
    ASSERT_EQ(rtl433_reader_poll_once(1003), 0);      /* nothing new */

    /* An overlong line, in two appends, then a good one: one bad line. */
    static char big[RTL433_MAX_LINE + 200];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    append(g_file, big);
    ASSERT(rtl433_reader_poll_once(1004) > 0);
    append(g_file, big);
    append(g_file, "\n" L_US "\n");
    ASSERT(rtl433_reader_poll_once(1005) > 0);
    rtl433_health_poll(&s, 1005);
    ASSERT_EQ(s.rtl433.bad_lines, 1u);
    ASSERT_EQ(s.rtl433.rej[RTL433_REJ_OVERSIZE], 1u);
    ASSERT_EQ(s.rtl433.msgs, 3u);

    /* copytruncate: logrotate empties the file in place. */
    ASSERT_EQ(truncate(g_file, 0), 0);
    append(g_file, L_TPMS "\n");
    ASSERT(rtl433_reader_poll_once(1006) > 0);
    rtl433_health_poll(&s, 1006);
    ASSERT_EQ(s.rtl433.truncations, 1u);
    ASSERT_EQ(s.rtl433.msgs, 4u);

    /* A rename rotation: a new file at the path, read from its start. */
    char old[TEST_TMP_MAX + 48];
    snprintf(old, sizeof(old), "%s.1", g_file);
    ASSERT_EQ(rename(g_file, old), 0);
    append(g_file, L_WX "\n");
    ASSERT(rtl433_reader_poll_once(1007) > 0);
    rtl433_health_poll(&s, 1007);
    ASSERT_EQ(s.rtl433.rotations, 1u);
    ASSERT_EQ(s.rtl433.msgs, 5u);
    unlink(old);

    /* Missing: waiting, nothing counted; the file that appears is new
     * and read from its start (rtl_433 creates it on its first decode). */
    unlink(g_file);
    ASSERT_EQ(rtl433_reader_poll_once(1008), -1);
    rtl433_health_poll(&s, 1008);
    ASSERT_EQ(s.rtl433.state, RTL433_WAITING);
    ASSERT_EQ(s.rtl433.missing, 1);
    ASSERT_EQ(s.rtl433.read_errors, 0u);        /* missing is not an error */
    append(g_file, L_US "\n");
    ASSERT(rtl433_reader_poll_once(1009) > 0);
    rtl433_health_poll(&s, 1009);
    ASSERT_EQ(s.rtl433.state, RTL433_LIVE);
    ASSERT_EQ(s.rtl433.msgs, 6u);
    ASSERT_EQ(s.rtl433.rotations, 1u);          /* appearing is no rotation */

    /* A directory where the file should be: an error, counted. */
    unlink(g_file);
    ASSERT_EQ(mkdir(g_file, 0700), 0);
    ASSERT_EQ(rtl433_reader_poll_once(1010), -1);
    rtl433_health_poll(&s, 1010);
    ASSERT_EQ(s.rtl433.state, RTL433_ERROR);
    ASSERT_STR(s.rtl433.err, "not a regular file");
    ASSERT_EQ(s.rtl433.read_errors, 1u);
    rmdir(g_file);
    rtl433_reader_stop();
    ASSERT_EQ(rtl433_reader_configured(), 0);
    ASSERT_EQ(rtl433_reader_poll_once(1011), -1);   /* no-op once stopped */
    rmdir(g_dir);
    rtl433_reset();
}

/* A file that is not there at the first poll is read from 0 when it
 * appears, and a backlog over RTL433_POLL_BYTES takes more than one
 * poll — the bound is per poll, not per file. */
static void test_reader_new_file_and_cap(void) {
    g_dir[0] = '\0';
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_rtl433_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/events.jsonl", g_dir);
    ASSERT_EQ(configure(), 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(rtl433_reader_poll_once(1000), -1);
    FILE *fp = fopen(g_file, "a");
    ASSERT(fp != NULL);
    if (!fp) return;
    int lines = 0;
    for (long b = 0; b < (long)RTL433_POLL_BYTES + 4096; b += (long)sizeof(L_WX)) {
        fputs(L_WX "\n", fp);
        lines++;
    }
    fclose(fp);
    ASSERT_EQ(rtl433_reader_poll_once(1001), (long)RTL433_POLL_BYTES);
    ASSERT(rtl433_reader_poll_once(1002) > 0);
    ASSERT_EQ(rtl433_reader_poll_once(1003), 0);
    rtl433_health_poll(&s, 1003);
    ASSERT_EQ(s.rtl433.msgs, (uint64_t)lines);
    ASSERT_EQ(s.rtl433.bad_lines, 0u);
    ASSERT_EQ(s.rtl433_count, 1);            /* one device, many lines */
    ASSERT_EQ(s.rtl433_rows[0].msgs, (uint32_t)lines);
    rtl433_reader_stop();
    unlink(g_file);
    rmdir(g_dir);
    rtl433_reset();
}

/* A SPEC the parser refuses configures nothing. */
static void test_reader_refuses_bad_spec(void) {
    char err[200];
    rtl433_reset();
    ASSERT_EQ(rtl433_reader_configure("events.jsonl", err, sizeof(err)), -1);
    ASSERT_EQ(rtl433_reader_configured(), 0);
    ASSERT_EQ(rtl433_reader_poll_once(1000), -1);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    rtl433_health_poll(&s, 1000);
    ASSERT_EQ(s.rtl433.state, RTL433_NONE);
    ASSERT_EQ(s.rtl433.configured, 0);
    rtl433_reset();
}

/* ── The sensor registry ───────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t t_mono(void) { return g_mono; }
static time_t   t_wall(void) { return g_wall; }

static int find_sensor(const sloth_state_t *s) {
    for (int i = 0; i < s->sensor_count; i++)
        if (s->sensors[i].kind == SENSOR_RTL433) return i;
    return -1;
}

static void test_sensor_registry_rtl433(void) {
    g_wall = 1793930000; g_mono = 1000000;
    sloth_clock_test_set(t_mono, t_wall);
    rtl433_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(find_sensor(&s), -1);           /* nothing without --rtl433 */

    rtl433_set_source("file:/var/lib/rtl_433/events.jsonl");
    rtl433_note_missing();
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    int k = find_sensor(&s);
    ASSERT(k >= 0);
    if (k < 0) { sloth_clock_test_set(NULL, NULL); return; }
    ASSERT_STR(sensor_kind_name(s.sensors[k].kind), "rtl433");
    /* The registry's iface is 32 bytes, so the reference host's own
     * label is stored truncated; tests/test_sensors.c holds the lookup
     * to matching that stored form (the #208 fix). */
    ASSERT_EQ(strncmp(s.sensors[k].iface, "file:/var/lib/rtl_433/events.js",
                      sizeof(s.sensors[k].iface) - 1), 0);
    ASSERT_EQ(s.sensor_count, 1);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_PRESENT);   /* missing is no error */

    rtl433_note_read(g_wall, 0, 0, 0);
    feed(L_TPMS, g_wall);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    ASSERT_EQ(s.sensors[k].observed, 1u);

    rtl433_note_read_error("open: Permission denied");
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ERROR);
    rtl433_note_read(g_wall, 0, 0, 0);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.sensors[k].state, SENSOR_STATE_ACTIVE);
    /* SENSOR_RTL433 is appended, so every earlier kind keeps its
     * number: the kind is persisted (include/sloth.h). */
    ASSERT_EQ(SENSOR_RTL433, SENSOR_KIND_COUNT - 1);
    ASSERT_EQ(SENSOR_APRS, SENSOR_RTL433 - 1);
    ASSERT_STR(sensor_kind_name(SENSOR_KIND_COUNT), "?");
    sloth_clock_test_set(NULL, NULL);
    rtl433_reset();
}

/* ── JSONL ─────────────────────────────────────────────────────── */

static char g_jl[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_rtl433_jl_XXXXXX"));
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
    rtl433_health_poll(s, g_wall);
    jsonl_emit_rtl433(s);
}

/* rtl433_device is change-only: a device heard ten times from one spot
 * is one record, a reading that moves a band is one more, and every
 * absent field is omitted (no "humidity":0, no "mic":""). The unit
 * suffix of a reading is the key it came in under.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the one-record-per-change claim with d->msgs mixed into
 * rtl433_device_sig() (a record per decode); the no-"gone"-record claim
 * cannot be isolated by a mutation, because no code path writes one -
 * the assertion is on the absence of the string in the output and the
 * comment says so rather than claiming a proved guard. */
static void test_jsonl_device_change_only(void) {
    g_wall = 1793930000; g_mono = 2000000;
    sloth_clock_test_set(t_mono, t_wall);
    rtl433_reset();
    rtl433_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    feed(L_TPMS, g_wall);
    tick(&s);
    tick(&s);
    /* Nine more lines from the same device, nothing changed but the
     * count and the clock. */
    for (int i = 0; i < 9; i++) { feed(L_TPMS, g_wall); tick(&s); }
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"rtl433_device\""), 1);
        ASSERT(strstr(b, "\"src\":\"file:/x\",\"model\":\"Testco-TP01\","
                         "\"id\":\"1a2b3c\",\"first_seen\":1793930000,"
                         "\"last_seen\":1793930000,\"msgs\":1,") != NULL);
        ASSERT(strstr(b, "\"dev_type\":\"TPMS\",\"mic\":\"CHECKSUM\","
                         "\"mod\":\"FSK\",\"protocol\":60,"
                         "\"freq_mhz\":433.918,\"freq2_mhz\":433.952,"
                         "\"rssi\":-0.2,\"snr\":22.4,\"noise\":-22.6,"
                         "\"temperature_C\":21.0,\"pressure_kPa\":241.4,"
                         "\"other_keys\":3}") != NULL);
        /* Absent is omitted, never written as 0 or "". */
        ASSERT(strstr(b, "\"humidity\"") == NULL);
        ASSERT(strstr(b, "\"battery_ok\"") == NULL);
        ASSERT(strstr(b, "\"subtype\"") == NULL);
        ASSERT(strstr(b, "\"channel\"") == NULL);
        ASSERT(strstr(b, "\"temperature_F\"") == NULL);
        ASSERT(strstr(b, "\"pressure_psi\"") == NULL);
        /* The table retires nothing by age, so there is no gone record. */
        ASSERT(strstr(b, "\"state\":\"gone\"") == NULL);
    }
    unlink(g_jl);

    /* A reading that moves its band writes one more record; a second
     * device writes its own. */
    jl_open();
    tick(&s);                                   /* the re-baseline */
    feed("{\"model\":\"Testco-TP01\",\"type\":\"TPMS\",\"id\":\"1a2b3c\","
         "\"pressure_kPa\":260.000,\"temperature_C\":21.000,"
         "\"mic\":\"CHECKSUM\",\"mod\":\"FSK\",\"freq1\":433.918,"
         "\"freq2\":433.952,\"rssi\":-0.158,\"snr\":22.431,"
         "\"noise\":-22.589}", g_wall);
    tick(&s);
    feed(L_WX, g_wall);
    tick(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"rtl433_device\""), 3);
        ASSERT_EQ(count_of(b, "\"pressure_kPa\":260.0"), 1);
        ASSERT(strstr(b, "\"model\":\"Testco-WX9\",\"id\":\"205\"") != NULL);
        ASSERT(strstr(b, "\"channel\":\"2\",\"mic\":\"CRC\",\"mod\":\"ASK\"") != NULL);
        ASSERT(strstr(b, "\"battery_ok\":1.0") != NULL);
        ASSERT(strstr(b, "\"humidity\":63.0") != NULL);
        ASSERT(strstr(b, "\"pressure_hPa\":1013.2") != NULL);
        ASSERT(strstr(b, "\"temperature_C\":-4.5") != NULL);
        ASSERT(strstr(b, "\"freq2_mhz\"") != NULL);     /* the TPMS row's */
    }
    unlink(g_jl);

    /* The Fahrenheit / psi row goes out under ITS keys. */
    jl_open();
    feed(L_US, g_wall);
    tick(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"temperature_F\":69.8") != NULL);
        ASSERT(strstr(b, "\"pressure_psi\":35.0") != NULL);
    }
    unlink(g_jl);

    /* Nothing without --rtl433, and nothing with no sink. */
    jl_open();
    rtl433_reset();
    tick(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) ASSERT_EQ(count_of(b, "\"type\":\"rtl433_device\""), 0);
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    rtl433_reset();
}

/* sensor_health carries rtl433_* ONLY with --rtl433, and signs the
 * state and none/some bands, never the counters: ten seconds of decodes
 * and reads are no line, a read error is one.
 *
 * Absence assertions, each seen red under a named mutation and
 * restored: the block's absence without the flag with the
 * `if (s->rtl433.configured)` guard removed; the counters out of the
 * signature with `sig.rtl433_msgs = s->rtl433.msgs` added (a line per
 * decode). */
static void test_sensor_health_rtl433_block(void) {
    g_wall = 1793930000; g_mono = 3000000;
    sloth_clock_test_set(t_mono, t_wall);
    rtl433_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    rtl433_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"type\":\"sensor_health\"") != NULL);
        ASSERT(strstr(b, "\"rtl433_") == NULL);
        /* The eviction breakout is written on every run, flag or not. */
        ASSERT(strstr(b, "\"evict_rtl433\":0") != NULL);
        /* The stream's version moved with the added record. */
        ASSERT(strstr(b, "\"jsonl_version\":\"1.8.0\"") != NULL);
    }
    unlink(g_jl);

    rtl433_set_source("file:/x");
    jl_open();
    for (int i = 0; i < 10; i++) {
        g_wall++; g_mono += 1000;
        rtl433_note_read(g_wall, 100, 0, 0);
        feed(L_TPMS, g_wall);
        rtl433_health_poll(&s, g_wall);
        jsonl_emit_sensor_health(&s);
    }
    g_wall++; g_mono += 1000;
    rtl433_note_read_error("read: Input/output error");
    rtl433_health_poll(&s, g_wall);
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"sensor_health\""), 2);
        ASSERT(strstr(b, "\"rtl433_state\":\"live\",\"rtl433_src\":\"file:/x\","
                         "\"rtl433_missing\":0,\"rtl433_last_read\":1793930001,"
                         "\"rtl433_last_msg\":1793930001,\"rtl433_devices\":1,"
                         "\"rtl433_bytes\":100,\"rtl433_lines\":1,"
                         "\"rtl433_msgs\":1,\"rtl433_bad_lines\":0,"
                         "\"rtl433_rej_oversize\":0,\"rtl433_rej_not_object\":0,"
                         "\"rtl433_rej_malformed\":0,\"rtl433_rej_no_model\":0,"
                         "\"rtl433_rej_no_id\":0,\"rtl433_bad_values\":0,"
                         "\"rtl433_other_keys\":3,\"rtl433_evicted\":0,"
                         "\"rtl433_truncations\":0,\"rtl433_rotations\":0,"
                         "\"rtl433_read_errors\":0,\"rtl433_err\":\"\"") != NULL);
        ASSERT(strstr(b, "\"rtl433_state\":\"error\"") != NULL);
        ASSERT(strstr(b, "\"rtl433_err\":\"read: Input/output error\"") != NULL);
        /* The block sits before the tail test_jsonl.c pins. */
        ASSERT(strstr(b, "\"rtl433_err\":\"\",\"db_max_mb\":") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    rtl433_reset();
}

void run_rtl433_tests(void) {
    TEST_SUITE("rtl433 — rtl_433's JSON event log (#208, 2026-11-14)");
    RUN_TEST(test_tpms_line);
    RUN_TEST(test_weather_line_ask_and_integer_id);
    RUN_TEST(test_units_are_the_keys_own);
    RUN_TEST(test_blank_lines_skipped);
    RUN_TEST(test_bad_lines_refused_by_reason);
    RUN_TEST(test_oversize_line_refused);
    RUN_TEST(test_out_of_range_values_absent_not_clamped);
    RUN_TEST(test_strings_cleaned_and_bounded);
    RUN_TEST(test_nested_values_counted_not_fatal);
    RUN_TEST(test_spec_parse);
    RUN_TEST(test_table_keyed_and_sticky);
    RUN_TEST(test_table_bounded_and_eviction_tallied);
    RUN_TEST(test_states);
    RUN_TEST(test_reject_counters);
    RUN_TEST(test_signature_bands);
    RUN_TEST(test_reader_tails_a_file);
    RUN_TEST(test_reader_new_file_and_cap);
    RUN_TEST(test_reader_refuses_bad_spec);
    RUN_TEST(test_sensor_registry_rtl433);
    RUN_TEST(test_jsonl_device_change_only);
    RUN_TEST(test_sensor_health_rtl433_block);
}
