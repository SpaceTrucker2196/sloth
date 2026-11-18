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
#include "victron.h"
#include "capture/victron_reader.h"
#include "jsonl.h"
#include "poll.h"
#include "sensors.h"
#include "sloth_clock.h"
#include "va/va_victron.h"

/* --victron (2026-11-15): sloth's reader of sloth-va's JSONL.
 *
 * The lines are written BY HAND to the shape docs/wiki/victron.md and
 * va_record_jsonl() give, and one test feeds sloth-va's own writer into
 * this reader (the contract between the two binaries; sloth_test links
 * va_victron.c, sloth does not).
 *
 * Absence assertions, each seen red under the named mutation and then
 * restored (docs/wiki/log.md, the 2026-11-15 --victron entry):
 *   - test_out_of_range_absent: the bound test in parse_values() made
 *     always true (an SOC of 150 % kept);
 *   - test_signature_bands: victron_value_band() returning the value x
 *     1000 unbanded (13.20 -> 13.22 V moved the signature);
 *   - test_table_refuses_a_17th: `else g.table_full++;` dropped (the
 *     refused records went uncounted). Raising the cap instead overran
 *     the array and crashed the suite, which is red but not a clean
 *     reading, so the count is the mutation named here;
 *   - test_sensor_health_block: `if (s->victron.configured)` removed
 *     from the block in jsonl.c (victron_* written without the flag);
 *   - test_services_kept_as_uuids: services_take()'s charset test
 *     removed (a list with a quote and a space kept);
 *   - test_services_follow_the_session: the services copy in merge()
 *     made conditional on a non-empty list (the next session's empty
 *     list left the old one standing).
 */

#define L_BMV "{\"type\":\"victron\",\"t\":1763200000,\"source\":\"readout\"," \
    "\"mac\":\"C7:FE:23:B1:1C:5F\",\"serial\":\"HQ2501YV9FU\"," \
    "\"label\":\"BMV-712 \\\"x\\\"\\u000a\",\"model_id\":\"0xa381\"," \
    "\"model\":\"BMV-712 Smart\",\"record\":\"battery_monitor\",\"rssi\":-71," \
    "\"values\":{\"voltage_v\":13.200,\"alarm_reason\":0,\"aux_input\":3," \
    "\"aux_input_name\":\"none\",\"current_a\":-1.500,\"consumed_ah\":-12.300," \
    "\"soc_pct\":87.500}}"

#define L_GATT "{\"type\":\"victron\",\"t\":1763200300,\"source\":\"gatt\"," \
    "\"mac\":\"c7:fe:23:b1:1c:5f\",\"serial\":\"HQ2501YV9FU\",\"session\":\"ok\"," \
    "\"values\":{\"voltage_v\":13.210,\"power_w\":-20.000}}"

static const victron_val_t *mval(const victron_msg_t *m, const char *n) {
    for (int i = 0; i < m->nvals; i++)
        if (!strcmp(m->vals[i].name, n)) return &m->vals[i];
    return NULL;
}

static const victron_val_t *dval(const victron_device_t *d, const char *n) {
    for (int i = 0; i < d->nvals; i++)
        if (!strcmp(d->vals[i].name, n)) return &d->vals[i];
    return NULL;
}

static void test_readout_line(void) {
    victron_msg_t m;
    int why = -1;
    ASSERT_EQ(victron_line_parse(L_BMV, strlen(L_BMV), &m, &why), 1);
    ASSERT_STR(m.mac, "c7:fe:23:b1:1c:5f");          /* lower-cased */
    ASSERT_STR(m.serial, "HQ2501YV9FU");
    ASSERT_STR(m.model, "BMV-712 Smart");
    ASSERT_STR(m.record, "battery_monitor");
    ASSERT_EQ(m.gatt, 0);
    ASSERT(m.has_rssi && m.rssi == -71);
    ASSERT_EQ(m.nvals, 6);
    const victron_val_t *v;
    ASSERT((v = mval(&m, "voltage_v")) && v->v > 13.199 && v->v < 13.201);
    ASSERT((v = mval(&m, "current_a")) && v->v > -1.501 && v->v < -1.499);
    ASSERT((v = mval(&m, "soc_pct")) && v->v > 87.49 && v->v < 87.51);
    ASSERT(mval(&m, "aux_input_name") == NULL);       /* derived: skipped */
    ASSERT_EQ(m.other_keys, 0u);
    ASSERT_EQ(m.bad_values, 0u);
    const char *unit;
    ASSERT(victron_value_known("consumed_ah", &unit) && !strcmp(unit, "Ah"));
    ASSERT(!victron_value_known("label", &unit));
}

static void test_gatt_line_and_blank(void) {
    victron_msg_t m;
    int why;
    ASSERT_EQ(victron_line_parse(L_GATT, strlen(L_GATT), &m, &why), 1);
    ASSERT_EQ(m.gatt, 1);
    ASSERT_STR(m.session, "ok");
    ASSERT(mval(&m, "power_w") != NULL);
    ASSERT_EQ(victron_line_parse("  \r", 3, &m, &why), 0);
    /* A session record with no serial and no values. */
    const char *l = "{\"type\":\"victron\",\"t\":5,\"source\":\"gatt\",\"mac\":\"e4:b9:aa:47:57:1f\","
                    "\"serial\":null,\"session\":\"no_supported_service\","
                    "\"services\":\"306b0001-b081-4037-83dc-e59fcc3cdfd0\",\"values\":{}}";
    ASSERT_EQ(victron_line_parse(l, strlen(l), &m, &why), 1);
    ASSERT_EQ(m.serial[0], '\0');
    ASSERT_STR(m.session, "no_supported_service");
    ASSERT_EQ(m.nvals, 0);
}

static void test_bad_lines_refused_by_reason(void) {
    static const struct { const char *l; int why; } C[] = {
        { "[1,2]", VICTRON_REJ_NOT_OBJECT },
        { "{\"type\":\"victron\"} x", VICTRON_REJ_NOT_OBJECT },
        { "{\"type\":\"victron\",", VICTRON_REJ_MALFORMED },
        { "{\"type\":\"victron\",\"values\":{\"voltage_v\":}}", VICTRON_REJ_MALFORMED },
        { "{\"type\":\"rtl433_device\",\"source\":\"gatt\",\"mac\":\"c7:fe:23:b1:1c:5f\"}", VICTRON_REJ_NOT_VICTRON },
        { "{\"type\":\"victron\",\"source\":\"other\",\"mac\":\"c7:fe:23:b1:1c:5f\"}", VICTRON_REJ_NOT_VICTRON },
        { "{\"type\":\"victron\",\"source\":\"gatt\"}", VICTRON_REJ_NO_MAC },
        { "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"c7:fe:23:b1:1c\"}", VICTRON_REJ_NO_MAC },
        { "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"c7-fe-23-b1-1c-5f\"}", VICTRON_REJ_NO_MAC },
    };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) {
        victron_msg_t m;
        int why = -1;
        int r = victron_line_parse(C[i].l, strlen(C[i].l), &m, &why);
        if (r != -1 || why != C[i].why)
            fprintf(stderr, "    case %zu: r %d why %d\n", i, r, why);
        ASSERT(r == -1 && why == C[i].why);
    }
    static char big[VICTRON_MAX_LINE + 10];
    memset(big, ' ', sizeof(big) - 1);
    big[0] = '{';
    victron_msg_t m;
    int why = -1;
    ASSERT_EQ(victron_line_parse(big, sizeof(big) - 1, &m, &why), -1);
    ASSERT_EQ(why, VICTRON_REJ_OVERSIZE);
    ASSERT_STR(victron_reject_name(VICTRON_REJ_NO_MAC), "no_mac");
    ASSERT_STR(victron_reject_name(99), "");
}

/* Out of range is absent and counted, never clamped; an unknown name is
 * counted and dropped; the device's own label is not kept anywhere. */
static void test_out_of_range_absent(void) {
    const char *l = "{\"type\":\"victron\",\"source\":\"readout\",\"mac\":\"c7:fe:23:b1:1c:5f\","
                    "\"model\":\"<script>\\u0007\",\"values\":{\"soc_pct\":150.0,\"voltage_v\":13.2,"
                    "\"frobs\":7,\"off_reason\":-1,\"rssi_like\":{\"a\":1}}}";
    victron_msg_t m;
    int why;
    ASSERT_EQ(victron_line_parse(l, strlen(l), &m, &why), 1);
    ASSERT(mval(&m, "soc_pct") == NULL);
    ASSERT(mval(&m, "off_reason") == NULL);
    ASSERT(mval(&m, "voltage_v") != NULL);
    ASSERT_EQ(m.bad_values, 2u);
    ASSERT_EQ(m.other_keys, 2u);
    ASSERT_STR(m.model, "scriptu0007");      /* cleaned: no <, >, backslash */
    ASSERT(strchr(m.model, '<') == NULL);
}

/* The contract: what sloth-va's writer puts out, this reader takes in. */
static void test_reads_sloth_va_records(void) {
    va_value_t vals[3] = {
        { "voltage_v", "V", 12.53, 0, NULL },
        { "device_state", "", 3, 1, "bulk" },
        { "soc_pct", "%", 50.0, 0, NULL },
    };
    va_record_t r;
    memset(&r, 0, sizeof(r));
    r.source = "readout";
    r.t = 1763200000;
    const uint8_t mac[6] = { 0xf5, 0xd8, 0x0c, 0xb6, 0x31, 0xcf };
    memcpy(r.mac, mac, 6);
    r.serial = "HQ2515QP3RX";
    r.label = "Orion \"van\"\n";
    r.has_model = 1;
    r.model_id = 0xA3C0;
    r.record_type = 0x04;
    r.nvals = 3;
    r.vals = vals;
    char buf[1024];
    int n = va_record_jsonl(&r, buf, sizeof(buf));
    ASSERT(n > 0);
    victron_msg_t m;
    int why;
    ASSERT_EQ(victron_line_parse(buf, (size_t)n - 1, &m, &why), 1);
    ASSERT_STR(m.mac, "f5:d8:0c:b6:31:cf");
    ASSERT_STR(m.serial, "HQ2515QP3RX");
    ASSERT_STR(m.model, "Orion Smart 12V/12V-18A");
    ASSERT_STR(m.record, "dcdc_converter");
    ASSERT_EQ(m.nvals, 3);
    const victron_val_t *v = mval(&m, "device_state");
    ASSERT(v && v->v == 3);
    ASSERT_EQ(m.other_keys, 0u);
}

static void test_spec_parse(void) {
    char p[64], e[160];
    ASSERT_EQ(victron_spec_parse("/var/lib/sloth-va/victron.jsonl", p, sizeof(p), e, sizeof(e)), 0);
    ASSERT_STR(p, "/var/lib/sloth-va/victron.jsonl");
    ASSERT_EQ(victron_spec_parse("file:///a/b.jsonl", p, sizeof(p), e, sizeof(e)), 0);
    ASSERT_STR(p, "/a/b.jsonl");
    ASSERT_EQ(victron_spec_parse("file://host/a", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(victron_spec_parse("http://x/y", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(victron_spec_parse("rel/path", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(victron_spec_parse("/dir/", p, sizeof(p), e, sizeof(e)), -1);
    ASSERT_EQ(victron_spec_parse("", p, sizeof(p), e, sizeof(e)), -1);
}

/* Sticky merge: a GATT record without SOC keeps the readout's SOC. */
static void test_table_sticky(void) {
    victron_reset();
    victron_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(victron_feed_line(L_BMV, strlen(L_BMV), 1000), 1);
    ASSERT_EQ(victron_feed_line(L_GATT, strlen(L_GATT), 1300), 1);
    ASSERT_EQ(victron_feed_line("garbage", 7, 1301), -1);
    victron_health_poll(&s, 1301);
    ASSERT_EQ(s.victron_count, 1);
    const victron_device_t *d = &s.victron_rows[0];
    ASSERT_STR(d->mac, "c7:fe:23:b1:1c:5f");
    ASSERT_EQ(d->first_seen, 1000);
    ASSERT_EQ(d->last_readout, 1000);
    ASSERT_EQ(d->last_gatt, 1300);
    ASSERT_EQ(d->readings, 2u);
    ASSERT_EQ(d->sessions, 1u);
    ASSERT_STR(d->session, "ok");
    const victron_val_t *v;
    ASSERT((v = dval(d, "soc_pct")) && v->v > 87.49);
    ASSERT((v = dval(d, "voltage_v")) && v->v > 13.209 && v->v < 13.211);
    ASSERT(dval(d, "power_w") != NULL);
    ASSERT_EQ(s.victron.records, 2u);
    ASSERT_EQ(s.victron.lines, 3u);
    ASSERT_EQ(s.victron.bad_lines, 1u);
    ASSERT_EQ(s.victron.rej[VICTRON_REJ_NOT_OBJECT], 1u);
    ASSERT_EQ(s.victron.state, VICTRON_WAITING);       /* no read noted yet */
    victron_note_read(1302, 10, 0, 0);
    victron_health_poll(&s, 1302);
    ASSERT_EQ(s.victron.state, VICTRON_LIVE);
    victron_note_read_error("read: Input/output error");
    victron_health_poll(&s, 1303);
    ASSERT_EQ(s.victron.state, VICTRON_ERROR);
    victron_reset();
    victron_health_poll(&s, 1304);
    ASSERT_EQ(s.victron.state, VICTRON_NONE);
    ASSERT_EQ(s.victron_count, 0);
}

/* sloth-va lists a session's services only for no_supported_service
 * (docs/wiki/victron.md); sloth keeps that list as lower-case UUIDs
 * joined by ',' and nothing else. A list with any other byte, or longer
 * than sloth-va's cap, is absent rather than cleaned or cut. */
static void test_services_kept_as_uuids(void) {
    victron_msg_t m;
    int why;
    const char *ok = "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"e4:b9:aa:47:57:1f\","
                     "\"session\":\"no_supported_service\","
                     "\"services\":\"306B0001-B081-4037-83DC-E59FCC3CDFD0,00001800-0000-1000-8000-00805f9b34fb\","
                     "\"values\":{}}";
    ASSERT_EQ(victron_line_parse(ok, strlen(ok), &m, &why), 1);
    ASSERT_STR(m.services, "306b0001-b081-4037-83dc-e59fcc3cdfd0,"
                           "00001800-0000-1000-8000-00805f9b34fb");
    const char *bad = "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"e4:b9:aa:47:57:1f\","
                      "\"services\":\"306b0001 \\\"x\",\"values\":{}}";
    ASSERT_EQ(victron_line_parse(bad, strlen(bad), &m, &why), 1);
    ASSERT_STR(m.services, "");
    /* One byte over the cap: absent, not cut to fit. */
    static char line[VICTRON_MAX_LINE];
    char list[VICTRON_SERVICES_MAX + 2];
    memset(list, 'a', VICTRON_SERVICES_MAX + 1);
    list[VICTRON_SERVICES_MAX + 1] = '\0';
    snprintf(line, sizeof(line), "{\"type\":\"victron\",\"source\":\"gatt\","
             "\"mac\":\"e4:b9:aa:47:57:1f\",\"services\":\"%s\",\"values\":{}}", list);
    ASSERT_EQ(victron_line_parse(line, strlen(line), &m, &why), 1);
    ASSERT_STR(m.services, "");
    list[VICTRON_SERVICES_MAX] = '\0';
    snprintf(line, sizeof(line), "{\"type\":\"victron\",\"source\":\"gatt\","
             "\"mac\":\"e4:b9:aa:47:57:1f\",\"services\":\"%s\",\"values\":{}}", list);
    ASSERT_EQ(victron_line_parse(line, strlen(line), &m, &why), 1);
    ASSERT_EQ((long long)strlen(m.services), VICTRON_SERVICES_MAX);
}

/* The list is the newest session's: a later session that names none
 * clears it, a readout leaves it. vals_gatt follows the newest record
 * that carried values, not a value-less session. The record carries
 * both, and a change of either is a change. */
static void test_services_follow_the_session(void) {
    victron_reset();
    victron_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const char *nss = "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"c7:fe:23:b1:1c:5f\","
                      "\"session\":\"no_supported_service\","
                      "\"services\":\"306b0001-b081-4037-83dc-e59fcc3cdfd0\",\"values\":{}}";
    const char *to = "{\"type\":\"victron\",\"source\":\"gatt\",\"mac\":\"c7:fe:23:b1:1c:5f\","
                     "\"session\":\"timeout\",\"values\":{}}";
    ASSERT_EQ(victron_feed_line(L_BMV, strlen(L_BMV), 1000), 1);
    victron_health_poll(&s, 1000);
    ASSERT_EQ(s.victron_rows[0].vals_gatt, 0);
    uint64_t sig0 = victron_device_sig(&s.victron_rows[0]);
    ASSERT_EQ(victron_feed_line(nss, strlen(nss), 1100), 1);
    victron_health_poll(&s, 1100);
    ASSERT_STR(s.victron_rows[0].services, "306b0001-b081-4037-83dc-e59fcc3cdfd0");
    ASSERT_EQ(s.victron_rows[0].vals_gatt, 0);        /* no values in that session */
    uint64_t sig1 = victron_device_sig(&s.victron_rows[0]);
    ASSERT(sig1 != sig0);
    ASSERT_EQ(victron_feed_line(L_BMV, strlen(L_BMV), 1130), 1);
    victron_health_poll(&s, 1130);
    ASSERT_STR(s.victron_rows[0].services, "306b0001-b081-4037-83dc-e59fcc3cdfd0");
    ASSERT_EQ(victron_feed_line(to, strlen(to), 1400), 1);
    victron_health_poll(&s, 1400);
    ASSERT_STR(s.victron_rows[0].services, "");
    ASSERT_STR(s.victron_rows[0].session, "timeout");
    ASSERT_EQ(victron_feed_line(L_GATT, strlen(L_GATT), 1700), 1);
    victron_health_poll(&s, 1700);
    ASSERT_EQ(s.victron_rows[0].vals_gatt, 1);
    uint64_t sig2 = victron_device_sig(&s.victron_rows[0]);
    victron_device_t d = s.victron_rows[0];
    d.vals_gatt = 0;
    ASSERT(victron_device_sig(&d) != sig2);
    victron_reset();
}

static void test_table_refuses_a_17th(void) {
    victron_reset();
    victron_set_source("file:/x");
    for (int i = 0; i < VICTRON_MAX_DEVICES + 3; i++) {
        char l[256];
        snprintf(l, sizeof(l), "{\"type\":\"victron\",\"source\":\"readout\","
                 "\"mac\":\"aa:bb:cc:dd:ee:%02x\",\"values\":{\"voltage_v\":12.0}}", i);
        ASSERT_EQ(victron_feed_line(l, strlen(l), 2000 + i), 1);
    }
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    victron_health_poll(&s, 2100);
    ASSERT_EQ(s.victron_count, VICTRON_MAX_DEVICES);
    ASSERT_EQ(s.victron.devices, VICTRON_MAX_DEVICES);
    ASSERT_EQ(s.victron.table_full, 3u);
    ASSERT_STR(s.victron_rows[0].mac, "aa:bb:cc:dd:ee:00");   /* the first kept */
    victron_reset();
}

/* A reading that stays in its band does not move the signature; one
 * that leaves it does; counts and clocks never do. */
static void test_signature_bands(void) {
    victron_device_t a, b;
    memset(&a, 0, sizeof(a));
    snprintf(a.mac, sizeof(a.mac), "c7:fe:23:b1:1c:5f");
    a.first_seen = 1000;
    a.nvals = 2;
    snprintf(a.vals[0].name, sizeof(a.vals[0].name), "voltage_v");
    a.vals[0].v = 13.20;
    snprintf(a.vals[1].name, sizeof(a.vals[1].name), "soc_pct");
    a.vals[1].v = 87.5;
    b = a;
    b.vals[0].v = 13.22;
    b.readings = 99; b.sessions = 4; b.last_seen = 5000; b.rssi = -40; b.has_rssi = 1;
    ASSERT_EQ(victron_device_sig(&a), victron_device_sig(&b));
    b.vals[0].v = 13.40;
    ASSERT(victron_device_sig(&a) != victron_device_sig(&b));
    /* Order of arrival does not matter. */
    b = a;
    b.vals[0] = a.vals[1];
    b.vals[1] = a.vals[0];
    ASSERT_EQ(victron_device_sig(&a), victron_device_sig(&b));
    /* Present at zero is not absent. */
    b = a;
    b.nvals = 1;
    victron_device_t c = b;
    c.nvals = 2;
    c.vals[1].v = 0;
    ASSERT(victron_device_sig(&b) != victron_device_sig(&c));
    ASSERT_EQ(victron_value_band("voltage_v", 13.24), 132);
    ASSERT_EQ(victron_value_band("off_reason", 128), 128);
    /* A session outcome is a change. */
    b = a;
    snprintf(b.session, sizeof(b.session), "pair_failed");
    ASSERT(victron_device_sig(&a) != victron_device_sig(&b));
}

/* ── the reader ── */

static char g_dir[TEST_TMP_MAX];
static char g_file[TEST_TMP_MAX + 32];

static void append(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    ASSERT(fd >= 0);
    if (fd < 0) return;
    ssize_t w = write(fd, text, strlen(text));
    ASSERT_EQ(w, (ssize_t)strlen(text));
    close(fd);
}

static void test_reader_tails_a_file(void) {
    victron_reset();
    ASSERT(mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_victron_XXXXXX")) != NULL);
    snprintf(g_file, sizeof(g_file), "%s/victron.jsonl", g_dir);
    char spec[TEST_TMP_MAX + 64], err[160];
    snprintf(spec, sizeof(spec), "%s", g_file);
    /* Not there yet: waiting, not an error. */
    ASSERT_EQ(victron_reader_configure(spec, err, sizeof(err)), 0);
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(victron_reader_poll_once(1000), -1);
    victron_health_poll(&s, 1000);
    ASSERT_EQ(s.victron.state, VICTRON_WAITING);
    ASSERT_EQ(s.victron.missing, 1);
    /* sloth-va creates it: read from 0, a partial line held. */
    append(g_file, L_BMV "\n{\"type\":\"victron\",\"source\":\"gatt\",");
    ASSERT(victron_reader_poll_once(1001) > 0);
    victron_health_poll(&s, 1001);
    ASSERT_EQ(s.victron.state, VICTRON_LIVE);
    ASSERT_EQ(s.victron.records, 1u);
    ASSERT_EQ(s.victron.bad_lines, 0u);
    append(g_file, "\"mac\":\"f5:d8:0c:b6:31:cf\",\"session\":\"no_values\",\"values\":{}}\n");
    ASSERT(victron_reader_poll_once(1002) > 0);
    victron_health_poll(&s, 1002);
    ASSERT_EQ(s.victron.records, 2u);
    ASSERT_EQ(s.victron_count, 2);
    ASSERT_EQ(victron_reader_poll_once(1003), 0);
    /* Rotation: a new file at the path is read from its start. */
    char old[TEST_TMP_MAX + 48];
    snprintf(old, sizeof(old), "%s.1", g_file);
    ASSERT_EQ(rename(g_file, old), 0);
    append(g_file, L_GATT "\n");
    ASSERT(victron_reader_poll_once(1004) > 0);
    victron_health_poll(&s, 1004);
    ASSERT_EQ(s.victron.rotations, 1u);
    ASSERT_EQ(s.victron.records, 3u);
    victron_reader_stop();
    unlink(old);
    unlink(g_file);
    rmdir(g_dir);
    ASSERT_EQ(victron_reader_configure("relative", err, sizeof(err)), -1);
    victron_reset();
}

/* ── the sensor and the stream ── */

static time_t   g_wall;
static uint64_t g_mono;
static time_t   t_wall(void) { return g_wall; }
static uint64_t t_mono(void) { return g_mono; }
static char g_jl[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_victron_jl_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jl);
    ASSERT(jsonl_open(g_jl));
}

static char *read_all(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[131072];
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

static void test_sensor_registered(void) {
    victron_reset();
    victron_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    ctx.wall = 3000;
    poll_st_health_rf(&s, &ctx);
    poll_st_sensors_rf(&s, &ctx);
    int at = -1;
    for (int i = 0; i < s.sensor_count; i++)
        if (s.sensors[i].kind == SENSOR_VICTRON) at = i;
    ASSERT(at >= 0);
    if (at >= 0) {
        ASSERT_STR(s.sensors[at].iface, "file:/x");
        ASSERT_EQ(s.sensors[at].state, SENSOR_STATE_PRESENT);
    }
    ASSERT_STR(sensor_kind_name(SENSOR_VICTRON), "victron");
    ASSERT_EQ(SENSOR_VICTRON, SENSOR_KIND_COUNT - 1);
    victron_reset();
}

/* victron_device: one record while nothing leaves its band, another
 * when a value does. sensor_health carries the block only with the
 * flag. */
static void test_jsonl_device_change_only(void) {
    g_wall = 1793930000; g_mono = 2000000;
    sloth_clock_test_set(t_mono, t_wall);
    victron_reset();
    victron_set_source("file:/x");
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    for (int i = 0; i < 8; i++) {
        victron_feed_line(L_BMV, strlen(L_BMV), g_wall);
        g_wall++; g_mono += 1000;
        victron_health_poll(&s, g_wall);
        jsonl_emit_victron(&s);
    }
    victron_feed_line(L_GATT, strlen(L_GATT), g_wall);
    g_wall++; g_mono += 1000;
    victron_health_poll(&s, g_wall);
    jsonl_emit_victron(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_of(b, "\"type\":\"victron_device\""), 2);
        ASSERT(strstr(b, "\"src\":\"file:/x\",\"mac\":\"c7:fe:23:b1:1c:5f\","
                         "\"serial\":\"HQ2501YV9FU\",\"model\":\"BMV-712 Smart\","
                         "\"record\":\"battery_monitor\"") != NULL);
        ASSERT(strstr(b, "\"soc_pct\":87.500") != NULL);
        ASSERT(strstr(b, "\"session\":\"ok\"") != NULL);
        ASSERT(strstr(b, "\"values_src\":\"readout\"") != NULL);
        ASSERT(strstr(b, "\"values_src\":\"gatt\"") != NULL);
        ASSERT(strstr(b, "\"services\"") == NULL);              /* none listed */
        ASSERT(strstr(b, "BMV-712 \\\"x") == NULL);           /* the label never */
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    victron_reset();
}

static void test_sensor_health_block(void) {
    g_wall = 1793930000; g_mono = 3000000;
    sloth_clock_test_set(t_mono, t_wall);
    victron_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    jl_open();
    victron_health_poll(&s, g_wall);
    jsonl_emit_sensor_health_rf(&s);
    jsonl_close();
    char *b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) ASSERT(strstr(b, "\"victron_") == NULL);
    unlink(g_jl);
    victron_set_source("file:/x");
    jl_open();
    victron_note_read(g_wall, 50, 0, 0);
    victron_feed_line(L_BMV, strlen(L_BMV), g_wall);
    victron_health_poll(&s, g_wall);
    jsonl_emit_sensor_health_rf(&s);
    jsonl_close();
    b = read_all(g_jl);
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"victron_state\":\"live\",\"victron_src\":\"file:/x\","
                         "\"victron_missing\":0") != NULL);
        ASSERT(strstr(b, "\"victron_devices\":1") != NULL);
        ASSERT(strstr(b, "\"victron_records\":1") != NULL);
        ASSERT(strstr(b, "\"victron_rej_no_mac\":0") != NULL);
        ASSERT(strstr(b, "\"victron_err\":\"\"") != NULL);
    }
    unlink(g_jl);
    sloth_clock_test_set(NULL, NULL);
    victron_reset();
}

void run_victron_tests(void) {
    TEST_SUITE("--victron (sloth-va's JSONL)");
    RUN_TEST(test_readout_line);
    RUN_TEST(test_gatt_line_and_blank);
    RUN_TEST(test_bad_lines_refused_by_reason);
    RUN_TEST(test_out_of_range_absent);
    RUN_TEST(test_reads_sloth_va_records);
    RUN_TEST(test_spec_parse);
    RUN_TEST(test_table_sticky);
    RUN_TEST(test_services_kept_as_uuids);
    RUN_TEST(test_services_follow_the_session);
    RUN_TEST(test_table_refuses_a_17th);
    RUN_TEST(test_signature_bands);
    RUN_TEST(test_reader_tails_a_file);
    RUN_TEST(test_sensor_registered);
    RUN_TEST(test_jsonl_device_change_only);
    RUN_TEST(test_sensor_health_block);
}
