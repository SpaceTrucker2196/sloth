#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "jsonl.h"
#include "db.h"
#include "capture_side.h"
#include "rf_profile.h"

/*
 * sensor_health names its daemon (#213, JSONL 1.9.0): "wifi" from
 * `sloth`, "rf" from sloth-rf. And sloth-rf's record is `sloth`'s
 * process, receiver and decoder blocks - the same members, written by
 * the same functions (src/jsonl_internal.h) - with the capture's
 * blocks absent, not zero.
 *
 * The state is seeded by hand: the blocks read sloth_state_t and
 * nothing else. Every absence assertion names the mutation it was seen
 * red under.
 */

static char g_path[TEST_TMP_MAX];
static char g_buf[65536];

static void sink_open(void) {
    g_path[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_rfj_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    db_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
}

static const char *sink_read(void) {
    jsonl_close();
    g_buf[0] = '\0';
    FILE *fp = fopen(g_path, "r");
    if (fp) {
        size_t n = fread(g_buf, 1, sizeof(g_buf) - 1, fp);
        g_buf[n] = '\0';
        fclose(fp);
    }
    unlink(g_path);
    return g_buf;
}

/* A sensor with a receiver that has a fix and all three decoders
 * configured and live, so every flag-gated block is written. */
static void seed(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    s->gps.configured = 1;
    s->gps.has_gps = 1;
    s->gps.state = 2;
    snprintf(s->gps.src, sizeof(s->gps.src), "gpsd:127.0.0.1:2947");
    s->gps.fix_age_s = 1;
    s->gps.sats = 9;
    s->gps.hdop = 0.9;
    s->gps.sentences = 120;
    s->gps.sats_in_view = 12;
    s->gps.sats_used = 9;
    s->gps.cn0_mean = 38.5;
    s->gps.has_loc = 1;
    s->gps.loc_lat = 10.0;
    s->gps.loc_lon = -20.0;
    s->gps.loc_src = 1;
    s->adsb.configured = 1;
    s->adsb.state = ADSB_LIVE;
    snprintf(s->adsb.src, sizeof(s->adsb.src), "file:/run/test/aircraft.json");
    s->adsb.aircraft = 3;
    s->adsb.messages = 500;
    s->aprs.configured = 1;
    s->aprs.state = APRS_LIVE;
    snprintf(s->aprs.src, sizeof(s->aprs.src), "file:/run/test/aprs.log");
    s->aprs.packets = 7;
    s->aprs.freq_hz = 144390000;
    s->rtl433.configured = 1;
    s->rtl433.state = RTL433_LIVE;
    snprintf(s->rtl433.src, sizeof(s->rtl433.src), "file:/run/test/events.jsonl");
    s->rtl433.msgs = 11;
}

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* "wifi" from sloth-wifi, once, as the third member from the end:
 * after the last block and before db_max_mb and jsonl_version, which
 * stay last (tests/test_jsonl.c pins those two). The last block is the
 * twin193 one since JSONL 2.0.0, with or without decoders in the
 * state: the rtl_433 block that stood between them is sloth-rf's. */
static void test_daemon_is_wifi_from_sloth(void) {
    TEST_STATE(s);
    seed(&s);
    sink_open();
    jsonl_emit_sensor_health(&s);
    const char *out = sink_read();
    char tail[128];
    snprintf(tail, sizeof(tail), ",\"daemon\":\"wifi\",\"db_max_mb\":-1,"
                                 "\"jsonl_version\":\"%s\"}\n", SLOTH_JSONL_VERSION);
    const char *at = strstr(out, tail);
    ASSERT(at != NULL);
    if (at) ASSERT_EQ(strlen(at), strlen(tail));       /* the record ends there */
    ASSERT_EQ(count(out, "\"daemon\":"), 1);
    ASSERT(strstr(out, "\"daemon\":\"rf\"") == NULL);
    ASSERT(strstr(out, "\"twin193_excl_any\":0,\"daemon\":\"wifi\",") != NULL);
    /* And with no decoder in the state, the same. */
    memset(&s, 0, sizeof(s));
    sink_open();
    jsonl_emit_sensor_health(&s);
    out = sink_read();
    ASSERT(strstr(out, "\"twin193_excl_any\":0,\"daemon\":\"wifi\",\"db_max_mb\":-1,") != NULL);
}

/* "rf" from sloth-rf, in the same place. (Seen red with the "rf"
 * literal in jsonl_emit_sensor_health_rf() changed to "wifi".) */
static void test_daemon_is_rf_from_sloth_rf(void) {
    TEST_STATE(s);
    seed(&s);
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    const char *out = sink_read();
    char tail[128];
    snprintf(tail, sizeof(tail), ",\"daemon\":\"rf\",\"db_max_mb\":-1,"
                                 "\"jsonl_version\":\"%s\"}\n", SLOTH_JSONL_VERSION);
    const char *at = strstr(out, tail);
    ASSERT(at != NULL);
    if (at) ASSERT_EQ(strlen(at), strlen(tail));
    ASSERT_EQ(count(out, "\"daemon\":"), 1);
    ASSERT(strstr(out, "\"daemon\":\"wifi\"") == NULL);
    ASSERT(strstr(out, "\"rtl433_err\":\"\",\"daemon\":\"rf\",") != NULL);
    ASSERT_EQ(strncmp(out, "{\"type\":\"sensor_health\",\"ts\":", 29), 0);
    ASSERT_EQ(count(out, "\n"), 1);
    capture_side_install();
}

/* The field arrived additively in 1.9.0; the stream both daemons report
 * is 2.x since the cutover (#216), one macro for both, so a consumer
 * that sees "daemon" and a 2.x version knows the RF members are in the
 * other daemon's record and not missing from this one. */
static void test_version_moved_with_the_field(void) {
    int maj = 0, min = 0, pat = 0;
    ASSERT_EQ(sscanf(SLOTH_JSONL_VERSION, "%d.%d.%d", &maj, &min, &pat), 3);
    ASSERT_EQ(maj, 2);
    TEST_STATE(s);
    seed(&s);
    char want[64];
    snprintf(want, sizeof(want), "\"jsonl_version\":\"%s\"}\n", SLOTH_JSONL_VERSION);
    sink_open();
    jsonl_emit_sensor_health(&s);
    ASSERT(strstr(sink_read(), want) != NULL);
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    ASSERT(strstr(sink_read(), want) != NULL);
    capture_side_install();
}

/* sloth-wifi's record has none of the decoders' members (JSONL 2.0.0,
 * #216): not the ADS-B, APRS, APRS-region, rtl_433 or Victron block,
 * with every decoder configured and live in the state it is handed.
 * Absent, not zero - a zero would say "a decoder that is down" about a
 * host whose decoders are another daemon's. Each name is in sloth-rf's
 * record of the same state, which is what makes its absence here a
 * statement. And what stays, stays: the receiver's gps_*, gnss_* and
 * loc_* members are in both (owner ruling 2026-11-15).
 *
 * Seen red (2026-11-15), every name, with the five jsonl_sh_{adsb,aprs,
 * aprs_region,rtl433,victron}() calls put back in
 * jsonl_emit_sensor_health(); the Makefile's check_wifi_no_rf refuses
 * that link as well. */
static void test_wifi_record_has_no_rf_member(void) {
    static const char *const rf_only[] = {
        "\"adsb_state\":", "\"adsb_src\":", "\"adsb_aircraft\":",
        "\"adsb_messages\":", "\"adsb_err\":",
        "\"aprs_state\":", "\"aprs_src\":", "\"aprs_packets\":",
        "\"aprs_err\":", "\"aprs_region\":", "\"aprs_freq_hz\":",
        "\"aprs_silent\":",
        "\"rtl433_state\":", "\"rtl433_src\":", "\"rtl433_msgs\":",
        "\"rtl433_err\":",
        "\"victron_state\":", "\"victron_src\":", "\"victron_err\":",
    };
    static const char *const both[] = {
        "\"gps_state\":", "\"gps_src\":", "\"gps_sats\":",
        "\"gnss_sats_in_view\":", "\"loc_lat\":", "\"loc_lon\":",
        "\"loc_src\":",
    };
    TEST_STATE(s);
    seed(&s);
    s.victron.configured = 1;
    s.victron.state = VICTRON_LIVE;
    snprintf(s.victron.src, sizeof(s.victron.src), "file:/run/test/victron.jsonl");
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    static char rf[32768];
    snprintf(rf, sizeof(rf), "%s", sink_read());

    capture_side_install();
    sink_open();
    jsonl_emit_sensor_health(&s);
    const char *wifi = sink_read();
    ASSERT(strstr(wifi, "\"type\":\"sensor_health\"") != NULL);
    for (size_t i = 0; i < sizeof(rf_only) / sizeof(rf_only[0]); i++) {
        if (strstr(wifi, rf_only[i]))
            fprintf(stderr, "    sloth-wifi's sensor_health has %s\n", rf_only[i]);
        ASSERT(strstr(wifi, rf_only[i]) == NULL);
        if (!strstr(rf, rf_only[i]))
            fprintf(stderr, "    sloth-rf's sensor_health has no %s to compare\n",
                    rf_only[i]);
        ASSERT(strstr(rf, rf_only[i]) != NULL);
    }
    /* No member of any decoder family, whatever its name. */
    ASSERT(strstr(wifi, "\"adsb_") == NULL);
    ASSERT(strstr(wifi, "\"aprs_") == NULL);
    ASSERT(strstr(wifi, "\"rtl433_") == NULL);
    ASSERT(strstr(wifi, "\"victron_") == NULL);
    for (size_t i = 0; i < sizeof(both) / sizeof(both[0]); i++) {
        if (!strstr(wifi, both[i]))
            fprintf(stderr, "    sloth-wifi's sensor_health lost %s\n", both[i]);
        ASSERT(strstr(wifi, both[i]) != NULL);
        ASSERT(strstr(rf, both[i]) != NULL);
    }
    /* A decoder changing state is not this daemon's news: no line. */
    sink_open();
    jsonl_emit_sensor_health(&s);
    s.adsb.state = ADSB_ERROR;
    s.aprs.state = APRS_ERROR;
    s.rtl433.state = RTL433_ERROR;
    jsonl_emit_sensor_health(&s);
    ASSERT_EQ(count(sink_read(), "\"type\":\"sensor_health\""), 1);
}

/* sloth-rf's record has none of the capture's members: not the IP
 * capture, the monitor radio, the hop, the scope, the pcap export, the
 * Bluetooth sources or the twin field counts. Absent, not zero - a
 * zero would say "a capture that is down" about a host whose capture
 * is another daemon's. Each name is in `sloth`'s record of the same
 * state, which is what makes its absence here a statement. (Seen red,
 * every name, with jsonl_emit_sensor_health_rf() made to call
 * jsonl_emit_sensor_health().) */
static void test_rf_record_has_no_capture_member(void) {
    static const char *const capture_only[] = {
        "\"capture_iface\":", "\"capture_linktype\":", "\"monitor_only\":",
        "\"monitor_iface\":", "\"monitor_err\":", "\"mon_bad_clock\":",
        "\"chan_requested\":", "\"chan_retune_failures\":", "\"hop_channels\":",
        "\"hop_dwells_completed\":", "\"capture_open\":", "\"capture_recv\":",
        "\"monitor_open\":", "\"monitor_stale_secs\":",
        "\"pcap_dir_free_mb\":", "\"pcap_dir_free_inodes\":",
        "\"storage_pcap_failures\":", "\"storage_eapol_failures\":",
        "\"scope\":", "\"scope_dropped\":", "\"btmon_iface\":",
        "\"btmon_open\":", "\"ble_controllers\":", "\"ble_own_tx\":",
        "\"btcap_iface\":", "\"btcap_recv\":", "\"twin193_since\":",
        "\"twin193_excl_any\":",
    };
    TEST_STATE(s);
    seed(&s);
    sink_open();
    jsonl_emit_sensor_health(&s);
    static char wifi[32768];
    snprintf(wifi, sizeof(wifi), "%s", sink_read());

    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    const char *rf = sink_read();
    ASSERT(strstr(rf, "\"type\":\"sensor_health\"") != NULL);
    for (size_t i = 0; i < sizeof(capture_only) / sizeof(capture_only[0]); i++) {
        if (strstr(rf, capture_only[i]))
            fprintf(stderr, "    sloth-rf's sensor_health has %s\n", capture_only[i]);
        ASSERT(strstr(rf, capture_only[i]) == NULL);
        if (!strstr(wifi, capture_only[i]))
            fprintf(stderr, "    sloth's sensor_health has no %s to compare\n",
                    capture_only[i]);
        ASSERT(strstr(wifi, capture_only[i]) != NULL);
    }
    capture_side_install();
}

/* The slice of `text` from `from` up to (not including) `to`, into out.
 * 0 when either marker is missing. */
static int slice(const char *text, const char *from, const char *to,
                 char *out, size_t sz) {
    const char *a = strstr(text, from);
    const char *b = a ? strstr(a, to) : NULL;
    out[0] = '\0';
    if (!a || !b || (size_t)(b - a) >= sz) return 0;
    memcpy(out, a, (size_t)(b - a));
    out[b - a] = '\0';
    return 1;
}

/* What the two records share is the same text: each shared block of
 * sloth-wifi's record, cut out by its first and following member, is in
 * sloth-rf's record byte for byte. One function writes each block, and
 * this is what holds that a second copy has not grown beside it. */
static void test_shared_blocks_are_the_same_text(void) {
    TEST_STATE(s);
    seed(&s);
    sink_open();
    jsonl_emit_sensor_health(&s);
    static char wifi[32768];
    snprintf(wifi, sizeof(wifi), "%s", sink_read());
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    const char *rf = sink_read();

    static const struct { const char *from, *to; } blocks[] = {
        /* evictions and its breakout, to storage_failures' value */
        { "\"evictions\":",        ",\"pcap_dir_free_mb\":" },
        /* tuned knobs, the socket, parse faults */
        { "\"tuned_count\":",      ",\"rss_kb\":" },
        /* the receiver and the position: the one flag-gated block both
         * write since JSONL 2.0.0 (the decoders' are sloth-rf's alone) */
        { "\"gps_state\":",        ",\"twin193_since\":" },
        /* the tail after the daemon's own word */
        { "\"db_max_mb\":",        "\n" },
    };
    for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); i++) {
        static char blk[16384];
        int cut = slice(wifi, blocks[i].from, blocks[i].to, blk, sizeof(blk));
        if (!cut) fprintf(stderr, "    no %s block in sloth's record\n", blocks[i].from);
        ASSERT(cut);
        ASSERT_GT(strlen(blk), strlen(blocks[i].from));
        int same = cut && strstr(rf, blk) != NULL;
        if (!same) fprintf(stderr, "    block %s differs in sloth-rf's record\n",
                           blocks[i].from);
        ASSERT(same);
    }
    /* The blocks follow one another with nothing of the capture's
     * between them. */
    ASSERT(strstr(rf, ",\"storage_jsonl_failures\":0,\"tuned_count\":") != NULL);
    ASSERT(strstr(rf, ",\"gps_state\":") != NULL);
    ASSERT(strstr(rf, "\"aprs_err\":\"\",\"aprs_region\":") != NULL);
    capture_side_install();
}

/* The two fields a daemon answers for itself. sloth-rf loads no
 * libpcap and has no resolver: "pcap: none", and resolver_calls -1
 * ("not measured", src/sensor_health.h) where `sloth` reports a count.
 * (Seen red with rf_profile_select() removed: resolver_calls read 0.) */
static void test_rf_record_names_no_pcap_and_no_resolver(void) {
    TEST_STATE(s);
    seed(&s);
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    const char *rf = sink_read();
    ASSERT(strstr(rf, "\"libs\":\"pcap: none; sqlite: ") != NULL);
    ASSERT(strstr(rf, "\"resolver_calls\":-1,") != NULL);
    capture_side_install();
    sink_open();
    jsonl_emit_sensor_health(&s);
    const char *wifi = sink_read();
    ASSERT(strstr(wifi, "\"resolver_calls\":0,") != NULL);
    ASSERT(strstr(wifi, "\"libs\":\"pcap: none;") == NULL);
}

/* Change-only, like `sloth`'s: a second emit with nothing changed
 * writes nothing, a figure that moves every tick writes nothing, and a
 * state change writes one line. */
static void test_rf_record_is_change_only(void) {
    TEST_STATE(s);
    seed(&s);
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    jsonl_emit_sensor_health_rf(&s);
    s.adsb.messages += 40;
    s.aprs.packets += 1;
    s.rtl433.msgs += 3;
    s.gps.sentences += 10;
    jsonl_emit_sensor_health_rf(&s);
    ASSERT_EQ(count(sink_read(), "\"type\":\"sensor_health\""), 1);

    sink_open();
    jsonl_emit_sensor_health_rf(&s);        /* a fresh sink: the baseline */
    s.adsb.state = ADSB_ERROR;
    snprintf(s.adsb.err, sizeof(s.adsb.err), "open: No such file or directory");
    jsonl_emit_sensor_health_rf(&s);
    const char *out = sink_read();
    ASSERT_EQ(count(out, "\"type\":\"sensor_health\""), 2);
    ASSERT(strstr(out, "\"adsb_state\":\"error\"") != NULL);
    capture_side_install();
}

/* --victron in sloth-rf (the flag reached origin/main while #213 was
 * in review, and src/victron.c is in RF_SRCS): the block is in this
 * daemon's record where it is in `sloth`'s, after rtl433's and straight
 * before "daemon", only with the flag; and the tick's list writes the
 * victron_device record. (The absence seen red with the
 * `if (s->victron.configured)` guard of jsonl_sh_victron() removed;
 * the record seen red with jsonl_emit_victron() taken out of
 * jsonl_emit_state_rf().) */
static void test_rf_record_carries_victron(void) {
    TEST_STATE(s);
    seed(&s);
    rf_profile_select();
    sink_open();
    jsonl_emit_sensor_health_rf(&s);
    const char *out = sink_read();
    ASSERT(strstr(out, "\"victron_") == NULL);

    static victron_device_t row;
    memset(&row, 0, sizeof(row));
    snprintf(row.mac, sizeof(row.mac), "c7:fe:23:b1:1c:5f");
    snprintf(row.model, sizeof(row.model), "BMV-712 Smart");
    row.first_seen = row.last_seen = 1793930000;
    row.readings = 1;
    row.nvals = 1;
    snprintf(row.vals[0].name, sizeof(row.vals[0].name), "soc_pct");
    row.vals[0].v = 87.5;
    s.victron.configured = 1;
    s.victron.state = VICTRON_LIVE;
    snprintf(s.victron.src, sizeof(s.victron.src), "file:/run/test/victron.jsonl");
    s.victron.records = 1;
    s.victron.devices = 1;
    s.victron_rows = &row;
    s.victron_count = 1;
    sink_open();
    jsonl_emit_state_rf(&s);
    out = sink_read();
    ASSERT(strstr(out, "\"rtl433_err\":\"\",\"victron_state\":\"live\","
                       "\"victron_src\":\"file:/run/test/victron.jsonl\",") != NULL);
    ASSERT(strstr(out, "\"victron_err\":\"\",\"daemon\":\"rf\",") != NULL);
    ASSERT_EQ(count(out, "\"type\":\"victron_device\""), 1);
    ASSERT(strstr(out, "\"src\":\"file:/run/test/victron.jsonl\","
                       "\"mac\":\"c7:fe:23:b1:1c:5f\",\"model\":\"BMV-712 Smart\",") != NULL);
    ASSERT(strstr(out, "\"soc_pct\":87.500") != NULL);
    capture_side_install();
}

/* No sink, no work and no crash; a NULL state likewise. */
static void test_rf_emitters_without_a_sink(void) {
    TEST_STATE(s);
    seed(&s);
    jsonl_close();
    jsonl_emit_sensor_health_rf(&s);
    jsonl_emit_state_rf(&s);
    jsonl_emit_sensor_health_rf(NULL);
    jsonl_emit_state_rf(NULL);
    sink_open();
    jsonl_emit_sensor_health_rf(NULL);
    jsonl_emit_state_rf(NULL);
    ASSERT_STR(sink_read(), "");
}

void run_rf_jsonl_tests(void) {
    TEST_SUITE("sloth-rf: sensor_health and the daemon field (#213)");
    RUN_TEST(test_daemon_is_wifi_from_sloth);
    RUN_TEST(test_wifi_record_has_no_rf_member);
    RUN_TEST(test_daemon_is_rf_from_sloth_rf);
    RUN_TEST(test_version_moved_with_the_field);
    RUN_TEST(test_rf_record_has_no_capture_member);
    RUN_TEST(test_shared_blocks_are_the_same_text);
    RUN_TEST(test_rf_record_names_no_pcap_and_no_resolver);
    RUN_TEST(test_rf_record_is_change_only);
    RUN_TEST(test_rf_record_carries_victron);
    RUN_TEST(test_rf_emitters_without_a_sink);
}
