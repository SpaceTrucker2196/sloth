#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "frame_build.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "sys_status.h"
#include "capture_side.h"
#include "jsonl.h"
#include "db.h"
#include "radiotap.h"
#include "mon_radios.h"
#include "wifi_chanhop.h"
#include "dot11_frame.h"
#include "cov_interval.h"
#include "cov_interval_capture.h"
#include "capture/probe.h"
#include "poll.h"
#include "reset_all.h"
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/*
 * The per-interval coverage record (#242 item 2): the frame classes,
 * the scheduler's per-channel time, the sampler that builds a minute
 * from them, the record and its cadence.
 *
 * Frames are hand-built per IEEE 802.11-2020 (tests/frame_build.h).
 * Schedulers are driven with a synthetic clock, as the poll loop drives
 * them: the hop step first, then the sampler.
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static char g_path[TEST_TMP_MAX];
static char g_buf[1 << 16];

static const uint8_t M_AP[6]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t M_STA[6] = { 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa };

static void begin(void) {
    capture_side_install();
    g_mono = 7000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    mon_radios_reset();
    cov_iv_capture_set_hop0(NULL);
    cov_iv_capture_reset();
#ifdef WITH_PCAP
    probe_test_reset_freshness();    /* radio 0's newest frequency */
#endif
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    jsonl_close();
    fake_net_reset();
    sys_status_reset();
    mon_radios_reset();
    cov_iv_capture_set_hop0(NULL);
    cov_iv_capture_reset();
    sloth_clock_test_set(NULL, NULL);
}

static void sink_open(void) {
    g_path[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_covi_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
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

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static void monitor_up(void) {
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    g_s.mon_health.open = 1;
    g_s.mon_health.running = 1;
    g_s.mon_health.stale_secs = 0;
}

/* The sampler's stage, after the hop stage, as the poll table runs it;
 * the health stage first so the source rows are this tick's. */
static void sample(void) {
    sys_status_poll(&g_s, g_wall, g_mono);
    cov_iv_capture_poll(&g_s, g_wall, g_mono);
}

/* ── Frame classes ──────────────────────────────────────────────── */

static int classify(const uint8_t *f, int n, int datapad, int bad_fcs) {
    dot11_rt_hints_t h = { 0, datapad, bad_fcs };
    dot11_frame_t fr;
    dot11_frame_decode(f, n, &h, &fr);
    return cov_frame_class(&fr, bad_fcs);
}

static int mgmt(uint8_t *buf, int cap, uint8_t sub) {
    fb_t b; fb_init(&b, buf, cap);
    fb_mgmt(&b, sub, 0, M_STA, M_AP, M_AP, 0x0010, 0);
    fb_u8(&b, 0); fb_u8(&b, 0);            /* two body octets */
    return fb_ok(&b) ? b.len : -1;
}

/* A data frame from the AP (FromDS, Table 9-26), QoS when asked, with
 * an LLC/SNAP header carrying `et` (IEEE 802.2 / RFC 1042). */
static int data_frame(uint8_t *buf, int cap, int qos, uint8_t extra,
                      int datapad, uint16_t et) {
    fb_t b; fb_init(&b, buf, cap);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = qos ? 8 : 0;
    h.flags = (uint8_t)(FB_FROMDS | extra);
    h.a1 = M_STA; h.a2 = M_AP; h.a3 = M_AP;
    h.qos_present = qos;
    fb_dot11_hdr(&b, &h);
    if (datapad) fb_datapad_to4(&b, 0);
    fb_llc_snap(&b, et);
    fb_u8(&b, 0x02); fb_u8(&b, 0x03); fb_be16(&b, 0);   /* 802.1X v2, Key */
    return fb_ok(&b) ? b.len : -1;
}

static void test_frame_classes(void) {
    uint8_t f[128];
    /* Management subtypes, Table 9-1. */
    static const struct { uint8_t sub; int fc; } m[] = {
        { 8, COV_FC_BEACON }, { 5, COV_FC_BEACON }, { 4, COV_FC_PROBE },
        { 11, COV_FC_AUTH }, { 0, COV_FC_ASSOC }, { 1, COV_FC_ASSOC },
        { 2, COV_FC_ASSOC }, { 3, COV_FC_ASSOC }, { 10, COV_FC_DEAUTH },
        { 12, COV_FC_DEAUTH }, { 13, COV_FC_ACTION }, { 14, COV_FC_ACTION },
        { 6, COV_FC_OTHER },  /* Timing Advertisement: no rule reads it */
        { 9, COV_FC_OTHER },  /* ATIM */
    };
    for (size_t i = 0; i < sizeof(m) / sizeof(*m); i++) {
        int n = mgmt(f, sizeof f, m[i].sub);
        ASSERT(n > 0);
        ASSERT_EQ(classify(f, n, 0, 0), m[i].fc);
    }
    /* Control: CTS (RA only, 10 octets) and RTS. */
    {
        fb_t b; fb_init(&b, f, sizeof f);
        fb_ctrl_hdr(&b, 12, 0, 0, M_STA, NULL);
        ASSERT_EQ(classify(f, b.len, 0, 0), COV_FC_CTRL);
        fb_init(&b, f, sizeof f);
        fb_ctrl_hdr(&b, 11, 0, 0, M_STA, M_AP);
        ASSERT_EQ(classify(f, b.len, 0, 0), COV_FC_CTRL);
    }
    /* Data: EtherType 0x888E is EAPOL, anything else data. */
    int n = data_frame(f, sizeof f, 0, 0, 0, 0x888E);
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_EAPOL);
    n = data_frame(f, sizeof f, 1, 0, 0, 0x888E);
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_EAPOL);
    n = data_frame(f, sizeof f, 0, 0, 0, 0x0800);
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_DATA);
    /* A QoS header on a DATAPAD radio: the LLC header sits after the
     * pad, and is still found (the view's body offset). */
    n = data_frame(f, sizeof f, 1, 0, 1, 0x888E);
    ASSERT_EQ(classify(f, n, 1, 0), COV_FC_EAPOL);
    /* A Protected frame's body is ciphertext: never read, so data, even
     * with octets that would spell 0x888E in the clear. */
    n = data_frame(f, sizeof f, 1, FB_PROTECTED, 0, 0x888E);
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_DATA);
    /* FCS-failed wins over whatever the octets say. */
    n = mgmt(f, sizeof f, 8);
    ASSERT_EQ(classify(f, n, 0, 1), COV_FC_FCS_BAD);
    /* Extension (type 3) and a non-zero protocol version: other. */
    f[0] = (uint8_t)((1 << 4) | (3 << 2));
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_OTHER);
    n = mgmt(f, sizeof f, 8);
    f[0] |= 0x01;
    ASSERT_EQ(classify(f, n, 0, 0), COV_FC_OTHER);
    ASSERT_EQ(cov_frame_class(NULL, 0), COV_FC_OTHER);
    /* Class i is COV_F_* bit i: the names agree with rule_coverage's. */
    ASSERT_STR(cov_fc_name(COV_FC_BEACON), "beacon");
    ASSERT_STR(cov_fc_name(COV_FC_EAPOL), "eapol");
    ASSERT_STR(cov_fc_name(COV_FC_FCS_BAD), "fcs_bad");
    ASSERT_STR(cov_fc_name(COV_FC_N), "");
}

/* ── The scheduler's per-channel time ───────────────────────────── */

static void test_slot_time(void) {
    chanhop_t h;
    static const int ch[3] = { 1, 36, 52 };
    ASSERT_EQ(chanhop_init(&h, ch, 3), 3);
    /* Nothing before the first acknowledged retune. */
    ASSERT_EQ(chanhop_slot_time_ms(&h, 0, 5000), 0);
    ASSERT_EQ(chanhop_tick(&h, 1000), 1);
    chanhop_confirm_retune(&h, 1, 1000);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 0, 1400), 400);    /* open dwell */
    ASSERT_EQ(chanhop_slot_time_ms(&h, 1, 1400), 0);
    ASSERT_EQ(chanhop_tick(&h, 2000), 1);
    /* A refused retune leaves the radio where it was: the time stays
     * with channel 1, and its open dwell keeps running. */
    chanhop_confirm_retune(&h, 0, 2000);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 0, 2100), 1100);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 1, 2100), 0);
    ASSERT_EQ(chanhop_tick(&h, 2200), 1);
    chanhop_confirm_retune(&h, 1, 2200);
    /* Closed: channel 1 kept 1200 ms; channel 52 (the refused 36 was
     * skipped) has its open 300. */
    ASSERT_EQ(chanhop_slot_time_ms(&h, 0, 2500), 1200);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 2, 2500), 300);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 1, 2500), 0);
    ASSERT_EQ(h.slots[0].dwell_ms, 1200);
    ASSERT_EQ(chanhop_slot_time_ms(&h, 3, 2500), 0);
    ASSERT_EQ(chanhop_slot_time_ms(&h, -1, 2500), 0);
    ASSERT_EQ(chanhop_slot_time_ms(NULL, 0, 2500), 0);
}

/* ── One hopping radio ──────────────────────────────────────────── */

static chanhop_t g_h0;

/* The hop stage on radio 0 alone: frames since the last poll to the
 * confirmed channel, then the retune when due. */
static void hop0(uint32_t frames) {
    chanhop_observe(&g_h0, frames);
    if (chanhop_tick(&g_h0, g_mono)) chanhop_confirm_retune(&g_h0, 1, g_mono);
}

static void test_hopping_radio_minute(void) {
    begin();
    monitor_up();
    static const int ch[3] = { 1, 36, 52 };
    ASSERT_EQ(chanhop_init(&g_h0, ch, 3), 3);
    cov_iv_capture_set_hop0(&g_h0);
    hop0(0);
    sample();                             /* opens the interval */
    ASSERT_EQ(cov_iv_is_open(), 1);
    for (int i = 1; i <= 59; i++) {
        g_mono += 1000; g_wall += 1;
        hop0(10);
        sample();
    }
    /* 59 s: nothing closed yet, a record is a whole minute. */
    ASSERT_EQ(cov_iv_seq(), 0);
    g_mono += 1000; g_wall += 1;
    hop0(10);
    sample();
    ASSERT_EQ(cov_iv_seq(), 1);

    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.dur_ms, 60000);
    ASSERT_EQ(iv.end - iv.start, 60);
    ASSERT_EQ(iv.nchan, 3);
    /* The radio's time is the whole minute, a third on each channel:
     * every dwell ran one poll, 1 s. */
    ASSERT_EQ(iv.radio_ms, 60000);
    uint64_t frames = 0;
    for (int i = 0; i < iv.nchan; i++) {
        ASSERT_EQ(iv.chan[i].radio, 0);
        ASSERT_EQ(iv.chan[i].ms, 20000);
        frames += iv.chan[i].frames;
    }
    ASSERT_EQ(frames, 600);
    ASSERT_EQ(iv.band_ms[COV_IVB_24], 20000);
    ASSERT_EQ(iv.band_ms[COV_IVB_5], 20000);
    ASSERT_EQ(iv.band_ms[COV_IVB_5DFS], 20000);
    ASSERT_EQ(iv.band_ms[COV_IVB_6], 0);

    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"coverage_interval\""), 1);
    ASSERT(strstr(out, "\"ch\":36,\"freq_mhz\":5180,\"band\":\"5\",\"ms\":20000,") != NULL);
    ASSERT(strstr(out, "{\"band\":\"5dfs\",\"ms\":20000,\"share\":0.333}") != NULL);
    ASSERT(strstr(out, "\"dur_ms\":60000,\"radio_ms\":60000,") != NULL);
    /* A record is written once: the next emit has nothing new. Seen
     * red with cov_iv_emit()'s cursor not advanced. */
    sink_open();
    cov_iv_emit();
    ASSERT_STR(sink_read(), "");
    end();
}

/* A fixed cadence, not a change feed: a second minute identical to the
 * first is written all the same. Seen red with cov_iv_close() made to
 * skip publishing when the interval equals the last one. */
static void test_cadence_not_change_only(void) {
    begin();
    monitor_up();
    sample();
    for (int i = 1; i <= 120; i++) { g_mono += 1000; g_wall += 1; sample(); }
    ASSERT_EQ(cov_iv_seq(), 2);
    cov_iv_t a, b;
    ASSERT_EQ(cov_iv_get(1, &a), 1);
    ASSERT_EQ(cov_iv_get(2, &b), 1);
    ASSERT_EQ(a.radio_ms, b.radio_ms);
    ASSERT_EQ(b.start, a.end);
    end();
}

/* A radio that is not retuned: the whole time it runs, on the
 * frequency of its newest frame, unknown before one. */
static void test_fixed_radio_minute(void) {
    begin();
    monitor_up();
    sample();
    for (int i = 1; i <= 60; i++) {
        g_mono += 1000; g_wall += 1;
        /* Down for ten seconds in the middle: those are not radio time. */
        g_s.mon_health.running = !(i > 20 && i <= 30);
        sample();
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.nchan, 1);
    ASSERT_EQ(iv.chan[0].radio, 0);
    ASSERT_EQ(iv.radio_ms, 50000);
    ASSERT_EQ(iv.band_ms[COV_IVB_UNKNOWN], 50000);
    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "\"band\":\"unknown\",\"ms\":50000,") != NULL);
    ASSERT(strstr(out, "{\"band\":\"unknown\",\"ms\":50000,\"share\":1.000}") != NULL);
    end();
}

/* No monitor radio: the record is still written (the classes, the
 * drops and the sources say what the sensor did) with no channel and
 * no radio time. */
static void test_no_radio_minute(void) {
    begin();
    sample();
    for (int i = 1; i <= 60; i++) { g_mono += 1000; g_wall += 1; sample(); }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.nchan, 0);
    ASSERT_EQ(iv.radio_ms, 0);
    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "\"chans\":[],\"chan_overflow\":0,\"bands\":[],") != NULL);
    end();
}

/* Two sensor radios dealt the list: each radio's own channels, each
 * with a minute of time, and no channel on both. */
static void test_two_hopping_radios(void) {
    begin();
    monitor_up();
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    ASSERT_EQ(mon_radios_add("mon1"), 1);
    mon_radios_set_state(0, MON_RADIO_RUNNING, "");
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    static const int ch[4] = { 1, 6, 36, 40 };
    ASSERT_EQ(chanhop_init(&g_h0, ch, 4), 4);
    ASSERT_EQ(mon_hop_setup(&g_h0), 2);
    cov_iv_capture_set_hop0(&g_h0);
    for (int i = 0; i <= 60; i++) {
        if (i) { g_mono += 1000; g_wall += 1; }
        chanhop_service(&g_h0, &g_s, g_mono, mon_hop_radio0_delta());
        (void)mon_hop_service(&g_h0, g_mono);
        sample();
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.nchan, 4);
    uint64_t per[2] = { 0, 0 };
    for (int i = 0; i < iv.nchan; i++) {
        ASSERT(iv.chan[i].radio == 0 || iv.chan[i].radio == 1);
        per[iv.chan[i].radio] += iv.chan[i].ms;
        /* The deal: radio 0 has 1 and 36, radio 1 has 6 and 40. */
        int c = iv.chan[i].channel;
        ASSERT_EQ(iv.chan[i].radio, (c == 6 || c == 40) ? 1 : 0);
    }
    ASSERT_EQ(per[0], 60000);
    ASSERT_EQ(per[1], 60000);
    ASSERT_EQ(iv.radio_ms, 120000);
    end();
}

/* Drops are the interval's deltas; a handle that is not open with a
 * stats sample at both ends is not measured, and the member is absent
 * rather than 0. */
static void test_drops(void) {
    begin();
    monitor_up();
    g_s.mon_health.stats_valid = 1;
    g_s.mon_health.ps_drop = 100;
    g_s.mon_health.ps_ifdrop = 7;
    sample();
    for (int i = 1; i <= 60; i++) {
        g_mono += 1000; g_wall += 1;
        g_s.mon_health.ps_drop += 3;
        sample();
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.has_mon, 1);
    ASSERT_EQ(iv.mon_drop, 180);
    ASSERT_EQ(iv.mon_ifdrop, 0);
    ASSERT_EQ(iv.has_cap, 0);
    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "\"monitor_drop\":180,\"monitor_ifdrop\":0") != NULL);
    /* Seen red with the has_cap guard in emit_one() removed. */
    ASSERT(strstr(out, "capture_drop") == NULL);
    end();
}

/* The sources at the end: name and state word, not-configured rows
 * left out. */
static void test_sources_at_the_end(void) {
    begin();
    monitor_up();
    sample();
    for (int i = 1; i <= 60; i++) {
        g_mono += 1000; g_wall += 1;
        if (i == 59) { g_s.mon_health.running = 0; g_s.mon_health.open = 0; }
        sample();
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "{\"name\":\"monitor\",\"state\":\"down\"}") != NULL);
    /* Seen red with the not_configured filter in take_sources()
     * removed: the gnss row (no --gps) appears. */
    ASSERT(strstr(out, "\"name\":\"gnss\"") == NULL);
    ASSERT(strstr(out, "not_configured") == NULL);
    end();
}

/* A --replay run writes no record: host time says nothing about a file
 * read as fast as it reads. Seen red with the replay test in
 * cov_iv_capture_poll() removed (one record after 60 s). */
static void test_replay_writes_none(void) {
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "replay");
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "replay");
    g_s.mon_health.running = 1;
    for (int i = 0; i <= 130; i++) { g_mono += 1000; g_wall += 1; sample(); }
    ASSERT_EQ(cov_iv_seq(), 0);
    ASSERT_EQ(cov_iv_is_open(), 0);
    sink_open();
    cov_iv_emit();
    ASSERT_STR(sink_read(), "");
    end();
}

/* With no sink, closed intervals are not held back for a later sink:
 * a sink opened after two minutes gets the next one, not a burst. Seen
 * red with the no-sink branch of cov_iv_emit() leaving its cursor (three
 * records). */
static void test_no_sink_no_burst(void) {
    begin();
    sample();
    for (int i = 1; i <= 120; i++) {
        g_mono += 1000; g_wall += 1; sample();
        cov_iv_emit();
    }
    ASSERT_EQ(cov_iv_seq(), 2);
    sink_open();
    cov_iv_emit();
    for (int i = 1; i <= 60; i++) { g_mono += 1000; g_wall += 1; sample(); }
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"coverage_interval\""), 1);
    ASSERT(strstr(out, "\"seq\":3,") != NULL);
    end();
}

/* A sink that is open while several intervals close between two emits
 * gets each of them, in order, once; more than the ring holds and it
 * gets the newest COV_IV_RING. Seen red with cov_iv_emit() writing only
 * the newest seq (one record each time). */
static void test_emit_catches_up_several(void) {
    begin();
    monitor_up();
    sink_open();
    sample();
    for (int i = 1; i <= 180; i++) { g_mono += 1000; g_wall += 1; sample(); }
    ASSERT_EQ(cov_iv_seq(), 3);
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"coverage_interval\""), 3);
    const char *a = strstr(out, "\"seq\":1,"), *b = strstr(out, "\"seq\":2,"),
               *c = strstr(out, "\"seq\":3,");
    ASSERT(a != NULL && b != NULL && c != NULL);
    ASSERT(a < b && b < c);

    sink_open();
    for (int i = 1; i <= 600; i++) { g_mono += 1000; g_wall += 1; sample(); }
    ASSERT_EQ(cov_iv_seq(), 13);
    cov_iv_emit();
    out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"coverage_interval\""), COV_IV_RING);
    ASSERT(strstr(out, "\"seq\":5,") == NULL);     /* out of the ring */
    ASSERT(strstr(out, "\"seq\":6,") != NULL);
    ASSERT(strstr(out, "\"seq\":13,") != NULL);
    end();
}

/* The sampler's stage reads the clock as it runs, after the hop stage
 * has stamped this tick's retune on its own later reading. Fed the
 * tick's start instead, an interval whose closing tick retunes credits
 * the closed slot past its end: here the closing tick's stages before
 * the sampler take 40 ms, and the channel time came to 60000 against a
 * dur_ms of 59960. Seen red with st_coverage_iv() passing ctx->mono_ms. */
static void test_closing_retune_on_the_stage_clock(void) {
    begin();
    monitor_up();
    static const int ch[3] = { 1, 36, 52 };
    ASSERT_EQ(chanhop_init(&g_h0, ch, 3), 3);
    cov_iv_capture_set_hop0(&g_h0);
    int k = poll_stage_index(&g_poll_wifi, "coverage_iv");
    ASSERT(k >= 0);
    poll_ctx_t ctx;
    for (int i = 0; i <= 60; i++) {
        if (i) { g_mono += 1000; g_wall += 1; }
        memset(&ctx, 0, sizeof(ctx));
        ctx.wall = g_wall;
        ctx.mono_ms = g_mono;
        if (i == 60) { ctx.mono_ms = g_mono; g_mono += 40; }   /* the tick began 40 ms ago */
        hop0(10);
        sys_status_poll(&g_s, ctx.wall, ctx.mono_ms);
        g_poll_wifi.stages[k].fn(&g_s, &ctx);
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    uint64_t listed = 0;
    for (int i = 0; i < iv.nchan; i++) listed += iv.chan[i].ms;
    ASSERT_EQ(iv.dur_ms, 60040);
    ASSERT_EQ(listed, iv.dur_ms);
    ASSERT_EQ(iv.radio_ms, iv.dur_ms);
    end();
}

/* The channel list is bounded; the excess is counted. */
static void test_channel_bound(void) {
    begin();
    cov_iv_open(g_wall, g_mono);
    for (int i = 0; i < COV_IV_CHAN_MAX + 3; i++)
        cov_iv_add(i % MON_RADIO_MAX, 2412 + 5 * i, i + 1, 10, 1);
    /* Merged with the entry of the same radio and frequency. */
    cov_iv_add(0, 2412, 1, 5, 0);
    g_mono += COV_IV_MS;
    uint64_t z[COV_FC_N] = { 0 };
    cov_iv_close(g_wall + 60, g_mono, z, 0, 0, 0, 0, 0, 0);
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.nchan, COV_IV_CHAN_MAX);
    ASSERT_EQ(iv.chan_overflow, 3);
    ASSERT_EQ(iv.chan[0].ms, 15);
    /* The three entries not written are still radio time: 35 entries of
     * 10 ms and the merged 5. Seen red with the overflow branch of
     * cov_iv_add() not adding to the totals (325). */
    ASSERT_EQ(iv.radio_ms, 355);
    uint64_t listed = 0, banded = 0;
    for (int i = 0; i < iv.nchan; i++) listed += iv.chan[i].ms;
    for (int b = 0; b < COV_IVB_N; b++) banded += iv.band_ms[b];
    ASSERT_EQ(listed, 325);
    ASSERT_EQ(banded, iv.radio_ms);
    /* The ring holds COV_IV_RING; an older seq is gone. */
    for (int k = 0; k < COV_IV_RING; k++) {
        g_mono += COV_IV_MS;
        cov_iv_close(g_wall + 60, g_mono, z, 0, 0, 0, 0, 0, 0);
    }
    ASSERT_EQ(cov_iv_get(1, NULL), 0);
    ASSERT_EQ(cov_iv_get(cov_iv_seq(), NULL), 1);
    ASSERT_EQ(cov_iv_get(cov_iv_seq() + 1, NULL), 0);
    ASSERT_EQ(cov_iv_get(0, NULL), 0);
    end();
}

#ifdef WITH_PCAP
/* ── Through the monitor path ───────────────────────────────────── */

static int rt_wrap(uint8_t *buf, int cap, uint8_t flags, uint16_t mhz,
                   const uint8_t *frame, int n) {
    fb_t b; fb_init(&b, buf, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof(rt));
    rt.has_flags = 1; rt.flags = flags;
    rt.has_channel = 1; rt.freq_mhz = mhz;
    fb_radiotap(&b, &rt);
    fb_bytes(&b, frame, n);
    return fb_ok(&b) ? b.len : -1;
}

/* Each frame the monitor path records is counted in exactly one class,
 * so the classes' deltas sum to mon_frame_total()'s. Radio 0's newest
 * frequency is what a fixed radio's channel reads. The FCS-failed
 * beacon is not a beacon: seen red with probe.c passing 0 for the FCS
 * verdict (two beacons). */
static void test_classes_through_the_monitor_path(void) {
    begin();
    enum { NF = 6 };
    static uint8_t raw[NF][128], wrapped[NF][160];
    int rn[NF];
    rn[0] = mgmt(raw[0], 128, 8);                          /* beacon */
    rn[1] = mgmt(raw[1], 128, 4);                          /* probe req */
    rn[2] = mgmt(raw[2], 128, 12);                         /* deauth */
    { fb_t b; fb_init(&b, raw[3], 128);
      fb_ctrl_hdr(&b, 12, 0, 0, M_STA, NULL); rn[3] = b.len; }   /* CTS */
    rn[4] = data_frame(raw[4], 128, 1, 0, 0, 0x888E);      /* EAPOL */
    rn[5] = mgmt(raw[5], 128, 8);                          /* FCS-failed */
    const uint8_t *fs[NF]; int ls[NF];
    for (int i = 0; i < NF; i++) {
        ASSERT(rn[i] > 0);
        ls[i] = rt_wrap(wrapped[i], 160, i == 5 ? RT_F_BADFCS : 0, 5180,
                        raw[i], rn[i]);
        ASSERT(ls[i] > 0);
        fs[i] = wrapped[i];
    }
    uint64_t before[COV_FC_N], after[COV_FC_N];
    mon_frame_class_totals(before);
    uint64_t t0 = mon_frame_total();
    static sloth_state_t ds;
    memset(&ds, 0, sizeof(ds));
    ASSERT_EQ(probe_test_dispatch(&ds, fs, ls, NULL, NULL, NF), NF);
    mon_frame_class_totals(after);
    uint64_t sum = 0;
    for (int k = 0; k < COV_FC_N; k++) sum += after[k] - before[k];
    ASSERT_EQ(sum, mon_frame_total() - t0);
    ASSERT_EQ(sum, NF);
    ASSERT_EQ(after[COV_FC_BEACON] - before[COV_FC_BEACON], 1);
    ASSERT_EQ(after[COV_FC_PROBE]  - before[COV_FC_PROBE], 1);
    ASSERT_EQ(after[COV_FC_DEAUTH] - before[COV_FC_DEAUTH], 1);
    ASSERT_EQ(after[COV_FC_CTRL]   - before[COV_FC_CTRL], 1);
    ASSERT_EQ(after[COV_FC_EAPOL]  - before[COV_FC_EAPOL], 1);
    ASSERT_EQ(after[COV_FC_FCS_BAD] - before[COV_FC_FCS_BAD], 1);
    ASSERT_EQ(mon_radio0_freq_mhz(), 5180);

    /* And into a minute: the record carries the interval's deltas and
     * the fixed radio's channel. */
    monitor_up();
    sample();
    g_mono += 1000; g_wall += 1;
    ASSERT_EQ(probe_test_dispatch(&ds, fs, ls, NULL, NULL, NF), NF);
    for (int i = 1; i <= 60; i++) {
        if (i > 1) { g_mono += 1000; g_wall += 1; }
        sample();
    }
    cov_iv_t iv;
    ASSERT_EQ(cov_iv_get(1, &iv), 1);
    ASSERT_EQ(iv.frames[COV_FC_BEACON], 1);
    ASSERT_EQ(iv.frames[COV_FC_FCS_BAD], 1);
    ASSERT_EQ(iv.nchan, 1);
    ASSERT_EQ(iv.chan[0].channel, 36);
    ASSERT_EQ(iv.chan[0].frames, NF);
    sink_open();
    cov_iv_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "\"frames\":{\"beacon\":1,\"probe\":1,\"auth\":0,"
                       "\"assoc\":0,\"deauth\":1,\"action\":0,\"ctrl\":1,"
                       "\"data\":0,\"eapol\":1,\"other\":0,\"fcs_bad\":1}") != NULL);
    /* Radio 0's frequency is a current value, cleared between tests by
     * the registry: the next test of a fixed radio reads unknown, not
     * this 5180. Seen red with mon_radio0_freq_reset left out of
     * SLOTH_RESETS. */
    sloth_reset_all();
    ASSERT_EQ(mon_radio0_freq_mhz(), 0);
    end();
}
#endif

#ifdef WITH_SQLITE
/* The database gets one row per closed interval, with the record's
 * figures, NULL drops where not measured, and the record's arrays. */
static void test_rows_in_the_database(void) {
    begin();
    char path[TEST_TMP_MAX];
    int fd = mkstemp(test_tmp_tpl(path, sizeof(path), "sloth_covdb_XXXXXX"));
    if (fd >= 0) close(fd);
    unlink(path);
    ASSERT_EQ(db_open(path), 1);
    monitor_up();
    g_s.mon_health.stats_valid = 1;
    sample();
    for (int i = 1; i <= 120; i++) {
        g_mono += 1000; g_wall += 1;
        g_s.mon_health.ps_drop += 1;
        sample();
        if (i % 30 == 0) db_tick(&g_s, g_wall);   /* a slower write tick */
    }
    db_close();
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(path, &h), SQLITE_OK);
    sqlite3_stmt *st = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(h,
        "SELECT COUNT(*), MIN(dur_ms), SUM(ms_unknown), SUM(mon_drop),"
        " SUM(cap_drop IS NULL), MIN(last_seen - start),"
        " MIN(instr(chans,'\"radio\":0')), MIN(instr(sources,'\"monitor\"'))"
        " FROM coverage_intervals", -1, &st, NULL), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    ASSERT_EQ(sqlite3_column_int(st, 0), 2);
    ASSERT_EQ(sqlite3_column_int(st, 1), 60000);
    ASSERT_EQ(sqlite3_column_int(st, 2), 120000);
    ASSERT_EQ(sqlite3_column_int(st, 3), 120);
    ASSERT_EQ(sqlite3_column_int(st, 4), 2);
    ASSERT_EQ(sqlite3_column_int(st, 5), 60);
    ASSERT(sqlite3_column_int(st, 6) > 0);
    ASSERT(sqlite3_column_int(st, 7) > 0);
    sqlite3_finalize(st);
    sqlite3_close(h);
    unlink(path);
    end();
}

/* A write tick longer than an interval writes every interval closed
 * since the last one, and past the ring's depth the newest COV_IV_RING.
 * Seen red with write_coverage_intervals() writing only the newest seq
 * (two rows). */
static void test_db_catches_up_several(void) {
    begin();
    char path[TEST_TMP_MAX];
    int fd = mkstemp(test_tmp_tpl(path, sizeof(path), "sloth_covdb_XXXXXX"));
    if (fd >= 0) close(fd);
    unlink(path);
    ASSERT_EQ(db_open(path), 1);
    monitor_up();
    const time_t w0 = g_wall;
    sample();
    /* --db-interval-secs 300: five intervals per write. */
    for (int i = 1; i <= 300; i++) { g_mono += 1000; g_wall += 1; sample(); }
    db_tick(&g_s, g_wall);
    /* Then thirteen minutes with no write: the ring keeps eight. */
    for (int i = 1; i <= 780; i++) { g_mono += 1000; g_wall += 1; sample(); }
    db_tick(&g_s, g_wall);
    ASSERT_EQ(cov_iv_seq(), 18);
    db_close();
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(path, &h), SQLITE_OK);
    sqlite3_stmt *st = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(h,
        "SELECT COUNT(*), COUNT(DISTINCT start), MIN(start), MAX(start),"
        " SUM(start >= ?1 + 300 AND start < ?1 + 600)"
        " FROM coverage_intervals", -1, &st, NULL), SQLITE_OK);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w0);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    ASSERT_EQ(sqlite3_column_int(st, 0), 5 + COV_IV_RING);
    ASSERT_EQ(sqlite3_column_int(st, 1), 5 + COV_IV_RING);
    ASSERT_EQ(sqlite3_column_int64(st, 2), (sqlite3_int64)w0);
    ASSERT_EQ(sqlite3_column_int64(st, 3), (sqlite3_int64)(w0 + 17 * 60));
    /* Seqs 6..10 fell out of the ring before the second write. */
    ASSERT_EQ(sqlite3_column_int(st, 4), 0);
    sqlite3_finalize(st);
    sqlite3_close(h);
    unlink(path);
    end();
}
#endif

void run_cov_interval_tests(void) {
    TEST_SUITE("coverage interval record (#242 item 2)");
    RUN_TEST(test_frame_classes);
    RUN_TEST(test_slot_time);
    RUN_TEST(test_hopping_radio_minute);
    RUN_TEST(test_cadence_not_change_only);
    RUN_TEST(test_fixed_radio_minute);
    RUN_TEST(test_no_radio_minute);
    RUN_TEST(test_two_hopping_radios);
    RUN_TEST(test_drops);
    RUN_TEST(test_sources_at_the_end);
    RUN_TEST(test_replay_writes_none);
    RUN_TEST(test_no_sink_no_burst);
    RUN_TEST(test_emit_catches_up_several);
    RUN_TEST(test_closing_retune_on_the_stage_clock);
    RUN_TEST(test_channel_bound);
#ifdef WITH_PCAP
    RUN_TEST(test_classes_through_the_monitor_path);
#endif
#ifdef WITH_SQLITE
    RUN_TEST(test_rows_in_the_database);
    RUN_TEST(test_db_catches_up_several);
#endif
}
