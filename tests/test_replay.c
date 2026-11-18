#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "frame_build.h"
#include "fake_platform.h"
#include "capture/replay.h"
#include "capture/capture.h"
#include "capture/probe.h"
#include "tmp_dir.h"

/*
 * --replay (#119). The savefiles here are written at test time, into a
 * mkdtemp() directory, from tests/frame_build.h byte arrays — tests/
 * gains no .pcap (agents/AGENTS.md, "No pcap fixtures"). The end-to-end
 * half, the shipped binary replaying and writing JSONL, is `make
 * replay-check`; this file pins the pieces that gate can only see as a
 * diff: routing, the list parser, batch boundaries, which clock and
 * which length a replayed frame keeps, and that no host state leaks in.
 */

#define RT_DLT_EN10MB   1
#define RT_DLT_SLL      113
#define RT_DLT_SLL2     276
#define RT_DLT_RADIOTAP 127
#define RT_DLT_RAW80211 105

static const uint8_t H_MAC[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x10 };
static const uint8_t G_MAC[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01 };
static const uint8_t H_IP[4]  = { 192, 0, 2, 10 };
static const uint8_t D_IP[4]  = { 198, 51, 100, 53 };

/* The reader needs libpcap; the link-only no-flag build
 * (sloth_test_noflags, #116) keeps the pure and builder cases only. */
#ifdef WITH_PCAP
static char g_dir[TEST_TMP_MAX];
static int  g_dir_ok;
static sloth_state_t g_rs;

/* Sentinel capture time. Not a real clock reading: the assertion is
 * that the replay carries the file's value through, whatever it is. */
#define RP_TS_SENTINEL 1234567u

/* One Ethernet/IPv4/UDP frame, 4 bytes of payload. Returns its length. */
static int udp_frame(uint8_t *f, int cap, uint16_t sport) {
    static const uint8_t pl[4] = { 0xde, 0xad, 0xbe, 0xef };
    fb_t b; fb_init(&b, f, cap);
    fb_eth_ipv4_udp(&b, G_MAC, H_MAC, H_IP, D_IP, sport, 9, pl, 4, 1);
    return fb_ok(&b) ? b.len : -1;
}

/* Write `n` copies of one frame as a savefile with link type `dlt`.
 * The image comes from capture_test_savefile(), the dispatch seams'
 * own writer, and goes to disk only because --replay reads a path. */
static int write_savefile(const char *path, int dlt, const uint8_t *frame,
                          int len, int orig, int n, uint32_t ts0) {
    const uint8_t **fr = calloc((size_t)n, sizeof *fr);
    int *ls = calloc((size_t)n, sizeof *ls);
    int *os = calloc((size_t)n, sizeof *os);
    uint32_t *ts = calloc((size_t)n, sizeof *ts);
    int rc = -1;
    if (fr && ls && os && ts) {
        for (int i = 0; i < n; i++) {
            fr[i] = frame; ls[i] = len; os[i] = orig; ts[i] = ts0 + (uint32_t)i;
        }
        size_t sz = 0;
        uint8_t *img = capture_test_savefile(dlt, fr, ls, os, ts, n, &sz);
        FILE *fp = img ? fopen(path, "wb") : NULL;
        if (fp) {
            rc = fwrite(img, 1, sz, fp) == sz ? 0 : -1;
            if (fclose(fp) != 0) rc = -1;
        }
        free(img);
    }
    free(fr); free(ls); free(os); free(ts);
    return rc;
}

static void path_in_dir(char *out, size_t sz, const char *name) {
    snprintf(out, sz, "%s/%s", g_dir, name);
}
#endif /* WITH_PCAP */

/* ── Pure: routing and the list parser ─────────────────────────────── */

static void test_route_follows_the_live_handles(void) {
    ASSERT_EQ(replay_route(RT_DLT_EN10MB),   REPLAY_ROUTE_WIRED);
    ASSERT_EQ(replay_route(RT_DLT_SLL),      REPLAY_ROUTE_WIRED);
    ASSERT_EQ(replay_route(RT_DLT_SLL2),     REPLAY_ROUTE_WIRED);
    ASSERT_EQ(replay_route(RT_DLT_RADIOTAP), REPLAY_ROUTE_MONITOR);
    /* Raw 802.11 without radiotap: neither live handle produces it and
     * the monitor path's parser starts at a radiotap header, so it is
     * refused rather than guessed at. */
    ASSERT_EQ(replay_route(RT_DLT_RAW80211), REPLAY_ROUTE_NONE);
    ASSERT_EQ(replay_route(0),               REPLAY_ROUTE_NONE);
    ASSERT_EQ(replay_route(-1),              REPLAY_ROUTE_NONE);
}

static void test_list_splits_on_commas(void) {
    char p[REPLAY_MAX_FILES][REPLAY_PATH_MAX];
    ASSERT_EQ(replay_split_list("a.pcap", p, REPLAY_MAX_FILES), 1);
    ASSERT_STR(p[0], "a.pcap");
    ASSERT_EQ(replay_split_list("/x/w.pcap,m.pcap", p, REPLAY_MAX_FILES), 2);
    ASSERT_STR(p[0], "/x/w.pcap");
    ASSERT_STR(p[1], "m.pcap");
}

static void test_list_refuses_rather_than_drops(void) {
    char p[REPLAY_MAX_FILES][REPLAY_PATH_MAX];
    ASSERT_EQ(replay_split_list("", p, REPLAY_MAX_FILES), -1);
    ASSERT_EQ(replay_split_list(",", p, REPLAY_MAX_FILES), -1);
    ASSERT_EQ(replay_split_list("a,", p, REPLAY_MAX_FILES), -1);
    ASSERT_EQ(replay_split_list(",a", p, REPLAY_MAX_FILES), -1);
    ASSERT_EQ(replay_split_list("a,,b", p, REPLAY_MAX_FILES), -1);
    ASSERT_EQ(replay_split_list(NULL, p, REPLAY_MAX_FILES), -1);
    /* Exactly the cap is accepted; one more is refused, not truncated. */
    ASSERT_EQ(replay_split_list("1,2,3,4,5,6,7,8", p, REPLAY_MAX_FILES), 8);
    ASSERT_STR(p[7], "8");
    ASSERT_EQ(replay_split_list("1,2,3,4,5,6,7,8,9", p, REPLAY_MAX_FILES), -1);
    /* The longest path that fits, then one byte past it. */
    char lng[REPLAY_PATH_MAX + 1];
    memset(lng, 'p', sizeof lng);
    lng[REPLAY_PATH_MAX - 1] = '\0';
    ASSERT_EQ(replay_split_list(lng, p, REPLAY_MAX_FILES), 1);
    ASSERT_EQ((int)strlen(p[0]), REPLAY_PATH_MAX - 1);
    lng[REPLAY_PATH_MAX - 1] = 'p';
    lng[REPLAY_PATH_MAX]     = '\0';
    ASSERT_EQ(replay_split_list(lng, p, REPLAY_MAX_FILES), -1);
}

/* ── The empty platform ────────────────────────────────────────────── */

/* The fake platform is seeded with an interface and a connection, so
 * each op has something to leak. After the install every op must read
 * as empty: a replay describes its files, not the host that ran it.
 * Proved red by dropping the get_ifaces and get_conns assignments from
 * replay_platform_install(). */
static void test_platform_reads_nothing_from_the_host(void) {
    platform_ops_t saved = g_platform;
    fake_net_reset();
    g_fake_net.iface_count = 1;
    snprintf(g_fake_net.ifaces[0].name, sizeof g_fake_net.ifaces[0].name, "eth9");
    g_fake_net.conn_count = 1;
    static iface_stat_t ifs[4];
    static conn_t cs[4];
    ASSERT_EQ(g_platform.get_ifaces(ifs, 4), 1);    /* premise: it leaks */
    ASSERT_EQ(g_platform.get_conns(cs, 4), 1);

    replay_platform_install();
    static wifi_ap_t aps[2];
    static wifi_sta_t stas[2];
    static arp_entry_t arps[2];
    static dhcp_lease_t ls[2];
    ASSERT_EQ(g_platform.get_ifaces(ifs, 4), 0);
    ASSERT_EQ(g_platform.get_conns(cs, 4), 0);
    ASSERT_EQ(g_platform.wifi_scan(aps, 2), 0);
    ASSERT_EQ(g_platform.get_wifi_stations(stas, 2), 0);
    ASSERT_EQ(g_platform.get_arp(arps, 2), 0);
    ASSERT_EQ(g_platform.get_dhcp(ls, 2), 0);
    ASSERT_EQ(g_platform.set_channel("replay", 2437), -EOPNOTSUPP);

    g_platform = saved;
    fake_net_reset();
}

/* ── The reader ────────────────────────────────────────────────────── */

#ifdef WITH_PCAP

static void test_check_routes_by_the_file_datalink(void) {
    if (!g_dir_ok) { ASSERT(g_dir_ok); return; }
    uint8_t f[128];
    int len = udp_frame(f, sizeof f, 5000);
    ASSERT_GT(len, 0);
    char w[256], m[256], r[256], err[512];
    path_in_dir(w, sizeof w, "w.pcap");
    path_in_dir(m, sizeof m, "m.pcap");
    path_in_dir(r, sizeof r, "raw.pcap");
    ASSERT_EQ(write_savefile(w, RT_DLT_EN10MB, f, len, len, 1, RP_TS_SENTINEL), 0);
    ASSERT_EQ(write_savefile(m, RT_DLT_RADIOTAP, f, len, len, 1, RP_TS_SENTINEL), 0);
    ASSERT_EQ(write_savefile(r, RT_DLT_RAW80211, f, len, len, 1, RP_TS_SENTINEL), 0);

    replay_src_t src;
    ASSERT_EQ(replay_check(w, &src, err, sizeof err), 0);
    ASSERT_EQ(src.dlt, RT_DLT_EN10MB);
    ASSERT_EQ(src.route, REPLAY_ROUTE_WIRED);
    ASSERT_EQ(replay_check(m, &src, err, sizeof err), 0);
    ASSERT_EQ(src.route, REPLAY_ROUTE_MONITOR);

    err[0] = '\0';
    ASSERT_EQ(replay_check(r, &src, err, sizeof err), -1);
    ASSERT(strstr(err, "datalink 105") != NULL);

    path_in_dir(r, sizeof r, "absent.pcap");
    err[0] = '\0';
    ASSERT_EQ(replay_check(r, &src, err, sizeof err), -1);
    ASSERT(strstr(err, "absent.pcap") != NULL);

    /* Not a savefile at all. libpcap's message for this one does not
     * name the file, and with eight on the command line it has to. */
    path_in_dir(r, sizeof r, "junk.pcap");
    FILE *fp = fopen(r, "wb");
    ASSERT(fp != NULL);
    if (fp) { fputs("not a savefile", fp); fclose(fp); }
    err[0] = '\0';
    ASSERT_EQ(replay_check(r, &src, err, sizeof err), -1);
    ASSERT(strstr(err, "junk.pcap") != NULL);
}

/* Every record reaches on_packet(), across a batch boundary. 600 is
 * past REPLAY_BATCH (512), so both kinds of flush run: one full batch
 * mid-file and the partial tail. Proved red, alone in the suite, by
 * discarding the full batch instead of flushing it; discarding the tail
 * instead reddens this and every smaller-file case below as well, since
 * for those the tail is the whole file. */
static void test_wired_replay_dispatches_every_record(void) {
    if (!g_dir_ok) { ASSERT(g_dir_ok); return; }
    uint8_t f[128];
    int len = udp_frame(f, sizeof f, 5001);
    char w[256], err[512];
    path_in_dir(w, sizeof w, "many.pcap");
    ASSERT_EQ(write_savefile(w, RT_DLT_EN10MB, f, len, len, 600, RP_TS_SENTINEL), 0);
    replay_src_t src;
    ASSERT_EQ(replay_check(w, &src, err, sizeof err), 0);
    memset(&g_rs, 0, sizeof g_rs);
    ASSERT_EQ(replay_run(&g_rs, &src, err, sizeof err), 600);
    ASSERT_EQ((long long)g_rs.pkt_total, 600);
    ASSERT_EQ(g_rs.pkt_count, MAX_PACKETS);
}

/* A replayed frame keeps the file's capture time and the file's wire
 * length. The seam this rides on defaults both (synthetic increasing
 * stamps, len = caplen), so passing NULL for either would still
 * dispatch — and stamp the frame with a time nobody captured it at.
 * Proved red by passing NULL ts and NULL orig in rp_batch_flush(). */
static void test_wired_replay_keeps_capture_time_and_wire_length(void) {
    if (!g_dir_ok) { ASSERT(g_dir_ok); return; }
    uint8_t f[128];
    int len = udp_frame(f, sizeof f, 5002);
    char w[256], err[512];
    path_in_dir(w, sizeof w, "snapped.pcap");
    /* Captured whole, but the record claims 1400 octets on the wire:
     * the "kernel snapped it" case (#92). */
    ASSERT_EQ(write_savefile(w, RT_DLT_EN10MB, f, len, 1400, 2, RP_TS_SENTINEL), 0);
    replay_src_t src;
    ASSERT_EQ(replay_check(w, &src, err, sizeof err), 0);
    memset(&g_rs, 0, sizeof g_rs);
    ASSERT_EQ(replay_run(&g_rs, &src, err, sizeof err), 2);
    ASSERT_EQ(g_rs.packets[0].ts_sec, RP_TS_SENTINEL);
    ASSERT_EQ(g_rs.packets[1].ts_sec, RP_TS_SENTINEL + 1);
    ASSERT_EQ(g_rs.packets[0].len, 1400u);
    ASSERT_EQ(g_rs.packets[0].src_port, 5002);
}

/* A radiotap file goes to the monitor path, not on_packet(): the 802.11
 * frame counter moves by exactly the record count. Proved red by routing
 * every file to the wired path. The pkt_total == 0 line is NOT what that
 * mutation catches — on_packet() drops a beacon (no LLC payload) either
 * way — so it pins only that a beacon file adds nothing to the IP ring. */
static void test_radiotap_replay_feeds_the_monitor_path(void) {
    if (!g_dir_ok) { ASSERT(g_dir_ok); return; }
    static const uint8_t ap[6] = { 0x02, 0x00, 0x5e, 0x00, 0x7b, 0x01 };
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t f[128];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 8, 0, bc, ap, ap, 0x0010, 0);       /* beacon, §9.3.3.3 */
    fb_beacon_fixed(&b, 0, 100, 0x0001);
    fb_ssid(&b, "replay-unit");
    ASSERT(fb_ok(&b));
    char m[256], err[512];
    path_in_dir(m, sizeof m, "beacons.pcap");
    ASSERT_EQ(write_savefile(m, RT_DLT_RADIOTAP, f, b.len, b.len, 3, RP_TS_SENTINEL), 0);
    replay_src_t src;
    ASSERT_EQ(replay_check(m, &src, err, sizeof err), 0);
    memset(&g_rs, 0, sizeof g_rs);
    uint64_t before = mon_frame_total();
    ASSERT_EQ(replay_run(&g_rs, &src, err, sizeof err), 3);
    ASSERT_EQ((long long)(mon_frame_total() - before), 3);
    ASSERT_EQ((long long)g_rs.pkt_total, 0);
}

/* A file that ends inside a record is damaged, and a replay of it must
 * not read as a replay of the whole file. libpcap reports the cut as
 * PCAP_ERROR, which replay_run() turns into -1 and a reason. */
static void test_truncated_file_is_an_error_not_a_short_replay(void) {
    if (!g_dir_ok) { ASSERT(g_dir_ok); return; }
    uint8_t f[128];
    int len = udp_frame(f, sizeof f, 5003);
    char w[256], err[512];
    path_in_dir(w, sizeof w, "cut.pcap");
    ASSERT_EQ(write_savefile(w, RT_DLT_EN10MB, f, len, len, 3, RP_TS_SENTINEL), 0);
    /* 24-byte file header + 3 x (16 + len); drop the last 10 octets. */
    ASSERT_EQ(truncate(w, (off_t)(24 + 3 * (16 + len) - 10)), 0);
    replay_src_t src;
    ASSERT_EQ(replay_check(w, &src, err, sizeof err), 0);
    memset(&g_rs, 0, sizeof g_rs);
    err[0] = '\0';
    ASSERT_EQ(replay_run(&g_rs, &src, err, sizeof err), -1);
    ASSERT(strstr(err, "cut.pcap") != NULL);
}

#endif /* WITH_PCAP */

/* ── frame_build.h's wired builders ────────────────────────────────── */

/* RFC 791 header checksum, against a value worked by hand rather than
 * by the builder: the textbook header 4500 0073 0000 0000 4011 ----
 * c0a8 0001 c0a8 00c7 (192.168.0.1 → 192.168.0.199, UDP, total length
 * 115, DF clear). 4500+0073+4011+c0a8+0001+c0a8+00c7 = 0x2079C, folded
 * 0x079E, complemented 0xF861. */
static void test_ipv4_header_checksum_matches_a_worked_example(void) {
    static const uint8_t s[4] = { 192, 168, 0, 1 };
    static const uint8_t d[4] = { 192, 168, 0, 199 };
    uint8_t h[20];
    fb_t b; fb_init(&b, h, sizeof h);
    int at = fb_ipv4(&b, 17, s, d, 115 - 20, 0);
    ASSERT_EQ(at, 0);
    ASSERT(fb_ok(&b));
    ASSERT_EQ(h[10], 0xF8);
    ASSERT_EQ(h[11], 0x61);
    /* The receiver's check (RFC 1071 §1): the sum including the
     * checksum folds to all ones. */
    ASSERT_EQ(fb_csum_fold(fb_csum_add(0, h, 20)), 0);
}

/* UDP and TCP checksums by the receiver's rule: pseudo-header plus
 * segment, checksum field included, sums to all ones. */
static void test_transport_checksums_verify_as_a_receiver_would(void) {
    uint8_t f[160];
    static const uint8_t pl[5] = { 'h', 'e', 'l', 'l', 'o' };
    for (int proto = 0; proto < 2; proto++) {
        fb_t b; fb_init(&b, f, sizeof f);
        if (proto == 0)
            fb_eth_ipv4_udp(&b, G_MAC, H_MAC, H_IP, D_IP, 1, 2, pl, 5, 7);
        else
            fb_eth_ipv4_tcp(&b, G_MAC, H_MAC, H_IP, D_IP, 1, 2, 9, 0,
                            FB_TCP_SYN, pl, 5, 7);
        ASSERT(fb_ok(&b));
        const uint8_t *ip = f + 14;
        int seg_len = b.len - 34;
        uint8_t ph[12];
        memcpy(ph, ip + 12, 8);
        ph[8] = 0; ph[9] = ip[9];
        ph[10] = (uint8_t)(seg_len >> 8); ph[11] = (uint8_t)seg_len;
        ASSERT_EQ(fb_csum_fold(fb_csum_add(fb_csum_add(0, ph, 12),
                                           f + 34, seg_len)), 0);
        ASSERT_EQ(ip[9], proto == 0 ? 17 : 6);
        ASSERT_EQ((ip[2] << 8) | ip[3], 20 + seg_len);
    }
}

void run_replay_tests(void) {
    TEST_SUITE("--replay savefile input (#119)");
    RUN_TEST(test_route_follows_the_live_handles);
    RUN_TEST(test_list_splits_on_commas);
    RUN_TEST(test_list_refuses_rather_than_drops);
    RUN_TEST(test_platform_reads_nothing_from_the_host);
    RUN_TEST(test_ipv4_header_checksum_matches_a_worked_example);
    RUN_TEST(test_transport_checksums_verify_as_a_receiver_would);
#ifdef WITH_PCAP
    g_dir_ok = mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_replay_XXXXXX")) != NULL;
    RUN_TEST(test_check_routes_by_the_file_datalink);
    RUN_TEST(test_wired_replay_dispatches_every_record);
    RUN_TEST(test_wired_replay_keeps_capture_time_and_wire_length);
    RUN_TEST(test_radiotap_replay_feeds_the_monitor_path);
    RUN_TEST(test_truncated_file_is_an_error_not_a_short_replay);
    if (g_dir_ok) {
        static const char *names[] = { "w.pcap", "m.pcap", "raw.pcap",
            "many.pcap", "snapped.pcap", "beacons.pcap", "cut.pcap",
            "junk.pcap" };
        char p[256];
        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
            path_in_dir(p, sizeof p, names[i]);
            unlink(p);
        }
        rmdir(g_dir);
    }
#endif
}
