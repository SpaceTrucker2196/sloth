#include <string.h>
#include <pcap.h>            /* DLT_* — this binary links libpcap by design */
#include <netinet/in.h>      /* IPPROTO_TCP */
#include "runner.h"
#include "sloth.h"
#include "capture/capture.h"

/* ── Real pcap_dispatch → on_packet path — issue #95 ─────────
 *
 * Every other capture test seeds sloth_state_t and asks what the tables
 * do. This file is the only one that makes libpcap hand bytes to the
 * real callback, which is where #95's threat model actually lives: the
 * parsers consume attacker-controlled frames, and until this existed
 * the sanitizers never saw a single one of them.
 *
 * Built only into sloth_test_pcap (make test-capture-path), because the
 * ordinary test binary is deliberately compiled without WITH_PCAP.
 *
 * Frames are hand-built from the RFCs/IEEE clauses per AGENTS.md — no
 * captures, and no .pcap files: capture_test_dispatch() assembles the
 * savefile in memory. The interesting cases are the malformed ones. */

#define ETH_HDR  14
#define SLL2_HDR 20

/* IPv4 + TCP at `ip`, built field by field. Returns bytes written. */
static int ipv4_tcp(uint8_t *ip, int payload_len, int ihl_words,
                    int ip_total_len_override) {
    int ihl = ihl_words * 4;
    ip[0] = (uint8_t)(0x40 | ihl_words);        /* v4, IHL */
    ip[1] = 0;
    int total = ip_total_len_override >= 0
              ? ip_total_len_override
              : ihl + 20 + payload_len;
    ip[2] = (uint8_t)(total >> 8); ip[3] = (uint8_t)total;
    ip[8] = 64;                                  /* TTL   */
    ip[9] = 6;                                   /* TCP   */
    memcpy(ip + 12, "\xc0\xa8\x01\x0a", 4);      /* src 192.168.1.10 */
    memcpy(ip + 16, "\x5d\xb8\xd8\x22", 4);      /* dst 93.184.216.34 */

    uint8_t *tcp = ip + ihl;
    tcp[0] = 0xd4; tcp[1] = 0x31;                /* sport 54321 */
    tcp[2] = 0x01; tcp[3] = 0xbb;                /* dport 443   */
    tcp[12] = 0x50;                              /* data offset 5 */
    tcp[13] = 0x18;                              /* PSH|ACK       */
    return ihl + 20 + payload_len;
}

/* Ethernet II + IPv4 + TCP. Returns length.
 *
 * Zeroes exactly the frame it goes on to build, not a fixed guess: an
 * earlier `memset(f, 0, 64 + payload_len)` overran every caller holding
 * a 64-byte buffer, and ASan called it on this suite's first
 * instrumented run. Fitting as bugs go — the frame builder was the one
 * thing here reading past the end of a buffer. */
static int eth_ipv4_tcp(uint8_t *f, int payload_len, int ihl_words,
                        int ip_total_len_override) {
    const int frame_len = ETH_HDR + ihl_words * 4 + 20 + payload_len;
    memset(f, 0, (size_t)frame_len);
    /* Ethernet: dst, src, ethertype 0x0800 */
    memcpy(f, "\x02\x00\x00\x00\x00\x01", 6);
    memcpy(f + 6, "\x02\x00\x00\x00\x00\x02", 6);
    f[12] = 0x08; f[13] = 0x00;
    ipv4_tcp(f + ETH_HDR, payload_len, ihl_words, ip_total_len_override);
    return frame_len;
}

/* Linux cooked v2 (SLL2) + IPv4 + TCP, per libpcap's linktypes spec:
   protocol 0..1, reserved 2..3, ifindex 4..7 big-endian, ARPHRD 8..9,
   packet type 10, lladdr len 11, lladdr 12..19, payload at 20. The
   ifindex is the field #85 treats as the authorization input. */
static int sll2_ipv4_tcp(uint8_t *f, uint32_t ifindex, int payload_len) {
    const int frame_len = SLL2_HDR + 20 + 20 + payload_len;
    memset(f, 0, (size_t)frame_len);
    f[0] = 0x08; f[1] = 0x00;                    /* protocol: IPv4 */
    f[4] = (uint8_t)(ifindex >> 24); f[5] = (uint8_t)(ifindex >> 16);
    f[6] = (uint8_t)(ifindex >>  8); f[7] = (uint8_t)ifindex;
    f[8] = 0x00; f[9] = 0x01;                    /* ARPHRD_ETHER */
    f[10] = 0;                                   /* PACKET_HOST  */
    f[11] = 6;                                   /* lladdr len   */
    ipv4_tcp(f + SLL2_HDR, payload_len, 5, -1);
    return frame_len;
}

static sloth_state_t g_s;

static int drive(int dlt, const uint8_t *const *f, const int *l, int n) {
    memset(&g_s, 0, sizeof(g_s));
    return capture_test_dispatch(&g_s, dlt, f, l, NULL, n);
}

static void test_wellformed_tcp_reaches_the_ring(void) {
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    /* The callback ran for real: it decoded and wrote the ring. */
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_EQ(g_s.pkt_count, 1);
    ASSERT_EQ(g_s.packets[0].proto, IPPROTO_TCP);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_STR(g_s.packets[0].dst, "93.184.216.34");
    ASSERT_EQ(g_s.packets[0].dst_port, 443);
    /* raw[] is capped at 64 bytes regardless of caplen. */
    ASSERT(g_s.packets[0].raw_len <= 64);
}

static void test_truncated_frames_do_not_read_past_the_end(void) {
    /* The case the sanitizers exist for: a frame cut at every offset
       through the ethernet, IP and TCP headers. Any read past caplen is
       an ASan abort, not an assertion failure — the value here is that
       libpcap hands the callback a buffer sized exactly to caplen. */
    uint8_t f[128];
    int full = eth_ipv4_tcp(f, 8, 5, -1);
    for (int cut = 0; cut <= full; cut++) {
        const uint8_t *fs[1] = { f };
        int ls[1] = { cut };
        int got = drive(DLT_EN10MB, fs, ls, 1);
        ASSERT_EQ(got, 1);                    /* delivered either way */
        /* Below a full ethernet header there is no ethertype to
           dispatch on, so nothing can reach a decoder. */
        if (cut < ETH_HDR) ASSERT_EQ((long long)g_s.pkt_total, 0);
        /* Above it, see test_undecodable_ip_still_occupies_a_ring_slot:
           decode_frame() returns 1 for any IPv4/IPv6 ethertype whether
           or not the decode succeeded, so the row is kept. What matters
           here is that no read went past caplen, which is ASan's call,
           not an assertion's. */
    }
}

static void test_lying_ip_total_length_is_not_trusted(void) {
    /* IP total_len claiming far more than was captured: the classic
       parser overread. The frame is real, the header lies. */
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, 60000);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    /* Whatever the decoder decides, it must not have read past the
       buffer to decide it — that is ASan's call, not ours. */
    ASSERT(g_s.pkt_total <= 1);
}

static void test_absurd_ihl_is_not_decoded(void) {
    /* IHL = 15 words (60 bytes) on a frame carrying nowhere near that:
       the option-length overread. decode_ipv4() is correctly bounded —
       `ihl > len` returns before any field is read — so nothing is
       parsed out of it. */
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 4, 5, -1);
    f[ETH_HDR] = 0x4F;                        /* v4, IHL 15 */
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    ASSERT_EQ(g_s.packets[0].proto, 0);       /* nothing decoded */
    ASSERT_STR(g_s.packets[0].src, "");
    ASSERT_STR(g_s.packets[0].dst, "");
}

static void test_undecodable_ip_still_occupies_a_ring_slot(void) {
    /* Found by this suite on its first run, and left asserted as-is
       rather than quietly adjusted: decode_frame() ends both IP arms
       with
           if (ethertype == 0x0800) { decode_ipv4(...); return 1; }
       so the return value reports "this was an IP ethertype", not "this
       decoded". An IPv4 frame whose header is malformed or truncated
       therefore lands in the ring as a blank row — proto 0, empty
       addresses — and bumps pkt_total, which drives the once-only JSONL
       emit (#20).

       Consequence worth a decision rather than a silent fix: a stream
       of malformed IPv4 frames evicts real packets from a 256-slot ring
       and inflates the counter, costing an attacker nothing. Reported
       on #95; if the arms are changed to propagate the decode result,
       this test fails and names itself. */
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    f[ETH_HDR] = 0x4F;                        /* undecodable */
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 1);   /* counted */
    ASSERT_EQ(g_s.pkt_count, 1);              /* and stored */
    ASSERT_EQ(g_s.packets[0].proto, 0);       /* with nothing in it */
    ASSERT_STR(g_s.packets[0].src, "");
}

static void test_zero_length_and_runt_frames(void) {
    uint8_t f[8] = { 0 };
    const uint8_t *fs[3] = { f, f, f };
    int ls[3] = { 0, 1, 8 };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 3), 3);
    ASSERT_EQ((long long)g_s.pkt_total, 0);
}

static void test_batch_of_mixed_frames(void) {
    /* Good and malformed interleaved, in one dispatch: the ring must
       take exactly the decodable ones, in order. */
    uint8_t good[128], runt[8] = { 0 }, lying[128];
    int gn = eth_ipv4_tcp(good, 8, 5, -1);
    int ln = eth_ipv4_tcp(lying, 8, 5, -1);
    lying[ETH_HDR] = 0x4F;                    /* absurd IHL */
    const uint8_t *fs[4] = { good, runt, lying, good };
    int ls[4] = { gn, 8, ln, gn };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 4), 4);
    /* Three rows, not two: the runt is dropped for having no ethertype,
       but the undecodable IPv4 frame keeps its slot — see
       test_undecodable_ip_still_occupies_a_ring_slot. */
    ASSERT_EQ((long long)g_s.pkt_total, 3);
    ASSERT_EQ(g_s.pkt_count, 3);
    /* Order is preserved and the decodable ones really did decode. */
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ(g_s.packets[1].proto, 0);       /* the undecodable one */
    ASSERT_STR(g_s.packets[2].src, "192.168.1.10");
}

static void test_non_ip_ethertypes_are_dropped(void) {
    uint8_t f[64];
    int n = eth_ipv4_tcp(f, 4, 5, -1);
    f[12] = 0x08; f[13] = 0x06;               /* ARP */
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 0);
}

static void test_sll2_truncated_below_the_ifindex(void) {
    /* SLL2's ifindex lives at bytes 4..7. A frame cut before it cannot
       be attributed, which is the fail-closed case #85 added and #95
       wants driven through the real callback rather than called
       directly. No allow-list here, so it is admitted and then dropped
       for being undecodable. */
    uint8_t f[32];
    memset(f, 0, sizeof(f));
    const uint8_t *fs[1] = { f };
    int ls[1] = { 6 };
    ASSERT_EQ(drive(DLT_LINUX_SLL2, fs, ls, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 0);
}

static void test_dispatch_rejects_bad_arguments(void) {
    uint8_t f[64];
    int n = eth_ipv4_tcp(f, 4, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(capture_test_dispatch(NULL, DLT_EN10MB, fs, ls, NULL, 1), -1);
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, NULL, ls, NULL, 1), -1);
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, NULL, NULL, 1), -1);
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, NULL, -1), -1);
    int bad[1] = { -5 };
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, bad, NULL, 1), -1);
}

static void test_capture_length_shorter_than_original(void) {
    /* A frame the kernel snapped: caplen < len. The record must carry
       the original length while only caplen bytes are readable — the
       #92 truncation case, driven through the real reader. */
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    int origs[1] = { n + 900 };
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, origs, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_EQ((long long)g_s.packets[0].len, n + 900);
    ASSERT(g_s.packets[0].raw_len <= 64);
}

/* ── Scope as an authorization boundary — issue #85 ──────────
 *
 * #85's regression list asks for an out-of-scope packet injected
 * "immediately after worker start", with zero decoder, event,
 * persistence and export side effects asserted. Until the #95 seam
 * existed that could not be written: every scope test calls
 * capture_frame_in_scope() directly, which proves the predicate and
 * not the callback that is supposed to consult it. These drive the
 * real on_packet() with a policy installed, so a frame that should
 * have been refused would show up as a decoded row.
 *
 * `capture_scope_verdict()` — the startup refusal itself — is a pure
 * function already covered in tests/test_capture.c; what was missing
 * is the enforcement on the other side of pthread_create(). */

/* An allow-list of one interface, pinned, as capture_run() leaves it
   just before the worker is created. `valid` 0 models what
   capture_scope_poll() does on delete, rename or index reuse. */
static void scope_setup(uint32_t ifindex, const char *name, int valid) {
    memset(&g_s, 0, sizeof(g_s));
    memcpy(g_s.iface_allowed[0], name, strlen(name) + 1);
    g_s.iface_allowed_count = 1;

    capture_policy_t pol;
    memset(&pol, 0, sizeof(pol));
    pol.count = 1;
    pol.pins[0].ifindex = ifindex;
    memcpy(pol.pins[0].name, name, strlen(name) + 1);
    pol.pins[0].valid = valid;
    pol.mu = NULL;                 /* single-threaded harness */
    capture_test_set_policy(&pol);
    capture_out_of_scope_dropped_reset();
}

/* Dispatch without clearing the state scope_setup() just built. */
static int dispatch(int dlt, const uint8_t *const *f, const int *l, int n) {
    return capture_test_dispatch(&g_s, dlt, f, l, NULL, n);
}

/* Nothing decoded, nothing stored, nothing counted for export. */
static void assert_no_side_effects(void) {
    ASSERT_EQ((long long)g_s.pkt_total, 0);   /* drives the #20 jsonl emit */
    ASSERT_EQ(g_s.pkt_count, 0);
    ASSERT_EQ(g_s.pkt_head, 0);
    ASSERT_EQ(g_s.packets[0].proto, 0);
    ASSERT_STR(g_s.packets[0].src, "");
    ASSERT_STR(g_s.packets[0].dst, "");
    ASSERT_EQ((long long)g_s.packets[0].len, 0);
    ASSERT_EQ(g_s.packets[0].raw_len, 0);
}

static void test_scope_admits_the_pinned_interface(void) {
    scope_setup(7, "wlan1", 1);
    uint8_t f[128];
    int n = sll2_ipv4_tcp(f, 7, 8);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 1), 1);
    /* The control case: the allow-list is active and this frame really
       did go all the way through the decoder. */
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ(g_s.packets[0].dst_port, 443);
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 0);
}

static void test_scope_refuses_an_unpinned_ifindex(void) {
    /* #85's regression bullet, through the real callback: a frame from
       an interface the operator never authorised. */
    scope_setup(7, "wlan1", 1);
    uint8_t f[128];
    int n = sll2_ipv4_tcp(f, 99, 8);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 1), 1);   /* libpcap delivered it */
    assert_no_side_effects();                     /* on_packet refused it */
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 1);
}

static void test_scope_refuses_the_first_frame_after_start(void) {
    /* "Immediately after worker start" — the seam is synchronous, so
       the first frame of the first dispatch *is* that moment. The
       refusal must also not wedge the stream: the authorised frame
       behind it still decodes, and it is the only row. */
    scope_setup(7, "wlan1", 1);
    uint8_t bad[128], good[128];
    int bn = sll2_ipv4_tcp(bad, 99, 8);
    int gn = sll2_ipv4_tcp(good, 7, 8);
    const uint8_t *fs[2] = { bad, good };
    int ls[2] = { bn, gn };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 2), 2);
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_EQ(g_s.pkt_count, 1);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 1);
}

static void test_scope_refuses_an_invalidated_pin(void) {
    /* Adapter deleted, renamed, or its index reused — capture_scope_poll()
       clears the valid bit and never sets it again. The index still
       matches a pin, so this is the case where matching alone must not
       be enough. */
    scope_setup(7, "wlan1", 0);
    uint8_t f[128];
    int n = sll2_ipv4_tcp(f, 7, 8);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 1), 1);
    assert_no_side_effects();
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 1);
}

static void test_scope_refuses_an_unattributable_frame(void) {
    /* Too short to hold the SLL2 ifindex at all. Fail-closed: under an
       allow-list an unattributable frame is refused, not admitted. */
    scope_setup(7, "wlan1", 1);
    uint8_t f[128];
    sll2_ipv4_tcp(f, 7, 8);
    const uint8_t *fs[2] = { f, f };
    int ls[2] = { 7, SLL2_HDR - 1 };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 2), 2);
    assert_no_side_effects();
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 2);
}

static void test_scope_refuses_a_datalink_without_an_ifindex(void) {
    /* An EN10MB frame carries no ingress index, so under an allow-list
       it cannot be attributed and is refused — even though the very
       same bytes decode fine when no allow-list is in force. */
    scope_setup(7, "wlan1", 1);
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_EN10MB, fs, ls, 1), 1);
    assert_no_side_effects();
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 1);
}

static void test_scope_refuses_a_deselected_pinned_interface(void) {
    /* A pinned, still-valid interface the operator has since switched
       off with [y]. The frame is refused, which is correct.

       It also *counts* toward out_of_scope_dropped, which is worth
       asserting explicitly because the counter's header says the
       runtime deselect "does not bump this counter". Both are true as
       written: tests/test_capture.c pins the documented case on an
       unrestricted stream, where the deselect arm returns without
       counting; under an allow-list the deselect is folded into the
       same `admit` test as attribution and does count. Reported on #85
       — if the counter is meant to mean "authorization failure" only,
       this frame should not be in it, and this assertion names itself
       when that changes. */
    scope_setup(7, "wlan1", 1);
    capture_policy_t pol;
    memset(&pol, 0, sizeof(pol));
    pol.count = 1;
    pol.pins[0].ifindex = 7;
    memcpy(pol.pins[0].name, "wlan1", 6);
    pol.pins[0].valid = 1;
    memcpy(pol.desel[0], "wlan1", 6);
    pol.desel_count = 1;
    capture_test_set_policy(&pol);

    uint8_t f[128];
    int n = sll2_ipv4_tcp(f, 7, 8);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 1), 1);
    assert_no_side_effects();
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 1);
}

static void test_no_allow_list_admits_any_ifindex(void) {
    /* The counter-control: with no allow-list the same unpinned frame
       decodes, so the refusals above come from the scope boundary and
       not from something incidental to the SLL2 path. */
    memset(&g_s, 0, sizeof(g_s));
    capture_test_set_policy(NULL);
    capture_out_of_scope_dropped_reset();
    uint8_t f[128];
    int n = sll2_ipv4_tcp(f, 12345, 8);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(dispatch(DLT_LINUX_SLL2, fs, ls, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ((long long)capture_out_of_scope_dropped(), 0);
}

void run_capture_path_tests(void) {
    TEST_SUITE("capture path: real pcap_dispatch -> on_packet (#95)");
    RUN_TEST(test_wellformed_tcp_reaches_the_ring);
    RUN_TEST(test_truncated_frames_do_not_read_past_the_end);
    RUN_TEST(test_lying_ip_total_length_is_not_trusted);
    RUN_TEST(test_absurd_ihl_is_not_decoded);
    RUN_TEST(test_undecodable_ip_still_occupies_a_ring_slot);
    RUN_TEST(test_zero_length_and_runt_frames);
    RUN_TEST(test_batch_of_mixed_frames);
    RUN_TEST(test_non_ip_ethertypes_are_dropped);
    RUN_TEST(test_sll2_truncated_below_the_ifindex);
    RUN_TEST(test_dispatch_rejects_bad_arguments);
    RUN_TEST(test_capture_length_shorter_than_original);

    TEST_SUITE("capture path: scope is an authorization boundary (#85)");
    RUN_TEST(test_scope_admits_the_pinned_interface);
    RUN_TEST(test_scope_refuses_an_unpinned_ifindex);
    RUN_TEST(test_scope_refuses_the_first_frame_after_start);
    RUN_TEST(test_scope_refuses_an_invalidated_pin);
    RUN_TEST(test_scope_refuses_an_unattributable_frame);
    RUN_TEST(test_scope_refuses_a_datalink_without_an_ifindex);
    RUN_TEST(test_scope_refuses_a_deselected_pinned_interface);
    RUN_TEST(test_no_allow_list_admits_any_ifindex);
}
