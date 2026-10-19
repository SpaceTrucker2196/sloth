/* The whole file is the WITH_PCAP capture path; the link-only no-flag
 * build (sloth_test_noflags, #116) gets an empty entry point instead. */
#ifdef WITH_PCAP
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>            /* DLT_* — this binary links libpcap by design */
#include <netinet/in.h>      /* IPPROTO_TCP */
#include "runner.h"
#include "sloth.h"
#include "capture/capture.h"
#include "capture/probe.h"   /* real under WITH_PCAP; the stub would prove nothing */
#include "evidence_ring.h"
#include "sensor_health.h"
#include "flood_window.h"
#include "deauth_snoop.h"   /* the one detector that cites evidence IDs (#92) */
#include "queue_evict.h"
#include "probe_pnl.h"      /* the PNL the +HTC offset feeds */
#include "assoc_track.h"    /* the grant a short assoc response must still record (#122) */
#include "frame_build.h"    /* spec-derived 802.11 builder (#122) */
#include "radiotap.h"       /* RT_F_* flag bits */
#include "beacon_snoop.h"   /* the fuzz counters an FCS trailer used to bump (#123) */
#include "eapol_log.h"      /* the collector DATAPAD used to blind (#123) */
#include "dns_log.h"
#include "rf_quality.h"     /* bad-FCS policy pin (#123) */
#include "libver.h"         /* loaded-libpcap report (#142) */
#include "capture/frame_edge.h" /* FRAME_CAPLEN_MAX (#141) */
#include "http_log.h"       /* IP-layer cases reach the payload parsers (#132) */
#include "kerb_snoop.h"
#include "snmp_snoop.h"

/* ── Real pcap_dispatch → on_packet path — issue #95 ─────────
 *
 * Every other capture test seeds sloth_state_t and asks what the tables
 * do. This file is the only one that makes libpcap hand bytes to the
 * real callback, which is where #95's threat model actually lives: the
 * parsers consume attacker-controlled frames, and until this existed
 * the sanitizers never saw a single one of them.
 *
 * Part of sloth_test since #116, which builds the suite WITH_PCAP; it was
 * a separate binary (sloth_test_pcap) while the suite was not.
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
    uint64_t fe0 = sh_parse_fault_count(SH_PF_FRAME_EDGE);
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 3), 3);
    ASSERT_EQ((long long)g_s.pkt_total, 0);
    /* The zero-length record is refused at the pcap edge (#141); the
       1- and 8-octet ones pass it and are dropped by the decoder for
       having no ethertype, which is not an edge fault. */
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 1);
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

/* -- [m] retarget vs. the allow-list - issue #85 -------------
 *
 * The Interfaces view's [m] key retargets the monitor radio onto the
 * selected row. probe_set_iface() is the chokepoint, so the refusal is
 * asserted there rather than through view_iface_key().
 *
 * These live in this binary and not tests/test_probe.c because
 * probe_set_iface() is real only under WITH_PCAP; sloth_test compiles
 * the inline no-op from probe.h, which would pass either way.
 *
 * MISSION.md section 2: nothing here may open a real interface. The
 * refusal path returns before any pcap call, so it needs no device at
 * all; the controls deliberately name an interface that cannot exist,
 * so pcap_open_live() fails rather than capturing. */

#define NO_SUCH_IF "zzz_no_such_if"

static void retarget_setup(const char *allowed, const char *current) {
    memset(&g_s, 0, sizeof(g_s));
    if (allowed) {
        snprintf(g_s.iface_allowed[0], sizeof(g_s.iface_allowed[0]), "%s", allowed);
        g_s.iface_allowed_count = 1;
    }
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "%s", current);
}

static void test_retarget_outside_the_allow_list_is_refused(void) {
    retarget_setup("wlan1", NO_SUCH_IF "9");
    probe_set_iface(&g_s, NO_SUCH_IF "9");

    /* The reason is recorded in s->probe_err. Note where that is and is
       not visible: src/views/probe.c, dashboard_bands.c and eapol.c
       render it, and it is exported in sensor_health — but
       src/views/iface.c does not, so the operator who presses [m] gets
       no feedback in the view they pressed it in. Surfacing it there is
       a follow-up, not something this assertion claims. */
    ASSERT_STR(g_s.probe_err, NO_SUCH_IF "9 not in --iface allow-list");
    /* The retarget did not take effect — probe_iface is untouched.
       What this does NOT prove is the ordering against probe_stop():
       probe_stop() never writes s->probe_iface, so this assertion would
       hold either way. That a refusal leaves an already-running worker
       alive needs a live capture thread, which needs a real radio, so
       it is argued from the code (the check precedes probe_stop()) and
       left unasserted rather than faked. */
    ASSERT_STR(g_s.probe_iface, NO_SUCH_IF "9");
}

static void test_refusal_is_attributable_to_the_allow_list(void) {
    /* Control: same call, same unopenable device, but the name is ON
       the list. The error that comes back is pcap's, not the boundary's
       - which is what makes the refusal above attributable to the
       allow-list rather than to a failed open. */
    retarget_setup(NO_SUCH_IF, "");
    probe_set_iface(&g_s, NO_SUCH_IF);

    ASSERT(g_s.probe_err[0] != '\0');
    ASSERT(strstr(g_s.probe_err, "allow-list") == NULL);
    ASSERT_EQ(strncmp(g_s.probe_err, "pcap(", 5), 0);
    ASSERT_STR(g_s.probe_iface, "");
}

static void test_an_empty_allow_list_admits_any_retarget(void) {
    /* iface_is_allowed() returns 1 on an empty list, so an unrestricted
       run keeps its pre-#85 behaviour: the retarget proceeds and fails
       only at the open. */
    retarget_setup(NULL, "");
    ASSERT_EQ(g_s.iface_allowed_count, 0);
    probe_set_iface(&g_s, NO_SUCH_IF);

    ASSERT_EQ(strncmp(g_s.probe_err, "pcap(", 5), 0);
}

static void test_a_failed_retarget_open_keeps_the_current_radio(void) {
    /* #140: a run that dropped CAP_NET_RAW cannot open a new radio, so
       [m] fails at pcap_open_live(). The new handle is opened before
       probe_stop(), so the failure leaves the radio already named in
       probe_iface in place instead of blanking it. The unopenable name
       stands in for the EPERM a dropped run gets.
       Seen to fail: with the pre-#140 clear of probe_iface put back in
       the failed-open branch, probe_iface comes back "" here. What this
       does not prove is the ordering against probe_stop() — with no
       live worker, probe_stop() changes nothing observable — nor that
       a live worker survives; both need a real radio, as the
       allow-list case above says, and are argued from the code. */
    retarget_setup(NULL, "current0");
    probe_set_iface(&g_s, NO_SUCH_IF);
    ASSERT_EQ(strncmp(g_s.probe_err, "pcap(", 5), 0);
    ASSERT_STR(g_s.probe_iface, "current0");
}

static void test_retarget_ignores_an_empty_name(void) {
    /* Guard ordering: an empty name is rejected before the boundary, so
       it must not be reported as an allow-list refusal. */
    retarget_setup("wlan1", "wlan1");
    probe_set_iface(&g_s, "");
    ASSERT_STR(g_s.probe_err, "");
    ASSERT_STR(g_s.probe_iface, "wlan1");
}

/* ── Monitor dispatch seam — issue #92 ───────────────────────
 *
 * The 802.11 path had no test entry point at all: on_probe_frame() is
 * static, src/capture/probe.c is not in TEST_CORE_SRCS, and every existing
 * monitor test seeds sloth_state_t instead. So radiotap parsing and the
 * frame-type guards — which read bytes straight off the air — were
 * reachable only through a real radio.
 *
 * probe_test_dispatch() is the monitor twin of capture_test_dispatch().
 * These cases pin the guards in on_probe_frame() by observing
 * mon_frame_total(), which it bumps once per admitted frame.
 *
 * This slice is the seam ONLY. #92's real defect — nine time(NULL)
 * calls in this callback beside one frame-timestamp read — is NOT
 * fixed here, and these tests do not claim it is. The seam takes
 * per-frame timestamps precisely so the fix can be pinned when it is
 * written. */

#define RT_HDR 8            /* the minimal radiotap header built below */

/* mon_frame_total() is a LIFETIME counter and probe_clear() does not
   reset it (it clears the probe list only), so every assertion here is
   a delta. Found by writing the absolute form first and watching three
   cases fail on carry-over from the case before — which is the correct
   behaviour of a monotonic counter, not a bug to design around. */
static uint64_t mon_before(void) { return mon_frame_total(); }
static long long mon_delta(uint64_t before) {
    return (long long)(mon_frame_total() - before);
}

/* radiotap (8-byte, no present fields) + the first dot11_len bytes of
   a zero-addressed management-shaped frame with Frame Control fc0 (a
   beacon's is 0x80). Built whole with tests/frame_build.h and then cut
   to the requested length, so a 9-byte runt is the prefix of a real
   frame rather than nine arbitrary octets. it_present = 0: no fields,
   so radiotap_parse() finds no signal or channel and the handler
   proceeds on defaults. Returns total length. */
static int mon_frame(uint8_t *f, int dot11_len, uint8_t fc0) {
    static const uint8_t a1[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t whole[RT_HDR + 64];
    fb_t b; fb_init(&b, whole, sizeof whole);
    fb_radiotap(&b, NULL);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = (uint8_t)((fc0 >> 2) & 0x03);
    h.subtype = (uint8_t)(fc0 >> 4);
    h.a1 = a1;
    fb_dot11_hdr(&b, &h);
    const int total = RT_HDR + dot11_len;
    /* Copy only what the builder wrote and zero the rest. `whole` holds
     * RT_HDR + 64 bytes; callers ask for far more (the evidence-ring tests
     * build a 900-byte frame), and copying `total` bytes out of it read
     * 836 bytes past the end of this stack buffer - ASan failed the
     * capture-path binary on 6f2f9c2 while every local gate was green,
     * because the sanitized capture-path run is a CI-only gate. */
    memset(f, 0, (size_t)total);
    int built = b.len < total ? b.len : total;
    memcpy(f, whole, (size_t)built);
    return total;
}

static void test_monitor_seam_admits_a_wellformed_frame(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);          /* beacon, full framing */
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint64_t b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    /* The real callback ran: it parsed radiotap, passed the framing
       guards and recorded the frame. */
    ASSERT_EQ(mon_delta(b), 1);
}

static void test_monitor_seam_counts_each_admitted_frame(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t a[128], b[128], c[128];
    int an = mon_frame(a, 24, 0x80);         /* beacon      */
    int bn = mon_frame(b, 24, 0x40);         /* probe req   */
    int cn = mon_frame(c, 10, 0xD4);         /* ACK, 10 bytes */
    const uint8_t *fs[3] = { a, b, c };
    int ls[3] = { an, bn, cn };
    uint64_t base = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 3), 3);
    ASSERT_EQ(mon_delta(base), 3);
}

/* A probe request carrying one SSID IE, optionally with +HTC/Order set.
 *
 * With `htc`, four octets of HT Control sit between Sequence Control and
 * the body, so the IEs start at 28 (IEEE 802.11-2020 §9.2.4.1.10,
 * §9.3.3.2). The HT Control bytes are DE AD BE EF: read as the start of
 * the IE list they look like tag 0xDE claiming length 0xAD, which
 * overruns and ends the walk, so no SSID is extracted at all. */
static int mon_probe_req(uint8_t *f, const uint8_t sa[6],
                         const char *ssid, int htc) {
    int sl    = (int)strlen(ssid);
    int dlen  = 24 + (htc ? 4 : 0) + 2 + sl;
    int total = RT_HDR + dlen;
    memset(f, 0, (size_t)total);
    f[2] = (uint8_t)RT_HDR;                 /* it_len, it_present = 0 */
    uint8_t *d = f + RT_HDR;
    d[0] = 0x40;                            /* probe request */
    d[1] = htc ? 0x80 : 0x00;               /* +HTC/Order */
    memset(d + 4,  0xff, 6);                /* addr1 = broadcast */
    memcpy(d + 10, sa,   6);                /* addr2 = the client */
    memset(d + 16, 0xff, 6);                /* addr3 = broadcast */
    int off = 24;
    if (htc) {
        d[24] = 0xDE; d[25] = 0xAD; d[26] = 0xBE; d[27] = 0xEF;
        off = 28;
    }
    d[off++] = 0x00;                        /* SSID tag */
    d[off++] = (uint8_t)sl;
    memcpy(d + off, ssid, (size_t)sl);
    return total;
}

static void test_probe_request_pnl_survives_the_htc_bit(void) {
    /* The preferred-network list is what the KARMA correlation is built
       on, and on_probe_frame() walked the IEs from a hardcoded 24 until
       2026-10-14 — so a probe request with the +HTC bit set contributed
       no SSID to the PNL. One bit, and the client's network list goes
       unseen.

       Driven through probe_test_dispatch(), the real pcap_dispatch
       seam, so the offset is exercised where the frame actually
       arrives. Both variants asserted together: the plain frame proves
       the harness works, the +HTC one proves the offset does. */
    const uint8_t sa[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t f[128];

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    int n = mon_probe_req(f, sa, "corp-wifi", 0);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(probe_pnl_ssid_count(sa), 1);

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    n = mon_probe_req(f, sa, "corp-wifi", 1);
    const uint8_t *fs2[1] = { f };
    int ls2[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs2, ls2, NULL, NULL, 1), 1);
    ASSERT_EQ(probe_pnl_ssid_count(sa), 1);
    probe_pnl_clear();
}

/* ── Fix I (#122): no 36-octet floor on (re)association responses ──
 *
 * on_probe_frame() kept `if (dot11_len < 36) return;` ahead of the
 * assoc/probe-response arm from before the +HTC work gave that arm a
 * proper `mhdr + fixed` check. An association response is legal at
 * header + 6 fixed octets (§9.3.3.7): 30 bytes bare, 33 with a
 * one-rate Supported Rates element. Every such grant was dropped
 * before the association tracker saw it, so a station joining an AP
 * whose response carried few elements never appeared in the assoc
 * view. Driven through probe_test_dispatch(), the real pcap_dispatch
 * seam.
 *
 * Mutation-proved: reinserting `if (dot11_len < 36) return;` at the
 * top of that arm reddens both cases; the inverse edit restores green. */
static const uint8_t SA_BSSID[6] = { 0x02, 0x00, 0x5e, 0x00, 0x01, 0x01 };
static const uint8_t SA_STA[6]   = { 0x02, 0x00, 0x5e, 0x00, 0x01, 0x02 };

static int assoc_resp_short(uint8_t *f, int cap, int with_rates) {
    fb_t b; fb_init(&b, f, cap);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 1, 0, SA_STA, SA_BSSID, SA_BSSID, 0x0010, 0);
    fb_assoc_resp_fixed(&b, 0x0411, 0 /* success */, 0xc001);
    if (with_rates) {
        static const uint8_t rates[1] = { 0x82 };     /* 1 Mb/s, basic */
        fb_ie(&b, 1, rates, 1);
    }
    return fb_ok(&b) ? b.len : -1;
}

static void test_a_short_assoc_response_records_the_grant(void) {
    uint8_t f[64];
    for (int rates = 0; rates <= 1; rates++) {
        memset(&g_s, 0, sizeof(g_s));
        probe_clear();
        assoc_clear();
        int n = assoc_resp_short(f, sizeof f, rates);
        ASSERT_EQ(n - RT_HDR, rates ? 33 : 30);
        const uint8_t *fs[1] = { f };
        int ls[1] = { n };
        ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
        ASSERT_EQ(assoc_count(), 1);
        assoc_snapshot(&g_s);
        ASSERT_EQ(g_s.assoc_count, 1);
        ASSERT_EQ(memcmp(g_s.assocs[0].bssid,   SA_BSSID, 6), 0);
        ASSERT_EQ(memcmp(g_s.assocs[0].sta_mac, SA_STA,   6), 0);
        ASSERT_EQ(g_s.assocs[0].source, ASSOC_SRC_ASSOC);
    }
    /* The floor that remains is the fixed part: 29 octets has no
       status code to read and records nothing. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    int n = assoc_resp_short(f, sizeof f, 0);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n - 1 };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(assoc_count(), 0);
    /* And a refused grant (status 17, AP full) is not an association. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    n = assoc_resp_short(f, sizeof f, 1);
    f[RT_HDR + 26] = 17;
    int ls2[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls2, NULL, NULL, 1), 1);
    ASSERT_EQ(assoc_count(), 0);
    assoc_clear();
}

/* #126: the (re)association / probe-response SSID walk in
 * on_probe_frame() runs on the shared iterator. A response whose first
 * element (Supported Rates) claims 8 octets with 1 present is a stop
 * counted once; the grant itself is still recorded, as before, because
 * the status code is a fixed field ahead of the elements. The same
 * response with a well-formed Supported Rates element counts nothing.
 * Mutation-proved by deleting that walk's sh_parse_fault_note(). */
static void test_assoc_response_element_overrun_is_tallied(void) {
    uint8_t f[64];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 1, 0, SA_STA, SA_BSSID, SA_BSSID, 0x0010, 0);
    fb_assoc_resp_fixed(&b, 0x0411, 0 /* success */, 0xc001);
    fb_u8(&b, 1);           /* Supported Rates */
    fb_u8(&b, 8);           /* claims 8 */
    fb_u8(&b, 0x82);        /* has 1 */
    ASSERT(fb_ok(&b));

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    uint64_t pf0 = sh_parse_fault_count(SH_PF_IE_OVERRUN);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IE_OVERRUN) - pf0), 1);
    ASSERT_EQ(assoc_count(), 1);

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    int n = assoc_resp_short(f, sizeof f, 1);
    ls[0] = n;
    pf0 = sh_parse_fault_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ((long long)(sh_parse_fault_total() - pf0), 0);
    ASSERT_EQ(assoc_count(), 1);
    assoc_clear();
}

/* #126: the probe-request SSID walk. A request whose first element
 * overruns adds THREE — this walk, then the vendor-IE fingerprint and
 * PHY-tier walks over the same list. That is the tally's stated
 * meaning (walks that stopped, not frames; sensor_health.h), pinned
 * here so a change to it is a visible decision. A well-formed request
 * adds nothing. Mutation-proved by deleting this walk's note: 3 → 2. */
static void test_probe_request_element_overrun_is_tallied_per_walk(void) {
    static const uint8_t sa[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x77 };
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t f[64];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 4, 0, bc, sa, bc, 0x0020, 0);
    fb_u8(&b, 1);           /* Supported Rates */
    fb_u8(&b, 8);           /* claims 8 */
    fb_u8(&b, 0x82);        /* has 1 */
    ASSERT(fb_ok(&b));

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    uint64_t pf0 = sh_parse_fault_count(SH_PF_IE_OVERRUN);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IE_OVERRUN) - pf0), 3);

    uint8_t g[128];
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    int n = mon_probe_req(g, sa, "corp-wifi", 0);
    const uint8_t *gs[1] = { g };
    int gl[1] = { n };
    pf0 = sh_parse_fault_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, gs, gl, NULL, NULL, 1), 1);
    ASSERT_EQ((long long)(sh_parse_fault_total() - pf0), 0);
    ASSERT_EQ(probe_pnl_ssid_count(sa), 1);
    probe_pnl_clear();
}

/* #127: both SSID walks in on_probe_frame() are dot11_ie_ssid(). A
 * 33-octet SSID element (§9.4.2.2 allows 0..32) reaches the PNL from a
 * probe request and the association table from an association
 * response clamped to its first 32 octets on each path. Neither path
 * has an oversize counter — the beacon path's is pinned in
 * tests/test_dot11_ie.c — so what is asserted here is the clamp. */
static const char SSID33[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";

static void test_probe_request_ssid_33_is_clamped_to_32(void) {
    static const uint8_t sa[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x78 };
    uint8_t f[RT_HDR + 24 + 2 + 33];
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    int n = mon_probe_req(f, sa, SSID33, 0);
    ASSERT_EQ(n, (int)sizeof f);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    probe_pnl_snapshot(&g_s);
    ASSERT_EQ(g_s.pnl_count, 1);
    ASSERT_EQ(g_s.pnl_clients[0].ssid_count, 1);
    ASSERT_STR(g_s.pnl_clients[0].ssids[0], "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    probe_pnl_clear();
}

static void test_assoc_response_ssid_33_is_clamped_to_32(void) {
    uint8_t f[RT_HDR + 24 + 6 + 2 + 33];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 1, 0, SA_STA, SA_BSSID, SA_BSSID, 0x0010, 0);
    fb_assoc_resp_fixed(&b, 0x0411, 0 /* success */, 0xc001);
    fb_ie(&b, 0, SSID33, 33);
    ASSERT(fb_ok(&b));
    ASSERT_EQ(b.len, (int)sizeof f);

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    assoc_snapshot(&g_s);
    ASSERT_EQ(g_s.assoc_count, 1);
    ASSERT_STR(g_s.assocs[0].ssid, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    assoc_clear();
}

/* ── FCS is a trailer, not frame (#122) ──────────────────────
 *
 * With radiotap FLAGS saying the FCS is present, the four trailing
 * octets used to reach every parser as frame body — an IE walker read
 * them as one more element. The monitor band's per-frame length is
 * the one place the stripped length is directly observable. */
static void test_fcs_is_stripped_before_the_frame_is_recorded(void) {
    static const uint8_t sa[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x66 };
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t f[128];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_FCS;
    int rtl = fb_radiotap(&b, &rt);
    fb_mgmt(&b, 4, 0, bc, sa, bc, 0x0020, 0);  /* probe request */
    fb_ssid(&b, "fb-test-net");
    int mpdu = b.len - rtl;
    fb_fcs(&b);
    ASSERT(fb_ok(&b));

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    mon_frame_snapshot(&g_s);
    ASSERT(g_s.mon_frame_count >= 1);
    ASSERT_EQ((int)g_s.mon_frames[0].len, mpdu);
    /* The SSID still arrives, with the trailer no longer walked. */
    ASSERT_EQ(probe_pnl_ssid_count(sa), 1);

    /* Same frame, FCS flag clear: the four octets are frame. */
    f[rtl - 1] = 0;                       /* the FLAGS octet */
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    mon_frame_snapshot(&g_s);
    ASSERT_EQ((int)g_s.mon_frames[0].len, mpdu + 4);

    /* A capture truncated inside the trailer strips only what is
       there: origlen says 4 FCS octets, caplen holds 2 of them. */
    f[rtl - 1] = RT_F_FCS;
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    int ls3[1] = { b.len - 2 };
    int ol3[1] = { b.len };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls3, ol3, NULL, 1), 1);
    mon_frame_snapshot(&g_s);
    ASSERT_EQ((int)g_s.mon_frames[0].len, mpdu);
    probe_pnl_clear();
}

/* ── DATAPAD on the IP side (#122) ───────────────────────────
 *
 * capture.c's DLT_IEEE802_11_RADIO arm now decodes through the view
 * with radiotap's hints. RT_F_DATAPAD means the driver padded the MAC
 * header to a 4-octet boundary: a 26-octet QoS header puts LLC/SNAP
 * at 28, and without honouring the flag the frame reads as bare LLC
 * and is dropped. With RT_F_FCS the trailer is also taken off the
 * length handed to the IP decoder. */
static void test_radiotap_datapad_frame_reaches_the_ip_decoder(void) {
    static const uint8_t ap [6] = { 0x02, 0x00, 0x5e, 0x00, 0x00, 0x11 };
    static const uint8_t sta[6] = { 0x02, 0x00, 0x5e, 0x00, 0x00, 0x12 };
    uint8_t f[160];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_DATAPAD | RT_F_FCS;
    int rtl = fb_radiotap(&b, &rt);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_FROMDS;
    h.a1 = sta; h.a2 = ap; h.a3 = ap; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    ASSERT_EQ(b.len - rtl, 26);
    fb_datapad_to4(&b, rtl);
    ASSERT_EQ(b.len - rtl, 28);
    fb_llc_snap(&b, 0x0800);
    uint8_t ip[48];
    memset(ip, 0, sizeof ip);
    int ipn = ipv4_tcp(ip, 8, 5, -1);
    fb_bytes(&b, ip, ipn);
    fb_fcs(&b);
    ASSERT(fb_ok(&b));

    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    ASSERT_EQ(drive(DLT_IEEE802_11_RADIO, fs, ls, 1), 1);
    ASSERT_EQ(g_s.pkt_count, 1);
    ASSERT_EQ(g_s.packets[0].proto, IPPROTO_TCP);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ(g_s.packets[0].dst_port, 443);

    /* Flag clear, pad bytes still there: LLC is read at 26, which is
       00 00 AA — not SNAP — so the frame is dropped rather than
       misparsed. The hint, not luck, is what placed the body. */
    f[rtl - 1] = RT_F_FCS;
    ASSERT_EQ(drive(DLT_IEEE802_11_RADIO, fs, ls, 1), 1);
    ASSERT_EQ(g_s.pkt_count, 0);
}

/* ── Radiotap applied before parsing (#123) ──────────────────
 *
 * #122 taught both monitor entry points to strip the FCS and decode
 * with radiotap's hints. These pin what that buys downstream, through
 * the real pcap_dispatch seam, plus the remainder #123 delivered: one
 * radiotap gate in probe.c, and DATAPAD removed before the data-frame
 * observers. */

static const uint8_t RT_AP [6] = { 0x02, 0x00, 0x5e, 0x00, 0x7b, 0x01 };
static const uint8_t RT_STA[6] = { 0x02, 0x00, 0x5e, 0x00, 0x7b, 0x02 };

/* A healthy beacon (§9.3.3.3): fixed part, SSID, Supported Rates, DSSS
 * Parameter Set, then a 4-octet trailer the radiotap FLAGS octet calls
 * the FCS. sloth never verifies an FCS value — the radiotap BADFCS bit
 * is the driver's verdict — so the trailer is chosen as the worst case
 * for an element walker that mistakes it for body: DD 7F reads as a
 * vendor-specific element claiming 127 octets with 2 left, an overrun
 * on every beacon. `rt_flags` is the FLAGS octet. Returns the length
 * and leaves the FLAGS octet's offset in *flags_at. */
static int rt_beacon(uint8_t *f, int cap, uint8_t rt_flags, int *flags_at) {
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t rates[4] = { 0x82, 0x84, 0x8b, 0x96 };
    static const uint8_t ds[1] = { 6 };
    static const uint8_t trailer[4] = { 0xdd, 0x7f, 0x00, 0x00 };
    fb_t b; fb_init(&b, f, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = rt_flags;
    int rtl = fb_radiotap(&b, &rt);
    *flags_at = rtl - 1;                  /* the only present field */
    fb_mgmt(&b, 8, 0, bc, RT_AP, RT_AP, 0x0010, 0);
    fb_beacon_fixed(&b, 0, 100, 0x0001);  /* ESS, open */
    fb_ssid(&b, "rt-test-net");
    fb_ie(&b, 1, rates, (int)sizeof rates);
    fb_ie(&b, 3, ds, 1);
    fb_bytes(&b, trailer, 4);
    return fb_ok(&b) ? b.len : -1;
}

static const beacon_ap_t *rt_find_ap(void) {
    beacon_snapshot(&g_s);
    for (int i = 0; i < g_s.beacon_count; i++)
        if (memcmp(g_s.beacon_aps[i].bssid, RT_AP, 6) == 0)
            return &g_s.beacon_aps[i];
    return NULL;
}

static void test_an_fcs_beacon_walks_no_phantom_element(void) {
    /* Defect G. On an FCS-including driver (ath9k, rt2800 in monitor
       mode) the trailer used to reach beacon_parse() as body: every
       beacon counted an IE overrun, which is MGMT_FUZZ's input, and the
       overrun suppressed ie_order_hash, so the evil-twin fingerprint
       lost that dimension on healthy air.

       Mutation-proved: passing 0 for fcs_present to
       dot11_fcs_strip_len() in on_probe_frame() reddens both
       assertions on the FCS frame; the inverse edit restores green. */
    uint8_t f[160];
    int fl = 0;
    int n = rt_beacon(f, sizeof f, RT_F_FCS, &fl);
    ASSERT_GT(n, 0);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); beacon_clear();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    const beacon_ap_t *ap = rt_find_ap();
    ASSERT(ap != NULL);
    if (ap) {
        ASSERT_STR(ap->ssid, "rt-test-net");
        ASSERT_EQ(ap->fuzz_ie_overruns, 0);
        ASSERT(ap->fp.ie_order_hash != 0);
    }

    /* Control: the same octets with the FCS flag clear ARE body, so
       the walker must see the overrun. Without this the zero above
       could be a beacon that never parsed far enough to overrun. */
    f[fl] = 0;
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); beacon_clear();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ap = rt_find_ap();
    ASSERT(ap != NULL);
    if (ap) {
        ASSERT_EQ(ap->fuzz_ie_overruns, 1);
        ASSERT_EQ(ap->fp.ie_order_hash, 0u);
    }
    beacon_clear();
}

/* QoS data, AP -> STA (FromDS), RT_F_DATAPAD set, carrying an
 * EAPOL-Key M1 (§12.7.6.2): Key Information = pairwise | Ack |
 * descriptor version 2, no MIC, no Install, no Secure; Key Data Length
 * 0. The 26-octet QoS header is padded to 28 per the flag. */
static int rt_datapad_m1(uint8_t *f, int cap, int *flags_at) {
    fb_t b; fb_init(&b, f, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_DATAPAD;
    int rtl = fb_radiotap(&b, &rt);
    *flags_at = rtl - 1;
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_FROMDS;
    h.a1 = RT_STA; h.a2 = RT_AP; h.a3 = RT_AP; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    fb_datapad_to4(&b, rtl);
    fb_llc_snap(&b, 0x888E);
    fb_u8(&b, 2);                 /* EAPOL version 802.1X-2004 */
    fb_u8(&b, 3);                 /* EAPOL-Key */
    fb_be16(&b, 95);              /* body: the fixed key descriptor */
    fb_u8(&b, 2);                 /* descriptor type: RSN */
    fb_be16(&b, 0x008A);          /* Key Info: Ack | Pairwise | ver 2 */
    fb_be16(&b, 16);              /* Key Length */
    fb_le64(&b, 0);               /* Replay Counter (8, value irrelevant) */
    for (int i = 0; i < 32; i++) fb_u8(&b, 0x11);   /* ANonce */
    for (int i = 0; i < 16 + 8 + 8 + 16; i++) fb_u8(&b, 0);  /* IV RSC ID MIC */
    fb_be16(&b, 0);               /* Key Data Length */
    return fb_ok(&b) ? b.len : -1;
}

static void test_a_datapad_eapol_m1_reaches_the_collector(void) {
    /* The data-frame observers in on_probe_frame() take a bare frame
       and put LLC at the end of the MAC header. With DATAPAD the two
       pad octets sat there instead, so the handshake was missed.

       Mutation-proved: `out->body_off = need;` in dot11_frame_decode()
       (the pad ignored) reddens the first assertion; the inverse edit
       restores green. */
    uint8_t f[200];
    int fl = 0;
    int n = rt_datapad_m1(f, sizeof f, &fl);
    ASSERT_GT(n, 0);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); eapol_clear();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(eapol_event_count(), 1);

    /* Control: flag clear, pad still present. LLC is then read at 26,
       which holds the pad — not SNAP — so nothing is recorded. The
       flag, not the frame's shape, is what moved the body. */
    f[fl] = 0;
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); eapol_clear();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(eapol_event_count(), 0);
    eapol_clear();
}

static void test_a_datapad_dns_query_reaches_the_dns_log(void) {
    /* The IP-side twin: capture.c's DLT_IEEE802_11_RADIO arm, a QoS
       data frame STA -> AP with DATAPAD and FCS, carrying an RFC 1035
       query. Pins #122's arm end to end at the DNS log rather than at
       the packet ring. */
    uint8_t f[200];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_DATAPAD | RT_F_FCS;
    int rtl = fb_radiotap(&b, &rt);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_TODS;
    h.a1 = RT_AP; h.a2 = RT_STA; h.a3 = RT_AP; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    fb_datapad_to4(&b, rtl);
    fb_llc_snap(&b, 0x0800);
    /* DNS: ID, RD, QDCOUNT 1, then QNAME "printer.lan" A IN. */
    static const uint8_t dns[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        7, 'p', 'r', 'i', 'n', 't', 'e', 'r', 3, 'l', 'a', 'n', 0,
        0x00, 0x01, 0x00, 0x01 };
    const int udp_len = 8 + (int)sizeof dns;
    const int ip_len  = 20 + udp_len;
    fb_u8(&b, 0x45); fb_u8(&b, 0);       /* v4, IHL 5, DSCP 0 */
    fb_be16(&b, (uint16_t)ip_len);
    fb_be16(&b, 0); fb_be16(&b, 0);      /* ID, flags/frag */
    fb_u8(&b, 64); fb_u8(&b, 17);        /* TTL, UDP */
    fb_be16(&b, 0);                      /* checksum: not verified */
    fb_bytes(&b, "\xc0\xa8\x01\x0a", 4); /* 192.168.1.10 */
    fb_bytes(&b, "\xc0\xa8\x01\x01", 4); /* 192.168.1.1  */
    fb_be16(&b, 40000); fb_be16(&b, 53);
    fb_be16(&b, (uint16_t)udp_len); fb_be16(&b, 0);
    fb_bytes(&b, dns, (int)sizeof dns);
    fb_fcs(&b);
    ASSERT(fb_ok(&b));

    dns_log_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    ASSERT_EQ(drive(DLT_IEEE802_11_RADIO, fs, ls, 1), 1);
    dns_log_snapshot(&g_s);
    ASSERT_EQ(g_s.dns_log_count, 1);
    ASSERT_STR(g_s.dns_log[0].qname, "printer.lan");
    ASSERT_STR(g_s.dns_log[0].src, "192.168.1.10");
    dns_log_clear();
}

static void test_a_short_radiotap_length_is_refused_and_counted(void) {
    /* Defect H. on_probe_frame() read it_len itself, checked only that
       it was below caplen, and ignored radiotap_parse()'s verdict — so
       an it_len of 4, which the parser rejects, was accepted and the
       "802.11 frame" began inside the present bitmap. capture.c already
       gated on the parser; now both entry points do.

       Mutation-proved: discarding the return (`radiotap_parse(data,
       len, &rt);` with no `if`) admits the frame and reddens both the
       mon_frame_total delta and the reject delta; the inverse edit
       restores green. */
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    f[2] = 4; f[3] = 0;                     /* it_len below the fixed 8 */
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };

    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    uint64_t b   = mon_before();
    uint64_t rj0 = mon_radiotap_reject_total();
    uint64_t pf0 = sh_parse_fault_count(SH_PF_RADIOTAP_BAD);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b), 0);
    ASSERT_EQ((long long)(mon_radiotap_reject_total() - rj0), 1);
    /* …and into the sensor-wide parse-fault tally the JSONL record
       carries (#126). Mutation-proved: deleting the
       sh_parse_fault_note(SH_PF_RADIOTAP_BAD) call reddens this line
       and the zero-delta one below stays green, as it should. */
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_RADIOTAP_BAD) - pf0), 1);

    /* Published to the operator through the health poll. */
    capture_health_t h; memset(&h, 0, sizeof h);
    probe_health_poll(&h);
    ASSERT_EQ((long long)h.parse_rejects,
              (long long)mon_radiotap_reject_total());
    ASSERT_GT((long long)h.parse_rejects, 0);

    /* A well-formed header is admitted and not tallied, so the tally
       counts refusals and not frames. */
    n = mon_frame(f, 24, 0x80);
    ls[0] = n;
    b   = mon_before();
    rj0 = mon_radiotap_reject_total();
    pf0 = sh_parse_fault_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b), 1);
    ASSERT_EQ((long long)(mon_radiotap_reject_total() - rj0), 0);
    ASSERT_EQ((long long)(sh_parse_fault_total() - pf0), 0);
}

/* ── The pcap-edge gate through both real callbacks (#141) ────
 *
 * tests/test_frame_edge.c pins frame_view_init() and
 * frame_view_radiotap() on their own; these prove on_packet() and
 * on_probe_frame() actually stand behind them, through the same
 * libpcap offline reader production uses. */

static void test_a_short_radiotap_probe_request_reaches_no_pnl(void) {
    /* it_len 4, and the bytes from offset 4 on are a whole probe
       request. A callback that took it_len on its own authority — what
       on_probe_frame() did before #123 — reads a probe request there
       and files its SSID in the client's PNL. The shared gate takes
       radiotap_parse()'s verdict, which refuses it.

       Mutation-proved: in frame_view_radiotap(), replacing the
       radiotap_parse() verdict with the old private rule (it_len read
       from bytes 2..3, refused only when >= caplen) puts "corp-wifi"
       in the PNL and reddens the three tally / PNL lines; the inverse
       edit restores green. */
    const uint8_t sa[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t whole[128], f[128];
    int wn = mon_probe_req(whole, sa, "corp-wifi", 0);
    f[0] = 0; f[1] = 0; f[2] = 4; f[3] = 0;   /* it_len 4 */
    memcpy(f + 4, whole + RT_HDR, (size_t)(wn - RT_HDR));
    const int n = 4 + wn - RT_HDR;
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    uint64_t b   = mon_before();
    uint64_t rtb = sh_parse_fault_count(SH_PF_RADIOTAP_BAD);
    uint64_t fe0 = sh_parse_fault_count(SH_PF_FRAME_EDGE);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(probe_pnl_ssid_count(sa), 0);
    ASSERT_EQ(mon_delta(b), 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_RADIOTAP_BAD) - rtb), 1);
    /* The record header itself was sound: not an edge fault. */
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 0);

    /* Control: the same probe request behind a real 8-octet header is
       admitted, so the zero above is the gate and not the harness. */
    const uint8_t *fs2[1] = { whole };
    int ls2[1] = { wn };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs2, ls2, NULL, NULL, 1), 1);
    ASSERT_EQ(probe_pnl_ssid_count(sa), 1);
    probe_pnl_clear();
}

static void test_a_caplen_above_origlen_is_refused_before_decode(void) {
    /* A record claiming one octet more was captured than was on the
       wire. No kernel produces it; a crafted savefile can. Before #141
       both callbacks read hdr->len only for the FCS-strip decision and
       the ring, and took the frame regardless.

       Driven through capture_test_decode_frame(), not the dispatch
       seams, and that is a limit worth stating: the savefile both
       dispatch seams build goes through pcap_fmt_rec_hdr(), which
       clamps origlen up to caplen so a bad record cannot misparse the
       ones after it (src/pcap_format.c). So the dispatch seams cannot
       express this case. The decode seam takes the same
       frame_view_init() call on_packet() makes, with no writer between.
       That on_packet() and on_probe_frame() stand behind the gate at
       all is proven by the snaplen case below, through both.

       Mutation-proved: deleting the `caplen > origlen` refusal from
       frame_view_init() decodes the frame and reddens the first
       assertion; the inverse edit restores green. */
    uint8_t e[128];
    int en = eth_ipv4_tcp(e, 8, 5, -1);
    packet_info_t pkt;
    ASSERT_EQ(capture_test_decode_frame(e, en, en - 1, DLT_EN10MB, &pkt), 0);
    ASSERT_STR(pkt.src, "");
    /* Control: the same bytes with an honest origlen decode. */
    ASSERT_EQ(capture_test_decode_frame(e, en, en, DLT_EN10MB, &pkt), 1);
    ASSERT_STR(pkt.src, "192.168.1.10");
}

static void test_a_caplen_past_the_snaplen_is_refused_at_both_edges(void) {
    /* 65536 octets: one past the snaplen both handles open with. The
       savefile the seams build advertises 262144, so libpcap delivers
       it — the edge is what has to say no. 65535 is the control, on
       both streams.

       Mutation-proved: deleting the FRAME_CAPLEN_MAX refusal from
       frame_view_init() admits both 65536-octet frames and reddens the
       pkt_total, mon_delta and tally lines; the inverse edit restores
       green. */
    enum { BIG = FRAME_CAPLEN_MAX + 1 };
    uint8_t *f = calloc(1, BIG);
    ASSERT(f != NULL);
    if (!f) return;
    uint64_t fe0 = sh_parse_fault_count(SH_PF_FRAME_EDGE);

    /* The IP stream: on_packet(). */
    eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { BIG };
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, NULL, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 1);

    ls[0] = FRAME_CAPLEN_MAX;
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, NULL, 1), 1);
    ASSERT_EQ((long long)g_s.pkt_total, 1);
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 1);

    /* The monitor stream: on_probe_frame(). A beacon header padded out
       with zeros to the full length. */
    mon_frame(f, BIG - RT_HDR, 0x80);
    ls[0] = BIG;
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    uint64_t b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b), 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 2);

    ls[0] = FRAME_CAPLEN_MAX;
    b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_FRAME_EDGE) - fe0), 2);
    free(f);
}

static void evidence_setup(void);   /* with the #92 evidence cases below */

static void test_bad_fcs_frames_still_feed_rf_quality_and_evidence(void) {
    /* Policy pinned, not changed. A frame the driver marked FCS-failed
       is untrustworthy content but real evidence about the channel, so
       it still reaches rf_quality_observe() and the evidence ring. It
       is also still parsed: whether a bad-FCS frame should feed the
       per-type parsers at all is a deferred decision (#123), and this
       test does not claim one either way. */
    evidence_setup();
    rf_quality_clear();
    uint8_t f[160];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_FCS | RT_F_BADFCS;
    rt.has_channel = 1; rt.freq_mhz = 2437;          /* channel 6 */
    fb_radiotap(&b, &rt);
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    fb_mgmt(&b, 4, 0, bc, RT_STA, bc, 0x0020, 0);    /* probe request */
    fb_ssid(&b, "rt-test-net");
    fb_fcs(&b);
    ASSERT(fb_ok(&b));

    enum { N = RF_MIN_FRAMES };
    const uint8_t *fs[N]; int ls[N]; uint32_t ts[N];
    for (int i = 0; i < N; i++) { fs[i] = f; ls[i] = b.len; ts[i] = 1600000000u; }
    uint64_t m0 = mon_before();
    uint64_t e0 = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, N), N);
    ASSERT_EQ(mon_delta(m0), N);
    ASSERT_EQ((long long)(evidence_ring_last_id() - e0), N);
    ASSERT_EQ(rf_quality_badfcs_pct(6, (time_t)1600000000), 100);
    rf_quality_clear();
    evidence_ring_shutdown();
}

static void test_monitor_seam_rejects_frames_below_the_guards(void) {
    /* The four reject paths in on_probe_frame(), each on its own.
       Every one of these is a frame an attacker can put on the air. */
    uint8_t f[128];
    int full = mon_frame(f, 24, 0x80);
    (void)full;

    /* (a) shorter than 8 bytes: no radiotap length to read. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    const uint8_t *fs1[1] = { f };
    int ls1[1] = { 7 };
    uint64_t b1 = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs1, ls1, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b1), 0);

    /* (b) radiotap it_len claiming the frame or more, so there is no
           802.11 left to read. Both an exact-length and an oversized
           claim are refused.

           Stated precisely: the private `rt_len >= len` check this
           case was written against is gone (#123); radiotap_parse()
           is the gate now, and it ACCEPTS it_len == caplen — a header
           with nothing after it is well-formed radiotap. The
           exact-length frame is refused by the `dot11_len < 10` runt
           guard instead, and is not counted as a radiotap reject. The
           oversized claim is the parser's refusal. What this case pins
           is that both are refused at all. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    uint8_t lying[128];
    int ln = mon_frame(lying, 24, 0x80);
    lying[2] = (uint8_t)ln;                 /* it_len == caplen */
    const uint8_t *fs2[1] = { lying };
    int ls2[1] = { ln };
    uint64_t b2 = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs2, ls2, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b2), 0);

    /* it_len far beyond caplen: the overread an attacker would aim for. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    uint8_t over[128];
    int on = mon_frame(over, 24, 0x80);
    over[2] = 200;                          /* it_len >> caplen */
    const uint8_t *fs2b[1] = { over };
    int ls2b[1] = { on };
    uint64_t b2b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs2b, ls2b, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b2b), 0);

    /* (c) 802.11 shorter than 10 bytes: not enough for FC + duration +
           addr1, which is the smallest real control frame. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    uint8_t runt[64];
    int rn = mon_frame(runt, 9, 0x80);
    const uint8_t *fs3[1] = { runt };
    int ls3[1] = { rn };
    uint64_t b3 = mon_before();
    uint64_t runt0 = sh_parse_fault_count(SH_PF_DOT11_RUNT);
    uint64_t rtb0  = sh_parse_fault_count(SH_PF_RADIOTAP_BAD);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs3, ls3, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b3), 0);
    /* Counted as a runt, not as a radiotap fault: the header was fine
       (#126). Mutation-proved by deleting the DOT11_RUNT note. */
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_DOT11_RUNT) - runt0), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_RADIOTAP_BAD) - rtb0), 0);

    /* (d) zero-length frame. */
    memset(&g_s, 0, sizeof(g_s)); probe_clear();
    const uint8_t *fs4[1] = { f };
    int ls4[1] = { 0 };
    uint64_t b4 = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs4, ls4, NULL, NULL, 1), 1);
    ASSERT_EQ(mon_delta(b4), 0);
}

static void test_monitor_seam_mixes_admitted_and_rejected(void) {
    /* Interleaved in one dispatch: the count must follow the guards and
       a rejected frame must not stop the ones behind it. */
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t good[128], runt[64];
    int gn = mon_frame(good, 24, 0x80);
    int rn = mon_frame(runt, 9, 0x80);
    const uint8_t *fs[4] = { good, runt, good, runt };
    int ls[4] = { gn, rn, gn, rn };
    uint64_t b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 4), 4);
    ASSERT_EQ(mon_delta(b), 2);
}

static void test_monitor_seam_carries_per_frame_timestamps(void) {
    /* The seam's reason for taking ts_secs. It does not assert which
       clock a record used — that is #92's open defect and this slice
       does not fix it — only that the savefile really carries the
       timestamps a caller asked for, so a later fix can be pinned
       through here. Proven by the frames arriving at all with
       deliberately far-apart stamps. */
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[2] = { f, f };
    int ls[2] = { n, n };
    uint32_t ts[2] = { 1000000000u, 1700000000u };
    uint64_t b = mon_before();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 2), 2);
    ASSERT_EQ(mon_delta(b), 2);
}

static void test_monitor_seam_rejects_bad_arguments(void) {
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(probe_test_dispatch(NULL, fs, ls, NULL, NULL, 1), -1);
    ASSERT_EQ(probe_test_dispatch(&g_s, NULL, ls, NULL, NULL, 1), -1);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, NULL, NULL, NULL, 1), -1);
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, -1), -1);
    int bad[1] = { -5 };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, bad, NULL, NULL, 1), -1);
}

/* ── One frame, one clock — issue #92 ────────────────────────
 *
 * Nine call sites in on_probe_frame() read time(NULL) while
 * eapol_observe_dot11() alone took the frame's own capture timestamp,
 * so one frame could be stamped two different seconds depending on
 * scheduling and a correlation window built from those stamps was not
 * reproducible from the capture. All nine now take the frame clock.
 *
 * Pinning that needs two kinds of assertion, and the first attempt at
 * this slice shipped only the weaker one — which is why 6 of its 10
 * threaded sites could be reverted to time(NULL) with the suite still
 * green:
 *
 *   1. BEHAVIOURAL, below: the frame ring's ts is observable through
 *      mon_frame_snapshot(), so a dispatched frame must carry the
 *      timestamp the caller gave it. That pins one site exactly.
 *   2. SOURCE-LEVEL, test_probe_callback_has_no_wall_clock_read: most
 *      of the other eight feed windows and thresholds inside their own
 *      modules and expose no timestamp an assertion here can read, so
 *      no behavioural test can pin them. What CAN be pinned is that the
 *      callback does not read the wall clock at all — which is the
 *      property the slice is actually about, and it fails if ANY of the
 *      nine is reverted. The repo already asserts source properties
 *      this way (tests/test_docs_consistency.c, tests/test_ci_pins.c).
 *
 * Together those two cover all nine. Neither alone does, and saying so
 * is the difference between this slice and the one that was blocked. */

static void test_frame_records_carry_the_capture_timestamp(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[2] = { f, f };
    int ls[2] = { n, n };
    /* Deliberately far apart, and far from any plausible "now", so a
       time(NULL) regression cannot coincidentally match. */
    uint32_t ts[2] = { 1000000000u, 1500000000u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 2), 2);

    mon_frame_snapshot(&g_s);
    ASSERT_GE(g_s.mon_frame_count, 2);
    /* Newest first, so the second frame's stamp leads. */
    ASSERT_EQ((long long)g_s.mon_frames[0].ts, 1500000000LL);
    ASSERT_EQ((long long)g_s.mon_frames[1].ts, 1000000000LL);
}

static void test_a_zero_capture_clock_is_counted_not_substituted(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint32_t ts[1] = { 0 };
    uint64_t bad_before = mon_bad_clock_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);
    /* Counted... */
    ASSERT_EQ((long long)(mon_bad_clock_total() - bad_before), 1);
    /* ...and NOT replaced by the wall clock. The record keeps the 0 the
       capture gave it, because substituting would reintroduce exactly
       the non-reproducibility this slice removes. */
    mon_frame_snapshot(&g_s);
    ASSERT_GE(g_s.mon_frame_count, 1);
    ASSERT_EQ((long long)g_s.mon_frames[0].ts, 0LL);
}

static void test_a_good_capture_clock_is_not_counted(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint32_t ts[1] = { 1700000000u };
    uint64_t bad_before = mon_bad_clock_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);
    ASSERT_EQ((long long)(mon_bad_clock_total() - bad_before), 0);
}

/* ── Evidence ring, through the real callback — issue #92 ─────
 *
 * tests/test_evidence_ring.c pins the ring as a data structure. These
 * pin the thing that structure exists for: that on_probe_frame() puts
 * real captured bytes into it, with the capture's own clock and lengths,
 * and that what comes back out by event ID is the frame that went in.
 *
 * Frames are the same hand-built radiotap + 802.11 arrays as above.
 * Carrying a recognisable payload is what makes "the bytes survived"
 * assertable rather than assumed — mon_frame() alone writes mostly
 * zeroes, which would compare equal to an empty arena.
 */

/* mon_frame() with a payload pattern seeded from `tag`, so a retrieved
   record can be shown to be this frame and not its neighbour. */
static int mon_frame_tagged(uint8_t *f, int dot11_len, uint8_t fc0,
                            uint8_t tag) {
    int n = mon_frame(f, dot11_len, fc0);
    for (int i = RT_HDR + 10; i < n; i++) f[i] = (uint8_t)(tag + i);
    return n;
}

static void evidence_setup(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    evidence_ring_shutdown();
    sh_evict_reset();
    ASSERT_EQ(evidence_ring_init(EVIDENCE_BUDGET_FLOOR), 0);
}

static void test_the_callback_retains_the_whole_frame_with_radiotap(void) {
    evidence_setup();
    static uint8_t f[900];
    int n = mon_frame_tagged(f, (int)sizeof(f) - RT_HDR, 0x80, 0x11);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint32_t ts[1] = { 1500000000u };
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);

    /* The callback really did store one record, and it is reachable by
       the ID the ring issued — no IP, no flow, no window. */
    uint64_t id = evidence_ring_last_id();
    ASSERT_EQ((long long)(id - before), 1);
    evidence_rec_t rec;
    static uint8_t out[1024];
    int got = evidence_ring_get(id, &rec, out, sizeof(out));
    ASSERT_EQ(got, n);
    ASSERT_EQ((long long)rec.cap_len,  n);
    ASSERT_EQ((long long)rec.orig_len, n);
    ASSERT_EQ(rec.truncated, 0);
    /* Byte-exact including the radiotap header — this is the fidelity
       the general ring's min(caplen, 64) cannot provide: at 64 bytes
       only 56 bytes of 802.11 would have survived. */
    ASSERT_EQ(memcmp(out, f, (size_t)n), 0);
    ASSERT_EQ(out[2], (uint8_t)RT_HDR);
    ASSERT_GT(got, 64);
    evidence_ring_shutdown();
}

static void test_retained_records_carry_the_capture_clock(void) {
    /* Two frames in one dispatch, stamps far apart and far from any
       plausible "now", so a time(NULL) regression in the retain path
       cannot coincidentally match. */
    evidence_setup();
    uint8_t a[128], b[128];
    int an = mon_frame_tagged(a, 64, 0x80, 0x21);
    int bn = mon_frame_tagged(b, 64, 0xC0, 0x31);
    const uint8_t *fs[2] = { a, b };
    int ls[2] = { an, bn };
    uint32_t ts[2] = { 1000000000u, 1500000000u };
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 2), 2);

    evidence_rec_t r1, r2;
    uint8_t out[256];
    ASSERT_EQ(evidence_ring_get(before + 1, &r1, out, sizeof(out)), an);
    ASSERT_EQ(memcmp(out, a, (size_t)an), 0);
    ASSERT_EQ(evidence_ring_get(before + 2, &r2, out, sizeof(out)), bn);
    ASSERT_EQ(memcmp(out, b, (size_t)bn), 0);
    ASSERT_EQ((long long)r1.ts_sec, 1000000000LL);
    ASSERT_EQ((long long)r2.ts_sec, 1500000000LL);
    evidence_ring_shutdown();
}

/* Radiotap + a complete 26-byte deauth (header + Reason Code), built
   per IEEE 802.11-2020 9.3.3.1 / 9.4.1.7. Addresses are explicit so the
   victim row this frame lands in can be named rather than guessed —
   on_probe_frame() keeps no index and other tests in this file push
   deauths through the same callback. */
#define DEAUTH_DOT11 26
static int mon_deauth(uint8_t *f, const uint8_t a1[6], const uint8_t a2[6],
                      const uint8_t a3[6], uint16_t seq, uint16_t reason) {
    int n = mon_frame(f, DEAUTH_DOT11, 0xC0);   /* type 0, subtype 12 */
    uint8_t *d = f + RT_HDR;
    d[1] = 0x00;                                 /* no Retry, no +HTC   */
    d[2] = 0x3a; d[3] = 0x01;                    /* Duration, any value */
    memcpy(d + 4,  a1, 6);
    memcpy(d + 10, a2, 6);
    memcpy(d + 16, a3, 6);
    uint16_t sc = (uint16_t)(seq << 4);          /* fragment 0 */
    d[22] = (uint8_t)(sc & 0xff);
    d[23] = (uint8_t)(sc >> 8);
    d[24] = (uint8_t)(reason & 0xff);
    d[25] = (uint8_t)(reason >> 8);
    return n;
}

/* The end-to-end claim of this slice: a frame the callback retained can
   be reached from the detector that saw it, with no IP and no flow in
   between. The ID the ring issued has to survive the parse, the record
   and the snapshot, and still resolve to these bytes. */
static void test_a_deauth_row_cites_the_frames_the_ring_kept(void) {
    evidence_setup();
    flood_test_set_clock(NULL, NULL);
    deauth_clear();

    static const uint8_t STA[6]   = {0x02,0x44,0x55,0x66,0x77,0x88};
    static const uint8_t BSSID[6] = {0x06,0xaa,0xbb,0xcc,0xdd,0xee};
    uint8_t a[64], b[64];
    int an = mon_deauth(a, STA, BSSID, BSSID, 11, 7);
    int bn = mon_deauth(b, STA, BSSID, BSSID, 12, 7);
    const uint8_t *fs[2] = { a, b };
    int ls[2] = { an, bn };
    uint32_t ts[2] = { 1700000000u, 1700000001u };
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 2), 2);

    /* deauth_record() writes deauth_snoop.c's statics; the state rows
       only exist once snapshot runs. */
    deauth_snapshot(&g_s);
    const deauth_victim_t *v = NULL;
    for (int i = 0; i < g_s.deauth_victim_count; i++)
        if (memcmp(g_s.deauth_victims[i].bssid,  BSSID, 6) == 0 &&
            memcmp(g_s.deauth_victims[i].victim, STA,   6) == 0)
            v = &g_s.deauth_victims[i];
    ASSERT(v != NULL);
    if (v) {
        ASSERT_EQ(v->frames, 2);
        ASSERT_EQ(v->evidence_id_count, 2);
        /* The IDs are the ones this dispatch issued, in order. */
        ASSERT_EQ((long long)v->evidence_ids[0], (long long)(before + 1));
        ASSERT_EQ((long long)v->evidence_ids[1], (long long)(before + 2));

        /* And they still resolve to the frames, byte for byte, radiotap
           included — which is what makes the citation evidence rather
           than a number. */
        evidence_rec_t r;
        static uint8_t out[128];
        ASSERT_EQ(evidence_ring_get(v->evidence_ids[0], &r, out, sizeof(out)), an);
        ASSERT_EQ((long long)r.cap_len, an);
        ASSERT_EQ(memcmp(out, a, (size_t)an), 0);
        ASSERT_EQ(evidence_ring_get(v->evidence_ids[1], &r, out, sizeof(out)), bn);
        ASSERT_EQ((long long)r.cap_len, bn);
        ASSERT_EQ(memcmp(out, b, (size_t)bn), 0);
    }
    deauth_clear();
    evidence_ring_shutdown();
}

/* With the ring down, evidence_ring_note() returns 0 and the detector
   must cite nothing. The frames are still counted — a missing evidence
   store is not a reason to stop detecting. */
static void test_a_deauth_row_cites_nothing_with_the_ring_down(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    evidence_ring_shutdown();
    sh_evict_reset();
    flood_test_set_clock(NULL, NULL);
    deauth_clear();

    static const uint8_t STA[6]   = {0x02,0x99,0x88,0x77,0x66,0x55};
    static const uint8_t BSSID[6] = {0x06,0x11,0x22,0x33,0x44,0x55};
    uint8_t a[64];
    int an = mon_deauth(a, STA, BSSID, BSSID, 21, 7);
    const uint8_t *fs[1] = { a };
    int ls[1] = { an };
    uint32_t ts[1] = { 1700000100u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);

    deauth_snapshot(&g_s);
    const deauth_victim_t *v = NULL;
    for (int i = 0; i < g_s.deauth_victim_count; i++)
        if (memcmp(g_s.deauth_victims[i].bssid,  BSSID, 6) == 0 &&
            memcmp(g_s.deauth_victims[i].victim, STA,   6) == 0)
            v = &g_s.deauth_victims[i];
    ASSERT(v != NULL);
    if (v) {
        ASSERT_EQ(v->frames, 1);
        ASSERT_EQ(v->evidence_id_count, 0);
    }
    deauth_clear();
}

static void test_a_kernel_snapped_frame_is_flagged_truncated(void) {
    /* caplen < len through the real reader: libpcap hands the callback
       the short buffer while the record header still reports the frame's
       length. Both lengths must reach the evidence record and the flag
       must be set — the case an analyst needs in order to know the
       reconstruction is partial. */
    evidence_setup();
    uint8_t f[256];
    int n = mon_frame_tagged(f, 128, 0x80, 0x41);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    int origs[1] = { n + 900 };
    uint32_t ts[1] = { 1500000000u };
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, origs, ts, 1), 1);

    evidence_rec_t rec;
    uint8_t out[512];
    int got = evidence_ring_get(before + 1, &rec, out, sizeof(out));
    ASSERT_EQ(got, n);
    ASSERT_EQ((long long)rec.cap_len,  n);
    ASSERT_EQ((long long)rec.orig_len, n + 900);
    ASSERT_EQ(rec.truncated, 1);
    evidence_ring_shutdown();
}

static void test_frames_refused_by_the_guards_are_not_retained(void) {
    /* The deliberate choice recorded in probe.c: the retain call sits
       behind the framing guards, so a runt an attacker sprays cannot
       flush the ring. Each of the guard cases, then a well-formed frame
       as the control that the retain path works at all in this run. */
    evidence_setup();
    uint8_t f[128], runt[64];
    int n  = mon_frame_tagged(f, 64, 0x80, 0x51);
    int rn = mon_frame_tagged(runt, 9, 0x80, 0x61);   /* dot11_len < 10 */
    const uint8_t *fs[3] = { runt, f, runt };
    int ls[3] = { rn, 7, rn };                        /* also a sub-8 caplen */
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 3), 3);
    ASSERT_EQ((long long)(evidence_ring_last_id() - before), 0);
    ASSERT_EQ(evidence_ring_count(), 0);

    const uint8_t *ok[1] = { f };
    int okl[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, ok, okl, NULL, NULL, 1), 1);
    ASSERT_EQ((long long)(evidence_ring_last_id() - before), 1);
    ASSERT_EQ(evidence_ring_count(), 1);
    evidence_ring_shutdown();
}

static void test_an_uninitialised_ring_does_not_stop_the_callback(void) {
    /* A run whose evidence ring failed to allocate must still detect:
       the retain call is a no-op and every other observer is unaffected. */
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    evidence_ring_shutdown();
    uint8_t f[128];
    int n = mon_frame_tagged(f, 64, 0x80, 0x71);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint32_t ts[1] = { 1500000000u };
    uint64_t mb = mon_frame_total();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);
    ASSERT_EQ((long long)(mon_frame_total() - mb), 1);   /* still observed */
    ASSERT_EQ(evidence_ring_count(), 0);
    mon_frame_snapshot(&g_s);
    ASSERT_GE(g_s.mon_frame_count, 1);
    ASSERT_EQ((long long)g_s.mon_frames[0].ts, 1500000000LL);
}

static void test_ring_pressure_from_the_callback_is_counted(void) {
    /* Eviction driven by real dispatched frames rather than by direct
       calls: a small ring, more frames than it holds, and the tally has
       to account for every record that went missing. */
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    evidence_ring_shutdown();
    sh_evict_reset();
    ASSERT_EQ(evidence_ring_init(EVIDENCE_MIN_BUDGET * 2), 0);

    static uint8_t f[1024];
    int n = mon_frame_tagged(f, (int)sizeof(f) - RT_HDR, 0x80, 0x81);
    const uint8_t *fs[32];
    int ls[32];
    for (int i = 0; i < 32; i++) { fs[i] = f; ls[i] = n; }
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 32), 32);

    int kept = evidence_ring_count();
    ASSERT_GT(kept, 0);
    ASSERT_LT(kept, 32);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_EVIDENCE_FRAME), 32 - kept);
    ASSERT(evidence_ring_bytes_used() <= evidence_ring_capacity());
    /* The newest frame survived and the oldest is gone — an evicted ID
       reads as absent, not as whatever now sits in its slot. */
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(before + 32, &rec, NULL, 0), 0);
    ASSERT_EQ(evidence_ring_get(before + 1, &rec, NULL, 0), -1);
    evidence_ring_shutdown();
}

/* The source-level half. Reads the callback's body and requires it to
 * contain no wall-clock read — the one assertion that covers all nine
 * sites at once, including the eight whose observers expose no
 * timestamp. Bounded to on_probe_frame() so a time(NULL) elsewhere in
 * the file (the capture thread's own bookkeeping, legitimately wall
 * clock) does not trip it. */
static void test_probe_callback_has_no_wall_clock_read(void) {
    FILE *fp = fopen("src/capture/probe.c", "rb");
    ASSERT(fp != NULL);
    if (!fp) return;
    static char src[600000];
    size_t got = fread(src, 1, sizeof(src) - 1, fp);
    fclose(fp);
    src[got] = '\0';
    ASSERT(got > 1000);

    const char *start = strstr(src, "static void on_probe_frame(");
    ASSERT(start != NULL);
    if (!start) return;
    /* The callback ends at the next function at column 0 after it. */
    const char *end = strstr(start, "\n/* \xe2\x94\x80\xe2\x94\x80 Monitor dispatch test seam");
    if (!end) end = strstr(start, "\nstatic void probe_health");
    if (!end) end = src + got;
    ASSERT(end > start);

    /* Comments in that span mention time(NULL) when explaining why it is
       gone, so count only calls: "time(NULL)" not preceded by a '*' on
       the same line. Crude, and sufficient — a real call is never in a
       comment line. */
    int calls = 0;
    for (const char *q = start; q < end; ) {
        const char *hit = strstr(q, "time(NULL)");
        if (!hit || hit >= end) break;
        const char *bol = hit;
        while (bol > start && bol[-1] != '\n') bol--;
        int commented = 0;
        for (const char *x = bol; x < hit; x++)
            if (*x == '*' || (*x == '/' && x + 1 < hit && x[1] == '/')) {
                commented = 1; break;
            }
        if (!commented) calls++;
        q = hit + 1;
    }
    if (calls)
        fprintf(stderr, "    on_probe_frame() reads the wall clock %d "
                        "time(s); #92 requires the frame's own "
                        "timestamp\n", calls);
    ASSERT_EQ(calls, 0);
}

/* ── Probe-client eviction is counted — issue #91 ─────────────
 *
 * The probe-client table LRU-evicts in the capture thread and nothing
 * counted it, so a busy site silently dropped probing clients while
 * `evictions` reported full coverage of everything else. It now has an
 * `evict_probe_client` kind.
 *
 * These also pin a boundary fix made in the same change. record_probe()
 * used to read `if (g_count == MAX_PROBE_CLIENTS)` AFTER `g_count++`,
 * so the arrival that filled the last slot ran the eviction scan over
 * the slot it had just allocated. On a fresh table that slot is zeroed,
 * last_seen 0 made it the oldest, and the scan chose it back — which is
 * why the defect was invisible. It is not invisible once the table has
 * aged: probe_snapshot() compacts with `g_clients[i] = g_clients[--g_count]`,
 * leaving the vacated index holding a copy of a live entry, so the scan
 * could prefer an older LIVE slot, overwrite it, and leave the stale
 * copy inside g_count — an aged-out client resurrected as current with
 * someone else's row destroyed to make room.
 *
 * The decisive assertion is the first one: filling the table to exactly
 * MAX must count ZERO evictions. Against the old condition it counts
 * one, because the scan ran. */

/* A probe request (FC 0x40) with a settable source address. addr2 is at
   offset 10; 24 bytes is the minimum the parser walks (it reads the
   sequence control at 22-23 before looking for IEs). */
static int probe_req_frame(uint8_t *f, int ordinal) {
    const int dot11_len = 24;
    int total = mon_frame(f, dot11_len, 0x40);
    uint8_t *d = f + RT_HDR;
    d[10] = 0x02;                             /* locally administered */
    d[11] = 0x00;
    d[12] = 0x00;
    d[13] = (uint8_t)((ordinal >> 16) & 0xff);
    d[14] = (uint8_t)((ordinal >> 8) & 0xff);
    d[15] = (uint8_t)(ordinal & 0xff);
    return total;
}

/* Drive `n` distinct probing clients through the real callback. */
static void drive_probe_clients(int first, int n) {
    enum { CHUNK = 64 };
    static uint8_t bufs[CHUNK][64];
    const uint8_t *fs[CHUNK];
    int ls[CHUNK];
    int done = 0;
    while (done < n) {
        int batch = n - done < CHUNK ? n - done : CHUNK;
        for (int i = 0; i < batch; i++) {
            ls[i] = probe_req_frame(bufs[i], first + done + i);
            fs[i] = bufs[i];
        }
        ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, batch), batch);
        done += batch;
    }
}

static void test_filling_the_probe_table_counts_no_eviction(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    sh_evict_reset();
    /* Exactly MAX distinct clients: the table fills and nothing is lost. */
    drive_probe_clients(1, MAX_PROBE_CLIENTS);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_PROBE_CLIENT), 0);
}

static void test_one_client_past_the_table_is_counted(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    sh_evict_reset();
    drive_probe_clients(1, MAX_PROBE_CLIENTS + 1);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_PROBE_CLIENT), 1);
    /* And it lands in the total, which is what the health strip shows. */
    ASSERT(sh_evict_total() >= 1);
}

static void test_a_repeat_client_is_an_update_not_an_eviction(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    sh_evict_reset();
    drive_probe_clients(1, MAX_PROBE_CLIENTS);
    /* The same MACs again: every one matches an existing row, so the
       table neither grows nor evicts. A tally that counted these would
       report loss on a stable population. */
    drive_probe_clients(1, MAX_PROBE_CLIENTS);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_PROBE_CLIENT), 0);
}

static void test_each_further_client_counts_once(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    sh_evict_reset();
    drive_probe_clients(1, MAX_PROBE_CLIENTS + 10);
    /* Ten past the cap, ten evictions — not nine, and not one per
       dispatch batch. */
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_PROBE_CLIENT), 10);
}

/* ── Per-stream freshness — issue #91 ────────────────────────
 *
 * "Healthy with no detections" and "not observing" were
 * indistinguishable to a consumer, which is the problem #91 was filed
 * about. These pin the two fields that separate them, through both
 * dispatch seams.
 *
 * The design decision under test is the two clocks. last_frame_ts is
 * the frame's OWN capture timestamp; stale_secs is measured on the host
 * clock. Deriving age from the frame clock would report a dead stream
 * for a healthy one replaying an old capture — so a frame stamped in
 * 2001 must still read as FRESH when it has just arrived, and that is
 * the assertion that would fail if someone "simplified" the two fields
 * into one. */

static time_t g_fake_wall = 1000;
static time_t fake_wall(void)      { return g_fake_wall; }
static uint64_t fake_mono(void)    { return (uint64_t)g_fake_wall * 1000u; }

static void test_monitor_freshness_starts_as_never(void) {
    flood_test_set_clock(fake_mono, fake_wall);
    g_fake_wall = 1000;
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    probe_test_reset_freshness();   /* earlier cases have delivered frames */
    capture_health_t h;
    memset(&h, 0, sizeof(h));
    probe_health_poll(&h);
    /* -1, not 0: a stream that has never delivered must not read as
       having delivered this instant. */
    ASSERT_EQ(h.stale_secs, -1);
    ASSERT_EQ((long long)h.last_frame_ts, 0);
    flood_test_set_clock(NULL, NULL);
}

static void test_monitor_freshness_follows_two_clocks(void) {
    flood_test_set_clock(fake_mono, fake_wall);
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();

    /* A frame whose capture clock is ancient, arriving right now. */
    g_fake_wall = 5000;
    uint8_t f[128];
    int n = mon_frame(f, 24, 0x80);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    uint32_t ts[1] = { 1000000000u };          /* 2001 */
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);

    capture_health_t h;
    memset(&h, 0, sizeof(h));
    probe_health_poll(&h);
    /* The frame's own clock is reported as-is... */
    ASSERT_EQ((long long)h.last_frame_ts, 1000000000LL);
    /* ...and it is FRESH, because it arrived now. This is the whole
       point of keeping the clocks apart: age from the frame clock would
       make this ~25 years stale. */
    ASSERT_EQ(h.stale_secs, 0);

    /* Host clock advances, no new frames: the stream goes stale while
       last_frame_ts does not move. */
    g_fake_wall = 5090;
    memset(&h, 0, sizeof(h));
    probe_health_poll(&h);
    ASSERT_EQ(h.stale_secs, 90);
    ASSERT_EQ((long long)h.last_frame_ts, 1000000000LL);
    flood_test_set_clock(NULL, NULL);
}

static void test_a_refused_frame_does_not_refresh_the_stream(void) {
    /* A runt the callback drops is not evidence the radio is delivering
       anything usable, so it must not reset the clock. */
    flood_test_set_clock(fake_mono, fake_wall);
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();

    g_fake_wall = 7000;
    uint8_t good[128];
    int gn = mon_frame(good, 24, 0x80);
    const uint8_t *fg[1] = { good };
    int lg[1] = { gn };
    uint32_t tg[1] = { 1700000000u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fg, lg, NULL, tg, 1), 1);

    g_fake_wall = 7100;
    uint8_t runt[64];
    int rn = mon_frame(runt, 9, 0x80);         /* below the framing guard */
    const uint8_t *fr[1] = { runt };
    int lr[1] = { rn };
    uint32_t tr[1] = { 1700000500u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fr, lr, NULL, tr, 1), 1);

    capture_health_t h;
    memset(&h, 0, sizeof(h));
    probe_health_poll(&h);
    /* Still the GOOD frame's clock, and 100s stale — the runt neither
       refreshed the stream nor overwrote the timestamp. */
    ASSERT_EQ((long long)h.last_frame_ts, 1700000000LL);
    ASSERT_EQ(h.stale_secs, 100);
    flood_test_set_clock(NULL, NULL);
}

static void test_capture_stream_freshness(void) {
    /* The IP stream, through its own seam. */
    flood_test_set_clock(fake_mono, fake_wall);
    g_fake_wall = 9000;
    memset(&g_s, 0, sizeof(g_s));
    capture_test_set_policy(NULL);
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, NULL, 1), 1);

    capture_health_t h;
    memset(&h, 0, sizeof(h));
    capture_health_poll(&h);
    /* capture_test_dispatch stamps synthetic timestamps from
       1700000000, so the first frame carries exactly that. */
    ASSERT_EQ((long long)h.last_frame_ts, 1700000000LL);
    ASSERT_EQ(h.stale_secs, 0);

    g_fake_wall = 9045;
    memset(&h, 0, sizeof(h));
    capture_health_poll(&h);
    ASSERT_EQ(h.stale_secs, 45);
    flood_test_set_clock(NULL, NULL);
}

/* ── Probe-table invariants — issue #91 ──────────────────────
 *
 * These are invariants over the table's state rather than assertions
 * about a feature, and they exist because the feature-shaped tests did
 * not find the bug that prompted them.
 *
 * The fill-boundary defect fixed alongside the eviction tally could
 * resurrect an aged-out client: probe_snapshot() compacts with
 * `g_clients[i] = g_clients[--g_count]`, so the vacated index keeps a
 * COPY of a live row, and the old eviction scan could then leave that
 * copy inside g_count. Because the stale row is a copy, the symptom is
 * a DUPLICATE MAC — which no test looked for, and which a single
 * invariant catches head-on for this and any other slot-reuse bug in
 * this table.
 *
 * Honest about the limit: a duplicate check alone would not have caught
 * the other half of that defect, a live row silently overwritten. So
 * the live count is asserted too. */

/* No MAC may appear twice in the snapshot. */
static int snapshot_has_duplicate_mac(const sloth_state_t *st) {
    for (int i = 0; i < st->probe_count; i++)
        for (int j = i + 1; j < st->probe_count; j++)
            if (memcmp(st->probe_clients[i].mac,
                       st->probe_clients[j].mac, 6) == 0)
                return 1;
    return 0;
}

static void test_probe_table_holds_no_duplicate_after_ageing(void) {
    /* The scenario matters, and my first attempt at it did not trigger
     * the bug: for the defect to bite, the slot the append allocates
     * must already hold stale data whose last_seen is NEWER than some
     * live row. A table that merely grew into fresh zeroed slots picks
     * that slot back (last_seen 0 is the oldest) and behaves.
     *
     * The shape that triggers it: fill to MAX, age out exactly ONE old
     * row so compaction copies the LAST (recent) row into its place and
     * leaves that recent copy sitting at index g_count, then add one
     * client. The append allocates that index, the scan sees its recent
     * timestamp, prefers an older LIVE row instead, overwrites it — and
     * the stale copy stays inside g_count as a duplicate. */
    flood_test_set_clock(fake_mono, fake_wall);
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    sh_evict_reset();

    /* Timings chosen so the bug can actually bite, which took three
     * attempts to get right and is worth recording:
     *
     *   - one lone early client, old enough to age out;
     *   - the survivors STAGGERED, because the scan compares with `<`.
     *     If every survivor shares one timestamp, nothing is strictly
     *     older than the stale copy and the scan picks the allocated
     *     slot back — the bug hides. My first two scenarios failed for
     *     exactly that reason and passed under the pre-fix code.
     *   - the copy left above g_count comes from the LAST row, so the
     *     survivors must be staggered with the newest last.
     *
     * Then the next append lands on that index, sees a recent
     * timestamp, prefers an older live row, and destroys it. */
    const time_t T0    = 100000;
    const time_t TSNAP = T0 + 200;

    /* The lone ager. */
    g_fake_wall = T0;
    drive_probe_clients(1, 1);

    /* Survivors, oldest group first, all inside PROBE_AGE_SECS of the
       snapshot so none of them ages out. */
    const int groups = 4, per = (MAX_PROBE_CLIENTS - 1) / groups;
    int placed = 0;
    for (int gi = 0; gi < groups; gi++) {
        int n = (gi == groups - 1) ? (MAX_PROBE_CLIENTS - 1 - placed) : per;
        g_fake_wall = TSNAP - 100 + gi * 20;      /* -100, -80, -60, -40 */
        drive_probe_clients(100 + placed, n);
        placed += n;
    }

    g_fake_wall = TSNAP;
    probe_snapshot(&g_s);
    ASSERT_EQ(g_s.probe_count, MAX_PROBE_CLIENTS - 1);
    ASSERT_EQ(snapshot_has_duplicate_mac(&g_s), 0);

    /* One more client: the append takes the slot holding the recent
       stale copy. */
    g_fake_wall = TSNAP + 10;
    drive_probe_clients(9000, 1);
    probe_snapshot(&g_s);

    /* The invariant. Under the pre-fix condition the stale copy stays
       live and a real row is destroyed to make room for the newcomer. */
    ASSERT_EQ(snapshot_has_duplicate_mac(&g_s), 0);
    ASSERT_EQ(g_s.probe_count, MAX_PROBE_CLIENTS);
    flood_test_set_clock(NULL, NULL);
}

static void test_probe_table_never_exceeds_its_cap(void) {
    /* The other half: a live row must not be lost to a slot that should
       have been free, and the table must not report more rows than it
       can hold. */
    flood_test_set_clock(fake_mono, fake_wall);
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    g_fake_wall = 200000;
    drive_probe_clients(1, MAX_PROBE_CLIENTS * 2);
    probe_snapshot(&g_s);
    ASSERT_EQ(g_s.probe_count, MAX_PROBE_CLIENTS);
    ASSERT_EQ(snapshot_has_duplicate_mac(&g_s), 0);
    flood_test_set_clock(NULL, NULL);
}


/* -- Queued-frame release wiring -- #107 shape B --------------
 *
 * queue_evict's own unit tests (tests/test_queue_evict.c) take the
 * session-change addresses directly. What they cannot reach is the code
 * in on_probe_frame() that *supplies* those addresses: the status==0
 * gate on a (re)association response, and which of addr1/addr2 is the
 * station on a disassoc/deauth, which differs by direction. Those are
 * exactly the places a wiring bug hides silently -- a detector wired to
 * the wrong address field never fires and nothing goes red.
 *
 * capture_test_savefile() stamps frame i at ts_usec == i * 1000, so
 * passing one ts_secs value for every frame puts them 1 ms apart,
 * inside QUEUE_EVICT_WINDOW_MS. */

static const uint8_t QE_BSSID[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x77 };
static const uint8_t QE_STA[6]   = { 0x02, 0xE7, 0x00, 0x00, 0x00, 0x07 };

/* radiotap + a management frame, addr1/addr2/addr3 set explicitly.
 * IEEE 802.11-2020 Sec 9.3.3.1: addr1=DA addr2=SA addr3=BSSID. */
static int qe_mgmt(uint8_t *f, uint8_t fc0, const uint8_t a1[6],
                   const uint8_t a2[6], const uint8_t a3[6], int dot11_len) {
    const int total = RT_HDR + dot11_len;
    memset(f, 0, (size_t)total);
    f[2] = (uint8_t)RT_HDR;
    uint8_t *d = f + RT_HDR;
    d[0] = fc0;
    memcpy(d + 4, a1, 6);
    memcpy(d + 10, a2, 6);
    memcpy(d + 16, a3, 6);
    return total;
}

/* Reassociation response (subtype 3), status `status`, one SSID element.
 * Fixed body is caps(2) + status(2) + aid(2) at offset 24 (Sec 9.3.3.7). */
static int qe_reassoc_resp(uint8_t *f, uint16_t status) {
    int n = qe_mgmt(f, 0x30, QE_STA, QE_BSSID, QE_BSSID, 36);
    uint8_t *d = f + RT_HDR;
    d[26] = (uint8_t)(status & 0xff);
    d[27] = (uint8_t)(status >> 8);
    d[30] = 0;                     /* SSID element */
    d[31] = 4;
    memcpy(d + 32, "qevt", 4);
    return n;
}

/* radiotap + AP->STA QoS data frame (FromDS), addr1=DA addr2=BSSID
 * addr3=SA (Sec 9.3.2.1 Table 9-26). */
static int qe_downlink_seq(uint8_t *f, int seq) {
    const int dot11_len = 26, total = RT_HDR + dot11_len;
    memset(f, 0, (size_t)total);
    f[2] = (uint8_t)RT_HDR;
    uint8_t *d = f + RT_HDR;
    d[0] = (uint8_t)((0x8 << 4) | (2 << 2));
    d[1] = 0x02;                   /* FromDS */
    memcpy(d + 4, QE_STA, 6);
    memcpy(d + 10, QE_BSSID, 6);
    memcpy(d + 16, QE_BSSID, 6);
    /* Sequence Control (Sec 9.2.4.4): the 12-bit sequence number sits in
     * the high bits. A parameter because the release threshold counts
     * DISTINCT frames — four memcpy'd copies of one frame are one MSDU
     * retried, which is what this test used to feed and is exactly the
     * ordinary-retransmission case the threshold must not accept. */
    d[22] = (uint8_t)((seq & 0x0f) << 4);
    d[23] = (uint8_t)((seq >> 4) & 0xff);
    return total;
}

static int qe_downlink(uint8_t *f) { return qe_downlink_seq(f, 0); }

static void test_a_granted_reassoc_plus_a_burst_records_a_release(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    queue_evict_clear();

    uint8_t r[128], d0[128], d1[128], d2[128], d3[128];
    int rn = qe_reassoc_resp(r, 0);
    /* Four DISTINCT frames, not four copies of one. */
    int dn = qe_downlink_seq(d0, 10);
    qe_downlink_seq(d1, 11);
    qe_downlink_seq(d2, 12);
    qe_downlink_seq(d3, 13);
    const uint8_t *fs[5] = { r, d0, d1, d2, d3 };
    int ls[5] = { rn, dn, dn, dn, dn };
    const uint32_t ts[5] = { 1700000000u, 1700000000u, 1700000000u,
                             1700000000u, 1700000000u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 5), 5);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(QE_BSSID, QE_STA, &e), 1);
    ASSERT_EQ(e.event_src, QUEUE_EVICT_SRC_REASSOC);
    ASSERT_EQ((int)e.burst_frames, 4);
    ASSERT_EQ((int)e.release_count, 1);
    queue_evict_clear();
}

/* The ordinary-retransmission case, through the REAL pcap_dispatch
 * callback rather than by calling the module directly. One MSDU the AP
 * keeps retrying must not reach the release threshold, because on a
 * lossy link that is routine and not a queued-frame release. */
static void test_a_retried_downlink_burst_records_no_release(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    queue_evict_clear();

    uint8_t r[128], d0[128], d1[128], d2[128], d3[128];
    int rn = qe_reassoc_resp(r, 0);
    /* Same sequence number throughout, Retry bit set — one frame. */
    int dn = qe_downlink_seq(d0, 20);
    d0[RT_HDR + 1] |= 0x08;
    memcpy(d1, d0, (size_t)dn);
    memcpy(d2, d0, (size_t)dn);
    memcpy(d3, d0, (size_t)dn);
    const uint8_t *fs[5] = { r, d0, d1, d2, d3 };
    int ls[5] = { rn, dn, dn, dn, dn };
    const uint32_t ts[5] = { 1700000000u, 1700000000u, 1700000000u,
                             1700000000u, 1700000000u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 5), 5);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(QE_BSSID, QE_STA, &e), 1);
    /* The window opened — the reassociation was granted — but nothing
       distinct arrived in it. */
    ASSERT_EQ(e.event_src, QUEUE_EVICT_SRC_REASSOC);
    ASSERT_EQ((int)e.burst_frames, 0);
    ASSERT_EQ((int)e.release_count, 0);
    queue_evict_clear();
}

static void test_a_refused_reassoc_opens_no_window(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    queue_evict_clear();

    /* Status 1 (unspecified failure): the station did not join, so the
     * AP has no session to release a queue across. The branch feeding
     * queue_evict is gated on the same status==0 evidence
     * assoc_observe() and frag_note_association() use. */
    uint8_t r[128], d0[128];
    int rn = qe_reassoc_resp(r, 1);
    int dn = qe_downlink(d0);
    const uint8_t *fs[5] = { r, d0, d0, d0, d0 };
    int ls[5] = { rn, dn, dn, dn, dn };
    const uint32_t ts[5] = { 1700000100u, 1700000100u, 1700000100u,
                             1700000100u, 1700000100u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 5), 5);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(QE_BSSID, QE_STA, &e), 0);
    ASSERT_EQ(queue_evict_count(), 0);
    queue_evict_clear();
}

static void test_a_deauth_attributes_the_station_in_both_directions(void) {
    /* AP -> STA deauth: addr1 is the station. */
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    queue_evict_clear();
    uint8_t m[128];
    int mn = qe_mgmt(m, 0xC0, QE_STA, QE_BSSID, QE_BSSID, 26);
    const uint8_t *fs1[1] = { m };
    int ls1[1] = { mn };
    const uint32_t ts1[1] = { 1700000200u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs1, ls1, NULL, ts1, 1), 1);
    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(QE_BSSID, QE_STA, &e), 1);
    ASSERT_EQ(e.event_src, QUEUE_EVICT_SRC_DISCONNECT);
    ASSERT_EQ(queue_evict_count(), 1);

    /* STA -> AP deauth: addr1 is the BSSID and addr2 is the station.
     * Reading addr1 unconditionally would make a second row keyed on
     * the AP's own address. */
    queue_evict_clear();
    mn = qe_mgmt(m, 0xC0, QE_BSSID, QE_STA, QE_BSSID, 26);
    const uint8_t *fs2[1] = { m };
    int ls2[1] = { mn };
    const uint32_t ts2[1] = { 1700000300u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs2, ls2, NULL, ts2, 1), 1);
    ASSERT_EQ(queue_evict_lookup(QE_BSSID, QE_STA, &e), 1);
    ASSERT_EQ(queue_evict_count(), 1);
    queue_evict_clear();
}

static void test_a_broadcast_deauth_opens_no_window(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    queue_evict_clear();
    static const uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    uint8_t m[128];
    int mn = qe_mgmt(m, 0xC0, bcast, QE_BSSID, QE_BSSID, 26);
    const uint8_t *fs[1] = { m };
    int ls[1] = { mn };
    const uint32_t ts[1] = { 1700000400u };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, ts, 1), 1);
    /* It names no station; one ff:ff:ff:ff:ff:ff row would collect
     * every station's downlink traffic on this BSS. */
    ASSERT_EQ(queue_evict_count(), 0);
    queue_evict_clear();
}


/* ── #111: the wired packet ring is a snapshot ───────────────────── */

/* Head / count / total keep their pre-#111 meanings through the copy:
 * bandwidth.c's cursor arithmetic and the once-only JSONL emit read
 * them off s->packets exactly as before. Pinned here single-threaded,
 * including the wrap, because the concurrent test below can only say
 * the copy is coherent, not that it is the same ring. */
static void test_ring_wraps_with_head_count_total_preserved(void) {
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[MAX_PACKETS + 44];
    int ls[MAX_PACKETS + 44];
    for (int i = 0; i < MAX_PACKETS + 44; i++) { fs[i] = f; ls[i] = n; }

    /* Two dispatches on one state continue the same ring. */
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, 1), 1);
    ASSERT_EQ(capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, NULL, 1), 1);
    ASSERT_EQ(g_s.pkt_count, 2);
    ASSERT_EQ(g_s.pkt_head, 2);
    ASSERT_EQ((long long)g_s.pkt_total, 2);

    /* 300 frames into a 256-slot ring: count saturates, head wraps to
     * 44, total keeps counting, and the oldest surviving frame is the
     * 45th (synthetic clock 1700000000 + 44). */
    ASSERT_EQ(drive(DLT_EN10MB, fs, ls, MAX_PACKETS + 44), MAX_PACKETS + 44);
    ASSERT_EQ(g_s.pkt_count, MAX_PACKETS);
    ASSERT_EQ(g_s.pkt_head, 44);
    ASSERT_EQ((long long)g_s.pkt_total, MAX_PACKETS + 44);
    ASSERT_EQ(g_s.packets[44].ts_sec, 1700000000u + 44);
    ASSERT_EQ(g_s.packets[43].ts_sec, 1700000000u + MAX_PACKETS + 43);

    /* The snapshot into a second state is the same ring. */
    sloth_state_t *m = calloc(1, sizeof(*m));
    ASSERT(m != NULL);
    if (!m) return;
    capture_ring_snapshot(m);
    ASSERT_EQ(m->pkt_count, g_s.pkt_count);
    ASSERT_EQ(m->pkt_head,  g_s.pkt_head);
    ASSERT_EQ((long long)m->pkt_total, (long long)g_s.pkt_total);
    ASSERT_EQ(memcmp(m->packets, g_s.packets, sizeof(m->packets)), 0);
    free(m);
    capture_ring_snapshot(NULL);               /* harmless */
}

/* on_packet() writes the ring on the capture thread; main reads it
 * through capture_ring_snapshot() once per poll. Before #111 the reads
 * went straight to s->packets with no lock on either side.
 *
 * Each dispatch is one "call": RING_RACE_PER_CALL copies of one frame
 * whose TCP source port names the call, with the seam's synthetic
 * clock numbering the frames inside it (1700000000 + i). Every slot
 * therefore has a position in one total order, which is what lets a
 * torn copy be recognised from the copy alone: oldest to newest, the
 * port never decreases, the clock steps by one inside a call and
 * restarts at the base when the port steps by one.
 *
 * The torn count is a tripwire, not the proof. With the snapshot's
 * lock/unlock replaced by no-ops it did go red here (2026-10-14, 8
 * cores: torn > 0 on the first plain run), but that is scheduling luck
 * a one-core CI runner need not repeat. Under ThreadSanitizer the same
 * mutation is a reported data race on g_ring_head between the writer
 * and capture_ring_snapshot, every run, and that job is the gate.
 *
 * The writer dispatches into its own state and main snapshots into
 * another: the seam re-seeds the ring from the caller's state on each
 * call, so two threads dispatching or snapshotting into one state would
 * be a race in the test, not in the code under test. Ops are counted on
 * the worker and asserted on main. */
#define RING_RACE_CALLS    64
#define RING_RACE_PER_CALL 48
#define RING_RACE_SNAPS    3000

typedef struct { sloth_state_t *s; int calls; } ring_race_arg_t;

static void *ring_race_writer(void *p) {
    ring_race_arg_t *a = p;
    uint8_t f[128];
    int n = eth_ipv4_tcp(f, 8, 5, -1);
    const uint8_t *fs[RING_RACE_PER_CALL];
    int ls[RING_RACE_PER_CALL];
    for (int i = 0; i < RING_RACE_PER_CALL; i++) { fs[i] = f; ls[i] = n; }
    for (int k = 0; k < RING_RACE_CALLS; k++) {
        uint16_t sport = (uint16_t)(1000 + k);
        f[ETH_HDR + 20] = (uint8_t)(sport >> 8);   /* TCP source port */
        f[ETH_HDR + 21] = (uint8_t)sport;
        if (capture_test_dispatch(a->s, DLT_EN10MB, fs, ls, NULL,
                                  RING_RACE_PER_CALL) == RING_RACE_PER_CALL)
            a->calls++;
    }
    return NULL;
}

/* 1 when the copy is one consistent prefix of the writer's order. */
static int ring_copy_is_coherent(const sloth_state_t *s) {
    if (s->pkt_count < 0 || s->pkt_count > MAX_PACKETS) return 0;
    if (s->pkt_head  < 0 || s->pkt_head  >= MAX_PACKETS) return 0;
    if (s->pkt_total < (uint64_t)s->pkt_count) return 0;
    if (s->pkt_count < MAX_PACKETS && s->pkt_head != s->pkt_count) return 0;
    int oldest = (s->pkt_head - s->pkt_count + MAX_PACKETS) % MAX_PACKETS;
    for (int j = 1; j < s->pkt_count; j++) {
        const packet_info_t *prev = &s->packets[(oldest + j - 1) % MAX_PACKETS];
        const packet_info_t *cur  = &s->packets[(oldest + j)     % MAX_PACKETS];
        if (cur->src_port == prev->src_port) {
            if (cur->ts_sec != prev->ts_sec + 1) return 0;
        } else if (cur->src_port == prev->src_port + 1) {
            if (cur->ts_sec != 1700000000u) return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

static void test_ring_snapshot_is_stable_under_writer(void) {
    capture_test_set_policy(NULL);
    sloth_state_t *w = calloc(1, sizeof(*w));
    sloth_state_t *m = calloc(1, sizeof(*m));
    ASSERT(w != NULL && m != NULL);
    if (!w || !m) { free(w); free(m); return; }

    /* Empty the ring before the writer exists: an empty dispatch seeds
     * it from the zeroed state. Otherwise main's first snapshots see
     * whatever the previous test left, and the writer's first re-seed
     * reads as pkt_total going backwards -- the harness tearing, not
     * the ring. Found on this test's first run. */
    ASSERT_EQ(capture_test_dispatch(w, DLT_EN10MB, NULL, NULL, NULL, 0), 0);

    ring_race_arg_t arg = { w, 0 };
    pthread_t th;
    ASSERT_EQ(pthread_create(&th, NULL, ring_race_writer, &arg), 0);

    int      torn = 0;
    uint64_t last_total = 0;
    for (int i = 0; i < RING_RACE_SNAPS; i++) {
        capture_ring_snapshot(m);
        if (!ring_copy_is_coherent(m)) torn++;
        if (m->pkt_total < last_total) torn++;      /* total only grows */
        last_total = m->pkt_total;
    }
    ASSERT_EQ(pthread_join(th, NULL), 0);
    ASSERT_EQ(arg.calls, RING_RACE_CALLS);
    ASSERT_EQ(torn, 0);

    /* After the writer: main's copy is the writer's ring, full, with the
     * newest frame being the last of the last call. */
    capture_ring_snapshot(m);
    ASSERT(ring_copy_is_coherent(m));
    ASSERT_EQ(m->pkt_count, MAX_PACKETS);
    ASSERT_EQ((long long)m->pkt_total,
              (long long)RING_RACE_CALLS * RING_RACE_PER_CALL);
    ASSERT_EQ(m->pkt_head,  w->pkt_head);
    ASSERT_EQ(m->pkt_count, w->pkt_count);
    ASSERT_EQ(memcmp(m->packets, w->packets, sizeof(m->packets)), 0);
    int newest = (m->pkt_head - 1 + MAX_PACKETS) % MAX_PACKETS;
    ASSERT_EQ(m->packets[newest].src_port, 1000 + RING_RACE_CALLS - 1);
    ASSERT_EQ(m->packets[newest].ts_sec, 1700000000u + RING_RACE_PER_CALL - 1);
    free(w);
    free(m);
}

/* #142: the one binary that links libpcap is the one that can prove
 * `--version` and sensor_health's `libs` report the LOADED libpcap —
 * pcap_lib_version() of this process — rather than "none" or a string
 * baked in at build time. Compared against the library, never a
 * literal, because which libpcap a host has is host state. */
static void test_libver_reports_the_loaded_libpcap(void) {
    ASSERT_STR(libver_pcap(), pcap_lib_version());
    ASSERT(strcmp(libver_pcap(), "none") != 0);
    char buf[192], want[192];
    libver_format(buf, sizeof(buf));
    snprintf(want, sizeof(want), "pcap: %s; sqlite: ", pcap_lib_version());
    ASSERT(strncmp(buf, want, strlen(want)) == 0);
}

/* #138: both SSID stores in on_probe_frame() go through
 * dot11_ie_ssid(), so '\n' / '\r' / DEL / ESC in an SSID reach the PNL
 * and the association table as '?'. Mutation: see test_beacon_snoop.c. */
static void test_probe_request_ssid_control_octets_marked(void) {
    static const uint8_t sa[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x79 };
    uint8_t f[RT_HDR + 24 + 2 + 4];
    memset(&g_s, 0, sizeof(g_s)); probe_clear(); probe_pnl_clear();
    int n = mon_probe_req(f, sa, "x\ny\x7f", 0);
    ASSERT_EQ(n, (int)sizeof f);
    const uint8_t *fs[1] = { f };
    int ls[1] = { n };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    probe_pnl_snapshot(&g_s);
    ASSERT_EQ(g_s.pnl_count, 1);
    ASSERT_STR(g_s.pnl_clients[0].ssids[0], "x?y?");
    probe_pnl_clear();
}

static void test_assoc_response_ssid_control_octets_marked(void) {
    uint8_t f[RT_HDR + 24 + 6 + 2 + 4];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_radiotap(&b, NULL);
    fb_mgmt(&b, 1, 0, SA_STA, SA_BSSID, SA_BSSID, 0x0010, 0);
    fb_assoc_resp_fixed(&b, 0x0411, 0 /* success */, 0xc001);
    fb_ie(&b, 0, "x\ry\x1b", 4);
    ASSERT(fb_ok(&b));

    memset(&g_s, 0, sizeof(g_s)); probe_clear(); assoc_clear();
    const uint8_t *fs[1] = { f };
    int ls[1] = { b.len };
    ASSERT_EQ(probe_test_dispatch(&g_s, fs, ls, NULL, NULL, 1), 1);
    assoc_snapshot(&g_s);
    ASSERT_EQ(g_s.assoc_count, 1);
    ASSERT_STR(g_s.assocs[0].ssid, "x?y?");
    assoc_clear();
}

/* ── IP to transport, once — issue #132 ──────────────────────
 *
 * Frames built field by field per RFC 791 §3.1 (IPv4), RFC 8200 §3-§4
 * (IPv6 and its extension headers), RFC 4302 §2 (AH), RFC 768 (UDP)
 * and RFC 9293 §3.1 (TCP). Every case that asserts something is NOT
 * parsed has a positive control beside it: the same bytes with the one
 * field flipped are parsed, so the absence is the field's doing and
 * not a frame the parsers would have refused anyway. */

static const uint8_t I132_MAC_A[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01 };
static const uint8_t I132_MAC_B[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x02 };

/* RFC 1035 §4.1 query: ID, RD, QDCOUNT 1, QNAME "printer.lan", A, IN. */
static const uint8_t I132_DNS_Q[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, 'p', 'r', 'i', 'n', 't', 'e', 'r', 3, 'l', 'a', 'n', 0,
    0x00, 0x01, 0x00, 0x01 };

static const char I132_GET[] =
    "GET /index.html HTTP/1.1\r\nHost: intranet.example\r\n\r\n";

/* IPv4 header, IHL 5. `total` is written as given — the tests are about
 * what the decoder does when it disagrees with the frame. `frag` is the
 * whole flags + Fragment Offset word (offset in 8-octet units). */
static void i132_ipv4(fb_t *b, int total, uint16_t frag, uint8_t proto) {
    fb_u8(b, 0x45); fb_u8(b, 0);
    fb_be16(b, (uint16_t)total);
    fb_be16(b, 0x4242);                   /* Identification */
    fb_be16(b, frag);
    fb_u8(b, 64); fb_u8(b, proto);
    fb_be16(b, 0);                        /* checksum: not verified */
    fb_bytes(b, "\xc0\xa8\x01\x0a", 4);   /* 192.168.1.10 */
    fb_bytes(b, "\xc0\xa8\x01\x01", 4);   /* 192.168.1.1  */
}

/* IPv6 fixed header (RFC 8200 §3), documentation prefix 2001:db8::/32. */
static void i132_ipv6(fb_t *b, int payload_len, uint8_t next_header) {
    fb_be16(b, 0x6000); fb_be16(b, 0x0000);   /* version 6, TC 0, flow 0 */
    fb_be16(b, (uint16_t)payload_len);
    fb_u8(b, next_header);
    fb_u8(b, 64);                             /* Hop Limit */
    fb_bytes(b, "\x20\x01\x0d\xb8\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x0a", 16);
    fb_bytes(b, "\x20\x01\x0d\xb8\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
}

static void i132_udp(fb_t *b, uint16_t sport, uint16_t dport,
                     const void *pay, int n) {
    fb_be16(b, sport); fb_be16(b, dport);
    fb_be16(b, (uint16_t)(8 + n)); fb_be16(b, 0);
    fb_bytes(b, pay, n);
}

/* TCP with `opt_words` 32-bit option words (NOP-filled), PSH|ACK. */
static void i132_tcp(fb_t *b, uint16_t sport, uint16_t dport, int opt_words,
                     const void *pay, int n) {
    fb_be16(b, sport); fb_be16(b, dport);
    fb_be16(b, 0); fb_be16(b, 1);             /* seq */
    fb_be16(b, 0); fb_be16(b, 1);             /* ack */
    fb_u8(b, (uint8_t)((5 + opt_words) << 4));
    fb_u8(b, 0x18);
    fb_be16(b, 65535); fb_be16(b, 0); fb_be16(b, 0);
    for (int i = 0; i < opt_words * 4; i++) fb_u8(b, 0x01);  /* NOP */
    fb_bytes(b, pay, n);
}

static int i132_dispatch(const uint8_t *f, int len, int orig) {
    const uint8_t *fs[1] = { f };
    int ls[1] = { len };
    int os[1] = { orig };
    memset(&g_s, 0, sizeof(g_s));
    return capture_test_dispatch(&g_s, DLT_EN10MB, fs, ls, os, 1);
}

static int i132_dns_records(void) {
    dns_log_snapshot(&g_s);
    return g_s.dns_log_count;
}

static int i132_http_records(void) {
    http_log_snapshot(&g_s);
    return g_s.http_log_count;
}

/* IPv4 TCP/80 GET with the given flags/offset word. */
static int i132_v4_http(uint8_t *f, int cap, uint16_t frag) {
    fb_t b; fb_init(&b, f, cap);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x0800);
    const int n = (int)sizeof I132_GET - 1;
    i132_ipv4(&b, 20 + 20 + n, frag, 6);
    i132_tcp(&b, 51000, 80, 0, I132_GET, n);
    return fb_ok(&b) ? b.len : -1;
}

static void test_ipv4_non_first_fragment_is_not_parsed_as_tcp(void) {
    uint8_t f[256];
    /* Control: offset 0 — the bytes are a real TCP header and GET. */
    int n = i132_v4_http(f, sizeof f, 0x0000);
    ASSERT(n > 0);
    http_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_http_records(), 1);
    ASSERT_EQ(g_s.packets[0].dst_port, 80);

    /* Fragment Offset 185 (1480 octets in): the same bytes are now the
       middle of some datagram. Mutation-proved: dropping the
       `frag_off != 0` test in l4_from_ipv4() records the GET. */
    n = i132_v4_http(f, sizeof f, 185);
    http_log_clear();
    uint64_t pf0 = sh_parse_fault_count(SH_PF_IP_FRAGMENT);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_http_records(), 0);
    ASSERT_EQ((long long)g_s.pkt_total, 1);       /* the row is kept */
    ASSERT_STR(g_s.packets[0].info, "IPv4 frag");
    ASSERT_EQ(g_s.packets[0].proto, IPPROTO_TCP);
    ASSERT_EQ(g_s.packets[0].src_port, 0);
    ASSERT_EQ(g_s.packets[0].dst_port, 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_FRAGMENT) - pf0), 1);
    http_log_clear();
}

static void test_ipv4_first_fragment_is_still_parsed(void) {
    /* MF set, offset 0: the transport header is real. Not a fault. */
    uint8_t f[256];
    int n = i132_v4_http(f, sizeof f, 0x2000);
    http_log_clear();
    uint64_t pf0 = sh_parse_fault_count(SH_PF_IP_FRAGMENT);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_http_records(), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_FRAGMENT) - pf0), 0);
    http_log_clear();
}

/* IPv4 UDP/53 carrying the query. `total_override` >= 0 replaces the
 * Total Length the frame actually has (20 + 8 + 29). */
static int i132_v4_dns(uint8_t *f, int cap, int total_override) {
    fb_t b; fb_init(&b, f, cap);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x0800);
    const int n = (int)sizeof I132_DNS_Q;
    i132_ipv4(&b, total_override >= 0 ? total_override : 20 + 8 + n, 0, 17);
    i132_udp(&b, 40000, 53, I132_DNS_Q, n);
    return fb_ok(&b) ? b.len : -1;
}

static void test_ipv4_bytes_past_total_length_are_not_payload(void) {
    uint8_t f[256];
    /* Control: Total Length covers the query. */
    int n = i132_v4_dns(f, sizeof f, -1);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);

    /* Total Length 28: IP + an empty UDP datagram. The query bytes are
       now link-layer trailer — what Ethernet padding is. Mutation-
       proved: removing the `len = total` clamp records the query. */
    n = i132_v4_dns(f, sizeof f, 28);
    dns_log_clear();
    uint64_t pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 0);
    ASSERT_EQ(g_s.packets[0].dst_port, 53);       /* UDP header still read */
    ASSERT_STR(g_s.packets[0].info, "UDP 37");    /* the UDP Length field */
    /* Padding is normal, not a fault. */
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 0);
    dns_log_clear();
}

static void test_ipv4_total_length_below_the_header_is_a_fault(void) {
    uint8_t f[256];
    int n = i132_v4_dns(f, sizeof f, 19);
    dns_log_clear();
    uint64_t pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 0);
    ASSERT_STR(g_s.packets[0].info, "IPv4 bad len");
    ASSERT_STR(g_s.packets[0].src, "192.168.1.10");   /* addresses kept */
    ASSERT_EQ(g_s.packets[0].dst_port, 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 1);
    dns_log_clear();
}

static void test_ipv4_total_length_past_the_frame_counts_unless_snapped(void) {
    uint8_t f[256];
    int n = i132_v4_dns(f, sizeof f, 1400);
    /* Whole frame captured, header claims more: a truncated packet. The
       captured part is still parsed — the clamp only ever shortens. */
    dns_log_clear();
    uint64_t pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 1);

    /* The capture snapped the frame (wire length 1414): a short packet
       is expected. Mutation-proved: dropping `&& !snapped` counts it. */
    dns_log_clear();
    pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, n, 14 + 1400), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 0);
    dns_log_clear();
}

static void test_ipv4_zero_total_length_is_read_as_unstated(void) {
    /* BIG TCP / TSO: 0 is "not stated". Parsed to the captured length,
       not counted. */
    uint8_t f[256];
    int n = i132_v4_dns(f, sizeof f, 0);
    dns_log_clear();
    uint64_t pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 0);
    dns_log_clear();
}

static void test_tcp_data_offset_is_honoured_once(void) {
    /* Three option words (data offset 8): the GET starts 32 octets in.
       Mutation-proved: reading the payload at a fixed 20 in
       decode_tcp() hands the parsers NOPs and records nothing. */
    uint8_t f[256];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x0800);
    const int n = (int)sizeof I132_GET - 1;
    i132_ipv4(&b, 20 + 32 + n, 0, 6);
    i132_tcp(&b, 51000, 80, 3, I132_GET, n);
    ASSERT(fb_ok(&b));
    http_log_clear();
    ASSERT_EQ(i132_dispatch(f, b.len, b.len), 1);
    ASSERT_EQ(i132_http_records(), 1);
    ASSERT_STR(g_s.http_log[0].host, "intranet.example");
    http_log_clear();
}

/* IPv6 + `ext` (already-encoded extension headers, ending in UDP's 17)
 * + UDP/53 query. `first_nh` is the fixed header's Next Header. */
static int i132_v6_dns(uint8_t *f, int cap, uint8_t first_nh,
                       const uint8_t *ext, int ext_len, int plen_override) {
    fb_t b; fb_init(&b, f, cap);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x86DD);
    const int n = (int)sizeof I132_DNS_Q;
    i132_ipv6(&b, plen_override >= 0 ? plen_override : ext_len + 8 + n,
              first_nh);
    if (ext_len) fb_bytes(&b, ext, ext_len);
    i132_udp(&b, 40000, 53, I132_DNS_Q, n);
    return fb_ok(&b) ? b.len : -1;
}

static void test_ipv6_hop_by_hop_is_walked_to_udp(void) {
    /* Hop-by-Hop (§4.3): Next Header 17, Hdr Ext Len 0 (8 octets), one
       PadN option (type 1, length 4) filling the rest. Mutation-proved:
       dropping 0 from the walked set leaves the query unparsed. */
    static const uint8_t hbh[8] = { 17, 0, 0x01, 0x04, 0, 0, 0, 0 };
    uint8_t f[256];
    int n = i132_v6_dns(f, sizeof f, 0, hbh, 8, -1);
    ASSERT(n > 0);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    ASSERT_STR(g_s.dns_log[0].src, "2001:db8::a");
    ASSERT_EQ(g_s.packets[0].proto, IPPROTO_UDP);  /* what it carries */
    ASSERT_EQ(g_s.packets[0].dst_port, 53);
    dns_log_clear();
}

static void test_ipv6_routing_then_destination_options_are_walked(void) {
    /* Routing (§4.4, Hdr Ext Len 1 = 16 octets) → Destination Options
       (§4.6, 8 octets) → UDP. Two headers, two different lengths. */
    static const uint8_t ext[24] = {
        60, 1, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* Routing */
        17, 0, 0x01, 0x04, 0, 0, 0, 0 };                     /* DestOpt */
    uint8_t f[256];
    int n = i132_v6_dns(f, sizeof f, 43, ext, 24, -1);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    dns_log_clear();
}

static void test_ipv6_ah_length_is_in_four_octet_units(void) {
    /* AH (RFC 4302 §2.2) with a 96-bit ICV: 12 fixed + 12 ICV = 24
       octets, Payload Len = 24/4 - 2 = 4. Mutation-proved: using the
       8 * (len + 1) rule for AH skips 40 octets and finds no query. */
    uint8_t ah[24];
    memset(ah, 0, sizeof ah);
    ah[0] = 17; ah[1] = 4;                  /* Next Header, Payload Len */
    ah[7] = 0x01;                           /* SPI 1 */
    ah[11] = 0x01;                          /* Sequence Number 1 */
    uint8_t f[256];
    int n = i132_v6_dns(f, sizeof f, 51, ah, 24, -1);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);
    dns_log_clear();
}

static void test_ipv6_non_first_fragment_is_not_parsed(void) {
    /* Fragment header (§4.5): Next Header 17, reserved, Offset|Res|M,
       Identification. Control: offset 0, M clear (an atomic fragment)
       is walked through to the query. */
    uint8_t fr[8] = { 17, 0, 0x00, 0x00, 0, 0, 0x13, 0x37 };
    uint8_t f[256];
    int n = i132_v6_dns(f, sizeof f, 44, fr, 8, -1);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);

    /* Offset 185 (185 << 3 in the high 13 bits). Mutation-proved:
       ignoring the offset walks into the bytes and records the query. */
    fr[2] = (uint8_t)((185 << 3) >> 8);
    fr[3] = (uint8_t)((185 << 3) & 0xff);
    n = i132_v6_dns(f, sizeof f, 44, fr, 8, -1);
    dns_log_clear();
    uint64_t pf0 = sh_parse_fault_count(SH_PF_IP_FRAGMENT);
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 0);
    ASSERT_STR(g_s.packets[0].info, "IPv6 frag");
    ASSERT_EQ(g_s.packets[0].proto, IPPROTO_UDP);
    ASSERT_EQ(g_s.packets[0].dst_port, 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_FRAGMENT) - pf0), 1);
    dns_log_clear();
}

static void test_ipv6_bytes_past_payload_length_are_not_payload(void) {
    /* Payload Length 8: an empty UDP datagram, the query is trailer.
       The control is test_ipv6_hop_by_hop_is_walked_to_udp's shape with
       no extension; asserted here too so the case stands alone. */
    uint8_t f[256];
    int n = i132_v6_dns(f, sizeof f, 17, NULL, 0, -1);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 1);

    n = i132_v6_dns(f, sizeof f, 17, NULL, 0, 8);
    dns_log_clear();
    ASSERT_EQ(i132_dispatch(f, n, n), 1);
    ASSERT_EQ(i132_dns_records(), 0);
    ASSERT_EQ(g_s.packets[0].dst_port, 53);
    dns_log_clear();
}

static void test_ipv6_extension_header_past_the_packet_is_a_fault(void) {
    /* Hop-by-Hop claiming 48 octets (Hdr Ext Len 5) in a packet that
       carries 8 of them before it ends. */
    static const uint8_t hbh[8] = { 17, 5, 0x01, 0x04, 0, 0, 0, 0 };
    uint8_t f[256];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x86DD);
    i132_ipv6(&b, 8, 0);
    fb_bytes(&b, hbh, 8);
    ASSERT(fb_ok(&b));
    uint64_t pt0 = sh_parse_fault_count(SH_PF_IP_TRUNCATED);
    ASSERT_EQ(i132_dispatch(f, b.len, b.len), 1);
    ASSERT_STR(g_s.packets[0].info, "IPv6 nh=0");
    ASSERT_EQ(g_s.packets[0].dst_port, 0);
    ASSERT_EQ((long long)(sh_parse_fault_count(SH_PF_IP_TRUNCATED) - pt0), 1);
}

static void test_ipv6_udp_kerberos_reaches_kerb_snoop(void) {
    /* Defect K: the IPv6 UDP dispatch was a copy without the Kerberos
       arm. AS-REQ is [APPLICATION 10] (RFC 4120 §5.4.1), outer tag 0x6A.
       Mutation-proved: restricting the 88 arm to IPv4 sources leaves
       kerb_event_count at 0. */
    uint8_t asreq[18];
    asreq[0] = 0x6A; asreq[1] = 0x10;
    memset(asreq + 2, 0, 16);
    uint8_t f[256];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x86DD);
    i132_ipv6(&b, 8 + (int)sizeof asreq, 17);
    i132_udp(&b, 49152, 88, asreq, (int)sizeof asreq);
    ASSERT(fb_ok(&b));
    kerb_snoop_clear();
    ASSERT_EQ(i132_dispatch(f, b.len, b.len), 1);
    ASSERT_STR(g_s.packets[0].info, "Kerberos");
    kerb_snoop_snapshot(&g_s);
    ASSERT_EQ(g_s.kerb_event_count, 1);
    ASSERT_STR(g_s.kerb_events[0].src_ip, "2001:db8::a");
    ASSERT_EQ(g_s.kerb_events[0].as_req_count, 1);
    kerb_snoop_clear();
}

static void test_ipv6_udp_snmp_reaches_snmp_snoop(void) {
    /* SNMPv1 GetRequest (RFC 1157 §4.1): SEQUENCE { INTEGER 0,
       OCTET STRING "public", GetRequest-PDU [0] { request-id,
       error-status, error-index, empty varbind list } }. */
    static const uint8_t get[] = {
        0x30, 0x19,
        0x02, 0x01, 0x00,
        0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
        0xA0, 0x0C,
        0x02, 0x02, 0x12, 0x34,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x00 };
    uint8_t f[256];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_eth(&b, I132_MAC_A, I132_MAC_B, 0x86DD);
    i132_ipv6(&b, 8 + (int)sizeof get, 17);
    i132_udp(&b, 49152, 161, get, (int)sizeof get);
    ASSERT(fb_ok(&b));
    snmp_snoop_clear();
    ASSERT_EQ(i132_dispatch(f, b.len, b.len), 1);
    ASSERT_STR(g_s.packets[0].info, "SNMP");
    snmp_snoop_snapshot(&g_s);
    ASSERT_EQ(g_s.snmp_flow_count, 1);
    ASSERT_STR(g_s.snmp_flows[0].src_ip, "2001:db8::a");
    ASSERT_EQ(g_s.snmp_flows[0].get_count, 1);
    ASSERT_STR(g_s.snmp_flows[0].last_community, "public");
    snmp_snoop_clear();
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
    RUN_TEST(test_libver_reports_the_loaded_libpcap);

    TEST_SUITE("capture path: scope is an authorization boundary (#85)");
    RUN_TEST(test_scope_admits_the_pinned_interface);
    RUN_TEST(test_scope_refuses_an_unpinned_ifindex);
    RUN_TEST(test_scope_refuses_the_first_frame_after_start);
    RUN_TEST(test_scope_refuses_an_invalidated_pin);
    RUN_TEST(test_scope_refuses_an_unattributable_frame);
    RUN_TEST(test_scope_refuses_a_datalink_without_an_ifindex);
    RUN_TEST(test_scope_refuses_a_deselected_pinned_interface);
    RUN_TEST(test_no_allow_list_admits_any_ifindex);

    TEST_SUITE("monitor dispatch seam: real on_probe_frame (#92)");
    RUN_TEST(test_monitor_seam_admits_a_wellformed_frame);
    RUN_TEST(test_monitor_seam_counts_each_admitted_frame);
    RUN_TEST(test_probe_request_pnl_survives_the_htc_bit);
    RUN_TEST(test_a_short_assoc_response_records_the_grant);
    RUN_TEST(test_assoc_response_element_overrun_is_tallied);
    RUN_TEST(test_probe_request_element_overrun_is_tallied_per_walk);
    RUN_TEST(test_probe_request_ssid_33_is_clamped_to_32);
    RUN_TEST(test_assoc_response_ssid_33_is_clamped_to_32);
    RUN_TEST(test_fcs_is_stripped_before_the_frame_is_recorded);
    RUN_TEST(test_radiotap_datapad_frame_reaches_the_ip_decoder);
    RUN_TEST(test_an_fcs_beacon_walks_no_phantom_element);
    RUN_TEST(test_a_datapad_eapol_m1_reaches_the_collector);
    RUN_TEST(test_a_datapad_dns_query_reaches_the_dns_log);
    RUN_TEST(test_a_short_radiotap_length_is_refused_and_counted);
    RUN_TEST(test_a_short_radiotap_probe_request_reaches_no_pnl);
    RUN_TEST(test_a_caplen_above_origlen_is_refused_before_decode);
    RUN_TEST(test_a_caplen_past_the_snaplen_is_refused_at_both_edges);
    RUN_TEST(test_bad_fcs_frames_still_feed_rf_quality_and_evidence);
    RUN_TEST(test_monitor_seam_rejects_frames_below_the_guards);
    RUN_TEST(test_monitor_seam_mixes_admitted_and_rejected);
    RUN_TEST(test_monitor_seam_carries_per_frame_timestamps);
    RUN_TEST(test_monitor_seam_rejects_bad_arguments);

    TEST_SUITE("evidence ring through the real callback (#92)");
    RUN_TEST(test_the_callback_retains_the_whole_frame_with_radiotap);
    RUN_TEST(test_retained_records_carry_the_capture_clock);
    RUN_TEST(test_a_kernel_snapped_frame_is_flagged_truncated);
    RUN_TEST(test_a_deauth_row_cites_the_frames_the_ring_kept);
    RUN_TEST(test_a_deauth_row_cites_nothing_with_the_ring_down);
    RUN_TEST(test_frames_refused_by_the_guards_are_not_retained);
    RUN_TEST(test_an_uninitialised_ring_does_not_stop_the_callback);
    RUN_TEST(test_ring_pressure_from_the_callback_is_counted);

    TEST_SUITE("one frame, one clock (#92)");
    RUN_TEST(test_frame_records_carry_the_capture_timestamp);
    RUN_TEST(test_a_zero_capture_clock_is_counted_not_substituted);
    RUN_TEST(test_a_good_capture_clock_is_not_counted);
    RUN_TEST(test_probe_callback_has_no_wall_clock_read);

    TEST_SUITE("probe-client eviction is counted (#91)");
    RUN_TEST(test_filling_the_probe_table_counts_no_eviction);
    RUN_TEST(test_one_client_past_the_table_is_counted);
    RUN_TEST(test_a_repeat_client_is_an_update_not_an_eviction);
    RUN_TEST(test_each_further_client_counts_once);

    TEST_SUITE("per-stream freshness: two clocks (#91)");
    RUN_TEST(test_monitor_freshness_starts_as_never);
    RUN_TEST(test_monitor_freshness_follows_two_clocks);
    RUN_TEST(test_a_refused_frame_does_not_refresh_the_stream);
    RUN_TEST(test_capture_stream_freshness);

    TEST_SUITE("probe-table invariants (#91)");
    RUN_TEST(test_probe_table_holds_no_duplicate_after_ageing);
    RUN_TEST(test_probe_table_never_exceeds_its_cap);

    TEST_SUITE("queued-frame release wiring (#107 shape B)");
    RUN_TEST(test_a_granted_reassoc_plus_a_burst_records_a_release);
    RUN_TEST(test_a_retried_downlink_burst_records_no_release);
    RUN_TEST(test_a_refused_reassoc_opens_no_window);
    RUN_TEST(test_a_deauth_attributes_the_station_in_both_directions);
    RUN_TEST(test_a_broadcast_deauth_opens_no_window);

    TEST_SUITE("capture path: [m] retarget honours the allow-list (#85)");
    RUN_TEST(test_retarget_outside_the_allow_list_is_refused);
    RUN_TEST(test_refusal_is_attributable_to_the_allow_list);
    RUN_TEST(test_an_empty_allow_list_admits_any_retarget);
    RUN_TEST(test_a_failed_retarget_open_keeps_the_current_radio);
    RUN_TEST(test_retarget_ignores_an_empty_name);

    TEST_SUITE("capture path: the packet ring is a snapshot (#111)");
    RUN_TEST(test_ring_wraps_with_head_count_total_preserved);
    RUN_TEST(test_ring_snapshot_is_stable_under_writer);
    RUN_TEST(test_probe_request_ssid_control_octets_marked);
    RUN_TEST(test_assoc_response_ssid_control_octets_marked);

    TEST_SUITE("capture path: IP to transport, once (#132)");
    RUN_TEST(test_ipv4_non_first_fragment_is_not_parsed_as_tcp);
    RUN_TEST(test_ipv4_first_fragment_is_still_parsed);
    RUN_TEST(test_ipv4_bytes_past_total_length_are_not_payload);
    RUN_TEST(test_ipv4_total_length_below_the_header_is_a_fault);
    RUN_TEST(test_ipv4_total_length_past_the_frame_counts_unless_snapped);
    RUN_TEST(test_ipv4_zero_total_length_is_read_as_unstated);
    RUN_TEST(test_tcp_data_offset_is_honoured_once);
    RUN_TEST(test_ipv6_hop_by_hop_is_walked_to_udp);
    RUN_TEST(test_ipv6_routing_then_destination_options_are_walked);
    RUN_TEST(test_ipv6_ah_length_is_in_four_octet_units);
    RUN_TEST(test_ipv6_non_first_fragment_is_not_parsed);
    RUN_TEST(test_ipv6_bytes_past_payload_length_are_not_payload);
    RUN_TEST(test_ipv6_extension_header_past_the_packet_is_a_fault);
    RUN_TEST(test_ipv6_udp_kerberos_reaches_kerb_snoop);
    RUN_TEST(test_ipv6_udp_snmp_reaches_snmp_snoop);
}
#else
void run_capture_path_tests(void);
void run_capture_path_tests(void) {}
#endif
