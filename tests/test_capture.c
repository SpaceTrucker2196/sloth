#include "runner.h"
#include "capture/capture.h"

/* pcap_activate() return codes, written out from libpcap's documented
   contract rather than #included from <pcap.h> — the test build links no
   libpcap, and pinning the literals here is what makes this a real
   inspection step instead of a tautology.

   Errors are negative, warnings are positive, clean success is 0.
   Values per pcap/pcap.h (libpcap 1.x, stable since 1.0). */
#define P_ERROR                       (-1)
#define P_ERROR_BREAK                 (-2)
#define P_ERROR_NOT_ACTIVATED         (-3)
#define P_ERROR_ACTIVATED             (-4)
#define P_ERROR_NO_SUCH_DEVICE        (-5)
#define P_ERROR_RFMON_NOTSUP          (-6)
#define P_ERROR_NOT_RFMON             (-7)
#define P_ERROR_PERM_DENIED           (-8)
#define P_ERROR_IFACE_NOT_UP          (-9)
#define P_ERROR_CANTSET_TSTAMP_TYPE  (-10)
#define P_ERROR_PROMISC_PERM_DENIED  (-11)
#define P_ERROR_TSTAMP_PRECISION_NOTSUP (-12)

#define P_WARNING                       1
#define P_WARNING_PROMISC_NOTSUP        2
#define P_WARNING_TSTAMP_TYPE_NOTSUP    3

/* ── activate classification (#46) ────────────────────────── */

static void test_activate_success_is_not_failure(void) {
    ASSERT_EQ(capture_activate_failed(0), 0);
}

static void test_activate_warnings_are_not_failure(void) {
    /* The regression: the "any" device has no promiscuous mode, so
       pcap_activate() succeeds with PCAP_WARNING_PROMISC_NOTSUP. Closing
       the handle here drops SLL2 and with it the ingress ifindex that
       --iface / --monitor-only scoping keys on. */
    ASSERT_EQ(capture_activate_failed(P_WARNING_PROMISC_NOTSUP), 0);
    ASSERT_EQ(capture_activate_failed(P_WARNING), 0);
    ASSERT_EQ(capture_activate_failed(P_WARNING_TSTAMP_TYPE_NOTSUP), 0);
}

static void test_activate_errors_are_failure(void) {
    ASSERT_NE(capture_activate_failed(P_ERROR), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_BREAK), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_NOT_ACTIVATED), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_ACTIVATED), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_NO_SUCH_DEVICE), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_RFMON_NOTSUP), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_NOT_RFMON), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_PERM_DENIED), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_IFACE_NOT_UP), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_CANTSET_TSTAMP_TYPE), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_PROMISC_PERM_DENIED), 0);
    ASSERT_NE(capture_activate_failed(P_ERROR_TSTAMP_PRECISION_NOTSUP), 0);
}

static void test_activate_unknown_codes_follow_sign(void) {
    /* Forward compatibility: libpcap may add codes. The sign is the
       contract, so an unseen warning must not be fatal and an unseen
       error must be. */
    ASSERT_EQ(capture_activate_failed(99), 0);
    ASSERT_NE(capture_activate_failed(-99), 0);
}

/* ── ingress-ifindex datalinks (#57) ──────────────────────── */

/* Datalink values per pcap-linktype(7), pinned here for the same reason
   as the activate codes above: the test build links no libpcap. */
#define D_NULL         0
#define D_EN10MB       1
#define D_LINUX_SLL  113
#define D_LINUX_SLL2 276
#define D_IEEE802_11 105
#define D_RADIOTAP   127

static void test_sll2_carries_ifindex(void) {
    ASSERT(capture_dlt_has_ifindex(D_LINUX_SLL2));
}

static void test_other_datalinks_carry_no_ifindex(void) {
    /* The #46 damage, stated directly: SLL v1 is what capture falls back
       to, and it has no ingress ifindex, so --iface / --monitor-only pass
       every frame. Reaching this datalink must be reportable. */
    ASSERT_EQ(capture_dlt_has_ifindex(D_LINUX_SLL), 0);
    ASSERT_EQ(capture_dlt_has_ifindex(D_EN10MB), 0);
    ASSERT_EQ(capture_dlt_has_ifindex(D_IEEE802_11), 0);
    ASSERT_EQ(capture_dlt_has_ifindex(D_RADIOTAP), 0);
}

static void test_unset_linktype_carries_no_ifindex(void) {
    /* pkt_linktype is 0 when capture never started (no root, no devices,
       or a build without WITH_PCAP). main.c reports that case separately,
       but it must not be mistaken for a scoping-capable datalink. */
    ASSERT_EQ(capture_dlt_has_ifindex(D_NULL), 0);
}

static void test_unknown_datalinks_carry_no_ifindex(void) {
    /* Fail closed: an unrecognised DLT is assumed to lack the ifindex, so
       a new capture route reports scope-inactive rather than claiming a
       filter that never runs. */
    ASSERT_EQ(capture_dlt_has_ifindex(9999), 0);
    ASSERT_EQ(capture_dlt_has_ifindex(-1), 0);
}

/* ── fail-closed capture scope (#85) ──────────────────────── */

#include <string.h>

/* Hand-built SLL2 header (pcap-linktype(7) LINKTYPE_LINUX_SLL2): protocol
   type (2), reserved (2), interface index (4, big-endian), ARPHRD (2),
   packet type (1), addr len (1), addr (8). 20 bytes, then the payload —
   here a bare IPv4 ethertype so the frame is otherwise decodable. */
static int sll2_frame(uint8_t *buf, uint32_t ifindex) {
    memset(buf, 0, 20);
    buf[0] = 0x08; buf[1] = 0x00;                 /* ETH_P_IP */
    buf[4] = (uint8_t)(ifindex >> 24);
    buf[5] = (uint8_t)(ifindex >> 16);
    buf[6] = (uint8_t)(ifindex >>  8);
    buf[7] = (uint8_t)(ifindex);
    buf[8] = 0x00; buf[9] = 0x01;                 /* ARPHRD_ETHER */
    buf[11] = 6;
    return 20;
}

/* Seeded resolver: ifindex 2 = eth0, 3 = wlan1, 4 = "" (a resolver that
   "succeeds" with an empty name), everything else fails the way a
   vanished interface makes if_indextoname() fail. */
static int g_resolve_calls;
static int fake_resolve(uint32_t idx, char name[16]) {
    g_resolve_calls++;
    switch (idx) {
    case 2: strcpy(name, "eth0");  return 1;
    case 3: strcpy(name, "wlan1"); return 1;
    case 4: name[0] = '\0';        return 1;
    default:                       return 0;
    }
}
static int fail_resolve(uint32_t idx, char name[16]) {
    (void)idx; (void)name;
    g_resolve_calls++;
    return 0;
}
static int eth_resolve(uint32_t idx, char name[16]) {
    (void)idx;
    g_resolve_calls++;
    strcpy(name, "eth0");
    return 1;
}

static sloth_state_t g_scope_state;

static sloth_state_t *scope_state(const char *allow) {
    memset(&g_scope_state, 0, sizeof(g_scope_state));
    if (allow) iface_allow_add(&g_scope_state, allow);
    capture_ifname_cache_reset();
    g_resolve_calls = 0;
    return &g_scope_state;
}

static void test_scope_allowed_iface_admitted(void) {
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; int n = sll2_frame(f, 3);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 1);
}

static void test_scope_other_iface_rejected(void) {
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; int n = sll2_frame(f, 2);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 0);
}

static void test_scope_unresolvable_ifindex_rejected(void) {
    /* The #85 bypass: a failed if_indextoname() used to skip the check
       and decode the frame. With an allow-list active, an index that
       cannot be named cannot be authorised. */
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; int n = sll2_frame(f, 99);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 0);
    /* ...and not just once: the second packet must still be refused. */
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 0);
}

static void test_scope_empty_name_rejected(void) {
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; int n = sll2_frame(f, 4);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 0);
}

static void test_scope_short_sll2_rejected_when_restricted(void) {
    /* A truncated header carries no trustworthy ifindex. */
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; sll2_frame(f, 3);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, 7, fake_resolve), 0);
}

static void test_scope_non_sll2_rejected_when_restricted(void) {
    /* Startup refuses a non-SLL2 datalink under an allow-list; the
       callback holds the same line rather than trusting that it did. */
    sloth_state_t *s = scope_state("wlan1");
    uint8_t f[64]; int n = sll2_frame(f, 3);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL, f, n, fake_resolve), 0);
    ASSERT_EQ(capture_frame_in_scope(s, D_EN10MB,    f, n, fake_resolve), 0);
}

static void test_scope_null_state_rejected(void) {
    uint8_t f[64]; int n = sll2_frame(f, 3);
    capture_ifname_cache_reset();
    ASSERT_EQ(capture_frame_in_scope(NULL, D_LINUX_SLL2, f, n, fake_resolve), 0);
}

static void test_scope_unrestricted_passes_everything(void) {
    /* No allow-list: behaviour is unchanged, including for frames whose
       index cannot be resolved and for datalinks without one. */
    sloth_state_t *s = scope_state(NULL);
    uint8_t f[64]; int n = sll2_frame(f, 99);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 1);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL,  f, n, fake_resolve), 1);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, 7, fake_resolve), 1);
    /* The hot path skips the name lookup entirely when nothing filters. */
    ASSERT_EQ(g_resolve_calls, 0);
}

static void test_scope_deselect_still_applies(void) {
    /* The runtime [y] election composes as before. */
    sloth_state_t *s = scope_state(NULL);
    memcpy(s->iface_deselected[0], "eth0", 5);
    s->iface_deselected_count = 1;
    uint8_t f[64]; int n = sll2_frame(f, 2);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 0);
    n = sll2_frame(f, 3);
    ASSERT_EQ(capture_frame_in_scope(s, D_LINUX_SLL2, f, n, fake_resolve), 1);
}

static void test_ifname_failure_not_cached(void) {
    /* A failed lookup must not be remembered as an answer: the next
       packet asks again, and a later success is used. */
    capture_ifname_cache_reset();
    g_resolve_calls = 0;
    ASSERT(capture_ifname_lookup(7, fail_resolve) == NULL);
    ASSERT(capture_ifname_lookup(7, fail_resolve) == NULL);
    ASSERT_EQ(g_resolve_calls, 2);
    const char *name = capture_ifname_lookup(7, eth_resolve);
    ASSERT(name != NULL);
    ASSERT_STR(name, "eth0");
}

static void test_ifname_empty_not_cached(void) {
    capture_ifname_cache_reset();
    g_resolve_calls = 0;
    ASSERT(capture_ifname_lookup(4, fake_resolve) == NULL);
    ASSERT(capture_ifname_lookup(4, fake_resolve) == NULL);
    ASSERT_EQ(g_resolve_calls, 2);
}

static void test_ifname_success_cached(void) {
    capture_ifname_cache_reset();
    g_resolve_calls = 0;
    ASSERT_STR(capture_ifname_lookup(3, fake_resolve), "wlan1");
    ASSERT_STR(capture_ifname_lookup(3, fake_resolve), "wlan1");
    ASSERT_EQ(g_resolve_calls, 1);
}

/* ── startup scope verdict (#85) ──────────────────────────── */

static void test_verdict_no_restriction(void) {
    ASSERT_EQ(capture_scope_verdict(0, 0, "", 0, 1, D_LINUX_SLL),
              CAPTURE_SCOPE_NONE);
    ASSERT_EQ(capture_scope_verdict(0, 0, NULL, 0, 0, 0), CAPTURE_SCOPE_NONE);
    ASSERT_EQ(capture_scope_refuses(CAPTURE_SCOPE_NONE), 0);
}

static void test_verdict_enforced(void) {
    ASSERT_EQ(capture_scope_verdict(1, 0, "", 1, 1, D_LINUX_SLL2),
              CAPTURE_SCOPE_ENFORCED);
    ASSERT_EQ(capture_scope_verdict(0, 1, "wlan1", 1, 1, D_LINUX_SLL2),
              CAPTURE_SCOPE_ENFORCED);
    ASSERT_EQ(capture_scope_refuses(CAPTURE_SCOPE_ENFORCED), 0);
}

static void test_verdict_monitor_only_without_radio_refuses(void) {
    /* Was: warn and capture everything. */
    capture_scope_t v = capture_scope_verdict(0, 1, "", 0, 1, D_LINUX_SLL2);
    ASSERT_EQ(v, CAPTURE_SCOPE_REFUSE_NO_MONITOR);
    ASSERT(capture_scope_refuses(v));
    ASSERT_EQ(capture_scope_verdict(0, 1, NULL, 0, 1, D_LINUX_SLL2),
              CAPTURE_SCOPE_REFUSE_NO_MONITOR);
    /* An explicit --iface alongside does not paper over the missing radio:
       the operator asked for the radio's stream and cannot get it. */
    ASSERT_EQ(capture_scope_verdict(1, 1, "", 1, 1, D_LINUX_SLL2),
              CAPTURE_SCOPE_REFUSE_NO_MONITOR);
    /* Nor does capture being off — the refusal is about the request. */
    ASSERT_EQ(capture_scope_verdict(0, 1, "", 0, 0, 0),
              CAPTURE_SCOPE_REFUSE_NO_MONITOR);
}

static void test_verdict_unsupported_datalink_refuses(void) {
    /* Was: "scope is INACTIVE — all traffic is captured", then capture. */
    capture_scope_t v = capture_scope_verdict(1, 0, "", 1, 1, D_LINUX_SLL);
    ASSERT_EQ(v, CAPTURE_SCOPE_REFUSE_DATALINK);
    ASSERT(capture_scope_refuses(v));
    ASSERT_EQ(capture_scope_verdict(0, 1, "wlan1", 1, 1, D_EN10MB),
              CAPTURE_SCOPE_REFUSE_DATALINK);
    /* DLT_NULL is 0 — a live handle on it (BSD loopback) must not be
       mistaken for "capture off". */
    ASSERT_EQ(capture_scope_verdict(1, 0, "", 1, 1, D_NULL),
              CAPTURE_SCOPE_REFUSE_DATALINK);
}

static void test_verdict_empty_policy_refuses(void) {
    /* `--iface ""` requested a restriction but installed no entry; an empty
       list means "unrestricted", so it must not reach the worker. */
    capture_scope_t v = capture_scope_verdict(1, 0, "", 0, 1, D_LINUX_SLL2);
    ASSERT_EQ(v, CAPTURE_SCOPE_REFUSE_EMPTY);
    ASSERT(capture_scope_refuses(v));
}

static void test_verdict_capture_off_is_not_refused(void) {
    /* No data-stream handle: nothing to leak, so the run proceeds with a
       warning (the /proc and netlink readers were never scoped). */
    capture_scope_t v = capture_scope_verdict(1, 0, "", 1, 0, 0);
    ASSERT_EQ(v, CAPTURE_SCOPE_NO_CAPTURE);
    ASSERT_EQ(capture_scope_refuses(v), 0);
}

static void test_verdict_reasons_are_distinct(void) {
    const char *a = capture_scope_reason(CAPTURE_SCOPE_REFUSE_NO_MONITOR);
    const char *b = capture_scope_reason(CAPTURE_SCOPE_REFUSE_DATALINK);
    const char *c = capture_scope_reason(CAPTURE_SCOPE_REFUSE_EMPTY);
    ASSERT(a && a[0] && b && b[0] && c && c[0]);
    ASSERT(strcmp(a, b) != 0 && strcmp(a, c) != 0 && strcmp(b, c) != 0);
    ASSERT(strstr(a, "--monitor-only") != NULL);
}

void run_capture_tests(void) {
    TEST_SUITE("capture pcap_activate classification");
    RUN_TEST(test_activate_success_is_not_failure);
    RUN_TEST(test_activate_warnings_are_not_failure);
    RUN_TEST(test_activate_errors_are_failure);
    RUN_TEST(test_activate_unknown_codes_follow_sign);

    TEST_SUITE("capture ingress-ifindex datalinks");
    RUN_TEST(test_sll2_carries_ifindex);
    RUN_TEST(test_other_datalinks_carry_no_ifindex);
    RUN_TEST(test_unset_linktype_carries_no_ifindex);
    RUN_TEST(test_unknown_datalinks_carry_no_ifindex);

    TEST_SUITE("capture fail-closed scope filter (#85)");
    RUN_TEST(test_scope_allowed_iface_admitted);
    RUN_TEST(test_scope_other_iface_rejected);
    RUN_TEST(test_scope_unresolvable_ifindex_rejected);
    RUN_TEST(test_scope_empty_name_rejected);
    RUN_TEST(test_scope_short_sll2_rejected_when_restricted);
    RUN_TEST(test_scope_non_sll2_rejected_when_restricted);
    RUN_TEST(test_scope_null_state_rejected);
    RUN_TEST(test_scope_unrestricted_passes_everything);
    RUN_TEST(test_scope_deselect_still_applies);
    RUN_TEST(test_ifname_failure_not_cached);
    RUN_TEST(test_ifname_empty_not_cached);
    RUN_TEST(test_ifname_success_cached);

    TEST_SUITE("capture startup scope verdict (#85)");
    RUN_TEST(test_verdict_no_restriction);
    RUN_TEST(test_verdict_enforced);
    RUN_TEST(test_verdict_monitor_only_without_radio_refuses);
    RUN_TEST(test_verdict_unsupported_datalink_refuses);
    RUN_TEST(test_verdict_empty_policy_refuses);
    RUN_TEST(test_verdict_capture_off_is_not_refused);
    RUN_TEST(test_verdict_reasons_are_distinct);
}
