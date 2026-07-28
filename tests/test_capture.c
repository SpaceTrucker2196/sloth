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

void run_capture_tests(void) {
    TEST_SUITE("capture pcap_activate classification");
    RUN_TEST(test_activate_success_is_not_failure);
    RUN_TEST(test_activate_warnings_are_not_failure);
    RUN_TEST(test_activate_errors_are_failure);
    RUN_TEST(test_activate_unknown_codes_follow_sign);
}
