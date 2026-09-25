#include "runner.h"

/* nl80211 scan-trigger policy, limiter and request builder (#84 slice 3).
 *
 * Linux-only: src/platform/linux_wifi.c is an empty translation unit
 * everywhere else, so these tests compile away with it. Nothing here
 * opens a socket or touches a radio — the point of splitting the builder
 * out of the sending path is that the policy is provable without one. */

#if defined(PLATFORM_LINUX) && defined(WITH_WIFI)

#include "observe.h"
#include "platform/linux_wifi.h"

#include <string.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define TEST_FAMILY 27          /* whatever the kernel assigned nl80211 */
#define IFIDX_MON   3
#define IFIDX_UPLINK 7

/* NLMSG_HDRLEN + GENL_HDRLEN + one aligned u32 attribute. */
#define TRIGGER_MSG_LEN (NLMSG_HDRLEN + GENL_HDRLEN + 8u)

static wifi_scan_trigger_stats_t snap(void) {
    wifi_scan_trigger_stats_t st;
    linux_wifi_scan_trigger_stats(&st);
    return st;
}

/* Fresh policy + limiter, active behaviour permitted. */
static void permit_active(void) {
    observe_reset_policy();
    observe_set_active_allowed(1);
    linux_wifi_scan_trigger_reset();
}

/* ── Strict mode builds nothing ──────────────────────────── */

static void test_strict_builds_zero_scan_triggers(void) {
    observe_reset_policy();
    observe_lock_strict();
    linux_wifi_scan_trigger_reset();

    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));

    /* Two interfaces, several poll ticks each, well past the rate limit
     * so nothing is hidden behind it. #84's regression section asks for
     * exactly this number to be zero. */
    for (time_t t = 1000; t < 1100; t += 10) {
        ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                      TEST_FAMILY, IFIDX_MON, t));
        ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                      TEST_FAMILY, IFIDX_UPLINK, t));
    }

    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(0u,  (unsigned)st.requests_built);
    ASSERT_EQ(20u, (unsigned)st.considered);
    ASSERT_EQ(20u, (unsigned)st.suppressed_policy);
    ASSERT_EQ(0u,  (unsigned)st.suppressed_rate);

    /* Refused means "no request exists", not "a request was built and
     * dropped" — the caller's buffer is untouched. */
    for (size_t i = 0; i < sizeof(buf); i++) ASSERT_EQ(0xAA, buf[i]);

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

static void test_default_profile_builds_zero_scan_triggers(void) {
    /* No flags at all: the shipped default is strict, so the trigger is
     * off without the lock too (the Captain's decision of 2026-09-25). */
    observe_reset_policy();
    linux_wifi_scan_trigger_reset();

    uint8_t buf[64];
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                  TEST_FAMILY, IFIDX_MON, 1000));
    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(0u, (unsigned)st.requests_built);
    ASSERT_EQ(1u, (unsigned)st.suppressed_policy);

    linux_wifi_scan_trigger_reset();
}

static void test_lock_after_opt_in_stops_further_triggers(void) {
    permit_active();
    uint8_t buf[64];
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));

    observe_lock_strict();
    /* Far past the rate limit, so a refusal here can only be the lock. */
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                  TEST_FAMILY, IFIDX_MON, 9000));
    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(1u, (unsigned)st.requests_built);
    ASSERT_EQ(1u, (unsigned)st.suppressed_policy);

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

/* ── Per-interface scheduling in permitted modes ─────────── */

static void test_two_interfaces_each_get_their_own_trigger(void) {
    permit_active();
    uint8_t a[64], b[64];

    /* The bug: one function-static timestamp shared by every interface,
     * so the second radio in the same poll pass was suppressed by the
     * first one's trigger and the first-enumerated interface was
     * preferentially scanned forever. */
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(a, sizeof(a),
                                                        TEST_FAMILY, IFIDX_MON, 1000));
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(b, sizeof(b),
                                                        TEST_FAMILY, IFIDX_UPLINK, 1000));

    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(2u, (unsigned)st.requests_built);
    ASSERT_EQ(0u, (unsigned)st.suppressed_rate);

    /* Each request names its own interface. */
    const struct nlattr *na =
        (const struct nlattr *)(a + NLMSG_HDRLEN + GENL_HDRLEN);
    ASSERT_EQ((unsigned)IFIDX_MON, *(const uint32_t *)((const char *)na + 4));
    na = (const struct nlattr *)(b + NLMSG_HDRLEN + GENL_HDRLEN);
    ASSERT_EQ((unsigned)IFIDX_UPLINK, *(const uint32_t *)((const char *)na + 4));

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

static void test_rate_limit_is_per_interface(void) {
    permit_active();
    uint8_t buf[64];

    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));
    /* Inside the window: this interface is limited... */
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                  TEST_FAMILY, IFIDX_MON, 1002));
    /* ...and the other one is not, because the budget is not shared. */
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_UPLINK, 1002));

    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(2u, (unsigned)st.requests_built);
    ASSERT_EQ(1u, (unsigned)st.suppressed_rate);
    ASSERT_EQ(0u, (unsigned)st.suppressed_policy);

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

static void test_rate_limit_reopens_after_the_interval(void) {
    permit_active();
    uint8_t buf[64];

    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));
    /* Boundary: exactly the interval is due, one second short is not. */
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(
                      buf, sizeof(buf), TEST_FAMILY, IFIDX_MON,
                      1000 + WIFI_SCAN_TRIGGER_MIN_INTERVAL_SEC - 1));
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(
                      buf, sizeof(buf), TEST_FAMILY, IFIDX_MON,
                      1000 + WIFI_SCAN_TRIGGER_MIN_INTERVAL_SEC));

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

static void test_every_enumerated_interface_gets_a_slot(void) {
    permit_active();
    uint8_t buf[64];

    /* find_wlan_ifaces() caps at WIFI_SCAN_TRIGGER_MAX_IFACES, so a full
     * poll pass must not evict anyone: all of them trigger at t, none of
     * them triggers again inside the window. */
    for (unsigned i = 1; i <= WIFI_SCAN_TRIGGER_MAX_IFACES; i++)
        ASSERT_EQ(TRIGGER_MSG_LEN,
                  (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                            TEST_FAMILY, i, 2000));
    for (unsigned i = 1; i <= WIFI_SCAN_TRIGGER_MAX_IFACES; i++)
        ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                      TEST_FAMILY, i, 2001));

    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ((unsigned)WIFI_SCAN_TRIGGER_MAX_IFACES, (unsigned)st.requests_built);
    ASSERT_EQ((unsigned)WIFI_SCAN_TRIGGER_MAX_IFACES, (unsigned)st.suppressed_rate);

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

/* ── Request layout ──────────────────────────────────────── */

static void test_scan_trigger_request_layout(void) {
    permit_active();
    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));

    size_t n = linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                               TEST_FAMILY, IFIDX_MON, 1000);
    ASSERT_EQ(TRIGGER_MSG_LEN, (unsigned)n);

    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
    ASSERT_EQ(TRIGGER_MSG_LEN, (unsigned)nlh->nlmsg_len);
    ASSERT_EQ((unsigned)TEST_FAMILY, (unsigned)nlh->nlmsg_type);
    /* NLM_F_REQUEST and nothing else: no NLM_F_ACK (success is silent),
     * no NLM_F_DUMP (this is not a read). */
    ASSERT_EQ((unsigned)NLM_F_REQUEST, (unsigned)nlh->nlmsg_flags);

    const struct genlmsghdr *gh =
        (const struct genlmsghdr *)(buf + NLMSG_HDRLEN);
    ASSERT_EQ((unsigned)NL80211_CMD_TRIGGER_SCAN, (unsigned)gh->cmd);

    const struct nlattr *na =
        (const struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    ASSERT_EQ((unsigned)NL80211_ATTR_IFINDEX, (unsigned)na->nla_type);
    ASSERT_EQ(8u, (unsigned)na->nla_len);
    ASSERT_EQ((unsigned)IFIDX_MON,
              *(const uint32_t *)((const char *)na + 4));

    /* The passivity property, pinned: IFINDEX is the ONLY attribute, so
     * NL80211_ATTR_SCAN_SSIDS cannot be present. With an SSID list the
     * kernel transmits directed probe requests — MISSION §2 forbids that
     * outright, and a well-meant future edit adding one here is exactly
     * what this assertion is for. */
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)(NLMSG_HDRLEN + GENL_HDRLEN + na->nla_len));

    /* Nothing was written past the request. */
    for (size_t i = n; i < sizeof(buf); i++) ASSERT_EQ(0xAA, buf[i]);

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

/* ── Argument handling ───────────────────────────────────── */

static void test_bad_args_build_nothing_and_are_not_policy_events(void) {
    permit_active();
    uint8_t buf[64];

    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(NULL, sizeof(buf),
                                                  TEST_FAMILY, IFIDX_MON, 1000));
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, TRIGGER_MSG_LEN - 1,
                                                  TEST_FAMILY, IFIDX_MON, 1000));
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                  TEST_FAMILY, 0, 1000));
    ASSERT_EQ(0u, linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                  -1, IFIDX_MON, 1000));

    /* A caller bug is not a suppressed trigger, and it must not consume
     * the interface's rate-limit slot either. */
    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(0u, (unsigned)st.considered);
    ASSERT_EQ(0u, (unsigned)st.requests_built);
    ASSERT_EQ(0u, (unsigned)st.suppressed_policy);
    ASSERT_EQ(0u, (unsigned)st.suppressed_rate);

    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

static void test_stats_reset_clears_counters_and_limiter(void) {
    permit_active();
    uint8_t buf[64];
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));
    linux_wifi_scan_trigger_reset();

    wifi_scan_trigger_stats_t st = snap();
    ASSERT_EQ(0u, (unsigned)st.considered);
    ASSERT_EQ(0u, (unsigned)st.requests_built);

    /* The limiter forgot the interface too, so the same timestamp is due
     * again — otherwise a test's leftover state would leak into the next. */
    ASSERT_EQ(TRIGGER_MSG_LEN,
              (unsigned)linux_wifi_prepare_scan_trigger(buf, sizeof(buf),
                                                        TEST_FAMILY, IFIDX_MON, 1000));

    observe_reset_policy();
    linux_wifi_scan_trigger_reset();
}

void run_wifi_scan_trigger_tests(void) {
    TEST_SUITE("nl80211 scan-trigger policy + limiter (#84)");
    RUN_TEST(test_strict_builds_zero_scan_triggers);
    RUN_TEST(test_default_profile_builds_zero_scan_triggers);
    RUN_TEST(test_lock_after_opt_in_stops_further_triggers);
    RUN_TEST(test_two_interfaces_each_get_their_own_trigger);
    RUN_TEST(test_rate_limit_is_per_interface);
    RUN_TEST(test_rate_limit_reopens_after_the_interval);
    RUN_TEST(test_every_enumerated_interface_gets_a_slot);
    RUN_TEST(test_scan_trigger_request_layout);
    RUN_TEST(test_bad_args_build_nothing_and_are_not_policy_events);
    RUN_TEST(test_stats_reset_clears_counters_and_limiter);
}

#else   /* not Linux, or built without WITH_WIFI */

void run_wifi_scan_trigger_tests(void) { }

#endif
