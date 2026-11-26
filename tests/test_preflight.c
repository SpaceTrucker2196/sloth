#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "runner.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "sloth.h"
#include "preflight.h"
#include "rule_coverage.h"
#include "db.h"
#include "intel_pack.h"
#include <sqlite3.h>
#ifdef PLATFORM_LINUX
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include "platform/linux_wifi.h"
#endif

/* ── sloth --preflight (src/preflight.h, #247) ──────────────────────
 *
 * Every check is a pure function of (configuration, facts), so each
 * one is driven here by a fixture that makes it fail, and by one that
 * makes it pass. The gatherer is run against the fake platform's
 * /sys and against stand-in nl80211 and gpsd hooks, and once with
 * every output path in a fresh directory to show it writes nothing.
 * The nl80211 replies are built byte by byte from <linux/netlink.h>
 * and <linux/nl80211.h>'s layout (nlmsghdr, genlmsghdr, nlattr), not
 * produced by the code under test. */

/* NL80211_IFTYPE_STATION and _MONITOR (<linux/nl80211.h>), for the
 * fixtures that do not need the header. */
#define T_STA 2
#define T_MON 6

/* 2026-11-24 00:00 UTC, five days after the shipped pack's date. */
#define T_NOW ((time_t)1795478400)

static pf_config_t g_c;
static pf_facts_t  g_f;
static pf_result_t g_r;

/* A host with one monitor radio on phy0 and nothing wrong. */
static void base(void) {
    memset(&g_c, 0, sizeof(g_c));
    memset(&g_f, 0, sizeof(g_f));
    memset(&g_r, 0, sizeof(g_r));
    g_c.have_pcap = g_c.have_wifi = g_c.have_sqlite = 1;
    g_f.netdev_listed = 1;
    g_f.n_netdev = 2;
    snprintf(g_f.netdev[0].name, 16, "mon0");
    g_f.netdev[0].type = 803;
    snprintf(g_f.netdev[0].phy, 16, "phy0");
    g_f.netdev[0].phy_index = 0;
    g_f.netdev[0].up = 1;
    snprintf(g_f.netdev[1].name, 16, "eth0");
    g_f.netdev[1].type = 1;
    g_f.netdev[1].phy_index = -1;
    g_f.netdev[1].up = 1;
    g_f.reg_rc = 1;
    snprintf(g_f.alpha2, 3, "US");
    g_f.now = T_NOW;
    g_f.sync_known = 1;
    g_f.synced = 1;
    g_f.gps_rc = -1;
    g_f.intel_version = "1.0.1";
    g_f.intel_hash = "04f82069fb3ef588712a11f82df50b049444df1c1a9a30bce324f491e645721c";
    g_f.intel_date = "2026-11-19";
    g_f.db_current = 18;
    g_f.db_migrates_from = 1;
    g_f.db_version = -1;
    g_f.db_wal_bytes = -1;
    g_f.bt_capture_rc = -1;
}

/* The line for (check, item), NULL when there is none. */
static const pf_line_t *line(const char *check, const char *item) {
    for (int i = 0; i < g_r.n; i++)
        if (!strcmp(g_r.line[i].check, check) && !strcmp(g_r.line[i].item, item))
            return &g_r.line[i];
    return NULL;
}

static int level(const char *check, const char *item) {
    const pf_line_t *l = line(check, item);
    return l ? (int)l->level : -1;
}

static int says(const char *check, const char *item, const char *text) {
    const pf_line_t *l = line(check, item);
    return l && strstr(l->reason, text) != NULL;
}

static void run(void) { pf_run_checks(&g_c, &g_f, &g_r); }

/* ── The whole fixture is ready ──────────────────────────────────── */

static void test_clean_host_is_ready(void) {
    base();
    run();
    ASSERT_EQ(level("radios", "mon0"), PF_OK);
    ASSERT(says("radios", "mon0", "discovery would take mon0"));
    ASSERT_EQ(level("radios", "regdom"), PF_OK);
    ASSERT_EQ(level("clock", "time"), PF_OK);
    ASSERT_EQ(level("clock", "gps"), PF_NA);
    ASSERT_EQ(level("intel", "pack"), PF_OK);
    ASSERT(says("intel", "pack", "5 days old"));
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT_EQ(level("output", "notify"), PF_NA);
    ASSERT(says("output", "notify", "no notification path in sloth"));
    ASSERT_EQ(level("rules", ""), PF_OK);
    ASSERT(says("rules", "", "not measured"));
    ASSERT_EQ(pf_exit_code(&g_r), 0);
}

/* ── 1. Radios ───────────────────────────────────────────────────── */

static void test_radios_named_interfaces(void) {
    /* --iface that is not on the host: the scope cannot be enforced. */
    base();
    g_c.iface[g_c.n_iface++] = "eth9";
    run();
    ASSERT_EQ(level("radios", "eth9"), PF_FAIL);
    ASSERT(says("radios", "eth9", "exits 1"));
    ASSERT_EQ(pf_exit_code(&g_r), 2);

    /* --monitor-iface missing. */
    base();
    g_c.mon[g_c.n_mon++] = "wlan7";
    run();
    ASSERT_EQ(level("radios", "wlan7"), PF_FAIL);
    ASSERT(says("radios", "wlan7", "no fallback"));

    /* --monitor-iface present, managed, on a phy that supports
     * monitor mode: named, and not set by sloth. */
    base();
    g_f.netdev[1].type = 1;
    snprintf(g_f.netdev[1].name, 16, "wlan0");
    snprintf(g_f.netdev[1].phy, 16, "phy1");
    g_f.netdev[1].phy_index = 1;
    g_f.phy_iftypes[1] = (1u << T_STA) | (1u << T_MON);
    g_f.phy_iftypes_known[1] = 1;
    g_c.mon[g_c.n_mon++] = "wlan0";
    run();
    ASSERT_EQ(level("radios", "wlan0"), PF_FAIL);
    ASSERT(says("radios", "wlan0", "phy1 supports it"));
    ASSERT(says("radios", "wlan0", "sets no mode"));
    /* The same phy without monitor in its modes. */
    g_f.phy_iftypes[1] = 1u << T_STA;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT(says("radios", "wlan0", "does not support monitor mode"));
    /* And not readable. */
    g_f.phy_iftypes_known[1] = 0;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT(says("radios", "wlan0", "was not checked"));

    /* A --df-iface that is missing costs that radio only. */
    base();
    g_c.df[g_c.n_df++] = "wlan5";
    run();
    ASSERT_EQ(level("radios", "wlan5"), PF_WARN);
    ASSERT_EQ(pf_exit_code(&g_r), 1);
}

static void test_radios_discovery_and_regdom(void) {
    /* No interface in monitor mode at all. */
    base();
    g_f.netdev[0].type = 1;
    g_f.phy_iftypes[0] = 1u << T_MON;
    g_f.phy_iftypes_known[0] = 1;
    run();
    ASSERT_EQ(level("radios", "monitor"), PF_WARN);
    ASSERT(says("radios", "monitor", "NO_MONITOR_MODE"));
    ASSERT(says("radios", "monitor", "available on mon0"));

    base();
    snprintf(g_f.alpha2, 3, "00");
    run();
    ASSERT_EQ(level("radios", "regdom"), PF_WARN);
    base();
    g_f.reg_rc = -95;
    run();
    ASSERT_EQ(level("radios", "regdom"), PF_NOT_CHECKED);
    base();
    g_f.netdev_listed = 0;
    run();
    ASSERT_EQ(level("radios", ""), PF_NOT_CHECKED);
    base();
    g_c.replay[g_c.n_replay++] = "x.pcap";
    run();
    ASSERT_EQ(level("radios", ""), PF_NA);
    base();
    g_c.have_pcap = 0;
    run();
    ASSERT_EQ(level("radios", "monitor"), PF_NA);
}

/* ── 2. Clock ────────────────────────────────────────────────────── */

static void test_clock(void) {
    /* A day before the pack: the clock is wrong. */
    base();
    g_f.now = (time_t)pf_date_days("2026-11-18") * 86400;
    run();
    ASSERT_EQ(level("clock", "time"), PF_FAIL);
    ASSERT(says("clock", "time", "before the intel pack's date 2026-11-19"));
    /* The pack's own day is not before it. */
    base();
    g_f.now = (time_t)pf_date_days("2026-11-19") * 86400;
    run();
    ASSERT_EQ(level("clock", "time"), PF_OK);

    base();
    g_f.synced = 0;
    run();
    ASSERT_EQ(level("clock", "time"), PF_WARN);
    ASSERT(says("clock", "time", "unsynchronised"));

    base();
    g_c.gps = "gpsd://";
    g_f.gps_rc = 0;
    snprintf(g_f.gps_detail, sizeof(g_f.gps_detail), "gpsd at 127.0.0.1:2947: Connection refused");
    run();
    ASSERT_EQ(level("clock", "gps"), PF_WARN);
    ASSERT(says("clock", "gps", "refused"));
    g_f.gps_rc = 1;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("clock", "gps"), PF_OK);

    base();
    g_c.gps = "/dev/ttyACM9";
    g_f.gps_serial_rc = -1;
    run();
    ASSERT_EQ(level("clock", "gps"), PF_FAIL);
    g_f.gps_serial_rc = 0;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("clock", "gps"), PF_OK);
    ASSERT(says("clock", "gps", "not opened"));
    g_f.gps_serial_rc = -3;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("clock", "gps"), PF_NOT_CHECKED);

    ASSERT_EQ(pf_date_days("1970-01-01"), 0);
    ASSERT_EQ(pf_date_days("2026-11-19"), 20776);
    ASSERT_EQ(pf_date_days("2026-13-01"), -1);
    ASSERT_EQ(pf_date_days("2026-1-01"), -1);
    ASSERT_EQ(pf_date_days(NULL), -1);
}

/* ── 3. Storage ──────────────────────────────────────────────────── */

static pf_path_t *db_path_fixture(uint64_t free_mb, uint64_t total_mb) {
    g_c.db = "/var/lib/sloth/sloth.db";
    g_f.n_path = 1;
    pf_path_t *p = &g_f.path[0];
    memset(p, 0, sizeof(*p));
    p->what = "db";
    p->path = g_c.db;
    snprintf(p->dir, sizeof(p->dir), "/var/lib/sloth");
    p->dir_ok = p->writable = p->has_fs = 1;
    p->free_bytes = free_mb * 1024ull * 1024ull;
    p->total_bytes = total_mb * 1024ull * 1024ull;
    return p;
}

static void test_storage(void) {
    base();
    run();
    ASSERT_EQ(level("storage", ""), PF_NA);

    base();
    pf_path_t *p = db_path_fixture(5000, 10000);
    p->dir_ok = 0;
    run();
    ASSERT_EQ(level("storage", "db"), PF_FAIL);
    ASSERT(says("storage", "db", "does not exist"));

    base();
    p = db_path_fixture(50, 10000);          /* 0.5 % free */
    run();
    ASSERT_EQ(level("storage", "db"), PF_FAIL);
    base();
    p = db_path_fixture(800, 10000);         /* 8 % */
    run();
    ASSERT_EQ(level("storage", "db"), PF_WARN);
    base();
    p = db_path_fixture(5000, 10000);
    p->denied = 1;
    p->dir_ok = 0;
    run();
    ASSERT_EQ(level("storage", "db"), PF_NOT_CHECKED);

    /* The schema, file by file. */
    base();
    db_path_fixture(5000, 10000);
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_OK);
    ASSERT(says("storage", "db-schema", "new file"));

    base();
    db_path_fixture(5000, 10000);
    g_f.db_exists = 1;
    g_f.db_bytes = 4096;
    g_f.db_version = 19;
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_FAIL);
    ASSERT(says("storage", "db-schema", "newer sloth"));

    g_f.db_version = 17;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_OK);
    ASSERT(says("storage", "db-schema", "migrated to v18 at start"));

    g_f.db_version = 18;
    g_f.db_wal_bytes = 32768;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT(says("storage", "db-schema", "current"));
    ASSERT(says("storage", "db-schema", "-wal"));

    g_f.db_rc = -1;
    snprintf(g_f.db_err, sizeof(g_f.db_err), "file is not a database");
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_FAIL);
    g_f.db_rc = -2;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_NOT_CHECKED);

    base();
    db_path_fixture(5000, 10000);
    g_c.have_sqlite = 0;
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_FAIL);

    /* db.max_mb against the room left. */
    base();
    db_path_fixture(300, 100000);
    g_c.db_max_mb = 512;
    run();
    ASSERT_EQ(level("storage", "db.max_mb"), PF_WARN);
    base();
    db_path_fixture(3000, 10000);
    g_c.db_max_mb = 512;
    run();
    ASSERT_EQ(level("storage", "db.max_mb"), PF_OK);
}

/* ── 4. Intel pack ───────────────────────────────────────────────── */

static void test_intel(void) {
    base();
    g_f.now = (time_t)(pf_date_days("2026-11-19") + 91) * 86400;
    run();
    ASSERT_EQ(level("intel", "pack"), PF_WARN);
    ASSERT(says("intel", "pack", "91 days old"));
    base();
    g_f.now = (time_t)(pf_date_days("2026-11-19") + 90) * 86400;
    run();
    ASSERT_EQ(level("intel", "pack"), PF_OK);
    base();
    g_f.intel_date = "2026-xx-19";
    run();
    ASSERT_EQ(level("intel", "pack"), PF_WARN);
    /* The binary's own: version, hash and date from intel/LOCK. */
    ASSERT_EQ(pf_date_days(intel_pack_date()) > 0, 1);
}

/* ── 5. Sources ──────────────────────────────────────────────────── */

static void test_sources(void) {
    base();
    run();
    ASSERT_EQ(level("sources", ""), PF_NA);

    base();
    g_c.bt_capture = "/run/sloth-ubt/ubt.fifo";
    g_f.bt_capture_rc = -1;
    run();
    ASSERT_EQ(level("sources", "btcap"), PF_FAIL);
    g_f.bt_capture_rc = -2;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("sources", "btcap"), PF_FAIL);
    g_f.bt_capture_rc = 0;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("sources", "btcap"), PF_OK);
    g_f.bt_capture_rc = -3;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("sources", "btcap"), PF_NOT_CHECKED);

    base();
    g_c.bt_monitor = 1;
    g_f.bt_controllers = 0;
    run();
    ASSERT_EQ(level("sources", "btmon"), PF_WARN);
    g_f.bt_controllers = 1;
    memset(&g_r, 0, sizeof(g_r));
    run();
    ASSERT_EQ(level("sources", "btmon"), PF_OK);

    base();
    g_c.replay[g_c.n_replay++] = "/nowhere.pcap";
    g_f.replay_rc[0] = -1;
    run();
    ASSERT_EQ(level("sources", "replay"), PF_FAIL);
}

/* ── 6. Host ─────────────────────────────────────────────────────── */

static void test_host(void) {
    base();
    run();
    ASSERT_EQ(level("host", "undervolt"), PF_NA);
    ASSERT_EQ(level("host", "temperature"), PF_NA);

    base();
    g_f.has_undervolt = 1;
    g_f.undervolt = 1;
    g_f.has_temp = 1;
    g_f.hottest_c = 85.0;
    snprintf(g_f.hottest_label, sizeof(g_f.hottest_label), "cpu_thermal");
    run();
    ASSERT_EQ(level("host", "undervolt"), PF_WARN);
    ASSERT_EQ(level("host", "temperature"), PF_WARN);
    base();
    g_f.has_undervolt = 1;
    g_f.has_temp = 1;
    g_f.hottest_c = 55.0;
    run();
    ASSERT_EQ(level("host", "undervolt"), PF_OK);
    ASSERT_EQ(level("host", "temperature"), PF_OK);

    /* The passive contract: a managed interface on the monitor radio's
     * phy transmits through it. */
    base();
    snprintf(g_f.netdev[1].name, 16, "wlan0");
    snprintf(g_f.netdev[1].phy, 16, "phy0");
    g_f.netdev[1].phy_index = 0;
    run();
    ASSERT_EQ(level("host", "passive"), PF_WARN);
    ASSERT(says("host", "passive", "wlan0 (phy0, beside mon0, up)"));

    /* A named radio not in monitor mode is not opened (sloth sets no
     * mode): check 1 fails it, and the passive line has no radio to
     * judge. */
    base();
    g_c.mon[g_c.n_mon++] = "eth0";
    run();
    ASSERT_EQ(level("radios", "eth0"), PF_FAIL);
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT(says("host", "passive", "no 802.11 interface would be opened"));

    /* Opt-ins that send are named, not failed. */
    base();
    g_c.allow_active = 1;
    g_c.data_socket_remote = 1;
    run();
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT(says("host", "passive", "--allow-active"));
    ASSERT(says("host", "passive", "routable --data-socket"));
}

/* ── 7. Output ───────────────────────────────────────────────────── */

static void test_output(void) {
    base();
    g_c.data_socket = "unix:/run/nowhere/sloth.sock";
    g_f.sock_dir_rc = -1;
    run();
    ASSERT_EQ(level("output", "socket"), PF_FAIL);
    base();
    g_c.data_socket = "tcp:127.0.0.1:8765";
    g_f.sock_dir_rc = 1;
    run();
    ASSERT_EQ(level("output", "socket"), PF_NOT_CHECKED);
    ASSERT(says("output", "socket", "binds nothing"));
    ASSERT_EQ(level("output", "notify"), PF_NA);
    /* #244: --notify-priority is sloth's one notification path, local. */
    base();
    g_c.notify_priority = 1;
    run();
    ASSERT_EQ(level("output", "notify"), PF_OK);
    ASSERT(says("output", "notify", "--notify-priority 1: a site question of priority 1 "
                                    "that turns to a finding is a line on stderr"));
    ASSERT(says("output", "notify", "local only"));
}

/* ── 8. Rule status ──────────────────────────────────────────────── */

static void test_rules_expectation(void) {
    /* No monitor radio: every 802.11 rule blind, for want of a source. */
    base();
    g_f.netdev[0].type = 1;
    run();
    int dot11 = 0, blind_dot11 = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const cov_inputs_t *in = cov_inputs((alert_type_t)t);
        if (!cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t) || !in ||
            in->input != COV_IN_DOT11) continue;
        dot11++;
        if (g_r.st[t] == COV_BLIND && g_r.why[t] == COV_R_NO_SOURCE) blind_dot11++;
    }
    ASSERT_GT(dot11, 20);
    ASSERT_EQ(blind_dot11, dot11);
    ASSERT_EQ(g_r.observable + g_r.partly + g_r.blind > dot11, 1);

    /* --hop on 1, 6 and 11 only: a handshake rule reads partly (off the
     * channel for most of the exchange), a DFS rule blind (no radio in
     * its band). */
    base();
    g_c.hop = 1;
    g_c.n_hop = 3;
    g_c.hop_mhz[0] = 2412;
    g_c.hop_mhz[1] = 2437;
    g_c.hop_mhz[2] = 2462;
    run();
    ASSERT_EQ(g_r.st[ALERT_TYPE_HANDSHAKE_HARVEST], COV_PARTLY);
    ASSERT_EQ(g_r.why[ALERT_TYPE_HANDSHAKE_HARVEST], COV_R_HOP);
    ASSERT_EQ(g_r.st[ALERT_TYPE_DFS_MASKING], COV_BLIND);
    ASSERT_EQ(g_r.why[ALERT_TYPE_DFS_MASKING], COV_R_BAND);
    ASSERT_EQ(g_r.env.channels, 3);
    ASSERT_EQ(g_r.env.hopping, 1);

    /* A named radio that is not there: blind because a configured source
     * would not deliver - which the preflight warns about. */
    base();
    g_c.mon[g_c.n_mon++] = "wlan7";
    run();
    ASSERT_EQ(g_r.env.input[COV_IN_DOT11], COV_AV_DOWN);
    ASSERT_EQ(g_r.st[ALERT_TYPE_HANDSHAKE_HARVEST], COV_BLIND);
    ASSERT_EQ(g_r.why[ALERT_TYPE_HANDSHAKE_HARVEST], COV_R_SOURCE_DOWN);
    ASSERT_EQ(level("rules", ""), PF_WARN);

    /* --my-ssid and --db reach the needs. */
    base();
    g_c.config = COV_N_OWN_NET;
    g_c.db = "/x/s.db";
    run();
    ASSERT_EQ((int)(g_r.env.config & (COV_N_OWN_NET | COV_N_DB)), (int)(COV_N_OWN_NET | COV_N_DB));

    /* A replay is not assessed. */
    base();
    g_c.replay[g_c.n_replay++] = "a.pcap";
    run();
    ASSERT_EQ(g_r.assessed, 0);
    ASSERT_EQ(level("rules", ""), PF_NA);
}

/* ── Exit codes and the two printers ────────────────────────────── */

static char *render(int json) {
    static char buf[65536];
    FILE *fp = tmpfile();
    buf[0] = '\0';
    if (!fp) return buf;
    if (json) pf_print_json(&g_r, fp);
    else pf_print_text(&g_r, fp);
    rewind(fp);
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static void test_exit_codes_and_output(void) {
    base();
    run();
    ASSERT_EQ(pf_exit_code(&g_r), 0);
    ASSERT(strstr(render(0), "ready (exit 0)") != NULL);
    char *j = render(1);
    ASSERT(strstr(j, "\"exit\":0,\"verdict\":\"ready\"") != NULL);
    ASSERT(strstr(j, "\"expectation\":true") != NULL);
    ASSERT(strstr(j, "\"level\":\"na\"") != NULL);
    ASSERT_EQ(j[strlen(j) - 1], '\n');
    ASSERT(strchr(j, '\n') == j + strlen(j) - 1);    /* one line */

    base();
    g_f.synced = 0;                               /* one warning */
    run();
    ASSERT_EQ(pf_exit_code(&g_r), 1);
    ASSERT(strstr(render(0), "ready with warnings (exit 1)") != NULL);
    ASSERT(strstr(render(1), "\"verdict\":\"ready_with_warnings\"") != NULL);

    base();
    g_f.synced = 0;
    g_c.iface[g_c.n_iface++] = "eth9";            /* and one failure */
    run();
    ASSERT_EQ(pf_exit_code(&g_r), 2);
    ASSERT(strstr(render(0), "not ready (exit 2)") != NULL);

    /* A reason with a quote and a control byte stays one JSON string. */
    base();
    g_c.bt_capture = "/tmp/a\"b\nc";
    g_f.bt_capture_rc = -1;
    run();
    j = render(1);
    ASSERT(strstr(j, "a\\\"b\\u000ac") != NULL);
    ASSERT(strchr(j, '\n') == j + strlen(j) - 1);
}

/* ── The gatherer, against the fake platform ────────────────────── */

static int fk_reg(char a2[3]) { a2[0] = 'D'; a2[1] = 'E'; a2[2] = '\0'; return 1; }
static int fk_iftypes(int phy, unsigned *mask) {
    *mask = phy == 1 ? (1u << 2) | (1u << 6) : (1u << 2);
    return 1;
}
static int g_gpsd_calls;
static int fk_gpsd(const char *host, int port, int t, char *d, size_t n) {
    (void)t;
    g_gpsd_calls++;
    snprintf(d, n, "fake gpsd at %s:%d", host, port);
    return 1;
}
static int fk_sync(int *s) { *s = 1; return 0; }
static const pf_ops_t g_fake_ops = { fk_reg, fk_iftypes, fk_gpsd, fk_sync };

static void test_gather_reads_sysfs(void) {
    fake_net_reset();
    fake_sys_put("/sys/class/net/wlan1/type", "803\n");
    fake_sys_put("/sys/class/net/wlan1/phy80211/name", "phy1\n");
    fake_sys_put("/sys/class/net/wlan1/phy80211/index", "1\n");
    fake_sys_put("/sys/class/net/eth0/type", "1\n");
    fake_sys_put("/sys/class/bluetooth/hci0/type", "Primary\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/name", "rpi_volt\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/in0_lcrit_alarm", "1\n");
    fake_sys_put("/sys/class/thermal/thermal_zone0/temp", "71500\n");
    fake_sys_put("/sys/class/thermal/thermal_zone0/type", "cpu-thermal\n");
    memset(&g_c, 0, sizeof(g_c));
    g_c.have_pcap = g_c.have_wifi = 1;
    g_c.bt_monitor = 1;
    g_c.gps = "gpsd://";
    g_gpsd_calls = 0;
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    ASSERT_EQ(g_f.netdev_listed, 1);
    ASSERT_EQ(g_f.n_netdev, 2);
    int w = -1;
    for (int i = 0; i < g_f.n_netdev; i++)
        if (!strcmp(g_f.netdev[i].name, "wlan1")) w = i;
    ASSERT(w >= 0);
    if (w < 0) return;
    ASSERT_EQ(g_f.netdev[w].type, 803);
    ASSERT_STR(g_f.netdev[w].phy, "phy1");
    ASSERT_EQ(g_f.netdev[w].phy_index, 1);
    ASSERT_EQ(g_f.phy_iftypes_known[w], 1);
    ASSERT_EQ((int)((g_f.phy_iftypes[w] >> 6) & 1u), 1);
    ASSERT_EQ(g_f.reg_rc, 1);
    ASSERT_STR(g_f.alpha2, "DE");
    ASSERT_EQ(g_f.bt_controllers, 1);
    ASSERT_EQ(g_f.has_undervolt, 1);
    ASSERT_EQ(g_f.undervolt, 1);
    ASSERT_EQ(g_f.has_temp, 1);
    ASSERT_NEAR(g_f.hottest_c, 71.5, 0.01);
    ASSERT_EQ(g_gpsd_calls, 1);
    ASSERT_EQ(g_f.gps_rc, 1);
    ASSERT_STR(g_f.intel_date, intel_pack_date());

    /* A gpsd off loopback is not dialled. */
    g_c.gps = "gpsd://192.0.2.7:2947";
    g_gpsd_calls = 0;
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    ASSERT_EQ(g_gpsd_calls, 0);
    ASSERT_EQ(g_f.gps_rc, -1);
    fake_net_reset();
}

/* ── The gpsd probe sends nothing ────────────────────────────────────
 *
 * A loopback listener in a child process plays gpsd: it greets with a
 * VERSION line, as gpsd does on every connect, then counts the bytes
 * the probe sends until it closes, and exits with that count. The real
 * probe (preflight_default_ops()) must read the greeting and send none.
 * Seen red with a send() of GPSD_WATCH_LINE added after the connect. */
static void test_gpsd_probe_reads_and_sends_nothing(void) {
    int ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT(ls >= 0);
    if (ls < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    int ok = bind(ls, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(ls, 1) == 0 &&
             getsockname(ls, (struct sockaddr *)&a, &al) == 0;
    ASSERT(ok);
    if (!ok) { close(ls); return; }
    fflush(NULL);
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid < 0) { close(ls); return; }
    if (pid == 0) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) _exit(200);
        static const char hello[] =
            "{\"class\":\"VERSION\",\"release\":\"3.25\",\"proto_major\":3}\n";
        if (write(c, hello, sizeof(hello) - 1) != (ssize_t)(sizeof(hello) - 1)) _exit(201);
        int got = 0;
        for (;;) {
            struct pollfd p = { c, POLLIN, 0 };
            if (poll(&p, 1, 3000) <= 0) _exit(202);
            char b[256];
            ssize_t n = read(c, b, sizeof(b));
            if (n <= 0) break;
            got += (int)n;
        }
        _exit(got > 199 ? 199 : got);
    }
    close(ls);
    char detail[240];
    int rc = preflight_default_ops()->gpsd("127.0.0.1", ntohs(a.sin_port), 1500,
                                           detail, sizeof(detail));
    int st = 0;
    waitpid(pid, &st, 0);
    ASSERT_EQ(rc, 1);
    ASSERT(strstr(detail, "release 3.25") != NULL);
    ASSERT(WIFEXITED(st));
    if (WEXITSTATUS(st) != 0)
        fprintf(stderr, "    gpsd stand-in received %d bytes\n", WEXITSTATUS(st));
    ASSERT_EQ(WEXITSTATUS(st), 0);
}

/* ── It writes nothing ──────────────────────────────────────────────
 *
 * Every output path of the command line in one fresh directory, with a
 * real sloth database already in it (WAL mode, as db_open() leaves
 * every file), then the gatherer, the checks and both printers. The
 * directory must hold exactly what it held before: no -wal or -shm
 * beside the database, no JSONL, report, pcap or eapol directory, no
 * socket. Seen red with db_probe_version() opening `mode=ro` without
 * `immutable=1` (a -shm and a -wal appear beside the file), and with
 * add_path() creating --pcap-dir. */

static int list_dir(const char *dir, char out[][64], int max) {
    DIR *d = opendir(dir);
    int n = 0;
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(out[n++], 64, "%.63s", e->d_name);
    }
    closedir(d);
    return n;
}

static void test_preflight_writes_nothing(void) {
    char dir[TEST_TMP_MAX] = "";
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_pf_XXXXXX")) != NULL);
    if (!dir[0]) return;
    char p[8][TEST_TMP_MAX + 32];
    static const char *const nm[8] = { "s.db", "out.jsonl", "pcap", "eapol",
                                       "r.md", "r.json", "snap.txt", "sock" };
    for (int i = 0; i < 8; i++) snprintf(p[i], sizeof(p[i]), "%s/%s", dir, nm[i]);

    /* The existing database: a real one, closed again. */
    ASSERT_EQ(db_open(p[0]), 1);
    db_close();
    struct stat sb0;
    ASSERT_EQ(stat(p[0], &sb0), 0);

    char before[16][64], after[16][64];
    int nb = list_dir(dir, before, 16);
    ASSERT_EQ(nb, 1);

    char sock[TEST_TMP_MAX + 40];
    snprintf(sock, sizeof(sock), "unix:%s", p[7]);
    memset(&g_c, 0, sizeof(g_c));
    g_c.have_pcap = g_c.have_wifi = g_c.have_sqlite = 1;
    g_c.db = p[0];
    g_c.jsonl = p[1];
    g_c.pcap_dir = p[2];
    g_c.eapol_dir = p[3];
    g_c.report_md = p[4];
    g_c.report_json = p[5];
    g_c.snapshot_out = p[6];
    g_c.data_socket = sock;
    g_c.gps = "gpsd://";
    g_c.db_max_mb = 512;
    fake_net_reset();
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    pf_run_checks(&g_c, &g_f, &g_r);
    FILE *null = fopen("/dev/null", "w");
    ASSERT(null != NULL);
    if (null) {
        pf_print_text(&g_r, null);
        pf_print_json(&g_r, null);
        fclose(null);
    }
    /* It did read the file it must not touch. */
    ASSERT_EQ(g_f.db_rc, 0);
    ASSERT_EQ(g_f.db_version, DB_SCHEMA_VERSION);
    ASSERT_EQ(level("storage", "db-schema"), PF_OK);
    ASSERT_EQ(level("storage", "pcap-dir"), PF_OK);
    ASSERT(says("storage", "pcap-dir", "created at start"));
    ASSERT_EQ(level("output", "socket"), PF_OK);

    int na = list_dir(dir, after, 16);
    ASSERT_EQ(na, nb);
    for (int i = 0; i < na; i++) {
        if (strcmp(after[i], "s.db") != 0)
            fprintf(stderr, "    preflight left %s in %s\n", after[i], dir);
        ASSERT_STR(after[i], "s.db");
    }
    struct stat sb1;
    ASSERT_EQ(stat(p[0], &sb1), 0);
    ASSERT_EQ((long long)sb1.st_size, (long long)sb0.st_size);
    ASSERT_EQ((long long)sb1.st_mtime, (long long)sb0.st_mtime);
    test_rm_tree(dir);
    fake_net_reset();
}

/* ── The two nl80211 parsers (src/platform/linux_wifi.h) ────────── */

#ifdef PLATFORM_LINUX
#define FAM 0x1c

typedef struct { uint8_t b[512]; size_t n; } nlbuf_t;

static void put16(uint8_t *p, unsigned v) { memcpy(p, &(uint16_t){ (uint16_t)v }, 2); }
static void put32(uint8_t *p, unsigned v) { memcpy(p, &(uint32_t){ (uint32_t)v }, 4); }

/* nlmsghdr (16) + genlmsghdr (4), its length fixed up by msg_end(). */
static size_t msg_begin(nlbuf_t *m, unsigned type, unsigned cmd) {
    size_t at = m->n;
    memset(m->b + at, 0, 20);
    put16(m->b + at + 4, type);
    m->b[at + 16] = (uint8_t)cmd;
    m->b[at + 17] = 1;
    m->n += 20;
    return at;
}
static void msg_end(nlbuf_t *m, size_t at) { put32(m->b + at, (unsigned)(m->n - at)); }
/* One attribute, padded to four bytes. */
static size_t attr(nlbuf_t *m, unsigned type, const void *data, size_t len) {
    size_t at = m->n;
    put16(m->b + at, (unsigned)(4 + len));
    put16(m->b + at + 2, type);
    if (len) memcpy(m->b + at + 4, data, len);
    m->n += (4 + len + 3) & ~(size_t)3;
    return at;
}

static void test_nl80211_parsers(void) {
    nlbuf_t m;
    char a2[3];
    /* GET_REG reply carrying "GB\0". */
    memset(&m, 0, sizeof(m));
    size_t h = msg_begin(&m, FAM, NL80211_CMD_GET_REG);
    attr(&m, NL80211_ATTR_REG_ALPHA2, "GB", 3);
    msg_end(&m, h);
    ASSERT_EQ(linux_wifi_parse_reg(m.b, m.n, FAM, a2), 1);
    ASSERT_STR(a2, "GB");
    /* Another family's message is not read. */
    ASSERT_EQ(linux_wifi_parse_reg(m.b, m.n, FAM + 1, a2), 0);
    /* Truncated: the attribute claims more than the buffer holds. */
    ASSERT_EQ(linux_wifi_parse_reg(m.b, m.n - 4, FAM, a2), 0);
    /* A one-byte code is not a code. */
    memset(&m, 0, sizeof(m));
    h = msg_begin(&m, FAM, NL80211_CMD_GET_REG);
    attr(&m, NL80211_ATTR_REG_ALPHA2, "G", 1);
    msg_end(&m, h);
    ASSERT_EQ(linux_wifi_parse_reg(m.b, m.n, FAM, a2), 0);
    /* NLMSG_ERROR carries the kernel's errno. */
    memset(&m, 0, sizeof(m));
    put32(m.b, 36);
    put16(m.b + 4, NLMSG_ERROR);
    put32(m.b + 16, (unsigned)-EPERM);
    m.n = 36;
    ASSERT_EQ(linux_wifi_parse_reg(m.b, m.n, FAM, a2), -EPERM);

    /* NEW_WIPHY with SUPPORTED_IFTYPES {station, monitor}, after an
     * unrelated attribute. */
    unsigned mask = 99;
    memset(&m, 0, sizeof(m));
    h = msg_begin(&m, FAM, NL80211_CMD_NEW_WIPHY);
    uint32_t idx = 3;
    attr(&m, NL80211_ATTR_WIPHY, &idx, 4);
    size_t nest = attr(&m, NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED, NULL, 0);
    attr(&m, NL80211_IFTYPE_STATION, NULL, 0);
    attr(&m, NL80211_IFTYPE_MONITOR, NULL, 0);
    put16(m.b + nest, (unsigned)(m.n - nest));
    msg_end(&m, h);
    ASSERT_EQ(linux_wifi_parse_iftypes(m.b, m.n, FAM, &mask), 1);
    ASSERT_EQ(mask, (1u << NL80211_IFTYPE_STATION) | (1u << NL80211_IFTYPE_MONITOR));
    /* A wiphy that lists no modes. */
    memset(&m, 0, sizeof(m));
    h = msg_begin(&m, FAM, NL80211_CMD_NEW_WIPHY);
    attr(&m, NL80211_ATTR_WIPHY, &idx, 4);
    msg_end(&m, h);
    ASSERT_EQ(linux_wifi_parse_iftypes(m.b, m.n, FAM, &mask), 0);
    ASSERT_EQ(mask, 0u);
    /* The GET_REG reply is not a wiphy. */
    memset(&m, 0, sizeof(m));
    h = msg_begin(&m, FAM, NL80211_CMD_GET_REG);
    attr(&m, NL80211_ATTR_REG_ALPHA2, "GB", 3);
    msg_end(&m, h);
    ASSERT_EQ(linux_wifi_parse_iftypes(m.b, m.n, FAM, &mask), 0);
}
#endif


/* ── Review fixes (dcb741a1) ─────────────────────────────────────── */

/* A managed wlan0 on phy1, which supports monitor mode. */
static void add_managed_wlan0(const char *phy, int up) {
    int i = g_f.n_netdev++;
    memset(&g_f.netdev[i], 0, sizeof(g_f.netdev[i]));
    snprintf(g_f.netdev[i].name, 16, "wlan0");
    g_f.netdev[i].type = 1;
    snprintf(g_f.netdev[i].phy, 16, "%s", phy);
    g_f.netdev[i].phy_index = phy[3] - '0';
    g_f.netdev[i].up = up;
    g_f.phy_iftypes[i] = (1u << T_STA) | (1u << T_MON);
    g_f.phy_iftypes_known[i] = 1;
}

/* --monitor-only with no monitor radio: capture_scope_verdict() refuses
 * (CAPTURE_SCOPE_REFUSE_NO_MONITOR) and main.c exits 1, so the page
 * fails. Seen red with the monitor-only line removed (exit 1, "ready
 * with warnings"). */
static void test_monitor_only_without_radio_fails(void) {
    base();
    g_f.netdev[0].type = 1;                     /* no monitor interface */
    g_c.monitor_only = 1;
    run();
    ASSERT_EQ(level("radios", "monitor-only"), PF_FAIL);
    ASSERT(says("radios", "monitor-only", "exit 1"));
    ASSERT_EQ(pf_exit_code(&g_r), 2);
    /* A named radio not in monitor mode, and a build with no libpcap. */
    base();
    add_managed_wlan0("phy1", 1);
    g_c.mon[g_c.n_mon++] = "wlan0";
    g_c.monitor_only = 1;
    run();
    ASSERT_EQ(level("radios", "monitor-only"), PF_FAIL);
    base();
    g_c.have_pcap = 0;
    g_c.monitor_only = 1;
    run();
    ASSERT_EQ(level("radios", "monitor-only"), PF_FAIL);
    /* With a radio it is not there at all. */
    base();
    g_c.monitor_only = 1;
    run();
    ASSERT_EQ(level("radios", "monitor-only"), -1);
    ASSERT_EQ(pf_exit_code(&g_r), 0);
}

/* A --df-iface or a further --monitor-iface that is not in monitor mode
 * is left out at run time (main.c), not put in monitor mode: it costs
 * that radio (warn in check 1), and the passive line does not fail.
 * Seen red with the old "not in monitor mode: sloth would have to
 * change its mode" fail restored for every named interface. */
static void test_passive_ignores_radios_left_out(void) {
    base();
    add_managed_wlan0("phy1", 1);
    g_c.df[g_c.n_df++] = "wlan0";
    run();
    ASSERT_EQ(level("radios", "wlan0"), PF_WARN);
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT_EQ(pf_exit_code(&g_r), 1);

    base();
    add_managed_wlan0("phy1", 1);
    g_c.mon[g_c.n_mon++] = "mon0";
    g_c.mon[g_c.n_mon++] = "wlan0";
    run();
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT_EQ(level("host", "passive") == PF_FAIL, 0);

    /* A named radio that is not on the host is not described as one
     * in monitor mode: nothing would be opened. */
    base();
    g_c.mon[g_c.n_mon++] = "wlan7";
    run();
    ASSERT(says("host", "passive", "no 802.11 interface would be opened"));
    ASSERT(!says("host", "passive", "every 802.11 interface"));
    /* And a missing --df-iface beside a real radio is not counted. */
    base();
    g_c.df[g_c.n_df++] = "wlan7";
    run();
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT(!says("host", "passive", "wlan7"));
}

/* An interface on the radio's phy that is down transmits nothing; one
 * that is up, or whose state cannot be read, may. Seen red with the
 * up test removed (a down wlan0 warned "transmits"). */
static void test_passive_shared_phy_up_or_down(void) {
    base();
    add_managed_wlan0("phy0", 0);
    run();
    ASSERT_EQ(level("host", "passive"), PF_OK);
    ASSERT(says("host", "passive", "down on a radio's phy, so not transmitting: wlan0"));
    ASSERT_EQ(pf_exit_code(&g_r), 0);

    base();
    add_managed_wlan0("phy0", 1);
    run();
    ASSERT_EQ(level("host", "passive"), PF_WARN);
    ASSERT(says("host", "passive", "wlan0 (phy0, beside mon0, up)"));

    base();
    add_managed_wlan0("phy0", -1);
    run();
    ASSERT_EQ(level("host", "passive"), PF_WARN);
    ASSERT(says("host", "passive", "up or down not readable"));

    /* The ok line says what it did not check. */
    base();
    run();
    ASSERT(says("host", "passive", "active flag"));
    ASSERT(says("host", "passive", "Not checked"));
}

/* A listing cut at PF_MAX_NETDEV is reported, and the passive line does
 * not claim the radio is alone on its phy. Seen red with the truncated
 * branch removed (passive read ok). */
static void test_truncated_listing_is_reported(void) {
    base();
    g_f.netdev_truncated = 1;
    run();
    ASSERT_EQ(level("radios", "netdevs"), PF_NOT_CHECKED);
    ASSERT_EQ(level("host", "passive"), PF_NOT_CHECKED);
    ASSERT(!says("host", "passive", "no interface that is up shares"));
}

/* The gatherer on a host with more netdevs than it lists: the cut is
 * known, and a named interface past it is found by its own path, not
 * reported missing. Seen red with add_named() made a no-op (the radio
 * read "not on this host"). Also the up flag from .../flags. */
static void test_gather_past_the_netdev_cut(void) {
    fake_net_reset();
    char path[96];
    int ok = 1;
    for (int i = 0; i < PF_MAX_NETDEV + 2 && ok; i++) {
        snprintf(path, sizeof(path), "/sys/class/net/v%03d/type", i);
        ok = fake_sys_put(path, "1\n") == 0;
    }
    ASSERT(ok);
    ok = fake_sys_put("/sys/class/net/zmon/type", "803\n") == 0 &&
         fake_sys_put("/sys/class/net/zmon/flags", "0x1003\n") == 0 &&
         fake_sys_put("/sys/class/net/v000/flags", "0x1002\n") == 0;
    ASSERT(ok);
    memset(&g_c, 0, sizeof(g_c));
    g_c.have_pcap = g_c.have_wifi = 1;
    g_c.mon[g_c.n_mon++] = "zmon";
    g_c.iface[g_c.n_iface++] = "nope0";
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    ASSERT_EQ(g_f.netdev_truncated, 1);
    int zi = -1, v0 = -1;
    for (int i = 0; i < g_f.n_netdev; i++) {
        if (!strcmp(g_f.netdev[i].name, "zmon")) zi = i;
        if (!strcmp(g_f.netdev[i].name, "v000")) v0 = i;
    }
    ASSERT(zi >= PF_MAX_NETDEV);
    if (zi >= 0) ASSERT_EQ(g_f.netdev[zi].up, 1);
    if (v0 >= 0) ASSERT_EQ(g_f.netdev[v0].up, 0);
    if (v0 >= 0 && v0 + 1 < g_f.n_netdev) ASSERT_EQ(g_f.netdev[v0 + 1].up, -1);
    pf_run_checks(&g_c, &g_f, &g_r);
    ASSERT_EQ(level("radios", "zmon"), PF_OK);
    ASSERT_EQ(level("radios", "nope0"), PF_FAIL);
    fake_net_reset();
}

/* Every --iface main.c accepts reaches the checks. */
static void test_iface_names_past_sixteen(void) {
    static char names[PF_MAX_IFACE][16];
    base();
    for (int i = 0; i < PF_MAX_IFACE; i++) {
        snprintf(names[i], sizeof(names[i]), i == PF_MAX_IFACE - 1 ? "eth9" : "eth0");
        g_c.iface[g_c.n_iface++] = names[i];
    }
    run();
    ASSERT_EQ(level("radios", "eth9"), PF_FAIL);
    ASSERT_EQ(pf_exit_code(&g_r), 2);
}

/* Output paths the run refuses at start (src/secure_file.h): an
 * existing permissive or symlinked file, a permissive directory, and
 * --pcap-dir and --eapol-dir naming one directory. Seen red with the
 * refused branch removed from pf_check_storage() (each read ok). */
static void test_storage_paths_the_run_refuses(void) {
    char dir[TEST_TMP_MAX] = "";
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_pfs_XXXXXX")) != NULL);
    if (!dir[0]) return;
    char open_f[TEST_TMP_MAX + 32], priv_f[TEST_TMP_MAX + 32], link_f[TEST_TMP_MAX + 32],
         wide_d[TEST_TMP_MAX + 32], priv_d[TEST_TMP_MAX + 32];
    snprintf(open_f, sizeof(open_f), "%s/open.jsonl", dir);
    snprintf(priv_f, sizeof(priv_f), "%s/priv.md", dir);
    snprintf(link_f, sizeof(link_f), "%s/link.json", dir);
    snprintf(wide_d, sizeof(wide_d), "%s/wide", dir);
    snprintf(priv_d, sizeof(priv_d), "%s/priv", dir);
    FILE *fp = fopen(open_f, "w");
    if (fp) fclose(fp);
    fp = fopen(priv_f, "w");
    if (fp) fclose(fp);
    int ok = chmod(open_f, 0644) == 0 && chmod(priv_f, 0600) == 0 &&
             symlink(priv_f, link_f) == 0 && mkdir(wide_d, 0700) == 0 &&
             chmod(wide_d, 0755) == 0 && mkdir(priv_d, 0700) == 0;
    ASSERT(ok);

    memset(&g_c, 0, sizeof(g_c));
    g_c.have_pcap = g_c.have_wifi = g_c.have_sqlite = 1;
    g_c.jsonl = open_f;
    g_c.report_md = priv_f;
    g_c.report_json = link_f;
    g_c.pcap_dir = wide_d;
    g_c.eapol_dir = priv_d;
    fake_net_reset();
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    memset(&g_r, 0, sizeof(g_r));
    pf_run_checks(&g_c, &g_f, &g_r);
    ASSERT_EQ(level("storage", "jsonl"), PF_FAIL);
    ASSERT(says("storage", "jsonl", "group/other"));
    ASSERT_EQ(level("storage", "report-json"), PF_FAIL);
    ASSERT(says("storage", "report-json", "symbolic link"));
    ASSERT_EQ(level("storage", "pcap-dir"), PF_FAIL);
    ASSERT_EQ(level("storage", "report") == PF_FAIL, 0);
    ASSERT_EQ(level("storage", "eapol-dir") == PF_FAIL, 0);
    ASSERT_EQ(level("storage", "pcap-eapol"), -1);

    /* One directory for both, by a second spelling. */
    char again[TEST_TMP_MAX + 40];
    snprintf(again, sizeof(again), "%s/./priv", dir);
    g_c.pcap_dir = priv_d;
    g_c.eapol_dir = again;
    preflight_gather(&g_c, &g_fake_ops, &g_f);
    memset(&g_r, 0, sizeof(g_r));
    pf_run_checks(&g_c, &g_f, &g_r);
    ASSERT_EQ(level("storage", "pcap-eapol"), PF_FAIL);
    ASSERT(says("storage", "pcap-eapol", "exits 2"));
    test_rm_tree(dir);
    fake_net_reset();

    /* Owned by another account: the run's account decides, so warn. */
    base();
    pf_path_t *p = db_path_fixture(5000, 10000);
    p->foreign = 1;
    p->owner_uid = 4242;
    run();
    ASSERT_EQ(level("storage", "db"), PF_WARN);
    ASSERT(says("storage", "db", "uid 4242"));
}

/* A schema_version row that holds no version is refused by db_open()'s
 * check_version(); the probe tells it from a missing row. Seen red with
 * the probe's old mapping (0 -> -1, "no version row", ok). */
static void test_db_version_row_without_a_version(void) {
    char dir[TEST_TMP_MAX] = "";
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_pfd_XXXXXX")) != NULL);
    if (!dir[0]) return;
    char db[TEST_TMP_MAX + 16];
    snprintf(db, sizeof(db), "%s/s.db", dir);
    ASSERT_EQ(db_open(db), 1);
    db_close();
    sqlite3 *h = NULL;
    int ok = sqlite3_open(db, &h) == SQLITE_OK &&
             sqlite3_exec(h, "PRAGMA journal_mode=DELETE;"
                          "UPDATE meta SET value='x' WHERE key='schema_version'",
                          NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(h);
    ASSERT(ok);
    int ver = 99;
    char err[160];
    ASSERT_EQ(db_probe_version(db, &ver, err, sizeof(err)), 0);
    ASSERT_EQ(ver, 0);
    h = NULL;
    ok = sqlite3_open(db, &h) == SQLITE_OK &&
         sqlite3_exec(h, "DELETE FROM meta WHERE key='schema_version'",
                      NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(h);
    ASSERT(ok);
    ASSERT_EQ(db_probe_version(db, &ver, err, sizeof(err)), 0);
    ASSERT_EQ(ver, -1);
    test_rm_tree(dir);

    base();
    db_path_fixture(5000, 10000);
    g_f.db_exists = 1;
    g_f.db_bytes = 4096;
    g_f.db_version = 0;
    run();
    ASSERT_EQ(level("storage", "db-schema"), PF_FAIL);
    ASSERT(says("storage", "db-schema", "holds no version"));
}

/* A path that is not UTF-8 still prints valid JSON (RFC 8259 section
 * 8.1): each stray byte becomes U+FFFD, well-formed UTF-8 passes. Seen
 * red with the high-byte branch removed (the raw 0xff reached the
 * output). */
static void test_json_is_utf8(void) {
    base();
    g_c.bt_capture = "/tmp/\xff\xc0\x80-\xc3\xa9-\xed\xa0\x80";
    g_f.bt_capture_rc = -1;
    run();
    const char *j = render(1);
    int high_ok = 1;
    for (const unsigned char *q = (const unsigned char *)j; *q; q++)
        if (*q == 0xff || *q == 0xc0 || *q == 0xed) high_ok = 0;
    ASSERT(high_ok);
    ASSERT(strstr(j, "/tmp/\\ufffd\\ufffd\\ufffd-\xc3\xa9-\\ufffd\\ufffd\\ufffd") != NULL);
}

/* ── #251: evidence kept on a disk with no dm-crypt ─────────────── */

/* The sysfs walk, against the fake /sys: LVM over LUKS is found through
 * slaves/, a plain partition is "none", no /sys/dev/block entry is
 * "cannot tell". Seen red with the CRYPT- prefix test inverted and with
 * the slaves walk removed (the LVM case then read 0). */
static void test_block_crypt_detection(void) {
    fake_net_reset();
    char what[48];
    /* 254:1 is LVM; its slave dm-0 is the LUKS mapping. */
    fake_sys_put("/sys/dev/block/254:1/dev", "254:1\n");
    fake_sys_put("/sys/dev/block/254:1/dm/uuid", "LVM-abc123\n");
    fake_sys_put("/sys/dev/block/254:1/slaves/dm-0/dev", "254:0\n");
    fake_sys_put("/sys/class/block/dm-0/dm/uuid",
                 "CRYPT-LUKS2-0123456789abcdef-sdcrypt\n");
    fake_sys_put("/sys/class/block/dm-0/dm/name", "sdcrypt\n");
    fake_sys_put("/sys/class/block/dm-0/slaves/mmcblk0p2/dev", "179:2\n");
    ASSERT_EQ(pf_block_crypt(254, 1, what, sizeof(what)), 1);
    ASSERT_STR(what, "dm-crypt sdcrypt");
    /* The partition alone. */
    fake_sys_put("/sys/dev/block/179:2/dev", "179:2\n");
    fake_sys_put("/sys/dev/block/179:2/partition", "2\n");
    ASSERT_EQ(pf_block_crypt(179, 2, what, sizeof(what)), 0);
    ASSERT_STR(what, "");
    /* LVM over a plain partition. */
    fake_sys_put("/sys/dev/block/254:3/dev", "254:3\n");
    fake_sys_put("/sys/dev/block/254:3/dm/uuid", "LVM-def\n");
    fake_sys_put("/sys/dev/block/254:3/slaves/sda1/dev", "8:1\n");
    fake_sys_put("/sys/class/block/sda1/dev", "8:1\n");
    ASSERT_EQ(pf_block_crypt(254, 3, what, sizeof(what)), 0);
    /* tmpfs, btrfs: no block device. */
    ASSERT_EQ(pf_block_crypt(0, 42, what, sizeof(what)), -1);
    fake_net_reset();
}

static void at_rest(int crypt, int days) {
    base();
    g_c.pcap_dir = "/var/lib/sloth/pcap";
    g_c.pcap_retain_days = days;
    g_f.n_path = 1;
    pf_path_t *p = &g_f.path[0];
    p->what = "pcap-dir";
    p->path = g_c.pcap_dir;
    snprintf(p->dir, sizeof(p->dir), "%s", g_c.pcap_dir);
    p->dir_ok = 1;
    p->writable = 1;
    p->has_fs = 1;
    p->free_bytes = p->total_bytes = 1ull << 34;
    p->crypt = crypt;
    snprintf(p->crypt_dev, sizeof(p->crypt_dev), crypt > 0 ? "254:1 (dm-crypt x)" : "179:2");
    pf_check_storage(&g_c, &g_f, &g_r);
}

/* The levels at the edge. Seen red with `>` made `>=` (7 warned) and
 * with the forever case dropped (0 read ok). */
static void test_at_rest_levels(void) {
    at_rest(0, 7);
    ASSERT_EQ(level("storage", "pcap-dir-at-rest"), PF_OK);
    at_rest(0, 8);
    ASSERT_EQ(level("storage", "pcap-dir-at-rest"), PF_WARN);
    ASSERT(says("storage", "pcap-dir-at-rest", "no dm-crypt"));
    ASSERT(says("storage", "pcap-dir-at-rest", "fscrypt"));
    at_rest(0, 0);
    ASSERT_EQ(level("storage", "pcap-dir-at-rest"), PF_WARN);
    ASSERT(says("storage", "pcap-dir-at-rest", "kept until removed"));
    at_rest(1, 0);
    ASSERT_EQ(level("storage", "pcap-dir-at-rest"), PF_OK);
    at_rest(-1, 30);
    ASSERT_EQ(level("storage", "pcap-dir-at-rest"), PF_NOT_CHECKED);
    ASSERT_EQ(pf_exit_code(&g_r), 0);
    /* Not a line for an output that is not an evidence directory. */
    at_rest(0, 30);
    g_f.path[0].what = "db";
    memset(&g_r, 0, sizeof(g_r));
    pf_check_storage(&g_c, &g_f, &g_r);
    ASSERT(line("storage", "pcap-dir-at-rest") == NULL);
    ASSERT(line("storage", "eapol-dir-at-rest") == NULL);
    /* --eapol-dir reads its own knob. */
    at_rest(0, 30);
    g_f.path[0].what = "eapol-dir";
    g_c.eapol_retain_days = 7;
    memset(&g_r, 0, sizeof(g_r));
    pf_check_storage(&g_c, &g_f, &g_r);
    ASSERT_EQ(level("storage", "eapol-dir-at-rest"), PF_OK);
    ASSERT(says("storage", "eapol-dir-at-rest", "handshake.retention_days"));
}

void run_preflight_tests(void) {
    TEST_SUITE("sloth --preflight (#247)");
    RUN_TEST(test_clean_host_is_ready);
    RUN_TEST(test_radios_named_interfaces);
    RUN_TEST(test_radios_discovery_and_regdom);
    RUN_TEST(test_clock);
    RUN_TEST(test_storage);
    RUN_TEST(test_intel);
    RUN_TEST(test_sources);
    RUN_TEST(test_host);
    RUN_TEST(test_output);
    RUN_TEST(test_rules_expectation);
    RUN_TEST(test_exit_codes_and_output);
    RUN_TEST(test_gather_reads_sysfs);
    RUN_TEST(test_preflight_writes_nothing);
    RUN_TEST(test_gpsd_probe_reads_and_sends_nothing);
    RUN_TEST(test_monitor_only_without_radio_fails);
    RUN_TEST(test_passive_ignores_radios_left_out);
    RUN_TEST(test_passive_shared_phy_up_or_down);
    RUN_TEST(test_truncated_listing_is_reported);
    RUN_TEST(test_gather_past_the_netdev_cut);
    RUN_TEST(test_iface_names_past_sixteen);
    RUN_TEST(test_storage_paths_the_run_refuses);
    RUN_TEST(test_db_version_row_without_a_version);
    RUN_TEST(test_json_is_utf8);
    RUN_TEST(test_block_crypt_detection);
    RUN_TEST(test_at_rest_levels);
#ifdef PLATFORM_LINUX
    RUN_TEST(test_nl80211_parsers);
#endif
}
