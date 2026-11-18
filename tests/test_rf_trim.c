#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "reset_all.h"
#include "fake_platform.h"
#include "alerts.h"
#include "alerts/rules.h"
#include "sys_status.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "rf_side.h"
#include "rf_trim.h"
#include "capture_side.h"
#include "capture/adsb_reader.h"
#include "capture/aprs_reader.h"
#include "capture/rtl433_reader.h"
#include "capture/victron_reader.h"
#include "rf/rf_args.h"

/*
 * sloth-rf's startup trim (src/rf_trim.h, owner 2026-11-18).
 *
 * The host's USB devices are served through the fake platform's /sys
 * table (tests/fake_platform.h), the seam src/sys_status.c reads every
 * /sys file through; sys_path_ok() admits nothing outside /proc and
 * /sys, so a tree in a temporary directory could not be read by the
 * code under test, and the fake is how every other sysfs read in this
 * suite is stood in. The IDs are the ones sys_usb_table[] cites
 * (usb.ids): 0bda:2838 RTL2838, 1546:01a8 u-blox 8, 0bda:0811 the
 * Realtek Wi-Fi adapter, 1d6b:0002 the Linux root hub (not in the
 * table). Nothing opens a device; the decoder SPECs name files that do
 * not exist and no worker thread is started.
 *
 * Every absence assertion names the mutation it was seen red under
 * (agents/AGENTS.md).
 */

#define USB "/sys/bus/usb/devices/"

/* A trimmed SPEC is NULL: compared as text, so a wrong trim fails the
 * assertion instead of crashing the suite. */
#define S(x) ((x) ? (x) : "(null)")

static void usb_dev(const char *port, const char *vid, const char *pid) {
    char p[96], v[16];
    snprintf(p, sizeof(p), USB "%s/idVendor", port);
    snprintf(v, sizeof(v), "%s\n", vid);
    ASSERT_EQ(fake_sys_put(p, v), 0);
    snprintf(p, sizeof(p), USB "%s/idProduct", port);
    snprintf(v, sizeof(v), "%s\n", pid);
    ASSERT_EQ(fake_sys_put(p, v), 0);
}

/* W9FJC's shape: a root hub, a GNSS receiver, a Wi-Fi adapter and the
 * Bluetooth controller's interface, no SDR. */
static void host_without_sdr(void) {
    fake_net_reset();
    usb_dev("usb1", "1d6b", "0002");
    usb_dev("1-3", "1546", "01a8");
    usb_dev("1-4", "0bda", "0811");
    ASSERT_EQ(fake_sys_put(USB "1-4:1.0/uevent", "DRIVER=rtl88xxau\n"), 0);
}

static void host_with_sdr(void) {
    host_without_sdr();
    usb_dev("1-1.2", "0bda", "2838");
}

/* ── detection ───────────────────────────────────────────────────── */

static int g_full_calls;
static int full_list(const char *dir, char *names, int name_sz, int max) {
    (void)dir;
    g_full_calls++;
    for (int i = 0; i < max; i++)
        snprintf(names + (size_t)i * (size_t)name_sz, (size_t)name_sz, "1-%d", i + 1);
    return max;
}

/* An RTL-SDR among the others is present and named; without it absent.
 * A root hub or an interface whose IDs would match is not a device
 * (usb_dev_name()). A sysfs that cannot be listed, or a list that fills
 * the buffer, is unknown: a "no SDR" read off a list cut short would
 * trim a decoder on a host that has one. Seen red with the n >= max
 * test removed from sys_usb_has_kind() (absent, not unknown). */
static void test_detect(void) {
    char d[128];
    host_with_sdr();
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_PRESENT);
    ASSERT_STR(d, "Realtek RTL2838 DVB-T (RTL-SDR) (0bda:2838 at usb:1-1.2)");

    host_without_sdr();
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_ABSENT);
    ASSERT_STR(d, "");
    /* The root hub given an SDR's ID is still a root hub. */
    usb_dev("usb2", "0bda", "2838");
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_ABSENT);

    /* Every SDR row of the table counts, not only the RTL2832U. */
    host_without_sdr();
    usb_dev("1-2", "1d50", "6089");
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_PRESENT);
    ASSERT(strstr(d, "HackRF One") != NULL);

    /* An RTL2832U stick under its maker's own ID (systemd's
     * software-radio hwdb, osmocom librtlsdr's known_devices[]) is an
     * SDR, not "no SDR". Seen red with that row removed from
     * sys_usb_table[] (absent, so the decoders would be trimmed). */
    host_without_sdr();
    usb_dev("1-2", "0ccd", "00d3");
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_PRESENT);
    ASSERT(strstr(d, "Terratec") != NULL);

    /* A device whose ID cannot be read might be the SDR: with none
     * found, cannot tell. Its idProduct alone is unreadable here (the
     * idVendor parses). Seen red with the unread flag ignored in
     * sys_usb_has_kind() (absent). */
    host_without_sdr();
    ASSERT_EQ(fake_sys_put(USB "1-2/idVendor", "0bda\n"), 0);
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_UNKNOWN);
    /* ... and an SDR found elsewhere still decides it. */
    usb_dev("1-1.2", "0bda", "2838");
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_PRESENT);

    /* No /sys/bus/usb at all. */
    fake_net_reset();
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_UNKNOWN);

    /* A list as long as the buffer: cannot tell. */
    int (*saved)(const char *, char *, int, int) = g_platform.sys_list;
    g_platform.sys_list = full_list;
    g_full_calls = 0;
    ASSERT_EQ(rf_trim_detect(d, (int)sizeof(d)), RF_SDR_UNKNOWN);
    ASSERT_EQ(g_full_calls, 1);
    g_platform.sys_list = saved;
    fake_net_reset();
}

/* ── the trim ────────────────────────────────────────────────────── */

static char g_log[2048];

static int apply(rf_flags_t *f, int have_gps, int no_trim, int sdr) {
    FILE *fp = tmpfile();
    ASSERT(fp != NULL);
    int r = rf_trim_apply(f, have_gps, no_trim, sdr, "Realtek RTL2838 DVB-T (RTL-SDR)", fp);
    g_log[0] = '\0';
    if (fp) {
        rewind(fp);
        size_t n = fread(g_log, 1, sizeof(g_log) - 1, fp);
        g_log[n] = '\0';
        fclose(fp);
    }
    return r;
}

static rf_flags_t beta_site(void) {
    rf_flags_t f = RF_FLAGS_INIT;
    f.adsb = "/run/readsb/aircraft.json";
    f.aprs = "/var/lib/direwolf/aprs.log";
    f.aprs_freq = 144390000u;
    f.aprs_silent_h = 4;
    f.rtl433 = "/var/lib/rtl_433/events.jsonl";
    f.victron = "/var/lib/sloth-va/victron.jsonl";
    return f;
}

/* An SDR attached: every input kept, and it says which SDR. Seen red
 * with rf_trim_apply()'s RF_SDR_PRESENT return removed. */
static void test_present_keeps_all(void) {
    rf_flags_t f = beta_site();
    ASSERT_EQ(apply(&f, 1, 0, RF_SDR_PRESENT), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "/run/readsb/aircraft.json");
    ASSERT_STR(S(f.aprs), "/var/lib/direwolf/aprs.log");
    ASSERT_EQ(f.aprs_freq, 144390000u);
    ASSERT_EQ(f.aprs_silent_h, 4);
    ASSERT_STR(S(f.rtl433), "/var/lib/rtl_433/events.jsonl");
    ASSERT_STR(S(f.victron), "/var/lib/sloth-va/victron.jsonl");
    ASSERT_STR(g_log, "sloth-rf: SDR attached: Realtek RTL2838 DVB-T (RTL-SDR); "
                      "decoder inputs kept\n");
    for (int i = 0; i < SYS_SRC_COUNT; i++) ASSERT_EQ(rf_trim_trimmed(i, NULL, 0), 0);
    rf_trim_reset();
}

/* No SDR: the three local decoder files go, each named with the reason,
 * --aprs with its two qualifiers; --gps (have_gps) and --victron stay.
 * Seen red with the --rtl433 branch removed from rf_trim_apply() (the
 * file kept, its line and its trimmed mark absent). */
static void test_absent_trims_local(void) {
    rf_flags_t f = beta_site();
    ASSERT_EQ(apply(&f, 1, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT(f.adsb == NULL);
    ASSERT(f.aprs == NULL);
    ASSERT_EQ(f.aprs_freq, 0u);
    ASSERT_EQ(f.aprs_silent_h, -1);
    ASSERT(f.rtl433 == NULL);
    ASSERT_STR(S(f.victron), "/var/lib/sloth-va/victron.jsonl");
    ASSERT_STR(g_log,
        "sloth-rf: --adsb /run/readsb/aircraft.json not started: no SDR on USB "
        "at startup (no known SDR USB ID under /sys/bus/usb/devices); "
        "--no-sdr-trim keeps it\n"
        "sloth-rf: --aprs /var/lib/direwolf/aprs.log not started (with its "
        "--aprs-freq / --aprs-silent-hours): no SDR on USB at startup (no known "
        "SDR USB ID under /sys/bus/usb/devices); --no-sdr-trim keeps it\n"
        "sloth-rf: --rtl433 /var/lib/rtl_433/events.jsonl not started: no SDR on "
        "USB at startup (no known SDR USB ID under /sys/bus/usb/devices); "
        "--no-sdr-trim keeps it\n");
    char spec[64];
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_ADSB, spec, (int)sizeof(spec)), 1);
    ASSERT_STR(spec, "/run/readsb/aircraft.json");
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_APRS, spec, (int)sizeof(spec)), 1);
    ASSERT_STR(spec, "/var/lib/direwolf/aprs.log");
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_RTL433, spec, (int)sizeof(spec)), 1);
    ASSERT_STR(spec, "/var/lib/rtl_433/events.jsonl");
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_VICTRON, NULL, 0), 0);
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_GNSS, NULL, 0), 0);
    rf_trim_reset();
}

/* A decoder's socket is never trimmed: what feeds it may take its
 * samples from an SDR on another machine. With it left, the run has
 * something to read even with no --gps. Seen red with the
 * ADSB_SPEC_FILE test removed from rf_trim_apply() (sbs:// trimmed and
 * NOTHING_LEFT returned). */
static void test_network_adsb_kept(void) {
    rf_flags_t f = RF_FLAGS_INIT;
    f.adsb = "sbs://127.0.0.1:30003";
    f.rtl433 = "file:///var/lib/rtl_433/events.jsonl";
    ASSERT_EQ(apply(&f, 0, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "sbs://127.0.0.1:30003");
    ASSERT(f.rtl433 == NULL);
    ASSERT(strstr(g_log, "--adsb") == NULL);
    ASSERT_EQ(rf_trim_trimmed(SYS_SRC_ADSB, NULL, 0), 0);
    f.adsb = "beast://127.0.0.1";
    ASSERT_EQ(apply(&f, 0, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "beast://127.0.0.1");
    rf_trim_reset();
}

/* --no-sdr-trim keeps every input with no SDR in sight, and says so.
 * Seen red with the no_trim return removed. */
static void test_override_keeps_all(void) {
    rf_flags_t f = beta_site();
    ASSERT_EQ(apply(&f, 0, 1, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "/run/readsb/aircraft.json");
    ASSERT_STR(S(f.aprs), "/var/lib/direwolf/aprs.log");
    ASSERT_EQ(f.aprs_freq, 144390000u);
    ASSERT_STR(S(f.rtl433), "/var/lib/rtl_433/events.jsonl");
    ASSERT_STR(g_log, "sloth-rf: --no-sdr-trim: every decoder input is started "
                      "whatever USB lists\n");
    for (int i = 0; i < SYS_SRC_COUNT; i++) ASSERT_EQ(rf_trim_trimmed(i, NULL, 0), 0);
    rf_trim_reset();
}

/* sysfs could not tell: nothing trimmed. Seen red with the
 * RF_SDR_UNKNOWN return removed (treated as absent). */
static void test_unknown_trims_nothing(void) {
    rf_flags_t f = beta_site();
    ASSERT_EQ(apply(&f, 0, 0, RF_SDR_UNKNOWN), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "/run/readsb/aircraft.json");
    ASSERT_STR(S(f.aprs), "/var/lib/direwolf/aprs.log");
    ASSERT_STR(S(f.rtl433), "/var/lib/rtl_433/events.jsonl");
    ASSERT_STR(g_log, "sloth-rf: cannot list /sys/bus/usb/devices: no input trimmed\n");
    rf_trim_reset();
}

/* A SPEC that does not parse is not trimmed, so rf_flags_check()
 * refuses it on a host with no SDR exactly as on one with: a typo is
 * not hidden until the day an SDR is plugged in. Seen red with the
 * parse guard dropped from the --adsb branch (an unparsed SPEC trimmed). */
static void test_bad_spec_is_left_to_refuse(void) {
    rf_flags_t f = RF_FLAGS_INIT;
    f.adsb = "relative.json";
    f.aprs = "relative.log";
    f.rtl433 = "relative.jsonl";
    ASSERT_EQ(apply(&f, 1, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT_STR(S(f.adsb), "relative.json");
    ASSERT_STR(S(f.aprs), "relative.log");
    ASSERT_STR(S(f.rtl433), "relative.jsonl");
    ASSERT_STR(g_log, "");
    rf_trim_reset();
}

/* Everything trimmed and nothing else: NOTHING_LEFT, which main()
 * says on stderr before running on idle (its socket then serves the
 * not_installed rows). --gps or --victron left over is a run. No input
 * at all is today's run (nothing trimmed, so not this case). Seen red
 * with have_gps dropped from the NOTHING_LEFT test. */
static void test_nothing_left(void) {
    rf_flags_t f = RF_FLAGS_INIT;
    f.adsb = "/run/readsb/aircraft.json";
    f.rtl433 = "/var/lib/rtl_433/events.jsonl";
    ASSERT_EQ(apply(&f, 0, 0, RF_SDR_ABSENT), RF_TRIM_NOTHING_LEFT);
    f.adsb = "/run/readsb/aircraft.json";
    ASSERT_EQ(apply(&f, 1, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    f.adsb = "/run/readsb/aircraft.json";
    f.victron = "/var/lib/sloth-va/victron.jsonl";
    ASSERT_EQ(apply(&f, 0, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    rf_flags_t none = RF_FLAGS_INIT;
    ASSERT_EQ(apply(&none, 0, 0, RF_SDR_ABSENT), RF_TRIM_GO);
    ASSERT_STR(g_log, "");
    rf_trim_reset();
}

/* ── end to end: the rows and SENSOR_SOURCE_DOWN ─────────────────── */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }
static int g_down_created;

static void hook(const alert_t *a, time_t now, const char *reason) {
    (void)now;
    if (a->type == ALERT_TYPE_SENSOR_SOURCE_DOWN && !reason && a->event_seq == 1)
        g_down_created++;
}

/* main()'s order on W9FJC's /etc/default/sloth-rf: parse, detect,
 * trim, check (which configures the readers left); then the poll's
 * health stages, sys_status and the rules, for long enough that a
 * configured decoder whose file never appears is judged stale. Returns
 * the SENSOR_SOURCE_DOWN incidents opened. */
static int run_w9fjc(int sdr_attached) {
    static const char *const args[] = {
        "sloth-rf", "--gps", "gpsd://127.0.0.1:2947",
        "--adsb", "/nonexistent/sloth-test/aircraft.json",
        "--aprs", "/nonexistent/sloth-test/aprs.log", "--aprs-freq", "144390000",
        "--rtl433", "/nonexistent/sloth-test/events.jsonl",
    };
    const int argc = (int)(sizeof(args) / sizeof(args[0]));
    if (sdr_attached) host_with_sdr(); else host_without_sdr();
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    sys_status_reset();
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
    /* sloth-rf's shape: its side and no capture's. */
    rf_side_install();
    sys_status_set_capture_side(NULL);
    g_down_created = 0;
    alerts_set_incident_hook(hook);

    rf_args_t a;
    FILE *devnull = fopen("/dev/null", "w");
    ASSERT_EQ(rf_args_parse(argc, (char **)args, &a), -1);
    char d[128] = "";
    int sdr = rf_trim_detect(d, (int)sizeof(d));
    ASSERT_EQ(sdr, sdr_attached ? RF_SDR_PRESENT : RF_SDR_ABSENT);
    ASSERT_EQ(rf_trim_apply(&a.rf, a.gnss.gps != NULL, a.no_sdr_trim, sdr, d,
                            devnull ? devnull : stderr), RF_TRIM_GO);
    if (devnull) fclose(devnull);
    /* The check announces each reader it configures on stderr; that is
     * tests/test_rf_args.c's to pin, and noise here. */
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0) { dup2(null_fd, STDERR_FILENO); close(null_fd); }
    int rc = rf_args_check(&a);
    fflush(stderr);
    if (saved >= 0) { dup2(saved, STDERR_FILENO); close(saved); }
    ASSERT_EQ(rc, 0);

    for (int i = 0; i < SENSOR_SRC_STALE_S + 60; i++) {
        g_mono += 1000;
        g_wall += 1;
        adsb_health_poll(&g_s, g_wall, g_mono);
        aprs_health_poll(&g_s, g_wall, g_mono);
        rtl433_health_poll(&g_s, g_wall);
        sys_status_poll(&g_s, g_wall, g_mono);
        alerts_update(&g_s);
    }
    return g_down_created;
}

static void run_end(void) {
    alerts_set_incident_hook(NULL);
    adsb_reader_stop();
    aprs_reader_stop();
    rtl433_reader_stop();
    victron_reader_stop();
    capture_side_install();
    sloth_reset_all();
    fake_net_reset();
    sys_status_reset();
    sloth_clock_test_set(NULL, NULL);
}

/* No SDR: the three rows read not_installed with the SPEC that was
 * given, and SENSOR_SOURCE_DOWN never opens for them, past the stale
 * span. The control is the same run with an SDR on USB: the readers
 * are configured, their files never appear, every row is stale and the
 * rule opens three incidents - so the zero below is the trim's and not
 * a run that judged nothing. Seen red with the trim skipped
 * (rf_trim_apply() returning RF_TRIM_GO before trimming: three rows
 * stale, three incidents) and, separately, with the not_installed test
 * removed from rule_sensor_source_down() (three incidents on the
 * not_installed rows once SENSOR_SRC_STALE_S had passed). */
static void test_rows_and_source_down(void) {
    ASSERT_EQ(run_w9fjc(1), 3);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->src[SYS_SRC_ADSB].state, SYS_ST_STALE);
    ASSERT_EQ(sn->src[SYS_SRC_RTL433].state, SYS_ST_STALE);
    run_end();

    ASSERT_EQ(run_w9fjc(0), 0);
    sn = sys_status_get();
    static const int ids[] = { SYS_SRC_ADSB, SYS_SRC_APRS, SYS_SRC_RTL433 };
    static const char *const eps[] = {
        "/nonexistent/sloth-test/aircraft.json", "/nonexistent/sloth-test/aprs.log",
        "/nonexistent/sloth-test/events.jsonl",
    };
    for (int i = 0; i < 3; i++) {
        const sys_source_t *o = &sn->src[ids[i]];
        ASSERT_EQ(o->state, SYS_ST_NOT_INSTALLED);
        ASSERT_STR(o->endpoint, eps[i]);
        ASSERT_STR(o->detail, "not started: no SDR on USB at startup "
                              "(--no-sdr-trim keeps it)");
    }
    ASSERT_STR(sys_src_state_name(SYS_ST_NOT_INSTALLED), "not_installed");
    /* --victron was not given: not_configured, not trimmed. */
    ASSERT_EQ(sn->src[SYS_SRC_VICTRON].state, SYS_ST_NOT_CONFIGURED);
    /* The readers were never configured. */
    ASSERT_EQ(adsb_reader_configured(), 0);
    run_end();
}

void run_rf_trim_tests(void) {
    TEST_SUITE("sloth-rf startup trim (no SDR on USB, src/rf_trim.h)");
    RUN_TEST(test_detect);
    RUN_TEST(test_present_keeps_all);
    RUN_TEST(test_absent_trims_local);
    RUN_TEST(test_network_adsb_kept);
    RUN_TEST(test_override_keeps_all);
    RUN_TEST(test_unknown_trims_nothing);
    RUN_TEST(test_bad_spec_is_left_to_refuse);
    RUN_TEST(test_nothing_left);
    RUN_TEST(test_rows_and_source_down);
}
