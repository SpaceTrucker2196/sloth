#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "reset_all.h"
#include "data_socket.h"
#include "tune.h"
#include "aprs.h"
#include "capture/adsb_reader.h"
#include "capture/aprs_reader.h"
#include "capture/rtl433_reader.h"
#include "capture/victron_reader.h"
#include "capture/gps_reader.h"
#include "rf/rf_args.h"

/*
 * sloth-rf's command line (src/rf/rf_args.c, #213).
 *
 * Every flag sloth-rf shares with `sloth` is read and refused by the
 * function `sloth` calls (src/gnss_flags.c, src/rf_flags.c,
 * src/daemon_start.c), so the two cannot rule differently. What these
 * tests pin is the other half of "the same": the words. Each refusal
 * below is the line src/main.c printed inline before #213, written out
 * here in full, so a shared function that drifts from what `sloth` has
 * always said turns red here - and `make replay-check` runs both
 * binaries on the same command lines and compares what they print.
 *
 * Nothing here opens a device. A --gps SPEC is only parsed
 * (rf_args_check); gnss_flags_open(), which would open a serial
 * receiver, is never called. The decoder SPECs name files that do not
 * exist: rf_args_check() configures the readers and opens nothing.
 */

/* stdout and stderr into a file for the length of one call. */
static FILE *g_cap;
static int   g_saved_err = -1, g_saved_out = -1;
static char  g_text[65536];

static void cap_begin(void) {
    fflush(stdout); fflush(stderr);
    g_cap = tmpfile();
    g_saved_err = dup(STDERR_FILENO);
    g_saved_out = dup(STDOUT_FILENO);
    if (g_cap) {
        dup2(fileno(g_cap), STDERR_FILENO);
        dup2(fileno(g_cap), STDOUT_FILENO);
    }
}

static void cap_end(void) {
    fflush(stdout); fflush(stderr);
    if (g_saved_err >= 0) { dup2(g_saved_err, STDERR_FILENO); close(g_saved_err); }
    if (g_saved_out >= 0) { dup2(g_saved_out, STDOUT_FILENO); close(g_saved_out); }
    g_saved_err = g_saved_out = -1;
    g_text[0] = '\0';
    if (!g_cap) return;
    rewind(g_cap);
    size_t n = fread(g_text, 1, sizeof(g_text) - 1, g_cap);
    g_text[n] = '\0';
    fclose(g_cap);
    g_cap = NULL;
}

#define ARGV_MAX 16
static rf_args_t g_a;

/* Parse, then - when the parse says go on - check. Returns the exit
 * code, -1 for "would run". The readers a check configured are put
 * back, so no test leaves one configured for the next. */
static int run(const char *const *args, int n) {
    char *argv[ARGV_MAX + 1];
    argv[0] = (char *)"sloth-rf";
    for (int i = 0; i < n && i < ARGV_MAX; i++) argv[i + 1] = (char *)args[i];
    cap_begin();
    int rc = rf_args_parse(n + 1, argv, &g_a);
    if (rc < 0) {
        int c = rf_args_check(&g_a);
        if (c != 0) rc = c;
    }
    cap_end();
    adsb_reader_stop();
    aprs_reader_stop();
    rtl433_reader_stop();
    victron_reader_stop();
    sloth_reset_all();
    return rc;
}
#define RUN(...) run((const char *const[]){ __VA_ARGS__ }, \
                     (int)(sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(char *)))

/* A refusal: exit 2 and exactly this line (the whole output). */
#define REFUSED(line, ...) do { \
    ASSERT_EQ(RUN(__VA_ARGS__), 2); \
    if (strcmp(g_text, line) != 0) fprintf(stderr, "    got: %s", g_text); \
    ASSERT_STR(g_text, line); \
} while (0)

/* --location: a position outside the globe exits 2 with gps.c's reason;
 * a good one is announced and goes on. */
static void test_location(void) {
    REFUSED("sloth: --location 91,0: latitude must be -90..90 and longitude "
            "-180..180 (WGS84 decimal degrees)\n", "--location", "91,0");
    ASSERT_EQ(RUN("--location", "nonsense"), 2);
    ASSERT_EQ(strncmp(g_text, "sloth: --location nonsense: ", 28), 0);
    ASSERT_EQ(RUN("--location", "10.5,-20.25,30"), -1);
    ASSERT_STR(g_text, "sloth: --location fixed sensor position 10.5,-20.25,30 "
                       "(WGS84): stamped on new alert incidents in the JSONL "
                       "log, --db and the evidence manifests\n");
    ASSERT_STR(g_a.gnss.location, "10.5,-20.25,30");
}

/* --gps and --gps-allow-remote: a remote gpsd needs the opt-in, and
 * --strict refuses it whatever the opt-in says. Loopback and a serial
 * path pass the check (and are not opened by it). */
static void test_gps_scope(void) {
    REFUSED("sloth: --gps gpsd://192.0.2.1 is not loopback; pass "
            "--gps-allow-remote to read a remote gpsd\n",
            "--gps", "gpsd://192.0.2.1");
    REFUSED("sloth: --strict refuses a remote gpsd (192.0.2.1): use "
            "gpsd://127.0.0.1 or a serial device, or drop --strict\n",
            "--strict", "--gps-allow-remote", "--gps", "gpsd://192.0.2.1");
    /* The same refusal with the flags in the other order: the outcome
     * is the command line's, not the typing order's. */
    REFUSED("sloth: --strict refuses a remote gpsd (192.0.2.1): use "
            "gpsd://127.0.0.1 or a serial device, or drop --strict\n",
            "--gps", "gpsd://192.0.2.1", "--gps-allow-remote", "--strict");
    REFUSED("sloth: --gps nonsense: SPEC is /dev/PATH (NMEA serial) or "
            "gpsd://[HOST[:PORT]] (gpsd has no Unix data socket)\n",
            "--gps", "nonsense");

    ASSERT_EQ(RUN("--gps", "gpsd://192.0.2.1", "--gps-allow-remote"), -1);
    ASSERT_EQ(g_a.gnss.allow_remote, 1);
    ASSERT_EQ(RUN("--gps", "gpsd://127.0.0.1"), -1);
    ASSERT_STR(g_text, "");
    ASSERT_EQ(RUN("--strict", "--gps", "gpsd://127.0.0.1:2947"), -1);
    ASSERT_EQ(RUN("--gps", "/dev/ttyZZ99"), -1);
    ASSERT_STR(g_a.gnss.gps, "/dev/ttyZZ99");
    ASSERT_EQ(gps_reader_configured(), 0);   /* checked, never opened */

    /* The opt-in with nothing to opt in to: said, not refused. */
    ASSERT_EQ(RUN("--gps-allow-remote"), -1);
    ASSERT_STR(g_text, "sloth: --gps-allow-remote ignored: no --gps\n");
}

/* --gps-baud: one of six speeds, only with a serial --gps. */
static void test_gps_baud(void) {
    REFUSED("sloth: --gps-baud 1234: want 4800, 9600, 19200, 38400, 57600 "
            "or 115200\n", "--gps-baud", "1234");
    REFUSED("sloth: --gps-baud 9600x: want 4800, 9600, 19200, 38400, 57600 "
            "or 115200\n", "--gps-baud", "9600x");
    REFUSED("sloth: --gps-baud needs --gps /dev/...\n", "--gps-baud", "9600");
    REFUSED("sloth: --gps-baud applies to a serial --gps /dev/... only\n",
            "--gps", "gpsd://127.0.0.1", "--gps-baud", "9600");
    ASSERT_EQ(RUN("--gps", "/dev/ttyZZ99", "--gps-baud", "115200"), -1);
    ASSERT_EQ(g_a.gnss.baud, 115200);
}

/* --adsb: an absolute file, or a loopback sbs:// / beast://. */
static void test_adsb(void) {
    REFUSED("sloth: --adsb relative.json: want an absolute path\n",
            "--adsb", "relative.json");
    REFUSED("sloth: --adsb sbs://192.0.2.1: sbs:// reads a decoder on this "
            "host: 192.0.2.1 is not loopback (127.0.0.0/8, [::1])\n",
            "--adsb", "sbs://192.0.2.1");
    ASSERT_EQ(RUN("--adsb", "/nonexistent/sloth-test/aircraft.json"), -1);
    ASSERT_STR(g_text, "sloth: --adsb reading /nonexistent/sloth-test/aircraft.json "
                       "about once a second (read-only; no SDR, no network)\n");
    ASSERT_EQ(RUN("--adsb", "sbs://127.0.0.1:30003"), -1);
    ASSERT_STR(g_text, "sloth: --adsb connecting to the decoder's SBS output at "
                       "127.0.0.1:30003 over TCP after the privilege drop "
                       "(loopback; read-only: sloth sends nothing on the "
                       "socket; no SDR)\n");
}

/* --aprs, --aprs-freq, --aprs-silent-hours: the two qualifiers are
 * parsed strictly and mean nothing without the decoder. */
static void test_aprs(void) {
    REFUSED("sloth: --aprs relative.log: want an absolute path\n",
            "--aprs", "relative.log");
    REFUSED("sloth: --aprs-freq 5: want the decoder's configured frequency "
            "in Hz, 144000000..148000000 (e.g. 144390000)\n",
            "--aprs-freq", "5");
    REFUSED("sloth: --aprs-silent-hours 999: want 0 (off) to 168\n",
            "--aprs-silent-hours", "999");
    REFUSED("sloth: --aprs-silent-hours 3h: want 0 (off) to 168\n",
            "--aprs-silent-hours", "3h");
    REFUSED("sloth: --aprs-freq and --aprs-silent-hours describe the --aprs "
            "decoder: give --aprs\n", "--aprs-freq", "144390000");
    REFUSED("sloth: --aprs-freq and --aprs-silent-hours describe the --aprs "
            "decoder: give --aprs\n", "--aprs-silent-hours", "0");

    ASSERT_EQ(RUN("--aprs", "/nonexistent/sloth-test/aprs.log",
                  "--aprs-freq", "144800000", "--aprs-silent-hours", "2"), -1);
    ASSERT_STR(g_text, "sloth: --aprs tailing /nonexistent/sloth-test/aprs.log "
                       "from its end (read-only; no radio, no network)\n");
    ASSERT_EQ(g_a.rf.aprs_freq, 144800000u);
    ASSERT_EQ(g_a.rf.aprs_silent_h, 2);
    /* Not given is -1, which is "the default", not 0, which is "off". */
    ASSERT_EQ(RUN("--aprs", "/nonexistent/sloth-test/aprs.log"), -1);
    ASSERT_EQ(g_a.rf.aprs_silent_h, -1);
    ASSERT_EQ(g_a.rf.aprs_freq, 0u);
}

/* --rtl433: an absolute file. */
static void test_rtl433(void) {
    REFUSED("sloth: --rtl433 relative.jsonl: want an absolute path\n",
            "--rtl433", "relative.jsonl");
    ASSERT_EQ(RUN("--rtl433", "file:///nonexistent/sloth-test/events.jsonl"), -1);
    ASSERT_STR(g_text, "sloth: --rtl433 tailing /nonexistent/sloth-test/events.jsonl "
                       "from its end (read-only; no SDR, no network)\n");
}

/* --victron: an absolute file, sloth-va's; the words are sloth's
 * (src/rf_flags.c is the one copy both mains call). */
static void test_victron(void) {
    REFUSED("sloth: --victron relative.jsonl: want an absolute path\n",
            "--victron", "relative.jsonl");
    ASSERT_EQ(RUN("--victron", "file:///nonexistent/sloth-test/victron.jsonl"), -1);
    ASSERT_STR(g_text, "sloth: --victron tailing /nonexistent/sloth-test/victron.jsonl "
                       "from its end (read-only; sloth-va's file, no Bluetooth)\n");
    ASSERT_STR(g_a.rf.victron, "file:///nonexistent/sloth-test/victron.jsonl");
}

/* --tune and --ticks: strict, as in sloth. */
static void test_tune_and_ticks(void) {
    REFUSED("sloth: --tune needs name=value (see --tune-list)\n", "--tune");
    REFUSED("sloth: --tune unknown knob 'nope' (see --tune-list)\n",
            "--tune", "nope=1");
    REFUSED("sloth: --ticks 0: want 1..1000000\n", "--ticks", "0");
    REFUSED("sloth: --ticks 3x: want 1..1000000\n", "--ticks", "3x");
    ASSERT_EQ(RUN("--ticks", "7", "--tune", "gps.sample_s=30"), -1);
    ASSERT_EQ(g_a.max_ticks, 7);
    /* run() reset the registry after reading it back. */
    ASSERT_EQ(tune_non_default(), 0);
}

/* --data-socket: bare, it is this daemon's own unix: socket in its own
 * runtime directory - never sloth's, never TCP - or a refusal naming
 * that directory. Both outcomes are right, depending on the host the
 * suite runs on, and both are checked. */
static void test_data_socket_default_is_its_own(void) {
    int rc = RUN("--data-socket");
    if (rc == -1) {
        ASSERT_STR(g_a.data_socket, DATA_SOCKET_RF_DEFAULT_SPEC);
    } else {
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(g_text, "sloth: --data-socket default "
                              "unix:/run/sloth-rf/sloth-rf.sock: ") == g_text);
        ASSERT(strstr(g_text, "RuntimeDirectory=sloth-rf, or: install -d "
                              "-m 0750 -o ") != NULL);
        ASSERT(strstr(g_text, " /run/sloth-rf)\n") != NULL);
        /* Its own transport, not sloth's port (review of #213). */
        ASSERT(strstr(g_text, "--data-socket tcp:127.0.0.1:PORT ") != NULL);
        ASSERT(strstr(g_text, "--data-socket tcp:127.0.0.1:8765") == NULL);
    }
    ASSERT_STR(DATA_SOCKET_RF_DEFAULT_SPEC, "unix:/run/sloth-rf/sloth-rf.sock");
    ASSERT(strcmp(DATA_SOCKET_RF_DEFAULT_SPEC, DATA_SOCKET_DEFAULT_SPEC) != 0);

    /* An explicit SPEC is taken as given; a following flag is not one. */
    ASSERT_EQ(RUN("--data-socket", "unix:/nonexistent/sloth-test/x.sock"), -1);
    ASSERT_STR(g_a.data_socket, "unix:/nonexistent/sloth-test/x.sock");
    ASSERT_EQ(RUN("--data-socket", "tcp:127.0.0.1:8799", "--strict"), -1);
    ASSERT_STR(g_a.data_socket, "tcp:127.0.0.1:8799");
    ASSERT_EQ(g_a.strict, 1);
}

/* The refusal text for sloth's own default did not move when the
 * function grew a second caller: data_socket_default_refusal() is the
 * general form with sloth's three values. */
static void test_default_refusal_is_one_text(void) {
    char a[768], b[768];
    data_socket_default_refusal("/run/sloth: No such file or directory", 1000,
                                a, sizeof(a));
    ASSERT_STR(a, "sloth: --data-socket default unix:/run/sloth/sloth.sock: "
                  "/run/sloth: No such file or directory.\n"
                  "  Create it (RuntimeDirectory=sloth, or: install -d -m 0750 "
                  "-o 1000 /run/sloth)\n"
                  "  or name a transport explicitly: "
                  "--data-socket tcp:127.0.0.1:8765\n");
    data_socket_default_refusal(NULL, 0, a, sizeof(a));
    ASSERT(strstr(a, ": /run/sloth unusable.\n") != NULL);
    data_socket_default_refusal_at(DATA_SOCKET_RF_DEFAULT_SPEC,
                                   DATA_SOCKET_RF_DEFAULT_DIR, "sloth-rf",
                                   DATA_SOCKET_RF_TCP_EXAMPLE,
                                   NULL, 0, b, sizeof(b));
    ASSERT(strstr(b, ": /run/sloth-rf unusable.\n") != NULL);
    ASSERT(strstr(b, "RuntimeDirectory=sloth-rf,") != NULL);
    /* sloth-rf's remedy does not offer sloth's port as the transport
     * to bind: on a host running both, that bind fails or puts the RF
     * stream where a consumer expects sloth's (review of #213). The
     * whole text, so the last line cannot drift back.
     * (Seen red with DATA_SOCKET_RF_TCP_EXAMPLE set to sloth's.) */
    ASSERT_STR(b, "sloth: --data-socket default "
                  "unix:/run/sloth-rf/sloth-rf.sock: /run/sloth-rf unusable.\n"
                  "  Create it (RuntimeDirectory=sloth-rf, or: install -d "
                  "-m 0750 -o 0 /run/sloth-rf)\n"
                  "  or name a transport explicitly: --data-socket "
                  "tcp:127.0.0.1:PORT (a port of its own; 8765 is "
                  "sloth's)\n");
    ASSERT(strstr(b, "--data-socket tcp:127.0.0.1:8765") == NULL);
}

/* --strict refuses a routable --data-socket, and the allow-remote flag
 * does not override it; loopback and unix: pass. */
static void test_strict_holds_the_data_socket(void) {
    REFUSED("sloth: --strict refuses a routable --data-socket (tcp:192.0.2.1:9).\n"
            "       A routable listener transmits to whoever connects, which is what\n"
            "       --strict declines for this run. Bind loopback (tcp:127.0.0.1:PORT)\n"
            "       or a unix: path, or drop --strict.\n",
            "--strict", "--data-socket", "tcp:192.0.2.1:9",
            "--data-socket-allow-remote");
    ASSERT_EQ(RUN("--strict", "--data-socket", "tcp:127.0.0.1:9"), -1);
    ASSERT_EQ(RUN("--strict", "--data-socket", "unix:/nonexistent/x.sock"), -1);
    /* Without --strict the routable spec passes the check here; it is
     * data_socket_init_ex() that then wants the allow-remote flag. */
    ASSERT_EQ(RUN("--data-socket", "tcp:192.0.2.1:9"), -1);
}

/* The sinks and the rest: sloth's two spellings of the JSONL flag,
 * --db, --site-label, --user, --no-privdrop.
 *
 * --jsonl is not one of them (owner ruling 2026-11-15: both daemons
 * take the same flags). sloth-rf took it as a third spelling until
 * then; it is refused now the way sloth refuses it, as an unknown
 * argument, exit 2, with the usage, and nothing is set. (Seen red with
 * the alias still in rf_args_parse(): -1, and the path taken.) */
static void test_sinks_and_account(void) {
    ASSERT_EQ(RUN("--jsonl", "/nonexistent/a.jsonl"), 2);
    ASSERT_EQ(strncmp(g_text, "unknown argument: --jsonl\nusage: sloth-rf ", 42), 0);
    ASSERT(g_a.jsonl_path == NULL);
    ASSERT_EQ(RUN("--help"), 0);
    ASSERT(strstr(g_text, "--jsonl") == NULL);
    ASSERT_EQ(RUN("-o", "/nonexistent/b.jsonl"), -1);
    ASSERT_STR(g_a.jsonl_path, "/nonexistent/b.jsonl");
    ASSERT_EQ(RUN("--out", "/nonexistent/c.jsonl"), -1);
    ASSERT_STR(g_a.jsonl_path, "/nonexistent/c.jsonl");
    ASSERT_EQ(RUN("--db", "/nonexistent/x.db", "--site-label", "bench",
                  "--user", "nobody", "--data-socket-allow-remote"), -1);
    ASSERT_STR(g_a.db_path, "/nonexistent/x.db");
    ASSERT_STR(g_a.site_label, "bench");
    ASSERT_STR(g_a.user, "nobody");
    ASSERT_EQ(g_a.ds_allow_remote, 1);
    ASSERT_EQ(g_a.no_privdrop, 0);
    ASSERT_EQ(RUN("--no-privdrop"), -1);
    ASSERT_EQ(g_a.no_privdrop, 1);
    /* Nothing given: nothing set, and it would run. */
    ASSERT_EQ(RUN("--ticks", "1"), -1);
    ASSERT(g_a.jsonl_path == NULL && g_a.db_path == NULL &&
           g_a.data_socket == NULL && g_a.user == NULL);
    ASSERT(g_a.gnss.gps == NULL && g_a.gnss.location == NULL);
    ASSERT(g_a.rf.adsb == NULL && g_a.rf.aprs == NULL && g_a.rf.rtl433 == NULL &&
           g_a.rf.victron == NULL);
}

/* The capture's flags are not this daemon's: each is an unknown
 * argument, exit 2 with the usage, not accepted and ignored. A sloth-rf
 * that took --hop or --allow-active and did nothing would read as one
 * that can retune a radio or resolve an address. (Seen red for --hop
 * with a branch accepting it added to rf_args_parse().) */
static void test_capture_flags_are_unknown(void) {
    static const char *const none[] = {
        "--hop", "--allow-active", "--monitor-only", "--bt-monitor",
        "--collect-handshakes", "--headless", "--no-discovery", "--no-correlate",
    };
    for (size_t i = 0; i < sizeof(none) / sizeof(none[0]); i++) {
        ASSERT_EQ(run(&none[i], 1), 2);
        char want[96];
        snprintf(want, sizeof(want), "unknown argument: %s\nusage: sloth-rf ", none[i]);
        if (strncmp(g_text, want, strlen(want)) != 0)
            fprintf(stderr, "    %s was not refused as unknown\n", none[i]);
        ASSERT_EQ(strncmp(g_text, want, strlen(want)), 0);
    }
    static const char *const with_value[][2] = {
        { "--iface", "eth0" }, { "--monitor-iface", "wlan0mon" },
        { "--replay", "/nonexistent.pcap" }, { "--pcap-dir", "/nonexistent" },
        { "--eapol-dir", "/nonexistent" }, { "--bt-capture", "/nonexistent" },
        { "--my-ssid", "x" }, { "--report", "/nonexistent.md" },
    };
    for (size_t i = 0; i < sizeof(with_value) / sizeof(with_value[0]); i++) {
        ASSERT_EQ(run(with_value[i], 2), 2);
        ASSERT_EQ(strncmp(g_text, "unknown argument: ", 18), 0);
    }
    /* A flag that needs a value and is last on the line: unknown, as
     * in sloth, not read past the end of argv. */
    ASSERT_EQ(RUN("--adsb"), 2);
    ASSERT_EQ(strncmp(g_text, "unknown argument: --adsb\n", 25), 0);
}

/* --help and --version exit 0; the version names this binary and the
 * loaded sqlite, and no libpcap, which it does not load. */
static void test_help_and_version(void) {
    ASSERT_EQ(RUN("--help"), 0);
    ASSERT_EQ(strncmp(g_text, "usage: sloth-rf ", 16), 0);
    ASSERT(strstr(g_text, "--rtl433 SPEC") != NULL);
    ASSERT(strstr(g_text, "--victron SPEC") != NULL);
    ASSERT(strstr(g_text, "unix:/run/sloth-rf/sloth-rf.sock") != NULL);
    ASSERT(strstr(g_text, "--hop") == NULL);
    ASSERT_EQ(RUN("-h"), 0);
    ASSERT_EQ(RUN("--version"), 0);
    char want[64];
    snprintf(want, sizeof(want), "sloth-rf %s\nsqlite: ", SLOTH_VERSION);
    ASSERT_EQ(strncmp(g_text, want, strlen(want)), 0);
    ASSERT(strstr(g_text, "pcap") == NULL);
    ASSERT_EQ(RUN("-V"), 0);
    ASSERT_EQ(RUN("--tune-list"), 0);
    ASSERT(strstr(g_text, "gps.sample_s") != NULL);
}

void run_rf_args_tests(void) {
    TEST_SUITE("sloth-rf: the command line (#213)");
    RUN_TEST(test_location);
    RUN_TEST(test_gps_scope);
    RUN_TEST(test_gps_baud);
    RUN_TEST(test_adsb);
    RUN_TEST(test_aprs);
    RUN_TEST(test_rtl433);
    RUN_TEST(test_victron);
    RUN_TEST(test_tune_and_ticks);
    RUN_TEST(test_data_socket_default_is_its_own);
    RUN_TEST(test_default_refusal_is_one_text);
    RUN_TEST(test_strict_holds_the_data_socket);
    RUN_TEST(test_sinks_and_account);
    RUN_TEST(test_capture_flags_are_unknown);
    RUN_TEST(test_help_and_version);
}
