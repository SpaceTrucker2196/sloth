#include <stdio.h>
#include <string.h>

#include "rf_args.h"
#include "sloth.h"
#include "daemon_start.h"
#include "db.h"
#include "data_socket.h"
#include "libver.h"
#include "observe.h"
#include "tune.h"
#include "alert_lifecycle.h"
#include "questions_live.h"
#include "jsonl_chain.h"

/* src/rf/rf_args.h. */

void rf_usage(FILE *fp, const char *argv0) {
    fprintf(fp,
            "usage: %s [--adsb SPEC] [--aprs SPEC] [--aprs-freq HZ]\n"
            "       [--aprs-silent-hours N] [--rtl433 SPEC] [--victron SPEC]\n"
            "       [--no-sdr-trim]\n"
            "       [--gps SPEC] [--gps-allow-remote] [--gps-baud N]\n"
            "       [--location LAT,LON[,ALT]]\n"
            "       [-o FILE [--jsonl-chain N]] [--db FILE] [--site-label TEXT]\n"
            "       [--data-socket [SPEC]] [--data-socket-allow-remote]\n"
            "       [--strict] [--tune NAME=VALUE ...] [--tune-list]\n"
            "       [--no-preliminary] [--value-period KIND=SECS ...]\n"
            "       [--questions PATH]\n"
            "       [--user NAME] [--no-privdrop] [--ticks N]\n"
            "       [--help] [--version] [--print-schema]\n"
            "\n"
            "sloth-rf is the RF half of the sloth sensor: it reads what\n"
            "decoders that are already running write, and a GNSS receiver.\n"
            "It opens no radio, tunes no SDR and transmits nothing; it has\n"
            "no terminal interface. Every flag it shares with sloth means\n"
            "what it means there and is refused the same way.\n"
            "\n"
            "  --adsb SPEC        a local ADS-B decoder (readsb, dump1090-fa):\n"
            "                       /path/aircraft.json or file:///path,\n"
            "                       re-read about once a second, or\n"
            "                       sbs://[HOST[:PORT]] (default\n"
            "                       127.0.0.1:30003) or beast://[HOST[:PORT]]\n"
            "                       (default 127.0.0.1:30005); loopback\n"
            "                       only, and nothing is sent on the socket.\n"
            "  --aprs SPEC        tail the packet log Dire Wolf writes\n"
            "                     (direwolf -L FILE): /path/aprs.log or\n"
            "                     file:///path, from its end at startup.\n"
            "  --aprs-freq HZ     the frequency the Dire Wolf decoder is\n"
            "                     configured for (144000000..148000000);\n"
            "                     sensor_health flags it when it is not the\n"
            "                     APRS channel of the region the position\n"
            "                     is in. Needs --aprs.\n"
            "  --aprs-silent-hours N\n"
            "                     report the decoder silent after N hours\n"
            "                     with a readable log and no packet (1..168,\n"
            "                     default 6; 0 off). Needs --aprs.\n"
            "  --rtl433 SPEC      tail the JSON event log rtl_433 writes\n"
            "                     (rtl_433 -F json): /path/events.jsonl or\n"
            "                     file:///path, from its end at startup.\n"
            "  --no-sdr-trim      start every decoder input whatever USB lists.\n"
            "                     By default, when /sys/bus/usb/devices shows\n"
            "                     no SDR at startup, a file --adsb, --aprs\n"
            "                     (with its two qualifiers) and --rtl433 are\n"
            "                     not started, each named on stderr, and\n"
            "                     their rows read not_installed. --adsb sbs://\n"
            "                     and beast://, --gps, --location and\n"
            "                     --victron are never trimmed. Read once: an\n"
            "                     SDR plugged in later needs a restart.\n"
            "  --victron SPEC     tail the JSONL the sloth-va helper writes\n"
            "                     (Victron readings): /path/victron.jsonl or\n"
            "                     file:///path, from its end at startup.\n"
            "                     The file is read only: sloth-va is what\n"
            "                     connects, and this daemon opens no\n"
            "                     Bluetooth socket.\n"
            "  --gps SPEC         the sensor's position and the GNSS\n"
            "                     records, from a receiver:\n"
            "                       /dev/ttyXXX          NMEA 0183, opened\n"
            "                                            read-only before the\n"
            "                                            privilege drop\n"
            "                       gpsd://[HOST[:PORT]] gpsd's JSON stream,\n"
            "                                            default\n"
            "                                            127.0.0.1:2947; one\n"
            "                                            ?WATCH line is sent\n"
            "                     A serial device opens once: on a host that\n"
            "                     also runs sloth with --gps, both read gpsd.\n"
            "  --gps-allow-remote permit a gpsd:// HOST outside loopback.\n"
            "                     --strict refuses a remote gpsd regardless.\n"
            "  --gps-baud N       serial speed for --gps /dev/... (4800, 9600\n"
            "                     (default), 19200, 38400, 57600, 115200).\n"
            "  --location LAT,LON[,ALT]\n"
            "                     the sensor's fixed position (WGS84 decimal\n"
            "                     degrees, ALT metres). A fresh --gps fix\n"
            "                     takes precedence.\n"
            "  -o, --out FILE     append the JSONL record stream to FILE\n"
            "                     (created 0600; an existing FILE must be\n"
            "                     private and yours, never a symlink).\n"
            "  --jsonl-chain N    a hash chain over the -o file, as sloth's\n"
            "                     (docs/wiki/record-integrity.md); sloth\n"
            "                     --verify FILE checks it.\n"
            "  --db FILE          persist to a SQLite database with sloth's\n"
            "                     own schema. The GNSS, ADS-B and APRS\n"
            "                     tables, the alerts and the sensor's own\n"
            "                     track fill; the capture's tables stay\n"
            "                     empty. Tune it with --tune db.max_mb=N,\n"
            "                     db.retain_days=N, db.interval_secs=N.\n"
            "  --site-label TEXT  operator label for the --db session row.\n"
            "  --data-socket [SPEC]\n"
            "                     stream the same records over a read-only\n"
            "                     socket: unix:/path or tcp:HOST:PORT. Bare,\n"
            "                     it is " DATA_SOCKET_RF_DEFAULT_SPEC ";\n"
            "                     if " DATA_SOCKET_RF_DEFAULT_DIR " is absent or not\n"
            "                     owned by root or this user, sloth-rf exits\n"
            "                     2 with the remedy and never falls back to\n"
            "                     TCP. A non-loopback bind is refused unless\n"
            "                     --data-socket-allow-remote is also given.\n"
            "                     Never advertised over mDNS.\n"
            "  --data-socket-allow-remote\n"
            "                     permit --data-socket to bind an address\n"
            "                     outside 127.0.0.0/8. The stream carries no\n"
            "                     authentication and no encryption.\n"
            "  --strict           refuse a remote gpsd and a routable\n"
            "                     --data-socket (exit 2, whatever the two\n"
            "                     allow-remote flags say).\n"
            "  --tune NAME=VALUE  move one threshold. Repeatable. An unknown\n"
            "                     name or an out-of-range value exits 2.\n"
            "  --no-preliminary   turn the finding lifecycle off (#245): no\n"
            "                     preliminary findings, no lapse, and no\n"
            "                     state or value_period_s on alert records.\n"
            "                     The stream is then the one before #245.\n"
            "  --value-period KIND=SECS\n"
            "                     seconds after a finding's last observation\n"
            "                     at which it lapses (1..2592000; default 300\n"
            "                     for every kind). Repeatable. An unknown KIND\n"
            "                     exits 2.\n"
            "  --questions PATH   the operator's site questions (#244), one\n"
            "                     per line: id|priority|question|decision|\n"
            "                     KIND,KIND. Replaces the seven defaults. An\n"
            "                     unknown kind or a duplicate id exits 2\n"
            "                     naming the line.\n"
            "  --tune-list        print every knob, then exit.\n"
            "  --user NAME        account a root run drops to once a serial\n"
            "                     --gps is open (default: sloth, when that\n"
            "                     account exists). Every sink is opened after\n"
            "                     the drop, as NAME. An unknown NAME exits 2.\n"
            "  --no-privdrop      keep every privilege for the whole run (dev\n"
            "                     boxes only). Conflicts with --user (exit 2).\n"
            "  --ticks N          exit 0 after N poll ticks (1..1000000).\n"
            "  --version, -V      print the version and the loaded sqlite,\n"
            "                     then exit.\n"
            "  --print-schema     print the --db schema (the DDL and\n"
            "                     DB_SCHEMA_VERSION, as SQL) and exit.\n"
            "                     Opens nothing; sloth-wifi prints the same.\n",
            argv0);
}

int rf_args_parse(int argc, char **argv, rf_args_t *a) {
    static const rf_args_t zero = {
        NULL, NULL, NULL, 0, 0, NULL, NULL, 0, 0,
        { NULL, NULL, 0, 0 }, RF_FLAGS_INIT, 0, 0
    };
    *a = zero;
    for (int i = 1; i < argc; i++) {
        /* Each flag is compared against argv[i] itself, as src/main.c
         * spells its loop: tests/test_docs_consistency.c reads both
         * loops by that shape to hold the CLI reference to what is
         * parsed. */
        const int has = i + 1 < argc;
        /* -o / --out, sloth's spellings and no other: the two daemons
         * take the same flags (owner ruling 2026-11-15), so a command
         * line written for one is read the same way by the other. */
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--out")) && has) {
            a->jsonl_path = argv[++i];
        } else if (!strcmp(argv[i], "--jsonl-chain") && has) {
            char cerr[96];
            if (jc_parse_block(argv[++i], &a->jsonl_chain, cerr, sizeof(cerr)) != 0) {
                fprintf(stderr, "sloth-rf: %s\n", cerr);
                return 2;
            }
        } else if (!strcmp(argv[i], "--db") && has) {
            a->db_path = argv[++i];
        } else if (!strcmp(argv[i], "--data-socket")) {
            /* Optional value, as in sloth: an explicit spec wins when the
             * next token is not another flag. Bare, it is this daemon's
             * own unix: socket, and a refusal - never loopback TCP - when
             * its directory is absent or not ours (#136). */
            if (has && argv[i + 1][0] != '-') {
                a->data_socket = argv[++i];
            } else {
                a->data_socket = daemon_data_socket_default(
                    DATA_SOCKET_RF_DEFAULT_DIR, DATA_SOCKET_RF_DEFAULT_SPEC,
                    "sloth-rf", DATA_SOCKET_RF_TCP_EXAMPLE);
                if (!a->data_socket) return 2;
            }
        } else if (!strcmp(argv[i], "--data-socket-allow-remote")) {
            a->ds_allow_remote = 1;
        } else if (!strcmp(argv[i], "--strict")) {
            a->strict = 1;
        } else if (!strcmp(argv[i], "--site-label") && has) {
            a->site_label = argv[++i];
        } else if (!strcmp(argv[i], "--location") && has) {
            a->gnss.location = argv[++i];
        } else if (!strcmp(argv[i], "--gps") && has) {
            a->gnss.gps = argv[++i];
        } else if (!strcmp(argv[i], "--gps-allow-remote")) {
            a->gnss.allow_remote = 1;
        } else if (!strcmp(argv[i], "--gps-baud") && has) {
            if (gnss_flag_baud(argv[++i], &a->gnss.baud) != 0) return 2;
        } else if (!strcmp(argv[i], "--adsb") && has) {
            a->rf.adsb = argv[++i];
        } else if (!strcmp(argv[i], "--aprs") && has) {
            a->rf.aprs = argv[++i];
        } else if (!strcmp(argv[i], "--rtl433") && has) {
            a->rf.rtl433 = argv[++i];
        } else if (!strcmp(argv[i], "--victron") && has) {
            a->rf.victron = argv[++i];
        } else if (!strcmp(argv[i], "--no-sdr-trim")) {
            a->no_sdr_trim = 1;
        } else if (!strcmp(argv[i], "--aprs-freq") && has) {
            if (rf_flag_aprs_freq(argv[++i], &a->rf.aprs_freq) != 0) return 2;
        } else if (!strcmp(argv[i], "--aprs-silent-hours") && has) {
            if (rf_flag_aprs_silent_hours(argv[++i], &a->rf.aprs_silent_h) != 0)
                return 2;
        } else if (!strcmp(argv[i], "--no-preliminary")) {
            alert_lifecycle_set_enabled(0);
        } else if (!strcmp(argv[i], "--value-period")) {
            if (daemon_flag_value_period(has ? argv[i + 1] : NULL) != 0)
                return 2;
            i++;
        } else if (!strcmp(argv[i], "--questions")) {
            if (q_live_flag(has ? argv[i + 1] : NULL) != 0) return 2;
            i++;
        } else if (!strcmp(argv[i], "--tune-list")) {
            tune_print_list(stdout);
            return 0;
        } else if (!strcmp(argv[i], "--tune")) {
            if (daemon_flag_tune(has ? argv[i + 1] : NULL) != 0) return 2;
            i++;
        } else if (!strcmp(argv[i], "--user") && has) {
            a->user = argv[++i];
        } else if (!strcmp(argv[i], "--no-privdrop")) {
            a->no_privdrop = 1;
        } else if (!strcmp(argv[i], "--ticks") && has) {
            if (daemon_flag_ticks(argv[++i], &a->max_ticks) != 0) return 2;
        } else if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-V")) {
            /* stdout: the requested output, not a diagnostic. No pcap
             * line, where sloth prints one: this binary loads no libpcap
             * to name. */
            printf("sloth-rf %s\n", SLOTH_VERSION);
            printf("sqlite: %s\n", libver_sqlite());
            return 0;
        } else if (!strcmp(argv[i], "--print-schema")) {
            /* sloth-wifi's flag, the same function: one DDL for both
             * daemons' databases (#185 item 4). */
            return db_schema_print(stdout) == 0 ? 0 : 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            rf_usage(stderr, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            rf_usage(stderr, argv[0]);
            return 2;
        }
    }
    return -1;
}

int rf_args_check(const rf_args_t *a) {
    /* sloth's order: the receiver's flags, then the decoders'. Neither
     * takes a --replay here: this daemon has no such flag. */
    if (gnss_flags_check(&a->gnss, a->strict, 0) != 0) return 2;
    if (rf_flags_check(&a->rf, 0) != 0) return 2;
    if (a->jsonl_chain && !a->jsonl_path) {
        fprintf(stderr, "sloth-rf: --jsonl-chain chains the -o file: name one "
                        "with -o\n");
        return 2;
    }

    /* --strict's hold on the data socket, through the resolver sloth
     * uses (src/observe.h), so the two cannot rule differently on one
     * SPEC. The other two inputs to it are flags this daemon does not
     * have: nothing here is active and nothing hops. */
    observe_profile_req_t req = {
        .strict           = a->strict,
        .allow_active     = 0,
        .hop              = 0,
        .have_data_socket = a->data_socket != NULL,
        .socket_is_remote = a->data_socket
                                ? data_socket_spec_is_remote(a->data_socket)
                                : 0,
    };
    observe_profile_t prof;
    observe_resolve_profile(&req, &prof);
    if (prof.refusal == OBSERVE_PROFILE_REFUSE_ROUTABLE_SOCKET_UNDER_STRICT) {
        daemon_strict_socket_refusal(a->data_socket);
        return prof.exit_code;
    }
    return 0;
}
