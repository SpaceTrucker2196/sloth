#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sloth.h"
#include "sloth_clock.h"
#include "alerts.h"
#include "alerts/rules.h"
#include "daemon_start.h"
#include "data_socket.h"
#include "db.h"
#include "event_wake.h"
#include "jsonl.h"
#include "poll.h"
#include "sys_status.h"
#include "tune.h"
#include "capture/gps_reader.h"
#include "capture/adsb_reader.h"
#include "capture/aprs_reader.h"
#include "capture/rtl433_reader.h"
#include "capture/victron_reader.h"
#include "rf_args.h"

/* sloth-rf: the RF half of the sensor (#213, ADR 0010).
 *
 * It reads what other programs write - readsb's aircraft.json or its
 * SBS / Beast socket, Dire Wolf's packet log, rtl_433's event log,
 * sloth-va's Victron readings (the file, never the devices), a GNSS
 * receiver or gpsd - and turns it into the same JSONL records,
 * database rows and alerts `sloth` makes from the same inputs. It is a
 * second process so that a restart, a crash or a stall of the Wi-Fi
 * monitor no longer stops the decoders' records, and the other way
 * round.
 *
 * MISSION.md section 2 holds here as it does in sloth, and more simply:
 * this binary opens no radio and links no capture. It has no libpcap,
 * no nl80211, no HCI socket, no resolver and no transmit path; the one
 * line it ever writes to a peer is gpsd's ?WATCH, announced. The
 * Makefile checks the linked binary's symbol table for that on every
 * build (check_rf_no_capture), so the claim is the build's and not
 * this comment's.
 *
 * Headless only. slothweb is its interface (ADR 0010).
 *
 * What it shares with sloth it shares as one copy: the flag checks
 * (src/gnss_flags.c, src/rf_flags.c, src/daemon_start.c), the readers,
 * the alert engine, the JSONL emitters for its records, the database
 * writer and DDL. What is its own is data: the poll table it passes
 * (g_poll_rf) and the rule table it selects (g_alert_table_rf). */

static sloth_state_t g_state;
/* The type a handler may store to (C99 7.14.1.1), as in sloth. */
static volatile sig_atomic_t g_quit = 0;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

int main(int argc, char **argv) {
    /* Before anything can tick: this daemon's rules. SENSOR_UNDERVOLT
     * is not among them (src/alerts/rules_table_rf.c says why). */
    alerts_set_table(&g_alert_table_rf);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    /* sloth writes its posture report on SIGUSR1. This daemon has none,
     * and the signal's default action is to terminate: ignored, so an
     * operator's `pkill -USR1 sloth` habit cannot take the decoders'
     * records down with it. */
    signal(SIGUSR1, SIG_IGN);

    time_t session_start = sloth_wall();
    /* Seed the --tune registry on the main thread, before a reader
     * thread can be its first reader (it seeds lazily on first read). */
    (void)tune_non_default();

    rf_args_t a;
    int rc = rf_args_parse(argc, argv, &a);
    if (rc >= 0) return rc;
    rc = rf_args_check(&a);
    if (rc != 0) return rc;

    /* The privilege plan, before anything opens, so a --user that names
     * no account exits 2 having opened nothing (#140). Nothing here
     * keeps a capability: no hop, nothing active. */
    privdrop_req_t  pd_req;
    privdrop_plan_t pd_plan;
    rc = daemon_privdrop_plan(&a.user, a.no_privdrop, 0, 0, &pd_req, &pd_plan);
    if (rc != 0) return rc;

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms = POLL_MS;

    /* sloth's order: the one handle that may need the invoking
     * account's groups - a serial GNSS receiver, usually group dialout -
     * is opened before the drop; gpsd is only recorded and is dialled
     * by the worker after it. */
    if (gnss_flags_open(&a.gnss) != 0) return 2;

    /* The drop: the serial handle is open and no thread exists yet
     * (capset and no_new_privs are per thread). Every sink below is
     * created as the account the run lives as. */
    if (daemon_privdrop_apply(&pd_req, &pd_plan, a.user) != 0) {
        gps_reader_stop();
        return 2;
    }

    if (a.jsonl_path && daemon_open_jsonl(a.jsonl_path) != 0) return 1;
    /* sys_status reports the filesystem the output lands on: the
     * database's, else the JSONL file's. */
    sys_status_set_disk_path(a.db_path ? a.db_path : a.jsonl_path,
                             a.db_path ? "db" : "jsonl");
    if (a.db_path && daemon_open_db(a.db_path, a.site_label, session_start) != 0)
        return 1;
    /* Never advertised: sloth publishes a routable socket over mDNS for
     * its phone client, which does not read this stream. */
    if (a.data_socket &&
        daemon_open_data_socket(a.data_socket, a.ds_allow_remote,
                                DATA_SOCKET_RF_DEFAULT_SPEC) != 0)
        return 1;
    /* Warn, do not refuse: a run with no sink still exercises the
     * readers, but it must not look like one that records. */
    if (!a.jsonl_path && !a.data_socket && !a.db_path)
        fprintf(stderr, "sloth-rf: no -o, --data-socket or --db: "
                        "this run produces no output\n");
    if (!a.rf.adsb && !a.rf.aprs && !a.rf.rtl433 && !a.rf.victron &&
        !a.gnss.gps)
        fprintf(stderr, "sloth-rf: no --adsb, --aprs, --rtl433, --victron "
                        "or --gps: there is nothing to read\n");

    /* After the drop, in sloth's order: gpsd is dialled and the
     * decoders' files are read as the run's account. */
    gps_reader_run();
    adsb_reader_run();
    aprs_reader_run();
    rtl433_reader_run();
    victron_reader_run();
    event_wake_init();
    /* What is true of every run, and no more: a gpsd:// source is sent
     * its one ?WATCH line and a routable --data-socket streams to
     * whoever connects, each announced on its own line above, so this
     * line does not say "nothing transmitted" after them. */
    fprintf(stderr, "sloth-rf: running (headless; no radio opened, "
                    "no SDR tuned)\n");

    long ticks_done = 0;
    while (!g_quit) {
        poll_ctx_t ctx;
        poll_ctx_init(&ctx);
        poll_tick(&g_poll_rf, &g_state, &ctx);
        data_socket_tick();
        /* --ticks: the last tick still emits; only the wait after it is
         * skipped, since nothing follows to wait for. */
        if (a.max_ticks > 0 && ++ticks_done >= a.max_ticks) break;
        /* An alert shortens the wait, as it does in sloth. */
        daemon_wait(g_state.poll_ms, event_wake_fd());
        event_wake_drain();
    }

    /* sloth's stop order for the same readers, then its sink order. */
    gps_reader_stop();
    adsb_reader_stop();
    aprs_reader_stop();
    rtl433_reader_stop();
    victron_reader_stop();
    jsonl_close();
    db_session_end(sloth_wall());
    db_close();
    data_socket_cleanup();
    return 0;
}
