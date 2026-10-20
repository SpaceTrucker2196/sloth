#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "wifi_chanhop.h"
#include "wifi_snapshot.h"
#include "wifi_baseline.h"
#include "sensors.h"
#include "wifi_merge.h"
#include "history.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"
#include "views/procs.h"
#include "views/stats.h"
#include "views/probe.h"
#include "views/arp.h"
#include "views/mdns.h"
#include "views/nbns.h"
#include "views/dhcp_snoop.h"
#include "views/ssdp.h"
#include "views/beacon.h"
#include "views/deauth.h"
#include "views/http.h"
#include "views/tls.h"
#include "views/quic.h"
#include "views/dns_log.h"
#include "views/ntp.h"
#include "views/icmp.h"
#include "views/alerts.h"
#include "views/devices.h"
#include "views/help.h"
#include "views/dashboard.h"
#include "views/pnl.h"
#include "views/eapol.h"
#include "views/seqnum.h"
#include "views/assoc.h"
#include "views/channel.h"
#include "views/osi.h"
#include "views/twins.h"
#include "views/karma.h"
#include "views/rogue_radius.h"
#include "views/research.h"
#include "views/fragattack.h"
#include "coverage.h"
#include "karma_detect.h"
#include "eap_track.h"
#include "twins.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "secure_file.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "ctrl_frames.h"
#include "mle.h"
#include "captive_portal.h"
#include "fragattack.h"
#include "query.h"
#include "libver.h"
#include "bandwidth.h"
#include "mdns_snoop.h"
#include "nbns_snoop.h"
#include "dhcp_snoop.h"
#include "ndp_snoop.h"
#include "smb_snoop.h"
#include "kerb_snoop.h"
#include "ldap_snoop.h"
#include "bgp_snoop.h"
#include "ssh_snoop.h"
#include "rdp_snoop.h"
#include "snmp_snoop.h"
#include "mqtt_snoop.h"
#include "ssdp_snoop.h"
#include "onvif_discovery.h"
#include "event_wake.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "http_log.h"
#include "cleartext_creds.h"
#include "posture.h"
#include "updater.h"
#include "tls_log.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "alerts.h"
#include "tune.h"
#include "devices.h"
#include "top_hosts.h"
#include "beacon_detect.h"
#include "jsonl.h"
#include "persist_health.h"
#include "poll.h"
#include "formatter.h"
#include "alert_pcap.h"
#include "data_socket.h"
#include "ownership.h"
#include "inventory.h"
#include "transit.h"
#include "rf_quality.h"
#include "presence.h"
#include "tui_palette.h"
#include <sys/select.h>
#include "db.h"
#include "discovery.h"
#include "dns.h"
#include "observe.h"
#include "privdrop.h"
#include <pwd.h>
#include "scan.h"
#include "capture/probe.h"     /* self-stubbing without WITH_PCAP */
#ifdef WITH_PCAP
#  include "evidence_ring.h"   /* raw 802.11 evidence ring (#92) */
#endif
#include "capture/capture.h"   /* likewise — and #57's scope check needs it
                                  in the no-pcap build too */
#include "capture/replay.h"    /* --replay / --ticks (#119) */

static sloth_state_t g_state;
/* Written from on_signal(), so the type is the one C99 7.14.1.1 allows a
 * handler to store to: volatile sig_atomic_t. Not a mutex — locking is
 * not async-signal-safe, and a handler interrupting the main thread while
 * it held the lock would deadlock (#95). Only the main thread reads it. */
static volatile sig_atomic_t g_quit = 0;

/* Passive channel-hop scheduler (issue #22). Off unless --hop is passed.
 * Drives platform set_channel from sloth's own observed activity — a
 * kernel-state write confined to sloth's own monitor interface. Not
 * "the only" one, which is what #84 corrected here, and not a counted
 * set either: the nl80211 scan trigger behind --allow-active is
 * another, and opening a capture handle sets promiscuous mode behind no
 * flag at all. See src/platform/linux_wifi.h. */
static chanhop_t g_chanhop;
static int       g_hop_enabled = 0;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

#ifdef WITH_PCAP
/* Advance the channel scheduler once per poll: attribute the packets seen
 * since the last tick to the current channel, then retune the monitor
 * interface if the dwell has elapsed. */
static void chanhop_drive(sloth_state_t *s) {
    static uint64_t last_total = 0;
    if (!g_hop_enabled || s->probe_iface[0] == '\0') return;
    uint64_t now_ms = sloth_mono_ms();
    /* #91: the monitor radio's own frame counter, not s->pkt_total.
     * The general capture counter includes every other interface, so a
     * busy wired management port used to lengthen the dwell of whatever
     * channel the radio happened to be parked on — the RF heuristic was
     * being steered by traffic that never touched the air. */
    uint64_t mon_total = mon_frame_total();
    chanhop_observe(&g_chanhop, (uint32_t)(mon_total - last_total));
    last_total = mon_total;
    if (chanhop_tick(&g_chanhop, now_ms)) {
        /* #91 slice 1: consume the retune result instead of discarding it —
         * a failed set_channel() used to leave the UI showing the intended
         * channel with no way to tell "healthy, quiet" from "not actually
         * listening there". */
        int requested = chanhop_current_channel(&g_chanhop);
        int ok = g_platform.set_channel(s->probe_iface,
                                        chanhop_current_freq(&g_chanhop)) == 0;
        chanhop_record_retune(requested, ok, &s->chan_requested,
                              &s->chan_confirmed, &s->chan_retune_failures);
    }
    /* Surface the scan state for the interface view's channel bar. */
    s->scan_chan_count = chanhop_export(&g_chanhop, s->scan_chans,
                                        (int)(sizeof(s->scan_chans) / sizeof(s->scan_chans[0])),
                                        &s->scan_cur_idx);
    /* #91: and the hop-activity summary, so "visiting but deaf" is
     * separable from "not hopping" in the log and the view. Copied
     * field by field rather than memcpy'd: sloth.h deliberately does
     * not include wifi_chanhop.h, so the two structs are distinct
     * types that happen to agree. */
    chanhop_activity_t ha;
    chanhop_activity(&g_chanhop, &ha);
    s->hop_activity.channels        = ha.channels;
    s->hop_activity.visits          = ha.visits;
    s->hop_activity.frames          = ha.frames;
    s->hop_activity.silent_channels = ha.silent_channels;
    s->hop_activity.cur_visits      = ha.cur_visits;
    s->hop_activity.cur_frames      = ha.cur_frames;
    chanhop_dwell_t hd;
    chanhop_dwell(&g_chanhop, &hd);
    s->hop_dwell.last_planned_ms    = hd.last_planned_ms;
    s->hop_dwell.last_measured_ms   = hd.last_measured_ms;
    s->hop_dwell.worst_overshoot_ms = hd.worst_overshoot_ms;
    s->hop_dwell.completed          = hd.completed;
    s->hop_dwell.mean_planned_ms    = hd.mean_planned_ms;
    s->hop_dwell.mean_measured_ms   = hd.mean_measured_ms;
}
#endif

/* Wait out a poll interval without touching the terminal (#50).
 * Mirrors tui_poll_key's wake behaviour so headless and interactive
 * runs have the same cadence — an alert wakes both early. */
static void headless_wait(int timeout_ms, int wake_fd) {
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (wake_fd < 0) { select(0, NULL, NULL, NULL, &tv); return; }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(wake_fd, &rfds);
    select(wake_fd + 1, &rfds, NULL, NULL, &tv);
}

/* The research corpus (#73), NULL when --with-research was not given
 * or the corpus could not be opened. Passed explicitly to the one
 * consumer that wants it rather than read as a global — see the note on
 * posture_render_md. */
static rq_handle_t *g_research = NULL;

/* One tick of the poll loop. The stages and their order are the phase
 * table in src/poll.c (#113); this only fills in what lives in the app
 * rather than the core library. */
static void poll_data(sloth_state_t *s) {
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    ctx.research  = g_research;
    ctx.alert_hot = tui_alert_hot_set;
#ifdef WITH_PCAP
    ctx.chanhop   = chanhop_drive;
#endif
    poll_tick(s, &ctx);
}

static void handle_filter_input(sloth_state_t *s, int key) {
    if (key == 10 || key == 13) {            /* Enter — commit */
        s->filter_editing = 0;
        return;
    }
    if (key == 27) {                          /* Esc — cancel + clear */
        s->filter[0]      = '\0';
        s->filter_editing = 0;
        return;
    }
    if (key == SLOTH_KEY_BACKSPACE) {
        int n = (int)strlen(s->filter);
        if (n > 0) s->filter[n - 1] = '\0';
        return;
    }
    if (key >= 32 && key <= 126) {
        int n = (int)strlen(s->filter);
        if (n + 1 < (int)sizeof(s->filter)) {
            s->filter[n]     = (char)key;
            s->filter[n + 1] = '\0';
        }
    }
}

/* Dispatch a key to the active view's handler. Extracted so
 * view_claims_key() paths and the fall-through paths share one
 * dispatch site. view_claims_key itself lives in src/view_route.c
 * so unit tests can cover the routing decision without linking main.c. */
static void dispatch_to_view(sloth_state_t *s, int key) {
    /* Generated from include/sloth_views.def (#117); no `default:`, so
     * -Wswitch names any view_t value the expansion misses. */
    switch (s->active_view) {
#define X(id, label, key_, slug) case VIEW_##id: view_##slug##_key(s, key); break;
#include "sloth_views.def"
#undef X
    case VIEW_COUNT: break;
    }
}

static void handle_key(sloth_state_t *s, int key) {
    if (key == 0) return;

    /* While editing the filter, capture all input. */
    if (s->filter_editing) {
        handle_filter_input(s, key);
        return;
    }

    if (key == '/') {
        s->filter[0]      = '\0';
        s->filter_editing = 1;
        return;
    }
    if (key == '\\') {
        s->filter[0]      = '\0';
        s->filter_editing = 0;
        return;
    }

    /* Quit and help toggle are absolute globals — always take effect. */
    if (key == 'q' || key == 'Q') { g_quit = 1; return; }
    if (key == '?') {
        s->active_view = (s->active_view == VIEW_HELP)
                          ? VIEW_IFACE : VIEW_HELP;
        return;
    }

    /* First refusal: if the active view has a documented claim on
     * this key, dispatch to the view and skip the global switch. */
    if (view_claims_key(s->active_view, key)) {
        dispatch_to_view(s, key);
        return;
    }

    /* The view-select keys, from include/sloth_views.def (#117) through
     * the same table the tab bar and help card render. */
    int sel = view_for_key(key);
    if (sel >= 0) {
        s->active_view = (view_t)sel;
        return;
    }

    switch (key) {
    case '\t':
        s->active_view = (view_t)((s->active_view + 1) % VIEW_COUNT);
        return;
    case 'n': case 'N':
        s->dns_enabled = !s->dns_enabled;
        return;
    default:
        break;
    }

    /* Non-global keys: delegate to the active view. */
    dispatch_to_view(s, key);
}

static void print_usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [-o FILE] [--pcap-dir DIR] [--eapol-dir DIR]\n"
            "       [--collect-handshakes] [--handshake-retention DAYS]\n"
            "       [--data-socket SPEC] [--data-socket-allow-remote]\n"
            "       [--no-discovery] [--out-format FORMAT]\n"
            "       [--refresh-ms N] [--hop] [--strict] [--allow-active]\n"
            "       [--user NAME] [--no-privdrop]\n"
            "       [--tune NAME=VALUE ...] [--tune-list]\n"
            "       [--no-correlate] [--correlate-retain SECS]\n"
            "       [--wps-pin-brute-cycles N] [--wps-lockout-cycles N]\n"
            "       [--wps-pbc-concurrent N]\n"
            "       [--snapshot-out FILE] [--baseline-in FILE] [--site-label TEXT]\n"
            "       [--my-ssid SSID] [--my-bssid BSSID]\n"
            "       [--inventory FILE] [--site TEXT]\n"
            "       [--known-mac MAC] [--known-macs FILE]\n"
            "       [--headless] [--no-color] [--version]\n"
            "       [--with-research research.db]\n"
            "       [--db FILE] [--db-interval-secs N]\n"
            "       [--db-retain-days N] [--db-max-mb N]\n"
            "       [--replay FILE[,FILE]] [--ticks N]\n"
            "  -o, --out FILE     append JSONL forensic log of all observed\n"
            "                     events to FILE (created 0600 if it doesn't\n"
            "                     exist; an existing FILE must already be\n"
            "                     private and owned by you, never a symlink)\n"
            "  --pcap-dir DIR     when a critical alert fires with a known\n"
            "                     flow, write the matching packets to a fresh\n"
            "                     pcap file under DIR. CRIT only and once per\n"
            "                     finding per hour by default; --tune\n"
            "                     pcap.min_severity / pcap.key_cooldown_secs\n"
            "                     widen it to a full capture\n"
            "  --eapol-dir DIR    append captured EAPOL PMKIDs / 4-way\n"
            "                     handshakes to DIR/eapol.22000 in hashcat\n"
            "                     mixed format (22000), AND write a\n"
            "                     per-handshake DIR/<bssid>_<sta>.pcap for\n"
            "                     replay with aircrack-ng / Wireshark.\n"
            "                     CRACKABLE MATERIAL: both dirs are created\n"
            "                     0700, files 0600; an existing dir that is\n"
            "                     group/other accessible, not yours, or a\n"
            "                     symlink is refused, never chmod'ed.\n"
            "                     Requires --collect-handshakes; without it\n"
            "                     this flag exits 2 rather than starting a\n"
            "                     run that writes nothing\n"
            "  --collect-handshakes\n"
            "                     opt in to writing crackable material to\n"
            "                     disk. OFF by default. A PMKID or a paired\n"
            "                     M1+M2 supports offline password guessing,\n"
            "                     so exporting one is a separate decision\n"
            "                     from observing one. Detection, alerting,\n"
            "                     the [e] view and the JSONL/DB records are\n"
            "                     unaffected by this flag — it gates the\n"
            "                     .22000 lines and the per-handshake pcaps\n"
            "                     only. sloth never cracks anything itself\n"
            "                     (MISSION 2.2)\n"
            "  --handshake-retention DAYS\n"
            "                     age-out window for the exported crackable\n"
            "                     material above. Default 7. Swept at\n"
            "                     startup and once a day while running:\n"
            "                     artifacts in DIR last written before the\n"
            "                     window are deleted. 0 = keep forever.\n"
            "                     Whole-file granularity by mtime, so\n"
            "                     eapol.22000 goes only once nothing has\n"
            "                     been appended for the whole window (the\n"
            "                     22000 format has no per-line timestamp).\n"
            "                     A failed delete is counted and shown in\n"
            "                     the EAPOL view header, never silent.\n"
            "                     See docs/wiki/retention.md\n"
            "  --data-socket [SPEC]\n"
            "                     stream the same records over a read-only\n"
            "                     socket. SPEC is one of:\n"
            "                       unix:/path/to/socket\n"
            "                       tcp:HOST:PORT  (HOST is a literal IPv4)\n"
            "                     If SPEC is omitted, defaults to\n"
            "                     unix:/run/sloth/sloth.sock; if /run/sloth\n"
            "                     is absent or not owned by root or this\n"
            "                     user, sloth exits 2 with the remedy —\n"
            "                     it never falls back to TCP. Loopback TCP\n"
            "                     must be asked for: tcp:127.0.0.1:8765.\n"
            "                     Read-only: nothing is ever read from the\n"
            "                     socket. The stream carries no authentication\n"
            "                     and no encryption, so a non-loopback bind is\n"
            "                     refused unless --data-socket-allow-remote is\n"
            "                     also given. unix: sockets are created 0600 —\n"
            "                     the kernel checks the peer's credentials, so\n"
            "                     that is the recommended deployment.\n"
            "  --data-socket-allow-remote\n"
            "                     permit --data-socket to bind an address\n"
            "                     outside 127.0.0.0/8 (including the 0.0.0.0\n"
            "                     wildcard). Off by default. Every observation\n"
            "                     sloth makes — SSIDs, MACs, hostnames,\n"
            "                     captured credentials — becomes readable by\n"
            "                     anyone who can reach the port. Prefer a\n"
            "                     tunnel: ssh -L 8765:127.0.0.1:8765 user@host,\n"
            "                     stunnel, or examples/forwarder/. See\n"
            "                     docs/wiki/data-socket-exposure.md.\n"
            "  --out-format FORMAT\n"
            "                     output format for -o FILE and --data-socket.\n"
            "                     One of: jsonl (default), cef, syslog.\n"
            "                     cef    = ArcSight Common Event Format\n"
            "                              (single-line per record, RFC-free\n"
            "                              vendor=sloth-net product=sloth).\n"
            "                     syslog = RFC 5424 (PRI 134 local0.info,\n"
            "                              SD-ID sloth@32473; MSG carries\n"
            "                              the original JSON for fidelity).\n"
            "  --refresh-ms N     dashboard refresh interval, milliseconds.\n"
            "                     Default 250 (~4 Hz). Floor 50ms — sub-50ms\n"
            "                     burns CPU without visible gain on a terminal.\n"
            "                     The loop also wakes early on alert fires,\n"
            "                     so the value is an upper bound, not a fixed\n"
            "                     cadence.\n"
            "  --hop              passive channel-hopping: retune sloth's own\n"
            "                     monitor interface across a 2.4/5 GHz list,\n"
            "                     dwelling longer where activity is seen. Off by\n"
            "                     default. A kernel-state write on sloth's own\n"
            "                     radio; the nl80211 scan trigger, opt-in under\n"
            "                     --allow-active, is another (MISSION.md §2\n"
            "                     lists them all). They are separately gated:\n"
            "                     --strict locks the scan trigger out for the\n"
            "                     run and does NOT refuse --hop (owner ruling,\n"
            "                     2026-09-30). Needs monitor mode +\n"
            "                     CAP_NET_ADMIN (Linux). No frame is transmitted.\n"
            "  --strict           near-no-op: strict observation is already the\n"
            "                     default. What it adds is a LOCK — any later\n"
            "                     attempt to enable active behaviour in this run\n"
            "                     is refused, so --strict --allow-active exits\n"
            "                     non-zero instead of quietly resolving in favour\n"
            "                     of one of them. It also suppresses the mDNS\n"
            "                     advertisement (see --no-discovery) and refuses\n"
            "                     a routable --data-socket (exit 2, even with\n"
            "                     --data-socket-allow-remote; loopback and unix:\n"
            "                     still work). It does NOT refuse --hop, which\n"
            "                     still retunes the monitor interface, and it\n"
            "                     does not change promiscuous mode.\n"
            "                     Worth passing because it puts the operator's\n"
            "                     intent where ps(1) and an audit log can see it.\n"
            "  --tune NAME=VALUE  move one detector threshold. Repeatable.\n"
            "                     An unknown name or an out-of-range value\n"
            "                     exits 2 rather than running with the\n"
            "                     default you thought you had changed. Any\n"
            "                     knob off its default is reported in\n"
            "                     sensor_health (tuned) and the health\n"
            "                     strip, so a detuned sensor and a quiet\n"
            "                     one do not read alike.\n"
            "                     --correlate-retain, --handshake-retention,\n"
            "                     --db-interval-secs, --db-retain-days,\n"
            "                     --db-max-mb and --wps-* are aliases for\n"
            "                     knobs and are validated the same way.\n"
            "  --tune-list        print every knob with default, current\n"
            "                     value and unit, then exit.\n"
            "  --allow-active     opt in to the two active behaviours sloth has:\n"
            "                     (1) reverse-DNS resolution — on a cache miss\n"
            "                     sloth may send a PTR query for an address it\n"
            "                     observed; (2) nl80211 scan triggers, a kernel\n"
            "                     scan kicked on each wireless interface so the\n"
            "                     cached AP list stays fresh (passive scan, no\n"
            "                     SSID list, so no probe request is transmitted).\n"
            "                     Both OFF by default — without this flag the\n"
            "                     resolver worker is never started, no TRIGGER_SCAN\n"
            "                     request is ever built, names come only from\n"
            "                     traffic sloth already saw (DNS/mDNS/NBNS/DHCP/\n"
            "                     SNI snooping) and the AP list comes only from\n"
            "                     whatever the kernel already had cached. Prints\n"
            "                     one line on stderr naming what it enabled; it\n"
            "                     is never silent. Does not re-enable per-packet\n"
            "                     lookups on the capture thread, which stay\n"
            "                     passive unconditionally.\n"
            "  --user NAME        account a root run drops to once the capture\n"
            "                     handles are open (default: sloth, when that\n"
            "                     account exists). Every sink (-o, --db,\n"
            "                     --pcap-dir, --eapol-dir, --data-socket) is\n"
            "                     opened AFTER the drop, as NAME, so its paths\n"
            "                     must be owned by NAME. CAP_NET_ADMIN is kept\n"
            "                     only for --hop / --allow-active; nothing else\n"
            "                     is. With no such account a root run keeps\n"
            "                     uid 0 but sheds every capability it does not\n"
            "                     need, and says so. An unknown NAME exits 2.\n"
            "                     no_new_privs is set on every run.\n"
            "  --no-privdrop      keep every privilege for the whole run (dev\n"
            "                     boxes only). Announced on stderr; never the\n"
            "                     default. Conflicts with --user (exit 2).\n"
            "  --no-correlate     disable longitudinal device correlation: the\n"
            "                     [j] seqnum view keeps showing each MAC's own\n"
            "                     counter trail, but no pair of addresses is\n"
            "                     linked across a rotation and no\n"
            "                     seqnum_correlation record is exported or\n"
            "                     stored. Linking addresses over time is a\n"
            "                     different purpose from observing the air, so\n"
            "                     it is switched separately. On by default.\n"
            "  --correlate-retain SECS\n"
            "                     evidence retention for correlation (default\n"
            "                     300). A pair is only reported while BOTH\n"
            "                     addresses have been heard inside this window,\n"
            "                     counted from now — nothing is inferred from\n"
            "                     two trails that were close an hour ago.\n"
            "  --wps-pin-brute-cycles N\n"
            "                     WPS PIN attempts (M1-M3-NACK restart cycles)\n"
            "                     from one station, or from one UUID-E behind\n"
            "                     rotating MACs, within 60 s before\n"
            "                     WPS_PIN_BRUTE fires (default 5, CERT/CC\n"
            "                     VU#723755). A floor: raising it only quiets\n"
            "                     the rule, it cannot invent a finding. The\n"
            "                     60 s window is not tunable — it is the rate\n"
            "                     the threshold is defined over.\n"
            "  --wps-lockout-cycles N\n"
            "                     completed AP-Setup-Locked lock->unlock cycles\n"
            "                     on one BSSID within an hour before\n"
            "                     WPS_LOCKOUT_CYCLING fires (default 2). An AP\n"
            "                     that locks once and stays locked is a posture,\n"
            "                     not an attack, and never fires.\n"
            "  --wps-pbc-concurrent N\n"
            "                     concurrent WPS Push-Button enrollees on one\n"
            "                     BSSID inside the 120 s walk time that\n"
            "                     WPS_PBC_RACE fires ABOVE (default 2, i.e. the\n"
            "                     third concurrent enrollee alerts). The walk\n"
            "                     time is fixed by the WSC protocol, not by\n"
            "                     this flag.\n"
            "  --iface NAME       restrict the data stream to NAME (repeatable).\n"
            "                     Launch-time form of the interface view's [y]\n"
            "                     deselect, for headless deployments: frames\n"
            "                     from every other interface are dropped in the\n"
            "                     capture callback before decode. Purely\n"
            "                     logical — OS interface state is untouched.\n"
            "  --monitor-only     shorthand: restrict the data stream to the\n"
            "                     monitor-mode Wi-Fi interface sloth discovers\n"
            "                     at startup. Fail-closed: if no monitor\n"
            "                     interface is found, or --iface/--monitor-only\n"
            "                     cannot be enforced on the capture datalink,\n"
            "                     sloth exits non-zero rather than capture an\n"
            "                     unrestricted stream.\n"
            "  --no-discovery     suppress the mDNS advertisement of the data\n"
            "                     socket. By default, when --data-socket is bound\n"
            "                     to a routable (non-loopback) TCP address, sloth\n"
            "                     writes an Avahi service file so the sloth-ios\n"
            "                     client can find it by name. Loopback/unix sockets\n"
            "                     never advertise. sloth transmits nothing itself —\n"
            "                     avahi-daemon does the announcing.\n"
            "  --db FILE          persist entity state to a SQLite database at\n"
            "                     FILE (off by default). Bounded by the fixed\n"
            "                     tables in sloth.h, not by uptime: state is\n"
            "                     upserted per entity with first_seen /\n"
            "                     last_seen rather than appended per tick, so a\n"
            "                     long run costs megabytes where -o costs\n"
            "                     gigabytes. Read it with the sqlite3 CLI --\n"
            "                     sloth exposes no query surface (MISSION 4).\n"
            "                     Independent of -o and --data-socket, which\n"
            "                     remain the wire format and are unchanged.\n"
            "  --db-interval-secs N\n"
            "                     seconds between database write ticks.\n"
            "                     Default 1. Raise it on slow storage.\n"
            "  --db-retain-days N\n"
            "                     age-out window for observation rows.\n"
            "                     Default 30. Tiered: entities keep 3x\n"
            "                     this, alerts and credential exposures\n"
            "                     keep 12x -- what fired outlives who was\n"
            "                     here, which outlives the individual\n"
            "                     observations.\n"
            "  --db-max-mb N      size target for the database, MiB. A\n"
            "                     pruning trigger, not a hard cap.\n"
            "                     Default 512, 0 = unlimited. On breach\n"
            "                     the oldest observation rows go first;\n"
            "                     entity, alert and credential rows are\n"
            "                     never dropped, so the file may exceed\n"
            "                     the target. See docs/wiki/retention.md.\n"
            "  --headless         draw nothing and never touch the\n"
            "                     terminal: no screen clears, no escape\n"
            "                     sequences, no raw-mode termios change,\n"
            "                     no key handling. For appliance and\n"
            "                     systemd deployments where the output is\n"
            "                     a journal, not a screen. Capture,\n"
            "                     alerting and every sink (-o,\n"
            "                     --data-socket, --db, --report) run\n"
            "                     exactly as normal.\n"
            "  --replay FILE[,FILE]\n"
            "                     read libpcap savefiles instead of opening\n"
            "                     any interface (max 8). Ethernet and Linux\n"
            "                     cooked files feed the IP path, radiotap\n"
            "                     files the 802.11 monitor path. No host\n"
            "                     state is read: interfaces, sockets, ARP,\n"
            "                     DHCP and Wi-Fi scan come back empty, so\n"
            "                     the output describes the files alone.\n"
            "                     Refused with --iface, --monitor-only and\n"
            "                     --hop, which name live capture.\n"
            "  --ticks N          exit 0 after N poll ticks (1..1000000).\n"
            "                     With --replay --headless this is a batch\n"
            "                     run: replay, tick, flush the sinks, exit.\n"
            "  --no-color         suppress colour escape sequences but\n"
            "                     keep drawing. Also honoured via the\n"
            "                     NO_COLOR environment variable.\n"
            "  --version, -V      print the version and exit. The banner\n"
            "                     shows it too, but that needs the TUI\n"
            "                     running — no use on a headless sensor.\n"
            "                     Lines 2-3 name the libpcap and sqlite\n"
            "                     actually loaded.\n"
            "  --with-research FILE\n"
            "                     load the research corpus for per-alert\n"
            "                     citations in --report. Additive: an\n"
            "                     unreadable corpus warns and continues.\n"
            "  --known-mac MAC    add MAC to the known-device roster\n"
            "                     (repeatable, max 512).\n"
            "  --known-macs FILE  load a roster: one MAC per line, #\n"
            "                     comments. Malformed lines are reported\n"
            "                     with their line number and skipped.\n"
            "                     With a roster AND a --my-ssid/--my-bssid\n"
            "                     designation, a device associated to your\n"
            "                     network that is not on the roster raises\n"
            "                     UNKNOWN_DEVICE. Both are required, so it\n"
            "                     is silent unless you opted into each.\n"
            "  --my-ssid SSID     designate SSID as the operator's own network\n"
            "                     (repeatable, max 16). Purely a label — no\n"
            "                     capture behaviour changes and nothing is\n"
            "                     transmitted. Unlocks MY_NET_RECON: a client\n"
            "                     that remembers a designated SSID but is not\n"
            "                     associated to it is probing your network.\n"
            "  --my-bssid BSSID   designate an AP (aa:bb:cc:dd:ee:ff) as the\n"
            "                     operator's own (repeatable, max 16). Deauth\n"
            "                     and auth floods aimed at a designated BSSID\n"
            "                     escalate WARN -> CRIT, and a designated\n"
            "                     BSSID is never named the impostor half of an\n"
            "                     evil-twin pair.\n"
            "  --inventory FILE   load the approved-inventory JSON: which\n"
            "                     BSSIDs are authorised for which SSID (#89).\n"
            "                     The only evil-twin trust input that does not\n"
            "                     come off the air, so it is the only one that\n"
            "                     can clear a pair: a same-OUI clone of a listed\n"
            "                     SSID raises EVIL_TWIN, and a declared\n"
            "                     mixed-vendor deployment stops raising it.\n"
            "                     Unioned with --my-ssid/--my-bssid, never\n"
            "                     intersected. All-or-nothing: a malformed file\n"
            "                     is refused with a reason and sloth exits,\n"
            "                     rather than loading half an anchor. Read once\n"
            "                     at startup, never re-read. Format:\n"
            "                     docs/wiki/inventory.md.\n"
            "  --site TEXT        operator label for where this sensor is,\n"
            "                     part of the evil-twin dedup key. Overrides\n"
            "                     the inventory file's \"site\". Configuration\n"
            "                     only — never derived from the uplink or any\n"
            "                     observed SSID. Distinct from --site-label,\n"
            "                     which names the --snapshot-out report.\n"
            "  --snapshot-out FILE\n"
            "                     on exit, write a passive AP-inventory snapshot\n"
            "                     (BSSID/SSID/security/channel/vendor) for repeat\n"
            "                     site assessments. No pcap — normalised text.\n"
            "  --baseline-in FILE on exit, diff the current AP inventory against a\n"
            "                     prior --snapshot-out file (new/gone/changed APs).\n"
            "  --site-label TEXT  operator label stamped into --snapshot-out.\n"
            "  --report FILE.md   on exit, write a Markdown posture report to\n"
            "                     FILE.md summarising alerts (by severity and\n"
            "                     MITRE ATT&CK technique), cleartext credential\n"
            "                     exposures, and high-risk devices.\n"
            "  --report-json FILE.json\n"
            "                     same rollup as --report, structured for\n"
            "                     machine consumption / SIEM diff.\n"
            "  --check-manifest FILE\n"
            "                     read a locally-populated release manifest\n"
            "                     (JSON) and show \"update available\" in the\n"
            "                     help view when its \"latest\" > SLOTH_VERSION.\n"
            "                     sloth never fetches from the network itself;\n"
            "                     populate FILE via a systemd timer / cron\n"
            "                     using examples/updater/check-latest.sh.\n"
            "                     See docs/wiki/manifest-format.md.\n",
            argv0);
}

/* A flag that is an alias for one --tune row (#120). The value goes
 * through the registry's own strict parse, so "--db-max-mb 5x" exits 2
 * with the knob named instead of running with atoi()'s 5, and the moved
 * value reaches sensor_health's `tuned` the way --tune's does. */
static int tune_alias(const char *flag, tune_id_t id, const char *value) {
    char terr[160];
    if (tune_set_value(id, value, terr, sizeof(terr)) == 0) return 1;
    fprintf(stderr, "sloth: %s %s (see --tune-list)\n", flag, terr);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    const char *jsonl_path   = NULL;
    const char *pcap_dir     = NULL;
    const char *eapol_dir    = NULL;
    int         collect_hs   = 0;      /* --collect-handshakes (#87) */
    const char *data_socket  = NULL;
    const char *report_md    = NULL;   /* --report      FILE.md   */
    const char *report_json  = NULL;   /* --report-json FILE.json */
    const char *check_manifest = NULL; /* --check-manifest FILE   */
    int         headless       = 0;    /* --headless           (#50) */
    const char *db_path        = NULL; /* --db FILE            (#42) */
    const char *snapshot_out   = NULL; /* --snapshot-out FILE  (#27) */
    const char *baseline_in    = NULL; /* --baseline-in  FILE  (#27) */
    const char *site_label     = NULL; /* --site-label   TEXT  (#27) */
    int         refresh_ms   = 0;        /* 0 = use POLL_MS default */
    int         no_discovery = 0;        /* --no-discovery: suppress mDNS advert (#29) */
    int         allow_active = 0;        /* --allow-active (#84) */
    const char *privdrop_user = NULL;    /* --user NAME    (#140) */
    int         no_privdrop  = 0;        /* --no-privdrop  (#140) */
    int         strict_lock  = 0;        /* --strict       (#84) */
    int         ds_allow_remote = 0;     /* --data-socket-allow-remote (#86) */
    const char *allow_ifaces[MAX_IFACES];/* --iface NAME, repeatable (#35) */
    int         allow_iface_count = 0;
    int         monitor_only = 0;        /* --monitor-only (#35) */
    const char *replay_arg   = NULL;     /* --replay FILE[,FILE] (#119) */
    long        max_ticks    = 0;        /* --ticks N; 0 = run until quit */
    time_t      session_start = sloth_wall();
    /* The wall stamp above is evidence (the DB session row, the posture
     * report header). The baseline settle delay below is a duration and
     * must not move when NTP steps the wall clock. */
    uint64_t    session_start_ms = sloth_mono_ms();
    /* NO_COLOR (no-color.org): any non-empty value disables colour.
     * Read before the flags so an explicit --no-color is redundant
     * rather than conflicting. */
    {
        const char *nc = getenv("NO_COLOR");
        if (nc && nc[0]) tui_set_color(0);
    }
    /* Seed the --tune registry here, on the main thread, before any
     * capture thread can be its first reader. Since #120 the capture
     * path reads knobs per frame (deauth, probe, SA Query, queue
     * eviction), and the registry seeds lazily on first read. */
    (void)tune_non_default();
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--out")) && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (!strcmp(argv[i], "--pcap-dir") && i + 1 < argc) {
            pcap_dir = argv[++i];
        } else if (!strcmp(argv[i], "--eapol-dir") && i + 1 < argc) {
            eapol_dir = argv[++i];
        } else if (!strcmp(argv[i], "--collect-handshakes")) {
            collect_hs = 1;
        } else if (!strcmp(argv[i], "--handshake-retention") && i + 1 < argc) {
            /* Whole days 0..EAPOL_MAX_RETENTION_DAYS, 0 = keep forever:
             * the bounds of the handshake.retention_days row. */
            if (!tune_alias("--handshake-retention",
                            TUNE_HANDSHAKE_RETENTION_DAYS, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--data-socket")) {
            /* Optional value. An explicit spec wins if the next token
             * doesn't look like another flag. Bare, it means the unix:
             * socket in /run/sloth (#136) — and when that directory is
             * absent or not ours, a refusal rather than loopback TCP:
             * an operator who named no transport must not get the one
             * every local account can read. */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                data_socket = argv[++i];
            } else {
                char why[256];
                int  ok = data_socket_default_dir_ok(DATA_SOCKET_DEFAULT_DIR,
                                                     why, sizeof(why));
                data_socket = data_socket_default_spec(ok);
                if (!data_socket) {
                    char msg[768];
                    data_socket_default_refusal(why, geteuid(),
                                                msg, sizeof(msg));
                    fputs(msg, stderr);
                    return 2;
                }
            }
        } else if (!strcmp(argv[i], "--refresh-ms") && i + 1 < argc) {
            char *endp = NULL;
            long v = strtol(argv[++i], &endp, 10);
            if (endp == argv[i] || *endp != '\0' || v < 1 || v > 60000) {
                fprintf(stderr,
                        "bad --refresh-ms %s (expected integer ms, 1..60000)\n",
                        argv[i]);
                return 2;
            }
            if (v < 50) v = 50;            /* floor — see usage */
            refresh_ms = (int)v;
        } else if (!strcmp(argv[i], "--report") && i + 1 < argc) {
            report_md = argv[++i];
        } else if (!strcmp(argv[i], "--report-json") && i + 1 < argc) {
            report_json = argv[++i];
        } else if (!strcmp(argv[i], "--check-manifest") && i + 1 < argc) {
            check_manifest = argv[++i];
        } else if (!strcmp(argv[i], "--iface") && i + 1 < argc) {
            if (allow_iface_count < MAX_IFACES)
                allow_ifaces[allow_iface_count++] = argv[++i];
            else {
                fprintf(stderr, "too many --iface entries (max %d)\n",
                        MAX_IFACES);
                return 2;
            }
        } else if (!strcmp(argv[i], "--monitor-only")) {
            monitor_only = 1;
        } else if (!strcmp(argv[i], "--hop")) {
            g_hop_enabled = 1;
        } else if (!strcmp(argv[i], "--tune-list")) {
            tune_print_list(stdout);
            return 0;
        } else if (!strcmp(argv[i], "--tune")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "sloth: --tune needs name=value "
                                "(see --tune-list)\n");
                return 2;
            }
            char terr[160];
            if (tune_set(argv[++i], terr, sizeof(terr)) != 0) {
                /* A mistyped knob exits rather than running with the
                 * default the operator thought they had changed (#82). */
                fprintf(stderr, "sloth: --tune %s\n", terr);
                return 2;
            }
        } else if (!strcmp(argv[i], "--allow-active")) {
            allow_active = 1;
        } else if (!strcmp(argv[i], "--user") && i + 1 < argc) {
            privdrop_user = argv[++i];
        } else if (!strcmp(argv[i], "--no-privdrop")) {
            no_privdrop = 1;
        } else if (!strcmp(argv[i], "--strict")) {
            strict_lock = 1;
        } else if (!strcmp(argv[i], "--data-socket-allow-remote")) {
            ds_allow_remote = 1;
        } else if (!strcmp(argv[i], "--no-correlate")) {
            seqnum_corr_set_enabled(0);
        } else if (!strcmp(argv[i], "--correlate-retain") && i + 1 < argc) {
            if (!tune_alias("--correlate-retain",
                            TUNE_CORRELATE_RETAIN_SECS, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--wps-pin-brute-cycles") && i + 1 < argc) {
            /* Already registry aliases since #82's reconciliation; #120
             * only swaps their atoi() for the registry's parse, so "5x"
             * is refused rather than read as 5. */
            if (!tune_alias("--wps-pin-brute-cycles",
                            TUNE_WPS_PIN_BRUTE_CYCLES, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--wps-lockout-cycles") && i + 1 < argc) {
            if (!tune_alias("--wps-lockout-cycles",
                            TUNE_WPS_LOCKOUT_CYCLES, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--wps-pbc-concurrent") && i + 1 < argc) {
            if (!tune_alias("--wps-pbc-concurrent",
                            TUNE_WPS_PBC_CONCURRENT, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--no-discovery")) {
            no_discovery = 1;
        } else if (!strcmp(argv[i], "--db") && i + 1 < argc) {
            db_path = argv[++i];
        } else if (!strcmp(argv[i], "--db-interval-secs") && i + 1 < argc) {
            /* atoi() before #120: "abc" read as 0, which db_set_* turned
             * into the default without a word. Now a startup error. */
            if (!tune_alias("--db-interval-secs",
                            TUNE_DB_INTERVAL_SECS, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--db-retain-days") && i + 1 < argc) {
            if (!tune_alias("--db-retain-days", TUNE_DB_RETAIN_DAYS, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--db-max-mb") && i + 1 < argc) {
            if (!tune_alias("--db-max-mb", TUNE_DB_MAX_MB, argv[++i]))
                return 2;
        } else if (!strcmp(argv[i], "--with-research") && i + 1 < argc) {
            /* Additive by construction (#73): a corpus that is missing,
             * unreadable or carrying the wrong schema logs a warning
             * and leaves sloth running with no research context. The
             * capture path must never depend on it. */
            g_research = rq_open(argv[++i]);
            if (!g_research) {
                fprintf(stderr, "sloth: research corpus unavailable: %s "
                                "— continuing without it\n", rq_open_error());
                /* Kept for the [f] view's header. "not loaded" alone
                 * sends the operator to check a flag they already
                 * passed; the reason is the actionable half. */
                snprintf(g_state.research_status,
                         sizeof(g_state.research_status), "%s",
                         rq_open_error());
            }
        } else if (!strcmp(argv[i], "--version") ||
                   !strcmp(argv[i], "-V")) {
            /* The version has only ever been visible in the TUI banner,
             * which means checking a deployed binary meant starting the
             * interface — awkward on a headless sensor and impossible
             * in a script. Goes to stdout, not stderr: this is the
             * requested output, not a diagnostic. */
            printf("sloth %s\n", SLOTH_VERSION);
            /* The loaded libraries, not the ones built against (#142):
             * libpcap and sqlite are the two that parse untrusted bytes,
             * and the distro patches them independently of this binary,
             * so matching a sensor against a CVE needs what the dynamic
             * linker found. First line unchanged for scripts that read
             * it alone. */
            printf("pcap: %s\n", libver_pcap());
            printf("sqlite: %s\n", libver_sqlite());
            return 0;
        } else if (!strcmp(argv[i], "--headless")) {
            headless = 1;
        } else if (!strcmp(argv[i], "--replay") && i + 1 < argc) {
            replay_arg = argv[++i];
        } else if (!strcmp(argv[i], "--ticks") && i + 1 < argc) {
            /* Strict, like --tune: a batch job that ran forever because
             * "3x" parsed as 0 would hang the CI step it was written for. */
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end || end == argv[i] || v < 1 || v > 1000000) {
                fprintf(stderr, "sloth: --ticks %s: want 1..1000000\n", argv[i]);
                return 2;
            }
            max_ticks = v;
        } else if (!strcmp(argv[i], "--no-color") ||
                   !strcmp(argv[i], "--no-colour")) {
            tui_set_color(0);
        } else if (!strcmp(argv[i], "--known-mac") && i + 1 < argc) {
            if (!ownership_add_known_mac(argv[++i])) return 2;
        } else if (!strcmp(argv[i], "--known-macs") && i + 1 < argc) {
            if (ownership_load_known_macs(argv[++i]) < 0) return 2;
        } else if (!strcmp(argv[i], "--my-ssid") && i + 1 < argc) {
            if (!ownership_add_ssid(argv[++i])) return 2;
        } else if (!strcmp(argv[i], "--my-bssid") && i + 1 < argc) {
            if (!ownership_add_bssid(argv[++i])) return 2;
        } else if (!strcmp(argv[i], "--inventory") && i + 1 < argc) {
            /* Hard failure, like --known-macs. An operator who believes
             * their APs are approved while the file silently failed to
             * load would read every one of their own radios as a
             * rogue — or miss the one that is (#89 slice 2). */
            char inv_err[INV_ERR_MAX];
            if (!inventory_load(argv[++i], inv_err, sizeof(inv_err))) {
                fprintf(stderr, "sloth: inventory %s\n", inv_err);
                return 2;
            }
            fprintf(stderr,
                    "sloth: inventory %s: %d networks, %d BSSIDs"
                    " (version %s, hash %s)\n",
                    argv[i], inventory_network_count(),
                    inventory_bssid_count(),
                    inventory_version()[0] ? inventory_version() : "-",
                    inventory_hash());
        } else if (!strcmp(argv[i], "--site") && i + 1 < argc) {
            if (!inventory_set_site(argv[++i])) return 2;
        } else if (!strcmp(argv[i], "--snapshot-out") && i + 1 < argc) {
            snapshot_out = argv[++i];
        } else if (!strcmp(argv[i], "--baseline-in") && i + 1 < argc) {
            baseline_in = argv[++i];
        } else if (!strcmp(argv[i], "--site-label") && i + 1 < argc) {
            site_label = argv[++i];
        } else if (!strcmp(argv[i], "--out-format") && i + 1 < argc) {
            out_format_t fmt;
            if (!formatter_parse_name(argv[++i], &fmt)) {
                fprintf(stderr,
                        "unknown --out-format %s (use jsonl|cef|syslog)\n",
                        argv[i]);
                return 2;
            }
            formatter_set(fmt);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    /* Observation profile (#84). Resolved after the whole argv is read,
     * not as each flag arrives, so the outcome cannot depend on the
     * order the operator typed them in. That guarantee now comes from
     * observe_resolve_profile() rather than from the order these blocks
     * happen to sit in: the request below records which flags were
     * given and never their sequence, and the resolver returns a final
     * state instead of applying flags one at a time. main() prints and
     * applies, decides nothing. Pinned by tests/test_observe.c, which
     * can reach the policy because it is pure — sloth_test does not
     * link main(). */
    /* Crackable material is opt-in (#87, owner decision 2026-09-30).
     * Resolved here, with the other whole-command-line policy, so the
     * outcome cannot depend on the order the flags were typed in.
     *
     * --eapol-dir without the opt-in is a startup error rather than a
     * run that writes nothing: the operator named a destination for
     * offline-crackable material, and a sloth that starts anyway reads as
     * "the export is happening". Failing loudly at argv time is also the
     * only version an init unit or a script can notice. */
    if (eapol_dir && !collect_hs) {
        fprintf(stderr,
                "sloth: --eapol-dir %s refused: PMKIDs and 4-way handshakes "
                "are offline-crackable material and need the explicit "
                "--collect-handshakes opt-in. Detection, alerting and the "
                "[e] view work without it — only writing to disk is gated.\n",
                eapol_dir);
        return 2;
    }
    eapol_set_collect_enabled(collect_hs);
    if (collect_hs && !eapol_dir)
        fprintf(stderr, "sloth: --collect-handshakes without --eapol-dir: "
                        "no destination, so nothing is exported\n");

    /* --replay (#119): the input is the files, so the flags that scope or
     * steer a live capture have nothing to act on. Refused rather than
     * ignored — an --iface that silently did nothing would read as a
     * replay filtered to that interface. Whole-command-line, like the
     * --eapol-dir check above. */
    char replay_paths[REPLAY_MAX_FILES][REPLAY_PATH_MAX];
    int  replay_count = 0;
    if (replay_arg) {
#ifndef WITH_PCAP
        fprintf(stderr, "sloth: --replay needs a build with libpcap "
                        "(this one is WITH_PCAP=0)\n");
        return 2;
#endif
        replay_count = replay_split_list(replay_arg, replay_paths,
                                         REPLAY_MAX_FILES);
        if (replay_count < 0) {
            fprintf(stderr, "sloth: --replay %s: want FILE[,FILE], at most "
                            "%d files, no empty names\n",
                    replay_arg, REPLAY_MAX_FILES);
            return 2;
        }
        if (allow_iface_count || monitor_only || g_hop_enabled) {
            fprintf(stderr, "sloth: --replay reads savefiles, not "
                            "interfaces: --iface, --monitor-only and --hop "
                            "do not apply\n");
            return 2;
        }
        /* --allow-active would send PTR queries for addresses read out of
         * the savefile - a replay that transmits on the analyst's own
         * network about someone else's capture. A replay stays passive
         * (MISSION section 2), so the combination is refused, not
         * silently narrowed (#119 review). */
        if (allow_active) {
            fprintf(stderr, "sloth: --replay is passive: --allow-active "
                            "would resolve addresses read from the "
                            "savefile; drop one of the two\n");
            return 2;
        }
    }

    /* socket_is_remote is only consulted when have_data_socket is set,
     * so the spec parser is never handed a NULL. */
    observe_profile_req_t prof_req = {
        .strict           = strict_lock,
        .allow_active     = allow_active,
        .hop              = g_hop_enabled,
        .have_data_socket = data_socket != NULL,
        .socket_is_remote = data_socket
                                ? data_socket_spec_is_remote(data_socket)
                                : 0,
    };
    observe_profile_t prof;
    observe_resolve_profile(&prof_req, &prof);

    /* Refused before any sink opens, so a refused run binds nothing —
     * the same ordering #85 established for scope. The refusal text is
     * main's job; which refusal applies is not. */
    switch (prof.refusal) {
    case OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT:
        fprintf(stderr, "sloth: --allow-active refused: --strict locks "
                        "strict observation for this run\n");
        return prof.exit_code;
    case OBSERVE_PROFILE_REFUSE_ROUTABLE_SOCKET_UNDER_STRICT:
        /* #84, owner ruling 2026-10-06. The loopback default
         * (tcp:127.0.0.1:8765) and a unix: path keep working, because
         * neither leaves the host and README has published bare
         * `--strict --data-socket` as usable.
         *
         * --data-socket-allow-remote does not override this: that flag
         * is how an operator says "expose this to the LAN", --strict is
         * how they say "not on this run", and a lock another flag can
         * override is not a lock. */
        fprintf(stderr,
                "sloth: --strict refuses a routable --data-socket (%s).\n"
                "       A routable listener transmits to whoever connects, "
                "which is what\n"
                "       --strict declines for this run. Bind loopback "
                "(tcp:127.0.0.1:PORT)\n"
                "       or a unix: path, or drop --strict.\n",
                data_socket);
        return prof.exit_code;
    case OBSERVE_PROFILE_OK:
        break;
    }

    if (prof.strict_locked) {
        observe_lock_strict();       /* scan trigger + discovery (slice 3) */
        dns_resolver_lock_strict();  /* resolver                (slice 2) */
    }
    if (prof.active_allowed)   observe_set_active_allowed(1);
    if (prof.resolver_enabled) dns_resolver_set_enabled(1);
    if (prof.active_allowed) {
        /* Never silent. A passive tool that quietly becomes active is
         * the failure mode #84 exists to prevent, so the opt-in names
         * exactly what it turned on — one line, on stderr, before any
         * of it can happen. */
        fprintf(stderr, "sloth: --allow-active enabled active reverse-DNS "
                        "resolution (PTR queries for observed addresses) and "
                        "nl80211 scan triggers on wireless interfaces; "
                        "everything else stays passive\n");
    }
    g_hop_enabled = prof.hop_enabled;

    if (g_hop_enabled) chanhop_init_default(&g_chanhop);

    /* Privilege plan (#140, owner ruling 2026-10-15: "only use root
     * when necessary"). Decided here, before anything opens, so a
     * --user that names no account exits 2 having opened nothing.
     * Applied below, between the capture opens (which need the
     * privilege) and the sinks (which must be created as the account
     * the run will live as). */
    privdrop_req_t pd_req;
    memset(&pd_req, 0, sizeof(pd_req));
    privdrop_probe(&pd_req);
    pd_req.hop          = g_hop_enabled;
    pd_req.allow_active = prof.active_allowed;
    pd_req.no_privdrop  = no_privdrop;
    pd_req.user_given   = privdrop_user != NULL;
    if (!privdrop_user) privdrop_user = PRIVDROP_DEFAULT_USER;
    {
        /* The reentrant form: nothing is threaded yet, but nothing here
         * should depend on that staying true. A lookup error (not just
         * "no such account") reads as unresolved, which refuses an
         * explicit --user and announces the default case. */
        static char pwbuf[16384];
        struct passwd pwd, *pw = NULL;
        if (getpwnam_r(privdrop_user, &pwd, pwbuf, sizeof(pwbuf), &pw) != 0)
            pw = NULL;
        if (pw) {
            pd_req.user_resolved = 1;
            pd_req.uid           = pw->pw_uid;
            pd_req.gid           = pw->pw_gid;
        }
    }
    privdrop_plan_t pd_plan;
    privdrop_resolve(&pd_req, &pd_plan);
    if (pd_plan.exit_code != 0) {
        fprintf(stderr, "sloth: %s (--user %s)\n", pd_plan.reason,
                privdrop_user);
        return pd_plan.exit_code;
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = refresh_ms > 0 ? refresh_ms : POLL_MS;
    g_state.active_view = VIEW_DASH;

    /* Capture scope is an authorisation boundary (#35, #85). The policy
     * is built and checked before any sink is opened and before the
     * data-stream worker exists:
     *   1. seed the explicit --iface entries;
     *   2. open (not run) the data-stream handle, fixing pkt_linktype;
     *   3. open (not run) the monitor radio; resolve --monitor-only;
     *   4. refuse to start if the request cannot be enforced;
     *   5. capture_run() / probe_run() — below, once the sinks are open,
     *      where capture_start() / probe_start() used to sit.
     * The allow-list is complete before the capture thread is created
     * and never written afterwards; capture_run() pins it to (ifindex,
     * name) pairs and thread creation publishes those to on_packet().
     * poll_data() revalidates the pins each tick (#85 slice 2). Refusing
     * here leaves no JSONL, DB session, socket or mDNS record behind. */
    for (int i = 0; i < allow_iface_count; i++)
        iface_allow_add(&g_state, allow_ifaces[i]);

    if (replay_count > 0) replay_platform_install();
    g_platform.init();
#ifdef WITH_PCAP
    /* --replay (#119) takes the place of steps 2-3: every file is opened
     * and routed here, before any sink, so a missing or undecodable file
     * is a refusal that leaves nothing behind — the same ordering #85
     * gave scope. The files are read further down, where the workers
     * would start. "replay" stands in for the interface names, and is
     * what sensor_health reports as the source. */
    replay_src_t replay_srcs[REPLAY_MAX_FILES];
    if (replay_count > 0) {
        for (int i = 0; i < replay_count; i++) {
            char rerr[512 + REPLAY_PATH_MAX];
            if (replay_check(replay_paths[i], &replay_srcs[i], rerr,
                             (int)sizeof(rerr)) != 0) {
                fprintf(stderr, "sloth: --replay %s\n", rerr);
                g_platform.cleanup();
                return 1;
            }
            if (replay_srcs[i].route == REPLAY_ROUTE_MONITOR) {
                snprintf(g_state.probe_iface, sizeof(g_state.probe_iface),
                         "replay");
            } else if (!g_state.pkt_iface[0]) {
                snprintf(g_state.pkt_iface, sizeof(g_state.pkt_iface),
                         "replay");
                g_state.pkt_linktype = replay_srcs[i].dlt;
            }
        }
    } else {
        capture_open(&g_state);
        probe_open(&g_state);
    }
    /* First-launch UX (#25): when a monitor interface is present, open on
     * the RF-aware dashboard rather than the interface list. */
    if (g_state.probe_iface[0])
        g_state.active_view = VIEW_DASH;
#endif
    /* probe_iface is set synchronously by probe_open(). */
    if (monitor_only && g_state.probe_iface[0])
        iface_allow_add(&g_state, g_state.probe_iface);
    {
        /* #57 tests the datalink end state, not the routes to it (an
         * older libpcap refusing SLL2, the open_live fallback, ...).
         * #85: a scope that cannot be enforced is a refusal, not a
         * warning — the old fallback captured everything. A sensor that
         * lost the boot race exits non-zero and Restart= re-resolves. */
        capture_scope_t v = capture_scope_verdict(
            allow_iface_count, monitor_only, g_state.probe_iface,
            g_state.iface_allowed_count, capture_is_open(),
            g_state.pkt_linktype);
        if (capture_scope_refuses(v)) {
            if (v == CAPTURE_SCOPE_REFUSE_DATALINK)
                fprintf(stderr, "sloth: %s (datalink is %d)\n",
                        capture_scope_reason(v), g_state.pkt_linktype);
            else
                fprintf(stderr, "sloth: %s\n", capture_scope_reason(v));
#ifdef WITH_PCAP
            probe_stop();
            capture_stop();
#endif
            dns_cleanup();
            g_platform.cleanup();
            return 1;
        }
        if (v == CAPTURE_SCOPE_NO_CAPTURE && replay_count == 0)
            fprintf(stderr, "sloth: %s\n", capture_scope_reason(v));
    }

    /* #140: drop here — every handle that needs CAP_NET_RAW is open,
     * the scope is sealed, and no thread exists yet (capset and
     * no_new_privs are per-thread, so a worker started earlier would
     * keep root's set). That is also why dns_init(), which starts the
     * --allow-active resolver worker, moved below this point. Every
     * sink after it is opened as the account the run lives as, so
     * secure_file's ownership check holds against that account. A
     * failed step fails closed: half-dropped is not a state to run in. */
    {
        char pd_err[160];
        if (privdrop_apply(&pd_plan, pd_err, sizeof(pd_err)) != 0) {
            fprintf(stderr, "sloth: privilege drop failed: %s — refusing "
                            "to run (--no-privdrop to keep privileges)\n",
                    pd_err);
#ifdef WITH_PCAP
            probe_stop();
            capture_stop();
#endif
            g_platform.cleanup();
            return 2;
        }
        char pd_msg[320];
        privdrop_describe(&pd_req, &pd_plan, privdrop_user, pd_msg,
                          sizeof(pd_msg));
        if (pd_msg[0]) fprintf(stderr, "%s\n", pd_msg);
    }
    dns_init();

    /* Export directories first: a refused one is a startup error, and
     * failing here — before the DB records a session — leaves nothing
     * half-begun. Both hold capture material (#87): created 0700, and
     * an existing permissive, foreign-owned or symlinked directory is
     * refused rather than chmod'ed or silently written into. */
    if (pcap_dir && alert_pcap_set_dir(pcap_dir) != 0) {
        fprintf(stderr, "sloth: --pcap-dir %s\n", alert_pcap_error());
        return 1;
    }
    if (eapol_dir && eapol_set_output_dir(eapol_dir) != 0) {
        fprintf(stderr, "sloth: --eapol-dir %s\n", eapol_export_error());
        return 1;
    }
    if (eapol_dir) {
        /* Sweep once here, then daily from the poll loop. At startup
         * because a sensor that is restarted more often than once a day
         * would otherwise never age anything out. */
        int swept = eapol_sweep(sloth_wall());
        if (eapol_retention_days() > 0)
            fprintf(stderr,
                    "sloth: handshake export %s — CRACKABLE MATERIAL, "
                    "retention %d day(s), %d artifact(s) swept at startup\n",
                    eapol_dir, eapol_retention_days(), swept > 0 ? swept : 0);
        else
            fprintf(stderr,
                    "sloth: handshake export %s — CRACKABLE MATERIAL, "
                    "retention disabled (--handshake-retention 0): artifacts "
                    "are kept until you delete them\n", eapol_dir);
    }
    if (jsonl_path) {
        if (!jsonl_open(jsonl_path)) {
            fprintf(stderr, "sloth: could not open jsonl output %s\n",
                    jsonl_error());
            return 1;
        }
    }
    if (db_path) {
        if (!db_open(db_path)) {
            /* Diagnostic already printed. A DB the operator explicitly
             * asked for and which cannot be opened is a startup error,
             * not something to silently continue without. */
            return 1;
        }
        fprintf(stderr,
                "sloth: db %s (schema v%d, every %ds, retain %dd, max %dMiB)\n",
                db_path, DB_SCHEMA_VERSION, db_interval(),
                db_retain_days(), db_max_mb());
        /* Record the visit so a later run can answer "what is new since
         * last time" (#56). --site-label already carries the operator's
         * name for the site, so reuse it rather than inventing one. */
        db_session_begin(site_label, session_start);
        if (db_previous_session_end() > 0)
            fprintf(stderr, "sloth: previous visit ended %ld\n",
                    (long)db_previous_session_end());
    }
    if (data_socket) {
        if (data_socket_init_ex(data_socket, ds_allow_remote) != 0) {
            /* error already printed by data_socket_init_ex */
            return 1;
        }
        fprintf(stderr, "sloth: data-socket listening on %s\n", data_socket);
        /* #135: a loopback TCP listener authenticates nobody — every
         * local account can connect to 127.0.0.1 (CWE-306) — where a
         * unix: path is created 0600 and the kernel vouches for the
         * peer's uid. Announced, not changed: the bare-flag default
         * above is #136's ruling, and MISSION §2 asks that an exposure
         * be said out loud rather than silently inherited. */
        if (strncmp(data_socket, "tcp:", 4) == 0 &&
            data_socket_spec_is_remote(data_socket) == 0)
            fprintf(stderr,
                    "sloth: data-socket %s is readable by every local account; "
                    "prefer unix:/run/sloth/sloth.sock (0600, kernel-checked peer)\n",
                    data_socket);
        /* #29: advertise the socket over mDNS so the sloth-ios client can
         * discover it by name — but only when it's bound to a routable
         * address (loopback/unix publish nothing) and the operator hasn't
         * opted out. sloth writes an Avahi service file; avahi-daemon does
         * the announcing. An opt-in network-using service under MISSION
         * §2 rule 1; --strict refuses the routable socket before here. */
        if (!no_discovery)
            discovery_publish(data_socket, NULL);
    }

    /* Say out loud whether addresses are being linked over time, and for
     * how long the evidence is kept (#94). An operator who has to read
     * the source to find out that a capability is on cannot answer for
     * it, and this is the one capability in sloth whose output can be
     * mistaken for an identification. */
    if (seqnum_corr_enabled())
        fprintf(stderr, "sloth: device correlation ON (seqnum trails across "
                        "MAC rotations, evidence retained %ds; hypothesis "
                        "only — not identification)\n",
                seqnum_corr_retain_secs());
    else
        fprintf(stderr, "sloth: device correlation OFF (--no-correlate)\n");

#ifdef WITH_PCAP
    /* Raw 802.11 evidence ring (#92), allocated before the monitor
     * worker exists so no frame can arrive to an uninitialised ring.
     *
     * Only with a monitor radio present: nothing but on_probe_frame()
     * feeds the ring, so on a run with no radiotap interface the arena
     * would be up to 32 MiB of permanently empty memory. A radio that
     * arrives later via an [m] retarget brings the ring up there —
     * probe_set_iface() makes the same call, which is idempotent.
     *
     * Zero-config, per the owner's 2026-09-30 ruling: ~1 % of MemTotal
     * clamped to [2 MiB, 32 MiB], no flag. An unreadable /proc/meminfo
     * — including every non-Linux build, where the path simply does not
     * exist — yields the floor rather than nothing. A failed allocation
     * is reported and the run continues: the ring is supporting
     * evidence, and losing it must not cost the operator detection. */
    if (g_state.probe_iface[0] && evidence_ring_init_default() != 0)
        fprintf(stderr, "sloth: evidence ring unavailable; 802.11 alerts "
                        "will carry no supporting frames\n");
    /* #85: both workers start here, after the scope policy was sealed
     * and every sink is open; nothing above this point can have decoded
     * a packet. */
    /* --replay (#119) decodes here instead, for the same reason: every
     * sink is open and the evidence ring exists. Synchronously, on this
     * thread and before the first tick, so tick 1 sees every file in
     * full and a run is a function of its inputs, not of how the decode
     * raced the poll loop. A file that fails part-way is fatal: a report
     * on a truncated replay would not say it was one. */
    for (int i = 0; i < replay_count; i++) {
        char rerr[512 + REPLAY_PATH_MAX];
        long nf = replay_run(&g_state, &replay_srcs[i], rerr, (int)sizeof(rerr));
        if (nf < 0) {
            fprintf(stderr, "sloth: --replay %s\n", rerr);
            return 1;
        }
        fprintf(stderr, "sloth: replayed %ld frame(s) from %s (%s path)\n",
                nf, replay_srcs[i].path,
                replay_srcs[i].route == REPLAY_ROUTE_MONITOR ? "802.11" : "IP");
    }
    capture_run();
    /* #85: an allow-listed name that did not resolve is failed closed,
     * which is right, but the only reports of it were the Interfaces
     * view's health strip and sensor_health's scope fields — so a
     * headless sensor, or an interactive one left on the dashboard,
     * collected no IP traffic and said nothing about why. Warn rather
     * than refuse: not pinning a name already suspends that interface's
     * collection, and continuing on a degraded scope is the decision
     * already taken for a capture that could not be opened at all
     * (cda85c5). Must run after capture_run() — the pins do not exist
     * until it has made them. The claim is scoped to the IP capture
     * stream because the 802.11 monitor radio is outside the --iface
     * allow-list (owner ruling 2026-10-04, bc316f5). */
    {
        char unpinned[MAX_IFACES * 17 + 1];
        int nun = capture_scope_unpinned(&g_state, unpinned,
                                         (int)sizeof(unpinned));
        switch (capture_scope_notice(capture_is_open(),
                                     g_state.iface_allowed_count, nun)) {
        case CAPTURE_SCOPE_NOTICE_ALL:
            fprintf(stderr, "sloth: none of the requested interfaces could "
                            "be resolved (%s): the IP capture stream will "
                            "admit nothing\n", unpinned);
            break;
        case CAPTURE_SCOPE_NOTICE_SOME:
            fprintf(stderr, "sloth: requested interfaces not resolved (%s): "
                            "frames arriving on them are refused for the "
                            "rest of this run; restart to re-pin\n", unpinned);
            break;
        case CAPTURE_SCOPE_NOTICE_NONE:
            break;
        }
    }
    probe_run();
#endif
    event_wake_init();
    updater_init(check_manifest);
    if (headless) {
        /* A headless run produces nothing an operator can see unless a
         * sink is configured. Warn rather than fail — a bare --headless
         * is a legitimate way to exercise the capture path — but say so,
         * because silently doing nothing observable is the worse
         * outcome. */
        if (!jsonl_path && !data_socket && !db_path && !report_md && !report_json)
            fprintf(stderr, "sloth: --headless with no -o, --data-socket, "
                            "--db or --report: this run produces no output\n");
        fprintf(stderr, "sloth: headless — terminal untouched\n");
    } else {
        tui_init();
    }

    int  first_poll = 1;
    long ticks_done = 0;
    while (!g_quit) {
        poll_data(&g_state);
        if (first_poll) {
            first_poll = 0;
            /* #25: with a monitor radio present, hide the noise interfaces
             * (loopback, docker, VPN, wired) so the operator's focus is
             * the radio world. Wi-Fi netdevs — the monitor radio AND any
             * managed station with its joined SSID — stay visible.
             * Un-hideable via [1]. Runs once, after the first poll
             * populates the interface list. */
            if (g_state.probe_iface[0])
                iface_hide_non_monitor(&g_state);
        }
        /* #23: once the RF picture has had time to settle, freeze it as the
         * session baseline so drift (new/gone/changed APs) can be reported. */
        if (g_state.probe_iface[0] && !wifi_baseline_ready() &&
            sloth_mono_ms() - session_start_ms >= 30000u)
            wifi_baseline_capture(&g_state);
        data_socket_tick();
        /* Daily retention sweep over the handshake export (#87). A time
         * comparison on every poll until the window rolls over; a no-op
         * entirely when nothing is being collected. */
        eapol_maintain(sloth_wall());
        /* Version check-in — cheap-when-idle; only re-reads the
         * manifest on mtime change or after UPDATER_CHECK_INTERVAL_S. */
        updater_tick(sloth_wall());
        updater_snapshot(&g_state);
        /* --ticks (#119): the last tick still emits and draws; only the
         * wait after it is skipped, since nothing follows to wait for. */
        int last_tick = max_ticks > 0 && ++ticks_done >= max_ticks;
        if (headless) {
            if (last_tick) break;
            /* No draw, no key read, no termios. Just wait out the poll
             * interval — honouring the wake fd so an alert still shortens
             * the cycle exactly as it does interactively. */
            headless_wait(g_state.poll_ms, event_wake_fd());
            event_wake_drain();
        } else {
            tui_draw(&g_state);
            if (last_tick) break;
            int ch = tui_poll_key(g_state.poll_ms, event_wake_fd());
            event_wake_drain();
            handle_key(&g_state, ch);
        }
    }

    if (!headless) tui_cleanup();
#ifdef WITH_PCAP
    probe_stop();
    capture_stop();
    /* After probe_stop() joins the monitor thread — the only writer — so
     * the arena cannot be freed from under a frame in flight. */
    evidence_ring_shutdown();
#endif

    /* Posture reports (roadmap #16 phase 5): rollup of alerts by
     * ATT&CK technique, cleartext exposures, and high-risk devices.
     * Written once at shutdown so the artifact represents a signed-off
     * session record — not a partial mid-run snapshot. */
    /* Reports name exposed credentials and high-risk devices: written
     * 0600, and an existing report must already be private — it is
     * validated before truncation, so a refused one is left as it was
     * (#87). A failed write is reported, not announced as written. */
    if (report_md) {
        char err[SFILE_ERR_MAX];
        FILE *fp = sfile_fopen(AT_FDCWD, report_md, SFILE_TRUNC,
                               err, sizeof(err));
        if (fp) {
            posture_render_md(fp, &g_state, session_start, g_research);
            if (sfile_fclose(fp, report_md, err, sizeof(err)) == 0)
                fprintf(stderr, "sloth: posture report -> %s\n", report_md);
            else
                fprintf(stderr, "sloth: --report %s\n", err);
        } else {
            fprintf(stderr, "sloth: could not open --report %s "
                            "(report skipped)\n", err);
        }
    }
    if (report_json) {
        char err[SFILE_ERR_MAX];
        FILE *fp = sfile_fopen(AT_FDCWD, report_json, SFILE_TRUNC,
                               err, sizeof(err));
        if (fp) {
            posture_render_json(fp, &g_state, session_start);
            if (sfile_fclose(fp, report_json, err, sizeof(err)) == 0)
                fprintf(stderr, "sloth: posture-json -> %s\n", report_json);
            else
                fprintf(stderr, "sloth: --report-json %s\n", err);
        } else {
            fprintf(stderr, "sloth: could not open --report-json %s "
                            "(report skipped)\n", err);
        }
    }

    /* Site snapshot export/import (#27) — passive AP inventory, no pcap. */
    if (baseline_in) {
        int d = wifi_snapshot_diff(&g_state, baseline_in, stderr);
        if (d < 0)
            fprintf(stderr, "sloth: could not read baseline %s\n", baseline_in);
        else
            fprintf(stderr, "sloth: %d change(s) vs baseline %s\n", d, baseline_in);
    }
    /* The snapshot is an AP target list: written 0600, an existing file
     * validated before truncation, and a refusal reported with the
     * reason rather than announced as written (#87). The reason already
     * carries the path, so it is not printed twice. */
    if (snapshot_out) {
        if (wifi_snapshot_write(&g_state, snapshot_out, site_label,
                                (long)sloth_wall()) == 0)
            fprintf(stderr, "sloth: site snapshot -> %s (%d APs)\n",
                    snapshot_out, g_state.beacon_count);
        else
            fprintf(stderr, "sloth: could not write snapshot %s\n",
                    wifi_snapshot_error());
    }

    dns_cleanup();
    g_platform.cleanup();
    jsonl_close();
    db_session_end(sloth_wall());
    db_close();
    discovery_unpublish();
    data_socket_cleanup();
    return 0;
}
