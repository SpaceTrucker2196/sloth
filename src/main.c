#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "wifi_chanhop.h"
#include "wifi_snapshot.h"
#include "wifi_baseline.h"
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
#include "twins.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "seqnum_track.h"
#include "assoc_track.h"
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
#include "devices.h"
#include "top_hosts.h"
#include "beacon_detect.h"
#include "jsonl.h"
#include "formatter.h"
#include "alert_pcap.h"
#include "data_socket.h"
#include "dns.h"
#include "scan.h"
#ifdef WITH_PCAP
#  include "capture/capture.h"
#  include "capture/probe.h"
#endif

static sloth_state_t g_state;
static volatile int g_quit = 0;

/* Passive channel-hop scheduler (issue #22). Off unless --hop is passed.
 * Drives platform set_channel from sloth's own observed activity — the
 * only kernel-state write sloth performs, and only on its own monitor
 * interface; see MISSION §2. */
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
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    chanhop_observe(&g_chanhop, (uint32_t)(s->pkt_total - last_total));
    last_total = s->pkt_total;
    if (chanhop_tick(&g_chanhop, now_ms))
        g_platform.set_channel(s->probe_iface, chanhop_current_freq(&g_chanhop));
    /* Surface the scan state for the interface view's channel bar. */
    s->scan_chan_count = chanhop_export(&g_chanhop, s->scan_chans,
                                        (int)(sizeof(s->scan_chans) / sizeof(s->scan_chans[0])),
                                        &s->scan_cur_idx);
}
#endif

static void poll_data(sloth_state_t *s) {
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    s->conn_count  = g_platform.get_conns(s->conns, MAX_CONNS);
#ifdef WITH_WIFI
    s->ap_count      = g_platform.wifi_scan(s->aps, MAX_WIFI_APS);
    s->wifi_sta_count = g_platform.get_wifi_stations(s->wifi_stas, MAX_WIFI_STAS);
#endif
    history_update(s);
    conn_rebuild_idx(s);
    bw_update(s);
    jsonl_emit_connections(s);
    twins_snapshot(s);
    jsonl_emit_twin_episodes(s);
    jsonl_emit_state_snapshots(s);
    if (!s->stats_init) stats_take_baseline(s);
#ifdef WITH_PCAP
    probe_snapshot(s);
    mon_frame_snapshot(s);
    probe_pnl_snapshot(s);
    eapol_snapshot(s);
    seqnum_snapshot(s);
    assoc_snapshot(s);
    channel_summary_update(s);
    mdns_snapshot(s);
    nbns_snapshot(s);
    dhcp_snoop_snapshot(s);
    ndp_snoop_snapshot(s);
    smb_snoop_snapshot(s);
    kerb_snoop_snapshot(s);
    ldap_snoop_snapshot(s);
    bgp_snoop_snapshot(s);
    ssh_snoop_snapshot(s);
    rdp_snoop_snapshot(s);
    snmp_snoop_snapshot(s);
    mqtt_snoop_snapshot(s);
    ssdp_snapshot(s);
    beacon_snapshot(s);
    deauth_snapshot(s);
    http_log_snapshot(s);
    tls_log_snapshot(s);
    quic_log_snapshot(s);
    dns_log_snapshot(s);
    ntp_log_snapshot(s);
    icmp_log_snapshot(s);
    cleartext_creds_snapshot(s);
#endif
    /* clamp selections in case counts shrunk */
    if (s->iface_sel >= s->iface_count && s->iface_count > 0)
        s->iface_sel = s->iface_count - 1;
    if (s->wifi_sel >= s->ap_count && s->ap_count > 0)
        s->wifi_sel = s->ap_count - 1;
    s->arp_count  = g_platform.get_arp(s->arp_entries, MAX_ARP_ENTRIES);
    if (s->arp_sel >= s->arp_count && s->arp_count > 0)
        s->arp_sel = s->arp_count - 1;
    s->dhcp_count = g_platform.get_dhcp(s->dhcp_leases, MAX_DHCP_LEASES);
    scan_update(s);
    bd_update(s, time(NULL));
    alerts_update(s);
    /* Feed the tui's alert-hot list: every alert with a concrete match_ip
     * gets the severity-coloured override for ALERT_HOT_TTL_S (1h).
     * LOW → yellow, WARN → orange, CRIT → red. Re-calls refresh the
     * timestamp; promotion-only — a later LOW won't downgrade an
     * earlier CRIT on the same IP within the TTL window. */
    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        if (!a->match_ip[0]) continue;
        tui_alert_hot_set(a->match_ip, (long)a->last_seen, (int)a->sev);
    }
    devices_update(s);
    top_hosts_update(s);
#ifdef WITH_PCAP
    chanhop_drive(s);
#endif
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
    switch (s->active_view) {
    case VIEW_IFACE:   view_iface_key(s, key);   break;
    case VIEW_CONNS:   view_conns_key(s, key);   break;
    case VIEW_WIFI:    view_wifi_key(s, key);     break;
    case VIEW_PACKETS: view_packets_key(s, key);  break;
    case VIEW_PROCS:   view_procs_key(s, key);    break;
    case VIEW_STATS:   view_stats_key(s, key);    break;
    case VIEW_PROBE:   view_probe_key(s, key);    break;
    case VIEW_ARP:     view_arp_key(s, key);      break;
    case VIEW_MDNS:    view_mdns_key(s, key);     break;
    case VIEW_NBNS:    view_nbns_key(s, key);          break;
    case VIEW_DHCP:    view_dhcp_snoop_key(s, key);    break;
    case VIEW_SSDP:    view_ssdp_key(s, key);          break;
    case VIEW_BEACON:  view_beacon_key(s, key);        break;
    case VIEW_DEAUTH:  view_deauth_key(s, key);        break;
    case VIEW_HTTP:    view_http_key(s, key);          break;
    case VIEW_TLS:     view_tls_key(s, key);           break;
    case VIEW_QUIC:    view_quic_key(s, key);          break;
    case VIEW_DNS:     view_dns_key(s, key);           break;
    case VIEW_NTP:     view_ntp_key(s, key);           break;
    case VIEW_ICMP:    view_icmp_key(s, key);          break;
    case VIEW_ALERTS:  view_alerts_key(s, key);        break;
    case VIEW_DEVICES: view_devices_key(s, key);       break;
    case VIEW_HELP:    view_help_key(s, key);          break;
    case VIEW_DASH:    view_dashboard_key(s, key);     break;
    case VIEW_PNL:     view_pnl_key(s, key);           break;
    case VIEW_EAPOL:   view_eapol_key(s, key);         break;
    case VIEW_SEQNUM:  view_seqnum_key(s, key);        break;
    case VIEW_ASSOC:   view_assoc_key(s, key);         break;
    case VIEW_CHANNEL: view_channel_key(s, key);       break;
    case VIEW_OSI:     view_osi_key(s, key);           break;
    case VIEW_TWINS:   view_twins_key(s, key);         break;
    default: break;
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

    switch (key) {
    case '1': s->active_view = VIEW_IFACE;   return;
    case '2': s->active_view = VIEW_CONNS;   return;
    case '3': s->active_view = VIEW_WIFI;    return;
    case '4': s->active_view = VIEW_PACKETS; return;
    case '5': s->active_view = VIEW_PROCS;   return;
    case '6': s->active_view = VIEW_STATS;   return;
    case '7': s->active_view = VIEW_PROBE;   return;
    case '8': s->active_view = VIEW_ARP;     return;
    case '9': s->active_view = VIEW_MDNS;    return;
    case '0': s->active_view = VIEW_NBNS;    return;
    case 'd': case 'D': s->active_view = VIEW_DHCP; return;
    case 's': case 'S': s->active_view = VIEW_SSDP;   return;
    case 'b': case 'B': s->active_view = VIEW_BEACON; return;
    case 'a': case 'A': s->active_view = VIEW_DEAUTH; return;
    case 'h': case 'H': s->active_view = VIEW_HTTP;   return;
    case 't': case 'T': s->active_view = VIEW_TLS;    return;
    case 'u': case 'U': s->active_view = VIEW_QUIC;   return;
    case 'r': case 'R': s->active_view = VIEW_DNS;    return;
    case 'p': case 'P': s->active_view = VIEW_NTP;    return;
    case 'i': case 'I': s->active_view = VIEW_ICMP;   return;
    case 'v': case 'V': s->active_view = VIEW_ALERTS; return;
    case 'g': case 'G': s->active_view = VIEW_DEVICES; return;
    case 'k': case 'K': s->active_view = VIEW_PNL;     return;
    case 'e': case 'E': s->active_view = VIEW_EAPOL;   return;
    case 'j': case 'J': s->active_view = VIEW_SEQNUM;  return;
    case 'w': case 'W': s->active_view = VIEW_ASSOC;   return;
    case 'm': case 'M': s->active_view = VIEW_CHANNEL; return;
    case 'l': case 'L': s->active_view = VIEW_OSI;     return;
    case 'x': case 'X': s->active_view = VIEW_TWINS;   return;
    case 'o': case 'O': s->active_view = VIEW_DASH;     return;
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
            "usage: %s [-o FILE] [--pcap-dir DIR] [--eapol-dir DIR] "
            "[--data-socket SPEC] [--out-format FORMAT] [--refresh-ms N] [--hop]\n"
            "       [--snapshot-out FILE] [--baseline-in FILE] [--site-label TEXT]\n"
            "  -o, --out FILE     append JSONL forensic log of all observed\n"
            "                     events to FILE (created if it doesn't exist)\n"
            "  --pcap-dir DIR     when a critical alert fires with a known\n"
            "                     flow, write the matching packets to a fresh\n"
            "                     pcap file under DIR\n"
            "  --eapol-dir DIR    append captured EAPOL PMKIDs / 4-way\n"
            "                     handshakes to DIR/eapol.22000 in hashcat\n"
            "                     mixed format (22000), AND write a\n"
            "                     per-handshake DIR/<bssid>_<sta>.pcap for\n"
            "                     replay with aircrack-ng / Wireshark\n"
            "  --data-socket [SPEC]\n"
            "                     stream the same records over a read-only\n"
            "                     socket. SPEC is one of:\n"
            "                       unix:/path/to/socket\n"
            "                       tcp:HOST:PORT  (HOST is a literal IPv4)\n"
            "                     If SPEC is omitted, defaults to\n"
            "                     tcp:127.0.0.1:8765 (loopback only).\n"
            "                     Read-only: nothing is ever read from the\n"
            "                     socket. Caller picks the bind address.\n"
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
            "                     dwelling longer where activity is seen. The\n"
            "                     only kernel-state write sloth performs; off by\n"
            "                     default. Needs monitor mode + CAP_NET_ADMIN\n"
            "                     (Linux). No frame is transmitted.\n"
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

int main(int argc, char **argv) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    const char *jsonl_path   = NULL;
    const char *pcap_dir     = NULL;
    const char *eapol_dir    = NULL;
    const char *data_socket  = NULL;
    const char *report_md    = NULL;   /* --report      FILE.md   */
    const char *report_json  = NULL;   /* --report-json FILE.json */
    const char *check_manifest = NULL; /* --check-manifest FILE   */
    const char *snapshot_out   = NULL; /* --snapshot-out FILE  (#27) */
    const char *baseline_in    = NULL; /* --baseline-in  FILE  (#27) */
    const char *site_label     = NULL; /* --site-label   TEXT  (#27) */
    int         refresh_ms   = 0;        /* 0 = use POLL_MS default */
    time_t      session_start = time(NULL);
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--out")) && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (!strcmp(argv[i], "--pcap-dir") && i + 1 < argc) {
            pcap_dir = argv[++i];
        } else if (!strcmp(argv[i], "--eapol-dir") && i + 1 < argc) {
            eapol_dir = argv[++i];
        } else if (!strcmp(argv[i], "--data-socket")) {
            /* Optional value — bare `--data-socket` defaults to the
             * loopback TCP listener so the common case of "stream to a
             * local consumer" needs zero typing. An explicit spec wins
             * if the next token doesn't look like another flag. */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                data_socket = argv[++i];
            } else {
                data_socket = "tcp:127.0.0.1:8765";
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
        } else if (!strcmp(argv[i], "--hop")) {
            g_hop_enabled = 1;
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

    if (g_hop_enabled) chanhop_init_default(&g_chanhop);

    if (jsonl_path) {
        if (!jsonl_open(jsonl_path)) {
            fprintf(stderr, "could not open jsonl output %s\n", jsonl_path);
            return 1;
        }
    }
    if (pcap_dir) {
        alert_pcap_set_dir(pcap_dir);
    }
    if (eapol_dir) {
        eapol_set_output_dir(eapol_dir);
    }
    if (data_socket) {
        if (data_socket_init(data_socket) != 0) {
            /* error already printed by data_socket_init */
            return 1;
        }
        fprintf(stderr, "sloth: data-socket listening on %s\n", data_socket);
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = refresh_ms > 0 ? refresh_ms : POLL_MS;
    g_state.active_view = VIEW_DASH;

    g_platform.init();
    dns_init();
#ifdef WITH_PCAP
    capture_start(&g_state);
    probe_start(&g_state);
    /* First-launch UX (#25): when a monitor interface is present, open on
     * the RF-aware dashboard rather than the interface list. */
    if (g_state.probe_iface[0])
        g_state.active_view = VIEW_DASH;
#endif
    event_wake_init();
    updater_init(check_manifest);
    tui_init();

    int first_poll = 1;
    while (!g_quit) {
        poll_data(&g_state);
        if (first_poll) {
            first_poll = 0;
            /* #25: with a monitor radio present, hide the noise interfaces
             * (loopback, docker, VPN, non-monitor wlan) so the operator's
             * focus is the RF world. Un-hideable via [1]. Runs once, after
             * the first poll populates the interface list. */
            if (g_state.probe_iface[0])
                iface_hide_non_monitor(&g_state);
        }
        /* #23: once the RF picture has had time to settle, freeze it as the
         * session baseline so drift (new/gone/changed APs) can be reported. */
        if (g_state.probe_iface[0] && !wifi_baseline_ready() &&
            time(NULL) - session_start >= 30)
            wifi_baseline_capture(&g_state);
        data_socket_tick();
        /* Version check-in — cheap-when-idle; only re-reads the
         * manifest on mtime change or after UPDATER_CHECK_INTERVAL_S. */
        updater_tick(time(NULL));
        updater_snapshot(&g_state);
        tui_draw(&g_state);
        int ch = tui_poll_key(g_state.poll_ms, event_wake_fd());
        event_wake_drain();
        handle_key(&g_state, ch);
    }

    tui_cleanup();
#ifdef WITH_PCAP
    probe_stop();
    capture_stop();
#endif

    /* Posture reports (roadmap #16 phase 5): rollup of alerts by
     * ATT&CK technique, cleartext exposures, and high-risk devices.
     * Written once at shutdown so the artifact represents a signed-off
     * session record — not a partial mid-run snapshot. */
    if (report_md) {
        FILE *fp = fopen(report_md, "w");
        if (fp) {
            posture_render_md(fp, &g_state, session_start);
            fclose(fp);
            fprintf(stderr, "sloth: posture report -> %s\n", report_md);
        } else {
            fprintf(stderr,
                    "sloth: could not open --report %s (report skipped)\n",
                    report_md);
        }
    }
    if (report_json) {
        FILE *fp = fopen(report_json, "w");
        if (fp) {
            posture_render_json(fp, &g_state, session_start);
            fclose(fp);
            fprintf(stderr, "sloth: posture-json -> %s\n", report_json);
        } else {
            fprintf(stderr,
                    "sloth: could not open --report-json %s (report skipped)\n",
                    report_json);
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
    if (snapshot_out) {
        if (wifi_snapshot_write(&g_state, snapshot_out, site_label,
                                (long)time(NULL)) == 0)
            fprintf(stderr, "sloth: site snapshot -> %s (%d APs)\n",
                    snapshot_out, g_state.beacon_count);
        else
            fprintf(stderr, "sloth: could not write snapshot %s\n", snapshot_out);
    }

    dns_cleanup();
    g_platform.cleanup();
    jsonl_close();
    data_socket_cleanup();
    return 0;
}
