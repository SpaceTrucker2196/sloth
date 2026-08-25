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
#include "karma_detect.h"
#include "eap_track.h"
#include "twins.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "ctrl_frames.h"
#include "mle.h"
#include "captive_portal.h"
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
#include "ownership.h"
#include "transit.h"
#include "rf_quality.h"
#include "presence.h"
#include "tui_palette.h"
#include <sys/select.h>
#include "db.h"
#include "discovery.h"
#include "dns.h"
#include "scan.h"
#include "capture/probe.h"     /* self-stubbing without WITH_PCAP */
#include "capture/capture.h"   /* likewise — and #57's scope check needs it
                                  in the no-pcap build too */

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
    assoc_request_snapshot(s);
    btm_snapshot(s);
    csa_snapshot(s);
    rrm_snapshot(s);
    mle_snapshot(s);
    cp_snapshot(s);
    channel_summary_update(s);
    ctrl_snapshot(s);   /* annotates the channel rows built above (#64) */
    rf_quality_snapshot(s, time(NULL));
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
    eap_track_snapshot(s);   /* 802.1X EAP method tracking for ROGUE_RADIUS (#31) */
    alerts_update(s);
    karma_update(s);   /* KARMA/PineAP candidate table for VIEW_KARMA (#30) */
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
    /* #28: register the monitor radio as the Wi-Fi sensor and record its
     * cumulative observation count. Future RF families register the same way. */
    if (s->probe_iface[0]) {
        time_t now = time(NULL);
        sensor_t *sn = sensor_register(s, SENSOR_WIFI, "Wi-Fi monitor",
                                       s->probe_iface, now);
        sensor_observe(sn, mon_frame_total(), now);
        /* #21: fold this radio's beacon observations into the merged
         * multi-radio world model. With one adapter this is an identity
         * map; a second monitor radio would merge under its own sensor id.
         * Rebuilt each poll so aged-out APs drop from the merged view too. */
        if (sn) {
            wifi_merge_reset(&s->wifi_merged);
            wifi_merge_from_beacons(s, (int)(sn - s->sensors));
        }
    }
#ifdef WITH_PCAP
    /* Recurring transit (#54): feed every client currently classified
     * as passing into the episode tracker, keyed by a canonical
     * identity so a randomising device's rotated MACs count as one.
     * Runs after the probe snapshot has refreshed the client table. */
    {
        time_t t_now = time(NULL);
        for (int i = 0; i < s->probe_count; i++) {
            const probe_client_t *c = &s->probe_clients[i];
            if (presence_classify(&c->rssi_ring, c->first_seen,
                                  c->last_seen, t_now) != PRESENCE_TRANSIENT)
                continue;
            uint8_t id[6];
            transit_canonical_mac(s, c->mac, id);
            transit_observe(id, c->last_seen, c->signal_dbm);
        }
        transit_snapshot(s, t_now);
    }
    chanhop_drive(s);
#endif
    /* Durable state (#42) — last, so every snapshot above has already
     * refreshed the tables it reads.
     *
     * Reads sloth_state_t directly rather than hanging off the jsonl
     * emitters: every jsonl_emit_* short-circuits on any_sink(), which
     * is false when neither -o nor --data-socket is active, so a
     * --db-only run would silently write an empty database. It also
     * keeps durable last_seen off the change-only cache, which would
     * otherwise let it lag by up to the 300 s heartbeat.
     *
     * Its own cadence (--db-interval-secs), so slow storage never paces
     * the poll loop. */
    {
        time_t db_now = time(NULL);
        if (db_due(db_now)) db_tick(s, db_now);
    }
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
    case VIEW_KARMA:   view_karma_key(s, key);         break;
    case VIEW_ROGUE_RADIUS: view_rogue_radius_key(s, key); break;
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
    case 'y': case 'Y': s->active_view = VIEW_KARMA;   return;
    case 'z': case 'Z': s->active_view = VIEW_ROGUE_RADIUS; return;
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
            "[--data-socket SPEC] [--no-discovery] [--out-format FORMAT]\n"
            "       [--refresh-ms N] [--hop]\n"
            "       [--snapshot-out FILE] [--baseline-in FILE] [--site-label TEXT]\n"
            "       [--my-ssid SSID] [--my-bssid BSSID]\n"
            "       [--known-mac MAC] [--known-macs FILE]\n"
            "       [--headless] [--no-color]\n"
            "       [--db FILE] [--db-interval-secs N]\n"
            "       [--db-retain-days N] [--db-max-mb N]\n"
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
            "  --iface NAME       restrict the data stream to NAME (repeatable).\n"
            "                     Launch-time form of the interface view's [y]\n"
            "                     deselect, for headless deployments: frames\n"
            "                     from every other interface are dropped in the\n"
            "                     capture callback before decode. Purely\n"
            "                     logical — OS interface state is untouched.\n"
            "  --monitor-only     shorthand: restrict the data stream to the\n"
            "                     monitor-mode Wi-Fi interface sloth discovers\n"
            "                     at startup. Fail-open: if no monitor\n"
            "                     interface is found the stream stays\n"
            "                     unrestricted and a warning is printed, so a\n"
            "                     headless sensor is never blinded.\n"
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
            "  --db-max-mb N      hard ceiling on the database, MiB.\n"
            "                     Default 512, 0 = unlimited. On breach\n"
            "                     the oldest observation rows go first;\n"
            "                     entity, alert and credential rows are\n"
            "                     never dropped by this guard.\n"
            "  --headless         draw nothing and never touch the\n"
            "                     terminal: no screen clears, no escape\n"
            "                     sequences, no raw-mode termios change,\n"
            "                     no key handling. For appliance and\n"
            "                     systemd deployments where the output is\n"
            "                     a journal, not a screen. Capture,\n"
            "                     alerting and every sink (-o,\n"
            "                     --data-socket, --db, --report) run\n"
            "                     exactly as normal.\n"
            "  --no-color         suppress colour escape sequences but\n"
            "                     keep drawing. Also honoured via the\n"
            "                     NO_COLOR environment variable.\n"
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
    int         headless       = 0;    /* --headless           (#50) */
    const char *db_path        = NULL; /* --db FILE            (#42) */
    const char *snapshot_out   = NULL; /* --snapshot-out FILE  (#27) */
    const char *baseline_in    = NULL; /* --baseline-in  FILE  (#27) */
    const char *site_label     = NULL; /* --site-label   TEXT  (#27) */
    int         refresh_ms   = 0;        /* 0 = use POLL_MS default */
    int         no_discovery = 0;        /* --no-discovery: suppress mDNS advert (#29) */
    const char *allow_ifaces[MAX_IFACES];/* --iface NAME, repeatable (#35) */
    int         allow_iface_count = 0;
    int         monitor_only = 0;        /* --monitor-only (#35) */
    time_t      session_start = time(NULL);
    /* NO_COLOR (no-color.org): any non-empty value disables colour.
     * Read before the flags so an explicit --no-color is redundant
     * rather than conflicting. */
    {
        const char *nc = getenv("NO_COLOR");
        if (nc && nc[0]) tui_set_color(0);
    }
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
        } else if (!strcmp(argv[i], "--no-discovery")) {
            no_discovery = 1;
        } else if (!strcmp(argv[i], "--db") && i + 1 < argc) {
            db_path = argv[++i];
        } else if (!strcmp(argv[i], "--db-interval-secs") && i + 1 < argc) {
            db_set_interval(atoi(argv[++i]));
        } else if (!strcmp(argv[i], "--db-retain-days") && i + 1 < argc) {
            db_set_retain_days(atoi(argv[++i]));
        } else if (!strcmp(argv[i], "--db-max-mb") && i + 1 < argc) {
            db_set_max_mb(atoi(argv[++i]));
        } else if (!strcmp(argv[i], "--headless")) {
            headless = 1;
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
        /* #29: advertise the socket over mDNS so the sloth-ios client can
         * discover it by name — but only when it's bound to a routable
         * address (loopback/unix publish nothing) and the operator hasn't
         * opted out. sloth writes an Avahi service file; avahi-daemon does
         * the announcing. This is the one place sloth's presence touches
         * the network — gated by MISSION §2's discovery carve-out. */
        if (!no_discovery)
            discovery_publish(data_socket, NULL);
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = refresh_ms > 0 ? refresh_ms : POLL_MS;
    g_state.active_view = VIEW_DASH;

    /* Headless data-stream scoping (#35): seed the launch-time
     * allow-list before the capture thread starts so no packet is ever
     * seen outside it. */
    for (int i = 0; i < allow_iface_count; i++)
        iface_allow_add(&g_state, allow_ifaces[i]);

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
    /* #35: resolve --monitor-only after probe_start() has discovered
     * the monitor radio (probe_iface is set synchronously). Fail-open:
     * a sensor that lost the boot race keeps an unrestricted stream
     * rather than going blind; Restart=always re-resolves next start.
     * The entry lands after capture starts — same benign main-thread
     * write the [y] deselect already performs (#17). */
    if (monitor_only) {
        if (g_state.probe_iface[0])
            iface_allow_add(&g_state, g_state.probe_iface);
        else
            fprintf(stderr, "sloth: --monitor-only: no monitor-mode "
                    "interface found; data stream left unrestricted\n");
    }
    /* #57: the allow-list only bites on SLL2, the one datalink carrying an
     * ingress ifindex. Several routes land elsewhere — pcap_set_datalink()
     * refused by an older libpcap, the open_live fallback, capture failing
     * outright — and every one of them leaves scoping inert while capture
     * looks healthy. Test the end state, not the routes. Ordering matters:
     * capture_start() has set pkt_linktype and both allow-list sources have
     * been seeded, and tui_init() has not yet taken the terminal. */
    if (g_state.iface_allowed_count > 0
        && !capture_dlt_has_ifindex(g_state.pkt_linktype)) {
        if (g_state.pkt_linktype == 0)
            fprintf(stderr, "sloth: --iface/--monitor-only requested but "
                    "packet capture is disabled; scope is INACTIVE\n");
        else
            fprintf(stderr, "sloth: --iface/--monitor-only requested but "
                    "capture datalink is %d (not SLL2/276); per-interface "
                    "scope is INACTIVE — all traffic is captured\n",
                    g_state.pkt_linktype);
    }
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

    int first_poll = 1;
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
            time(NULL) - session_start >= 30)
            wifi_baseline_capture(&g_state);
        data_socket_tick();
        /* Version check-in — cheap-when-idle; only re-reads the
         * manifest on mtime change or after UPDATER_CHECK_INTERVAL_S. */
        updater_tick(time(NULL));
        updater_snapshot(&g_state);
        if (headless) {
            /* No draw, no key read, no termios. Just wait out the poll
             * interval — honouring the wake fd so an alert still shortens
             * the cycle exactly as it does interactively. */
            headless_wait(g_state.poll_ms, event_wake_fd());
            event_wake_drain();
        } else {
            tui_draw(&g_state);
            int ch = tui_poll_key(g_state.poll_ms, event_wake_fd());
            event_wake_drain();
            handle_key(&g_state, ch);
        }
    }

    if (!headless) tui_cleanup();
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
    db_session_end(time(NULL));
    db_close();
    discovery_unpublish();
    data_socket_cleanup();
    return 0;
}
