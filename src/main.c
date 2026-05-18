#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "sloth.h"
#include "tui.h"
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
#include "bandwidth.h"
#include "mdns_snoop.h"
#include "nbns_snoop.h"
#include "dhcp_snoop.h"
#include "ssdp_snoop.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "http_log.h"
#include "tls_log.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "alerts.h"
#include "devices.h"
#include "beacon_detect.h"
#include "jsonl.h"
#include "alert_pcap.h"
#include "dns.h"
#include "scan.h"
#ifdef WITH_PCAP
#  include "capture/capture.h"
#  include "capture/probe.h"
#endif

static sloth_state_t g_state;
static volatile int g_quit = 0;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

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
    if (!s->stats_init) stats_take_baseline(s);
#ifdef WITH_PCAP
    probe_snapshot(s);
    mdns_snapshot(s);
    nbns_snapshot(s);
    dhcp_snoop_snapshot(s);
    ssdp_snapshot(s);
    beacon_snapshot(s);
    deauth_snapshot(s);
    http_log_snapshot(s);
    tls_log_snapshot(s);
    quic_log_snapshot(s);
    dns_log_snapshot(s);
    ntp_log_snapshot(s);
    icmp_log_snapshot(s);
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
    devices_update(s);
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

    switch (key) {
    case 'q': case 'Q':
        g_quit = 1;
        return;
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
    case '?':           s->active_view = (s->active_view == VIEW_HELP)
                                          ? VIEW_IFACE : VIEW_HELP;
                        return;
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

    /* delegate remaining keys to the active view */
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
    default: break;
    }
}

static void print_usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [-o FILE] [--pcap-dir DIR]\n"
            "  -o, --out FILE     append JSONL forensic log of all observed\n"
            "                     events to FILE (created if it doesn't exist)\n"
            "  --pcap-dir DIR     when a critical alert fires with a known\n"
            "                     flow, write the matching packets to a fresh\n"
            "                     pcap file under DIR\n",
            argv0);
}

int main(int argc, char **argv) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    const char *jsonl_path = NULL;
    const char *pcap_dir   = NULL;
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--out")) && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (!strcmp(argv[i], "--pcap-dir") && i + 1 < argc) {
            pcap_dir = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (jsonl_path) {
        if (!jsonl_open(jsonl_path)) {
            fprintf(stderr, "could not open jsonl output %s\n", jsonl_path);
            return 1;
        }
    }
    if (pcap_dir) {
        alert_pcap_set_dir(pcap_dir);
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = POLL_MS;
    g_state.active_view = VIEW_IFACE;

    g_platform.init();
    dns_init();
#ifdef WITH_PCAP
    capture_start(&g_state);
    probe_start(&g_state);
#endif
    tui_init();

    while (!g_quit) {
        poll_data(&g_state);
        tui_draw(&g_state);
        handle_key(&g_state, tui_poll_key(g_state.poll_ms));
    }

    tui_cleanup();
#ifdef WITH_PCAP
    probe_stop();
    capture_stop();
#endif
    dns_cleanup();
    g_platform.cleanup();
    jsonl_close();
    return 0;
}
