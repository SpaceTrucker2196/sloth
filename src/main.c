#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "ntop.h"
#include "tui.h"
#include "history.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"
#include "views/procs.h"
#ifdef WITH_PCAP
#  include "capture/capture.h"
#endif

static ntop_state_t g_state;
static volatile int g_quit = 0;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

static void poll_data(ntop_state_t *s) {
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    s->conn_count  = g_platform.get_conns(s->conns, MAX_CONNS);
#ifdef WITH_WIFI
    s->ap_count = g_platform.wifi_scan(s->aps, MAX_WIFI_APS);
#endif
    history_update(s);
    conn_rebuild_idx(s);
    /* clamp selections in case counts shrunk */
    if (s->iface_sel >= s->iface_count && s->iface_count > 0)
        s->iface_sel = s->iface_count - 1;
    if (s->wifi_sel >= s->ap_count && s->ap_count > 0)
        s->wifi_sel = s->ap_count - 1;
}

static void handle_key(ntop_state_t *s, int key) {
    switch (key) {
    case 'q': case 'Q':
        g_quit = 1;
        return;
    case '1': s->active_view = VIEW_IFACE;   return;
    case '2': s->active_view = VIEW_CONNS;   return;
    case '3': s->active_view = VIEW_WIFI;    return;
    case '4': s->active_view = VIEW_PACKETS; return;
    case '5': s->active_view = VIEW_PROCS;   return;
    case '\t':
        s->active_view = (view_t)((s->active_view + 1) % VIEW_COUNT);
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
    default: break;
    }
}

int main(void) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = POLL_MS;
    g_state.active_view = VIEW_IFACE;

    g_platform.init();
#ifdef WITH_PCAP
    capture_start(&g_state);
#endif
    tui_init();

    while (!g_quit) {
        poll_data(&g_state);
        tui_draw(&g_state);
        handle_key(&g_state, tui_poll_key(g_state.poll_ms));
    }

    tui_cleanup();
#ifdef WITH_PCAP
    capture_stop();
#endif
    g_platform.cleanup();
    return 0;
}
