#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "ntop.h"
#include "tui.h"

static ntop_state_t g_state;
static volatile int g_quit = 0;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

static void poll_data(ntop_state_t *s) {
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    s->conn_count  = g_platform.get_conns(s->conns, MAX_CONNS);
#ifdef WITH_WIFI
    s->ap_count = g_platform.wifi_scan(s->aps, MAX_WIFI_APS);
#endif
}

int main(void) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    memset(&g_state, 0, sizeof(g_state));
    g_state.poll_ms     = POLL_MS;
    g_state.active_view = VIEW_IFACE;

    g_platform.init();
    tui_init();

    while (!g_quit) {
        poll_data(&g_state);
        tui_draw(&g_state);

        int key = tui_poll_key(g_state.poll_ms);
        switch (key) {
        case 'q': case 'Q':
            g_quit = 1;
            break;
        case '1': g_state.active_view = VIEW_IFACE;   break;
        case '2': g_state.active_view = VIEW_CONNS;   break;
        case '3': g_state.active_view = VIEW_WIFI;    break;
        case '4': g_state.active_view = VIEW_PACKETS; break;
        case '\t':
            g_state.active_view = (view_t)((g_state.active_view + 1) % VIEW_COUNT);
            break;
        default:
            break;
        }
    }

    tui_cleanup();
    g_platform.cleanup();
    return 0;
}
