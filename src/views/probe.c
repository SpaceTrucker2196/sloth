#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ntop.h"
#include "tui.h"
#include "oui.h"
#include "capture/probe.h"
#include "views/probe.h"

#define PROBE_PAGE 30

/* ── Helpers ─────────────────────────────────────────────── */

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void fmt_age(time_t last_seen, char *buf, int sz) {
    time_t age = time(NULL) - last_seen;
    if      (age <   60) snprintf(buf, sz, "%llds", (long long)age);
    else if (age < 3600) snprintf(buf, sz, "%lldm", (long long)(age / 60));
    else                 snprintf(buf, sz, "%lldh", (long long)(age / 3600));
}

/* Signal strength → phosphor intensity */
static void phos_signal(int8_t dbm) {
    if      (dbm > -55) tui_bright();
    else if (dbm > -70) tui_normal();
    else                tui_dim();
}

/* ── Draw ────────────────────────────────────────────────── */

void view_probe_draw(const ntop_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = PROBE_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" Probe clients: ");
    tui_bright();  TPRINT("%d", s->probe_count);
    if (s->probe_iface[0]) {
        tui_dim(); TPRINT("  iface: ");
        tui_bright(); TPRINT("%s", s->probe_iface);
    } else {
        tui_dim(); TPRINT("  (no monitor interface)");
    }
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [up/dn] navigate  [c] clear");
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-17s  %-12s  %6s  %3s  %5s  %5s  %s\n",
           "MAC", "Vendor", "Signal", "Ch", "Seen", "Pkts", "Probing");
    TPRINT(" %-17s  %-12s  %6s  %3s  %5s  %5s  %s\n",
           "-----------------", "------------", "------", "---",
           "-----", "-----", "-------");
    tui_normal();

    if (s->probe_count == 0) {
        tui_dim();
        if (s->probe_iface[0])
            TPRINT("  (listening — no probe requests seen yet)\n");
        else
            TPRINT("  (no monitor-mode interface found — try: iw dev wlan1 set type monitor)\n");
        tui_normal();
        return;
    }

#ifdef WITH_NCURSES
    int page_top = s->probe_sel - page / 2;
#else
    int page_top = s->probe_sel - page / 2;
#endif
    if (page_top + page > s->probe_count) page_top = s->probe_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->probe_count) page_end = s->probe_count;

    for (int row = page_top; row < page_end; row++) {
        const probe_client_t *c = &s->probe_clients[row];

        char mac[18], age[8];
        fmt_mac(c->mac, mac, sizeof(mac));
        fmt_age(c->last_seen, age, sizeof(age));
        const char *ssid   = c->ssid[0] ? c->ssid : "(wildcard)";
        const char *vendor = oui_lookup(c->mac);
        const char *vstr   = vendor ? vendor : "";

#ifdef WITH_NCURSES
        if (row == s->probe_sel) {
            tui_sel();
            printw(" %-17s  %-12.12s  %6d  %3d  %5s  %5d  %.32s\n",
                   mac, vstr, (int)c->signal_dbm, c->channel, age,
                   c->frame_count, ssid);
            tui_reset();
        } else {
            tui_dim(); printw(" %s", mac);
            tui_dim(); printw("  %-12.12s", vstr);
            phos_signal(c->signal_dbm);
            printw("  %6d  %3d", (int)c->signal_dbm, c->channel);
            tui_dim(); printw("  %5s  %5d  ", age, c->frame_count);
            if (c->ssid[0]) tui_normal(); else tui_dim();
            printw("%.32s\n", ssid);
            tui_normal();
        }
#else
        if (row == s->probe_sel) {
            tui_sel();
            printf(" %-17s  %-12.12s  %6d  %3d  %5s  %5d  %.32s",
                   mac, vstr, (int)c->signal_dbm, c->channel, age,
                   c->frame_count, ssid);
            tui_reset(); printf("\n");
        } else {
            tui_dim(); printf(" %s", mac);
            tui_dim(); printf("  %-12.12s", vstr);
            phos_signal(c->signal_dbm);
            printf("  %6d  %3d", (int)c->signal_dbm, c->channel);
            tui_dim(); printf("  %5s  %5d  ", age, c->frame_count);
            if (c->ssid[0]) tui_normal(); else tui_dim();
            printf("%.32s\n", ssid);
            tui_normal();
        }
#endif
    }
    tui_normal();
}

/* ── Key handler ─────────────────────────────────────────── */

void view_probe_key(ntop_state_t *s, int key) {
    switch (key) {
    case NTOP_KEY_UP:
        if (s->probe_sel > 0) s->probe_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->probe_count > 0 && s->probe_sel < s->probe_count - 1)
            s->probe_sel++;
        break;
    case 'c': case 'C':
        probe_clear();
        s->probe_count = 0;
        s->probe_sel   = 0;
        break;
    default:
        break;
    }
}
