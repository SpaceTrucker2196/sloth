#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "oui.h"
#include "views/arp.h"

#define ARP_PAGE 30

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ── Draw ────────────────────────────────────────────────── */

void view_arp_draw(const ntop_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = ARP_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" ARP neighbors: ");
    tui_bright();  TPRINT("%d", s->arp_count);
#ifndef WITH_NCURSES
    if (s->arp_count > 0) { tui_dim(); TPRINT("  [up/dn] navigate"); }
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-15s  %-17s  %-12s  %s\n",
           "IP", "MAC", "Vendor", "Interface");
    TPRINT(" %-15s  %-17s  %-12s  %s\n",
           "---------------", "-----------------",
           "------------", "---------");
    tui_normal();

    if (s->arp_count == 0) {
        tui_dim(); TPRINT("  (ARP table empty — no LAN neighbors seen yet)\n");
        tui_normal();
        return;
    }

    int top = s->arp_sel - page / 2;
    if (top + page > s->arp_count) top = s->arp_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->arp_count) end = s->arp_count;

    for (int row = top; row < end; row++) {
        const arp_entry_t *e = &s->arp_entries[row];
        char mac[18];
        fmt_mac(e->mac, mac, sizeof(mac));
        const char *vendor = oui_lookup(e->mac);
        const char *vstr   = vendor ? vendor : "";

#ifdef WITH_NCURSES
        if (row == s->arp_sel) {
            tui_sel();
            printw(" %-15s  %-17s  %-12.12s  %s\n",
                   e->ip, mac, vstr, e->iface);
            tui_reset();
        } else {
            tui_bright(); printw(" %-15s", e->ip);
            tui_dim();    printw("  %-17s", mac);
            tui_normal(); printw("  %-12.12s", vstr);
            tui_dim();    printw("  %s\n", e->iface);
            tui_normal();
        }
#else
        if (row == s->arp_sel) {
            tui_sel();
            printf(" %-15s  %-17s  %-12.12s  %s",
                   e->ip, mac, vstr, e->iface);
            tui_reset(); printf("\n");
        } else {
            tui_bright(); printf(" %-15s", e->ip);
            tui_dim();    printf("  %-17s", mac);
            tui_normal(); printf("  %-12.12s", vstr);
            tui_dim();    printf("  %s\n", e->iface);
            tui_normal();
        }
#endif
    }
    tui_normal();
}

/* ── Key handler ─────────────────────────────────────────── */

void view_arp_key(ntop_state_t *s, int key) {
    switch (key) {
    case NTOP_KEY_UP:
        if (s->arp_sel > 0) s->arp_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->arp_count > 0 && s->arp_sel < s->arp_count - 1)
            s->arp_sel++;
        break;
    default:
        break;
    }
}
