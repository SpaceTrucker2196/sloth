#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "views/arp.h"

#define ARP_PAGE 30

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void fmt_lease_age(time_t expire, char *buf, int sz) {
    if (expire == 0) { snprintf(buf, sz, "--");  return; }
    time_t now = time(NULL);
    if (expire <= now) { snprintf(buf, sz, "exp"); return; }
    time_t rem = expire - now;
    if (rem >= 3600)
        snprintf(buf, sz, "%dh%02dm", (int)(rem / 3600), (int)((rem % 3600) / 60));
    else
        snprintf(buf, sz, "%dm", (int)(rem / 60));
}

static const char *dhcp_lookup(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->dhcp_count; i++) {
        if (strcmp(s->dhcp_leases[i].ip, ip) == 0)
            return s->dhcp_leases[i].hostname[0] ? s->dhcp_leases[i].hostname : NULL;
    }
    return NULL;
}

static time_t dhcp_expire(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->dhcp_count; i++) {
        if (strcmp(s->dhcp_leases[i].ip, ip) == 0)
            return s->dhcp_leases[i].expire;
    }
    return 0;
}

/* ── Draw ────────────────────────────────────────────────── */

void view_arp_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = ARP_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" ARP neighbors: ");
    tui_bright();  TPRINT("%d", s->arp_count);
    if (s->dhcp_count > 0) {
        tui_dim(); TPRINT("  leases: ");
        tui_bright(); TPRINT("%d", s->dhcp_count);
    }
#ifndef WITH_NCURSES
    if (s->arp_count > 0) { tui_dim(); TPRINT("  [up/dn] navigate"); }
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-15s  %-17s  %-16s  %-12s  %-6s  %s\n",
           "IP", "MAC", "Hostname", "Vendor", "Expiry", "Interface");
    TPRINT(" %-15s  %-17s  %-16s  %-12s  %-6s  %s\n",
           "---------------", "-----------------",
           "----------------", "------------", "------", "---------");
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
        const char *vendor   = oui_lookup(e->mac);
        const char *vstr     = vendor ? vendor : "";
        const char *hostname = dhcp_lookup(s, e->ip);
        const char *hstr     = hostname ? hostname : "";
        char expiry[12];
        fmt_lease_age(dhcp_expire(s, e->ip), expiry, sizeof(expiry));
        /* if no lease at all, show empty expiry */
        if (!hostname && dhcp_expire(s, e->ip) == 0) expiry[0] = '\0';

#ifdef WITH_NCURSES
        if (row == s->arp_sel) {
            tui_sel();
            printw(" %-15s  %-17s  %-16.16s  %-12.12s  %-6s  %s\n",
                   e->ip, mac, hstr, vstr, expiry, e->iface);
            tui_reset();
        } else {
            tui_bright(); printw(" %-15s", e->ip);
            tui_dim();    printw("  %-17s", mac);
            if (hostname) { tui_bright(); } else { tui_dim(); }
            printw("  %-16.16s", hstr);
            tui_normal(); printw("  %-12.12s", vstr);
            tui_dim();    printw("  %-6s  %s\n", expiry, e->iface);
            tui_normal();
        }
#else
        if (row == s->arp_sel) {
            tui_sel();
            printf(" %-15s  %-17s  %-16.16s  %-12.12s  %-6s  %s",
                   e->ip, mac, hstr, vstr, expiry, e->iface);
            tui_reset(); printf("\n");
        } else {
            tui_bright(); printf(" %-15s", e->ip);
            tui_dim();    printf("  %-17s", mac);
            if (hostname) { tui_bright(); } else { tui_dim(); }
            printf("  %-16.16s", hstr);
            tui_normal(); printf("  %-12.12s", vstr);
            tui_dim();    printf("  %-6s  %s\n", expiry, e->iface);
            tui_normal();
        }
#endif
    }
    tui_normal();
}

/* ── Key handler ─────────────────────────────────────────── */

void view_arp_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->arp_sel > 0) s->arp_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->arp_count > 0 && s->arp_sel < s->arp_count - 1)
            s->arp_sel++;
        break;
    default:
        break;
    }
}
