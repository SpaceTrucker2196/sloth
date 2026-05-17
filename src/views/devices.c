#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/devices.h"

#define DEV_PAGE 30

static void mac_str(const uint8_t mac[6], char *out, int sz) {
    snprintf(out, (size_t)sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void sources_str(int s, char out[8]) {
    /* 5 single-letter source flags: A D M B P, dash if unseen.
       (M for mDNS reserved — populated by future hookup.) */
    out[0] = (s & DEV_SRC_ARP)    ? 'A' : '-';
    out[1] = (s & DEV_SRC_DHCP)   ? 'D' : '-';
    out[2] = (s & DEV_SRC_MDNS)   ? 'M' : '-';
    out[3] = (s & DEV_SRC_BEACON) ? 'B' : '-';
    out[4] = (s & DEV_SRC_PROBE)  ? 'P' : '-';
    out[5] = (s & DEV_SRC_STA)    ? 'S' : '-';
    out[6] = '\0';
    out[7] = '\0';
}

void view_devices_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = DEV_PAGE;
#endif

    tui_normal(); TPRINT(" Devices: ");
    tui_bright();  TPRINT("%d", s->device_count);
    tui_dim();     TPRINT("  [up/dn] navigate  (joined from ARP/DHCP/Beacon/Probe/STA, newest first)");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-17s  %-15s  %-16s  %-20s  %-6s  %-3s  %s\n",
           "MAC", "IP", "Vendor", "Hostname / SSID", "Src", "RSI", "Hits");
    TPRINT(" %-17s  %-15s  %-16s  %-20s  %-6s  %-3s  %s\n",
           "-----------------", "---------------", "----------------",
           "--------------------", "------", "---", "----");
    tui_normal();

    if (s->device_count == 0) {
        tui_dim();
        TPRINT("  (no devices seen yet)\n");
        tui_normal();
        return;
    }

    int page_top = s->device_sel - page / 2;
    if (page_top + page > s->device_count) page_top = s->device_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->device_count) page_end = s->device_count;

    for (int row = page_top; row < page_end; row++) {
        const device_t *d = &s->devices[row];
        char mac[20]; mac_str(d->mac, mac, sizeof(mac));
        char src[8];  sources_str(d->sources, src);

        /* The "name" column: hostname preferred, else last probed SSID,
           else the AP marker. */
        char name[40];
        if (d->hostname[0])
            snprintf(name, sizeof(name), "%.31s", d->hostname);
        else if (d->last_ssid[0])
            snprintf(name, sizeof(name), "ssid:%.26s", d->last_ssid);
        else if (d->is_ap)
            snprintf(name, sizeof(name), "(access point)");
        else
            snprintf(name, sizeof(name), "-");

        char sig[8];
        if (d->signal_dbm < 0) snprintf(sig, sizeof(sig), "%d", d->signal_dbm);
        else                   snprintf(sig, sizeof(sig), "-");

        int hits = d->probe_count;

        if (row == s->device_sel) {
            tui_sel();
            TPRINT(" %-17s  %-15.15s  %-16.16s  %-20.20s  %-6s  %-3s  %d\n",
                   mac, d->ip, d->vendor, name, src, sig, hits);
            tui_reset();
        } else {
            tui_dim();    TPRINT(" %-17s", mac);
            tui_normal(); TPRINT("  %-15.15s", d->ip[0] ? d->ip : "-");

            if (d->vendor[0]) tui_bright(); else tui_dim();
            TPRINT("  %-16.16s", d->vendor[0] ? d->vendor : "?");

            if (d->is_ap)             tui_heat(0.7);
            else if (d->hostname[0])  tui_bright();
            else                      tui_normal();
            TPRINT("  %-20.20s", name);

            tui_dim();    TPRINT("  %-6s", src);
            tui_dim();    TPRINT("  %-3s", sig);

            if (hits > 0) tui_heat(0.5); else tui_dim();
            TPRINT("  %d\n", hits);
            tui_normal();
        }
    }
    tui_normal();
}

void view_devices_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->device_sel > 0) s->device_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->device_count > 0 && s->device_sel < s->device_count - 1)
            s->device_sel++;
        break;
    default:
        break;
    }
}
