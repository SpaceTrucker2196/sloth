#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/help.h"

static void section(const char *title) {
    int len = (int)strlen(title);
    tui_dim();    TPRINT("\n  ");
    tui_bright(); TPRINT("%s\n", title);
    tui_dim();    TPRINT("  ");
    for (int i = 0; i < len && i < 40; i++) TPRINT("-");
    TPRINT("\n");
    tui_normal();
}

static void key_row(const char *k1, const char *l1,
                    const char *k2, const char *l2,
                    const char *k3, const char *l3) {
    tui_normal();  TPRINT("    ");
    tui_bright();  TPRINT("[%-3s]", k1);
    tui_normal();  TPRINT(" %-18s", l1);
    if (k2 && k2[0]) {
        tui_bright(); TPRINT(" [%-3s]", k2);
        tui_normal(); TPRINT(" %-18s", l2);
    } else {
        TPRINT("%-26s", "");
    }
    if (k3 && k3[0]) {
        tui_bright(); TPRINT(" [%-3s]", k3);
        tui_normal(); TPRINT(" %s", l3);
    }
    TPRINT("\n");
}

void view_help_draw(const sloth_state_t *s) {
    (void)s;
    tui_normal(); TPRINT(" sloth help");
    tui_dim();    TPRINT("       press [?] or any view key to return");
    TPRINT("\n");

    section("View selection");
    key_row("1", "Interfaces",   "d", "DHCP",     "u", "QUIC");
    key_row("2", "Connections",  "s", "SSDP",     "r", "DNS");
    key_row("3", "WiFi",         "b", "Beacons",  "p", "NTP");
    key_row("4", "Packets",      "a", "Deauth",   "i", "ICMP");
    key_row("5", "Processes",    "h", "HTTP",     "v", "Alerts");
    key_row("6", "Stats",        "t", "TLS",      "g", "Devices");
    key_row("7", "Probe",        "o", "Dashboard", "l", "OSI stack");
    key_row("8", "ARP",          "",  "",         "",  "");
    key_row("9", "mDNS",         "",  "",         "",  "");
    key_row("0", "NBNS",         "",  "",         "",  "");

    section("Global");
    key_row("tab", "cycle views forward",
            "n",   "toggle DNS-name resolve",
            "?",   "this screen");
    key_row("q",   "quit",
            "/",   "filter current view",
            "\\",  "clear filter");

    section("Per-view (when shown in a list view)");
    key_row("up/dn", "navigate rows",
            "c",     "clear log",
            "",      "");
    key_row("t",     "iface: toggle visible",
            "",      "",
            "",      "");

    section("Command line");
    tui_normal(); TPRINT("    ");
    tui_bright(); TPRINT("sloth -o FILE");
    tui_normal(); TPRINT("   append a JSONL forensic log of every observed event\n");
    TPRINT("\n");

    section("About");
    tui_dim();
    TPRINT("    sloth is a passive network monitor for Linux. Run it on the\n");
    TPRINT("    host whose traffic you want to observe -- it never injects\n");
    TPRINT("    packets, scans, or alters routes.\n");
    tui_normal();
}

void view_help_key(sloth_state_t *s, int key) {
    (void)s; (void)key;
}
