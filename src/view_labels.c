#include "sloth.h"

/* The one "[key] Name" table for every view, in enum order. Lives here
 * — not in tui.c — so both the real ncurses/ANSI build and the test
 * binary (which swaps in null_tui.c) share a single source of truth.
 * The tab bar and the [?] help card both read it through view_label(),
 * so a new view can't appear in one place and be missing from the
 * other. Keep in sync with the view_t enum in sloth.h. */
static const char *view_labels[VIEW_COUNT] = {
    "[1] Interfaces",
    "[2] Connections",
    "[3] WiFi",
    "[4] Packets",
    "[5] Processes",
    "[6] Stats",
    "[7] Probe",
    "[8] ARP",
    "[9] mDNS",
    "[0] NBNS",
    "[d] DHCP",
    "[s] SSDP",
    "[b] Beacons",
    "[a] Deauth",
    "[h] HTTP",
    "[t] TLS",
    "[u] QUIC",
    "[r] DNS",
    "[p] NTP",
    "[i] ICMP",
    "[v] Alerts",
    "[g] Devices",
    "[?] Help",
    "[o] Dash",
    "[k] PNL",
    "[e] EAPOL",
    "[j] Seqnum",
    "[w] Assoc",
    "[m] Channel",
    "[l] OSI",
    "[x] Twins",
    "[y] KARMA",
    "[z] RADIUS",
    "[f] Research",
};

const char *view_label(view_t v) {
    if (v < 0 || v >= VIEW_COUNT) return "?";
    return view_labels[v];
}
