/* Dashboard grid panels: the smaller equal-column panels that make up
 * the 3-panel rows (wifi/roaming/beacons, mdns/dhcp/ssdp, etc.) plus
 * the half-width DNS/ICMP log panels and the Summary panel. ncurses only. */

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "views/dashboard_internal.h"
#include "ip_color.h"
#include "oui.h"

#ifdef WITH_NCURSES


/* ── Bottom panels ───────────────────────────────────────── */

void draw_wifi_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    /* Title includes the scanning adapter and (if associated) the SSID
     * the adapter is currently on, so the operator knows whose
     * neighbourhood this scan is from. */
    char title[80];
    const char *iface = s->pkt_iface[0] ? s->pkt_iface : "?";
    const char *assoc_ssid = NULL;
#ifdef WITH_WIFI
    for (int i = 0; i < s->ap_count; i++) {
        if (s->aps[i].status == WIFI_STATUS_ASSOC && s->aps[i].ssid[0]) {
            assoc_ssid = s->aps[i].ssid; break;
        }
    }
#endif
    if (assoc_ssid)
        snprintf(title, sizeof(title), "WiFi APs (%s \xc2\xb7 %.24s)",
                 iface, assoc_ssid);
    else
        snprintf(title, sizeof(title), "WiFi APs (%s)", iface);
    panel_title_passive(y0, x, w, title, DASH_PANEL_WIFI);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-*s %4s %3s",
             w - 12 > 8 ? w - 12 : 8, "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->ap_count < rows ? s->ap_count : rows;
    int ssid_w = w - 12;
    if (ssid_w < 8) ssid_w = 8;
    for (int i = 0; i < n; i++) {
        const wifi_ap_t *a = &s->aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        move(y0 + 2 + i, x);
        attrset(COLOR_PAIR(CP_NORMAL));
        addstr("  ");
        const char *ssid = a->ssid[0] ? a->ssid : "(hidden)";
        char buf[40];
        snprintf(buf, sizeof(buf), "%-*.*s", ssid_w, ssid_w, ssid);
        tui_ssid_addstr(buf, (int)PKT_CAT_OTHER);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw(" %4d %3d", a->signal_dbm, a->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

/* Estimate distance from RSSI using the log-distance path-loss model:
 *     P(d) = P(d0) - 10 * n * log10(d / d0)
 *   -> d  = d0 * 10^((P(d0) - P) / (10*n))
 * Defaults: P(d0) = -30 dBm at d0 = 1 m, n = 3.0 (typical indoor with walls).
 *
 * This is wildly environment-dependent — real-world distance depends on
 * obstacles, antennas, frequency, multipath. Treat the number as a rough
 * order-of-magnitude hint, not a metric measurement. */
static double rssi_to_meters(int8_t rssi) {
    if (rssi >= -30) return 1.0;
    double exponent = ((-30.0) - (double)rssi) / 30.0;  /* 10 * n=3 */
    if (exponent > 5.0) exponent = 5.0;
    return pow(10.0, exponent);
}

/* "Roaming clients" panel: enhanced Probe view with vendor + estimated
 * distance. Pulls from the same probe_clients[] source the old Probe
 * panel used. Replaces draw_probe_panel — the data is identical, this
 * just exposes more of the radio metadata. */
void draw_radio_clients_panel(const sloth_state_t *s,
                                      int y0, int h, int x, int w) {
    /* Roaming clients comes from monitor-mode probe capture — show the
     * monitor adapter so it's clear what radio is listening. */
    char rtitle[64];
    const char *miface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(rtitle, sizeof(rtitle), "Roaming clients (%s)", miface);
    panel_title_passive(y0, x, w, rtitle, DASH_PANEL_ROAMING);
    attrset(COLOR_PAIR(CP_DIM));
    /* Geometry: 2 (margin) + 17 (MAC) + 1 + 14 (vendor) + 1 + ssid +
     *           1 + 4 (sig) + 1 + 5 (dist) = 46 + ssid_w. */
    int ssid_w = w - 46;
    if (ssid_w < 6) ssid_w = 6;
    clipline(y0 + 1, x, w, "  %-17s %-14s %-*s %4s %5s",
             "MAC", "vendor", ssid_w, "ssid", "sig", "dist");

    int rows = h - 2;
    int n = s->probe_count < rows ? s->probe_count : rows;
    for (int i = 0; i < n; i++) {
        const probe_client_t *p = &s->probe_clients[i];

        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);

        /* Shared vendor label (random-aware) — see oui_vendor_label. */
        int is_random = 0;
        const char *vendor = oui_vendor_label(p->mac, &is_random);

        double dist = rssi_to_meters(p->signal_dbm);
        char dist_buf[12];
        if      (dist >= 100.0)  snprintf(dist_buf, sizeof(dist_buf), ">99m");
        else if (dist >= 10.0)   snprintf(dist_buf, sizeof(dist_buf), "%.0fm", dist);
        else                     snprintf(dist_buf, sizeof(dist_buf), "%.1fm", dist);

        /* paint full row first */
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        int xc = x;
        move(y0 + 2 + i, xc);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw("  %-17s ", mac);
        xc += 2 + 17 + 1;

        /* vendor: dim for "?" / "(random)", bright for known */
        move(y0 + 2 + i, xc);
        if (is_random || vendor[0] == '?') attrset(COLOR_PAIR(CP_DIM));
        else                                attrset(COLOR_PAIR(CP_BRIGHT));
        printw("%-14.14s ", vendor);
        xc += 14 + 1;

        /* SSID column - coloured via hash palette */
        const char *ssid = p->ssid[0] ? p->ssid : "(any)";
        char ssid_buf[40];
        snprintf(ssid_buf, sizeof(ssid_buf), "%-*.*s", ssid_w, ssid_w, ssid);
        move(y0 + 2 + i, xc);
        tui_ssid_addstr(ssid_buf, (int)PKT_CAT_OTHER);
        xc += ssid_w + 1;

        /* sig: heat-colour by signal strength.
         *   >= -50 dBm  = bright (very close / strong)
         *   -50..-65    = normal phosphor
         *   -65..-80    = heat-mid
         *   < -80       = heat-hi (almost out of range) */
        move(y0 + 2 + i, xc);
        if      (p->signal_dbm >= -50) attrset(COLOR_PAIR(CP_BRIGHT));
        else if (p->signal_dbm >= -65) attrset(COLOR_PAIR(CP_NORMAL));
        else if (p->signal_dbm >= -80) attrset(COLOR_PAIR(CP_HEAT_MID));
        else                            attrset(COLOR_PAIR(CP_HEAT_HI));
        printw("%4d ", p->signal_dbm);
        xc += 4 + 1;

        /* dist: dim, since it's a rough estimate */
        move(y0 + 2 + i, xc);
        attrset(COLOR_PAIR(CP_DIM));
        printw("%-5s", dist_buf);
    }
    for (int i = n; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
    }
}

/* KARMA score for a BSSID from the synthesised candidate table, or 0 if
 * it isn't a candidate. Lets the beacon panel badge active lures (#30). */
static int karma_score_for(const sloth_state_t *s, const uint8_t bssid[6]) {
    for (int i = 0; i < s->karma_count; i++)
        if (memcmp(s->karma_aps[i].bssid, bssid, 6) == 0)
            return s->karma_aps[i].score;
    return 0;
}

#define KARMA_BADGE_SCORE 5   /* deep-red badge at/above this score */

void draw_beacon_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    char btitle[64];
    const char *biface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(btitle, sizeof(btitle), "Beacons (%s)", biface);
    panel_title_passive(y0, x, w, btitle, DASH_PANEL_BEACONS);
    attrset(COLOR_PAIR(CP_DIM));
    int ssid_w = w - 12;
    if (ssid_w < 8) ssid_w = 8;
    clipline(y0 + 1, x, w, "  %-*s %4s %3s", ssid_w, "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->beacon_count < rows ? s->beacon_count : rows;
    for (int i = 0; i < n; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        move(y0 + 2 + i, x);
        /* KARMA badge: a candidate scoring >= threshold gets a deep-red
         * "!" and a red SSID — the dashboard tell for an active lure
         * (#30), mirroring how THREAT_IP flags a hostile host. */
        int kscore = karma_score_for(s, b->bssid);
        int hot = kscore >= KARMA_BADGE_SCORE;
        if (hot) { attrset(COLOR_PAIR(CP_HEAT_PEAK)); addstr("! "); }
        else     { attrset(COLOR_PAIR(CP_NORMAL));    addstr("  "); }
        const char *ssid = b->ssid[0] ? b->ssid : "(hidden)";
        char buf[40];
        snprintf(buf, sizeof(buf), "%-*.*s", ssid_w, ssid_w, ssid);
        if (hot) { attrset(COLOR_PAIR(CP_HEAT_PEAK)); addstr(buf); }
        else     tui_ssid_addstr(buf, (int)PKT_CAT_OTHER);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw(" %4d %3d", b->signal_dbm, b->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

void draw_mdns_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "mDNS services", DASH_PANEL_MDNS);
    attrset(COLOR_PAIR(CP_DIM));
    /* Layout: 2 (margin) + instance_w + 1 (sep) + 6 (port) = w. Instance
     * column is capped at 32 chars so even on a wide terminal the column
     * stays tight and doesn't dominate the panel. */
    int instance_w = w - 9;
    if (instance_w < 8)  instance_w = 8;
    if (instance_w > 32) instance_w = 32;
    clipline(y0 + 1, x, w, "  %-*s %-6s", instance_w, "instance", "port");
    int rows = h - 2;
    int n = s->mdns_count < rows ? s->mdns_count : rows;
    for (int i = 0; i < n; i++) {
        const mdns_service_t *m = &s->mdns_services[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-*.*s %-6u",
                 instance_w, instance_w,
                 m->instance[0] ? m->instance : m->service,
                 (unsigned)m->port);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

void draw_dhcp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "DHCP events", DASH_PANEL_DHCP);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-9s %-15s %s", "msg", "ip", "host");
    int rows = h - 2;
    /* Newest first across the live-event ring. */
    int n = s->dhcp_event_count < rows ? s->dhcp_event_count : rows;
    for (int i = 0; i < n; i++) {
        int slot = s->dhcp_event_count - 1 - i;
        if (slot < 0) break;
        const dhcp_event_t *e = &s->dhcp_events[slot];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-9s %-15.15s %s",
                 dhcp_msg_name(e->msg_type),
                 e->ip[0] ? e->ip : "-",
                 e->hostname[0] ? e->hostname : "");
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

void draw_arp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "ARP table", DASH_PANEL_ARP);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-15s %-17s", "ip", "mac");
    int rows = h - 2;
    int n = s->arp_count < rows ? s->arp_count : rows;
    for (int i = 0; i < n; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->mac[0], a->mac[1], a->mac[2],
                 a->mac[3], a->mac[4], a->mac[5]);
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-15.15s %-17s", a->ip, mac);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

void draw_deauth_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    char dtitle[64];
    const char *diface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(dtitle, sizeof(dtitle), "Deauth (%s)", diface);
    panel_title_passive(y0, x, w, dtitle, DASH_PANEL_DEAUTH);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-17s %5s %s",
             "target", "rsn", "flood");
    int rows = h - 2;
    int n = s->deauth_count < rows ? s->deauth_count : rows;
    for (int i = 0; i < n; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        char dst[20];
        snprintf(dst, sizeof(dst), "%02x:%02x:%02x:%02x:%02x:%02x",
                 e->dst[0], e->dst[1], e->dst[2],
                 e->dst[3], e->dst[4], e->dst[5]);
        if (e->flood) attrset(COLOR_PAIR(CP_HEAT_PEAK));
        else          attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-17s %5u %s",
                 dst, (unsigned)e->reason, e->flood ? "FLOOD" : "");
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

void draw_stats_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Summary", DASH_PANEL_SUMMARY);
    /* Compose a few summary counters. */
    int crit_n = 0, warn_n = 0;
    for (int i = 0; i < s->alert_count; i++) {
        if (s->alerts[i].sev == ALERT_SEV_CRIT) crit_n++;
        else if (s->alerts[i].sev == ALERT_SEV_WARN) warn_n++;
    }
    int tcp_n = 0, udp_n = 0;
    for (int i = 0; i < s->conn_count; i++) {
        if (s->conns[i].proto == PROTO_TCP)      tcp_n++;
        else if (s->conns[i].proto == PROTO_UDP) udp_n++;
    }

    struct { const char *label; char val[40]; } rows_data[6];
    int rc = 0;
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d / %d", s->iface_count, s->ap_count); rows_data[rc++].label = "iface/ap ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d (TCP %d, UDP %d)", s->conn_count, tcp_n, udp_n);
                                                       rows_data[rc++].label = "conns    ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d", s->device_count);                  rows_data[rc++].label = "devices  ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d (DNS %d / TLS %d)",
             s->dns_log_count + s->tls_log_count +
             s->quic_log_count + s->http_log_count,
             s->dns_log_count, s->tls_log_count);     rows_data[rc++].label = "log evts ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d crit %d warn", crit_n, warn_n);      rows_data[rc++].label = "alerts   ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d", s->scan_count);                     rows_data[rc++].label = "scanners ";

    int rows = h - 1;          /* no header line — just the panel title */
    int n = rc < rows ? rc : rows;
    for (int i = 0; i < n; i++) {
        attrset(COLOR_PAIR(CP_DIM));
        clipline(y0 + 1 + i, x, w, "  %-9s", rows_data[i].label);
        attrset(COLOR_PAIR(CP_NORMAL));
        /* overprint the value to the right of the label */
        move(y0 + 1 + i, x + 2 + 9 + 1);
        addstr(rows_data[i].val);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 1 + i, x, w, "");
}

void draw_dns_log_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "DNS log", DASH_PANEL_DNS);
    /* DNS log shares the DNS category grey with DNS rows in the packets band. */
    int cat = (int)PKT_CAT_DNS;
    tui_pkt_bg_cat(cat);
    clipline(y0 + 1, x, w, "  %-3s %-5s %-22s %s",
             "Q/R", "type", "qname", "answer");
    int rows = h - 2;
    int n = s->dns_log_count < rows ? s->dns_log_count : rows;
    /* fixed prefix width = 2 + 3 + 1 + 5 + 1 + qname_w + 1 = 13 + qname_w
       Variable: qname grows, answer fills the remainder. */
    int qname_w  = (w - 13) / 2;
    if (qname_w < 16) qname_w = 16;
    int answer_w = w - (13 + qname_w);
    if (answer_w < 8) answer_w = 8;
    for (int i = 0; i < n; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        /* Paint grey bg first, then overprint. */
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
        /* status prefix: Q/R */
        int xc = x;
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        printw("  %-3s %-5.5s ",
               e->is_resp ? "R" : "Q", e->qtype);
        xc += 12;
        /* qname column — brand-coloured (Google rainbow, Firefox orange, …) */
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        {
            char qbuf[64];
            snprintf(qbuf, sizeof(qbuf), "%-*.*s", qname_w, qname_w, e->qname);
            tui_brand_addstr(qbuf, cat);
        }
        tui_pkt_bg_cat(cat);
        addch(' ');
        xc += qname_w + 1;
        /* answer column — IP if it looks like one */
        move(y0 + 2 + i, xc);
        if (strchr(e->answer, '.') && e->answer[0] >= '0' &&
            e->answer[0] <= '9') {
            tui_ip_addstr(e->answer, cat);
        } else {
            int is_nx = (strcmp(e->answer, "NXDOMAIN") == 0);
            if (is_nx)           tui_pkt_bg_cat(cat), attrset(COLOR_PAIR(CP_HEAT_HI));
            else if (e->is_resp) tui_pkt_bg_cat(cat), attrset(COLOR_PAIR(CP_BRIGHT));
            else                 tui_pkt_bg_cat(cat);
            printw("%.*s", answer_w, e->answer[0] ? e->answer : "-");
        }
    }
    for (int i = n; i < rows; i++) {
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
    }
}

void draw_icmp_log_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "ICMP log", DASH_PANEL_ICMP);
    int cat = (int)PKT_CAT_ICMP;
    tui_pkt_bg_cat(cat);
    clipline(y0 + 1, x, w, "  %-3s %-15s %s",
             "v",  "src", "type");
    int rows = h - 2;
    int n = s->icmp_log_count < rows ? s->icmp_log_count : rows;
    /* fixed prefix: 2 + 3 + 1 + 15 + 1 = 22 chars  */
    int desc_w = w - 22;
    if (desc_w < 8) desc_w = 8;
    for (int i = 0; i < n; i++) {
        const icmp_log_entry_t *e = &s->icmp_log[i];

        /* full-row grey bg */
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");

        int xc = x;
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        printw("  %-3s ", e->is_v6 ? "v6" : "v4");
        xc += 6;
        /* src IP coloured */
        move(y0 + 2 + i, xc);
        tui_ip_addstr(e->src, cat);
        /* pad to 15 chars + trailing space */
        tui_pkt_bg_cat(cat);
        int srclen = (int)strlen(e->src);
        for (int j = srclen; j < 15; j++) addch(' ');
        addch(' ');
        xc += 16;
        /* desc column, colour-coded by class */
        int is_err = e->is_v6
            ? (e->type >= 1 && e->type <= 4)
            : (e->type == 3 || e->type == 11 || e->type == 12);
        int is_req = e->is_v6 ? (e->type == 128) : (e->type == 8);
        if (is_err)      attrset(COLOR_PAIR(CP_HEAT_HI));
        else if (is_req) attrset(COLOR_PAIR(CP_BRIGHT));
        else             tui_pkt_bg_cat(cat);
        move(y0 + 2 + i, xc);
        printw("%.*s", desc_w, e->desc);
    }
    for (int i = n; i < rows; i++) {
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
    }
}

void draw_ssdp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "SSDP / UPnP", DASH_PANEL_SSDP);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-15s %s", "ip", "type");
    int rows = h - 2;
    int n = s->ssdp_count < rows ? s->ssdp_count : rows;
    for (int i = 0; i < n; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-15.15s %.*s",
                 d->ip, w - 18 > 0 ? w - 18 : 8, d->type);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}


#endif /* WITH_NCURSES */
