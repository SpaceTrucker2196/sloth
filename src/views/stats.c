#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ntop.h"
#include "tui.h"
#include "bandwidth.h"
#include "dns.h"
#include "views/stats.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void fmt_bytes(uint64_t b, char *buf, int sz) {
    if      (b >= (uint64_t)1 << 30) snprintf(buf, sz, "%.2f GB", (double)b / (1 << 30));
    else if (b >= (uint64_t)1 << 20) snprintf(buf, sz, "%.2f MB", (double)b / (1 << 20));
    else if (b >= (uint64_t)1 << 10) snprintf(buf, sz, "%.2f KB", (double)b / (1 << 10));
    else                              snprintf(buf, sz, "%llu B",  (unsigned long long)b);
}

static void fmt_uptime(time_t secs, char *buf, int sz) {
    int h = (int)(secs / 3600);
    int m = (int)((secs % 3600) / 60);
    int s = (int)(secs % 60);
    if (h > 0) snprintf(buf, sz, "%dh %02dm %02ds", h, m, s);
    else        snprintf(buf, sz, "%dm %02ds", m, s);
}

/* Find baseline index for iface name; returns -1 if not found. */
static int baseline_find(const ntop_state_t *s, const char *name) {
    for (int i = 0; i < s->stats_base_count; i++) {
        if (strcmp(s->stats_base_name[i], name) == 0) return i;
    }
    return -1;
}

/* ── Baseline ────────────────────────────────────────────── */

void stats_take_baseline(ntop_state_t *s) {
    s->stats_start      = time(NULL);
    s->stats_base_count = 0;
    int n = s->iface_count < MAX_IFACES ? s->iface_count : MAX_IFACES;
    for (int i = 0; i < n; i++) {
        s->stats_base_rx[i]   = s->ifaces[i].rx_bytes;
        s->stats_base_tx[i]   = s->ifaces[i].tx_bytes;
        s->stats_base_rxp[i]  = s->ifaces[i].rx_packets;
        s->stats_base_txp[i]  = s->ifaces[i].tx_packets;
        strncpy(s->stats_base_name[i], s->ifaces[i].name,
                sizeof(s->stats_base_name[i]) - 1);
        s->stats_base_name[i][sizeof(s->stats_base_name[i]) - 1] = '\0';
    }
    s->stats_base_count = n;
    s->stats_init       = 1;
}

/* ── Top-N by bandwidth ──────────────────────────────────── */

#define STATS_TOP 5

static void draw_top_bw(const ntop_state_t *s) {
    /* partial selection sort for top STATS_TOP entries */
    int indices[MAX_CONNS];
    int n = s->conn_bw_count < MAX_CONNS ? s->conn_bw_count : MAX_CONNS;
    for (int i = 0; i < n; i++) indices[i] = i;

    int top = n < STATS_TOP ? n : STATS_TOP;
    for (int i = 0; i < top; i++) {
        int best = i;
        double best_rate = s->conn_bw[indices[i]].rx_rate + s->conn_bw[indices[i]].tx_rate;
        for (int j = i + 1; j < n; j++) {
            double r = s->conn_bw[indices[j]].rx_rate + s->conn_bw[indices[j]].tx_rate;
            if (r > best_rate) { best_rate = r; best = j; }
        }
        int tmp = indices[i]; indices[i] = indices[best]; indices[best] = tmp;
    }

    /* header */
    tui_dim();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 Top %d by bandwidth \xe2\x94\x80\xe2\x94\x80\n", top > 0 ? top : STATS_TOP);
    tui_dim();
    TPRINT("  %-21s  %-21s  %-16s\n", "Local", "Remote", "Rate (rx/tx)");
    TPRINT("  %-21s  %-21s  %-16s\n",
           "---------------------", "---------------------", "----------------");
    tui_normal();

    if (top == 0) {
        tui_dim(); TPRINT("  (no connections tracked)\n");
        return;
    }

    for (int i = 0; i < top; i++) {
        const conn_bw_t *bw = &s->conn_bw[indices[i]];
        double total = bw->rx_rate + bw->tx_rate;
        if (total <= 0.0) break;

        char local[56], remote[56], rx_s[12], tx_s[12], rate_col[32];
        snprintf(local, sizeof(local), "%s:%u", bw->local_addr, bw->local_port);
        if (s->dns_enabled)
            dns_fmt_addr(bw->remote_addr, bw->remote_port, remote, sizeof(remote));
        else
            snprintf(remote, sizeof(remote), "%s:%u", bw->remote_addr, bw->remote_port);
        bw_fmt_rate(bw->rx_rate, rx_s, sizeof(rx_s));
        bw_fmt_rate(bw->tx_rate, tx_s, sizeof(tx_s));
        snprintf(rate_col, sizeof(rate_col), "%s\xe2\x86\x93 %s\xe2\x86\x91", rx_s, tx_s);

        tui_bright(); TPRINT("  %-21.21s  ", local);
        tui_normal(); TPRINT("%-21.21s  ", remote);
        if (total > 0) tui_bright(); else tui_dim();
        TPRINT("%-16s\n", rate_col);
        tui_normal();
    }
}

/* ── Draw ────────────────────────────────────────────────── */

void view_stats_draw(const ntop_state_t *s) {
    /* uptime */
    time_t now    = time(NULL);
    time_t uptime = s->stats_init ? (now - s->stats_start) : 0;
    char upbuf[32];
    fmt_uptime(uptime, upbuf, sizeof(upbuf));

    tui_normal(); TPRINT(" Session Statistics");
    tui_dim();    TPRINT("  uptime: ");
    tui_bright(); TPRINT("%s", upbuf);
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [r] reset");
#endif
    TPRINT("\n");

    /* ── Interface session totals ── */
    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 Interfaces \xe2\x94\x80\xe2\x94\x80\n");
    tui_dim();
    TPRINT("  %-8s  %-14s  %-14s  %-12s  %-12s  %s\n",
           "Name", "Session RX", "Session TX", "RX pkts", "TX pkts", "Live RX/s");
    TPRINT("  %-8s  %-14s  %-14s  %-12s  %-12s  %s\n",
           "--------", "--------------", "--------------",
           "------------", "------------", "----------");
    tui_normal();

    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *ifc = &s->ifaces[i];
        int bi = baseline_find(s, ifc->name);

        uint64_t drx = 0, dtx = 0, drxp = 0, dtxp = 0;
        if (bi >= 0) {
            drx  = ifc->rx_bytes   >= s->stats_base_rx[bi]  ? ifc->rx_bytes   - s->stats_base_rx[bi]  : 0;
            dtx  = ifc->tx_bytes   >= s->stats_base_tx[bi]  ? ifc->tx_bytes   - s->stats_base_tx[bi]  : 0;
            drxp = ifc->rx_packets >= s->stats_base_rxp[bi] ? ifc->rx_packets - s->stats_base_rxp[bi] : 0;
            dtxp = ifc->tx_packets >= s->stats_base_txp[bi] ? ifc->tx_packets - s->stats_base_txp[bi] : 0;
        }

        char srx[16], stx[16], rate_s[12];
        fmt_bytes(drx,  srx,    sizeof(srx));
        fmt_bytes(dtx,  stx,    sizeof(stx));
        bw_fmt_rate(ifc->rx_rate, rate_s, sizeof(rate_s));

        tui_bright(); TPRINT("  %-8.8s", ifc->name);
        tui_normal(); TPRINT("  %-14s  %-14s", srx, stx);
        tui_dim();    TPRINT("  %-12llu  %-12llu",
                             (unsigned long long)drxp, (unsigned long long)dtxp);
        if (ifc->rx_rate > 0 || ifc->tx_rate > 0) tui_bright(); else tui_dim();
        TPRINT("  %s\n", rate_s);
        tui_normal();
    }
    if (s->iface_count == 0) {
        tui_dim(); TPRINT("  (no interfaces)\n");
    }

    /* ── Connection protocol split ── */
    int tcp_n = 0, udp_n = 0, other_n = 0;
    for (int i = 0; i < s->conn_count; i++) {
        if      (s->conns[i].proto == PROTO_TCP) tcp_n++;
        else if (s->conns[i].proto == PROTO_UDP) udp_n++;
        else                                     other_n++;
    }
    int total_c = s->conn_count;

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 Connections (%d total) \xe2\x94\x80\xe2\x94\x80\n", total_c);

    /* draw a simple bar (20 chars wide) for TCP/UDP */
    char bar[22];
    if (total_c > 0) {
        int tcp_w  = (int)((double)tcp_n  / total_c * 20 + 0.5);
        int udp_w  = (int)((double)udp_n  / total_c * 20 + 0.5);
        int other_w = 20 - tcp_w - udp_w;
        if (other_w < 0) other_w = 0;
        for (int i = 0; i < tcp_w;   i++) bar[i]             = '#';
        for (int i = 0; i < udp_w;   i++) bar[tcp_w + i]     = '=';
        for (int i = 0; i < other_w; i++) bar[tcp_w + udp_w + i] = '.';
        bar[20] = '\0';
        tui_normal(); TPRINT("  [%s]", bar);
        tui_dim();
        TPRINT("  TCP: "); tui_bright(); TPRINT("%d", tcp_n);
        tui_dim();
        TPRINT("  UDP: "); tui_bright(); TPRINT("%d", udp_n);
        if (other_n > 0) {
            tui_dim(); TPRINT("  Other: "); tui_bright(); TPRINT("%d", other_n);
        }
        TPRINT("\n");
    } else {
        tui_dim(); TPRINT("  (no connections)\n");
    }

    /* ── Top-5 by bandwidth ── */
    TPRINT("\n");
    draw_top_bw(s);

    /* ── Packet capture stats ── */
#ifdef WITH_PCAP
    TPRINT("\n");
    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 Packet capture \xe2\x94\x80\xe2\x94\x80\n");
    tui_dim();   TPRINT("  Captured: ");
    tui_bright(); TPRINT("%d", s->pkt_count < MAX_PACKETS ? s->pkt_count : MAX_PACKETS);
    if (s->pkt_count >= MAX_PACKETS) {
        tui_dim(); TPRINT("  (ring — %d total seen)", s->pkt_count);
    }
    TPRINT("\n");
#endif

    tui_normal();
}

/* ── Key handler ─────────────────────────────────────────── */

void view_stats_key(ntop_state_t *s, int key) {
    switch (key) {
    case 'r': case 'R':
        s->stats_init = 0;   /* next poll_data call re-takes baseline */
        break;
    default:
        break;
    }
}
