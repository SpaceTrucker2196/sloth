#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "bandwidth.h"
#include "dns.h"
#include "services.h"
#include "views/stats.h"
#include "geo.h"
#include "rule_coverage_live.h"

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
static int baseline_find(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < s->stats_base_count; i++) {
        if (strcmp(s->stats_base_name[i], name) == 0) return i;
    }
    return -1;
}

/* ── Baseline ────────────────────────────────────────────── */

void stats_take_baseline(sloth_state_t *s) {
    s->stats_start      = sloth_wall();
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

/* ── Connection geography ────────────────────────────────── */

#define GEO_TRACK 16
#define GEO_BAR   32

static void draw_geo(const sloth_state_t *s) {
    char codes[GEO_TRACK][4];
    int  counts[GEO_TRACK];
    int  n = 0;

    for (int i = 0; i < s->conn_count; i++) {
        const char *cc = geo_lookup_str(s->conns[i].remote_addr);
        if (!cc) continue;  /* IPv6 or unparseable — skip */

        int found = 0;
        for (int j = 0; j < n; j++) {
            if (strcmp(codes[j], cc) == 0) { counts[j]++; found = 1; break; }
        }
        if (!found && n < GEO_TRACK) {
            strncpy(codes[n], cc, 3); codes[n][3] = '\0';
            counts[n++] = 1;
        }
    }

    if (n == 0) {
        tui_dim(); TPRINT("  (no connections)\n"); return;
    }

    /* selection sort descending by count */
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (counts[j] > counts[best]) best = j;
        if (best != i) {
            int  ti = counts[i]; counts[i] = counts[best]; counts[best] = ti;
            char tc[4]; memcpy(tc, codes[i], 4);
            memcpy(codes[i], codes[best], 4); memcpy(codes[best], tc, 4);
        }
    }

    int max_c = counts[0];
    int show  = n < 8 ? n : 8;
    for (int i = 0; i < show; i++) {
        int bar_w = (max_c > 0) ? (counts[i] * GEO_BAR / max_c) : 0;
        tui_dim(); TPRINT("  %-2s  ", codes[i]);
        tui_bright();
        for (int b = 0; b < bar_w; b++) TPRINT("\xe2\x96\x88");
        tui_dim(); TPRINT("  %d\n", counts[i]);
    }
    tui_normal();
}

/* ── Top-N by bandwidth ──────────────────────────────────── */

#define STATS_TOP 5

static void draw_top_bw(const sloth_state_t *s) {
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
        svc_fmt_addr(local, sizeof(local), bw->local_addr, bw->local_port);
        if (s->dns_enabled)
            dns_fmt_addr(bw->remote_addr, bw->remote_port, remote, sizeof(remote));
        else
            svc_fmt_addr(remote, sizeof(remote), bw->remote_addr, bw->remote_port);
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

/* ── Collection gaps (#242 item 3) ───────────────────────────
 *
 * The rules that cannot fire, or can and miss part of their evidence,
 * grouped by reason: the same grouping and order as the posture
 * report's "Collection coverage" (cov_live_gaps(), the first thing to
 * fix first). Within a reason the kinds are grouped by the input they
 * read, so a line says what is missing as well as what it costs. Each
 * group is one logical line broken between words at the terminal's
 * width (gap_put()), so the list flexes with the screen, nothing is
 * cut and no kind name is split. Without a status it says "not
 * assessed" and why, never zero counts: zero blind rules would read as
 * full coverage. */

#define GAP_LINE 4096

static void gap_addf(char *buf, int *off, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void gap_addf(char *buf, int *off, const char *fmt, ...) {
    if (*off >= GAP_LINE - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, (size_t)(GAP_LINE - *off), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    *off += n;
    if (*off > GAP_LINE - 1) *off = GAP_LINE - 1;
}

/* Draw `line` from column 0, broken before a word that would reach the
 * last column, each later row after `indent` spaces; the spaces at a
 * break are dropped, and a word ending in ':' is kept with the word
 * after it. Every string here is ASCII (kind, input and
 * reason names, fixed prose), so an octet is a cell. The ANSI build has
 * no width: one row. A word longer than a row is drawn whole and the
 * terminal folds it. */
static void gap_put(const char *line, int indent) {
#ifdef WITH_NCURSES
    int width = getmaxx(stdscr) - 1;
#else
    int width = 1 << 30;
#endif
    int x = 0;
    const char *p = line;
    while (*p) {
        const char *w = p;
        while (*w == ' ') w++;
        if (!*w) break;
        const char *e = w;
        while (*e && *e != ' ') e++;
        /* An input's label stays with its first kind ("ip: X"). */
        if (e > w && e[-1] == ':' && e[0] == ' ' && e[1] && e[1] != ' ')
            for (e++; *e && *e != ' '; e++) {}
        int sp = (int)(w - p), wl = (int)(e - w);
        if (x > indent && x + sp + wl > width) {
            TPRINT("\n%*s", indent, "");
            x = indent;
            sp = 0;
        }
        TPRINT("%*s%.*s", sp, "", wl, w);
        x += sp + wl;
        p = e;
    }
    TPRINT("\n");
}

static void draw_gaps(const sloth_state_t *s) {
    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 Collection gaps \xe2\x94\x80\xe2\x94\x80\n");
    cov_live_state_t st = cov_live_state();
    if (st != COV_LIVE_VALID) {
        tui_dim();    TPRINT("  not assessed: ");
        tui_normal(); TPRINT("%s\n", cov_live_state_why(st));
        tui_normal();
        return;
    }
    int ob = 0, pa = 0, bl = 0;
    cov_live_counts(&ob, &pa, &bl);
    const cov_env_t *e = cov_live_env();
    char bands[24];
    cov_bands_str(e->bands, bands, sizeof(bands));
    tui_dim();    TPRINT("  %d rules: ", ob + pa + bl);
    tui_bright(); TPRINT("%d", ob);
    tui_dim();    TPRINT(" observable  ");
    tui_bright(); TPRINT("%d", pa);
    tui_dim();    TPRINT(" partly  ");
    tui_bright(); TPRINT("%d", bl);
    tui_dim();    TPRINT(" blind    radios %d  channels %d  %s  bands %s\n",
                         e->radios, e->channels, e->hopping ? "hopping" : "fixed",
                         bands[0] ? bands : "unknown");

    cov_gap_t gaps[COV_R_COUNT];
    int ng = cov_live_gaps(gaps, COV_R_COUNT);
    if (ng == 0) { tui_dim(); TPRINT("  none: every rule is observable\n"); }
    for (int i = 0; i < ng; i++) {
        char line[GAP_LINE];
        int off = 0;
        line[0] = '\0';
        gap_addf(line, &off, "  %s %s (%d)", cov_status_name(gaps[i].st),
                 cov_reason_name(gaps[i].why), gaps[i].n);
        for (int in = 0; in < COV_IN_COUNT; in++) {
            int first = 1;
            for (int k = 0; k < gaps[i].n; k++) {
                const cov_inputs_t *d = cov_inputs(gaps[i].kind[k]);
                if (!d || (int)d->input != in) continue;
                if (first) gap_addf(line, &off, "  %s:",
                                    cov_input_name((cov_input_t)in));
                gap_addf(line, &off, " %s", cov_kind_name(gaps[i].kind[k]));
                first = 0;
            }
        }
        if (gaps[i].st == COV_BLIND) tui_bright(); else tui_normal();
        gap_put(line, 6);
    }

    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        if (a->type != ALERT_TYPE_SENSOR_SUPPRESSED || a->resolved) continue;
        tui_bright(); TPRINT("  SENSOR_SUPPRESSED open: %s\n", a->key);
    }
    tui_dim();
    for (int i = 0; i < COV_LIMIT_COUNT; i++) {
        char line[GAP_LINE];
        snprintf(line, sizeof(line), "  %s", cov_limits[i]);
        gap_put(line, 4);
    }
    tui_normal();
}

/* ── Draw ────────────────────────────────────────────────── */

void view_stats_draw(const sloth_state_t *s) {
    /* uptime */
    time_t now    = sloth_wall();
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

    /* ── Collection gaps ── under the interfaces, above the traffic
     * tables: it describes the sensor, as the rows above do, and a
     * section at the foot of this view is below a 33-row screen. */
    draw_gaps(s);

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

    /* ── Connection geography ── */
    TPRINT("\n");
    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 Connection geography \xe2\x94\x80\xe2\x94\x80\n");
    draw_geo(s);

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

void view_stats_key(sloth_state_t *s, int key) {
    switch (key) {
    case 'r': case 'R':
        s->stats_init = 0;   /* next poll_data call re-takes baseline */
        break;
    default:
        break;
    }
}
