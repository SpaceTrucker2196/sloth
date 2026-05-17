#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntop.h"
#include "tui.h"
#include "bandwidth.h"
#include "dns.h"
#include "services.h"
#include "views/conns.h"
#include "geo.h"

#define CONNS_PAGE 30

static const char *tcp_state_name(int st) {
    static const char *names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };
    if (st < 0 || st > 11) return "?";
    return names[st];
}

/* Phosphor intensity for a TCP state: bright = active, dim = dying. */
static void phos_tcp_state(int proto, int state) {
    if (proto != PROTO_TCP) { tui_normal(); return; }
    switch (state) {
    case 1:  /* ESTABLISHED */
    case 2:  /* SYN_SENT   */
    case 3:  /* SYN_RECV   */
    case 10: /* LISTEN      */
        tui_bright(); break;
    case 4:  /* FIN_WAIT1  */
    case 5:  /* FIN_WAIT2  */
    case 6:  /* TIME_WAIT  */
    case 7:  /* CLOSE      */
    case 8:  /* CLOSE_WAIT */
    case 9:  /* LAST_ACK   */
    case 11: /* CLOSING    */
        tui_dim(); break;
    default:
        tui_normal(); break;
    }
}

/* ── Rate / RTT formatting & sparkline helpers ───────────── */

static void fmt_rate(double bps, char *buf, int sz) {
    bw_fmt_rate(bps, buf, sz);
}

static void fmt_rtt(uint32_t us, char *buf, int sz) {
    if (us == 0)        { snprintf(buf, sz, "--");            return; }
    if (us < 1000)      { snprintf(buf, sz, "%uus", us);     return; }
    if (us < 1000000)   { snprintf(buf, sz, "%.1fms", us / 1000.0); return; }
    snprintf(buf, sz, "%.2fs", us / 1000000.0);
}

static void bw_spark(const conn_bw_t *bw, char *out, int w) {
    static const char lvl[] = " ._-=+#";
    int nlvl = 7;
    float mx = 1.0f;
    for (int i = 0; i < bw->hist_count; i++) {
        int hi = (bw->hist_head - bw->hist_count + i + CONN_BW_HIST) % CONN_BW_HIST;
        if (bw->rx_hist[hi] > mx) mx = bw->rx_hist[hi];
        if (bw->tx_hist[hi] > mx) mx = bw->tx_hist[hi];
    }
    for (int i = 0; i < w; i++) {
        if (i >= bw->hist_count) { out[i] = ' '; continue; }
        int hi = (bw->hist_head - w + i + CONN_BW_HIST) % CONN_BW_HIST;
        int li = (int)(bw->rx_hist[hi] / mx * (float)(nlvl - 1) + 0.5f);
        if (li < 0) li = 0;
        if (li >= nlvl) li = nlvl - 1;
        out[i] = lvl[li];
    }
    out[w] = '\0';
}

/* ── Sort ───────────────────────────────────────────────── */

static const conn_t       *g_sort_conns;
static conn_sort_t         g_sort_key;
static const ntop_state_t *g_sort_state;
static double              g_sort_rates[MAX_CONNS];

static int conn_cmp(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    const conn_t *ca = &g_sort_conns[ia];
    const conn_t *cb = &g_sort_conns[ib];
    int d;
    switch (g_sort_key) {
    case CONN_SORT_STATE:
        d = ca->state - cb->state;
        return d ? d : (ca->proto - cb->proto);
    case CONN_SORT_PROTO:
        return ca->proto - cb->proto;
    case CONN_SORT_LPORT:
        return (int)ca->local_port - (int)cb->local_port;
    case CONN_SORT_PID:
        return ca->pid - cb->pid;
    case CONN_SORT_BW:
        /* descending by total rate */
        if (g_sort_rates[ia] > g_sort_rates[ib]) return -1;
        if (g_sort_rates[ia] < g_sort_rates[ib]) return  1;
        return 0;
    case CONN_SORT_RTT:
        /* descending by RTT — highest latency first */
        if (ca->rtt_us > cb->rtt_us) return -1;
        if (ca->rtt_us < cb->rtt_us) return  1;
        return 0;
    default:
        return 0;
    }
}

void conn_rebuild_idx(ntop_state_t *s) {
    int n = 0;
    for (int i = 0; i < s->conn_count && n < MAX_CONNS; i++) {
        if (s->conn_filter == CONN_FILTER_TCP && s->conns[i].proto != PROTO_TCP) continue;
        if (s->conn_filter == CONN_FILTER_UDP && s->conns[i].proto != PROTO_UDP) continue;
        s->conn_idx[n++] = i;
    }
    s->conn_idx_count = n;

    /* precompute rates so the comparator stays O(1) */
    for (int i = 0; i < s->conn_count; i++) {
        const conn_bw_t *bw = bw_lookup(s, &s->conns[i]);
        g_sort_rates[i] = bw ? (bw->rx_rate + bw->tx_rate) : 0.0;
    }

    g_sort_conns = s->conns;
    g_sort_key   = s->conn_sort;
    g_sort_state = s;
    qsort(s->conn_idx, (size_t)n, sizeof(int), conn_cmp);

    if (s->conn_idx_count == 0)
        s->conn_sel = 0;
    else if (s->conn_sel >= s->conn_idx_count)
        s->conn_sel = s->conn_idx_count - 1;
}

/* ── Draw ───────────────────────────────────────────────── */

void view_conns_draw(const ntop_state_t *s) {
    static const char *sort_names[]   = {"STATE", "PROTO", "LPORT", "PID", "BW", "RTT"};
    static const char *filter_names[] = {"ALL", "TCP", "UDP"};

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = CONNS_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" Conns: ");
    tui_bright();
    TPRINT("%d", s->conn_idx_count);
    if (s->conn_idx_count != s->conn_count) {
        tui_dim(); TPRINT("/%d", s->conn_count);
    }
    tui_dim();  TPRINT("  filter: ");
    tui_bright(); TPRINT("%-3s", filter_names[s->conn_filter]);
    tui_dim();  TPRINT("  sort: ");
    tui_bright(); TPRINT("%-5s", sort_names[s->conn_sort]);
    tui_dim();  TPRINT("  [n] ");
    tui_bright(); TPRINT("%s", s->dns_enabled ? "names" : "numeric");
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [s]ort [f]ilter");
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-21s  %-21s  %-2s  %-5s  %-13s  %5s  %-14s  %-16s %-8s  %-7s  %s\n",
           "Local", "Remote", "CC", "Proto", "State", "PID", "Process",
           "Rate (rx/tx)", "Trend", "RTT", "Retx");
    TPRINT(" %-21s  %-21s  %-2s  %-5s  %-13s  %-5s  %-14s  %-16s %-8s  %-7s  %s\n",
           "---------------------", "---------------------", "--",
           "-----", "-------------", "-----", "--------------",
           "----------------", "--------", "-------", "----");
    tui_normal();

    if (s->conn_idx_count == 0) {
        tui_dim(); TPRINT(" (no connections)\n"); tui_normal();
        return;
    }

    int top = s->conn_sel - page / 2;
    if (top + page > s->conn_idx_count) top = s->conn_idx_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->conn_idx_count) end = s->conn_idx_count;

    for (int row = top; row < end; row++) {
        const conn_t *c = &s->conns[s->conn_idx[row]];

        char local[56], remote[56];
        svc_fmt_addr(local, sizeof(local), c->local_addr, c->local_port);
        if (s->dns_enabled)
            dns_fmt_addr(c->remote_addr, c->remote_port, remote, sizeof(remote));
        else
            svc_fmt_addr(remote, sizeof(remote), c->remote_addr, c->remote_port);

        const char *cc    = geo_lookup_str(c->remote_addr);
        const char *proto = (c->proto == PROTO_TCP) ? "TCP" : "UDP";
        const char *state = (c->proto == PROTO_TCP) ? tcp_state_name(c->state) : "";

        char pid_str[12] = "";
        if (c->pid > 0) snprintf(pid_str, sizeof(pid_str), "%d", c->pid);

        /* bandwidth annotation */
        const conn_bw_t *bw = bw_lookup(s, c);
        char rx_s[10], tx_s[10], rate_col[28], spark[9];
        if (bw) {
            fmt_rate(bw->rx_rate, rx_s, sizeof(rx_s));
            fmt_rate(bw->tx_rate, tx_s, sizeof(tx_s));
            snprintf(rate_col, sizeof(rate_col), "%s\xe2\x86\x93 %s\xe2\x86\x91",
                     rx_s, tx_s);
            bw_spark(bw, spark, 8);
        } else {
            snprintf(rate_col, sizeof(rate_col), "--");
            memset(spark, ' ', 8); spark[8] = '\0';
        }

        /* RTT and retransmit annotation */
        char rtt_s[12];
        char retx_s[8];
        fmt_rtt(c->rtt_us, rtt_s, sizeof(rtt_s));
        if (c->retrans > 0)
            snprintf(retx_s, sizeof(retx_s), "%u", c->retrans);
        else
            snprintf(retx_s, sizeof(retx_s), "--");

#ifdef WITH_NCURSES
        if (row == s->conn_sel) {
            tui_sel();
            printw(" %-21.21s  %-21.21s  %-2s  %-5s  %-13s  %5s  %-14.14s  %-16s %-8s  %-7s  %s\n",
                   local, remote, cc ? cc : "", proto, state, pid_str,
                   c->pid > 0 ? c->proc : "", rate_col, spark, rtt_s, retx_s);
            tui_reset();
        } else {
            tui_normal();
            printw(" %-21.21s  %-21.21s  ", local, remote);
            tui_dim(); printw("%-2s  ", cc ? cc : "");
            tui_normal(); printw("%-5s  ", proto);
            phos_tcp_state(c->proto, c->state);
            printw("%-13s", state);
            tui_dim();
            printw("  %5s  ", pid_str);
            if (c->pid > 0) { tui_bright(); printw("%-14.14s", c->proc); }
            else            { tui_dim();    printw("%-14s", ""); }
            if (bw && (bw->rx_rate > 0 || bw->tx_rate > 0)) tui_bright();
            else tui_dim();
            printw("  %-16s ", rate_col);
            tui_dim(); printw("%-8s  ", spark);
            if (c->rtt_us > 0) tui_bright(); else tui_dim();
            printw("%-7s  ", rtt_s);
            if (c->retrans > 0) tui_bright(); else tui_dim();
            printw("%s", retx_s);
            tui_normal(); printw("\n");
        }
#else
        if (row == s->conn_sel) {
            tui_sel();
            printf(" %-21.21s  %-21.21s  %-2s  %-5s  %-13s  %5s  %-14.14s  %-16s %-8s  %-7s  %s",
                   local, remote, cc ? cc : "", proto, state, pid_str,
                   c->pid > 0 ? c->proc : "", rate_col, spark, rtt_s, retx_s);
            tui_reset(); printf("\n");
        } else {
            tui_normal();
            printf(" %-21.21s  %-21.21s  ", local, remote);
            tui_dim(); printf("%-2s  ", cc ? cc : "");
            tui_normal(); printf("%-5s  ", proto);
            phos_tcp_state(c->proto, c->state);
            printf("%-13s", state);
            tui_dim();
            printf("  %5s  ", pid_str);
            if (c->pid > 0) { tui_bright(); printf("%-14.14s", c->proc); }
            else            { tui_dim();    printf("%-14s", ""); }
            if (bw && (bw->rx_rate > 0 || bw->tx_rate > 0)) tui_bright();
            else tui_dim();
            printf("  %-16s ", rate_col);
            tui_dim(); printf("%-8s  ", spark);
            if (c->rtt_us > 0) tui_bright(); else tui_dim();
            printf("%-7s  ", rtt_s);
            if (c->retrans > 0) tui_bright(); else tui_dim();
            printf("%s", retx_s);
            tui_normal(); printf("\n");
        }
#endif
    }
    tui_normal();
}

/* ── Key handler ────────────────────────────────────────── */

void view_conns_key(ntop_state_t *s, int key) {
    switch (key) {
    case 's': case 'S':
        s->conn_sort = (conn_sort_t)((s->conn_sort + 1) % CONN_SORT_COUNT);
        conn_rebuild_idx(s);
        break;
    case 'f': case 'F':
        s->conn_filter = (conn_filter_t)((s->conn_filter + 1) % CONN_FILTER_COUNT);
        conn_rebuild_idx(s);
        break;
    case NTOP_KEY_UP:
        if (s->conn_sel > 0) s->conn_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->conn_idx_count > 0 && s->conn_sel < s->conn_idx_count - 1)
            s->conn_sel++;
        break;
    default:
        break;
    }
}
