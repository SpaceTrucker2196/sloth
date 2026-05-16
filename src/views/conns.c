#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntop.h"
#include "tui.h"
#include "views/conns.h"

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

/* ── Sort ───────────────────────────────────────────────── */

static const conn_t *g_sort_conns;
static conn_sort_t   g_sort_key;

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

    g_sort_conns = s->conns;
    g_sort_key   = s->conn_sort;
    qsort(s->conn_idx, (size_t)n, sizeof(int), conn_cmp);

    if (s->conn_idx_count == 0)
        s->conn_sel = 0;
    else if (s->conn_sel >= s->conn_idx_count)
        s->conn_sel = s->conn_idx_count - 1;
}

/* ── Draw ───────────────────────────────────────────────── */

void view_conns_draw(const ntop_state_t *s) {
    static const char *sort_names[]   = {"STATE", "PROTO", "LPORT", "PID"};
    static const char *filter_names[] = {"ALL", "TCP", "UDP"};

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = CONNS_PAGE;
#endif

    /* status bar */
    TPRINT(" Conns: %d", s->conn_idx_count);
    if (s->conn_idx_count != s->conn_count)
        TPRINT("/%d", s->conn_count);
    TPRINT("  filter: %-3s  sort: %-5s",
           filter_names[s->conn_filter],
           sort_names[s->conn_sort]);
#ifndef WITH_NCURSES
    TPRINT("  [s]ort [f]ilter");
#endif
    TPRINT("\n");

    /* column headers */
    TPRINT(" %-21s  %-21s  %-5s  %-13s  %5s  %-14s\n",
           "Local", "Remote", "Proto", "State", "PID", "Process");
    TPRINT(" %-21s  %-21s  %-5s  %-13s  %-5s  %-14s\n",
           "---------------------", "---------------------",
           "-----", "-------------", "-----", "--------------");

    if (s->conn_idx_count == 0) {
        TPRINT(" (no connections)\n");
        return;
    }

    /* viewport: keep conn_sel roughly centred */
    int top = s->conn_sel - page / 2;
    if (top + page > s->conn_idx_count) top = s->conn_idx_count - page;
    if (top < 0) top = 0;

    int end = top + page;
    if (end > s->conn_idx_count) end = s->conn_idx_count;

    for (int row = top; row < end; row++) {
        const conn_t *c = &s->conns[s->conn_idx[row]];

        char local[56], remote[56];
        snprintf(local,  sizeof(local),  "%s:%u", c->local_addr,  c->local_port);
        snprintf(remote, sizeof(remote), "%s:%u", c->remote_addr, c->remote_port);

        const char *proto = (c->proto == PROTO_TCP) ? "TCP" : "UDP";
        const char *state = (c->proto == PROTO_TCP) ? tcp_state_name(c->state) : "";

        char pid_str[12] = "";
        if (c->pid > 0) snprintf(pid_str, sizeof(pid_str), "%d", c->pid);

#ifdef WITH_NCURSES
        if (row == s->conn_sel) attron(A_REVERSE);
        TPRINT(" %-21.21s  %-21.21s  %-5s  %-13s  %5s  %-14.14s\n",
               local, remote, proto, state, pid_str,
               c->pid > 0 ? c->proc : "");
        if (row == s->conn_sel) attroff(A_REVERSE);
#else
        TPRINT("%c%-21.21s  %-21.21s  %-5s  %-13s  %5s  %-14.14s\n",
               (row == s->conn_sel) ? '>' : ' ',
               local, remote, proto, state, pid_str,
               c->pid > 0 ? c->proc : "");
#endif
    }
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
