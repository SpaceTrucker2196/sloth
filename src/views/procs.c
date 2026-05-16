#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntop.h"
#include "tui.h"
#include "views/procs.h"

#define PROCS_PAGE 30

/* Module-static proc count — used by key handler after draw. */
static int g_proc_count = 0;

/* ── Aggregate ──────────────────────────────────────────── */

static int proc_cmp_desc(const void *a, const void *b) {
    const proc_stat_t *pa = (const proc_stat_t *)a;
    const proc_stat_t *pb = (const proc_stat_t *)b;
    return pb->conn_count - pa->conn_count;   /* descending */
}

int procs_aggregate(const ntop_state_t *s, proc_stat_t *out, int max) {
    if (max <= 0) return 0;

    int n = 0;                  /* known-PID entries */
    proc_stat_t unresolved;
    memset(&unresolved, 0, sizeof(unresolved));
    unresolved.pid = -1;
    strncpy(unresolved.proc, "(unresolved)", sizeof(unresolved.proc) - 1);
    int has_unresolved = 0;

    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];

        if (c->pid <= 0) {
            /* unresolved */
            unresolved.conn_count++;
            if (c->proto == PROTO_TCP) unresolved.tcp_count++;
            if (c->proto == PROTO_UDP) unresolved.udp_count++;
            has_unresolved = 1;
            continue;
        }

        /* find-or-create known PID entry (cap at max-1 to leave room for unresolved) */
        int found = -1;
        for (int j = 0; j < n; j++) {
            if (out[j].pid == c->pid) { found = j; break; }
        }
        if (found < 0) {
            if (n >= max - 1) continue;   /* no room */
            found = n++;
            memset(&out[found], 0, sizeof(out[found]));
            out[found].pid = c->pid;
            strncpy(out[found].proc, c->proc, sizeof(out[found].proc) - 1);
        }

        out[found].conn_count++;
        if (c->proto == PROTO_TCP) out[found].tcp_count++;
        if (c->proto == PROTO_UDP) out[found].udp_count++;

        /* add unique remote port */
        if (c->remote_port > 0) {
            int dup = 0;
            for (int k = 0; k < out[found].port_count; k++) {
                if (out[found].ports[k] == c->remote_port) { dup = 1; break; }
            }
            if (!dup && out[found].port_count < MAX_PROC_PORTS)
                out[found].ports[out[found].port_count++] = c->remote_port;
        }
    }

    /* sort known entries descending by conn_count */
    qsort(out, (size_t)n, sizeof(proc_stat_t), proc_cmp_desc);

    /* append unresolved bucket at the end */
    if (has_unresolved && n < max) {
        out[n++] = unresolved;
    }

    return n;
}

/* ── Draw ───────────────────────────────────────────────── */

void view_procs_draw(const ntop_state_t *s) {
    proc_stat_t procs[MAX_PROCS];
    int n = procs_aggregate(s, procs, MAX_PROCS);
    g_proc_count = n;

    int sel = (n > 0) ? (s->proc_sel < n ? s->proc_sel : n - 1) : 0;

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = PROCS_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" Processes: ");
    tui_bright();  TPRINT("%d", n);
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [up/dn] navigate");
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-15s  %6s  %5s  %4s  %4s  %s\n",
           "Process", "PID", "Conns", "TCP", "UDP", "Remote Ports");
    TPRINT(" %-15s  %6s  %5s  %4s  %4s  %s\n",
           "---------------", "------", "-----", "----", "----",
           "------------");
    tui_normal();

    if (n == 0) {
        tui_dim(); TPRINT("  (no connections)\n"); tui_normal();
        return;
    }

    int top = sel - page / 2;
    if (top + page > n) top = n - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > n) end = n;

    for (int row = top; row < end; row++) {
        const proc_stat_t *p = &procs[row];

        char pid_str[12];
        if (p->pid == -1) snprintf(pid_str, sizeof(pid_str), "%s", "-");
        else              snprintf(pid_str, sizeof(pid_str), "%d", p->pid);

        /* build port list string */
        char port_buf[64] = "";
        int pos = 0;
        for (int k = 0; k < p->port_count && pos < (int)sizeof(port_buf) - 1; k++) {
            int written = snprintf(port_buf + pos, sizeof(port_buf) - (size_t)pos,
                                   "%s%u", k > 0 ? " " : "", (unsigned)p->ports[k]);
            if (written > 0) pos += written;
        }

#ifdef WITH_NCURSES
        if (row == sel) {
            tui_sel();
            printw(" %-15.15s  %6s  %5d  %4d  %4d  %s\n",
                   p->proc, pid_str, p->conn_count, p->tcp_count, p->udp_count,
                   port_buf);
            tui_reset();
        } else if (p->pid == -1) {
            tui_dim();
            printw(" %-15.15s  %6s  %5d  %4d  %4d  %s\n",
                   p->proc, pid_str, p->conn_count, p->tcp_count, p->udp_count,
                   port_buf);
            tui_normal();
        } else {
            tui_bright(); printw(" %-15.15s", p->proc);
            tui_dim();    printw("  %6s", pid_str);
            tui_bright(); printw("  %5d", p->conn_count);
            tui_normal(); printw("  %4d  %4d", p->tcp_count, p->udp_count);
            tui_dim();    printw("  %s\n", port_buf);
            tui_normal();
        }
#else
        if (row == sel) {
            tui_sel();
            printf(" %-15.15s  %6s  %5d  %4d  %4d  %s",
                   p->proc, pid_str, p->conn_count, p->tcp_count, p->udp_count,
                   port_buf);
            tui_reset(); printf("\n");
        } else if (p->pid == -1) {
            tui_dim();
            printf(" %-15.15s  %6s  %5d  %4d  %4d  %s\n",
                   p->proc, pid_str, p->conn_count, p->tcp_count, p->udp_count,
                   port_buf);
            tui_normal();
        } else {
            tui_bright(); printf(" %-15.15s", p->proc);
            tui_dim();    printf("  %6s", pid_str);
            tui_bright(); printf("  %5d", p->conn_count);
            tui_normal(); printf("  %4d  %4d", p->tcp_count, p->udp_count);
            tui_dim();    printf("  %s\n", port_buf);
            tui_normal();
        }
#endif
    }
    tui_normal();
}

/* ── Key handler ────────────────────────────────────────── */

void view_procs_key(ntop_state_t *s, int key) {
    switch (key) {
    case NTOP_KEY_UP:
        if (s->proc_sel > 0) s->proc_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->proc_sel < g_proc_count - 1) s->proc_sel++;
        break;
    default:
        break;
    }
}
