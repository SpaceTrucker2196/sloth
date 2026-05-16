#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntop.h"
#include "tui.h"
#include "dns.h"
#include "services.h"
#include "views/procs.h"

#define PROCS_PAGE 30

/* Module-static proc table — shared between draw and key handler. */
static proc_stat_t g_procs[MAX_PROCS];
static int         g_proc_count = 0;

/* ── Aggregate ──────────────────────────────────────────── */

static int proc_cmp_desc(const void *a, const void *b) {
    const proc_stat_t *pa = (const proc_stat_t *)a;
    const proc_stat_t *pb = (const proc_stat_t *)b;
    return pb->conn_count - pa->conn_count;   /* descending */
}

int procs_aggregate(const ntop_state_t *s, proc_stat_t *out, int max) {
    if (max <= 0) return 0;

    int n = 0;
    proc_stat_t unresolved;
    memset(&unresolved, 0, sizeof(unresolved));
    unresolved.pid = -1;
    strncpy(unresolved.proc, "(unresolved)", sizeof(unresolved.proc) - 1);
    int has_unresolved = 0;

    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];

        if (c->pid <= 0) {
            unresolved.conn_count++;
            if (c->proto == PROTO_TCP) unresolved.tcp_count++;
            if (c->proto == PROTO_UDP) unresolved.udp_count++;
            has_unresolved = 1;
            continue;
        }

        int found = -1;
        for (int j = 0; j < n; j++) {
            if (out[j].pid == c->pid) { found = j; break; }
        }
        if (found < 0) {
            if (n >= max - 1) continue;
            found = n++;
            memset(&out[found], 0, sizeof(out[found]));
            out[found].pid = c->pid;
            strncpy(out[found].proc, c->proc, sizeof(out[found].proc) - 1);
        }

        out[found].conn_count++;
        if (c->proto == PROTO_TCP) out[found].tcp_count++;
        if (c->proto == PROTO_UDP) out[found].udp_count++;

        if (c->remote_port > 0) {
            int dup = 0;
            for (int k = 0; k < out[found].port_count; k++) {
                if (out[found].ports[k] == c->remote_port) { dup = 1; break; }
            }
            if (!dup && out[found].port_count < MAX_PROC_PORTS)
                out[found].ports[out[found].port_count++] = c->remote_port;
        }
    }

    qsort(out, (size_t)n, sizeof(proc_stat_t), proc_cmp_desc);

    if (has_unresolved && n < max)
        out[n++] = unresolved;

    return n;
}

/* ── /proc helpers (Linux only) ─────────────────────────── */

#ifdef PLATFORM_LINUX
static void proc_read_cmdline(int pid, char *buf, int sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) { buf[0] = '\0'; return; }
    int n = (int)fread(buf, 1, (size_t)(sz - 1), f);
    fclose(f);
    if (n <= 0) { buf[0] = '\0'; return; }
    buf[n] = '\0';
    for (int i = 0; i < n - 1; i++)
        if (buf[i] == '\0') buf[i] = ' ';
}

static int proc_read_ppid(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    int ppid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = atoi(line + 5);
            break;
        }
    }
    fclose(f);
    return ppid;
}

static void proc_read_comm(int pid, char *buf, int sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { buf[0] = '\0'; return; }
    buf[0] = '\0';
    if (fgets(buf, sz, f)) {
        int len = (int)strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
    }
    fclose(f);
}
#endif /* PLATFORM_LINUX */

/* ── TCP state name (local to this view) ────────────────── */

static const char *proc_tcp_state(int st) {
    static const char *names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };
    if (st < 0 || st > 11) return "?";
    return names[st];
}

/* ── Detail panel ───────────────────────────────────────── */

static void draw_proc_detail(const ntop_state_t *s) {
    int sel = s->proc_sel;
    if (sel < 0 || sel >= g_proc_count) return;
    const proc_stat_t *p = &g_procs[sel];
    if (p->pid <= 0) return;

    char cmdline[256] = "";
    int  ppid  = 0;
    char ppname[20] = "";

#ifdef PLATFORM_LINUX
    proc_read_cmdline(p->pid, cmdline, sizeof(cmdline));
    ppid = proc_read_ppid(p->pid);
    if (ppid > 0) proc_read_comm(ppid, ppname, sizeof(ppname));
#endif
    if (cmdline[0] == '\0') snprintf(cmdline, sizeof(cmdline), "(unavailable)");

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 PROCESS DETAIL \xe2\x94\x80\xe2\x94\x80\n");

    tui_dim(); TPRINT("  Name:    "); tui_bright(); TPRINT("%s\n",  p->proc);
    tui_dim(); TPRINT("  PID:     "); tui_bright(); TPRINT("%d\n",  p->pid);
    if (ppid > 0) {
        tui_dim(); TPRINT("  Parent:  "); tui_bright();
        if (ppname[0]) TPRINT("%d (%s)\n", ppid, ppname);
        else           TPRINT("%d\n", ppid);
    }
    tui_dim(); TPRINT("  Cmdline: "); tui_bright(); TPRINT("%.120s\n", cmdline);

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 CONNECTIONS (%d) \xe2\x94\x80\xe2\x94\x80\n", p->conn_count);

    tui_dim();
    TPRINT("  %-21s  %-21s  %-5s  %s\n",
           "Local", "Remote", "Proto", "State");
    TPRINT("  %-21s  %-21s  %-5s  %s\n",
           "---------------------", "---------------------", "-----", "-------");
    tui_normal();

    int shown = 0;
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (c->pid != p->pid) continue;

        char local[56], remote[56];
        svc_fmt_addr(local, sizeof(local), c->local_addr, c->local_port);
        if (s->dns_enabled)
            dns_fmt_addr(c->remote_addr, c->remote_port, remote, sizeof(remote));
        else
            svc_fmt_addr(remote, sizeof(remote), c->remote_addr, c->remote_port);

        const char *proto = (c->proto == PROTO_TCP) ? "TCP" : "UDP";
        const char *state = (c->proto == PROTO_TCP) ? proc_tcp_state(c->state) : "";

        tui_normal();
        TPRINT("  %-21.21s  %-21.21s  %-5s  %s\n",
               local, remote, proto, state);
        shown++;
    }
    if (shown == 0) {
        tui_dim(); TPRINT("  (no connections)\n");
    }

    tui_dim(); TPRINT(" [Enter/Esc] back\n");
    tui_normal();
}

/* ── Draw ───────────────────────────────────────────────── */

void view_procs_draw(const ntop_state_t *s) {
    int n = procs_aggregate(s, g_procs, MAX_PROCS);
    g_proc_count = n;

    if (s->proc_detail) { draw_proc_detail(s); return; }

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
    if (n > 0 && sel < n && g_procs[sel].pid > 0)
        TPRINT("  [Enter] detail");
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
        const proc_stat_t *p = &g_procs[row];

        char pid_str[12];
        if (p->pid == -1) snprintf(pid_str, sizeof(pid_str), "%s", "-");
        else              snprintf(pid_str, sizeof(pid_str), "%d", p->pid);

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
    if (s->proc_detail) {
        if (key == '\r' || key == '\n' || key == '\033')
            s->proc_detail = 0;
        /* all other keys consumed */
        return;
    }

    switch (key) {
    case '\r': case '\n': {
        int sel = s->proc_sel;
        if (sel >= 0 && sel < g_proc_count && g_procs[sel].pid > 0)
            s->proc_detail = 1;
        break;
    }
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
