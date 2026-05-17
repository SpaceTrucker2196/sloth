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

/* Visible row index: g_vis_idx[i] is the g_procs[] index of visible row i. */
static int g_vis_idx[MAX_PROCS];
static int g_vis_count = 0;

/* Folded PIDs: tree nodes whose children are collapsed. */
static int g_folded_pids[MAX_PROCS];
static int g_folded_n = 0;

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

/* ── Tree helpers ───────────────────────────────────────── */

static int find_proc_idx_by_pid(int pid) {
    for (int i = 0; i < g_proc_count; i++) {
        if (g_procs[i].pid == pid) return i;
    }
    return -1;
}

static int is_folded(int pid) {
    for (int i = 0; i < g_folded_n; i++) {
        if (g_folded_pids[i] == pid) return 1;
    }
    return 0;
}

static void toggle_folded(int pid) {
    for (int i = 0; i < g_folded_n; i++) {
        if (g_folded_pids[i] == pid) {
            g_folded_pids[i] = g_folded_pids[--g_folded_n];
            return;
        }
    }
    if (g_folded_n < MAX_PROCS)
        g_folded_pids[g_folded_n++] = pid;
}

/* Does g_procs[idx] have any children in the tree? */
static int has_children_in_tree(int idx) {
    return (idx + 1 < g_proc_count && g_procs[idx + 1].depth > g_procs[idx].depth);
}

/* DFS append: place g_procs[src_idx] + all its descendants into tmp. */
static void dfs_append(proc_stat_t *tmp, int *tmp_n, char *used,
                       int src_idx, int depth) {
    if (used[src_idx]) return;
    used[src_idx] = 1;
    tmp[*tmp_n] = g_procs[src_idx];
    tmp[(*tmp_n)].depth = depth;
    (*tmp_n)++;

    int src_pid = g_procs[src_idx].pid;
    if (src_pid <= 0) return;
    for (int i = 0; i < g_proc_count; i++) {
        if (!used[i] && g_procs[i].ppid == src_pid)
            dfs_append(tmp, tmp_n, used, i, depth + 1);
    }
}

/* Reorder g_procs[] in DFS pre-order using parent–child links. */
static void build_tree(void) {
    int n = g_proc_count;

    /* read PPIDs from /proc */
    for (int i = 0; i < n; i++) {
        g_procs[i].ppid  = 0;
        g_procs[i].depth = 0;
#ifdef PLATFORM_LINUX
        if (g_procs[i].pid > 0)
            g_procs[i].ppid = proc_read_ppid(g_procs[i].pid);
#endif
    }

    proc_stat_t tmp[MAX_PROCS];
    int tmp_n = 0;
    char used[MAX_PROCS];
    memset(used, 0, (size_t)n);

    /* visit roots first (parent not in g_procs), in original sort order */
    for (int i = 0; i < n; i++) {
        if (used[i]) continue;
        int par_idx = (g_procs[i].ppid > 0)
                      ? find_proc_idx_by_pid(g_procs[i].ppid) : -1;
        if (par_idx < 0)
            dfs_append(tmp, &tmp_n, used, i, 0);
    }
    /* append any remaining (cycles or stale ppids) as roots */
    for (int i = 0; i < n && tmp_n < n; i++) {
        if (!used[i]) { tmp[tmp_n] = g_procs[i]; tmp[tmp_n++].depth = 0; }
    }

    memcpy(g_procs, tmp, (size_t)tmp_n * sizeof(proc_stat_t));
}

/* Rebuild g_vis_idx[] from the tree, respecting folded nodes. */
static void rebuild_vis(void) {
    int n = g_proc_count;
    g_vis_count = 0;

    char hidden[MAX_PROCS];
    memset(hidden, 0, (size_t)n);

    for (int i = 0; i < n; i++) {
        if (hidden[i]) continue;
        g_vis_idx[g_vis_count++] = i;

        if (is_folded(g_procs[i].pid)) {
            int fold_depth = g_procs[i].depth;
            for (int j = i + 1; j < n; j++) {
                if (g_procs[j].depth > fold_depth) hidden[j] = 1;
                else break;
            }
        }
    }

    /* prune stale folded PIDs that are no longer in the proc list */
    int new_n = 0;
    for (int i = 0; i < g_folded_n; i++) {
        if (find_proc_idx_by_pid(g_folded_pids[i]) >= 0)
            g_folded_pids[new_n++] = g_folded_pids[i];
    }
    g_folded_n = new_n;
}

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
    int vis_sel = (g_vis_count > 0)
                  ? (s->proc_sel < g_vis_count ? s->proc_sel : g_vis_count - 1)
                  : 0;
    int sel = (g_vis_count > 0) ? g_vis_idx[vis_sel] : 0;
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
    build_tree();
    rebuild_vis();

    if (s->proc_detail) { draw_proc_detail(s); return; }

    int vis_sel = (g_vis_count > 0)
                  ? (s->proc_sel < g_vis_count ? s->proc_sel : g_vis_count - 1)
                  : 0;

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = PROCS_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" Processes: ");
    tui_bright();  TPRINT("%d", g_vis_count);
    if (g_vis_count != n) {
        tui_dim(); TPRINT("/%d", n);
    }
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [up/dn] navigate");
    if (g_vis_count > 0 && vis_sel < g_vis_count) {
        int ti = g_vis_idx[vis_sel];
        if (has_children_in_tree(ti))
            TPRINT("  [Enter] fold");
        else if (g_procs[ti].pid > 0)
            TPRINT("  [Enter] detail");
    }
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-15s %-3s  %6s  %5s  %4s  %4s  %s\n",
           "Process", "   ", "PID", "Conns", "TCP", "UDP", "Remote Ports");
    TPRINT(" %-15s %-3s  %6s  %5s  %4s  %4s  %s\n",
           "---------------", "---", "------", "-----",
           "----", "----", "------------");
    tui_normal();

    if (g_vis_count == 0) {
        tui_dim(); TPRINT("  (no connections)\n"); tui_normal();
        return;
    }

    int top = vis_sel - page / 2;
    if (top + page > g_vis_count) top = g_vis_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > g_vis_count) end = g_vis_count;

    for (int row = top; row < end; row++) {
        int ti = g_vis_idx[row];
        const proc_stat_t *p = &g_procs[ti];

        /* indented name */
        char ind_name[20] = "";
        int spaces = p->depth * 2;
        if (spaces > 8) spaces = 8;
        memset(ind_name, ' ', (size_t)spaces);
        snprintf(ind_name + spaces, sizeof(ind_name) - (size_t)spaces, "%s", p->proc);

        /* fold indicator */
        const char *fold_ind = "   ";
        if (has_children_in_tree(ti)) {
            fold_ind = is_folded(p->pid) ? "[+]" : "[-]";
        }

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
        if (row == vis_sel) {
            tui_sel();
            printw(" %-15.15s %-3s  %6s  %5d  %4d  %4d  %s\n",
                   ind_name, fold_ind, pid_str,
                   p->conn_count, p->tcp_count, p->udp_count, port_buf);
            tui_reset();
        } else if (p->pid == -1) {
            tui_dim();
            printw(" %-15.15s %-3s  %6s  %5d  %4d  %4d  %s\n",
                   ind_name, fold_ind, pid_str,
                   p->conn_count, p->tcp_count, p->udp_count, port_buf);
            tui_normal();
        } else {
            if (p->depth > 0) tui_dim(); else tui_bright();
            printw(" %-15.15s", ind_name);
            tui_dim();    printw(" %-3s", fold_ind);
            tui_dim();    printw("  %6s", pid_str);
            tui_bright(); printw("  %5d", p->conn_count);
            tui_normal(); printw("  %4d  %4d", p->tcp_count, p->udp_count);
            tui_dim();    printw("  %s\n", port_buf);
            tui_normal();
        }
#else
        if (row == vis_sel) {
            tui_sel();
            printf(" %-15.15s %-3s  %6s  %5d  %4d  %4d  %s",
                   ind_name, fold_ind, pid_str,
                   p->conn_count, p->tcp_count, p->udp_count, port_buf);
            tui_reset(); printf("\n");
        } else if (p->pid == -1) {
            tui_dim();
            printf(" %-15.15s %-3s  %6s  %5d  %4d  %4d  %s\n",
                   ind_name, fold_ind, pid_str,
                   p->conn_count, p->tcp_count, p->udp_count, port_buf);
            tui_normal();
        } else {
            if (p->depth > 0) tui_dim(); else tui_bright();
            printf(" %-15.15s", ind_name);
            tui_dim();    printf(" %-3s", fold_ind);
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
        if (s->proc_sel < 0 || s->proc_sel >= g_vis_count) break;
        int ti = g_vis_idx[s->proc_sel];
        if (has_children_in_tree(ti)) {
            toggle_folded(g_procs[ti].pid);
            rebuild_vis();
            /* clamp selection to new visible count */
            if (s->proc_sel >= g_vis_count && g_vis_count > 0)
                s->proc_sel = g_vis_count - 1;
        } else if (g_procs[ti].pid > 0) {
            s->proc_detail = 1;
        }
        break;
    }
    case NTOP_KEY_UP:
        if (s->proc_sel > 0) s->proc_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->proc_sel < g_vis_count - 1) s->proc_sel++;
        break;
    default:
        break;
    }
}
