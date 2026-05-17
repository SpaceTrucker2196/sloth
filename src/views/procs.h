#ifndef VIEWS_PROCS_H
#define VIEWS_PROCS_H
#include "ntop.h"
#define MAX_PROCS      64
#define MAX_PROC_PORTS  8
typedef struct {
    char     proc[16];
    int      pid;         /* -1 = unresolved bucket */
    int      ppid;        /* parent PID (from /proc/<pid>/status; 0 = unknown) */
    int      depth;       /* indentation level in tree view */
    int      conn_count;
    int      tcp_count;
    int      udp_count;
    uint16_t ports[MAX_PROC_PORTS];
    int      port_count;
} proc_stat_t;
int  procs_aggregate(const ntop_state_t *s, proc_stat_t *out, int max);
void view_procs_draw(const ntop_state_t *s);
void view_procs_key(ntop_state_t *s, int key);
#endif
