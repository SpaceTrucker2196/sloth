#ifndef LINUX_PID_H
#define LINUX_PID_H

#include "sloth.h"

/* Scan /proc/[pid]/fd for socket inodes and fill conn_t.pid + .proc.
   Best-effort: connections owned by other users may be skipped.
   Called once per poll after the connection list is built. */
void resolve_pids(conn_t *conns, int count);

#endif /* LINUX_PID_H */
