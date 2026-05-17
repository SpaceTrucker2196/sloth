#ifndef LINUX_TCPDIAG_H
#define LINUX_TCPDIAG_H

#include "sloth.h"

/* Fill rtt_us for each TCP conn in conns[0..n) via INET_DIAG netlink.
   Matched by inode. UDP entries and unmatched inodes are left as-is. */
void linux_tcpdiag_fill(conn_t *conns, int n);

#endif /* LINUX_TCPDIAG_H */
