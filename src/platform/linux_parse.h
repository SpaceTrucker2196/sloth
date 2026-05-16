#ifndef LINUX_PARSE_H
#define LINUX_PARSE_H

#include <stdio.h>
#include "ntop.h"

/* Parse a /proc/net/dev-format stream.
   rx_rate / tx_rate are left zero — caller applies delta calculation. */
int parse_proc_ifaces(FILE *f, iface_stat_t *out, int max);

/* Parse a /proc/net/tcp or /proc/net/udp stream.
   Appends entries to out[*n], increments *n. */
void parse_proc_conns(FILE *f, int proto, conn_t *out, int max, int *n);

/* Decode a "AABBCCDD:PPPP" hex addr+port into dotted-decimal + port.
   addr must be at least 46 bytes. */
void parse_hex_addr(const char *hex, char *addr, uint16_t *port);

#endif /* LINUX_PARSE_H */
