#ifndef LINUX_PARSE_H
#define LINUX_PARSE_H

#include <stdio.h>
#include "ntop.h"

/* Parse /proc/net/dev format. Returns count.
   rx_rate / tx_rate left zero — caller applies delta calculation. */
int parse_proc_ifaces(FILE *f, iface_stat_t *out, int max);

/* Parse /proc/net/tcp or /proc/net/udp (IPv4).
   Appends to out[*n], increments *n. Populates inode field. */
void parse_proc_conns(FILE *f, int proto, conn_t *out, int max, int *n);

/* Parse /proc/net/tcp6 or /proc/net/udp6 (IPv6). */
void parse_proc_conns6(FILE *f, int proto, conn_t *out, int max, int *n);

/* Decode "AABBCCDD:PPPP" hex addr+port → dotted-decimal + port.
   addr must be at least 46 bytes. */
void parse_hex_addr(const char *hex, char *addr, uint16_t *port);

/* Decode 32-hex-char IPv6 addr + ":PPPP" → text + port.
   addr must be at least 46 bytes. */
void parse_hex_addr6(const char *hex, char *addr, uint16_t *port);

#endif /* LINUX_PARSE_H */
