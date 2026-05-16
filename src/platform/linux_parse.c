#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>   /* inet_ntop — Linux/POSIX */
#include "ntop.h"
#include "platform/linux_parse.h"

/* ── IPv4 helpers ────────────────────────────────────────── */

void parse_hex_addr(const char *hex, char *addr, uint16_t *port) {
    unsigned long ip = 0;
    unsigned int  p  = 0;
    sscanf(hex, "%lX:%X", &ip, &p);
    /* Linux stores IPv4 in little-endian host order */
    snprintf(addr, 46, "%lu.%lu.%lu.%lu",
             (ip      ) & 0xffUL,
             (ip >>  8) & 0xffUL,
             (ip >> 16) & 0xffUL,
             (ip >> 24) & 0xffUL);
    *port = (uint16_t)p;
}

/* ── IPv6 helpers ────────────────────────────────────────── */

void parse_hex_addr6(const char *hex, char *addr, uint16_t *port) {
    /* hex is 32 hex chars (4 × 8-char LE words) followed by ":PPPP" */
    uint32_t w[4] = {0, 0, 0, 0};
    unsigned int p = 0;
    sscanf(hex, "%08X%08X%08X%08X:%X", &w[0], &w[1], &w[2], &w[3], &p);

    /* reconstruct IPv6 bytes from little-endian 32-bit words */
    uint8_t b[16];
    for (int i = 0; i < 4; i++) {
        b[i*4+0] = (uint8_t)((w[i]      ) & 0xff);
        b[i*4+1] = (uint8_t)((w[i] >>  8) & 0xff);
        b[i*4+2] = (uint8_t)((w[i] >> 16) & 0xff);
        b[i*4+3] = (uint8_t)((w[i] >> 24) & 0xff);
    }
    inet_ntop(AF_INET6, b, addr, 46);
    *port = (uint16_t)p;
}

/* ── /proc/net/dev parser ────────────────────────────────── */

int parse_proc_ifaces(FILE *f, iface_stat_t *out, int max) {
    char line[256];
    fgets(line, sizeof(line), f);   /* Inter-| header */
    fgets(line, sizeof(line), f);   /* face  | header */

    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';

        char *name = line;
        while (*name == ' ') name++;

        /* rx: bytes pkts errs drop fifo frame cmp mcast
           tx: bytes pkts errs drop fifo colls carrier cmp */
        unsigned long long v[16] = {0};
        if (sscanf(colon + 1,
                   "%llu %llu %llu %llu %llu %llu %llu %llu"
                   " %llu %llu %llu %llu %llu %llu %llu %llu",
                   &v[0],  &v[1],  &v[2],  &v[3],
                   &v[4],  &v[5],  &v[6],  &v[7],
                   &v[8],  &v[9],  &v[10], &v[11],
                   &v[12], &v[13], &v[14], &v[15]) < 10)
            continue;

        iface_stat_t *s = &out[n];
        memset(s, 0, sizeof(*s));

        size_t nl = strlen(name);
        if (nl >= sizeof(s->name)) nl = sizeof(s->name) - 1;
        memcpy(s->name, name, nl);
        s->name[nl] = '\0';

        s->rx_bytes   = (uint64_t)v[0];
        s->rx_packets = (uint64_t)v[1];
        s->tx_bytes   = (uint64_t)v[8];
        s->tx_packets = (uint64_t)v[9];
        n++;
    }
    return n;
}

/* ── /proc/net/tcp|udp parser (IPv4) ─────────────────────── */

void parse_proc_conns(FILE *f, int proto, conn_t *out, int max, int *n) {
    char line[512];
    fgets(line, sizeof(line), f);   /* skip header */

    while (*n < max && fgets(line, sizeof(line), f)) {
        char local[32], remote[32];
        unsigned int state = 0;
        unsigned long inode = 0;
        /* fields after slot#: local remote state tx:rx tr:tm retrnsmt uid timeout inode */
        if (sscanf(line,
                   " %*d: %31s %31s %X"
                   " %*X:%*X %*X:%*X %*X %*u %*u %lu",
                   local, remote, &state, &inode) < 3)
            continue;

        conn_t *c = &out[*n];
        memset(c, 0, sizeof(*c));
        parse_hex_addr(local,  c->local_addr,  &c->local_port);
        parse_hex_addr(remote, c->remote_addr, &c->remote_port);
        c->proto = proto;
        c->state = (int)state;
        c->inode = inode;
        (*n)++;
    }
}

/* ── /proc/net/tcp6|udp6 parser (IPv6) ───────────────────── */

void parse_proc_conns6(FILE *f, int proto, conn_t *out, int max, int *n) {
    char line[640];
    fgets(line, sizeof(line), f);   /* skip header */

    while (*n < max && fgets(line, sizeof(line), f)) {
        /* IPv6 address fields are 32+1+4 = 37 chars each */
        char local[40], remote[40];
        unsigned int  state = 0;
        unsigned long inode = 0;
        if (sscanf(line,
                   " %*d: %39s %39s %X"
                   " %*X:%*X %*X:%*X %*X %*u %*u %lu",
                   local, remote, &state, &inode) < 3)
            continue;

        conn_t *c = &out[*n];
        memset(c, 0, sizeof(*c));
        parse_hex_addr6(local,  c->local_addr,  &c->local_port);
        parse_hex_addr6(remote, c->remote_addr, &c->remote_port);
        c->proto = proto;
        c->state = (int)state;
        c->inode = inode;
        (*n)++;
    }
}
