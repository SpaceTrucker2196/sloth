#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "platform/linux_parse.h"

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

        /* columns: rx(bytes pkts errs drop fifo frame cmp mcast)
                    tx(bytes pkts errs drop fifo colls carrier cmp) */
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
        /* rx_rate / tx_rate stay zero — caller computes with timestamps */
        n++;
    }
    return n;
}

void parse_proc_conns(FILE *f, int proto, conn_t *out, int max, int *n) {
    char line[512];
    fgets(line, sizeof(line), f);   /* skip header */

    while (*n < max && fgets(line, sizeof(line), f)) {
        char local[32], remote[32];
        unsigned int state = 0;
        if (sscanf(line, " %*d: %31s %31s %X", local, remote, &state) < 3)
            continue;

        conn_t *c = &out[*n];
        memset(c, 0, sizeof(*c));
        parse_hex_addr(local,  c->local_addr,  &c->local_port);
        parse_hex_addr(remote, c->remote_addr, &c->remote_port);
        c->proto = proto;
        c->state = (int)state;
        (*n)++;
    }
}
