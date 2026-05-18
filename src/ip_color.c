#include <stdio.h>
#include <string.h>
#include "ip_color.h"

/* ── Packet categorisation ───────────────────────────────── */

pkt_category_t pkt_categorize(int proto, uint16_t sport, uint16_t dport) {
    if (proto == 1 || proto == 58)            return PKT_CAT_ICMP;
    if (sport == 53 || dport == 53)           return PKT_CAT_DNS;
    if (proto == 6)                            return PKT_CAT_TCP;
    if (proto == 17)                           return PKT_CAT_UDP;
    return PKT_CAT_OTHER;
}

/* ── IP -> stable colour index ───────────────────────────── */

/* djb2 over the IP string, mod IP_NUM_COLORS. Stable across runs since it
 * doesn't depend on order of insertion. */
int ip_color_index(const char *ip) {
    if (!ip || !ip[0]) return 0;
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)ip; *p; p++)
        h = ((h << 5) + h) + (uint32_t)*p;  /* h*33 + c */
    return (int)(h % IP_NUM_COLORS);
}

/* ── Cross-panel source index ────────────────────────────── */

#define IP_INDEX_CAP 512

static struct {
    char     ip[46];
    uint32_t sources;   /* bitmask of IP_SRC_* */
} g_index[IP_INDEX_CAP];
static int g_index_n;

void ip_index_clear(void) {
    g_index_n = 0;
}

static int find_slot(const char *ip) {
    for (int i = 0; i < g_index_n; i++)
        if (strcmp(g_index[i].ip, ip) == 0) return i;
    return -1;
}

void ip_index_add(const char *ip, int src_bit) {
    if (!ip || !ip[0]) return;
    int idx = find_slot(ip);
    if (idx >= 0) {
        g_index[idx].sources |= (uint32_t)src_bit;
        return;
    }
    if (g_index_n >= IP_INDEX_CAP) return;
    snprintf(g_index[g_index_n].ip, sizeof(g_index[g_index_n].ip), "%s", ip);
    g_index[g_index_n].sources = (uint32_t)src_bit;
    g_index_n++;
}

int ip_index_is_cross_panel(const char *ip) {
    if (!ip || !ip[0]) return 0;
    int idx = find_slot(ip);
    if (idx < 0) return 0;
    /* >1 bit set */
    uint32_t s = g_index[idx].sources;
    return (s & (s - 1)) != 0;
}

void ip_index_build(const sloth_state_t *s) {
    if (!s) return;
    ip_index_clear();

    for (int i = 0; i < s->conn_count; i++) {
        ip_index_add(s->conns[i].local_addr,  IP_SRC_CONN);
        ip_index_add(s->conns[i].remote_addr, IP_SRC_CONN);
    }
    int pkt_n = s->pkt_count < MAX_PACKETS ? s->pkt_count : MAX_PACKETS;
    for (int i = 0; i < pkt_n; i++) {
        const packet_info_t *p = &s->packets[i];
        ip_index_add(p->src, IP_SRC_PKT);
        ip_index_add(p->dst, IP_SRC_PKT);
    }
    for (int i = 0; i < s->arp_count; i++)
        ip_index_add(s->arp_entries[i].ip, IP_SRC_ARP);
    for (int i = 0; i < s->dns_log_count; i++) {
        ip_index_add(s->dns_log[i].src,    IP_SRC_DNS);
        ip_index_add(s->dns_log[i].answer, IP_SRC_DNS);
    }
    for (int i = 0; i < s->icmp_log_count; i++) {
        ip_index_add(s->icmp_log[i].src, IP_SRC_ICMP);
        ip_index_add(s->icmp_log[i].dst, IP_SRC_ICMP);
    }
    for (int i = 0; i < s->alert_count; i++)
        ip_index_add(s->alerts[i].match_ip, IP_SRC_ALERT);
    for (int i = 0; i < s->device_count; i++)
        ip_index_add(s->devices[i].ip, IP_SRC_DEV);
}
