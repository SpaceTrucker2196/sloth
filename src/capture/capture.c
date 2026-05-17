#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ntop.h"
#include "capture/capture.h"

/* ── Thread state ─────────────────────────────────────────── */

static volatile int    g_running = 0;
static pthread_t       g_thread;
static pthread_mutex_t g_mu      = PTHREAD_MUTEX_INITIALIZER;
static ntop_state_t   *g_state;
static pcap_t         *g_handle;

/* ── Byte helpers ─────────────────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* ── Protocol decoders ────────────────────────────────────── */

static void decode_tcp_flags(uint8_t flags, char *buf, int sz) {
    snprintf(buf, sz, "TCP%s%s%s%s%s%s",
             (flags & 0x02) ? " SYN" : "",
             (flags & 0x10) ? " ACK" : "",
             (flags & 0x08) ? " PSH" : "",
             (flags & 0x01) ? " FIN" : "",
             (flags & 0x04) ? " RST" : "",
             (flags & 0x20) ? " URG" : "");
}

static void decode_icmp(uint8_t type, uint8_t code, char *buf, int sz) {
    switch (type) {
    case 0:  snprintf(buf, sz, "ICMP Echo Reply");             break;
    case 3:  snprintf(buf, sz, "ICMP Unreachable c=%u", code); break;
    case 8:  snprintf(buf, sz, "ICMP Echo Request");           break;
    case 11: snprintf(buf, sz, "ICMP TTL Exceeded");           break;
    default: snprintf(buf, sz, "ICMP type=%u code=%u", type, code); break;
    }
}

static void decode_ipv4(const uint8_t *p, int len, packet_info_t *pkt) {
    if (len < 20) return;
    int ihl = (p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return;

    pkt->proto = p[9];
    inet_ntop(AF_INET, p + 12, pkt->src, sizeof(pkt->src));
    inet_ntop(AF_INET, p + 16, pkt->dst, sizeof(pkt->dst));

    const uint8_t *tp   = p + ihl;
    int            tlen = len - ihl;

    if (pkt->proto == 6 && tlen >= 20) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        decode_tcp_flags(tp[13], pkt->info, sizeof(pkt->info));
    } else if (pkt->proto == 17 && tlen >= 8) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
    } else if (pkt->proto == 1 && tlen >= 2) {
        decode_icmp(tp[0], tp[1], pkt->info, sizeof(pkt->info));
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "IP proto %u", pkt->proto);
    }
}

static void decode_ipv6(const uint8_t *p, int len, packet_info_t *pkt) {
    if (len < 40) return;
    pkt->proto = p[6];
    inet_ntop(AF_INET6, p + 8,  pkt->src, sizeof(pkt->src));
    inet_ntop(AF_INET6, p + 24, pkt->dst, sizeof(pkt->dst));

    const uint8_t *tp   = p + 40;
    int            tlen = len - 40;

    if (pkt->proto == 6 && tlen >= 20) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        decode_tcp_flags(tp[13], pkt->info, sizeof(pkt->info));
    } else if (pkt->proto == 17 && tlen >= 8) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
    } else if (pkt->proto == 58 && tlen >= 2) {
        snprintf(pkt->info, sizeof(pkt->info), "ICMPv6 type=%u", tp[0]);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "IPv6 nh=%u", pkt->proto);
    }
}

/* DLT_LINUX_SLL (113) — Linux cooked capture used by "any" */
#define MY_DLT_LINUX_SLL 113

static void decode_frame(const uint8_t *data, int caplen, int dlt,
                         packet_info_t *pkt) {
    int       offset    = 0;
    uint16_t  ethertype = 0;

    if (dlt == DLT_EN10MB) {
        if (caplen < 14) return;
        ethertype = u16be(data + 12);
        offset    = 14;
    } else if (dlt == MY_DLT_LINUX_SLL) {
        if (caplen < 16) return;
        ethertype = u16be(data + 14);
        offset    = 16;
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "DLT %d", dlt);
        return;
    }

    /* strip 802.1Q VLAN tag */
    if (ethertype == 0x8100 && offset + 4 <= caplen) {
        ethertype = u16be(data + offset + 2);
        offset   += 4;
    }

    const uint8_t *payload = data + offset;
    int            plen    = caplen - offset;

    if      (ethertype == 0x0800) decode_ipv4(payload, plen, pkt);
    else if (ethertype == 0x86DD) decode_ipv6(payload, plen, pkt);
    else if (ethertype == 0x0806) memcpy(pkt->info, "ARP", 4);
    else snprintf(pkt->info, sizeof(pkt->info), "EtherType 0x%04x", ethertype);
}

/* ── pcap callback ────────────────────────────────────────── */

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *data) {
    (void)user;
    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ts_sec  = (uint32_t)hdr->ts.tv_sec;
    pkt.ts_usec = (uint32_t)hdr->ts.tv_usec;
    pkt.len     = hdr->len;
    decode_frame(data, (int)hdr->caplen, pcap_datalink(g_handle), &pkt);

    int rl = (int)hdr->caplen < 64 ? (int)hdr->caplen : 64;
    memcpy(pkt.raw, data, (size_t)rl);
    pkt.raw_len = (uint16_t)rl;

    pthread_mutex_lock(&g_mu);
    g_state->packets[g_state->pkt_head] = pkt;
    g_state->pkt_head = (g_state->pkt_head + 1) % MAX_PACKETS;
    if (g_state->pkt_count < MAX_PACKETS) g_state->pkt_count++;
    pthread_mutex_unlock(&g_mu);
}

/* ── Capture thread ───────────────────────────────────────── */

static void *capture_thread(void *arg) {
    (void)arg;
    while (g_running) {
        int r = pcap_dispatch(g_handle, 32, on_packet, NULL);
        if (r < 0) break;   /* PCAP_ERROR or PCAP_ERROR_BREAK */
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────── */

void capture_start(ntop_state_t *s) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_state  = s;
    g_handle = pcap_open_live("any", 65535, 1, 100, errbuf);

    if (!g_handle) {
        /* "any" unavailable — try first enumerated device */
        pcap_if_t *devs = NULL;
        if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
            g_handle = pcap_open_live(devs->name, 65535, 1, 100, errbuf);
            pcap_freealldevs(devs);
        }
    }
    if (!g_handle) return;  /* silently disabled — show live hint in view */

    s->pkt_linktype = pcap_datalink(g_handle);
    g_running = 1;
    pthread_create(&g_thread, NULL, capture_thread, NULL);
}

void capture_stop(void) {
    if (!g_running) return;
    g_running = 0;
    if (g_handle) pcap_breakloop(g_handle);
    pthread_join(g_thread, NULL);
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
}

int capture_set_filter(const char *expr, char *errbuf, int errsz) {
    if (!g_handle) return 0;
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "%s", pcap_geterr(g_handle));
        return -1;
    }
    pcap_setfilter(g_handle, &fp);
    pcap_freecode(&fp);
    return 0;
}

#endif /* WITH_PCAP */
