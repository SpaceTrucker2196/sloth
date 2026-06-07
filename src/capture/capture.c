#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "sloth.h"
#include "capture/capture.h"
#include "dns_snoop.h"
#include "sni_snoop.h"
#include "mdns_snoop.h"
#include "nbns_snoop.h"
#include "dhcp_snoop.h"
#include "ndp_snoop.h"
#include "smb_snoop.h"
#include "kerb_snoop.h"
#include "ldap_snoop.h"
#include "bgp_snoop.h"
#include "ssh_snoop.h"
#include "rdp_snoop.h"
#include "snmp_snoop.h"
#include "mqtt_snoop.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "ssdp_snoop.h"
#include "http_snoop.h"
#include "http_log.h"
#include "tls_log.h"
#include "dns.h"

/* ── Thread state ─────────────────────────────────────────── */

static volatile int    g_running = 0;
static pthread_t       g_thread;
static pthread_mutex_t g_mu      = PTHREAD_MUTEX_INITIALIZER;
static sloth_state_t   *g_state;
static pcap_t         *g_handle;

/* ── Byte helpers ─────────────────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* ── Protocol decoders ────────────────────────────────────── */

/* Try to decode TLS SNI from a TCP segment. Updates pkt->info and
   calls dns_set_resolved if an SNI hostname is found. */
/* Try to decode HTTP Host header from a TCP segment. */
static void try_http(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 16) return;
    http_log_entry_t entry;
    if (!http_log_parse(tp + tcp_hdr, pay_len, pkt->src, &entry)) return;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    snprintf(pkt->info, sizeof(pkt->info), "HTTP %.54s", entry.host[0] ? entry.host : "?");
    http_log_record(&entry);
}

static void try_sni(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 9) return;
    tls_log_entry_t entry;
    if (!tls_log_parse(tp + tcp_hdr, pay_len, pkt->src, pkt->dst, &entry)) return;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    snprintf(pkt->info, sizeof(pkt->info), "%s %.46s",
             entry.tls_ver, entry.host[0] ? entry.host : pkt->dst);
    tls_log_record(&entry);
}

static void try_smb(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 4) return;
    if (smb_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port,
                          tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "SMB");
    }
}

/* Kerberos over TCP/88 — payload starts with a 4-byte length prefix
 * then the ASN.1 message. UDP path is handled directly in the
 * decode_ipv4 / decode_ipv6 UDP branch. */
static void try_kerb_tcp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 1) return;
    if (kerb_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port,
                           tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "Kerberos");
    }
}

/* LDAP over TCP/389 (default) or TCP/3268 (Global Catalog). TLS
 * variants 636 / 3269 are opaque past the handshake and not
 * observed. */
static void try_ldap(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 2) return;
    if (ldap_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port,
                           tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP");
    }
}

/* BGP over TCP/179. The 19-byte marker + length + type header is
 * distinctive enough that we can match on it directly. */
static void try_bgp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 19) return;
    if (bgp_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port,
                          tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "BGP");
    }
}

/* RDP X.224 Connection Request on TCP/3389 — TPKT envelope
 * (version 0x03) wrapping a Class 0 CR TPDU (code 0xE0). */
static void try_rdp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 11) return;
    if (rdp_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port,
                          tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "RDP");
    }
}

/* MQTT on TCP/1883. Fixed header is one type byte + 1-4 byte
 * Remaining Length varint, so the protocol is tag-recognisable. */
static void try_mqtt(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 2) return;
    if (mqtt_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port,
                           tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "MQTT");
    }
}

/* SSH banner on TCP/22. Matches the cleartext "SSH-protoversion-..."
 * exchange that precedes the encrypted key exchange. */
static void try_ssh(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 6) return;
    if (ssh_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port,
                          tp + tcp_hdr, pay_len)) {
        snprintf(pkt->info, sizeof(pkt->info), "SSH");
    }
}

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
        try_sni(tp, tlen, pkt);
        if (pkt->dst_port == 80 || pkt->src_port == 80 ||
            pkt->dst_port == 8080 || pkt->src_port == 8080 ||
            pkt->dst_port == 8000 || pkt->src_port == 8000)
            try_http(tp, tlen, pkt);
        if (pkt->dst_port == 445 || pkt->src_port == 445 ||
            pkt->dst_port == 139 || pkt->src_port == 139)
            try_smb(tp, tlen, pkt);
        if (pkt->dst_port == 88 || pkt->src_port == 88)
            try_kerb_tcp(tp, tlen, pkt);
        if (pkt->dst_port == 389  || pkt->src_port == 389 ||
            pkt->dst_port == 3268 || pkt->src_port == 3268)
            try_ldap(tp, tlen, pkt);
        if (pkt->dst_port == 179 || pkt->src_port == 179)
            try_bgp(tp, tlen, pkt);
        if (pkt->dst_port == 22 || pkt->src_port == 22)
            try_ssh(tp, tlen, pkt);
        if (pkt->dst_port == 3389 || pkt->src_port == 3389)
            try_rdp(tp, tlen, pkt);
        if (pkt->dst_port == 1883 || pkt->src_port == 1883)
            try_mqtt(tp, tlen, pkt);
    } else if (pkt->proto == 17 && tlen >= 8) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        if ((pkt->src_port == 53 || pkt->dst_port == 53) && tlen > 8) {
            if (!dns_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
            dns_log_entry_t dqe;
            if (dns_log_parse(tp + 8, tlen - 8, pkt->src, &dqe))
                dns_log_record(&dqe);
        } else if ((pkt->src_port == 5353 || pkt->dst_port == 5353) && tlen > 8) {
            mdns_snoop(tp + 8, tlen - 8);
            snprintf(pkt->info, sizeof(pkt->info), "mDNS");
        } else if ((pkt->src_port == 137 || pkt->dst_port == 137) && tlen > 8) {
            if (!nbns_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "NBNS");
        } else if ((pkt->src_port == 67 || pkt->dst_port == 67 ||
                    pkt->src_port == 68 || pkt->dst_port == 68) && tlen > 8) {
            if (!dhcp_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "DHCP");
        } else if ((pkt->src_port == 443 || pkt->dst_port == 443) && tlen > 8) {
            const char *remote = (pkt->dst_port == 443) ? pkt->dst : pkt->src;
            const char *host   = dns_lookup(remote);
            quic_log_entry_t qe;
            if (quic_log_parse(tp + 8, tlen - 8, pkt->src, pkt->dst,
                               host && host[0] ? host : NULL, &qe)) {
                snprintf(pkt->info, sizeof(pkt->info), "QUIC %.58s",
                         qe.host[0] ? qe.host : qe.ver);
                quic_log_record(&qe);
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "UDP 443");
            }
        } else if ((pkt->src_port == 1900 || pkt->dst_port == 1900) && tlen > 8) {
            if (!ssdp_snoop(pkt->src, tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "SSDP");
        } else if ((pkt->src_port == 123 || pkt->dst_port == 123) && tlen > 8) {
            ntp_log_entry_t ne;
            if (ntp_log_parse(tp + 8, tlen - 8, pkt->src, pkt->dst, &ne)) {
                snprintf(pkt->info, sizeof(pkt->info),
                         "NTP v%u %.6s str=%u", ne.version, ne.mode, ne.stratum);
                ntp_log_record(&ne);
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "NTP");
            }
        } else if ((pkt->src_port == 88 || pkt->dst_port == 88) && tlen > 8) {
            if (kerb_snoop_observe(pkt->src, pkt->src_port,
                                    pkt->dst, pkt->dst_port,
                                    tp + 8, tlen - 8)) {
                snprintf(pkt->info, sizeof(pkt->info), "Kerberos");
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "UDP 88");
            }
        } else if ((pkt->src_port == 161 || pkt->dst_port == 161 ||
                    pkt->src_port == 162 || pkt->dst_port == 162) && tlen > 8) {
            if (snmp_snoop_observe(pkt->src, pkt->src_port,
                                    pkt->dst, pkt->dst_port,
                                    tp + 8, tlen - 8)) {
                snprintf(pkt->info, sizeof(pkt->info), "SNMP");
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "UDP %u",
                         pkt->dst_port == 161 || pkt->dst_port == 162
                         ? pkt->dst_port : pkt->src_port);
            }
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
        }
    } else if (pkt->proto == 1 && tlen >= 2) {
        decode_icmp(tp[0], tp[1], pkt->info, sizeof(pkt->info));
        icmp_log_entry_t ie;
        if (icmp_log_parse(tp, tlen, pkt->src, pkt->dst, 0, &ie))
            icmp_log_record(&ie);
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
        try_sni(tp, tlen, pkt);
        if (pkt->dst_port == 80 || pkt->src_port == 80 ||
            pkt->dst_port == 8080 || pkt->src_port == 8080 ||
            pkt->dst_port == 8000 || pkt->src_port == 8000)
            try_http(tp, tlen, pkt);
        if (pkt->dst_port == 445 || pkt->src_port == 445 ||
            pkt->dst_port == 139 || pkt->src_port == 139)
            try_smb(tp, tlen, pkt);
        if (pkt->dst_port == 88 || pkt->src_port == 88)
            try_kerb_tcp(tp, tlen, pkt);
        if (pkt->dst_port == 389  || pkt->src_port == 389 ||
            pkt->dst_port == 3268 || pkt->src_port == 3268)
            try_ldap(tp, tlen, pkt);
        if (pkt->dst_port == 179 || pkt->src_port == 179)
            try_bgp(tp, tlen, pkt);
        if (pkt->dst_port == 22 || pkt->src_port == 22)
            try_ssh(tp, tlen, pkt);
        if (pkt->dst_port == 3389 || pkt->src_port == 3389)
            try_rdp(tp, tlen, pkt);
        if (pkt->dst_port == 1883 || pkt->src_port == 1883)
            try_mqtt(tp, tlen, pkt);
    } else if (pkt->proto == 17 && tlen >= 8) {
        pkt->src_port = u16be(tp + 0);
        pkt->dst_port = u16be(tp + 2);
        if ((pkt->src_port == 53 || pkt->dst_port == 53) && tlen > 8) {
            if (!dns_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
            dns_log_entry_t dqe;
            if (dns_log_parse(tp + 8, tlen - 8, pkt->src, &dqe))
                dns_log_record(&dqe);
        } else if ((pkt->src_port == 5353 || pkt->dst_port == 5353) && tlen > 8) {
            mdns_snoop(tp + 8, tlen - 8);
            snprintf(pkt->info, sizeof(pkt->info), "mDNS");
        } else if ((pkt->src_port == 137 || pkt->dst_port == 137) && tlen > 8) {
            if (!nbns_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "NBNS");
        } else if ((pkt->src_port == 67 || pkt->dst_port == 67 ||
                    pkt->src_port == 68 || pkt->dst_port == 68) && tlen > 8) {
            if (!dhcp_snoop(tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "DHCP");
        } else if ((pkt->src_port == 443 || pkt->dst_port == 443) && tlen > 8) {
            const char *remote = (pkt->dst_port == 443) ? pkt->dst : pkt->src;
            const char *host   = dns_lookup(remote);
            quic_log_entry_t qe;
            if (quic_log_parse(tp + 8, tlen - 8, pkt->src, pkt->dst,
                               host && host[0] ? host : NULL, &qe)) {
                snprintf(pkt->info, sizeof(pkt->info), "QUIC %.58s",
                         qe.host[0] ? qe.host : qe.ver);
                quic_log_record(&qe);
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "UDP 443");
            }
        } else if ((pkt->src_port == 1900 || pkt->dst_port == 1900) && tlen > 8) {
            if (!ssdp_snoop(pkt->src, tp + 8, tlen - 8, pkt->info, sizeof(pkt->info)))
                snprintf(pkt->info, sizeof(pkt->info), "SSDP");
        } else if ((pkt->src_port == 123 || pkt->dst_port == 123) && tlen > 8) {
            ntp_log_entry_t ne;
            if (ntp_log_parse(tp + 8, tlen - 8, pkt->src, pkt->dst, &ne)) {
                snprintf(pkt->info, sizeof(pkt->info),
                         "NTP v%u %.6s str=%u", ne.version, ne.mode, ne.stratum);
                ntp_log_record(&ne);
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "NTP");
            }
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "UDP %u", u16be(tp + 4));
        }
    } else if (pkt->proto == 58 && tlen >= 2) {
        snprintf(pkt->info, sizeof(pkt->info), "ICMPv6 type=%u", tp[0]);
        icmp_log_entry_t ie;
        if (icmp_log_parse(tp, tlen, pkt->src, pkt->dst, 1, &ie))
            icmp_log_record(&ie);
        /* NDP Router Advertisement (type 134) — feeds the rogue-RA
         * tracker. Other NDP types (RS, NS, NA, Redirect) are not yet
         * snooped; see docs/wiki/ipv6-ndp.md for the scope decision. */
        if (tp[0] == 134) {
            ndp_snoop_ra(pkt->src, tp, tlen);
            snprintf(pkt->info, sizeof(pkt->info), "NDP RA");
        }
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "IPv6 nh=%u", pkt->proto);
    }
}

/* DLT_LINUX_SLL (113) — Linux cooked capture used by "any" */
#define MY_DLT_LINUX_SLL 113

/* Returns 1 if the frame was decoded as IPv4 or IPv6 (worth keeping in the
 * packets view); 0 for ARP, LLC frames (ethertype < 0x0600), unknown DLTs
 * and any other ethertype. Those drop on the floor — VIEW_ARP and the
 * per-protocol logs cover the data we still care about, and they were
 * otherwise polluting the live list with zero-IP rows. */
static int decode_frame(const uint8_t *data, int caplen, int dlt,
                        packet_info_t *pkt) {
    int       offset    = 0;
    uint16_t  ethertype = 0;

    if (dlt == DLT_EN10MB) {
        if (caplen < 14) return 0;
        ethertype = u16be(data + 12);
        offset    = 14;
    } else if (dlt == MY_DLT_LINUX_SLL) {
        if (caplen < 16) return 0;
        ethertype = u16be(data + 14);
        offset    = 16;
    } else {
        return 0;
    }

    /* strip 802.1Q VLAN tag */
    if (ethertype == 0x8100 && offset + 4 <= caplen) {
        ethertype = u16be(data + offset + 2);
        offset   += 4;
    }

    /* IEEE 802.3 / LLC frames put a length value (< 0x0600) where ethernet II
     * puts an ethertype. We don't decode them — drop. */
    if (ethertype < 0x0600) return 0;

    const uint8_t *payload = data + offset;
    int            plen    = caplen - offset;

    if      (ethertype == 0x0800) { decode_ipv4(payload, plen, pkt); return 1; }
    else if (ethertype == 0x86DD) { decode_ipv6(payload, plen, pkt); return 1; }
    /* ARP and the rest are dropped on purpose. */
    return 0;
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
    if (!decode_frame(data, (int)hdr->caplen, pcap_datalink(g_handle), &pkt))
        return;  /* drop ARP / LLC / unknown — see decode_frame() comment */

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

void capture_start(sloth_state_t *s) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_state  = s;
    g_handle = pcap_open_live("any", 65535, 1, 100, errbuf);

    if (!g_handle) {
        /* "any" unavailable — try first enumerated device */
        pcap_if_t *devs = NULL;
        if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
            snprintf(s->pkt_iface, sizeof(s->pkt_iface), "%s", devs->name);
            g_handle = pcap_open_live(devs->name, 65535, 1, 100, errbuf);
            pcap_freealldevs(devs);
        }
    } else {
        snprintf(s->pkt_iface, sizeof(s->pkt_iface), "any");
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
