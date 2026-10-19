#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns_snoop.h"
#include "dns.h"
#include "dns_wire.h"
#include "bytes.h"

/* ── Public API ──────────────────────────────────────────── */

int dns_snoop(const uint8_t *msg, int len, char *info, int info_sz) {
    if (len < 12) return 0;

    uint16_t flags   = be16(msg + 2);
    int      is_resp = (flags >> 15) & 1;
    int      qdcount = (int)be16(msg + 4);
    int      ancount = (int)be16(msg + 6);

    /* reject obviously-broken counts */
    if (qdcount > 32 || ancount > 64) return 0;

    char qname[256];
    qname[0] = '\0';
    int off = 12;

    /* first question name is what we searched for */
    if (qdcount > 0) {
        int noff = dns_read_name(msg, len, off, qname, sizeof(qname));
        if (noff < 0 || noff + 4 > len) return 0;
        off = noff + 4;   /* skip QTYPE + QCLASS */
    }
    /* skip remaining questions */
    for (int q = 1; q < qdcount; q++) {
        char tmp[256];
        int noff = dns_read_name(msg, len, off, tmp, sizeof(tmp));
        if (noff < 0 || noff + 4 > len) return 0;
        off = noff + 4;
    }

    snprintf(info, info_sz, is_resp ? "DNS %s" : "DNS qry %s",
             qname[0] ? qname : "?");

    if (!is_resp || ancount == 0) return 1;

    /* walk answer RRs, extract A/AAAA */
    char first_ip[46];
    int  ip_count = 0;
    first_ip[0] = '\0';

    for (int i = 0; i < ancount; i++) {
        char rname[256];
        int noff = dns_read_name(msg, len, off, rname, sizeof(rname));
        if (noff < 0 || noff + 10 > len) break;

        uint16_t type  = be16(msg + noff);
        uint16_t rdlen = be16(msg + noff + 8);   /* skip TYPE(2)+CLASS(2)+TTL(4) */
        int      rdata = noff + 10;
        if (rdata + (int)rdlen > len) break;

        if (type == 1 && rdlen == 4) {
            /* A record */
            struct in_addr a;
            memcpy(&a, msg + rdata, 4);
            char ip[46];
            inet_ntop(AF_INET, &a, ip, sizeof(ip));
            dns_set_resolved(ip, qname[0] ? qname : rname);
            ip_count++;
            if (!first_ip[0]) {
                strncpy(first_ip, ip, sizeof(first_ip) - 1);
                first_ip[sizeof(first_ip) - 1] = '\0';
            }
        } else if (type == 28 && rdlen == 16) {
            /* AAAA record */
            struct in6_addr a6;
            memcpy(&a6, msg + rdata, 16);
            char ip[46];
            inet_ntop(AF_INET6, &a6, ip, sizeof(ip));
            dns_set_resolved(ip, qname[0] ? qname : rname);
            ip_count++;
            if (!first_ip[0]) {
                strncpy(first_ip, ip, sizeof(first_ip) - 1);
                first_ip[sizeof(first_ip) - 1] = '\0';
            }
        }
        /* CNAME / MX / NS etc. — skip without injection */

        off = rdata + rdlen;
    }

    /* append first resolved IP to the info string */
    if (first_ip[0]) {
        char base[64];
        strncpy(base, info, sizeof(base) - 1);
        base[sizeof(base) - 1] = '\0';
        if (ip_count > 1)
            snprintf(info, info_sz, "%s → %s +%d", base, first_ip, ip_count - 1);
        else
            snprintf(info, info_sz, "%s → %s", base, first_ip);
    }

    return 1;
}
