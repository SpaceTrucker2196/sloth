#include "web_pcap.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "dns_wire.h"
#include "dot11_frame.h"
#include "dot11_ie.h"
#include "radiotap.h"
#include "web_dot11_names.h"
#include "wifi_freq.h"

/* ── the file ─────────────────────────────────────────────────────── */

#define MAGIC_US  0xa1b2c3d4u
#define MAGIC_NS  0xa1b23c4du
#define PCAPNG    0x0a0d0d0au

static uint32_t rd32(const uint8_t *p, int swapped) {
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                 ((uint32_t)p[3] << 24);
    if (!swapped) return v;
    return (v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24);
}

static uint32_t rd16(const uint8_t *p, int swapped) {
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
    return swapped ? ((v >> 8) | ((v & 0xff) << 8)) : v;
}

int web_pcap_header(const uint8_t *buf, size_t n, web_pcap_hdr_t *h,
                    const char **why) {
    memset(h, 0, sizeof(*h));
    if (why) *why = NULL;
    if (n < 4 || (n < WEB_PCAP_FILE_HDR && rd32(buf, 0) != PCAPNG)) {
        if (why) *why = "short_file";
        return -1;
    }
    /* The magic is read in the file's own order: little-endian first
     * (sloth's, src/pcap_format.c), then the swapped form. */
    uint32_t m = rd32(buf, 0);
    if (m == PCAPNG) { if (why) *why = "pcapng_not_supported"; return -1; }
    if (m == MAGIC_US || m == MAGIC_NS) {
        h->swapped = 0;
    } else {
        m = rd32(buf, 1);
        if (m != MAGIC_US && m != MAGIC_NS) { if (why) *why = "not_pcap"; return -1; }
        h->swapped = 1;
    }
    h->nanos    = m == MAGIC_NS;
    h->major    = rd16(buf + 4, h->swapped);
    h->minor    = rd16(buf + 6, h->swapped);
    h->snaplen  = rd32(buf + 16, h->swapped);
    /* §4: the LinkType field is the low 16 bits; the high bits are an
     * FCS length and a reserved area, read by nothing here. */
    h->linktype = rd32(buf + 20, h->swapped) & 0xffffu;
    return 0;
}

int web_pcap_next(const uint8_t *buf, size_t n, const web_pcap_hdr_t *h,
                  size_t *off, web_pcap_rec_t *r) {
    memset(r, 0, sizeof(*r));
    if (*off >= n) return 0;
    if (n - *off < WEB_PCAP_REC_HDR) return -1;
    const uint8_t *p = buf + *off;
    r->ts_sec  = (long long)rd32(p, h->swapped);
    r->ts_frac = rd32(p + 4, h->swapped);
    r->caplen  = rd32(p + 8, h->swapped);
    r->origlen = rd32(p + 12, h->swapped);
    if (r->caplen > WEB_PCAP_REC_MAX || (h->snaplen && r->caplen > h->snaplen)) return -1;
    if (n - *off - WEB_PCAP_REC_HDR < r->caplen) return -1;
    if (r->origlen < r->caplen) r->origlen = r->caplen;
    r->off = *off + WEB_PCAP_REC_HDR;
    *off = r->off + r->caplen;
    return 1;
}

const char *web_pcap_linktype_name(unsigned linktype, char *buf, size_t cap) {
    switch (linktype) {
    case 1:   return "ethernet";
    case 105: return "802.11";
    case 113: return "linux sll";
    case 127: return "802.11 radiotap";
    case 254: return "bluetooth hci monitor";
    case 276: return "linux sll2";
    default:
        snprintf(buf, cap, "dlt %u", linktype);
        return buf;
    }
}

/* ── strings ──────────────────────────────────────────────────────── */

static void scopy(char *d, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    memcpy(d, s, n);
    d[n] = '\0';
}

/* Bytes off the wire as text: printable ASCII only, '?' for the rest,
 * cut to cap - 1. Nothing above 0x7e is kept: the page sets it as
 * text, but a name is shown, not interpreted. */
static void textcopy(char *d, size_t cap, const uint8_t *s, size_t n) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        uint8_t c = s[i];
        if (c == 0) break;
        d[o++] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    d[o] = '\0';
}

static void kv(web_pcap_dec_t *o, const char *k, const char *v) {
    if (o->nkv >= WEB_PCAP_KV_MAX) return;
    scopy(o->k[o->nkv], sizeof(o->k[0]), k);
    scopy(o->v[o->nkv], sizeof(o->v[0]), v);
    o->nkv++;
}

static void kvf(web_pcap_dec_t *o, const char *k, const char *fmt, long long a) {
    char b[WEB_PCAP_STR];
    snprintf(b, sizeof(b), fmt, a);
    kv(o, k, b);
}

static void mac_str(const uint8_t *m, char *out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void ip4_str(const uint8_t *a, char *out, size_t cap) {
    snprintf(out, cap, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void ip6_str(const uint8_t *a, char *out, size_t cap) {
    /* inet_ntop formats; it resolves nothing. */
    if (!inet_ntop(AF_INET6, a, out, (socklen_t)cap)) scopy(out, cap, "?");
}

static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* ── the IP tiers: this file's summary decoder ────────────────────── */

static void dec_dns(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "DNS");
    if (n < 12) { o->truncated = 1; scopy(o->summary, sizeof(o->summary), "DNS (header cut by snaplen)"); return; }
    unsigned flags = be16(p + 2), qd = be16(p + 4), an = be16(p + 6);
    int qr = (flags >> 15) & 1, opcode = (flags >> 11) & 15, rcode = flags & 15;
    kvf(o, "dns id", "0x%04llx", (long long)be16(p));
    kv(o, "dns", qr ? "response" : "query");
    kvf(o, "opcode", "%lld", opcode);
    if (qr) kvf(o, "rcode", "%lld", rcode);
    kvf(o, "questions", "%lld", qd);
    if (qr) kvf(o, "answers", "%lld", an);
    char name[256] = "";
    int end = qd ? dns_read_name(p, (int)n, 12, name, sizeof(name)) : -1;
    if (qd && end < 0) {
        o->truncated = 1;
        scopy(o->summary, sizeof(o->summary), qr ? "DNS response (name cut or malformed)"
                                                : "DNS query (name cut or malformed)");
        return;
    }
    char nm[128];
    textcopy(nm, sizeof(nm), (const uint8_t *)name, strlen(name));
    if (qd) kv(o, "qname", nm);
    const char *qt = "";
    char qtb[16] = "";
    if (qd && end >= 0 && (unsigned)end + 2 <= n) {
        unsigned t = be16(p + end);
        qt = t == 1 ? "A" : t == 28 ? "AAAA" : t == 12 ? "PTR" : t == 15 ? "MX" : t == 16 ? "TXT"
           : t == 33 ? "SRV" : t == 5 ? "CNAME" : t == 2 ? "NS" : t == 6 ? "SOA" : t == 255 ? "ANY"
           : t == 65 ? "HTTPS" : (snprintf(qtb, sizeof(qtb), "type %u", t), qtb);
        kv(o, "qtype", qt);
    } else if (qd) {
        o->truncated = 1;
    }
    static const char *const RC[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };
    snprintf(o->summary, sizeof(o->summary), "DNS %s %s %s%s%s", qr ? "response" : "query",
             qt, nm, qr && rcode < 6 ? " " : "", qr && rcode < 6 ? RC[rcode] : "");
}

static int http_method(const uint8_t *p, unsigned n) {
    static const char *const M[] = { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
                                     "CONNECT ", "PATCH ", "TRACE " };
    for (size_t i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
        size_t l = strlen(M[i]);
        if (n >= l && !memcmp(p, M[i], l)) return 1;
    }
    return 0;
}

/* The request line and the two headers the page names; a line cut by
 * caplen marks the frame truncated and keeps what was there. */
static void dec_http(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "HTTP");
    unsigned i = 0;
    int line = 0;
    char first[160] = "";
    while (i < n && line < 24) {
        unsigned s = i;
        while (i < n && p[i] != '\n') i++;
        int complete = i < n;
        unsigned e = i;
        if (e > s && p[e - 1] == '\r') e--;
        if (!complete) o->truncated = 1;
        if (e == s && complete) break;        /* the empty line: body follows */
        char l[200];
        textcopy(l, sizeof(l), p + s, e - s);
        if (line == 0) {
            scopy(first, sizeof(first), l);
            if (!strncmp(l, "HTTP/", 5)) {
                kv(o, "status", l);
            } else {
                char *sp = strchr(l, ' ');
                if (sp) {
                    *sp = '\0';
                    kv(o, "method", l);
                    char *sp2 = strchr(sp + 1, ' ');
                    if (sp2) *sp2 = '\0';
                    kv(o, "path", sp + 1);
                    if (sp2) kv(o, "version", sp2 + 1);
                } else {
                    kv(o, "method", l);
                }
            }
        } else if (!strncasecmp(l, "Host:", 5)) {
            const char *v = l + 5;
            while (*v == ' ') v++;
            kv(o, "host", v);
        } else if (!strncasecmp(l, "User-Agent:", 11)) {
            const char *v = l + 11;
            while (*v == ' ') v++;
            kv(o, "user-agent", v);
        }
        line++;
        i++;
    }
    snprintf(o->summary, sizeof(o->summary), "HTTP %s%s", first, o->truncated ? " (cut by snaplen)" : "");
}

/* TLS record 0x16, version 3.x, a ClientHello's SNI (RFC 6066 §3) or a
 * ServerHello's version. Every length read is bounded by n. */
static void dec_tls(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "TLS");
    if (n < 6) { o->truncated = 1; scopy(o->summary, sizeof(o->summary), "TLS (record cut by snaplen)"); return; }
    unsigned rv = be16(p + 1), rlen = be16(p + 3), ht = p[5];
    char ver[16];
    snprintf(ver, sizeof(ver), "%u.%u", rv >> 8, rv & 0xff);
    kv(o, "record version", ver);
    const char *hn = ht == 1 ? "ClientHello" : ht == 2 ? "ServerHello" : ht == 11 ? "Certificate"
                   : ht == 16 ? "ClientKeyExchange" : "handshake";
    kv(o, "handshake", hn);
    if (rlen + 5 > n) o->truncated = 1;
    unsigned i = 9;                         /* after the 4-byte handshake header */
    char sni[128] = "";
    if ((ht == 1 || ht == 2) && i + 2 <= n) {
        unsigned hv = be16(p + i);
        snprintf(ver, sizeof(ver), "%u.%u", hv >> 8, hv & 0xff);
        kv(o, "hello version", ver);
        i += 2 + 32;                         /* version, random */
        if (i < n) {
            unsigned sid = p[i];
            i += 1 + sid;
            if (ht == 1) {
                if (i + 2 <= n) { unsigned cl = be16(p + i); i += 2 + cl; }
                if (i < n) { unsigned cm = p[i]; i += 1 + cm; }
            } else {
                i += 2 + 1;                  /* cipher, compression */
            }
            if (i + 2 <= n) {
                unsigned el = be16(p + i), end = i + 2 + el;
                i += 2;
                if (end > n) { end = n; o->truncated = 1; }
                int hops = 0;
                while (i + 4 <= end && hops++ < 64) {
                    unsigned et = be16(p + i), l = be16(p + i + 2);
                    i += 4;
                    if (i + l > end) { o->truncated = 1; break; }
                    if (et == 0 && l >= 5) {
                        /* server_name list: list len 2, type 1, name len 2 */
                        unsigned nl = be16(p + i + 3);
                        if (p[i + 2] == 0 && 5 + nl <= l) textcopy(sni, sizeof(sni), p + i + 5, nl);
                    }
                    i += l;
                }
                if (sni[0]) kv(o, "sni", sni);
            } else if (ht == 1) {
                o->truncated = 1;
            }
        } else {
            o->truncated = 1;
        }
    } else if (ht == 1 || ht == 2) {
        o->truncated = 1;
    }
    snprintf(o->summary, sizeof(o->summary), "TLS %s%s%s%s", hn, sni[0] ? " SNI " : "", sni,
             o->truncated ? " (cut by snaplen)" : "");
}

static void dec_app_tcp(web_pcap_dec_t *o, unsigned sport, unsigned dport,
                        const uint8_t *p, unsigned n) {
    if (n == 0) return;
    if ((sport == 53 || dport == 53) && n >= 2) { dec_dns(o, p + 2, n - 2); return; }
    if (http_method(p, n) || (n >= 5 && !memcmp(p, "HTTP/", 5))) { dec_http(o, p, n); return; }
    if (p[0] == 0x16 && n >= 3 && p[1] == 3 && p[2] <= 4) { dec_tls(o, p, n); return; }
    if (n >= 3 && p[0] >= 0x14 && p[0] <= 0x17 && p[1] == 3 && p[2] <= 4) {
        scopy(o->kind, sizeof(o->kind), "TLS");
        kv(o, "record", p[0] == 0x17 ? "application data" : p[0] == 0x15 ? "alert" : "change cipher spec");
        return;
    }
    /* NetBIOS session service (RFC 1002 §4.3.1: type 0, a 24-bit
     * length) carrying SMB: "\xffSMB" is SMB1 ([MS-CIFS] §2.2.3.1,
     * the command byte after it), "\xfeSMB" SMB2 or 3 ([MS-SMB2]
     * §2.2.1). SMB1_USE's capture shows which. */
    if ((sport == 445 || dport == 445 || sport == 139 || dport == 139) && n >= 8 && p[0] == 0 &&
        (p[4] == 0xff || p[4] == 0xfe) && !memcmp(p + 5, "SMB", 3)) {
        int v1 = p[4] == 0xff;
        scopy(o->kind, sizeof(o->kind), v1 ? "SMB1" : "SMB2/3");
        kv(o, "dialect", v1 ? "SMB1 (\\xffSMB)" : "SMB2 or 3 (\\xfeSMB)");
        if (v1 && n >= 9) {
            unsigned c = p[8];
            char b[48];
            snprintf(b, sizeof(b), "0x%02x%s", c, c == 0x72 ? " NEGOTIATE" : c == 0x73 ? " SESSION_SETUP_ANDX"
                     : c == 0x75 ? " TREE_CONNECT_ANDX" : "");
            kv(o, "command", b);
        } else if (v1) {
            o->truncated = 1;
        }
        snprintf(o->summary, sizeof(o->summary), "%s %s -> %s", o->kind, o->from, o->to);
        return;
    }
    if (n >= 4 && !memcmp(p, "SSH-", 4)) {
        char b[64];
        unsigned l = 0;
        while (l < n && l < 60 && p[l] != '\r' && p[l] != '\n') l++;
        textcopy(b, sizeof(b), p, l);
        scopy(o->kind, sizeof(o->kind), "SSH");
        kv(o, "banner", b);
    }
}

static void dec_app_udp(web_pcap_dec_t *o, unsigned sport, unsigned dport,
                        const uint8_t *p, unsigned n) {
    if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) {
        if (sport == 5353 || dport == 5353) kv(o, "mdns", "yes");
        dec_dns(o, p, n);
        return;
    }
    if (sport == 67 || dport == 67 || sport == 68 || dport == 68) {
        scopy(o->kind, sizeof(o->kind), "DHCP");
        if (n >= 1) kv(o, "op", p[0] == 1 ? "request" : p[0] == 2 ? "reply" : "?");
        else o->truncated = 1;
        return;
    }
    if (sport == 123 || dport == 123) {
        scopy(o->kind, sizeof(o->kind), "NTP");
        if (n >= 1) kvf(o, "mode", "%lld", p[0] & 7); else o->truncated = 1;
        return;
    }
    if ((sport == 443 || dport == 443) && n >= 5 && (p[0] & 0x80)) {
        scopy(o->kind, sizeof(o->kind), "QUIC");
        kvf(o, "version", "0x%08llx", (long long)be32(p + 1));
        return;
    }
    if ((sport == 1900 || dport == 1900 || sport == 3702 || dport == 3702) && n >= 4 &&
        (http_method(p, n) || (n >= 6 && !memcmp(p, "NOTIFY", 6)) ||
         (n >= 8 && !memcmp(p, "M-SEARCH", 8)) || (n >= 5 && !memcmp(p, "HTTP/", 5)))) {
        dec_http(o, p, n);
        scopy(o->kind, sizeof(o->kind), sport == 3702 || dport == 3702 ? "WS-Discovery" : "SSDP");
        return;
    }
    if (n >= 4 && (sport == 3702 || dport == 3702)) scopy(o->kind, sizeof(o->kind), "WS-Discovery");
}

static void dec_l4(web_pcap_dec_t *o, unsigned proto, const uint8_t *p, unsigned n, int v6) {
    char b[64];
    if (proto == 6) {
        scopy(o->kind, sizeof(o->kind), v6 ? "IPv6 TCP" : "IPv4 TCP");
        if (n < 20) { o->truncated = 1; return; }
        unsigned sp = be16(p), dp = be16(p + 2), doff = (p[12] >> 4) * 4, fl = p[13];
        size_t l = strlen(o->from);
        snprintf(o->from + l, sizeof(o->from) - l, "%s%u", v6 ? "." : ":", sp);
        l = strlen(o->to);
        snprintf(o->to + l, sizeof(o->to) - l, "%s%u", v6 ? "." : ":", dp);
        char f[48] = "";
        static const struct { unsigned bit; const char *w; } FL[] = {
            { 0x02, "SYN" }, { 0x10, "ACK" }, { 0x01, "FIN" }, { 0x04, "RST" },
            { 0x08, "PSH" }, { 0x20, "URG" }, { 0x40, "ECE" }, { 0x80, "CWR" },
        };
        for (size_t i = 0; i < sizeof(FL) / sizeof(FL[0]); i++)
            if (fl & FL[i].bit) { if (f[0]) strcat(f, " "); strcat(f, FL[i].w); }
        kv(o, "tcp flags", f[0] ? f : "none");
        kvf(o, "seq", "%llu", (long long)be32(p + 4));
        if (fl & 0x10) kvf(o, "ack", "%llu", (long long)be32(p + 8));
        kvf(o, "window", "%llu", (long long)be16(p + 14));
        snprintf(o->summary, sizeof(o->summary), "TCP %s %s -> %s", f[0] ? f : "", o->from, o->to);
        if (doff < 20 || doff > n) { o->truncated = 1; return; }
        dec_app_tcp(o, sp, dp, p + doff, n - doff);
    } else if (proto == 17) {
        scopy(o->kind, sizeof(o->kind), v6 ? "IPv6 UDP" : "IPv4 UDP");
        if (n < 8) { o->truncated = 1; return; }
        unsigned sp = be16(p), dp = be16(p + 2), ul = be16(p + 4);
        size_t l = strlen(o->from);
        snprintf(o->from + l, sizeof(o->from) - l, "%s%u", v6 ? "." : ":", sp);
        l = strlen(o->to);
        snprintf(o->to + l, sizeof(o->to) - l, "%s%u", v6 ? "." : ":", dp);
        kvf(o, "udp length", "%llu", ul);
        snprintf(o->summary, sizeof(o->summary), "UDP %s -> %s", o->from, o->to);
        if (ul < 8) return;
        unsigned pl = n - 8;
        if (ul - 8 > pl) o->truncated = 1; else pl = ul - 8;
        dec_app_udp(o, sp, dp, p + 8, pl);
    } else if (proto == 1 || proto == 58) {
        scopy(o->kind, sizeof(o->kind), proto == 1 ? "ICMP" : "ICMPv6");
        if (n < 4) { o->truncated = 1; return; }
        unsigned t = p[0], c = p[1];
        const char *tn = proto == 1
            ? (t == 0 ? "echo reply" : t == 3 ? "destination unreachable" : t == 5 ? "redirect"
               : t == 8 ? "echo request" : t == 11 ? "time exceeded" : "type")
            : (t == 128 ? "echo request" : t == 129 ? "echo reply" : t == 133 ? "router solicitation"
               : t == 134 ? "router advertisement" : t == 135 ? "neighbor solicitation"
               : t == 136 ? "neighbor advertisement" : t == 1 ? "destination unreachable" : "type");
        snprintf(b, sizeof(b), "%u (%s)", t, tn);
        kv(o, "icmp type", b);
        kvf(o, "icmp code", "%lld", c);
        if ((proto == 1 && (t == 0 || t == 8)) || (proto == 58 && (t == 128 || t == 129))) {
            if (n >= 8) { kvf(o, "id", "%lld", be16(p + 4)); kvf(o, "seq", "%lld", be16(p + 6)); }
            else o->truncated = 1;
            kvf(o, "payload bytes", "%lld", n >= 8 ? n - 8 : 0);
        }
        snprintf(o->summary, sizeof(o->summary), "%s %s %s -> %s", o->kind, tn, o->from, o->to);
    } else {
        snprintf(o->kind, sizeof(o->kind), "%s proto %u", v6 ? "IPv6" : "IPv4", proto);
        snprintf(o->summary, sizeof(o->summary), "%s %s -> %s", o->kind, o->from, o->to);
    }
}

static void dec_ipv4(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "IPv4");
    if (n < 20) { o->truncated = 1; return; }
    unsigned ihl = (p[0] & 15) * 4, tot = be16(p + 2), ff = be16(p + 6), proto = p[9];
    ip4_str(p + 12, o->from, sizeof(o->from));
    ip4_str(p + 16, o->to, sizeof(o->to));
    kvf(o, "ttl", "%lld", p[8]);
    kvf(o, "ip length", "%lld", tot);
    snprintf(o->summary, sizeof(o->summary), "IPv4 proto %u %s -> %s", proto, o->from, o->to);
    if ((ff & 0x1fff) != 0) {
        kv(o, "fragment", "not first: not parsed");
        snprintf(o->kind, sizeof(o->kind), "IPv4 fragment");
        return;
    }
    if (ff & 0x2000) kv(o, "fragment", "first, more follow");
    if (ihl < 20 || ihl > n) { o->truncated = 1; return; }
    /* The L4 bytes are what caplen holds, never what Total Length
     * claims: a 64-byte snaplen cuts most packets here. */
    unsigned l4 = n - ihl;
    if (tot >= ihl && tot - ihl < l4) l4 = tot - ihl;
    else if (tot > n) o->truncated = 1;
    dec_l4(o, proto, p + ihl, l4, 0);
}

static void dec_ipv6(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "IPv6");
    if (n < 40) { o->truncated = 1; return; }
    unsigned nh = p[6], pl = be16(p + 4);
    ip6_str(p + 8, o->from, sizeof(o->from));
    ip6_str(p + 24, o->to, sizeof(o->to));
    kvf(o, "hop limit", "%lld", p[7]);
    kvf(o, "payload length", "%lld", pl);
    unsigned off = 40, hops = 0;
    /* One pass over the extension chain: hop-by-hop (0), routing (43),
     * destination options (60), AH (51), fragment (44). */
    while (hops++ < 8 && off < n) {
        if (nh == 0 || nh == 43 || nh == 60 || nh == 51) {
            if (off + 2 > n) { o->truncated = 1; return; }
            unsigned el = nh == 51 ? (p[off + 1] + 2) * 4 : (p[off + 1] + 1) * 8;
            nh = p[off];
            off += el;
        } else if (nh == 44) {
            if (off + 8 > n) { o->truncated = 1; return; }
            unsigned fo = be16(p + off + 2) & 0xfff8u;
            unsigned next = p[off];
            off += 8;
            if (fo) {
                kv(o, "fragment", "not first: not parsed");
                snprintf(o->kind, sizeof(o->kind), "IPv6 fragment");
                return;
            }
            nh = next;
        } else {
            break;
        }
    }
    if (off > n) { o->truncated = 1; return; }
    snprintf(o->summary, sizeof(o->summary), "IPv6 next header %u %s -> %s", nh, o->from, o->to);
    unsigned l4 = n - off;
    if (pl + 40 < n && pl + 40 >= off) l4 = pl + 40 - off;
    else if (pl + 40 > n) o->truncated = 1;
    if (nh == 59) { kv(o, "next header", "none"); return; }
    dec_l4(o, nh, p + off, l4, 1);
}

static void dec_arp(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->kind, sizeof(o->kind), "ARP");
    if (n < 28) { o->truncated = 1; return; }
    unsigned op = be16(p + 6);
    char s[20], t[20], sm[18], tm[18];
    ip4_str(p + 14, s, sizeof(s));
    ip4_str(p + 24, t, sizeof(t));
    mac_str(p + 8, sm);
    mac_str(p + 18, tm);
    kv(o, "arp", op == 1 ? "request" : op == 2 ? "reply" : "op");
    kv(o, "sender", s);
    kv(o, "sender mac", sm);
    kv(o, "target", t);
    if (op == 2) kv(o, "target mac", tm);
    snprintf(o->summary, sizeof(o->summary), op == 1 ? "ARP who has %s, tell %s" : "ARP %s is at %s",
             op == 1 ? t : s, op == 1 ? s : sm);
}

static void dec_ethertype(web_pcap_dec_t *o, unsigned et, const uint8_t *p, unsigned n) {
    switch (et) {
    case 0x0800: dec_ipv4(o, p, n); break;
    case 0x86dd: dec_ipv6(o, p, n); break;
    case 0x0806: dec_arp(o, p, n); break;
    case 0x888e:
        scopy(o->kind, sizeof(o->kind), "EAPOL");
        if (n >= 4) kvf(o, "eapol type", "%lld", p[1]); else o->truncated = 1;
        scopy(o->summary, sizeof(o->summary), "802.1X EAPOL");
        break;
    case 0x88cc: scopy(o->kind, sizeof(o->kind), "LLDP"); break;
    default:
        snprintf(o->kind, sizeof(o->kind), "ethertype 0x%04x", et);
        snprintf(o->summary, sizeof(o->summary), "ethertype 0x%04x", et);
        break;
    }
}

static void dec_ethernet(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->link, sizeof(o->link), "ethernet");
    if (n < 14) { o->truncated = 1; scopy(o->kind, sizeof(o->kind), "ethernet (cut)"); return; }
    char d[18], s[18];
    mac_str(p, d);
    mac_str(p + 6, s);
    kv(o, "dst mac", d);
    kv(o, "src mac", s);
    scopy(o->from, sizeof(o->from), s);
    scopy(o->to, sizeof(o->to), d);
    unsigned et = be16(p + 12), off = 14;
    /* 802.1Q, and a second tag for 802.1ad. */
    for (int k = 0; k < 2 && (et == 0x8100 || et == 0x88a8); k++) {
        if (off + 4 > n) { o->truncated = 1; return; }
        kvf(o, "vlan", "%lld", be16(p + off) & 0xfff);
        et = be16(p + off + 2);
        off += 4;
    }
    dec_ethertype(o, et, p + off, n - off);
}

static const char *pkttype_name(unsigned t) {
    return t == 0 ? "to host" : t == 1 ? "broadcast" : t == 2 ? "multicast" : t == 3 ? "to another host"
         : t == 4 ? "sent by host" : "packet type";
}

/* LINKTYPE_LINUX_SLL: packet type 2, ARPHRD 2, address length 2,
 * address 8, protocol 2, 16 bytes. */
static void dec_sll(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->link, sizeof(o->link), "linux sll");
    if (n < 16) { o->truncated = 1; scopy(o->kind, sizeof(o->kind), "sll (cut)"); return; }
    kv(o, "direction", pkttype_name(be16(p)));
    unsigned al = be16(p + 4);
    if (al == 6) { char m[18]; mac_str(p + 6, m); kv(o, "ll addr", m); scopy(o->from, sizeof(o->from), m); }
    dec_ethertype(o, be16(p + 14), p + 16, n - 16);
}

/* LINKTYPE_LINUX_SLL2: protocol 2, reserved 2, ifindex 4, ARPHRD 2,
 * packet type 1, address length 1, address 8, 20 bytes. */
static void dec_sll2(web_pcap_dec_t *o, const uint8_t *p, unsigned n) {
    scopy(o->link, sizeof(o->link), "linux sll2");
    if (n < 20) { o->truncated = 1; scopy(o->kind, sizeof(o->kind), "sll2 (cut)"); return; }
    kvf(o, "ifindex", "%lld", (long long)be32(p + 4));
    kv(o, "direction", pkttype_name(p[10]));
    if (p[11] == 6) { char m[18]; mac_str(p + 12, m); kv(o, "ll addr", m); scopy(o->from, sizeof(o->from), m); }
    dec_ethertype(o, be16(p), p + 20, n - 20);
}

/* ── 802.11: sloth's own view of the header ───────────────────────── */

static void addr_roles(web_pcap_dec_t *o, const dot11_frame_t *f) {
    const uint8_t *const A[4] = { f->a1, f->a2, f->a3, f->a4 };
    static const char *const NAME[4] = { "addr1", "addr2", "addr3", "addr4" };
    for (int i = 0; i < 4; i++) {
        if (!A[i]) continue;
        char m[18], roles[40] = "";
        mac_str(A[i], m);
        if (f->ra == A[i])    strcat(roles, " RA");
        if (f->ta == A[i])    strcat(roles, " TA");
        if (f->da == A[i])    strcat(roles, " DA");
        if (f->sa == A[i])    strcat(roles, " SA");
        if (f->bssid == A[i]) strcat(roles, " BSSID");
        char v[WEB_PCAP_STR];
        snprintf(v, sizeof(v), "%s%s%s", m, roles[0] ? " =" : "", roles);
        kv(o, NAME[i], v);
    }
    if (f->ta) mac_str(f->ta, o->from); else if (f->a2) mac_str(f->a2, o->from);
    if (f->ra) mac_str(f->ra, o->to);   else if (f->a1) mac_str(f->a1, o->to);
}

static void dec_dot11_body(web_pcap_dec_t *o, const dot11_frame_t *f) {
    const uint8_t *b = NULL;
    int bl = 0;
    char v[WEB_PCAP_STR];
    if (f->type == 0) {
        if (!dot11_frame_body(f, &b, &bl)) { o->truncated = 1; return; }
        unsigned st = f->subtype;
        if (st == 12 || st == 10) {
            if (bl < 2) { o->truncated = 1; return; }
            unsigned r = b[0] | (b[1] << 8);
            snprintf(v, sizeof(v), "%u: %s", r, web_dot11_reason_name(r));
            kv(o, "reason", v);
            snprintf(o->summary, sizeof(o->summary), "%s reason %u (%s) %s -> %s", o->kind, r,
                     web_dot11_reason_name(r), o->from, o->to);
        } else if (st == 11) {
            if (bl < 6) { o->truncated = 1; return; }
            unsigned alg = b[0] | (b[1] << 8), seq = b[2] | (b[3] << 8), sc = b[4] | (b[5] << 8);
            snprintf(v, sizeof(v), "%u: %s", alg, web_dot11_auth_alg_name(alg));
            kv(o, "algorithm", v);
            kvf(o, "auth seq", "%lld", seq);
            snprintf(v, sizeof(v), "%u: %s", sc, web_dot11_status_name(sc));
            kv(o, "status", v);
            snprintf(o->summary, sizeof(o->summary), "Authentication %s seq %u status %u (%s)",
                     web_dot11_auth_alg_name(alg), seq, sc, web_dot11_status_name(sc));
        } else if (st == 1 || st == 3) {
            if (bl < 6) { o->truncated = 1; return; }
            unsigned sc = b[2] | (b[3] << 8), aid = (b[4] | (b[5] << 8)) & 0x3fff;
            snprintf(v, sizeof(v), "%u: %s", sc, web_dot11_status_name(sc));
            kv(o, "status", v);
            kvf(o, "aid", "%lld", aid);
            snprintf(o->summary, sizeof(o->summary), "%s status %u (%s)", o->kind, sc,
                     web_dot11_status_name(sc));
        } else if (st == 8 || st == 5 || st == 4 || st == 0 || st == 2) {
            int fixed = st == 8 || st == 5 ? 12 : st == 4 ? 0 : st == 0 ? 4 : 10;
            if (bl < fixed) { o->truncated = 1; return; }
            if (st == 8 || st == 5) {
                unsigned cap = b[10] | (b[11] << 8);
                kvf(o, "beacon interval", "%lld TU", b[8] | (b[9] << 8));
                kv(o, "capability", (cap & 0x10) ? ((cap & 1) ? "ESS, privacy" : "privacy")
                                                : ((cap & 1) ? "ESS, open" : "open"));
            }
            const uint8_t *ies = b + fixed;
            int il = bl - fixed;
            char ssid[33];
            int oversize = 0, has = dot11_ie_ssid(ies, il, ssid, &oversize);
            if (has) {
                char s2[64];
                textcopy(s2, sizeof(s2), (const uint8_t *)ssid, strlen(ssid));
                kv(o, "ssid", ssid[0] ? s2 : "(hidden or wildcard)");
                if (oversize) kv(o, "ssid element", "over 32 octets: invalid");
            }
            const uint8_t *eb;
            int el;
            if (dot11_ie_find(ies, il, 3, &eb, &el) && el >= 1) kvf(o, "ds channel", "%lld", eb[0]);
            if (dot11_ie_find(ies, il, 48, &eb, &el)) kv(o, "rsn", "present");
            dot11_phy_t phy;
            dot11_ie_phy(ies, il, &phy);
            kv(o, "phy", dot11_phy_tier(&phy));
            snprintf(o->summary, sizeof(o->summary), "%s%s%s %s -> %s", o->kind, has ? " ssid " : "",
                     has ? (ssid[0] ? ssid : "(hidden)") : "", o->from, o->to);
            /* The summary, like every string, is printable ASCII. */
            for (char *c = o->summary; *c; c++)
                if ((unsigned char)*c < 0x20 || (unsigned char)*c > 0x7e) *c = '?';
        } else if (st == 13 || st == 14) {
            if (bl < 2) { o->truncated = 1; return; }
            kvf(o, "category", "%lld", b[0]);
            kvf(o, "action", "%lld", b[1]);
        }
    } else if (f->type == 2) {
        int po = 0;
        uint16_t et = 0;
        int rc = dot11_frame_payload(f, &po, &et);
        if (rc == DOT11_DATA_OK) {
            kvf(o, "ethertype", "0x%04llx", et);
            web_pcap_dec_t inner;
            memset(&inner, 0, sizeof(inner));
            dec_ethertype(&inner, et, f->p + po, (unsigned)(f->len - po));
            size_t l = strlen(o->kind);
            snprintf(o->kind + l, sizeof(o->kind) - l, " / %s", inner.kind);
            for (int i = 0; i < inner.nkv; i++) kv(o, inner.k[i], inner.v[i]);
            if (inner.summary[0]) scopy(o->summary, sizeof(o->summary), inner.summary);
            if (inner.truncated) o->truncated = 1;
        } else if (rc == DOT11_DATA_ENCRYPTED) {
            kv(o, "body", "protected: not read");
        } else if (rc == DOT11_DATA_TRUNCATED) {
            o->truncated = 1;
        } else if (rc == DOT11_DATA_AMSDU) {
            kv(o, "body", "A-MSDU: not parsed");
        } else if (rc == DOT11_DATA_FRAGMENT) {
            kv(o, "body", "fragment: not parsed");
        } else if (rc == DOT11_DATA_NOT_SNAP) {
            kv(o, "body", "LLC without SNAP: not parsed");
        }
    }
}

static void dec_dot11(web_pcap_dec_t *o, const uint8_t *p, unsigned caplen, unsigned origlen,
                      int radiotap) {
    dot11_rt_hints_t hints;
    memset(&hints, 0, sizeof(hints));
    unsigned off = 0;
    scopy(o->link, sizeof(o->link), radiotap ? "802.11 radiotap" : "802.11");
    if (radiotap) {
        radiotap_info_t rt;
        if (!radiotap_parse(p, (int)caplen, &rt)) {
            o->truncated = 1;
            scopy(o->kind, sizeof(o->kind), "radiotap: malformed or cut");
            return;
        }
        off = (unsigned)rt.hdr_len;
        if (rt.freq_mhz) {
            wifi_band_t band;
            int ch = wifi_freq_channel(rt.freq_mhz, &band);
            char v[48];
            snprintf(v, sizeof(v), "%d MHz%s%d%s", rt.freq_mhz, ch ? " (ch " : "", ch,
                     ch ? (band == WIFI_BAND_2GHZ ? ", 2.4 GHz)" : band == WIFI_BAND_5GHZ ? ", 5 GHz)"
                          : band == WIFI_BAND_6GHZ ? ", 6 GHz)" : ")") : "");
            kv(o, "channel", v);
        }
        if (rt.has_signal) kvf(o, "rssi", "%lld dBm", rt.signal_dbm);
        if (rt.rate_kbps) kvf(o, "rate", "%lld kbps", rt.rate_kbps);
        if (rt.has_flags) {
            char f[64] = "";
            if (rt.fcs_present) strcat(f, "fcs ");
            if (rt.bad_fcs) strcat(f, "BAD-FCS ");
            if (rt.datapad) strcat(f, "datapad ");
            kv(o, "radiotap flags", f[0] ? f : "none");
        }
        hints.fcs_present = rt.fcs_present;
        hints.datapad = rt.datapad;
        hints.bad_fcs = rt.bad_fcs;
    }
    if (off > caplen) { o->truncated = 1; return; }
    unsigned flen = caplen - off, olen = origlen > off ? origlen - off : flen;
    int strip = dot11_fcs_strip_len((int)flen, (int)olen, hints.fcs_present);
    if (strip > 0 && (unsigned)strip <= flen) flen -= (unsigned)strip;
    dot11_frame_t f;
    int ok = dot11_frame_decode(p + off, (int)flen, &hints, &f);
    snprintf(o->kind, sizeof(o->kind), "%s", web_dot11_subtype_name(f.type, f.subtype));
    kvf(o, "type/subtype", "%lld", (long long)f.type * 16 + f.subtype);
    char fl[80] = "";
    if (f.to_ds) strcat(fl, "to-ds ");
    if (f.from_ds) strcat(fl, "from-ds ");
    if (f.more_frag) strcat(fl, "more-frag ");
    if (f.retry) strcat(fl, "retry ");
    if (f.pwr_mgmt) strcat(fl, "pwr-mgmt ");
    if (f.more_data) strcat(fl, "more-data ");
    if (f.protected_) strcat(fl, "protected ");
    if (f.order) strcat(fl, "order ");
    kv(o, "fc flags", fl[0] ? fl : "none");
    addr_roles(o, &f);
    if (f.seq_num >= 0) {
        char v[32];
        snprintf(v, sizeof(v), "%d / %d", f.seq_num, f.frag_num);
        kv(o, "seq / frag", v);
    }
    if (f.proto != 0) kv(o, "protocol version", "not 0: not interpreted");
    snprintf(o->summary, sizeof(o->summary), "%s %s -> %s", o->kind, o->from, o->to);
    if (!ok) { o->truncated = f.type != 3; if (f.type == 3) kv(o, "body", "extension frame: not parsed"); return; }
    if (f.bad_fcs) kv(o, "fcs", "failed: contents untrustworthy");
    dec_dot11_body(o, &f);
}

void web_pcap_decode(unsigned linktype, const uint8_t *p, unsigned caplen, unsigned origlen,
                     web_pcap_dec_t *o) {
    memset(o, 0, sizeof(*o));
    char nb[24];
    switch (linktype) {
    case 1:   dec_ethernet(o, p, caplen); break;
    case 113: dec_sll(o, p, caplen); break;
    case 276: dec_sll2(o, p, caplen); break;
    case 105: dec_dot11(o, p, caplen, origlen, 0); break;
    case 127: dec_dot11(o, p, caplen, origlen, 1); break;
    default:
        scopy(o->link, sizeof(o->link), web_pcap_linktype_name(linktype, nb, sizeof(nb)));
        scopy(o->kind, sizeof(o->kind), "hex only");
        break;
    }
    if (!o->summary[0]) snprintf(o->summary, sizeof(o->summary), "%s%s%s%s%s", o->kind,
                                 o->from[0] ? " " : "", o->from, o->to[0] ? " -> " : "", o->to);
}

/* ── the hex dump ─────────────────────────────────────────────────── */

size_t web_pcap_hexdump(const uint8_t *p, size_t n, char *out, size_t cap) {
    if (n > WEB_PCAP_HEX) n = WEB_PCAP_HEX;
    size_t o = 0;
    static const char HEX[] = "0123456789abcdef";
    for (size_t row = 0; row < n; row += 16) {
        /* "oooo  " + 16 x "xx " + " |" + 16 + "|\n" = 76 bytes a row */
        if (o + 78 > cap) break;
        out[o++] = HEX[(row >> 12) & 15]; out[o++] = HEX[(row >> 8) & 15];
        out[o++] = HEX[(row >> 4) & 15];  out[o++] = HEX[row & 15];
        out[o++] = ' '; out[o++] = ' ';
        for (size_t i = 0; i < 16; i++) {
            if (row + i < n) { out[o++] = HEX[p[row + i] >> 4]; out[o++] = HEX[p[row + i] & 15]; }
            else { out[o++] = ' '; out[o++] = ' '; }
            out[o++] = ' ';
            if (i == 7) out[o++] = ' ';
        }
        out[o++] = ' '; out[o++] = '|';
        for (size_t i = 0; i < 16 && row + i < n; i++)
            out[o++] = p[row + i] >= 0x20 && p[row + i] <= 0x7e ? (char)p[row + i] : '.';
        out[o++] = '|';
        out[o++] = '\n';
    }
    if (o && out[o - 1] == '\n') o--;
    out[o] = '\0';
    return n;
}

/* ── the page's JSON ──────────────────────────────────────────────── */

int web_pcap_frames_json(const uint8_t *buf, size_t n, long long offset, web_jw_t *w,
                         const char **why) {
    web_pcap_hdr_t h;
    if (web_pcap_header(buf, n, &h, why) != 0) return -1;
    char nb[24];
    web_jw_raw(w, "\"file\":{\"magic\":");
    web_jw_str(w, h.swapped ? "swapped" : "little-endian");
    web_jw_raw(w, ",\"resolution\":");    web_jw_str(w, h.nanos ? "ns" : "us");
    web_jw_raw(w, ",\"version\":");
    { char v[16]; snprintf(v, sizeof(v), "\"%u.%u\"", h.major, h.minor); web_jw_raw(w, v); }
    web_jw_raw(w, ",\"snaplen\":");       web_jw_int(w, h.snaplen);
    web_jw_raw(w, ",\"linktype\":");      web_jw_int(w, h.linktype);
    web_jw_raw(w, ",\"linktype_name\":");
    web_jw_str(w, web_pcap_linktype_name(h.linktype, nb, sizeof(nb)));
    web_jw_raw(w, ",\"bytes\":");         web_jw_int(w, (long long)n);
    web_jw_raw(w, "},\"frames\":[");
    size_t off = WEB_PCAP_FILE_HDR;
    web_pcap_rec_t r;
    long long i = 0, shown = 0, first_ns = 0;
    int rc, capped = 0, room = 1;
    if (offset < 0) offset = 0;
    /* Every record is walked (headers only past the page), so the
     * total is the file's whatever the page shows. */
    while ((rc = web_pcap_next(buf, n, &h, &off, &r)) == 1) {
        if (i >= WEB_PCAP_RECORDS) { capped = 1; break; }
        long long t_ns = r.ts_sec * 1000000000LL +
                         (h.nanos ? (long long)r.ts_frac : (long long)r.ts_frac * 1000LL);
        if (i == 0) first_ns = t_ns;
        /* Room for one frame at its largest, then the tail. */
        if (room && i >= offset && shown < WEB_PCAP_PAGE && w->cap - w->len < WEB_PCAP_FRAME_JSON)
            room = 0;
        if (room && i >= offset && shown < WEB_PCAP_PAGE) {
            web_pcap_dec_t d;
            web_pcap_decode(h.linktype, buf + r.off, r.caplen, r.origlen, &d);
            web_jw_raw(w, shown ? ",{\"i\":" : "{\"i\":");
            web_jw_int(w, i);
            web_jw_raw(w, ",\"ts\":");       web_jw_int(w, r.ts_sec);
            web_jw_raw(w, ",\"ts_frac\":");  web_jw_int(w, r.ts_frac);
            web_jw_raw(w, ",\"ts_ns\":");    web_jw_raw(w, h.nanos ? "true" : "false");
            web_jw_raw(w, ",\"t_rel_ns\":"); web_jw_int(w, t_ns - first_ns);
            web_jw_raw(w, ",\"caplen\":");   web_jw_int(w, r.caplen);
            web_jw_raw(w, ",\"len\":");      web_jw_int(w, r.origlen);
            web_jw_raw(w, ",\"link\":");     web_jw_str(w, d.link);
            web_jw_raw(w, ",\"kind\":");     web_jw_str(w, d.kind);
            web_jw_raw(w, ",\"from\":");     web_jw_str(w, d.from);
            web_jw_raw(w, ",\"to\":");       web_jw_str(w, d.to);
            web_jw_raw(w, ",\"summary\":");  web_jw_str(w, d.summary);
            web_jw_raw(w, ",\"truncated\":"); web_jw_raw(w, d.truncated ? "true" : "false");
            /* The record kept fewer bytes than the packet had: what a
             * decode could not reach was never on disk. --pcap-dir
             * files are snaplen 64 (src/pcap_format.h), so this is the
             * common case and the page says it rather than showing an
             * absent field as "none". */
            web_jw_raw(w, ",\"cut\":");
            if (r.caplen < r.origlen) {
                /* The snaplen is the reason only when the record
                 * stopped exactly there; otherwise something else cut
                 * it, and the page states the counts, not a cause. */
                char cut[64];
                if (r.caplen == h.snaplen)
                    snprintf(cut, sizeof(cut), "truncated at snaplen %u", h.snaplen);
                else
                    snprintf(cut, sizeof(cut), "%u of %u bytes captured",
                             (unsigned)r.caplen, (unsigned)r.origlen);
                web_jw_str(w, cut);
            } else {
                web_jw_raw(w, "null");
            }
            web_jw_raw(w, ",\"fields\":[");
            for (int k = 0; k < d.nkv; k++) {
                web_jw_raw(w, k ? ",[" : "[");
                web_jw_str(w, d.k[k]);
                web_jw_raw(w, ",");
                web_jw_str(w, d.v[k]);
                web_jw_raw(w, "]");
            }
            char hex[WEB_PCAP_HEX / 16 * 78 + 8];
            size_t dumped = web_pcap_hexdump(buf + r.off, r.caplen, hex, sizeof(hex));
            web_jw_raw(w, "],\"hex\":");     web_jw_str(w, hex);
            web_jw_raw(w, ",\"hex_more\":"); web_jw_int(w, (long long)(r.caplen - dumped));
            web_jw_raw(w, "}");
            shown++;
        }
        i++;
    }
    int more = offset + shown < i || capped;
    web_jw_raw(w, "],\"frames_total\":");   web_jw_int(w, i);
    web_jw_raw(w, ",\"frames_capped\":");   web_jw_raw(w, capped ? "true" : "false");
    web_jw_raw(w, ",\"truncated_file\":");  web_jw_raw(w, rc < 0 ? "true" : "false");
    web_jw_raw(w, ",\"offset\":");          web_jw_int(w, offset);
    web_jw_raw(w, ",\"shown\":");           web_jw_int(w, shown);
    web_jw_raw(w, ",\"more\":");            web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"next_offset\":");
    if (more && offset + shown < i) web_jw_int(w, offset + shown); else web_jw_raw(w, "null");
    return 0;
}
