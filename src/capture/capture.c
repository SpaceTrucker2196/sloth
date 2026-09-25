#include <string.h>
#include <stdint.h>
#include "capture/capture.h"
#include "captive_portal.h"
#include "dns.h"
#include "dot11_data.h"
#include "radiotap.h"

/* DLT_LINUX_SLL  (113) — Linux cooked capture v1 used by "any"
 * DLT_LINUX_SLL2 (276) — Linux cooked capture v2, carries the ingress
 * interface index as sll2_if_index (offset 4). Selectable via
 * pcap_set_datalink() after activate on libpcap ≥ 1.10; default for
 * "any" on ≥ 1.11. Enables per-iface data-stream filtering (#17).
 *
 * Above the WITH_PCAP guard because capture_dlt_has_ifindex() below is
 * compiled into the test build, which links no libpcap. */
#define MY_DLT_LINUX_SLL  113
#define MY_DLT_LINUX_SLL2 276

/* Kept outside the WITH_PCAP guard: it is pure arithmetic on libpcap's
   documented return contract, so the test build (which links no libpcap)
   can still assert it. See capture.h for the contract and issue #46. */
int capture_activate_failed(int rc) {
    return rc < 0;
}

/* Also outside the guard, and for the same reason. See capture.h. */
int capture_dlt_has_ifindex(int dlt) {
    return dlt == MY_DLT_LINUX_SLL2;
}

/* Outside the guard again so the test build can pin it (#84 slice 2).
   Rationale and the defect it removes are in capture.h. */
const char *capture_quic_hostname(const char *remote_ip) {
    return dns_lookup_cached(remote_ip);
}

/* ── Fail-closed capture scope (#85) ───────────────────────────
 * Outside the guard for the same reason again: the test build drives
 * these with hand-built SLL2 headers and a seeded resolver. Contract in
 * capture.h. */
#define SLL2_HDRLEN 20

#define IFINDEX_CACHE_MAX 16
typedef struct { uint32_t idx; char name[16]; } ifname_cache_t;
static ifname_cache_t g_ifname_cache[IFINDEX_CACHE_MAX];
static int            g_ifname_cache_n;
static int            g_ifname_cache_next;   /* round-robin victim */

void capture_ifname_cache_reset(void) {
    g_ifname_cache_n    = 0;
    g_ifname_cache_next = 0;
}

const char *capture_ifname_lookup(uint32_t idx, capture_ifname_fn resolve) {
    for (int i = 0; i < g_ifname_cache_n; i++)
        if (g_ifname_cache[i].idx == idx) return g_ifname_cache[i].name;
    char name[16];
    memset(name, 0, sizeof(name));
    /* A miss is not an answer: an index that failed to resolve now is
     * asked again next packet, and never lands in the cache. The old
     * cache stored "" and every later frame on that index bypassed the
     * allow-list. */
    if (!resolve || !resolve(idx, name)) return NULL;
    name[sizeof(name) - 1] = '\0';
    if (!name[0]) return NULL;
    ifname_cache_t *e;
    if (g_ifname_cache_n < IFINDEX_CACHE_MAX) {
        e = &g_ifname_cache[g_ifname_cache_n++];
    } else {
        e = &g_ifname_cache[g_ifname_cache_next];
        g_ifname_cache_next = (g_ifname_cache_next + 1) % IFINDEX_CACHE_MAX;
    }
    e->idx = idx;
    memcpy(e->name, name, sizeof(e->name));
    return e->name;
}

int capture_frame_in_scope(const sloth_state_t *s, int dlt,
                           const uint8_t *frame, int caplen,
                           capture_ifname_fn resolve) {
    if (!s) return 0;
    int restricted = s->iface_allowed_count > 0;
    if (!capture_dlt_has_ifindex(dlt) || !frame || caplen < SLL2_HDRLEN)
        return !restricted;
    /* Nothing filters: skip the lookup so the hot path stays syscall-free. */
    if (!restricted && s->iface_deselected_count == 0) return 1;
    uint32_t ifi = ((uint32_t)frame[4] << 24) | ((uint32_t)frame[5] << 16)
                 | ((uint32_t)frame[6] <<  8) |  (uint32_t)frame[7];
    const char *name = capture_ifname_lookup(ifi, resolve);
    if (!name) return !restricted;
    return !iface_is_deselected(s, name) && iface_is_allowed(s, name);
}

capture_scope_t capture_scope_verdict(int iface_args, int monitor_only,
                                      const char *monitor_iface,
                                      int allowed_count, int capture_open,
                                      int linktype) {
    if (iface_args <= 0 && !monitor_only) return CAPTURE_SCOPE_NONE;
    if (monitor_only && (!monitor_iface || !monitor_iface[0]))
        return CAPTURE_SCOPE_REFUSE_NO_MONITOR;
    /* An empty list reads as "unrestricted" everywhere downstream. */
    if (allowed_count <= 0)          return CAPTURE_SCOPE_REFUSE_EMPTY;
    if (!capture_open)               return CAPTURE_SCOPE_NO_CAPTURE;
    if (!capture_dlt_has_ifindex(linktype))
        return CAPTURE_SCOPE_REFUSE_DATALINK;
    return CAPTURE_SCOPE_ENFORCED;
}

int capture_scope_refuses(capture_scope_t v) {
    return v == CAPTURE_SCOPE_REFUSE_NO_MONITOR
        || v == CAPTURE_SCOPE_REFUSE_EMPTY
        || v == CAPTURE_SCOPE_REFUSE_DATALINK;
}

/* ── Capture-worker exit classification (#91 slice 2) ──────────
 * Contract and rationale in capture.h. Kept above the WITH_PCAP guard
 * for the same reason capture_activate_failed() is: it is pure logic
 * over libpcap's documented return contract, so the test build can pin
 * it without linking libpcap or touching a radio. */

/* pcap_dispatch()'s error codes, written out rather than #included:
 * the test build has no <pcap.h>, and these have been stable since
 * libpcap 1.0. */
#define CAP_PCAP_ERROR               (-1)
#define CAP_PCAP_ERROR_BREAK         (-2)
#define CAP_PCAP_ERROR_NOT_ACTIVATED (-3)

/* Case-insensitive substring search. strcasestr() is a GNU extension and
 * this file is C99 with no gating, so it is spelled out. */
static int err_has(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return 0;
    for (const char *h = hay; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
            if (ca != cb) break;
            a++; b++;
        }
        if (!*b) return 1;
    }
    return 0;
}

capture_exit_t capture_classify_exit(int dispatch_rc, int stop_requested,
                                     const char *err) {
    /* A requested stop wins over everything else: pcap_breakloop() makes
     * the pending dispatch fail, so reporting an error here would flag a
     * fault on every clean shutdown. */
    if (stop_requested)                       return CAPTURE_EXIT_STOPPED;
    if (dispatch_rc >= 0)                     return CAPTURE_EXIT_NONE;
    /* breakloop() is only ever called from the stop paths, which clear
     * the run flag first; a -2 without the flag is a lost race on it,
     * not a fault. */
    if (dispatch_rc == CAP_PCAP_ERROR_BREAK)  return CAPTURE_EXIT_STOPPED;
    if (dispatch_rc == CAP_PCAP_ERROR_NOT_ACTIVATED)
        return CAPTURE_EXIT_NOT_ACTIVATED;
    if (dispatch_rc != CAP_PCAP_ERROR)        return CAPTURE_EXIT_ERROR;

    /* PCAP_ERROR only: the code cannot separate a revoked capability
     * from a vanished adapter, and those need different responses. The
     * text is libpcap's wording, not a kernel contract, so an unmatched
     * message degrades to ERROR rather than being guessed at — the raw
     * string travels alongside in exit_detail either way. */
    if (err_has(err, "no such device")     ||
        err_has(err, "device is not up")   ||
        err_has(err, "went down")          ||
        err_has(err, "disappeared")        ||
        err_has(err, "network is down")    ||
        err_has(err, "not found"))
        return CAPTURE_EXIT_IFACE_GONE;
    if (err_has(err, "permission denied")  ||
        err_has(err, "not permitted"))
        return CAPTURE_EXIT_PERM_LOST;
    return CAPTURE_EXIT_ERROR;
}

const char *capture_exit_name(capture_exit_t r) {
    switch (r) {
    case CAPTURE_EXIT_NONE:          return "none";
    case CAPTURE_EXIT_STOPPED:       return "stopped";
    case CAPTURE_EXIT_IFACE_GONE:    return "iface_gone";
    case CAPTURE_EXIT_PERM_LOST:     return "perm_lost";
    case CAPTURE_EXIT_NOT_ACTIVATED: return "not_activated";
    case CAPTURE_EXIT_ERROR:         break;
    }
    return "error";
}

void capture_stats_accumulate(capture_health_t *h,
                              uint32_t recv, uint32_t drop, uint32_t ifdrop) {
    if (!h) return;
    uint32_t d_recv, d_drop, d_ifdrop;
    if (!h->stats_valid) {
        /* libpcap's counters start at zero with the handle, so the first
         * sample IS the total so far. Discarding it as a baseline would
         * lose every drop before the first poll — the startup window
         * where an undersized buffer drops hardest. */
        d_recv = recv; d_drop = drop; d_ifdrop = ifdrop;
        h->stats_valid = 1;
    } else {
        /* A sample below the previous one is a counter reset, not a wrap:
         * on Linux libpcap accumulates these in user space per handle, so
         * a decrease means it restarted. Taking the new value keeps the
         * exported lifetime monotonic either way. */
        d_recv   = recv   >= h->last_recv   ? recv   - h->last_recv   : recv;
        d_drop   = drop   >= h->last_drop   ? drop   - h->last_drop   : drop;
        d_ifdrop = ifdrop >= h->last_ifdrop ? ifdrop - h->last_ifdrop : ifdrop;
    }
    h->last_recv   = recv;
    h->last_drop   = drop;
    h->last_ifdrop = ifdrop;
    h->d_recv      = d_recv;
    h->d_drop      = d_drop;
    h->d_ifdrop    = d_ifdrop;
    h->ps_recv    += d_recv;
    h->ps_drop    += d_drop;
    h->ps_ifdrop  += d_ifdrop;
}

const char *capture_scope_reason(capture_scope_t v) {
    switch (v) {
    case CAPTURE_SCOPE_REFUSE_NO_MONITOR:
        return "--monitor-only requested but no monitor-mode interface was "
               "found; refusing to capture an unrestricted stream";
    case CAPTURE_SCOPE_REFUSE_EMPTY:
        return "--iface requested but no usable interface name was given; "
               "refusing to capture an unrestricted stream";
    case CAPTURE_SCOPE_REFUSE_DATALINK:
        return "--iface/--monitor-only requested but the capture datalink "
               "carries no ingress interface (needs SLL2/276); refusing to "
               "capture an unrestricted stream";
    case CAPTURE_SCOPE_NO_CAPTURE:
        return "--iface/--monitor-only requested but packet capture is "
               "disabled; no data stream is collected";
    case CAPTURE_SCOPE_NONE:
    case CAPTURE_SCOPE_ENFORCED:
        break;
    }
    return "";
}

#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>       /* if_indextoname — issue #17 SLL2 lookup */

#include "sloth.h"
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
#include "ftp_snoop.h"
#include "pop3_snoop.h"
#include "imap_snoop.h"
#include "smtp_snoop.h"
#include "cleartext_creds.h"
#include "http_log.h"
#include "tls_log.h"

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

    /* Responses first (#71): a response and a request cannot be
     * confused — one starts "HTTP/1.x", the other a method — and trying
     * the request parser on a response wastes the pass. */
    if (http_log_parse_response(tp + tcp_hdr, pay_len, pkt->src, &entry)) {
        snprintf(entry.dst, sizeof(entry.dst), "%s", pkt->dst);
        entry.src_port = pkt->src_port;
        entry.dst_port = pkt->dst_port;
        http_log_pair_response(&entry);
        /* A connectivity-check probe answered by something other than
         * the real endpoint (#69). Only fires on a complete body — see
         * cp_check_response. */
        int cp = cp_check_response(&entry);
        if (cp) {
            char ev[80];
            snprintf(ev, sizeof(ev), "HTTP %u, %d body bytes",
                     entry.status, entry.resp_body_len);
            cp_record((uint8_t)cp, entry.host, pkt->dst, ev, time(NULL));
        }
        snprintf(pkt->info, sizeof(pkt->info), "HTTP %u %.40s",
                 entry.status, entry.host[0] ? entry.host : "");
        http_log_record(&entry);
        return;
    }

    if (!http_log_parse(tp + tcp_hdr, pay_len, pkt->src, &entry)) return;
    snprintf(entry.dst, sizeof(entry.dst), "%s", pkt->dst);
    entry.src_port = pkt->src_port;
    entry.dst_port = pkt->dst_port;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    snprintf(pkt->info, sizeof(pkt->info), "HTTP %.54s", entry.host[0] ? entry.host : "?");
    http_log_record(&entry);
    /* Same payload pass: look for Authorization: Basic and record any
     * cleartext credential exposure. Username only — see #16 phase 3. */
    http_snoop_scan_creds(tp + tcp_hdr, pay_len,
                          pkt->src, pkt->dst, pkt->dst_port);
}

/* FTP command-channel observer on TCP/21. Records USER<->PASS
 * exposures via the cleartext_creds ring. #16 phase 3. */
static void try_ftp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 5) return;
    if (ftp_snoop(tp + tcp_hdr, pay_len,
                  pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "FTP");
}

/* POP3 on TCP/110 — same shape as FTP (USER/PASS lines). */
static void try_pop3(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 5) return;
    if (pop3_snoop(tp + tcp_hdr, pay_len,
                   pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "POP3");
}

/* IMAP on TCP/143 — tagged LOGIN with optional quoting. */
static void try_imap(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 8) return;
    if (imap_snoop(tp + tcp_hdr, pay_len,
                   pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "IMAP");
}

/* SMTP on TCP/25/587 — AUTH PLAIN in one shot. */
static void try_smtp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 5) return;
    if (smtp_snoop(tp + tcp_hdr, pay_len,
                   pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "SMTP");
}

static void try_sni(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    int tcp_hdr = (tp[12] >> 4) * 4;
    if (tcp_hdr < 20 || tcp_hdr > tlen) return;
    int pay_len = tlen - tcp_hdr;
    if (pay_len < 9) return;
    tls_log_entry_t entry;
    if (!tls_log_parse(tp + tcp_hdr, pay_len, pkt->src, pkt->dst, &entry)) return;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    /* A sentinel host reached over TLS at a private address is a portal
     * terminating the connection (#69). Independent of the body check —
     * a rogue that chunks its HTTP answer still has to do this. */
    {
        int cp = cp_check_tls(entry.host, pkt->dst);
        if (cp) cp_record((uint8_t)cp, entry.host, pkt->src, pkt->dst,
                          time(NULL));
    }
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
        if (pkt->dst_port == 21 || pkt->src_port == 21)
            try_ftp(tp, tlen, pkt);
        if (pkt->dst_port == 110 || pkt->src_port == 110)
            try_pop3(tp, tlen, pkt);
        if (pkt->dst_port == 143 || pkt->src_port == 143)
            try_imap(tp, tlen, pkt);
        if (pkt->dst_port == 25 || pkt->src_port == 25 ||
            pkt->dst_port == 587 || pkt->src_port == 587)
            try_smtp(tp, tlen, pkt);
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
            if (dns_log_parse(tp + 8, tlen - 8, pkt->src, &dqe)) {
                dns_log_record(&dqe);
                /* A connectivity-check host resolving into private or
                 * CGNAT space is a portal answering for it (#69). */
                int cp = cp_check_dns(dqe.qname, dqe.answer);
                if (cp) cp_record((uint8_t)cp, dqe.qname, pkt->dst,
                                  dqe.answer, time(NULL));
            }
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
            const char *host   = capture_quic_hostname(remote);
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
        if (pkt->dst_port == 21 || pkt->src_port == 21)
            try_ftp(tp, tlen, pkt);
        if (pkt->dst_port == 110 || pkt->src_port == 110)
            try_pop3(tp, tlen, pkt);
        if (pkt->dst_port == 143 || pkt->src_port == 143)
            try_imap(tp, tlen, pkt);
        if (pkt->dst_port == 25 || pkt->src_port == 25 ||
            pkt->dst_port == 587 || pkt->src_port == 587)
            try_smtp(tp, tlen, pkt);
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
            if (dns_log_parse(tp + 8, tlen - 8, pkt->src, &dqe)) {
                dns_log_record(&dqe);
                /* A connectivity-check host resolving into private or
                 * CGNAT space is a portal answering for it (#69). */
                int cp = cp_check_dns(dqe.qname, dqe.answer);
                if (cp) cp_record((uint8_t)cp, dqe.qname, pkt->dst,
                                  dqe.answer, time(NULL));
            }
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
            const char *host   = capture_quic_hostname(remote);
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

/* SLL2 header layout (per pcap-linktype(7)):
 *   0  protocol   (2)  big-endian ethertype
 *   2  reserved   (2)
 *   4  ifindex    (4)  big-endian
 *   8  hatype     (2)
 *   10 pkttype    (1)
 *   11 halen      (1)
 *   12 addr       (8)
 *   20 payload
 * Payload starts at offset 20; ethertype lives at offset 0.
 * SLL2_HDRLEN is defined above the WITH_PCAP guard (#85). */

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
    } else if (dlt == MY_DLT_LINUX_SLL2) {
        if (caplen < SLL2_HDRLEN) return 0;
        ethertype = u16be(data + 0);
        offset    = SLL2_HDRLEN;
    } else if (dlt == DLT_IEEE802_11_RADIO) {
        /* The monitor radio (#72). Until this existed the two capture
         * paths saw disjoint worlds — 802.11 metadata on one side, IP
         * on the other — with no bridge even on an open network where
         * the payload is in the clear.
         *
         * Radiotap first, then the variable 802.11 header, then
         * LLC/SNAP. The arithmetic lives in dot11_data.c because that
         * is where the risk is and this file is not in TEST_SRCS. */
        radiotap_info_t rti;
        if (!radiotap_parse(data, caplen, &rti)) return 0;
        int rt = rti.hdr_len;
        if (rt <= 0 || rt >= caplen) return 0;
        const uint8_t *dot11 = data + rt;
        int dlen = caplen - rt;
        int poff = 0;
        if (dot11_data_payload(dot11, dlen, &poff, &ethertype)
            != DOT11_DATA_OK) return 0;
        offset = rt + poff;
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

/* if_indextoname() adapter for capture_ifname_lookup(), whose cache
 * keeps the hot path free of per-packet syscalls (#17, #85). */
static int sys_ifname(uint32_t idx, char name[16]) {
    return if_indextoname(idx, name) != NULL;
}

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *data) {
    (void)user;
    int dlt = pcap_datalink(g_handle);

    /* Data-stream election (#17 + #35), fail-closed since #85: drop
     * before decode when the runtime deselect ([y]) or the launch-time
     * allow-list (--iface / --monitor-only) rejects the ingress iface,
     * and — whenever an allow-list is active — when the frame cannot be
     * attributed to an allowed iface at all. The allow-list was complete
     * before this thread was created and is never written again. */
    if (!capture_frame_in_scope(g_state, dlt, data, (int)hdr->caplen,
                                sys_ifname))
        return;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ts_sec  = (uint32_t)hdr->ts.tv_sec;
    pkt.ts_usec = (uint32_t)hdr->ts.tv_usec;
    pkt.len     = hdr->len;
    if (!decode_frame(data, (int)hdr->caplen, dlt, &pkt))
        return;  /* drop ARP / LLC / unknown — see decode_frame() comment */

    int rl = (int)hdr->caplen < 64 ? (int)hdr->caplen : 64;
    memcpy(pkt.raw, data, (size_t)rl);
    pkt.raw_len = (uint16_t)rl;

    pthread_mutex_lock(&g_mu);
    g_state->packets[g_state->pkt_head] = pkt;
    g_state->pkt_head = (g_state->pkt_head + 1) % MAX_PACKETS;
    if (g_state->pkt_count < MAX_PACKETS) g_state->pkt_count++;
    g_state->pkt_total++;   /* monotonic; drives once-only jsonl emit (issue #20) */
    pthread_mutex_unlock(&g_mu);
}

/* ── Capture thread ───────────────────────────────────────── */

/* Why the worker left its loop, published for the poll loop to read
 * (#91 slice 2). Written once by the dying thread, read once per tick by
 * main(). The pair goes under the module's existing g_mu rather than
 * being bare volatiles: exit_detail is a string, and a torn read would
 * hand the operator a truncated or interleaved error message at exactly
 * the moment they need it. The lock is cold — once at thread death,
 * once per poll. */
static int  g_exit_reason = CAPTURE_EXIT_NONE;
static char g_exit_detail[80];

static void *capture_thread(void *arg) {
    (void)arg;
    int r = 0;
    while (g_running) {
        r = pcap_dispatch(g_handle, 32, on_packet, NULL);
        if (r < 0) break;   /* PCAP_ERROR or PCAP_ERROR_BREAK */
    }
    /* The gap #91 opens with: this used to `return NULL` and leave an
     * open handle with no packets behind it, which reads exactly like a
     * quiet segment. */
    const char *err = (r < 0 && g_handle) ? pcap_geterr(g_handle) : "";
    pthread_mutex_lock(&g_mu);
    snprintf(g_exit_detail, sizeof(g_exit_detail), "%s", err ? err : "");
    g_exit_reason = (int)capture_classify_exit(r, !g_running, g_exit_detail);
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

void capture_health_poll(capture_health_t *h) {
    if (!h) return;
    h->open = g_handle != NULL;
    pthread_mutex_lock(&g_mu);
    h->exit_reason = g_exit_reason;
    snprintf(h->exit_detail, sizeof(h->exit_detail), "%s", g_exit_detail);
    int reason = g_exit_reason;
    pthread_mutex_unlock(&g_mu);
    /* A dead worker leaves g_running set — it broke out of the loop
     * rather than being asked to stop — so liveness is the run flag AND
     * the absence of a terminal reason. That conjunction is the whole
     * point: the handle staying open is what made the failure invisible. */
    h->running = g_running && reason == CAPTURE_EXIT_NONE;
    if (!g_handle) return;
    struct pcap_stat ps;
    memset(&ps, 0, sizeof(ps));
    if (pcap_stats(g_handle, &ps) == 0)
        capture_stats_accumulate(h, (uint32_t)ps.ps_recv, (uint32_t)ps.ps_drop,
                                 (uint32_t)ps.ps_ifdrop);
}

/* ── Public API ───────────────────────────────────────────── */

void capture_open(sloth_state_t *s) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_state  = s;
    /* Reset the ifindex cache — a re-start on the same handle would
     * otherwise carry stale ifindex → name mappings. */
    capture_ifname_cache_reset();

    /* Prefer pcap_create + activate so we can request DLT_LINUX_SLL2
     * (276) as the datalink. SLL2 is what gives the pcap callback
     * access to the ingress interface index, which the data-stream
     * election needs to filter by iface name (#17). Anything short of
     * SLL2 — SLL v1, EN10MB — still captures; the per-iface filter
     * just becomes a no-op on those datalinks. */
    g_handle = pcap_create("any", errbuf);
    if (g_handle) {
        pcap_set_snaplen(g_handle, 65535);
        pcap_set_promisc(g_handle, 1);
        pcap_set_timeout(g_handle, 100);
        if (capture_activate_failed(pcap_activate(g_handle))) {
            pcap_close(g_handle);
            g_handle = NULL;
        } else {
            /* Try to switch to SLL2; ignore errors (older libpcap
             * doesn't know the DLT, some kernels reject it). */
            (void)pcap_set_datalink(g_handle, MY_DLT_LINUX_SLL2);
            snprintf(s->pkt_iface, sizeof(s->pkt_iface), "any");
        }
    }

    if (!g_handle) {
        /* pcap_create("any") failed or activation rejected — try the
         * simpler open_live path, then fall back to first device. */
        g_handle = pcap_open_live("any", 65535, 1, 100, errbuf);
        if (g_handle) {
            snprintf(s->pkt_iface, sizeof(s->pkt_iface), "any");
        } else {
            pcap_if_t *devs = NULL;
            if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
                snprintf(s->pkt_iface, sizeof(s->pkt_iface), "%s", devs->name);
                g_handle = pcap_open_live(devs->name, 65535, 1, 100, errbuf);
                pcap_freealldevs(devs);
            }
        }
    }
    if (!g_handle) return;  /* silently disabled — show live hint in view */

    s->pkt_linktype = pcap_datalink(g_handle);
}

int capture_is_open(void) {
    return g_handle != NULL;
}

void capture_run(void) {
    if (!g_handle || g_running) return;
    /* pthread_create() synchronises memory with the new thread (POSIX
     * XBD 4.12), so every allow-list write main() made before this call
     * is visible to on_packet() from its first frame. */
    /* A restart clears the previous run's verdict — otherwise a fresh
     * worker would report the reason the last one died (#91 slice 2). */
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = CAPTURE_EXIT_NONE;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    g_running = 1;
    if (pthread_create(&g_thread, NULL, capture_thread, NULL) != 0)
        g_running = 0;
}

void capture_start(sloth_state_t *s) {
    capture_open(s);
    capture_run();
}

void capture_stop(void) {
    if (g_running) {
        g_running = 0;
        if (g_handle) pcap_breakloop(g_handle);
        pthread_join(g_thread, NULL);
    }
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
