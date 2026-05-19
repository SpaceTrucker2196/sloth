#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sloth.h"
#include "dns_log.h"
#include "jsonl.h"
#include "host_cache.h"

static dns_log_entry_t g_log[MAX_DNS_LOG];
static int             g_head  = 0;
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── DNS parser helpers ──────────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* Decode DNS-encoded name from msg into buf.  Returns offset after name,
   or -1 on error.  Handles compression pointers (RFC 1035 §4.1.4). */
static int read_name(const uint8_t *msg, int msglen, int off,
                     char *buf, int bufsz) {
    int out = 0, jumped = 0, resume = -1, hops = 0;
    buf[0] = '\0';
    for (;;) {
        if (off < 0 || off >= msglen) return -1;
        uint8_t c = msg[off];
        if ((c & 0xC0) == 0xC0) {
            if (off + 1 >= msglen) return -1;
            if (!jumped) resume = off + 2;
            off = ((c & 0x3F) << 8) | msg[off + 1];
            jumped = 1;
            if (++hops > 20) return -1;
            continue;
        }
        if (c & 0x80) return -1;
        off++;
        if (c == 0) break;
        if (off + (int)c > msglen) return -1;
        if (out > 0 && out < bufsz - 1) buf[out++] = '.';
        int copy = (int)c;
        if (out + copy >= bufsz) copy = bufsz - out - 1;
        if (copy > 0) { memcpy(buf + out, msg + off, (size_t)copy); out += copy; }
        buf[out] = '\0';
        off += c;
    }
    return jumped ? resume : off;
}

static const char *qtype_str(uint16_t t) {
    switch (t) {
    case  1: return "A";
    case  2: return "NS";
    case  5: return "CNAME";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    default: return "?";
    }
}

/* ── Public parse API ────────────────────────────────────── */

int dns_log_parse(const uint8_t *msg, int len,
                  const char *src_ip,
                  dns_log_entry_t *out)
{
    if (len < 12) return 0;

    uint16_t flags   = u16be(msg + 2);
    int      is_resp = (flags >> 15) & 1;
    int      rcode   = flags & 0x0f;
    int      qdcount = (int)u16be(msg + 4);
    int      ancount = (int)u16be(msg + 6);

    if (qdcount == 0 || qdcount > 32) return 0;
    if (ancount > 64) return 0;

    char qname[DNS_NAME_LEN];
    int  noff = read_name(msg, len, 12, qname, sizeof(qname));
    if (noff < 0 || noff + 4 > len) return 0;
    uint16_t qtype = u16be(msg + noff);

    memset(out, 0, sizeof(*out));
    if (src_ip) snprintf(out->src, sizeof(out->src), "%s", src_ip);
    snprintf(out->qname, sizeof(out->qname), "%s", qname);
    snprintf(out->qtype, sizeof(out->qtype), "%s", qtype_str(qtype));
    out->is_resp = is_resp;
    out->ts      = time(NULL);

    if (!is_resp) return 1;

    if (rcode == 3) {
        strncpy(out->answer, "NXDOMAIN", sizeof(out->answer) - 1);
        return 1;
    }
    if (ancount == 0) return 1;

    /* skip remaining questions */
    int off = noff + 4;
    for (int q = 1; q < qdcount; q++) {
        char tmp[DNS_NAME_LEN];
        int n = read_name(msg, len, off, tmp, sizeof(tmp));
        if (n < 0 || n + 4 > len) return 1;
        off = n + 4;
    }

    /* walk answer RRs for first A / AAAA */
    for (int i = 0; i < ancount; i++) {
        char rname[DNS_NAME_LEN];
        int n = read_name(msg, len, off, rname, sizeof(rname));
        if (n < 0 || n + 10 > len) break;
        uint16_t rtype  = u16be(msg + n);
        uint16_t rdlen  = u16be(msg + n + 8);
        int      rdata  = n + 10;
        if (rdata + (int)rdlen > len) break;

        if (rtype == 1 && rdlen == 4) {
            struct in_addr a;
            memcpy(&a, msg + rdata, 4);
            inet_ntop(AF_INET, &a, out->answer, sizeof(out->answer));
            break;
        } else if (rtype == 28 && rdlen == 16) {
            struct in6_addr a6;
            memcpy(&a6, msg + rdata, 16);
            inet_ntop(AF_INET6, &a6, out->answer, sizeof(out->answer));
            break;
        }
        off = rdata + rdlen;
    }
    return 1;
}

/* ── Ring buffer ─────────────────────────────────────────── */

void dns_log_record(const dns_log_entry_t *e)
{
    pthread_mutex_lock(&g_mu);
    g_log[g_head] = *e;
    g_head = (g_head + 1) % MAX_DNS_LOG;
    if (g_count < MAX_DNS_LOG) g_count++;
    pthread_mutex_unlock(&g_mu);
    jsonl_emit_dns(e);
    /* Feed the IP->host cache so downstream views can show qnames
     * next to bare IPs (e.g. the packets dst column). host_cache_add
     * silently drops NXDOMAIN / empty answers. */
    host_cache_add(e->answer, e->qname);
}

void dns_log_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_DNS_LOG ? g_count : MAX_DNS_LOG;
    for (int i = 0; i < n; i++) {
        int idx = ((g_head - 1 - i) % MAX_DNS_LOG + MAX_DNS_LOG) % MAX_DNS_LOG;
        s->dns_log[i] = g_log[idx];
    }
    s->dns_log_count = n;
    s->dns_log_head  = g_head;
    if (s->dns_log_sel >= n) s->dns_log_sel = n > 0 ? n - 1 : 0;
    pthread_mutex_unlock(&g_mu);
}

void dns_log_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head  = 0;
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
