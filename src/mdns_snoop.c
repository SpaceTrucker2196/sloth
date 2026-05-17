#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

#include "mdns_snoop.h"
#include "dns.h"

/* ── Internal state ──────────────────────────────────────── */

static mdns_service_t  g_svcs[MAX_MDNS_SERVICES];
static int             g_svc_count = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ─────────────────────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* Identical to dns_snoop's read_name — handles compression pointers. */
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
        int copy = (int)c < bufsz - out - 1 ? (int)c : bufsz - out - 1;
        if (copy > 0) { memcpy(buf + out, msg + off, (size_t)copy); out += copy; }
        buf[out] = '\0';
        off += c;
    }
    return jumped ? resume : off;
}

/* Extract _proto._transport from a name such as "Dev._http._tcp.local".
   Walks to the first label that begins with '_', copies it and the next
   label into buf.  Sets buf="" on failure. */
static void extract_service(const char *name, char *buf, int sz) {
    buf[0] = '\0';
    const char *p = name;
    while (p && *p) {
        if (*p == '_') {
            const char *dot1 = strchr(p, '.');
            if (!dot1) break;
            const char *dot2 = strchr(dot1 + 1, '.');
            int len = dot2 ? (int)(dot2 - p) : (int)strlen(p);
            if (len >= sz) len = sz - 1;
            memcpy(buf, p, (size_t)len);
            buf[len] = '\0';
            return;
        }
        p = strchr(p, '.');
        if (p) p++;
    }
}

static mdns_service_t *find_or_create(const char *instance) {
    for (int i = 0; i < g_svc_count; i++)
        if (strcmp(g_svcs[i].instance, instance) == 0)
            return &g_svcs[i];
    if (g_svc_count >= MAX_MDNS_SERVICES) return NULL;
    mdns_service_t *e = &g_svcs[g_svc_count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->instance, instance, sizeof(e->instance) - 1);
    return e;
}

/* Walk count RRs at msg[*off]; updates *off.  Returns services touched. */
static int process_rrs(const uint8_t *msg, int len, int *off, int count) {
    int updated = 0;
    for (int i = 0; i < count; i++) {
        char rname[256];
        int noff = read_name(msg, len, *off, rname, sizeof(rname));
        if (noff < 0 || noff + 10 > len) return updated;

        uint16_t type  = u16be(msg + noff);
        /* CLASS field: strip cache-flush bit (0x8000) per RFC 6762 §11 */
        uint16_t rdlen = u16be(msg + noff + 8);
        int      rdata = noff + 10;
        if (rdata + (int)rdlen > len) return updated;

        time_t now = time(NULL);

        if (type == 12) {
            /* PTR: rname=service_type, rdata=instance_name */
            char instance[256];
            if (read_name(msg, len, rdata, instance, sizeof(instance)) >= 0) {
                mdns_service_t *e = find_or_create(instance);
                if (e) {
                    if (!e->service[0])
                        extract_service(rname, e->service, sizeof(e->service));
                    e->last_seen = now;
                    updated++;
                }
            }
        } else if (type == 33 && rdlen >= 7) {
            /* SRV: rname=instance_name, rdata=priority(2)+weight(2)+port(2)+target */
            char host[256];
            if (read_name(msg, len, rdata + 6, host, sizeof(host)) >= 0) {
                mdns_service_t *e = find_or_create(rname);
                if (e) {
                    e->port = u16be(msg + rdata + 4);
                    snprintf(e->host, sizeof(e->host), "%.63s", host);
                    if (!e->service[0])
                        extract_service(rname, e->service, sizeof(e->service));
                    e->last_seen = now;
                    updated++;
                }
            }
        } else if (type == 1 && rdlen == 4) {
            /* A record: inject hostname→IP into DNS cache */
            struct in_addr a;
            memcpy(&a, msg + rdata, 4);
            char ip[46];
            inet_ntop(AF_INET, &a, ip, sizeof(ip));
            dns_set_resolved(ip, rname);
            /* fill ip in any service whose host matches this name */
            for (int j = 0; j < g_svc_count; j++) {
                if (strcmp(g_svcs[j].host, rname) == 0) {
                    snprintf(g_svcs[j].ip, sizeof(g_svcs[j].ip), "%s", ip);
                    g_svcs[j].last_seen = now;
                    updated++;
                }
            }
        } else if (type == 28 && rdlen == 16) {
            /* AAAA record */
            struct in6_addr a6;
            memcpy(&a6, msg + rdata, 16);
            char ip[46];
            inet_ntop(AF_INET6, &a6, ip, sizeof(ip));
            dns_set_resolved(ip, rname);
            for (int j = 0; j < g_svc_count; j++) {
                if (strcmp(g_svcs[j].host, rname) == 0 && !g_svcs[j].ip[0]) {
                    snprintf(g_svcs[j].ip, sizeof(g_svcs[j].ip), "%s", ip);
                    g_svcs[j].last_seen = now;
                    updated++;
                }
            }
        }

        *off = rdata + rdlen;
    }
    return updated;
}

/* ── Public API ──────────────────────────────────────────── */

int mdns_snoop(const uint8_t *msg, int len) {
    if (len < 12) return 0;

    int qdcount = (int)u16be(msg + 4);
    int ancount = (int)u16be(msg + 6);
    int nscount = (int)u16be(msg + 8);
    int arcount = (int)u16be(msg + 10);

    if (qdcount > 32 || ancount > 64 || nscount > 64 || arcount > 64) return 0;

    /* skip question section */
    int off = 12;
    for (int q = 0; q < qdcount; q++) {
        char tmp[256];
        int noff = read_name(msg, len, off, tmp, sizeof(tmp));
        if (noff < 0 || noff + 4 > len) return 0;
        off = noff + 4;
    }

    pthread_mutex_lock(&g_mu);
    int updated = 0;
    updated += process_rrs(msg, len, &off, ancount);
    updated += process_rrs(msg, len, &off, nscount);
    updated += process_rrs(msg, len, &off, arcount);
    pthread_mutex_unlock(&g_mu);

    return updated;
}

void mdns_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_svc_count < MAX_MDNS_SERVICES ? g_svc_count : MAX_MDNS_SERVICES;
    memcpy(s->mdns_services, g_svcs, (size_t)n * sizeof(mdns_service_t));
    s->mdns_count = n;
    pthread_mutex_unlock(&g_mu);
}

void mdns_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_svcs, 0, sizeof(g_svcs));
    g_svc_count = 0;
    pthread_mutex_unlock(&g_mu);
}
