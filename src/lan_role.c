/* Router-role observations (#155). Contract in lan_role.h. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "lan_role.h"
#include "sloth_clock.h"
#include "sensor_health.h"
#include "stab.h"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static int role_key_eq(const void *row, const void *key) {
    return strcmp(((const lan_role_t *)row)->ip, (const char *)key) == 0;
}

/* STAB_OLDEST: the key is a source address anyone on the segment can
 * forge, so a spray of fake servers churns the table and is counted. */
STAB_DECL(g_roles, lan_role_t, MAX_LAN_ROLES, last_seen, STAB_OLDEST,
          SH_EVICT_LAN_ROLE, NULL, role_key_eq);

int lan_addr_is_local(const char *ip) {
    unsigned char a[16];
    if (!ip || !ip[0]) return 0;
    if (inet_pton(AF_INET, ip, a) == 1) {
        if (a[0] == 10) return 1;                                /* 1918 */
        if (a[0] == 172 && (a[1] & 0xf0) == 16) return 1;        /* 1918 */
        if (a[0] == 192 && a[1] == 168) return 1;                /* 1918 */
        if (a[0] == 100 && (a[1] & 0xc0) == 64) return 1;        /* 6598 */
        if (a[0] == 169 && a[1] == 254) return 1;                /* 3927 */
        return 0;
    }
    if (inet_pton(AF_INET6, ip, a) == 1) {
        if ((a[0] & 0xfe) == 0xfc) return 1;                     /* 4193 */
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1;     /* 4291 */
        return 0;
    }
    return 0;
}

/* Caller holds g_mu. */
static lan_role_t *role_get(const char *ip, time_t now) {
    int created;
    lan_role_t *r = stab_get(&g_roles, ip, now, &created);
    if (created) {
        snprintf(r->ip, sizeof(r->ip), "%s", ip);
        r->first_seen = now;
    }
    r->last_seen = now;
    return r;
}

void lan_role_note_dhcp(const char *ip, int role) {
    if (!lan_addr_is_local(ip)) return;
    role &= LAN_ROLE_DHCP_REPLY | LAN_ROLE_DHCP_SID;
    if (!role) return;
    time_t now = sloth_wall();
    pthread_mutex_lock(&g_mu);
    lan_role_t *r = role_get(ip, now);
    r->roles    |= role;
    r->dhcp_seen = now;
    pthread_mutex_unlock(&g_mu);
}

int lan_role_dns_observe(const char *src_ip, uint16_t src_port,
                         const char *dst_ip, const uint8_t *msg, int len) {
    /* RFC 1035 §4.1.1: QR is the top bit of octet 2. */
    if (src_port != 53 || !msg || len < 12 || !(msg[2] & 0x80)) return 0;
    if (!lan_addr_is_local(src_ip) || !lan_addr_is_local(dst_ip)) return 0;
    if (strcmp(src_ip, dst_ip) == 0) return 0;
    time_t now = sloth_wall();
    pthread_mutex_lock(&g_mu);
    lan_role_t *r = role_get(src_ip, now);
    r->roles   |= LAN_ROLE_DNS;
    r->dns_seen = now;
    int known = 0;
    int k = r->dns_clients < LAN_ROLE_DNS_CLIENTS ? r->dns_clients
                                                  : LAN_ROLE_DNS_CLIENTS;
    for (int i = 0; i < k && !known; i++)
        known = strcmp(r->dns_client[i], dst_ip) == 0;
    if (!known && r->dns_clients < LAN_ROLE_DNS_CLIENTS) {
        snprintf(r->dns_client[r->dns_clients],
                 sizeof(r->dns_client[0]), "%s", dst_ip);
        r->dns_clients++;
    }
    pthread_mutex_unlock(&g_mu);
    return 1;
}

void lan_role_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    s->lan_role_count = stab_snapshot(&g_roles, s->lan_roles, MAX_LAN_ROLES);
    pthread_mutex_unlock(&g_mu);
}

void lan_role_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_roles);
    pthread_mutex_unlock(&g_mu);
}
