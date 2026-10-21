#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "dhcp_snoop.h"
#include "lan_role.h"

/* libFuzzer target for the DHCP option walk and the router-role table
 * it feeds (#155).
 *
 * dhcp_snoop() walks options a client or server chose byte by byte, and
 * since #155 also formats option 55 into a code list, copies option 60
 * and hands the packet source and option 54 to lan_role. The same bytes
 * then go to lan_role_dns_observe() as a DNS datagram, the other writer
 * of that table. Every stored string is held to its terminator here, so
 * a missing NUL faults at the read rather than in a later view.
 *
 * The source port follows the first input byte, so both the BOOTREPLY
 * branch (67) and the client side are reached. Table state persists
 * across runs on purpose: the eviction path is reached only once rows
 * exist. Addresses are RFC 1918, which lan_role accepts; RFC 5737 ones
 * would be refused before the table. */
static sloth_state_t g_s;

#define TERMINATED(f) (strnlen((f), sizeof(f)) < sizeof(f))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65507) return 0;      /* largest UDP payload over IPv4 */
    char info[64];
    uint16_t sport = (size && (data[0] & 1)) ? 67 : 68;
    info[0] = '\0';
    dhcp_snoop("192.168.7.1", sport, data, (int)size, info,
               (int)sizeof(info));
    if (!TERMINATED(info)) abort();
    lan_role_dns_observe("192.168.7.53", 53, "192.168.7.20", data,
                         (int)size);

    dhcp_snoop_snapshot(&g_s);
    size_t n = 0;
    for (int i = 0; i < g_s.dhcp_event_count; i++) {
        const dhcp_event_t *e = &g_s.dhcp_events[i];
        if (!TERMINATED(e->mac) || !TERMINATED(e->ip) ||
            !TERMINATED(e->hostname) || !TERMINATED(e->server_ip) ||
            !TERMINATED(e->prl) || !TERMINATED(e->vci))
            abort();
        n += strlen(e->prl) + strlen(e->vci);
    }
    lan_role_snapshot(&g_s);
    for (int i = 0; i < g_s.lan_role_count; i++) {
        const lan_role_t *r = &g_s.lan_roles[i];
        if (!TERMINATED(r->ip)) abort();
        if (r->dns_clients < 0 || r->dns_clients > LAN_ROLE_DNS_CLIENTS)
            abort();
        if (!lan_addr_is_local(r->ip)) abort();
    }
    return (int)(n & 0);
}
