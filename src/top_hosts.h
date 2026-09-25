#ifndef TOP_HOSTS_H
#define TOP_HOSTS_H

#include "sloth.h"

/* Walk s->conns and s->conn_bw, aggregate per-remote-IP activity into
 * an internal table that survives across polls (so first_seen and the
 * resolved hostname/owner stick), then snapshot the top MAX_TOP_HOSTS
 * by combined RX+TX rate into s->top_hosts.
 *
 * Hostname follows the operator's names/numeric toggle (#84 slice 2):
 * with names on it goes through dns_resolve() (non-blocking — async
 * resolver, and itself strict-by-default), with names off through the
 * passive dns_lookup_cached(), which reads only what sloth already
 * observed. Owner comes from ip_owner_lookup_str() (embedded prefix
 * table). Private, loopback, link-local and multicast addresses are
 * ignored. */
void top_hosts_update(sloth_state_t *s);

/* Drop the internal table — useful for tests. */
void top_hosts_clear(void);

#endif /* TOP_HOSTS_H */
