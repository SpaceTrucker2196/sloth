#ifndef BGP_SNOOP_H
#define BGP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* BGP snoop. v1: detect BGP messages by their RFC 4271 §4.1
 * common header (16 bytes of 0xFF marker + 2-byte length + 1-byte
 * type) and count the four message types per peer-pair. Aggregate
 * feeds the BGP_NOTIFICATION_BURST alert.
 *
 * payload is the TCP payload (no TCP header). server_port is 179
 * — both endpoints of a peering session can be on 179
 * simultaneously (a router accepts inbound on 179 AND sources
 * outbound from 179 if so configured), so we don't infer a
 * "client" side. Sessions are keyed by the SORTED pair of peer
 * IPs so messages in either direction map to the same entry.
 *
 * Returns 1 if at least one BGP message was identified and
 * recorded; 0 otherwise. TCP segments may carry multiple BGP
 * messages back-to-back — the parser walks the payload until it
 * runs out. */
int  bgp_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len);

void bgp_snoop_snapshot(sloth_state_t *s);
void bgp_snoop_clear   (void);

#endif /* BGP_SNOOP_H */
