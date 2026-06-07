#ifndef RDP_SNOOP_H
#define RDP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* RDP X.224 Connection Request snoop — TCP/3389.
 *
 * Parses the TPKT/X.224 envelope (RFC 1006 / X.224) of an RDP
 * client→server connection request and the optional MS-RDPBCGR
 * §2.2.1.1 RDP Negotiation Request. Aggregates per (client_ip,
 * server_ip). Each parsed CR TPDU = one connection that reached
 * the RDP handshake. Returns 1 on observation, 0 otherwise. */
int  rdp_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len);

void rdp_snoop_snapshot(sloth_state_t *s);
void rdp_snoop_clear   (void);

#endif /* RDP_SNOOP_H */
