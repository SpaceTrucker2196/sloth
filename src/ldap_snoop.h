#ifndef LDAP_SNOOP_H
#define LDAP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* LDAP snoop. v1: detect BindRequest, SearchRequest, and
 * SearchResultReference via RFC 4511 BER framing — outer SEQUENCE
 * (0x30), messageID INTEGER (0x02), then the protocolOp tagged
 * [APPLICATION n] (0x60 = bind, 0x63 = search, 0x73 = searchResRef).
 *
 * payload is the raw TCP payload (no TCP header). server_port is
 * 389 or 3268 — TLS variants 636/3269 are opaque past the handshake
 * and not observed.
 *
 * Returns 1 if the payload was identifiable as LDAP and recorded;
 * 0 otherwise. */
int  ldap_snoop_observe(const char *src_ip, uint16_t src_port,
                        const char *dst_ip, uint16_t dst_port,
                        const uint8_t *payload, int len);

void ldap_snoop_snapshot(sloth_state_t *s);
void ldap_snoop_clear   (void);

#endif /* LDAP_SNOOP_H */
