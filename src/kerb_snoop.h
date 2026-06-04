#ifndef KERB_SNOOP_H
#define KERB_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Kerberos snoop. v1: detect message types via the outer ASN.1
 * [APPLICATION] tag byte (AS-REQ = 10/0x6A, AS-REP = 11/0x6B,
 * TGS-REQ = 12/0x6C, TGS-REP = 13/0x6D, KRB-ERROR = 30/0x7E) and
 * extract the KRB-ERROR error-code via a minimal ASN.1 walk. Per-
 * source aggregate counts feed the KERB_PREAUTH_BURST alert.
 *
 * src_ip / dst_ip and the matching ports come from the L4
 * dispatch in capture.c. server_port is 88 (KDC). payload is the
 * raw transport-layer payload — for UDP this is the bare Kerberos
 * message, for TCP it carries the standard 4-byte length prefix
 * which we skip.
 *
 * Returns 1 if the payload was identifiable as Kerberos and
 * recorded; 0 otherwise. */
int  kerb_snoop_observe(const char *src_ip, uint16_t src_port,
                        const char *dst_ip, uint16_t dst_port,
                        const uint8_t *payload, int len);

void kerb_snoop_snapshot(sloth_state_t *s);
void kerb_snoop_clear   (void);

#endif /* KERB_SNOOP_H */
