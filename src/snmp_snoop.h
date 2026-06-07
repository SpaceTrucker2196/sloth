#ifndef SNMP_SNOOP_H
#define SNMP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* SNMPv1 / v2c BER snoop — UDP/161 and UDP/162.
 *
 * Parses the outer SEQUENCE + version INTEGER + community OCTET
 * STRING + PDU tag of an SNMP message per RFC 1157 / RFC 1901.
 * Aggregates per (src_ip, dst_ip), where src_ip is whoever sent
 * the message (community guessers are the request side). Returns
 * 1 on a parseable SNMP message, 0 otherwise. */
int  snmp_snoop_observe(const char *src_ip, uint16_t src_port,
                        const char *dst_ip, uint16_t dst_port,
                        const uint8_t *payload, int len);

void snmp_snoop_snapshot(sloth_state_t *s);
void snmp_snoop_clear   (void);

#endif /* SNMP_SNOOP_H */
