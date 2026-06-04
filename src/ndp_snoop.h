#ifndef NDP_SNOOP_H
#define NDP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* IPv6 NDP (RFC 4861) snoop. v1: Router Advertisement tracking only.
 *
 * Threat model: a single legitimate default router exists on a normal
 * segment. Multiple RA-emitters with non-zero router lifetime indicates
 * either an attacker (mitm6, Slaacers, IPv6-only attack toolkits) or
 * a serious misconfiguration. This is the IPv6 analogue of rogue DHCP. */

/* Record an observed Router Advertisement.
 *   src_ip   — IPv6 source address of the RA (link-local, typically)
 *   payload  — ICMPv6 message starting at type byte (so payload[0]=134)
 *   len      — total length of the ICMPv6 message (≥ 16)
 *
 * Returns 1 if the message was an RA and was recorded (or updated an
 * existing entry); 0 if it wasn't an RA or was malformed. */
int  ndp_snoop_ra(const char *src_ip, const uint8_t *payload, int len);

/* Copy the current RA tracker state into s. */
void ndp_snoop_snapshot(sloth_state_t *s);

/* Drop all tracked RAs — for tests / `[c]` reset. */
void ndp_snoop_clear(void);

#endif /* NDP_SNOOP_H */
