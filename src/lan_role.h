#ifndef LAN_ROLE_H
#define LAN_ROLE_H

#include <stdint.h>
#include "sloth.h"

/* Router-role observations for the camera classifier (#155).
 *
 * A camera does not hand out leases or answer other hosts' DNS; a
 * router does both. Ubiquiti, TP-Link and Wyze blocks carry both kinds
 * of box, so these roles are what lets a mixed-vendor record read
 * NOT_CAMERA instead of staying unclassified. Every row comes from a
 * frame another host sent — sloth asks nothing (MISSION.md §2).
 *
 * What is visible, honestly: a DHCP OFFER/ACK is broadcast whenever the
 * client asks for it (RFC 2131 §4.1, the BROADCAST bit) and otherwise
 * unicast; a DNS answer is always unicast. On a switched port sloth
 * sees the broadcast ones and its own exchanges, on a mirror port or
 * the gateway all of them (docs/wiki/camera-detection.md). */

/* DHCP evidence, from dhcp_snoop(): `role` is LAN_ROLE_DHCP_REPLY (this
 * address sent a BOOTREPLY from UDP 67) or LAN_ROLE_DHCP_SID (named in
 * option 54). Ignored unless `ip` is a LAN address (lan_addr_is_local). */
void lan_role_note_dhcp(const char *ip, int role);

/* A UDP datagram from capture: recorded when it is a DNS response
 * (RFC 1035 §4.1.1: QR set, 12-byte header) sent from port 53 by a LAN
 * address to a different LAN address. Returns 1 when recorded. */
int  lan_role_dns_observe(const char *src_ip, uint16_t src_port,
                          const char *dst_ip, const uint8_t *msg, int len);

/* RFC 1918 / RFC 6598 (CGNAT) / RFC 3927 link-local IPv4, RFC 4193 ULA
 * and RFC 4291 link-local IPv6. Loopback and unspecified are not LAN. */
int  lan_addr_is_local(const char *ip);

void lan_role_snapshot(sloth_state_t *s);
void lan_role_clear(void);

#endif /* LAN_ROLE_H */
