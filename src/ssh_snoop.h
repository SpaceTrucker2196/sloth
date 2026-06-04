#ifndef SSH_SNOOP_H
#define SSH_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* SSH banner snoop — TCP/22.
 *
 * Observes the cleartext "SSH-protoversion-softwareversion\r\n"
 * banner (RFC 4253 §4.2) that both sides emit before the encrypted
 * key exchange. Aggregates per (src_ip, dst_ip), where src_ip is
 * the TCP initiator (the SSH client). Each banner from the server
 * counts as one connection that reached the SSH handshake — the
 * unit we threshold for brute-force detection.
 *
 * Returns 1 on first byte of a banner observed (per-call, not
 * per-connection — see below), 0 if the payload doesn't look
 * like SSH or the port isn't 22. */
int  ssh_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len);

void ssh_snoop_snapshot(sloth_state_t *s);
void ssh_snoop_clear   (void);

#endif /* SSH_SNOOP_H */
