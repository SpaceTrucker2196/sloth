#ifndef SMB_SNOOP_H
#define SMB_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* SMB observation. v1 (Tier 1) detects the SMB1 vs SMB2/3 magic
 * header and tracks flows by (client_ip, server_ip, server_port).
 * Any observed SMB1 use fires ROGUE_SMB1 via the alerts pipeline —
 * SMBv1 has been deprecated since 2017 (EternalBlue / WannaCry) and
 * is disabled by default on every modern Windows.
 *
 * Deeper SMB observability (NTLM auth extraction, tree-connect to
 * admin shares, NULL session detection) is deliberately out of
 * scope for this pass — see docs/wiki/smb-snoop.md. */

/* Record an observed SMB segment. `src_ip` / `dst_ip` and the
 * matching ports come from the L4 dispatch in capture.c.
 * `payload` is the TCP payload (no TCP header). server_port is
 * inferred as whichever of src_port / dst_port is 445 or 139.
 *
 * Returns 1 if the payload was identifiable as SMB and recorded;
 * 0 otherwise. Safe to call on any TCP payload — the magic check
 * is the gate. */
int  smb_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len);

void smb_snoop_snapshot(sloth_state_t *s);
void smb_snoop_clear   (void);

#endif /* SMB_SNOOP_H */
