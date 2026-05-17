#ifndef SSDP_SNOOP_H
#define SSDP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse an SSDP datagram (UDP/1900 payload).
   Extracts NOTIFY (ssdp:alive / ssdp:byebye) and M-SEARCH messages;
   updates the internal device table keyed by USN.
   Fills info/infosz with a human-readable description.
   Returns 1 if the payload was a recognised SSDP message, 0 otherwise. */
int  ssdp_snoop(const char *src_ip, const uint8_t *data, int len,
                char *info, int infosz);

/* Copy the current device table into state under lock. */
void ssdp_snapshot(sloth_state_t *s);

/* Clear the device table. */
void ssdp_clear(void);

#endif /* SSDP_SNOOP_H */
