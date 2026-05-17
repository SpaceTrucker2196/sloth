#ifndef SCAN_H
#define SCAN_H

#include "ntop.h"

/* Update scan table from s->conns[]; expires old entries. */
void scan_update(ntop_state_t *s);

/* Returns port_count if ip is currently flagged as a scanner, 0 otherwise. */
int scan_is_flagged(const ntop_state_t *s, const char *ip);

#endif /* SCAN_H */
