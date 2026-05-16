#ifndef HISTORY_H
#define HISTORY_H

#include "ntop.h"

/* Find or allocate a history slot for the named interface.
   Returns NULL only if all MAX_IFACES slots are taken by other names. */
iface_hist_t *history_find(ntop_state_t *s, const char *name);

/* Push the current poll's rx_rate/tx_rate into each interface's history. */
void history_update(ntop_state_t *s);

#endif /* HISTORY_H */
