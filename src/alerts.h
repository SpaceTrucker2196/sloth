#ifndef ALERTS_H
#define ALERTS_H

#include "sloth.h"

/* Walk the current state for trigger conditions, dedupe against any
 * previously-fired alerts, and copy the resulting set into s->alerts.
 * Safe to call once per poll. */
void alerts_update(sloth_state_t *s);

/* Drop all known alerts (clears engine state, not just the snapshot). */
void alerts_clear(void);

#endif /* ALERTS_H */
