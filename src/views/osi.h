#ifndef VIEWS_OSI_H
#define VIEWS_OSI_H

#include "sloth.h"

/* OSI / TCP-IP stack view — one row per layer, each showing what sloth
 * observes at that layer drawn from the current sloth_state_t. Pure
 * synthesis; no new state fields. */

void view_osi_draw(const sloth_state_t *s);
void view_osi_key(sloth_state_t *s, int key);

#endif /* VIEWS_OSI_H */
