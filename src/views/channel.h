#ifndef SLOTH_VIEW_CHANNEL_H
#define SLOTH_VIEW_CHANNEL_H

#include "sloth.h"

/* Aggregator — called from main poll path. Walks beacon + assoc
 * tables and populates s->channels[] / s->channel_count. */
void channel_summary_update(sloth_state_t *s);

void view_channel_draw(const sloth_state_t *s);
void view_channel_key (sloth_state_t *s, int key);

#endif /* SLOTH_VIEW_CHANNEL_H */
