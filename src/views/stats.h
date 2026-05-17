#ifndef VIEWS_STATS_H
#define VIEWS_STATS_H

#include "sloth.h"

void stats_take_baseline(sloth_state_t *s);
void view_stats_draw(const sloth_state_t *s);
void view_stats_key(sloth_state_t *s, int key);

#endif /* VIEWS_STATS_H */
