#ifndef VIEWS_STATS_H
#define VIEWS_STATS_H

#include "ntop.h"

void stats_take_baseline(ntop_state_t *s);
void view_stats_draw(const ntop_state_t *s);
void view_stats_key(ntop_state_t *s, int key);

#endif /* VIEWS_STATS_H */
