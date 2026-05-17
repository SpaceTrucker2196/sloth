#ifndef VIEWS_CONNS_H
#define VIEWS_CONNS_H
#include "sloth.h"

/* Rebuild conn_idx[] from conns[] applying current filter and sort.
   Clamps conn_sel. Call after each poll and after sort/filter key changes. */
void conn_rebuild_idx(sloth_state_t *s);

void view_conns_draw(const sloth_state_t *s);
void view_conns_key(sloth_state_t *s, int key);

#endif /* VIEWS_CONNS_H */
