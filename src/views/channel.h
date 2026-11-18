#ifndef SLOTH_VIEW_CHANNEL_H
#define SLOTH_VIEW_CHANNEL_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Aggregator — called from main poll path. Walks beacon + assoc
 * tables and populates s->channels[] / s->channel_count. */
void channel_summary_update(sloth_state_t *s);

/* G3's TUI form (#195): control frames a minute per channel row, the
 * last CHAN_HZ_CELLS minutes, from the deltas of the cumulative
 * ctrl_total ctrl_snapshot() writes. Call after ctrl_snapshot(). A cell
 * before the channel's history began is TG_HZ_UNSEEN. */
#define CHAN_HZ_CELLS  24
#define CHAN_HZ_CELL_S 60
void channel_hz_update(const sloth_state_t *s, time_t now);
/* Oldest first; *max is the channel's largest minute so far (it grows,
 * never shrinks: R11). Returns 0 for a channel with no history. */
int  channel_hz_cells(int channel, uint32_t out[CHAN_HZ_CELLS],
                      uint32_t *max);
void channel_hz_clear(void);

void view_channel_draw(const sloth_state_t *s);
void view_channel_key (sloth_state_t *s, int key);

#endif /* SLOTH_VIEW_CHANNEL_H */
