#ifndef VIEW_GNSS_H
#define VIEW_GNSS_H

#include "sloth.h"

/* [#] GNSS (2026-11-02): the --gps receiver's sky — one row per
 * satellite in view with its C/N0, elevation, azimuth, used and health
 * flags — above a header of the fix, the DOPs and the receiver's clock
 * offset. Reads s->gnss_sky / s->gnss_fix only (docs/wiki/gnss.md). */
void view_gnss_draw(const sloth_state_t *s);
void view_gnss_key (sloth_state_t *s, int key);

#endif /* VIEW_GNSS_H */
