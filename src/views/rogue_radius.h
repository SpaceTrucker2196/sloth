#ifndef VIEW_ROGUE_RADIUS_H
#define VIEW_ROGUE_RADIUS_H

#include "sloth.h"

void view_rogue_radius_draw(const sloth_state_t *s);
void view_rogue_radius_key (sloth_state_t *s, int key);

/* Decode the eap_types_seen bitmap into a comma-separated method-name
 * list ("MD5,PEAP", unknown types as "T<n>"). Exposed for tests. */
void rogue_radius_fmt_methods(uint32_t types, char *buf, int sz);

#endif /* VIEW_ROGUE_RADIUS_H */
