#ifndef SLOTH_VIEW_EAPOL_H
#define SLOTH_VIEW_EAPOL_H

#include "sloth.h"

void view_eapol_draw(const sloth_state_t *s);
void view_eapol_key (sloth_state_t *s, int key);

/* The cluster [g] is showing, 0 for every row; and back to every row
 * (tests). */
uint32_t view_eapol_group(void);
void     view_eapol_group_reset(void);

#endif /* SLOTH_VIEW_EAPOL_H */
