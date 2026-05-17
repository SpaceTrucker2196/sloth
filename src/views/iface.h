#ifndef VIEWS_IFACE_H
#define VIEWS_IFACE_H
#include "sloth.h"
void view_iface_draw(const sloth_state_t *s);
void view_iface_key(sloth_state_t *s, int key);
#endif
