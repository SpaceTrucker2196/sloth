#ifndef SLOTH_VIEW_H
#define SLOTH_VIEW_H

/* The view enum and its lookups, generated from sloth_views.def (#117).
 *
 * Split out of sloth.h because nothing here depends on anything else in
 * it. sloth.h re-includes this header, so every existing includer
 * compiles unchanged; a file that needs only view_t can include this
 * one alone. */

typedef enum {
#define X(id, label, key, slug) VIEW_##id,
#include "sloth_views.def"
#undef X
    VIEW_COUNT
} view_t;

/* "[key] Name" label for a view — the tab bar and the [?] help card
 * both read this so their key lists can't drift apart. "?" out of
 * range. */
const char *view_label(view_t v);

/* The view a global key selects, or -1 when the key selects none.
 * Letters match in either case. Pure table lookup: whether the key
 * reaches this point at all (filter editing, the absolute globals, a
 * view's own claim on the key) is src/main.c::handle_key's decision. */
int view_for_key(int key);

#endif /* SLOTH_VIEW_H */
