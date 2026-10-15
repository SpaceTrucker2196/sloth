#include "sloth.h"
#include "sloth_compat.h"

/* The one "[key] Name" table for every view, generated in enum order
 * from include/sloth_views.def (#117). Lives here — not in tui.c — so
 * both the real ncurses/ANSI build and the test binary (which swaps in
 * null_tui.c) share it. The tab bar and the [?] help card both read it
 * through view_label(), so a new view can't appear in one place and be
 * missing from the other. */
static const char *const view_labels[] = {
#define X(id, label, key, slug) [VIEW_##id] = "[" key "] " label,
#include "sloth_views.def"
#undef X
};
SLOTH_STATIC_ASSERT(sizeof(view_labels) / sizeof(*view_labels) == VIEW_COUNT,
                    view_labels_cover_every_view);

/* The keys, from the same rows. A key is a one-character string literal
 * so the label above can be assembled at compile time; the assertion
 * below is what holds a row to one character, since a longer one would
 * still concatenate cleanly into a label nobody can type. */
static const char *const view_keys[] = {
#define X(id, label, key, slug) [VIEW_##id] = key,
#include "sloth_views.def"
#undef X
};
#define X(id, label, key, slug) \
    SLOTH_STATIC_ASSERT(sizeof(key) == 2, view_key_is_one_char_##id);
#include "sloth_views.def"
#undef X

const char *view_label(view_t v) {
    if (v < 0 || v >= VIEW_COUNT) return "?";
    return view_labels[v];
}

int view_for_key(int key) {
    if (key >= 'A' && key <= 'Z') key += 'a' - 'A';
    for (int v = 0; v < VIEW_COUNT; v++)
        if ((unsigned char)view_keys[v][0] == key) return v;
    return -1;
}
