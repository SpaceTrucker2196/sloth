/* The SQL box's recipes (#163): docs/wiki/sqlite-schema.md's
 * `sqlite3 sloth.db "..."` commands, extracted at build time by
 * web/tools/recipes.c into build/web/web_recipes.c (generated, never
 * committed). The SQL is the page's byte for byte. */
#ifndef SLOTHWEB_RECIPES_H
#define SLOTHWEB_RECIPES_H

#include <stddef.h>

typedef struct {
    const char *title;      /* the # comment lines before it */
    const char *sql;
} web_recipe_t;

extern const web_recipe_t web_recipes[];
extern const size_t       web_recipes_n;
extern const char         web_recipes_source[];

#endif
