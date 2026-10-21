/* The embedded page (#158). Defined in build/web/web_assets.c, which
 * web/tools/embed.c generates from web/ui/ at build time; that file is
 * not committed. web_page is NUL-terminated past web_page_len. */
#ifndef SLOTHWEB_ASSETS_H
#define SLOTHWEB_ASSETS_H

#include <stddef.h>

extern const unsigned char web_page[];
extern const size_t        web_page_len;
extern const char          web_page_etag[];   /* quoted, strong */
extern const char          web_page_csp[];    /* hashes of its two inline blocks */

#endif
