/* The OUI table builder (#162, M4), build time only: what
 * web/tools/oui_gen.c runs, and what the tests run on a CSV they write
 * themselves. It never reaches the network: the developer fetches the
 * IEEE registry CSVs by hand into web/data/ (see web/README.md).
 *
 * Input, the IEEE registry CSV (RFC 4180: comma-separated, a field may
 * be double-quoted, "" is a quote inside one, a quoted field may hold a
 * comma or a line break):
 *
 *   Registry,Assignment,Organization Name,Organization Address
 *   MA-L,000393,"Apple, Inc.",1 Infinite Loop Cupertino CA US 95014
 *
 * Registry MA-L takes a 6-digit assignment, MA-M 7, MA-S and IAB 9;
 * anything else (CID, which is locally administered by definition) is
 * skipped and counted. A row whose assignment does not have its
 * registry's length in hex is an error, as is a field past 4 KiB, a
 * file past 64 MiB or more than 262,144 rows: a malformed registry
 * fails the build rather than quietly building a smaller table. A name
 * is trimmed, any byte that is not printable ASCII or well-formed UTF-8
 * becomes '?', and it is cut to WEB_OUI_NAME_MAX bytes on a code-point
 * boundary. The same (class, prefix) twice keeps the first.
 *
 * The fallback reads sloth's own table out of src/oui.c as text: every
 * "{ 0xHHHHHH, "Name" }" initialiser line. */
#ifndef SLOTHWEB_OUI_CSV_H
#define SLOTHWEB_OUI_CSV_H

#include <stddef.h>
#include <stdio.h>

#include "web_oui.h"

#define OUI_CSV_MAX_BYTES  (64u << 20)
#define OUI_CSV_MAX_ROWS   262144
#define OUI_CSV_FIELD_MAX  4096

typedef struct {
    web_oui_ent_t *e;
    size_t         n, cap;
    char         **names;
    size_t         nnames, names_cap;
    unsigned       counts[WEB_OUI_CLASSES];
    unsigned long  skipped;      /* rows of another registry (CID) */
    unsigned long  duplicates;   /* (class, prefix) seen before */
    char           err[256];
    web_oui_tab_t  tab;          /* a view of the above, after finish */
} oui_build_t;

void oui_build_init(oui_build_t *b);
void oui_build_free(oui_build_t *b);

/* Add one registry CSV. 0, or -1 with b->err set. */
int  oui_build_csv(oui_build_t *b, const char *path);
/* Add sloth's src/oui.c table. 0 (n entries added), or -1. */
int  oui_build_sloth(oui_build_t *b, const char *path);
/* Sort, drop duplicates and fill b->tab with source. 0, or -1. */
int  oui_build_finish(oui_build_t *b, const char *source);

/* Write b->tab as C defining `const web_oui_tab_t web_oui_generated`.
 * 0, or -1. */
int  oui_build_emit(const oui_build_t *b, FILE *out);

#endif
