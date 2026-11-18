/* slothweb's Bluetooth SIG assigned numbers: the company behind a
 * Manufacturer Specific Data block, the service a 16-bit UUID names and
 * the device class an Appearance value states, for the BLE view.
 *
 * The table is generated at build time by web/tools/btsig_gen.c from
 * the three CSVs committed in web/data/btsig/ (web/data/btsig/SOURCE.md
 * says where they come from and their hashes; web/tools/update_btsig.sh
 * refreshes them from a given directory and never fetches). The
 * generated build/web/web_btsig_table.c is build output, never
 * committed. A build with no CSV (WEB_BTSIG_DIR elsewhere) still
 * succeeds with an empty table whose source is "none", and the page
 * then shows the numbers alone, as the TUI does.
 *
 * Each table is sorted by value, so a lookup is one binary search. A
 * name is cut to WEB_BTSIG_NAME_MAX bytes on a code-point boundary and
 * holds printable UTF-8 only (the generator replaces anything else with
 * '?'), so it can be written to the page with web_jw_str() as any
 * registry name is. */
#ifndef SLOTHWEB_BTSIG_H
#define SLOTHWEB_BTSIG_H

#include <stddef.h>
#include <stdint.h>

#define WEB_BTSIG_NAME_MAX 63

typedef struct {
    uint16_t value;
    uint32_t name;     /* index into names */
} web_btsig_ent_t;

typedef struct {
    const web_btsig_ent_t *company;
    size_t                 ncompany;
    const web_btsig_ent_t *service;
    size_t                 nservice;
    const web_btsig_ent_t *appearance;
    size_t                 nappearance;
    const char *const     *names;
    size_t                 nnames;
    const char            *source;   /* "sig" or "none" */
} web_btsig_tab_t;

/* The table this binary was built with (build/web/web_btsig_table.c). */
const web_btsig_tab_t *web_btsig_builtin(void);

/* The name for a value in one of the three tables, or NULL when the
 * table has none (or the value is out of 0..65535). */
const char *web_btsig_company(const web_btsig_tab_t *t, long long id);
const char *web_btsig_service(const web_btsig_tab_t *t, long long uuid16);
const char *web_btsig_appearance(const web_btsig_tab_t *t, long long value);

#endif
