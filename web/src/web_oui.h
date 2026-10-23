/* slothweb vendor lookup (#162, M4): docs/web-ui-spec.md §9.2 as the
 * 2026-10-21 OUI ruling amends it.
 *
 * The table is generated at build time by web/tools/oui_gen.c from the
 * IEEE registry CSVs the developer has fetched into web/data/ (oui.csv
 * is MA-L, mam.csv MA-M, oui36.csv MA-S, iab.csv the old IAB blocks).
 * Neither a CSV nor the generated build/web/web_oui_table.c is ever
 * committed. A build with no CSV still succeeds: the generator then
 * reads sloth's own 123-entry table out of src/oui.c as text (no src/
 * file is compiled into slothweb) and says so, and with neither it
 * builds an empty table. web_oui_full() is what A4 and the Lookup card
 * ask: only a table built from the IEEE MA-L registry can say a vendor
 * is unknown.
 *
 * An entry is one assignment: a 24-bit (MA-L), 28-bit (MA-M) or 36-bit
 * (MA-S, IAB) prefix. The key packs the prefix, padded to 36 bits, with
 * its class in the low two bits; the table is sorted by key, so each
 * class is an exact binary search, and a lookup tries the most specific
 * class first (MA-M and MA-S blocks sit inside MA-L assignments the
 * IEEE registered to itself). */
#ifndef SLOTHWEB_OUI_H
#define SLOTHWEB_OUI_H

#include <stddef.h>
#include <stdint.h>

enum { WEB_OUI_MAL = 0, WEB_OUI_MAM, WEB_OUI_MAS, WEB_OUI_CLASSES };

/* A name is cut to this many bytes, on a code-point boundary. */
#define WEB_OUI_NAME_MAX 63

typedef struct {
    uint64_t key;     /* prefix36 << 2 | class */
    uint32_t name;    /* index into names */
} web_oui_ent_t;

typedef struct {
    const web_oui_ent_t *e;
    size_t               n;
    const char *const   *names;
    size_t               nnames;
    const char          *source;   /* "ieee", "sloth" or "none" */
    unsigned             counts[WEB_OUI_CLASSES];
} web_oui_tab_t;

typedef struct {
    int      found;
    int      cls;                   /* WEB_OUI_*, or -1 */
    int      bits;                  /* 24, 28 or 36; 0 when not found */
    char     block[16];             /* "00:03:93", "70:b3:d5:1" ... */
    char     name[WEB_OUI_NAME_MAX + 1];
    int      private_;              /* the IEEE lists it as "Private" */
    int      local;                 /* locally administered bit */
    int      multicast;             /* group bit */
} web_oui_hit_t;

/* The table this binary was built with (build/web/web_oui_table.c). */
const web_oui_tab_t *web_oui_builtin(void);

/* 1 when t was built from the IEEE MA-L registry: only then is a miss
 * "vendor unknown" rather than "not in a small table". */
int  web_oui_full(const web_oui_tab_t *t);

/* Look mac up, most specific class first. The local and multicast bits
 * are always reported; a miss leaves found 0. 1 found, 0 not. */
int  web_oui_lookup(const web_oui_tab_t *t, const uint8_t mac[6],
                    web_oui_hit_t *out);

/* A canonical MAC (web_key_mac's form) to bytes. 0, or -1. */
int  web_oui_mac_bytes(const char *mac, uint8_t out[6]);

/* The bits a class assigns, and the key of a prefix of that class
 * (prefix holds the assignment's own 24, 28 or 36 bits). static inline
 * so that the generator, which links no web/src/ file, shares them. */
static inline int web_oui_class_bits(int cls) {
    return cls == WEB_OUI_MAL ? 24 : cls == WEB_OUI_MAM ? 28 : 36;
}

static inline uint64_t web_oui_key(uint64_t prefix, int cls) {
    return ((prefix << (36 - web_oui_class_bits(cls))) << 2) | (uint64_t)cls;
}

#endif
