/* What slothweb knows about the holder of an OUI beyond the IEEE's
 * name (owner request 2026-10-27: a details view under the drawer's OUI
 * card with researched vendor and product information). One Markdown
 * file per researched vendor under web/data/vendors/, compiled at build
 * time by web/tools/vendorkb.c into build/web/web_vendorkb_table.c
 * (generated, never committed): slothweb fetches nothing at run time,
 * so the research is committed data, like the registry CSVs beside it.
 * docs/wiki/vendor-research.md holds the file format.
 *
 * An OUI names the registrant of a block (a module maker, a brand, a
 * carrier), not a product, so an entry documents the vendor: who they
 * are, what a MAC in their blocks usually is, the silicon documented in
 * their modules and products, the radios, FCC grantee codes, whether
 * their devices randomise, notable advisories, with a confidence word
 * per field and "unknown" where nothing is documented. Every claim
 * carries a [n] into the entry's Sources, and the generator refuses a
 * file whose [n] has no source line or whose required field is
 * missing, naming the file: the build fails rather than ship a guess.
 *
 * Entries are keyed by the IEEE "Organization Name" as the registry
 * spells it, by each alias (the registry's other spellings of the same
 * legal entity: case, punctuation, spacing, a department suffix, or a
 * straight rename such as Facebook Inc to Meta Platforms, Inc.), and by
 * each affiliate: a separate legal entity with its own registration (a
 * subsidiary, branch, parent or predecessor) that a cited source ties
 * to the entry. A registrant found through an affiliate is not the
 * company the entry describes, so the lookup says so and the drawer
 * shows its country, parent and founded as unknown rather than the
 * entry's. The lookup folds spelling: web_vkb_norm() lower-cases
 * ASCII letters, keeps digits and bytes >= 0x80, and turns every run
 * of anything else (spaces, punctuation) into one space, trimmed, so
 * "FLEXTRONICS", "Flextronics" and "Flextronics, Inc." meet and
 * "AMPAK Technology,Inc." finds the file named for
 * "AMPAK Technology, Inc.". The generator and web/tests/test_vendorkb.c
 * share the function (static inline, as web_oui.h does), so the key
 * the table was built with is the key the lookup computes.
 *
 * Text is plain: no link, code or emphasis markup, and the page sets
 * it with textContent; the sources are shown as plain text lines, never
 * as links (test_routes.c: the page holds no href but fragments). */
#ifndef SLOTHWEB_VENDORKB_H
#define SLOTHWEB_VENDORKB_H

#include <stddef.h>

/* web/data/vendors/COVERAGE.md lists which of the reference host's
 * vendors have an entry and which are still pending; it sits beside
 * the entries and is not one (the generator, the tests and
 * tools/docs_counts.sh all pass over it by this name). */
#define WEB_VKB_COVERAGE "COVERAGE.md"

/* A normalised key is cut to this many bytes. */
#define WEB_VKB_KEY_MAX 127

typedef struct {
    const char *title;
    const char *url;
    const char *accessed;      /* YYYY-MM-DD */
} web_vkb_src_t;

typedef struct {
    const char *file;          /* web/data/vendors/<slug>.md */
    const char *name;          /* the IEEE Organization Name, exactly */
    const char *const *aliases;
    int                naliases;
    const char *const *affiliates;  /* "Registry String [n]" */
    int                naffiliates;
    const char *country;       /* "JP [1]" or "unknown" */
    const char *parent;        /* "independent [1]", a company, "unknown" */
    const char *founded;       /* "1944 [1]" or "unknown" */
    const char *kind;          /* brand, module-maker, odm/ems, chip-vendor,
                                  carrier/isp, automotive, network-equipment,
                                  other */
    const char *const *device_classes;
    int                ndevice_classes;
    const char *const *found_in;
    int                nfound_in;
    const char *const *radios;
    int                nradios;
    const char *const *silicon;
    int                nsilicon;
    const char *const *fcc_grantee;
    int                nfcc_grantee;
    const char *randomization;
    const char *const *security_notes;
    int                nsecurity_notes;
    /* documented | inferred | unknown, one per field */
    const char *conf_country, *conf_silicon, *conf_radios, *conf_found_in,
               *conf_randomization;
    const char *researched;    /* YYYY-MM-DD */
    const char *summary;       /* paragraphs, "\n\n" between, [n] kept */
    const web_vkb_src_t *sources;
    int                  nsources;
} web_vkb_t;

typedef struct {
    const char *key;           /* web_vkb_norm() of a name, alias or affiliate */
    int         entry;         /* index into web_vkb */
    int         affiliate;     /* 1: the key is an affiliate's */
} web_vkb_key_t;

/* The generated table: entries in file-name order, keys sorted by
 * strcmp for the binary search. */
extern const web_vkb_t      web_vkb[];
extern const int            web_vkb_n;
extern const web_vkb_key_t  web_vkb_keys[];
extern const int            web_vkb_nkeys;

/* The entry for an IEEE organisation name, spelling folded, or NULL;
 * *affiliate (when not NULL) is set to 1 when the name is one of the
 * entry's affiliates, a different company, and 0 otherwise. */
const web_vkb_t *web_vendorkb_lookup(const char *ieee_name, int *affiliate);
/* web_vendorkb_lookup() without the flag. */
const web_vkb_t *web_vendorkb_find(const char *ieee_name);

/* Normalise s into out (cap bytes, cap >= 1): ASCII letters lower-cased,
 * digits and bytes >= 0x80 kept, every run of anything else one space,
 * no leading or trailing space, cut to cap - 1 bytes. Returns the
 * length written. */
static inline size_t web_vkb_norm(const char *s, char *out, size_t cap) {
    size_t o = 0;
    int pending = 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        int keep = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                   (c >= 'A' && c <= 'Z') || c >= 0x80;
        if (!keep) { pending = o > 0; continue; }
        if (pending && o + 1 < cap) out[o++] = ' ';
        pending = 0;
        if (o + 1 < cap) out[o++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    if (cap) out[o] = '\0';
    return o;
}

#endif
