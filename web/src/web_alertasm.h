/* Each alert type's assessment, for the alert page (owner request
 * 2026-10-27: "full verbose details of the alert, include bibliography,
 * when possible prove the alert with evidence"): extracted at build
 * time by web/tools/alertasm.c into build/web/web_alertasm_table.c
 * (generated, never committed) from docs/wiki/alert-assessments/
 * <TYPE>.md, one document per alert type, written by hand in the wiki.
 *
 * The directory is optional: a type with no document, or a build with
 * no directory, has no entry, and /api/alert says "assessment": null
 * (the page: "no assessment yet"). What a document holds is the wiki's
 * own: its front matter as key/value pairs, kept as written; its "## "
 * sections in order, as words (code spans and [n] marks verbatim); its
 * Bibliography as text entries, never links: the page sends nothing
 * anywhere but its own server. The generator stops the build on a stem
 * that is not an alert type or a [n] with no Bibliography entry, so a
 * shipped assessment always cites what it says it cites. */
#ifndef SLOTHWEB_ALERTASM_H
#define SLOTHWEB_ALERTASM_H

typedef struct {
    const char *heading;
    const char *text;          /* paragraphs separated by a blank line */
} web_asm_sec_t;

typedef struct {
    const char *name;          /* "DEAUTH_FLOOD": the file's stem */
    const char *path;          /* docs/wiki/alert-assessments/<name>.md */
    const char *title;         /* its "# " line, or "" */
    const char *updated;       /* **Last updated** or last_updated:, or "" */
    const char *const *fm_k;   /* the front matter, in order */
    const char *const *fm_v;
    int                nfm;
    const web_asm_sec_t *sec;
    int                  nsec;
    const char *const *bib;    /* the Bibliography's entries, in order */
    int                nbib;
} web_asm_t;

extern const web_asm_t web_asm[];
extern const int       web_asm_n;
extern const int       web_asm_by_type[];
extern const int       web_asm_ntypes;

/* The assessment of a type number, or NULL. */
const web_asm_t *web_asm_get(long long type);
/* A front matter value, or NULL. */
const char *web_asm_fm(const web_asm_t *a, const char *key);

#endif
