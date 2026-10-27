/* What slothweb knows about each alert type, for the alert detail page
 * (owner request 2026-10-23..26): extracted at build time by
 * web/tools/alertkb.c into build/web/web_alertkb.c (generated, never
 * committed) from the files sloth already keeps, never copied by hand:
 *
 *   include/sloth_alerts.def      the types, in enum order, and each
 *                                 one's ATT&CK technique
 *   docs/views/alerts.md          the rule table: severity, trigger,
 *                                 what match_ip / port name
 *   docs/wiki/alerts.md           the paragraphs that name the type
 *   research/ (every .md)         the corpus documents whose
 *                                 alert_kinds list the type: citation,
 *                                 source URL, the lead paragraph and the
 *                                 paragraphs that name the type
 *   docs/wiki/alert-remediation.md  how to investigate and fix each one,
 *                                 with the corpus documents it rests on
 *
 * One entry per row of sloth_alerts.def, in its order, so web_akb[t] is
 * the entry for the JSONL `ty` / sloth.db `type` t. Text is plain: the
 * Markdown is reduced to its words (links to their text, emphasis and
 * code marks dropped), except that `what` keeps its code spans whole,
 * backticks included, for the page to set as code (textContent, never
 * markup). web/tests/test_alertkb.c holds the table to the
 * files: every type has a trigger, a source and steps, and every source
 * the remediation names is a corpus document that cites the type. */
#ifndef SLOTHWEB_ALERTKB_H
#define SLOTHWEB_ALERTKB_H

#define WEB_AKB_SUMMARY_MAX 280

typedef struct {
    const char *path;        /* research/... or docs/... */
    const char *citation;    /* the frontmatter's citation, or the path */
    const char *url;         /* source_url, or "" */
    const char *lead;        /* the paragraph under its title */
    const char *excerpt;     /* the paragraphs that name the type, or "" */
} web_akb_src_t;

typedef struct {
    const char *name;        /* "PORT_SCAN": ALERT_TYPE_<name> */
    const char *technique;   /* "T1046", or "" */
    const char *sev;         /* the rule table's Sev cell: "LOW", "LOW/WARN" */
    const char *summary;     /* the Trigger cell's first sentence, its
                                issue references dropped, at most
                                WEB_AKB_SUMMARY_MAX bytes */
    const char *what;        /* the whole Trigger cell, code spans kept */
    const char *match;       /* the rule table's match_ip / port cell */
    const char *context;     /* docs/wiki/alerts.md's paragraphs naming it */
    const web_akb_src_t *src;            /* the corpus documents citing it */
    int                  nsrc;
    const char *const   *investigate;    /* steps, in order */
    int                  ninvestigate;
    const char *const   *fix;
    int                  nfix;
    const char *vendor_fix;  /* the remediation's "Vendor fix" line */
    const char *const   *fix_src;        /* the paths the remediation cites */
    int                  nfix_src;
} web_akb_t;

extern const web_akb_t web_akb[];
extern const int       web_akb_n;
/* The files the table was built from, for /api/alert's "kb_sources". */
extern const char      web_akb_inputs[];

/* The entry for a type number, or NULL. */
const web_akb_t *web_akb_get(long long type);
/* The type number for a name ("PORT_SCAN"), or -1. */
int web_akb_find(const char *name);

#endif
