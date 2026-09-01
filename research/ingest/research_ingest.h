#ifndef RESEARCH_INGEST_H
#define RESEARCH_INGEST_H

#include <stddef.h>

/* Research-corpus document parsing — issue #73, slice 1.
 *
 * Every detector in this tree names its basis (see agents/AGENTS.md
 * § Discipline). Those citations live as prose in issue bodies, wiki
 * pages and rule-table rows, which means an operator looking at a CRIT
 * cannot ask "what backs this" without a browser and the git log.
 *
 * The corpus is one curated markdown document per source, under
 * research/<class>/<slug>.md, with YAML-subset frontmatter naming what
 * it covers. This header is the *parser* — pure, no filesystem, no
 * SQLite — so it can be tested directly. The binary that walks the tree
 * and writes the FTS5 index is main.c beside it.
 *
 * ── Frontmatter ──
 *
 *   ---
 *   source_url: https://www.kb.cert.org/vuls/id/871675
 *   retrieved: 2026-08-31
 *   topics: [wpa3, dragonblood, pmf]
 *   alert_kinds: [ALERT_TYPE_WPA_DOWNGRADE]
 *   citation: CERT/CC VU#871675
 *   ---
 *
 * A YAML *subset* deliberately: scalars and single-line bracketed
 * lists, nothing else. A full YAML parser is a large dependency and a
 * large attack surface for a file format we control on both ends, and
 * the failure mode of a permissive parser here is a document that
 * silently indexes under the wrong alert kind. */

#define RI_MAX_TOPICS       12
#define RI_MAX_ALERT_KINDS   8
#define RI_MAX_SECTIONS     32
#define RI_STR              128
#define RI_BODY            4096

typedef enum {
    RI_OK = 0,
    RI_ERR_NO_FRONTMATTER,   /* file does not open with --- */
    RI_ERR_FRONTMATTER,      /* malformed key/value or unterminated */
    RI_ERR_MISSING_FIELD,    /* a required key was absent */
    RI_ERR_TOO_MANY,         /* more list entries than the bound holds */
} ri_status_t;

typedef struct {
    char source_url[RI_STR];
    char retrieved[16];              /* YYYY-MM-DD */
    char citation[RI_STR];
    char topics[RI_MAX_TOPICS][RI_STR];
    int  topic_count;
    char alert_kinds[RI_MAX_ALERT_KINDS][RI_STR];
    int  alert_kind_count;
} ri_frontmatter_t;

typedef struct {
    char title[RI_STR];              /* the heading text, or the H1 */
    char body[RI_BODY];
} ri_section_t;

typedef struct {
    ri_frontmatter_t fm;
    ri_section_t     sections[RI_MAX_SECTIONS];
    int              section_count;
    int              sections_truncated;
} ri_doc_t;

/* Parse a whole document. `text` is NUL-terminated markdown.
 *
 * Splits the body on `## ` headings, one section per heading, with
 * anything before the first heading attributed to the document's `# `
 * title. Sections rather than whole files because a BM25 hit on a
 * 400-line advisory should point at the paragraph that matched, not at
 * the file.
 *
 * `out` is zeroed on entry, so a failed parse leaves no stale fields
 * rather than a half-populated struct. */
ri_status_t ri_parse(const char *text, ri_doc_t *out);

/* Human label for a status; "" for RI_OK. */
const char *ri_status_str(ri_status_t s);

#endif /* RESEARCH_INGEST_H */
