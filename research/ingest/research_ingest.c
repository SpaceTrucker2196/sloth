#include <string.h>
#include <stdio.h>

#include "research_ingest.h"

const char *ri_status_str(ri_status_t s) {
    switch (s) {
    case RI_OK:                  return "";
    case RI_ERR_NO_FRONTMATTER:  return "no frontmatter block";
    case RI_ERR_FRONTMATTER:     return "malformed frontmatter";
    case RI_ERR_MISSING_FIELD:   return "required field missing";
    case RI_ERR_TOO_MANY:        return "too many list entries";
    }
    return "?";
}

/* Copy up to `cap`-1 bytes of the line-slice [b, e) with surrounding
 * whitespace trimmed. */
static void trim_copy(char *dst, size_t cap, const char *b, const char *e) {
    while (b < e && (*b == ' ' || *b == '\t')) b++;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\r')) e--;
    size_t n = (size_t)(e - b);
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, b, n);
    dst[n] = '\0';
}

/* Parse `[a, b, c]` into `out`. Returns RI_ERR_TOO_MANY when the list
 * is longer than the bound — refused rather than truncated, because a
 * silently dropped alert kind is a document that indexes under fewer
 * detectors than it claims to cover, and nothing would ever say so. */
static ri_status_t parse_list(const char *b, const char *e,
                              char out[][RI_STR], int cap, int *count) {
    *count = 0;
    while (b < e && (*b == ' ' || *b == '\t')) b++;
    if (b >= e || *b != '[') return RI_ERR_FRONTMATTER;
    b++;
    /* Find the closing bracket; anything after it is ignored. */
    const char *close = b;
    while (close < e && *close != ']') close++;
    if (close >= e) return RI_ERR_FRONTMATTER;

    const char *item = b;
    while (item <= close) {
        const char *comma = item;
        while (comma < close && *comma != ',') comma++;
        /* An empty list `[]` is legal and yields nothing. */
        if (!(item == b && comma == close && item == comma)) {
            char buf[RI_STR];
            trim_copy(buf, sizeof(buf), item, comma);
            if (buf[0]) {
                if (*count >= cap) return RI_ERR_TOO_MANY;
                snprintf(out[*count], RI_STR, "%s", buf);
                (*count)++;
            }
        }
        if (comma >= close) break;
        item = comma + 1;
    }
    return RI_OK;
}

static ri_status_t parse_frontmatter(const char *b, const char *e,
                                     ri_frontmatter_t *fm) {
    const char *p = b;
    while (p < e) {
        const char *eol = p;
        while (eol < e && *eol != '\n') eol++;

        /* Blank lines and comments are permitted inside the block. */
        const char *scan = p;
        while (scan < eol && (*scan == ' ' || *scan == '\t')) scan++;
        if (scan == eol || *scan == '#') { p = eol + 1; continue; }

        const char *colon = scan;
        while (colon < eol && *colon != ':') colon++;
        /* A line inside the block with no colon is malformed. Accepting
         * it would let a typo'd key vanish silently, which for
         * `alert_kinds` means a document that never surfaces. */
        if (colon >= eol) return RI_ERR_FRONTMATTER;

        char key[RI_STR];
        trim_copy(key, sizeof(key), scan, colon);
        const char *vb = colon + 1;

        if (!strcmp(key, "source_url"))
            trim_copy(fm->source_url, sizeof(fm->source_url), vb, eol);
        else if (!strcmp(key, "retrieved"))
            trim_copy(fm->retrieved, sizeof(fm->retrieved), vb, eol);
        else if (!strcmp(key, "citation"))
            trim_copy(fm->citation, sizeof(fm->citation), vb, eol);
        else if (!strcmp(key, "topics")) {
            ri_status_t st = parse_list(vb, eol, fm->topics,
                                        RI_MAX_TOPICS, &fm->topic_count);
            if (st != RI_OK) return st;
        } else if (!strcmp(key, "alert_kinds")) {
            ri_status_t st = parse_list(vb, eol, fm->alert_kinds,
                                        RI_MAX_ALERT_KINDS,
                                        &fm->alert_kind_count);
            if (st != RI_OK) return st;
        }
        /* Unknown keys are ignored rather than rejected: the corpus
         * should tolerate a document carrying extra metadata a later
         * slice adds meaning to. */

        p = eol + 1;
    }

    /* source_url and retrieved are the two that make a row citable at
     * all — without them a hit says "something backs this" and cannot
     * say what or when. citation and the lists are optional. */
    if (!fm->source_url[0] || !fm->retrieved[0]) return RI_ERR_MISSING_FIELD;
    return RI_OK;
}

/* Append to the current section's body, stopping at the bound rather
 * than overflowing. */
static void body_append(ri_section_t *sec, const char *b, const char *e) {
    size_t have = strlen(sec->body);
    size_t room = RI_BODY - 1 - have;
    if (room == 0) return;
    size_t n = (size_t)(e - b);
    if (n > room) n = room;
    memcpy(sec->body + have, b, n);
    sec->body[have + n] = '\0';
}

ri_status_t ri_parse(const char *text, ri_doc_t *out) {
    if (!out) return RI_ERR_FRONTMATTER;
    memset(out, 0, sizeof(*out));
    if (!text) return RI_ERR_NO_FRONTMATTER;

    /* The document must open with the fence. A file without one is not
     * a corpus document — most likely a README that wandered into the
     * tree — and indexing it would produce hits with no provenance. */
    if (strncmp(text, "---", 3) != 0) return RI_ERR_NO_FRONTMATTER;
    const char *p = text + 3;
    while (*p == '\r') p++;
    if (*p != '\n') return RI_ERR_NO_FRONTMATTER;
    p++;

    /* Closing fence: a line that is exactly ---. */
    const char *fm_start = p;
    const char *fm_end = NULL;
    const char *body = NULL;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n') eol++;
        const char *t = p;
        const char *te = eol;
        while (te > t && (te[-1] == ' ' || te[-1] == '\r')) te--;
        if (te - t == 3 && !strncmp(t, "---", 3)) {
            fm_end = p;
            body = *eol ? eol + 1 : eol;
            break;
        }
        if (!*eol) break;
        p = eol + 1;
    }
    if (!fm_end) return RI_ERR_FRONTMATTER;

    ri_status_t st = parse_frontmatter(fm_start, fm_end, &out->fm);
    if (st != RI_OK) return st;

    /* Sections. Everything before the first `## ` belongs to the H1. */
    ri_section_t *cur = &out->sections[0];
    out->section_count = 1;
    snprintf(cur->title, sizeof(cur->title), "%s", "(preamble)");

    const char *q = body;
    while (q && *q) {
        const char *eol = q;
        while (*eol && *eol != '\n') eol++;

        int is_h1 = (q[0] == '#' && q[1] == ' ');
        int is_h2 = (q[0] == '#' && q[1] == '#' && q[2] == ' ');

        if (is_h1 && out->section_count == 1 && !cur->body[0]) {
            /* The document title names the preamble section rather than
             * opening a new one — a hit in the intro should cite the
             * document, not a section called "(preamble)". */
            trim_copy(cur->title, sizeof(cur->title), q + 2, eol);
        } else if (is_h2) {
            if (out->section_count >= RI_MAX_SECTIONS) {
                out->sections_truncated = 1;
                break;
            }
            cur = &out->sections[out->section_count++];
            trim_copy(cur->title, sizeof(cur->title), q + 3, eol);
        } else {
            body_append(cur, q, *eol ? eol + 1 : eol);
        }

        if (!*eol) break;
        q = eol + 1;
    }

    /* A section that captured nothing but its heading still counts —
     * the title itself is indexed text and may be the only thing that
     * matches a query. */
    return RI_OK;
}
