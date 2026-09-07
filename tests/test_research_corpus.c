#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"

/*
 * The corpus guard — issue #73, slice 1.
 *
 * Two directions, and only one of them can be enforced today.
 *
 * **Enforced: no document cites an alert kind that does not exist.**
 * Frontmatter names alert kinds as strings, so a renamed or deleted
 * ALERT_TYPE_* leaves documents pointing at nothing and the runtime
 * query silently returns zero hits. This catches that immediately, and
 * it passes now.
 *
 * **Enforced since the content pass: every alert kind that *can* be
 * cited is.** Warning-only through slices 1-3, on the grounds that a
 * red suite until the corpus was finished would make the guard
 * something to work around rather than satisfy. The corpus is finished,
 * so it fails now.
 *
 * "Can be cited" is doing work. alert_technique() returns "" for a rule
 * reporting sloth's own operational state rather than an adversary —
 * ALERT_TYPE_NO_MONITOR_MODE is the case that exists — and there is no
 * CVE, advisory or clause to cite for one. Those are excluded rather
 * than counted as gaps: a target that cannot be met stops being read.
 *
 * ── The tokenizer trap, again ──
 *
 * This file's coverage query used `alert_kinds MATCH <kind>` from slice
 * 1 until the content pass. That is wrong, for the reason documented on
 * rq_for_alert: FTS5's unicode61 tokenizer splits on underscores and a
 * bare term sequence is a *phrase*, so MATCH 'ALERT_TYPE_EVIL_TWIN'
 * is satisfied by a document naming only ALERT_TYPE_EVIL_TWIN_PROXIMITY
 * — the shorter kind's tokens are a consecutive prefix of the longer
 * one's.
 *
 * The guard therefore over-reported coverage for three slices. It
 * happened to reach the same number as an exact query today, because
 * every kind that is a token-prefix of another is also independently
 * cited, but that is luck and not correctness. Now delimiter-wrapped
 * LIKE, the same comparison research/query.c makes, with a test that
 * fails if it ever goes back.
 */

/* Every ALERT_TYPE_* the build knows about, via the table every alert
 * type is already required to appear in. alert_technique() returns ""
 * for host-posture alerts, which is a real answer, so presence rather
 * than content is what is checked. */
static int alert_kind_exists(const char *name) {
    /* The enum has no reflection in C, so the check is the inverse:
     * a name is valid if it appears in the header the enum lives in.
     * Reading the header at test time is deliberate — it is the same
     * source of truth the frontmatter is claiming to reference. */
    FILE *f = fopen("include/sloth.h", "r");
    if (!f) return -1;                     /* cannot tell */
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        const char *p = strstr(line, name);
        if (!p) continue;
        /* Must be a whole token: the next char cannot continue an
         * identifier, or ALERT_TYPE_ROGUE_RA would match
         * ALERT_TYPE_ROGUE_RADIUS. */
        char next = p[strlen(name)];
        if (next == '_' || (next >= 'A' && next <= 'Z') ||
            (next >= '0' && next <= '9')) continue;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

static sqlite3 *open_corpus(void) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2("research.db", &db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    return db;
}

static void test_corpus_is_present_and_readable(void) {
    /* Committed, so it is here from a fresh clone with no build step —
     * which is the property that makes --with-research work without
     * one. If this fails, `make research-index` was not run. */
    sqlite3 *db = open_corpus();
    ASSERT(db != NULL);
    if (!db) return;
    sqlite3_stmt *st = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM research", -1,
                                 &st, NULL), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    ASSERT(sqlite3_column_int(st, 0) > 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
}

static void test_no_document_cites_a_nonexistent_alert_kind(void) {
    /* The enforceable direction. A renamed alert leaves its documents
     * pointing at nothing, and the runtime query returns zero hits with
     * no indication why. */
    sqlite3 *db = open_corpus();
    ASSERT(db != NULL);
    if (!db) return;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db,
        "SELECT DISTINCT alert_kinds, path FROM research "
        "WHERE alert_kinds <> ''", -1, &st, NULL);
    int checked = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *kinds = (const char *)sqlite3_column_text(st, 0);
        const char *path  = (const char *)sqlite3_column_text(st, 1);
        if (!kinds) continue;
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", kinds);
        for (char *tok = strtok(buf, " "); tok; tok = strtok(NULL, " ")) {
            int ok = alert_kind_exists(tok);
            if (ok < 0) continue;          /* header unreadable; skip */
            if (!ok)
                printf("    corpus: %s cites unknown %s\n",
                       path ? path : "?", tok);
            ASSERT(ok == 1);
            checked++;
        }
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    /* The check is worthless if it examined nothing. */
    ASSERT(checked > 0);
}

static void test_every_row_carries_provenance(void) {
    /* A hit that cannot say where it came from or when is not a
     * citation. The parser enforces this per document; this asserts it
     * survived into every row. */
    sqlite3 *db = open_corpus();
    ASSERT(db != NULL);
    if (!db) return;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM research "
        "WHERE source_url IS NULL OR source_url = '' "
        "   OR retrieved  IS NULL OR retrieved  = ''", -1, &st, NULL);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    ASSERT_EQ(sqlite3_column_int(st, 0), 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
}

/* Exact whole-token containment, not FTS5 MATCH. See the tokenizer note
 * at the top of this file. Identical comparison to rq_for_alert's. */
static int corpus_cites(sqlite3 *db, const char *kind) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM research"
            " WHERE (' ' || alert_kinds || ' ') LIKE ('% ' || ?1 || ' %')",
            -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    int hits = (sqlite3_step(st) == SQLITE_ROW) ? sqlite3_column_int(st, 0) : 0;
    sqlite3_finalize(st);
    return hits;
}

static void test_coverage_query_is_exact_not_fts_match(void) {
    /* The regression this guard shipped with for three slices. A
     * document naming only ALERT_TYPE_EVIL_TWIN_PROXIMITY must not
     * satisfy coverage for ALERT_TYPE_EVIL_TWIN — under MATCH it does,
     * because the shorter kind's tokens are a consecutive prefix of the
     * longer one's and a bare term sequence is a phrase query.
     *
     * Built as its own one-row corpus so the assertion holds whatever
     * the shipped corpus happens to contain. */
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { sqlite3_close(db); return; }
    char *err = NULL;
    int ok = sqlite3_exec(db,
        "CREATE VIRTUAL TABLE research USING fts5(title, body,"
        " source_url UNINDEXED, retrieved UNINDEXED, topics, alert_kinds,"
        " path UNINDEXED, tokenize = 'porter unicode61');"
        "INSERT INTO research VALUES('d','b','u','2026-01-01','t',"
        "'ALERT_TYPE_EVIL_TWIN_PROXIMITY','p');",
        NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    ASSERT(ok);
    if (!ok) { sqlite3_close(db); return; }

    ASSERT_EQ(corpus_cites(db, "ALERT_TYPE_EVIL_TWIN"), 0);
    ASSERT_EQ(corpus_cites(db, "ALERT_TYPE_EVIL_TWIN_PROXIMITY"), 1);

    /* And the shape MATCH gets wrong, asserted directly so the comment
     * above is not the only record of why this function exists. */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM research"
                           " WHERE alert_kinds MATCH 'ALERT_TYPE_EVIL_TWIN'",
                       -1, &st, NULL);
    int fts = (sqlite3_step(st) == SQLITE_ROW) ? sqlite3_column_int(st, 0) : -1;
    sqlite3_finalize(st);
    ASSERT_EQ(fts, 1);          /* MATCH says yes; it is wrong */
    sqlite3_close(db);
}

static void test_every_citable_alert_kind_is_cited(void) {
    /* Enforced since the content pass. A new detector arrives uncited
     * and turns the suite red until someone writes down what it detects
     * *from* — which is the rule agents/AGENTS.md states and this is the
     * mechanism that holds it.
     *
     * Iterates the enum rather than parsing include/sloth.h, so a kind
     * cannot escape the guard by being formatted unusually. Both
     * alert_type_name() and alert_technique() are already asserted total
     * over the enum elsewhere. */
    sqlite3 *db = open_corpus();
    ASSERT(db != NULL);
    if (!db) return;

    int total = 0, citable = 0, cited = 0, no_basis = 0;
    char missing[512];
    int  moff = 0;
    missing[0] = '\0';

    for (int t = 0; t < (int)ALERT_TYPE_COUNT; t++) {
        const char *kind = alert_type_name((alert_type_t)t);
        ASSERT(kind && kind[0]);
        if (!kind || !kind[0]) continue;
        total++;

        const char *tech = alert_technique((alert_type_t)t);
        if (!tech || !tech[0]) { no_basis++; continue; }
        citable++;

        if (corpus_cites(db, kind) > 0) { cited++; continue; }
        if (moff < (int)sizeof(missing) - 40)
            moff += snprintf(missing + moff, sizeof(missing) - (size_t)moff,
                             "%s%s", moff ? ", " : "", kind);
    }
    sqlite3_close(db);

    printf("    corpus coverage: %d/%d citable alert kinds cited"
           " (%d have no external basis)\n", cited, citable, no_basis);
    if (cited != citable)
        printf("    UNCITED: %s\n", missing);

    ASSERT(total > 0);
    ASSERT(citable > 0);
    /* The guard. A detector with no cited basis is incomplete, the same
     * way an untested one is — agents/AGENTS.md § Discipline. */
    ASSERT_EQ(cited, citable);
}

void run_research_corpus_tests(void) {
    TEST_SUITE("research corpus guard (#73)");
    RUN_TEST(test_corpus_is_present_and_readable);
    RUN_TEST(test_no_document_cites_a_nonexistent_alert_kind);
    RUN_TEST(test_every_row_carries_provenance);
    RUN_TEST(test_coverage_query_is_exact_not_fts_match);
    RUN_TEST(test_every_citable_alert_kind_is_cited);
}
