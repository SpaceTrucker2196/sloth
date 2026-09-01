#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "runner.h"
#include "sloth.h"

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
 * **Warning-only: every alert kind has at least one document.** That is
 * the direction the issue ultimately wants, and it needs the week-2
 * content pass first — 46 alert kinds, 11 cited at slice 1. Failing on
 * it today would mean a red suite until the corpus is finished, which
 * makes the guard something to be worked around rather than satisfied.
 * Same shape as #68's empty signature table: ship the mechanism, be
 * honest that the data is not there yet, and flip it in the commit that
 * closes the gap.
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

static void test_alert_kind_coverage_reported(void) {
    /* Warning-only, deliberately. See the note at the top of this file.
     * It prints what is missing so the gap is visible in every run
     * rather than discovered when someone goes looking. */
    sqlite3 *db = open_corpus();
    ASSERT(db != NULL);
    if (!db) return;

    FILE *f = fopen("include/sloth.h", "r");
    ASSERT(f != NULL);
    if (!f) { sqlite3_close(db); return; }

    char line[512];
    int total = 0, cited = 0;
    while (fgets(line, sizeof(line), f)) {
        char name[128];
        if (sscanf(line, " ALERT_TYPE_%127[A-Z0-9_],", name) != 1) continue;
        char full[160];
        snprintf(full, sizeof(full), "ALERT_TYPE_%s", name);
        if (!strcmp(full, "ALERT_TYPE_COUNT")) continue;
        total++;

        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM research WHERE alert_kinds MATCH ?1",
            -1, &st, NULL);
        sqlite3_bind_text(st, 1, full, -1, SQLITE_TRANSIENT);
        int hits = (sqlite3_step(st) == SQLITE_ROW)
                   ? sqlite3_column_int(st, 0) : 0;
        sqlite3_finalize(st);
        if (hits > 0) cited++;
    }
    fclose(f);
    sqlite3_close(db);

    printf("    corpus coverage: %d/%d alert kinds cited "
           "(warning-only until the content pass lands)\n", cited, total);
    /* What *is* asserted: the mechanism resolves at least one kind. A
     * coverage report that could never find anything would look like
     * progress while measuring nothing. */
    ASSERT(total > 0);
    ASSERT(cited > 0);
}

void run_research_corpus_tests(void) {
    TEST_SUITE("research corpus guard (#73)");
    RUN_TEST(test_corpus_is_present_and_readable);
    RUN_TEST(test_no_document_cites_a_nonexistent_alert_kind);
    RUN_TEST(test_every_row_carries_provenance);
    RUN_TEST(test_alert_kind_coverage_reported);
}
