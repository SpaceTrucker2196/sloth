#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include "runner.h"
#include "sloth.h"
#include "updater.h"

/* Version check-in — exercises the manifest reader against files we
 * write into /tmp. Bumps mtime by writing then sleeping isn't needed:
 * updater_tick's per-poll rate limit is what we test around by
 * writing manifests before the first call. */

static const char *MANIFEST_PATH = "/tmp/sloth_test_manifest.json";

static void write_manifest(const char *body) {
    FILE *fp = fopen(MANIFEST_PATH, "w");
    if (!fp) return;
    fwrite(body, 1, strlen(body), fp);
    fclose(fp);
}

static void bump_mtime(void) {
    /* Force the file to look newer than the previously-cached mtime
     * even if the write completed in the same wall-second. */
    struct stat st;
    if (stat(MANIFEST_PATH, &st) != 0) return;
    struct utimbuf tv;
    tv.actime  = st.st_atime;
    tv.modtime = st.st_mtime + 5;
    utime(MANIFEST_PATH, &tv);
}

static void reset_manifest(void) {
    unlink(MANIFEST_PATH);
    updater_init(NULL);   /* clear the module's internal state */
}

/* Force the next tick to actually re-run by re-init'ing (which resets
 * g_next_check to 0). We keep the same path. */
static void force_recheck(void) {
    updater_init(MANIFEST_PATH);
}

/* ── Init / disable ────────────────────────────────── */

static void test_disabled_when_null_path(void) {
    updater_init(NULL);
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.enabled, 0);
    ASSERT_EQ(s.updater.has_update, 0);
}

/* ── Missing / malformed manifest ─────────────────── */

static void test_missing_manifest_sets_err(void) {
    reset_manifest();
    updater_init(MANIFEST_PATH);
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.enabled, 1);
    ASSERT_EQ(s.updater.err, 1);
    ASSERT(strstr(s.updater.err_msg, "missing") != NULL);
}

static void test_malformed_manifest_sets_err(void) {
    write_manifest("not json at all");
    updater_init(MANIFEST_PATH);
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.err, 1);
    ASSERT(s.updater.err_msg[0] != '\0');
}

/* ── Happy paths ──────────────────────────────────── */

/* Decouple these tests from SLOTH_VERSION so a routine version bump
 * doesn't break them. We compare using the running SLOTH_VERSION
 * itself as the equality case, plus a synthetic "way newer" and
 * "way older" version. */

static void test_up_to_date_reports_no_update(void) {
    char body[128];
    snprintf(body, sizeof(body),
             "{\"latest\":\"%s\",\"url\":\"https://example/\"}", SLOTH_VERSION);
    write_manifest(body);
    force_recheck();
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.err, 0);
    ASSERT_EQ(s.updater.has_update, 0);
    ASSERT_STR(s.updater.latest, SLOTH_VERSION);
    ASSERT_STR(s.updater.url,    "https://example/");
}

static void test_newer_manifest_flags_update(void) {
    /* "99.99.0" is safely greater than any realistic SLOTH_VERSION
     * for the lifetime of this project. */
    write_manifest("{\"latest\":\"99.99.0\",\"url\":\"https://x/\"}");
    force_recheck();
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.err, 0);
    ASSERT_EQ(s.updater.has_update, 1);
    ASSERT_STR(s.updater.latest, "99.99.0");
}

static void test_older_manifest_no_update(void) {
    /* Manifest older than the running binary should NOT flag an
     * update — otherwise a stale local file could induce a
     * confusing "downgrade available" message. "0.0.1" is below
     * every real release. */
    write_manifest("{\"latest\":\"0.0.1\"}");
    force_recheck();
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_EQ(s.updater.has_update, 0);
    ASSERT_STR(s.updater.latest, "0.0.1");
}

/* ── Cache behaviour ────────────────────────────── */

static void test_tick_is_noop_within_interval(void) {
    /* First read succeeds; second read at the same time should not
     * re-open the file even if the on-disk content changed. The
     * observable proxy: the stored `latest` stays at the first
     * value. */
    write_manifest("{\"latest\":\"1.5.0\"}");
    force_recheck();
    updater_tick(1700000000);
    write_manifest("{\"latest\":\"1.6.0\"}");   /* new content, same tick */
    updater_tick(1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_STR(s.updater.latest, "1.5.0");
}

static void test_mtime_change_triggers_reread(void) {
    write_manifest("{\"latest\":\"1.5.0\"}");
    force_recheck();
    updater_tick(1700000000);

    write_manifest("{\"latest\":\"1.6.0\"}");
    bump_mtime();
    /* Second tick is after the check interval (60s) — normally the
     * stat-based mtime comparison decides whether to re-read. */
    updater_tick(1700000000 + 61);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    updater_snapshot(&s);
    ASSERT_STR(s.updater.latest, "1.6.0");
}

void run_updater_tests(void) {
    TEST_SUITE("updater — init");
    RUN_TEST(test_disabled_when_null_path);

    TEST_SUITE("updater — errors");
    RUN_TEST(test_missing_manifest_sets_err);
    RUN_TEST(test_malformed_manifest_sets_err);

    TEST_SUITE("updater — comparison");
    RUN_TEST(test_up_to_date_reports_no_update);
    RUN_TEST(test_newer_manifest_flags_update);
    RUN_TEST(test_older_manifest_no_update);

    TEST_SUITE("updater — cache");
    RUN_TEST(test_tick_is_noop_within_interval);
    RUN_TEST(test_mtime_change_triggers_reread);

    reset_manifest();   /* clean up shared tmp path */
}
