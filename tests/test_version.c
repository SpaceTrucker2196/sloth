#include <string.h>
#include "runner.h"
#include "version.h"

/* Semver parse + compare, covering the shapes SLOTH_VERSION and git
 * tags actually emit, plus the classic 1.10.0 > 1.9.0 lexical trap. */

static void test_parse_basic(void) {
    semver_t v;
    ASSERT(semver_parse("1.4.0", &v));
    ASSERT_EQ(v.major, 1);
    ASSERT_EQ(v.minor, 4);
    ASSERT_EQ(v.patch, 0);
    ASSERT_EQ(v.has_prerelease, 0);
}

static void test_parse_strips_v_prefix(void) {
    semver_t v;
    ASSERT(semver_parse("v1.4.0", &v));
    ASSERT_EQ(v.major, 1);
    ASSERT_EQ(v.minor, 4);
    ASSERT(semver_parse("V2.10.7", &v));
    ASSERT_EQ(v.major, 2);
    ASSERT_EQ(v.patch, 7);
}

static void test_parse_prerelease(void) {
    semver_t v;
    ASSERT(semver_parse("1.5.0-rc1", &v));
    ASSERT_EQ(v.has_prerelease, 1);
    ASSERT_STR(v.prerelease, "rc1");
}

static void test_parse_ignores_build_metadata(void) {
    /* semver 2.0: "+…" is build metadata, dropped for ordering. */
    semver_t v;
    ASSERT(semver_parse("1.4.0+deadbeef", &v));
    ASSERT_EQ(v.major, 1);
    ASSERT_EQ(v.has_prerelease, 0);
}

static void test_parse_rejects_malformed(void) {
    semver_t v;
    ASSERT_EQ(semver_parse("",       &v), 0);
    ASSERT_EQ(semver_parse("1.4",    &v), 0);   /* only two components */
    ASSERT_EQ(semver_parse("a.b.c",  &v), 0);   /* non-numeric */
    ASSERT_EQ(semver_parse("1..0",   &v), 0);   /* empty middle */
    ASSERT_EQ(semver_parse("1.4.0-", &v), 0);   /* trailing '-' with no tag */
}

static void test_cmp_ordering(void) {
    semver_t a, b;
    /* Classic lexical trap: string cmp would rank "1.10.0" < "1.9.0". */
    ASSERT(semver_parse("1.10.0", &a));
    ASSERT(semver_parse("1.9.0",  &b));
    ASSERT(semver_cmp(&a, &b) > 0);

    /* Patch-level */
    ASSERT(semver_parse("1.4.1", &a));
    ASSERT(semver_parse("1.4.0", &b));
    ASSERT(semver_cmp(&a, &b) > 0);
}

static void test_cmp_equal(void) {
    semver_t a, b;
    ASSERT(semver_parse("1.4.0", &a));
    ASSERT(semver_parse("v1.4.0", &b));
    ASSERT_EQ(semver_cmp(&a, &b), 0);
}

static void test_cmp_prerelease_sorts_below(void) {
    /* rc1 must sort *below* the base release — otherwise a
     * pre-release build would be reported as "newer" than the actual
     * release it's a candidate for. */
    semver_t a, b;
    ASSERT(semver_parse("1.5.0-rc1", &a));
    ASSERT(semver_parse("1.5.0",     &b));
    ASSERT(semver_cmp(&a, &b) < 0);
}

static void test_cmp_prerelease_string(void) {
    /* Both prerelease → lexical compare on the tag. Good enough for
     * "rc1" < "rc2" and "beta.1" < "rc.1". */
    semver_t a, b;
    ASSERT(semver_parse("1.5.0-rc1", &a));
    ASSERT(semver_parse("1.5.0-rc2", &b));
    ASSERT(semver_cmp(&a, &b) < 0);
}

static void test_cmp_build_metadata_ignored(void) {
    semver_t a, b;
    ASSERT(semver_parse("1.4.0+deadbeef", &a));
    ASSERT(semver_parse("1.4.0+cafebabe", &b));
    ASSERT_EQ(semver_cmp(&a, &b), 0);
}

void run_version_tests(void) {
    TEST_SUITE("version — parse");
    RUN_TEST(test_parse_basic);
    RUN_TEST(test_parse_strips_v_prefix);
    RUN_TEST(test_parse_prerelease);
    RUN_TEST(test_parse_ignores_build_metadata);
    RUN_TEST(test_parse_rejects_malformed);

    TEST_SUITE("version — compare");
    RUN_TEST(test_cmp_ordering);
    RUN_TEST(test_cmp_equal);
    RUN_TEST(test_cmp_prerelease_sorts_below);
    RUN_TEST(test_cmp_prerelease_string);
    RUN_TEST(test_cmp_build_metadata_ignored);
}
