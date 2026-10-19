#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "runner.h"
#include "libver.h"
#include "db.h"
#include "query.h"

/*
 * Loaded-library versions and the runtime sqlite floor (#142).
 *
 * The compile-time #error in src/db.c and research/query.c (#134) sees
 * only the headers. The library that runs is whatever the dynamic
 * linker finds, so a binary copied to an older host would open its
 * database with NOFOLLOW and TRUSTED_SCHEMA unknown to the library
 * doing the open. These cases drive the refusal through the test seam,
 * because the sqlite this suite is linked against is necessarily new
 * enough to compile — the real-version path can never be the old one
 * here.
 *
 * Nothing below asserts which libpcap or sqlite this host has: that is
 * host state. Each check compares against what the library itself
 * reports.
 */

static void test_floor_boundary(void) {
    ASSERT_EQ(libver_sqlite_floor_ok(LIBVER_SQLITE_FLOOR_NUM), 1);
    ASSERT_EQ(libver_sqlite_floor_ok(LIBVER_SQLITE_FLOOR_NUM - 1), 0);
    ASSERT_EQ(libver_sqlite_floor_ok(3030001), 0);   /* 3.30.1 */
    ASSERT_EQ(libver_sqlite_floor_ok(3031001), 1);   /* 3.31.1 */
    ASSERT_EQ(libver_sqlite_floor_ok(0), 0);
    /* The number and the string the messages print are one floor. */
    ASSERT_STR(LIBVER_SQLITE_FLOOR_STR, "3.31.0");
    ASSERT_EQ(LIBVER_SQLITE_FLOOR_NUM, 3031000);
}

static void test_refuse_names_both_versions(void) {
    char err[96];
    libver_sqlite_override_for_test(3030001);
    memset(err, 0, sizeof(err));
    ASSERT_EQ(libver_sqlite_refuse(err, sizeof(err)), -1);
    ASSERT(strstr(err, "3.30.1") != NULL);
    ASSERT(strstr(err, LIBVER_SQLITE_FLOOR_STR) != NULL);
    libver_sqlite_override_for_test(0);
}

static void test_real_library_is_what_is_compared(void) {
    /* With the seam cleared, the comparison is against the loaded
     * library's own number — whatever it is on this host. */
    char err[96];
    libver_sqlite_override_for_test(0);
    ASSERT_EQ(libver_sqlite_loaded(), sqlite3_libversion_number());
    ASSERT_EQ(libver_sqlite_refuse(err, sizeof(err)) == 0,
              libver_sqlite_floor_ok(sqlite3_libversion_number()));
    ASSERT_STR(libver_sqlite(), sqlite3_libversion());
}

static void test_db_open_refuses_below_floor(void) {
    char path[] = "/tmp/sloth_libver_db_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    if (fd < 0) return;
    close(fd);
    unlink(path);                     /* db_open creates it when allowed */

    libver_sqlite_override_for_test(3030001);
    ASSERT_EQ(db_open(path), 0);
    /* Refused before the path was touched: no file was created. */
    struct stat st;
    ASSERT(stat(path, &st) != 0);

    /* The same path opens once the seam reports a library at the floor —
     * so the refusal above was the floor, not something about the
     * path. */
    libver_sqlite_override_for_test(LIBVER_SQLITE_FLOOR_NUM);
    ASSERT_EQ(db_open(path), 1);
    db_close();
    libver_sqlite_override_for_test(0);

    char side[64];
    unlink(path);
    snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
}

static void test_rq_open_refuses_below_floor(void) {
    /* research.db is committed at the repo root, which is the suite's
     * working directory (test_research_view.c opens it the same way). */
    libver_sqlite_override_for_test(3030001);
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h == NULL);
    ASSERT(strstr(rq_open_error(), "below the " LIBVER_SQLITE_FLOOR_STR
                                   " floor") != NULL);
    if (h) rq_close(h);

    libver_sqlite_override_for_test(LIBVER_SQLITE_FLOOR_NUM);
    h = rq_open("research.db");
    ASSERT(h != NULL);
    ASSERT_STR(rq_open_error(), "");
    if (h) rq_close(h);
    libver_sqlite_override_for_test(0);
}

static void test_format_carries_both_libraries(void) {
    char buf[192], want[192];
    libver_format(buf, sizeof(buf));
    snprintf(want, sizeof(want), "pcap: %s; sqlite: %s",
             libver_pcap(), libver_sqlite());
    ASSERT_STR(buf, want);
#ifdef WITH_PCAP
    /* sloth_test is built WITH_PCAP since #116: the linked library's
     * own string, never the "none" a pcap-less build reports. */
    ASSERT(strcmp(libver_pcap(), "none") != 0);
#else
    ASSERT_STR(libver_pcap(), "none");
#endif
    /* Truncates rather than overrunning. */
    char tiny[8];
    memset(tiny, 'X', sizeof(tiny));
    libver_format(tiny, sizeof(tiny));
    ASSERT_EQ(tiny[sizeof(tiny) - 1], '\0');
    /* The truncated form is the full form's first 7 octets, whatever
     * the linked pcap reports. It used to be the literal "pcap: n" -
     * true only while sloth_test was built without WITH_PCAP, which
     * #116 ended. */
    ASSERT(strncmp(tiny, want, sizeof(tiny) - 1) == 0);
    ASSERT_EQ((int)strlen(tiny), (int)sizeof(tiny) - 1);
}

/* tools/sbom.sh, the `make sbom` fallback. Driven with a stand-in
 * pkg-config so the versions are sentinels rather than this host's. The
 * stand-in reports a version carrying JSON metacharacters: a .pc file
 * is outside sloth's control, and its text lands inside a JSON
 * string. */
static char *run_capture(const char *cmd) {
    FILE *p = popen(cmd, "r");
    if (!p) return NULL;
    size_t cap = 8192, n = 0;
    char *out = malloc(cap);
    if (!out) { pclose(p); return NULL; }
    size_t got;
    while ((got = fread(out + n, 1, cap - 1 - n, p)) > 0) {
        n += got;
        if (n >= cap - 1) break;
    }
    out[n] = '\0';
    pclose(p);
    return out;
}

static void test_sbom_fallback_names_link_deps(void) {
    /* Under build/, not /tmp: the stand-in is executed, and /tmp may be
     * mounted noexec. */
    char stub[] = "build/test/pkgconfig_stub_XXXXXX";
    int fd = mkstemp(stub);
    ASSERT(fd >= 0);
    if (fd < 0) return;
    static const char body[] =
        "#!/bin/sh\n"
        "printf '%s\\n' '7.7.7\"},{\"evil\":\"1'\n";
    ASSERT_EQ(write(fd, body, sizeof(body) - 1), (ssize_t)(sizeof(body) - 1));
    close(fd);
    chmod(stub, 0700);

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "SLOTH_VERSION=9.8.7 PKG_CONFIG=%s sh tools/sbom.sh", stub);
    char *out = run_capture(cmd);
    unlink(stub);
    ASSERT(out != NULL);
    if (!out) return;

    ASSERT(strstr(out, "\"bomFormat\": \"CycloneDX\"") != NULL);
    ASSERT(strstr(out, "\"specVersion\": \"1.5\"") != NULL);
    ASSERT(strstr(out, "\"name\": \"sloth\"") != NULL);
    ASSERT(strstr(out, "\"version\": \"9.8.7\"") != NULL);
    static const char *const deps[] = {
        "ncursesw", "libpcap", "sqlite3", "libpthread", "libm",
    };
    for (size_t i = 0; i < sizeof(deps) / sizeof(deps[0]); i++) {
        char key[64];
        snprintf(key, sizeof(key), "\"name\": \"%s\"", deps[i]);
        ASSERT(strstr(out, key) != NULL);
    }
    /* The reported version reached the document with the metacharacters
     * dropped: the sentinel's safe characters are there, the quote and
     * brace that would have closed the string are not. */
    ASSERT(strstr(out, "\"version\": \"7.7.7evil1\"") != NULL);
    ASSERT(strstr(out, "\"evil\"") == NULL);
    free(out);

    /* No pkg-config at all: every pkg-config version reads "unknown",
     * never an empty string a consumer would take for a value. */
    out = run_capture("SLOTH_VERSION=9.8.7 PKG_CONFIG=/nonexistent/pkg-config"
                      " sh tools/sbom.sh");
    ASSERT(out != NULL);
    if (!out) return;
    ASSERT(strstr(out, "\"name\": \"sqlite3\",\n"
                       "      \"version\": \"unknown\"") != NULL);
    ASSERT(strstr(out, "\"version\": \"\"") == NULL);
    free(out);
}

void run_libver_tests(void) {
    TEST_SUITE("loaded library versions and sqlite floor (#142)");
    RUN_TEST(test_floor_boundary);
    RUN_TEST(test_refuse_names_both_versions);
    RUN_TEST(test_real_library_is_what_is_compared);
    RUN_TEST(test_db_open_refuses_below_floor);
    RUN_TEST(test_rq_open_refuses_below_floor);
    RUN_TEST(test_format_carries_both_libraries);
    RUN_TEST(test_sbom_fallback_names_link_deps);
}
