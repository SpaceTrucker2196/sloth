#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"

/*
 * Build-recipe guard — issue #95.
 *
 * The property under test: a flag handed to the build through
 * EXTRA_CFLAGS reaches *every* `$(CC)` invocation the Makefile makes —
 * the compile steps and the link steps alike.
 *
 * It did not. `$(TARGET)` linked with `$(CC) -o $@ $^ $(LDFLAGS)`, which
 * carries no compiler flags at all, so
 * `make EXTRA_CFLAGS=-fsanitize=address,undefined` compiled 140-odd
 * instrumented objects and then died at ld with undefined references to
 * __asan_init / __asan_report_*. The shipped binary had therefore never
 * been linked under a sanitizer once — and `src/main.c`, the libpcap
 * capture path and the ncurses renderer exist only in `sloth`, never in
 * `sloth_test`, so CI's `sanitize` and `tsan` jobs (which run `make test`
 * and nothing else) had never instrumented them either. `sloth_test`
 * escaped the bug only because its rule compiles and links in a single
 * `$(CC)` call that already carries TEST_CFLAGS.
 *
 * Why a text scan of the Makefile rather than a behavioural test: this
 * is a property of the build recipe, and the suite is built *by* that
 * recipe — a test binary cannot link a second binary to check how it was
 * linked. The CI job added alongside this (.github/workflows/ci.yml,
 * `sanitize`) is the behavioural half: it actually builds `sloth` under
 * -fsanitize=address,undefined and goes red if ld fails. This half is
 * what makes the invariant visible to `make test` on a developer's
 * machine, before the push, and generalises it to link rules that do not
 * exist yet.
 *
 * Deliberately stated as "every $(CC) line", not "line 269 says CFLAGS":
 * the second would pass the day someone adds a fourth binary and forgets.
 */

#define BR_MAX_LINES 512

static char *slurp_makefile(void) {
    FILE *f = fopen("Makefile", "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Collapse make's backslash continuations so a recipe that wraps over
 * several source lines is examined as the one command it becomes. The
 * buffer is rewritten in place; `out[i]` points into it. */
static int logical_lines(char *buf, char *out[], int max) {
    int n = 0;
    char *p = buf;
    while (*p && n < max) {
        out[n++] = p;
        for (;;) {
            char *nl = strchr(p, '\n');
            if (!nl) { p += strlen(p); break; }
            /* Continuation when the newline is preceded by a backslash. */
            if (nl > buf && nl[-1] == '\\') {
                nl[-1] = ' ';
                *nl = ' ';
                p = nl + 1;
                continue;
            }
            *nl = '\0';
            p = nl + 1;
            break;
        }
    }
    return n;
}

/* A recipe line is one make hands to the shell: it starts with a tab. */
static int is_recipe(const char *line) { return line[0] == '\t'; }

static int invokes_cc(const char *line) { return strstr(line, "$(CC)") != NULL; }

static int carries_cflags(const char *line) {
    return strstr(line, "$(CFLAGS)") != NULL ||
           strstr(line, "$(TEST_CFLAGS)") != NULL;
}

/* ── the invariant ── */

static void test_every_cc_invocation_carries_compiler_flags(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;

    char *lines[BR_MAX_LINES];
    int n = logical_lines(buf, lines, BR_MAX_LINES);
    ASSERT_GT(n, 0);
    /* A capped scan would silently stop before the later rules. */
    ASSERT_LT(n, BR_MAX_LINES);

    int seen = 0;
    for (int i = 0; i < n; i++) {
        if (!is_recipe(lines[i]) || !invokes_cc(lines[i])) continue;
        seen++;
        if (!carries_cflags(lines[i]))
            fprintf(stderr,
                    "    Makefile: $(CC) invocation with neither $(CFLAGS) "
                    "nor $(TEST_CFLAGS):\n      %s\n", lines[i] + 1);
        ASSERT(carries_cflags(lines[i]));
    }

    /* Five today: the sloth link, the %.o compile, research-index,
     * research-mcp and the test binary. Asserting a floor keeps the loop
     * from passing vacuously if the scan ever stops matching anything. */
    ASSERT_GE(seen, 5);

    free(buf);
}

/* The link rule specifically, named: the one that was broken, and the one
 * whose breakage a compile-only check cannot see. */
static void test_sloth_link_rule_passes_cflags(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;

    char *lines[BR_MAX_LINES];
    int n = logical_lines(buf, lines, BR_MAX_LINES);

    int found = 0;
    for (int i = 0; i + 1 < n; i++) {
        if (strncmp(lines[i], "$(TARGET): $(OBJS)", 18) != 0) continue;
        found = 1;
        ASSERT(is_recipe(lines[i + 1]));
        ASSERT(invokes_cc(lines[i + 1]));
        /* Without this the sanitizer runtime is never linked in. */
        ASSERT(strstr(lines[i + 1], "$(CFLAGS)") != NULL);
        /* -l libraries must still trail the objects that reference them. */
        ASSERT(strstr(lines[i + 1], "$(LDFLAGS)") != NULL);
        char *objs = strstr(lines[i + 1], "$^");
        char *ld   = strstr(lines[i + 1], "$(LDFLAGS)");
        ASSERT(objs != NULL && ld != NULL && objs < ld);
    }
    ASSERT_EQ(found, 1);

    free(buf);
}

/* The other half of the chain. $(CFLAGS) on the link line only helps if
 * EXTRA_CFLAGS lands in $(CFLAGS) in the first place; CI passes every
 * sanitizer and -Werror through that one variable. */
static void test_extra_cflags_reaches_both_flag_sets(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;

    ASSERT(strstr(buf, "CFLAGS += $(EXTRA_CFLAGS)") != NULL);
    ASSERT(strstr(buf, "TEST_CFLAGS += $(EXTRA_CFLAGS)") != NULL);

    free(buf);
}

/* Regression cover for the scanner itself, so the checks above are known
 * to be capable of failing. Hand-built strings, not Makefile output. */
static void test_scanner_distinguishes_flagged_from_bare(void) {
    ASSERT(is_recipe("\t$(CC) -o $@ $^"));
    ASSERT(!is_recipe("$(TARGET): $(OBJS)"));
    ASSERT(!is_recipe("# $(CC) in a comment"));

    ASSERT(invokes_cc("\t$(CC) $(CFLAGS) -c -o $@ $<"));
    ASSERT(!invokes_cc("\tinstall -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)"));

    ASSERT(carries_cflags("\t$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)"));
    ASSERT(carries_cflags("\t$(CC) $(TEST_CFLAGS) -o $@ $(TEST_SRCS) -lm"));
    /* The exact shape of the bug this slice fixes. */
    ASSERT(!carries_cflags("\t$(CC) -o $@ $^ $(LDFLAGS)"));
    /* $(LDFLAGS) alone is not a substitute — it holds -l flags, and a
     * sanitizer is requested through the compiler driver, not there. */
    ASSERT(!carries_cflags("\t$(CC) -o $@ $^ -lpthread -lm"));
}

static void test_continuations_join_into_one_command(void) {
    char src[] = "\t$(CC) $(CFLAGS) -DWITH_SQLITE \\\n"
                 "\t      -o sloth-research-mcp $(MCP_SRCS) -lsqlite3\n"
                 "plain: line\n";
    char *lines[8];
    int n = logical_lines(src, lines, 8);
    ASSERT_EQ(n, 2);
    ASSERT(is_recipe(lines[0]));
    ASSERT(invokes_cc(lines[0]));
    ASSERT(carries_cflags(lines[0]));
    /* Both halves are present in the single joined command. */
    ASSERT(strstr(lines[0], "-DWITH_SQLITE") != NULL);
    ASSERT(strstr(lines[0], "sloth-research-mcp") != NULL);
    ASSERT(!is_recipe(lines[1]));
}

void run_build_recipe_tests(void) {
    TEST_SUITE("build recipe (#95)");
    RUN_TEST(test_scanner_distinguishes_flagged_from_bare);
    RUN_TEST(test_continuations_join_into_one_command);
    RUN_TEST(test_every_cc_invocation_carries_compiler_flags);
    RUN_TEST(test_sloth_link_rule_passes_cflags);
    RUN_TEST(test_extra_cflags_reaches_both_flag_sets);
}
