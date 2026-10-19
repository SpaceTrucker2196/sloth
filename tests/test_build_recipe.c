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

/* Sized well past the Makefile's logical-line count (~600 after #115) so
 * the scan never stops short of the later rules for a reason unrelated
 * to what is being checked; the ASSERT_LT below fails if it ever does. */
#define BR_MAX_LINES 4096

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


/* ── the mutation sandbox must carry everything the test build needs ──
 *
 * .github/scripts/mutate.py copies the repo into a scratch tree and runs
 * `make test` there as its baseline. It used to copy a hand-kept tuple
 * ("Makefile", "src", "include", "tests"), and that rotted without a
 * sound: #73 added the research/ sources to TEST_SRCS and research.db to what the
 * tests open, so from then until 2026-10-14 every `make mutate` aborted
 * at "baseline not green" — which from outside is indistinguishable from
 * never having run it. Adding research/ by hand only moved the failure
 * into the docs-consistency and CI-pin suites, which read docs/, agents/,
 * .github/, README.md and MISSION.md.
 *
 * The durable property is therefore not "the tuple names X" but "the
 * sandbox is derived from the tracked tree", so whatever the tests read
 * next year travels too. Like the rest of this file, a text scan of the
 * recipe: the behavioural proof is `make mutate MUTATE_FLAGS="--limit 1"`
 * reaching a green baseline, recorded on #108. */

static char *slurp_path(const char *path) {
    FILE *f = fopen(path, "rb");
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

static void test_mutate_sandbox_is_built_from_the_tracked_tree(void) {
    char *py = slurp_path(".github/scripts/mutate.py");
    ASSERT(py != NULL);
    if (!py) return;
    char *fn = strstr(py, "def make_sandbox(");
    ASSERT(fn != NULL);
    if (!fn) { free(py); return; }
    char *end = strstr(fn, "\ndef ");            /* next top-level def */
    if (end) *end = '\0';

    /* Derived from git, not enumerated. */
    ASSERT(strstr(fn, "ls-files") != NULL);
    /* And no longer a hand-kept tuple of roots: the old form was
       `for entry in ("Makefile", "src", ...)`. Its return would mean the
       rot is back, so it is asserted absent, not merely unused. */
    ASSERT(strstr(fn, "for entry in (") == NULL);
    free(py);
}

/* ── the invariant ── */

static void test_every_cc_invocation_carries_compiler_flags(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;

    static char *lines[BR_MAX_LINES];
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

    /* Eight today: the sloth link and its object compile, research-index,
     * research-mcp, and the compile and link of sloth_test and of
     * sloth_test_noflags (#116; sloth_test_pcap held that place before). Asserting a floor keeps the loop from passing
     * vacuously if the scan ever stops matching anything. */
    ASSERT_GE(seen, 8);

    free(buf);
}

/* The link rule specifically, named: the one that was broken, and the one
 * whose breakage a compile-only check cannot see. */
static void test_sloth_link_rule_passes_cflags(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;

    static char *lines[BR_MAX_LINES];
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

/* ── derived source lists (#115) ──
 *
 * The Makefile used to keep seven source lists by hand: SRCS, TEST_SRCS,
 * CAPTURE_PATH_SRCS, FUZZ_EAPOL_SRCS and three inline lists in the fuzz
 * recipe. The inline ones rotted first — on 2026-10-14 two fuzz targets
 * failed to LINK in CI because a module they listed gained a dependency
 * they did not. Since #115 every binary links libsloth_core.a built from
 * one list, and each test or fuzz binary takes its own files by wildcard.
 *
 * The property, stated so a regression of any shape trips it: no command
 * that compiles or links names a source file, and no variable spells out
 * a test file. Both are text scans of the Makefile for the same reason as
 * everything else here. */

/* Does `line` contain a whitespace-delimited token that is a literal C
 * source path ("src/x.c", "tests/fuzz/fuzz_y.c")? A make pattern
 * ("%.c", "tests/test_capture_path%.c") or a variable reference is not
 * one: those are how a derived list is written. */
static int names_c_path_under(const char *line, const char *prefix) {
    const char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        const char *t = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        size_t len = (size_t)(p - t);
        if (len < 3) continue;
        /* Trailing shell punctuation is not part of the path. */
        while (len > 2 && (t[len - 1] == ';' || t[len - 1] == ')' ||
                           t[len - 1] == ','))
            len--;
        if (len < 3 || t[len - 2] != '.' || t[len - 1] != 'c') continue;
        int plain = 1;
        for (size_t i = 0; i < len; i++)
            if (t[i] == '%' || t[i] == '$' || t[i] == '*' || t[i] == '(') {
                plain = 0;
                break;
            }
        if (plain && (!prefix || strncmp(t, prefix, strlen(prefix)) == 0))
            return 1;
    }
    return 0;
}

static int names_c_path(const char *line) { return names_c_path_under(line, NULL); }

/* Blank the first argument of every $(filter-out ...) in `s`, in place.
 * Naming a file in order to EXCLUDE it from a wildcard (the runner, the
 * capture-path pair) is how a derived list is written, not a hand list. */
static void blank_filter_out_patterns(char *s) {
    char *p = s;
    while ((p = strstr(p, "$(filter-out ")) != NULL) {
        p += strlen("$(filter-out ");
        while (*p && *p != ',') *p++ = ' ';
    }
}

static int invokes_fuzz_cc(const char *line) {
    return strstr(line, "$(FUZZ_CC)") != NULL;
}

static void test_scanner_finds_literal_c_paths(void) {
    ASSERT(names_c_path("\t$(FUZZ_CC) $(FUZZ_FLAGS) -o x tests/fuzz/fuzz_a.c src/radiotap.c"));
    ASSERT(names_c_path("\t$(CC) $(CFLAGS) -c src/x.c;"));
    ASSERT(names_c_path("TEST_SRCS = tests/main_test.c"));
    ASSERT(!names_c_path("\t$(CC) $(CFLAGS) -MMD -c -o $@ $<"));
    ASSERT(!names_c_path("TEST_SRCS = $(filter-out tests/test_capture_path%.c,$(wildcard tests/*.c))"));
    ASSERT(!names_c_path("$(OBJDIR)/%.o: %.c $(OBJDIR)/.flags"));
    /* An object, a header or a word that merely ends in "c" is not one. */
    ASSERT(!names_c_path("\tar rcs lib.a src/x.o include/sloth.h -lc"));
    /* Under a prefix, and with exclusions blanked. */
    ASSERT(names_c_path_under("X = src/a.c tests/b.c", "tests/"));
    ASSERT(!names_c_path_under("X = src/a.c", "tests/"));
    char ex[] = "X = $(filter-out tests/main_test.c tests/test_%.c,$(wildcard tests/*.c))";
    ASSERT(names_c_path_under(ex, "tests/"));
    blank_filter_out_patterns(ex);
    ASSERT(!names_c_path_under(ex, "tests/"));
    ASSERT(invokes_fuzz_cc("\t$(FUZZ_CC) $(FUZZ_FLAGS) -o $@ $<"));
    ASSERT(!invokes_fuzz_cc("\t$(CC) $(CFLAGS) -o $@ $^"));
}

static void test_no_compile_or_link_command_names_a_source(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;
    static char *lines[BR_MAX_LINES];
    int n = logical_lines(buf, lines, BR_MAX_LINES);
    ASSERT_LT(n, BR_MAX_LINES);

    int cc_seen = 0, fuzz_seen = 0, listed = 0;
    for (int i = 0; i < n; i++) {
        if (!is_recipe(lines[i])) continue;
        int cc = invokes_cc(lines[i]), fz = invokes_fuzz_cc(lines[i]);
        if (!cc && !fz) continue;
        cc_seen += cc;
        fuzz_seen += fz;
        if (names_c_path(lines[i])) {
            fprintf(stderr, "    Makefile: compiler command with a hand-kept "
                            "source path:\n      %s\n", lines[i] + 1);
            listed++;
        }
    }
    ASSERT_EQ(listed, 0);
    /* Floors, so neither half passes by matching nothing: the fuzz object
     * compile and the one fuzz link rule; every $(CC) line counted by
     * test_every_cc_invocation_carries_compiler_flags. */
    ASSERT_GE(fuzz_seen, 2);
    ASSERT_GE(cc_seen, 8);
    free(buf);
}

static void test_no_variable_spells_out_a_test_file(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;
    static char *lines[BR_MAX_LINES];
    int n = logical_lines(buf, lines, BR_MAX_LINES);
    ASSERT_LT(n, BR_MAX_LINES);

    int test_srcs_def = 0, hand = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ') l++;
        if (*l == '#' || *l == '\t') continue;
        /* A literal tests/ source anywhere outside a comment — other than
         * as an exclusion from a wildcard — is a hand list starting again. */
        static char copy[8192];
        snprintf(copy, sizeof copy, "%s", l);
        blank_filter_out_patterns(copy);
        if (names_c_path_under(copy, "tests/")) {
            fprintf(stderr, "    Makefile: hand-kept test source:\n      %s\n", l);
            hand++;
        }
        if (strncmp(l, "TEST_SRCS", 9) == 0 && strchr(l, '=') &&
            strstr(l, "$(wildcard tests/*.c)") != NULL)
            test_srcs_def = 1;
    }
    ASSERT_EQ(hand, 0);
    ASSERT(test_srcs_def);
    free(buf);
}

/* The object directory must spell every feature flag. Leave one out and
 * two configs share a directory again — the stale-object link failure the
 * per-config split exists to end — so this is checked by name, flag by
 * flag, rather than trusted. */
static void test_object_dir_is_per_config(void) {
    char *buf = slurp_makefile();
    ASSERT(buf != NULL);
    if (!buf) return;
    static char *lines[BR_MAX_LINES];
    int n = logical_lines(buf, lines, BR_MAX_LINES);

    int tag = 0, objdir = 0, bare_rule = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        if (strncmp(l, "CFG_TAG", 7) == 0 && strchr(l, '=')) {
            tag = 1;
            ASSERT(strstr(l, "$(WITH_NCURSES)") != NULL);
            ASSERT(strstr(l, "$(WITH_PCAP)") != NULL);
            ASSERT(strstr(l, "$(WITH_WIFI)") != NULL);
            ASSERT(strstr(l, "$(WITH_SQLITE)") != NULL);
        }
        if (strncmp(l, "OBJDIR", 6) == 0 && strchr(l, '=') &&
            strstr(l, "$(CFG_TAG)") != NULL)
            objdir = 1;
        /* The pre-#115 rule compiled every config beside its source. */
        if (strncmp(l, "%.o: %.c", 8) == 0) bare_rule = 1;
    }
    ASSERT(tag);
    ASSERT(objdir);
    ASSERT(!bare_rule);
    free(buf);
}

/* `make cppcheck` runs CI's cppcheck command (ci.yml, job `cppcheck`)
 * and says so in its comment: green locally means green in CI. Until
 * #119 makes CI call the target, the two are separate texts, so the
 * claim is checked here: the same arguments in the same order, with
 * $(CPPCHECK_DEFS) expanded and the -j value (make's `nproc` vs the
 * shell's "$(nproc)") left out. This is why the target still names the
 * `src research` directories rather than $(CORE_SRCS): the directory
 * scan is what CI runs, and it already covers every source the lists
 * above derive from. */

static void test_ci_cppcheck_is_the_make_target(void) {
    /* #119 removed the duplicate: CI runs `make cppcheck` and nothing
       else, so the Makefile is the only place the command lives. The
       old test pinned two copies together token by token; this one
       asserts there is only one copy. */
    char *ci = slurp_path(".github/workflows/ci.yml");
    ASSERT(ci != NULL);
    if (!ci) return;
    char *job = strstr(ci, "\n  cppcheck:\n");
    ASSERT(job != NULL);
    char *next = job ? strstr(job + 3, "\n  fuzz:\n") : NULL;
    if (next) *next = '\0';
    ASSERT(job && strstr(job, "run: make cppcheck\n") != NULL);   /* whole line */
    ASSERT(job && strstr(job, "cppcheck -q") == NULL);   /* no inline copy */
    free(ci);
}

void run_build_recipe_tests(void) {
    TEST_SUITE("build recipe (#95)");
    RUN_TEST(test_scanner_distinguishes_flagged_from_bare);
    RUN_TEST(test_continuations_join_into_one_command);
    RUN_TEST(test_every_cc_invocation_carries_compiler_flags);
    RUN_TEST(test_sloth_link_rule_passes_cflags);
    RUN_TEST(test_extra_cflags_reaches_both_flag_sets);
    RUN_TEST(test_mutate_sandbox_is_built_from_the_tracked_tree);
    RUN_TEST(test_scanner_finds_literal_c_paths);
    RUN_TEST(test_no_compile_or_link_command_names_a_source);
    RUN_TEST(test_no_variable_spells_out_a_test_file);
    RUN_TEST(test_object_dir_is_per_config);
    RUN_TEST(test_ci_cppcheck_is_the_make_target);
}
