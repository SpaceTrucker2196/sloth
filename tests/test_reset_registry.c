#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include "runner.h"

/*
 * Reset-registry completeness — issue #114.
 *
 * sloth_reset_all() (src/reset_all.h/.c) exists so a test author never
 * has to remember which module clears their test's state touches. That
 * guarantee is only as good as the registry being exhaustive, so this
 * scrapes every zero-arg `_clear`/`_reset` declared in the production
 * headers and asserts each one is either in SLOTH_RESETS or named, with
 * a reason, in the exclusion list below. A declared reset that is
 * silently neither would be exactly the drift this exists to catch.
 *
 * Mutation: delete one X(...) line from src/reset_all.h and this goes
 * red naming that function; restore it and it is green again. Verified
 * by hand on 2026-10-15, not left as an unexercised claim.
 */

/* The same fixed set of header locations tests/'s own build uses
 * (the pre-#115 TEST_HDRS list) minus tests/ and research/ — this is a
 * production-only registry, and research/ has none of this shape. */
static const char *HDR_DIRS[] = {
    "include", "src", "src/views", "src/capture", "src/platform"
};
#define N_HDR_DIRS (int)(sizeof(HDR_DIRS) / sizeof(HDR_DIRS[0]))

#define MAX_NAMES 256
#define NAME_LEN  80

typedef struct {
    char names[MAX_NAMES][NAME_LEN];
    int  n;
} name_set_t;

static void set_add(name_set_t *s, const char *name) {
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->names[i], name) == 0) return;   /* dedupe */
    if (s->n >= MAX_NAMES) return;
    snprintf(s->names[s->n], NAME_LEN, "%s", name);
    s->n++;
}

static int set_has(const name_set_t *s, const char *name) {
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->names[i], name) == 0) return 1;
    return 0;
}

/* Declared-reset shape: optional indent, "void", space, an identifier
 * ending "_clear" or "_reset", optional space, "(void)", optional
 * space, ';' — then anything (a trailing comment). Deliberately not a
 * regex: the codebase's own convention (test_research_corpus.c et al.)
 * is a hand-rolled scan over fgets() lines, and that is followed here. */
static int parse_reset_decl(const char *line, char *name, size_t namesz) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "void", 4) != 0) return 0;
    p += 4;
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    const char *id_start = p;
    while (isalnum((unsigned char)*p) || *p == '_') p++;
    size_t idlen = (size_t)(p - id_start);
    if (idlen < 7 || idlen >= namesz) return 0;
    int is_reset_or_clear =
        strncmp(p - 6, "_reset", 6) == 0 || strncmp(p - 6, "_clear", 6) == 0;
    if (!is_reset_or_clear) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '(') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "void", 4) != 0) return 0;
    p += 4;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ')') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ';') return 0;
    memcpy(name, id_start, idlen);
    name[idlen] = '\0';
    return 1;
}

static void scan_header_dir(const char *dir, name_set_t *out, int *files_seen) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl < 3 || strcmp(e->d_name + nl - 2, ".h") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%.200s", dir, e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        (*files_seen)++;
        char line[512];
        char name[NAME_LEN];
        while (fgets(line, sizeof(line), f)) {
            if (parse_reset_decl(line, name, sizeof(name)))
                set_add(out, name);
        }
        fclose(f);
    }
    closedir(d);
}

/* Pulls every `X(identifier)` token out of src/reset_all.h — robust to
 * the macro's own line-continuation formatting because it does not
 * depend on it, just on the literal "X(" + identifier + ")" shape. */
static void scan_sloth_resets(name_set_t *out) {
    FILE *f = fopen("src/reset_all.h", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while ((p = strstr(p, "X(")) != NULL) {
            p += 2;
            char *close = strchr(p, ')');
            if (!close) break;
            size_t len = (size_t)(close - p);
            if (len > 0 && len < NAME_LEN) {
                char name[NAME_LEN];
                memcpy(name, p, len);
                name[len] = '\0';
                set_add(out, name);
            }
            p = close + 1;
        }
    }
    fclose(f);
}

/* Declared resets that are deliberately not in SLOTH_RESETS, with the
 * reason a reviewer needs and nothing more. Add to this list only with
 * a reason that would survive being read by someone who did not write
 * it. */
typedef struct { const char *name; const char *reason; } excluded_t;
static const excluded_t EXCLUDED[] = {
    { "probe_clear",
      "src/capture/probe.c is not in TEST_CORE_SRCS (only CAPTURE_PATH_CORE_SRCS) — "
      "calling it here would break the main test binary's link. The "
      "separate test-capture-path binary calls it directly." },
};
#define N_EXCLUDED (int)(sizeof(EXCLUDED) / sizeof(EXCLUDED[0]))

static const char *excluded_reason(const char *name) {
    for (int i = 0; i < N_EXCLUDED; i++)
        if (strcmp(EXCLUDED[i].name, name) == 0) return EXCLUDED[i].reason;
    return NULL;
}

static void test_every_declared_reset_is_registered(void) {
    name_set_t declared; declared.n = 0;
    int files_seen = 0;
    for (int i = 0; i < N_HDR_DIRS; i++)
        scan_header_dir(HDR_DIRS[i], &declared, &files_seen);
    /* A wrong path or an empty tree would otherwise pass this test by
     * checking nothing at all. */
    ASSERT_GE(files_seen, 30);
    ASSERT_GE(declared.n, 60);

    name_set_t registered; registered.n = 0;
    scan_sloth_resets(&registered);
    ASSERT_GE(registered.n, 60);

    for (int i = 0; i < declared.n; i++) {
        const char *name = declared.names[i];
        int ok = set_has(&registered, name) || excluded_reason(name) != NULL;
        if (!ok)
            fprintf(stderr,
                "    reset registry: %s is declared but neither in "
                "SLOTH_RESETS nor in tests/test_reset_registry.c's "
                "EXCLUDED list\n", name);
        ASSERT(ok);
    }

    /* Every documented exclusion must still be a real declaration —
     * otherwise a rename silently drops the only test coverage of it
     * rather than failing loudly. */
    for (int i = 0; i < N_EXCLUDED; i++)
        ASSERT(set_has(&declared, EXCLUDED[i].name));
}

/* main_test.c keeps two hand-written lists in sync by hand: a
 * `void run_X_tests(void);` prototype per test file and a call to it
 * inside main(). Forgetting the call is "caught by nothing" (#114) —
 * the prototype alone satisfies the compiler. This scrapes both lists
 * out of the one file that owns them and asserts they are the same
 * set, so a new test file that never gets wired up fails here instead
 * of silently contributing zero coverage. */
/* `suffix` (e.g. "_tests(void);") is split at its first '(' into an
 * identifier tail ("_tests") and a literal rest ("(void);"). The tail
 * is alnum/underscore, same as the identifier it follows, so a plain
 * greedy scan from after `prefix` swallows it as part of the name —
 * "run_parse_tests" reads as one token, not "run_" + "parse" + "_tests".
 * Scanning greedily first and then trimming the known tail off the end
 * (checked, not assumed) is what correctly recovers "parse". */
static void collect_idents_after(const char *path, const char *prefix,
                                  const char *suffix, name_set_t *out) {
    const char *paren = strchr(suffix, '(');
    size_t tail_len = paren ? (size_t)(paren - suffix) : strlen(suffix);
    const char *rest = paren ? paren : "";
    size_t rest_len = strlen(rest);

    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    size_t plen = strlen(prefix);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while ((p = strstr(p, prefix)) != NULL) {
            char *id_start = p + plen;
            char *q = id_start;
            while (isalnum((unsigned char)*q) || *q == '_') q++;
            size_t full_len = (size_t)(q - id_start);
            if (full_len > tail_len &&
                strncmp(q - tail_len, suffix, tail_len) == 0 &&
                strncmp(q, rest, rest_len) == 0) {
                size_t idlen = full_len - tail_len;
                if (idlen > 0 && idlen < NAME_LEN) {
                    char name[NAME_LEN];
                    memcpy(name, id_start, idlen);
                    name[idlen] = '\0';
                    set_add(out, name);
                }
            }
            p = id_start;
        }
    }
    fclose(f);
}

static void test_every_run_tests_fn_is_declared_and_called(void) {
    name_set_t declared; declared.n = 0;
    name_set_t called;   called.n   = 0;
    /* "void run_X_tests(void);" — prototypes near the top of main(). */
    collect_idents_after("tests/main_test.c", "void run_", "_tests(void);",
                         &declared);
    /* "run_X_tests();" — the call sites inside main(). Matched
     * separately from the prototype scan (suffix "_tests();" rather
     * than "_tests(void);") so the two lists come from genuinely
     * different line shapes, not the same regex twice. */
    collect_idents_after("tests/main_test.c", "run_", "_tests();", &called);

    ASSERT_GE(declared.n, 100);
    ASSERT_GE(called.n, 100);

    for (int i = 0; i < declared.n; i++) {
        if (!set_has(&called, declared.names[i]))
            fprintf(stderr,
                "    run_%s_tests is declared but never called from main()\n",
                declared.names[i]);
        ASSERT(set_has(&called, declared.names[i]));
    }
    for (int i = 0; i < called.n; i++) {
        if (!set_has(&declared, called.names[i]))
            fprintf(stderr,
                "    run_%s_tests is called but has no prototype\n",
                called.names[i]);
        ASSERT(set_has(&declared, called.names[i]));
    }
}

void run_reset_registry_tests(void) {
    TEST_SUITE("reset registry completeness (#114)");
    RUN_TEST(test_every_declared_reset_is_registered);
    RUN_TEST(test_every_run_tests_fn_is_declared_and_called);
}
