#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include "runner.h"

/*
 * Workflow action-pin guard — issue #95 ("pin actions", release
 * integrity).
 *
 * A `uses: actions/checkout@v4` reference resolves at run time to
 * whatever commit the `v4` tag points at *then*. Tags are mutable and
 * are moved by whoever controls that repository, not by us; an upstream
 * compromise or a hostile maintainer therefore executes arbitrary code
 * inside a job that holds a GITHUB_TOKEN. Pinning to the 40-hex commit
 * the tag resolved to at review time removes that: the digest is
 * content-addressed, so the code the reviewer looked at is the code the
 * runner gets. The tag survives as a trailing comment because a bare
 * digest tells a reader nothing about which release they are on.
 *
 * Why a test rather than a one-off sweep: pinning is not a state the
 * repo reaches once. Every new workflow, and every step copy-pasted
 * from documentation, arrives on a moving tag by default. A sweep is
 * undone by the next PR and nobody notices, because an unpinned action
 * works perfectly — right up until it doesn't.
 *
 * The directory is scanned, never a hardcoded file list: the case this
 * exists for is a workflow file that did not exist when the check was
 * written.
 *
 * Deliberately *not* checked: whether the digest is the newest release,
 * or that it exists at all. The suite is offline and must stay offline;
 * freshness is Dependabot's job, and a wrong digest fails CI loudly on
 * the first run.
 */

#define CP_DIR       ".github/workflows"
#define CP_MAX_REF   256

/* Floors, not exact counts — a scan that matches nothing passes every
 * "all of them are pinned" assertion vacuously. Six workflow files and
 * thirteen action references exist today; adding either only raises the
 * numbers. Removing one is a deliberate act and should be visible here. */
#define CP_MIN_FILES 6
#define CP_MIN_USES  13

typedef enum {
    USES_NONE,    /* not a `uses:` mapping key */
    USES_DIGEST,  /* pinned to a 40-hex commit */
    USES_TAG,     /* a mutable ref: tag, branch, short sha, or no ref */
    USES_LOCAL    /* ./path — same repo, same commit, nothing to pin */
} uses_kind_t;

static int is_hex40(const char *s) {
    int i;
    for (i = 0; i < 40; i++)
        if (!isxdigit((unsigned char)s[i])) return 0;
    return s[40] == '\0';
}

/*
 * Classify one line. `ref` receives the bare `uses:` value (comment and
 * surrounding space stripped); `tag_comment` receives the trailing
 * `# ...` text, or "" when the line carries none.
 */
static uses_kind_t classify_uses(const char *line, char *ref, size_t ref_sz,
                                 char *tag_comment, size_t tc_sz) {
    const char *p = line;
    const char *at;
    size_t n = 0;

    ref[0] = '\0';
    tag_comment[0] = '\0';

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '-' && (p[1] == ' ' || p[1] == '\t')) {       /* list item */
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (strncmp(p, "uses:", 5) != 0) return USES_NONE;      /* incl. `#` */
    p += 5;
    if (*p != ' ' && *p != '\t') return USES_NONE;
    while (*p == ' ' || *p == '\t') p++;

    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
        if (n + 1 < ref_sz) ref[n++] = *p;
        p++;
    }
    ref[n] = '\0';
    if (n == 0) return USES_TAG;

    /* YAML permits a quoted scalar. Strip one matching pair before
     * classifying: review found `uses: "owner/action@<40 hex>"` — a
     * correctly pinned line — reported as an unpinned tag, because the
     * closing quote landed inside the digest and failed is_hex40(). A
     * guard that fails valid input teaches people to delete the
     * guard. */
    if (n >= 2 && ((ref[0] == '"' && ref[n - 1] == '"') ||
                   (ref[0] == '\'' && ref[n - 1] == '\''))) {
        memmove(ref, ref + 1, n - 2);
        ref[n - 2] = '\0';
    }

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') {
        n = 0;
        while (*p && *p != '\n' && *p != '\r') {
            if (n + 1 < tc_sz) tag_comment[n++] = *p;
            p++;
        }
        while (n > 0 && (tag_comment[n - 1] == ' ' ||
                         tag_comment[n - 1] == '\t')) n--;
        tag_comment[n] = '\0';
    }

    if (ref[0] == '.' && ref[1] == '/') return USES_LOCAL;
    at = strrchr(ref, '@');
    if (!at) return USES_TAG;
    return is_hex40(at + 1) ? USES_DIGEST : USES_TAG;
}

/* A digest alone is unreadable, so the convention is a trailing
 * `# v1.2.3` naming what the digest was. Requiring merely "some #
 * comment" would pass `# pinned`, which is the claim without the
 * information — review caught that the first version asserted exactly
 * that. A digit anywhere in the comment is the floor: it admits
 * `# v4`, `# v4.2.2` and `# 2026-10-05`, and rejects a bare note. */
static int comment_names_a_version(const char *c) {
    if (!c || c[0] != '#') return 0;
    for (const char *p = c; *p; p++)
        if (*p >= '0' && *p <= '9') return 1;
    return 0;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    size_t got;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

static int is_workflow_file(const char *name) {
    size_t n = strlen(name);
    if (name[0] == '.') return 0;
    return (n > 4 && strcmp(name + n - 4, ".yml") == 0) ||
           (n > 5 && strcmp(name + n - 5, ".yaml") == 0);
}

/* Walks every workflow file, calling back per `uses:` line. Returns the
 * number of files read, or -1 if the directory could not be opened. */
typedef void (*uses_fn)(const char *file, int lineno, uses_kind_t kind,
                        const char *ref, const char *tag_comment);

/* Read one file, calling back per `uses:` line. Returns 1 if it was
   read. Split out of scan_workflows() so composite actions share it. */
static int scan_one(const char *path, uses_fn cb) {
    char ref[CP_MAX_REF], tc[CP_MAX_REF];
    char *buf = slurp(path), *line;
    int lineno = 0;
    if (!buf) return 0;
    line = buf;
    while (line && *line) {
        char *next = strchr(line, '\n');
        uses_kind_t k;
        if (next) *next++ = '\0';
        lineno++;
        k = classify_uses(line, ref, sizeof(ref), tc, sizeof(tc));
        if (k != USES_NONE) cb(path, lineno, k, ref, tc);
        line = next;
    }
    free(buf);
    return 1;
}

/* A composite action (.github/actions/<name>/action.yml) carries its
 * own `uses:` steps and is as capable as a workflow step, so leaving it
 * unscanned would be a hole in the guard rather than a gap in coverage.
 * None exists today; scanning the directory now means the first one
 * added is pinned on arrival instead of whenever someone remembers.
 * Review caught the omission. */
static int scan_composite_actions(uses_fn cb) {
    DIR *d = opendir(".github/actions");
    struct dirent *e;
    int files = 0;
    if (!d) return 0;                 /* absent is fine, not an error */
    while ((e = readdir(d)) != NULL) {
        char path[512];
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), ".github/actions/%.200s/action.yml",
                 e->d_name);
        files += scan_one(path, cb);
        snprintf(path, sizeof(path), ".github/actions/%.200s/action.yaml",
                 e->d_name);
        files += scan_one(path, cb);
    }
    closedir(d);
    return files;
}

static int scan_workflows(uses_fn cb) {
    DIR *d = opendir(CP_DIR);
    struct dirent *e;
    int files = 0;

    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        char path[512];
        if (!is_workflow_file(e->d_name)) continue;
        snprintf(path, sizeof(path), "%s/%.200s", CP_DIR, e->d_name);
        files += scan_one(path, cb);
    }
    closedir(d);
    files += scan_composite_actions(cb);
    return files;
}

/* Callback state — the scanner is a single pass, so results accumulate. */
static int g_uses_seen;
static int g_unpinned;
static int g_no_tag_comment;

static void tally(const char *file, int lineno, uses_kind_t kind,
                  const char *ref, const char *tag_comment) {
    g_uses_seen++;
    if (kind == USES_TAG) {
        g_unpinned++;
        fprintf(stderr, "    unpinned action %s:%d: %s\n", file, lineno, ref);
    }
    if (kind == USES_DIGEST && !comment_names_a_version(tag_comment)) {
        g_no_tag_comment++;
        fprintf(stderr, "    digest without tag comment %s:%d: %s\n",
                file, lineno, ref);
    }
}

/* Hand-written lines, not output of the scanner fed back to itself. */
static void test_classifier_separates_pinned_from_moving(void) {
    char ref[CP_MAX_REF], tc[CP_MAX_REF];

    ASSERT_EQ(classify_uses("      - uses: actions/checkout@v4", ref,
                            sizeof(ref), tc, sizeof(tc)), USES_TAG);
    ASSERT_STR(ref, "actions/checkout@v4");
    ASSERT_STR(tc, "");

    ASSERT_EQ(classify_uses("        uses: actions/checkout@"
                            "11d5960a326750d5838078e36cf38b85af677262"
                            "  # v4.4.0", ref, sizeof(ref), tc, sizeof(tc)),
              USES_DIGEST);
    ASSERT_STR(tc, "# v4.4.0");

    /* 39 hex digits: a truncated digest is ambiguous, so not a pin. */
    ASSERT_EQ(classify_uses("  uses: a/b@11d5960a326750d5838078e36cf38b85af67726",
                            ref, sizeof(ref), tc, sizeof(tc)), USES_TAG);
    /* Branch names can contain hex-looking text but are still mutable. */
    ASSERT_EQ(classify_uses("  uses: a/b@main", ref, sizeof(ref), tc,
                            sizeof(tc)), USES_TAG);
    ASSERT_EQ(classify_uses("  uses: a/b", ref, sizeof(ref), tc,
                            sizeof(tc)), USES_TAG);
    ASSERT_EQ(classify_uses("  uses: ./.github/actions/build", ref,
                            sizeof(ref), tc, sizeof(tc)), USES_LOCAL);

    /* Not mapping keys: a commented-out step and prose inside a script. */
    ASSERT_EQ(classify_uses("      # - uses: actions/checkout@v4", ref,
                            sizeof(ref), tc, sizeof(tc)), USES_NONE);
    ASSERT_EQ(classify_uses("          echo \"uses: nothing\"", ref,
                            sizeof(ref), tc, sizeof(tc)), USES_NONE);
    ASSERT_EQ(classify_uses("      - name: build", ref, sizeof(ref), tc,
                            sizeof(tc)), USES_NONE);
}

static void test_every_workflow_action_is_digest_pinned(void) {
    int files;
    g_uses_seen = g_unpinned = g_no_tag_comment = 0;
    files = scan_workflows(tally);

    ASSERT_GE(files, CP_MIN_FILES);          /* scan reached the files */
    ASSERT_GE(g_uses_seen, CP_MIN_USES);     /* and found the references */
    ASSERT_EQ(g_unpinned, 0);
    ASSERT_EQ(g_no_tag_comment, 0);
}

void run_ci_pin_tests(void) {
    TEST_SUITE("CI action pins (#95)");
    RUN_TEST(test_classifier_separates_pinned_from_moving);
    RUN_TEST(test_every_workflow_action_is_digest_pinned);
}
