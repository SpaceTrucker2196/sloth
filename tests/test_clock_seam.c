#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "runner.h"
#include "sloth_clock.h"

/* The clock seam (#109) and the migration off direct libc clock calls.
 *
 * A module that reads the libc clocks itself is one a test cannot
 * drive: its TTLs and windows age only in real time, and a value
 * stamped through the seam compared against one read from libc is the
 * exact bug the taint TTL had. The migration ran module by module
 * against a hand-kept list of files; once it completed, the list was
 * replaced by a walk of the whole of src/ (.c and .h — a static inline
 * in a header is a call site too), so a new file cannot regress by
 * simply not being on a list. src/sloth_clock.c is the one exemption,
 * and the walk asserts it found that file and saw the calls in it, so
 * the zero for everything else is not the zero of a walk that read
 * nothing. Same shape as the scrapers in test_docs_consistency.c:
 * read the source, count, assert. */

static char *slurp(const char *path) {
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

/* Occurrences of needle in hay, comments included: a comment quoting
 * the call reads as a call, and the file's own prose can say "libc
 * clock" instead. Strict beats clever here. */
static int cs_count(const char *hay, const char *needle) {
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += len) n++;
    return n;
}

/* The counter must see calls before its zero means anything. */
static int cs_count_wall(const char *src);
static void test_wall_counter_sees_every_spelling(void) {
    ASSERT_EQ(cs_count_wall("t = time(NULL);"), 1);
    ASSERT_EQ(cs_count_wall("t = time(0);"), 1);
    ASSERT_EQ(cs_count_wall("t = time( NULL );"), 1);
    ASSERT_EQ(cs_count_wall("time(&t);"), 1);
    ASSERT_EQ(cs_count_wall("gettimeofday(&tv, NULL);"), 1);
    ASSERT_EQ(cs_count_wall("timespec_get(&ts, TIME_UTC);"), 1);
    /* Not clock reads: other functions that end in "time". */
    ASSERT_EQ(cs_count_wall("localtime(&t); gmtime_r(&t, &tm); mktime(&tm);"), 0);
    ASSERT_EQ(cs_count_wall("strftime(b, n, f, tm); difftime(a, b);"), 0);
    ASSERT_EQ(cs_count_wall("t = sloth_wall();"), 0);
    /* Prose is not a call: comments and string literals are skipped. */
    ASSERT_EQ(cs_count_wall("/* one time(2) compare */ x();"), 0);
    ASSERT_EQ(cs_count_wall("// time(NULL) was here\n"), 0);
    ASSERT_EQ(cs_count_wall("f(\"%d time(s)\");"), 0);
    ASSERT_EQ(cs_count_wall("f(\"x\\\"y\"); t = time(0);"), 1);   /* escaped quote */
}

static void test_counter_sees_direct_clock_calls(void) {
    static const char src[] =
        "    time_t now = time(NULL);\n"
        "    /* was time(NULL) */\n"
        "    clock_gettime(CLOCK_MONOTONIC, &ts);\n";
    ASSERT_EQ(cs_count(src, "time(NULL)"), 2);
    ASSERT_EQ(cs_count(src, "clock_gettime("), 1);
    ASSERT_EQ(cs_count("    time_t now = sloth_wall();\n", "time(NULL)"), 0);
    ASSERT_EQ(cs_count("", "time(NULL)"), 0);
}

/* ── The tree walk ───────────────────────────────────────── */

#define CS_SEAM_FILE "src/sloth_clock.c"

typedef struct {
    int files;          /* .c / .h files read, the seam file included */
    int offenders;      /* files other than the seam with a libc call */
    int seam_seen;      /* the exempt file was found ... */
    int seam_wall;      /* ... and the counter saw its calls */
    int seam_mono;
    int saw_subdir;     /* a file below src/<dir>/ was read */
} cs_walk_t;

static int cs_is_source(const char *name) {
    size_t n = strlen(name);
    return n > 2 && name[n - 2] == '.' &&
           (name[n - 1] == 'c' || name[n - 1] == 'h');
}

/* Any libc wall-clock read, however spelled: `time(` as a standalone
 * identifier with any argument - time(NULL), time(0), time( NULL ),
 * time(&t) - plus gettimeofday( and timespec_get(. The first version
 * matched the literal "time(NULL)" only; the #109 review changed
 * seqnum.c to time(0) and the walk stayed green. localtime(, gmtime(,
 * mktime( and the like are not reads of the clock and are skipped by
 * requiring a non-identifier character before `time`. */
static int cs_is_ident(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}
/* Code only: comments and string/char literals blanked to spaces, so
 * prose such as "time(2)" or an alert detail reading "%d time(s)" is
 * not a call. Newlines are kept so nothing else shifts. */
static char *cs_code_only(const char *src) {
    size_t n = strlen(src);
    char *o = malloc(n + 1);
    if (!o) return NULL;
    size_t i = 0;
    while (i < n) {
        if (src[i] == '/' && src[i + 1] == '*') {
            o[i] = o[i + 1] = ' '; i += 2;
            while (i < n && !(src[i] == '*' && src[i + 1] == '/')) { o[i] = src[i] == '\n' ? '\n' : ' '; i++; }
            if (i < n) { o[i] = o[i + 1] = ' '; i += 2; }
        } else if (src[i] == '/' && src[i + 1] == '/') {
            while (i < n && src[i] != '\n') o[i++] = ' ';
        } else if (src[i] == '"' || src[i] == '\'') {
            char q = src[i]; o[i++] = ' ';
            while (i < n && src[i] != q) {
                if (src[i] == '\\' && i + 1 < n) { o[i++] = ' '; }
                o[i] = src[i] == '\n' ? '\n' : ' '; i++;
            }
            if (i < n) o[i++] = ' ';
        } else { o[i] = src[i]; i++; }
    }
    o[n] = '\0';
    return o;
}

static int cs_count_wall(const char *src) {
    char *c = cs_code_only(src);
    if (!c) return -1;
    int n = 0;
    for (const char *p = strstr(c, "time("); p; p = strstr(p + 1, "time("))
        if (p == c || !cs_is_ident(p[-1])) n++;
    n += cs_count(c, "gettimeofday(") + cs_count(c, "timespec_get(");
    free(c);
    return n;
}

static void cs_check_file(const char *path, cs_walk_t *w) {
    char *src = slurp(path);
    ASSERT(src != NULL);
    if (!src) {
        fprintf(stderr, "    cannot read %s\n", path);
        return;
    }
    w->files++;
    if (strchr(path + 4, '/')) w->saw_subdir = 1;   /* past "src/" */
    int wall = cs_count_wall(src);
    int mono = cs_count(src, "clock_gettime(");
    if (strcmp(path, CS_SEAM_FILE) == 0) {
        w->seam_seen = 1;
        w->seam_wall = wall;
        w->seam_mono = mono;
    } else if (wall || mono) {
        w->offenders++;
        fprintf(stderr, "    %s reads libc directly: %d wall reads (time()/gettimeofday/timespec_get), "
                        "%d clock_gettime(); use sloth_wall() / "
                        "sloth_mono_ms()\n", path, wall, mono);
    }
    free(src);
}

static void cs_walk(const char *dir, cs_walk_t *w, int depth) {
    if (depth > 8) return;
    DIR *d = opendir(dir);
    ASSERT(d != NULL);
    if (!d) {
        fprintf(stderr, "    cannot open %s (run from the repo root)\n", dir);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))
            cs_walk(path, w, depth + 1);
        else if (S_ISREG(st.st_mode) && cs_is_source(e->d_name))
            cs_check_file(path, w);
    }
    closedir(d);
}

/* #109's acceptance: no file under src/ but the seam reads a libc
 * clock. The floor of 300 files is below today's 341 and far above
 * any walk that silently stopped at the top directory. */
static void test_no_file_under_src_reads_libc_clocks(void) {
    cs_walk_t w;
    memset(&w, 0, sizeof(w));
    cs_walk("src", &w, 0);
    ASSERT(w.files >= 300);
    ASSERT(w.saw_subdir);
    ASSERT(w.seam_seen);
    ASSERT(w.seam_wall >= 1);
    ASSERT(w.seam_mono >= 1);
    ASSERT_EQ(w.offenders, 0);
}

/* ── The seam itself ─────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t fake_mono(void) { return g_mono; }
static time_t   fake_wall(void) { return g_wall; }

#define WALL0 ((time_t)1500000000)

static void test_real_clocks_by_default(void) {
    sloth_clock_test_set(NULL, NULL);
    time_t libc = time(NULL);
    time_t wall = sloth_wall();
    ASSERT(wall - libc >= -1 && wall - libc <= 1);
    uint64_t a = sloth_mono_ms();
    uint64_t b = sloth_mono_ms();
    ASSERT(b >= a);
}

/* A fake monotonic value no real clock can produce: CLOCK_MONOTONIC in
 * milliseconds since boot would need ~290 million years to get here, so
 * "the value is not the sentinel" proves the real clock is back without
 * assuming anything about how long the host has been up. The first
 * version of this test asserted real > 123456 ms, i.e. uptime over two
 * minutes, and a fresh CI runner failed it under TSan on 2026-10-15. */
#define MONO_SENTINEL (UINT64_MAX - 1)

static void test_test_set_swaps_and_null_restores(void) {
    g_mono = MONO_SENTINEL; g_wall = WALL0;
    sloth_clock_test_set(fake_mono, fake_wall);
    ASSERT_EQ(sloth_mono_ms(), MONO_SENTINEL);
    ASSERT_EQ((long)sloth_wall(), (long)WALL0);
    g_wall = WALL0 + 7;
    ASSERT_EQ((long)sloth_wall(), (long)(WALL0 + 7));
    /* Each clock restores independently: mono is real again (not the
     * sentinel, plausible magnitude, non-decreasing) while wall is still
     * the fake. */
    sloth_clock_test_set(NULL, fake_wall);
    uint64_t m1 = sloth_mono_ms();
    uint64_t m2 = sloth_mono_ms();
    ASSERT(m1 != MONO_SENTINEL);
    ASSERT(m1 < UINT64_MAX / 2);
    ASSERT(m2 >= m1);
    ASSERT_EQ((long)sloth_wall(), (long)(WALL0 + 7));
    sloth_clock_test_set(NULL, NULL);
    time_t libc = time(NULL);
    time_t wall = sloth_wall();
    ASSERT(wall - libc >= -1 && wall - libc <= 1);
}

/* The rate code (bandwidth, interface counters) divides a counter
 * delta by elapsed seconds taken from sloth_mono_ts(). It must be the
 * same clock as sloth_mono_ms(), split on the millisecond, or an
 * injected clock would move one and not the other. 12345 ms is chosen
 * so both the seconds and the sub-second part are non-zero and a
 * swapped or mis-scaled field cannot pass. */
static void test_mono_ts_is_mono_ms_split(void) {
    g_mono = 12345; g_wall = WALL0;
    sloth_clock_test_set(fake_mono, fake_wall);
    struct timespec ts = { 0, 0 };
    sloth_mono_ts(&ts);
    ASSERT_EQ((long)ts.tv_sec, 12L);
    ASSERT_EQ((long)ts.tv_nsec, 345000000L);
    g_mono = 999;
    sloth_mono_ts(&ts);
    ASSERT_EQ((long)ts.tv_sec, 0L);
    ASSERT_EQ((long)ts.tv_nsec, 999000000L);
    sloth_clock_test_set(NULL, NULL);
}

void run_clock_seam_tests(void) {
    TEST_SUITE("clock seam (#109)");
    RUN_TEST(test_counter_sees_direct_clock_calls);
    RUN_TEST(test_wall_counter_sees_every_spelling);
    RUN_TEST(test_no_file_under_src_reads_libc_clocks);
    RUN_TEST(test_real_clocks_by_default);
    RUN_TEST(test_test_set_swaps_and_null_restores);
    RUN_TEST(test_mono_ts_is_mono_ms_split);
    sloth_clock_test_set(NULL, NULL);
}
