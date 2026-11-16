#ifndef RUNNER_H
#define RUNNER_H

#include <stdio.h>
#include <string.h>

/* Defined once in main_test.c */
extern int g_pass;
extern int g_fail;
extern int g_test_fail;   /* failures within the current test */
extern int g_test_total;  /* assertions executed within the current test —
                            * a test that never moves this off zero proves
                            * nothing, however many times it "passes" (#114) */

/* Called once before each RUN_TEST, if registered. NULL means no
 * default setUp. main_test.c points this at sloth_reset_all() plus a
 * clock-seam reset so no individual test has to remember either. */
extern void (*g_test_setup)(void);

/* Called once after each RUN_TEST, if registered. main_test.c points
 * this at sloth_reset_all() — the same registry setUp runs, run again
 * on the way out so a module's own long-lived descriptor is released
 * inside the case that opened it and not at the start of the next one.
 * #114 took module state off the test author; this is the matching
 * half, and it is what makes the descriptor guard below honest. */
extern void (*g_test_teardown)(void);

/* The descriptor-leak guard (#209), defined in main_test.c over
 * tests/fd_guard.h. fd_guard_enter() samples the open-descriptor count
 * at a case's entry — before setUp, so a descriptor the shared setup
 * leaves open is the shared setup's finding and not silently every
 * test's. fd_guard_check() samples it again after the teardown above,
 * so what it reports is a descriptor NOTHING releases: a test's own
 * forgotten mkstemp fd or socket, which accumulates for the rest of the
 * run, rather than a module descriptor the registry owns. When the
 * count did not come back it prints the case's name with what is new
 * and fails the suite. Returns the signed delta. Declared here rather
 * than in fd_guard.h so a test file need not include the guard to be
 * measured by it. */
void fd_guard_enter(void);
int  fd_guard_check(const char *name);

#define ASSERT(cond) do { \
    g_test_total++; \
    if (cond) { \
        g_pass++; \
    } else { \
        fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_fail++; g_test_fail++; \
    } \
} while (0)

#define ASSERT_EQ(a, b)  ASSERT((a) == (b))
#define ASSERT_NE(a, b)  ASSERT((a) != (b))
#define ASSERT_GT(a, b)  ASSERT((a) >  (b))
#define ASSERT_GE(a, b)  ASSERT((a) >= (b))
#define ASSERT_LT(a, b)  ASSERT((a) <  (b))
#define ASSERT_STR(a, b) ASSERT(strcmp((a), (b)) == 0)

#define ASSERT_NEAR(a, b, tol) ASSERT(((a)-(b)) > -(tol) && ((a)-(b)) < (tol))

#define RUN_TEST(fn) do { \
    g_test_fail = 0; \
    g_test_total = 0; \
    fd_guard_enter(); \
    if (g_test_setup) g_test_setup(); \
    fn(); \
    if (g_test_total == 0) { \
        fprintf(stderr, "    FAIL %s: zero assertions executed\n", #fn); \
        g_fail++; g_test_fail++; \
    } \
    if (g_test_teardown) g_test_teardown(); \
    fd_guard_check(#fn); \
    printf("  [%s] %s\n", g_test_fail == 0 ? "pass" : "FAIL", #fn); \
} while (0)

#define TEST_SUITE(name) printf("\n%s\n", name)

/* Places a sloth_state_t in static storage instead of on the stack.
 * sloth_state_t is 2.2 MB; a stack declaration in every test function
 * is 1,300+ copies of that frame size across the suite (#114). Static
 * storage is zeroed at load time, not per-call, so callers that rely on
 * a fresh zeroed struct must still memset it themselves (RUN_TEST's
 * setUp does this for state sloth_reset_all knows about; the struct's
 * own fields are the test's responsibility, same as before). */
#define TEST_STATE(name) static sloth_state_t name

/* ── Rendered-output assertions (#116) ───────────────────────
 * The suite draws into an offscreen ncurses screen of this size, opened
 * by main_test.c and re-cleared before every test. A view test asserts on
 * what landed in the cells, not on having returned: a draw that prints
 * nothing passes ASSERT(1) and fails these. Declared here rather than by
 * including tui.h so runner.h stays includable from any test. */
#define TEST_SCREEN_ROWS 120
#define TEST_SCREEN_COLS 220

int  tui_test_line(int y, char *out, size_t n);
int  tui_test_screen(char *out, size_t n);
int  tui_test_rows(void);
int  tui_test_is_reverse(int y, int x);
int  tui_test_pair(int y, int x);
void tui_test_erase(void);
void tui_test_dump(FILE *fp);
int  tui_test_overflow(void);

static inline int runner_line_has(int y, const char *needle) {
    char line[4096];
    if (tui_test_line(y, line, sizeof(line)) < 0) return 0;
    return strstr(line, needle) != NULL;
}

/* Row of the first line containing `needle`, or -1. */
static inline int runner_screen_find(const char *needle) {
    char line[4096];
    int rows = tui_test_rows();
    for (int y = 0; y < rows; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) return -1;
        if (strstr(line, needle)) return y;
    }
    return -1;
}

/* Screen column of `needle` on row y, or -1. A column is a cell, so
 * UTF-8 continuation bytes before the match are not counted; every
 * glyph sloth draws is one cell wide. */
static inline int runner_find_col(int y, const char *needle) {
    char line[4096];
    if (tui_test_line(y, line, sizeof(line)) < 0) return -1;
    const char *hit = strstr(line, needle);
    if (!hit) return -1;
    int col = 0;
    for (const char *p = line; p < hit; p++)
        if (((unsigned char)*p & 0xC0) != 0x80) col++;
    return col;
}

#define RUNNER_SCREEN_FAIL(what, needle) do { \
    fprintf(stderr, "    FAIL %s:%d: %s \"%s\"; screen was:\n", \
            __FILE__, __LINE__, what, needle); \
    tui_test_dump(stderr); \
} while (0)

#define ASSERT_LINE_HAS(y, needle) do { \
    g_test_total++; \
    if (runner_line_has((y), (needle))) { g_pass++; } else { \
        RUNNER_SCREEN_FAIL("row " #y " lacks", needle); \
        g_fail++; g_test_fail++; \
    } \
} while (0)

#define ASSERT_SCREEN_HAS(needle) do { \
    g_test_total++; \
    if (runner_screen_find(needle) >= 0) { g_pass++; } else { \
        RUNNER_SCREEN_FAIL("screen lacks", needle); \
        g_fail++; g_test_fail++; \
    } \
} while (0)

#define ASSERT_SCREEN_LACKS(needle) do { \
    g_test_total++; \
    if (runner_screen_find(needle) < 0) { g_pass++; } else { \
        RUNNER_SCREEN_FAIL("screen unexpectedly has", needle); \
        g_fail++; g_test_fail++; \
    } \
} while (0)

#define RUNNER_SUMMARY() do { \
    printf("\n%d assertions passed, %d failed\n", g_pass, g_fail); \
} while (0)

#endif /* RUNNER_H */
