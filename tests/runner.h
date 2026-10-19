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
    if (g_test_setup) g_test_setup(); \
    fn(); \
    if (g_test_total == 0) { \
        fprintf(stderr, "    FAIL %s: zero assertions executed\n", #fn); \
        g_fail++; g_test_fail++; \
    } \
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
void tui_test_erase(void);
void tui_test_dump(FILE *fp);

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
