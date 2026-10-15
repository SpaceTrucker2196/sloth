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

#define RUNNER_SUMMARY() do { \
    printf("\n%d assertions passed, %d failed\n", g_pass, g_fail); \
} while (0)

#endif /* RUNNER_H */
