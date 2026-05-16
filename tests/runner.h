#ifndef RUNNER_H
#define RUNNER_H

#include <stdio.h>
#include <string.h>

/* Defined once in main_test.c */
extern int g_pass;
extern int g_fail;
extern int g_test_fail;  /* failures within the current test */

#define ASSERT(cond) do { \
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
    fn(); \
    printf("  [%s] %s\n", g_test_fail == 0 ? "pass" : "FAIL", #fn); \
} while (0)

#define TEST_SUITE(name) printf("\n%s\n", name)

#define RUNNER_SUMMARY() do { \
    printf("\n%d assertions passed, %d failed\n", g_pass, g_fail); \
} while (0)

#endif /* RUNNER_H */
