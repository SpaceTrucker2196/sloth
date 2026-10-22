/* slothweb's own assertion harness. web/ includes nothing from tests/,
 * so sloth's suite and this one can change independently. */
#ifndef SLOTHWEB_WTEST_H
#define SLOTHWEB_WTEST_H

#include <stdio.h>
#include <string.h>

extern int wt_pass, wt_fail;

#define WT_ASSERT(c) do {                                              \
        if (c) wt_pass++;                                              \
        else { wt_fail++;                                              \
               fprintf(stderr, "  FAIL %s:%d: %s\n",                   \
                       __FILE__, __LINE__, #c); }                      \
    } while (0)

#define WT_EQ(a, b) do {                                               \
        long long wt_a = (long long)(a), wt_b = (long long)(b);        \
        if (wt_a == wt_b) wt_pass++;                                   \
        else { wt_fail++;                                              \
               fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", \
                       __FILE__, __LINE__, #a, #b, wt_a, wt_b); }      \
    } while (0)

#define WT_HAS(hay, needle) do {                                       \
        const char *wt_h = (hay);                                      \
        if (wt_h && strstr(wt_h, (needle))) wt_pass++;                 \
        else { wt_fail++;                                              \
               fprintf(stderr, "  FAIL %s:%d: \"%s\" not in output\n", \
                       __FILE__, __LINE__, (needle)); }                \
    } while (0)

#define WT_LACKS(hay, needle) do {                                     \
        const char *wt_h = (hay);                                      \
        if (!wt_h || !strstr(wt_h, (needle))) wt_pass++;               \
        else { wt_fail++;                                              \
               fprintf(stderr, "  FAIL %s:%d: \"%s\" unexpectedly in output\n", \
                       __FILE__, __LINE__, (needle)); }                \
    } while (0)

#define WT_RUN(fn) do { fprintf(stderr, "%s\n", #fn); fn(); } while (0)

void run_acl_tests(void);
void run_config_tests(void);
void run_http_tests(void);
void run_routes_tests(void);
void run_server_tests(void);
void run_json_tests(void);
void run_jsonl_tests(void);
void run_live_tests(void);
void run_ingest_tests(void);
void run_rollup_tests(void);
void run_metrics_tests(void);
void run_store_tests(void);
void run_series_tests(void);
void run_baseline_tests(void);
void run_ident_tests(void);
void run_anomaly_tests(void);
void run_replay_tests(void);

#endif
