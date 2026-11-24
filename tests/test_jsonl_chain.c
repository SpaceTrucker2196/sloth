/* The -o hash chain and sloth --verify (#251 part 1, src/jsonl_chain.h).
 *
 * The chain is written through the real sink (jsonl_open(),
 * jsonl_emit_line(), jsonl_close()) into a temporary file and read back
 * with the verifier; the expected bytes are built here from
 * sha256_hex() over strings this file assembles, not by the writer, so
 * a writer and a verifier that agree on a wrong hash do not pass. The
 * shell cross-check (sha256sum over the lines) is in
 * docs/wiki/record-integrity.md; `make replay-check` runs the binary.
 *
 * The evidence-directory half builds a manifest by hand, in the #92
 * format (docs/wiki/pcap-export.md section 5). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "runner.h"
#include "jsonl.h"
#include "jsonl_chain.h"
#include "jsonl_internal.h"
#include "sha256.h"
#include "sloth_clock.h"
#include "tmp_dir.h"

#define T0 1700000000

static time_t fixed_wall(void) { return (time_t)T0; }
static uint64_t fixed_mono(void) { return 1000; }

static char g_dir[TEST_TMP_MAX];

static int setup(void) {
    g_dir[0] = '\0';
    if (!mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_jc_XXXXXX"))) {
        g_dir[0] = '\0';
        return -1;
    }
    sloth_clock_test_set(fixed_mono, fixed_wall);
    return 0;
}

static void teardown(void) {
    jsonl_close();
    jsonl_chain_set(0);
    sloth_clock_test_set(NULL, NULL);
    if (g_dir[0]) test_rm_tree(g_dir);
    g_dir[0] = '\0';
}

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap + 1);
    size_t r;
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (b) b[n] = '\0';
    *len = n;
    return b;
}

static int spit(const char *path, const char *bytes, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(bytes, 1, n, f) == n;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

static void verify_path(const char *path, jc_verify_t *v) {
    FILE *f = fopen(path, "rb");
    jc_verify_stream(f, v);
    if (f) fclose(f);
}

static const char *LINES[7] = {
    "{\"type\":\"a\",\"ts\":1,\"n\":1}",
    "{\"type\":\"b\",\"ts\":2,\"s\":\"x\"}",
    "{\"type\":\"c\",\"ts\":3}",
    "{\"type\":\"a\",\"ts\":4,\"n\":4}",
    "{\"type\":\"d\",\"ts\":5,\"k\":[1,2]}",
    "{\"type\":\"e\",\"ts\":6}",
    "{\"type\":\"a\",\"ts\":7,\"n\":7}",
};

/* What the file must hold for LINES under --jsonl-chain 3, built from
 * the record's definition: genesis, three blocks of 3, 3 and 1 (the
 * last sealed at close). */
static size_t expected_file(char *out, size_t cap) {
    static const char Z[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char empty[65], prev[65], blk[65];
    sha256_hex((const uint8_t *)"", 0, empty);
    size_t o = 0;
    char rec[JC_RECORD_MAX + 2];
    int n = snprintf(rec, sizeof(rec), "{\"type\":\"chain\",\"ts\":%d,\"v\":1,"
                     "\"seq\":1,\"lines\":0,\"block_sha256\":\"%s\","
                     "\"prev_sha256\":\"%s\"}\n", T0, empty, Z);
    memcpy(out + o, rec, (size_t)n); o += (size_t)n;
    sha256_hex((const uint8_t *)rec, (size_t)n, prev);
    static const int sizes[3] = { 3, 3, 1 };
    int li = 0;
    for (int b = 0; b < 3; b++) {
        size_t start = o;
        for (int k = 0; k < sizes[b]; k++) {
            size_t l = strlen(LINES[li]);
            memcpy(out + o, LINES[li], l); o += l;
            out[o++] = '\n';
            li++;
        }
        sha256_hex((const uint8_t *)out + start, o - start, blk);
        n = snprintf(rec, sizeof(rec), "{\"type\":\"chain\",\"ts\":%d,\"v\":1,"
                     "\"seq\":%d,\"lines\":%d,\"block_sha256\":\"%s\","
                     "\"prev_sha256\":\"%s\"}\n", T0, b + 2, sizes[b], blk, prev);
        memcpy(out + o, rec, (size_t)n); o += (size_t)n;
        sha256_hex((const uint8_t *)rec, (size_t)n, prev);
    }
    (void)cap;
    return o;
}

static void write_chained(const char *path, unsigned n, int lines) {
    jsonl_chain_set(n);
    ASSERT_EQ(jsonl_open(path), 1);
    for (int i = 0; i < lines; i++) jsonl_emit_line(LINES[i]);
    jsonl_close();
}

/* The writer's bytes are the record's definition, byte for byte. */
static void test_writer_matches_the_definition(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/c.jsonl", g_dir);
    write_chained(path, 3, 7);
    size_t n = 0;
    char *got = slurp(path, &n);
    static char want[8192];
    size_t wn = expected_file(want, sizeof(want));
    ASSERT(got != NULL);
    ASSERT_EQ(n, wn);
    if (got && n == wn) ASSERT(memcmp(got, want, n) == 0);
    free(got);

    jc_verify_t v;
    verify_path(path, &v);
    ASSERT_EQ(v.status, 0);
    ASSERT_EQ(v.records, 4u);
    ASSERT_EQ(v.segments, 1u);
    ASSERT_EQ(v.blocks, 3u);
    ASSERT_EQ(v.head_seq, 4u);
    ASSERT_EQ(v.head_line, 11u);
    ASSERT_EQ(v.pending, 0u);
    ASSERT_EQ(v.uncovered, 0u);
    /* The head a report prints is the head --verify finds. */
    unsigned long long seq = 0;
    char hex[65];
    ASSERT_EQ(jsonl_chain_head(&seq, hex), 0);   /* closed: no head to give */
    teardown();
}

/* The issue's acceptance: one byte changed in the file, and --verify
 * names the block that holds it. */
static void test_one_byte_names_the_block(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/c.jsonl", g_dir);
    write_chained(path, 3, 7);
    size_t n = 0;
    char *b = slurp(path, &n);
    ASSERT(b != NULL);
    if (!b) { teardown(); return; }
    /* LINES[4] is the second line of the second block (seq 3). */
    char *p = strstr(b, "\"k\":[1,2]");
    ASSERT(p != NULL);
    if (p) p[6] = '3';
    ASSERT_EQ(spit(path, b, n), 0);
    free(b);
    jc_verify_t v;
    verify_path(path, &v);
    ASSERT_EQ(v.status, 1);
    ASSERT_EQ(v.brk_segment, 1u);
    ASSERT_EQ(v.brk_seq, 3u);
    ASSERT_EQ(v.brk_first, 6u);     /* genesis, 3 lines, a record, then these */
    ASSERT_EQ(v.brk_last, 8u);
    ASSERT_EQ(v.head_seq, 2u);      /* intact up to the first block's record */
    ASSERT(strstr(v.brk_what, "block_sha256") != NULL);

    /* And the command says so in words. */
    char out[TEST_TMP_MAX + 16];
    snprintf(out, sizeof(out), "%s/verify.txt", g_dir);
    FILE *o = fopen(out, "w");
    ASSERT(o != NULL);
    if (o) {
        ASSERT_EQ(jc_verify_main(path, o), 1);
        fclose(o);
        size_t tn = 0;
        char *t = slurp(out, &tn);
        ASSERT(t && strstr(t, "segment 1 block 3 (lines 6-8)") != NULL);
        ASSERT(t && strstr(t, "result: break") != NULL);
        free(t);
    }
    teardown();
}

/* Every single-byte change anywhere before the head's line is a break.
 * The head's own line is covered by nothing after it: a change there
 * either breaks or moves the head --verify prints, which is why a
 * report prints it. Both halves counted. */
static void test_every_byte(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/c.jsonl", g_dir);
    write_chained(path, 3, 7);
    size_t n = 0;
    char *orig = slurp(path, &n);
    ASSERT(orig != NULL);
    if (!orig) { teardown(); return; }
    jc_verify_t v0;
    verify_path(path, &v0);
    ASSERT_EQ(v0.status, 0);
    /* Where the head's line starts, less the newline before it: that
     * byte changed joins the last block's last line to the head, which
     * then reads as a pending line after an earlier head. */
    size_t head_at = n - 1;
    while (head_at > 0 && orig[head_at - 1] != '\n') head_at--;
    head_at--;
    char *b = malloc(n);
    int missed = 0, head_seen = 0;
    for (size_t i = 0; b && i < n; i++) {
        memcpy(b, orig, n);
        b[i] ^= 0x01;
        if (spit(path, b, n) != 0) { missed++; continue; }
        jc_verify_t v;
        verify_path(path, &v);
        if (i < head_at) {
            if (v.status != 1) {
                fprintf(stderr, "    byte %zu (0x%02x) not caught\n", i,
                        (unsigned char)orig[i]);
                missed++;
            }
        } else if (v.status != 1 && strcmp(v.head_sha, v0.head_sha) == 0) {
            missed++;
        } else {
            head_seen++;
        }
    }
    ASSERT_EQ(missed, 0);
    ASSERT_EQ((size_t)head_seen, n - head_at);
    free(b);
    free(orig);
    teardown();
}

/* With the chain off the file is the records and nothing else: the
 * claim of "byte-identical". Seen red with jsonl_open() writing the
 * genesis whatever g_chain_n is. */
static void test_off_is_byte_identical(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/plain.jsonl", g_dir);
    write_chained(path, 0, 7);
    size_t n = 0;
    char *got = slurp(path, &n);
    char want[2048];
    size_t o = 0;
    for (int i = 0; i < 7; i++) {
        size_t l = strlen(LINES[i]);
        memcpy(want + o, LINES[i], l); o += l;
        want[o++] = '\n';
    }
    ASSERT(got != NULL);
    ASSERT_EQ(n, o);
    if (got && n == o) ASSERT(memcmp(got, want, n) == 0);
    free(got);
    ASSERT_EQ(jsonl_chain_enabled(), 0);
    jc_verify_t v;
    verify_path(path, &v);
    ASSERT_EQ(v.status, 2);          /* nothing to verify, said so */
    ASSERT_EQ(v.uncovered, 7u);
    teardown();
}

/* The file is appended across runs: each run is a segment, and what lies
 * between (a crash tail) is counted as not covered, never as a break. */
static void test_segments_and_pending(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/c.jsonl", g_dir);
    write_chained(path, 3, 4);
    /* A crash tail: two records no chain record follows. */
    FILE *f = fopen(path, "ab");
    ASSERT(f != NULL);
    if (f) { fputs(LINES[5], f); fputc('\n', f); fputs(LINES[6], f); fputc('\n', f); fclose(f); }
    /* The next run, which then crashes with two lines pending. */
    jsonl_chain_set(3);
    ASSERT_EQ(jsonl_open(path), 1);
    jsonl_emit_line(LINES[0]);
    jsonl_emit_line(LINES[1]);
    unsigned long long seq = 0;
    char hex[65];
    /* A report's head seals the pending block, so it names a line that
     * is in the file. */
    ASSERT_EQ(jsonl_chain_head(&seq, hex), 1);
    ASSERT_EQ(seq, 2ull);
    jsonl_emit_line(LINES[2]);
    jsonl_close();                   /* seals LINES[2]: seq 3 */
    /* Then a line the next seal never came for. */
    f = fopen(path, "ab");
    ASSERT(f != NULL);
    if (f) { fputs(LINES[3], f); fputc('\n', f); fclose(f); }
    jc_verify_t v;
    verify_path(path, &v);
    ASSERT_EQ(v.status, 0);
    ASSERT_EQ(v.segments, 2u);
    ASSERT_EQ(v.uncovered, 2u);
    ASSERT_EQ(v.uncovered_first, 8u);
    ASSERT_EQ(v.pending, 1u);
    ASSERT_EQ(v.head_segment, 2u);
    ASSERT_EQ(v.head_seq, 3u);
    ASSERT_EQ(v.head_line, 15u);
    /* The head the report was given is line 13, a line in the file. */
    size_t n = 0;
    char *b = slurp(path, &n);
    const char *ln = b;
    for (int k = 1; ln && k < 13; k++) { ln = strchr(ln, '\n'); if (ln) ln++; }
    const char *end = ln ? strchr(ln, '\n') : NULL;
    ASSERT(end != NULL);
    if (end) {
        char h13[65];
        sha256_hex((const uint8_t *)ln, (size_t)(end + 1 - ln), h13);
        ASSERT_STR(h13, hex);
    }
    free(b);
    teardown();
}

/* A removed line, and a removed block with its record. */
static void test_removals(void) {
    if (setup() != 0) { ASSERT(0); return; }
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/c.jsonl", g_dir);
    write_chained(path, 3, 7);
    size_t n = 0;
    char *b = slurp(path, &n);
    ASSERT(b != NULL);
    if (!b) { teardown(); return; }
    /* Line 3 (LINES[1]) out. */
    char *p = strstr(b, LINES[1]);
    size_t l = strlen(LINES[1]) + 1;
    ASSERT(p != NULL);
    if (p) {
        char *c = malloc(n);
        size_t k = (size_t)(p - b);
        memcpy(c, b, k);
        memcpy(c + k, p + l, n - k - l);
        ASSERT_EQ(spit(path, c, n - l), 0);
        jc_verify_t v;
        verify_path(path, &v);
        ASSERT_EQ(v.status, 1);
        ASSERT_EQ(v.brk_seq, 2u);
        ASSERT(strstr(v.brk_what, "covers 3 lines, the file holds 2") != NULL);
        free(c);
    }
    /* The second block and its record (lines 6-9) out: the next
     * record's prev no longer names the record before it. */
    char *s2 = strstr(b, LINES[3]);
    char *e2 = s2 ? strstr(s2, "\"seq\":3,") : NULL;
    char *e2n = e2 ? strchr(e2, '\n') : NULL;
    ASSERT(e2n != NULL);
    if (s2 && e2n) {
        size_t k = (size_t)(s2 - b), cut = (size_t)(e2n + 1 - s2);
        char *c = malloc(n);
        memcpy(c, b, k);
        memcpy(c + k, e2n + 1, n - k - cut);
        ASSERT_EQ(spit(path, c, n - cut), 0);
        jc_verify_t v;
        verify_path(path, &v);
        ASSERT_EQ(v.status, 1);
        ASSERT_EQ(v.brk_seq, 4u);
        ASSERT(strstr(v.brk_what, "seq 4 follows seq 2") != NULL);
        free(c);
    }
    free(b);
    teardown();
}

static void test_parse_block(void) {
    unsigned n = 0;
    char err[96];
    ASSERT_EQ(jc_parse_block("1", &n, err, sizeof(err)), 0);
    ASSERT_EQ(n, 1u);
    ASSERT_EQ(jc_parse_block("100000", &n, err, sizeof(err)), 0);
    ASSERT_EQ(n, 100000u);
    ASSERT_EQ(jc_parse_block("100001", &n, err, sizeof(err)), -1);
    ASSERT_EQ(jc_parse_block("0", &n, err, sizeof(err)), -1);
    ASSERT_EQ(jc_parse_block("", &n, err, sizeof(err)), -1);
    ASSERT_EQ(jc_parse_block("12x", &n, err, sizeof(err)), -1);
    ASSERT_EQ(jc_parse_block("-3", &n, err, sizeof(err)), -1);
    ASSERT(strstr(err, "1..100000") != NULL);
}

/* ── --verify on an evidence directory ───────────────────────────── */

static void put_file(const char *dir, const char *name, const char *body) {
    char p[TEST_TMP_MAX + 96];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    ASSERT_EQ(spit(p, body, strlen(body)), 0);
}

static void manifest_line(char *out, size_t cap, int seq, const char *file,
                          const char *body) {
    char hex[65];
    sha256_hex((const uint8_t *)body, strlen(body), hex);
    snprintf(out, cap, "{\"v\":1,\"session\":\"20231114T221320Z-0000000000000001\","
             "\"seq\":%d,\"file\":\"%s\",\"size\":%zu,\"sha256\":\"%s\","
             "\"sink\":\"alert_pcap\",\"incident_id\":\"22bdad5846ecd3fb\","
             "\"rule\":\"THREAT_IP\",\"reconstructed\":false,"
             "\"written_at\":\"2023-11-14T22:13:20Z\",\"written_at_epoch\":1700000000}\n",
             seq, file, strlen(body), hex);
}

#define MF_NAME "sloth-manifest-20231114T221320Z-0000000000000001.jsonl"

static void test_evidence_dir(void) {
    if (setup() != 0) { ASSERT(0); return; }
    put_file(g_dir, "a.pcap", "AAAA-capture-bytes");
    put_file(g_dir, "b.pcap", "BBBB-capture-bytes");
    /* A replaced handshake pcap: an earlier line names bytes gone by
     * design, the later line the current ones. */
    put_file(g_dir, "hs.pcap", "handshake-v2");
    char m[4096], l[600];
    m[0] = '\0';
    manifest_line(l, sizeof(l), 1, "a.pcap", "AAAA-capture-bytes"); strcat(m, l);
    manifest_line(l, sizeof(l), 2, "hs.pcap", "handshake-v1");       strcat(m, l);
    manifest_line(l, sizeof(l), 3, "b.pcap", "BBBB-capture-bytes");  strcat(m, l);
    manifest_line(l, sizeof(l), 4, "hs.pcap", "handshake-v2");       strcat(m, l);
    manifest_line(l, sizeof(l), 5, "gone.pcap", "swept");            strcat(m, l);
    strcat(m, "{\"v\":1,\"seq\":6,\"fi");     /* a crash tail */
    put_file(g_dir, MF_NAME, m);
    put_file(g_dir, "operator-notes.txt", "x");

    jc_evdir_t v;
    jc_verify_evidence_dir(g_dir, &v);
    ASSERT_EQ(v.status, 0);
    ASSERT_EQ(v.manifests, 1);
    ASSERT_EQ(v.lines, 5u);
    ASSERT_EQ(v.files_ok, 3u);
    ASSERT_EQ(v.missing, 1u);
    ASSERT_STR(v.first_missing, "gone.pcap");
    ASSERT_EQ(v.unlisted, 1u);
    ASSERT_STR(v.first_unlisted, "operator-notes.txt");

    /* One byte of a capture. */
    put_file(g_dir, "b.pcap", "BBBB-capture-bytez");
    jc_verify_evidence_dir(g_dir, &v);
    ASSERT_EQ(v.status, 1);
    ASSERT(strstr(v.brk_what, "b.pcap") != NULL);
    put_file(g_dir, "b.pcap", "BBBB-capture-bytes");

    /* A manifest line taken out: seq skips. */
    char m2[4096];
    m2[0] = '\0';
    manifest_line(l, sizeof(l), 1, "a.pcap", "AAAA-capture-bytes"); strcat(m2, l);
    manifest_line(l, sizeof(l), 3, "b.pcap", "BBBB-capture-bytes"); strcat(m2, l);
    put_file(g_dir, MF_NAME, m2);
    jc_verify_evidence_dir(g_dir, &v);
    ASSERT_EQ(v.status, 1);
    ASSERT(strstr(v.brk_what, "seq 3 where 2 was due") != NULL);

    /* A directory sloth never wrote into. */
    char p[TEST_TMP_MAX + 96];
    snprintf(p, sizeof(p), "%s/%s", g_dir, MF_NAME);
    unlink(p);
    jc_verify_evidence_dir(g_dir, &v);
    ASSERT_EQ(v.status, 2);
    teardown();
}

void run_jsonl_chain_tests(void) {
    TEST_SUITE("jsonl chain (#251)");
    RUN_TEST(test_parse_block);
    RUN_TEST(test_writer_matches_the_definition);
    RUN_TEST(test_one_byte_names_the_block);
    RUN_TEST(test_every_byte);
    RUN_TEST(test_off_is_byte_identical);
    RUN_TEST(test_segments_and_pending);
    RUN_TEST(test_removals);
    TEST_SUITE("verify an evidence directory (#251)");
    RUN_TEST(test_evidence_dir);
}
