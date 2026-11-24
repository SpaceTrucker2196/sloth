#ifndef SLOTH_JSONL_CHAIN_H
#define SLOTH_JSONL_CHAIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "sha256.h"

/* ── A hash chain over the -o JSONL file (#251 part 1) ───────────────
 *
 * FM 6-02.43 (2009) 3-19: integrity is "the protection from
 * unauthorized change". A report for an auditor has to show that the
 * records it rests on were not changed after capture. Before #251 the
 * evidence captures had that (the #92 per-session manifest, SHA-256 of
 * each committed file) and the JSONL file had nothing: any line could
 * be edited, removed or inserted and nothing in the file would say so.
 *
 * Off unless `--jsonl-chain N`. With it on, the file sink (never the
 * data socket, whose clients join mid-stream and could not check a
 * block they saw half of) gets one `chain` record after every N
 * records:
 *
 *   {"type":"chain","ts":T,"v":1,"n":N,"seq":S,"lines":L,
 *    "block_sha256":"<64 hex>","prev_sha256":"<64 hex>"}
 *
 *   n             the run's --jsonl-chain N, the same on every record
 *                 of a segment: the writer never leaves N or more
 *                 lines unchained, so --verify can tell a crash tail
 *                 (at most N-1 lines) from chain records taken out
 *   block_sha256  SHA-256 of the exact bytes of the L lines between
 *                 the previous chain record and this one, each with
 *                 its '\n'
 *   prev_sha256   SHA-256 of the previous chain record's line, with
 *                 its '\n'
 *
 * SEGMENTS. Each jsonl_open() starts a segment with a genesis record
 * (seq 1, lines 0, block_sha256 of nothing, prev_sha256 all zeros)
 * before any record of the run. The -o file is appended to across
 * runs, and a run does not read back what an earlier one wrote, so the
 * lines between one segment's last chain record and the next genesis
 * (an earlier run's tail after a crash) are not covered, and --verify
 * says how many there are and where. More
 * than N-1 of them after a segment's last chain record is a break:
 * either chain records were taken out, or a run without the flag
 * appended to a chained file, and the file cannot say which. A whole
 * segment removed from the middle of the file (genesis and all), the
 * first segment's chain records all removed, or the end of the file
 * cut off at a chain record leaves a file that verifies: only
 * something kept off the file can show that, which is why --report
 * prints the head (the last chain record, with its SHA-256), why
 * --verify prints every segment's head, and why the issue's optional
 * signature is a later step (not built:
 * a key on a sensor that can be stolen proves less than it seems,
 * docs/wiki/sensor-compromise.md).
 *
 * SEALS. A partial block is sealed (a chain record with fewer than N
 * lines) at jsonl_close() and when a report is written, so a clean
 * stop ends on a chain record and the head a report prints is a line
 * that is in the file. A crash leaves up to N-1 lines after the head;
 * --verify calls them pending, not a break. */

#define JC_MAX_BLOCK   100000u   /* --jsonl-chain's upper bound */
#define JC_RECORD_MAX  320       /* the chain record, without '\n' */
#define JC_HEX_LEN     65

/* "--jsonl-chain N": 1..JC_MAX_BLOCK, decimal, nothing else. 0, or -1
 * with a reason in err. */
int jc_parse_block(const char *arg, unsigned *out, char *err, size_t errsz);

typedef struct {
    unsigned     n;               /* records per block; 0 = off */
    uint64_t     seq;             /* the last chain record written, 0 none */
    char         prev[JC_HEX_LEN];/* SHA-256 of that record's line */
    sha256_ctx_t blk;
    unsigned     blk_lines;
} jc_writer_t;

void jc_writer_init(jc_writer_t *w, unsigned n);

/* The genesis record, into out (no '\n'); it becomes the head. */
int jc_writer_genesis(jc_writer_t *w, time_t ts, char *out, size_t cap);

/* One line as written to the file, with its '\n'. 1 when the block is
 * full and jc_writer_seal() should run now, else 0. */
int jc_writer_add(jc_writer_t *w, const char *bytes, size_t len);

/* The chain record for the pending lines, into out (no '\n'); it
 * becomes the head. 0 when nothing is pending (no record), else its
 * length. */
int jc_writer_seal(jc_writer_t *w, time_t ts, char *out, size_t cap);

/* The record's exact bytes, which --verify re-renders to compare. */
int jc_format(char *out, size_t cap, long long ts, unsigned n,
              unsigned long long seq, unsigned lines,
              const char *block_hex, const char *prev_hex);

/* SHA-256 of the regular file `name` (one path component, not followed
 * if a symlink) in the directory dirfd, lowercase hex. 0, or -1. For
 * the alert records' pcap_sha256: each exporter hashes through the
 * directory descriptor it pinned and wrote through, never through a
 * printable path, which can be a bare name or name another directory
 * by now. */
int jc_sha256_at(int dirfd, const char *name, char hex[JC_HEX_LEN]);

/* ── --verify on a JSONL file ──────────────────────────────────────── */

typedef struct {
    int      status;              /* 0 intact, 1 break, 2 cannot verify */
    uint64_t lines;               /* complete lines read (to the break) */
    uint64_t records;             /* chain records */
    uint64_t segments;
    uint64_t blocks;              /* non-genesis chain records that checked */
    uint64_t uncovered;           /* lines in no block (before a genesis) */
    uint64_t uncovered_first;     /* the first such line, 0 none */
    uint64_t pending;             /* lines after the head */
    int      fragment;            /* the file ends without '\n' */
    /* The head: the last chain record. */
    unsigned head_n;              /* its segment's n */
    uint64_t head_segment, head_seq, head_line;
    char     head_sha[JC_HEX_LEN];
    /* The first break. */
    uint64_t brk_segment, brk_seq, brk_first, brk_last, brk_line;
    char     brk_what[240];
} jc_verify_t;

/* Reads `f` to its end or to the first break. */
void jc_verify_stream(FILE *f, jc_verify_t *v);

/* The same, calling seg_head once per segment that ended before the
 * end of the file or the break, and for the last one when the file
 * verifies, with that segment's head: what a report written during
 * that run is compared with. */
typedef void (*jc_seg_head_fn)(void *ctx, uint64_t segment, uint64_t seq,
                               uint64_t line, const char *sha);
void jc_verify_stream_segs(FILE *f, jc_verify_t *v, jc_seg_head_fn seg_head,
                           void *ctx);

/* ── --verify on an evidence directory (the #92 manifests) ────────── */

typedef struct {
    int      status;              /* 0 intact, 1 break, 2 cannot verify */
    int      manifests;
    uint64_t lines;
    uint64_t files_ok;            /* names some line's hash matches */
    uint64_t missing;             /* listed, not on disk */
    uint64_t unlisted;            /* on disk, in no manifest */
    char     first_missing[160];
    char     first_unlisted[160];
    char     brk_what[400];
} jc_evdir_t;

void jc_verify_evidence_dir(const char *dir, jc_evdir_t *v);

/* sloth --verify PATH: a regular file is a JSONL file, a directory an
 * evidence directory. Prints to out; returns 0 intact, 1 a break, 2
 * cannot verify. */
int jc_verify_main(const char *path, FILE *out);

#endif /* SLOTH_JSONL_CHAIN_H */
