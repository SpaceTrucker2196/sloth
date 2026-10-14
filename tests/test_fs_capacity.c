#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "runner.h"
#include "fs_capacity.h"

/* ── Filesystem headroom for --pcap-dir — issue #96 ───────────────
 *
 * The decision is a pure function of four numbers, which is the whole
 * reason it is shaped that way: the interesting cases are "almost out"
 * and "out", and neither can be produced by filling a real disk inside
 * a test suite that must run anywhere without root.
 *
 * The case that drove the module is the one at the top: plenty of bytes,
 * no inodes. That is what the owner's monitor host actually looked like
 * — 267 GB free, 15.9M alert pcaps, 93% of the filesystem's inodes
 * consumed — and a byte-only floor reads it as healthy. */

static fs_capacity_t cap_of(uint64_t free_b, uint64_t free_f, int files_known) {
    fs_capacity_t c;
    memset(&c, 0, sizeof(c));
    c.free_bytes  = free_b;
    c.total_bytes = free_b * 2 + 1;
    c.free_files  = free_f;
    c.total_files = files_known ? free_f * 2 + 1 : 0;
    c.files_known = files_known;
    return c;
}

static void test_the_measured_failure_is_caught(void) {
    /* 267 GB free, 13.1M inodes free — the real figures. With a byte
       floor of 1 GB and no inode floor, nothing fires: this is the
       false reassurance, asserted so a later change cannot quietly
       claim the byte floor was sufficient. */
    fs_capacity_t c = cap_of(267ull * 1024 * 1024 * 1024, 13138050, 1);
    char why[320];
    ASSERT_EQ(fs_capacity_blocked(&c, 1024ull * 1024 * 1024, 0, 0, why, sizeof(why)), 0);
    ASSERT_STR(why, "");

    /* With an inode floor above the remaining count, it fires — and the
       reason names inodes, because an operator staring at `df -h` needs
       to be told the constraint is not bytes. */
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 20000000, 0, why, sizeof(why)), 1);
    ASSERT(strstr(why, "inode") != NULL);
}

static void test_inode_floor_is_reported_before_the_byte_floor(void) {
    /* Both floors breached at once. The inode reason must win, so the
       message names the constraint that will actually bite first. */
    fs_capacity_t c = cap_of(10ull * 1024 * 1024, 100, 1);
    char why[320];
    ASSERT_EQ(fs_capacity_blocked(&c, 500ull * 1024 * 1024, 1000, 0, why, sizeof(why)), 1);
    ASSERT(strstr(why, "inode") != NULL);
    ASSERT(strstr(why, "MB free") == NULL);
}

static void test_zero_floor_disables_that_floor(void) {
    fs_capacity_t c = cap_of(0, 0, 1);   /* genuinely empty */
    char why[320];
    /* Both floors off: never refuses, even on a full filesystem. That
       is the shipped default, so this is the upgrade-safety assertion —
       an existing deployment must not start refusing writes. */
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 0, why, sizeof(why)), 0);
    /* One floor off, the other on, each independently. */
    ASSERT_EQ(fs_capacity_blocked(&c, 1, 0, 0, why, sizeof(why)), 1);
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 1, 0, why, sizeof(why)), 1);
}

static void test_floor_is_a_floor_not_a_ceiling(void) {
    char why[320];
    /* Exactly at the floor is allowed: the comparison is `<`, so a
       floor of N means "N must remain", and having exactly N remaining
       satisfies it. Off by one here would refuse a write the operator
       asked to permit. */
    fs_capacity_t at = cap_of(1000, 50, 1);
    ASSERT_EQ(fs_capacity_blocked(&at, 1000, 50, 0, why, sizeof(why)), 0);
    /* One below either floor refuses. */
    fs_capacity_t b = cap_of(999, 50, 1);
    ASSERT_EQ(fs_capacity_blocked(&b, 1000, 50, 0, why, sizeof(why)), 1);
    fs_capacity_t i = cap_of(1000, 49, 1);
    ASSERT_EQ(fs_capacity_blocked(&i, 1000, 50, 0, why, sizeof(why)), 1);
}

static void test_filesystem_without_an_inode_table_is_not_refused(void) {
    /* btrfs and most network filesystems report f_files == 0, meaning
       "no fixed inode table" — not "no inodes left". Treating the two
       alike would refuse every write on btrfs, which is why
       files_known is a separate field rather than a count of zero. */
    fs_capacity_t c = cap_of(100ull * 1024 * 1024 * 1024, 0, 0);
    char why[320];
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 1000000, 0, why, sizeof(why)), 0);
    ASSERT_STR(why, "");
    /* The byte floor still applies there — only the inode check is
       skipped, not the whole guard. */
    ASSERT_EQ(fs_capacity_blocked(&c, 200ull * 1024 * 1024 * 1024, 0, 0,
                                  why, sizeof(why)), 1);
}

static void test_null_and_short_buffers_are_safe(void) {
    char why[320];
    ASSERT_EQ(fs_capacity_blocked(NULL, 1, 1, 0, why, sizeof(why)), 0);
    fs_capacity_t c = cap_of(0, 0, 1);
    /* No output buffer at all, and a buffer too small for the message:
       neither may write out of bounds, and both must still return the
       verdict. ASan is the real assertion here. */
    ASSERT_EQ(fs_capacity_blocked(&c, 1, 0, 0, NULL, 0), 1);
    char tiny[4];
    ASSERT_EQ(fs_capacity_blocked(&c, 1, 0, 0, tiny, sizeof(tiny)), 1);
}

static void test_probe_reads_a_real_directory(void) {
    /* The one case that needs a filesystem. It asserts coherence, not
       specific numbers — the numbers belong to whatever host this runs
       on, and pinning them would make the suite machine-dependent. */
    int fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT(fd >= 0);
    if (fd < 0) return;
    fs_capacity_t c;
    ASSERT_EQ(fs_capacity_probe(fd, &c), 0);
    close(fd);
    ASSERT(c.total_bytes > 0);
    ASSERT(c.free_bytes <= c.total_bytes);
    if (c.files_known) ASSERT(c.free_files <= c.total_files);
    /* A working tree we just built in has room; if this fails the host
       is genuinely full and the suite's own writes would have failed
       first. */
    ASSERT(c.free_bytes > 0);
}

static void test_probe_rejects_a_bad_descriptor(void) {
    fs_capacity_t c;
    memset(&c, 0xAA, sizeof(c));
    ASSERT_EQ(fs_capacity_probe(-1, &c), -1);
    /* Zeroed on failure, so a caller that ignores the return code reads
       zeros rather than the 0xAA garbage that was there — and zeros with
       files_known == 0 refuse nothing. */
    ASSERT_EQ((long long)c.free_bytes, 0);
    ASSERT_EQ(c.files_known, 0);
    ASSERT_EQ(fs_capacity_probe(0, NULL), -1);
}

static void test_band_widens_as_headroom_tightens(void) {
    /* The band exists so the change-only JSONL signature does not
       firehose, so what matters is that it is COARSE at the top and
       FINE at the bottom: 80% vs 60% free is not news, 5% vs 1% is. */
    ASSERT_EQ(fs_capacity_band(100, 100), 0);
    ASSERT_EQ(fs_capacity_band(80,  100), 0);
    ASSERT_EQ(fs_capacity_band(25,  100), 0);   /* boundary, inclusive */
    ASSERT_EQ(fs_capacity_band(24,  100), 1);
    ASSERT_EQ(fs_capacity_band(10,  100), 1);
    ASSERT_EQ(fs_capacity_band(9,   100), 2);
    ASSERT_EQ(fs_capacity_band(5,   100), 2);
    ASSERT_EQ(fs_capacity_band(4,   100), 3);
    ASSERT_EQ(fs_capacity_band(1,   100), 3);
    ASSERT_EQ(fs_capacity_band(0,   100), 4);
}

static void test_band_is_undefined_without_a_total(void) {
    /* total == 0 is the btrfs no-inode-table case. -1 rather than 0,
       because 0 means "plenty" and would be a false reassurance — the
       exact bug this module exists to avoid. */
    ASSERT_EQ(fs_capacity_band(0, 0), -1);
    ASSERT_EQ(fs_capacity_band(500, 0), -1);
}

static void test_band_tolerates_free_above_total(void) {
    /* f_bavail can exceed f_blocks on some filesystems. Clamping keeps
       the division in range rather than producing a band above 0. */
    ASSERT_EQ(fs_capacity_band(200, 100), 0);
}

static void test_band_does_not_overflow_on_real_sizes(void) {
    /* free * 100 on a multi-terabyte figure overflows a 32-bit
       intermediate. These are the owner's actual numbers: 267 GB free
       of 454 GB, and 13,138,050 inodes free of 30,269,440. */
    ASSERT_EQ(fs_capacity_band(267ull * 1024 * 1024 * 1024,
                               454ull * 1024 * 1024 * 1024), 0);
    ASSERT_EQ(fs_capacity_band(13138050, 30269440), 0);
    /* And the shape of the failure this module is named for: inodes at
       the same instant the byte band reads comfortable. */
    ASSERT_EQ(fs_capacity_band(300000, 30269440), 4);
}

/* ── The relative floor, which is the one on by default ────
 *
 * An absolute default cannot be right for two deployments of different
 * size, and that is not a hypothetical: the floor that would have
 * protected the host this module was measured on is ~1.5M free inodes,
 * which is 5% of its 30,269,440-inode filesystem and would refuse every
 * write on a small one. So the default is a percentage and the absolute
 * knobs are overrides. */
static void test_percentage_floor_scales_with_the_filesystem(void) {
    char why[320];
    /* The owner's host: 30,269,440 total inodes. 5% is 1,513,472. */
    fs_capacity_t big = cap_of(100ull * 1024 * 1024 * 1024, 13138050, 1);
    big.total_files = 30269440;
    big.total_bytes = 454ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&big, 0, 0, 5, why, sizeof(why)), 0);
    /* Drop free inodes under 5% and the SAME percentage refuses. */
    big.free_files = 1000000;
    ASSERT_EQ(fs_capacity_blocked(&big, 0, 0, 5, why, sizeof(why)), 1);
    ASSERT(strstr(why, "inode") != NULL);

    /* A small filesystem: 500,000 total inodes, 5% is 25,000. The same
       knob value that protects the 30M host does not lock this one out,
       which is the whole reason the default is relative. */
    fs_capacity_t small = cap_of(8ull * 1024 * 1024 * 1024, 100000, 1);
    small.total_files = 500000;
    small.total_bytes = 16ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&small, 0, 0, 5, why, sizeof(why)), 0);
    /* An ABSOLUTE floor of 1.5M — the right number for the big host —
       would refuse every write here. Asserted so the reason the default
       is not absolute is written down as a test, not just a comment. */
    ASSERT_EQ(fs_capacity_blocked(&small, 0, 1513472, 0, why, sizeof(why)), 1);
}

static void test_percentage_floor_checks_bytes_too(void) {
    char why[320];
    /* Inodes comfortable, bytes under the percentage. */
    fs_capacity_t c = cap_of(1ull * 1024 * 1024 * 1024, 20000000, 1);
    c.total_files = 30000000;
    c.total_bytes = 454ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 5, why, sizeof(why)), 1);
    ASSERT(strstr(why, "MB") != NULL);
}

static void test_percentage_floor_reports_inodes_first(void) {
    /* Both under the percentage at once. Inodes win the message, for
       the same reason the absolute terms are ordered that way: on the
       measured failure inodes were the binding constraint while `df -h`
       read 39% used, so naming bytes first would bury the cause. */
    char why[320];
    fs_capacity_t c = cap_of(1ull * 1024 * 1024, 1000, 1);
    c.total_files = 30000000;
    c.total_bytes = 454ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 5, why, sizeof(why)), 1);
    ASSERT(strstr(why, "inode")  != NULL);
    ASSERT(strstr(why, "MB of")  == NULL);
}

static void test_percentage_zero_disables_the_relative_floor(void) {
    /* The escape hatch for a deployment that wants the pre-guard
       behaviour: all three floors at 0 never refuses. */
    char why[320];
    fs_capacity_t c = cap_of(0, 0, 1);
    c.total_files = 30000000;
    c.total_bytes = 454ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 0, why, sizeof(why)), 0);
    /* And with the default 5 it refuses, so the two are distinguishable
       rather than both passing for unrelated reasons. */
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 5, why, sizeof(why)), 1);
}

static void test_percentage_floor_skips_inodes_without_a_table(void) {
    /* btrfs again: f_files == 0 means no fixed inode table, not none
       left, so the percentage must not divide by it either. */
    char why[320];
    fs_capacity_t c = cap_of(100ull * 1024 * 1024 * 1024, 0, 0);
    c.total_files = 0;
    c.total_bytes = 454ull * 1024 * 1024 * 1024;
    ASSERT_EQ(fs_capacity_blocked(&c, 0, 0, 5, why, sizeof(why)), 0);
}

void run_fs_capacity_tests(void) {
    TEST_SUITE("fs capacity: storage floors for --pcap-dir (#96)");
    RUN_TEST(test_the_measured_failure_is_caught);
    RUN_TEST(test_inode_floor_is_reported_before_the_byte_floor);
    RUN_TEST(test_zero_floor_disables_that_floor);
    RUN_TEST(test_floor_is_a_floor_not_a_ceiling);
    RUN_TEST(test_filesystem_without_an_inode_table_is_not_refused);
    RUN_TEST(test_null_and_short_buffers_are_safe);
    RUN_TEST(test_probe_reads_a_real_directory);
    RUN_TEST(test_probe_rejects_a_bad_descriptor);
    RUN_TEST(test_band_widens_as_headroom_tightens);
    RUN_TEST(test_band_is_undefined_without_a_total);
    RUN_TEST(test_band_tolerates_free_above_total);
    RUN_TEST(test_band_does_not_overflow_on_real_sizes);
    RUN_TEST(test_percentage_floor_scales_with_the_filesystem);
    RUN_TEST(test_percentage_floor_checks_bytes_too);
    RUN_TEST(test_percentage_floor_reports_inodes_first);
    RUN_TEST(test_percentage_zero_disables_the_relative_floor);
    RUN_TEST(test_percentage_floor_skips_inodes_without_a_table);
}
