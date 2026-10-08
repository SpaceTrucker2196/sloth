#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "runner.h"
#include "evidence_export.h"
#include "evidence_ring.h"
#include "eapol_log.h"

/* ── Gated evidence export — issue #92 ───────────────────────
 *
 * The owner ruled on 2026-10-08 that raw 802.11 export shares #87's
 * `--collect-handshakes` gate rather than getting one of its own,
 * because the payload is the same crackable material: a raw frame
 * carries the EAPOL 4-way and PMKID.
 *
 * So the weight here is on the refusals. An export that writes when it
 * should not is the whole failure this gate exists to prevent, and it is
 * silent — a file appears and nothing complains. Every case below that
 * asserts "nothing was written" also asserts the directory is still
 * EMPTY, because a function returning -1 while leaving a file behind
 * would satisfy a weaker test and defeat the gate completely.
 *
 * ── What these cases do and do not pin ──
 *
 * They pin the COMPOSITE refusal, not any single check, and the
 * difference was measured rather than assumed. Three mechanisms refuse
 * independently: this exporter's own early eapol_collect_enabled()
 * test, eapol_export_create()'s gate test under #87's lock, and the
 * fact that closing the gate drops the pinned descriptor so there is
 * nothing to write through. Deleting any ONE of them leaves the suite
 * green, because the other two still refuse — verified by mutating each
 * in turn. Deleting the gated helper entirely, so the export opens a
 * path directly, fails three cases.
 *
 * That is defence in depth behaving correctly, not a hole: no
 * single-point edit gets crackable material onto disk. But it means a
 * reader should not take a green run here as proof that a particular
 * line is load-bearing, and single-mutation testing cannot isolate
 * redundant layers by construction. The layer that would notice a
 * genuine regression first is the dropped descriptor, because it is the
 * one no caller can route around. */

#define EXP_DIR "/tmp/sloth_evexport_test"

/* Delete our candidate files and recreate EXP_DIR 0700 — #87 refuses a
   permissive directory, and a leftover file would make the emptiness
   assertions below pass or fail for the wrong reason. */
static void reset_dir(void) {
    char path[512];
    const char *names[] = { "ev1.pcap", "ev2.pcap", "ev3.pcap",
                            "eapol.22000", NULL };
    for (int i = 0; names[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", EXP_DIR, names[i]);
        unlink(path);
    }
    rmdir(EXP_DIR);
    mkdir(EXP_DIR, 0700);
}

/* How many of our candidate names exist in EXP_DIR. */
static int exported_files(void) {
    char path[512];
    const char *names[] = { "ev1.pcap", "ev2.pcap", "ev3.pcap", NULL };
    int n = 0;
    for (int i = 0; names[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", EXP_DIR, names[i]);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) n++;
    }
    return n;
}

static long file_size(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", EXP_DIR, name);
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* A radiotap + 802.11 beacon, hand-built: 8-byte radiotap with no
   present fields, then a frame whose Frame Control says beacon. */
static int ev_frame(uint8_t *f, int dot11_len) {
    const int total = 8 + dot11_len;
    memset(f, 0, (size_t)total);
    f[2] = 8;                       /* it_len */
    f[8] = 0x80;                    /* beacon */
    f[12] = 0x02; f[17] = 0x01;     /* addr1 bytes, arbitrary */
    return total;
}

/* Store `n` frames and hand back their event IDs. */
static void seed_ring(uint64_t *ids, int n) {
    evidence_ring_reset();
    ASSERT_EQ(evidence_ring_init(64 * 1024), 0);
    uint8_t f[256];
    for (int i = 0; i < n; i++) {
        int len = ev_frame(f, 40 + i);
        ids[i] = evidence_ring_note(f, (uint32_t)len, (uint32_t)len,
                                    1700000000 + i, i * 100, 2412, -42);
        ASSERT(ids[i] != 0);
    }
}

static void test_export_refused_without_the_opt_in(void) {
    /* The case the gate exists for. */
    reset_dir();
    eapol_set_collect_enabled(0);
    uint64_t ids[2];
    seed_ring(ids, 2);

    char err[256] = "";
    int skipped = -1;
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 2, &skipped,
                                   err, sizeof(err)), -1);
    ASSERT(strstr(err, "--collect-handshakes") != NULL);
    /* And nothing was left behind. A -1 with a file on disk would be
       worse than no gate, because the operator would believe the
       refusal. */
    ASSERT_EQ(exported_files(), 0);
}

static void test_export_refused_without_a_destination(void) {
    /* Gate open, no --eapol-dir: still nothing to write into. */
    reset_dir();
    eapol_set_collect_enabled(1);
    eapol_set_output_dir(NULL);
    uint64_t ids[1];
    seed_ring(ids, 1);

    char err[256] = "";
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT(err[0] != '\0');
    ASSERT_EQ(exported_files(), 0);
}

static void test_export_writes_when_the_gate_is_open(void) {
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[3];
    seed_ring(ids, 3);

    char err[256] = "";
    int skipped = -1;
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 3, &skipped,
                                   err, sizeof(err)), 3);
    ASSERT_EQ(skipped, 0);
    ASSERT_EQ(exported_files(), 1);

    /* 24-byte global header + 3 * (16-byte record header + frame). The
       frames are 48, 49 and 50 bytes (8 radiotap + 40/41/42). */
    long want = 24 + (16 + 48) + (16 + 49) + (16 + 50);
    ASSERT_EQ(file_size("ev1.pcap"), want);
}

static void test_export_file_is_a_real_pcap(void) {
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[1];
    seed_ring(ids, 1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 1, NULL, NULL, 0), 1);

    char path[512];
    snprintf(path, sizeof(path), "%s/ev1.pcap", EXP_DIR);
    FILE *fp = fopen(path, "rb");
    ASSERT(fp != NULL);
    if (!fp) return;
    uint8_t hdr[24];
    ASSERT_EQ((int)fread(hdr, 1, sizeof(hdr), fp), 24);

    /* Parsed field by field rather than compared against bytes this
       test also generated — a byte-for-byte compare would pass even if
       both sides were wrong in the same way. */
    uint32_t magic;  memcpy(&magic, hdr + 0, 4);
    uint16_t major;  memcpy(&major, hdr + 4, 2);
    uint32_t snap;   memcpy(&snap,  hdr + 16, 4);
    uint32_t dlt;    memcpy(&dlt,   hdr + 20, 4);
    ASSERT_EQ((long long)magic, 0xa1b2c3d4LL);
    ASSERT_EQ((long long)major, 2);
    ASSERT_EQ((long long)snap, 262144LL);
    ASSERT_EQ((long long)dlt, 127LL);      /* radiotap, as the ring stores */

    /* The record header carries the ring's timestamp, not "now". */
    uint8_t rh[16];
    ASSERT_EQ((int)fread(rh, 1, sizeof(rh), fp), 16);
    uint32_t ts, caplen, origlen;
    memcpy(&ts, rh + 0, 4); memcpy(&caplen, rh + 8, 4);
    memcpy(&origlen, rh + 12, 4);
    ASSERT_EQ((long long)ts, 1700000000LL);
    ASSERT_EQ((long long)caplen, 48LL);
    ASSERT_EQ((long long)origlen, 48LL);
    fclose(fp);
}

static void test_export_skips_an_evicted_id_and_says_so(void) {
    /* An incident whose oldest frame aged out is still worth the frames
       that remain, so a missing ID is skipped and counted, never fatal
       and never substituted by a different record. */
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[2];
    seed_ring(ids, 2);

    uint64_t mixed[3] = { ids[0], ids[1] + 9999, ids[1] };
    char err[256] = "";
    int skipped = -1;
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", mixed, 3, &skipped,
                                   err, sizeof(err)), 2);
    ASSERT_EQ(skipped, 1);
    long want = 24 + (16 + 48) + (16 + 49);
    ASSERT_EQ(file_size("ev1.pcap"), want);
}

static void test_export_refuses_to_overwrite(void) {
    /* SFILE_EXCL: a second export under the same name must not quietly
       replace evidence already on disk. */
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[1];
    seed_ring(ids, 1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 1, NULL, NULL, 0), 1);
    long first = file_size("ev1.pcap");

    char err[256] = "";
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT_EQ(file_size("ev1.pcap"), first);   /* untouched */
}

static void test_export_rejects_bad_arguments(void) {
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[1];
    seed_ring(ids, 1);
    char err[256];
    ASSERT_EQ(evidence_export_pcap(NULL, ids, 1, NULL, err, sizeof(err)), -1);
    ASSERT_EQ(evidence_export_pcap("", ids, 1, NULL, err, sizeof(err)), -1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", NULL, 1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 0, NULL,
                                   err, sizeof(err)), -1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, -1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT_EQ(exported_files(), 0);
}

static void test_closing_the_gate_mid_run_stops_export(void) {
    /* #87 drops the pinned descriptor when the gate closes, so an
       exporter that cached nothing cannot keep writing. Asserted
       because a cached fd is the obvious way to get this wrong. */
    reset_dir();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(EXP_DIR), 0);
    uint64_t ids[1];
    seed_ring(ids, 1);
    ASSERT_EQ(evidence_export_pcap("ev1.pcap", ids, 1, NULL, NULL, 0), 1);

    eapol_set_collect_enabled(0);
    char err[256] = "";
    ASSERT_EQ(evidence_export_pcap("ev2.pcap", ids, 1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT_EQ(file_size("ev2.pcap"), -1);      /* never created */
}

void run_evidence_export_tests(void) {
    TEST_SUITE("evidence export: gated on --collect-handshakes (#92)");
    RUN_TEST(test_export_refused_without_the_opt_in);
    RUN_TEST(test_export_refused_without_a_destination);
    RUN_TEST(test_export_writes_when_the_gate_is_open);
    RUN_TEST(test_export_file_is_a_real_pcap);
    RUN_TEST(test_export_skips_an_evicted_id_and_says_so);
    RUN_TEST(test_export_refuses_to_overwrite);
    RUN_TEST(test_export_rejects_bad_arguments);
    RUN_TEST(test_closing_the_gate_mid_run_stops_export);

    /* Leave the gate shut and the directory gone: a later suite that
       assumes the shipped default would otherwise inherit an open gate
       from here. */
    eapol_set_collect_enabled(0);
    reset_dir();
    rmdir(EXP_DIR);
    evidence_ring_reset();
}
