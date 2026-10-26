#ifndef SLOTH_FS_CAPACITY_H
#define SLOTH_FS_CAPACITY_H

#include <stddef.h>
#include <stdint.h>

/* ── Filesystem headroom for the unbounded output sink (#96) ──────
 *
 * `--pcap-dir` was the one operator-named sink with no cap, no sweep
 * and no retention: src/alert_pcap.c wrote a new file per firing and
 * never removed one. Since #166 it has an age sweep (two weeks by
 * default, alert_pcap_maintain()); this module is still what holds the
 * line inside a burst, which a sweep measured in days cannot.
 *
 * That is not theoretical. Measured on the owner's own monitor host,
 * 2026-10-13: 15,919,490 files, 77 GB, against a filesystem whose total
 * inode usage was 17,131,390 — so roughly 93% of every inode on the
 * machine was a sloth alert pcap, and inodes, not bytes, were the
 * binding constraint. Disk sat at 39% used the whole time.
 *
 * That measurement decided this module's shape twice over:
 *
 *   1. INODES ARE CHECKED, NOT ONLY BYTES. A byte-only floor — the
 *      obvious reading of "add filesystem capacity controls" — would
 *      not have fired once in the real case, because there were 267 GB
 *      free throughout. A guard that cannot catch the failure that
 *      motivated it is worse than none, because it reads as covered.
 *
 *   2. VISIBILITY IS ON BY DEFAULT; REFUSAL IS OPT-IN. The operator
 *      failure mode here is reassurance: `df -h` says 39% and the
 *      sensor looks healthy while it is three million files from being
 *      unable to create any. So the headroom is always reported (the
 *      sensor_health record), and the floors that make sloth REFUSE to
 *      write default to 0, meaning off. Refusing by default would
 *      change the behaviour of every existing deployment on upgrade,
 *      and the floor an operator wants depends on their disk.
 *
 * Deliberately NOT here: deleting anything. An alert pcap is the
 * operator's forensic evidence and the retention window for evidence is
 * a policy call, not an engineering one. That call was made on #166
 * (owner ruling 2026-10-26: two weeks), and the deletion it allows
 * lives beside the writer in src/alert_pcap.c, not in a probe. A guard
 * that refuses to write is non-destructive and reversible; a sweep is
 * neither, which is why the two stay separate. */

typedef struct {
    uint64_t free_bytes;
    uint64_t total_bytes;
    uint64_t free_files;    /* free inodes, or 0 if the fs does not report them */
    uint64_t total_files;
    int      files_known;   /* 0 when the filesystem reports no inode limit */
} fs_capacity_t;

/* Read the headroom of the filesystem holding `dirfd`. Returns 0 on
 * success, -1 on failure (and zeroes *out).
 *
 * `files_known` is its own field rather than an inode count of zero,
 * because the two are different facts: btrfs and most network
 * filesystems report f_files == 0 meaning "no fixed inode table", which
 * is not the same as "no inodes left". Conflating them would make this
 * module refuse every write on btrfs. */
int fs_capacity_probe(int dirfd, fs_capacity_t *out);

/* The decision, as a pure function of the numbers — so it is testable
 * without a filesystem to fill.
 *
 * Returns 1 when a write should be refused and writes a reason into
 * `why`, 0 when there is room. THREE floors, any one of which refuses:
 *
 *   min_pct    a PERCENTAGE of the filesystem's own total, checked for
 *              bytes and for inodes. This is the one that is on by
 *              default, and it has to be relative: the floor that
 *              protected the host where this was measured was 1.5M
 *              inodes, which is 5% of its 30M-inode filesystem and
 *              would refuse every write on a small one. An absolute
 *              default cannot be right for both.
 *   min_bytes  absolute byte floor, 0 for none
 *   min_files  absolute inode floor, 0 for none
 *
 * The absolutes are overrides for an operator who knows their segment,
 * not the primary mechanism. All three at 0 means this never refuses,
 * which is what a deployment that wants the old behaviour sets.
 *
 * Inode terms — both the absolute and the percentage — are compared
 * only when c->files_known, for the btrfs reason above. */
int fs_capacity_blocked(const fs_capacity_t *c,
                        uint64_t min_bytes, uint64_t min_files,
                        int min_pct,
                        char *why, size_t whysz);

/* Coarse headroom band, 0 (plenty) to 4 (essentially none), or -1 when
 * `total` is 0 and the fraction is undefined.
 *
 * This exists for the change-only JSONL signature, not for display. The
 * free figures themselves move every second on a live sensor, so signing
 * over them would emit sensor_health once a second forever and bury the
 * transitions that record exists to surface — the same reason stale_secs
 * enters its signature as a three-state bucket and the flow rings stay
 * out of it entirely (see the note in src/jsonl.c). A band changes a
 * handful of times over a filesystem's life, which is exactly the news
 * a consumer wants: not "it moved", but "it crossed". */
int fs_capacity_band(uint64_t free, uint64_t total);

#endif /* SLOTH_FS_CAPACITY_H */
