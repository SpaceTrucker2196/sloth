#ifndef SLOTH_FS_CAPACITY_H
#define SLOTH_FS_CAPACITY_H

#include <stddef.h>
#include <stdint.h>

/* ── Filesystem headroom for the unbounded output sink (#96) ──────
 *
 * `--pcap-dir` is the one operator-named sink with no cap, no sweep and
 * no retention: src/alert_pcap.c writes a new file per firing and never
 * removes one (its only unlinkat is the cleanup after a failed write).
 * src/eapol_log.c has eapol_sweep(); this has nothing.
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
 * a policy call, not an engineering one — eapol_sweep()'s age policy
 * exists because #87 gave crackable material a stated short default,
 * which alert pcaps do not have. A guard that refuses to write is
 * non-destructive and reversible; a sweep is neither. */

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
 * `why`, 0 when there is room. A floor of 0 disables that floor; both
 * at 0 means this never refuses.
 *
 * `min_files` is compared only when c->files_known, for the btrfs
 * reason above. */
int fs_capacity_blocked(const fs_capacity_t *c,
                        uint64_t min_bytes, uint64_t min_files,
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
