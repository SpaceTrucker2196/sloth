#include <string.h>
#include <stdio.h>
#include <sys/statvfs.h>

#include "fs_capacity.h"

int fs_capacity_probe(int dirfd, fs_capacity_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (dirfd < 0) return -1;

    struct statvfs v;
    if (fstatvfs(dirfd, &v) != 0) return -1;

    /* f_bavail, not f_bfree: the latter counts blocks reserved for root,
     * which sloth cannot use unless it is running as root — and whether
     * it is varies by deployment. Reporting space we may not be able to
     * spend is the same reassurance bug this module exists to fix.
     *
     * f_frsize is the fragment size and is the correct multiplier for
     * f_bavail; f_bsize is a preferred IO size and is not. They are
     * equal on ext4, which is why the distinction is easy to get wrong
     * and never notice. */
    uint64_t unit = v.f_frsize ? (uint64_t)v.f_frsize : (uint64_t)v.f_bsize;
    out->free_bytes  = (uint64_t)v.f_bavail * unit;
    out->total_bytes = (uint64_t)v.f_blocks * unit;

    out->total_files = (uint64_t)v.f_files;
    out->free_files  = (uint64_t)v.f_favail;
    out->files_known = v.f_files != 0;
    return 0;
}

int fs_capacity_blocked(const fs_capacity_t *c,
                        uint64_t min_bytes, uint64_t min_files,
                        char *why, size_t whysz) {
    if (why && whysz) why[0] = '\0';
    if (!c) return 0;

    /* Inodes first. On the measured failure this is the one that would
     * have fired, and reporting the byte figure first would bury it. */
    if (min_files && c->files_known && c->free_files < min_files) {
        if (why && whysz)
            snprintf(why, whysz,
                     "only %llu free inodes left, floor is %llu "
                     "(inodes run out before disk does when every alert "
                     "writes its own file)",
                     (unsigned long long)c->free_files,
                     (unsigned long long)min_files);
        return 1;
    }
    if (min_bytes && c->free_bytes < min_bytes) {
        if (why && whysz)
            snprintf(why, whysz,
                     "only %llu MB free, floor is %llu MB",
                     (unsigned long long)(c->free_bytes / (1024u * 1024u)),
                     (unsigned long long)(min_bytes / (1024u * 1024u)));
        return 1;
    }
    return 0;
}

int fs_capacity_band(uint64_t free, uint64_t total) {
    if (total == 0) return -1;
    if (free > total) free = total;      /* f_bavail can exceed on odd fs */
    /* Percent free, integer, then widening bands as it gets tighter: the
     * difference between 80% and 60% free is not news, the difference
     * between 5% and 1% is. */
    unsigned pct = (unsigned)((free * 100u) / total);
    if (pct >= 25) return 0;
    if (pct >= 10) return 1;
    if (pct >= 5)  return 2;
    if (pct >= 1)  return 3;
    return 4;
}
