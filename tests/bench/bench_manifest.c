/* Manifest cost bench (#92 slice 3): what one manifest line costs, and
 * how much of it sits under the EAPOL lock.
 *
 * Every eapol.22000 append re-reads the whole run-spanning file to hash
 * it, and every line is fsync'ed. The capture thread used to do both
 * while holding the EAPOL lock; now it only pins the file there
 * (evidence_manifest_pin: openat + fstat + dup) and hashes and appends
 * after unlocking (evidence_manifest_record_pinned). This times the two
 * halves separately against a 22000 file of 4 KiB, 1 MiB and 16 MiB —
 * roughly 10, 3,000 and 50,000 PMKID lines — so the figure says both
 * what the capture thread still pays per handshake and what it no
 * longer pays with the lock held.
 *
 * The directory is a fresh mkdtemp() under $BENCH_DIR (default /tmp),
 * removed at the end; point BENCH_DIR at the sensor's --eapol-dir
 * filesystem to measure its fsync rather than tmpfs's. Times, asserts
 * nothing about speed; exits non-zero only if a record fails.
 *
 * Run: make bench [BENCH_ITERS=n]. Recorded in docs/wiki/pcap-export.md
 * §5 with the host and command. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "evidence_manifest.h"
#include "secure_file.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *v, int n) {
    qsort(v, (size_t)n, sizeof(*v), cmp_d);
    return v[n / 2];
}

static void rm_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        char p[512];
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 50;
    if (iters < 1) iters = 1;
    const char *root = getenv("BENCH_DIR");
    char dir[400];
    snprintf(dir, sizeof(dir), "%s/sloth_bench_manifest_XXXXXX",
             root && *root ? root : "/tmp");
    if (!mkdtemp(dir)) { perror("bench: mkdtemp"); return 2; }
    char err[SFILE_ERR_MAX];
    int dfd = sfile_private_dir(dir, err, sizeof(err));
    if (dfd < 0) { fprintf(stderr, "bench: %s\n", err); rm_dir(dir); return 2; }
    double *pin_ms = calloc((size_t)iters, sizeof(double));
    double *rec_ms = calloc((size_t)iters, sizeof(double));
    char *chunk = malloc(65536);
    if (!pin_ms || !rec_ms || !chunk) { fprintf(stderr, "bench: oom\n"); return 2; }
    memset(chunk, 'a', 65536);

    printf("sloth manifest bench (#92 slice 3), %d iterations, dir %s\n",
           iters, root && *root ? root : "/tmp");
    static const long sizes[] = { 4L << 10, 1L << 20, 16L << 20 };
    int fail = 0;
    for (size_t z = 0; z < sizeof(sizes) / sizeof(sizes[0]); z++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/eapol.22000", dir);
        FILE *f = fopen(path, "wb");
        if (!f) { perror("bench: fopen"); fail = 1; break; }
        for (long w = 0; w < sizes[z]; ) {
            long n = sizes[z] - w < 65536 ? sizes[z] - w : 65536;
            fwrite(chunk, 1, (size_t)n, f);
            w += n;
        }
        fclose(f);
        evm_meta_t m = { EVM_SINK_HASHCAT_22000, NULL, NULL };
        for (int i = 0; i < iters; i++) {
            evm_pin_t pin;
            double a = now_ms();
            int rc = evidence_manifest_pin(dfd, "eapol.22000", &pin,
                                           err, sizeof(err));
            double b = now_ms();
            if (rc == 0)
                rc = evidence_manifest_record_pinned(&pin, &m, err, sizeof(err));
            double c = now_ms();
            if (rc != 0) { fprintf(stderr, "bench: %s\n", err); fail = 1; break; }
            pin_ms[i] = b - a;
            rec_ms[i] = c - b;
        }
        if (fail) break;
        printf("  eapol.22000 %6ld KiB  under lock (pin) median %8.3f ms"
               "   after unlock (hash+append+fsync) median %8.3f ms\n",
               sizes[z] >> 10, median(pin_ms, iters), median(rec_ms, iters));
    }
    close(dfd);
    evidence_manifest_reset();
    rm_dir(dir);
    free(pin_ms); free(rec_ms); free(chunk);
    return fail;
}
