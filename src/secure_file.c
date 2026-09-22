#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "secure_file.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void seterr(char *err, size_t errsz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void seterr(char *err, size_t errsz, const char *fmt, ...) {
    if (!err || errsz == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* The shared ownership + mode rule. `want_dir` selects the type check;
 * files additionally need st_nlink == 1 so a hard link planted to some
 * other file of ours cannot be written through. */
static int validate(const struct stat *st, int want_dir, const char *path,
                    char *err, size_t errsz) {
    if (want_dir ? !S_ISDIR(st->st_mode) : !S_ISREG(st->st_mode)) {
        seterr(err, errsz, "%s: not a %s — refusing", path,
               want_dir ? "directory" : "regular file");
        return -1;
    }
    if (st->st_uid != geteuid()) {
        seterr(err, errsz, "%s: owned by another user — refusing", path);
        return -1;
    }
    if (st->st_mode & 077) {
        seterr(err, errsz,
               "%s: mode %04o is group/other accessible — refusing "
               "(sloth will not chmod it; make it private or pick a new path)",
               path, (unsigned)(st->st_mode & 07777));
        return -1;
    }
    if (!want_dir && st->st_nlink != 1) {
        seterr(err, errsz, "%s: has multiple hard links — refusing", path);
        return -1;
    }
    return 0;
}

int sfile_private_dir(const char *path, char *err, size_t errsz) {
    if (!path || !path[0]) {
        seterr(err, errsz, "empty directory path");
        return -1;
    }
    /* mkdir's mode is still masked by umask, but umask can only remove
     * bits from 0700 — never add group/other. EEXIST falls through to
     * validation: mkdir does not touch the mode of an existing path. */
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        seterr(err, errsz, "%s: could not create directory: %s",
               path, strerror(errno));
        return -1;
    }
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* O_DIRECTORY|O_NOFOLLOW on a link reports ENOTDIR or ELOOP
         * depending on the kernel; name the actual problem. */
        int e = errno;
        struct stat ls;
        if (lstat(path, &ls) == 0 && S_ISLNK(ls.st_mode))
            seterr(err, errsz, "%s: is a symbolic link — refusing", path);
        else
            seterr(err, errsz, "%s: %s", path, strerror(e));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        seterr(err, errsz, "%s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (validate(&st, 1, path, err, errsz) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int sfile_open(int dirfd, const char *name, sfile_mode_t mode,
               char *err, size_t errsz) {
    /* O_NONBLOCK so a FIFO planted at the path cannot hang the open
     * waiting for a reader; it is refused by the type check below and
     * the flag is cleared again for the regular file we keep. */
    int flags = O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (mode == SFILE_APPEND) flags |= O_APPEND;
    if (mode == SFILE_EXCL)   flags |= O_EXCL;
    int fd = openat(dirfd, name, flags, 0600);
    if (fd < 0) {
        int e = errno;
        if (e == ELOOP)
            seterr(err, errsz, "%s: is a symbolic link — refusing", name);
        else
            seterr(err, errsz, "%s: %s", name, strerror(e));
        errno = e;
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = errno;
        seterr(err, errsz, "%s: %s", name, strerror(e));
        close(fd);
        errno = e;
        return -1;
    }
    if (validate(&st, 0, name, err, errsz) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    if (mode == SFILE_TRUNC && ftruncate(fd, 0) != 0) {
        int e = errno;
        seterr(err, errsz, "%s: truncate failed: %s", name, strerror(e));
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

FILE *sfile_fopen(int dirfd, const char *name, sfile_mode_t mode,
                  char *err, size_t errsz) {
    int fd = sfile_open(dirfd, name, mode, err, errsz);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, mode == SFILE_APPEND ? "ab" : "wb");
    if (!f) {
        int e = errno;
        seterr(err, errsz, "%s: %s", name, strerror(e));
        close(fd);
        errno = e;
    }
    return f;
}

FILE *sfile_fopen_unique(int dirfd, const char *stem, const char *ext,
                         char *name_out, size_t name_sz,
                         char *err, size_t errsz) {
    for (int i = 1; i <= 99; i++) {
        if (i == 1) snprintf(name_out, name_sz, "%s%s", stem, ext);
        else        snprintf(name_out, name_sz, "%s_%d%s", stem, i, ext);
        FILE *f = sfile_fopen(dirfd, name_out, SFILE_EXCL, err, errsz);
        if (f || errno != EEXIST) return f;
    }
    seterr(err, errsz, "%s%s: 99 same-named files already exist", stem, ext);
    return NULL;
}

int sfile_check_existing(const char *path, char *err, size_t errsz) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) return 0;
        seterr(err, errsz, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        seterr(err, errsz, "%s: is a symbolic link — refusing", path);
        return -1;
    }
    return validate(&st, 0, path, err, errsz);
}

int sfile_fclose(FILE *f, const char *what, char *err, size_t errsz) {
    if (!f) return -1;
    int bad = ferror(f);
    int e = bad ? errno : 0;
    if (fflush(f) != 0 && !bad) { bad = 1; e = errno; }
    if (fclose(f) != 0 && !bad) { bad = 1; e = errno; }
    if (bad) {
        seterr(err, errsz, "%s: write failed: %s", what,
               e ? strerror(e) : "I/O error");
        return -1;
    }
    return 0;
}

void sfile_fail(sfile_fail_t *f, const char *who, const char *msg) {
    f->failures++;
    snprintf(f->last, sizeof(f->last), "%s", msg ? msg : "?");
    if (!f->reported) {
        fprintf(stderr, "sloth: %s export failed: %s "
                        "(further failures counted, not repeated)\n",
                who, f->last);
        f->reported = 1;
    }
}

void sfile_fail_reset(sfile_fail_t *f) {
    f->failures = 0;
    f->reported = 0;
    f->last[0]  = '\0';
}
