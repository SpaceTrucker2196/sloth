/* slothweb's Camera tab: see web_camera.h. */
#include "web_camera.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void web_camera_init(web_camera_t *cam, const char *dir) {
    snprintf(cam->dir, sizeof(cam->dir), "%s", dir && dir[0] ? dir : WEB_CAMERA_DIR);
}

int web_camera_get(const web_camera_t *cam, unsigned char **data, size_t *len,
                   long long *mtime_s, int *status) {
    *data = NULL;
    *len = 0;
    *mtime_s = 0;
    *status = 503;
    char path[1100];
    if (snprintf(path, sizeof(path), "%s/latest.jpg", cam->dir) >= (int)sizeof(path))
        return 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) *status = 404;
        return 0;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 4 ||
        st.st_size > WEB_CAMERA_MAX_BYTES) {
        close(fd);
        return 0;
    }
    size_t n = (size_t)st.st_size;
    unsigned char *buf = malloc(n);
    if (!buf) {
        close(fd);
        return -1;
    }
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    /* A whole JPEG: SOI first, EOI last. A file cut short (or grown)
     * under the read is refused, not served half. */
    if (got != n || buf[0] != 0xFF || buf[1] != 0xD8 || buf[2] != 0xFF ||
        buf[n - 2] != 0xFF || buf[n - 1] != 0xD9) {
        free(buf);
        return 0;
    }
    *data = buf;
    *len = n;
    *mtime_s = (long long)st.st_mtime;
    *status = 200;
    return 0;
}
