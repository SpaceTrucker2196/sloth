/* slothweb's Camera tab (2026-11-15): the latest still a capture helper
 * wrote.
 *
 * slothweb never drives the camera. A helper run under its own account
 * (on Beta-Site, sloth-camera.service: ffmpeg on a GoPro's USB preview
 * stream) writes latest.jpg into its state directory, WEB_CAMERA_DIR by
 * default (--camera-dir), world-readable, replacing it atomically.
 *
 *   GET /api/camera.jpg   the still, image/jpeg, with X-Sloth-Captured
 *                         (its mtime, Unix seconds) and X-Sloth-Age (s).
 *                         404 {"error":"no_image"} when there is none,
 *                         503 {"error":"invalid"} when the file is not a
 *                         whole JPEG or is too large.
 *
 * GET and HEAD only; nothing is written, and no request parameter is
 * read. The file is another account's output and treated as untrusted:
 * opened O_NOFOLLOW, read only when it is a regular file of at most
 * WEB_CAMERA_MAX_BYTES, served only when it starts with a JPEG SOI and
 * ends with an EOI, and always as image/jpeg under nosniff. The page
 * fetches it and shows it as a data: URL, so the page's img-src stays
 * data: alone. */
#ifndef SLOTHWEB_CAMERA_H
#define SLOTHWEB_CAMERA_H

#include <stddef.h>

#define WEB_CAMERA_DIR        "/var/lib/sloth-camera"
#define WEB_CAMERA_MAX_BYTES  (8L << 20)

typedef struct web_camera {
    char dir[1024];
} web_camera_t;

void web_camera_init(web_camera_t *cam, const char *dir);

/* *data is malloc'd on 200 (the caller frees it), NULL otherwise.
 * *status: 200, 404 (no file) or 503 (not a regular file, too large,
 * not a whole JPEG, unreadable). *mtime_s is the file's mtime on 200.
 * 0, or -1 when out of memory. */
int  web_camera_get(const web_camera_t *cam, unsigned char **data, size_t *len,
                    long long *mtime_s, int *status);

#endif
