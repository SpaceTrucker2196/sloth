#include "web_agent.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* 32 bytes from the kernel's pool, or -1: there is no weaker fallback,
 * because a guessable secret is worse than none. */
static int random_bytes(unsigned char *b, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);
    return got == n ? 0 : -1;
}

int web_agent_secret_make(const char *path, char out[WEB_AGENT_SECRET_LEN + 1],
                          char *err, size_t errsz) {
    static const char hex[] = "0123456789abcdef";
    unsigned char raw[WEB_AGENT_SECRET_LEN / 2];
    char tmp[4200];
    out[0] = '\0';
    int tn = snprintf(tmp, sizeof(tmp), "%s.new", path);
    if (!path[0] || tn < 0 || (size_t)tn >= sizeof(tmp)) {
        snprintf(err, errsz, "--web-agent-secret: empty or too long a path");
        return -1;
    }
    /* What is at the path now is validated, never repaired: a file of
     * someone else's, one others can read, a link or a directory there
     * is a mistake to be looked at, not written over. */
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) || st.st_nlink != 1) {
            snprintf(err, errsz, "--web-agent-secret %s: exists and is not a private regular file "
                                 "of this user (mode 0600, one link); refused, left as it is", path);
            return -1;
        }
    } else if (errno != ENOENT) {
        snprintf(err, errsz, "--web-agent-secret %s: %s", path, strerror(errno));
        return -1;
    }
    if (random_bytes(raw, sizeof(raw)) != 0) {
        snprintf(err, errsz, "--web-agent-secret: no random bytes from /dev/urandom");
        return -1;
    }
    char sec[WEB_AGENT_SECRET_LEN + 2];
    for (size_t i = 0; i < sizeof(raw); i++) {
        sec[2 * i] = hex[raw[i] >> 4];
        sec[2 * i + 1] = hex[raw[i] & 0xF];
    }
    sec[WEB_AGENT_SECRET_LEN] = '\n';
    /* A leftover of a run that died between the create and the rename
     * is ours to remove; anything else at that name fails the create. */
    if (lstat(tmp, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid()) unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err, errsz, "--web-agent-secret %s: %s", tmp, strerror(errno));
        return -1;
    }
    int ok = fchmod(fd, 0600) == 0 &&
             write(fd, sec, WEB_AGENT_SECRET_LEN + 1) == WEB_AGENT_SECRET_LEN + 1 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) {
        snprintf(err, errsz, "--web-agent-secret %s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    memcpy(out, sec, WEB_AGENT_SECRET_LEN);
    out[WEB_AGENT_SECRET_LEN] = '\0';
    return 0;
}

static int peer_loopback(const char *peer) {
    return !strncmp(peer, "127.", 4) || !strcmp(peer, "::1");
}

int web_agent_check(const char *secret, const web_req_t *rq, const char **why) {
    if (rq->agent_count == 0) return 0;
    if (!secret || !secret[0]) { *why = "agent_off"; return -1; }
    /* Every byte of both is read whatever differs: how long a wrong
     * guess took says nothing about how much of it was right. */
    unsigned diff = rq->agent_count != 1 || rq->agent_long ||
                    strlen(rq->agent) != WEB_AGENT_SECRET_LEN;
    for (size_t i = 0; i < WEB_AGENT_SECRET_LEN; i++) {
        unsigned char a = i < sizeof(rq->agent) ? (unsigned char)rq->agent[i] : 0;
        diff |= (unsigned)(a ^ (unsigned char)secret[i]);
        if (!secret[i]) { diff |= 1; break; }
    }
    if (diff) { *why = "bad_agent_secret"; return -1; }
    if (!peer_loopback(rq->peer)) { *why = "agent_not_local"; return -1; }
    if (rq->origin_count || rq->origin_long || rq->fetch_site[0] || rq->fetch_site_long) {
        *why = "agent_with_origin";
        return -1;
    }
    return 1;
}
