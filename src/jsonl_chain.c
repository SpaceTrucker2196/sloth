#include "jsonl_chain.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* See the header for the record, the segments and what the chain does
 * not show. */

static const char ZERO_HEX[JC_HEX_LEN] =
    "0000000000000000000000000000000000000000000000000000000000000000";
#define CHAIN_PREFIX "{\"type\":\"chain\","

static void hex_of(const uint8_t d[32], char hex[JC_HEX_LEN]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 0xf];
    }
    hex[64] = '\0';
}

static void ctx_hex(sha256_ctx_t *c, char hex[JC_HEX_LEN]) {
    uint8_t d[32];
    sha256_final(c, d);
    hex_of(d, hex);
}

/* SHA-256 of a record's line as the file holds it: the bytes and '\n'. */
static void line_hex(const char *rec, size_t n, char hex[JC_HEX_LEN]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)rec, n);
    sha256_update(&c, (const uint8_t *)"\n", 1);
    ctx_hex(&c, hex);
}

int jc_parse_block(const char *arg, unsigned *out, char *err, size_t errsz) {
    unsigned long v = 0;
    const char *p = arg ? arg : "";
    if (!*p) goto bad;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') goto bad;
        v = v * 10 + (unsigned long)(*p - '0');
        if (v > JC_MAX_BLOCK) goto bad;
    }
    if (v == 0) goto bad;
    *out = (unsigned)v;
    return 0;
bad:
    snprintf(err, errsz, "--jsonl-chain %s: records per block, 1..%u",
             arg ? arg : "", JC_MAX_BLOCK);
    return -1;
}

int jc_format(char *out, size_t cap, long long ts, unsigned n_per,
              unsigned long long seq, unsigned lines,
              const char *block_hex, const char *prev_hex) {
    int n = snprintf(out, cap,
        CHAIN_PREFIX "\"ts\":%lld,\"v\":1,\"n\":%u,\"seq\":%llu,\"lines\":%u,"
        "\"block_sha256\":\"%s\",\"prev_sha256\":\"%s\"}",
        ts, n_per, seq, lines, block_hex, prev_hex);
    return (n > 0 && (size_t)n < cap) ? n : 0;
}

void jc_writer_init(jc_writer_t *w, unsigned n) {
    memset(w, 0, sizeof(*w));
    w->n = n;
    memcpy(w->prev, ZERO_HEX, sizeof(w->prev));
    sha256_init(&w->blk);
}

int jc_writer_add(jc_writer_t *w, const char *bytes, size_t len) {
    if (!w->n || !bytes) return 0;
    sha256_update(&w->blk, (const uint8_t *)bytes, len);
    for (size_t i = 0; i < len; i++)
        if (bytes[i] == '\n') w->blk_lines++;
    return w->blk_lines >= w->n;
}

/* Close the block into a record. Genesis is the same with no lines:
 * its block is the hash of nothing and its prev the zeros. */
static int seal(jc_writer_t *w, time_t ts, char *out, size_t cap, int genesis) {
    char blk[JC_HEX_LEN];
    ctx_hex(&w->blk, blk);
    int n = jc_format(out, cap, (long long)ts, w->n,
                      (unsigned long long)(w->seq + 1), w->blk_lines, blk,
                      genesis ? ZERO_HEX : w->prev);
    if (!n) return 0;
    w->seq++;
    line_hex(out, (size_t)n, w->prev);
    w->blk_lines = 0;
    sha256_init(&w->blk);
    return n;
}

int jc_writer_genesis(jc_writer_t *w, time_t ts, char *out, size_t cap) {
    unsigned n = w->n;
    jc_writer_init(w, n);
    return seal(w, ts, out, cap, 1);
}

int jc_writer_seal(jc_writer_t *w, time_t ts, char *out, size_t cap) {
    if (!w->n || w->seq == 0 || w->blk_lines == 0) return 0;
    return seal(w, ts, out, cap, 0);
}


int jc_sha256_at(int dirfd, const char *name, char hex[JC_HEX_LEN]) {
    hex[0] = '\0';
    if (dirfd < 0 || !name || !name[0] || strchr(name, '/') ||
        !strcmp(name, ".") || !strcmp(name, ".."))
        return -1;
    /* O_NOCTTY and O_NONBLOCK: nothing at the name is a terminal to
     * acquire or a FIFO to wait on before the S_ISREG test. */
    int fd = openat(dirfd, name,
                    O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    sha256_ctx_t c;
    sha256_init(&c);
    uint8_t buf[8192];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        sha256_update(&c, buf, (size_t)r);
    }
    close(fd);
    ctx_hex(&c, hex);
    return 0;
}
