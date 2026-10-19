#include <string.h>
#include "dns_wire.h"

int dns_read_name(const uint8_t *msg, int msglen, int off,
                  char *buf, int bufsz) {
    int out = 0, jumped = 0, resume = -1, hops = 0;
    if (!buf || bufsz < 1) return -1;
    buf[0] = '\0';
    if (!msg) return -1;
    for (;;) {
        if (off < 0 || off >= msglen) return -1;
        uint8_t c = msg[off];
        if ((c & 0xC0) == 0xC0) {
            if (off + 1 >= msglen) return -1;
            if (!jumped) resume = off + 2;
            off = ((c & 0x3F) << 8) | msg[off + 1];
            jumped = 1;
            if (++hops > DNS_NAME_MAX_HOPS) return -1;
            continue;
        }
        if (c & 0xC0) return -1;   /* 01 / 10: reserved label types */
        off++;
        if (c == 0) break;         /* root label ends the name */
        if (off + (int)c > msglen) return -1;
        if (out > 0 && out < bufsz - 1) buf[out++] = '.';
        int copy = (int)c;
        if (out + copy >= bufsz) copy = bufsz - out - 1;
        if (copy > 0) { memcpy(buf + out, msg + off, (size_t)copy); out += copy; }
        buf[out] = '\0';
        off += c;
    }
    return jumped ? resume : off;
}

int dns_skip_name(const uint8_t *msg, int msglen, int off) {
    if (!msg) return -1;
    for (;;) {
        if (off < 0 || off >= msglen) return -1;
        uint8_t c = msg[off];
        if ((c & 0xC0) == 0xC0)
            return off + 2 <= msglen ? off + 2 : -1;
        if (c & 0xC0) return -1;
        off++;
        if (c == 0) return off;
        if (off + (int)c > msglen) return -1;
        off += c;
    }
}
