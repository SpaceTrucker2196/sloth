#include <string.h>
#include "sni_snoop.h"

/*
 * TLS record and handshake layout (RFC 5246, RFC 8446):
 *
 *  TLS Record (5 bytes):
 *    [0]   content_type   0x16 = handshake
 *    [1-2] version        0x03 0x01..0x03
 *    [3-4] length         (record payload length, big-endian)
 *
 *  Handshake header (4 bytes):
 *    [0]   msg_type       0x01 = ClientHello
 *    [1-3] length         (3-byte big-endian)
 *
 *  ClientHello body:
 *    [0-1]   legacy_version        (2)
 *    [2-33]  random                (32)
 *    [34]    session_id_len        (1)
 *    [35+]   session_id            (0–32)
 *    cipher_suites_len             (2)
 *    cipher_suites                 (variable)
 *    compression_methods_len       (1)
 *    compression_methods           (variable)
 *    extensions_len                (2)
 *    extensions…
 *
 *  SNI extension (type 0x0000):
 *    list_len   (2)
 *    name_type  (1) — 0x00 = host_name
 *    name_len   (2)
 *    name       (name_len bytes) — the SNI hostname, no NUL
 */

static uint16_t u16(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

int sni_snoop(const uint8_t *data, int len, char *host, int hostsz) {
    if (hostsz <= 0) return 0;
    host[0] = '\0';

    /* ── TLS record header ─────────────────────────────────── */
    if (len < 9) return 0;            /* need record(5) + handshake type(1) */
    if (data[0] != 0x16) return 0;   /* not handshake record */
    if (data[1] != 0x03) return 0;   /* not TLS (major version must be 3) */

    uint16_t rec_len = u16(data + 3);
    if ((int)rec_len < 4 || 5 + (int)rec_len > len) return 0;

    /* ── Handshake header ──────────────────────────────────── */
    const uint8_t *hs = data + 5;
    if (hs[0] != 0x01) return 0;     /* not ClientHello */

    int ch_len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
    if (ch_len < 34 + 1 || 4 + ch_len > (int)rec_len) return 0;

    /* ── ClientHello body ──────────────────────────────────── */
    const uint8_t *ch  = hs + 4;     /* points at legacy_version */
    int            rem = ch_len;     /* remaining bytes in ClientHello */
    int            off = 0;

    /* skip legacy_version (2) + random (32) = 34 */
    if (rem < 35) return 0;
    off = 34;

    /* session ID */
    int sid_len = ch[off++];
    if (sid_len < 0 || sid_len > 32 || off + sid_len > rem) return 0;
    off += sid_len;

    /* cipher suites */
    if (off + 2 > rem) return 0;
    int cs_len = (int)u16(ch + off);
    off += 2;
    if (cs_len < 2 || off + cs_len > rem) return 0;
    off += cs_len;

    /* compression methods */
    if (off + 1 > rem) return 0;
    int cm_len = ch[off++];
    if (off + cm_len > rem) return 0;
    off += cm_len;

    /* extensions present? */
    if (off + 2 > rem) return 0;
    int ext_total = (int)u16(ch + off);
    off += 2;
    if (off + ext_total > rem) return 0;

    int ext_end = off + ext_total;

    /* ── Walk extensions ───────────────────────────────────── */
    while (off + 4 <= ext_end) {
        uint16_t ext_type     = u16(ch + off);
        uint16_t ext_data_len = u16(ch + off + 2);
        off += 4;

        if (off + (int)ext_data_len > ext_end) break;

        if (ext_type == 0x0000) {
            /* server_name extension
               [0-1] server_name_list_length
               [2]   name_type  (0x00 = host_name)
               [3-4] name_length
               [5..] name bytes (no NUL terminator) */
            if (ext_data_len < 5) break;
            if (ch[off + 2] != 0x00) break;   /* not host_name type */
            int name_len = (int)u16(ch + off + 3);
            if (name_len <= 0 || off + 5 + name_len > ext_end) break;
            int copy = name_len < hostsz - 1 ? name_len : hostsz - 1;
            memcpy(host, ch + off + 5, (size_t)copy);
            host[copy] = '\0';
            return 1;
        }

        off += (int)ext_data_len;
    }

    return 0;
}
