#include <stdio.h>
#include <stdint.h>
#include "quic_snoop.h"

/*
 * QUIC Long Header layout (RFC 9000 §17.2):
 *
 *   Byte 0:  1 H H T T R R P   (H=Fixed=1, TT=type, R=reserved, PP=PNLEN)
 *            bit 7 = Header Form = 1  (Long Header)
 *            bit 6 = Fixed Bit  = 1  (must be 1 on wire, before HP mask)
 *            bits 5-4 = Long Packet Type
 *            bits 3-0 = reserved + PNLEN (protected by header protection)
 *
 *   Bytes 1-4: Version (big-endian)
 *   Byte 5:  DCIL (Destination Connection ID Length, 0-20)
 *   Bytes 6..(6+DCIL-1): DCID
 *   Byte 6+DCIL: SCIL
 *   ... rest is encrypted / variable
 *
 * Note: bits 3-0 of byte 0 are XOR'd by the QUIC header-protection mask,
 * so they may not carry their plaintext values on the wire.  Bits 7-4 are
 * NOT header-protected and can be read directly.
 *
 * Long Packet Type for Initial:
 *   QUIC v1 (RFC 9000): bits 5-4 = 00  → (first & 0x30) == 0x00
 *   QUIC v2 (RFC 9369): bits 5-4 = 01  → (first & 0x30) == 0x10
 */

int quic_detect(const uint8_t *data, int len, char *ver_out, int versz) {
    if (len < 7) return 0;   /* need at least header through DCIL */

    uint8_t first = data[0];

    /* Long Header (bit 7) and Fixed Bit (bit 6) must both be set */
    if ((first & 0xC0) != 0xC0) return 0;

    uint32_t ver = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                   ((uint32_t)data[3] <<  8) |  (uint32_t)data[4];

    const char *vstr;
    uint8_t     init_type;   /* expected value of (first & 0x30) for Initial */

    switch (ver) {
    case 0x00000001u:                  /* QUIC v1 RFC 9000 */
        vstr = "v1"; init_type = 0x00; break;
    case 0x6b3343cfu:                  /* QUIC v2 RFC 9369 */
        vstr = "v2"; init_type = 0x10; break;
    case 0xff00001du:                  /* draft-29 */
    case 0xff000020u:                  /* draft-32 */
    case 0xff000021u:                  /* draft-33 */
    case 0xff000022u:                  /* draft-34 */
        vstr = "draft"; init_type = 0x00; break;
    default:
        return 0;
    }

    /* Verify packet type is Initial for this version */
    if ((first & 0x30) != init_type) return 0;

    /* DCIL must be 0-20 (RFC 9000 §17.2) */
    uint8_t dcil = data[5];
    if (dcil > 20) return 0;

    /* Enough bytes to cover DCID + SCIL byte */
    if (len < 6 + (int)dcil + 1) return 0;

    if (ver_out && versz > 0)
        snprintf(ver_out, (size_t)versz, "%s", vstr);
    return 1;
}
