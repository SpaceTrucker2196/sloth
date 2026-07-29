/* Radiotap header parser. Contract in radiotap.h (roadmap B3). */

#include <string.h>

#include "radiotap.h"

#define RT_PAD(o, a)  (((o) + ((a)-1)) & ~((a)-1))

int radiotap_freq_to_channel(int mhz) {
    if (mhz >= 2412 && mhz <= 2472) return (mhz - 2407) / 5;
    if (mhz == 2484)                return 14;          /* Japan, ch 14 */
    if (mhz >= 5160 && mhz <= 5895) return (mhz - 5000) / 5;
    if (mhz >= 5955 && mhz <= 7115) return (mhz - 5950) / 5;   /* 6 GHz */
    return 0;
}

int radiotap_parse(const uint8_t *buf, int len, radiotap_info_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->signal_dbm = -100;

    if (!buf || len < 8) return 0;

    uint16_t rt_len = (uint16_t)(buf[2] | (buf[3] << 8));
    if (rt_len < 8 || (int)rt_len > len) return 0;
    out->hdr_len = rt_len;

    uint32_t pres = (uint32_t)(buf[4] | ((uint32_t)buf[5] << 8) |
                               ((uint32_t)buf[6] << 16) |
                               ((uint32_t)buf[7] << 24));

    /* Skip any extended present bitmaps.
     *
     * Each present word's bit 31 says another word follows, so the
     * loop has to read each successive word — testing the *first*
     * word's bit repeatedly (as the original in probe.c did) never
     * terminates on its own condition and instead advanced `off` to
     * the end of the header, leaving every field unread. Any capture
     * from a driver that emits extended bitmaps therefore produced no
     * signal and no channel at all. */
    int off = 8;
    uint32_t word = pres;
    while (word & (1u << RT_BIT_EXT)) {
        if (off + 4 > (int)rt_len) return 0;   /* truncated header */
        word = (uint32_t)(buf[off] | ((uint32_t)buf[off+1] << 8) |
                          ((uint32_t)buf[off+2] << 16) |
                          ((uint32_t)buf[off+3] << 24));
        off += 4;
    }

    /* Fields follow in bit order, each naturally aligned relative to
     * the start of the header. Only the first present word's bits
     * describe the fields we read. */
    if (pres & (1u << RT_BIT_TSFT)) {
        off = RT_PAD(off, 8);
        off += 8;
    }
    if (pres & (1u << RT_BIT_FLAGS)) {
        if (off + 1 > (int)rt_len) return 1;
        out->has_flags = 1;
        out->bad_fcs   = (buf[off] & RT_F_BADFCS) ? 1 : 0;
        off += 1;
    }
    if (pres & (1u << RT_BIT_RATE)) {
        if (off + 1 > (int)rt_len) return 1;
        /* Radiotap rate is in 500 kbps units. */
        out->rate_kbps = (int)buf[off] * 500;
        off += 1;
    }
    if (pres & (1u << RT_BIT_CHANNEL)) {
        off = RT_PAD(off, 2);
        if (off + 2 <= (int)rt_len) {
            int freq = (int)(buf[off] | ((uint16_t)buf[off+1] << 8));
            out->freq_mhz = freq;
            out->channel  = radiotap_freq_to_channel(freq);
        }
        off += 4;                       /* u16 freq + u16 channel flags */
    }
    if (pres & (1u << RT_BIT_FHSS)) {
        off += 2;
    }
    if (pres & (1u << RT_BIT_DBM_ANTSIGNAL)) {
        if (off < (int)rt_len) {
            out->signal_dbm = (int8_t)buf[off];
            out->has_signal = 1;
        }
    }
    return 1;
}
