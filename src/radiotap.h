/* Radiotap header parser — roadmap B3.
 *
 * Extracted from src/capture/probe.c so it can be unit-tested. probe.c
 * is compiled only under WITH_PCAP and is not in the test build, so
 * this parser — a pure byte decoder of a documented layout, exactly the
 * kind of thing this repo tests from first principles — had no test
 * coverage at all while living there.
 *
 * The extraction also widened it. probe.c read only the antenna signal
 * and the channel, stepping over FLAGS and RATE with `off += 1`. FLAGS
 * carries the **FCS-failed** bit, which is the passive signature of
 * interference, a hidden node, or a jammer, and it was being discarded
 * one byte at a time.
 *
 * Layout reference: https://www.radiotap.org — an 8-byte header
 * (version, pad, length, present bitmap) followed by the present
 * fields in bit order, each naturally aligned. */

#ifndef SLOTH_RADIOTAP_H
#define SLOTH_RADIOTAP_H

#include <stdint.h>

/* Present-bitmap bits this parser understands. */
#define RT_BIT_TSFT           0
#define RT_BIT_FLAGS          1
#define RT_BIT_RATE           2
#define RT_BIT_CHANNEL        3
#define RT_BIT_FHSS           4
#define RT_BIT_DBM_ANTSIGNAL  5
#define RT_BIT_EXT           31   /* another present word follows */

/* FLAGS field bits (radiotap "Flags"). */
#define RT_F_CFP        0x01
#define RT_F_SHORTPRE   0x02
#define RT_F_WEP        0x04
#define RT_F_FRAG       0x08
#define RT_F_FCS        0x10   /* frame includes a trailing FCS */
#define RT_F_DATAPAD    0x20
#define RT_F_BADFCS     0x40   /* FCS check failed */

typedef struct {
    int8_t signal_dbm;   /* -100 when the field is absent */
    int    has_signal;
    int    freq_mhz;     /* 0 when absent */
    int    channel;      /* 0 when absent or unmapped */
    int    rate_kbps;    /* 0 when absent */
    int    bad_fcs;      /* 1 iff RT_F_BADFCS was set */
    int    has_flags;
    int    hdr_len;      /* radiotap header length, for skipping to 802.11 */
} radiotap_info_t;

/* Decode `buf` (at least `len` bytes). Returns 1 on a well-formed
 * header, 0 otherwise; `out` is always fully initialised first, so a
 * failed parse leaves usable defaults rather than garbage. */
int radiotap_parse(const uint8_t *buf, int len, radiotap_info_t *out);

/* Frequency (MHz) to 802.11 channel number across 2.4 / 5 / 6 GHz.
 * Shared so a monitor capture and a managed-mode scan cannot disagree
 * about what channel an AP is on. Returns 0 for anything unmapped. */
int radiotap_freq_to_channel(int mhz);

#endif /* SLOTH_RADIOTAP_H */
