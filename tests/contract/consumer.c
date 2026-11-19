/* A consumer of the contract artifact's libsloth-wire (#185 item 4),
 * compiled by tests/contract/check.sh against the UNPACKED archive
 * only: the -I and -L it is given come from the shipped sloth-wire.pc,
 * nothing of this tree is on its include path, and sloth.h is not in
 * the archive. If a shipped header ever pulls in sloth's state, this
 * file stops compiling; if the archive stops carrying a parser, it
 * stops linking; if a parser's answer changes, it exits 1.
 *
 * The frame is built per the specifications, annotated byte by byte as
 * tests/test_beacon_snoop.c builds its frames (agents/AGENTS.md: no
 * pcap fixtures). Radiotap: radiotap.org's header and field
 * definitions. 802.11: IEEE 802.11-2020 §9.2.4 (MAC header), §9.3.3.2
 * (Beacon frame body), §9.4.2.2 (SSID element), §9.4.2.4 (DSSS
 * Parameter Set). */
#include <stdio.h>
#include <string.h>

#include <dot11_frame.h>
#include <dot11_ie.h>
#include <radiotap.h>
#include <sensor_health.h>
#include <wifi_freq.h>

/* The one call the archive makes out of itself: dot11_ie.c notes an
 * element walk that ran past its buffer. libsloth-wire does not define
 * it; its consumer does (slothweb's is sloth-mesh's src/web_sh_stub.c). Counted
 * here so the check can see the archive really calls it. */
static int g_overruns;
void sh_parse_fault_note(sh_parse_fault_t kind) {
    if (kind == SH_PF_IE_OVERRUN) g_overruns++;
}

static int g_fail;
#define EXPECT(cond) do { if (!(cond)) { \
    fprintf(stderr, "consumer: FAIL %s (line %d)\n", #cond, __LINE__); g_fail = 1; } } while (0)

static const unsigned char FRAME[] = {
    /* ── radiotap header ───────────────────────────────────────── */
    0x00,                   /* it_version 0 */
    0x00,                   /* it_pad */
    0x0f, 0x00,             /* it_len 15, little-endian: the whole header */
    0x2e, 0x00, 0x00, 0x00, /* it_present: bits 1 Flags, 2 Rate, 3 Channel,
                             * 5 dBm Antenna Signal; bit 31 clear, one word */
    0x00,                   /* Flags (u8): no FCS, no datapad, FCS not bad */
    0x02,                   /* Rate (u8), 500 kb/s units: 1 Mb/s */
    0x85, 0x09,             /* Channel frequency (u16, 2-aligned at 10): 2437 MHz */
    0xa0, 0x00,             /* Channel flags (u16): 0x00a0, 2 GHz + CCK */
    0xd3,                   /* dBm Antenna Signal (s8): -45 dBm */
    /* ── 802.11 MAC header, §9.3.3.2 ───────────────────────────── */
    0x80, 0x00,             /* Frame Control: version 0, type 0 (management),
                             * subtype 8 (Beacon); no flags */
    0x00, 0x00,             /* Duration */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* Address 1 (DA): broadcast */
    0x02, 0x00, 0x00, 0xc0, 0xff, 0xee, /* Address 2 (SA): locally administered */
    0x02, 0x00, 0x00, 0xc0, 0xff, 0xee, /* Address 3 (BSSID) */
    0x50, 0x01,             /* Sequence Control: fragment 0, sequence 21 */
    /* ── Beacon frame body ─────────────────────────────────────── */
    0, 0, 0, 0, 0, 0, 0, 0, /* Timestamp (8) */
    0x64, 0x00,             /* Beacon Interval: 100 TU */
    0x01, 0x04,             /* Capability: ESS, Short Slot Time */
    0x00, 0x08,             /* SSID element, length 8 */
    'c', 'o', 'n', 't', 'r', 'a', 'c', 't',
    0x03, 0x01, 0x06,       /* DSSS Parameter Set, length 1: channel 6 */
};

#define RT_LEN   15
#define MAC_LEN  24
#define FIXED    12   /* Timestamp + Beacon Interval + Capability */

int main(void) {
    radiotap_info_t rt;
    EXPECT(radiotap_parse(FRAME, (int)sizeof(FRAME), &rt) == 1);
    EXPECT(rt.hdr_len == RT_LEN);
    EXPECT(rt.freq_mhz == 2437);
    EXPECT(rt.channel == 6);
    EXPECT(rt.has_signal && rt.signal_dbm == -45);
    EXPECT(rt.rate_kbps == 1000);
    EXPECT(!rt.fcs_present && !rt.bad_fcs);
    EXPECT(radiotap_freq_to_band(rt.freq_mhz) == WIFI_BAND_2GHZ);

    dot11_rt_hints_t hints = { rt.fcs_present, rt.datapad, rt.bad_fcs };
    dot11_frame_t f;
    const unsigned char *mac = FRAME + RT_LEN;
    int mlen = (int)sizeof(FRAME) - RT_LEN;
    dot11_frame_decode(mac, mlen, &hints, &f);
    EXPECT(f.proto == 0 && f.type == 0 && f.subtype == 8);
    EXPECT(f.hdr_len == MAC_LEN);
    EXPECT(f.seq_num == 21 && f.frag_num == 0);
    EXPECT(f.bssid == mac + 16);
    EXPECT(f.bssid && !memcmp(f.bssid, "\x02\x00\x00\xc0\xff\xee", 6));

    const unsigned char *body = NULL;
    int blen = 0;
    EXPECT(dot11_frame_body(&f, &body, &blen) == 1);
    EXPECT(blen == mlen - MAC_LEN);
    char ssid[33];
    int oversize = -1;
    EXPECT(body && dot11_ie_ssid(body + FIXED, blen - FIXED, ssid, &oversize) == 1);
    EXPECT(!strcmp(ssid, "contract") && oversize == 0);
    const unsigned char *ds = NULL;
    int dslen = 0;
    EXPECT(body && dot11_ie_find(body + FIXED, blen - FIXED, 3, &ds, &dslen) == 1);
    EXPECT(dslen == 1 && ds && ds[0] == 6);

    /* An element list cut inside its last element (an SSID claiming 8
     * octets with 2 present): the walk stops and calls out of the
     * archive through the hook above, once per walk. dot11_ie.c has two
     * walks that note it (the element search and the PHY summary), so
     * both are fed the cut list and each must add one. */
    static const unsigned char CUT[] = { 0x03, 0x01, 0x06, 0x00, 0x08, 'c', 'o' };
    EXPECT(dot11_ie_find(CUT, (int)sizeof(CUT), 0, NULL, NULL) == 0);
    EXPECT(g_overruns == 1);
    dot11_phy_t phy;
    memset(&phy, 0, sizeof(phy));
    dot11_ie_phy(CUT, (int)sizeof(CUT), &phy);
    EXPECT(g_overruns == 2);

    if (!g_fail) printf("consumer: beacon decoded through libsloth-wire\n");
    return g_fail;
}
