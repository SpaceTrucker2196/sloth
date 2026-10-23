/* Replay input generator (#119).
 *
 *   gen_replay OUTDIR [BASE_TS]
 *
 * Writes OUTDIR/wired.pcap (EN10MB), OUTDIR/monitor.pcap (radiotap) and
 * OUTDIR/bt.pcap (Bluetooth Linux monitor, DLT 254, #144 slice 2) for
 * `make replay-check`. The savefiles are BUILT, never committed:
 * tests/ holds no .pcap and must not start to (agents/AGENTS.md, "No
 * pcap fixtures"). What is committed is the normalised JSONL sloth
 * writes after reading them — tests/replay/golden.jsonl — so a change
 * in behaviour shows as a diff of output, reviewable in a PR, while the
 * input stays a set of hand-built byte arrays anyone can audit here.
 *
 * Every frame is assembled from tests/frame_build.h, field by field per
 * its clause. Addresses are documentation values only: RFC 5737 IPv4
 * blocks, locally-administered MACs (02:00:5e:...), and SSIDs that name
 * no real network. The one IOC hit (THREAT_DOMAIN) is against sloth's
 * own synthetic demo list in src/threat_intel.c, not a real indicator;
 * THREAT_IP reads the platform conn table, which a replay empties, so
 * the SYN to the IOC address only feeds the packet ring.
 *
 * BASE_TS stamps the first frame; the rest follow it a second apart.
 * Detection windows and table ageing run on the wall-clock arrival
 * time, not on the record's own timestamp, so the record times do not
 * change what the golden pins: replaying a 2023-stamped file gives a
 * byte-identical normalised output (checked by the #119 review). The
 * timestamps are stripped by normalise.sh regardless. The file is written with src/pcap_format.c, the writer the
 * four production sinks use, so the generator needs no libpcap.
 *
 * Exit 0 on success, 1 on a write failure, 2 on usage. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pcap_format.h"
#include "frame_build.h"

#define MAX_FRAMES 64
#define FRAME_CAP  512

typedef struct {
    uint8_t  buf[MAX_FRAMES][FRAME_CAP];
    int      len[MAX_FRAMES];
    int      n;
    int      bad;          /* a builder overflowed its frame */
} set_t;

static fb_t *next_frame(set_t *s, fb_t *b) {
    if (s->n >= MAX_FRAMES) { s->bad = 1; s->n = MAX_FRAMES - 1; }
    fb_init(b, s->buf[s->n], FRAME_CAP);
    return b;
}

static void keep(set_t *s, const fb_t *b) {
    if (!fb_ok(b)) s->bad = 1;
    s->len[s->n++] = b->len;
}

static int write_set(const char *path, uint32_t dlt, const set_t *s,
                     uint32_t base_ts) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    pcap_fmt_put_file_hdr(f, dlt, PCAP_SNAPLEN_FRAME);
    for (int i = 0; i < s->n; i++)
        pcap_fmt_put_rec(f, base_ts + (uint32_t)i, 0, s->buf[i],
                         (uint32_t)s->len[i], (uint32_t)s->len[i]);
    if (fclose(f) != 0) { perror(path); return -1; }
    return 0;
}

/* ── Wired ──────────────────────────────────────────────────────────── */

static const uint8_t GW_MAC[6]   = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01 };
static const uint8_t HOST_MAC[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x10 };
static const uint8_t HOST_IP[4]  = { 192, 0, 2, 10 };      /* RFC 5737 */
static const uint8_t DNS_IP[4]   = { 198, 51, 100, 53 };
static const uint8_t WEB_IP[4]   = { 198, 51, 100, 80 };
static const uint8_t PING_IP[4]  = { 198, 51, 100, 1 };
/* On src/threat_intel.c's synthetic demo list, so THREAT_* has an input. */
static const uint8_t IOC_IP[4]   = { 203, 0, 113, 13 };
static const char    IOC_NAME[]  = "c2.example-bad.com";

/* DNS message (RFC 1035 §4.1): header, one question, and for a response
 * one A answer using a compression pointer to the question name
 * (§4.1.4, 0xC00C = offset 12). Returns the message length. */
static int dns_msg(uint8_t *m, int cap, uint16_t id, int response,
                   const char *name, const uint8_t a[4]) {
    fb_t b; fb_init(&b, m, cap);
    fb_be16(&b, id);
    fb_be16(&b, response ? 0x8180 : 0x0100);   /* QR|RD|RA : RD */
    fb_be16(&b, 1);                            /* QDCOUNT */
    fb_be16(&b, response ? 1 : 0);             /* ANCOUNT */
    fb_be16(&b, 0);
    fb_be16(&b, 0);
    for (const char *p = name; *p; ) {         /* QNAME as labels */
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        fb_u8(&b, (uint8_t)l);
        fb_bytes(&b, p, l);
        p += l + (dot ? 1 : 0);
    }
    fb_u8(&b, 0);
    fb_be16(&b, 1);                            /* QTYPE A */
    fb_be16(&b, 1);                            /* QCLASS IN */
    if (response) {
        fb_be16(&b, 0xC00C);
        fb_be16(&b, 1);
        fb_be16(&b, 1);
        fb_be16(&b, 0); fb_be16(&b, 300);      /* TTL */
        fb_be16(&b, 4);
        fb_bytes(&b, a, 4);
    }
    return fb_ok(&b) ? b.len : -1;
}

static void build_wired(set_t *s) {
    fb_t b;
    uint8_t msg[128];
    int ml;

    ml = dns_msg(msg, sizeof msg, 0x1901, 0, IOC_NAME, NULL);
    if (ml < 0) s->bad = 1;
    fb_eth_ipv4_udp(next_frame(s, &b), GW_MAC, HOST_MAC, HOST_IP, DNS_IP,
                    53001, 53, msg, ml < 0 ? 0 : ml, 1);
    keep(s, &b);

    ml = dns_msg(msg, sizeof msg, 0x1901, 1, IOC_NAME, IOC_IP);
    if (ml < 0) s->bad = 1;
    fb_eth_ipv4_udp(next_frame(s, &b), HOST_MAC, GW_MAC, DNS_IP, HOST_IP,
                    53, 53001, msg, ml < 0 ? 0 : ml, 2);
    keep(s, &b);

    fb_eth_ipv4_tcp(next_frame(s, &b), GW_MAC, HOST_MAC, HOST_IP, IOC_IP,
                    40000, 443, 0x1000, 0, FB_TCP_SYN, NULL, 0, 3);
    keep(s, &b);

    /* RFC 7617 Basic credentials, "replay:demo" in base64. */
    static const char get[] =
        "GET /replay HTTP/1.1\r\n"
        "Host: replay.example\r\n"
        "Authorization: Basic cmVwbGF5OmRlbW8=\r\n"
        "\r\n";
    fb_eth_ipv4_tcp(next_frame(s, &b), GW_MAC, HOST_MAC, HOST_IP, WEB_IP,
                    40001, 80, 0x2000, 0x3000, FB_TCP_PSH | FB_TCP_ACK,
                    get, (int)strlen(get), 4);
    keep(s, &b);

    fb_eth_ipv4_icmp_echo(next_frame(s, &b), GW_MAC, HOST_MAC, HOST_IP,
                          PING_IP, 8, 0x0119, 1, 5);
    keep(s, &b);
    fb_eth_ipv4_icmp_echo(next_frame(s, &b), HOST_MAC, GW_MAC, PING_IP,
                          HOST_IP, 0, 0x0119, 1, 6);
    keep(s, &b);
}

/* ── Monitor (radiotap + 802.11) ────────────────────────────────────── */

static const uint8_t AP[6]  = { 0x02, 0x00, 0x5e, 0x00, 0x7b, 0x01 };
static const uint8_t STA[6] = { 0x02, 0x00, 0x5e, 0x00, 0x7b, 0x02 };
static const uint8_t BC[6]  = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Channel 6, -50 dBm: radiotap CHANNEL (bit 3) and DBM_ANTSIGNAL (bit 5). */
static int rt_hdr(fb_t *b) {
    fb_rt_t rt;
    memset(&rt, 0, sizeof rt);
    rt.has_channel = 1; rt.freq_mhz = 2437;
    rt.has_signal  = 1; rt.dbm      = -50;
    return fb_radiotap(b, &rt);
}

static void build_monitor(set_t *s) {
    static const uint8_t rates[4] = { 0x82, 0x84, 0x8b, 0x96 };
    static const uint8_t ds[1]    = { 6 };
    fb_t b;

    /* Beacons (IEEE 802.11-2020 §9.3.3.3): an open ESS on channel 6. */
    for (int i = 0; i < 3; i++) {
        next_frame(s, &b);
        rt_hdr(&b);
        fb_mgmt(&b, 8, 0, BC, AP, AP, (uint16_t)((10 + i) << 4), 0);
        fb_beacon_fixed(&b, (uint64_t)i * 102400u, 100, 0x0001);
        fb_ssid(&b, "replay-open");
        fb_ie(&b, 1, rates, (int)sizeof rates);
        fb_ie(&b, 3, ds, 1);
        keep(s, &b);
    }

    /* Probe request (§9.3.3.10) naming a network the client remembers. */
    next_frame(s, &b);
    rt_hdr(&b);
    fb_mgmt(&b, 4, 0, BC, STA, BC, 0x0200, 0);
    fb_ssid(&b, "replay-home");
    fb_ie(&b, 1, rates, (int)sizeof rates);
    keep(s, &b);

    /* Deauthentication (§9.3.3.12), reason 7 (Table 9-49: class 3 frame
     * from a nonassociated STA), AP → client, distinct sequence numbers
     * so none reads as a retransmission (10.3.2.14). Twelve inside one
     * replay is past DEAUTH_FLOOD_THRESH in any window the tune table
     * allows a default run. */
    for (int i = 0; i < 12; i++) {
        next_frame(s, &b);
        rt_hdr(&b);
        fb_mgmt(&b, 12, 0, STA, AP, AP, (uint16_t)((100 + i) << 4), 0);
        fb_le16(&b, 7);
        keep(s, &b);
    }
}

/* ── Bluetooth host source (DLT 254) ───────────────────────────────── */

/* libpcap's monitor header, then the payload by monitor opcode (Linux
 * include/net/bluetooth/hci_mon.h): 0 NEW_INDEX, 2 COMMAND, 3 EVENT,
 * 5 ACL_RX. Addresses are locally administered / random-static shapes
 * naming no real device; the local names say what they are. */
static void bt_hdr(fb_t *b, uint16_t opcode) {
    fb_be16(b, 0);          /* adapter index: hci0 */
    fb_be16(b, opcode);
}

static void bt_cmd(set_t *s, uint16_t op, const uint8_t *p, uint8_t plen) {
    fb_t b;
    next_frame(s, &b);
    bt_hdr(&b, 2);
    fb_le16(&b, op);        /* Core Spec v5.4 Vol 4 Part E §5.4.1 */
    fb_u8(&b, plen);
    fb_bytes(&b, p, plen);
    keep(s, &b);
}

/* One LE Advertising Report (§7.7.65.2), one report, a Complete Local
 * Name AD structure (Vol 3 Part C §11). */
static void bt_adv(set_t *s, const uint8_t addr_le[6], const char *name,
                   int8_t rssi) {
    fb_t b;
    int nl = (int)strlen(name);
    next_frame(s, &b);
    bt_hdr(&b, 3);
    fb_u8(&b, 0x3E);
    fb_u8(&b, (uint8_t)(12 + 2 + nl));
    fb_u8(&b, 0x02);        /* LE Advertising Report */
    fb_u8(&b, 1);           /* Num_Reports */
    fb_u8(&b, 0x03);        /* ADV_NONCONN_IND */
    fb_u8(&b, 0x01);        /* random address */
    fb_bytes(&b, addr_le, 6);
    fb_u8(&b, (uint8_t)(2 + nl));
    fb_u8(&b, (uint8_t)(1 + nl));
    fb_u8(&b, 0x09);        /* Complete Local Name */
    fb_bytes(&b, name, nl);
    fb_u8(&b, (uint8_t)rssi);
    keep(s, &b);
}

static void build_bt(set_t *s) {
    static const uint8_t CTRL[6] = { 0x01, 0x53, 0x00, 0x5e, 0x00, 0x02 };
    static const uint8_t TAG1[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0 };
    static const uint8_t TAG2[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xC0 };
    static const uint8_t TAG3[6] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0xC0 };
    fb_t b;

    /* NEW_INDEX: primary controller on USB, "hci0". */
    next_frame(s, &b);
    bt_hdr(&b, 0);
    fb_u8(&b, 0x00);
    fb_u8(&b, 0x01);
    fb_bytes(&b, CTRL, 6);
    fb_bytes(&b, "hci0\0\0\0\0", 8);
    keep(s, &b);

    /* LE Set Scan Parameters (§7.8.10): PASSIVE, 10 ms / 10 ms, public
     * own address, basic unfiltered policy — the scan docs/wiki/ble.md
     * asks the operator to run. Then LE Set Scan Enable (§7.8.11). */
    static const uint8_t params[7] = { 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    bt_cmd(s, 0x200B, params, 7);
    static const uint8_t enable[2] = { 0x01, 0x00 };
    bt_cmd(s, 0x200C, enable, 2);

    bt_adv(s, TAG1, "replay-tag-1", -48);
    bt_adv(s, TAG2, "replay-tag-2", -71);
    bt_adv(s, TAG1, "replay-tag-1", -45);

    /* A two-report event, as the consecutive records Vol 4 Part E §5.2
     * orders arrayed parameters in: both reports decoded. */
    next_frame(s, &b);
    bt_hdr(&b, 3);
    fb_u8(&b, 0x3E);
    fb_u8(&b, 2 + 2 * 10);
    fb_u8(&b, 0x02);
    fb_u8(&b, 2);
    fb_u8(&b, 0x03); fb_u8(&b, 0x01); fb_bytes(&b, TAG1, 6);
    fb_u8(&b, 0);    fb_u8(&b, (uint8_t)-60);
    fb_u8(&b, 0x03); fb_u8(&b, 0x01); fb_bytes(&b, TAG2, 6);
    fb_u8(&b, 0);    fb_u8(&b, (uint8_t)-61);
    keep(s, &b);

    /* An LE Extended Advertising Report (§7.7.65.13) holding two
     * reports: a Legacy-bit ADV_NONCONN_IND from TAG2 (LE 1M, no
     * secondary PHY, no ADI, as the clause requires of a legacy PDU),
     * which keys TAG2's legacy row, and an extended PDU from TAG3 on
     * LE Coded with a 2M secondary, SID 5, carrying a name. */
    static const char ext_name[] = "replay-ext-3";
    const int enl = (int)sizeof(ext_name) - 1;
    next_frame(s, &b);
    bt_hdr(&b, 3);
    fb_u8(&b, 0x3E);
    fb_u8(&b, (uint8_t)(2 + 24 + 24 + 2 + enl));
    fb_u8(&b, 0x0D);
    fb_u8(&b, 2);
    fb_le16(&b, 0x0010);    /* Legacy, ADV_NONCONN_IND, complete */
    fb_u8(&b, 0x01);
    fb_bytes(&b, TAG2, 6);
    fb_u8(&b, 0x01); fb_u8(&b, 0x00); fb_u8(&b, 0xFF);
    fb_u8(&b, 127);         /* TX_Power not available */
    fb_u8(&b, (uint8_t)-66);
    fb_le16(&b, 0);
    fb_u8(&b, 0); for (int i = 0; i < 6; i++) fb_u8(&b, 0);
    fb_u8(&b, 0);           /* Data_Length */
    fb_le16(&b, 0x0000);    /* extended, non-connectable, complete */
    fb_u8(&b, 0x01);
    fb_bytes(&b, TAG3, 6);
    fb_u8(&b, 0x03); fb_u8(&b, 0x02); fb_u8(&b, 0x05);
    fb_u8(&b, (uint8_t)-4);
    fb_u8(&b, (uint8_t)-52);
    fb_le16(&b, 0);
    fb_u8(&b, 0); for (int i = 0; i < 6; i++) fb_u8(&b, 0);
    fb_u8(&b, (uint8_t)(2 + enl));
    fb_u8(&b, (uint8_t)(1 + enl));
    fb_u8(&b, 0x09);        /* Complete Local Name */
    fb_bytes(&b, ext_name, enl);
    keep(s, &b);

    /* ACL data: outside the allow-list, never read. */
    next_frame(s, &b);
    bt_hdr(&b, 5);
    for (int i = 0; i < 12; i++) fb_u8(&b, 0xA5);
    keep(s, &b);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s OUTDIR [BASE_TS]\n", argv[0]);
        return 2;
    }
    uint32_t base = (uint32_t)time(NULL);
    if (argc == 3) {
        char *end = NULL;
        unsigned long v = strtoul(argv[2], &end, 10);
        if (!end || *end || end == argv[2] || v == 0 || v > 0xffffffffUL) {
            fprintf(stderr, "gen_replay: BASE_TS %s: want seconds since the epoch\n",
                    argv[2]);
            return 2;
        }
        base = (uint32_t)v;
    }

    static set_t wired, mon, bt;
    build_wired(&wired);
    build_monitor(&mon);
    build_bt(&bt);
    if (wired.bad || mon.bad || bt.bad) {
        fprintf(stderr, "gen_replay: a frame overflowed its buffer\n");
        return 1;
    }

    char path[1024];
    snprintf(path, sizeof path, "%s/wired.pcap", argv[1]);
    if (write_set(path, PCAP_DLT_EN10MB, &wired, base) != 0) return 1;
    snprintf(path, sizeof path, "%s/monitor.pcap", argv[1]);
    if (write_set(path, PCAP_DLT_RADIOTAP, &mon, base) != 0) return 1;
    snprintf(path, sizeof path, "%s/bt.pcap", argv[1]);
    if (write_set(path, PCAP_DLT_BT_MONITOR, &bt, base) != 0) return 1;
    return 0;
}
