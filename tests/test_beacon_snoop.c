#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "beacon_snoop.h"
#include "views/beacon.h"

/* ── Beacon frame builder helpers ────────────────────────── */

/*
 * Minimal 802.11 beacon frame layout:
 *   [0-1]   Frame Control  (0x80 0x00 = management/beacon)
 *   [2-3]   Duration
 *   [4-9]   DA             (ff:ff:ff:ff:ff:ff broadcast)
 *   [10-15] SA             (BSSID)
 *   [16-21] BSSID
 *   [22-23] Sequence Control
 *   [24-31] Timestamp      (8 bytes)
 *   [32-33] Beacon Interval (little-endian TUs)
 *   [34-35] Capability Information
 *   [36+]  Information Elements
 */

#define BEACON_HDR_LEN 36

static void fill_hdr(uint8_t *f, const uint8_t bssid[6],
                     uint16_t bi_tu, uint16_t cap)
{
    f[0] = 0x80; f[1] = 0x00;                        /* FC */
    f[2] = f[3] = 0x00;                              /* Duration */
    memset(f + 4, 0xff, 6);                           /* DA = broadcast */
    memcpy(f + 10, bssid, 6);                         /* SA = BSSID */
    memcpy(f + 16, bssid, 6);                         /* BSSID */
    f[22] = f[23] = 0x00;                             /* Seq ctrl */
    memset(f + 24, 0x00, 8);                          /* Timestamp */
    f[32] = (uint8_t)(bi_tu & 0xff);                  /* Beacon interval lo */
    f[33] = (uint8_t)(bi_tu >> 8);                    /* Beacon interval hi */
    f[34] = (uint8_t)(cap & 0xff);                    /* Capability lo */
    f[35] = (uint8_t)(cap >> 8);                      /* Capability hi */
}

static const uint8_t BSSID_A[6] = {0xaa,0xbb,0xcc,0x11,0x22,0x33};
static const uint8_t BSSID_B[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};

/* ── beacon_parse tests ──────────────────────────────────── */

static void test_parse_rejects_non_beacon(void) {
    uint8_t f[BEACON_HDR_LEN + 4];
    memset(f, 0, sizeof(f));
    fill_hdr(f, BSSID_A, 100, 0);
    f[0] = 0x40;   /* probe request, not beacon */

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL), 0);
}

static void test_parse_rejects_too_short(void) {
    uint8_t f[30];
    memset(f, 0, sizeof(f));
    f[0] = 0x80;

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL), 0);
}

static void test_parse_ssid(void) {
    uint8_t f[BEACON_HDR_LEN + 2 + 6];  /* header + SSID IE */
    fill_hdr(f, BSSID_A, 100, 0x0000);
    f[BEACON_HDR_LEN + 0] = 0x00;        /* SSID tag */
    f[BEACON_HDR_LEN + 1] = 6;           /* length */
    memcpy(f + BEACON_HDR_LEN + 2, "HomeAP", 6);

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    int r = beacon_parse(f, (int)sizeof(f), -60, ssid, bssid, &ch, enc, &bms, NULL);
    ASSERT_EQ(r, 1);
    ASSERT_STR(ssid, "HomeAP");
    ASSERT_EQ(memcmp(bssid, BSSID_A, 6), 0);
}

static void test_parse_hidden_ssid(void) {
    uint8_t f[BEACON_HDR_LEN + 2];       /* header + zero-length SSID IE */
    fill_hdr(f, BSSID_A, 100, 0x0000);
    f[BEACON_HDR_LEN + 0] = 0x00;
    f[BEACON_HDR_LEN + 1] = 0;           /* length 0 = hidden */

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -70, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(ssid, "");
}

static void test_parse_channel_ds_param(void) {
    /* SSID IE + DS Parameter Set IE (tag 3, len 1, channel) */
    uint8_t f[BEACON_HDR_LEN + 4 + 3];
    fill_hdr(f, BSSID_A, 100, 0x0000);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 2;
    f[BEACON_HDR_LEN + 2] = 'A';  f[BEACON_HDR_LEN + 3] = 'P';
    f[BEACON_HDR_LEN + 4] = 0x03; f[BEACON_HDR_LEN + 5] = 1; /* DS Param */
    f[BEACON_HDR_LEN + 6] = 11;   /* channel 11 */

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -55, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_EQ(ch, 11);
}

static void test_parse_beacon_interval(void) {
    /* 100 TU = 100 * 1024 / 1000 = 102 ms */
    uint8_t f[BEACON_HDR_LEN + 2];
    fill_hdr(f, BSSID_A, 100, 0x0000);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0; /* SSID "" */

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_EQ(bms, (uint16_t)(100 * 1024 / 1000));
}

static void test_parse_enc_open(void) {
    uint8_t f[BEACON_HDR_LEN + 2];
    fill_hdr(f, BSSID_A, 100, 0x0000);  /* cap = 0, no privacy bit */
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(enc, "OPEN");
}

static void test_parse_enc_wep(void) {
    /* Capability bit 4 = Privacy, no WPA/RSN IEs → WEP */
    uint8_t f[BEACON_HDR_LEN + 2];
    fill_hdr(f, BSSID_A, 100, 0x0010);  /* cap bit 4 set */
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(enc, "WEP");
}

static void test_parse_enc_wpa2(void) {
    /*
     * RSN IE (tag 48):
     *   version(2) + group_cipher(4) + pairwise_count(2) + pairwise(4)
     *   + akm_count(2) + akm(4) + rsn_cap(2) = 20 bytes
     * AKM = 00-0F-AC type 2 (PSK) → WPA2
     */
    static const uint8_t rsn_ie[] = {
        0x30, 0x14,                          /* tag 48, len 20 */
        0x01, 0x00,                          /* version = 1 */
        0x00, 0x0f, 0xac, 0x04,             /* group cipher: CCMP */
        0x01, 0x00,                          /* pairwise count = 1 */
        0x00, 0x0f, 0xac, 0x04,             /* pairwise: CCMP */
        0x01, 0x00,                          /* AKM count = 1 */
        0x00, 0x0f, 0xac, 0x02,             /* AKM: PSK → WPA2 */
        0x00, 0x00                           /* RSN capabilities */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(rsn_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);      /* privacy bit set */
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, rsn_ie, sizeof(rsn_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -45, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(enc, "WPA2");
}

static void test_parse_enc_wpa3(void) {
    /* RSN IE with AKM 00-0F-AC type 8 (SAE) → WPA3 */
    static const uint8_t rsn_ie[] = {
        0x30, 0x14,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x08,              /* AKM: SAE → WPA3 */
        0x00, 0x00
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(rsn_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, rsn_ie, sizeof(rsn_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -45, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(enc, "WPA3");
}

static void test_parse_enc_wpa(void) {
    /* WPA vendor IE: tag 221, OUI 00:50:F2, type 0x01 */
    static const uint8_t wpa_ie[] = {
        0xdd, 0x16,                          /* tag 221, len 22 */
        0x00, 0x50, 0xf2, 0x01,             /* Microsoft OUI + type 1 */
        0x01, 0x00,                          /* WPA IE version */
        0x00, 0x50, 0xf2, 0x02,             /* multicast cipher: TKIP */
        0x01, 0x00,                          /* unicast count = 1 */
        0x00, 0x50, 0xf2, 0x02,             /* unicast: TKIP */
        0x01, 0x00,                          /* auth count = 1 */
        0x00, 0x50, 0xf2, 0x02              /* auth: WPA-PSK */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(wpa_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);      /* privacy set */
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, wpa_ie, sizeof(wpa_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -60, ssid, bssid, &ch, enc, &bms, NULL), 1);
    ASSERT_STR(enc, "WPA");
}

static void test_parse_rsn_inventory_wpa2_psk_ccmp(void) {
    /* WPA2-PSK with CCMP, MFP not advertised. */
    static const uint8_t rsn_ie[] = {
        0x30, 0x14,
        0x01, 0x00,                              /* version */
        0x00, 0x0f, 0xac, 0x04,                  /* group: CCMP (4) */
        0x01, 0x00,                              /* pairwise count = 1 */
        0x00, 0x0f, 0xac, 0x04,                  /* pairwise: CCMP */
        0x01, 0x00,                              /* AKM count = 1 */
        0x00, 0x0f, 0xac, 0x02,                  /* AKM: PSK (2) */
        0x00, 0x00                               /* RSN caps = 0 */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(rsn_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, rsn_ie, sizeof(rsn_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.group,    "CCMP");
    ASSERT_STR(rsn.pairwise, "CCMP");
    ASSERT_STR(rsn.akm,      "PSK");
    ASSERT_EQ(rsn.mfp, 0);
}

static void test_parse_rsn_inventory_wpa3_sae_mfp_required(void) {
    /* WPA3-SAE with MFP REQUIRED (caps bit 6 = 0x40). */
    static const uint8_t rsn_ie[] = {
        0x30, 0x14,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,                  /* group: CCMP */
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,                  /* pairwise: CCMP */
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x08,                  /* AKM: SAE (8) */
        0xc0, 0x00                               /* RSN caps: MFPR+MFPC */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(rsn_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, rsn_ie, sizeof(rsn_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.pairwise, "CCMP");
    ASSERT_STR(rsn.akm,      "SAE");
    ASSERT_EQ(rsn.mfp, 2);
}

static void test_parse_truncated_ie(void) {
    /* IE length claims more bytes than remain — parser must not crash */
    uint8_t f[BEACON_HDR_LEN + 4];
    fill_hdr(f, BSSID_A, 100, 0x0000);
    f[BEACON_HDR_LEN + 0] = 0x00;  /* SSID tag */
    f[BEACON_HDR_LEN + 1] = 10;    /* length 10, but only 2 bytes follow */
    f[BEACON_HDR_LEN + 2] = 'A';
    f[BEACON_HDR_LEN + 3] = 'P';

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    int r = beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, NULL);
    ASSERT_EQ(r, 1);   /* still a valid beacon, just truncated IE walk */
    ASSERT_STR(ssid, "");  /* SSID not populated — IE was truncated */
}

/* ── beacon_record / beacon_snapshot tests ───────────────── */

static void test_record_new_entry(void) {
    beacon_clear();
    beacon_record(BSSID_A, "TestNet", -55, 6, "WPA2", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 1);
    ASSERT_STR(s.beacon_aps[0].ssid, "TestNet");
    ASSERT_EQ(s.beacon_aps[0].signal_dbm, -55);
    ASSERT_EQ(s.beacon_aps[0].channel, 6);
    ASSERT_STR(s.beacon_aps[0].enc, "WPA2");
    ASSERT_EQ(s.beacon_aps[0].beacon_ms, 102);
    ASSERT_EQ(memcmp(s.beacon_aps[0].bssid, BSSID_A, 6), 0);
}

static void test_record_update_existing(void) {
    beacon_clear();
    beacon_record(BSSID_A, "Net", -70, 1, "WPA2", 102, NULL);
    beacon_record(BSSID_A, "Net", -65, 1, "WPA2", 102, NULL);  /* update */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 1);
    ASSERT_EQ(s.beacon_aps[0].signal_dbm, -65);
    ASSERT_EQ(s.beacon_aps[0].frame_count, 2);
}

static void test_record_distinct_bssids(void) {
    beacon_clear();
    beacon_record(BSSID_A, "NetA", -50, 6,  "WPA2", 102, NULL);
    beacon_record(BSSID_B, "NetB", -80, 11, "OPEN", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 2);
}

static void test_snapshot_sorts_by_signal(void) {
    beacon_clear();
    beacon_record(BSSID_A, "Weak",   -80, 6,  "WPA2", 102, NULL);
    beacon_record(BSSID_B, "Strong", -40, 11, "WPA2", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 2);
    /* strongest first */
    ASSERT_EQ(s.beacon_aps[0].signal_dbm, -40);
    ASSERT_EQ(s.beacon_aps[1].signal_dbm, -80);
}

static void test_clear_empties_table(void) {
    beacon_record(BSSID_A, "X", -50, 6, "WPA2", 102, NULL);
    beacon_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    beacon_clear();
    beacon_record(BSSID_A, "X", -50, 6, "WPA2", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.beacon_sel = 99;  /* out of range */
    beacon_snapshot(&s);

    ASSERT_EQ(s.beacon_count, 1);
    ASSERT_EQ(s.beacon_sel, 0);
}

/* ── view_beacon_draw smoke tests ────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_beacon_draw(&s);   /* must not crash */
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    beacon_clear();
    beacon_record(BSSID_A, "HomeNet", -55, 6,  "WPA2", 102, NULL);
    beacon_record(BSSID_B, "Hidden",  -70, 11, "WPA3", 100, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);
    view_beacon_draw(&s);
    ASSERT(1);
}

static void test_view_draw_hidden_ssid(void) {
    beacon_clear();
    beacon_record(BSSID_A, "", -80, 1, "WPA2", 102, NULL);  /* hidden SSID */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);
    view_beacon_draw(&s);
    ASSERT(1);
}

/* ── view_beacon_key tests ───────────────────────────────── */

static void test_view_key_nav(void) {
    beacon_clear();
    beacon_record(BSSID_A, "A", -50, 6,  "WPA2", 102, NULL);
    beacon_record(BSSID_B, "B", -60, 11, "WPA2", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);
    s.beacon_sel = 0;

    view_beacon_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.beacon_sel, 1);

    view_beacon_key(&s, SLOTH_KEY_DOWN);  /* already at end */
    ASSERT_EQ(s.beacon_sel, 1);

    view_beacon_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.beacon_sel, 0);

    view_beacon_key(&s, SLOTH_KEY_UP);   /* already at top */
    ASSERT_EQ(s.beacon_sel, 0);
}

static void test_parse_vendor_ie_apple(void) {
    /* Apple AirPort vendor IE: tag 221, OUI 00:17:F2 */
    static const uint8_t apple_ie[] = {
        0xdd, 0x04,
        0x00, 0x17, 0xf2, 0x01,
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(apple_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, apple_ie, sizeof(apple_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.vendor, "Apple");
    ASSERT_EQ(rsn.has_wps, 0);
}

static void test_parse_vendor_ie_wps(void) {
    /* Microsoft WPS IE: tag 221, OUI 00:50:F2, type 0x04 */
    static const uint8_t wps_ie[] = {
        0xdd, 0x06,
        0x00, 0x50, 0xf2, 0x04,
        0x10, 0x4a,         /* WPS attribute Type (version) */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(wps_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, wps_ie, sizeof(wps_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_EQ(rsn.has_wps, 1);
}

static void test_parse_vendor_ie_mikrotik(void) {
    static const uint8_t mt_ie[] = {
        0xdd, 0x04,
        0x4c, 0x5e, 0x0c, 0x01,
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(mt_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, mt_ie, sizeof(mt_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.vendor, "Mikrotik");
}

static void test_parse_vendor_ie_unknown_oui_leaves_empty(void) {
    static const uint8_t unk_ie[] = {
        0xdd, 0x04,
        0xab, 0xcd, 0xef, 0x01,
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(unk_ie)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, unk_ie, sizeof(unk_ie));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.vendor, "");
    ASSERT_EQ(rsn.has_wps, 0);
}

static void test_parse_vendor_first_match_wins(void) {
    /* Microsoft (skipped as a vendor hit) then Apple — Apple should win. */
    static const uint8_t ms_then_apple[] = {
        0xdd, 0x04, 0x00, 0x50, 0xf2, 0x02,   /* MS WMM */
        0xdd, 0x04, 0x00, 0x17, 0xf2, 0x01,   /* Apple */
        0xdd, 0x04, 0x00, 0x40, 0x96, 0x01,   /* Cisco — later, should NOT win */
    };
    uint8_t f[BEACON_HDR_LEN + 2 + sizeof(ms_then_apple)];
    fill_hdr(f, BSSID_A, 100, 0x0010);
    f[BEACON_HDR_LEN + 0] = 0x00; f[BEACON_HDR_LEN + 1] = 0;
    memcpy(f + BEACON_HDR_LEN + 2, ms_then_apple, sizeof(ms_then_apple));

    char ssid[33]; uint8_t bssid[6]; int ch; char enc[10]; uint16_t bms;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, (int)sizeof(f), -50, ssid, bssid, &ch, enc, &bms, &rsn), 1);
    ASSERT_STR(rsn.vendor, "Apple");
}

static void test_record_persists_vendor_and_wps(void) {
    beacon_clear();
    beacon_rsn_t rsn = {0};
    snprintf(rsn.vendor, sizeof(rsn.vendor), "Mikrotik");
    rsn.has_wps = 1;
    beacon_record(BSSID_A, "MtNet", -55, 6, "WPA2", 102, &rsn);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);
    ASSERT_EQ(s.beacon_count, 1);
    ASSERT_STR(s.beacon_aps[0].vendor, "Mikrotik");
    ASSERT_EQ(s.beacon_aps[0].has_wps, 1);
}

static void test_find_ssid_hit_and_miss(void) {
    beacon_clear();
    beacon_record(BSSID_A, "HomeWiFi", -50, 6, "WPA2", 102, NULL);
    beacon_record(BSSID_B, "",         -70, 11, "WPA2", 102, NULL); /* hidden */

    char ssid[33];
    /* Hit on known BSSID. */
    ASSERT_EQ(beacon_find_ssid(BSSID_A, ssid), 1);
    ASSERT_STR(ssid, "HomeWiFi");
    /* Miss when SSID is hidden — function reports 0 since there's
     * nothing useful to return. */
    ASSERT_EQ(beacon_find_ssid(BSSID_B, ssid), 0);
    ASSERT_STR(ssid, "");
    /* Miss on unknown BSSID. */
    static const uint8_t unknown[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 };
    ASSERT_EQ(beacon_find_ssid(unknown, ssid), 0);
    ASSERT_STR(ssid, "");
}

static void test_view_key_clear(void) {
    beacon_clear();
    beacon_record(BSSID_A, "X", -55, 6, "WPA2", 102, NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_snapshot(&s);
    ASSERT_EQ(s.beacon_count, 1);

    view_beacon_key(&s, 'c');
    ASSERT_EQ(s.beacon_count, 0);
    ASSERT_EQ(s.beacon_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_beacon_snoop_tests(void) {
    TEST_SUITE("beacon_snoop");
    RUN_TEST(test_parse_rejects_non_beacon);
    RUN_TEST(test_parse_rejects_too_short);
    RUN_TEST(test_parse_ssid);
    RUN_TEST(test_parse_hidden_ssid);
    RUN_TEST(test_parse_channel_ds_param);
    RUN_TEST(test_parse_beacon_interval);
    RUN_TEST(test_parse_enc_open);
    RUN_TEST(test_parse_enc_wep);
    RUN_TEST(test_parse_enc_wpa2);
    RUN_TEST(test_parse_enc_wpa3);
    RUN_TEST(test_parse_rsn_inventory_wpa2_psk_ccmp);
    RUN_TEST(test_parse_rsn_inventory_wpa3_sae_mfp_required);
    RUN_TEST(test_parse_vendor_ie_apple);
    RUN_TEST(test_parse_vendor_ie_wps);
    RUN_TEST(test_parse_vendor_ie_mikrotik);
    RUN_TEST(test_parse_vendor_ie_unknown_oui_leaves_empty);
    RUN_TEST(test_parse_vendor_first_match_wins);
    RUN_TEST(test_record_persists_vendor_and_wps);
    RUN_TEST(test_parse_enc_wpa);
    RUN_TEST(test_parse_truncated_ie);
    RUN_TEST(test_record_new_entry);
    RUN_TEST(test_record_update_existing);
    RUN_TEST(test_find_ssid_hit_and_miss);
    RUN_TEST(test_record_distinct_bssids);
    RUN_TEST(test_snapshot_sorts_by_signal);
    RUN_TEST(test_clear_empties_table);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_draw_hidden_ssid);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
