/* Camera-vendor identity tables (#106 slice A). Contracts are in
 * camera_vendor.h; sources in research/papers/camera-vendor-identity.md. */
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "camera_vendor.h"

/* ── OUI table ─────────────────────────────────────────────
 *
 * Every row is one MA-L (24-bit) assignment from the IEEE Registration
 * Authority public listing, oui.csv, as distributed by Debian's
 * ieee-data package (.lastupdate 2024-07-22). The second string is the
 * registry's "Organization Name" column verbatim, so a row is its own
 * citation: look the assignment up at
 * https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
 * and the assignee must read exactly as written here.
 * tests/test_camera_vendor.c holds the table to that file when the
 * host has it, and everywhere to a digest of the registry's names for
 * these assignments, so CI without ieee-data still catches an edit.
 *
 * Two kinds of row. A camera-vendor row (mixed 0) is an assignee whose
 * own published material describes it as a camera maker. That is a
 * vendor test, not a product test: a Hikvision block is on an NVR as
 * readily as on a camera, which is why the alert says "camera vendor",
 * not "camera". A mixed-vendor row (mixed 1, #155) is Ubiquiti, TP-Link
 * or Wyze: they sell cameras, but most of what their blocks put on the
 * wire is an AP, a router, a plug or a bulb — every UniFi AP in a
 * building would match — so such a match names the vendor and is a +1
 * prior in camera_join.c's score, never a class and never CAM_SETUP_OUI
 * on its own (camera_vendor.h). MA-M / MA-S blocks are not here: they
 * are 28- and 36-bit prefixes and this compares 24. */
typedef struct {
    uint8_t     oui[3];
    const char *vendor;
    const char *org;
    int         mixed;
} cam_oui_row_t;

static const cam_oui_row_t g_cam_oui[] = {
    /* IEEE RA MA-L, assignee "Amcrest Technologies" */
    { {0x00,0x65,0x1E}, "Amcrest", "Amcrest Technologies", 0 },
    { {0x9C,0x8E,0xCD}, "Amcrest", "Amcrest Technologies", 0 },
    { {0xA0,0x60,0x32}, "Amcrest", "Amcrest Technologies", 0 },
    /* IEEE RA MA-L, assignee "Arlo Technology" */
    { {0x48,0x62,0x64}, "Arlo", "Arlo Technology", 0 },
    { {0xA4,0x11,0x62}, "Arlo", "Arlo Technology", 0 },
    { {0xFC,0x9C,0x98}, "Arlo", "Arlo Technology", 0 },
    /* IEEE RA MA-L, assignee "Axis Communications AB" */
    { {0x00,0x40,0x8C}, "Axis", "Axis Communications AB", 0 },
    { {0xAC,0xCC,0x8E}, "Axis", "Axis Communications AB", 0 },
    { {0xB8,0xA4,0x4F}, "Axis", "Axis Communications AB", 0 },
    { {0xE8,0x27,0x25}, "Axis", "Axis Communications AB", 0 },
    /* IEEE RA MA-L, assignee "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" */
    { {0x30,0xDD,0xAA}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD", 0 },
    { {0x40,0x7A,0xA4}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD", 0 },
    { {0x4C,0x99,0xE8}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD", 0 },
    { {0xF8,0xCE,0x07}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD", 0 },
    /* IEEE RA MA-L, assignee "Zhejiang Dahua Technology Co., Ltd." */
    { {0x08,0xED,0xED}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x14,0xA7,0x8B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x24,0x52,0x6A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x38,0xAF,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x3C,0xE3,0x6B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x3C,0xEF,0x8C}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x4C,0x11,0xBF}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x5C,0xF5,0x1A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x64,0xFD,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x6C,0x1C,0x71}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x74,0xC9,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x8C,0xE9,0xB4}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x90,0x02,0xA9}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x98,0xF9,0xCC}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0x9C,0x14,0x63}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xA0,0xBD,0x1D}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xB4,0x4C,0x3B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xBC,0x32,0x5F}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xC0,0x39,0x5A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xC4,0xAA,0xC4}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xD4,0x43,0x0E}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xE0,0x2E,0xFE}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xE0,0x50,0x8B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xE4,0x24,0x6C}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xF4,0xB1,0xC2}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xFC,0x5F,0x49}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    { {0xFC,0xB6,0x9D}, "Dahua", "Zhejiang Dahua Technology Co., Ltd.", 0 },
    /* IEEE RA MA-L, assignee "Hangzhou Ezviz Software Co.,Ltd." */
    { {0x0C,0xA6,0x4C}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x20,0xBB,0xBC}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x34,0xC6,0xDD}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x54,0xD6,0x0D}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x58,0x8F,0xCF}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x64,0x24,0x4D}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x64,0xF2,0xFB}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x78,0xA6,0xA0}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x78,0xC1,0xAE}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0x94,0xEC,0x13}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0xAC,0x1C,0x26}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0xEC,0x97,0xE0}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0xF4,0x70,0x18}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    { {0xFC,0x24,0x22}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd.", 0 },
    /* IEEE RA MA-L, assignee "Hangzhou Hikvision Digital Technology Co.,Ltd." */
    { {0x00,0xBC,0x99}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x04,0x03,0x12}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x04,0xEE,0xCD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x08,0x3B,0xC1}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x08,0x54,0x11}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x08,0xA1,0x89}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x08,0xCC,0x81}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x0C,0x75,0xD2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x10,0x12,0xFB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x18,0x68,0xCB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x18,0x80,0x25}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x24,0x0F,0x9B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x24,0x28,0xFD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x24,0x32,0xAE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x24,0x48,0x45}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x28,0x57,0xBE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x2C,0xA5,0x9C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x34,0x09,0x62}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x3C,0x1B,0xF8}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x40,0xAC,0xBF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x40,0xB5,0x70}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x44,0x19,0xB6}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x44,0x47,0xCC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x44,0xA6,0x42}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x48,0x78,0x5B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x4C,0x1F,0x86}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x4C,0x62,0xDF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x4C,0xBD,0x8F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x4C,0xF5,0xDC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x50,0xE5,0x38}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x54,0x8C,0x81}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x54,0xC4,0x15}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x58,0x03,0xFB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x58,0x50,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x5C,0x34,0x5B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x64,0xDB,0x8B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x68,0x6D,0xBC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x74,0x3F,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x80,0x48,0x9F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x80,0x7C,0x62}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x80,0xBE,0xAF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x80,0xF5,0xAE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x84,0x94,0x59}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x84,0x9A,0x40}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x88,0xDE,0x39}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x8C,0x22,0xD2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x8C,0xE7,0x48}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x94,0xE1,0xAC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x98,0x8B,0x0A}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x98,0x9D,0xE5}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x98,0xDF,0x82}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0x98,0xF1,0x12}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA0,0xFF,0x0C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA4,0x14,0x37}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA4,0x29,0x02}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA4,0x4B,0xD9}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA4,0xA4,0x59}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xA4,0xD5,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xAC,0xB9,0x2F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xAC,0xCB,0x51}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xB4,0xA3,0x82}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xBC,0x5E,0x33}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xBC,0x9B,0x5E}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xBC,0xAD,0x28}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xBC,0xBA,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xC0,0x51,0x7E}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xC0,0x56,0xE3}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xC0,0x6D,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xC4,0x2F,0x90}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xC8,0xA7,0x02}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xCC,0x13,0xF3}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xD4,0xE8,0x53}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xDC,0x07,0xF8}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xDC,0xD2,0x6A}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xE0,0xBA,0xAD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xE0,0xCA,0x3C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xE0,0xDF,0x13}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xE4,0xD5,0x8B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xE8,0xA0,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xEC,0xA9,0x71}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xEC,0xC8,0x9C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xF8,0x4D,0xFC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    { {0xFC,0x9F,0xFD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd.", 0 },
    /* IEEE RA MA-L, assignee "Lorex Technology Inc." */
    { {0x00,0x1F,0x54}, "Lorex", "Lorex Technology Inc.", 0 },
    /* IEEE RA MA-L, assignee "Mobotix AG" */
    { {0x00,0x03,0xC5}, "Mobotix", "Mobotix AG", 0 },
    /* IEEE RA MA-L, assignee "Reolink Innovation Limited" */
    { {0xEC,0x71,0xDB}, "Reolink", "Reolink Innovation Limited", 0 },

    /* ── mixed-vendor rows (#155, owner ruling 2026-10-21) ──────
     * Every assignment the same registry snapshot lists under these
     * three companies' Organization Names, all of them: a partial list
     * would make the prior depend on which block a device happened to
     * be built in. Generated from oui.csv, sorted per assignee. */
    /* IEEE RA MA-L, assignee "TP-LINK TECHNOLOGIES CO.,LTD." (mixed vendor) */
    { {0x00,0x0A,0xEB}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x14,0x78}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x19,0xE0}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x1D,0x0F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x21,0x27}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x23,0xCD}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x25,0x86}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x00,0x27,0x19}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x04,0xF9,0xF8}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x08,0x1F,0x71}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x08,0x57,0x00}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x0C,0x4B,0x54}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x0C,0x72,0x2C}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x0C,0x80,0x63}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x0C,0x82,0x68}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x10,0xFE,0xED}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0x75,0x90}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0x86,0x92}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0xCC,0x20}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0xCF,0x92}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0xD8,0x64}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x14,0xE6,0xE4}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x18,0xA6,0xF7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x18,0xD6,0xC7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x18,0xF2,0x2C}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x1C,0x3B,0xF3}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x1C,0x44,0x19}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x1C,0xFA,0x68}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x20,0x6B,0xE7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x20,0xDC,0xE6}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x24,0x5A,0x5F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x24,0x69,0x68}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x28,0x2C,0xB2}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x28,0xEE,0x52}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x2C,0x79,0xBE}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x30,0xB4,0x9E}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x30,0xB5,0xC2}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x30,0xFC,0x68}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x34,0x96,0x72}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x34,0xE8,0x94}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x34,0xF7,0x16}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x38,0x83,0x45}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x3C,0x06,0xA7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x3C,0x46,0xD8}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x3C,0x6A,0x48}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x3C,0x84,0x6A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x40,0x16,0x9F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x40,0x3F,0x8C}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x44,0x66,0x90}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x44,0xB3,0x2D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x48,0x0E,0xEC}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x48,0x5F,0x08}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x48,0x7D,0x2E}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x4C,0x10,0xD5}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x50,0x3E,0xAA}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x50,0xBD,0x5F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x50,0xC7,0xBF}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x50,0xD4,0xF7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x50,0xFA,0x84}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x54,0x75,0x95}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x54,0xA7,0x03}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x54,0xC8,0x0F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x54,0xE6,0xFC}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x58,0x41,0x20}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x5C,0x63,0xBF}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x5C,0x89,0x9A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x60,0x29,0x2B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x60,0x32,0xB1}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x60,0x3A,0x7C}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x60,0xA3,0xE3}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x60,0xE3,0x27}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x64,0x56,0x01}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x64,0x66,0xB3}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x64,0x6E,0x97}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x64,0x70,0x02}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x68,0x77,0x24}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x68,0xDD,0xB7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x68,0xFF,0x7B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x6C,0xB1,0x58}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x6C,0xE8,0x73}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x70,0x4F,0x57}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x74,0x05,0xA5}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x74,0x39,0x89}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x74,0xDA,0x88}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x74,0xEA,0x3A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x78,0x44,0xFD}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x78,0x60,0x5B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x78,0xA1,0x06}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x7C,0x8B,0xCA}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x7C,0xB5,0x9B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x80,0x89,0x17}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x80,0x8F,0x1D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x80,0xAE,0x54}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x80,0xEA,0x07}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x84,0x16,0xF9}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x84,0xB8,0x90}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x84,0xD8,0x1B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x88,0x25,0x93}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x88,0x99,0x86}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x8C,0x21,0x0A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x8C,0xA6,0xDF}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x90,0x9A,0x4A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x90,0xAE,0x1B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x90,0xF6,0x52}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x94,0x0C,0x6D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x94,0xD9,0xB3}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x98,0x48,0x27}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x98,0x97,0xCC}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x98,0xDA,0xC4}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x98,0xDE,0xD0}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x9C,0x21,0x6A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x9C,0x47,0x82}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0x9C,0xA6,0x15}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xA0,0xF3,0xC1}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xA4,0x1A,0x3A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xA4,0x2B,0xB0}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xA8,0x15,0x4D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xA8,0x57,0x4E}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xAC,0x84,0xC6}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB0,0x48,0x7A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB0,0x4E,0x26}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB0,0x95,0x75}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB0,0x95,0x8E}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB0,0xBE,0x76}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xB8,0xF8,0x83}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xBC,0x46,0x99}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xBC,0xD1,0x77}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC0,0x25,0xE9}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC0,0x4A,0x00}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC0,0x61,0x18}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC0,0xC9,0xE3}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC0,0xE4,0x2D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC4,0x6E,0x1F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC4,0x71,0x54}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xC4,0xE9,0x84}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xCC,0x08,0xFB}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xCC,0x32,0xE5}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xCC,0x34,0x29}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD0,0x37,0x45}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD0,0x76,0xE7}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD0,0xC7,0xC0}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD4,0x01,0x6D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD4,0x6E,0x0E}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD8,0x07,0xB6}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD8,0x0D,0x17}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD8,0x15,0x0D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD8,0x47,0x32}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xD8,0x5D,0x4C}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xDC,0x00,0x77}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xDC,0xFE,0x18}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xE0,0x05,0xC5}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xE4,0xC3,0x2A}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xE4,0xD3,0x32}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xE8,0x94,0xF6}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xE8,0xDE,0x27}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xEC,0x08,0x6B}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xEC,0x17,0x2F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xEC,0x26,0xCA}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xEC,0x60,0x73}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xEC,0x88,0x8F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF0,0xF3,0x36}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0x2A,0x7D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0x6D,0x2F}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0x83,0xCD}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0x84,0x8D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0xEC,0x38}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF4,0xF2,0x6D}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0x1A,0x67}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0x6F,0xB0}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0x8C,0x21}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0xC9,0x03}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0xCE,0x21}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xF8,0xD1,0x11}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    { {0xFC,0xD7,0x33}, "TP-Link", "TP-LINK TECHNOLOGIES CO.,LTD.", 1 },
    /* IEEE RA MA-L, assignee "TP-Link Systems Inc" (mixed vendor) */
    { {0x00,0x31,0x92}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x00,0x5F,0x67}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x10,0x27,0xF5}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x14,0xEB,0xB6}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x1C,0x61,0xB4}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x20,0x23,0x51}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x20,0x36,0x26}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x24,0x2F,0xD0}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x28,0x87,0xBA}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x30,0xDE,0x4B}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x34,0x60,0xF9}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x3C,0x52,0xA1}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x3C,0x64,0xCF}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x40,0xAE,0x30}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x40,0xED,0x00}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x48,0x22,0x54}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x50,0x91,0xE3}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x54,0xAF,0x97}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x5C,0x62,0x8B}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x5C,0xA6,0xE6}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x5C,0xE9,0x31}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x60,0x83,0xE7}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x60,0xA4,0xB7}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x68,0x7F,0xF0}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x6C,0x5A,0xB0}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x74,0xFE,0xCE}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x78,0x8C,0xB5}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x7C,0xC2,0xC6}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x7C,0xF1,0x7E}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x98,0x25,0x4A}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x9C,0x53,0x22}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0x9C,0xA2,0xF4}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xA8,0x42,0xA1}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xA8,0x6E,0x84}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xAC,0x15,0xA2}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xB0,0x19,0x21}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xB0,0xA7,0xB9}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xB4,0xB0,0x24}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xC0,0x06,0xC3}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xCC,0x68,0xB6}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xD8,0x44,0x89}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xDC,0x62,0x79}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xE4,0xFA,0xC4}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xE8,0x48,0xB8}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xF0,0x09,0x0D}, "TP-Link", "TP-Link Systems Inc", 1 },
    { {0xF0,0xA7,0x31}, "TP-Link", "TP-Link Systems Inc", 1 },
    /* IEEE RA MA-L, assignee "TP-Link Systems Inc." (mixed vendor) */
    { {0x04,0x0F,0x66}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x04,0xC8,0x45}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x0C,0xEF,0x15}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x10,0x5A,0x95}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x18,0x69,0x45}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x20,0xE1,0x5D}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x28,0x91,0x04}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x30,0x68,0x93}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x3C,0x6A,0xD2}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x3C,0x78,0x95}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x40,0x95,0x95}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x48,0xC3,0x81}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x50,0x3D,0xD1}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x58,0x04,0x4F}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x58,0xD8,0x12}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x5C,0xA6,0x4F}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x60,0x15,0x6F}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x6C,0x4C,0xBC}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x78,0x20,0x51}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x80,0x3C,0x04}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x8C,0x86,0xDD}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x8C,0x90,0x2D}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x94,0xEF,0x50}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x98,0x03,0x8E}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0x98,0xBA,0x5F}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xA8,0x29,0x48}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xA8,0x29,0xDC}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xAC,0xA7,0xF1}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xB4,0x5B,0xD1}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xB4,0xC0,0xC3}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xB8,0xFB,0xB3}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xBC,0x07,0x1D}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xC0,0x3A,0x55}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xCC,0xBA,0xBD}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xD4,0xD6,0xDF}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xD8,0xF1,0x2E}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xE0,0x28,0x0A}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xE0,0xD3,0x62}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xEC,0x75,0x0C}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xEC,0xB9,0x31}, "TP-Link", "TP-Link Systems Inc.", 1 },
    { {0xF4,0xF5,0x0B}, "TP-Link", "TP-Link Systems Inc.", 1 },
    /* IEEE RA MA-L, assignee "Ubiquiti Inc" (mixed vendor) */
    { {0x00,0x15,0x6D}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x00,0x27,0x22}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x04,0x18,0xD6}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x0C,0xEA,0x14}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x18,0xE8,0x29}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x1C,0x0B,0x8B}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x1C,0x6A,0x1B}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x24,0x5A,0x4C}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x24,0xA4,0x3C}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x28,0x70,0x4E}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x2C,0xE5,0xBD}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x44,0xD9,0xE7}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x58,0xD6,0x1F}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x60,0x22,0x32}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x68,0x2E,0x3C}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x68,0x72,0x51}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x68,0xD7,0x9A}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x6C,0x63,0xF8}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x70,0xA7,0x41}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x74,0x83,0xC2}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x74,0xAC,0xB9}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x74,0xF9,0x2C}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x74,0xFA,0x29}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x78,0x45,0x58}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x78,0x8A,0x20}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x80,0x2A,0xA8}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x84,0x78,0x48}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x8C,0x30,0x66}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x8C,0xED,0xE1}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x90,0x41,0xB2}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x94,0x2A,0x6F}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0x9C,0x05,0xD6}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xA4,0xF8,0xFF}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xA8,0x9C,0x6C}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xAC,0x8B,0xA9}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xB4,0xFB,0xE4}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xCC,0x35,0xD9}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xD0,0x21,0xF9}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xD4,0x89,0xC1}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xD8,0xB3,0x70}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xD8,0xC2,0x62}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xDC,0x9F,0xDB}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xE0,0x63,0xDA}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xE4,0x38,0x83}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xF0,0x9F,0xC2}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xF4,0x92,0xBF}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xF4,0xE2,0xC6}, "Ubiquiti", "Ubiquiti Inc", 1 },
    { {0xFC,0xEC,0xDA}, "Ubiquiti", "Ubiquiti Inc", 1 },
    /* IEEE RA MA-L, assignee "Wyze Labs Inc" (mixed vendor) */
    { {0x2C,0xAA,0x8E}, "Wyze", "Wyze Labs Inc", 1 },
    { {0x7C,0x78,0xB2}, "Wyze", "Wyze Labs Inc", 1 },
    { {0x80,0x48,0x2C}, "Wyze", "Wyze Labs Inc", 1 },
    { {0xD0,0x3F,0x27}, "Wyze", "Wyze Labs Inc", 1 },
    { {0xF0,0xC8,0x8B}, "Wyze", "Wyze Labs Inc", 1 },
};

#define CAM_OUI_N ((int)(sizeof(g_cam_oui) / sizeof(g_cam_oui[0])))

/* IEEE 802-2014 §8.2: bit 1 of octet 0 is U/L (1 = locally
 * administered), bit 0 is I/G (1 = group). */
#define MAC_UL_BIT 0x02

int cam_vendor_oui(const uint8_t mac[6], const char **vendor,
                   const char **org, int *local, int *mixed) {
    if (!mac) return 0;
    /* No I/G test needed: every row has it clear (MA-L, pinned by
     * test_oui_table_rows_are_registry_shaped) and it is not masked,
     * so a group address cannot compare equal. */
    int ul = (mac[0] & MAC_UL_BIT) ? 1 : 0;
    uint8_t o0 = (uint8_t)(mac[0] & ~MAC_UL_BIT);
    for (int i = 0; i < CAM_OUI_N; i++) {
        const cam_oui_row_t *r = &g_cam_oui[i];
        if (r->oui[0] != o0 || r->oui[1] != mac[1] || r->oui[2] != mac[2])
            continue;
        /* A mixed-vendor prior is already weak; one resting on the 22
         * free bits of a local address coinciding is no prior at all. */
        if (r->mixed && ul) return 0;
        if (vendor) *vendor = r->vendor;
        if (org)    *org    = r->org;
        if (local)  *local  = ul;
        if (mixed)  *mixed  = r->mixed;
        return 1;
    }
    return 0;
}

int cam_vendor_oui_count(void) { return CAM_OUI_N; }

int cam_vendor_oui_mixed_at(int i) {
    if (i < 0 || i >= CAM_OUI_N) return 0;
    return g_cam_oui[i].mixed;
}

void cam_vendor_oui_at(int i, uint8_t oui[3], const char **vendor,
                       const char **org) {
    if (i < 0 || i >= CAM_OUI_N) return;
    memcpy(oui, g_cam_oui[i].oui, 3);
    if (vendor) *vendor = g_cam_oui[i].vendor;
    if (org)    *org    = g_cam_oui[i].org;
}

/* ── SERVER product token ──────────────────────────────────
 *
 * The same vendor set as the OUI table, by brand — a firmware that
 * names its maker in SERVER names the brand, not the registry's legal
 * name. Not a list of observed SERVER strings: nobody publishes those,
 * and a row for one would be a guess. What is matched is the vendor
 * naming itself in the field UDA 1.0 §1.1.2 reserves for the product
 * name, which is the device's own claim and is reported as such. */
static const char *const g_cam_server_brands[] = {
    "Hikvision", "EZVIZ", "Dahua", "Amcrest", "Axis",
    "Reolink", "Mobotix", "Lorex", "Arlo",
};

static int is_tok_sep(char c) {
    return c == ' ' || c == '\t' || c == ',' || c == '\0';
}

int cam_vendor_server(const char *server, const char **vendor) {
    if (!server) return 0;
    const char *p = server;
    while (*p) {
        while (*p && is_tok_sep(*p)) p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && !is_tok_sep(*p)) p++;
        /* product name is the part of the token before '/' */
        size_t tlen = (size_t)(p - tok);
        const char *slash = memchr(tok, '/', tlen);
        size_t nlen = slash ? (size_t)(slash - tok) : tlen;
        for (size_t b = 0; b < sizeof(g_cam_server_brands) /
                               sizeof(g_cam_server_brands[0]); b++) {
            const char *brand = g_cam_server_brands[b];
            size_t blen = strlen(brand);
            if (nlen < blen || strncasecmp(tok, brand, blen) != 0) continue;
            if (nlen == blen || tok[blen] == '-' || tok[blen] == '_') {
                if (vendor) *vendor = brand;
                return 1;
            }
        }
    }
    return 0;
}

/* ── DNS-SD service types ──────────────────────────────────
 *
 * Each row is a Service Name in the IANA "Service Name and Transport
 * Protocol Port Number Registry" (RFC 6335), Description column quoted.
 * Vendor-specific names the issue proposed (_hikvision, _dahua,
 * _reolink, _wyze, _arlo, _nest-cam, _ubnt) are not registered and no
 * vendor document naming them was found, so they are not here. ONVIF
 * discovery is WS-Discovery, which CAM_WS_DISCOVERY already reads;
 * "onvif" is not a registered service name either. */
typedef struct {
    const char *name;            /* service label, leading '_' */
    const char *label;
    int         camera_specific;
} cam_svc_row_t;

static const cam_svc_row_t g_cam_svcs[] = {
    /* IANA: axis-video, "Axis Video Cameras" — the registry entry
     * names the device class itself, which is why it is a row. */
    { "_axis-video", "Axis video camera service (IANA axis-video)", 1 },
    /* IANA: cctv, "IP and Closed-Circuit Television for Securitiy
     * applications" (registry spelling). */
    { "_cctv",       "IP/CCTV security video service (IANA cctv)", 1 },
    /* IANA: rtsp, port 554, "Real Time Streaming Protocol (RTSP)".
     * A streaming protocol, not a device class: cameras advertise it,
     * so do some media servers. Carried with camera_specific 0 so the
     * alert says so instead of calling the host a camera. */
    { "_rtsp",       "RTSP stream service (IANA rtsp)", 0 },
};

int cam_mdns_service(const char *service, const char **label,
                     int *camera_specific) {
    if (!service || service[0] != '_') return 0;
    const char *dot = strchr(service, '.');
    size_t n = dot ? (size_t)(dot - service) : strlen(service);
    for (size_t i = 0; i < sizeof(g_cam_svcs) / sizeof(g_cam_svcs[0]); i++) {
        const cam_svc_row_t *r = &g_cam_svcs[i];
        if (strlen(r->name) != n || strncasecmp(service, r->name, n) != 0)
            continue;
        if (label)           *label = r->label;
        if (camera_specific) *camera_specific = r->camera_specific;
        return 1;
    }
    return 0;
}

/* ── Setup-SoftAP SSID prefixes (CAM_SETUP_SSID) ───────────
 *
 * Moved from src/alerts/rules_twin.c unchanged (#106 round 2). Every
 * row cites the vendor's own onboarding documentation — see
 * research/papers/camera-setup-softap.md. Rows whose SSID shape could
 * not be sourced to a vendor document were left out rather than
 * guessed; see that document's "considered and not shipped" section. */
typedef struct {
    const char *prefix;
    const char *label;     /* rendered into the alert detail */
    const char *brand;     /* device record's camera_vendor   */
} cam_setup_ssid_pat_t;

static const cam_setup_ssid_pat_t g_camera_setup_ssid_pats[] = {
    /* "Hikvision Access Point". SSID is HAP_ + the verification code
     * from the device label; the AP key is the last 8 characters of
     * the serial number, also on the label. */
    { "HAP_",      "Hikvision camera",     "Hikvision" },
    /* "Dahua Access Point", DAP-<serial fragment>. Amcrest is a Dahua
     * OEM and uses the same prefix (DAP-AMC...), so one row covers
     * both brands — which is why the label says the OEM, not Amcrest. */
    { "DAP-",      "Dahua/Amcrest camera", "Dahua" },
    /* EZVIZ is Hikvision's consumer brand; AP mode broadcasts
     * EZVIZ_<9-digit serial>, keyed on the label's verification code. */
    { "EZVIZ_",    "EZVIZ camera",         "EZVIZ" },
    /* TP-Link Tapo camera setup SoftAP: Tapo_Cam_<last 4 of MAC>.
     * Prefix includes the trailing underscore so it cannot collide
     * with a Tapo plug or bulb, which are not cameras. */
    { "Tapo_Cam_", "TP-Link Tapo camera",  "TP-Link Tapo" },
};

/* SSIDs are bytes, not text: fold ASCII only, never by locale. */
static int ssid_ascii_iprefix(const char *hay, const char *prefix) {
    for (int i = 0; prefix[i]; i++) {
        unsigned char h = (unsigned char)hay[i], p = (unsigned char)prefix[i];
        if (h >= 'A' && h <= 'Z') h = (unsigned char)(h - 'A' + 'a');
        if (p >= 'A' && p <= 'Z') p = (unsigned char)(p - 'A' + 'a');
        if (h != p) return 0;   /* also stops at hay's NUL */
    }
    return 1;
}

int cam_setup_ssid(const char *ssid, const char **label, const char **brand) {
    if (!ssid || !ssid[0]) return 0;
    for (size_t i = 0; i < sizeof(g_camera_setup_ssid_pats) /
                           sizeof(g_camera_setup_ssid_pats[0]); i++) {
        const cam_setup_ssid_pat_t *r = &g_camera_setup_ssid_pats[i];
        if (!ssid_ascii_iprefix(ssid, r->prefix)) continue;
        if (label) *label = r->label;
        if (brand) *brand = r->brand;
        return 1;
    }
    return 0;
}

/* ── SSDP camera row (CAM_SSDP_DEVICE) ─────────────────────── */

#define UPNP_DSC1   "urn:schemas-upnp-org:device:DigitalSecurityCamera:1"
#define UPNP_BASIC1 "urn:schemas-upnp-org:device:Basic:1"

int cam_ssdp_row(const char *type, const char *nts, const char *server,
                 int *dsc, const char **vendor) {
    const char *v = NULL;
    int d = 0, ok = 0;
    if (type && nts && strcmp(nts, "search") != 0) {
        int named = server ? cam_vendor_server(server, &v) : 0;
        if (strcasecmp(type, UPNP_DSC1) == 0)        { d = 1; ok = 1; }
        else if (strcasecmp(type, UPNP_BASIC1) == 0) ok = named;
        if (!named) v = NULL;
    }
    if (dsc)    *dsc    = ok ? d : 0;
    if (vendor) *vendor = ok ? v : NULL;
    return ok;
}
