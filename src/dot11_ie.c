#include <stddef.h>
#include <string.h>
#include "dot11_ie.h"
#include "bytes.h"
#include "sensor_health.h"

/* A first-match walk. Stopping at the match leaves the iterator at
 * TLV_OK, which is not a fault; only a stop before it is counted. */
static int find_first(const uint8_t *ies, int len, uint8_t tag, int ext,
                      const uint8_t **body, int *blen) {
    tlv_it_t it;
    uint16_t t; int l; const uint8_t *b;
    tlv_init(&it, ies, len);
    while (tlv_next(&it, &t, &l, &b) == TLV_OK) {
        if (t != tag) continue;
        if (ext >= 0) {
            if (l < 1 || b[0] != (uint8_t)ext) continue;
            b++; l--;
        }
        if (body) *body = b;
        if (blen) *blen = l;
        return 1;
    }
    if (it.status == TLV_OVERRUN) sh_parse_fault_note(SH_PF_IE_OVERRUN);
    return 0;
}

int dot11_ie_find(const uint8_t *ies, int len, uint8_t tag,
                  const uint8_t **body, int *blen) {
    return find_first(ies, len, tag, -1, body, blen);
}

int dot11_ie_find_ext(const uint8_t *ies, int len, uint8_t ext_id,
                      const uint8_t **body, int *blen) {
    return find_first(ies, len, 255, ext_id, body, blen);
}

int dot11_ie_ssid_copy(const uint8_t *body, int blen, char out[33]) {
    int n = blen < 32 ? blen : 32;
    if (n < 0 || !body) n = 0;
    if (n) memcpy(out, body, (size_t)n);
    out[n] = '\0';
    return blen > 32;
}

int dot11_ie_ssid(const uint8_t *ies, int len, char out[33], int *oversize) {
    const uint8_t *b; int l;
    out[0] = '\0';
    if (oversize) *oversize = 0;
    if (!dot11_ie_find(ies, len, 0, &b, &l)) return 0;
    int over = dot11_ie_ssid_copy(b, l, out);
    if (oversize) *oversize = over;
    return 1;
}

void dot11_ie_phy_note(dot11_phy_t *p, uint8_t tag,
                       const uint8_t *body, int blen) {
    if (tag == 45)  p->ht  = 1;
    if (tag == 191) p->vht = 1;
    if (tag == 255 && blen >= 1) {
        uint8_t ext = body[0];
        if (ext == 35) p->he = 1;
        if (ext == 106 || ext == 107 || ext == 108) p->eht = 1;
    }
}

void dot11_ie_phy(const uint8_t *ies, int len, dot11_phy_t *out) {
    memset(out, 0, sizeof(*out));
    tlv_it_t it;
    uint16_t t; int l; const uint8_t *b;
    tlv_init(&it, ies, len);
    while (tlv_next(&it, &t, &l, &b) == TLV_OK)
        dot11_ie_phy_note(out, (uint8_t)t, b, l);
    /* The tier read before a stop stands; the stop is still counted. */
    if (it.status == TLV_OVERRUN) sh_parse_fault_note(SH_PF_IE_OVERRUN);
}

const char *dot11_phy_tier(const dot11_phy_t *p) {
    if (!p)     return "legacy";
    if (p->eht) return "Wi-Fi 7";
    if (p->he)  return "Wi-Fi 6";
    if (p->vht) return "Wi-Fi 5";
    if (p->ht)  return "Wi-Fi 4";
    return "legacy";
}

/* The union of the two tables this replaced: beacon_snoop.c's AP-vendor
 * list (SOHO, enterprise, IoT silicon) and the OUIs probe_pnl.c's OS
 * fingerprint keys on. Vendor names only — what a vendor's IE says
 * about the client OS stays in probe_pnl.c. */
static const struct { uint8_t oui[3]; const char *name; } k_oui[] = {
    { { 0x00, 0x17, 0xf2 }, "Apple"          },
    { { 0x00, 0x40, 0x96 }, "Cisco"          },
    { { 0x00, 0x03, 0x7f }, "Atheros"        },
    { { 0x00, 0x10, 0x18 }, "Broadcom"       },
    { { 0x4c, 0x5e, 0x0c }, "Mikrotik"       },
    { { 0x00, 0x15, 0x6d }, "Ubiquiti"       },
    { { 0xdc, 0x9f, 0xdb }, "Ubiquiti"       },
    { { 0x24, 0x0a, 0xc4 }, "Espressif"      },
    { { 0x00, 0x0d, 0x97 }, "Ruckus"         },
    { { 0x00, 0x24, 0x6c }, "Aruba"          },
    { { 0xc0, 0xc9, 0xe3 }, "TP-Link"        },
    { { 0x00, 0x09, 0x5b }, "Netgear"        },
    { { 0x00, 0x18, 0xe7 }, "D-Link"         },
    { { 0x00, 0x14, 0x6c }, "Netgear"        },
    { { 0x50, 0x6f, 0x9a }, "Wi-Fi Alliance" },
    { { 0x00, 0x50, 0xf2 }, "Microsoft"      },
};

const char *dot11_oui_vendor(const uint8_t oui[3]) {
    if (!oui) return NULL;
    for (size_t i = 0; i < sizeof(k_oui) / sizeof(k_oui[0]); i++)
        if (memcmp(k_oui[i].oui, oui, 3) == 0) return k_oui[i].name;
    return NULL;
}
