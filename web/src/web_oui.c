#include "web_oui.h"

#include <stdio.h>
#include <string.h>

/* Defined by the generated build/web/web_oui_table.c. */
extern const web_oui_tab_t web_oui_generated;

const web_oui_tab_t *web_oui_builtin(void) { return &web_oui_generated; }

int web_oui_full(const web_oui_tab_t *t) {
    return t && t->source && !strcmp(t->source, "ieee") &&
           t->counts[WEB_OUI_MAL] > 0;
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int web_oui_mac_bytes(const char *mac, uint8_t out[6]) {
    if (!mac || strlen(mac) != 17) return -1;
    for (int i = 0; i < 6; i++) {
        int a = hexv((unsigned char)mac[i * 3]);
        int b = hexv((unsigned char)mac[i * 3 + 1]);
        if (a < 0 || b < 0 || (i < 5 && mac[i * 3 + 2] != ':')) return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return 0;
}

static const web_oui_ent_t *find(const web_oui_tab_t *t, uint64_t key) {
    size_t lo = 0, hi = t->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t->e[mid].key < key) lo = mid + 1;
        else if (t->e[mid].key > key) hi = mid;
        else return &t->e[mid];
    }
    return NULL;
}

/* "70:b3:d5:1" for a 28-bit block, "70:b3:d5:1f:a" for 36: the
 * assignment's own hex digits, grouped the way a MAC is. */
static void block_text(uint64_t prefix, int bits, char *out, size_t sz) {
    int digits = bits / 4;
    size_t o = 0;
    for (int i = 0; i < digits && o + 2 < sz; i++) {
        if (i && i % 2 == 0) out[o++] = ':';
        out[o++] = "0123456789abcdef"[(prefix >> (4 * (digits - 1 - i))) & 15];
    }
    out[o] = '\0';
}

int web_oui_lookup(const web_oui_tab_t *t, const uint8_t mac[6],
                   web_oui_hit_t *out) {
    memset(out, 0, sizeof(*out));
    out->cls = -1;
    out->local = (mac[0] & 0x02) != 0;
    out->multicast = (mac[0] & 0x01) != 0;
    uint64_t m48 = 0;
    for (int i = 0; i < 6; i++) m48 = (m48 << 8) | mac[i];
    if (!t || !t->e) return 0;
    static const int order[] = { WEB_OUI_MAS, WEB_OUI_MAM, WEB_OUI_MAL };
    for (int k = 0; k < 3; k++) {
        int cls = order[k];
        int bits = web_oui_class_bits(cls);
        uint64_t prefix = m48 >> (48 - bits);
        const web_oui_ent_t *e = find(t, web_oui_key(prefix, cls));
        if (!e || e->name >= t->nnames) continue;
        out->found = 1;
        out->cls = cls;
        out->bits = bits;
        block_text(prefix, bits, out->block, sizeof(out->block));
        snprintf(out->name, sizeof(out->name), "%s", t->names[e->name]);
        out->private_ = !strcmp(out->name, "Private");
        return 1;
    }
    return 0;
}
