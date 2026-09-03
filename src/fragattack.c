#include <string.h>

#include "fragattack.h"
#include "dot11_data.h"

#define ETHERTYPE_EAPOL 0x888E

static frag_bss_t g_bss[FRAG_MAX_BSS];
static int        g_bss_n;

/* Stations witnessed installing a key, as (bssid, sta). Separate from
 * the BSS table because the gate is per-station: one client still
 * associating must not make another client's plaintext look like an
 * attack. */
typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    time_t  last_seen;
} frag_sta_t;

static frag_sta_t g_sta[FRAG_MAX_STATIONS];
static int        g_sta_n;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

/* EtherType of a frame that carries an LLC/SNAP header, or -1.
 *
 * Not dot11_data_payload(): that rejects *any* fragment, because for
 * #72's purpose — feeding the IP decoder — a partial packet is
 * undecodable. Here the first fragment is the interesting one and it
 * does carry its LLC header, which is the only way to tell a plaintext
 * EAPOL frame (legal) from a plaintext data frame (CVE-2020-26143).
 * The header arithmetic is still dot11_data.c's; only the eight-byte
 * SNAP check is repeated. */
static int first_frag_ethertype(const uint8_t *dot11, int len) {
    if (dot11_frag_num(dot11, len) != 0) return -1;

    int sub = (dot11[0] >> 4) & 0x0f;
    /* An A-MSDU body is subframes, not one LLC-encapsulated packet, so
     * there is no single EtherType to read. Plaintext A-MSDU on a
     * protected network is CVE-2020-26144 and its own detector. */
    if (sub & 0x08) {
        int qos_off = 24 + (((dot11[1] & 0x01) && ((dot11[1] >> 1) & 0x01))
                            ? 6 : 0);
        if (qos_off + 1 < len && (dot11[qos_off] & 0x80)) return -1;
    }

    int hdr = dot11_data_header_len(dot11, len);
    if (hdr < 0 || hdr + 8 > len) return -1;
    const uint8_t *llc = dot11 + hdr;
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03) return -1;
    return (llc[6] << 8) | llc[7];
}

int frag_find(const uint8_t bssid[6]) {
    if (!bssid) return -1;
    for (int i = 0; i < g_bss_n; i++)
        if (mac_eq(g_bss[i].bssid, bssid)) return i;
    return -1;
}

/* Evicts the stalest row when full rather than dropping the new one. A
 * table that stops learning after 64 BSSes is worse on a hopping radio
 * than one that forgets the BSS it has not heard from in longest. */
static frag_bss_t *bss_get(const uint8_t bssid[6], time_t now) {
    int i = frag_find(bssid);
    if (i >= 0) { g_bss[i].last_seen = now; return &g_bss[i]; }

    if (g_bss_n < FRAG_MAX_BSS) {
        i = g_bss_n++;
    } else {
        i = 0;
        for (int k = 1; k < g_bss_n; k++)
            if (g_bss[k].last_seen < g_bss[i].last_seen) i = k;
    }
    memset(&g_bss[i], 0, sizeof(g_bss[i]));
    memcpy(g_bss[i].bssid, bssid, 6);
    g_bss[i].first_seen = g_bss[i].last_seen = now;
    return &g_bss[i];
}

static int sta_find(const uint8_t bssid[6], const uint8_t sta[6]) {
    for (int i = 0; i < g_sta_n; i++)
        if (mac_eq(g_sta[i].bssid, bssid) && mac_eq(g_sta[i].sta, sta))
            return i;
    return -1;
}

static void sta_mark_protected(const uint8_t bssid[6], const uint8_t sta[6],
                               time_t now) {
    int i = sta_find(bssid, sta);
    if (i >= 0) { g_sta[i].last_seen = now; return; }
    if (g_sta_n < FRAG_MAX_STATIONS) {
        i = g_sta_n++;
    } else {
        i = 0;
        for (int k = 1; k < g_sta_n; k++)
            if (g_sta[k].last_seen < g_sta[i].last_seen) i = k;
    }
    memcpy(g_sta[i].bssid, bssid, 6);
    memcpy(g_sta[i].sta,   sta,   6);
    g_sta[i].last_seen = now;
}

void frag_observe(const uint8_t *dot11, int len, time_t now) {
    if (!dot11 || len < 24) return;
    if (((dot11[0] >> 2) & 0x03) != 2) return;      /* data frames only */

    int sub = (dot11[0] >> 4) & 0x0f;
    /* Null / QoS-Null carry no body. They are sent unprotected as a
     * matter of course — they are how a station signals power-save
     * state — so counting them would fire on every idle client. */
    if (sub & 0x04) return;

    uint8_t bssid[6], sa[6], da[6];
    int rc = dot11_data_addrs(dot11, len, bssid, sa, da);
    /* A four-address frame crosses two BSSes and has no single BSSID.
     * Skipped rather than attributed to a guess. */
    if (rc != 1) return;

    int protected_bit = (dot11[1] & 0x40) != 0;
    frag_bss_t *b = bss_get(bssid, now);

    if (protected_bit) {
        b->protected_frames++;
        /* The transmitter is the one whose key install we witnessed.
         * For a downlink frame that is the AP, which is exactly right:
         * a later plaintext frame *from the AP* is the -26140 case. */
        sta_mark_protected(bssid, sa, now);
        return;
    }

    /* Everything below is Protected=0 on a BSS we may or may not have
     * evidence about. Without a prior protected frame from this
     * station, an unprotected frame is an open network or a client
     * mid-association — the overwhelmingly common case, and not a
     * signal. */
    if (sta_find(bssid, sa) < 0) return;

    int fn   = dot11_frag_num(dot11, len);
    int more = dot11_more_frags(dot11, len);
    if (fn < 0 || more < 0) return;
    int fragmented = (fn > 0) || (more == 1);

    if (dot11_is_group_addr(da)) {
        /* CVE-2020-26145. Broadcast reassembly is not permitted in a
         * protected network, so a fragmented group-addressed plaintext
         * frame is already wrong before anything reassembles it — which
         * is why this fires on the fragment rather than waiting for a
         * completion that only the victim can perform. */
        if (!fragmented) return;
        b->plaintext_bcast_frag++;
    } else {
        /* CVE-2020-26140 / -26143. EAPOL is legitimately unprotected
         * even after key install — that is how rekeying works — so it
         * has to be excluded, and the EtherType is only readable on the
         * first fragment. A later fragment's payload could be anything,
         * and calling it an attack because we cannot see what it is
         * would be a guess dressed as a detection. Counted only when
         * the frame says what it carries. */
        int et = first_frag_ethertype(dot11, len);
        if (et < 0 || et == ETHERTYPE_EAPOL) return;
        b->plaintext_unicast++;
    }

    memcpy(b->last_sa, sa, 6);
    memcpy(b->last_da, da, 6);
    b->last_hit = now;
}

int frag_bss_count(void) { return g_bss_n; }

const frag_bss_t *frag_bss_at(int i) {
    return (i >= 0 && i < g_bss_n) ? &g_bss[i] : NULL;
}

void frag_clear(void) {
    memset(g_bss, 0, sizeof(g_bss));
    memset(g_sta, 0, sizeof(g_sta));
    g_bss_n = 0;
    g_sta_n = 0;
}
