#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rdp_snoop.h"

static rdp_flow_t      g_tbl[MAX_RDP_FLOWS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* RFC 1006 §6 — TPKT envelope:
 *   byte 0   version (always 0x03)
 *   byte 1   reserved (0x00)
 *   bytes 2-3 length (big-endian, includes 4-byte TPKT header)
 *
 * Followed by an X.224 (ITU T.0) Class 0 TPDU. For a Connection
 * Request the layout is:
 *   byte 0   LI (length indicator — bytes that follow, not incl. LI)
 *   byte 1   CR code = 0xE0 (low nibble is credit, always 0 in C0)
 *   bytes 2-3 DST-REF (always 0x0000 in C0)
 *   bytes 4-5 SRC-REF
 *   byte 6   class/options (usually 0x00)
 *   ... variable-length user data (RDP Negotiation Request + cookie)
 *
 * MS-RDPBCGR §2.2.1.1.1 — the cookie field is an ASCII string
 *   "Cookie: mstshash=USERNAME\r\n"
 * followed optionally by the RDP Negotiation Request TLV:
 *   byte 0   type = 0x01 (RDP_NEG_REQ)
 *   byte 1   flags
 *   bytes 2-3 length = 0x0008 (little-endian)
 *   bytes 4-7 requestedProtocols bitmask (little-endian uint32)
 */
#define TPKT_HDR_LEN     4
#define X224_CR_CODE  0xE0
#define X224_CR_MASK  0xF0
#define RDP_NEG_REQ   0x01

#define MIN_CR_LEN   (TPKT_HDR_LEN + 7)   /* TPKT + minimal CR TPDU */

static int find_or_alloc(const char *src_ip, const char *dst_ip) {
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].src_ip, src_ip) == 0 &&
            strcmp(g_tbl[i].dst_ip, dst_ip) == 0) {
            return i;
        }
    }
    int slot;
    if (g_n < MAX_RDP_FLOWS) {
        slot = g_n++;
    } else {
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_tbl[i].last_seen < g_tbl[slot].last_seen) slot = i;
        }
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].src_ip, sizeof(g_tbl[slot].src_ip), "%s", src_ip);
    snprintf(g_tbl[slot].dst_ip, sizeof(g_tbl[slot].dst_ip), "%s", dst_ip);
    return slot;
}

/* Pull the username out of "Cookie: mstshash=USERNAME\r\n" if
 * present in the X.224 user-data field. Returns 1 if a cookie
 * was found and copied into out (NUL-terminated). The CR/LF
 * boundary marks the end of the value. */
static int extract_mstshash(const uint8_t *p, int len,
                            char *out, size_t cap) {
    static const char NEEDLE[] = "Cookie: mstshash=";
    int needle_len = (int)sizeof(NEEDLE) - 1;
    if (cap == 0 || len < needle_len) return 0;
    int last_start = len - needle_len;
    for (int i = 0; i <= last_start; i++) {
        if (memcmp(p + i, NEEDLE, (size_t)needle_len) != 0) continue;
        int j = i + needle_len;
        size_t k = 0;
        while (j < len && k + 1 < cap) {
            uint8_t c = p[j];
            if (c == '\r' || c == '\n') break;
            if (c < 0x20 || c > 0x7E) break;
            out[k++] = (char)c;
            j++;
        }
        out[k] = '\0';
        return k > 0;
    }
    return 0;
}

/* Look for the RDP Negotiation Request TLV and OR its
 * requestedProtocols field into *mask. The TLV always has
 * length = 0x0008 LE and is 8 bytes total. */
static void extract_neg_req_protocols(const uint8_t *p, int len,
                                       uint8_t *mask) {
    for (int i = 0; i + 8 <= len; i++) {
        if (p[i] != RDP_NEG_REQ)        continue;
        if (p[i + 2] != 0x08 || p[i + 3] != 0x00) continue;
        uint32_t protos = (uint32_t)p[i + 4]
                        | ((uint32_t)p[i + 5] << 8)
                        | ((uint32_t)p[i + 6] << 16)
                        | ((uint32_t)p[i + 7] << 24);
        /* Only the low nibble has documented meanings; mask it
         * to keep proto_mask tight and reserved bits out. */
        *mask |= (uint8_t)(protos & 0x0Fu);
        return;
    }
}

int rdp_snoop_observe(const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port,
                      const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < MIN_CR_LEN) return 0;
    if (src_port != 3389 && dst_port != 3389) return 0;

    /* TPKT envelope check. */
    if (payload[0] != 0x03 || payload[1] != 0x00) return 0;
    int tpkt_len = ((int)payload[2] << 8) | payload[3];
    if (tpkt_len < MIN_CR_LEN || tpkt_len > len) return 0;

    /* X.224 TPDU header. LI is bytes 0 of the TPDU body. */
    const uint8_t *tpdu = payload + TPKT_HDR_LEN;
    int tpdu_len = tpkt_len - TPKT_HDR_LEN;
    int li = tpdu[0];
    /* LI counts the bytes after itself; the TPDU is LI+1 bytes. */
    if (li < 6 || li + 1 > tpdu_len) return 0;
    if ((tpdu[1] & X224_CR_MASK) != X224_CR_CODE) return 0;   /* CR? */
    /* DST-REF in C0 CR must be 0x0000. */
    if (tpdu[2] != 0x00 || tpdu[3] != 0x00) return 0;

    /* CR fixed part is 7 bytes (LI included via tpdu[0..6]).
     * User data starts at offset 7 and runs to LI+1. */
    int user_off = 7;
    int user_len = (li + 1) - user_off;
    const uint8_t *user_data = (user_len > 0) ? tpdu + user_off : NULL;

    /* Client→server direction is the one we want. RDP is
     * symmetric in that responses also use TPKT, but X.224
     * Connection Confirm has code 0xD0 — already rejected by
     * the CR check above. So whichever side sent this packet
     * is the client. */
    const char *client_ip, *server_ip;
    if (dst_port == 3389) {
        client_ip = src_ip;
        server_ip = dst_ip;
    } else {
        /* src_port=3389 means this is server→client; can't be a
         * CR (the CR check would have failed) but guard anyway. */
        return 0;
    }
    (void)src_port;

    char    cookie[64];
    cookie[0] = '\0';
    uint8_t protos = 0;
    if (user_data) {
        extract_mstshash(user_data, user_len, cookie, sizeof(cookie));
        extract_neg_req_protocols(user_data, user_len, &protos);
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    int idx = find_or_alloc(client_ip, server_ip);
    rdp_flow_t *e = &g_tbl[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;
    e->connect_req_count++;
    if (cookie[0])
        snprintf(e->last_cookie, sizeof(e->last_cookie), "%s", cookie);
    e->proto_mask |= protos;
    pthread_mutex_unlock(&g_mu);
    return 1;
}

void rdp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_RDP_FLOWS ? g_n : MAX_RDP_FLOWS;
    for (int i = 0; i < n; i++) s->rdp_flows[i] = g_tbl[i];
    s->rdp_flow_count = n;
    pthread_mutex_unlock(&g_mu);
}

void rdp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
