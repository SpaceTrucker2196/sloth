#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "snmp_snoop.h"

static snmp_flow_t     g_tbl[MAX_SNMP_FLOWS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* SNMP message (RFC 1157 §4.1 v1, RFC 1901 §3 v2c):
 *
 *   Message ::= SEQUENCE {
 *       version   INTEGER (0=v1, 1=v2c, 3=v3),
 *       community OCTET STRING,       -- v1/v2c only
 *       data      ANY                  -- the PDU
 *   }
 *
 * The PDU is one of [APPLICATION 0..8], which BER-encodes as a
 * context-specific constructed tag 0xA0..0xA8:
 *   0xA0 GetRequest
 *   0xA1 GetNextRequest
 *   0xA2 GetResponse
 *   0xA3 SetRequest
 *   0xA4 Trap            (v1)
 *   0xA5 GetBulkRequest  (v2+)
 *   0xA6 InformRequest
 *   0xA7 SNMPv2-Trap
 *   0xA8 Report          (v3)
 *
 * Tags above use the context-specific class because the SMI maps
 * [APPLICATION n] in PDU position to that encoding. */
#define BER_SEQUENCE   0x30
#define BER_INTEGER    0x02
#define BER_OCTSTRING  0x04

#define PDU_GET        0xA0
#define PDU_GETNEXT    0xA1
#define PDU_RESPONSE   0xA2
#define PDU_SET        0xA3
#define PDU_TRAP_V1    0xA4
#define PDU_GETBULK    0xA5
#define PDU_INFORM     0xA6
#define PDU_TRAP_V2    0xA7
#define PDU_REPORT     0xA8

/* Parse a single BER length byte / short form. Returns the decoded
 * length and the number of bytes consumed, or -1 on indefinite or
 * unsupported encodings. Indefinite length doesn't appear in
 * SNMP per the SMI rules. */
static int ber_len(const uint8_t *p, int len, int *consumed) {
    if (len < 1) return -1;
    uint8_t b = p[0];
    if ((b & 0x80) == 0) {                   /* short form */
        *consumed = 1;
        return (int)b;
    }
    int n = b & 0x7F;
    if (n == 0 || n > 4 || 1 + n > len) return -1;  /* indefinite or huge */
    int v = 0;
    for (int i = 0; i < n; i++) v = (v << 8) | p[1 + i];
    *consumed = 1 + n;
    return v;
}

static int find_or_alloc(const char *src_ip, const char *dst_ip) {
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].src_ip, src_ip) == 0 &&
            strcmp(g_tbl[i].dst_ip, dst_ip) == 0) {
            return i;
        }
    }
    int slot;
    if (g_n < MAX_SNMP_FLOWS) {
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

static void record_community(snmp_flow_t *e, const char *community) {
    if (!community || !community[0]) return;
    snprintf(e->last_community, sizeof(e->last_community), "%s", community);
    for (int i = 0; i < e->community_count; i++) {
        if (strcmp(e->communities[i], community) == 0) return;
    }
    if (e->community_count >= MAX_SNMP_COMMUNITIES) return;
    snprintf(e->communities[e->community_count],
             sizeof(e->communities[0]), "%s", community);
    e->community_count++;
}

int snmp_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < 8) return 0;
    if (src_port != 161 && dst_port != 161 &&
        src_port != 162 && dst_port != 162) return 0;

    /* Outer SEQUENCE. */
    if (payload[0] != BER_SEQUENCE) return 0;
    int seq_len_off = 1;
    int seq_consumed = 0;
    int seq_len = ber_len(payload + seq_len_off, len - seq_len_off,
                          &seq_consumed);
    if (seq_len < 0) return 0;
    int p_off = seq_len_off + seq_consumed;
    int p_end = p_off + seq_len;
    if (p_end > len) return 0;

    /* version INTEGER. */
    if (p_off + 2 > p_end) return 0;
    if (payload[p_off] != BER_INTEGER) return 0;
    p_off++;
    int v_consumed = 0;
    int v_len = ber_len(payload + p_off, p_end - p_off, &v_consumed);
    if (v_len < 1 || v_len > 4) return 0;
    p_off += v_consumed;
    if (p_off + v_len > p_end) return 0;
    int version = 0;
    for (int i = 0; i < v_len; i++) version = (version << 8) | payload[p_off + i];
    p_off += v_len;

    /* SNMPv3 changes the structure — the next field is msgGlobalData
     * (a SEQUENCE), not a community OCTET STRING. We don't parse v3
     * here; just record that we saw a v3 packet on the flow. */
    char community[SNMP_COMMUNITY_LEN];
    community[0] = '\0';
    int pdu_tag = 0;

    if (version == 3) {
        /* Nothing more to extract reliably without the v3 USM dance. */
    } else {
        /* community OCTET STRING. */
        if (p_off + 2 > p_end) return 0;
        if (payload[p_off] != BER_OCTSTRING) return 0;
        p_off++;
        int c_consumed = 0;
        int c_len = ber_len(payload + p_off, p_end - p_off, &c_consumed);
        if (c_len < 0 || c_len > (int)sizeof(community) - 1) return 0;
        p_off += c_consumed;
        if (p_off + c_len > p_end) return 0;
        /* Copy + sanitize (printable ASCII only). */
        int k = 0;
        for (int i = 0; i < c_len && k + 1 < (int)sizeof(community); i++) {
            uint8_t c = payload[p_off + i];
            if (c < 0x20 || c > 0x7E) { community[0] = '\0'; break; }
            community[k++] = (char)c;
        }
        if (k > 0) community[k] = '\0';
        p_off += c_len;

        /* PDU tag — must be one of 0xA0..0xA8. */
        if (p_off >= p_end) return 0;
        pdu_tag = payload[p_off];
        if (pdu_tag < PDU_GET || pdu_tag > PDU_REPORT) return 0;
    }

    /* Attribute traffic to whichever side initiated the request.
     * Response source = 161 → attribute to dst (the querier). */
    const char *flow_src, *flow_dst;
    if (src_port == 161 || src_port == 162) {
        flow_src = dst_ip;
        flow_dst = src_ip;
    } else {
        flow_src = src_ip;
        flow_dst = dst_ip;
    }
    (void)dst_port;

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    int idx = find_or_alloc(flow_src, flow_dst);
    snmp_flow_t *e = &g_tbl[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;
    e->version   = version;
    record_community(e, community);
    switch (pdu_tag) {
    case PDU_GET:      e->get_count++;      break;
    case PDU_GETNEXT:  e->getnext_count++;  break;
    case PDU_RESPONSE: e->response_count++; break;
    case PDU_SET:      e->set_count++;      break;
    case PDU_TRAP_V1:  e->trap_count++;     break;
    case PDU_GETBULK:  e->getbulk_count++;  break;
    case PDU_INFORM:   e->trap_count++;     break;
    case PDU_TRAP_V2:  e->trap_count++;     break;
    default: break;
    }
    pthread_mutex_unlock(&g_mu);
    return 1;
}

void snmp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_SNMP_FLOWS ? g_n : MAX_SNMP_FLOWS;
    for (int i = 0; i < n; i++) s->snmp_flows[i] = g_tbl[i];
    s->snmp_flow_count = n;
    pthread_mutex_unlock(&g_mu);
}

void snmp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
