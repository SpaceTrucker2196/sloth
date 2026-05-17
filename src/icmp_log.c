#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "icmp_log.h"

/* ICMP header (RFC 792 / RFC 4443):
 *   0       1       2       3
 *  +-------+-------+---------------+
 *  | type  | code  |   checksum    |
 *  +-------+-------+---------------+
 *  |  rest of header (type-specific) ...
 *
 * For Echo (type 0/8, or v6 128/129):
 *  +-------+-------+---------------+
 *  |       id      |     seq       |
 *  +-------+-------+---------------+
 */

#define ICMP_HDR_MIN 4

static pthread_mutex_t  icmp_mu = PTHREAD_MUTEX_INITIALIZER;
static icmp_log_entry_t icmp_buf[MAX_ICMP_LOG];
static int              icmp_head;
static int              icmp_count;

static const char *desc_v4(uint8_t type, uint8_t code) {
    (void)code;
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Unreachable";
        case 4:  return "Src Quench";
        case 5:  return "Redirect";
        case 8:  return "Echo Req";
        case 9:  return "Router Adv";
        case 10: return "Router Sol";
        case 11: return "TTL Exceeded";
        case 12: return "Param Prob";
        case 13: return "Timestamp";
        case 14: return "TS Reply";
        case 30: return "Traceroute";
        default: return "ICMP";
    }
}

static const char *desc_v6(uint8_t type, uint8_t code) {
    (void)code;
    switch (type) {
        case 1:   return "Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "TTL Exceeded";
        case 4:   return "Param Prob";
        case 128: return "Echo Req";
        case 129: return "Echo Reply";
        case 130: return "MLD Query";
        case 131: return "MLD Report";
        case 132: return "MLD Done";
        case 133: return "Router Sol";
        case 134: return "Router Adv";
        case 135: return "Neigh Sol";
        case 136: return "Neigh Adv";
        case 137: return "Redirect";
        default:  return "ICMPv6";
    }
}

int icmp_log_parse(const uint8_t *msg, int len,
                   const char *src_ip, const char *dst_ip,
                   int is_v6, icmp_log_entry_t *out) {
    if (!msg || !out || len < ICMP_HDR_MIN) return 0;

    uint8_t type = msg[0];
    uint8_t code = msg[1];
    uint16_t seq = 0;

    int is_echo = is_v6
        ? (type == 128 || type == 129)
        : (type == 0 || type == 8);
    if (is_echo && len >= 8) {
        seq = (uint16_t)((msg[6] << 8) | msg[7]);
    }

    memset(out, 0, sizeof(*out));
    if (src_ip) snprintf(out->src, sizeof(out->src), "%s", src_ip);
    if (dst_ip) snprintf(out->dst, sizeof(out->dst), "%s", dst_ip);
    snprintf(out->desc, sizeof(out->desc), "%s",
             is_v6 ? desc_v6(type, code) : desc_v4(type, code));
    out->type  = type;
    out->code  = code;
    out->seq   = seq;
    out->is_v6 = is_v6 ? 1 : 0;
    out->ts    = time(NULL);
    return 1;
}

void icmp_log_record(const icmp_log_entry_t *e) {
    if (!e) return;
    pthread_mutex_lock(&icmp_mu);
    icmp_buf[icmp_head] = *e;
    icmp_head = (icmp_head + 1) % MAX_ICMP_LOG;
    if (icmp_count < MAX_ICMP_LOG) icmp_count++;
    pthread_mutex_unlock(&icmp_mu);
}

void icmp_log_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&icmp_mu);
    int n = icmp_count;
    for (int i = 0; i < n; i++) {
        int idx = (icmp_head - 1 - i + MAX_ICMP_LOG) % MAX_ICMP_LOG;
        s->icmp_log[i] = icmp_buf[idx];
    }
    s->icmp_log_count = n;
    if (s->icmp_log_sel >= n) s->icmp_log_sel = n > 0 ? n - 1 : 0;
    if (s->icmp_log_sel < 0)  s->icmp_log_sel = 0;
    pthread_mutex_unlock(&icmp_mu);
}

void icmp_log_clear(void) {
    pthread_mutex_lock(&icmp_mu);
    icmp_head  = 0;
    icmp_count = 0;
    pthread_mutex_unlock(&icmp_mu);
}
