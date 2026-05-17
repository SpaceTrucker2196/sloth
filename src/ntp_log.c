#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include "ntp_log.h"
#include "jsonl.h"

/* RFC 5905 — NTPv3/v4 fixed header (48 bytes minimum):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Root Delay (4)                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Root Dispersion (4)                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Reference Identifier (4)                   |
 *  ... timestamps (32 bytes) follow ...
 */

#define NTP_HDR_MIN 48

static pthread_mutex_t ntp_mu  = PTHREAD_MUTEX_INITIALIZER;
static ntp_log_entry_t ntp_buf[MAX_NTP_LOG];
static int             ntp_head;
static int             ntp_count;

static const char *mode_str(uint8_t mode) {
    switch (mode) {
        case 0: return "?";
        case 1: return "sym-act";
        case 2: return "sym-pas";
        case 3: return "client";
        case 4: return "server";
        case 5: return "bcast";
        case 6: return "ctrl";
        case 7: return "private";
        default: return "?";
    }
}

/* Reference ID interpretation depends on stratum:
 *   stratum 0 or 1: 4-char ASCII "kiss code" or server tag ("GPS\0", "PPS\0", etc.)
 *   stratum 2..15:  IPv4 address of upstream server.
 *   stratum 16:     unsynchronized — implementations commonly stuff an ASCII
 *                    code here ("INIT", "STEP", "AUTH"), so treat as ASCII too.
 * For IPv6 servers, the field holds the low-order 32 bits of an MD5 hash. */
static void format_ref(uint8_t stratum, const uint8_t *ref, char *out, int sz) {
    if (sz <= 0) return;
    if (stratum <= 1 || stratum >= 16) {
        int len = 0;
        for (int i = 0; i < 4 && ref[i] != 0; i++) {
            if (isprint(ref[i])) {
                if (len + 1 < sz) out[len++] = (char)ref[i];
            } else {
                break;
            }
        }
        if (len == 0) {
            snprintf(out, sz, "-");
        } else {
            out[len] = 0;
        }
    } else {
        snprintf(out, sz, "%u.%u.%u.%u", ref[0], ref[1], ref[2], ref[3]);
    }
}

int ntp_log_parse(const uint8_t *msg, int len,
                  const char *src_ip, const char *dst_ip,
                  ntp_log_entry_t *out) {
    if (!msg || !out || len < NTP_HDR_MIN) return 0;

    uint8_t b0      = msg[0];
    uint8_t version = (b0 >> 3) & 0x7;
    uint8_t mode    = b0 & 0x7;
    uint8_t stratum = msg[1];

    if (version < 1 || version > 4) return 0;

    memset(out, 0, sizeof(*out));
    if (src_ip) snprintf(out->src, sizeof(out->src), "%s", src_ip);
    if (dst_ip) snprintf(out->dst, sizeof(out->dst), "%s", dst_ip);
    snprintf(out->mode, sizeof(out->mode), "%s", mode_str(mode));
    format_ref(stratum, msg + 12, out->ref, (int)sizeof(out->ref));
    out->version = version;
    out->stratum = stratum;
    out->ts      = time(NULL);
    return 1;
}

void ntp_log_record(const ntp_log_entry_t *e) {
    if (!e) return;
    pthread_mutex_lock(&ntp_mu);
    ntp_buf[ntp_head] = *e;
    ntp_head = (ntp_head + 1) % MAX_NTP_LOG;
    if (ntp_count < MAX_NTP_LOG) ntp_count++;
    pthread_mutex_unlock(&ntp_mu);
    jsonl_emit_ntp(e);
}

void ntp_log_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&ntp_mu);

    /* Copy newest-first into s->ntp_log. Newest entry is at (head-1). */
    int n = ntp_count;
    for (int i = 0; i < n; i++) {
        int idx = (ntp_head - 1 - i + MAX_NTP_LOG) % MAX_NTP_LOG;
        s->ntp_log[i] = ntp_buf[idx];
    }
    s->ntp_log_count = n;
    if (s->ntp_log_sel >= n) s->ntp_log_sel = n > 0 ? n - 1 : 0;
    if (s->ntp_log_sel < 0)  s->ntp_log_sel = 0;
    pthread_mutex_unlock(&ntp_mu);
}

void ntp_log_clear(void) {
    pthread_mutex_lock(&ntp_mu);
    ntp_head  = 0;
    ntp_count = 0;
    pthread_mutex_unlock(&ntp_mu);
}
