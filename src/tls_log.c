#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "tls_log.h"

static tls_log_entry_t g_log[MAX_TLS_LOG];
static int             g_head  = 0;
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── TLS ClientHello parser ──────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static const char *ver_string(uint16_t v) {
    switch (v) {
    case 0x0304: return "TLS 1.3";
    case 0x0303: return "TLS 1.2";
    case 0x0302: return "TLS 1.1";
    case 0x0301: return "TLS 1.0";
    default:     return "TLS";
    }
}

int tls_log_parse(const uint8_t *data, int len,
                  const char *src_ip, const char *dst_ip,
                  tls_log_entry_t *out)
{
    /* ── TLS record header (5 bytes) ── */
    if (len < 9) return 0;
    if (data[0] != 0x16) return 0;   /* handshake record */
    if (data[1] != 0x03) return 0;   /* major version == 3 */

    uint16_t rec_len = u16be(data + 3);
    if ((int)rec_len < 4 || 5 + (int)rec_len > len) return 0;

    /* ── Handshake header (4 bytes) ── */
    const uint8_t *hs = data + 5;
    if (hs[0] != 0x01) return 0;     /* ClientHello */

    int ch_len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
    if (ch_len < 35 || 4 + ch_len > (int)rec_len) return 0;

    /* ── ClientHello body ── */
    const uint8_t *ch  = hs + 4;
    int            rem = ch_len;
    int            off = 0;

    /* legacy_version: save for fallback */
    if (rem < 2) return 0;
    uint16_t legacy_ver = u16be(ch + off);
    off += 2;

    /* random (32) */
    if (off + 32 > rem) return 0;
    off += 32;

    /* session_id */
    if (off + 1 > rem) return 0;
    int sid = ch[off++];
    if (off + sid > rem) return 0;
    off += sid;

    /* cipher_suites */
    if (off + 2 > rem) return 0;
    int cs = (int)u16be(ch + off); off += 2;
    if (off + cs > rem) return 0;
    off += cs;

    /* compression_methods */
    if (off + 1 > rem) return 0;
    int cm = ch[off++];
    if (off + cm > rem) return 0;
    off += cm;

    /* extensions */
    if (off + 2 > rem) return 0;
    int ext_total = (int)u16be(ch + off); off += 2;
    if (off + ext_total > rem) return 0;
    int ext_end = off + ext_total;

    /* ── Walk extensions ── */
    char     sni[64] = "";
    uint16_t best_ver = legacy_ver;
    int      has_sv   = 0;

    while (off + 4 <= ext_end) {
        uint16_t etype = u16be(ch + off);
        uint16_t elen  = u16be(ch + off + 2);
        off += 4;
        if (off + (int)elen > ext_end) break;

        if (etype == 0x0000 && elen >= 5 && sni[0] == '\0') {
            /* server_name list: list_len(2) + name_type(1) + name_len(2) + name */
            uint16_t list_len  = u16be(ch + off);
            if (list_len + 2 <= elen && ch[off + 2] == 0x00) {
                int nlen = (int)u16be(ch + off + 3);
                if (nlen > 0 && nlen + 5 <= (int)elen) {
                    int sz = nlen < 63 ? nlen : 63;
                    memcpy(sni, ch + off + 5, (size_t)sz);
                    sni[sz] = '\0';
                }
            }
            (void)list_len;
        } else if (etype == 0x002b && elen >= 1) {
            /* supported_versions: versions_len(1) + list of uint16 */
            int vlen = ch[off];
            int vi   = 1;
            has_sv   = 1;
            best_ver = 0;   /* reset; pick highest from list */
            while (vi + 1 <= vlen && vi + 1 <= (int)elen) {
                uint16_t v = u16be(ch + off + vi);
                if (v > best_ver) best_ver = v;
                vi += 2;
            }
        }

        off += (int)elen;
    }

    /* if no supported_versions extension, use legacy_version */
    if (!has_sv) best_ver = legacy_ver;

    memset(out, 0, sizeof(*out));
    if (src_ip) strncpy(out->src, src_ip, sizeof(out->src) - 1);
    if (dst_ip) strncpy(out->dst, dst_ip, sizeof(out->dst) - 1);
    snprintf(out->host,    sizeof(out->host),    "%s", sni);
    snprintf(out->tls_ver, sizeof(out->tls_ver), "%s", ver_string(best_ver));
    out->ts = time(NULL);
    return 1;
}

/* ── Rolling log ─────────────────────────────────────────── */

void tls_log_record(const tls_log_entry_t *e)
{
    pthread_mutex_lock(&g_mu);
    g_log[g_head] = *e;
    g_head = (g_head + 1) % MAX_TLS_LOG;
    if (g_count < MAX_TLS_LOG) g_count++;
    pthread_mutex_unlock(&g_mu);
}

void tls_log_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_TLS_LOG ? g_count : MAX_TLS_LOG;
    for (int i = 0; i < n; i++) {
        int idx = ((g_head - 1 - i) % MAX_TLS_LOG + MAX_TLS_LOG) % MAX_TLS_LOG;
        s->tls_log[i] = g_log[idx];
    }
    s->tls_log_count = n;
    s->tls_log_head  = g_head;
    if (s->tls_log_sel >= n) s->tls_log_sel = n > 0 ? n - 1 : 0;
    pthread_mutex_unlock(&g_mu);
}

void tls_log_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head  = 0;
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
