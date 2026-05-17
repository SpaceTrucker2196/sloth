#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "tls_log.h"
#include "md5.h"
#include "jsonl.h"

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

/* GREASE values (RFC 8701) — must be filtered from JA3 lists. */
static int is_grease(uint16_t v) {
    return ((v & 0x0f0f) == 0x0a0a) && (((v >> 8) & 0xff) == (v & 0xff));
}

/* Append "%u" to ja3_buf at *pos; on first emit pass leading=0, then leading=1
 * inserts a '-' separator. Truncates silently if the buffer fills. */
static void ja3_emit(char *buf, int bufsz, int *pos, int *leading, uint16_t v) {
    char tmp[8];
    int  n = snprintf(tmp, sizeof(tmp), "%u", v);
    int  need = n + (*leading ? 1 : 0);
    if (*pos + need + 1 >= bufsz) return;   /* leave room for NUL */
    if (*leading) buf[(*pos)++] = '-';
    memcpy(buf + *pos, tmp, (size_t)n);
    *pos += n;
    buf[*pos] = '\0';
    *leading = 1;
}

static void ja3_section_separator(char *buf, int bufsz, int *pos) {
    if (*pos + 1 >= bufsz) return;
    buf[(*pos)++] = ',';
    buf[*pos] = '\0';
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

    /* JA3 accumulator: version,ciphers,extensions,curves,ec_formats */
    char ja3_str[512];
    int  ja3_pos     = 0;
    int  ja3_leading = 0;
    ja3_str[0] = '\0';

    /* legacy_version: save for fallback */
    if (rem < 2) return 0;
    uint16_t legacy_ver = u16be(ch + off);
    off += 2;

    /* JA3 section 1: TLS version (legacy_version, decimal). */
    ja3_emit(ja3_str, sizeof(ja3_str), &ja3_pos, &ja3_leading, legacy_ver);
    ja3_leading = 0;
    ja3_section_separator(ja3_str, sizeof(ja3_str), &ja3_pos);

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
    /* JA3 section 2: cipher suites (decimal), GREASE filtered. */
    for (int i = 0; i + 1 < cs; i += 2) {
        uint16_t c = u16be(ch + off + i);
        if (is_grease(c)) continue;
        ja3_emit(ja3_str, sizeof(ja3_str), &ja3_pos, &ja3_leading, c);
    }
    off += cs;
    ja3_leading = 0;
    ja3_section_separator(ja3_str, sizeof(ja3_str), &ja3_pos);

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

    /* JA3 section 3 fills as we go (extensions). Sections 4 (curves) and 5
     * (ec_point_formats) are deferred — we save them and emit after the
     * extensions list. */
    char curves_buf[256];  int curves_pos = 0; int curves_lead = 0; curves_buf[0] = 0;
    char fmts_buf[64];     int fmts_pos   = 0; int fmts_lead   = 0; fmts_buf[0]   = 0;

    while (off + 4 <= ext_end) {
        uint16_t etype = u16be(ch + off);
        uint16_t elen  = u16be(ch + off + 2);
        off += 4;
        if (off + (int)elen > ext_end) break;

        if (!is_grease(etype)) {
            ja3_emit(ja3_str, sizeof(ja3_str), &ja3_pos, &ja3_leading, etype);
        }

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
            /* supported_versions */
            int vlen = ch[off];
            int vi   = 1;
            has_sv   = 1;
            best_ver = 0;
            while (vi + 1 <= vlen && vi + 1 <= (int)elen) {
                uint16_t v = u16be(ch + off + vi);
                if (v > best_ver) best_ver = v;
                vi += 2;
            }
        } else if (etype == 0x000a && elen >= 2) {
            /* supported_groups (curves): list_len(2) + uint16[]. */
            int list_len = (int)u16be(ch + off);
            int gi       = 2;
            while (gi + 1 < list_len + 2 && gi + 1 <= (int)elen) {
                uint16_t g = u16be(ch + off + gi);
                if (!is_grease(g))
                    ja3_emit(curves_buf, sizeof(curves_buf),
                             &curves_pos, &curves_lead, g);
                gi += 2;
            }
        } else if (etype == 0x000b && elen >= 1) {
            /* ec_point_formats: fmt_list_len(1) + uint8[]. */
            int flist = ch[off];
            int fi    = 1;
            while (fi < 1 + flist && fi <= (int)elen) {
                ja3_emit(fmts_buf, sizeof(fmts_buf),
                         &fmts_pos, &fmts_lead, ch[off + fi]);
                fi++;
            }
        }

        off += (int)elen;
    }

    /* if no supported_versions extension, use legacy_version */
    if (!has_sv) best_ver = legacy_ver;

    /* Append sections 4 + 5 (curves, ec_formats). */
    ja3_leading = 0;
    ja3_section_separator(ja3_str, sizeof(ja3_str), &ja3_pos);
    if (curves_pos > 0 && ja3_pos + curves_pos < (int)sizeof(ja3_str) - 1) {
        memcpy(ja3_str + ja3_pos, curves_buf, (size_t)curves_pos);
        ja3_pos += curves_pos;
        ja3_str[ja3_pos] = '\0';
    }
    ja3_section_separator(ja3_str, sizeof(ja3_str), &ja3_pos);
    if (fmts_pos > 0 && ja3_pos + fmts_pos < (int)sizeof(ja3_str) - 1) {
        memcpy(ja3_str + ja3_pos, fmts_buf, (size_t)fmts_pos);
        ja3_pos += fmts_pos;
        ja3_str[ja3_pos] = '\0';
    }

    memset(out, 0, sizeof(*out));
    if (src_ip) snprintf(out->src, sizeof(out->src), "%s", src_ip);
    if (dst_ip) snprintf(out->dst, sizeof(out->dst), "%s", dst_ip);
    snprintf(out->host,    sizeof(out->host),    "%s", sni);
    snprintf(out->tls_ver, sizeof(out->tls_ver), "%s", ver_string(best_ver));
    md5_hex((const uint8_t *)ja3_str, (size_t)ja3_pos, out->ja3);
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
    jsonl_emit_tls(e);
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
