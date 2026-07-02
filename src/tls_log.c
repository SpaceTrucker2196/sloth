#include <stdio.h>
#include <stdlib.h>   /* qsort — JA4 cipher/ext sort */
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "tls_log.h"
#include "md5.h"
#include "sha256.h"
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

/* ── JA4 helpers ─────────────────────────────────────────
 *
 * Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * Format: <a>_<b>_<c> where
 *   a = protocol(1) + version(2) + sni(1) + numciphers(2) + numexts(2) + alpn(2)
 *   b = first 12 hex chars of sha256(sorted-hex-ciphers joined by ',')
 *   c = first 12 hex chars of sha256(sorted-hex-extensions + '_' + sig-algs-as-observed)
 *
 * GREASE is filtered from ciphers, extensions, sig_algs everywhere it
 * matters. SNI (0x0000) and ALPN (0x0010) are counted in numexts but
 * excluded from JA4_c. */

static const char *ja4_version(uint16_t v) {
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    default:     return "00";
    }
}

static int u16_cmp(const void *a, const void *b) {
    uint16_t ua = *(const uint16_t *)a;
    uint16_t ub = *(const uint16_t *)b;
    return (ua > ub) - (ua < ub);
}

/* Format u16 list as comma-separated lowercase hex, e.g. "003c,c02f".
 * out must hold at least (5*count + 1) bytes. Returns bytes written
 * (excluding NUL). */
static int ja4_hex_list(uint16_t *vals, int n, char *out, int outsz) {
    int p = 0;
    for (int i = 0; i < n; i++) {
        int need = (i > 0) ? 5 : 4;
        if (p + need + 1 >= outsz) break;
        if (i > 0) out[p++] = ',';
        static const char hexc[] = "0123456789abcdef";
        out[p++] = hexc[(vals[i] >> 12) & 0xf];
        out[p++] = hexc[(vals[i] >>  8) & 0xf];
        out[p++] = hexc[(vals[i] >>  4) & 0xf];
        out[p++] = hexc[ vals[i]        & 0xf];
    }
    out[p] = '\0';
    return p;
}

/* True if the SNI string looks like a numeric IP literal (contains no
 * alphabetic chars). Used for the JA4 SNI flag ("d" vs "i" vs "n"). */
static int sni_is_ip_only(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))
            return 0;
    }
    return 1;
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

    /* JA4 collection buffers — kept in observed order until we know the
     * cipher/ext/sig-alg counts, then sorted for sections b + c. Sized
     * to comfortably hold Chrome/Firefox ClientHellos (typically <32
     * ciphers, <32 extensions). */
    uint16_t ja4_ciphers[128];  int ja4_nciphers = 0;
    uint16_t ja4_exts[64];      int ja4_nexts    = 0;
    uint16_t ja4_sigalgs[32];   int ja4_nsigalgs = 0;
    /* ALPN edge chars — first char of first proto + last char of last. */
    char     ja4_alpn_first = 0;
    char     ja4_alpn_last  = 0;

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
    /* JA3 section 2: cipher suites (decimal), GREASE filtered. Same
     * pass populates the JA4 cipher collector (non-GREASE, observed
     * order — sort happens later during JA4_b assembly). */
    for (int i = 0; i + 1 < cs; i += 2) {
        uint16_t c = u16be(ch + off + i);
        if (is_grease(c)) continue;
        ja3_emit(ja3_str, sizeof(ja3_str), &ja3_pos, &ja3_leading, c);
        if (ja4_nciphers < (int)(sizeof(ja4_ciphers)/sizeof(ja4_ciphers[0])))
            ja4_ciphers[ja4_nciphers++] = c;
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
            /* JA4: every non-GREASE extension counts toward numexts,
             * even SNI/ALPN (which are excluded from section c's hash
             * but still count in section a). */
            if (ja4_nexts < (int)(sizeof(ja4_exts)/sizeof(ja4_exts[0])))
                ja4_exts[ja4_nexts++] = etype;
        }

        /* signature_algorithms (0x000d): list_len(2) + uint16[]. */
        if (etype == 0x000d && elen >= 2) {
            int sig_list = (int)u16be(ch + off);
            int si       = 2;
            while (si + 1 < sig_list + 2 && si + 1 <= (int)elen) {
                uint16_t sa = u16be(ch + off + si);
                if (!is_grease(sa)
                    && ja4_nsigalgs < (int)(sizeof(ja4_sigalgs)/sizeof(ja4_sigalgs[0])))
                    ja4_sigalgs[ja4_nsigalgs++] = sa;
                si += 2;
            }
        }

        /* ALPN (0x0010): list_len(2) + [name_len(1) + name]... — record
         * the first char of the first proto and last char of the last
         * so we can emit JA4's 2-char ALPN summary. Full list not
         * retained. */
        if (etype == 0x0010 && elen >= 3) {
            int alpn_list = (int)u16be(ch + off);
            int ai        = 2;
            int last_seen = 0;
            while (ai < 2 + alpn_list && ai < (int)elen) {
                int nlen = ch[off + ai++];
                if (nlen <= 0 || ai + nlen > (int)elen) break;
                if (!ja4_alpn_first) ja4_alpn_first = (char)ch[off + ai];
                last_seen = ch[off + ai + nlen - 1];
                ai += nlen;
            }
            if (last_seen) ja4_alpn_last = (char)last_seen;
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
                /* RFC 8701: skip GREASE values so a leading 0x?a?a
                 * doesn't win over 0x0304. */
                if (!is_grease(v) && v > best_ver) best_ver = v;
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

    /* ── JA4 assembly ──────────────────────────────────────
     * Section a: t + version(2) + sni(1) + numciphers(2) + numexts(2)
     *          + alpn(2) = 10 chars.
     * Section b: 12 hex chars, sha256(sorted ciphers as ",\"-joined
     *            4-digit hex).
     * Section c: 12 hex chars, sha256(sorted extensions [excl SNI +
     *            ALPN] + "_" + sig_algs as-observed). */
    char sni_flag = sni[0] ? (sni_is_ip_only(sni) ? 'i' : 'd') : 'n';
    int  nc = ja4_nciphers > 99 ? 99 : ja4_nciphers;
    int  ne = ja4_nexts    > 99 ? 99 : ja4_nexts;
    char alpn2[3];
    if (ja4_alpn_first && ja4_alpn_last) {
        alpn2[0] = ja4_alpn_first;
        alpn2[1] = ja4_alpn_last;
    } else {
        alpn2[0] = '0'; alpn2[1] = '0';
    }
    alpn2[2] = '\0';

    char sec_a[16];
    snprintf(sec_a, sizeof(sec_a), "t%s%c%02d%02d%s",
             ja4_version(best_ver), sni_flag, nc, ne, alpn2);

    /* Section b: sorted ciphers → hex list → sha256 → first 12 hex. */
    uint16_t sorted_ciphers[128];
    memcpy(sorted_ciphers, ja4_ciphers, (size_t)ja4_nciphers * sizeof(uint16_t));
    qsort(sorted_ciphers, (size_t)ja4_nciphers, sizeof(uint16_t), u16_cmp);
    char cipher_str[128 * 5 + 1];
    ja4_hex_list(sorted_ciphers, ja4_nciphers, cipher_str, sizeof(cipher_str));
    char sec_b_hex[65];
    sha256_hex((const uint8_t *)cipher_str, strlen(cipher_str), sec_b_hex);

    /* Section c: sorted exts (excl SNI 0x0000 + ALPN 0x0010) + "_" +
     * sig_algs as observed. */
    uint16_t sorted_exts[64];
    int      sec_c_next = 0;
    for (int i = 0; i < ja4_nexts; i++) {
        if (ja4_exts[i] == 0x0000 || ja4_exts[i] == 0x0010) continue;
        sorted_exts[sec_c_next++] = ja4_exts[i];
    }
    qsort(sorted_exts, (size_t)sec_c_next, sizeof(uint16_t), u16_cmp);
    char sec_c_input[64 * 5 + 32 * 5 + 2];
    int  p = ja4_hex_list(sorted_exts, sec_c_next, sec_c_input, sizeof(sec_c_input));
    if (p + 1 < (int)sizeof(sec_c_input)) sec_c_input[p++] = '_';
    ja4_hex_list(ja4_sigalgs, ja4_nsigalgs,
                 sec_c_input + p, (int)sizeof(sec_c_input) - p);
    char sec_c_hex[65];
    sha256_hex((const uint8_t *)sec_c_input, strlen(sec_c_input), sec_c_hex);

    snprintf(out->ja4, sizeof(out->ja4), "%s_%.12s_%.12s",
             sec_a, sec_b_hex, sec_c_hex);

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
