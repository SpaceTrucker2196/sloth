#include "wifi_snapshot.h"
#include "secure_file.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

/* No mutex, unlike jsonl's: the snapshot is written once at shutdown
 * on the main thread, so nothing races the reason buffer. */
static sfile_fail_t g_fail;

const char *wifi_snapshot_error(void) { return g_fail.last; }

/* One field-safe copy: replace tab/newline with space so the TSV round-trips. */
static void safe_field(const char *in, char *out, int sz) {
    int i = 0;
    for (; in && in[i] && i < sz - 1; i++)
        out[i] = (in[i] == '\t' || in[i] == '\n' || in[i] == '\r') ? ' ' : in[i];
    out[i] = '\0';
    if (i == 0) { out[0] = '-'; out[1] = '\0'; }   /* never empty */
}

/* The SSID is chosen by whoever is transmitting, and 802.11 lets it be
 * any 32 octets (#137). A raw tab or newline in it would add fields or
 * whole rows to the file the next run reads back as its baseline — an
 * on-air string editing the assessor's ground truth. safe_field(),
 * which the SSID used to share with the columns sloth generates itself,
 * blanks them to spaces: that stops the injection but loses the bytes,
 * so an SSID differing from another only by a tab read back as that
 * other one.
 *
 * Escaped instead, losslessly: `\\` `\t` `\n` `\r`, `\xHH` for any
 * other C0 byte or DEL, and a lone "-" (the column's "hidden" marker)
 * as `\x2d`. A file with no backslashes — every v1 file written before
 * this — parses exactly as before, so the format line does not change.
 * Escapes are never split at the buffer end: a sequence that does not
 * fit is dropped whole, so the reader never meets half of one. */
static void show_escaped(const char *in, char *out, size_t cap) {
    size_t o = 0;
    if (cap == 0) return;
    if (!in || !in[0]) { snprintf(out, cap, "-"); return; }
    for (size_t i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        char esc[5];
        size_t len;
        if      (c == '\\') { memcpy(esc, "\\\\", 2); len = 2; }
        else if (c == '\t') { memcpy(esc, "\\t", 2);  len = 2; }
        else if (c == '\n') { memcpy(esc, "\\n", 2);  len = 2; }
        else if (c == '\r') { memcpy(esc, "\\r", 2);  len = 2; }
        else if (c < 0x20 || c == 0x7f) {
            static const char hx[] = "0123456789abcdef";
            esc[0] = '\\'; esc[1] = 'x';
            esc[2] = hx[c >> 4]; esc[3] = hx[c & 15];
            len = 4;
        } else { esc[0] = (char)c; len = 1; }
        if (o + len >= cap) break;
        memcpy(out + o, esc, len);
        o += len;
    }
    out[o] = '\0';
}

/* The file form: show_escaped plus the one rule a display does not
 * need — a real SSID of "-" must not read back as the hidden marker. */
static void field_escape(const char *in, char *out, size_t cap) {
    if (cap > 0 && in && strcmp(in, "-") == 0) {
        snprintf(out, cap, "\\x2d");
        return;
    }
    show_escaped(in, out, cap);
}

static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Inverse of field_escape. An escape it does not recognise — or `\x00`,
 * which no SSID string can hold — is kept as the literal backslash, so
 * a hand-edited file degrades to "shown as typed" rather than to a
 * truncated or merged field. "-" alone is the hidden network, "". */
static void field_unescape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    if (cap == 0) return;
    if (strcmp(in, "-") == 0) { out[0] = '\0'; return; }
    for (size_t i = 0; in[i] && o + 1 < cap; i++) {
        char c = in[i];
        if (c == '\\' && in[i + 1]) {
            char n = in[i + 1];
            if (n == '\\') { c = '\\'; i++; }
            else if (n == 't') { c = '\t'; i++; }
            else if (n == 'n') { c = '\n'; i++; }
            else if (n == 'r') { c = '\r'; i++; }
            else if (n == 'x' && hexnib(in[i + 2]) >= 0 &&
                     hexnib(in[i + 3]) >= 0) {
                int v = hexnib(in[i + 2]) * 16 + hexnib(in[i + 3]);
                if (v != 0) { c = (char)v; i += 3; }
            }
        }
        out[o++] = c;
    }
    out[o] = '\0';
}

/* Integer field with a range, or 0 for "reject this row". atoi() turned
 * "6junk" into 6 and "x" into a silent 0 — channel 0 compared equal to
 * nothing and reported a CHANGED that never happened. */
static int field_int(const char *s, long lo, long hi, int *out) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < lo || v > hi) return 0;
    *out = (int)v;
    return 1;
}

static void bssid_str(const uint8_t *b, char *out, int sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

int wifi_snapshot_write(const sloth_state_t *s, const char *path,
                        const char *label, long now) {
    /* Reset BEFORE the argument guard, not after: wifi_snapshot_error()
     * is read by src/main.c on any -1, and returning early left it
     * holding the previous call's reason — or "" on the first call,
     * which reads as "failed for no reason". */
    sfile_fail_reset(&g_fail);
    if (!s || !path) return -1;
    /* A snapshot names every AP in range with its security posture, so
     * it gets the same treatment as --report: created 0600, an existing
     * file validated BEFORE it is truncated, so a refused one is left
     * byte-for-byte intact (#87). TRUNC rather than EXCL because
     * re-pointing --snapshot-out at last visit's file is the documented
     * repeat-survey workflow. stderr is left to the caller, which
     * already prints one line per outcome. */
    FILE *f = sfile_fopen(AT_FDCWD, path, SFILE_TRUNC,
                          g_fail.last, sizeof(g_fail.last));
    if (!f) return -1;

    fprintf(f, "# sloth-snapshot v1\n");
    /* The label is the operator's, but a newline in it would still start
     * a row in the next run's baseline, so it takes the same escape. */
    char lab[256];
    field_escape(label, lab, sizeof(lab));
    fprintf(f, "# label\t%s\n", lab);
    fprintf(f, "# ts\t%ld\n", now);
    fprintf(f, "# count\t%d\n", s->beacon_count);
    fprintf(f, "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n");

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        /* 32 octets at four bytes per \xHH, plus the NUL. */
        char bss[20], ssid[32 * 4 + 1], enc[16], akm[32], vendor[32];
        bssid_str(a->bssid, bss, sizeof(bss));
        field_escape(a->ssid, ssid, sizeof(ssid));
        safe_field(a->enc,    enc,    sizeof(enc));
        safe_field(a->akm,    akm,    sizeof(akm));
        safe_field(a->vendor, vendor, sizeof(vendor));
        fprintf(f, "%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
                bss, ssid, enc, a->channel, akm, a->mfp, vendor);
    }
    /* sfile_fclose folds in ferror, the flush and the close, so a
     * failure anywhere in the fprintf run above surfaces here — which
     * is why the individual writes stay unchecked. Before this the
     * return was an unconditional 0, and a truncated file was announced
     * to the operator as written. */
    return sfile_fclose(f, path, g_fail.last, sizeof(g_fail.last)) == 0
           ? 0 : -1;
}

/* Parsed baseline AP — only the fields we diff on. */
typedef struct {
    char bssid[20];
    char ssid[33];      /* unescaped: the octets as heard */
    char enc[16];
    int  channel;
    int  mfp;
    int  matched;   /* set when a current AP pairs with it */
} base_ap_t;

int wifi_snapshot_diff(const sloth_state_t *s, const char *baseline_path,
                       FILE *out) {
    if (!s || !baseline_path || !out) return -1;
    FILE *f = fopen(baseline_path, "r");
    if (!f) return -1;

    base_ap_t *base = calloc(MAX_BEACON_APS, sizeof(base_ap_t));
    if (!base) { fclose(f); return -1; }
    int nb = 0;

    char line[512];
    while (fgets(line, sizeof(line), f) && nb < MAX_BEACON_APS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        /* fields: bssid ssid enc channel akm mfp vendor */
        char *save = NULL;
        char *bssid = strtok_r(line, "\t", &save);
        char *ssid  = strtok_r(NULL, "\t", &save);
        char *enc   = strtok_r(NULL, "\t", &save);
        char *chan  = strtok_r(NULL, "\t", &save);
        (void)strtok_r(NULL, "\t", &save);              /* akm — not diffed */
        char *mfp   = strtok_r(NULL, "\t", &save);
        if (!bssid || !ssid || !enc || !chan || !mfp) continue;
        /* Channel numbers top out at 233 (6 GHz); mfp is 0/1/2. A row
         * outside either is not one this writer produced. */
        int ch_v, mfp_v;
        if (!field_int(chan, 0, 255, &ch_v) || !field_int(mfp, 0, 2, &mfp_v))
            continue;
        base_ap_t *b = &base[nb++];
        snprintf(b->bssid, sizeof(b->bssid), "%s", bssid);
        field_unescape(ssid, b->ssid, sizeof(b->ssid));
        snprintf(b->enc,   sizeof(b->enc),   "%s", enc);
        b->channel = ch_v;
        b->mfp     = mfp_v;
    }
    fclose(f);

    int diffs = 0;
    fprintf(out, "site drift vs %s:\n", baseline_path);

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        char bss[20];
        bssid_str(a->bssid, bss, sizeof(bss));
        base_ap_t *m = NULL;
        for (int j = 0; j < nb; j++)
            if (strcmp(base[j].bssid, bss) == 0) { m = &base[j]; break; }
        /* The report goes to the operator's terminal: an SSID is shown
         * escaped, never as the raw octets heard. */
        char ssid[32 * 4 + 1];
        show_escaped(a->ssid, ssid, sizeof(ssid));
        if (!m) {
            fprintf(out, "  NEW      %s  %s  %s ch%d\n",
                    bss, ssid, a->enc, a->channel);
            diffs++;
            continue;
        }
        m->matched = 1;
        if (strcmp(m->enc, a->enc) != 0 || m->channel != a->channel ||
            m->mfp != a->mfp) {
            char enc[64];
            show_escaped(m->enc, enc, sizeof(enc));
            fprintf(out, "  CHANGED  %s  %s: %s ch%d mfp%d -> %s ch%d mfp%d\n",
                    bss, ssid,
                    enc, m->channel, m->mfp, a->enc, a->channel, a->mfp);
            diffs++;
        }
    }
    for (int j = 0; j < nb; j++) {
        if (base[j].matched) continue;
        /* Every field here came from the baseline file, not from sloth. */
        char bss[80], ssid[32 * 4 + 1], enc[64];
        show_escaped(base[j].bssid, bss,  sizeof(bss));
        show_escaped(base[j].ssid,  ssid, sizeof(ssid));
        show_escaped(base[j].enc,   enc,  sizeof(enc));
        fprintf(out, "  GONE     %s  %s  %s ch%d\n",
                bss, ssid, enc, base[j].channel);
        diffs++;
    }
    if (diffs == 0) fprintf(out, "  (no changes)\n");

    free(base);
    return diffs;
}
