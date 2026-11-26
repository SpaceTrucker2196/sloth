#include "wifi_snapshot.h"
#include "secure_file.h"
#include "sweep.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

/* No mutex, unlike jsonl's: the snapshot is written on the main thread
 * only (at shutdown, and since #190 by the live tick after poll_data()),
 * so nothing races the reason buffer. */
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

static void mac_str(const uint8_t *b, char *out, int sz) {
    bssid_str(b, out, sz);
}

/* The file body. `live` adds one header line (#190): the diff reader
 * skips every '#' line, so a live file still reads as a baseline, but a
 * person or a script looking at it can tell it is not the shutdown
 * snapshot.
 *
 * Format v2 (#249) adds the clients and the BLE advertisers a sweep
 * compares against, after the AP rows and in the same file, so one
 * file is still one site's baseline. Each such row starts with its kind
 * ("client", "ble") and has fewer than the six fields an AP row needs,
 * so a v1 reader - every sloth before #249, and wifi_snapshot_diff() -
 * skips it and reads the APs as it always did. The rotating addresses
 * are counts only (src/sweep.h) and are header lines, never rows. */
static void emit(FILE *f, const sw_inv_t *inv, const char *label,
                 long now, int live) {
    fprintf(f, "# sloth-snapshot v2\n");
    /* The label is the operator's, but a newline in it would still start
     * a row in the next run's baseline, so it takes the same escape. */
    char lab[256];
    field_escape(label, lab, sizeof(lab));
    fprintf(f, "# label\t%s\n", lab);
    fprintf(f, "# ts\t%ld\n", now);
    if (live) fprintf(f, "# session\trunning\n");
    fprintf(f, "# count\t%d\n", inv->per_kind[SW_K_AP]);
    fprintf(f, "# clients\t%d\n", inv->per_kind[SW_K_CLIENT]);
    fprintf(f, "# ble_devices\t%d\n", inv->per_kind[SW_K_BLE]);
    fprintf(f, "# client_random\t%d\n", sweep_set_count(&inv->client_random));
    fprintf(f, "# ble_private\t%d\n", sweep_set_count(&inv->ble_private));
    /* Since the #249 follow-up a randomised address the sweep resolved
     * (src/sweep.h) is a row, with its method and confidence; this line
     * says the file can hold such rows, so a reader comparing against
     * it knows an absent one is absent and not unrecorded. */
    sw_rand_t rc;
    sweep_rand_counts(inv, &rc);
    fprintf(f, "# resolved\t%d\n", rc.client_resolved + rc.ble_resolved);
    fprintf(f, "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n");
    for (int i = 0; i < inv->n; i++) {
        const sw_emitter_t *e = &inv->e[i];
        if (e->kind != SW_K_AP) continue;
        char bss[20];
        mac_str(e->addr, bss, sizeof(bss));
        wifi_snapshot_row(f, bss, e->ssid, e->enc, e->channel, e->akm,
                          e->mfp, e->vendor);
    }
    fprintf(f, "# client\tmac\tchannel\tvendor\tresolved\tconfidence\n");
    for (int i = 0; i < inv->n; i++) {
        const sw_emitter_t *e = &inv->e[i];
        if (e->kind != SW_K_CLIENT) continue;
        char mac[20], ve[32 * 4 + 1];
        mac_str(e->addr, mac, sizeof(mac));
        field_escape(e->vendor, ve, sizeof(ve));
        /* A resolved randomised address carries its method and
         * confidence; a v2 reader before them parses the first three
         * fields and skips the row (its address is locally
         * administered), so an older sloth reads the file as before. */
        if (e->res)
            fprintf(f, "client\t%s\t%d\t%s\t%s\t%d\n", mac,
                    e->channel > 0 && e->channel < 256 ? e->channel : 0, ve,
                    sweep_res_name(e->res), e->res_conf);
        else
            fprintf(f, "client\t%s\t%d\t%s\n", mac,
                    e->channel > 0 && e->channel < 256 ? e->channel : 0, ve);
    }
    fprintf(f, "# ble\taddr\ttype\tcategory\tname\tresolved\tconfidence\n");
    for (int i = 0; i < inv->n; i++) {
        const sw_emitter_t *e = &inv->e[i];
        if (e->kind != SW_K_BLE) continue;
        /* The name and the category are the advertiser's choice of
         * octets, as untrusted as an SSID. */
        char mac[20], cat[16 * 4 + 1], name[32 * 4 + 1];
        mac_str(e->addr, mac, sizeof(mac));
        field_escape(e->cat, cat, sizeof(cat));
        field_escape(e->name, name, sizeof(name));
        if (e->res)
            fprintf(f, "ble\t%s\t%s\t%s\t%s\t%s\t%d\n", mac,
                    sweep_ble_type_name(e->ble_type), cat, name,
                    sweep_res_name(e->res), e->res_conf);
        else
            fprintf(f, "ble\t%s\t%s\t%s\t%s\n", mac,
                    sweep_ble_type_name(e->ble_type), cat, name);
    }
}

/* The state's inventory as the file holds it. NULL on allocation
 * failure (the reason is the caller's to set). */
static sw_inv_t *state_inv(const sloth_state_t *s) {
    sw_inv_t *inv = sweep_inv_new();
    if (inv) sweep_inv_observe(inv, s);
    return inv;
}

void wifi_snapshot_escape(const char *in, char *out, size_t cap) {
    field_escape(in, out, cap);
}

void wifi_snapshot_row(FILE *f, const char *bssid, const char *ssid,
                       const char *enc, int channel, const char *akm,
                       int mfp, const char *vendor) {
    /* 32 octets at four bytes per \xHH, plus the NUL. */
    char bss[20], ss[32 * 4 + 1], en[16], ak[32], ve[32];
    safe_field(bssid,  bss, sizeof(bss));
    field_escape(ssid, ss, sizeof(ss));
    safe_field(enc,    en, sizeof(en));
    safe_field(akm,    ak, sizeof(ak));
    safe_field(vendor, ve, sizeof(ve));
    fprintf(f, "%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
            bss, ss, en, channel, ak, mfp, ve);
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
    sw_inv_t *inv = state_inv(s);
    if (!inv) {
        snprintf(g_fail.last, sizeof(g_fail.last), "%.200s: out of memory", path);
        return -1;
    }
    int rc = wifi_snapshot_write_inv(inv, path, label, now);
    sweep_inv_free(inv);
    return rc;
}

int wifi_snapshot_write_inv(const sw_inv_t *inv, const char *path,
                            const char *label, long now) {
    sfile_fail_reset(&g_fail);
    if (!inv || !path) return -1;
    FILE *f = sfile_fopen(AT_FDCWD, path, SFILE_TRUNC,
                          g_fail.last, sizeof(g_fail.last));
    if (!f) return -1;
    emit(f, inv, label, now, 0);
    /* sfile_fclose folds in ferror, the flush and the close, so a
     * failure anywhere in the fprintf run above surfaces here — which
     * is why the individual writes stay unchecked. Before this the
     * return was an unconditional 0, and a truncated file was announced
     * to the operator as written. */
    return sfile_fclose(f, path, g_fail.last, sizeof(g_fail.last)) == 0
           ? 0 : -1;
}

void wifi_snapshot_write_inv_f(FILE *f, const sw_inv_t *inv,
                               const char *label, long now) {
    if (f && inv) emit(f, inv, label, now, 0);
}

int wifi_snapshot_write_live(const sloth_state_t *s, const char *live,
                             const char *label, long now,
                             char *err, size_t errsz) {
    if (!s || !live || !err || errsz == 0) return -1;
    /* ".<name>.tmp" in the live file's own directory: rename(2) is only
     * atomic within one filesystem, and the leading dot keeps the
     * temporary out of a glob for the snapshot. */
    const char *slash = strrchr(live, '/');
    size_t base = slash ? (size_t)(slash - live) + 1 : 0;
    char tmp[1100];
    int n = snprintf(tmp, sizeof(tmp), "%.*s.%s.tmp",
                     (int)base, live, live + base);
    if (!live[base] || n < 0 || (size_t)n >= sizeof(tmp)) {
        snprintf(err, errsz, "%.200s: bad or over-long path", live);
        return -1;
    }
    /* A temporary of this name is ours, left by a crash mid-write: the
     * unlink removes the name without following it, and O_EXCL then
     * guarantees the file written is one this call created, 0600. */
    (void)unlink(tmp);
    sw_inv_t *inv = state_inv(s);
    if (!inv) {
        snprintf(err, errsz, "%.200s: out of memory", live);
        return -1;
    }
    FILE *f = sfile_fopen(AT_FDCWD, tmp, SFILE_EXCL, err, errsz);
    if (!f) { sweep_inv_free(inv); return -1; }
    emit(f, inv, label, now, 1);
    sweep_inv_free(inv);
    /* On disk before it is visible: a rename that survives a power cut
     * while the data does not is how a zero-length file appears. */
    int sync_bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    int sync_err = errno;
    if (sfile_fclose(f, live, err, errsz) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    if (sync_bad) {
        snprintf(err, errsz, "%.200s: write failed: %s", live,
                 strerror(sync_err));
        (void)unlink(tmp);
        return -1;
    }
    if (rename(tmp, live) != 0) {
        snprintf(err, errsz, "%.200s: rename failed: %s", live,
                 strerror(errno));
        (void)unlink(tmp);
        return -1;
    }
    return 0;
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
        /* A v2 file's client and BLE rows (#249) are not APs; they
         * already fall short of six fields, and are named here too so
         * a hand-edited one cannot read as an AP. */
        if (!strcmp(bssid, "client") || !strcmp(bssid, "ble")) continue;
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

/* "aa:bb:cc:dd:ee:ff", hex either case, nothing after. */
static int parse_mac(const char *s, uint8_t out[6]) {
    if (strlen(s) != 17) return 0;
    for (int i = 0; i < 6; i++) {
        int hi = hexnib(s[3 * i]), lo = hexnib(s[3 * i + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && s[3 * i + 2] != ':')) return 0;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return 1;
}

static int read_ap(sw_inv_t *inv, char *line) {
    char *save = NULL;
    char *bssid = strtok_r(line, "\t", &save);
    char *ssid  = strtok_r(NULL, "\t", &save);
    char *enc   = strtok_r(NULL, "\t", &save);
    char *chan  = strtok_r(NULL, "\t", &save);
    char *akm   = strtok_r(NULL, "\t", &save);
    char *mfp   = strtok_r(NULL, "\t", &save);
    char *ven   = strtok_r(NULL, "\t", &save);
    sw_emitter_t e;
    memset(&e, 0, sizeof(e));
    int ch_v, mfp_v;
    if (!bssid || !ssid || !enc || !chan || !akm || !mfp ||
        !parse_mac(bssid, e.addr) || !field_int(chan, 0, 255, &ch_v) ||
        !field_int(mfp, 0, 2, &mfp_v))
        return 0;
    e.kind = SW_K_AP;
    field_unescape(ssid, e.ssid, sizeof(e.ssid));
    if (!e.ssid[0]) e.flags |= SW_F_HIDDEN;
    if (strcmp(enc, "-")) snprintf(e.enc, sizeof(e.enc), "%s", enc);
    if (strcmp(akm, "-")) snprintf(e.akm, sizeof(e.akm), "%s", akm);
    if (ven && strcmp(ven, "-")) snprintf(e.vendor, sizeof(e.vendor), "%s", ven);
    e.channel = ch_v;
    e.mfp = mfp_v;
    return sweep_inv_add(inv, &e) == 0;
}

/* A resolved row's method and confidence (src/sweep.h). 1 with them
 * set, 0 when the fields are not a resolution this writer produces. */
static int read_res(char *how, char *conf, sw_emitter_t *e) {
    int c;
    if (!how || !conf || !field_int(conf, 1, 100, &c)) return 0;
    if (!strcmp(how, "assoc"))           e->res = SW_RES_ASSOC;
    else if (!strcmp(how, "persistent")) e->res = SW_RES_PERSIST;
    else return 0;
    e->res_conf = (uint8_t)c;
    return 1;
}

static int read_client(sw_inv_t *inv, char *rest) {
    char *save = NULL;
    char *mac = strtok_r(rest, "\t", &save);
    char *chan = strtok_r(NULL, "\t", &save);
    char *ven = strtok_r(NULL, "\t", &save);
    char *how = strtok_r(NULL, "\t", &save);
    char *conf = strtok_r(NULL, "\t", &save);
    sw_emitter_t e;
    memset(&e, 0, sizeof(e));
    int ch_v;
    if (!mac || !chan || !parse_mac(mac, e.addr) ||
        !field_int(chan, 0, 255, &ch_v))
        return 0;
    /* A group address is never a row. A locally administered one is a
     * row only as a resolved address, with its method (src/sweep.h), in
     * a hand-edited file as in a sweep; a universal one never carries a
     * method. */
    if (e.addr[0] & 0x01) return 0;
    if ((e.addr[0] & 0x02) ? !read_res(how, conf, &e) : how != NULL) return 0;
    e.kind = SW_K_CLIENT;
    e.channel = ch_v;
    if (ven) field_unescape(ven, e.vendor, sizeof(e.vendor));
    return sweep_inv_add(inv, &e) == 0;
}

static int read_ble(sw_inv_t *inv, char *rest) {
    char *save = NULL;
    char *mac  = strtok_r(rest, "\t", &save);
    char *type = strtok_r(NULL, "\t", &save);
    char *cat  = strtok_r(NULL, "\t", &save);
    char *name = strtok_r(NULL, "\t", &save);
    char *how  = strtok_r(NULL, "\t", &save);
    char *conf = strtok_r(NULL, "\t", &save);
    sw_emitter_t e;
    memset(&e, 0, sizeof(e));
    if (!mac || !type || !parse_mac(mac, e.addr)) return 0;
    if (!strcmp(type, "public"))       e.ble_type = SW_BLE_PUBLIC;
    else if (!strcmp(type, "static"))  e.ble_type = SW_BLE_STATIC;
    else if (!strcmp(type, "private")) e.ble_type = SW_BLE_PRIVATE;
    else return 0;
    /* Only a static address's top bits are 11; a private one (01 or 00)
     * is a row only as a resolved address with its method (src/sweep.h,
     * owner rulings 2026-11-25), and only "persistent" resolves one. */
    if (e.ble_type == SW_BLE_STATIC && (e.addr[0] & 0xC0) != 0xC0) return 0;
    if (e.ble_type == SW_BLE_PRIVATE &&
        ((e.addr[0] & 0xC0) == 0xC0 || (e.addr[0] & 0xC0) == 0x80 ||
         !read_res(how, conf, &e) || e.res != SW_RES_PERSIST))
        return 0;
    if (e.ble_type != SW_BLE_PRIVATE && how) return 0;
    e.kind = SW_K_BLE;
    e.channel = -1;
    if (cat)  field_unescape(cat, e.cat, sizeof(e.cat));
    if (name) field_unescape(name, e.name, sizeof(e.name));
    return sweep_inv_add(inv, &e) == 0;
}

int wifi_snapshot_read(const char *path, sw_inv_t *out, int *version) {
    if (!path || !out) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int rc = wifi_snapshot_read_f(f, out, version);
    fclose(f);
    return rc;
}

int wifi_snapshot_read_f(FILE *f, sw_inv_t *out, int *version) {
    if (!f || !out) return -1;
    sweep_inv_clear(out);
    int ver = 0;
    char line[1024];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        else if (!feof(f)) {
            /* A line longer than any this writer produces: skip it
             * whole rather than read its tail as a row. */
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {}
            first = 0;
            continue;
        }
        if (first) {
            first = 0;
            if (!strcmp(line, "# sloth-snapshot v1")) { ver = 1; continue; }
            if (!strcmp(line, "# sloth-snapshot v2")) { ver = 2; continue; }
        }
        if (line[0] == '#') {
            int v;
            if (!strncmp(line, "# ble_private\t", 14) &&
                field_int(line + 14, 0, 1L << 30, &v))
                out->file_ble_private = v;
            else if (!strncmp(line, "# client_random\t", 16) &&
                     field_int(line + 16, 0, 1L << 30, &v))
                out->file_client_random = v;
            else if (!strncmp(line, "# resolved\t", 11) &&
                     field_int(line + 11, 0, 1L << 30, &v))
                out->has_resolved = 1;
            continue;
        }
        if (!line[0]) continue;
        if (!strncmp(line, "client\t", 7))   (void)read_client(out, line + 7);
        else if (!strncmp(line, "ble\t", 4)) (void)read_ble(out, line + 4);
        else                                 (void)read_ap(out, line);
    }
    /* No magic line: a file the diff reader has always accepted (the
     * pre-#137 hand-made baselines), read as v1. */
    if (!ver) ver = 1;
    out->has_kind[SW_K_AP] = 1;
    out->has_kind[SW_K_CLIENT] = ver >= 2;
    out->has_kind[SW_K_BLE] = ver >= 2;
    if (version) *version = ver;
    return 0;
}
