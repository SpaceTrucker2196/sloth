#include "wifi_snapshot.h"
#include <string.h>
#include <stdlib.h>

/* One field-safe copy: replace tab/newline with space so the TSV round-trips. */
static void safe_field(const char *in, char *out, int sz) {
    int i = 0;
    for (; in && in[i] && i < sz - 1; i++)
        out[i] = (in[i] == '\t' || in[i] == '\n' || in[i] == '\r') ? ' ' : in[i];
    out[i] = '\0';
    if (i == 0) { out[0] = '-'; out[1] = '\0'; }   /* never empty */
}

static void bssid_str(const uint8_t *b, char *out, int sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

int wifi_snapshot_write(const sloth_state_t *s, const char *path,
                        const char *label, long now) {
    if (!s || !path) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "# sloth-snapshot v1\n");
    fprintf(f, "# label\t%s\n", (label && label[0]) ? label : "-");
    fprintf(f, "# ts\t%ld\n", now);
    fprintf(f, "# count\t%d\n", s->beacon_count);
    fprintf(f, "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n");

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        char bss[20], ssid[40], enc[16], akm[32], vendor[32];
        bssid_str(a->bssid, bss, sizeof(bss));
        safe_field(a->ssid,   ssid,   sizeof(ssid));
        safe_field(a->enc,    enc,    sizeof(enc));
        safe_field(a->akm,    akm,    sizeof(akm));
        safe_field(a->vendor, vendor, sizeof(vendor));
        fprintf(f, "%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
                bss, ssid, enc, a->channel, akm, a->mfp, vendor);
    }
    fclose(f);
    return 0;
}

/* Parsed baseline AP — only the fields we diff on. */
typedef struct {
    char bssid[20];
    char ssid[40];
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
        base_ap_t *b = &base[nb++];
        snprintf(b->bssid, sizeof(b->bssid), "%s", bssid);
        snprintf(b->ssid,  sizeof(b->ssid),  "%s", ssid);
        snprintf(b->enc,   sizeof(b->enc),   "%s", enc);
        b->channel = atoi(chan);
        b->mfp     = atoi(mfp);
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
        if (!m) {
            fprintf(out, "  NEW      %s  %s  %s ch%d\n",
                    bss, a->ssid[0] ? a->ssid : "-", a->enc, a->channel);
            diffs++;
            continue;
        }
        m->matched = 1;
        if (strcmp(m->enc, a->enc) != 0 || m->channel != a->channel ||
            m->mfp != a->mfp) {
            fprintf(out, "  CHANGED  %s  %s: %s ch%d mfp%d -> %s ch%d mfp%d\n",
                    bss, a->ssid[0] ? a->ssid : "-",
                    m->enc, m->channel, m->mfp, a->enc, a->channel, a->mfp);
            diffs++;
        }
    }
    for (int j = 0; j < nb; j++) {
        if (base[j].matched) continue;
        fprintf(out, "  GONE     %s  %s  %s ch%d\n",
                base[j].bssid, base[j].ssid, base[j].enc, base[j].channel);
        diffs++;
    }
    if (diffs == 0) fprintf(out, "  (no changes)\n");

    free(base);
    return diffs;
}
