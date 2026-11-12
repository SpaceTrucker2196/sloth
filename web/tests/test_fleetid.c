/* Identity across the sites (#192 I2, I3, I4, I8; web_fleetid.h): the
 * reach model, then web_fid_run() on hand-built two-site data at near
 * (16.8 m, the owner's two sensors) and far (55 km) spacing, one case
 * per finding and per reason a check does not apply; then the export's
 * ident=1 over a generated sloth.db and the ledger, the importer's
 * bounds on every new member, the own networks replaced by the next
 * answer, and the route over a store holding a peer's answer: a peer's
 * verdict shown and never written into this site's triage, nothing not
 * finite in the body. The I7 peer's fallback is test_fleet.c's, beside
 * the other kinds'. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rf_model.h"
#include "web_assets.h"
#include "web_chain.h"
#include "web_config.h"
#include "web_fleet.h"
#include "web_fleetid.h"
#include "web_frrs.h"
#include "web_gnss.h"
#include "web_jsonl.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "wtest.h"
#include "wt_tmp.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#include "sdb_gen.h"
#endif

#define T 1792627000LL
#define SELF_LAT 33.32922
#define SELF_LON (-111.87006)
#define NEAR_LAT 33.32910               /* 16.8 m from SELF */
#define NEAR_LON (-111.86995)
#define FAR_LAT  33.82922               /* 55.6 km north */

/* ── the model ─────────────────────────────────────────────────────── */

/* The reach of a site whose weakest AP is -100 dBm: P.1238 at 2.4 GHz,
 * N 2.8, an AP at 20 dBm heard at -120 (the floor less the 20 dB
 * margin). Every value finite and positive, whatever the input. */
static void test_reach(void) {
    double ref = 20 * log10(2437.0) - 28;
    double want = pow(10, (20 + 120 - ref) / 28.0);
    WT_ASSERT(fabs(web_fid_reach_m(-100) - want) < 0.5);
    WT_ASSERT(web_fid_reach_m(-100) > 3000 && web_fid_reach_m(-100) < 5000);
    double up = pow(10, (20 + 60 - ref) / 28.0);
    WT_ASSERT(fabs(web_fid_upper_m(-40) - up) < 0.05);
    static const int odd[] = { 0, 5, -1, -200, 1000, -32768 };
    for (size_t i = 0; i < sizeof(odd) / sizeof(odd[0]); i++) {
        WT_ASSERT(isfinite(web_fid_reach_m(odd[i])) && web_fid_reach_m(odd[i]) > 0);
        WT_ASSERT(isfinite(web_fid_upper_m(odd[i])) && web_fid_upper_m(odd[i]) > 0);
    }
    web_fid_site_t s;
    memset(&s, 0, sizeof(s));
    WT_EQ(web_fid_floor(&s), WEB_FID_FLOOR_DEF);
    web_fid_ap_t ap[3];
    memset(ap, 0, sizeof(ap));
    ap[0].has_rssi = 1; ap[0].rssi = -70;
    ap[1].has_rssi = 1; ap[1].rssi = -88;
    ap[2].has_rssi = 0; ap[2].rssi = -120;
    s.ap = ap;
    s.nap = 3;
    WT_EQ(web_fid_floor(&s), -88);
    ap[1].rssi = -130;
    WT_EQ(web_fid_floor(&s), WEB_FID_FLOOR_MIN);
    ap[0].rssi = -10; ap[1].rssi = -20;
    WT_EQ(web_fid_floor(&s), WEB_FID_FLOOR_MAX);
}

/* --my-ssid and --my-bssid: up to 16 of each, as sloth; an SSID of 1
 * to 32 octets with no control character (DEL included), a BSSID six
 * hex octets kept canonical; anything else, or a seventeenth, refused. */
static int my_parse(web_config_t *c, const char *const *args, char *err, size_t errsz) {
    char *argv[48];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args[i] && argc < 47; i++) argv[argc++] = (char *)args[i];
    argv[argc] = NULL;
    char *out = NULL, *eb = NULL;
    size_t ol = 0, el = 0;
    FILE *o = open_memstream(&out, &ol), *e = open_memstream(&eb, &el);
    int rc = web_config_parse(c, argc, argv, o, e);
    fclose(o);
    fclose(e);
    snprintf(err, errsz, "%s", eb ? eb : "");
    free(out);
    free(eb);
    return rc;
}

static void test_my_flags(void) {
    web_config_t *c = malloc(sizeof(*c));
    WT_ASSERT(c != NULL);
    if (!c) return;
    char err[256];
    static const char *const ok[] = { "--my-ssid", "Cafe Net \xc3\xa9", "--my-bssid",
                                      "AA:BB:CC:DD:EE:0F", NULL };
    WT_EQ(my_parse(c, ok, err, sizeof(err)), 0);
    WT_EQ(c->mine.nssid, 1);
    WT_EQ(c->mine.nbssid, 1);
    WT_ASSERT(!strcmp(c->mine.ssid[0], "Cafe Net \xc3\xa9"));
    WT_ASSERT(!strcmp(c->mine.bssid[0], "aa:bb:cc:dd:ee:0f"));
    static const char *const bad[][3] = {
        { "--my-ssid", "", NULL },
        { "--my-ssid", "123456789012345678901234567890123", NULL },
        { "--my-ssid", "a\tb", NULL },
        { "--my-ssid", "a\x7f", NULL },
        { "--my-bssid", "aa:bb:cc:dd:ee", NULL },
        { "--my-bssid", "aa:bb:cc:dd:ee:fg", NULL },
        { "--my-bssid", NULL, NULL },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        WT_EQ(my_parse(c, bad[i], err, sizeof(err)), -1);
    WT_EQ(my_parse(c, (const char *const[]){ "--my-ssid",
                   "123456789012345678901234567890AB", NULL }, err, sizeof(err)), 0);
    const char *many[40];
    char names[17][8];
    int k = 0;
    for (int i = 0; i < 17; i++) {
        snprintf(names[i], sizeof(names[i]), "n%d", i);
        many[k++] = "--my-ssid";
        many[k++] = names[i];
    }
    many[k] = NULL;
    many[32] = NULL;                     /* sixteen */
    WT_EQ(my_parse(c, many, err, sizeof(err)), 0);
    WT_EQ(c->mine.nssid, 16);
    many[32] = "--my-ssid";              /* seventeen */
    WT_EQ(my_parse(c, many, err, sizeof(err)), -1);
    WT_ASSERT(strstr(err, "at most 16") != NULL);
    free(c);
}

static void test_words(void) {
    WT_EQ(web_fid_class_find("I2", 2), WEB_FID_I2);
    WT_EQ(web_fid_class_find("I8", 2), WEB_FID_I8);
    WT_EQ(web_fid_class_find("I5", 2), -1);
    WT_EQ(web_fid_class_find("I", 1), -1);
    unsigned t;
    WT_EQ(web_fid_atk_parse("EVIL_TWIN,KARMA_AP", &t), 0);
    WT_EQ(t, 3u);
    WT_EQ(web_fid_atk_parse("KARMA_AP", &t), 0);
    WT_EQ(t, 2u);
    WT_EQ(web_fid_atk_parse("KARMA_AP,KARMA_AP", &t), -1);
    WT_EQ(web_fid_atk_parse("DEAUTH_FLOOD", &t), -1);
    WT_EQ(web_fid_atk_parse("", &t), -1);
    WT_EQ(web_fid_atk_parse("KARMA_AP,", &t), -1);
    /* An unattributed half is a third word; one half is attributed or
     * it is not, never both. */
    WT_EQ(web_fid_atk_parse("KARMA_AP,TWIN_UNATTRIBUTED", &t), 0);
    WT_EQ(t, WEB_FID_ATK_KARMA | WEB_FID_ATK_UNATTR);
    WT_EQ(web_fid_atk_parse("EVIL_TWIN,TWIN_UNATTRIBUTED", &t), -1);
    char w[64];
    web_fid_atk_words(3, w, sizeof(w));
    WT_ASSERT(!strcmp(w, "EVIL_TWIN,KARMA_AP"));
    web_fid_atk_words(0, w, sizeof(w));
    WT_ASSERT(!strcmp(w, ""));
}

/* ── two hand-built sites ──────────────────────────────────────────── */

#define NAP 8
static web_fid_site_t S2[2];
static web_fid_ap_t   AP2[2][NAP];
static web_fid_probe_t PR2[2][NAP];
static web_fid_ver_t  VR2[2][NAP];
static web_fid_t      OUT[64];

/* self and beta, beta near or far; each hears one ordinary AP at -60,
 * so each site's floor is -60 and its reach 142 m. */
static void two(int far) {
    memset(S2, 0, sizeof(S2));
    memset(AP2, 0, sizeof(AP2));
    memset(PR2, 0, sizeof(PR2));
    memset(VR2, 0, sizeof(VR2));
    for (int i = 0; i < 2; i++) {
        snprintf(S2[i].name, sizeof(S2[i].name), "%s", i ? "beta" : "self");
        S2[i].self = i == 0;
        S2[i].offered = 1;
        S2[i].has_pos = 1;
        S2[i].ap = AP2[i];
        S2[i].probe = PR2[i];
        S2[i].ver = VR2[i];
        snprintf(AP2[i][0].bssid, 18, "%s", i ? "0a:00:00:00:00:b0" : "0a:00:00:00:00:a0");
        snprintf(AP2[i][0].ssid, 33, "%s", "Neighbour");
        AP2[i][0].has_rssi = 1;
        AP2[i][0].rssi = -60;
        AP2[i][0].first = T - 900;
        AP2[i][0].last = T - 10;
        S2[i].nap = 1;
    }
    S2[0].lat = SELF_LAT;
    S2[0].lon = SELF_LON;
    S2[1].lat = far ? FAR_LAT : NEAR_LAT;
    S2[1].lon = far ? SELF_LON : NEAR_LON;
}

/* An AP into site i, kept sorted by BSSID. */
static web_fid_ap_t *ap_in(int i, const char *bssid, const char *ssid, int rssi) {
    web_fid_site_t *s = &S2[i];
    web_fid_ap_t *a = &AP2[i][s->nap++];
    memset(a, 0, sizeof(*a));
    snprintf(a->bssid, sizeof(a->bssid), "%s", bssid);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    a->has_rssi = rssi < 0;
    a->rssi = rssi;
    a->first = T - 600;
    a->last = T - 5;
    for (int k = s->nap - 1; k > 0 && strcmp(AP2[i][k].bssid, AP2[i][k - 1].bssid) < 0; k--) {
        web_fid_ap_t t = AP2[i][k];
        AP2[i][k] = AP2[i][k - 1];
        AP2[i][k - 1] = t;
        a = &AP2[i][k - 1];
    }
    return a;
}

static void ver_in(int i, const char *addr, int state, long long ts) {
    web_fid_site_t *s = &S2[i];
    web_fid_ver_t *v = &VR2[i][s->nver++];
    snprintf(v->addr, sizeof(v->addr), "%s", addr);
    snprintf(v->type, sizeof(v->type), "KARMA_AP");
    v->state = state;
    v->ts = ts;
    for (int k = s->nver - 1; k > 0 && strcmp(VR2[i][k].addr, VR2[i][k - 1].addr) < 0; k--) {
        web_fid_ver_t t = VR2[i][k];
        VR2[i][k] = VR2[i][k - 1];
        VR2[i][k - 1] = t;
    }
}

static int run(void) {
    memset(OUT, 0, sizeof(OUT));
    return web_fid_run(S2, 2, OUT, 64);
}

static int count_sub(int n, int sub) {
    int c = 0;
    for (int i = 0; i < n && i < 64; i++) c += OUT[i].sub == sub;
    return c;
}

static const web_fid_t *find_sub(int n, int sub) {
    for (int i = 0; i < n && i < 64; i++)
        if (OUT[i].sub == sub) return &OUT[i];
    return NULL;
}

/* I2: a client at self probing for beta's own SSID. Always a lead;
 * applicable 55 km apart and with no position, not applicable
 * (co_located) at 16.8 m, where the client may live at both (seen red
 * with run_i2()'s `f->applicable = 0` dropped). An SSID that
 * is self's own too is self's own question, not a finding. A client
 * either site triaged known is exonerated, the other states not. The
 * exoneration was seen red with run_i2()'s `f->exonerated =
 * known_anywhere()` line removed. */
static void test_i2(void) {
    for (int far = 0; far < 2; far++) {
        two(far);
        snprintf(S2[1].mine.ssid[0], 33, "BetaNet");
        S2[1].mine.nssid = 1;
        web_fid_probe_t *p = &PR2[0][S2[0].nprobe++];
        snprintf(p->mac, sizeof(p->mac), "00:11:22:33:44:55");
        snprintf(p->ssid, sizeof(p->ssid), "BetaNet");
        p->first = T - 3000;
        p->last = T - 100;
        int n = run();
        WT_EQ(n, 1);
        const web_fid_t *f = find_sub(n, WEB_FID_PROBE_OTHER);
        WT_ASSERT(f != NULL);
        if (!f) continue;
        WT_EQ(f->cls, WEB_FID_I2);
        WT_ASSERT(!strcmp(f->key, "00:11:22:33:44:55"));
        WT_ASSERT(!strcmp(f->ssid, "BetaNet"));
        WT_EQ(f->applicable, far);
        WT_EQ(f->lead, 1);
        WT_ASSERT(far ? f->reason == NULL : f->reason && !strcmp(f->reason, "co_located"));
        WT_EQ(f->exonerated, 0);
        WT_EQ(f->nleg, 2);
        WT_EQ(f->leg[0].site, 0);
        WT_ASSERT(!strcmp(f->leg[0].role, "prober"));
        WT_EQ(f->leg[1].site, 1);
        WT_ASSERT(!strcmp(f->leg[1].role, "owner"));
        WT_EQ(f->first, T - 3000);
        WT_EQ(f->has_dist, 1);
        WT_ASSERT(f->note && strstr(f->note, far ? "a lead" : "live at or near both"));
        /* No position at either: still a lead, applicable, no distance. */
        S2[1].has_pos = 0;
        n = run();
        f = find_sub(n, WEB_FID_PROBE_OTHER);
        WT_ASSERT(f && f->applicable && f->lead && !f->has_dist && f->reason == NULL);
        S2[1].has_pos = 1;
        /* Triaged incident at beta: shown, not exonerated. */
        ver_in(1, "00:11:22:33:44:55", WEB_TRI_INCIDENT, T - 50);
        n = run();
        f = find_sub(n, WEB_FID_PROBE_OTHER);
        WT_ASSERT(f && !f->exonerated && f->leg[1].state == WEB_TRI_INCIDENT);
        /* Known at beta: exonerated, ranked after the open ones. */
        VR2[1][0].state = WEB_TRI_KNOWN;
        n = run();
        f = find_sub(n, WEB_FID_PROBE_OTHER);
        WT_ASSERT(f && f->exonerated);
        /* Self's own SSID too: nothing. */
        S2[1].nver = 0;
        snprintf(S2[0].mine.ssid[0], 33, "BetaNet");
        S2[0].mine.nssid = 1;
        WT_EQ(run(), 0);
    }
}

/* I3 (i): beta hears self's own BSSID. At 16.8 m that is expected (not
 * applicable, co_located); 55 km away it cannot be self's AP; with no
 * position at either site, no_position. The bound is self's AP's upper
 * distance from self's sensor (heard at -40) plus beta's reach. */
static void test_i3_own_bssid(void) {
    for (int far = 0; far < 2; far++) {
        two(far);
        snprintf(S2[0].mine.bssid[0], 18, "28:25:5f:19:0e:1c");
        S2[0].mine.nbssid = 1;
        ap_in(0, "28:25:5f:19:0e:1c", "HomeNet", -40);
        ap_in(1, "28:25:5f:19:0e:1c", "HomeNet", -75);
        int n = run();
        const web_fid_t *f = find_sub(n, WEB_FID_OWN_BSSID);
        WT_ASSERT(f != NULL);
        if (!f) continue;
        WT_EQ(f->cls, WEB_FID_I3);
        WT_ASSERT(!strcmp(f->key, "28:25:5f:19:0e:1c"));
        WT_ASSERT(fabs(f->bound_m - (web_fid_upper_m(-40) + web_fid_reach_m(-75))) < 1e-6);
        WT_EQ(f->applicable, far);
        if (!far) WT_ASSERT(f->reason && !strcmp(f->reason, "co_located"));
        WT_EQ(count_sub(n, WEB_FID_TWO_PLACES), 0);   /* an own BSSID is (i)'s */
        S2[1].has_pos = 0;
        n = run();
        f = find_sub(n, WEB_FID_OWN_BSSID);
        WT_ASSERT(f && !f->applicable && !strcmp(f->reason, "no_position"));
    }
}

/* I3 (ii): self's own SSID from a BSSID self does not name. Far: a
 * lure; near: not applicable. Self naming no BSSID: no_own_bssid.
 * beta's own BSSID of the same name: beta's own network, nothing. A
 * BSSID self hears carrying its own SSID at home (an unlisted VAP) is
 * reported as self's own heard elsewhere, with the note. */
static void test_i3_foreign(void) {
    for (int far = 0; far < 2; far++) {
        two(far);
        snprintf(S2[0].mine.ssid[0], 33, "HomeNet");
        S2[0].mine.nssid = 1;
        snprintf(S2[0].mine.bssid[0], 18, "28:25:5f:19:0e:1c");
        S2[0].mine.nbssid = 1;
        ap_in(0, "28:25:5f:19:0e:1c", "HomeNet", -40);
        ap_in(1, "0e:66:66:66:66:01", "HomeNet", -62);
        int n = run();
        const web_fid_t *f = find_sub(n, WEB_FID_FOREIGN_BSSID);
        WT_ASSERT(f != NULL);
        if (!f) continue;
        WT_ASSERT(!strcmp(f->key, "0e:66:66:66:66:01"));
        WT_ASSERT(!strcmp(f->ssid, "HomeNet"));
        WT_EQ(f->applicable, far);
        WT_ASSERT(fabs(f->bound_m - (web_fid_upper_m(-40) + web_fid_reach_m(-62))) < 1e-6);
        /* Self hears it at home with its SSID: an unlisted own AP. */
        ap_in(0, "0e:66:66:66:66:01", "HomeNet", -50);
        n = run();
        WT_EQ(count_sub(n, WEB_FID_FOREIGN_BSSID), 0);
        f = find_sub(n, WEB_FID_OWN_BSSID);
        WT_ASSERT(f && f->note && strstr(f->note, "--my-bssid"));
        WT_EQ(f ? f->applicable : -1, far);
    }
    two(1);
    snprintf(S2[0].mine.ssid[0], 33, "HomeNet");
    S2[0].mine.nssid = 1;
    ap_in(1, "0e:66:66:66:66:01", "HomeNet", -62);
    int n = run();
    const web_fid_t *f = find_sub(n, WEB_FID_FOREIGN_BSSID);
    WT_ASSERT(f && !f->applicable && !strcmp(f->reason, "no_own_bssid"));
    /* beta names that BSSID as its own: beta's network of the same name. */
    snprintf(S2[1].mine.bssid[0], 18, "0e:66:66:66:66:01");
    S2[1].mine.nbssid = 1;
    WT_EQ(count_sub(run(), WEB_FID_FOREIGN_BSSID), 0);
}

/* I3: one BSSID at both sites within 600 s, the sites beyond both
 * reaches: a clone. Never listed at 16.8 m, where it is the norm (seen
 * red with run_two_places()'s `if (d <= bound) continue;` removed: the
 * near pair then gave one), nor when the two hearings are 601 s apart. */
static void test_i3_two_places(void) {
    two(1);
    ap_in(0, "0e:77:77:77:77:01", "CafeFree", -70);
    web_fid_ap_t *b = ap_in(1, "0e:77:77:77:77:01", "CafeFree", -72);
    b->last = T - 5 - WEB_FID_SIMUL_S;
    int n = run();
    const web_fid_t *f = find_sub(n, WEB_FID_TWO_PLACES);
    WT_ASSERT(f && f->applicable && f->has_dist && f->dist_m > f->bound_m);
    WT_ASSERT(f && f->dist_m > 55000 && f->dist_m < 56000);
    b->last = T - 6 - WEB_FID_SIMUL_S;
    WT_EQ(count_sub(run(), WEB_FID_TWO_PLACES), 0);
    two(0);
    ap_in(0, "0e:77:77:77:77:01", "CafeFree", -70);
    ap_in(1, "0e:77:77:77:77:01", "CafeFree", -72);
    WT_EQ(count_sub(run(), WEB_FID_TWO_PLACES), 0);
}

/* I4: one fingerprint on an attack-associated AP at both sites, legs in
 * the order of each site's first attack. Without an attack alert at one
 * site, nothing (seen red with run_i4()'s `!a->atk` dropped: the common
 * fingerprint then gave a finding); near, not applicable; an own BSSID
 * or one triaged false at either site, left out; a fingerprint with a
 * different vendor-IE hash, a different tool. */
static void test_i4(void) {
    for (int far = 0; far < 2; far++) {
        two(far);
        web_fid_ap_t *a = ap_in(0, "0e:00:00:00:00:09", "FreeWiFi", -58);
        web_fid_ap_t *b = ap_in(1, "0e:00:00:00:00:01", "Starbucks", -66);
        snprintf(a->ie, sizeof(a->ie), "123456789");
        snprintf(a->vie, sizeof(a->vie), "987");
        snprintf(b->ie, sizeof(b->ie), "123456789");
        snprintf(b->vie, sizeof(b->vie), "987");
        a->atk = 2; a->atk_first = T - 500; a->atk_last = T - 400;
        b->atk = 3; b->atk_first = T - 9000; b->atk_last = T - 8000;
        int n = run();
        const web_fid_t *f = find_sub(n, WEB_FID_TOOL);
        WT_ASSERT(f != NULL);
        if (!f) continue;
        WT_ASSERT(!strcmp(f->key, "123456789/987"));
        WT_EQ(f->nleg, 2);
        WT_EQ(f->leg[0].site, 1);            /* beta first */
        WT_EQ(f->leg[0].first, T - 9000);
        WT_EQ(f->leg[1].site, 0);
        WT_EQ(f->first, T - 9000);
        WT_EQ(f->last, T - 400);
        WT_EQ(f->applicable, far);
        if (!far) WT_ASSERT(!strcmp(f->reason, "co_located"));
        WT_EQ(f->lead, 1);
        /* The same fingerprint with no attack alert at self. */
        a->atk = 0;
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
        /* Only a half of an unattributed twin pair at self: either half
         * may be the real AP, so it counts for nothing (seen red with
         * run_i4()'s WEB_FID_ATK_ATTACKER mask widened to every bit). */
        a->atk = WEB_FID_ATK_UNATTR;
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
        a->atk = 2;
        /* Self's own BSSID. */
        snprintf(S2[0].mine.bssid[0], 18, "0e:00:00:00:00:09");
        S2[0].mine.nbssid = 1;
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
        S2[0].mine.nbssid = 0;
        /* Triaged false at beta. */
        ver_in(1, "0e:00:00:00:00:09", WEB_TRI_FALSE, T - 30);
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
        S2[1].nver = 0;
        snprintf(b->vie, sizeof(b->vie), "988");
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
        /* No IE-order hash: no fingerprint. */
        snprintf(b->vie, sizeof(b->vie), "987");
        a->ie[0] = '\0';
        WT_EQ(count_sub(run(), WEB_FID_TOOL), 0);
    }
}

/* I8: known at self and incident at beta is a conflict, with both legs
 * and the newest verdict's type; the same state at both is not. */
static void test_i8(void) {
    two(0);
    ver_in(0, "0e:00:00:00:00:09", WEB_TRI_KNOWN, T - 300);
    ver_in(1, "0e:00:00:00:00:09", WEB_TRI_INCIDENT, T - 200);
    int n = run();
    const web_fid_t *f = find_sub(n, WEB_FID_CONFLICT);
    WT_ASSERT(f && f->cls == WEB_FID_I8 && f->applicable && f->nleg == 2);
    WT_ASSERT(f && !strcmp(f->vtype, "KARMA_AP"));
    WT_EQ(f ? f->last : 0, T - 200);
    VR2[1][0].state = WEB_TRI_KNOWN;
    WT_EQ(count_sub(run(), WEB_FID_CONFLICT), 0);
    VR2[1][0].state = WEB_TRI_FALSE;
    WT_EQ(count_sub(run(), WEB_FID_CONFLICT), 0);
}

/* More findings than room: the count says so, nothing overruns. */
static void test_room(void) {
    two(1);
    snprintf(S2[1].mine.ssid[0], 33, "BetaNet");
    S2[1].mine.nssid = 1;
    for (int i = 0; i < NAP; i++) {
        snprintf(PR2[0][i].mac, 18, "00:11:22:33:44:%02x", i);
        snprintf(PR2[0][i].ssid, 33, "BetaNet");
        PR2[0][i].first = PR2[0][i].last = T - i;
    }
    S2[0].nprobe = NAP;
    web_fid_t small[3];
    WT_EQ(web_fid_run(S2, 2, small, 3), NAP);
    WT_EQ(web_fid_run(S2, 2, small, 0), 0);
    WT_EQ(web_fid_run(NULL, 0, small, 3), 0);
}

#ifdef WITH_SQLITE

/* ── the export, the import and the route ──────────────────────────── */

static char g_dir[TEST_TMP_MAX];
static char g_peer_db[TEST_TMP_MAX + 32], g_peer_web[TEST_TMP_MAX + 32];
static char g_here_db[TEST_TMP_MAX + 32], g_here_web[TEST_TMP_MAX + 32];
static web_slothdb_t PSDB, HSDB;
static web_store_t   PS, HS;
static web_frrs_t    PFR, HFR;
static web_gnss_t    PG, HG;
static web_fleet_t   F;

static void rm_dir(void) {
    static const char *const names[] = { "peer.db", "peer-web.db", "here.db", "here-web.db" };
    static const char *const sfx[] = { "", "-wal", "-shm", "-journal" };
    char p[TEST_TMP_MAX + 48];
    for (size_t i = 0; i < 4; i++)
        for (size_t k = 0; k < 4; k++) {
            snprintf(p, sizeof(p), "%s/%s%s", g_dir, names[i], sfx[k]);
            unlink(p);
        }
    rmdir(g_dir);
}

static long long q1(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        else
            fprintf(stderr, "    q1: %s\n", sqlite3_errmsg(h));
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

static int sql_on(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = sqlite3_open(path, &h);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", sqlite3_errmsg(h));
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static void feed(web_frrs_t *f, const char *line) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_frrs_record(f, &r);
}

static void site_at(web_gnss_t *g, double lat, double lon) {
    WT_EQ(web_gnss_init(g), 0);
    g->loc.has = 1;
    g->loc.lat = lat;
    g->loc.lon = lon;
    g->loc.ts = T;
    snprintf(g->loc.src, sizeof(g->loc.src), "fixed");
}

/* One beacon_aps row, as sloth writes it. */
static void ap_row(const char *db, const char *bssid, const char *ssid, int sig,
                   long long first, long long last) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,first_seen,last_seen)"
             " VALUES ('%s','%s',%d,6,'WPA2',%lld,%lld);", bssid, ssid, sig, first, last);
    WT_EQ(sdb_exec(db, sql), 0);
}

static void alert_row(const char *db, const char *key, int type, long long first,
                      long long last) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
             "count) VALUES ('%s',%lld,%lld,%d,1,'t','d','T1557',3);", key, first, last, type);
    WT_EQ(sdb_exec(db, sql), 0);
}

static void triage_row(const char *web, const char *addr, int type, int state, long long ts) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts) VALUES"
             " ('x%d:%s',NULL,%d,'%s',0,%lld,%d,%lld);", type, addr, type, addr, ts - 100,
             state, ts);
    WT_EQ(sql_on(web, sql), 0);
}

/* The peer (beta, 55 km north): a PineAP-like AP 0e:..:01 named by a
 * KARMA_AP key and in the ledger with its fingerprint; its own network
 * BetaNet; a karma: key older than the window and a deauth key naming
 * the BSSID at a field the reader never matches, neither counted; a
 * triage verdict of known on a MAC this site triaged incident. Here
 * (self): the same fingerprint on 0e:..:09 with its own KARMA_AP key; a
 * client probing for BetaNet and a randomised one. */
static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-fleetid-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_peer_db, sizeof(g_peer_db), "%s/peer.db", g_dir);
    snprintf(g_peer_web, sizeof(g_peer_web), "%s/peer-web.db", g_dir);
    snprintf(g_here_db, sizeof(g_here_db), "%s/here.db", g_dir);
    snprintf(g_here_web, sizeof(g_here_web), "%s/here-web.db", g_dir);
    WT_EQ(sdb_make(g_peer_db, db_schema_version(), 0), 0);
    WT_EQ(sdb_make(g_here_db, db_schema_version(), 0), 0);
    ap_row(g_peer_db, "0e:00:00:00:00:01", "Starbucks", -66, T - 9500, T - 20);
    ap_row(g_peer_db, "0e:00:00:00:00:02", "Quiet", -91, T - 9500, T - 20);
    ap_row(g_peer_db, "0b:00:00:00:00:b1", "BetaNet", -45, T - 99999, T - 5);
    alert_row(g_peer_db, "karma:0e:00:00:00:00:01", 20, T - 9000, T - 8000);
    alert_row(g_peer_db, "karma:0e:00:00:00:00:02", 20, T - 40 * 86400, T - 35 * 86400);
    alert_row(g_peer_db, "deauth:0e:00:00:00:00:02@ff:ff:ff:ff:ff:ff", 1, T - 100, T - 50);
    ap_row(g_here_db, "0e:00:00:00:00:09", "FreeWiFi", -58, T - 900, T - 10);
    alert_row(g_here_db, "karma:0e:00:00:00:00:09", 20, T - 500, T - 400);
    WT_EQ(sdb_exec(g_here_db,
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('00:11:22:33:44:55','BetaNet',1792620000,1792626000),"
        " ('06:11:22:33:44:56','BetaNet',1792620000,1792626000),"
        " ('00:11:22:33:44:57','Elsewhere',1792620000,1792626000);"), 0);
    web_slothdb_init(&PSDB, g_peer_db, NULL);
    web_slothdb_init(&HSDB, g_here_db, NULL);
    char err[512];
    WT_EQ(web_store_open(&PS, g_peer_web, err, sizeof(err)), 0);
    WT_EQ(web_store_open(&HS, g_here_web, err, sizeof(err)), 0);
    triage_row(g_peer_web, "00:11:22:33:44:55", 20, WEB_TRI_KNOWN, T - 300);
    triage_row(g_here_web, "00:11:22:33:44:55", 20, WEB_TRI_INCIDENT, T - 200);
    WT_EQ(web_frrs_init(&PFR, &PS, NULL, 1, err, sizeof(err)), 0);
    WT_EQ(web_frrs_init(&HFR, &HS, NULL, 1, err, sizeof(err)), 0);
    feed(&PFR, "{\"type\":\"beacon\",\"ts\":1792626990,\"bssid\":\"0e:00:00:00:00:01\","
               "\"ssid\":\"Starbucks\",\"ie_order_hash\":123456789,\"vendor_ies_hash\":987,"
               "\"wps_manufacturer\":\"Hak5\",\"wps_model_name\":\"Pineapple\","
               "\"wps_model_number\":\"MK7\"}");
    feed(&PFR, "{\"type\":\"beacon\",\"ts\":1792626990,\"bssid\":\"0e:00:00:00:00:02\","
               "\"ssid\":\"Quiet\",\"ie_order_hash\":0,\"vendor_ies_hash\":5,"
               "\"wps_manufacturer\":\"bad\\u0001x\"}");
    feed(&HFR, "{\"type\":\"beacon\",\"ts\":1792626990,\"bssid\":\"0e:00:00:00:00:09\","
               "\"ssid\":\"FreeWiFi\",\"ie_order_hash\":123456789,\"vendor_ies_hash\":987}");
    site_at(&PG, FAR_LAT, SELF_LON);
    site_at(&HG, SELF_LAT, SELF_LON);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://100.64.0.2:8770", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 0, &HS);
    WT_EQ(web_store_open_aux(&HS, &F.wr, err, sizeof(err)), 0);
}

static void down(void) {
    web_fleet_destroy(&F);
    web_frrs_destroy(&PFR);
    web_frrs_destroy(&HFR);
    web_slothdb_destroy(&PSDB);
    web_slothdb_destroy(&HSDB);
    web_store_close(&PS);
    web_store_close(&HS);
    web_gnss_destroy(&PG);
    web_gnss_destroy(&HG);
    rm_dir();
}

static web_fleet_mine_t PEER_MINE;

static char *peer_export(const char *q) {
    memset(&PEER_MINE, 0, sizeof(PEER_MINE));
    snprintf(PEER_MINE.ssid[0], 33, "BetaNet");
    PEER_MINE.nssid = 1;
    snprintf(PEER_MINE.bssid[0], 18, "0b:00:00:00:00:b1");
    PEER_MINE.nbssid = 1;
    web_fleet_src_t src = { &PSDB, NULL, &PG, &PFR, NULL, NULL, &PEER_MINE, NULL };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, q, T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

static int ingest(const char *b, int write, char *err, size_t errsz) {
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&F, 0, b, strlen(b), T, write, &rows, &rts, err, errsz);
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    return rc;
}

/* ident=1: the own networks, each ap line's fingerprint (sloth's 0 IE
 * order sent as none, a WPS string with a control byte as none) and the
 * attacks naming it (the old karma: key and the deauth key not counted:
 * seen red with web_sdb_ap_attacks()'s window bound `a.last_seen >= ?2`
 * dropped, Quiet then KARMA_AP too); the end line's count; and the
 * importer takes it. Without ident=1 none of it, so an I7 importer is
 * never sent a member it does not know. */
static void test_export_ident(void) {
    up();
    char *b = peer_export("since=0&ident=1");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_HAS(b, "{\"type\":\"own_net\",\"ssid\":\"BetaNet\",\"bssid\":null}\n");
        WT_HAS(b, "{\"type\":\"own_net\",\"ssid\":null,\"bssid\":\"0b:00:00:00:00:b1\"}\n");
        WT_HAS(b, "\"bssid\":\"0e:00:00:00:00:01\",\"ssid\":\"Starbucks\"");
        char want[256];
        snprintf(want, sizeof(want), "\"ie_fp\":\"123456789\",\"vie_fp\":\"987\",\"wps_manuf\":"
                 "\"Hak5\",\"wps_model\":\"Pineapple\",\"wps_num\":\"MK7\",\"attacks\":"
                 "\"KARMA_AP\",\"attack_first\":%lld,\"attack_last\":%lld}", T - 9000, T - 8000);
        WT_HAS(b, want);
        WT_HAS(b, "\"ie_fp\":null,\"vie_fp\":\"5\",\"wps_manuf\":null,\"wps_model\":null,"
                  "\"wps_num\":null,\"attacks\":null,\"attack_first\":null,\"attack_last\":null}");
        WT_HAS(b, ",\"own_net\":2,\"complete\":true}");
        char err[200];
        WT_EQ(ingest(b, 0, err, sizeof(err)), 0);
        free(b);
    }
    b = peer_export("since=0&next=1&own=1&gnss=1&adsb=1");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_LACKS(b, "own_net");
        WT_LACKS(b, "ie_fp");
        WT_LACKS(b, "attacks");
        free(b);
    }
    /* A page carries the ap members with ident=1; never own_net. */
    b = peer_export("since=0&kind=ap&after=4102444800~&ident=1");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_HAS(b, "\"attacks\":\"KARMA_AP\"");
        WT_LACKS(b, "own_net");
        free(b);
    }
    char *e = NULL;
    size_t el = 0;
    int st = 0;
    web_fleet_src_t src = { &PSDB, NULL, &PG, &PFR, NULL, NULL, NULL, NULL };
    WT_EQ(web_fleet_export_route(&src, "since=0&ident=2", T, &e, &el, &st), 0);
    WT_EQ(st, 400);
    free(e);
    WT_EQ(web_fleet_export_route(&src, "since=0&ident=1&ident=1", T, &e, &el, &st), 0);
    WT_EQ(st, 400);
    free(e);
    down();
}

#define HDR "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":1792627000," \
    "\"since\":0,\"site_label\":\"beta-site\",\"slothweb_version\":\"1.8.6\"," \
    "\"sloth_version\":null,\"sloth_db\":\"open\",\"lat\":33.82922,\"lon\":-111.87006," \
    "\"alt_m\":181.0,\"pos_source\":\"fixed\",\"pos_ts\":1792627000,\"pos_age_s\":0}\n"
#define END(ap, own) "{\"type\":\"fleet_end\",\"rows\":" #ap ",\"wifi\":0,\"ble\":0,\"ap\":" #ap \
    ",\"probe\":0,\"alert\":0,\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false," \
    "\"truncated_ap\":false,\"truncated_probe\":false,\"truncated_alert\":false," \
    "\"truncated_verdict\":false" own ",\"complete\":true}\n"
#define AP_HEAD "{\"type\":\"ap\",\"bssid\":\"0e:00:00:00:00:01\",\"ssid\":\"S\",\"channel\":6," \
    "\"enc\":\"WPA2\",\"vendor\":null,\"rssi\":-60,\"first_seen\":1792620000," \
    "\"last_seen\":1792626000"

/* Every new member held to its range, each refusal the whole answer:
 * seen red with ap_ident()'s attacks check made to pass (the unknown
 * word then taken) and with the end line's own_net count check removed
 * (a short count then taken). */
static void test_ident_import_bounds(void) {
    static const char *const bad[] = {
        HDR AP_HEAD ",\"ie_fp\":\"12a\"}\n" END(1, ""),
        HDR AP_HEAD ",\"ie_fp\":\"\"}\n" END(1, ""),
        HDR AP_HEAD ",\"ie_fp\":\"123456789012345678901\"}\n" END(1, ""),
        HDR AP_HEAD ",\"vie_fp\":123}\n" END(1, ""),
        HDR AP_HEAD ",\"wps_manuf\":\"a\\u0007b\"}\n" END(1, ""),
        HDR AP_HEAD ",\"wps_model\":\"123456789012345678901234567890123\"}\n" END(1, ""),
        HDR AP_HEAD ",\"attacks\":\"DEAUTH_FLOOD\",\"attack_first\":1,\"attack_last\":2}\n" END(1, ""),
        HDR AP_HEAD ",\"attacks\":\"KARMA_AP\"}\n" END(1, ""),
        HDR AP_HEAD ",\"attack_first\":1,\"attack_last\":2}\n" END(1, ""),
        HDR AP_HEAD ",\"attacks\":\"KARMA_AP\",\"attack_first\":3,\"attack_last\":2}\n" END(1, ""),
        HDR AP_HEAD ",\"attacks\":\"KARMA_AP\",\"attack_first\":1,\"attack_last\":4102444801}\n"
            END(1, ""),
        HDR AP_HEAD ",\"attacks\":null,\"attack_first\":1,\"attack_last\":2}\n" END(1, ""),
        HDR AP_HEAD ",\"bogus\":1}\n" END(1, ""),
        HDR "{\"type\":\"own_net\",\"ssid\":\"A\",\"bssid\":\"0b:00:00:00:00:b1\"}\n"
            END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"ssid\":null,\"bssid\":null}\n" END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"ssid\":\"123456789012345678901234567890123\"}\n"
            END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"ssid\":\"a\\nb\"}\n" END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"bssid\":\"not-a-mac\"}\n" END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"ssid\":\"A\",\"x\":1}\n" END(0, ",\"own_net\":1"),
        HDR "{\"type\":\"own_net\",\"ssid\":\"A\"}\n" END(0, ",\"own_net\":2"),
        HDR "{\"type\":\"own_net\",\"ssid\":\"A\"}\n" END(0, ""),
        HDR END(0, ",\"own_net\":-1"),
        HDR END(0, ",\"own_net\":17"),
    };
    up();
    char err[200];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        long long rows = 0, rts = 0;
        int rc = web_fleet_ingest(&F, 0, bad[i], strlen(bad[i]), T, 1, &rows, &rts, err,
                                  sizeof(err));
        if (rc != -1) fprintf(stderr, "    taken: %zu\n", i);
        WT_EQ(rc, -1);
    }
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings"), 0);
    /* And the good forms: the ap row's extra gains only what was sent. */
    static const char good[] =
        HDR AP_HEAD ",\"ie_fp\":\"42\",\"vie_fp\":null,\"wps_manuf\":\"Hak5\",\"attacks\":"
        "\"EVIL_TWIN,KARMA_AP\",\"attack_first\":1792620000,\"attack_last\":1792626000}\n"
        "{\"type\":\"own_net\",\"ssid\":\"BetaNet\",\"bssid\":null}\n"
        END(1, ",\"own_net\":1");
    WT_EQ(ingest(good, 1, err, sizeof(err)), 0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='ap' AND extra="
             "'{\"channel\":6,\"enc\":\"WPA2\",\"ie_fp\":\"42\",\"wps_manuf\":\"Hak5\","
             "\"attacks\":\"EVIL_TWIN,KARMA_AP\",\"attack_first\":1792620000,"
             "\"attack_last\":1792626000}'"), 1);
    static const char plain[] = HDR AP_HEAD "}\n" END(1, "");
    WT_EQ(ingest(plain, 1, err, sizeof(err)), 0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='ap' AND extra="
             "'{\"channel\":6,\"enc\":\"WPA2\"}'"), 1);
    down();
}

/* The own networks: an answer naming them replaces what was named
 * before (one dropped is gone), the meta row says when and how many;
 * an answer that does not name them (an I7 export, a plain pull)
 * leaves them. Seen red with store_answer()'s own_net DELETE removed
 * (the dropped SSID then stayed). */
static void test_own_net_replaced(void) {
    up();
    char err[200];
    static const char two_own[] =
        HDR "{\"type\":\"own_net\",\"ssid\":\"BetaNet\",\"bssid\":null}\n"
        "{\"type\":\"own_net\",\"ssid\":\"OldNet\",\"bssid\":null}\n" END(0, ",\"own_net\":2");
    static const char one_own[] =
        HDR "{\"type\":\"own_net\",\"ssid\":\"BetaNet\",\"bssid\":null}\n" END(0, ",\"own_net\":1");
    static const char none[] = HDR END(0, "");
    WT_EQ(ingest(two_own, 1, err, sizeof(err)), 0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='own_net'"), 2);
    WT_EQ(ingest(one_own, 1, err, sizeof(err)), 0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='own_net'"), 1);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='own_net' AND"
             " key='ssid:BetaNet' AND label='BetaNet'"), 1);
    WT_EQ(ingest(none, 1, err, sizeof(err)), 0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM peer_sightings WHERE kind='own_net'"), 1);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM meta WHERE name='fleet.ident.beta' AND"
             " value='1792627000 1'"), 1);
    down();
}

/* EVIL_TWIN's key names both halves of a pair; which is the impostor is
 * the stream's (web_chain.h). Peer's 0e:..:01 (KARMA_AP too) and
 * 0e:..:02 under one twin: key: with no chain, or no attributed
 * episode, each is TWIN_UNATTRIBUTED; attributed, the impostor carries
 * EVIL_TWIN and the real half neither, its attack times its own
 * karma ones only. Seen red with twin_part() returning
 * WEB_FID_ATK_TWIN for every half (the real half then EVIL_TWIN). */
static char *export_chain(web_chain_t *ch) {
    web_fleet_src_t src = { &PSDB, NULL, &PG, &PFR, NULL, NULL, NULL, ch };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0&ident=1", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

static void chain_ep(web_chain_t *ch, const char *real, const char *twin, int attributed) {
    char line[512];
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(r != NULL);
    if (!r) return;
    snprintf(line, sizeof(line),
             "{\"type\":\"twin_episode\",\"ts\":%lld,\"ssid\":\"Starbucks\",\"real_bssid\":"
             "\"%s\",\"twin_bssid\":\"%s\",\"enc\":\"WPA2\",\"real_rssi\":-70,\"twin_rssi\":-45,"
             "\"rssi_swing_dbm\":25,\"attack_in_progress\":0,\"attacker_oui\":0,"
             "\"hash_mismatch\":0,\"attributed\":%d}", T - 2500, real, twin, attributed);
    WT_EQ(web_jl_parse(line, strlen(line), r), WEB_JL_OK);
    web_chain_record(ch, r);
    free(r);
}

static void test_export_twin_attribution(void) {
    up();
    alert_row(g_peer_db, "twin:0e:00:00:00:00:01:0e:00:00:00:00:02::WPA2/WPA2", WEB_ALERT_EVIL_TWIN,
              T - 3000, T - 2000);
    char k01[160], k02[160], none[160];
    snprintf(none, sizeof(none), "\"attacks\":null,\"attack_first\":null,\"attack_last\":null}");
    /* No chain: both halves unattributed. */
    char *b = export_chain(NULL);
    WT_ASSERT(b != NULL);
    if (b) {
        snprintf(k01, sizeof(k01), "\"attacks\":\"KARMA_AP,TWIN_UNATTRIBUTED\",\"attack_first\":"
                 "%lld,\"attack_last\":%lld}", T - 9000, T - 2000);
        snprintf(k02, sizeof(k02), "\"attacks\":\"TWIN_UNATTRIBUTED\",\"attack_first\":%lld,"
                 "\"attack_last\":%lld}", T - 3000, T - 2000);
        WT_HAS(b, k01);
        WT_HAS(b, k02);
        WT_LACKS(b, "\"attacks\":\"EVIL_TWIN");
        char err[200];
        WT_EQ(ingest(b, 0, err, sizeof(err)), 0);
        free(b);
    }
    web_chain_t ch;
    WT_EQ(web_chain_init(&ch), 0);
    /* An unattributed episode: the same. */
    chain_ep(&ch, "0e:00:00:00:00:01", "0e:00:00:00:00:02", 0);
    b = export_chain(&ch);
    if (b) {
        WT_HAS(b, k01);
        WT_HAS(b, k02);
        free(b);
    }
    /* Attributed, 0e:..:02 the impostor: it alone carries EVIL_TWIN;
     * 0e:..:01 keeps its own KARMA_AP and its own times. */
    chain_ep(&ch, "0e:00:00:00:00:01", "0e:00:00:00:00:02", 1);
    b = export_chain(&ch);
    if (b) {
        snprintf(k01, sizeof(k01), "\"attacks\":\"KARMA_AP\",\"attack_first\":%lld,"
                 "\"attack_last\":%lld}", T - 9000, T - 8000);
        snprintf(k02, sizeof(k02), "\"attacks\":\"EVIL_TWIN\",\"attack_first\":%lld,"
                 "\"attack_last\":%lld}", T - 3000, T - 2000);
        WT_HAS(b, k01);
        WT_HAS(b, k02);
        WT_LACKS(b, "UNATTRIBUTED");
        free(b);
    }
    web_chain_destroy(&ch);
    /* Attributed the other way: 0e:..:02 is the real AP, and no attack
     * names it. */
    WT_EQ(web_chain_init(&ch), 0);
    chain_ep(&ch, "0e:00:00:00:00:02", "0e:00:00:00:00:01", 1);
    b = export_chain(&ch);
    if (b) {
        snprintf(k01, sizeof(k01), "\"attacks\":\"EVIL_TWIN,KARMA_AP\",\"attack_first\":%lld,"
                 "\"attack_last\":%lld}", T - 9000, T - 2000);
        WT_HAS(b, k01);
        const char *q = strstr(b, "\"bssid\":\"0e:00:00:00:00:02\"");
        const char *nl = q ? strchr(q, '\n') : NULL;
        const char *at = q ? strstr(q, none) : NULL;
        WT_ASSERT(q && nl && at && at < nl);
        free(b);
    }
    web_chain_destroy(&ch);
    down();
}

static char *findings(const char *q, int *st) {
    web_fleet_mine_t mine;
    memset(&mine, 0, sizeof(mine));
    web_fleet_src_t src = { &HSDB, NULL, &HG, &HFR, NULL, NULL, &mine, NULL };
    char *b = NULL;
    size_t len = 0;
    WT_EQ(web_fleet_findings_route(&F, &src, q, T, &b, &len, st), 0);
    if (!b) return NULL;
    char *t = realloc(b, len + 1);
    if (!t) { free(b); return NULL; }
    t[len] = '\0';
    return t;
}

/* End to end: the peer's ident answer stored here, then the route.
 * I2 (the client probing BetaNet; the randomised one counted, not
 * listed), I4 (the fingerprint attacking at both, beta first, 55 km
 * apart), I8 (known there, incident here), the peer's verdict shown and
 * this site's triage left exactly as it was; the overview's counts; no
 * nan or inf anywhere. The no-write claim was seen red with a write of
 * each peer verdict into this site's triage, over the triage writer,
 * added to build() (the triage count then 2, one of them known). */
static void test_findings_route(void) {
    up();
    char *b = peer_export("since=0&next=1&own=1&gnss=1&adsb=1&ident=1");
    char err[200];
    WT_ASSERT(b && ingest(b, 1, err, sizeof(err)) == 0);
    free(b);
    long long tri0 = q1(g_here_web, "SELECT COUNT(*) FROM triage");
    WT_EQ(tri0, 1);
    int st = 0;
    b = findings("", &st);
    WT_EQ(st, 200);
    WT_ASSERT(b != NULL);
    if (b) {
        WT_LACKS(b, "nan");
        WT_LACKS(b, "inf");
        WT_HAS(b, "\"configure\":null");
        WT_HAS(b, "\"own_ssids\":[\"BetaNet\"],\"own_bssids\":[\"0b:00:00:00:00:b1\"]");
        WT_HAS(b, "\"randomised\":1,");
        WT_HAS(b, "\"co_located\":false}");
        WT_HAS(b, "\"class\":\"I2\",\"kind\":\"probe_other_site\",\"key\":\"00:11:22:33:44:55\","
                  "\"ssid\":\"BetaNet\"");
        WT_LACKS(b, "06:11:22:33:44:56");
        WT_LACKS(b, "00:11:22:33:44:57");
        WT_HAS(b, "\"class\":\"I4\",\"kind\":\"tool_travel\",\"key\":\"123456789/987\","
                  "\"ssid\":null,\"alert_type\":null,\"sites\":[\"beta\",\"self\"]");
        WT_HAS(b, "\"wps\":[\"Hak5\",\"Pineapple\",\"MK7\"]");
        WT_HAS(b, "\"class\":\"I8\",\"kind\":\"verdict_conflict\",\"key\":\"00:11:22:33:44:55\"");
        WT_HAS(b, "\"verdicts\":[{\"addr\":\"00:11:22:33:44:55\",\"states\":[{\"site\":\"self\","
                  "\"state\":\"incident\"");
        WT_HAS(b, "{\"site\":\"beta\",\"state\":\"known\"");
        WT_HAS(b, "\"counts\":{\"I2\":0,\"I3\":0,\"I4\":1,\"I8\":1,\"not_applicable\":0,"
                  "\"exonerated\":1}");
        free(b);
    }
    /* Never applied here: this site's triage is as it was, and its
     * current state on the address is still its own. */
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM triage"), tri0);
    WT_EQ(q1(g_here_web, "SELECT COUNT(*) FROM triage WHERE state=4"), 0);
    const char *addrs[1] = { "00:11:22:33:44:55" };
    int state = -1;
    WT_EQ(web_frrs_addr_states(&HFR, addrs, 1, &state), 1);
    WT_EQ(state, WEB_TRI_INCIDENT);
    b = findings("kind=I4&limit=1", &st);
    WT_EQ(st, 200);
    if (b) {
        WT_LACKS(b, "\"class\":\"I2\"");
        WT_HAS(b, "\"total\":1,");
        WT_HAS(b, "\"applicable\":true,\"lead\":true,");
        free(b);
    }
    static const char *const badq[] = { "kind=I5", "limit=0", "limit=501", "x=1", "kind=I2&kind=I3" };
    for (size_t i = 0; i < sizeof(badq) / sizeof(badq[0]); i++) {
        b = findings(badq[i], &st);
        WT_EQ(st, 400);
        free(b);
    }
    /* The overview's counts. */
    web_fleet_src_t src = { &HSDB, NULL, &HG, &HFR, NULL, NULL, NULL, NULL };
    static char ov[1 << 17];
    size_t ol = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T, ov, sizeof(ov) - 1, &ol, &st), 0);
    ov[ol] = '\0';
    WT_EQ(st, 200);
    WT_HAS(ov, ",\"findings\":{\"counts\":{\"I2\":0,\"I3\":0,\"I4\":1,\"I8\":1,");
    WT_LACKS(ov, "nan");
    down();
}

/* No site names its own networks: the route says how to configure
 * them; a peer that has not offered them (an I7 build) says so. */
static void test_findings_unconfigured(void) {
    up();
    int st = 0;
    char *b = findings("", &st);
    WT_EQ(st, 200);
    if (b) {
        WT_HAS(b, "\"configure\":\"no site names its own networks: give the slothweb at each "
                  "site --my-ssid and --my-bssid");
        WT_HAS(b, "{\"site\":\"beta\",\"label\":null,\"lat\":null,\"lon\":null,\"offered\":false,"
                  "\"own_age_s\":null,");
        WT_HAS(b, "\"co_located\":null}");
        free(b);
    }
    down();
}
#endif

/* ── the panel (web/ui/fleetid.js) ─────────────────────────────────── */

static char *fid_module(const char *p) {
    const char *s = strstr(p, "// slothweb: identity across the sites");
    const char *m = strstr(p, "window.SlothFleetId = { init: init, show: show };");
    if (!s || !m || s >= m) return NULL;
    size_t n = (size_t)(m - s);
    char *mod = malloc(n + 1);
    if (!mod) return NULL;
    memcpy(mod, s, n);
    mod[n] = '\0';
    return mod;
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    if (!s) return 0;
    for (const char *q = strstr(s, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

/* The panel on the Fleet tab after the aircraft panel, its ids in the
 * page and the module, app.js's two hooks, the one route it fetches
 * (through the page's getJSON, no fetch(), no innerHTML), and its
 * stylesheet by token only. Pinned by whole functions (#171 V1's
 * review): the drawer link, a site's part, the applicability words,
 * the rows and the load. The fetch census was seen red with a second
 * getJSON("/api/fleet/overview") added to load(); the token census with
 * .fid-on's colour written as #ff8c26. */
static void test_fleetid_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "    if (v === \"fleet\" && window.SlothFleetId) SlothFleetId.show();");
    WT_HAS(p, "  if (window.SlothFleetId) SlothFleetId.init({ el: el, set: set, getJSON: getJSON, errText: errText,\n"
              "    stamp: stamp, openDrawer: openDrawer });");
    static const char *const ids[] = { "fid-note", "fid-config", "fid-rows", "fid-ver-rows" };
    char *mod = fid_module(p);
    WT_ASSERT(mod != NULL);
    if (!mod) return;
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", ids[i]);
        WT_EQ(count_of(p, want), 1);
        snprintf(want, sizeof(want), "\"%s\"", ids[i]);
        WT_HAS(mod, want);
    }
    /* Inside the Fleet view, after the aircraft panel. */
    const char *v = strstr(p, "<div id=\"v-fleet\" hidden>"), *ac = strstr(p, " id=\"fleet-ac-rows\"");
    const char *me = strstr(p, " id=\"fid-rows\""), *ve = strstr(p, "<div id=\"v-tacdb\" hidden>");
    WT_ASSERT(v && ac && me && ve && v < ac && ac < me && me < ve);
    WT_HAS(mod,
              "  function keyEl(k) {\n"
              "    if (!MAC.test(k)) return H.el(\"span\", \"fid-key\", k);\n"
              "    var b = H.el(\"button\", \"fid-link\", k);\n"
              "    b.type = \"button\";\n"
              "    b.title = \"open \" + k;\n"
              "    b.addEventListener(\"click\", function () { H.openDrawer(k); });\n"
              "    return b;\n"
              "  }\n");
    WT_HAS(mod,
              "  function legEl(e) {\n"
              "    var d = H.el(\"div\", \"fid-leg\");\n"
              "    d.appendChild(H.el(\"span\", \"fid-who\", siteName(e.site) + \" (\" + e.role + \")\"));\n"
              "    if (e.key !== \"\" && e.role !== \"owner\") d.appendChild(keyEl(e.key));\n"
              "    var bits = [];\n"
              "    if (num(e.rssi)) bits.push(e.rssi + \" dBm\");\n"
              "    if (num(e.first_seen) && num(e.last_seen))\n"
              "      bits.push(H.stamp(e.first_seen) + (e.last_seen > e.first_seen ? \" to \" + H.stamp(e.last_seen) : \"\"));\n"
              "    if (e.attacks) bits.push(\"attacks: \" + e.attacks.replace(/,/g, \", \"));\n"
              "    if (e.wps) bits.push(\"WPS \" + e.wps.map(function (w) { return w || \"-\"; }).join(\" / \"));\n"
              "    if (e.verdict) bits.push(\"triaged \" + e.verdict);\n"
              "    if (bits.length) d.appendChild(H.el(\"span\", \"\", \" \" + bits.join(\", \")));\n"
              "    return d;\n"
              "  }\n");
    WT_HAS(mod,
              "  function status(f) {\n"
              "    if (f.exonerated) return \"exonerated: triaged known at a site\";\n"
              "    if (!f.applicable)\n"
              "      return \"not applicable: \" + words(f.reason) + (num(f.distance_m) ? \" (\" + dist(f.distance_m) +\n"
              "             (num(f.bound_m) ? \", reach \" + dist(f.bound_m) : \"\") + \")\" : \"\");\n"
              "    return (f.lead ? \"a lead to confirm\" : \"applies\") + (num(f.distance_m) ? \" (\" + dist(f.distance_m) +\n"
              "           (num(f.bound_m) ? \" apart, reach \" + dist(f.bound_m) : \" apart\") + \")\" : \"\");\n"
              "  }\n");
    WT_HAS(mod,
              "  function rows(j) {\n"
              "    var box = $(\"fid-rows\");\n"
              "    while (box.firstChild) box.removeChild(box.firstChild);\n"
              "    j.findings.forEach(function (f) {\n"
              "      var row = H.el(\"div\", \"fid-row\" + (f.applicable && !f.exonerated ? \"\" : \" dim\"));\n"
              "      var c = H.el(\"span\", \"fid-class\", f.class + \" \" + words(f.kind) + (f.lead ? \" (lead)\" : \"\"));\n"
              "      c.title = f.basis;\n"
              "      row.appendChild(c);\n"
              "      var k = H.el(\"span\", \"\");\n"
              "      k.appendChild(keyEl(f.key));\n"
              "      if (f.ssid) k.appendChild(H.el(\"span\", \"\", \" \\\"\" + f.ssid + \"\\\"\"));\n"
              "      if (f.alert_type) k.appendChild(H.el(\"span\", \"\", \" \" + f.alert_type));\n"
              "      row.appendChild(k);\n"
              "      var ev = H.el(\"span\", \"\");\n"
              "      f.evidence.forEach(function (e) { ev.appendChild(legEl(e)); });\n"
              "      row.appendChild(ev);\n"
              "      var st = H.el(\"span\", f.applicable && !f.exonerated ? \"fid-on\" : \"fid-off\", status(f));\n"
              "      st.title = f.basis;\n"
              "      if (f.note) st.appendChild(H.el(\"div\", \"sub\", words(f.note)));\n"
              "      row.appendChild(st);\n"
              "      box.appendChild(row);\n"
              "    });\n"
              "    if (!box.firstChild) box.appendChild(H.el(\"div\", \"sub\", \"no finding\"));\n"
              "  }\n");
    WT_HAS(mod,
              "  function load() {\n"
              "    var gen = ++S.gen;\n"
              "    return H.getJSON(\"/api/fleet/findings?limit=200\").then(function (j) {\n"
              "      if (gen !== S.gen) return;\n"
              "      S.sites = {};\n"
              "      j.sites.forEach(function (s) { S.sites[s.site] = s; });\n"
              "      rows(j);\n"
              "      verRows(j);\n"
              "      var cf = $(\"fid-config\");\n"
              "      cf.hidden = !j.configure;\n"
              "      H.set(\"fid-config\", j.configure || \"\");\n"
              "      var c = j.counts, own = j.sites.map(function (s) {\n"
              "        return siteName(s.site) + \" \" + (s.offered ? s.own_ssids.length + \" SSID, \" + s.own_bssids.length +\n"
              "               \" BSSID\" : \"not offered (older build)\");\n"
              "      });\n"
              "      var pairs = j.pairs.map(function (p) {\n"
              "        return siteName(p.a) + \" - \" + siteName(p.b) + \" \" + (p.co_located === null ? \"no position\" :\n"
              "               dist(p.distance_m) + (p.co_located ? \", co-located\" : \", apart\"));\n"
              "      });\n"
              "      H.set(\"fid-note\", c.I2 + \" I2, \" + c.I3 + \" I3, \" + c.I4 + \" I4, \" + c.I8 + \" I8; \" +\n"
              "            c.not_applicable + \" not applicable, \" + c.exonerated + \" exonerated; own networks: \" +\n"
              "            own.join(\", \") + (pairs.length ? \"; \" + pairs.join(\"; \") : \"\") + (j.partial ? \"; partial\" : \"\"));\n"
              "    }).catch(function (e) {\n"
              "      if (gen === S.gen) H.set(\"fid-note\", H.errText(e.message));\n"
              "    });\n"
              "  }\n");
    WT_EQ(count_of(mod, "getJSON("), 1);
    WT_HAS(mod, "H.getJSON(\"/api/fleet/findings?limit=200\")");
    WT_LACKS(mod, "fetch(");
    WT_LACKS(mod, "XMLHttpRequest");
    WT_LACKS(mod, "innerHTML");
    WT_LACKS(mod, "<canvas");
    /* The script after fleet.js, the stylesheet after fleet.css, colours
     * by token only. */
    const char *fjs = strstr(p, "// slothweb: the Fleet view"), *ijs = strstr(p, "// slothweb: identity across");
    WT_ASSERT(fjs && ijs && fjs < ijs);
    const char *c0 = strstr(p, ".fid-row { display: grid;"), *c1 = c0 ? strstr(c0, ".fid-ver.dhead {") : NULL;
    const char *fcss = strstr(p, "#fleet-map { display: block;");
    WT_ASSERT(c0 && c1 && fcss && fcss < c0);
    if (c0 && c1) {
        size_t n = (size_t)(c1 - c0);
        char *css = malloc(n + 1);
        if (css) {
            memcpy(css, c0, n);
            css[n] = '\0';
            WT_LACKS(css, "#");
            WT_LACKS(css, "rgb");
            WT_ASSERT(count_of(css, "var(--") >= 6);
            free(css);
        }
    }
    free(mod);
}

void run_fleetid_tests(void) {
    WT_RUN(test_reach);
    WT_RUN(test_words);
    WT_RUN(test_i2);
    WT_RUN(test_i3_own_bssid);
    WT_RUN(test_i3_foreign);
    WT_RUN(test_i3_two_places);
    WT_RUN(test_i4);
    WT_RUN(test_i8);
    WT_RUN(test_room);
    WT_RUN(test_fleetid_page);
    WT_RUN(test_my_flags);
#ifdef WITH_SQLITE
    WT_RUN(test_export_ident);
    WT_RUN(test_ident_import_bounds);
    WT_RUN(test_own_net_replaced);
    WT_RUN(test_export_twin_attribution);
    WT_RUN(test_findings_route);
    WT_RUN(test_findings_unconfigured);
#endif
}
