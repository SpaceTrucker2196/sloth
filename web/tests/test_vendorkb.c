/* The vendor research table (web_vendorkb.h) held to the files it is
 * generated from and to the registry it keys into, read again here:
 * every .md under web/data/vendors/ is an entry and every entry a file named
 * for its name; every [n] in every field resolves to a source; the name
 * and each alias are exact IEEE "Organization Name" strings in the
 * committed registry (an entry no OUI can reach is dead, and red); the
 * lookup folds case, white space and punctuation; the drawer and
 * Lookup carry the section and {"found":false} for a vendor without
 * one; and the page shows it as text, with no link. Runs from the top
 * of the tree, as the suite does. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oui_csv.h"
#include "web_assets.h"
#include "web_devices.h"
#include "web_vendorkb.h"
#include "wt_tmp.h"
#include "wtest.h"

#define VKB_DIR "web/data/vendors"

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0, r;
    char *b = malloc(cap + 1);
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

/* Every [n] in s (digits, commas and spaces inside the brackets) is in
 * 1..n; -1 names the first that is not. */
static int cites_resolve(const char *s, int n) {
    for (const char *p = strchr(s, '['); p; p = strchr(p + 1, '[')) {
        const char *q = p + 1;
        int any = 0, ok = 1;
        for (; *q && *q != ']'; q++) {
            if (*q >= '0' && *q <= '9') any = 1;
            else if (*q != ',' && *q != ' ') ok = 0;
        }
        if (*q != ']' || !any || !ok) continue;
        for (q = p + 1; *q != ']'; ) {
            while (*q == ',' || *q == ' ') q++;
            if (*q == ']') break;
            int k = 0;
            while (*q >= '0' && *q <= '9') k = k * 10 + (*q++ - '0');
            if (k < 1 || k > n) return k;
        }
    }
    return 0;
}

static int plain(const char *s) {
    return !strstr(s, "](") && !strstr(s, "**") && !strchr(s, '`');
}

static void check_texts(const web_vkb_t *e, const char *const *v, int n, const char *what) {
    for (int i = 0; i < n; i++) {
        int bad = cites_resolve(v[i], e->nsources);
        if (bad) fprintf(stderr, "    %s: %s cites [%d] of %d sources\n", e->file, what, bad, e->nsources);
        WT_EQ(bad, 0);
        WT_ASSERT(plain(v[i]));
        /* a list item carries its source */
        if (strcmp(what, "aliases") && strcmp(what, "device_classes"))
            WT_ASSERT(strchr(v[i], '[') != NULL);
    }
}

/* Seen red with web/tools/vendorkb.c's read_dir() skipping files whose
 * name starts with 't' (fewer entries than files), and separately
 * with its citation check short-circuited and "[9]" written into
 * tesla-inc.md's summary (the dangling mark reached the table; the
 * file restored byte for byte). */
static void test_every_entry_is_complete_and_cited(void) {
    WT_ASSERT(web_vkb_n >= 3);
    DIR *d = opendir(VKB_DIR);
    WT_ASSERT(d != NULL);
    int files = 0;
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            size_t l = strlen(de->d_name);
            if (de->d_name[0] != '.' && l > 3 && !strcmp(de->d_name + l - 3, ".md") &&
                strcmp(de->d_name, WEB_VKB_COVERAGE)) files++;
        }
        closedir(d);
    }
    WT_EQ(files, web_vkb_n);
    for (int i = 0; i < web_vkb_n; i++) {
        const web_vkb_t *e = &web_vkb[i];
        WT_ASSERT(e->name[0] && e->kind[0] && e->country[0] && e->parent[0] &&
                  e->founded[0] && e->randomization[0] && e->summary[0]);
        WT_EQ(strlen(e->researched), 10);
        WT_ASSERT(e->nsources >= 1);
        for (int s = 0; s < e->nsources; s++) {
            WT_ASSERT(e->sources[s].title[0]);
            WT_ASSERT(!strncmp(e->sources[s].url, "http", 4));
            WT_EQ(strlen(e->sources[s].accessed), 10);
            WT_ASSERT(plain(e->sources[s].title));
        }
        /* the file is the slug of the name: the key with '-' for ' ' */
        char key[WEB_VKB_KEY_MAX + 1], want[WEB_VKB_KEY_MAX + 32];
        web_vkb_norm(e->name, key, sizeof(key));
        for (char *p = key; *p; p++) if (*p == ' ') *p = '-';
        snprintf(want, sizeof(want), VKB_DIR "/%s.md", key);
        if (strcmp(want, e->file)) fprintf(stderr, "    %s should be %s\n", e->file, want);
        WT_ASSERT(!strcmp(want, e->file));
        WT_ASSERT(access(e->file, R_OK) == 0);
        /* every field's marks resolve; a cited scalar carries one */
        const char *const scalars[] = { e->country, e->parent, e->founded, e->randomization, e->kind };
        for (size_t k = 0; k < sizeof(scalars) / sizeof(scalars[0]); k++) {
            WT_EQ(cites_resolve(scalars[k], e->nsources), 0);
            WT_ASSERT(plain(scalars[k]));
            if (k < 4) WT_ASSERT(!strcmp(scalars[k], "unknown") || strchr(scalars[k], '['));
        }
        check_texts(e, e->aliases, e->naliases, "aliases");
        check_texts(e, e->device_classes, e->ndevice_classes, "device_classes");
        check_texts(e, e->found_in, e->nfound_in, "found_in");
        check_texts(e, e->radios, e->nradios, "radios");
        check_texts(e, e->silicon, e->nsilicon, "silicon");
        check_texts(e, e->fcc_grantee, e->nfcc_grantee, "fcc_grantee");
        check_texts(e, e->security_notes, e->nsecurity_notes, "security_notes");
        int bad = cites_resolve(e->summary, e->nsources);
        if (bad) fprintf(stderr, "    %s: the summary cites [%d] of %d sources\n", e->file, bad, e->nsources);
        WT_EQ(bad, 0);
        WT_ASSERT(strchr(e->summary, '[') != NULL);
        WT_ASSERT(plain(e->summary));
        static const char *const words[] = { "documented", "inferred", "unknown" };
        const char *const conf[] = { e->conf_country, e->conf_silicon, e->conf_radios,
                                     e->conf_found_in, e->conf_randomization };
        for (size_t k = 0; k < 5; k++) {
            int ok = 0;
            for (size_t w = 0; w < 3; w++) ok |= !strcmp(conf[k], words[w]);
            WT_ASSERT(ok);
        }
    }
}

/* Is name an Organization Name field of one of the registry CSVs: the
 * field as the IEEE writes it, quoted when it holds a comma or a
 * quote, bare otherwise, between the assignment's and the address's
 * commas. */
static int in_registry(const char *const *csv, int ncsv, const char *name) {
    char quoted[512], bare[512];
    size_t o = 0;
    quoted[o++] = ',';
    quoted[o++] = '"';
    for (const char *p = name; *p && o + 3 < sizeof(quoted); p++) {
        if (*p == '"') quoted[o++] = '"';
        quoted[o++] = *p;
    }
    quoted[o++] = '"';
    quoted[o++] = ',';
    quoted[o] = '\0';
    snprintf(bare, sizeof(bare), ",%s,", name);
    for (int i = 0; i < ncsv; i++)
        if (csv[i] && (strstr(csv[i], quoted) || strstr(csv[i], bare))) return 1;
    return 0;
}

/* Seen red with tesla-inc.md's name written "Tesla, Inc" (a spelling
 * the registry does not hold; restored byte for byte). */
static void test_every_entry_names_an_ieee_vendor(void) {
    static const char *const files[] = { "web/data/oui.csv", "web/data/mam.csv",
                                         "web/data/oui36.csv", "web/data/iab.csv" };
    char *csv[4];
    for (int i = 0; i < 4; i++) {
        csv[i] = slurp(files[i]);
        WT_ASSERT(csv[i] != NULL);
    }
    for (int i = 0; i < web_vkb_n; i++) {
        const web_vkb_t *e = &web_vkb[i];
        int ok = in_registry((const char *const *)csv, 4, e->name);
        if (!ok) fprintf(stderr, "    %s: \"%s\" is no registry Organization Name\n", e->file, e->name);
        WT_ASSERT(ok);
        for (int a = 0; a < e->naliases; a++) {
            ok = in_registry((const char *const *)csv, 4, e->aliases[a]);
            if (!ok) fprintf(stderr, "    %s: alias \"%s\" is no registry Organization Name\n",
                             e->file, e->aliases[a]);
            WT_ASSERT(ok);
            /* and it is another spelling of the same name, not a second
             * vendor: the alias finds this entry */
            WT_ASSERT(web_vendorkb_find(e->aliases[a]) == e);
        }
        WT_ASSERT(web_vendorkb_find(e->name) == e);
    }
    for (int i = 0; i < 4; i++) free(csv[i]);
}

/* Seen red with web_vendorkb_find() comparing the name as given
 * (strcmp against the key) in place of its normalised form. */
static void test_find_folds_spelling(void) {
    char k[WEB_VKB_KEY_MAX + 1];
    web_vkb_norm("  Flextronics, Inc. ", k, sizeof(k));
    WT_ASSERT(!strcmp(k, "flextronics inc"));
    web_vkb_norm("FLEXTRONICS", k, sizeof(k));
    WT_ASSERT(!strcmp(k, "flextronics"));
    web_vkb_norm("Tesla,Inc.", k, sizeof(k));
    WT_ASSERT(!strcmp(k, "tesla inc"));
    web_vkb_norm("---", k, sizeof(k));
    WT_ASSERT(!strcmp(k, ""));
    /* bytes outside ASCII pass through, cut only on the cap */
    web_vkb_norm("Caf\303\251 S.A.", k, sizeof(k));
    WT_ASSERT(!strcmp(k, "caf\303\251 s a"));
    WT_EQ(web_vkb_norm("abcdef", k, 4), 3);
    WT_ASSERT(!strcmp(k, "abc"));

    const web_vkb_t *a = web_vendorkb_find("AMPAK Technology,Inc.");
    WT_ASSERT(a != NULL);
    WT_ASSERT(web_vendorkb_find("AMPAK Technology, Inc.") == a);
    WT_ASSERT(web_vendorkb_find("ampak   technology inc") == a);
    WT_ASSERT(web_vendorkb_find("AMPAK TECHNOLOGY INC.") == a);
    WT_ASSERT(web_vendorkb_find("Tesla Inc") == web_vendorkb_find("Tesla,Inc."));
    WT_ASSERT(web_vendorkb_find("Tesla,Inc.") != NULL);
    WT_ASSERT(web_vendorkb_find("MURATA MANUFACTURING CO., LTD.") ==
              web_vendorkb_find("Murata Manufacturing Co., Ltd."));
    WT_ASSERT(web_vendorkb_find("Murata Manufacturing Co., Ltd.") != NULL);
    WT_ASSERT(web_vendorkb_find("Not A Vendor") == NULL);
    WT_ASSERT(web_vendorkb_find("Tesla") == NULL);           /* no prefix match */
    WT_ASSERT(web_vendorkb_find("") == NULL);
    WT_ASSERT(web_vendorkb_find(NULL) == NULL);
    /* the keys are sorted, as the search needs */
    for (int i = 1; i < web_vkb_nkeys; i++)
        WT_ASSERT(strcmp(web_vkb_keys[i - 1].key, web_vkb_keys[i].key) < 0);
}

static char g_body[1 << 16];

/* The drawer and the Lookup card from the OUI table alone (no sloth.db,
 * no stream): the section for a researched vendor, {"found":false} for
 * one with no entry and for an IP. Seen red with research_member()'s
 * call left out of oui_member() in web/src/web_devices.c. */
static void test_drawer_and_lookup_carry_the_section(void) {
    char path[TEST_TMP_MAX + 32];
    snprintf(path, sizeof(path), "%s/vkb-oui-XXXXXX", test_tmpdir());
    int fd = mkstemp(path);
    WT_ASSERT(fd >= 0);
    if (fd < 0) return;
    FILE *f = fdopen(fd, "w");
    fputs("Registry,Assignment,Organization Name,Organization Address\n"
          "MA-L,98ED5C,\"Tesla,Inc.\",3500 Deer Creek Road Palo Alto CA US 94304\n"
          "MA-L,0000FE,Example Unresearched Ltd,1 Nowhere Road XX\n", f);
    fclose(f);
    oui_build_t b;
    oui_build_init(&b);
    WT_EQ(oui_build_csv(&b, path), 0);
    WT_EQ(oui_build_finish(&b, "ieee"), 0);
    web_m4_t m;
    memset(&m, 0, sizeof(m));
    m.oui = &b.tab;
    size_t len = 0;
    int status = 0;
    WT_EQ(web_device_route(&m, "98:ed:5c:00:00:01", "", 1792627200, g_body, sizeof(g_body),
                           &len, &status), 0);
    WT_EQ(status, 200);
    WT_HAS(g_body, "\"oui\":{\"found\":true,\"vendor\":\"Tesla,Inc.\"");
    WT_HAS(g_body, "\"vendor_research\":{\"found\":true,\"file\":\"web/data/vendors/tesla-inc.md\","
                   "\"name\":\"Tesla,Inc.\",\"aliases\":[\"Tesla Inc\"],\"kind\":\"automotive\","
                   "\"country\":\"US [1]\"");
    WT_HAS(g_body, "\"fcc_grantee\":[\"2AEIM (attested by FCC ID 2AEIM-QCA6234) [7]\"]");
    WT_HAS(g_body, "\"confidence\":{\"country\":\"documented\",\"silicon\":\"documented\","
                   "\"radios\":\"documented\",\"found_in\":\"documented\",\"randomization\":\"unknown\"}");
    WT_HAS(g_body, "\"summary\":\"Tesla, Inc. is the Austin, Texas electric-vehicle");
    WT_HAS(g_body, "\"sources\":[{\"n\":1,\"title\":\"Wikipedia - Tesla, Inc.\",\"url\":"
                   "\"https://en.wikipedia.org/wiki/Tesla,_Inc.\",\"accessed\":\"2026-10-27\"}");
    WT_HAS(g_body, "\"researched\":\"2026-10-27\"}");
    WT_HAS(g_body, "\"record\":null");
    /* a vendor with no entry */
    WT_EQ(web_device_route(&m, "00:00:fe:aa:bb:cc", "", 1792627200, g_body, sizeof(g_body),
                           &len, &status), 0);
    WT_HAS(g_body, "\"vendor\":\"Example Unresearched Ltd\"");
    WT_HAS(g_body, "\"vendor_research\":{\"found\":false}");
    /* no vendor at all */
    WT_EQ(web_device_route(&m, "02:11:22:33:44:55", "", 1792627200, g_body, sizeof(g_body),
                           &len, &status), 0);
    WT_HAS(g_body, "\"oui\":{\"found\":false");
    WT_HAS(g_body, "\"vendor_research\":{\"found\":false}");
    /* Lookup: the same for a MAC, and nothing to research for an IP */
    WT_EQ(web_lookup_route(&m, "q=98%3AED%3A5C%3A00%3A00%3A01", 1792627200, g_body,
                           sizeof(g_body), &len, &status), 0);
    WT_EQ(status, 200);
    WT_HAS(g_body, "\"kind\":\"mac\"");
    WT_HAS(g_body, "\"vendor_research\":{\"found\":true,\"file\":\"web/data/vendors/tesla-inc.md\"");
    WT_EQ(web_lookup_route(&m, "q=10.0.0.1", 1792627200, g_body, sizeof(g_body), &len,
                           &status), 0);
    WT_HAS(g_body, "\"oui\":null,\"vendor_research\":{\"found\":false}");
    oui_build_free(&b);
    unlink(path);
}

/* The page: the section is drawn by one function the drawer and Lookup
 * both call, every value through textContent, the sources as text (the
 * whole page has no href but fragments and no markup sink:
 * test_routes.c). Seen red with Lookup's call removed. */
static void test_page_shows_research_as_text(void) {
    const char *p = (const char *)web_page;
    const char *fn = strstr(p, "  function vendorResearch(box, vr, oui) {");
    WT_ASSERT(fn != NULL);
    if (!fn) return;
    const char *end = strstr(fn, "\n  }\n");
    WT_ASSERT(end != NULL);
    if (!end) return;
    size_t n = (size_t)(end - fn);
    char *body = malloc(n + 1);
    memcpy(body, fn, n);
    body[n] = '\0';
    WT_HAS(body, "\"no research yet for \" + oui.vendor");
    WT_HAS(body, "el(\"li\", \"\", s.n + \". \" + s.title + \" - \" + s.url +");
    WT_LACKS(body, "href");
    WT_LACKS(body, "\"a\"");
    WT_LACKS(body, "innerHTML");
    WT_LACKS(body, "setAttribute");
    free(body);
    int calls = 0;
    for (const char *c = p; (c = strstr(c, "vendorResearch(box, j.vendor_research, j.oui);")) != NULL; c++)
        calls++;
    WT_EQ(calls, 2);                 /* the drawer and Lookup */
    WT_HAS(p, "if (j.kind === \"mac\") vendorResearch(box, j.vendor_research, j.oui);");
    WT_HAS(p, ".vr-src { ");
}

/* ── coverage of the reference host ── */

#define REF_MAX 512

typedef struct { char name[256]; int devices; int seen; } ref_t;

/* REFERENCE_HOST.txt: "#" comment lines, then "NAME<TAB>DEVICES" per
 * line, NAME exactly as the registry spells it (a trailing space kept). */
static int read_reference(ref_t *r, int cap) {
    char *t = slurp(VKB_DIR "/REFERENCE_HOST.txt");
    WT_ASSERT(t != NULL);
    if (!t) return 0;
    int n = 0;
    for (char *l = t; l && *l; ) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        if (*l && *l != '#') {
            char *tab = strchr(l, '\t');
            WT_ASSERT(tab != NULL);
            if (tab && n < cap && (size_t)(tab - l) < sizeof(r[n].name)) {
                memcpy(r[n].name, l, (size_t)(tab - l));
                r[n].name[tab - l] = '\0';
                r[n].devices = atoi(tab + 1);
                r[n].seen = 0;
                n++;
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    free(t);
    return n;
}

static ref_t *ref_find(ref_t *r, int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(r[i].name, name)) return &r[i];
    return NULL;
}

/* COVERAGE.md's two lists, "## Have" and "## Pending", each line
 *   - "NAME" - N device[s] - <the entry's file | why it is pending>
 * held to REFERENCE_HOST.txt (together exactly its names, each once,
 * with its device count) and to the table (a Have name finds the file
 * the line names, a Pending name finds none). Seen red with
 * web/data/vendors/wnc-corporation.md moved out of the tree ("WNC
 * Corporation" under Have found no entry), with the "SJIT Co., Ltd."
 * line deleted from Pending (a reference name in neither list), and
 * with "Ring LLC" copied into Pending (a name twice, and a Pending
 * name that resolves); each file restored byte for byte. */
static void test_coverage_matches_reference_and_entries(void) {
    static ref_t ref[REF_MAX];
    int nref = read_reference(ref, REF_MAX);
    WT_ASSERT(nref >= 100);
    char *t = slurp(VKB_DIR "/" WEB_VKB_COVERAGE);
    WT_ASSERT(t != NULL);
    if (!t) return;
    int section = 0, have = 0, pending = 0, have_devices = 0, total = 0;
    for (char *l = t; l && *l; ) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        if (!strcmp(l, "## Have")) section = 1;
        else if (!strcmp(l, "## Pending")) section = 2;
        else if (!strncmp(l, "## ", 3)) section = 0;
        else if (section && !strncmp(l, "- \"", 3)) {
            char *name = l + 3, *q = strstr(name, "\" - ");
            WT_ASSERT(q != NULL);
            if (q) {
                *q = '\0';
                char *rest = q + 4;
                int dev = atoi(rest);
                char *tail = strstr(rest, " - ");
                WT_ASSERT(tail != NULL);
                ref_t *r = ref_find(ref, nref, name);
                if (!r) fprintf(stderr, "    COVERAGE.md: \"%s\" is not in REFERENCE_HOST.txt\n", name);
                WT_ASSERT(r != NULL);
                if (r) {
                    if (r->seen) fprintf(stderr, "    COVERAGE.md: \"%s\" is listed twice\n", name);
                    WT_EQ(r->seen, 0);
                    r->seen = 1;
                    WT_EQ(dev, r->devices);
                }
                const web_vkb_t *e = web_vendorkb_find(name);
                if (section == 1) {
                    have++;
                    have_devices += dev;
                    if (!e) fprintf(stderr, "    COVERAGE.md: \"%s\" is under Have and has no entry\n", name);
                    WT_ASSERT(e != NULL);
                    if (e && tail) WT_ASSERT(!strcmp(e->file, tail + 3));
                } else {
                    pending++;
                    if (e) fprintf(stderr, "    COVERAGE.md: \"%s\" is under Pending and has %s\n",
                                   name, e->file);
                    WT_ASSERT(e == NULL);
                }
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    free(t);
    for (int i = 0; i < nref; i++) {
        if (!ref[i].seen) fprintf(stderr, "    COVERAGE.md: \"%s\" is in neither list\n", ref[i].name);
        WT_ASSERT(ref[i].seen);
        total += ref[i].devices;
    }
    WT_EQ(have + pending, nref);
    WT_ASSERT(have > 0 && pending >= 0 && have_devices <= total);
}

void run_vendorkb_tests(void) {
    WT_RUN(test_every_entry_is_complete_and_cited);
    WT_RUN(test_every_entry_names_an_ieee_vendor);
    WT_RUN(test_find_folds_spelling);
    WT_RUN(test_drawer_and_lookup_carry_the_section);
    WT_RUN(test_page_shows_research_as_text);
    WT_RUN(test_coverage_matches_reference_and_entries);
}
