/* Build-time generator for slothweb's GNSS vehicle table (2026-11-05,
 * web/src/web_gnssmeta.h): reads the IGS satellite metadata SINEX file
 * committed in web/data/gnss/ (web/data/gnss/SOURCE.md) and writes a C
 * file with three tables:
 *
 *   SATELLITE/IDENTIFIER  one vehicle per SVN: COSPAR ID, satellite
 *                         catalogue (NORAD) number, block, and the
 *                         comment's launch date and name
 *   SATELLITE/PRN         which vehicle transmitted which PRN when
 *   SATELLITE/PLANE       its orbital plane and slot when
 *
 * Format: Steigenberger P, Montenbruck O (2024) IGS Satellite Metadata
 * File Description, Version 1.10, doi:10.57677/metadata-sinex. Times
 * are YYYY:DDD:SSSSS (UTC; 0000:000:00000 open-ended). Fields are
 * whitespace-separated in the blocks read here; anything that does not
 * parse fails the build naming the line, rather than shipping a table
 * that quietly names the wrong satellite.
 *
 *   gnssmeta_gen OUT.c [IGS.snx]
 *
 * Without the input it writes empty tables (release "none"). Never
 * fetches anything. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VEH   1024
#define MAX_ROWS  4096
#define LINE_MAX_ 512

typedef struct {
    char svn[8], cospar[16], block[24], name[48], launched[12];
    long satcat;
} veh_t;
typedef struct { int veh; char sys; int num; long long from, to; } asg_t;
typedef struct { int veh; long long from, to; char plane[4], slot[8]; } pln_t;

static veh_t V[MAX_VEH];
static asg_t A[MAX_ROWS];
static pln_t P[MAX_ROWS];
static int nv, na, np;
static char release[32] = "none";

static void die(const char *what, int line) {
    fprintf(stderr, "gnssmeta_gen: %s (line %d)\n", what, line);
    exit(1);
}

/* Days from 1970-01-01 to y-01-01 (proleptic Gregorian). */
static long long days_to_year(int y) {
    long long d = 0;
    for (int i = 1970; i < y; i++)
        d += (i % 4 == 0 && (i % 100 != 0 || i % 400 == 0)) ? 366 : 365;
    return d;
}

/* YYYY:DDD:SSSSS to unix seconds; 0000:000:00000 open (a far future). */
static int sinex_time(const char *s, long long *out) {
    int y, d, sec;
    if (strlen(s) != 14 || s[4] != ':' || s[8] != ':') return -1;
    for (int i = 0; i < 14; i++)
        if (i != 4 && i != 8 && !isdigit((unsigned char)s[i])) return -1;
    if (sscanf(s, "%4d:%3d:%5d", &y, &d, &sec) != 3) return -1;
    if (y == 0 && d == 0 && sec == 0) { *out = 1LL << 40; return 0; }
    if (y < 1970 || y > 2999 || d < 1 || d > 366 || sec > 86400) return -1;
    *out = (days_to_year(y) + d - 1) * 86400LL + sec;
    return 0;
}

static int find_veh(const char *svn) {
    for (int i = 0; i < nv; i++) if (!strcmp(V[i].svn, svn)) return i;
    return -1;
}

static int svn_ok(const char *s) {
    if (strlen(s) != 4 || !strchr("GRECJI", s[0])) return 0;
    for (int i = 1; i < 4; i++) if (!isdigit((unsigned char)s[i])) return 0;
    return 1;
}

/* Copy src (printable ASCII only, else the build fails) into dst. */
static void take(char *dst, size_t cap, const char *src, int line) {
    size_t n = strlen(src);
    if (n >= cap) die("field too long", line);
    for (size_t i = 0; i < n; i++)
        if (src[i] < 0x20 || src[i] > 0x7e || src[i] == '"' || src[i] == '\\')
            die("field not plain printable ASCII", line);
    memcpy(dst, src, n + 1);
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = '\0';
}

static void identifier(char *ln, int line) {
    char svn[16], cospar[24], block[40];
    long satcat;
    int used = 0;
    if (sscanf(ln, " %15s %23s %ld %39s %n", svn, cospar, &satcat, block, &used) != 4)
        die("SATELLITE/IDENTIFIER row does not parse", line);
    if (!svn_ok(svn)) die("bad SVN", line);
    if (nv >= MAX_VEH) die("too many vehicles", line);
    veh_t *v = &V[nv++];
    memset(v, 0, sizeof(*v));
    take(v->svn, sizeof(v->svn), svn, line);
    take(v->cospar, sizeof(v->cospar), cospar, line);
    take(v->block, sizeof(v->block), block, line);
    v->satcat = satcat;
    /* "Launched 2009-08-17; NAVSTAR 64": the date, then the name. */
    char *c = ln + used;
    trim(c);
    if (!strncmp(c, "Launched ", 9) && strlen(c) >= 19) {
        char d[12];
        memcpy(d, c + 9, 10);
        d[10] = '\0';
        take(v->launched, sizeof(v->launched), d, line);
        c += 19;
        if (*c == ';') c++;
        while (*c == ' ') c++;
    }
    if (strlen(c) >= sizeof(v->name)) c[sizeof(v->name) - 1] = '\0';
    trim(c);
    take(v->name, sizeof(v->name), c, line);
}

static void prn_row(char *ln, int line) {
    char svn[16], f[24], t[24], prn[16];
    if (sscanf(ln, " %15s %23s %23s %15s", svn, f, t, prn) != 4)
        die("SATELLITE/PRN row does not parse", line);
    int vi = find_veh(svn);
    if (vi < 0) die("PRN row names an SVN with no IDENTIFIER row", line);
    if (strlen(prn) != 3 || prn[0] != svn[0] || !isdigit((unsigned char)prn[1]) ||
        !isdigit((unsigned char)prn[2]))
        die("bad PRN", line);
    if (na >= MAX_ROWS) die("too many PRN rows", line);
    asg_t *a = &A[na++];
    a->veh = vi;
    a->sys = prn[0];
    a->num = atoi(prn + 1);
    if (sinex_time(f, &a->from) || sinex_time(t, &a->to)) die("bad time", line);
}

static void plane_row(char *ln, int line) {
    char svn[16], f[24], t[24], pl[8], slot[16];
    if (sscanf(ln, " %15s %23s %23s %7s %15s", svn, f, t, pl, slot) != 5)
        die("SATELLITE/PLANE row does not parse", line);
    int vi = find_veh(svn);
    if (vi < 0) return;   /* a plane for a vehicle never identified: unused */
    if (np >= MAX_ROWS) die("too many PLANE rows", line);
    pln_t *p = &P[np++];
    p->veh = vi;
    if (sinex_time(f, &p->from) || sinex_time(t, &p->to)) die("bad time", line);
    take(p->plane, sizeof(p->plane), pl, line);
    take(p->slot, sizeof(p->slot), slot, line);
}

static void read_snx(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    char ln[LINE_MAX_];
    int line = 0, block = 0;   /* 1 identifier, 2 prn, 3 plane */
    while (fgets(ln, sizeof(ln), f)) {
        line++;
        if (!strncmp(ln, " DESCRIPTION", 12)) {
            const char *r = strstr(ln, "release ");
            if (r) {
                int k = 0;
                r += 8;
                while (isdigit((unsigned char)r[k]) && k < 16) k++;
                if (k) { memcpy(release, r, (size_t)k); release[k] = '\0'; }
            }
        }
        if (ln[0] == '+') {
            block = !strncmp(ln, "+SATELLITE/IDENTIFIER", 21) ? 1
                  : !strncmp(ln, "+SATELLITE/PRN", 14) ? 2
                  : !strncmp(ln, "+SATELLITE/PLANE", 16) ? 3 : 0;
            continue;
        }
        if (ln[0] == '-') { block = 0; continue; }
        if (!block || ln[0] == '*') continue;
        trim(ln);
        if (!ln[0]) continue;
        if (block == 1) identifier(ln, line);
        else if (block == 2) prn_row(ln, line);
        else plane_row(ln, line);
    }
    fclose(f);
    /* PLANE precedes PRN in the file but needs only IDENTIFIER, which
     * precedes both; a file in another order fails above by name. */
    if (!nv || !na) die("no IDENTIFIER or PRN rows", line);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: gnssmeta_gen OUT.c [IGS.snx]\n");
        return 2;
    }
    if (argc == 3) read_snx(argv[2]);
    FILE *o = fopen(argv[1], "w");
    if (!o) { perror(argv[1]); return 1; }
    fprintf(o, "/* Generated by web/tools/gnssmeta_gen.c from %s. Do not edit. */\n",
            argc == 3 ? argv[2] : "(no input)");
    fprintf(o, "#include \"web_gnssmeta.h\"\n\n");
    fprintf(o, "const char web_gnssmeta_release[] = \"%s\";\n", release);
    fprintf(o, "const web_gnss_veh_t web_gnss_vehs[] = {\n");
    for (int i = 0; i < nv; i++)
        fprintf(o, "    { \"%s\", \"%s\", %ld, \"%s\", \"%s\", \"%s\" },\n", V[i].svn,
                V[i].cospar, V[i].satcat, V[i].block, V[i].name, V[i].launched);
    if (!nv) fprintf(o, "    { \"\", \"\", 0, \"\", \"\", \"\" },\n");
    fprintf(o, "};\nconst int web_gnss_vehs_n = %d;\n", nv);
    fprintf(o, "const web_gnss_asg_t web_gnss_asgs[] = {\n");
    for (int i = 0; i < na; i++)
        fprintf(o, "    { %d, '%c', %d, %lldLL, %lldLL },\n", A[i].veh, A[i].sys, A[i].num,
                A[i].from, A[i].to);
    if (!na) fprintf(o, "    { 0, 0, 0, 0, 0 },\n");
    fprintf(o, "};\nconst int web_gnss_asgs_n = %d;\n", na);
    fprintf(o, "const web_gnss_plane_t web_gnss_planes[] = {\n");
    for (int i = 0; i < np; i++)
        fprintf(o, "    { %d, %lldLL, %lldLL, \"%s\", \"%s\" },\n", P[i].veh, P[i].from,
                P[i].to, P[i].plane, P[i].slot);
    if (!np) fprintf(o, "    { 0, 0, 0, \"\", \"\" },\n");
    fprintf(o, "};\nconst int web_gnss_planes_n = %d;\n", np);
    if (fclose(o) != 0) { perror(argv[1]); return 1; }
    return 0;
}
