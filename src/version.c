/* Semver parse + compare — companion to SLOTH_VERSION.
 * See src/version.h for scope; roadmap: docs/wiki/version-checkin.md. */

#include <ctype.h>
#include <string.h>
#include "version.h"

/* Parse a run of ASCII digits into *val. Returns the number of chars
 * consumed, or 0 on empty / non-numeric input. */
static int parse_uint(const char *s, int *val) {
    int n = 0;
    int v = 0;
    while (s[n] >= '0' && s[n] <= '9') {
        /* clamp to something sane; sloth won't hit MAJOR.MINOR.PATCH
         * bigger than a few hundred in this century. */
        if (v > 1000000) return 0;
        v = v * 10 + (s[n] - '0');
        n++;
    }
    if (n == 0) return 0;
    *val = v;
    return n;
}

int semver_parse(const char *s, semver_t *out) {
    if (!s || !out) return 0;
    memset(out, 0, sizeof(*out));

    /* Strip leading 'v' or 'V' — git tags use this convention. */
    if (*s == 'v' || *s == 'V') s++;

    int n = parse_uint(s, &out->major);
    if (n == 0 || s[n] != '.') return 0;
    s += n + 1;

    n = parse_uint(s, &out->minor);
    if (n == 0 || s[n] != '.') return 0;
    s += n + 1;

    n = parse_uint(s, &out->patch);
    if (n == 0) return 0;
    s += n;

    /* Optional pre-release suffix: "-<tag>". Terminates on '+' (build
     * metadata, which we drop per semver 2.0) or end-of-string. */
    if (*s == '-') {
        out->has_prerelease = 1;
        s++;
        size_t i = 0;
        while (*s && *s != '+' && i + 1 < sizeof(out->prerelease)) {
            out->prerelease[i++] = *s++;
        }
        out->prerelease[i] = '\0';
        if (i == 0) return 0;   /* trailing "-" with no tag is malformed */
    }

    /* Any remaining characters must be a build-metadata "+…" chunk. */
    if (*s == '+') return 1;
    return (*s == '\0');
}

int semver_cmp(const semver_t *a, const semver_t *b) {
    if (a->major != b->major) return a->major - b->major;
    if (a->minor != b->minor) return a->minor - b->minor;
    if (a->patch != b->patch) return a->patch - b->patch;

    /* Prerelease sorts strictly less than the base release. */
    if (a->has_prerelease && !b->has_prerelease) return -1;
    if (!a->has_prerelease &&  b->has_prerelease) return  1;
    if (!a->has_prerelease && !b->has_prerelease) return  0;

    /* Both have prerelease tags — compare lexically. */
    return strcmp(a->prerelease, b->prerelease);
}
