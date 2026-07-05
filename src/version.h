#ifndef VERSION_H
#define VERSION_H

/* Minimal semver parse + compare, matching the shape sloth uses in
 * SLOTH_VERSION and the git tag scheme (`vMAJOR.MINOR.PATCH`).
 *
 * Scope for the first landing: MAJOR.MINOR.PATCH only. Prerelease
 * tags ("-rc1", "-beta.2") parse cleanly but sort strictly less than
 * their base release, which is enough to keep "1.4.0" > "1.4.0-rc1"
 * without hauling in the full semver 2.0 grammar. Build-metadata
 * ("+deadbeef") is ignored during comparison, matching semver 2.0.
 *
 * All functions are pure and thread-safe. */

typedef struct {
    int  major;
    int  minor;
    int  patch;
    int  has_prerelease;   /* 1 if the version had a "-…" tail */
    char prerelease[32];   /* the tail without the leading '-' */
} semver_t;

/* Parse "1.4.0", "v1.4.0", or "1.4.0-rc1" into *out. Returns 1 on
 * success, 0 on any parse failure (missing components, non-numeric
 * fields, buffer overflow). A leading 'v' or 'V' is stripped. */
int semver_parse(const char *s, semver_t *out);

/* Compare two parsed semvers. Returns <0 if a<b, 0 if equal, >0 if
 * a>b. Prerelease-tagged versions sort strictly less than their base
 * release ("1.4.0-rc1" < "1.4.0"). Prerelease strings themselves are
 * compared with strcmp — sufficient for typical "rcN" / "betaN" tags
 * where N is the same width. */
int semver_cmp(const semver_t *a, const semver_t *b);

#endif /* VERSION_H */
