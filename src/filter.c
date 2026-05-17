#include <ctype.h>
#include <string.h>
#include "filter.h"

static int ci_substr(const char *needle, const char *haystack) {
    if (!needle || !needle[0]) return 1;
    if (!haystack || !haystack[0]) return 0;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        size_t j = 0;
        while (j < nlen && tolower((unsigned char)haystack[i + j]) ==
                            tolower((unsigned char)needle[j]))
            j++;
        if (j == nlen) return 1;
    }
    return 0;
}

int filter_match(const char *needle, const char *haystack) {
    return ci_substr(needle, haystack);
}

int filter_match_any(const char *needle,
                     const char *a, const char *b, const char *c,
                     const char *d, const char *e) {
    if (!needle || !needle[0]) return 1;
    if (ci_substr(needle, a)) return 1;
    if (ci_substr(needle, b)) return 1;
    if (ci_substr(needle, c)) return 1;
    if (ci_substr(needle, d)) return 1;
    if (ci_substr(needle, e)) return 1;
    return 0;
}
