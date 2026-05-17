#ifndef FILTER_H
#define FILTER_H

/* Case-insensitive substring match.
 *   - empty or NULL needle: always matches
 *   - empty or NULL haystack with non-empty needle: never matches */
int filter_match(const char *needle, const char *haystack);

/* Match against any of up to 5 fields, NULL-terminated.
 * Variadic NULL-terminated would be cleaner but harder to use safely. */
int filter_match_any(const char *needle,
                     const char *a, const char *b, const char *c,
                     const char *d, const char *e);

#endif /* FILTER_H */
