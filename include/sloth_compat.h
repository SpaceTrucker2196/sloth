#ifndef SLOTH_COMPAT_H
#define SLOTH_COMPAT_H

/* Compile-time assertion for C99 (#117).
 *
 * _Static_assert is C11; under -std=c99 -Wpedantic it warns, and the
 * build is held to C99 with no ungated extensions. The negative-size
 * array is the portable C99 form: a false condition is a hard error at
 * the line that states it. `tag` must be a valid identifier unique in
 * its file scope, because C99 forbids redeclaring a typedef and the tag
 * is what names the failure in the compiler's message.
 *
 * File scope only. Inside a function an unused local typedef warns
 * under -Wextra, and every call site in the tree is a table definition
 * at file scope anyway. */
#define SLOTH_STATIC_ASSERT(cond, tag) \
    typedef char sloth_static_assert_##tag[(cond) ? 1 : -1]

#endif /* SLOTH_COMPAT_H */
