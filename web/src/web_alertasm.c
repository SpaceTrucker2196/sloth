#include "web_alertasm.h"

#include <stddef.h>
#include <string.h>

const web_asm_t *web_asm_get(long long type) {
    if (type < 0 || type >= web_asm_ntypes) return NULL;
    int i = web_asm_by_type[type];
    return i >= 0 && i < web_asm_n ? &web_asm[i] : NULL;
}

const char *web_asm_fm(const web_asm_t *a, const char *key) {
    if (!a || !key) return NULL;
    for (int i = 0; i < a->nfm; i++)
        if (!strcmp(a->fm_k[i], key)) return a->fm_v[i];
    return NULL;
}
