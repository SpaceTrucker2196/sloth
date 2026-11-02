#include "web_btsig.h"

extern const web_btsig_tab_t web_btsig_generated;

const web_btsig_tab_t *web_btsig_builtin(void) { return &web_btsig_generated; }

static const char *find(const web_btsig_tab_t *t, const web_btsig_ent_t *e,
                        size_t n, long long v) {
    if (!t || !e || v < 0 || v > 0xffff) return NULL;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (e[mid].value == (uint16_t)v)
            return e[mid].name < t->nnames ? t->names[e[mid].name] : NULL;
        if (e[mid].value < (uint16_t)v) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

const char *web_btsig_company(const web_btsig_tab_t *t, long long id) {
    return t ? find(t, t->company, t->ncompany, id) : NULL;
}

const char *web_btsig_service(const web_btsig_tab_t *t, long long uuid16) {
    return t ? find(t, t->service, t->nservice, uuid16) : NULL;
}

const char *web_btsig_appearance(const web_btsig_tab_t *t, long long value) {
    return t ? find(t, t->appearance, t->nappearance, value) : NULL;
}
