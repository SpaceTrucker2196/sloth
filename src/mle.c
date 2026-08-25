#include <string.h>
#include <pthread.h>

#include "mle.h"

static sloth_mld_t     g_mld[SLOTH_MLD_MAX];
static int             g_mld_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static int mac_is_usable(const uint8_t m[6]) {
    if (m[0] & 0x01) return 0;
    for (int i = 0; i < 6; i++) if (m[i]) return 1;
    return 0;
}

int mle_parse(const uint8_t *ie_body, int len, sloth_mld_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    /* ExtID(1) + Control(2) + CommonInfoLen(1) + MLD MAC(6) */
    if (!ie_body || len < 10) return 0;
    if (ie_body[0] != MLE_EXT_ID) return 0;

    uint16_t ctl  = (uint16_t)(ie_body[1] | (ie_body[2] << 8));
    int      type = ctl & 0x0007;
    /* Only the Basic variant carries an MLD MAC in this position. The
     * other variants share the container and mean different things;
     * reading one as Basic takes an "MLD address" from a field that is
     * not one, which is worse than not decoding it at all. */
    if (type != MLE_TYPE_BASIC) return 0;

    /* Presence bit 4 (Control bit 4) is MLD MAC Address Present. The
     * Basic variant effectively always sets it, but a frame that does
     * not is one we cannot take an identity from. */
    if (!(ctl & 0x0010)) return 0;

    int common_off = 3;                 /* after ExtID + Control */
    int common_len = ie_body[common_off];
    /* The length covers itself, so it must at least hold itself plus
     * the MLD MAC. */
    if (common_len < 7) return 0;
    if (common_off + common_len > len) return 0;

    memcpy(out->mld_mac, ie_body + common_off + 1, 6);
    if (!mac_is_usable(out->mld_mac)) return 0;

    /* Link Info starts where Common Info ends. Using the declared
     * length rather than summing the optional fields present means a
     * later amendment adding one does not silently shift every link
     * address that follows. */
    int off = common_off + common_len;

    while (off + 2 <= len) {
        uint8_t sid  = ie_body[off];
        uint8_t slen = ie_body[off + 1];
        if (off + 2 + (int)slen > len) break;
        if (sid == MLE_SUBELEM_PER_STA && slen >= 3) {
            const uint8_t *p = ie_body + off + 2;
            /* STA Control(2): bits 0-3 Link ID, bit 5 MAC Address
             * Present. Then STA Info Length(1), then the affiliated
             * address when present. */
            uint16_t sc = (uint16_t)(p[0] | (p[1] << 8));
            int link_id = sc & 0x000f;
            int mac_present = (sc & 0x0020) != 0;
            int info_len = p[2];
            if (mac_present && info_len >= 7 && slen >= 3 + 6) {
                const uint8_t *lm = p + 3;
                if (mac_is_usable(lm)) {
                    if (out->link_count < SLOTH_MLD_MAX_LINKS) {
                        memcpy(out->link_mac[out->link_count], lm, 6);
                        out->link_id[out->link_count] = (uint8_t)link_id;
                        out->link_count++;
                    } else {
                        out->links_truncated = 1;
                    }
                }
            }
        }
        off += 2 + slen;
    }
    return 1;
}

void mle_observe(const sloth_mld_t *m, time_t now) {
    if (!m || !mac_is_usable(m->mld_mac)) return;
    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_mld_n; i++)
        if (memcmp(g_mld[i].mld_mac, m->mld_mac, 6) == 0) { idx = i; break; }
    if (idx < 0) {
        if (g_mld_n < SLOTH_MLD_MAX) {
            idx = g_mld_n++;
        } else {
            idx = 0;
            for (int i = 1; i < SLOTH_MLD_MAX; i++)
                if (g_mld[i].last_seen < g_mld[idx].last_seen) idx = i;
        }
        memset(&g_mld[idx], 0, sizeof(g_mld[idx]));
        memcpy(g_mld[idx].mld_mac, m->mld_mac, 6);
        g_mld[idx].first_seen = now;
    }
    sloth_mld_t *e = &g_mld[idx];
    e->last_seen = now;

    /* Merge rather than replace. A device advertises different subsets
     * of its links depending on which band the frame was heard on, so
     * replacing would make the link set flap and the canonical lookup
     * intermittent — which is worse than not having it. */
    for (int i = 0; i < m->link_count; i++) {
        int known = 0;
        for (int j = 0; j < e->link_count; j++)
            if (memcmp(e->link_mac[j], m->link_mac[i], 6) == 0) { known = 1; break; }
        if (known) continue;
        if (e->link_count < SLOTH_MLD_MAX_LINKS) {
            memcpy(e->link_mac[e->link_count], m->link_mac[i], 6);
            e->link_id[e->link_count] = m->link_id[i];
            e->link_count++;
        } else {
            e->links_truncated = 1;
        }
    }
    if (m->links_truncated) e->links_truncated = 1;

    pthread_mutex_unlock(&g_mu);
}

int mle_canonical(const uint8_t mac[6], uint8_t out[6]) {
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_mld_n && !hit; i++) {
        /* The MLD address itself resolves to itself — a caller that
         * already has the canonical form must not be told there is no
         * mapping and fall back to a seqnum guess. */
        if (memcmp(g_mld[i].mld_mac, mac, 6) == 0) hit = 1;
        for (int j = 0; !hit && j < g_mld[i].link_count; j++)
            if (memcmp(g_mld[i].link_mac[j], mac, 6) == 0) hit = 1;
        if (hit && out) memcpy(out, g_mld[i].mld_mac, 6);
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

void mle_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    int n = g_mld_n;
    memcpy(s->mlds, g_mld, (size_t)n * sizeof(g_mld[0]));
    s->mld_count = n;
    pthread_mutex_unlock(&g_mu);
}

int mle_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_mld_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void mle_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_mld, 0, sizeof(g_mld));
    g_mld_n = 0;
    pthread_mutex_unlock(&g_mu);
}
