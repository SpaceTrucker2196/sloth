#include "web_chmix.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"

void web_mix_mac_text(const uint8_t mac[6], char *out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int web_mix_mac_bytes(const char *s, uint8_t mac[6]) {
    if (!s || strlen(s) != 17) return -1;
    for (int i = 0; i < 6; i++) {
        int a = hexv((unsigned char)s[i * 3]), b = hexv((unsigned char)s[i * 3 + 1]);
        if (a < 0 || b < 0 || (i < 5 && s[i * 3 + 2] != ':')) return -1;
        mac[i] = (uint8_t)(a << 4 | b);
    }
    return 0;
}

int web_chmix_init(web_chmix_t *c, int store_on) {
    memset(c, 0, sizeof(*c));
    c->store_on = store_on;
    c->ring = calloc(WEB_CHMIX_RING, sizeof(*c->ring));
    c->queue = store_on ? calloc(WEB_CHMIX_QUEUE, sizeof(*c->queue)) : NULL;
    if (!c->ring || (store_on && !c->queue)) {
        free(c->ring);
        free(c->queue);
        c->ring = c->queue = NULL;
        return -1;
    }
    pthread_mutex_init(&c->mu, NULL);
    c->st.ring_oldest = -1;
    return 0;
}

void web_chmix_destroy(web_chmix_t *c) {
    if (!c->ring) return;
    pthread_mutex_destroy(&c->mu);
    free(c->ring);
    free(c->queue);
    c->ring = c->queue = NULL;
}

/* Frames first, then the MAC, so a tie is cut the same way every time. */
static int by_frames(const void *a, const void *b) {
    const web_mix_tx_t *x = a, *y = b;
    if (x->frames != y->frames) return x->frames > y->frames ? -1 : 1;
    int m = memcmp(x->mac, y->mac, 6);
    if (m) return m;
    return (int)x->kind - (int)y->kind;
}

static uint32_t sat_add(uint32_t a, uint32_t b) {
    return a > 0xffffffffu - b ? 0xffffffffu : a + b;
}

static void push_ring(web_chmix_t *c, const web_mix_row_t *r) {
    size_t at = (c->ring_head + c->ring_n) % WEB_CHMIX_RING;
    if (c->ring_n == WEB_CHMIX_RING) {
        c->ring_head = (c->ring_head + 1) % WEB_CHMIX_RING;
        c->st.ring_overwritten++;
    } else {
        c->ring_n++;
    }
    c->ring[at] = *r;
}

static void push_queue(web_chmix_t *c, const web_mix_row_t *r) {
    if (!c->queue) return;
    if (c->q_n == WEB_CHMIX_QUEUE) {
        c->q_head = (c->q_head + 1) % WEB_CHMIX_QUEUE;
        c->q_n--;
        c->st.queue_dropped++;
    }
    c->queue[(c->q_head + c->q_n) % WEB_CHMIX_QUEUE] = *r;
    c->q_n++;
}

/* Close one open bucket: the top transmitters stay named, the rest
 * join "other". */
static void close_acc(web_chmix_t *c, web_mix_chan_t *ch, int tier) {
    web_mix_acc_t *a = &ch->open[tier];
    if (a->t < 0) return;
    web_mix_row_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.chan, ch->key, sizeof(r.chan));
    r.tier = tier;
    r.t = a->t;
    r.other = a->other;
    qsort(a->tx, (size_t)a->n, sizeof(a->tx[0]), by_frames);
    for (int i = 0; i < a->n; i++) {
        if (i < WEB_CHMIX_TOP) r.tx[r.n++] = a->tx[i];
        else r.other = sat_add(r.other, a->tx[i].frames);
    }
    if (tier == WEB_TIER_FINE) push_ring(c, &r);
    else push_queue(c, &r);
    c->st.rows_closed[tier]++;
    a->t = -1;
    a->n = 0;
    a->other = 0;
}

static int tiers_kept(const web_chmix_t *c) {
    return c->store_on ? WEB_TIER_COUNT : 1;
}

static web_mix_chan_t *chan_of(web_chmix_t *c, const char *key, long long now) {
    web_mix_chan_t *free_slot = NULL, *lru = NULL;
    for (int i = 0; i < WEB_CHMIX_CHANNELS; i++) {
        web_mix_chan_t *ch = &c->ch[i];
        if (!ch->used) { if (!free_slot) free_slot = ch; continue; }
        if (!strcmp(ch->key, key)) return ch;
        if (!lru || ch->last_seen < lru->last_seen) lru = ch;
    }
    web_mix_chan_t *ch = free_slot;
    if (!ch) {
        ch = lru;
        for (int t = 0; t < WEB_TIER_COUNT; t++) close_acc(c, ch, t);
        c->st.channel_evictions++;
    }
    memset(ch, 0, sizeof(*ch));
    ch->used = 1;
    snprintf(ch->key, sizeof(ch->key), "%s", key);
    ch->last_seen = now;
    for (int t = 0; t < WEB_TIER_COUNT; t++) ch->open[t].t = -1;
    return ch;
}

static void acc_add(web_chmix_t *c, web_mix_acc_t *a, const uint8_t mac[6],
                    int kind, uint32_t f) {
    for (int i = 0; i < a->n; i++)
        if (a->tx[i].kind == kind && !memcmp(a->tx[i].mac, mac, 6)) {
            a->tx[i].frames = sat_add(a->tx[i].frames, f);
            return;
        }
    if (a->n < WEB_CHMIX_TRACK) {
        web_mix_tx_t *e = &a->tx[a->n++];
        memcpy(e->mac, mac, 6);
        e->kind = (uint8_t)kind;
        e->frames = f;
        return;
    }
    /* Full: the quietest tracked transmitter goes to "other" in this
     * one's place only when this one already outweighs it. */
    int q = 0;
    for (int i = 1; i < a->n; i++)
        if (a->tx[i].frames < a->tx[q].frames) q = i;
    c->st.folded++;
    if (f > a->tx[q].frames) {
        a->other = sat_add(a->other, a->tx[q].frames);
        memcpy(a->tx[q].mac, mac, 6);
        a->tx[q].kind = (uint8_t)kind;
        a->tx[q].frames = f;
    } else {
        a->other = sat_add(a->other, f);
    }
}

void web_chmix_add(web_chmix_t *c, const char *chan, const uint8_t mac[6],
                   int kind, double frames, long long now_s) {
    if (!c || !c->ring || !chan || !chan[0] || strlen(chan) > WEB_CHMIX_KEY_MAX)
        return;
    if (!isfinite(frames) || frames < 0.5) return;
    if (kind != WEB_TX_AP && kind != WEB_TX_CLIENT) return;
    uint32_t f = frames >= 4294967295.0 ? 0xffffffffu : (uint32_t)(frames + 0.5);
    pthread_mutex_lock(&c->mu);
    web_mix_chan_t *ch = chan_of(c, chan, now_s);
    if (now_s > ch->last_seen) ch->last_seen = now_s;
    for (int t = 0; t < tiers_kept(c); t++) {
        long long step = web_tier_step(t);
        long long b = now_s - ((now_s % step) + step) % step;
        web_mix_acc_t *a = &ch->open[t];
        if (a->t >= 0 && a->t != b) close_acc(c, ch, t);
        if (a->t < 0) a->t = b;
        acc_add(c, a, mac, kind, f);
    }
    c->st.samples++;
    pthread_mutex_unlock(&c->mu);
}

void web_chmix_name(web_chmix_t *c, const uint8_t mac[6], const char *ssid,
                    long long now_s) {
    if (!c || !c->ring || !ssid) return;
    pthread_mutex_lock(&c->mu);
    web_mix_name_t *slot = NULL;
    for (int i = 0; i < WEB_CHMIX_NAMES; i++) {
        web_mix_name_t *n = &c->names[i];
        if (n->used && !memcmp(n->mac, mac, 6)) { slot = n; break; }
        if (!slot || (slot->used && (!n->used || n->seen < slot->seen))) slot = n;
    }
    memcpy(slot->mac, mac, 6);
    slot->used = 1;
    slot->seen = now_s;
    web_utf8_copy(slot->ssid, WEB_CHMIX_SSID_MAX, ssid);
    pthread_mutex_unlock(&c->mu);
}

int web_chmix_ssid(web_chmix_t *c, const uint8_t mac[6], char *out) {
    int found = 0;
    out[0] = '\0';
    if (!c || !c->ring) return 0;
    pthread_mutex_lock(&c->mu);
    for (int i = 0; i < WEB_CHMIX_NAMES && !found; i++)
        if (c->names[i].used && !memcmp(c->names[i].mac, mac, 6)) {
            memcpy(out, c->names[i].ssid, sizeof(c->names[i].ssid));
            found = 1;
        }
    pthread_mutex_unlock(&c->mu);
    return found;
}

void web_chmix_close_due(web_chmix_t *c, long long now_s) {
    if (!c || !c->ring) return;
    pthread_mutex_lock(&c->mu);
    for (int i = 0; i < WEB_CHMIX_CHANNELS; i++) {
        web_mix_chan_t *ch = &c->ch[i];
        if (!ch->used) continue;
        for (int t = 0; t < WEB_TIER_COUNT; t++)
            if (ch->open[t].t >= 0 && ch->open[t].t + web_tier_step(t) <= now_s)
                close_acc(c, ch, t);
    }
    pthread_mutex_unlock(&c->mu);
}

void web_chmix_close_all(web_chmix_t *c) {
    if (!c || !c->ring) return;
    pthread_mutex_lock(&c->mu);
    for (int i = 0; i < WEB_CHMIX_CHANNELS; i++)
        if (c->ch[i].used)
            for (int t = 0; t < WEB_TIER_COUNT; t++) close_acc(c, &c->ch[i], t);
    pthread_mutex_unlock(&c->mu);
}

size_t web_chmix_take(web_chmix_t *c, web_mix_row_t *out, size_t max) {
    if (!c || !c->queue) return 0;
    pthread_mutex_lock(&c->mu);
    size_t n = 0;
    while (n < max && c->q_n) {
        out[n++] = c->queue[c->q_head];
        c->q_head = (c->q_head + 1) % WEB_CHMIX_QUEUE;
        c->q_n--;
    }
    pthread_mutex_unlock(&c->mu);
    return n;
}

int web_chmix_each_fine(web_chmix_t *c, long long from, long long to,
                        web_mix_row_fn fn, void *ctx) {
    if (!c || !c->ring) return 0;
    int n = 0;
    pthread_mutex_lock(&c->mu);
    for (size_t i = 0; i < c->ring_n; i++) {
        const web_mix_row_t *r = &c->ring[(c->ring_head + i) % WEB_CHMIX_RING];
        if (r->t < from || r->t >= to) continue;
        n++;
        if (fn(ctx, r)) break;
    }
    pthread_mutex_unlock(&c->mu);
    return n;
}

void web_chmix_stats(web_chmix_t *c, web_chmix_stats_t *out) {
    memset(out, 0, sizeof(*out));
    out->ring_oldest = -1;
    if (!c || !c->ring) return;
    pthread_mutex_lock(&c->mu);
    *out = c->st;
    out->ring_rows = c->ring_n;
    out->queue_rows = c->q_n;
    out->ring_oldest = c->ring_n ? c->ring[c->ring_head].t : -1;
    for (int i = 0; i < WEB_CHMIX_CHANNELS; i++) out->channels += c->ch[i].used;
    pthread_mutex_unlock(&c->mu);
}
