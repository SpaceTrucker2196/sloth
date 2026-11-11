/* The triage store, the write path's checks, the ledger, the
 * assessment reader and the routes' dispatch (web_frrs.h). The record
 * is web_frrs_report.c's, the TACDB web_frrs_tacdb.c's. */
#include "web_frrs_int.h"
#include "web_agent.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "web_alertdb.h"
#include "web_alertkb.h"
#include "web_history.h"
#include "web_metrics.h"
#include "web_notes.h"
#include "web_scope.h"
#include "web_series.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/* ── words ──────────────────────────────────────────────────────────── */

static const char *const STATE_WORD[WEB_TRI_COUNT] = {
    "untriaged", "false", "noise", "incident", "known",
};
static const char *const VIA_WORD[WEB_TRI_VIA_COUNT] = { "manual", "recommended", "import", "agent" };
static const char *const KIND_WORD[FRRS_K_COUNT] = { "sta", "bssid", "ble" };

const char *web_frrs_state_word(int s) {
    return s >= 0 && s < WEB_TRI_COUNT ? STATE_WORD[s] : "untriaged";
}
const char *web_frrs_via_word(int v) {
    return v >= 0 && v < WEB_TRI_VIA_COUNT ? VIA_WORD[v] : "manual";
}
const char *frrs_kind_word(int k) {
    return k >= 0 && k < FRRS_K_COUNT ? KIND_WORD[k] : "sta";
}
int frrs_kind_find(const char *w) {
    for (int k = 0; w && k < FRRS_K_COUNT; k++) if (!strcmp(w, KIND_WORD[k])) return k;
    return -1;
}

int web_frrs_filter_find(const char *w) {
    if (!w) return WEB_TRI_F_BAD;
    if (!strcmp(w, "any")) return WEB_TRI_F_ANY;
    if (!strcmp(w, "triaged")) return WEB_TRI_F_TRIAGED;
    if (!strcmp(w, "out")) return WEB_TRI_F_OUT;
    for (int s = 0; s < WEB_TRI_COUNT; s++) if (!strcmp(w, STATE_WORD[s])) return s;
    return WEB_TRI_F_BAD;
}

int web_frrs_state_out(int state) {
    return state == WEB_TRI_FALSE || state == WEB_TRI_NOISE || state == WEB_TRI_KNOWN;
}

int web_frrs_filter_pass(int filter, int state) {
    if (filter == WEB_TRI_F_ANY) return 1;
    if (filter == WEB_TRI_F_TRIAGED) return state != WEB_TRI_UNTRIAGED;
    if (filter == WEB_TRI_F_OUT) return web_frrs_state_out(state);
    return filter == state;
}

/* ── small helpers ──────────────────────────────────────────────────── */

void frrs_str_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

int frrs_error(int status, const char *why, const char *member, char *body,
               size_t cap, size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, why);
    if (member) {
        /* A member name off the request: a word of ours when it is one
         * we know, else said as unknown without echoing it. */
        web_jw_raw(&w, ",\"member\":");
        web_jw_strn(&w, member, strnlen(member, 32));
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

int frrs_mac_in(const char *s, char out[18]) {
    if (!s) return 0;
    size_t n = strlen(s);
    for (size_t i = 0; i + 17 <= n; i++) {
        int ok = 1;
        for (int k = 0; k < 17 && ok; k++) {
            char c = s[i + (size_t)k];
            ok = (k % 3 == 2) ? c == ':' : hexv((unsigned char)c) >= 0;
        }
        /* Not the middle of a longer hex run (an IPv6 address). */
        if (ok && i + 17 < n && (hexv((unsigned char)s[i + 17]) >= 0 || s[i + 17] == ':')) ok = 0;
        if (ok && i > 0 && (hexv((unsigned char)s[i - 1]) >= 0 || s[i - 1] == ':')) ok = 0;
        if (ok) {
            char m[18];
            memcpy(m, s + i, 17);
            m[17] = '\0';
            if (web_key_mac(m, out) == 0) return 1;
        }
    }
    return 0;
}

int frrs_addr_canon(int k, const char *in, char *out, size_t outsz) {
    if (!in || outsz < 22) return -1;
    if (k == FRRS_K_BLE) {
        const char *sl = strchr(in, '/');
        if (!sl || sl - in != 17) return -1;
        char m[18], mm[WEB_KEY_MAX + 1];
        memcpy(m, in, 17);
        m[17] = '\0';
        /* A BLE address may be all zeros (an anonymous advertiser);
         * web_key_mac refuses that, so it is checked by hand. */
        if (web_key_mac(m, mm) != 0) {
            if (strcmp(m, "00:00:00:00:00:00")) return -1;
            memcpy(mm, m, 18);
        }
        const char *t = sl + 1;
        if (!strcmp(t, "0") || !strcmp(t, "1") || !strcmp(t, "2") || !strcmp(t, "3") ||
            !strcmp(t, "255")) {
            snprintf(out, outsz, "%.17s/%s", mm, t);
            return 0;
        }
        return -1;
    }
    char mm[WEB_KEY_MAX + 1];
    if (web_key_mac(in, mm) != 0) return -1;
    snprintf(out, outsz, "%.17s", mm);
    return 0;
}

int frrs_members_ok(const web_jrec_t *r, const char *const *allowed, const char **bad) {
    for (int i = 0; i < r->n; i++) {
        int ok = 0;
        for (int k = 0; allowed[k] && !ok; k++) ok = !strcmp(r->f[i].key, allowed[k]);
        if (!ok || r->f[i].kind == WEB_J_NEST) {
            *bad = r->f[i].key;
            return 0;
        }
    }
    return 1;
}

int frrs_text(const web_jrec_t *r, const char *name, size_t max, char *out,
              const char **why) {
    out[0] = '\0';
    const web_jfield_t *f = web_jl_get(r, name);
    if (!f || f->kind == WEB_J_NULL) return 1;
    if (f->kind != WEB_J_STR) { *why = "bad_text"; return 0; }
    if (f->slen > max) { *why = "too_long"; return 0; }
    const unsigned char *u = (const unsigned char *)f->str;
    for (size_t i = 0; i < f->slen; i++) {
        unsigned char c = u[i];
        if (c < 0x20 || c == 0x7f) { *why = "bad_text"; return 0; }
        /* The bidirectional embeddings and isolates, U+202A-U+202E
         * (E2 80 AA-AE) and U+2066-U+2069 (E2 81 A6-A9): invisible, they
         * reorder what follows them, so a note or a name could show a
         * reader text other than the bytes stored. Refused as a control
         * byte is. */
        if (c == 0xe2 && i + 2 < f->slen &&
            ((u[i + 1] == 0x80 && u[i + 2] >= 0xaa && u[i + 2] <= 0xae) ||
             (u[i + 1] == 0x81 && u[i + 2] >= 0xa6 && u[i + 2] <= 0xa9))) {
            *why = "bad_text";
            return 0;
        }
    }
    /* The decoder already refused ill-formed UTF-8, so a whole copy is
     * a valid one. */
    memcpy(out, f->str, f->slen);
    out[f->slen] = '\0';
    return 1;
}

/* ── the ledger ─────────────────────────────────────────────────────── */

/* The slot of key in a table of n (of cap) entries, the least recently
 * touched one taken when full (*evicted set). */
#define LRU_SLOT(arr, n, cap, field, key, evicted, clock) do {               \
        int at_ = -1, old_ = 0;                                              \
        for (int i_ = 0; i_ < (n); i_++) {                                   \
            if (!strcmp((arr)[i_].field, (key))) { at_ = i_; break; }        \
            if ((arr)[i_].touch < (arr)[old_].touch) old_ = i_;              \
        }                                                                    \
        if (at_ < 0) {                                                       \
            if ((n) < (cap)) at_ = (n)++;                                    \
            else { at_ = old_; (evicted) = 1; }                              \
            memset(&(arr)[at_], 0, sizeof((arr)[at_]));                      \
            snprintf((arr)[at_].field, sizeof((arr)[at_].field), "%s", (key)); \
        }                                                                    \
        (arr)[at_].touch = ++(clock);                                        \
        slot_ = at_;                                                         \
    } while (0)

static long long jint(const web_jrec_t *r, const char *k, long long def) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f) return def;
    if (f->kind == WEB_J_INT || f->kind == WEB_J_BOOL) return f->i;
    if (f->kind == WEB_J_REAL && isfinite(f->d) && f->d > -9e18 && f->d < 9e18)
        return (long long)f->d;
    return def;
}

static void jstr(const web_jrec_t *r, const char *k, char *out, size_t cap) {
    const char *s = web_jl_str(r, k);
    web_utf8_copy(out, cap - 1, s ? s : "");
}

/* A 64-bit hash as sloth wrote it: an integer, or a number too large
 * for one, kept as the text of a whole number; "" when neither. */
static void jhash(const web_jrec_t *r, const char *k, char *out, size_t cap) {
    const web_jfield_t *f = web_jl_get(r, k);
    out[0] = '\0';
    if (!f) return;
    if (f->kind == WEB_J_INT) snprintf(out, cap, "%lld", f->i);
    else if (f->kind == WEB_J_REAL && isfinite(f->d) && f->d >= 0 && f->d < 1.9e19)
        snprintf(out, cap, "%.0f", f->d);
}

static void jest(const web_jrec_t *r, frrs_est_t *e) {
    double m;
    memset(e, 0, sizeof(*e));
    if (!web_jl_num(r, "est_dist_m", &m)) return;
    e->have = 1;
    e->m = m;
    jstr(r, "est_dist_band", e->band, sizeof(e->band));
    jstr(r, "est_dist_trend", e->trend, sizeof(e->trend));
    jstr(r, "est_ptx_source", e->ptx, sizeof(e->ptx));
}

static unsigned long long fnv64(const char *s) {
    unsigned long long h = 1469598103934665603ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}

static frrs_bss_t *bss_slot(web_frrs_t *f, const char *mac) {
    struct web_frrs_led *L = f->led;
    int slot_ = 0, ev = 0;
    LRU_SLOT(L->bss, L->nbss, WEB_FRRS_LEDGER_BSSID, mac, mac, ev, L->clock);
    if (ev) f->st.ledger_evictions++;
    return &L->bss[slot_];
}

static frrs_sta_t *sta_slot(web_frrs_t *f, const char *mac) {
    struct web_frrs_led *L = f->led;
    int slot_ = 0, ev = 0;
    LRU_SLOT(L->sta, L->nsta, WEB_FRRS_LEDGER_STA, mac, mac, ev, L->clock);
    if (ev) f->st.ledger_evictions++;
    return &L->sta[slot_];
}

static frrs_ip_t *ip_slot(web_frrs_t *f, const char *ip) {
    struct web_frrs_led *L = f->led;
    int slot_ = 0, ev = 0;
    LRU_SLOT(L->ip, L->nip, WEB_FRRS_LEDGER_IP, ip, ip, ev, L->clock);
    if (ev) f->st.ledger_evictions++;
    return &L->ip[slot_];
}

static void led_beacon(web_frrs_t *f, const web_jrec_t *r, const char *mac, long long ts) {
    frrs_bss_t *b = bss_slot(f, mac);
    b->has_b = 1;
    b->ts_b = ts;
    b->channel = (int)jint(r, "channel", 0);
    b->primary_channel = (int)jint(r, "primary_channel", 0);
    b->secondary_offset = (int)jint(r, "secondary_offset", 0);
    b->operating_width = (int)jint(r, "operating_width", 0);
    b->channel_source = (int)jint(r, "channel_source", 0);
    b->beacon_ms = (int)jint(r, "beacon_ms", 0);
    b->signal_dbm = (int)jint(r, "signal_dbm", 0);
    b->has_rssi60 = web_jl_get(r, "rssi_min_60s") != NULL;
    b->rssi_min = (int)jint(r, "rssi_min_60s", 0);
    b->rssi_max = (int)jint(r, "rssi_max_60s", 0);
    jstr(r, "ssid", b->ssid, sizeof(b->ssid));
    jstr(r, "phy", b->phy, sizeof(b->phy));
    jstr(r, "enc", b->enc, sizeof(b->enc));
    jstr(r, "pairwise", b->pairwise, sizeof(b->pairwise));
    jstr(r, "group", b->group, sizeof(b->group));
    jstr(r, "akm", b->akm, sizeof(b->akm));
    b->akm_bits = jint(r, "akm_bits", 0);
    b->downgrade_flags = jint(r, "downgrade_flags", 0);
    b->fp_flags = jint(r, "fp_flags", 0);
    b->mfp = (int)jint(r, "mfp", -1);
    b->has_wps = (int)jint(r, "has_wps", 0);
    b->wps_state = (int)jint(r, "wps_state", 0);
    b->wps_locked = (int)jint(r, "wps_locked", 0);
    b->wps_config_methods = jint(r, "wps_config_methods", 0);
    b->wps_device_pwd_id = jint(r, "wps_device_pwd_id", 0);
    jstr(r, "wps_manufacturer", b->wps_manufacturer, sizeof(b->wps_manufacturer));
    jstr(r, "wps_model_name", b->wps_model_name, sizeof(b->wps_model_name));
    jstr(r, "wps_model_number", b->wps_model_number, sizeof(b->wps_model_number));
    jhash(r, "vendor_ies_hash", b->vendor_ies_hash, sizeof(b->vendor_ies_hash));
    jhash(r, "ie_order_hash", b->ie_order_hash, sizeof(b->ie_order_hash));
    b->ie_order_count = (int)jint(r, "ie_order_count", 0);
    b->tbtt_jitter_us = jint(r, "tbtt_jitter_us", 0);
    b->tbtt_jitter_samples = jint(r, "tbtt_jitter_samples", 0);
    jest(r, &b->est);
}

static void led_reg(web_frrs_t *f, const web_jrec_t *r, const char *mac, long long ts) {
    frrs_bss_t *b = bss_slot(f, mac);
    b->has_r = 1;
    b->ts_r = ts;
    b->country_present = (int)jint(r, "country_present", 0);
    jstr(r, "country", b->country, sizeof(b->country));
    jstr(r, "env", b->env, sizeof(b->env));
    b->triplets_truncated = (int)jint(r, "triplets_truncated", 0);
    b->power_constraint_present = (int)jint(r, "power_constraint_present", 0);
    b->power_constraint_db = (int)jint(r, "power_constraint_db", 0);
    b->tpc_present = (int)jint(r, "tpc_present", 0);
    b->tpc_tx_power_dbm = (int)jint(r, "tpc_tx_power_dbm", 0);
    b->tpc_link_margin_db = (int)jint(r, "tpc_link_margin_db", 0);
    b->he6_present = (int)jint(r, "he6_present", 0);
    jstr(r, "he6_reg_info_name", b->he6_name, sizeof(b->he6_name));
    b->malformed_country = jint(r, "malformed_country", 0);
}

static void led_mld(web_frrs_t *f, const web_jrec_t *r, const char *mac, long long ts) {
    frrs_bss_t *b = bss_slot(f, mac);
    b->has_m = 1;
    b->ts_m = ts;
    b->link_count = (int)jint(r, "link_count", 0);
    b->links_truncated = (int)jint(r, "links_truncated", 0);
    b->nlinks = 0;
    for (int i = 0; i < 16 && b->nlinks < WEB_FRRS_MLD_LINKS; i++) {
        char k[24], m[WEB_KEY_MAX + 1];
        snprintf(k, sizeof(k), "link_%d_mac", i);
        const char *v = web_jl_str(r, k);
        if (v && web_key_mac(v, m) == 0) snprintf(b->links[b->nlinks++], 18, "%.17s", m);
    }
}

static void led_assoc_req(web_frrs_t *f, const web_jrec_t *r, long long ts) {
    char sm[WEB_KEY_MAX + 1], bm[WEB_KEY_MAX + 1];
    if (web_key_mac(web_jl_str(r, "sta_mac"), sm) != 0) return;
    frrs_sta_t *s = sta_slot(f, sm);
    s->has_ar = 1;
    s->ts_ar = ts;
    if (web_key_mac(web_jl_str(r, "bssid"), bm) == 0) snprintf(s->ar_bssid, 18, "%.17s", bm);
    s->listen_interval = (int)jint(r, "listen_interval", 0);
    s->capability_info = jint(r, "capability_info", 0);
    s->akm_bits = jint(r, "akm_bits", 0);
    s->pairwise_bits = jint(r, "pairwise_bits", 0);
    s->requested_mfp = (int)jint(r, "requested_mfp", 0);
    s->supported_rates = jint(r, "supported_rates", 0);
    s->downgrade_flags = jint(r, "downgrade_flags", 0);
    jstr(r, "phy", s->ar_phy, sizeof(s->ar_phy));
    jhash(r, "vendor_ie_hash", s->ar_vie, sizeof(s->ar_vie));
}

static void led_probe(web_frrs_t *f, const web_jrec_t *r, const char *mac, long long ts) {
    frrs_sta_t *s = sta_slot(f, mac);
    s->has_p = 1;
    s->ts_p = ts;
    s->frame_count = jint(r, "frame_count", 0);
    s->burst_frames = jint(r, "burst_frames", 0);
    s->burst_span_ms = jint(r, "burst_span_ms", 0);
    s->flood = (int)jint(r, "flood", 0);
    s->signal_dbm = (int)jint(r, "signal_dbm", 0);
    s->channel = (int)jint(r, "channel", 0);
    jest(r, &s->est);
}

static void led_pnl(web_frrs_t *f, const web_jrec_t *r, const char *mac, long long ts) {
    frrs_sta_t *s = sta_slot(f, mac);
    s->has_pnl = 1;
    s->ts_pnl = ts;
    s->mac_random = (int)jint(r, "mac_random", 0);
    s->phy_confirmed = (int)jint(r, "phy_confirmed", 0);
    s->probe_count = jint(r, "probe_count", 0);
    jstr(r, "os_fp", s->os_fp, sizeof(s->os_fp));
    jstr(r, "phy", s->phy, sizeof(s->phy));
}

static void seq_note(frrs_sta_t *s, const char *other, const web_jrec_t *r, int earlier,
                     long long ts) {
    int at = -1;
    for (int i = 0; i < s->nseq; i++) if (!strcmp(s->seq[i].mac, other)) at = i;
    if (at < 0) {
        if (s->nseq < WEB_FRRS_SEQ_PARTNERS) at = s->nseq++;
        else {
            at = 0;
            for (int i = 1; i < s->nseq; i++) if (s->seq[i].ts < s->seq[at].ts) at = i;
        }
    }
    frrs_seq_t *q = &s->seq[at];
    snprintf(q->mac, sizeof(q->mac), "%s", other);
    q->confidence = (int)jint(r, "confidence", -1);
    q->fwd_gap = (int)jint(r, "fwd_gap", -1);
    q->gap = (int)jint(r, "gap", -1);
    q->window_start = jint(r, "window_start", 0);
    q->window_end = jint(r, "window_end", 0);
    q->earlier = earlier;
    q->ts = ts;
}

static void led_seq(web_frrs_t *f, const web_jrec_t *r, long long ts) {
    char a[WEB_KEY_MAX + 1], b[WEB_KEY_MAX + 1];
    if (web_key_mac(web_jl_str(r, "mac_a"), a) != 0 ||
        web_key_mac(web_jl_str(r, "mac_b"), b) != 0) return;
    int ae = (int)jint(r, "a_is_earlier", -1);
    seq_note(sta_slot(f, a), b, r, ae == 1, ts);
    seq_note(sta_slot(f, b), a, r, ae == 0, ts);
}

static void led_ble(web_frrs_t *f, const web_jrec_t *r, long long ts) {
    const char *a = web_jl_str(r, "addr");
    char m[WEB_KEY_MAX + 1];
    if (!a || strlen(a) != 17) return;
    if (web_key_mac(a, m) != 0) {
        if (strcmp(a, "00:00:00:00:00:00")) return;
        memcpy(m, a, 18);
    }
    int at = (int)jint(r, "addr_type", -1);
    if (at < 0 || at > 255) return;
    char iface[24];
    jstr(r, "iface", iface, sizeof(iface));
    struct web_frrs_led *L = f->led;
    int slot = -1, old = 0;
    for (int i = 0; i < L->nble; i++) {
        if (!strcmp(L->ble[i].addr, m) && L->ble[i].addr_type == at &&
            !strcmp(L->ble[i].iface, iface)) { slot = i; break; }
        if (L->ble[i].touch < L->ble[old].touch) old = i;
    }
    if (slot < 0) {
        if (L->nble < WEB_FRRS_LEDGER_BLE) slot = L->nble++;
        else { slot = old; f->st.ledger_evictions++; }
        memset(&L->ble[slot], 0, sizeof(L->ble[slot]));
        snprintf(L->ble[slot].addr, sizeof(L->ble[slot].addr), "%.17s", m);
        L->ble[slot].addr_type = at;
        snprintf(L->ble[slot].iface, sizeof(L->ble[slot].iface), "%s", iface);
    }
    frrs_ble_t *e = &L->ble[slot];
    e->touch = ++L->clock;
    e->ts = ts;
    e->adapter = (int)jint(r, "adapter", 0);
    e->sampled = (int)jint(r, "sampled", 0);
    e->channel = (int)jint(r, "channel", -1);
    jstr(r, "last_pdu", e->last_pdu, sizeof(e->last_pdu));
    e->pdu_mask = jint(r, "pdu_mask", 0);
    jstr(r, "name", e->name, sizeof(e->name));
    e->name_complete = (int)jint(r, "name_complete", 0);
    e->uuid16 = jint(r, "uuid16", -1);
    e->mfr_id = jint(r, "mfr_id", -1);
    e->mfr_subtype = jint(r, "mfr_subtype", -1);
    e->svc_data_uuid16 = jint(r, "svc_data_uuid16", -1);
    e->appearance = jint(r, "appearance", -1);
    e->hid = jint(r, "hid", 0);
    e->tx_power = (int)jint(r, "tx_power", -128);
    e->flags = jint(r, "flags", -1);
    e->has_rssi = (int)jint(r, "has_rssi", 0);
    e->rssi = (int)jint(r, "rssi", 0);
    e->rssi_best = (int)jint(r, "rssi_best", 0);
    e->adv_count = jint(r, "adv_count", 0);
    jstr(r, "watch_category", e->watch, sizeof(e->watch));
    e->ext_adv = (int)jint(r, "ext_adv", 0);
    e->primary_phy = (int)jint(r, "primary_phy", 0);
    e->secondary_phy = (int)jint(r, "secondary_phy", 0);
    e->adv_sid = (int)jint(r, "adv_sid", -1);
    e->first_seen = jint(r, "first_seen", 0);
    e->last_seen = jint(r, "last_seen", 0);
    jest(r, &e->est);
}

static void led_ip(web_frrs_t *f, const web_jrec_t *r, const char *type, long long ts) {
    char ip[WEB_KEY_MAX + 1];
    if (web_key_ip(web_jl_str(r, "src"), ip) != 0) return;
    frrs_ip_t *p = ip_slot(f, ip);
    p->ts = ts;
    if (!strcmp(type, "dns")) { p->proto |= FRRS_P_DNS; p->dns_n++; return; }
    if (!strcmp(type, "quic")) { p->proto |= FRRS_P_QUIC; p->quic_n++; return; }
    if (!strcmp(type, "http")) { p->proto |= FRRS_P_HTTP; p->http_n++; return; }
    if (!strcmp(type, "ntp")) { p->proto |= FRRS_P_NTP; return; }
    if (!strcmp(type, "cleartext_cred")) {
        /* The protocol only: the username and the secret never leave
         * the record (web_frrs.h). */
        char pr[16];
        jstr(r, "proto", pr, sizeof(pr));
        p->proto |= FRRS_P_CRED;
        p->cred_n++;
        if (pr[0] && !strstr(p->cred_protos, pr) &&
            strlen(p->cred_protos) + strlen(pr) + 2 < sizeof(p->cred_protos)) {
            if (p->cred_protos[0]) strcat(p->cred_protos, " ");
            strcat(p->cred_protos, pr);
        }
        return;
    }
    /* tls */
    p->proto |= FRRS_P_TLS;
    p->tls_n++;
    jstr(r, "ver", p->tls_ver, sizeof(p->tls_ver));
    const char *h = web_jl_str(r, "host");
    if (!h || !h[0]) return;
    unsigned long long hh = fnv64(h);
    for (int i = 0; i < p->nsni; i++) if (p->sni_h[i] == hh) return;
    if (p->nsni == WEB_FRRS_SNI) {
        memmove(&p->sni[0], &p->sni[1], sizeof(p->sni[0]) * (WEB_FRRS_SNI - 1));
        memmove(&p->sni_h[0], &p->sni_h[1], sizeof(p->sni_h[0]) * (WEB_FRRS_SNI - 1));
        p->nsni--;
    }
    web_utf8_copy(p->sni[p->nsni], WEB_FRRS_SNI_MAX, h);
    p->sni_h[p->nsni++] = hh;
}

static void led_chan(web_frrs_t *f, const web_jrec_t *r, long long ts) {
    struct web_frrs_led *L = f->led;
    int ch = (int)jint(r, "channel", 0);
    if (ch <= 0 || ch > 233) return;
    char band[12];
    jstr(r, "band", band, sizeof(band));
    int at = -1, old = 0;
    for (int i = 0; i < L->nchan; i++) {
        if (L->chan[i].ch == ch && !strcmp(L->chan[i].band, band)) { at = i; break; }
        if (L->chan[i].ts < L->chan[old].ts) old = i;
    }
    if (at < 0) at = L->nchan < WEB_FRRS_LEDGER_CHAN ? L->nchan++ : old;
    frrs_chan_t *c = &L->chan[at];
    c->ch = ch;
    snprintf(c->band, sizeof(c->band), "%s", band);
    c->ctrl_total = jint(r, "ctrl_total", 0);
    c->ap_count = (int)jint(r, "ap_count", 0);
    c->assoc_count = (int)jint(r, "assoc_count", 0);
    c->ts = ts;
}

void web_frrs_record(web_frrs_t *f, const web_jrec_t *r) {
    if (!f || !f->led) return;
    const char *type = web_jl_str(r, "type");
    if (!type) return;
    long long ts = jint(r, "ts", 0);
    char mac[WEB_KEY_MAX + 1];
    pthread_mutex_lock(&f->lmu);
    if (!strcmp(type, "beacon")) {
        if (web_key_mac(web_jl_str(r, "bssid"), mac) == 0) led_beacon(f, r, mac, ts);
    } else if (!strcmp(type, "wifi_regulatory")) {
        if (web_key_mac(web_jl_str(r, "bssid"), mac) == 0) led_reg(f, r, mac, ts);
    } else if (!strcmp(type, "wifi_mld")) {
        if (web_key_mac(web_jl_str(r, "mld_mac"), mac) == 0) led_mld(f, r, mac, ts);
    } else if (!strcmp(type, "wifi_assoc_req")) {
        led_assoc_req(f, r, ts);
    } else if (!strcmp(type, "probe_client")) {
        if (web_key_mac(web_jl_str(r, "mac"), mac) == 0) led_probe(f, r, mac, ts);
    } else if (!strcmp(type, "pnl_client")) {
        if (web_key_mac(web_jl_str(r, "mac"), mac) == 0) led_pnl(f, r, mac, ts);
    } else if (!strcmp(type, "seqnum_correlation")) {
        led_seq(f, r, ts);
    } else if (!strcmp(type, "ble_device")) {
        led_ble(f, r, ts);
    } else if (!strcmp(type, "tls") || !strcmp(type, "dns") || !strcmp(type, "quic") ||
               !strcmp(type, "http") || !strcmp(type, "ntp") ||
               !strcmp(type, "cleartext_cred")) {
        led_ip(f, r, type, ts);
    } else if (!strcmp(type, "channel_summary")) {
        led_chan(f, r, ts);
    } else if (!strcmp(type, "sensor_health")) {
        jstr(r, "monitor_iface", f->led->mon_iface, sizeof(f->led->mon_iface));
        jstr(r, "capture_iface", f->led->cap_iface, sizeof(f->led->cap_iface));
        f->led->ts_sh = ts;
    }
    pthread_mutex_unlock(&f->lmu);
}

const frrs_bss_t *frrs_led_bss(const web_frrs_t *f, const char *mac) {
    if (!f || !f->led) return NULL;
    for (int i = 0; i < f->led->nbss; i++)
        if (!strcmp(f->led->bss[i].mac, mac)) return &f->led->bss[i];
    return NULL;
}

const frrs_bss_t *frrs_led_mld_of(const web_frrs_t *f, const char *mac) {
    if (!f || !f->led) return NULL;
    for (int i = 0; i < f->led->nbss; i++) {
        const frrs_bss_t *b = &f->led->bss[i];
        for (int k = 0; b->has_m && k < b->nlinks; k++)
            if (!strcmp(b->links[k], mac)) return b;
    }
    return NULL;
}

static int one_of(const char *s, const char *const *words) {
    for (int i = 0; words[i]; i++) if (!strcmp(s, words[i])) return 1;
    return 0;
}

int web_frrs_rf(web_frrs_t *f, int bssid, const char *mac, web_frrs_rf_t *out) {
    static const char *const BAND[] = { "immediate", "near", "room", "building",
                                        "far", NULL };
    static const char *const TREND[] = { "approaching", "steady", "leaving",
                                         "unknown", NULL };
    memset(out, 0, sizeof(*out));
    if (!f || !f->led || !f->lmu_init || !mac) return 0;
    const frrs_est_t *e = NULL;
    int got = 0;
    pthread_mutex_lock(&f->lmu);
    if (bssid) {
        const frrs_bss_t *b = frrs_led_bss(f, mac);
        if (b && b->has_b) {
            got = 1;
            out->ts = b->ts_b;
            out->channel = b->channel;
            out->six = b->channel_source == 3;   /* CH_SRC_HE_6GHZ */
            e = &b->est;
            if (b->has_rssi60 && b->rssi_min >= -127 && b->rssi_max <= -1 &&
                b->rssi_min <= b->rssi_max) {
                out->have_range = 1;
                out->rmin = b->rssi_min;
                out->rmax = b->rssi_max;
            }
        }
    } else {
        const frrs_sta_t *st = frrs_led_sta(f, mac);
        if (st && st->has_p) {
            got = 1;
            out->ts = st->ts_p;
            out->channel = st->channel;
            e = &st->est;
        }
    }
    if (e && e->have) {
        if (one_of(e->band, BAND)) snprintf(out->band, sizeof(out->band), "%s", e->band);
        if (one_of(e->trend, TREND)) snprintf(out->trend, sizeof(out->trend), "%s", e->trend);
    }
    pthread_mutex_unlock(&f->lmu);
    return got;
}

/* The estimate's metres and trend into row, for the census. */
static void census_est(const frrs_est_t *e, web_frrs_rf_row_t *row) {
    static const char *const TREND[] = { "approaching", "steady", "leaving",
                                         "unknown", NULL };
    row->has_m = e->have && row->band[0] && isfinite(e->m) && e->m >= 0.0 && e->m <= 100000.0;
    row->m = row->has_m ? e->m : 0.0;
    row->trend = e->have && one_of(e->trend, TREND) ? e->trend : "";
}

void web_frrs_rf_census(web_frrs_t *f, void (*cb)(const web_frrs_rf_row_t *, void *),
                        void *ctx) {
    static const char *const BAND[] = { "immediate", "near", "room", "building",
                                        "far", NULL };
    if (!f || !f->led || !f->lmu_init || !cb) return;
    web_frrs_rf_row_t row;
    pthread_mutex_lock(&f->lmu);
    const struct web_frrs_led *L = f->led;
    for (int i = 0; i < L->nbss; i++) {
        const frrs_bss_t *b = &L->bss[i];
        if (!b->has_b) continue;
        row.kind = "ap";
        row.mac = b->mac;
        row.ssid = b->ssid;
        row.has_rssi = b->signal_dbm != 0;
        row.rssi = b->signal_dbm;
        row.band = b->est.have && one_of(b->est.band, BAND) ? b->est.band : "";
        census_est(&b->est, &row);
        row.ts = b->ts_b;
        cb(&row, ctx);
    }
    for (int i = 0; i < L->nsta; i++) {
        const frrs_sta_t *s = &L->sta[i];
        if (!s->has_p) continue;
        row.kind = "sta";
        row.mac = s->mac;
        row.ssid = "";
        row.has_rssi = s->signal_dbm != 0;
        row.rssi = s->signal_dbm;
        row.band = s->est.have && one_of(s->est.band, BAND) ? s->est.band : "";
        census_est(&s->est, &row);
        row.ts = s->ts_p;
        cb(&row, ctx);
    }
    pthread_mutex_unlock(&f->lmu);
}

const frrs_sta_t *frrs_led_sta(const web_frrs_t *f, const char *mac) {
    if (!f || !f->led) return NULL;
    for (int i = 0; i < f->led->nsta; i++)
        if (!strcmp(f->led->sta[i].mac, mac)) return &f->led->sta[i];
    return NULL;
}

int frrs_led_ble(const web_frrs_t *f, const char *addr, int addr_type,
                 const frrs_ble_t **out, int max) {
    int n = 0;
    if (!f || !f->led) return 0;
    for (int i = 0; i < f->led->nble && n < max; i++)
        if (!strcmp(f->led->ble[i].addr, addr) &&
            (addr_type < 0 || f->led->ble[i].addr_type == addr_type))
            out[n++] = &f->led->ble[i];
    return n;
}

const frrs_ip_t *frrs_led_ip(const web_frrs_t *f, const char *ip) {
    if (!f || !f->led || !ip || !ip[0]) return NULL;
    for (int i = 0; i < f->led->nip; i++)
        if (!strcmp(f->led->ip[i].ip, ip)) return &f->led->ip[i];
    return NULL;
}

const frrs_chan_t *frrs_led_chan(const web_frrs_t *f, int ch) {
    if (!f || !f->led) return NULL;
    const frrs_chan_t *best = NULL;
    for (int i = 0; i < f->led->nchan; i++)
        if (f->led->chan[i].ch == ch && (!best || f->led->chan[i].ts > best->ts))
            best = &f->led->chan[i];
    return best;
}

/* ── the write path's header checks ─────────────────────────────────── */

/* host[:port] lower-cased with the port defaulted to 80, into out. 0,
 * or -1 when it does not fit. */
static int host_norm(const char *h, char *out, size_t cap) {
    size_t n = strlen(h);
    if (n + 4 >= cap) return -1;
    for (size_t i = 0; i <= n; i++) out[i] = (char)tolower((unsigned char)h[i]);
    const char *port = out[0] == '[' ? strstr(out, "]:") : strrchr(out, ':');
    if (out[0] == '[') {
        if (!port) strcat(out, ":80");
    } else if (!port) {
        strcat(out, ":80");
    }
    return 0;
}

int web_frrs_origin_ok(const web_req_t *rq) {
    if (rq->origin_count != 1 || rq->origin_long || rq->host_count != 1 || rq->host_long)
        return 0;
    if (strncmp(rq->origin, "http://", 7) != 0) return 0;
    const char *oh = rq->origin + 7;
    /* An origin is scheme://host[:port], nothing after. */
    if (!oh[0] || strchr(oh, '/') || strchr(oh, '?') || strchr(oh, '#') || strchr(oh, '@'))
        return 0;
    if (!web_http_host_ok(oh)) return 0;
    char a[WEB_HOST_MAX + 8], b[WEB_HOST_MAX + 8];
    if (host_norm(oh, a, sizeof(a)) != 0 || host_norm(rq->host, b, sizeof(b)) != 0) return 0;
    return strcmp(a, b) == 0;
}

int web_frrs_ctype_ok(const web_req_t *rq) {
    if (rq->ctype_count != 1 || rq->ctype_long) return 0;
    static const char J[] = "application/json";
    const char *c = rq->ctype;
    if (strncasecmp(c, J, sizeof(J) - 1) != 0) return 0;
    c += sizeof(J) - 1;
    if (!*c) return 1;
    while (*c == ' ' || *c == '\t') c++;
    if (*c != ';') return 0;
    c++;
    while (*c == ' ' || *c == '\t') c++;
    if (strncasecmp(c, "charset=utf-8", 13) != 0) return 0;
    c += 13;
    while (*c == ' ' || *c == '\t') c++;
    return *c == '\0';
}

int web_frrs_rate_admit(web_frrs_t *f, const char *peer, long long now_ms, int cost) {
    int at = -1, old = 0;
    for (int i = 0; i < WEB_FRRS_PEERS; i++) {
        if (f->bucket[i].peer[0] && !strcmp(f->bucket[i].peer, peer)) { at = i; break; }
        if (!f->bucket[i].peer[0]) { if (f->bucket[old].peer[0]) old = i; continue; }
        if (f->bucket[old].peer[0] && f->bucket[i].last_ms < f->bucket[old].last_ms) old = i;
    }
    if (at < 0) {
        at = old;
        snprintf(f->bucket[at].peer, sizeof(f->bucket[at].peer), "%s", peer);
        f->bucket[at].tokens = WEB_FRRS_RATE_BURST;
        f->bucket[at].last_ms = now_ms;
    }
    web_frrs_bucket_t *b = &f->bucket[at];
    double dt = (double)(now_ms - b->last_ms) / 60000.0;
    if (dt > 0) b->tokens += dt * WEB_FRRS_RATE_PER_MIN;
    if (b->tokens > WEB_FRRS_RATE_BURST) b->tokens = WEB_FRRS_RATE_BURST;
    b->last_ms = now_ms;
    if (b->tokens < cost) return 0;
    b->tokens -= cost;
    return 1;
}

/* A count from the store, or null when there is no store to count. */
static void jw_count(web_jw_t *w, long long n) {
    if (n < 0) web_jw_raw(w, "null"); else web_jw_int(w, n);
}

static void stat_inc(web_frrs_t *f, unsigned long *c) {
    pthread_mutex_lock(&f->lmu);
    (*c)++;
    pthread_mutex_unlock(&f->lmu);
}
void frrs_stat_inc(web_frrs_t *f, unsigned long *c) { stat_inc(f, c); }

int web_frrs_gate(web_frrs_t *f, const web_req_t *rq, long long now_ms,
                  const char **why, char *extra, size_t extracap) {
    extra[0] = '\0';
    if (!f) { *why = "no_store"; return 503; }
    /* Whose write: a request with the agent header is held to the
     * agent's rule and no other, and one without it to the browser's,
     * unchanged (web_agent.h). A refused agent header is never tried
     * again as a browser's. */
    int agent = web_agent_check(f->agent_secret, rq, why);
    if (agent < 0) {
        stat_inc(f, &f->st.refused_agent);
        return 403;
    }
    if (!agent && !web_frrs_origin_ok(rq)) {
        stat_inc(f, &f->st.refused_origin);
        *why = "bad_origin";
        return 403;
    }
    if (!agent && (rq->fetch_site_long ||
        (rq->fetch_site[0] && strcmp(rq->fetch_site, "same-origin") && strcmp(rq->fetch_site, "none")))) {
        stat_inc(f, &f->st.refused_origin);
        *why = "bad_fetch_site";
        return 403;
    }
    int cost = !strcmp(rq->path, "/api/frrs/import") ? WEB_FRRS_IMPORT_COST : 1;
    /* An agent's writes draw on a bucket of their own for the peer: it
     * is limited as any peer is and cannot spend the operator's. */
    char who[WEB_PEER_MAX];
    snprintf(who, sizeof(who), "%s%.45s", agent ? "a/" : "", rq->peer[0] ? rq->peer : "?");
    if (!web_frrs_rate_admit(f, who, now_ms, cost)) {
        stat_inc(f, &f->st.rate_limited);
        snprintf(extra, extracap, "Retry-After: %d\r\n", 60 * cost / WEB_FRRS_RATE_PER_MIN + 1);
        *why = "rate_limited";
        return 429;
    }
    if (!web_frrs_ctype_ok(rq)) {
        stat_inc(f, &f->st.refused_ctype);
        *why = "bad_content_type";
        return 415;
    }
    return 0;
}

size_t web_frrs_refusal(int status, const char *why, const char *extra,
                        char *out, size_t outsz) {
    char body[96];
    int bl = snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", why);
    if (bl < 0 || (size_t)bl >= sizeof(body)) return 0;
    int n = snprintf(out, outsz,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Cache-Control: no-store\r\n"
        "%s"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
        "Connection: close\r\n"
        "\r\n%s", status, web_http_reason(status), bl, extra ? extra : "", body);
    return n < 0 || (size_t)n >= outsz ? 0 : (size_t)n;
}

/* ── the research assessment (§3.1) ─────────────────────────────────── */

static void fm_value(const char *v, size_t n, char *out, size_t cap) {
    while (n && (*v == ' ' || *v == '\t')) { v++; n--; }
    while (n && (v[n - 1] == ' ' || v[n - 1] == '\t' || v[n - 1] == '\r')) n--;
    if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) { v++; n -= 2; }
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c < 0x20 || c > 0x7e) { o = 0; break; }      /* printable ASCII or nothing */
        out[o++] = (char)c;
    }
    out[o] = '\0';
}

/* v begins with the words w, in any case, and they end there. */
static int fm_starts(const char *v, const char *w) {
    size_t n = strlen(w);
    return !strncasecmp(v, w, n) && !isalpha((unsigned char)v[n]);
}

int web_frrs_recommend(const web_frrs_t *f, int type, char *basis, size_t basiscap,
                       web_frrs_fm_t *fm) {
    web_frrs_fm_t local;
    if (!fm) fm = &local;
    memset(fm, 0, sizeof(*fm));
    if (basiscap) basis[0] = '\0';
    const web_akb_t *k = web_akb_get(type);
    if (!f || !f->assess_dir[0] || !k || !k->name) return WEB_TRI_UNTRIAGED;
    char path[4200];
    int pn = snprintf(path, sizeof(path), "%s/%s.md", f->assess_dir, k->name);
    if (pn < 0 || (size_t)pn >= sizeof(path)) return WEB_TRI_UNTRIAGED;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return WEB_TRI_UNTRIAGED;
    struct stat st;
    char *buf = malloc(WEB_FRRS_ASSESS_MAX + 1);
    ssize_t got = 0;
    if (!buf) { close(fd); return WEB_TRI_UNTRIAGED; }
    /* Read until the front matter closes (a line "---" after the
     * first), never more than WEB_FRRS_ASSESS_MAX: the body below it,
     * most of the file, is not read. */
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        for (;;) {
            size_t want = (size_t)(WEB_FRRS_ASSESS_MAX - got) < 4096 ? (size_t)(WEB_FRRS_ASSESS_MAX - got) : 4096;
            ssize_t r = read(fd, buf + got, want);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            got += r;
            buf[got] = '\0';
            if (got >= WEB_FRRS_ASSESS_MAX || strstr(buf + 3, "\n---\n") || strstr(buf + 3, "\n---\r\n")) break;
        }
    }
    close(fd);
    buf[got > 0 ? got : 0] = '\0';
    if (strncmp(buf, "---\n", 4) && strncmp(buf, "---\r\n", 5)) { free(buf); return WEB_TRI_UNTRIAGED; }
    const char *p = strchr(buf, '\n') + 1;
    int closed = 0;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if ((n == 3 || (n == 4 && p[3] == '\r')) && !strncmp(p, "---", 3)) { closed = 1; break; }
        static const struct { const char *key; size_t off; } K[] = {
            { "false_positive_risk:", offsetof(web_frrs_fm_t, fpr) },
            { "noise_verdict:", offsetof(web_frrs_fm_t, noise) },
            { "severity_assessment:", offsetof(web_frrs_fm_t, sev) },
        };
        for (size_t i = 0; i < sizeof(K) / sizeof(K[0]); i++) {
            size_t kl = strlen(K[i].key);
            if (n > kl && !strncmp(p, K[i].key, kl))
                fm_value(p + kl, n - kl, (char *)fm + K[i].off, 48);
        }
        if (!e) break;
        p = e + 1;
    }
    free(buf);
    if (!closed) { memset(fm, 0, sizeof(*fm)); return WEB_TRI_UNTRIAGED; }
    fm->found = 1;
    /* The assessments judge a rule, not an alert (Q3). noise_verdict
     * describes the counting artefact on the reference host (how often
     * the rule fired, mostly per-evaluation re-firing of one standing
     * condition), not whether an alert is real: FRAG_PLAINTEXT is "very
     * noisy" with false_positive_risk "low", a real finding re-counted.
     * So noise is recommended only where both say it: the rule is often
     * wrong (false_positive_risk "high") AND it fires on ordinary
     * traffic (noise_verdict "noisy" / "very noisy"). Never false: that
     * is a claim about this alert no assessment makes, and a real attack
     * marked false is dimmed everywhere. Never incident:
     * severity_assessment judges the severity level, not whether the
     * alert is real. Anything else is "no automatic triage", the front
     * matter shown beside the buttons as advice. */
    if (fm_starts(fm->fpr, "high") &&
        (fm_starts(fm->noise, "noisy") || fm_starts(fm->noise, "very noisy"))) {
        snprintf(basis, basiscap, "false_positive_risk high; noise_verdict: %s", fm->noise);
        return WEB_TRI_NOISE;
    }
    return WEB_TRI_UNTRIAGED;
}

static void recommend_json(const web_frrs_t *f, int type, web_jw_t *w) {
    char basis[WEB_FRRS_BASIS_MAX + 1];
    web_frrs_fm_t fm;
    int st = web_frrs_recommend(f, type, basis, sizeof(basis), &fm);
    const web_akb_t *k = web_akb_get(type);
    web_jw_raw(w, "{\"type\":");
    frrs_str_or_null(w, k ? k->name : NULL);
    web_jw_raw(w, ",\"state\":");
    if (st == WEB_TRI_UNTRIAGED) web_jw_raw(w, "null"); else web_jw_str(w, STATE_WORD[st]);
    web_jw_raw(w, ",\"basis\":");
    frrs_str_or_null(w, basis);
    web_jw_raw(w, ",\"source\":");
    web_jw_str(w, f && f->assess_dir[0] ? "dir" : "none");
    /* Why there is no state: "none" (no directory or no file), or
     * "no_automatic_triage" (an assessment that does not meet the bar). */
    web_jw_raw(w, ",\"why_none\":");
    if (st != WEB_TRI_UNTRIAGED) web_jw_raw(w, "null");
    else web_jw_str(w, fm.found ? "no_automatic_triage" : "no_assessment");
    web_jw_raw(w, ",\"file\":");
    if (k && k->name) {
        char nm[96];
        snprintf(nm, sizeof(nm), "docs/wiki/alert-assessments/%s.md", k->name);
        web_jw_str(w, nm);
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"front_matter\":");
    if (!fm.found) {
        web_jw_raw(w, "null");
    } else {
        web_jw_raw(w, "{\"false_positive_risk\":"); frrs_str_or_null(w, fm.fpr);
        web_jw_raw(w, ",\"noise_verdict\":");       frrs_str_or_null(w, fm.noise);
        web_jw_raw(w, ",\"severity_assessment\":"); frrs_str_or_null(w, fm.sev);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "}");
}

/* ── the triage store ───────────────────────────────────────────────── */

/* One finding as a request names it: tri_subj_t (web_frrs_int.h). */

static void desc_addr(const char *ip, const char *key, char *out) {
    char k[WEB_KEY_MAX + 1], m[18];
    out[0] = '\0';
    if (ip && ip[0] && web_key_ip(ip, k) == 0) { snprintf(out, WEB_FRRS_ADDR_MAX + 1, "%.45s", k); return; }
    if (key && frrs_mac_in(key, m)) snprintf(out, WEB_FRRS_ADDR_MAX + 1, "%s", m);
}

#ifdef WITH_SQLITE

static int db_err(web_frrs_t *f, const char *what) {
    pthread_mutex_lock(&f->lmu);
    f->st.write_errors++;
    snprintf(f->err, sizeof(f->err), "%s: %s", what, f->wr ? sqlite3_errmsg(f->wr) : "no store");
    pthread_mutex_unlock(&f->lmu);
    return -1;
}

static void col_text(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

/* The predicate every triage read of one finding shares. */
#define TRI_MATCH(t) \
    " (" t "subject = ?1 OR (?2 <> '' AND " t "subject = ?2) OR (?3 > 0 AND " t "finding = ?3)" \
    " OR (?4 >= 0 AND " t "finding IS NULL AND " t "type = ?4 AND " t "addr = ?5 AND " \
    t "port = ?6 AND " t "first_seen = ?7)) "

static void bind_subj(sqlite3_stmt *s, const tri_subj_t *q) {
    sqlite3_bind_text(s, 1, q->subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, q->alt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, q->finding);
    sqlite3_bind_int(s, 4, q->type);
    sqlite3_bind_text(s, 5, q->addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, q->port);
    sqlite3_bind_int64(s, 7, q->first);
}

static int tri_lookup(web_frrs_t *f, const tri_subj_t *q, web_tri_t *out) {
    memset(out, 0, sizeof(*out));
    if (!f->wr) return 0;
    sqlite3_stmt *s = NULL;
    static const char SQL[] =
        "SELECT state, prev_state, via, ts, finding, note, who, basis, peer,"
        " (SELECT COUNT(*) FROM triage u WHERE" TRI_MATCH("u.") "),"
        " claim_by, claim_peer,"
        " (SELECT TOTAL(folded) FROM triage u WHERE" TRI_MATCH("u.") "),"
        " first_seen"
        " FROM triage t WHERE" TRI_MATCH("t.") "ORDER BY t.id DESC LIMIT 1";
    if (sqlite3_prepare_v2(f->wr, SQL, -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return db_err(f, "triage read");
    }
    bind_subj(s, q);
    int rc = sqlite3_step(s), found = 0;
    if (rc == SQLITE_ROW) {
        out->state = sqlite3_column_int(s, 0);
        if (out->state < 0 || out->state >= WEB_TRI_COUNT) out->state = 0;
        out->prev_state = sqlite3_column_int(s, 1);
        out->via = sqlite3_column_int(s, 2);
        out->ts = sqlite3_column_int64(s, 3);
        out->finding = sqlite3_column_type(s, 4) == SQLITE_NULL ? 0 : sqlite3_column_int64(s, 4);
        col_text(s, 5, out->note, sizeof(out->note));
        col_text(s, 6, out->by, sizeof(out->by));
        col_text(s, 7, out->basis, sizeof(out->basis));
        col_text(s, 8, out->peer, sizeof(out->peer));
        out->history_n = sqlite3_column_int(s, 9);
        col_text(s, 10, out->claim_by, sizeof(out->claim_by));
        col_text(s, 11, out->claim_peer, sizeof(out->claim_peer));
        out->folded = (long long)sqlite3_column_double(s, 12);
        /* An anomaly's row: the episode it was written on, and whether
         * the one held now is another. */
        if (q->anom) {
            out->anom = 1;
            out->episode = sqlite3_column_int64(s, 13);
            out->carried = q->first > 0 && out->episode != q->first;
        }
        found = 1;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) return db_err(f, "triage read");
    if (!found) memset(out, 0, sizeof(*out));
    return found;
}

int web_frrs_triage_any(web_frrs_t *f) {
    if (!f || !f->wr) return 0;
    sqlite3_stmt *s = NULL;
    int any = 0;
    if (sqlite3_prepare_v2(f->wr, "SELECT EXISTS (SELECT 1 FROM triage)", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        any = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return any;
}

/* The fleet export's verdicts (web_fleet.h): each subject's current
 * state (its newest row) decided at or after since, newest first. The
 * descriptor and the state only: the note, who and from where stay
 * here. */
int web_frrs_verdicts(web_frrs_t *f, long long since, int max,
                      int (*fn)(void *ctx, const web_frrs_verdict_t *v), void *ctx) {
    if (!f || !f->wr || max <= 0) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr,
            "SELECT t.type, t.addr, t.port, t.first_seen, t.state, t.ts FROM triage t"
            /* Alerts only: an anomaly's rows (type -1, web_relate.c)
             * are this sensor's own baselines' findings, no verdict on
             * an alert a peer could hold, and would take the limit's
             * rows from the ones that are. */
            " WHERE t.type >= 0 AND t.ts >= ?1 AND t.id = (SELECT MAX(u.id) FROM triage u"
            " WHERE u.subject = t.subject) ORDER BY t.ts DESC, t.id DESC LIMIT ?2",
            -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_int64(s, 1, since);
    sqlite3_bind_int(s, 2, max);
    int n = 0, rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        web_frrs_verdict_t v;
        memset(&v, 0, sizeof(v));
        v.type = sqlite3_column_int(s, 0);
        col_text(s, 1, v.addr, sizeof(v.addr));
        v.port = sqlite3_column_int(s, 2);
        v.first_seen = sqlite3_column_int64(s, 3);
        v.state = sqlite3_column_int(s, 4);
        v.ts = sqlite3_column_int64(s, 5);
        n++;
        if (fn(ctx, &v)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? n : -1;
}

static long long q_count(web_frrs_t *f, const char *sql) {
    sqlite3_stmt *s = NULL;
    long long n = -1;
    if (f->wr && sqlite3_prepare_v2(f->wr, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

#else

static int tri_lookup(web_frrs_t *f, const tri_subj_t *q, web_tri_t *out) {
    (void)f; (void)q;
    memset(out, 0, sizeof(*out));
    return 0;
}
int web_frrs_triage_any(web_frrs_t *f) { (void)f; return 0; }
int web_frrs_verdicts(web_frrs_t *f, long long since, int max,
                      int (*fn)(void *ctx, const web_frrs_verdict_t *v), void *ctx) {
    (void)f; (void)since; (void)max; (void)fn; (void)ctx;
    return 0;
}
static long long q_count(web_frrs_t *f, const char *sql) { (void)f; (void)sql; return -1; }

#endif

/* The subject of a query from the alert routes: by the finding when
 * sloth.db names it, else by the stream handle and the descriptor. */
static int subj_of_q(web_sdb_conn_t *c, const web_tri_q_t *q, tri_subj_t *s) {
    memset(s, 0, sizeof(*s));
    s->type = q->type;
    s->port = q->ip && q->ip[0] ? q->port : 0;
    s->first = q->first;
    desc_addr(q->ip, q->key, s->addr);
    if (q->id && q->id[0] == 's') snprintf(s->alt, sizeof(s->alt), "%s", q->id);
    else if (q->id) snprintf(s->subject, sizeof(s->subject), "%s", q->id);
    if (c && (q->key || q->rid > 0)) {
        web_adb_finding_t fd;
        int g = web_adb_finding(c, q->key ? 0 : q->rid, q->key, &fd);
        if (g < 0) return -1;
        if (g > 0) {
            s->finding = fd.first_rid;
            snprintf(s->subject, sizeof(s->subject), "d%lld", fd.first_rid);
            s->type = fd.type;
            if (fd.ip[0]) {
                char k[WEB_KEY_MAX + 1];
                if (web_key_ip(fd.ip, k) == 0) snprintf(s->addr, sizeof(s->addr), "%.45s", k);
                s->port = fd.port > 0 ? fd.port : 0;
            }
            s->first = fd.first_seen;
        }
    }
    if (!s->subject[0]) snprintf(s->subject, sizeof(s->subject), "%s", s->alt);
    return 0;
}

int web_frrs_triage_find(web_frrs_t *f, web_sdb_conn_t *c, const web_tri_q_t *q,
                         web_tri_t *out) {
    memset(out, 0, sizeof(*out));
    if (!f || !f->wr) return 0;
    tri_subj_t s;
    if (subj_of_q(c, q, &s) != 0) return -1;
    return tri_lookup(f, &s, out);
}

/* Resolve an alert id a request names to its subject, as the routes
 * do: a stream incident by its handle (its key a predicate on
 * sloth.db), a sloth.db row by its rowid. 1, 0 no such alert, -1. *inc
 * set when it is a stream incident (type from it). */
int frrs_resolve_alert(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *cin,
                       const char *id, long long now_s, tri_subj_t *s, long long *last) {
    memset(s, 0, sizeof(*s));
    if (last) *last = 0;
    if (!id || (id[0] != 's' && id[0] != 'd') || strlen(id) < 2 || strlen(id) > 25) return 0;
    for (const char *p = id + 1; *p; p++) if (!isalnum((unsigned char)*p)) return 0;
    web_sdb_conn_t own;
    web_sdb_conn_t *cp = cin;
    int have_c = cin != NULL, opened = 0;
    char err[200];
    if (!cin && m && m->sdb && m->sdb->configured &&
        web_slothdb_open(m->sdb, &own, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0) {
        have_c = opened = 1;
        cp = &own;
    }
    int rc = 0;
    if (id[0] == 's') {
        web_live_inc_t *e = calloc(1, sizeof(*e));
        if (!e) { if (opened) web_slothdb_close(cp); return -1; }
        if (live && web_live_incident(live, id + 1, e)) {
            if (last) *last = e->last_ts;
            /* The earliest first_ts of the key's incidents in the
             * stream: the descriptor a stream-only row keeps. */
            long long first = e->first_ts;
            web_live_inc_t *all = calloc(WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, sizeof(*all));
            int na = all ? web_live_incidents(live, all, WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, NULL) : 0;
            for (int i = 0; i < na; i++)
                if (e->key[0] && !strcmp(all[i].key, e->key) && all[i].first_ts > 0 &&
                    all[i].first_ts < first)
                    first = all[i].first_ts;
            free(all);
            web_tri_q_t q = { id, e->key[0] ? e->key : NULL, 0, e->type, e->match_port,
                              e->match_ip, first };
            rc = subj_of_q(have_c ? cp : NULL, &q, s) == 0 ? 1 : -1;
        }
        free(e);
    } else {
        char *end = NULL;
        long long rid = strtoll(id + 1, &end, 10);
        if (end && !*end && rid > 0 && have_c) {
            web_adb_finding_t fd;
            int g = web_adb_finding(cp, rid, NULL, &fd);
            if (g > 0) {
                web_tri_q_t q = { id, NULL, rid, fd.type, fd.port, fd.ip, fd.first_seen };
                rc = subj_of_q(cp, &q, s) == 0 ? 1 : -1;
                /* A Wi-Fi finding with no address: the MAC its key names. */
                if (rc == 1 && !s->addr[0]) {
                    char mac[18];
                    if (web_adb_device(cp, rid, NULL, NULL, mac) > 0)
                        snprintf(s->addr, sizeof(s->addr), "%s", mac);
                }
                /* The finding's newest last_seen: its newest row's. */
                web_adb_totals_t tt;
                web_adb_row_t *row = last ? calloc(1, sizeof(*row)) : NULL;
                if (rc == 1 && row && web_adb_key_totals(cp, rid, NULL, &tt) > 0 &&
                    web_adb_row(cp, tt.newest_rid, row) > 0)
                    *last = row->last_seen;
                free(row);
            } else if (g < 0) {
                rc = -1;
            }
        }
    }
    if (opened) web_slothdb_close(cp);
    return rc;
}

static int resolve_id(const web_m4_t *m, web_live_t *live, const char *id, long long now_s,
                      tri_subj_t *s) {
    return frrs_resolve_alert(m, live, NULL, id, now_s, s, NULL);
}

/* An id of either kind, as the triage routes take it: an alert's, or an
 * anomaly's ("a" and sixteen hex digits), whose descriptor is then in
 * *an. 1, 0 no such finding, -1, -2 (an anomaly id whose stored
 * descriptor is not the engine's: frrs_anom_resolve()). */
static int resolve_any(const web_m4_t *m, web_live_t *live, const char *id, long long now_s,
                       tri_subj_t *s, frrs_anom_t *an) {
    memset(an, 0, sizeof(*an));
    if (!frrs_anom_id_ok(id)) return resolve_id(m, live, id, now_s, s);
    memset(s, 0, sizeof(*s));
    int r = frrs_anom_resolve(m, id, an);
    if (r == 1) frrs_anom_subj(an, s);
    return r;
}

int frrs_tri_current(web_frrs_t *f, const tri_subj_t *s, web_tri_t *out) {
    memset(out, 0, sizeof(*out));
    return f ? tri_lookup(f, s, out) : 0;
}

static void tri_json(web_jw_t *w, const web_tri_t *t, int full) {
    web_jw_raw(w, "{\"state\":");
    web_jw_str(w, web_frrs_state_word(t->state));
    web_jw_raw(w, ",\"ts\":");
    web_jw_int(w, t->ts);
    web_jw_raw(w, ",\"via\":");
    web_jw_str(w, web_frrs_via_word(t->via));
    web_jw_raw(w, ",\"history_n\":");
    web_jw_int(w, t->history_n);
    web_jw_raw(w, ",\"folded\":");
    web_jw_int(w, t->folded);
    if (full) {
        web_jw_raw(w, ",\"prev_state\":");
        web_jw_str(w, web_frrs_state_word(t->prev_state));
        web_jw_raw(w, ",\"note\":");  web_jw_str(w, t->note);
        web_jw_raw(w, ",\"by\":");    web_jw_str(w, t->by);
        web_jw_raw(w, ",\"basis\":"); web_jw_str(w, t->basis);
        web_jw_raw(w, ",\"peer\":");  web_jw_str(w, t->peer);
        if (t->via == WEB_TRI_VIA_IMPORT) {
            web_jw_raw(w, ",\"claimed_by\":");   web_jw_str(w, t->claim_by);
            web_jw_raw(w, ",\"claimed_peer\":"); web_jw_str(w, t->claim_peer);
        }
        web_jw_raw(w, ",\"finding\":");
        if (t->finding > 0) {
            char d[32];
            snprintf(d, sizeof(d), "d%lld", t->finding);
            web_jw_str(w, d);
        } else {
            web_jw_raw(w, "null");
        }
    }
    if (t->anom) {
        web_jw_raw(w, ",\"episode\":");
        web_jw_int(w, t->episode);
        web_jw_raw(w, ",\"carried\":");
        web_jw_raw(w, t->carried ? "true" : "false");
    }
    web_jw_raw(w, "}");
}
void frrs_tri_json(web_jw_t *w, const web_tri_t *t, int full) { tri_json(w, t, full); }

/* ── the triage routes ──────────────────────────────────────────────── */

/* ids=a,b,c (a comma or %2C between), each an alert id or an anomaly's. */
static int parse_ids(const char *query, char ids[][32], int *n, const char **why) {
    *n = 0;
    if (strncmp(query, "ids=", 4) || strchr(query, '&')) { *why = "bad_ids"; return -1; }
    const char *p = query + 4;
    while (*p) {
        char id[32];
        size_t o = 0;
        while (*p && *p != ',' && strncmp(p, "%2C", 3) && strncmp(p, "%2c", 3)) {
            if (o + 1 >= sizeof(id) || !isalnum((unsigned char)*p)) { *why = "bad_ids"; return -1; }
            id[o++] = *p++;
        }
        id[o] = '\0';
        if (o < 2 || (id[0] != 's' && id[0] != 'd' && !frrs_anom_id_ok(id)) ||
            *n >= WEB_FRRS_IDS_MAX) {
            *why = "bad_ids";
            return -1;
        }
        memcpy(ids[(*n)++], id, o + 1);
        if (*p == ',') p++;
        else if (*p == '%') p += 3;
        else break;
        if (!*p) { *why = "bad_ids"; return -1; }
    }
    if (!*n) { *why = "bad_ids"; return -1; }
    return 0;
}

static int route_states(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status) {
    char ids[WEB_FRRS_IDS_MAX][32];
    int n;
    const char *why = NULL;
    if (parse_ids(query, ids, &n, &why) != 0) return frrs_error(400, why, NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"store\":");
    web_jw_str(&w, f && f->wr ? "open" : "none");
    web_jw_raw(&w, ",\"triage\":{");
    int first = 1, any = web_frrs_triage_any(f);
    char un[WEB_FRRS_IDS_MAX][32], gone[WEB_FRRS_IDS_MAX][32];
    int nun = 0, ngone = 0, type[WEB_FRRS_IDS_MAX];
    for (int i = 0; i < n; i++) {
        web_tri_t t;
        int got = 0;
        tri_subj_t s;
        /* Resolved whatever the store holds: the type names the row's
         * "follow recommended" (the page asks /api/frrs/recommend). */
        frrs_anom_t an;
        int r = resolve_any(m, live, ids[i], now_s, &s, &an);
        if (r == -1) return frrs_error(503, "read_failed", NULL, body, cap, len, status);
        type[i] = r > 0 ? s.type : -1;
        if (r <= 0) { memcpy(gone[ngone++], ids[i], 32); continue; }
        if (any) got = tri_lookup(f, &s, &t);
        if (got < 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
        if (got > 0 && t.state != WEB_TRI_UNTRIAGED) {
            web_jw_raw(&w, first ? "" : ",");
            web_jw_key(&w, ids[i]);
            tri_json(&w, &t, 1);
            first = 0;
        } else {
            memcpy(un[nun++], ids[i], 32);
        }
    }
    web_jw_raw(&w, "},\"types\":{");
    for (int i = 0, k = 0; i < n; i++) {
        const web_akb_t *kb = type[i] >= 0 ? web_akb_get(type[i]) : NULL;
        if (!kb || !kb->name) continue;
        web_jw_raw(&w, k++ ? "," : "");
        web_jw_key(&w, ids[i]);
        web_jw_str(&w, kb->name);
    }
    web_jw_raw(&w, "},\"untriaged\":[");
    for (int i = 0; i < nun; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_str(&w, un[i]);
    }
    web_jw_raw(&w, "],\"missing\":[");
    for (int i = 0; i < ngone; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_str(&w, gone[i]);
    }
    web_jw_raw(&w, "],\"writes\":");
    web_jw_raw(&w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

#ifdef WITH_SQLITE
static void history_rows(web_frrs_t *f, const tri_subj_t *s, web_jw_t *w, size_t cap) {
    sqlite3_stmt *st = NULL;
    static const char SQL[] =
        "SELECT state, prev_state, via, basis, note, who, peer, ts, claim_by, claim_peer, folded,"
        " first_seen"
        " FROM triage t WHERE" TRI_MATCH("t.") "ORDER BY t.id DESC LIMIT 64";
    web_jw_raw(w, "[");
    if (f->wr && sqlite3_prepare_v2(f->wr, SQL, -1, &st, NULL) == SQLITE_OK) {
        bind_subj(st, s);
        int k = 0;
        while (sqlite3_step(st) == SQLITE_ROW && w->len + 2048 < cap) {
            char t[WEB_FRRS_NOTE_MAX + 1];
            web_jw_raw(w, k++ ? ",{\"state\":" : "{\"state\":");
            web_jw_str(w, web_frrs_state_word(sqlite3_column_int(st, 0)));
            web_jw_raw(w, ",\"prev_state\":");
            web_jw_str(w, web_frrs_state_word(sqlite3_column_int(st, 1)));
            web_jw_raw(w, ",\"via\":");
            web_jw_str(w, web_frrs_via_word(sqlite3_column_int(st, 2)));
            static const char *const K[] = { ",\"basis\":", ",\"note\":", ",\"by\":", ",\"peer\":" };
            for (int c = 0; c < 4; c++) {
                col_text(st, 3 + c, t, sizeof(t));
                web_jw_raw(w, K[c]);
                web_jw_str(w, t);
            }
            web_jw_raw(w, ",\"ts\":");
            web_jw_int(w, sqlite3_column_int64(st, 7));
            if (sqlite3_column_int(st, 2) == WEB_TRI_VIA_IMPORT) {
                /* What the file said: claims, not this sensor's facts. */
                col_text(st, 8, t, sizeof(t));
                web_jw_raw(w, ",\"claimed_by\":");
                web_jw_str(w, t);
                col_text(st, 9, t, sizeof(t));
                web_jw_raw(w, ",\"claimed_peer\":");
                web_jw_str(w, t);
            }
            web_jw_raw(w, ",\"folded\":");
            web_jw_int(w, sqlite3_column_int64(st, 10));
            /* An anomaly's row: the episode it was written on. */
            if (s->anom) {
                web_jw_raw(w, ",\"episode\":");
                web_jw_int(w, sqlite3_column_int64(st, 11));
            }
            web_jw_raw(w, "}");
        }
    }
    sqlite3_finalize(st);
    web_jw_raw(w, "]");
}
#else
static void history_rows(web_frrs_t *f, const tri_subj_t *s, web_jw_t *w, size_t cap) {
    (void)f; (void)s; (void)cap;
    web_jw_raw(w, "[]");
}
#endif

static int route_history(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                         char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return frrs_error(400, "missing_id", NULL, body, cap, len, status);
    tri_subj_t s;
    frrs_anom_t an;
    int r = resolve_any(m, live, ps[0].val, now_s, &s, &an);
    if (r == -2) return frrs_error(409, "id_collision", NULL, body, cap, len, status);
    if (r < 0) return frrs_error(503, "read_failed", NULL, body, cap, len, status);
    if (r == 0)
        return frrs_error(404, frrs_anom_id_ok(ps[0].val) ? "no_such_anomaly" : "no_such_alert",
                          NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    web_tri_t t;
    int got = f ? tri_lookup(f, &s, &t) : 0;
    if (got < 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    const web_akb_t *k = s.anom ? NULL : web_akb_get(s.type);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"id\":");       web_jw_str(&w, ps[0].val);
    web_jw_raw(&w, ",\"subject\":");  web_jw_str(&w, s.subject);
    web_jw_raw(&w, ",\"finding\":");
    if (s.finding > 0) {
        char d[32];
        snprintf(d, sizeof(d), "d%lld", s.finding);
        web_jw_str(&w, d);
    } else {
        web_jw_raw(&w, "null");
    }
    if (s.anom) {
        /* What the id names, and the episode of it held now (held false:
         * the engine has let it go, the descriptor is the store's). */
        web_jw_raw(&w, ",\"anomaly\":");
        frrs_anom_json(&w, &an);
        web_jw_raw(&w, ",\"store\":");
    } else {
    web_jw_raw(&w, ",\"descriptor\":{\"type\":");
    frrs_str_or_null(&w, k ? k->name : NULL);
    web_jw_raw(&w, ",\"addr\":");       web_jw_str(&w, s.addr);
    web_jw_raw(&w, ",\"port\":");       web_jw_int(&w, s.port);
    web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, s.first);
    web_jw_raw(&w, "},\"store\":");
    }
    web_jw_str(&w, f && f->wr ? "open" : "none");
    web_jw_raw(&w, ",\"writes\":");
    web_jw_raw(&w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"current\":");
    if (got > 0) tri_json(&w, &t, 1);
    else web_jw_raw(&w, "{\"state\":\"untriaged\",\"history_n\":0}");
    web_jw_raw(&w, ",\"history_cap\":");
    web_jw_int(&w, WEB_FRRS_HIST_PER);
    web_jw_raw(&w, ",\"folded\":");
    web_jw_int(&w, got > 0 ? t.folded : 0);
    /* No assessment judges an anomaly rule: nothing to recommend. */
    web_jw_raw(&w, ",\"recommend\":");
    if (s.anom) web_jw_raw(&w, "null");
    else recommend_json(f, s.type, &w);
    web_jw_raw(&w, ",\"rows\":");
    if (f) history_rows(f, &s, &w, cap);
    else web_jw_raw(&w, "[]");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

static int route_recommend(const web_m4_t *m, const char *query, char *body, size_t cap,
                           size_t *len, int *status) {
    web_param_t ps[1] = { { "type", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return frrs_error(400, "missing_type", NULL, body, cap, len, status);
    int type = web_akb_find(ps[0].val);
    if (type < 0) {
        char *end = NULL;
        long v = strtol(ps[0].val, &end, 10);
        if (end && !*end && ps[0].val[0] >= '0' && ps[0].val[0] <= '9' && v >= 0 && v < web_akb_n)
            type = (int)v;
    }
    if (type < 0) return frrs_error(400, "bad_type", NULL, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    recommend_json(m->frrs, type, &w);
    web_jw_raw(&w, "\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* /api/frrs/summary: the open incidents (the tile's) by their current
 * triage, under the request's scope as /api/alerts counts them. */
static int route_summary(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                         char *body, size_t cap, size_t *len, int *status) {
    if (query[0]) return frrs_error(400, "unknown_parameter", NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    long long open[WEB_TRI_COUNT] = { 0 }, total = 0;
    int nopen = 0;
    web_live_inc_t *inc = NULL;
    if (live) {
        inc = calloc(WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, sizeof(*inc));
        if (!inc) return -1;
        int ninc = web_live_incidents(live, inc, WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, &nopen);
        (void)ninc;
    }
    int any = web_frrs_triage_any(f);
    web_sdb_conn_t c;
    int have_c = 0;
    char err[200];
    if (any && m->sdb && m->sdb->configured &&
        web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0)
        have_c = 1;
    for (int i = 0; i < nopen; i++) {
        if (m->sc && m->sc->scope && !web_scope_pass(m->sc->scope, web_live_inc_tag(m->sc, &inc[i])))
            continue;
        /* One per key, as the Alerts page's open rows are. */
        int dup = 0;
        for (int j = 0; j < i && !dup; j++) dup = inc[i].key[0] && !strcmp(inc[j].key, inc[i].key);
        if (dup) continue;
        total++;
        int st = WEB_TRI_UNTRIAGED;
        if (any) {
            char id[40];
            snprintf(id, sizeof(id), "s%s", inc[i].hid);
            web_tri_q_t q = { id, inc[i].key[0] ? inc[i].key : NULL, 0, inc[i].type,
                              inc[i].match_port, inc[i].match_ip, inc[i].first_ts };
            web_tri_t t;
            if (web_frrs_triage_find(f, have_c ? &c : NULL, &q, &t) > 0) st = t.state;
        }
        open[st]++;
    }
    if (have_c) web_slothdb_close(&c);
    free(inc);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"store\":");
    web_jw_str(&w, f && f->wr ? "open" : "none");
    web_jw_raw(&w, ",\"writes\":");
    web_jw_raw(&w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"read_only\":");
    web_jw_raw(&w, f && !f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"recommendations\":");
    web_jw_str(&w, f && f->assess_dir[0] ? "dir" : "none");
    web_jw_raw(&w, ",\"open\":{\"total\":");
    web_jw_int(&w, total);
    for (int s = 0; s < WEB_TRI_COUNT; s++) {
        web_jw_raw(&w, ",");
        web_jw_key(&w, STATE_WORD[s]);
        web_jw_int(&w, open[s]);
    }
    web_jw_raw(&w, ",\"out\":");
    long long nout = 0;
    for (int s = 0; s < WEB_TRI_COUNT; s++) if (web_frrs_state_out(s)) nout += open[s];
    web_jw_int(&w, nout);
    /* The table's fill, for the page's warning near the cap (the
     * oldest superseded rows fold there; §3.1). */
    long long rows = q_count(f, "SELECT COUNT(*) FROM triage");
    long long tcap = f ? f->triage_cap : WEB_FRRS_TRIAGE_CAP;
    web_jw_raw(&w, "},\"rows\":");
    jw_count(&w, rows);
    web_jw_raw(&w, ",\"cap\":");
    web_jw_int(&w, tcap);
    web_jw_raw(&w, ",\"near_cap\":");
    web_jw_raw(&w, rows >= 0 && rows * 100 >= tcap * WEB_FRRS_WARN_PCT ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── triage writes: room, folding and the rows ──────────────────────── */

#ifdef WITH_SQLITE

/* One write transaction's view of the triage table: the counts, read
 * once and kept in step by every insert and fold, and the statements it
 * reuses (an import runs up to WEB_FRRS_IMPORT_TRIAGE lines through one
 * transaction, so nothing here is prepared or counted per line). */
struct frrs_tri_ctx {
    web_frrs_t   *f;
    long long     now_s, rows, imported, folded;
    sqlite3_stmt *ins, *del, *addf, *alert_m, *alert_d, *dup;
};

/* The predicate an import files under: the descriptor alone. */
#define DESC_MATCH(t) \
    " (" t "type = ?4 AND " t "addr = ?5 AND " t "port = ?6 AND " t "first_seen = ?7) "

static long long tri_cap(const web_frrs_t *f) {
    return f->triage_cap > 0 ? f->triage_cap : WEB_FRRS_TRIAGE_CAP;
}
static long long cap_part(const web_frrs_t *f, long long div) {
    long long n = tri_cap(f) / div;
    return n > 0 ? n : 1;
}

static void ctx_close(frrs_tri_ctx_t *x) {
    sqlite3_finalize(x->ins);
    sqlite3_finalize(x->del);
    sqlite3_finalize(x->addf);
    sqlite3_finalize(x->alert_m);
    sqlite3_finalize(x->alert_d);
    sqlite3_finalize(x->dup);
    x->ins = x->del = x->addf = x->alert_m = x->alert_d = x->dup = NULL;
}

/* Inside a transaction already begun. 0, or -1 (closed again). */
static int ctx_open(web_frrs_t *f, frrs_tri_ctx_t *x, long long now_s, int imports) {
    memset(x, 0, sizeof(*x));
    x->f = f;
    x->now_s = now_s;
    x->rows = q_count(f, "SELECT COUNT(*) FROM triage");
    x->imported = imports ? q_count(f, "SELECT COUNT(*) FROM triage WHERE via = 2") : 0;
    if (x->rows < 0 || x->imported < 0 ||
        sqlite3_prepare_v2(f->wr,
            "INSERT INTO triage (subject, finding, type, addr, port, first_seen, state,"
            " prev_state, via, basis, note, who, peer, ts, claim_by, claim_peer) VALUES"
            " (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            -1, &x->ins, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "DELETE FROM triage WHERE id = ?1", -1, &x->del, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "UPDATE triage SET folded = folded + ?2 WHERE id = ?1", -1,
                           &x->addf, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "SELECT COUNT(*), TOTAL(via = 2), MAX(ts), MIN(id) FROM triage t"
                           " WHERE" TRI_MATCH("t."), -1, &x->alert_m, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "SELECT COUNT(*), TOTAL(via = 2), MAX(ts), MIN(id) FROM triage t"
                           " WHERE" DESC_MATCH("t."), -1, &x->alert_d, NULL) != SQLITE_OK) {
        ctx_close(x);
        return -1;
    }
    return 0;
}

static int step_done(sqlite3_stmt *s) {
    int rc = sqlite3_step(s);
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* One alert's rows (TRI_MATCH, or for an import its descriptor): how
 * many, how many imported, the newest ts, the first row's id. */
static int alert_counts(frrs_tri_ctx_t *x, const tri_subj_t *s, int by_desc, long long *n,
                        long long *ni, long long *maxts, long long *first) {
    sqlite3_stmt *st = by_desc ? x->alert_d : x->alert_m;
    bind_subj(st, s);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *n = sqlite3_column_int64(st, 0);
        *ni = (long long)sqlite3_column_double(st, 1);
        *maxts = sqlite3_column_int64(st, 2);
        *first = sqlite3_column_int64(st, 3);
    }
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* Row id deleted, its own folded count and itself added to row keep's
 * (0: no row left to carry it). */
static int fold_row(frrs_tri_ctx_t *x, long long id, long long carry, int via, long long keep) {
    sqlite3_bind_int64(x->del, 1, id);
    if (step_done(x->del)) return -1;
    if (keep > 0) {
        sqlite3_bind_int64(x->addf, 1, keep);
        sqlite3_bind_int64(x->addf, 2, 1 + carry);
        if (step_done(x->addf)) return -1;
    }
    x->rows--;
    if (via == WEB_TRI_VIA_IMPORT) x->imported--;
    x->folded++;
    return 0;
}

/* n of one alert's rows folded, oldest first, never its first row
 * (which carries the count); only_imp: imported rows only. The number
 * folded, or -1. */
#define FOLD_MAX 256
static long long fold_alert(frrs_tri_ctx_t *x, const tri_subj_t *s, int by_desc, int only_imp,
                            long long first, long long n) {
    static const char SQL_M[] = "SELECT id, folded, via FROM triage t WHERE" TRI_MATCH("t.")
                                "AND t.id <> ?8 AND (?9 = 0 OR t.via = 2) ORDER BY t.id LIMIT ?10";
    static const char SQL_D[] = "SELECT id, folded, via FROM triage t WHERE" DESC_MATCH("t.")
                                "AND t.id <> ?8 AND (?9 = 0 OR t.via = 2) ORDER BY t.id LIMIT ?10";
    if (n <= 0) return 0;
    if (n > FOLD_MAX) n = FOLD_MAX;
    long long ids[FOLD_MAX], carry[FOLD_MAX];
    int via[FOLD_MAX], k = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(x->f->wr, by_desc ? SQL_D : SQL_M, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    bind_subj(st, s);
    sqlite3_bind_int64(st, 8, first);
    sqlite3_bind_int(st, 9, only_imp);
    sqlite3_bind_int64(st, 10, n);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && k < FOLD_MAX) {
        ids[k] = sqlite3_column_int64(st, 0);
        carry[k] = sqlite3_column_int64(st, 1);
        via[k] = sqlite3_column_int(st, 2);
        k++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) return -1;
    /* Collected first, deleted after: never a delete under an open read. */
    for (int i = 0; i < k; i++)
        if (fold_row(x, ids[i], carry[i], via[i], first) != 0) return -1;
    return k;
}

/* The table at its cap (§3.1): the cap / WEB_FRRS_FOLD_DIV superseded rows, or
 * as many as bring it under the cap, folded at once, so the scan runs
 * once per batch, not per write.
 * Superseded: a newer row of the same alert exists (by subject, finding
 * or descriptor), so the alert's current state is never what folds.
 * Order: imported rows first, then the rows of alerts aged out (their
 * newest row older than WEB_FRRS_AGED_S), then the oldest. Each folded
 * row's count goes to its alert's newest row. only_imp: an import makes
 * room among imported rows alone, never by folding an operator's. */
typedef struct {
    long long id, carry, first;
    int       via, type, port;
    char      addr[WEB_FRRS_ADDR_MAX + 1];
    char      subject[40];
} fold_cand_t;

static long long retain(frrs_tri_ctx_t *x, int only_imp, long long need) {
    static const char SQL[] =
        "SELECT t.id, t.folded, t.via, t.type, t.addr, t.port, t.first_seen, t.subject"
        " FROM triage t WHERE (?3 = 0 OR t.via = 2) AND ("
        " EXISTS (SELECT 1 FROM triage n WHERE n.subject = t.subject AND n.id > t.id) OR"
        " (t.finding IS NOT NULL AND"
        "  EXISTS (SELECT 1 FROM triage n WHERE n.finding = t.finding AND n.id > t.id)) OR"
        " EXISTS (SELECT 1 FROM triage n WHERE n.type = t.type AND n.addr = t.addr AND"
        "  n.port = t.port AND n.first_seen = t.first_seen AND n.id > t.id))"
        " ORDER BY t.via = 2 DESC,"
        " (SELECT MAX(n.ts) FROM triage n WHERE n.type = t.type AND n.addr = t.addr AND"
        "  n.port = t.port AND n.first_seen = t.first_seen) < ?1 DESC, t.id LIMIT ?2";
    long long batch = cap_part(x->f, WEB_FRRS_FOLD_DIV);
    if (batch < need) batch = need;
    fold_cand_t *c = calloc((size_t)batch, sizeof(*c));
    if (!c) return -1;
    sqlite3_stmt *st = NULL, *keep = NULL;
    long long k = 0, done = 0;
    int rc = SQLITE_ERROR;
    if (sqlite3_prepare_v2(x->f->wr, SQL, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, x->now_s - WEB_FRRS_AGED_S);
        sqlite3_bind_int64(st, 2, batch);
        sqlite3_bind_int(st, 3, only_imp);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && k < batch) {
            fold_cand_t *o = &c[k++];
            o->id = sqlite3_column_int64(st, 0);
            o->carry = sqlite3_column_int64(st, 1);
            o->via = sqlite3_column_int(st, 2);
            o->type = sqlite3_column_int(st, 3);
            col_text(st, 4, o->addr, sizeof(o->addr));
            o->port = sqlite3_column_int(st, 5);
            o->first = sqlite3_column_int64(st, 6);
            col_text(st, 7, o->subject, sizeof(o->subject));
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) { free(c); return -1; }
    if (sqlite3_prepare_v2(x->f->wr,
            "SELECT COALESCE((SELECT MAX(id) FROM triage WHERE type = ?1 AND addr = ?2 AND"
            " port = ?3 AND first_seen = ?4 AND id <> ?6),"
            " (SELECT MAX(id) FROM triage WHERE subject = ?5 AND id <> ?6), 0)",
            -1, &keep, NULL) != SQLITE_OK) {
        sqlite3_finalize(keep);
        free(c);
        return -1;
    }
    for (long long i = 0; i < k; i++) {
        sqlite3_bind_int(keep, 1, c[i].type);
        sqlite3_bind_text(keep, 2, c[i].addr, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(keep, 3, c[i].port);
        sqlite3_bind_int64(keep, 4, c[i].first);
        sqlite3_bind_text(keep, 5, c[i].subject, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(keep, 6, c[i].id);
        long long to = sqlite3_step(keep) == SQLITE_ROW ? sqlite3_column_int64(keep, 0) : 0;
        sqlite3_reset(keep);
        if (fold_row(x, c[i].id, c[i].carry, c[i].via, to) != 0) { done = -1; break; }
        done++;
    }
    sqlite3_finalize(keep);
    free(c);
    return done;
}

/* Room for one more row of alert s, of the given state and via (§3.1).
 * n, ni, first: the alert's row count, imported count and first row.
 * Its history folds past WEB_FRRS_HIST_PER (an import's past
 * WEB_FRRS_IMPORT_PER of its own first); the table folds past its cap.
 * 0; 1 with *why "triage_full" only for an import (nothing imported
 * left to fold) or, with nothing superseded anywhere, a decided state;
 * -1. A clear is let in up to the cap / WEB_FRRS_CLEAR_DIV past it, and
 * tri_write() folds the row it superseded straight after. */
static int tri_room(frrs_tri_ctx_t *x, const tri_subj_t *s, int via, int state, long long n,
                    long long ni, long long first, const char **why) {
    int imp = via == WEB_TRI_VIA_IMPORT;
    if (n > 0 && imp && ni >= WEB_FRRS_IMPORT_PER) {
        long long k = fold_alert(x, s, 1, 1, first, ni - WEB_FRRS_IMPORT_PER + 1);
        if (k < 0) return -1;
        n -= k;
    }
    if (n >= WEB_FRRS_HIST_PER) {
        long long k = fold_alert(x, s, imp, 0, first, n - WEB_FRRS_HIST_PER + 1);
        if (k < 0) return -1;
    }
    if (x->rows >= tri_cap(x->f) && retain(x, imp, x->rows - tri_cap(x->f) + 1) < 0) return -1;
    if (x->rows < tri_cap(x->f)) return 0;
    if (!imp && state == WEB_TRI_UNTRIAGED && x->rows < tri_cap(x->f) + cap_part(x->f, WEB_FRRS_CLEAR_DIV)) return 0;
    *why = "triage_full";
    return 1;
}

static int tri_insert(frrs_tri_ctx_t *x, const tri_subj_t *s, int state, int prev, int via,
                      const char *basis, const char *note, const char *by, const char *peer,
                      long long ts, const char *claim_by, const char *claim_peer) {
    sqlite3_stmt *st = x->ins;
    sqlite3_bind_text(st, 1, s->subject, -1, SQLITE_TRANSIENT);
    if (s->finding > 0) sqlite3_bind_int64(st, 2, s->finding); else sqlite3_bind_null(st, 2);
    sqlite3_bind_int(st, 3, s->type);
    sqlite3_bind_text(st, 4, s->addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, s->port);
    sqlite3_bind_int64(st, 6, s->first);
    sqlite3_bind_int(st, 7, state);
    sqlite3_bind_int(st, 8, prev);
    sqlite3_bind_int(st, 9, via);
    sqlite3_bind_text(st, 10, basis, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, peer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 14, ts);
    sqlite3_bind_text(st, 15, claim_by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, claim_peer, -1, SQLITE_TRANSIENT);
    if (step_done(st)) return -1;
    x->rows++;
    if (via == WEB_TRI_VIA_IMPORT) x->imported++;
    return 0;
}

static void stat_add(web_frrs_t *f, unsigned long *c, long long n) {
    if (n <= 0) return;
    pthread_mutex_lock(&f->lmu);
    *c += (unsigned long)n;
    pthread_mutex_unlock(&f->lmu);
}

/* POST /api/frrs/triage's write: one transaction. 0, 1 refused (why),
 * -1. */
static int tri_write(web_frrs_t *f, const tri_subj_t *s, int state, int prev, int via,
                     const char *basis, const char *note, const char *by, const char *peer,
                     long long now_s, const char **why) {
    if (sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_busy";
        return db_err(f, "triage begin");
    }
    frrs_tri_ctx_t x;
    sqlite3_stmt *st = NULL;
    int rc = 0, opened = 0;
    if (ctx_open(f, &x, now_s, 0) != 0) { *why = "store_error"; rc = -1; goto out; }
    opened = 1;
    /* A row filed before sloth.db held the finding (under its stream
     * handle or its descriptor) gets the finding now, once: only where
     * it is still NULL (docs/web-frrs-spec.md §3.6). */
    if (s->finding > 0) {
        if (sqlite3_prepare_v2(f->wr,
                "UPDATE triage SET finding = ?3 WHERE finding IS NULL AND (subject = ?1"
                " OR (?2 <> '' AND subject = ?2) OR (type = ?4 AND addr = ?5 AND port = ?6"
                " AND first_seen = ?7))", -1, &st, NULL) != SQLITE_OK) {
            *why = "store_error"; rc = -1; goto out;
        }
        bind_subj(st, s);
        if (sqlite3_step(st) != SQLITE_DONE) { *why = "store_error"; rc = -1; goto out; }
        sqlite3_finalize(st);
        st = NULL;
    }
    long long n = 0, ni = 0, maxts = 0, first = 0;
    if (alert_counts(&x, s, 0, &n, &ni, &maxts, &first) != 0) { *why = "store_error"; rc = -1; goto out; }
    rc = tri_room(&x, s, via, state, n, ni, first, why);
    if (rc < 0) *why = "store_error";
    if (rc != 0) goto out;
    if (tri_insert(&x, s, state, prev, via, basis, note, by, peer, now_s, "", "") != 0) {
        *why = "store_error";
        rc = -1;
        goto out;
    }
    /* A clear let in past the cap superseded this alert's last row: that
     * row folds now, so the table is back at its cap, never above it. */
    if (x.rows > tri_cap(f) && retain(&x, 0, x.rows - tri_cap(f)) < 0) {
        *why = "store_error";
        rc = -1;
    }
out:
    sqlite3_finalize(st);
    long long folded = opened ? x.folded : 0;
    if (opened) ctx_close(&x);
    if (rc == 0 && sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_error";
        rc = -1;
    }
    if (rc != 0) {
        sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
        if (rc < 0) db_err(f, "triage write");
    } else {
        stat_inc(f, &f->st.writes);
        stat_add(f, &f->st.triage_folded, folded);
    }
    return rc;
}

frrs_tri_ctx_t *frrs_tri_begin(web_frrs_t *f, long long now_s) {
    frrs_tri_ctx_t *x = malloc(sizeof(*x));
    if (!x) return NULL;
    if (ctx_open(f, x, now_s, 1) != 0) { free(x); return NULL; }
    return x;
}

void frrs_tri_end(frrs_tri_ctx_t *x, int committed) {
    if (!x) return;
    if (committed) stat_add(x->f, &x->f->st.triage_folded, x->folded);
    ctx_close(x);
    free(x);
}
#else
static int tri_write(web_frrs_t *f, const tri_subj_t *s, int state, int prev, int via,
                     const char *basis, const char *note, const char *by, const char *peer,
                     long long now_s, const char **why) {
    (void)f; (void)s; (void)state; (void)prev; (void)via; (void)basis; (void)note;
    (void)by; (void)peer; (void)now_s;
    *why = "no_store";
    return -1;
}
frrs_tri_ctx_t *frrs_tri_begin(web_frrs_t *f, long long now_s) {
    (void)f; (void)now_s;
    return NULL;
}
void frrs_tri_end(frrs_tri_ctx_t *x, int committed) { (void)x; (void)committed; }
#endif

/* A text member over its bound, refused with the bound and the length
 * that was sent, both in bytes of UTF-8 (#181): the page says "note too
 * long: N of M" from these, and a browser's maxlength counts UTF-16
 * units, so a note of 230 characters with a few accents in it can pass
 * the field and still be over. The text itself is never echoed. */
int frrs_text_refused(const web_jrec_t *r, const char *member, size_t max, const char *why,
                      char *body, size_t cap, size_t *len, int *status) {
    const web_jfield_t *f = web_jl_get(r, member);
    if (strcmp(why, "too_long") != 0 || !f)
        return frrs_error(400, why, member, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":\"too_long\",\"member\":");
    web_jw_str(&w, member);
    web_jw_raw(&w, ",\"length\":");     web_jw_int(&w, (long long)f->slen);
    web_jw_raw(&w, ",\"limit\":");      web_jw_int(&w, (long long)max);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 400;
    return 0;
}

static int post_triage(const web_m4_t *m, web_live_t *live, const web_jrec_t *r,
                       const char *peer, int via, long long now_s, char *body, size_t cap,
                       size_t *len, int *status) {
    static const char *const MEMBERS[] = { "id", "state", "note", "by", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad))
        return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char id[32], sw[16], note[WEB_FRRS_NOTE_MAX + 1], by[WEB_FRRS_BY_MAX + 1];
    if (!frrs_text(r, "id", 25, id, &why))
        return frrs_error(400, why, "id", body, cap, len, status);
    if (!frrs_text(r, "state", 12, sw, &why))
        return frrs_error(400, why, "state", body, cap, len, status);
    if (!frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why))
        return frrs_text_refused(r, "note", WEB_FRRS_NOTE_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "by", WEB_FRRS_BY_MAX, by, &why))
        return frrs_text_refused(r, "by", WEB_FRRS_BY_MAX, why, body, cap, len, status);
    if (!id[0]) return frrs_error(400, "missing_id", "id", body, cap, len, status);
    int state = -1;
    for (int s = 0; s < WEB_TRI_COUNT; s++) if (!strcmp(sw, STATE_WORD[s])) state = s;
    /* "Follow recommended" is the page's button and records via
     * recommended; an agent's row is via agent and nothing else, so it
     * names the state it means. */
    if (!strcmp(sw, "recommended") && via != WEB_TRI_VIA_AGENT) state = 100;
    if (state < 0) return frrs_error(400, "bad_state", "state", body, cap, len, status);
    tri_subj_t s;
    frrs_anom_t an;
    int rr = resolve_any(m, live, id, now_s, &s, &an);
    if (rr == -2) return frrs_error(409, "id_collision", "id", body, cap, len, status);
    if (rr < 0) return frrs_error(503, "read_failed", NULL, body, cap, len, status);
    if (rr == 0)
        return frrs_error(404, frrs_anom_id_ok(id) ? "no_such_anomaly" : "no_such_alert", "id",
                          body, cap, len, status);
    web_frrs_t *f = m->frrs;
    char basis[WEB_FRRS_BASIS_MAX + 1] = "";
    if (state == 100 && s.anom)
        return frrs_error(409, "no_recommendation", NULL, body, cap, len, status);
    if (state == 100) {
        state = web_frrs_recommend(f, s.type, basis, sizeof(basis), NULL);
        if (state == WEB_TRI_UNTRIAGED)
            return frrs_error(409, "no_recommendation", NULL, body, cap, len, status);
        via = WEB_TRI_VIA_RECOMMENDED;
    }
    web_tri_t cur;
    if (tri_lookup(f, &s, &cur) < 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    /* The state it already has, and no note that is new: nothing to
     * record, so no row (a double click, or a clear of an untriaged
     * alert, never spends its history). */
    int unchanged = state == cur.state && (!note[0] || !strcmp(note, cur.note));
    /* An anomaly's decided state carried from an earlier episode is not
     * this episode's until it is said again: saying it is a row. */
    if (unchanged && cur.carried && cur.state != WEB_TRI_UNTRIAGED) unchanged = 0;
    if (unchanged) {
        stat_inc(f, &f->st.triage_unchanged);
    } else {
        /* What an anomaly's id names is kept beside its first row: the
         * engine forgets the episode after a day, the note stays. */
        if (s.anom) {
            int g = frrs_anom_register(f, &an, now_s, &why);
            if (g != 0)
                return frrs_error(g > 0 ? 507 : 500, why, NULL, body, cap, len, status);
        }
        int w = tri_write(f, &s, state, cur.state, via, basis, note, by, peer, now_s, &why);
        if (w != 0)
            return frrs_error(w > 0 ? 507 : !strcmp(why, "store_busy") ? 503 : 500, why, NULL,
                              body, cap, len, status);
    }
    web_tri_t now;
    if (tri_lookup(f, &s, &now) < 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    web_jw_t jw;
    web_jw_init(&jw, body, cap);
    web_jw_raw(&jw, "{\"ok\":true,\"id\":");  web_jw_str(&jw, id);
    web_jw_raw(&jw, ",\"subject\":");         web_jw_str(&jw, s.subject);
    web_jw_raw(&jw, ",\"unchanged\":");       web_jw_raw(&jw, unchanged ? "true" : "false");
    web_jw_raw(&jw, ",\"current\":");
    tri_json(&jw, &now, 1);
    web_jw_raw(&jw, "}\n");
    if (jw.overflow) return -1;
    *len = jw.len;
    *status = 200;
    return 0;
}

/* ── triage export and import lines ─────────────────────────────────── */

#ifdef WITH_SQLITE
void frrs_triage_export(web_frrs_t *f, web_jw_t *w, long long *rows) {
    *rows = 0;
    sqlite3_stmt *s = NULL;
    /* An imported row's by and peer go out as its file said them: what
     * this sensor knows of them is the claim, and the next importer
     * records it as one. */
    if (!f->wr || sqlite3_prepare_v2(f->wr,
            "SELECT type, addr, port, first_seen, state, prev_state, via, basis, note,"
            " CASE WHEN via = 2 THEN claim_by ELSE who END,"
            " CASE WHEN via = 2 THEN claim_peer ELSE peer END, ts FROM triage"
            /* Alerts only: an anomaly's rows (type -1) are this
             * sensor's own baselines' findings, and the file's lines
             * are filed by an alert's descriptor. */
            " WHERE type >= 0 ORDER BY id",
            -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return;
    }
    while (sqlite3_step(s) == SQLITE_ROW && w->len + 4096 < w->cap) {
        char t[WEB_FRRS_NOTE_MAX + 1];
        const web_akb_t *k = web_akb_get(sqlite3_column_int(s, 0));
        web_jw_raw(w, "{\"type\":\"triage\",\"alert_type\":");
        frrs_str_or_null(w, k ? k->name : NULL);
        col_text(s, 1, t, sizeof(t));
        web_jw_raw(w, ",\"addr\":");       web_jw_str(w, t);
        web_jw_raw(w, ",\"port\":");       web_jw_int(w, sqlite3_column_int(s, 2));
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, sqlite3_column_int64(s, 3));
        web_jw_raw(w, ",\"state\":");      web_jw_str(w, web_frrs_state_word(sqlite3_column_int(s, 4)));
        web_jw_raw(w, ",\"prev_state\":"); web_jw_str(w, web_frrs_state_word(sqlite3_column_int(s, 5)));
        web_jw_raw(w, ",\"via\":");        web_jw_str(w, web_frrs_via_word(sqlite3_column_int(s, 6)));
        static const char *const K[] = { ",\"basis\":", ",\"note\":", ",\"by\":", ",\"peer\":" };
        for (int c = 0; c < 4; c++) {
            col_text(s, 7 + c, t, sizeof(t));
            web_jw_raw(w, K[c]);
            web_jw_str(w, t);
        }
        web_jw_raw(w, ",\"ts\":");         web_jw_int(w, sqlite3_column_int64(s, 11));
        web_jw_raw(w, "}\n");
        (*rows)++;
    }
    sqlite3_finalize(s);
}

int frrs_triage_import(web_frrs_t *f, frrs_tri_ctx_t *x, const web_jrec_t *r, int write,
                       long long now_s, const char *peer, const char **why) {
    static const char *const MEMBERS[] = {
        "type", "alert_type", "addr", "port", "first_seen", "state", "prev_state", "via",
        "basis", "note", "by", "peer", "ts", NULL,
    };
    const char *bad = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad)) { *why = "unknown_member"; return 1; }
    char at[48], addr[WEB_FRRS_ADDR_MAX + 1], sw[16], note[WEB_FRRS_NOTE_MAX + 1];
    char by[WEB_FRRS_BY_MAX + 1], basis[WEB_FRRS_BASIS_MAX + 1], pr[WEB_PEER_MAX];
    if (!frrs_text(r, "alert_type", 47, at, why) || !frrs_text(r, "addr", WEB_FRRS_ADDR_MAX, addr, why) ||
        !frrs_text(r, "state", 12, sw, why) || !frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, why) ||
        !frrs_text(r, "by", WEB_FRRS_BY_MAX, by, why) ||
        !frrs_text(r, "basis", WEB_FRRS_BASIS_MAX, basis, why) ||
        !frrs_text(r, "peer", WEB_PEER_MAX - 1, pr, why))
        return 1;
    int type = web_akb_find(at), state = -1;
    for (int s = 0; s < WEB_TRI_COUNT; s++) if (!strcmp(sw, STATE_WORD[s])) state = s;
    if (type < 0) { *why = "bad_alert_type"; return 1; }
    if (state < 0) { *why = "bad_state"; return 1; }
    char k[WEB_KEY_MAX + 1];
    if (addr[0] && web_key_ip(addr, k) != 0 && web_key_mac(addr, k) != 0) { *why = "bad_addr"; return 1; }
    if (addr[0]) snprintf(addr, sizeof(addr), "%.45s", k);
    long long port = web_jl_int(r, "port", 0), first = web_jl_int(r, "first_seen", 0);
    long long ts = web_jl_int(r, "ts", 0);
    if (port < 0 || port > 65535 || first < 0 || ts <= 0) { *why = "bad_number"; return 1; }
    /* A decision dated in the future would stay the newest of its alert
     * against every later one here: refused, beyond a clock's skew. */
    if (ts > now_s + WEB_FRRS_TS_AHEAD_S) { *why = "future_ts"; return 1; }
    if (!write) return 0;
    if (!x) return -1;
    /* Filed by its descriptor: the finding is attached when this
     * sloth.db has it (the next triage of it resolves it, §8). */
    tri_subj_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.subject, sizeof(s.subject), "x%d:%lld", type, first);
    s.type = type;
    s.port = (int)port;
    s.first = first;
    snprintf(s.addr, sizeof(s.addr), "%s", addr);
    long long n = 0, ni = 0, maxts = 0, firstid = 0;
    if (alert_counts(x, &s, 1, &n, &ni, &maxts, &firstid) != 0) return -1;
    /* Never newer than what is here: the current state is the newest
     * row, so a line no newer than this alert's newest would either be
     * the same import twice or an older decision put over a later one. */
    if (n > 0 && ts <= maxts) {
        int dup = 0;
        if (!x->dup && sqlite3_prepare_v2(f->wr, "SELECT 1 FROM triage t WHERE" DESC_MATCH("t.")
                                          "AND state = ?8 AND ts = ?9", -1, &x->dup, NULL) != SQLITE_OK)
            return -1;
        bind_subj(x->dup, &s);
        sqlite3_bind_int(x->dup, 8, state);
        sqlite3_bind_int64(x->dup, 9, ts);
        dup = sqlite3_step(x->dup) == SQLITE_ROW;
        sqlite3_reset(x->dup);
        sqlite3_clear_bindings(x->dup);
        *why = dup ? "already_here" : "older_than_here";
        return 1;
    }
    int prev = 0;
    const char *pw = web_jl_str(r, "prev_state");
    for (int q = 0; q < WEB_TRI_COUNT; q++) if (pw && !strcmp(pw, STATE_WORD[q])) prev = q;
    if (x->imported >= cap_part(f, 2)) { *why = "import_share_full"; return 1; }
    int room = tri_room(x, &s, WEB_TRI_VIA_IMPORT, state, n, ni, firstid, why);
    if (room) return room;
    /* who: nobody here typed it. peer: the importer. The file's by and
     * peer are kept as what they are, claims. */
    return tri_insert(x, &s, state, prev, WEB_TRI_VIA_IMPORT, basis, note, "", peer, ts, by, pr) ? -1 : 0;
}
#else
void frrs_triage_export(web_frrs_t *f, web_jw_t *w, long long *rows) {
    (void)f; (void)w;
    *rows = 0;
}
int frrs_triage_import(web_frrs_t *f, frrs_tri_ctx_t *x, const web_jrec_t *r, int write,
                       long long now_s, const char *peer, const char **why) {
    (void)f; (void)x; (void)r; (void)write; (void)now_s; (void)peer;
    *why = "no_store";
    return -1;
}
#endif

/* ── the record routes ──────────────────────────────────────────────── */

static int route_report(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "kind", "", 0 }, { "addr", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen || !ps[1].seen) return frrs_error(400, "missing_parameter", NULL, body, cap, len, status);
    int k = frrs_kind_find(ps[0].val);
    if (k < 0) return frrs_error(400, "bad_kind", NULL, body, cap, len, status);
    char addr[24];
    if (frrs_addr_canon(k, ps[1].val, addr, sizeof(addr)) != 0)
        return frrs_error(400, "bad_addr", NULL, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    frrs_report_json(m, live, k, addr, now_s, &w);
    web_jw_raw(&w, "\n");
    if (w.overflow) return frrs_error(503, "record_too_large", NULL, body, cap, len, status);
    *len = w.len;
    *status = 200;
    return 0;
}

/* The emitter an alert names: a MAC in a stream incident's key (the
 * ledger says whether it is a BSSID or a BLE address), else the one
 * sloth.db's rows name (web_adb_emitter), else the device holding its
 * match_ip. */
static int route_report_alert(const web_m4_t *m, web_live_t *live, const char *query,
                              long long now_s, char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[200];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return frrs_error(400, "missing_id", NULL, body, cap, len, status);
    const char *id = ps[0].val;
    if ((id[0] != 's' && id[0] != 'd') || strlen(id) < 2)
        return frrs_error(400, "bad_id", NULL, body, cap, len, status);
    for (const char *p = id + 1; *p; p++)
        if (!isalnum((unsigned char)*p)) return frrs_error(400, "bad_id", NULL, body, cap, len, status);
    char mac[18] = "", via[48] = "";
    int kind = FRRS_K_STA, found = 0, type = -1;
    char ip[WEB_LIVE_IP_MAX + 1] = "";
    web_frrs_t *f = m->frrs;
    web_sdb_conn_t c;
    int have_c = m->sdb && m->sdb->configured &&
                 web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0;
    if (id[0] == 's') {
        web_live_inc_t *e = calloc(1, sizeof(*e));
        if (!e) { if (have_c) web_slothdb_close(&c); return -1; }
        if (!live || !web_live_incident(live, id + 1, e)) {
            free(e);
            if (have_c) web_slothdb_close(&c);
            return frrs_error(404, "no_such_alert", NULL, body, cap, len, status);
        }
        type = e->type;
        snprintf(ip, sizeof(ip), "%s", e->match_ip);
        if (frrs_mac_in(e->key, mac)) {
            found = 1;
            snprintf(via, sizeof(via), "the MAC in the alert's key");
        } else if (have_c && e->key[0]) {
            int g = web_adb_emitter(&c, 0, e->key, mac, &kind);
            if (g > 0) { found = 1; snprintf(via, sizeof(via), "sloth.db's emitter in the key"); }
        }
        free(e);
    } else {
        long long rid = strtoll(id + 1, NULL, 10);
        web_adb_finding_t fd;
        if (!have_c || rid <= 0 || web_adb_finding(&c, rid, NULL, &fd) <= 0) {
            if (have_c) web_slothdb_close(&c);
            return frrs_error(404, "no_such_alert", NULL, body, cap, len, status);
        }
        type = fd.type;
        snprintf(ip, sizeof(ip), "%.45s", fd.ip);
        if (web_adb_emitter(&c, rid, NULL, mac, &kind) > 0) {
            found = 1;
            snprintf(via, sizeof(via), "sloth.db's emitter in the key");
        }
    }
    if (!found && ip[0] && have_c) {
        if (web_adb_device(&c, 0, NULL, ip, mac) > 0) {
            found = 1;
            kind = FRRS_K_STA;
            snprintf(via, sizeof(via), "the device holding match_ip");
        }
    }
    if (have_c) web_slothdb_close(&c);
    /* A MAC from a key: a BSSID or a BLE address when the ledger knows
     * it as one. */
    char addr[24];
    snprintf(addr, sizeof(addr), "%s", mac);
    if (found && kind == FRRS_K_STA && f) {
        pthread_mutex_lock(&f->lmu);
        const frrs_ble_t *bl[1] = { NULL };
        const frrs_bss_t *b = frrs_led_bss(f, mac);
        if (b && b->has_b) kind = FRRS_K_BSSID;
        else if (!frrs_led_sta(f, mac) && frrs_led_ble(f, mac, -1, bl, 1) == 1) {
            kind = FRRS_K_BLE;
            snprintf(addr, sizeof(addr), "%.17s/%d", mac, bl[0]->addr_type);
        }
        pthread_mutex_unlock(&f->lmu);
    }
    const web_akb_t *k = web_akb_get(type);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"alert\":{\"id\":");
    web_jw_str(&w, id);
    web_jw_raw(&w, ",\"type\":");
    frrs_str_or_null(&w, k ? k->name : NULL);
    web_jw_raw(&w, ",\"emitter_from\":");
    frrs_str_or_null(&w, found ? via : NULL);
    web_jw_raw(&w, "},\"record\":");
    if (found) {
        frrs_report_json(m, live, kind, addr, now_s, &w);
    } else {
        web_jw_raw(&w, "null,\"reason\":");
        web_jw_str(&w, "this alert names no emitter sloth heard on the air or holds a device "
                       "for: no MAC in its key and no device with its address");
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return frrs_error(503, "record_too_large", NULL, body, cap, len, status);
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── the dispatch ───────────────────────────────────────────────────── */

static const char *const GET_PATHS[] = {
    "/api/frrs/states", "/api/frrs/history", "/api/frrs/summary", "/api/frrs/recommend",
    "/api/frrs/report", "/api/frrs/report/alert", "/api/frrs/tacdb", "/api/frrs/tacdb/view",
    "/api/frrs/suggest", "/api/frrs/export", "/api/frrs/related",
    "/api/frrs/notes", "/api/frrs/notes/marks", NULL,
};

int web_frrs_path(const char *path) {
    for (int i = 0; GET_PATHS[i]; i++) if (!strcmp(path, GET_PATHS[i])) return 1;
    return web_http_post_path(path);
}

int web_frrs_route(const web_m4_t *m, web_live_t *live, const web_req_t *rq,
                   long long now_s, long long now_ms, char *body, size_t cap,
                   size_t *len, int *status, char *extra, size_t extracap,
                   char **big, size_t *biglen) {
    static const web_m4_t none;
    if (!m) m = &none;
    extra[0] = '\0';
    *big = NULL;
    *biglen = 0;
    web_frrs_t *f = m->frrs;
    int post = web_http_post_path(rq->path);
    if (post != rq->is_post) {
        /* A write path answers POST only, and a read path GET and HEAD
         * only: a GET can never write. */
        snprintf(extra, extracap, "Allow: %s\r\n", post ? "POST" : "GET, HEAD");
        return frrs_error(405, "method_not_allowed", NULL, body, cap, len, status);
    }
    if (!post) {
        if (rq->query_long || strlen(rq->query) >= WEB_QUERY_ROUTE_MAX)
            return frrs_error(400, "query_too_long", NULL, body, cap, len, status);
        const char *p = rq->path, *q = rq->query;
        if (!strcmp(p, "/api/frrs/states")) return route_states(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/history")) return route_history(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/summary")) return route_summary(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/recommend")) return route_recommend(m, q, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/report")) return route_report(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/report/alert"))
            return route_report_alert(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/tacdb")) return frrs_tacdb_get(m, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/tacdb/view")) return frrs_tacdb_view(m, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/suggest")) return frrs_suggest_get(m, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/related"))
            return frrs_related_get(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/notes"))
            return web_notes_get(m, live, q, now_s, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/notes/marks"))
            return web_notes_marks(m, q, body, cap, len, status);
        if (!strcmp(p, "/api/frrs/export")) {
            if (q[0]) return frrs_error(400, "unknown_parameter", NULL, body, cap, len, status);
            int rc = frrs_export(m, now_s, big, biglen, body, cap, len, status);
            if (rc == 0 && *big)
                snprintf(extra, extracap, "Content-Disposition: attachment; "
                                          "filename=\"slothweb-tacdb.jsonl\"\r\n");
            return rc;
        }
        return frrs_error(404, "not_found", NULL, body, cap, len, status);
    }
    /* A POST: the header checks, unless the server ran them before it
     * read the body; then the body. */
    if (!rq->gated) {
        const char *why = NULL;
        int g = web_frrs_gate(f, rq, now_ms, &why, extra, extracap);
        if (g) return frrs_error(g, why, NULL, body, cap, len, status);
    }
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    if (!f->writes) return frrs_error(405, "read_only", NULL, body, cap, len, status);
    /* How the row will be marked, from what the request proved and
     * never from what its body says (web_agent.h). The gate ran the
     * same check; here it decides via. An agent writes triage, notes
     * and links: the TACDB and the import are the operator's. */
    const char *awhy = NULL;
    int agent = web_agent_check(f->agent_secret, rq, &awhy);
    if (agent < 0) return frrs_error(403, awhy, NULL, body, cap, len, status);
    if (agent && strcmp(rq->path, "/api/frrs/triage") && strcmp(rq->path, "/api/frrs/relate") &&
        strcmp(rq->path, "/api/frrs/note"))
        return frrs_error(403, "agent_path", NULL, body, cap, len, status);
    if (!strcmp(rq->path, "/api/frrs/import")) {
        int rc = frrs_import(m, rq, now_s, body, cap, len, status);
        if (rc == 0 && *status == 200) stat_inc(f, &f->st.imports);
        return rc;
    }
    if (!rq->body || rq->body_len == 0 || rq->body_len > WEB_POST_MAX) {
        stat_inc(f, &f->st.refused_body);
        return frrs_error(400, "bad_body", NULL, body, cap, len, status);
    }
    web_jrec_t *r = malloc(sizeof(*r));
    if (!r) return -1;
    int pr = web_jl_parse(rq->body, rq->body_len, r);
    if (pr != WEB_JL_OK && pr != WEB_JL_ETYPE) {
        free(r);
        stat_inc(f, &f->st.refused_body);
        return frrs_error(400, "bad_body", NULL, body, cap, len, status);
    }
    int rc, via = agent ? WEB_TRI_VIA_AGENT : WEB_TRI_VIA_MANUAL;
    /* An agent's row always says which agent. */
    const char *aby = agent ? web_jl_str(r, "by") : NULL;
    if (agent && (!aby || !aby[0])) {
        free(r);
        stat_inc(f, &f->st.refused_body);
        return frrs_error(400, "missing_by", "by", body, cap, len, status);
    }
    if (!strcmp(rq->path, "/api/frrs/triage"))
        rc = post_triage(m, live, r, rq->peer, via, now_s, body, cap, len, status);
    else if (!strcmp(rq->path, "/api/frrs/relate"))
        rc = frrs_relate_post(m, live, r, rq->peer, via, now_s, body, cap, len, status);
    else if (!strcmp(rq->path, "/api/frrs/note"))
        rc = web_notes_post(m, live, r, rq->peer, via, now_s, body, cap, len, status);
    else
        rc = frrs_tacdb_post(m, rq->path, r, rq->peer, now_s, body, cap, len, status);
    free(r);
    if (rc == 0 && *status >= 400 && *status < 500 && *status != 404 && *status != 409)
        stat_inc(f, &f->st.refused_body);
    if (rc == 0 && *status == 200 && agent) stat_inc(f, &f->st.agent_writes);
    return rc;
}

void web_frrs_set_agent(web_frrs_t *f, const char *secret) {
    snprintf(f->agent_secret, sizeof(f->agent_secret), "%s", secret ? secret : "");
}

/* ── open, close, health ────────────────────────────────────────────── */

int web_frrs_init(web_frrs_t *f, web_store_t *store, const char *assess_dir,
                  int writes, char *err, size_t errsz) {
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->lmu, NULL);
    f->lmu_init = 1;
    f->writes = writes;
    f->triage_cap = WEB_FRRS_TRIAGE_CAP;
    f->note_cap = WEB_NOTE_CAP;
    f->note_per = WEB_NOTE_PER;
    err[0] = '\0';
    f->led = calloc(1, sizeof(*f->led));
    if (!f->led) {
        snprintf(err, errsz, "frrs: out of memory for the ledger");
        return -1;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    f->nonce = (unsigned)ts.tv_nsec ^ (unsigned)ts.tv_sec ^ (unsigned)getpid() * 2654435761u;
    /* A directory that is not there (an install without the
     * assessments) is no directory: "no recommendation yet". */
    struct stat sb;
    if (assess_dir && assess_dir[0] && stat(assess_dir, &sb) == 0 && S_ISDIR(sb.st_mode))
        snprintf(f->assess_dir, sizeof(f->assess_dir), "%s", assess_dir);
    if (store && store->st.open) {
        if (web_store_open_aux(store, &f->wr, err, errsz) != 0) {
            f->wr = NULL;
            return -1;
        }
    }
    return 0;
}

void web_frrs_destroy(web_frrs_t *f) {
    if (!f->lmu_init) return;
#ifdef WITH_SQLITE
    if (f->wr) sqlite3_close(f->wr);
#endif
    f->wr = NULL;
    free(f->led);
    f->led = NULL;
    pthread_mutex_destroy(&f->lmu);
    f->lmu_init = 0;
}

void web_frrs_stats(web_frrs_t *f, web_frrs_stats_t *out) {
    pthread_mutex_lock(&f->lmu);
    *out = f->st;
    pthread_mutex_unlock(&f->lmu);
}

void web_frrs_health(web_frrs_t *f, web_jw_t *w) {
    web_jw_raw(w, ",\"frrs\":");
    if (!f || !f->lmu_init) { web_jw_raw(w, "null"); return; }
    web_frrs_stats_t s;
    int nb, ns, nl, ni;
    pthread_mutex_lock(&f->lmu);
    s = f->st;
    nb = f->led ? f->led->nbss : 0;
    ns = f->led ? f->led->nsta : 0;
    nl = f->led ? f->led->nble : 0;
    ni = f->led ? f->led->nip : 0;
    pthread_mutex_unlock(&f->lmu);
    web_jw_raw(w, "{\"writes\":");     web_jw_raw(w, f->wr && f->writes ? "true" : "false");
    web_jw_raw(w, ",\"store\":");      web_jw_str(w, f->wr ? "open" : "none");
    web_jw_raw(w, ",\"triage_rows\":"); jw_count(w, q_count(f, "SELECT COUNT(*) FROM triage"));
    web_jw_raw(w, ",\"triage_cap\":");  web_jw_int(w, f->triage_cap);
    web_jw_raw(w, ",\"triage_folded\":"); web_jw_int(w, (long long)s.triage_folded);
    web_jw_raw(w, ",\"triage_unchanged\":"); web_jw_int(w, (long long)s.triage_unchanged);
    web_jw_raw(w, ",\"tacdb\":{\"units\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM tacdb_unit WHERE deleted = 0"));
    web_jw_raw(w, ",\"platforms\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM tacdb_platform WHERE deleted = 0"));
    web_jw_raw(w, ",\"emitters\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM tacdb_emitter WHERE deleted = 0"));
    web_jw_raw(w, ",\"dismissed\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM tacdb_dismiss"));
    web_jw_raw(w, "},\"ledger\":{\"bssid\":"); web_jw_int(w, nb);
    web_jw_raw(w, ",\"sta\":");        web_jw_int(w, ns);
    web_jw_raw(w, ",\"ble\":");        web_jw_int(w, nl);
    web_jw_raw(w, ",\"ip\":");         web_jw_int(w, ni);
    web_jw_raw(w, ",\"evictions\":");  web_jw_int(w, (long long)s.ledger_evictions);
    web_jw_raw(w, "},\"posts\":");     web_jw_int(w, (long long)s.writes);
    web_jw_raw(w, ",\"write_errors\":"); web_jw_int(w, (long long)s.write_errors);
    web_jw_raw(w, ",\"rate_limited\":"); web_jw_int(w, (long long)s.rate_limited);
    web_jw_raw(w, ",\"refused\":{\"origin\":"); web_jw_int(w, (long long)s.refused_origin);
    web_jw_raw(w, ",\"content_type\":"); web_jw_int(w, (long long)s.refused_ctype);
    web_jw_raw(w, ",\"body\":");       web_jw_int(w, (long long)s.refused_body);
    web_jw_raw(w, "},\"imports\":");   web_jw_int(w, (long long)s.imports);
    web_jw_raw(w, ",\"exports\":");    web_jw_int(w, (long long)s.exports);
    web_jw_raw(w, ",\"recommendations\":");
    web_jw_str(w, f->assess_dir[0] ? "dir" : "none");
    /* Anomaly triage and the links (web_relate.c): additive, last. */
    web_jw_raw(w, ",\"anomaly_subjects\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM anom_subject"));
    web_jw_raw(w, ",\"links\":");
    jw_count(w, q_count(f, "SELECT COUNT(*) FROM relation"));
    /* The plain notes (web_notes.h): additive, last. */
    web_jw_raw(w, ",\"notes\":{\"rows\":");
    jw_count(w, web_notes_rows(f));
    web_jw_raw(w, ",\"cap\":");       web_jw_int(w, f->note_cap);
    web_jw_raw(w, ",\"added\":");     web_jw_int(w, (long long)s.notes_added);
    web_jw_raw(w, ",\"retracted\":"); web_jw_int(w, (long long)s.notes_retracted);
    web_jw_raw(w, ",\"folded\":");    web_jw_int(w, (long long)s.notes_folded);
    web_jw_raw(w, "}");
    /* The agent's path (web_agent.h): whether a secret is set, never
     * the secret; its writes and its refusals. */
    web_jw_raw(w, ",\"agent\":{\"enabled\":");
    web_jw_raw(w, f->agent_secret[0] ? "true" : "false");
    web_jw_raw(w, ",\"writes\":");    web_jw_int(w, (long long)s.agent_writes);
    web_jw_raw(w, ",\"refused\":");   web_jw_int(w, (long long)s.refused_agent);
    web_jw_raw(w, "}");
    web_jw_raw(w, "}");
}
