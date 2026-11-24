#include <string.h>
#include "cov_interval.h"
#include "rule_coverage.h"
#include "sys_status.h"
#include "jsonl.h"
#include "jsonl_internal.h"

/* The per-interval coverage record (#242 item 2). Contract:
 * cov_interval.h. Main thread only: the sampler, the JSONL stage and
 * the database tick all run on it. */

static struct {
    int      open;
    time_t   start;
    uint64_t start_ms;
    cov_iv_t cur;                  /* the open interval's channels */
    uint32_t seq;                  /* newest closed */
    cov_iv_t ring[COV_IV_RING];    /* closed, by seq % COV_IV_RING */
    uint32_t emitted;              /* newest seq written to the stream */
} g;

void cov_iv_reset(void) { memset(&g, 0, sizeof(g)); }

const char *cov_fc_name(int fc) {
    static const char *const n[COV_FC_N] = {
        "beacon", "probe", "auth", "assoc", "deauth", "action", "ctrl",
        "data", "eapol", "other", "fcs_bad",
    };
    return fc >= 0 && fc < COV_FC_N ? n[fc] : "";
}

const char *cov_ivb_name(int b) {
    static const char *const n[COV_IVB_N] = { "2.4", "5", "5dfs", "6", "unknown" };
    return b >= 0 && b < COV_IVB_N ? n[b] : "";
}

int cov_ivb_of_mhz(int mhz) {
    switch (cov_band_of_mhz(mhz)) {
    case COV_B_24:   return COV_IVB_24;
    case COV_B_5:    return COV_IVB_5;
    case COV_B_5DFS: return COV_IVB_5DFS;
    case COV_B_6:    return COV_IVB_6;
    default:         return COV_IVB_UNKNOWN;
    }
}

void cov_iv_add(int radio, int freq_mhz, int channel, uint64_t ms,
                uint64_t frames) {
    if (!g.open || (ms == 0 && frames == 0)) return;
    cov_iv_t *c = &g.cur;
    int i = 0;
    while (i < c->nchan && !(c->chan[i].radio == radio && c->chan[i].freq_mhz == freq_mhz))
        i++;
    if (i == c->nchan) {
        if (c->nchan >= COV_IV_CHAN_MAX) {
            /* The entry is not written, but its time was radio time on
             * a known band: kept in the band and radio totals (which
             * cov_iv_close() adds the listed channels to), so the
             * shares describe the whole minute and only the per-channel
             * breakdown is short. */
            c->chan_overflow++;
            c->band_ms[cov_ivb_of_mhz(freq_mhz)] += ms;
            c->radio_ms += ms;
            return;
        }
        c->nchan++;
        c->chan[i].radio    = radio;
        c->chan[i].freq_mhz = freq_mhz;
        c->chan[i].channel  = channel;
    }
    c->chan[i].ms     += ms;
    c->chan[i].frames += frames;
}

int cov_iv_open(time_t wall, uint64_t mono_ms) {
    if (g.open) return 0;
    memset(&g.cur, 0, sizeof(g.cur));
    g.open     = 1;
    g.start    = wall;
    g.start_ms = mono_ms;
    return 1;
}

int cov_iv_is_open(void) { return g.open; }

int cov_iv_due(uint64_t mono_ms) {
    return g.open && mono_ms >= g.start_ms && mono_ms - g.start_ms >= COV_IV_MS;
}

void cov_iv_abandon(void) { g.open = 0; }

/* The rows a reader would call up or down. A row that is not configured
 * is a source this sensor was never given, and listing every one of
 * them each minute says nothing. */
static void take_sources(cov_iv_t *iv) {
    const sys_snapshot_t *sn = sys_status_get();
    if (!sn || !sn->valid) return;
    for (int k = 0; k < SYS_SRC_COUNT && iv->nsrc < COV_IV_SRC_MAX; k++) {
        const sys_source_t *o = &sn->src[k];
        if (!o->name || o->state == SYS_ST_NOT_CONFIGURED) continue;
        iv->src[iv->nsrc].name  = o->name;
        iv->src[iv->nsrc].state = sys_src_state_name(o->state);
        iv->nsrc++;
    }
}

void cov_iv_close(time_t wall, uint64_t mono_ms, const uint64_t *frames,
                  int has_cap, uint64_t cap_drop, uint64_t cap_ifdrop,
                  int has_mon, uint64_t mon_drop, uint64_t mon_ifdrop) {
    if (!g.open) return;
    cov_iv_t *iv = &g.cur;
    iv->seq    = g.seq + 1;
    iv->start  = g.start;
    iv->end    = wall;
    iv->dur_ms = mono_ms >= g.start_ms ? mono_ms - g.start_ms : 0;
    for (int i = 0; i < iv->nchan; i++) {
        iv->band_ms[cov_ivb_of_mhz(iv->chan[i].freq_mhz)] += iv->chan[i].ms;
        iv->radio_ms += iv->chan[i].ms;
    }
    if (frames) memcpy(iv->frames, frames, sizeof(iv->frames));
    iv->has_cap = has_cap;
    iv->cap_drop = has_cap ? cap_drop : 0;
    iv->cap_ifdrop = has_cap ? cap_ifdrop : 0;
    iv->has_mon = has_mon;
    iv->mon_drop = has_mon ? mon_drop : 0;
    iv->mon_ifdrop = has_mon ? mon_ifdrop : 0;
    take_sources(iv);
    g.seq = iv->seq;
    g.ring[g.seq % COV_IV_RING] = *iv;
    g.open = 0;
    cov_iv_open(wall, mono_ms);
}

uint32_t cov_iv_seq(void) { return g.seq; }

int cov_iv_get(uint32_t seq, cov_iv_t *out) {
    if (seq == 0 || seq > g.seq || g.seq - seq >= COV_IV_RING) return 0;
    if (out) *out = g.ring[seq % COV_IV_RING];
    return 1;
}

/* ── Writers ─────────────────────────────────────────────────────── */

int cov_iv_chans_json(const cov_iv_t *iv, char *out, int sz) {
    int off = 0;
    if (!out || sz <= 0) return 0;
    out[0] = '\0';
    appendf(out, sz, &off, "[");
    for (int i = 0; iv && i < iv->nchan; i++) {
        const cov_iv_chan_t *c = &iv->chan[i];
        appendf(out, sz, &off,
                "%s{\"radio\":%d,\"ch\":%d,\"freq_mhz\":%d,\"band\":\"%s\","
                "\"ms\":%llu,\"frames\":%llu}",
                i ? "," : "", c->radio, c->channel, c->freq_mhz,
                cov_ivb_name(cov_ivb_of_mhz(c->freq_mhz)),
                (unsigned long long)c->ms, (unsigned long long)c->frames);
    }
    appendf(out, sz, &off, "]");
    return off;
}

int cov_iv_srcs_json(const cov_iv_t *iv, char *out, int sz) {
    int off = 0;
    if (!out || sz <= 0) return 0;
    out[0] = '\0';
    appendf(out, sz, &off, "[");
    for (int i = 0; iv && i < iv->nsrc; i++)
        appendf(out, sz, &off, "%s{\"name\":\"%s\",\"state\":\"%s\"}",
                i ? "," : "", iv->src[i].name, iv->src[i].state);
    appendf(out, sz, &off, "]");
    return off;
}

/* A share in thousandths, so it reads as a fraction with three places
 * and needs no floating point to agree with the ms beside it. */
static void share(char *buf, int *off, const char *key, uint64_t part,
                  uint64_t whole) {
    unsigned long long m = whole ? (part * 1000 + whole / 2) / whole : 0;
    appendf(buf, LINEBUF, off, ",\"%s\":%llu.%03llu", key, m / 1000, m % 1000);
}

static void emit_one(const cov_iv_t *iv) {
    char buf[LINEBUF];
    int off = 0;
    start_obj(buf, LINEBUF, &off, "coverage_interval", iv->end);
    kv_int(buf, LINEBUF, &off, "seq", (long long)iv->seq);
    kv_int(buf, LINEBUF, &off, "start", (long long)iv->start);
    kv_int(buf, LINEBUF, &off, "dur_ms", (long long)iv->dur_ms);
    kv_int(buf, LINEBUF, &off, "radio_ms", (long long)iv->radio_ms);

    char arr[LINEBUF / 2];
    cov_iv_chans_json(iv, arr, (int)sizeof(arr));
    appendf(buf, LINEBUF, &off, ",\"chans\":%s", arr);
    kv_int(buf, LINEBUF, &off, "chan_overflow", iv->chan_overflow);

    appendf(buf, LINEBUF, &off, ",\"bands\":[");
    int first = 1;
    for (int b = 0; b < COV_IVB_N; b++) {
        if (!iv->band_ms[b]) continue;
        int o2 = 0;
        char one[96];
        appendf(one, (int)sizeof(one), &o2, "%s{\"band\":\"%s\",\"ms\":%llu",
                first ? "" : ",", cov_ivb_name(b),
                (unsigned long long)iv->band_ms[b]);
        appendf(buf, LINEBUF, &off, "%s", one);
        share(buf, &off, "share", iv->band_ms[b], iv->radio_ms);
        appendf(buf, LINEBUF, &off, "}");
        first = 0;
    }
    appendf(buf, LINEBUF, &off, "]");

    appendf(buf, LINEBUF, &off, ",\"frames\":{");
    for (int k = 0; k < COV_FC_N; k++)
        appendf(buf, LINEBUF, &off, "%s\"%s\":%llu", k ? "," : "",
                cov_fc_name(k), (unsigned long long)iv->frames[k]);
    appendf(buf, LINEBUF, &off, "}");

    if (iv->has_cap) {
        kv_int(buf, LINEBUF, &off, "capture_drop", (long long)iv->cap_drop);
        kv_int(buf, LINEBUF, &off, "capture_ifdrop", (long long)iv->cap_ifdrop);
    }
    if (iv->has_mon) {
        kv_int(buf, LINEBUF, &off, "monitor_drop", (long long)iv->mon_drop);
        kv_int(buf, LINEBUF, &off, "monitor_ifdrop", (long long)iv->mon_ifdrop);
    }
    cov_iv_srcs_json(iv, arr, (int)sizeof(arr));
    appendf(buf, LINEBUF, &off, ",\"sources\":%s", arr);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void cov_iv_emit(void) {
    if (!any_sink()) { g.emitted = g.seq; return; }
    uint32_t from = g.emitted + 1;
    if (g.seq >= COV_IV_RING && from <= g.seq - COV_IV_RING)
        from = g.seq - COV_IV_RING + 1;
    for (uint32_t q = from; q <= g.seq; q++) {
        cov_iv_t iv;
        if (cov_iv_get(q, &iv)) emit_one(&iv);
    }
    g.emitted = g.seq;
}
