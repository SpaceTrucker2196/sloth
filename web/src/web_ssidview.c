#include "web_ssidview.h"
#include "web_own.h"

#include <stdlib.h>

#include "web_chain.h"
#include "web_metrics.h"
#include "web_probeq.h"
#include "web_series.h"
#include "web_wifi.h"

/* ── the parameter ───────────────────────────────────────────────────── */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int web_ssid_param(const char *val, char *out) {
    out[0] = '\0';
    if (!val) return -1;
    if (!strcmp(val, "-")) return 0;
    size_t n = strlen(val), o = 0;
    if (n == 0 || n > 43 || n % 4 == 1) return -1;
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        const char *at = val[i] ? strchr(B64, val[i]) : NULL;
        if (!at) return -1;
        acc = ((acc << 6) | (unsigned)(at - B64)) & 0xffffu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            unsigned char b = (unsigned char)((acc >> bits) & 0xffu);
            if (!b || o >= WEB_SSID_OCTETS) return -1;
            out[o++] = (char)b;
        }
    }
    /* One spelling an octet string: the bits left over are zero. */
    if (acc & ((1u << bits) - 1u)) return -1;
    out[o] = '\0';
    return (int)o;
}

void web_ssid_param_of(const char *ssid, size_t n, char *out) {
    size_t o = 0;
    if (n > WEB_SSID_OCTETS) n = WEB_SSID_OCTETS;
    if (!n) { out[0] = '-'; out[1] = '\0'; return; }
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        acc = ((acc << 8) | (unsigned char)ssid[i]) & 0xffffu;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[o++] = B64[(acc >> bits) & 63u];
        }
    }
    if (bits) out[o++] = B64[(acc << (6 - bits)) & 63u];
    out[o] = '\0';
}

#ifdef WITH_SQLITE

/* ── /api/wifi/ssid ──────────────────────────────────────────────────── */

typedef struct {
    char      bssid[WEB_KEY_MAX + 1];
    char      vendor[WEB_SDB_TEXT_MAX + 1], enc[WEB_SDB_TEXT_MAX + 1],
              akm[WEB_SDB_TEXT_MAX + 1];
    long long channel, akm_bits, mfp, signal, first_seen, last_seen;
    int       has_signal, current;
} sb_t;

/* The largest one BSSID row renders to: three text members at their
 * cut length escaped six-fold, every AKM name, the twin links. */
#define SB_ROW_MAX 2600
/* Kept for the lists after the BSSIDs. */
#define SB_TAIL    32000

static void sb_read(sqlite3_stmt *st, sb_t *b, int base, int current) {
    memset(b, 0, sizeof(*b));
    ctext(st, base, b->vendor, WEB_SDB_TEXT_MAX);
    b->channel = sqlite3_column_int64(st, base + 1);
    ctext(st, base + 2, b->enc, WEB_SDB_TEXT_MAX);
    ctext(st, base + 3, b->akm, WEB_SDB_TEXT_MAX);
    b->akm_bits = sqlite3_column_int64(st, base + 4);
    b->mfp = sqlite3_column_int64(st, base + 5);
    b->has_signal = sqlite3_column_type(st, base + 6) != SQLITE_NULL;
    b->signal = sqlite3_column_int64(st, base + 6);
    b->current = current;
}

static void sb_json(web_jw_t *w, const web_m4_t *m, sqlite3_stmt *karma,
                    const sb_t *b, long long now_s) {
    web_jw_raw(w, "{\"bssid\":");     web_jw_str(w, b->bssid);
    web_jw_raw(w, ",\"current\":");   jw_bool(w, b->current);
    web_jw_raw(w, ",\"designated\":"); web_own_jw(w, web_own_bssid(b->bssid));
    web_jw_raw(w, ",\"vendor\":");    jw_text_or_null(w, b->vendor);
    web_jw_raw(w, ",\"channel\":");   web_jw_int(w, b->channel & 0xffff);
    web_jw_raw(w, ",\"enc\":");       jw_text_or_null(w, b->enc);
    web_jw_raw(w, ",\"akm\":");       jw_text_or_null(w, b->akm);
    unsigned long long bits = (unsigned long long)b->akm_bits & 0xffffffffULL;
    web_jw_raw(w, ",\"akm_names\":[");
    int k = 0;
    for (int t = 0; t < 32; t++) {
        if (!(bits & (1ULL << t))) continue;
        const char *nm = web_akm_name(t);
        char other[16];
        if (!strcmp(nm, "?")) { snprintf(other, sizeof(other), "AKM-%d", t); nm = other; }
        if (k++) web_jw_raw(w, ",");
        web_jw_str(w, nm);
    }
    static const char *const MFP[] = { "off", "capable", "required" };
    long long mfp = b->mfp < 0 ? 0 : b->mfp > 2 ? 2 : b->mfp;
    web_jw_raw(w, "],\"mfp_word\":");  web_jw_str(w, MFP[mfp]);
    web_jw_raw(w, ",\"signal\":");     jw_signal(w, b->has_signal, b->signal);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, b->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, b->last_seen);
    web_jw_raw(w, ",\"karma\":");
    int have = 0;
    if (karma) {
        sqlite3_reset(karma);
        bind_t(karma, 1, b->bssid);
        if (sqlite3_step(karma) == SQLITE_ROW) {
            have = 1;
            web_jw_raw(w, "{\"score\":");      web_jw_int(w, sqlite3_column_int64(karma, 0));
            web_jw_raw(w, ",\"ssid_count\":"); web_jw_int(w, sqlite3_column_int64(karma, 1));
            web_jw_raw(w, "}");
        }
    }
    if (!have) web_jw_raw(w, "null");
    /* The pairs the stream's twin_episode made with this BSSID, since
     * slothweb started (web_chain.h): sloth.db keeps none the page may
     * read. */
    web_jw_raw(w, ",\"twins\":[");
    if (m->chain) {
        web_chain_pair_t pr[WEB_CHAIN_LINKS];
        long long since = 0;
        int n = web_chain_links(m->chain, b->bssid, 0, now_s + 86400, pr,
                                WEB_CHAIN_LINKS, &since);
        for (int i = 0; i < n; i++) {
            web_jw_raw(w, i ? ",{\"real\":" : "{\"real\":");
            web_jw_str(w, pr[i].real);
            web_jw_raw(w, ",\"twin\":");        web_jw_str(w, pr[i].twin);
            web_jw_raw(w, ",\"attributed\":");  jw_bool(w, pr[i].attributed);
            web_jw_raw(w, ",\"tainted\":");     jw_bool(w, pr[i].taint_ts > 0);
            web_jw_raw(w, ",\"confidence\":");
            if (pr[i].confidence >= 0) web_jw_int(w, pr[i].confidence);
            else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"first_seen\":");  web_jw_int(w, pr[i].first_ts);
            web_jw_raw(w, ",\"last_seen\":");   web_jw_int(w, pr[i].last_ts);
            web_jw_raw(w, "}");
        }
    }
    web_jw_raw(w, "]}");
}

/* The component src/alert_key.c akey_remote(k, ssid, 32) writes for an
 * SSID: ':', its first 32 octets with anything outside 0x21..0x7e and
 * ':' ',' '[' ']' as '_', ':', and the 16 hex digits of FNV-1a 64 over
 * all of it. An alert keyed by this SSID holds exactly this. */
static void key_token(const char *ssid, char *out, size_t cap) {
    size_t n = strlen(ssid), m = n < 32 ? n : 32, o = 0;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)ssid[i];
        h *= 0x100000001b3ULL;
    }
    out[o++] = ':';
    for (size_t i = 0; i < m && o + 20 < cap; i++) {
        unsigned char c = (unsigned char)ssid[i];
        int keep = c > 0x20 && c < 0x7f && c != ':' && c != ',' && c != '[' && c != ']';
        out[o++] = keep ? (char)c : '_';
    }
    snprintf(out + o, cap - o, ":%016llx", (unsigned long long)h);
}

/* The alert walk's bound, in units of work: a row read costs about
 * SSID_ALERT_ROW units and each BSSID's instr() over its key one more
 * (measured on the suite's large file: 30,000 rows against 40 BSSIDs in
 * 220 ms, against one in 47 ms). 320,000 is some 55 ms of it. */
#define SSID_ALERT_WORK 320000LL
#define SSID_ALERT_ROW  8

#define SSID_IS  "(b.ssid = ?1 OR (?1 = '' AND b.ssid IS NULL))"

typedef struct {
    char      title[WEB_SDB_TEXT_MAX + 1];
    long long type, sev, count, first_seen, last_seen, rid, rows;
} sa_t;

int web_ssid_route(const web_m4_t *m, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    if (no_db(m)) return NO_DB_ANSWER();
    web_param_t ps[1] = { { "ssid", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return answer_error(400, "missing_ssid", NULL, body, cap, len, status);
    char ssid[WEB_SSID_OCTETS + 1];
    int octets = web_ssid_param(ps[0].val, ssid);
    if (octets < 0) return answer_error(400, "bad_ssid", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

    web_sdb_conn_t conn;
    if (open_db(m, &conn, now_s, body, cap, len, status) != 0) return 0;

    sb_t *bs = calloc(WEB_SSID_BSSIDS * 2, sizeof(*bs));
    if (!bs) { web_slothdb_close(&conn); return -1; }
    int nb = 0, ncur = 0;
    long long total = 0, first = 0, last = 0;
    sqlite3_stmt *st = prep(&conn,
        "SELECT count(*), min(b.first_seen), max(b.last_seen) FROM beacon_aps b"
        " WHERE " SSID_IS);
    if (st) {
        bind_t(st, 1, ssid);
        if (sqlite3_step(st) == SQLITE_ROW) {
            total = sqlite3_column_int64(st, 0);
            first = sqlite3_column_int64(st, 1);
            last = sqlite3_column_int64(st, 2);
        }
        sqlite3_finalize(st);
    }
    st = prep(&conn,
        "SELECT b.bssid, b.first_seen, b.last_seen, COALESCE(b.vendor,''),"
        " COALESCE(b.channel,0), COALESCE(b.enc,''), COALESCE(b.akm,''),"
        " COALESCE(b.akm_bits,0), COALESCE(b.mfp,0), b.signal_dbm FROM beacon_aps b"
        " WHERE " SSID_IS " ORDER BY b.last_seen DESC, b.bssid LIMIT ?2");
    if (st) {
        bind_t(st, 1, ssid);
        sqlite3_bind_int(st, 2, WEB_SSID_BSSIDS);
        while (sqlite3_step(st) == SQLITE_ROW && nb < WEB_SSID_BSSIDS) {
            char mac[WEB_KEY_MAX + 1];
            if (!cmac(st, 0, mac)) continue;
            sb_read(st, &bs[nb], 3, 1);
            snprintf(bs[nb].bssid, sizeof(bs[nb].bssid), "%s", mac);
            bs[nb].first_seen = sqlite3_column_int64(st, 1);
            bs[nb].last_seen = sqlite3_column_int64(st, 2);
            nb++;
        }
        sqlite3_finalize(st);
    }
    ncur = nb;
    /* The BSSIDs that beaconed it once and beacon something else now:
     * the times are when each beaconed this SSID. The empty SSID has no
     * beacon_ap_ssids row. */
    int past_more = 0;
    st = octets ? prep(&conn,
        "SELECT h.bssid, h.first_seen, h.last_seen, COALESCE(b.vendor,''),"
        " COALESCE(b.channel,0), COALESCE(b.enc,''), COALESCE(b.akm,''),"
        " COALESCE(b.akm_bits,0), COALESCE(b.mfp,0), b.signal_dbm"
        " FROM beacon_ap_ssids h LEFT JOIN beacon_aps b ON b.bssid = h.bssid"
        " WHERE h.ssid = ?1 AND (b.ssid IS NULL OR b.ssid <> ?1)"
        " ORDER BY h.last_seen DESC, h.bssid LIMIT ?2") : NULL;
    if (st) {
        bind_t(st, 1, ssid);
        sqlite3_bind_int(st, 2, WEB_SSID_BSSIDS + 1);
        while (sqlite3_step(st) == SQLITE_ROW) {
            char mac[WEB_KEY_MAX + 1];
            if (!cmac(st, 0, mac)) continue;
            if (nb - ncur >= WEB_SSID_BSSIDS) { past_more = 1; break; }
            sb_read(st, &bs[nb], 3, 0);
            snprintf(bs[nb].bssid, sizeof(bs[nb].bssid), "%s", mac);
            bs[nb].first_seen = sqlite3_column_int64(st, 1);
            bs[nb].last_seen = sqlite3_column_int64(st, 2);
            nb++;
        }
        sqlite3_finalize(st);
    }
    if (conn.timed_out) { free(bs); return db_failed(&conn, body, cap, len, status); }

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"ssid\":");     web_jw_ssid(&w, ssid);
    web_jw_ssid_meta(&w, "ssid", ssid);
    web_jw_raw(&w, ",\"hidden\":");   jw_bool(&w, octets == 0);
    web_jw_raw(&w, ",\"octets\":");   web_jw_int(&w, octets);
    web_jw_raw(&w, ",\"now\":");      web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"db\":\"open\",\"db_schema\":"); web_jw_int(&w, conn.schema);
    /* sloth's --my-ssid, from its `ownership` record (web_own.h): null
     * until sloth has reported it, never a guess. */
    web_jw_raw(&w, ",\"designated\":"); web_own_jw(&w, web_own_ssid(ssid, (size_t)octets));
    int ndes = web_own_ssid_count();
    web_jw_raw(&w, ",\"designated_count\":");
    if (ndes >= 0) web_jw_int(&w, ndes); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"first_seen\":");
    if (total > 0) web_jw_int(&w, first); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"last_seen\":");
    if (total > 0) web_jw_int(&w, last); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"bssids\":[");
    sqlite3_stmt *karma = prep(&conn, "SELECT score, ssid_count FROM karma_candidates"
                                      " WHERE bssid = ?1");
    int shown = 0, cut = 0;
    for (int i = 0; i < nb; i++) {
        if (w.len + SB_ROW_MAX + SB_TAIL > cap) { cut = 1; break; }
        if (shown++) web_jw_raw(&w, ",");
        sb_json(&w, m, karma, &bs[i], now_s);
    }
    sqlite3_finalize(karma);
    web_jw_raw(&w, "],\"bssids_total\":"); web_jw_int(&w, total);
    web_jw_raw(&w, ",\"bssids_more\":");   jw_bool(&w, cut || total > ncur || past_more);

    /* The stations associated to it: by the SSID the association
     * carried, or to one of its current BSSIDs. */
    static const char ASSOC_W[] =
        " FROM assocs a WHERE (?1 <> '' AND a.ssid = ?1) OR a.bssid IN"
        " (SELECT b.bssid FROM beacon_aps b WHERE " SSID_IS ")";
    char sql[2048];
    snprintf(sql, sizeof(sql), "SELECT count(*)%s", ASSOC_W);
    long long atotal = one_count(&conn, sql, ssid, 0, 0);
    web_jw_raw(&w, ",\"assocs\":[");
    snprintf(sql, sizeof(sql),
             "SELECT a.sta_mac, a.bssid, COALESCE(a.channel,0), a.signal_dbm,"
             " a.first_seen, a.last_seen%s ORDER BY a.last_seen DESC, a.sta_mac,"
             " a.bssid LIMIT ?2", ASSOC_W);
    st = prep(&conn, sql);
    int n = 0;
    if (st) {
        bind_t(st, 1, ssid);
        sqlite3_bind_int(st, 2, WEB_SSID_ITEMS);
        while (sqlite3_step(st) == SQLITE_ROW) {
            char sta[WEB_KEY_MAX + 1], ap[WEB_KEY_MAX + 1];
            if (!cmac(st, 0, sta) || !cmac(st, 1, ap)) continue;
            if (n++) web_jw_raw(&w, ",");
            jw_mac(&w, m, sta);
            web_jw_raw(&w, ",\"bssid\":");      web_jw_str(&w, ap);
            web_jw_raw(&w, ",\"channel\":");    web_jw_int(&w, sqlite3_column_int64(st, 2) & 0xffff);
            web_jw_raw(&w, ",\"signal\":");
            jw_signal(&w, sqlite3_column_type(st, 3) != SQLITE_NULL, sqlite3_column_int64(st, 3));
            web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, sqlite3_column_int64(st, 4));
            web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, sqlite3_column_int64(st, 5));
            web_jw_raw(&w, "}");
        }
        sqlite3_finalize(st);
    }
    web_jw_raw(&w, "],\"assocs_total\":"); web_jw_int(&w, atotal < 0 ? 0 : atotal);

    /* The stations asking for it by name. None for the empty SSID: a
     * wildcard probe names no network. */
    long long ptotal = octets ? one_count(&conn,
        "SELECT count(*) FROM pnl_ssids WHERE ssid = ?1", ssid, 0, 0) : 0;
    web_jw_raw(&w, ",\"probers\":[");
    st = octets ? prep(&conn, "SELECT mac, first_seen, last_seen FROM pnl_ssids"
                              " WHERE ssid = ?1 ORDER BY last_seen DESC, mac LIMIT ?2") : NULL;
    n = 0;
    if (st) {
        bind_t(st, 1, ssid);
        sqlite3_bind_int(st, 2, WEB_SSID_ITEMS);
        while (sqlite3_step(st) == SQLITE_ROW) {
            char mac[WEB_KEY_MAX + 1];
            if (!cmac(st, 0, mac)) continue;
            if (n++) web_jw_raw(&w, ",");
            jw_mac(&w, m, mac);
            web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, sqlite3_column_int64(st, 1));
            web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, sqlite3_column_int64(st, 2));
            web_jw_raw(&w, "}");
        }
        sqlite3_finalize(st);
    }
    web_jw_raw(&w, "],\"probers_total\":"); web_jw_int(&w, ptotal < 0 ? 0 : ptotal);
    if (conn.timed_out) { free(bs); return db_failed(&conn, body, cap, len, status); }

    /* The alerts of the last WEB_SSID_ALERT_DAYS days naming it. The
     * key is in the WHERE and the GROUP BY only (predicate-only, as
     * web_sdb_alerts() reads it), against the SSID's own key component
     * and each current BSSID; a group is named by its newest rowid.
     * instr() over every recent key, once a BSSID, is the cost, and no
     * index helps it, so the walk is bounded by work and not by a clock:
     * at most SSID_ALERT_WORK / (SSID_ALERT_ROW + BSSIDs) alert rows,
     * the newest, found through idx_alerts_last_seen before the walk
     * begins. When that is not the whole window the answer says how far
     * back it read ("alerts_reached", null for all of it). Read last: if
     * the request's budget ends here anyway, the rest of the answer
     * stands and "alerts_read" is false. */
    char tok[64] = "", tys[640];
    if (octets) key_token(ssid, tok, sizeof(tok));
    web_sdb_scope_types(&conn, "w.type", tys, sizeof(tys));
    long long from = now_s - (long long)WEB_SSID_ALERT_DAYS * 86400, reached = 0;
    st = prep(&conn, "SELECT last_seen FROM alerts WHERE last_seen >= ?1"
                     " ORDER BY last_seen DESC LIMIT 1 OFFSET ?2");
    if (st) {
        sqlite3_bind_int64(st, 1, from);
        sqlite3_bind_int64(st, 2, SSID_ALERT_WORK / (SSID_ALERT_ROW + (total > 0 ? total : 0)));
        if (sqlite3_step(st) == SQLITE_ROW) {
            /* The first row not read: everything newer is. */
            from = sqlite3_column_int64(st, 0) + 1;
            reached = from;
        }
        sqlite3_finalize(st);
    }
    snprintf(sql, sizeof(sql),
             "SELECT COALESCE(w.title,''), w.type, max(w.sev), sum(w.count),"
             " min(w.first_seen), max(w.last_seen),"
             " (SELECT max(x.rowid) FROM alerts x WHERE x.key = w.key), %s"
             " FROM alerts w WHERE w.last_seen >= ?3 AND"
             " ((?2 <> '' AND instr(w.key, ?2) > 0) OR EXISTS (SELECT 1 FROM beacon_aps b"
             " WHERE " SSID_IS " AND instr(w.key, b.bssid) > 0))%s"
             " GROUP BY w.key ORDER BY max(w.last_seen) DESC LIMIT ?4",
             (conn.opt & WEB_SDB_OPT_INC) ? "sum(1 + w.reopens)" : "count(*)", tys);
    conn.pred_ok = 1;
    st = prep(&conn, sql);
    sa_t al[WEB_SSID_ALERTS + 1];
    int na = 0, amore = 0, aread = st != NULL;
    if (st) {
        bind_t(st, 1, ssid);
        bind_t(st, 2, tok);
        sqlite3_bind_int64(st, 3, from);
        sqlite3_bind_int(st, 4, WEB_SSID_ALERTS + 1);
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && na <= WEB_SSID_ALERTS) {
            sa_t *a = &al[na++];
            ctext(st, 0, a->title, WEB_SDB_TEXT_MAX);
            a->type = sqlite3_column_int64(st, 1);
            a->sev = sqlite3_column_int64(st, 2);
            a->count = sqlite3_column_int64(st, 3);
            a->first_seen = sqlite3_column_int64(st, 4);
            a->last_seen = sqlite3_column_int64(st, 5);
            a->rid = sqlite3_column_int64(st, 6);
            a->rows = sqlite3_column_int64(st, 7);
        }
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) { aread = 0; na = 0; }
    }
    sqlite3_finalize(st);
    conn.pred_ok = 0;
    if (na > WEB_SSID_ALERTS) { na = WEB_SSID_ALERTS; amore = 1; }
    web_jw_raw(&w, ",\"alerts\":[");
    for (int i = 0; i < na; i++) {
        const sa_t *a = &al[i];
        web_jw_raw(&w, i ? ",{\"title\":" : "{\"title\":");
        web_jw_text(&w, a->title);
        web_jw_raw(&w, ",\"type\":");      web_jw_int(&w, a->type & 0xffff);
        web_jw_raw(&w, ",\"sev\":");       web_jw_int(&w, a->sev < 0 ? 0 : a->sev > 3 ? 3 : a->sev);
        web_jw_raw(&w, ",\"count\":");     web_jw_int(&w, a->count > 0 ? a->count : 0);
        web_jw_raw(&w, ",\"incidents\":"); web_jw_int(&w, a->rows > 0 ? a->rows : 1);
        web_jw_raw(&w, ",\"id\":");
        if (a->rid > 0) {
            char id[32];
            snprintf(id, sizeof(id), "d%lld", a->rid);
            web_jw_str(&w, id);
        } else {
            web_jw_raw(&w, "null");
        }
        web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, a->first_seen);
        web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, a->last_seen);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"alerts_more\":");    jw_bool(&w, amore);
    web_jw_raw(&w, ",\"alerts_read\":");     jw_bool(&w, aread);
    web_jw_raw(&w, ",\"alerts_reached\":");
    if (reached > 0) web_jw_int(&w, reached); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"alerts_days\":");     web_jw_int(&w, WEB_SSID_ALERT_DAYS);
    web_slothdb_close(&conn);

    /* G5: a cell is present when any current BSSID was. */
    unsigned char any[WEB_DEV_CELLS / 8];
    memset(any, 0, sizeof(any));
    if (ncur) {
        char (*macs)[WEB_KEY_MAX + 1] = calloc((size_t)ncur, sizeof(*macs));
        unsigned char *bits = calloc((size_t)ncur, WEB_DEV_CELLS / 8);
        if (macs && bits) {
            for (int i = 0; i < ncur; i++) snprintf(macs[i], sizeof(macs[i]), "%s", bs[i].bssid);
            web_dev_strips(m, (const char (*)[WEB_KEY_MAX + 1])macs, ncur, now_s, bits);
            for (int i = 0; i < ncur; i++)
                for (int k = 0; k < WEB_DEV_CELLS / 8; k++)
                    any[k] |= bits[(size_t)i * (WEB_DEV_CELLS / 8) + k];
        }
        free(macs);
        free(bits);
    }
    free(bs);
    char hx[WEB_DEV_CELLS / 4 + 1];
    web_dev_presence_hex(any, hx);
    web_jw_raw(&w, ",\"presence\":");        web_jw_str(&w, hx);
    web_jw_raw(&w, ",\"presence_from\":");   web_jw_int(&w, web_dev_strip_from(now_s));
    web_jw_raw(&w, ",\"presence_bssids\":"); web_jw_int(&w, ncur);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

#else /* !WITH_SQLITE */

/* no_db() is always true here: web_slothdb_available() says so. */
int web_ssid_route(const web_m4_t *m, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return NO_DB_ANSWER();
}

#endif
