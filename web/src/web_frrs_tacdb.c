/* TACDB (docs/web-frrs-spec.md §3.2, §6.3, §7, §8): the operator's units,
 * platforms and each platform's equipment complement, in slothweb.db;
 * the suggestions sloth's own correlations make; the JSON Lines export
 * and its import. Every row is operator state: soft-deleted, never
 * dropped by --web-max-mb, refused at its cap (507 tacdb_full). The
 * emitters' parametrics are never copied here: the record reads them
 * live (web_frrs_report.c), so the filing cannot go stale. */
#include "web_frrs_int.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_oui.h"
#include "web_metrics.h"
#include "web_series.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#ifdef WITH_SQLITE

/* Everything below needs the store; a build without SQLite has the
 * stubs at the end. */
static const char *const UNIT_KIND[] = { "site", "area", "room", "vehicle", "person", "other" };
#define N_UNIT_KIND 6
static const char *const CLASS_WORD[] = {
    "unknown", "phone", "laptop", "ap", "iot", "camera", "wearable", "vehicle",
    "infrastructure", "other",
};
#define N_CLASS 10
static const char *const ROLE_WORD[] = { "primary", "mld-link", "rotation", "vap", "other" };
#define N_ROLE 5

/* The suggestion rules (§7). S4 waits on a field sloth does not emit,
 * S5 fills identity and suggests nothing. */
enum { RULE_S1 = 1, RULE_S2 = 2, RULE_S3 = 3, RULE_S6 = 6 };
static const char *rule_name(int r) {
    switch (r) {
    case RULE_S1: return "sequence-number trail";
    case RULE_S2: return "MLD affiliation";
    case RULE_S3: return "BSSID family";
    case RULE_S6: return "station and card";
    default:      return "?";
    }
}

static int word_of(const char *const *t, int n, const char *w) {
    for (int i = 0; w && i < n; i++) if (!strcmp(t[i], w)) return i;
    return -1;
}

static const char *origin_word(int o) {
    if (o == 0) return "operator";
    if (o == 1) return "import";
    if (o >= 10) return "suggestion";
    return "operator";
}

/* ── suggestion tokens ──────────────────────────────────────────────── */

static unsigned tok_hash(unsigned nonce, int rule, const char *a, const char *b) {
    unsigned h = 2166136261u ^ nonce;
    char buf[64];
    snprintf(buf, sizeof(buf), "%d|%s|%s", rule, a, b);
    for (const char *p = buf; *p; p++) { h ^= (unsigned char)*p; h *= 16777619u; }
    return h;
}

static void hex12(const char *mac, char out[13]) {
    int o = 0;
    for (const char *p = mac; *p && o < 12; p++) if (*p != ':') out[o++] = *p;
    out[o] = '\0';
}

static void unhex12(const char *h, char out[18]) {
    for (int i = 0; i < 6; i++) {
        out[i * 3] = h[i * 2];
        out[i * 3 + 1] = h[i * 2 + 1];
        out[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
}

static void tok_make(unsigned nonce, int rule, const char *a, const char *b, char out[48]) {
    char ha[13], hb[13] = "-";
    hex12(a, ha);
    if (b[0]) hex12(b, hb);
    snprintf(out, 48, "S%d.%s.%s.%08x", rule, ha, hb, tok_hash(nonce, rule, a, b));
}

/* 0 with rule, a, b filled, or -1 (malformed, or this process did not
 * make it: a token of an earlier run is refused). */
static int tok_read(unsigned nonce, const char *t, int *rule, char a[18], char b[18]) {
    if (!t || strlen(t) < 26 || t[0] != 'S' || !isdigit((unsigned char)t[1]) || t[2] != '.') return -1;
    *rule = t[1] - '0';
    const char *p = t + 3;
    if (strlen(p) < 12 + 1 + 1 + 1 + 8) return -1;
    char ha[13], hb[13];
    memcpy(ha, p, 12);
    ha[12] = '\0';
    p += 12;
    if (*p++ != '.') return -1;
    if (*p == '-') { hb[0] = '\0'; p++; }
    else {
        memcpy(hb, p, 12);
        hb[12] = '\0';
        p += 12;
    }
    if (*p++ != '.' || strlen(p) != 8) return -1;
    for (int i = 0; i < 12; i++)
        if (!isxdigit((unsigned char)ha[i]) || (hb[0] && !isxdigit((unsigned char)hb[i]))) return -1;
    char m[WEB_KEY_MAX + 1];
    unhex12(ha, a);
    if (web_key_mac(a, m) != 0) return -1;
    memcpy(a, m, 18);
    b[0] = '\0';
    if (hb[0]) {
        unhex12(hb, b);
        if (web_key_mac(b, m) != 0) return -1;
        memcpy(b, m, 18);
    }
    char want[9];
    snprintf(want, sizeof(want), "%08x", tok_hash(nonce, *rule, a, b));
    return strcmp(want, p) == 0 &&
           (*rule == RULE_S1 || *rule == RULE_S2 || *rule == RULE_S3 || *rule == RULE_S6) ? 0 : -1;
}

/* The auto nomenclature (Q5): "<vendor> <class> <last two octets>". */
static void auto_name(const web_m4_t *m, const char *mac, int cls, char *out, size_t cap) {
    uint8_t b[6];
    web_oui_hit_t h;
    const char *vendor = "unknown";
    char v[WEB_OUI_NAME_MAX + 1];
    if (web_oui_mac_bytes(mac, b) == 0) {
        if (b[0] & 2) vendor = "randomised";
        else if (m->oui && web_oui_lookup(m->oui, b, &h)) {
            /* The vendor's first word: "Apple, Inc." is "Apple". */
            size_t n = 0;
            while (h.name[n] && h.name[n] != ' ' && h.name[n] != ',' && n + 1 < sizeof(v)) {
                v[n] = h.name[n];
                n++;
            }
            v[n] = '\0';
            if (n) vendor = v;
        }
    }
    snprintf(out, cap, "%s %s %.5s", vendor, cls > 0 && cls < N_CLASS ? CLASS_WORD[cls] : "device",
             strlen(mac) >= 17 ? mac + 12 : "?");
}

/* ── store helpers ──────────────────────────────────────────────────── */

static sqlite3_stmt *prep(web_frrs_t *f, const char *sql) {
    sqlite3_stmt *s = NULL;
    if (!f->wr || sqlite3_prepare_v2(f->wr, sql, -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return NULL;
    }
    return s;
}

static long long scalar(web_frrs_t *f, const char *sql, long long a, const char *t, long long dflt) {
    sqlite3_stmt *s = prep(f, sql);
    long long v = dflt;
    if (!s) return dflt;
    if (sqlite3_bind_parameter_count(s) >= 1) sqlite3_bind_int64(s, 1, a);
    if (t && sqlite3_bind_parameter_count(s) >= 2) sqlite3_bind_text(s, 2, t, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) != SQLITE_NULL)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

static void ctext(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

static int begin(web_frrs_t *f) {
    return sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}
static int commit(web_frrs_t *f) {
    if (sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) return 0;
    sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}
static void rollback(web_frrs_t *f) { sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL); }

/* A unit's depth from its root (a root is 1), or -1 when the chain is
 * broken or longer than any the tree allows. */
static int unit_depth(web_frrs_t *f, long long id) {
    int d = 0;
    while (id > 0 && d <= WEB_FRRS_UNIT_DEPTH + 1) {
        d++;
        long long p = scalar(f, "SELECT COALESCE(parent, 0) FROM tacdb_unit WHERE id = ?1", id, NULL, -1);
        if (p < 0) return -1;
        id = p;
    }
    return id > 0 ? -1 : d;
}

/* The deepest level below id (0 none). */
static int subtree_height(web_frrs_t *f, long long id, int lvl) {
    if (lvl > WEB_FRRS_UNIT_DEPTH + 1) return lvl;
    sqlite3_stmt *s = prep(f, "SELECT id FROM tacdb_unit WHERE parent = ?1 AND deleted = 0");
    int h = 0;
    if (!s) return 0;
    sqlite3_bind_int64(s, 1, id);
    long long kids[64];
    int nk = 0;
    while (sqlite3_step(s) == SQLITE_ROW && nk < 64) kids[nk++] = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    for (int i = 0; i < nk; i++) {
        int k = 1 + subtree_height(f, kids[i], lvl + 1);
        if (k > h) h = k;
    }
    return h;
}

static int in_subtree(web_frrs_t *f, long long root, long long id) {
    for (int d = 0; id > 0 && d < 16; d++) {
        if (id == root) return 1;
        id = scalar(f, "SELECT COALESCE(parent, 0) FROM tacdb_unit WHERE id = ?1", id, NULL, 0);
    }
    return 0;
}

static int unit_live(web_frrs_t *f, long long id) {
    return scalar(f, "SELECT COUNT(*) FROM tacdb_unit WHERE id = ?1 AND deleted = 0", id, NULL, 0) > 0;
}
static int platform_live(web_frrs_t *f, long long id) {
    return scalar(f, "SELECT COUNT(*) FROM tacdb_platform WHERE id = ?1 AND deleted = 0", id, NULL, 0) > 0;
}

/* The live platform an emitter is on, or 0. */
static long long owner_of(web_frrs_t *f, int kind, const char *addr) {
    sqlite3_stmt *s = prep(f, "SELECT platform FROM tacdb_emitter WHERE kind = ?1 AND addr = ?2"
                              " AND deleted = 0");
    long long p = 0;
    if (!s) return 0;
    sqlite3_bind_int(s, 1, kind);
    sqlite3_bind_text(s, 2, addr, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) == SQLITE_ROW) p = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return p;
}

static int nom_taken(web_frrs_t *f, const char *nom, long long except) {
    sqlite3_stmt *s = prep(f, "SELECT COUNT(*) FROM tacdb_platform WHERE deleted = 0 AND"
                              " lower(nomenclature) = lower(?2) AND id <> ?1");
    int n = 0;
    if (!s) return 1;
    sqlite3_bind_int64(s, 1, except);
    sqlite3_bind_text(s, 2, nom, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n > 0;
}

static int unit_name_taken(web_frrs_t *f, long long parent, const char *name, long long except) {
    sqlite3_stmt *s = prep(f, "SELECT COUNT(*) FROM tacdb_unit WHERE deleted = 0 AND parent IS ?1"
                              " AND lower(name) = lower(?2) AND id <> ?3");
    int n = 0;
    if (!s) return 1;
    if (parent > 0) sqlite3_bind_int64(s, 1, parent); else sqlite3_bind_null(s, 1);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, except);
    if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n > 0;
}

static long long insert_unit(web_frrs_t *f, long long parent, const char *name, int kind,
                             const char *note, int origin, long long now) {
    sqlite3_stmt *s = prep(f, "INSERT INTO tacdb_unit (parent, name, kind, note, origin, created,"
                              " updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)");
    if (!s) return -1;
    if (parent > 0) sqlite3_bind_int64(s, 1, parent); else sqlite3_bind_null(s, 1);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, kind);
    sqlite3_bind_text(s, 4, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 5, origin);
    sqlite3_bind_int64(s, 6, now);
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok ? sqlite3_last_insert_rowid(f->wr) : -1;
}

static long long insert_platform(web_frrs_t *f, long long unit, const char *nom, int cls,
                                 const char *vendor, const char *note, int confirmed, int origin,
                                 long long now) {
    sqlite3_stmt *s = prep(f, "INSERT INTO tacdb_platform (unit, nomenclature, class, vendor, note,"
                              " confirmed, origin, created, updated) VALUES"
                              " (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)");
    if (!s) return -1;
    if (unit > 0) sqlite3_bind_int64(s, 1, unit); else sqlite3_bind_null(s, 1);
    sqlite3_bind_text(s, 2, nom, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, cls);
    sqlite3_bind_text(s, 4, vendor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, confirmed);
    sqlite3_bind_int(s, 7, origin);
    sqlite3_bind_int64(s, 8, now);
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok ? sqlite3_last_insert_rowid(f->wr) : -1;
}

/* Put (kind, addr) on platform p (a row of it there revived). 0, or -1. */
static int put_emitter(web_frrs_t *f, long long p, int kind, const char *addr, int role,
                       const char *label, int origin, long long now) {
    sqlite3_stmt *s = prep(f, "INSERT INTO tacdb_emitter (platform, kind, addr, role, label,"
                              " confirmed, origin, created, updated, deleted) VALUES"
                              " (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?7, 0) ON CONFLICT (platform, kind, addr)"
                              " DO UPDATE SET role = ?4, label = ?5, updated = ?7, deleted = 0");
    if (!s) return -1;
    sqlite3_bind_int64(s, 1, p);
    sqlite3_bind_int(s, 2, kind);
    sqlite3_bind_text(s, 3, addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, role);
    sqlite3_bind_text(s, 5, label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, origin);
    sqlite3_bind_int64(s, 7, now);
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok ? 0 : -1;
}

static long long live_count(web_frrs_t *f, const char *table) {
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s WHERE deleted = 0", table);
    return scalar(f, sql, 0, NULL, 0);
}

/* ── the JSON of rows ───────────────────────────────────────────────── */

static void unit_path(web_frrs_t *f, long long id, char *out, size_t cap) {
    char names[WEB_FRRS_UNIT_DEPTH + 2][WEB_FRRS_NAME_MAX + 1];
    int n = 0;
    out[0] = '\0';
    while (id > 0 && n < WEB_FRRS_UNIT_DEPTH + 2) {
        sqlite3_stmt *s = prep(f, "SELECT name, COALESCE(parent, 0) FROM tacdb_unit WHERE id = ?1");
        if (!s) return;
        sqlite3_bind_int64(s, 1, id);
        id = 0;
        if (sqlite3_step(s) == SQLITE_ROW) {
            ctext(s, 0, names[n++], WEB_FRRS_NAME_MAX + 1);
            id = sqlite3_column_int64(s, 1);
        }
        sqlite3_finalize(s);
    }
    for (int i = n - 1; i >= 0; i--) {
        if (out[0]) strncat(out, " / ", cap - strlen(out) - 1);
        strncat(out, names[i], cap - strlen(out) - 1);
    }
}

/* An emitter's last sight in sloth.db, and the scopes it was seen in. */
static long long seen_of(web_sdb_conn_t *c, int kind, const char *addr, int *local) {
    static const char *const STA[] = {
        "SELECT last_seen FROM devices WHERE mac = ?1",
        "SELECT last_seen FROM probe_clients WHERE mac = ?1",
        "SELECT last_seen FROM pnl_clients WHERE mac = ?1",
        NULL,
    };
    static const char *const BSS[] = { "SELECT last_seen FROM beacon_aps WHERE bssid = ?1", NULL };
    const char *const *q = kind == FRRS_K_BSSID ? BSS : STA;
    long long best = 0;
    *local = 0;
    if (!c || kind == FRRS_K_BLE) return 0;
    for (int i = 0; q[i]; i++) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(c->db, q[i], -1, &s, NULL) != SQLITE_OK) { sqlite3_finalize(s); continue; }
        sqlite3_bind_text(s, 1, addr, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int64(s, 0) > best)
            best = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    if (kind == FRRS_K_STA) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(c->db, "SELECT last_seen FROM wifi_stas WHERE mac = ?1", -1, &s, NULL)
                == SQLITE_OK) {
            sqlite3_bind_text(s, 1, addr, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(s) == SQLITE_ROW) {
                *local = 1;
                if (sqlite3_column_int64(s, 0) > best) best = sqlite3_column_int64(s, 0);
            }
        }
        sqlite3_finalize(s);
        if (sqlite3_prepare_v2(c->db, "SELECT sources FROM devices WHERE mac = ?1", -1, &s, NULL)
                == SQLITE_OK) {
            sqlite3_bind_text(s, 1, addr, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(s) == SQLITE_ROW && (sqlite3_column_int64(s, 0) & WEB_SRC_LOCAL)) *local = 1;
        }
        sqlite3_finalize(s);
    }
    return best;
}

static void emitters_json(web_frrs_t *f, web_sdb_conn_t *c, long long p, int with_deleted,
                          web_jw_t *w, int *count) {
    sqlite3_stmt *s = prep(f, "SELECT kind, addr, role, label, origin, deleted, updated FROM tacdb_emitter"
                              " WHERE platform = ?1 AND (deleted = 0 OR ?2) ORDER BY kind, addr");
    int n = 0;
    web_jw_raw(w, "[");
    if (s) {
        sqlite3_bind_int64(s, 1, p);
        sqlite3_bind_int(s, 2, with_deleted);
        while (sqlite3_step(s) == SQLITE_ROW) {
            char addr[24], label[WEB_FRRS_LABEL_MAX + 1];
            int kind = sqlite3_column_int(s, 0);
            ctext(s, 1, addr, sizeof(addr));
            ctext(s, 3, label, sizeof(label));
            int role = sqlite3_column_int(s, 2), local = 0;
            long long seen = seen_of(c, kind, addr, &local);
            if (kind == FRRS_K_BLE && f->led) {
                pthread_mutex_lock(&f->lmu);
                const frrs_ble_t *b[4] = { NULL };
                char m[18];
                snprintf(m, sizeof(m), "%.17s", addr);
                int nb = frrs_led_ble(f, m, strlen(addr) > 18 ? atoi(addr + 18) : -1, b, 4);
                for (int i = 0; i < nb; i++) if (b[i]->last_seen > seen) seen = b[i]->last_seen;
                pthread_mutex_unlock(&f->lmu);
            }
            web_jw_raw(w, n++ ? ",{\"kind\":" : "{\"kind\":");
            web_jw_str(w, frrs_kind_word(kind));
            web_jw_raw(w, ",\"addr\":");   web_jw_str(w, addr);
            web_jw_raw(w, ",\"role\":");
            web_jw_str(w, role >= 0 && role < N_ROLE ? ROLE_WORD[role] : "other");
            web_jw_raw(w, ",\"label\":");  web_jw_str(w, label);
            web_jw_raw(w, ",\"origin\":"); web_jw_str(w, origin_word(sqlite3_column_int(s, 4)));
            web_jw_raw(w, ",\"deleted\":"); web_jw_raw(w, sqlite3_column_int(s, 5) ? "true" : "false");
            web_jw_raw(w, ",\"last_seen\":");
            if (seen > 0) web_jw_int(w, seen); else web_jw_raw(w, "null");
            /* The scopes it was seen in: on the air always (its kind is a
             * Monitor datum), and Local too when the host's own card or
             * its ARP/DHCP saw it. */
            web_jw_raw(w, ",\"scopes\":");
            web_jw_raw(w, local ? "[\"monitor\",\"local\"]" : "[\"monitor\"]");
            web_jw_raw(w, "}");
        }
        sqlite3_finalize(s);
    }
    web_jw_raw(w, "]");
    if (count) *count = n;
}

static void platform_json(web_frrs_t *f, web_sdb_conn_t *c, sqlite3_stmt *s, int with_deleted,
                          web_jw_t *w) {
    char nom[WEB_FRRS_NAME_MAX + 1], vendor[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
    char path[WEB_FRRS_UNIT_DEPTH * (WEB_FRRS_NAME_MAX + 3) + 1];
    long long id = sqlite3_column_int64(s, 0);
    long long unit = sqlite3_column_type(s, 1) == SQLITE_NULL ? 0 : sqlite3_column_int64(s, 1);
    ctext(s, 2, nom, sizeof(nom));
    int cls = sqlite3_column_int(s, 3);
    ctext(s, 4, vendor, sizeof(vendor));
    ctext(s, 5, note, sizeof(note));
    web_jw_raw(w, "{\"id\":");           web_jw_int(w, id);
    web_jw_raw(w, ",\"nomenclature\":"); web_jw_str(w, nom);
    web_jw_raw(w, ",\"class\":");
    web_jw_str(w, cls >= 0 && cls < N_CLASS ? CLASS_WORD[cls] : "unknown");
    web_jw_raw(w, ",\"vendor\":");       web_jw_str(w, vendor);
    web_jw_raw(w, ",\"note\":");         web_jw_str(w, note);
    web_jw_raw(w, ",\"unit\":");
    if (unit > 0) web_jw_int(w, unit); else web_jw_raw(w, "null");
    unit_path(f, unit, path, sizeof(path));
    web_jw_raw(w, ",\"unit_path\":");    frrs_str_or_null(w, path);
    web_jw_raw(w, ",\"confirmed\":");    web_jw_raw(w, sqlite3_column_int(s, 6) ? "true" : "false");
    web_jw_raw(w, ",\"origin\":");       web_jw_str(w, origin_word(sqlite3_column_int(s, 7)));
    web_jw_raw(w, ",\"updated\":");      web_jw_int(w, sqlite3_column_int64(s, 8));
    web_jw_raw(w, ",\"deleted\":");      web_jw_raw(w, sqlite3_column_int(s, 9) ? "true" : "false");
    web_jw_raw(w, ",\"emitters\":");
    emitters_json(f, c, id, with_deleted, w, NULL);
    web_jw_raw(w, "}");
}

#define PLAT_COLS "id, unit, nomenclature, class, vendor, note, confirmed, origin, updated, deleted"

/* ASCII case-insensitive substring. */
static int has_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    if (!n) return 1;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == n) return 1;
    }
    return 0;
}

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (!n || n > 12) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* ── GET /api/frrs/tacdb ────────────────────────────────────────────── */

int frrs_tacdb_get(const web_m4_t *m, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[5] = { { "unit", "", 0 }, { "q", "", 0 }, { "deleted", "", 0 },
                          { "limit", "", 0 }, { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 5, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    long long unit = 0, limit = 100, offset = 0;
    int del = 0;
    if (ps[0].seen && decimal(ps[0].val, 1, 1LL << 40, &unit) != 0)
        return frrs_error(400, "bad_unit", NULL, body, cap, len, status);
    for (const char *p = ps[1].val; *p; p++)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e)
            return frrs_error(400, "bad_q", NULL, body, cap, len, status);
    if (ps[2].seen) {
        if (!strcmp(ps[2].val, "1")) del = 1;
        else if (strcmp(ps[2].val, "0")) return frrs_error(400, "bad_deleted", NULL, body, cap, len, status);
    }
    if (ps[3].seen && decimal(ps[3].val, 1, 200, &limit) != 0)
        return frrs_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[4].seen && decimal(ps[4].val, 0, WEB_FRRS_PLATFORMS, &offset) != 0)
        return frrs_error(400, "bad_offset", NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    web_sdb_conn_t c;
    char e2[200];
    int have_c = m->sdb && m->sdb->configured &&
                 web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, e2, sizeof(e2)) == 0;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"note\":\"operator data: not captured, not scoped; the evidence under each "
                   "emitter is\",\"writes\":");
    web_jw_raw(&w, f->writes ? "true" : "false");
    /* The tree: every unit, depth first by name, each with its depth. */
    web_jw_raw(&w, ",\"units\":[");
    {
        typedef struct { long long id, parent; int kind, deleted; char name[WEB_FRRS_NAME_MAX + 1];
                         char note[WEB_FRRS_NOTE_MAX + 1]; long long plats; } u_t;
        u_t *u = calloc(WEB_FRRS_UNITS * 2, sizeof(*u));
        int nu = 0;
        sqlite3_stmt *s = prep(f, "SELECT id, COALESCE(parent, 0), kind, deleted, name, note,"
                                  " (SELECT COUNT(*) FROM tacdb_platform p WHERE p.unit = tacdb_unit.id"
                                  " AND p.deleted = 0) FROM tacdb_unit WHERE (deleted = 0 OR ?1)"
                                  " ORDER BY lower(name)");
        if (s && u) {
            sqlite3_bind_int(s, 1, del);
            while (sqlite3_step(s) == SQLITE_ROW && nu < WEB_FRRS_UNITS * 2) {
                u[nu].id = sqlite3_column_int64(s, 0);
                u[nu].parent = sqlite3_column_int64(s, 1);
                u[nu].kind = sqlite3_column_int(s, 2);
                u[nu].deleted = sqlite3_column_int(s, 3);
                ctext(s, 4, u[nu].name, sizeof(u[nu].name));
                ctext(s, 5, u[nu].note, sizeof(u[nu].note));
                u[nu].plats = sqlite3_column_int64(s, 6);
                nu++;
            }
        }
        sqlite3_finalize(s);
        /* Depth first: an explicit stack of (index, depth). */
        enum { STK = WEB_FRRS_UNITS * 2 + 1 };
        int stack[STK][2], sp = 0, shown = 0, more = 0;
        for (int i = nu - 1; i >= 0 && sp < STK; i--) {
            int root = u[i].parent == 0;
            for (int k = 0; k < nu && !root; k++) if (u[k].id == u[i].parent) break; else if (k == nu - 1) root = 1;
            if (root) { stack[sp][0] = i; stack[sp][1] = 1; sp++; }
        }
        while (sp > 0) {
            sp--;
            int i = stack[sp][0], d = stack[sp][1];
            if (w.len + 1024 > cap / 3) { more = 1; break; }
            web_jw_raw(&w, shown++ ? ",{\"id\":" : "{\"id\":");
            web_jw_int(&w, u[i].id);
            web_jw_raw(&w, ",\"parent\":");
            if (u[i].parent) web_jw_int(&w, u[i].parent); else web_jw_raw(&w, "null");
            web_jw_raw(&w, ",\"name\":");      web_jw_str(&w, u[i].name);
            web_jw_raw(&w, ",\"kind\":");
            web_jw_str(&w, u[i].kind >= 0 && u[i].kind < N_UNIT_KIND ? UNIT_KIND[u[i].kind] : "other");
            web_jw_raw(&w, ",\"note\":");      web_jw_str(&w, u[i].note);
            web_jw_raw(&w, ",\"depth\":");     web_jw_int(&w, d);
            web_jw_raw(&w, ",\"platforms\":"); web_jw_int(&w, u[i].plats);
            web_jw_raw(&w, ",\"deleted\":");   web_jw_raw(&w, u[i].deleted ? "true" : "false");
            web_jw_raw(&w, "}");
            for (int k = nu - 1; k >= 0 && sp < STK; k--)
                if (u[k].parent == u[i].id) { stack[sp][0] = k; stack[sp][1] = d + 1; sp++; }
        }
        web_jw_raw(&w, "],\"units_more\":");
        web_jw_raw(&w, more ? "true" : "false");
        free(u);
    }
    /* The platforms, by nomenclature. */
    web_jw_raw(&w, ",\"platforms\":[");
    sqlite3_stmt *s = prep(f, "SELECT " PLAT_COLS " FROM tacdb_platform WHERE (deleted = 0 OR ?1)"
                              " ORDER BY lower(nomenclature), id");
    long long matched = 0, shown = 0;
    int more = 0;
    if (s) {
        sqlite3_bind_int(s, 1, del);
        while (sqlite3_step(s) == SQLITE_ROW) {
            long long id = sqlite3_column_int64(s, 0);
            long long pu = sqlite3_column_type(s, 1) == SQLITE_NULL ? 0 : sqlite3_column_int64(s, 1);
            if (unit > 0 && !in_subtree(f, unit, pu)) continue;
            if (ps[1].val[0]) {
                char nom[WEB_FRRS_NAME_MAX + 1], ven[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
                ctext(s, 2, nom, sizeof(nom));
                ctext(s, 4, ven, sizeof(ven));
                ctext(s, 5, note, sizeof(note));
                int hit = has_ci(nom, ps[1].val) || has_ci(ven, ps[1].val) || has_ci(note, ps[1].val);
                if (!hit) {
                    sqlite3_stmt *e = prep(f, "SELECT addr FROM tacdb_emitter WHERE platform = ?1"
                                              " AND deleted = 0");
                    if (e) {
                        sqlite3_bind_int64(e, 1, id);
                        while (!hit && sqlite3_step(e) == SQLITE_ROW) {
                            char a[24];
                            ctext(e, 0, a, sizeof(a));
                            hit = has_ci(a, ps[1].val);
                        }
                    }
                    sqlite3_finalize(e);
                }
                if (!hit) continue;
            }
            matched++;
            if (matched <= offset) continue;
            if (shown >= limit || w.len + 4096 > cap) { more = 1; continue; }
            if (shown++) web_jw_raw(&w, ",");
            platform_json(f, have_c ? &c : NULL, s, del, &w);
        }
        sqlite3_finalize(s);
    }
    if (have_c) web_slothdb_close(&c);
    web_jw_raw(&w, "],\"matched\":"); web_jw_int(&w, matched);
    web_jw_raw(&w, ",\"more\":");      web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"counts\":{\"units\":"); web_jw_int(&w, live_count(f, "tacdb_unit"));
    web_jw_raw(&w, ",\"platforms\":"); web_jw_int(&w, live_count(f, "tacdb_platform"));
    web_jw_raw(&w, ",\"emitters\":");  web_jw_int(&w, live_count(f, "tacdb_emitter"));
    web_jw_raw(&w, ",\"caps\":{\"units\":"); web_jw_int(&w, WEB_FRRS_UNITS);
    web_jw_raw(&w, ",\"platforms\":"); web_jw_int(&w, WEB_FRRS_PLATFORMS);
    web_jw_raw(&w, ",\"emitters\":");  web_jw_int(&w, WEB_FRRS_EMITTERS);
    web_jw_raw(&w, "}}}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int frrs_tacdb_view(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[200];
    long long id = 0;
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen || decimal(ps[0].val, 1, 1LL << 40, &id) != 0)
        return frrs_error(400, "bad_id", NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    sqlite3_stmt *s = prep(f, "SELECT " PLAT_COLS " FROM tacdb_platform WHERE id = ?1");
    if (!s) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    sqlite3_bind_int64(s, 1, id);
    if (sqlite3_step(s) != SQLITE_ROW) {
        sqlite3_finalize(s);
        return frrs_error(404, "no_such_platform", NULL, body, cap, len, status);
    }
    web_sdb_conn_t c;
    int have_c = m->sdb && m->sdb->configured &&
                 web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"platform\":");
    platform_json(f, have_c ? &c : NULL, s, 1, &w);
    sqlite3_finalize(s);
    if (have_c) web_slothdb_close(&c);
    web_jw_raw(&w, ",\"writes\":");
    web_jw_raw(&w, f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"position_limit\":\"no location axis\",\"content_limit\":\"sloth decrypts nothing\"}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

void frrs_tacdb_of(web_frrs_t *f, int kind, const char *addr, web_jw_t *w) {
    sqlite3_stmt *s = prep(f, "SELECT p.id, p.nomenclature, p.class, COALESCE(p.unit, 0), e.role,"
                              " e.label, (SELECT COUNT(*) FROM tacdb_emitter x WHERE x.platform = p.id"
                              " AND x.deleted = 0) FROM tacdb_emitter e JOIN tacdb_platform p"
                              " ON p.id = e.platform WHERE e.kind = ?1 AND e.addr = ?2"
                              " AND e.deleted = 0 AND p.deleted = 0");
    if (!s) { web_jw_raw(w, "null"); return; }
    sqlite3_bind_int(s, 1, kind);
    sqlite3_bind_text(s, 2, addr, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) != SQLITE_ROW) {
        sqlite3_finalize(s);
        web_jw_raw(w, "null");
        return;
    }
    char nom[WEB_FRRS_NAME_MAX + 1], label[WEB_FRRS_LABEL_MAX + 1];
    char path[WEB_FRRS_UNIT_DEPTH * (WEB_FRRS_NAME_MAX + 3) + 1];
    ctext(s, 1, nom, sizeof(nom));
    ctext(s, 5, label, sizeof(label));
    int cls = sqlite3_column_int(s, 2), role = sqlite3_column_int(s, 4);
    long long pid = sqlite3_column_int64(s, 0), unit = sqlite3_column_int64(s, 3);
    long long n = sqlite3_column_int64(s, 6);
    sqlite3_finalize(s);
    unit_path(f, unit, path, sizeof(path));
    web_jw_raw(w, "{\"platform\":{\"id\":"); web_jw_int(w, pid);
    web_jw_raw(w, ",\"nomenclature\":");      web_jw_str(w, nom);
    web_jw_raw(w, ",\"class\":");
    web_jw_str(w, cls >= 0 && cls < N_CLASS ? CLASS_WORD[cls] : "unknown");
    web_jw_raw(w, "},\"role\":");
    web_jw_str(w, role >= 0 && role < N_ROLE ? ROLE_WORD[role] : "other");
    web_jw_raw(w, ",\"label\":");             web_jw_str(w, label);
    web_jw_raw(w, ",\"unit\":");
    if (unit > 0) web_jw_int(w, unit); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"unit_path\":");         frrs_str_or_null(w, path);
    web_jw_raw(w, ",\"emitters_on_platform\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"src\":\"tacdb_platform, tacdb_emitter, tacdb_unit (slothweb.db: the operator's)\"}");
}

/* ── suggestions (§7) ───────────────────────────────────────────────── */

typedef struct {
    int       rule, kind, role, cls, conf;
    char      a[18], b[18];
    long long last;
    char      evidence[200];
} sugg_t;

static int dismissed(web_frrs_t *f, int rule, const char *a, const char *b, long long last) {
    sqlite3_stmt *s = prep(f, "SELECT ts FROM tacdb_dismiss WHERE rule = ?1 AND a = ?2 AND b = ?3");
    long long ts = -1;
    if (!s) return 0;
    sqlite3_bind_int(s, 1, rule);
    sqlite3_bind_text(s, 2, a, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, b, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) == SQLITE_ROW) ts = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    /* Dismissed stays dismissed until either address is seen with new
     * evidence after the dismissal. */
    return ts >= 0 && last <= ts;
}

static int add_sugg(web_frrs_t *f, sugg_t *out, int *n, const sugg_t *s) {
    if (*n >= WEB_FRRS_SUGGEST_MAX) return 0;
    long long pa = owner_of(f, s->kind, s->a), pb = s->b[0] ? owner_of(f, s->kind, s->b) : 0;
    if (s->b[0] && pa && pa == pb) return 0;       /* already one platform */
    if (!s->b[0] && pa) return 0;                   /* already filed */
    if (dismissed(f, s->rule, s->a, s->b, s->last)) return 0;
    for (int i = 0; i < *n; i++)
        if (out[i].rule == s->rule && !strcmp(out[i].a, s->a) && !strcmp(out[i].b, s->b)) return 0;
    out[(*n)++] = *s;
    return 1;
}

static int by_conf(const void *x, const void *y) {
    const sugg_t *a = x, *b = y;
    if (a->conf != b->conf) return b->conf - a->conf;
    return a->last < b->last ? 1 : a->last > b->last ? -1 : 0;
}

static int compute_suggestions(const web_m4_t *m, long long now_s, sugg_t *out) {
    web_frrs_t *f = m->frrs;
    int n = 0;
    web_sdb_conn_t c;
    char err[200];
    int have_c = m->sdb && m->sdb->configured &&
                 web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0;
    /* S1: sequence-number trails, sloth.db's rows with the stream's
     * confidence when the ledger has it. */
    if (have_c) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(c.db, "SELECT mac_a, mac_b, gap, last_seen FROM seqnum_correlations"
                               " ORDER BY last_seen DESC LIMIT 400", -1, &s, NULL) == SQLITE_OK) {
            while (sqlite3_step(s) == SQLITE_ROW) {
                sugg_t g;
                memset(&g, 0, sizeof(g));
                char a[24], b[24], ka[WEB_KEY_MAX + 1], kb[WEB_KEY_MAX + 1];
                ctext(s, 0, a, sizeof(a));
                ctext(s, 1, b, sizeof(b));
                if (web_key_mac(a, ka) || web_key_mac(b, kb)) continue;
                int gap = sqlite3_column_int(s, 2);
                g.last = sqlite3_column_int64(s, 3);
                int conf = -1, fwd = -1;
                if (f->led) {
                    pthread_mutex_lock(&f->lmu);
                    const frrs_sta_t *st = frrs_led_sta(f, ka);
                    for (int i = 0; st && i < st->nseq; i++)
                        if (!strcmp(st->seq[i].mac, kb)) { conf = st->seq[i].confidence; fwd = st->seq[i].fwd_gap; }
                    pthread_mutex_unlock(&f->lmu);
                }
                /* mac-randomisation.md's limits: confidence 60 of 90 and a
                 * forward gap of at most 64 when the stream says them,
                 * else the absolute gap sloth.db keeps. */
                if (conf >= 0 ? (conf < 60 || fwd < 0 || fwd > 64) : (gap < 0 || gap > 64)) continue;
                g.rule = RULE_S1;
                g.kind = FRRS_K_STA;
                g.role = 2;
                g.conf = conf >= 0 ? conf : 30;
                snprintf(g.a, sizeof(g.a), "%.17s", ka);
                snprintf(g.b, sizeof(g.b), "%.17s", kb);
                if (conf >= 0)
                    snprintf(g.evidence, sizeof(g.evidence), "sequence counter continued across the "
                             "change (confidence %d of 90, a ranking not a probability; forward gap %d)",
                             conf, fwd);
                else
                    snprintf(g.evidence, sizeof(g.evidence), "sequence counter continued across the "
                             "change (gap %d; confidence not observed: sloth.db keeps the gap, the "
                             "stream the confidence)", gap);
                add_sugg(f, out, &n, &g);
            }
        }
        sqlite3_finalize(s);
    }
    /* S2: Multi-Link Devices, from the stream. */
    if (f->led) {
        sugg_t *tmp = calloc(64, sizeof(*tmp));
        int nt = 0;
        pthread_mutex_lock(&f->lmu);
        for (int i = 0; tmp && i < f->led->nbss && nt < 64; i++) {
            const frrs_bss_t *b = &f->led->bss[i];
            if (!b->has_m) continue;
            const frrs_bss_t *bb = frrs_led_bss(f, b->mac);
            int ap = bb && bb->has_b;
            for (int k = 0; k < b->nlinks && nt < 64; k++) {
                if (!strcmp(b->links[k], b->mac)) continue;
                const frrs_bss_t *lb = frrs_led_bss(f, b->links[k]);
                sugg_t *g = &tmp[nt++];
                memset(g, 0, sizeof(*g));
                g->rule = RULE_S2;
                g->kind = ap || (lb && lb->has_b) ? FRRS_K_BSSID : FRRS_K_STA;
                g->role = 1;
                g->cls = g->kind == FRRS_K_BSSID ? 3 : 0;
                g->conf = 80;
                g->last = b->ts_m;
                snprintf(g->a, sizeof(g->a), "%s", b->mac);
                snprintf(g->b, sizeof(g->b), "%s", b->links[k]);
                snprintf(g->evidence, sizeof(g->evidence), "advertised as links of one Multi-Link "
                         "Device (wifi_mld %s, %d links)", b->mac, b->link_count);
            }
        }
        pthread_mutex_unlock(&f->lmu);
        for (int i = 0; i < nt; i++) add_sugg(f, out, &n, &tmp[i]);
        free(tmp);
    }
    if (have_c) {
        /* S3: BSSID families: the same first five octets and high nibble,
         * on the same channel. The beacon interval alone is not enough:
         * 100 TU is nearly every AP's, and taken alone it joined every
         * neighbour in a block (seen on the demo's eight BSSIDs: 28
         * pairs). A KARMA candidate is not suggested: its evidence is its
         * own. */
        typedef struct { char mac[18]; int ch, bms; long long last; } ap_t;
        ap_t *ap = calloc(512, sizeof(*ap));
        int na = 0;
        sqlite3_stmt *s = NULL;
        if (ap && sqlite3_prepare_v2(c.db, "SELECT bssid, channel, beacon_ms, last_seen FROM beacon_aps"
                                     " ORDER BY bssid LIMIT 512", -1, &s, NULL) == SQLITE_OK) {
            while (sqlite3_step(s) == SQLITE_ROW && na < 512) {
                char a[24], k[WEB_KEY_MAX + 1];
                ctext(s, 0, a, sizeof(a));
                if (web_key_mac(a, k)) continue;
                memcpy(ap[na].mac, k, 18);
                ap[na].ch = sqlite3_column_int(s, 1);
                ap[na].bms = sqlite3_column_type(s, 2) == SQLITE_NULL ? -1 : sqlite3_column_int(s, 2);
                ap[na].last = sqlite3_column_int64(s, 3);
                na++;
            }
        }
        sqlite3_finalize(s);
        for (int i = 0; i < na; i++)
            for (int j = i + 1; j < na && !strncmp(ap[i].mac, ap[j].mac, 15); j++) {
                if (ap[i].ch <= 0 || ap[i].ch != ap[j].ch) continue;
                int karma = 0;
                sqlite3_stmt *k = NULL;
                if (sqlite3_prepare_v2(c.db, "SELECT bssid FROM karma_candidates WHERE bssid = ?1 OR"
                                       " bssid = ?2", -1, &k, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(k, 1, ap[i].mac, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(k, 2, ap[j].mac, -1, SQLITE_TRANSIENT);
                    karma = sqlite3_step(k) == SQLITE_ROW;
                }
                sqlite3_finalize(k);
                if (karma) continue;
                sugg_t g;
                memset(&g, 0, sizeof(g));
                g.rule = RULE_S3;
                g.kind = FRRS_K_BSSID;
                g.role = 3;
                g.cls = 3;
                g.conf = ap[i].bms >= 0 && ap[i].bms == ap[j].bms ? 60 : 50;
                g.last = ap[i].last > ap[j].last ? ap[i].last : ap[j].last;
                snprintf(g.a, sizeof(g.a), "%s", ap[i].mac);
                snprintf(g.b, sizeof(g.b), "%s", ap[j].mac);
                snprintf(g.evidence, sizeof(g.evidence), "same OUI block, adjacent addresses, same channel%s: "
                         "one AP's virtual BSSIDs", g.conf == 60 ? " and beacon interval" : "");
                add_sugg(f, out, &n, &g);
            }
        free(ap);
        /* S6: the host's own card and the air heard the same address. */
        if (sqlite3_prepare_v2(c.db, "SELECT mac, last_seen FROM wifi_stas ORDER BY last_seen DESC"
                               " LIMIT 64", -1, &s, NULL) == SQLITE_OK) {
            while (sqlite3_step(s) == SQLITE_ROW) {
                char a[24], k[WEB_KEY_MAX + 1];
                ctext(s, 0, a, sizeof(a));
                if (web_key_mac(a, k)) continue;
                sqlite3_stmt *q = NULL;
                int air = 0;
                if (sqlite3_prepare_v2(c.db, "SELECT mac FROM probe_clients WHERE mac = ?1", -1, &q,
                                       NULL) == SQLITE_OK) {
                    sqlite3_bind_text(q, 1, k, -1, SQLITE_TRANSIENT);
                    air = sqlite3_step(q) == SQLITE_ROW;
                }
                sqlite3_finalize(q);
                if (!air && sqlite3_prepare_v2(c.db, "SELECT sta_mac FROM assocs WHERE sta_mac = ?1"
                                               " LIMIT 1", -1, &q, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(q, 1, k, -1, SQLITE_TRANSIENT);
                    air = sqlite3_step(q) == SQLITE_ROW;
                    sqlite3_finalize(q);
                } else if (!air) {
                    sqlite3_finalize(q);
                }
                if (!air) continue;
                sugg_t g;
                memset(&g, 0, sizeof(g));
                g.rule = RULE_S6;
                g.kind = FRRS_K_STA;
                g.conf = 70;
                g.last = sqlite3_column_int64(s, 1);
                snprintf(g.a, sizeof(g.a), "%.17s", k);
                snprintf(g.evidence, sizeof(g.evidence), "the host's own card and the air heard the "
                         "same address: one emitter seen in both scopes");
                add_sugg(f, out, &n, &g);
            }
        }
        sqlite3_finalize(s);
        web_slothdb_close(&c);
    }
    qsort(out, (size_t)n, sizeof(*out), by_conf);
    return n;
}

int frrs_suggest_get(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    long long limit = 50;
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_FRRS_SUGGEST_MAX, &limit) != 0)
        return frrs_error(400, "bad_limit", NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    sugg_t *sg = calloc(WEB_FRRS_SUGGEST_MAX, sizeof(*sg));
    if (!sg) return -1;
    int n = compute_suggestions(m, now_s, sg);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"note\":\"each says 'may be one platform', never 'is the same device': a "
                   "hypothesis about radios, never an identification of a person\",\"suggestions\":[");
    int shown = 0;
    for (int i = 0; i < n && shown < limit && w.len + 1024 < cap; i++) {
        char tok[48], nom[WEB_FRRS_NAME_MAX + 1];
        tok_make(f->nonce, sg[i].rule, sg[i].a, sg[i].b, tok);
        auto_name(m, sg[i].a, sg[i].cls, nom, sizeof(nom));
        web_jw_raw(&w, shown++ ? ",{\"token\":" : "{\"token\":");
        web_jw_str(&w, tok);
        char rn[4];
        snprintf(rn, sizeof(rn), "S%d", sg[i].rule);
        web_jw_raw(&w, ",\"rule\":");       web_jw_str(&w, rn);
        web_jw_raw(&w, ",\"rule_name\":");  web_jw_str(&w, rule_name(sg[i].rule));
        web_jw_raw(&w, ",\"kind\":");       web_jw_str(&w, frrs_kind_word(sg[i].kind));
        web_jw_raw(&w, ",\"a\":");          web_jw_str(&w, sg[i].a);
        web_jw_raw(&w, ",\"b\":");          frrs_str_or_null(&w, sg[i].b);
        web_jw_raw(&w, ",\"role_b\":");     web_jw_str(&w, ROLE_WORD[sg[i].role]);
        web_jw_raw(&w, ",\"class\":");      web_jw_str(&w, CLASS_WORD[sg[i].cls]);
        web_jw_raw(&w, ",\"confidence\":"); web_jw_int(&w, sg[i].conf);
        web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, sg[i].last);
        web_jw_raw(&w, ",\"nomenclature\":"); web_jw_str(&w, nom);
        web_jw_raw(&w, ",\"evidence\":");   web_jw_str(&w, sg[i].evidence);
        web_jw_raw(&w, "}");
    }
    free(sg);
    web_jw_raw(&w, "],\"more\":");
    web_jw_raw(&w, shown < n ? "true" : "false");
    web_jw_raw(&w, ",\"rules_off\":[{\"rule\":\"S4\",\"why\":\"BLE rotation: sloth's link is an "
                   "estimate on its own panes, not a field (Q6)\"},{\"rule\":\"S5\",\"why\":\"Wi-Fi "
                   "and IP: one MAC, so it fills a platform's identity rather than suggesting one\"}],"
                   "\"writes\":");
    web_jw_raw(&w, f->writes ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── the POSTs ──────────────────────────────────────────────────────── */

static int jid(const web_jrec_t *r, const char *k, long long *out, int *isnull) {
    const web_jfield_t *f = web_jl_get(r, k);
    *isnull = 0;
    if (!f) return 0;
    if (f->kind == WEB_J_NULL) { *isnull = 1; *out = 0; return 1; }
    if (f->kind != WEB_J_INT || f->i < 1 || f->i > (1LL << 40)) return -1;
    *out = f->i;
    return 1;
}

static int ok_unit(web_frrs_t *f, long long id, char *body, size_t cap, size_t *len, int *status) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    sqlite3_stmt *s = prep(f, "SELECT id, COALESCE(parent, 0), name, kind, note, deleted FROM tacdb_unit"
                              " WHERE id = ?1");
    if (!s) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    sqlite3_bind_int64(s, 1, id);
    if (sqlite3_step(s) == SQLITE_ROW) {
        char name[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
        ctext(s, 2, name, sizeof(name));
        ctext(s, 4, note, sizeof(note));
        int k = sqlite3_column_int(s, 3);
        web_jw_raw(&w, "{\"ok\":true,\"unit\":{\"id\":"); web_jw_int(&w, id);
        web_jw_raw(&w, ",\"parent\":");
        if (sqlite3_column_int64(s, 1)) web_jw_int(&w, sqlite3_column_int64(s, 1)); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"name\":"); web_jw_str(&w, name);
        web_jw_raw(&w, ",\"kind\":"); web_jw_str(&w, k >= 0 && k < N_UNIT_KIND ? UNIT_KIND[k] : "other");
        web_jw_raw(&w, ",\"note\":"); web_jw_str(&w, note);
        web_jw_raw(&w, ",\"deleted\":"); web_jw_raw(&w, sqlite3_column_int(s, 5) ? "true" : "false");
        web_jw_raw(&w, "}}\n");
    }
    sqlite3_finalize(s);
    if (w.overflow || !w.len) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    *len = w.len;
    *status = 200;
    return 0;
}

static int ok_platform(web_frrs_t *f, long long id, char *body, size_t cap, size_t *len, int *status) {
    sqlite3_stmt *s = prep(f, "SELECT " PLAT_COLS " FROM tacdb_platform WHERE id = ?1");
    if (!s) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    sqlite3_bind_int64(s, 1, id);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    if (sqlite3_step(s) == SQLITE_ROW) {
        web_jw_raw(&w, "{\"ok\":true,\"platform\":");
        platform_json(f, NULL, s, 1, &w);
        web_jw_raw(&w, "}\n");
    }
    sqlite3_finalize(s);
    if (w.overflow || !w.len) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    *len = w.len;
    *status = 200;
    return 0;
}

#define FAIL(st, why, mem) do { rollback(f); return frrs_error(st, why, mem, body, cap, len, status); } while (0)

static int post_unit(web_frrs_t *f, const web_jrec_t *r, long long now, char *body, size_t cap,
                     size_t *len, int *status) {
    static const char *const MEMBERS[] = { "op", "id", "parent", "name", "kind", "note", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad)) return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], name[WEB_FRRS_NAME_MAX + 1], kw[12], note[WEB_FRRS_NOTE_MAX + 1];
    if (!frrs_text(r, "op", 10, op, &why)) return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "name", WEB_FRRS_NAME_MAX, name, &why)) return frrs_error(400, why, "name", body, cap, len, status);
    if (!frrs_text(r, "kind", 10, kw, &why)) return frrs_error(400, why, "kind", body, cap, len, status);
    if (!frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why)) return frrs_error(400, why, "note", body, cap, len, status);
    long long id = 0, parent = 0;
    int idn, pn;
    int hid = jid(r, "id", &id, &idn), hpar = jid(r, "parent", &parent, &pn);
    if (hid < 0 || (hid && idn)) return frrs_error(400, "bad_id", "id", body, cap, len, status);
    if (hpar < 0) return frrs_error(400, "bad_parent", "parent", body, cap, len, status);
    int kind = kw[0] ? word_of(UNIT_KIND, N_UNIT_KIND, kw) : -2;
    if (kind == -1) return frrs_error(400, "bad_kind", "kind", body, cap, len, status);
    if (begin(f) != 0) return frrs_error(503, "store_busy", NULL, body, cap, len, status);
    if (!strcmp(op, "create")) {
        if (hid) FAIL(400, "unknown_member", "id");
        if (!name[0]) FAIL(400, "missing_name", "name");
        if (live_count(f, "tacdb_unit") >= WEB_FRRS_UNITS) FAIL(507, "tacdb_full", NULL);
        if (parent && !unit_live(f, parent)) FAIL(404, "no_such_unit", "parent");
        if (parent && unit_depth(f, parent) + 1 > WEB_FRRS_UNIT_DEPTH) FAIL(409, "unit_depth", "parent");
        if (unit_name_taken(f, parent, name, 0)) FAIL(409, "duplicate_name", "name");
        id = insert_unit(f, parent, name, kind < 0 ? 5 : kind, note, 0, now);
        if (id < 0) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "update")) {
        if (!hid) FAIL(400, "missing_id", "id");
        if (!unit_live(f, id)) FAIL(404, "no_such_unit", "id");
        long long cur_parent = scalar(f, "SELECT COALESCE(parent, 0) FROM tacdb_unit WHERE id = ?1", id, NULL, 0);
        long long np = hpar ? parent : cur_parent;
        if (hpar && np) {
            if (!unit_live(f, np)) FAIL(404, "no_such_unit", "parent");
            if (in_subtree(f, id, np)) FAIL(409, "unit_cycle", "parent");
            if (unit_depth(f, np) + 1 + subtree_height(f, id, 0) > WEB_FRRS_UNIT_DEPTH) FAIL(409, "unit_depth", "parent");
        }
        char cur[WEB_FRRS_NAME_MAX + 1] = "";
        sqlite3_stmt *q = prep(f, "SELECT name FROM tacdb_unit WHERE id = ?1");
        if (q) { sqlite3_bind_int64(q, 1, id); if (sqlite3_step(q) == SQLITE_ROW) ctext(q, 0, cur, sizeof(cur)); }
        sqlite3_finalize(q);
        const char *nm = name[0] ? name : cur;
        if (unit_name_taken(f, np, nm, id)) FAIL(409, "duplicate_name", "name");
        sqlite3_stmt *s = prep(f, "UPDATE tacdb_unit SET parent = ?2, name = ?3,"
                                  " kind = COALESCE(?4, kind), note = COALESCE(?5, note), updated = ?6"
                                  " WHERE id = ?1");
        if (!s) FAIL(500, "store_error", NULL);
        sqlite3_bind_int64(s, 1, id);
        if (np) sqlite3_bind_int64(s, 2, np); else sqlite3_bind_null(s, 2);
        sqlite3_bind_text(s, 3, nm, -1, SQLITE_TRANSIENT);
        if (kind >= 0) sqlite3_bind_int(s, 4, kind); else sqlite3_bind_null(s, 4);
        if (web_jl_get(r, "note")) sqlite3_bind_text(s, 5, note, -1, SQLITE_TRANSIENT);
        else sqlite3_bind_null(s, 5);
        sqlite3_bind_int64(s, 6, now);
        int ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
        if (!ok) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "delete") || !strcmp(op, "restore")) {
        int del = op[0] == 'd';
        if (!hid) FAIL(400, "missing_id", "id");
        if (name[0] || kw[0] || hpar || web_jl_get(r, "note")) FAIL(400, "unknown_member", NULL);
        if (scalar(f, "SELECT COUNT(*) FROM tacdb_unit WHERE id = ?1", id, NULL, 0) == 0)
            FAIL(404, "no_such_unit", "id");
        if (del) {
            /* Nothing is left hanging: a unit with live subunits or
             * platforms is emptied first. */
            if (scalar(f, "SELECT COUNT(*) FROM tacdb_unit WHERE parent = ?1 AND deleted = 0", id, NULL, 0) ||
                scalar(f, "SELECT COUNT(*) FROM tacdb_platform WHERE unit = ?1 AND deleted = 0", id, NULL, 0))
                FAIL(409, "unit_not_empty", "id");
        } else {
            long long p = scalar(f, "SELECT COALESCE(parent, 0) FROM tacdb_unit WHERE id = ?1", id, NULL, 0);
            char nm[WEB_FRRS_NAME_MAX + 1] = "";
            sqlite3_stmt *q = prep(f, "SELECT name FROM tacdb_unit WHERE id = ?1");
            if (q) { sqlite3_bind_int64(q, 1, id); if (sqlite3_step(q) == SQLITE_ROW) ctext(q, 0, nm, sizeof(nm)); }
            sqlite3_finalize(q);
            if (p && !unit_live(f, p)) FAIL(409, "parent_deleted", "id");
            if (unit_name_taken(f, p, nm, id)) FAIL(409, "duplicate_name", "id");
            if (live_count(f, "tacdb_unit") >= WEB_FRRS_UNITS) FAIL(507, "tacdb_full", NULL);
        }
        sqlite3_stmt *s = prep(f, "UPDATE tacdb_unit SET deleted = ?2, updated = ?3 WHERE id = ?1");
        if (!s) FAIL(500, "store_error", NULL);
        sqlite3_bind_int64(s, 1, id);
        sqlite3_bind_int(s, 2, del);
        sqlite3_bind_int64(s, 3, now);
        int ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
        if (!ok) FAIL(500, "store_error", NULL);
    } else {
        FAIL(400, "bad_op", "op");
    }
    if (commit(f) != 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    return ok_unit(f, id, body, cap, len, status);
}

/* The emitter a body names: kind and addr, canonical. 1, 0 absent, -1 bad. */
static int body_emitter(const web_jrec_t *r, const char *kk, const char *ka, int *kind, char addr[24],
                        const char **why) {
    char kw[8], a[WEB_FRRS_ADDR_MAX + 1];
    if (!frrs_text(r, kk, 6, kw, why) || !frrs_text(r, ka, 24, a, why)) return -1;
    if (!kw[0] && !a[0]) return 0;
    if ((*kind = frrs_kind_find(kw)) < 0) { *why = "bad_kind"; return -1; }
    if (frrs_addr_canon(*kind, a, addr, 24) != 0) { *why = "bad_addr"; return -1; }
    return 1;
}

static int post_platform(const web_m4_t *m, web_frrs_t *f, const web_jrec_t *r, long long now,
                         char *body, size_t cap, size_t *len, int *status) {
    static const char *const MEMBERS[] = {
        "op", "id", "nomenclature", "class", "unit", "vendor", "note", "suggest",
        "emitter_kind", "emitter_addr", "emitter_role", "emitter_label", NULL,
    };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad)) return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], nom[WEB_FRRS_NAME_MAX + 1], cw[16], vendor[WEB_FRRS_NAME_MAX + 1];
    char note[WEB_FRRS_NOTE_MAX + 1], tok[48], rw[12], label[WEB_FRRS_LABEL_MAX + 1], addr[24];
    if (!frrs_text(r, "op", 10, op, &why)) return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "nomenclature", WEB_FRRS_NAME_MAX, nom, &why))
        return frrs_error(400, why, "nomenclature", body, cap, len, status);
    if (!frrs_text(r, "class", 15, cw, &why)) return frrs_error(400, why, "class", body, cap, len, status);
    if (!frrs_text(r, "vendor", WEB_FRRS_NAME_MAX, vendor, &why)) return frrs_error(400, why, "vendor", body, cap, len, status);
    if (!frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why)) return frrs_error(400, why, "note", body, cap, len, status);
    if (!frrs_text(r, "suggest", 47, tok, &why)) return frrs_error(400, why, "suggest", body, cap, len, status);
    if (!frrs_text(r, "emitter_role", 10, rw, &why)) return frrs_error(400, why, "emitter_role", body, cap, len, status);
    if (!frrs_text(r, "emitter_label", WEB_FRRS_LABEL_MAX, label, &why))
        return frrs_error(400, why, "emitter_label", body, cap, len, status);
    int ekind = 0;
    int he = body_emitter(r, "emitter_kind", "emitter_addr", &ekind, addr, &why);
    if (he < 0) return frrs_error(400, why, "emitter_addr", body, cap, len, status);
    int cls = cw[0] ? word_of(CLASS_WORD, N_CLASS, cw) : -2;
    if (cls == -1) return frrs_error(400, "bad_class", "class", body, cap, len, status);
    int role = rw[0] ? word_of(ROLE_WORD, N_ROLE, rw) : 0;
    if (role < 0) return frrs_error(400, "bad_role", "emitter_role", body, cap, len, status);
    long long id = 0, unit = 0;
    int idn, un;
    int hid = jid(r, "id", &id, &idn), hunit = jid(r, "unit", &unit, &un);
    if (hid < 0 || (hid && idn)) return frrs_error(400, "bad_id", "id", body, cap, len, status);
    if (hunit < 0) return frrs_error(400, "bad_unit", "unit", body, cap, len, status);
    if (begin(f) != 0) return frrs_error(503, "store_busy", NULL, body, cap, len, status);
    if (!strcmp(op, "create")) {
        if (hid || tok[0]) FAIL(400, "unknown_member", hid ? "id" : "suggest");
        if (!nom[0]) FAIL(400, "missing_nomenclature", "nomenclature");
        if (live_count(f, "tacdb_platform") >= WEB_FRRS_PLATFORMS) FAIL(507, "tacdb_full", NULL);
        if (unit && !unit_live(f, unit)) FAIL(404, "no_such_unit", "unit");
        if (nom_taken(f, nom, 0)) FAIL(409, "duplicate_name", "nomenclature");
        if (he > 0) {
            long long o = owner_of(f, ekind, addr);
            if (o) FAIL(409, "emitter_owned", "emitter_addr");
            if (live_count(f, "tacdb_emitter") >= WEB_FRRS_EMITTERS) FAIL(507, "tacdb_full", NULL);
        }
        id = insert_platform(f, unit, nom, cls < 0 ? 0 : cls, vendor, note, 1, 0, now);
        if (id < 0) FAIL(500, "store_error", NULL);
        if (he > 0 && put_emitter(f, id, ekind, addr, role, label, 0, now) != 0) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "update")) {
        if (!hid) FAIL(400, "missing_id", "id");
        if (he || tok[0]) FAIL(400, "unknown_member", he ? "emitter_addr" : "suggest");
        if (!platform_live(f, id)) FAIL(404, "no_such_platform", "id");
        if (hunit && unit && !unit_live(f, unit)) FAIL(404, "no_such_unit", "unit");
        if (nom[0] && nom_taken(f, nom, id)) FAIL(409, "duplicate_name", "nomenclature");
        sqlite3_stmt *s = prep(f, "UPDATE tacdb_platform SET nomenclature = COALESCE(?2, nomenclature),"
                                  " class = COALESCE(?3, class), unit = CASE WHEN ?4 THEN ?5 ELSE unit END,"
                                  " vendor = COALESCE(?6, vendor), note = COALESCE(?7, note), updated = ?8"
                                  " WHERE id = ?1");
        if (!s) FAIL(500, "store_error", NULL);
        sqlite3_bind_int64(s, 1, id);
        if (nom[0]) sqlite3_bind_text(s, 2, nom, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(s, 2);
        if (cls >= 0) sqlite3_bind_int(s, 3, cls); else sqlite3_bind_null(s, 3);
        sqlite3_bind_int(s, 4, hunit);
        if (hunit && unit) sqlite3_bind_int64(s, 5, unit); else sqlite3_bind_null(s, 5);
        if (web_jl_get(r, "vendor")) sqlite3_bind_text(s, 6, vendor, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(s, 6);
        if (web_jl_get(r, "note")) sqlite3_bind_text(s, 7, note, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(s, 7);
        sqlite3_bind_int64(s, 8, now);
        int ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
        if (!ok) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "delete") || !strcmp(op, "restore")) {
        int del = op[0] == 'd';
        if (!hid) FAIL(400, "missing_id", "id");
        if (nom[0] || cw[0] || hunit || he || tok[0]) FAIL(400, "unknown_member", NULL);
        if (scalar(f, "SELECT COUNT(*) FROM tacdb_platform WHERE id = ?1", id, NULL, 0) == 0)
            FAIL(404, "no_such_platform", "id");
        if (!del) {
            char cur[WEB_FRRS_NAME_MAX + 1] = "";
            sqlite3_stmt *q = prep(f, "SELECT nomenclature FROM tacdb_platform WHERE id = ?1");
            if (q) { sqlite3_bind_int64(q, 1, id); if (sqlite3_step(q) == SQLITE_ROW) ctext(q, 0, cur, sizeof(cur)); }
            sqlite3_finalize(q);
            if (nom_taken(f, cur, id)) FAIL(409, "duplicate_name", "id");
            if (live_count(f, "tacdb_platform") >= WEB_FRRS_PLATFORMS) FAIL(507, "tacdb_full", NULL);
        }
        /* Its emitters go with it (deleted 2: with the platform) and
         * come back with it, unless another platform has one since. */
        static const char *const SQL_DEL[] = {
            "UPDATE tacdb_emitter SET deleted = 2, updated = ?2 WHERE platform = ?1 AND deleted = 0",
            "UPDATE tacdb_platform SET deleted = 1, updated = ?2 WHERE id = ?1",
        };
        static const char *const SQL_RES[] = {
            "UPDATE tacdb_emitter SET deleted = 0, updated = ?2 WHERE platform = ?1 AND deleted = 2"
            " AND NOT EXISTS (SELECT 1 FROM tacdb_emitter o WHERE o.kind = tacdb_emitter.kind"
            " AND o.addr = tacdb_emitter.addr AND o.deleted = 0)",
            "UPDATE tacdb_platform SET deleted = 0, updated = ?2 WHERE id = ?1",
        };
        for (int i = 0; i < 2; i++) {
            sqlite3_stmt *s = prep(f, del ? SQL_DEL[i] : SQL_RES[i]);
            if (!s) FAIL(500, "store_error", NULL);
            sqlite3_bind_int64(s, 1, id);
            sqlite3_bind_int64(s, 2, now);
            int ok = sqlite3_step(s) == SQLITE_DONE;
            sqlite3_finalize(s);
            if (!ok) FAIL(500, "store_error", NULL);
        }
    } else if (!strcmp(op, "confirm")) {
        if (hid || he || cw[0]) FAIL(400, "unknown_member", NULL);
        int rule;
        char a[18], b[18];
        if (tok_read(f->nonce, tok, &rule, a, b) != 0) FAIL(400, "bad_suggestion", "suggest");
        int kind = FRRS_K_STA, rb = 2, rc = 0;
        if (rule == RULE_S2) {
            int ap = 0;
            if (f->led) {
                pthread_mutex_lock(&f->lmu);
                const frrs_bss_t *x = frrs_led_bss(f, a), *y = frrs_led_bss(f, b);
                ap = (x && x->has_b) || (y && y->has_b);
                pthread_mutex_unlock(&f->lmu);
            }
            kind = ap ? FRRS_K_BSSID : FRRS_K_STA;
            rb = 1;
            rc = ap ? 3 : 0;
        } else if (rule == RULE_S3) {
            kind = FRRS_K_BSSID;
            rb = 3;
            rc = 3;
        } else if (rule == RULE_S6) {
            rb = 0;
        }
        long long pa = owner_of(f, kind, a), pb = b[0] ? owner_of(f, kind, b) : 0;
        if (pa && pb && pa != pb) FAIL(409, "emitter_owned", "suggest");
        id = pa ? pa : pb;
        if (!id) {
            if (live_count(f, "tacdb_platform") >= WEB_FRRS_PLATFORMS) FAIL(507, "tacdb_full", NULL);
            if (unit && !unit_live(f, unit)) FAIL(404, "no_such_unit", "unit");
            char auto_nom[WEB_FRRS_NAME_MAX + 1];
            if (!nom[0]) {
                auto_name(m, a, rc, auto_nom, sizeof(auto_nom));
                /* Unique: a second one of the same name gets a number. */
                for (int k = 2; nom_taken(f, auto_nom, 0) && k < 100; k++) {
                    char t[WEB_FRRS_NAME_MAX + 1];
                    auto_name(m, a, rc, t, sizeof(t) - 4);
                    snprintf(auto_nom, sizeof(auto_nom), "%.58s %d", t, k);
                }
            }
            const char *use = nom[0] ? nom : auto_nom;
            if (nom_taken(f, use, 0)) FAIL(409, "duplicate_name", "nomenclature");
            char ven[WEB_FRRS_NAME_MAX + 1] = "";
            uint8_t mb[6];
            web_oui_hit_t h;
            if (vendor[0]) snprintf(ven, sizeof(ven), "%s", vendor);
            else if (web_oui_mac_bytes(a, mb) == 0 && m->oui && web_oui_lookup(m->oui, mb, &h))
                snprintf(ven, sizeof(ven), "%s", h.name);
            id = insert_platform(f, unit, use, rc, ven, note, 1, 10 + rule, now);
            if (id < 0) FAIL(500, "store_error", NULL);
        }
        if (live_count(f, "tacdb_emitter") + 2 > WEB_FRRS_EMITTERS) FAIL(507, "tacdb_full", NULL);
        if (!pa && put_emitter(f, id, kind, a, 0, "", 10 + rule, now) != 0) FAIL(500, "store_error", NULL);
        if (b[0] && !pb && put_emitter(f, id, kind, b, rb, "", 10 + rule, now) != 0) FAIL(500, "store_error", NULL);
    } else {
        FAIL(400, "bad_op", "op");
    }
    if (commit(f) != 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    return ok_platform(f, id, body, cap, len, status);
}

static int post_emitter(web_frrs_t *f, const web_jrec_t *r, long long now, char *body, size_t cap,
                        size_t *len, int *status) {
    static const char *const MEMBERS[] = { "op", "platform", "kind", "addr", "role", "label", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad)) return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], rw[12], label[WEB_FRRS_LABEL_MAX + 1], addr[24];
    if (!frrs_text(r, "op", 10, op, &why)) return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "role", 10, rw, &why)) return frrs_error(400, why, "role", body, cap, len, status);
    if (!frrs_text(r, "label", WEB_FRRS_LABEL_MAX, label, &why)) return frrs_error(400, why, "label", body, cap, len, status);
    int kind = 0;
    int he = body_emitter(r, "kind", "addr", &kind, addr, &why);
    if (he < 0) return frrs_error(400, why, "addr", body, cap, len, status);
    if (he == 0) return frrs_error(400, "missing_addr", "addr", body, cap, len, status);
    int role = rw[0] ? word_of(ROLE_WORD, N_ROLE, rw) : 0;
    if (role < 0) return frrs_error(400, "bad_role", "role", body, cap, len, status);
    long long p = 0;
    int pn;
    int hp = jid(r, "platform", &p, &pn);
    if (hp < 0 || (hp && pn)) return frrs_error(400, "bad_platform", "platform", body, cap, len, status);
    if (begin(f) != 0) return frrs_error(503, "store_busy", NULL, body, cap, len, status);
    long long owner = owner_of(f, kind, addr);
    if (!strcmp(op, "add") || !strcmp(op, "move")) {
        if (!hp) FAIL(400, "missing_platform", "platform");
        if (!platform_live(f, p)) FAIL(404, "no_such_platform", "platform");
        if (op[0] == 'a' && owner && owner != p) FAIL(409, "emitter_owned", "addr");
        if (op[0] == 'm' && !owner) FAIL(404, "no_such_emitter", "addr");
        if (!owner && live_count(f, "tacdb_emitter") >= WEB_FRRS_EMITTERS) FAIL(507, "tacdb_full", NULL);
        if (op[0] == 'm' && owner != p) {
            sqlite3_stmt *s = prep(f, "UPDATE tacdb_emitter SET deleted = 1, updated = ?3 WHERE"
                                      " platform = ?1 AND kind = ?2 AND addr = ?4");
            if (!s) FAIL(500, "store_error", NULL);
            sqlite3_bind_int64(s, 1, owner);
            sqlite3_bind_int(s, 2, kind);
            sqlite3_bind_int64(s, 3, now);
            sqlite3_bind_text(s, 4, addr, -1, SQLITE_TRANSIENT);
            int ok = sqlite3_step(s) == SQLITE_DONE;
            sqlite3_finalize(s);
            if (!ok) FAIL(500, "store_error", NULL);
        }
        if (put_emitter(f, p, kind, addr, role, label, 0, now) != 0) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "remove")) {
        if (!owner) FAIL(404, "no_such_emitter", "addr");
        if (hp && p != owner) FAIL(409, "emitter_owned", "platform");
        p = owner;
        sqlite3_stmt *s = prep(f, "UPDATE tacdb_emitter SET deleted = 1, updated = ?3 WHERE"
                                  " platform = ?1 AND kind = ?2 AND addr = ?4 AND deleted = 0");
        if (!s) FAIL(500, "store_error", NULL);
        sqlite3_bind_int64(s, 1, p);
        sqlite3_bind_int(s, 2, kind);
        sqlite3_bind_int64(s, 3, now);
        sqlite3_bind_text(s, 4, addr, -1, SQLITE_TRANSIENT);
        int ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
        if (!ok) FAIL(500, "store_error", NULL);
    } else if (!strcmp(op, "restore")) {
        if (!hp) FAIL(400, "missing_platform", "platform");
        if (owner) FAIL(409, "emitter_owned", "addr");
        if (!platform_live(f, p)) FAIL(404, "no_such_platform", "platform");
        if (live_count(f, "tacdb_emitter") >= WEB_FRRS_EMITTERS) FAIL(507, "tacdb_full", NULL);
        sqlite3_stmt *s = prep(f, "UPDATE tacdb_emitter SET deleted = 0, updated = ?3 WHERE"
                                  " platform = ?1 AND kind = ?2 AND addr = ?4 AND deleted <> 0");
        if (!s) FAIL(500, "store_error", NULL);
        sqlite3_bind_int64(s, 1, p);
        sqlite3_bind_int(s, 2, kind);
        sqlite3_bind_int64(s, 3, now);
        sqlite3_bind_text(s, 4, addr, -1, SQLITE_TRANSIENT);
        int ok = sqlite3_step(s) == SQLITE_DONE;
        int changed = sqlite3_changes(f->wr);
        sqlite3_finalize(s);
        if (!ok) FAIL(500, "store_error", NULL);
        if (!changed) FAIL(404, "no_such_emitter", "addr");
    } else {
        FAIL(400, "bad_op", "op");
    }
    if (commit(f) != 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    return ok_platform(f, p, body, cap, len, status);
}

static int post_dismiss(web_frrs_t *f, const web_jrec_t *r, long long now, char *body, size_t cap,
                        size_t *len, int *status) {
    static const char *const MEMBERS[] = { "suggest", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad)) return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char tok[48], a[18], b[18];
    int rule;
    if (!frrs_text(r, "suggest", 47, tok, &why)) return frrs_error(400, why, "suggest", body, cap, len, status);
    if (tok_read(f->nonce, tok, &rule, a, b) != 0)
        return frrs_error(400, "bad_suggestion", "suggest", body, cap, len, status);
    if (begin(f) != 0) return frrs_error(503, "store_busy", NULL, body, cap, len, status);
    if (scalar(f, "SELECT COUNT(*) FROM tacdb_dismiss", 0, NULL, 0) >= WEB_FRRS_DISMISS) FAIL(507, "tacdb_full", NULL);
    sqlite3_stmt *s = prep(f, "INSERT INTO tacdb_dismiss (rule, a, b, ts) VALUES (?1, ?2, ?3, ?4)"
                              " ON CONFLICT (rule, a, b) DO UPDATE SET ts = ?4");
    if (!s) FAIL(500, "store_error", NULL);
    sqlite3_bind_int(s, 1, rule);
    sqlite3_bind_text(s, 2, a, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, b, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, now);
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    if (!ok) FAIL(500, "store_error", NULL);
    if (commit(f) != 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"ok\":true,\"dismissed\":{\"rule\":");
    char rn[4];
    snprintf(rn, sizeof(rn), "S%d", rule);
    web_jw_str(&w, rn);
    web_jw_raw(&w, ",\"a\":"); web_jw_str(&w, a);
    web_jw_raw(&w, ",\"b\":"); frrs_str_or_null(&w, b);
    web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, now);
    web_jw_raw(&w, "}}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int frrs_tacdb_post(const web_m4_t *m, const char *path, const web_jrec_t *r,
                    const char *peer, long long now_s, char *body, size_t cap,
                    size_t *len, int *status) {
    (void)peer;
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    if (!strcmp(path, "/api/frrs/tacdb/unit")) return post_unit(f, r, now_s, body, cap, len, status);
    if (!strcmp(path, "/api/frrs/tacdb/platform")) return post_platform(m, f, r, now_s, body, cap, len, status);
    if (!strcmp(path, "/api/frrs/tacdb/emitter")) return post_emitter(f, r, now_s, body, cap, len, status);
    if (!strcmp(path, "/api/frrs/tacdb/dismiss")) return post_dismiss(f, r, now_s, body, cap, len, status);
    return frrs_error(404, "not_found", NULL, body, cap, len, status);
}

/* ── export and import (§8) ─────────────────────────────────────────── */

int frrs_export(const web_m4_t *m, long long now_s, char **big, size_t *biglen,
                char *body, size_t cap, size_t *len, int *status) {
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    char *buf = malloc(WEB_FRRS_EXPORT_MAX);
    if (!buf) return frrs_error(503, "out_of_memory", NULL, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, buf, WEB_FRRS_EXPORT_MAX);
    long long lines = 1, tri = 0;
    web_jw_raw(&w, "{\"type\":\"slothweb-tacdb\",\"format\":\"slothweb-tacdb\",\"version\":1,\"exported\":");
    web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"note\":\"operator state: units, platforms, emitters, dismissed suggestions "
                   "and triage history; deleted rows included\"}\n");
    sqlite3_stmt *s = prep(f, "SELECT id, COALESCE(parent, 0), name, kind, note, deleted FROM tacdb_unit ORDER BY id");
    while (s && sqlite3_step(s) == SQLITE_ROW && w.len + 2048 < w.cap) {
        char name[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
        ctext(s, 2, name, sizeof(name));
        ctext(s, 4, note, sizeof(note));
        int k = sqlite3_column_int(s, 3);
        web_jw_raw(&w, "{\"type\":\"unit\",\"id\":"); web_jw_int(&w, sqlite3_column_int64(s, 0));
        web_jw_raw(&w, ",\"parent\":");
        if (sqlite3_column_int64(s, 1)) web_jw_int(&w, sqlite3_column_int64(s, 1)); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"name\":"); web_jw_str(&w, name);
        web_jw_raw(&w, ",\"kind\":"); web_jw_str(&w, k >= 0 && k < N_UNIT_KIND ? UNIT_KIND[k] : "other");
        web_jw_raw(&w, ",\"note\":"); web_jw_str(&w, note);
        web_jw_raw(&w, ",\"deleted\":"); web_jw_raw(&w, sqlite3_column_int(s, 5) ? "true" : "false");
        web_jw_raw(&w, "}\n");
        lines++;
    }
    sqlite3_finalize(s);
    s = prep(f, "SELECT id, COALESCE(unit, 0), nomenclature, class, vendor, note, confirmed, origin, deleted"
                " FROM tacdb_platform ORDER BY id");
    while (s && sqlite3_step(s) == SQLITE_ROW && w.len + 2048 < w.cap) {
        char nom[WEB_FRRS_NAME_MAX + 1], ven[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
        ctext(s, 2, nom, sizeof(nom));
        ctext(s, 4, ven, sizeof(ven));
        ctext(s, 5, note, sizeof(note));
        int c = sqlite3_column_int(s, 3);
        web_jw_raw(&w, "{\"type\":\"platform\",\"id\":"); web_jw_int(&w, sqlite3_column_int64(s, 0));
        web_jw_raw(&w, ",\"unit\":");
        if (sqlite3_column_int64(s, 1)) web_jw_int(&w, sqlite3_column_int64(s, 1)); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"nomenclature\":"); web_jw_str(&w, nom);
        web_jw_raw(&w, ",\"class\":"); web_jw_str(&w, c >= 0 && c < N_CLASS ? CLASS_WORD[c] : "unknown");
        web_jw_raw(&w, ",\"vendor\":"); web_jw_str(&w, ven);
        web_jw_raw(&w, ",\"note\":"); web_jw_str(&w, note);
        web_jw_raw(&w, ",\"confirmed\":"); web_jw_raw(&w, sqlite3_column_int(s, 6) ? "true" : "false");
        web_jw_raw(&w, ",\"origin\":"); web_jw_str(&w, origin_word(sqlite3_column_int(s, 7)));
        web_jw_raw(&w, ",\"deleted\":"); web_jw_raw(&w, sqlite3_column_int(s, 8) ? "true" : "false");
        web_jw_raw(&w, "}\n");
        lines++;
    }
    sqlite3_finalize(s);
    s = prep(f, "SELECT platform, kind, addr, role, label, deleted FROM tacdb_emitter ORDER BY platform, kind, addr");
    while (s && sqlite3_step(s) == SQLITE_ROW && w.len + 2048 < w.cap) {
        char addr[24], label[WEB_FRRS_LABEL_MAX + 1];
        ctext(s, 2, addr, sizeof(addr));
        ctext(s, 4, label, sizeof(label));
        int role = sqlite3_column_int(s, 3);
        web_jw_raw(&w, "{\"type\":\"emitter\",\"platform\":"); web_jw_int(&w, sqlite3_column_int64(s, 0));
        web_jw_raw(&w, ",\"kind\":"); web_jw_str(&w, frrs_kind_word(sqlite3_column_int(s, 1)));
        web_jw_raw(&w, ",\"addr\":"); web_jw_str(&w, addr);
        web_jw_raw(&w, ",\"role\":"); web_jw_str(&w, role >= 0 && role < N_ROLE ? ROLE_WORD[role] : "other");
        web_jw_raw(&w, ",\"label\":"); web_jw_str(&w, label);
        web_jw_raw(&w, ",\"deleted\":"); web_jw_raw(&w, sqlite3_column_int(s, 5) ? "true" : "false");
        web_jw_raw(&w, "}\n");
        lines++;
    }
    sqlite3_finalize(s);
    s = prep(f, "SELECT rule, a, b, ts FROM tacdb_dismiss ORDER BY ts");
    while (s && sqlite3_step(s) == SQLITE_ROW && w.len + 2048 < w.cap) {
        char a[24], b[24], rn[4];
        ctext(s, 1, a, sizeof(a));
        ctext(s, 2, b, sizeof(b));
        snprintf(rn, sizeof(rn), "S%d", sqlite3_column_int(s, 0) % 10);
        web_jw_raw(&w, "{\"type\":\"dismiss\",\"rule\":"); web_jw_str(&w, rn);
        web_jw_raw(&w, ",\"a\":"); web_jw_str(&w, a);
        web_jw_raw(&w, ",\"b\":"); web_jw_str(&w, b);
        web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, sqlite3_column_int64(s, 3));
        web_jw_raw(&w, "}\n");
        lines++;
    }
    sqlite3_finalize(s);
    size_t before = w.len;
    frrs_triage_export(f, &w, &tri);
    (void)before;
    lines += tri;
    int complete = w.len + 2048 < w.cap;
    web_jw_raw(&w, "{\"type\":\"end\",\"lines\":");
    web_jw_int(&w, lines + 1);
    web_jw_raw(&w, ",\"complete\":");
    web_jw_raw(&w, complete ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) {
        free(buf);
        return frrs_error(507, "export_too_large", NULL, body, cap, len, status);
    }
    pthread_mutex_lock(&f->lmu);
    f->st.exports++;
    pthread_mutex_unlock(&f->lmu);
    *big = buf;
    *biglen = w.len;
    *len = 0;
    *status = 200;
    return 0;
}

typedef struct {
    long long from, to;
} idmap_t;

static long long map_of(const idmap_t *mp, int n, long long from) {
    for (int i = 0; i < n; i++) if (mp[i].from == from) return mp[i].to;
    return 0;
}

int frrs_import(const web_m4_t *m, const web_req_t *rq, long long now_s,
                char *body, size_t cap, size_t *len, int *status) {
    web_frrs_t *f = m->frrs;
    web_param_t ps[1] = { { "mode", "", 0 } };
    char err[48];
    if (web_params_parse(rq->query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    int write = ps[0].seen ? !strcmp(ps[0].val, "merge") ? 1 : !strcmp(ps[0].val, "check") ? 0 : -1 : 0;
    if (write < 0) return frrs_error(400, "bad_mode", NULL, body, cap, len, status);
    if (!rq->body || !rq->body_len) return frrs_error(400, "bad_body", NULL, body, cap, len, status);
    web_jrec_t *r = malloc(sizeof(*r));
    idmap_t *um = calloc(WEB_FRRS_UNITS * 2, sizeof(*um)), *pm = calloc(WEB_FRRS_PLATFORMS * 2, sizeof(*pm));
    if (!r || !um || !pm) { free(r); free(um); free(pm); return -1; }
    int nu = 0, np = 0;
    long long nlines = 0, merged[5] = { 0, 0, 0, 0, 0 }, skipped = 0;
    int bad_line = 0, saw_head = 0;
    const char *bad_why = NULL;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"mode\":");
    web_jw_str(&w, write ? "merge" : "check");
    web_jw_raw(&w, ",\"skipped\":[");
    int nskip_shown = 0;
    /* Two passes: every line checked first; only a file that checks
     * whole is merged, in one transaction. */
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
            if (bad_line || !write) break;
            if (begin(f) != 0) {
                free(r); free(um); free(pm);
                return frrs_error(503, "store_busy", NULL, body, cap, len, status);
            }
        }
        const char *p = rq->body, *end = rq->body + rq->body_len;
        long long ln = 0;
        while (p < end) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
            ln++;
            const char *line = p;
            p = nl ? nl + 1 : end;
            if (n == 0) continue;
            const char *why = NULL;
            if (n > WEB_JL_MAX_LINE || web_jl_parse(line, n, r) != WEB_JL_OK) why = "bad_line";
            const char *type = why ? "" : web_jl_str(r, "type");
            int skip = 0;
            if (!why && pass == 0) nlines++;
            if (!why && !strcmp(type, "slothweb-tacdb")) {
                if (web_jl_int(r, "version", 0) != 1) why = "bad_version";
                saw_head = 1;
            } else if (!why && !strcmp(type, "end")) {
                /* the trailer */
            } else if (!why && !strcmp(type, "unit")) {
                static const char *const M[] = { "type", "id", "parent", "name", "kind", "note", "deleted", NULL };
                const char *b = NULL;
                char name[WEB_FRRS_NAME_MAX + 1], kw[12], note[WEB_FRRS_NOTE_MAX + 1];
                long long id = web_jl_int(r, "id", 0), par = web_jl_int(r, "parent", 0);
                if (!frrs_members_ok(r, M, &b)) why = "unknown_member";
                else if (!frrs_text(r, "name", WEB_FRRS_NAME_MAX, name, &why) ||
                         !frrs_text(r, "kind", 10, kw, &why) || !frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why)) {}
                else if (!name[0] || id <= 0 || par < 0) why = "bad_unit";
                else if (word_of(UNIT_KIND, N_UNIT_KIND, kw) < 0) why = "bad_kind";
                else if (pass == 1) {
                    if (web_jl_int(r, "deleted", 0)) { skip = 1; why = "deleted_in_file"; }
                    else {
                        long long lp = par ? map_of(um, nu, par) : 0;
                        if (par && !lp) { skip = 1; why = "parent_not_merged"; }
                        else {
                            long long here = 0;
                            sqlite3_stmt *s = prep(f, "SELECT id FROM tacdb_unit WHERE deleted = 0 AND"
                                                      " parent IS ?1 AND lower(name) = lower(?2)");
                            if (s) {
                                if (lp) sqlite3_bind_int64(s, 1, lp); else sqlite3_bind_null(s, 1);
                                sqlite3_bind_text(s, 2, name, -1, SQLITE_TRANSIENT);
                                if (sqlite3_step(s) == SQLITE_ROW) here = sqlite3_column_int64(s, 0);
                            }
                            sqlite3_finalize(s);
                            if (!here) {
                                if (live_count(f, "tacdb_unit") >= WEB_FRRS_UNITS) { skip = 1; why = "tacdb_full"; }
                                else if (lp && unit_depth(f, lp) + 1 > WEB_FRRS_UNIT_DEPTH) { skip = 1; why = "unit_depth"; }
                                else {
                                    here = insert_unit(f, lp, name, word_of(UNIT_KIND, N_UNIT_KIND, kw), note, 1, now_s);
                                    if (here < 0) { why = "store_error"; bad_line = 1; }
                                    else merged[0]++;
                                }
                            } else { skip = 1; why = "already_here"; }
                            if (here > 0 && nu < WEB_FRRS_UNITS * 2) { um[nu].from = id; um[nu].to = here; nu++; }
                        }
                    }
                }
            } else if (!why && !strcmp(type, "platform")) {
                static const char *const M[] = { "type", "id", "unit", "nomenclature", "class", "vendor",
                                                 "note", "confirmed", "origin", "deleted", NULL };
                const char *b = NULL;
                char nom[WEB_FRRS_NAME_MAX + 1], cw[16], ven[WEB_FRRS_NAME_MAX + 1], note[WEB_FRRS_NOTE_MAX + 1];
                long long id = web_jl_int(r, "id", 0), un = web_jl_int(r, "unit", 0);
                if (!frrs_members_ok(r, M, &b)) why = "unknown_member";
                else if (!frrs_text(r, "nomenclature", WEB_FRRS_NAME_MAX, nom, &why) ||
                         !frrs_text(r, "class", 15, cw, &why) || !frrs_text(r, "vendor", WEB_FRRS_NAME_MAX, ven, &why) ||
                         !frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why)) {}
                else if (!nom[0] || id <= 0 || un < 0) why = "bad_platform";
                else if (word_of(CLASS_WORD, N_CLASS, cw) < 0) why = "bad_class";
                else if (pass == 1) {
                    if (web_jl_int(r, "deleted", 0)) { skip = 1; why = "deleted_in_file"; }
                    else {
                        long long here = scalar(f, "SELECT id FROM tacdb_platform WHERE deleted = 0 AND"
                                                   " lower(nomenclature) = lower(?2) AND ?1 = ?1", 0, nom, 0);
                        if (here) { skip = 1; why = "already_here"; }
                        else if (live_count(f, "tacdb_platform") >= WEB_FRRS_PLATFORMS) { skip = 1; why = "tacdb_full"; }
                        else {
                            here = insert_platform(f, un ? map_of(um, nu, un) : 0, nom,
                                                   word_of(CLASS_WORD, N_CLASS, cw), ven, note, 1, 1, now_s);
                            if (here < 0) { why = "store_error"; bad_line = 1; }
                            else merged[1]++;
                        }
                        if (here > 0 && np < WEB_FRRS_PLATFORMS * 2) { pm[np].from = id; pm[np].to = here; np++; }
                    }
                }
            } else if (!why && !strcmp(type, "emitter")) {
                static const char *const M[] = { "type", "platform", "kind", "addr", "role", "label", "deleted", NULL };
                const char *b = NULL;
                char rw[12], label[WEB_FRRS_LABEL_MAX + 1], addr[24];
                int kind = 0;
                long long pl = web_jl_int(r, "platform", 0);
                if (!frrs_members_ok(r, M, &b)) why = "unknown_member";
                else if (!frrs_text(r, "role", 10, rw, &why) || !frrs_text(r, "label", WEB_FRRS_LABEL_MAX, label, &why)) {}
                else if (body_emitter(r, "kind", "addr", &kind, addr, &why) <= 0) { if (!why) why = "bad_addr"; }
                else if (pl <= 0 || word_of(ROLE_WORD, N_ROLE, rw) < 0) why = "bad_emitter";
                else if (pass == 1) {
                    long long lp = map_of(pm, np, pl);
                    long long o = owner_of(f, kind, addr);
                    if (web_jl_int(r, "deleted", 0)) { skip = 1; why = "deleted_in_file"; }
                    else if (!lp) { skip = 1; why = "platform_not_merged"; }
                    else if (o && o != lp) { skip = 1; why = "emitter_owned"; }
                    else if (o == lp) { skip = 1; why = "already_here"; }
                    else if (live_count(f, "tacdb_emitter") >= WEB_FRRS_EMITTERS) { skip = 1; why = "tacdb_full"; }
                    else if (put_emitter(f, lp, kind, addr, word_of(ROLE_WORD, N_ROLE, rw), label, 1, now_s) != 0) {
                        why = "store_error"; bad_line = 1;
                    } else merged[2]++;
                }
            } else if (!why && !strcmp(type, "dismiss")) {
                static const char *const M[] = { "type", "rule", "a", "b", "ts", NULL };
                const char *b = NULL;
                char rn[4], a[24], bb[24], ka[WEB_KEY_MAX + 1], kb[WEB_KEY_MAX + 1];
                if (!frrs_members_ok(r, M, &b)) why = "unknown_member";
                else if (!frrs_text(r, "rule", 3, rn, &why) || !frrs_text(r, "a", 17, a, &why) ||
                         !frrs_text(r, "b", 17, bb, &why)) {}
                else if (rn[0] != 'S' || !isdigit((unsigned char)rn[1]) || rn[2] || web_key_mac(a, ka) ||
                         (bb[0] && web_key_mac(bb, kb))) why = "bad_dismiss";
                else if (pass == 1) {
                    if (scalar(f, "SELECT COUNT(*) FROM tacdb_dismiss", 0, NULL, 0) >= WEB_FRRS_DISMISS) {
                        skip = 1; why = "tacdb_full";
                    } else {
                        sqlite3_stmt *s = prep(f, "INSERT OR IGNORE INTO tacdb_dismiss (rule, a, b, ts)"
                                                  " VALUES (?1, ?2, ?3, ?4)");
                        if (s) {
                            sqlite3_bind_int(s, 1, rn[1] - '0');
                            sqlite3_bind_text(s, 2, ka, -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(s, 3, bb[0] ? kb : "", -1, SQLITE_TRANSIENT);
                            sqlite3_bind_int64(s, 4, web_jl_int(r, "ts", now_s));
                            if (sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(f->wr)) merged[3]++;
                            else { skip = 1; why = "already_here"; }
                        }
                        sqlite3_finalize(s);
                    }
                }
            } else if (!why && !strcmp(type, "triage")) {
                int t = frrs_triage_import(f, r, pass == 1, now_s, rq->peer, &why);
                if (t == 0 && pass == 1) merged[4]++;
                else if (t > 0) {
                    if (pass == 1 || strcmp(why, "already_here")) skip = pass == 1;
                    if (pass == 0 && !strcmp(why, "already_here")) why = NULL;
                } else if (t < 0) { why = "store_error"; bad_line = 1; }
            } else if (!why) {
                why = "unknown_type";
            }
            if (why && (pass == 0 || skip || bad_line)) {
                if (pass == 0 && !skip) {
                    bad_line = 1;
                    if (!bad_why) bad_why = why;
                }
                if (pass == 1 || !skip) skipped++;
                if (nskip_shown < 50 && w.len + 256 < cap) {
                    web_jw_raw(&w, nskip_shown++ ? ",{\"line\":" : "{\"line\":");
                    web_jw_int(&w, ln);
                    web_jw_raw(&w, ",\"why\":");
                    web_jw_str(&w, why);
                    web_jw_raw(&w, "}");
                }
            }
        }
    }
    int ok = !bad_line && saw_head;
    if (write && ok) {
        if (commit(f) != 0) ok = 0;
    } else if (write && !bad_line) {
        /* nothing begun */
    } else if (write && bad_line && saw_head) {
        /* pass 1 never ran (the check failed) or failed mid-way */
        sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    }
    web_jw_raw(&w, "],\"skipped_n\":"); web_jw_int(&w, skipped);
    web_jw_raw(&w, ",\"lines\":");      web_jw_int(&w, nlines);
    web_jw_raw(&w, ",\"ok\":");         web_jw_raw(&w, ok ? "true" : "false");
    web_jw_raw(&w, ",\"why\":");
    frrs_str_or_null(&w, !saw_head ? "not a slothweb-tacdb file (no header line)" : bad_why);
    web_jw_raw(&w, ",\"merged\":{\"units\":"); web_jw_int(&w, write && ok ? merged[0] : 0);
    web_jw_raw(&w, ",\"platforms\":");  web_jw_int(&w, write && ok ? merged[1] : 0);
    web_jw_raw(&w, ",\"emitters\":");   web_jw_int(&w, write && ok ? merged[2] : 0);
    web_jw_raw(&w, ",\"dismissed\":");  web_jw_int(&w, write && ok ? merged[3] : 0);
    web_jw_raw(&w, ",\"triage\":");     web_jw_int(&w, write && ok ? merged[4] : 0);
    web_jw_raw(&w, "}}\n");
    free(r);
    free(um);
    free(pm);
    if (w.overflow) return -1;
    *len = w.len;
    *status = ok ? 200 : 400;
    return 0;
}

#else /* !WITH_SQLITE */

int frrs_tacdb_get(const web_m4_t *m, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
int frrs_tacdb_view(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
int frrs_suggest_get(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)query; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
int frrs_export(const web_m4_t *m, long long now_s, char **big, size_t *biglen,
                char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)now_s; (void)big; (void)biglen;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
int frrs_tacdb_post(const web_m4_t *m, const char *path, const web_jrec_t *r,
                    const char *peer, long long now_s, char *body, size_t cap,
                    size_t *len, int *status) {
    (void)m; (void)path; (void)r; (void)peer; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
int frrs_import(const web_m4_t *m, const web_req_t *rq, long long now_s,
                char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)rq; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
void frrs_tacdb_of(web_frrs_t *f, int kind, const char *addr, web_jw_t *w) {
    (void)f; (void)kind; (void)addr;
    web_jw_raw(w, "null");
}

#endif
