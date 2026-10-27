/* slothweb device query language (#162, M4): docs/web-ui-spec.md §9.1.
 *
 *   vendor:apple random:yes seen:<24h -name:printer "living room"
 *
 * Terms are separated by spaces and all must hold (AND). A leading '-'
 * negates one. A term is `prefix:value` for a prefix below, else free
 * text, which matches the MAC, IP, hostname, vendor or last SSID. A
 * value with a space in it is double-quoted (no escapes inside). A word
 * before a ':' that is not a prefix (b8:27:eb, ab:cd) is free text.
 *
 *   vendor:TEXT   vendor (the OUI table's, or sloth's own)  substring
 *   mac:HEX       MAC, from the start: b8:27:eb, b8-27-eb     prefix
 *   ip:ADDR       IP (the device's or an ARP binding's)       prefix
 *   ssid:TEXT     last SSID or a PNL SSID                     substring
 *   name:TEXT     hostname, DHCP, mDNS, NBNS or passive PTR  substring
 *   random:yes|no the locally administered bit
 *   seen:<24h     last seen less than 24 h ago; seen:>7d more than 7 d
 *                 ago; seen:>2026-09-29 (or >=) at or after that day
 *                 (UTC), seen:<2026-09-29 before it, seen:<=2026-09-29
 *                 on or before it, seen:2026-09-29 on it.
 *                 Units s m h d w; no operator means '<'.
 *   first:...     first seen, the same forms
 *   risk:N        risk level 0..3, with = < > <= >= (default =)
 *   z:>3          |z| now (the latest A1 score of the device's metrics)
 *   src:WORD      arp dhcp mdns beacon probe sta camera
 *   has:WORD      pnl alert anomaly name ip ssid
 *   anomaly:KIND  an episode of that kind (rate new hours vendor ident
 *                 fanout dns proto sensor) keyed by the MAC
 *   pass:latest   in the device pass sloth sent last on the stream: the
 *                 set the Overview's devices tile counts
 *
 * Bounded: the query is at most WEB_Q_LEN bytes, WEB_Q_TERMS terms of
 * at most WEB_Q_TERM_LEN bytes; text is well-formed UTF-8 with no
 * control byte; every other value is checked against its prefix's
 * form. A refusal names the reason in a word of slothweb's own.
 *
 * Compiled to ONE statement: its text is assembled only from the
 * constant fragments in web_query.c, and every value from the query is
 * a bound parameter (?N), a LIKE pattern with \, % and _ escaped. The
 * statement reads only columns on the sloth.db reader's allow-list
 * (web_slothdb.h), which its authorizer enforces again at prepare.
 * Pure: no SQLite here, so the fuzz target needs none. */
#ifndef SLOTHWEB_QUERY_H
#define SLOTHWEB_QUERY_H

#include <stddef.h>

#define WEB_Q_LEN       256
#define WEB_Q_TERMS     12
#define WEB_Q_TERM_LEN  64
#define WEB_Q_SQL_MAX   32768   /* a scoped statement (web_scope.h) is the long one */
#define WEB_Q_BINDS     (2 * WEB_Q_TERMS + 2)
#define WEB_Q_BIND_TEXT (WEB_Q_TERM_LEN * 2 + 3)

enum {
    WEB_QT_FREE = 0, WEB_QT_VENDOR, WEB_QT_MAC, WEB_QT_IP, WEB_QT_SSID,
    WEB_QT_NAME, WEB_QT_RANDOM, WEB_QT_SEEN, WEB_QT_FIRST, WEB_QT_RISK,
    WEB_QT_Z, WEB_QT_SRC, WEB_QT_HAS, WEB_QT_ANOMALY, WEB_QT_PASS, WEB_QT_COUNT
};

enum { WEB_QOP_EQ = 0, WEB_QOP_LT, WEB_QOP_GT, WEB_QOP_LE, WEB_QOP_GE };

enum { WEB_HAS_PNL = 0, WEB_HAS_ALERT, WEB_HAS_ANOMALY, WEB_HAS_NAME,
       WEB_HAS_IP, WEB_HAS_SSID };

typedef struct {
    int       kind;            /* WEB_QT_* */
    int       neg;
    int       op;              /* WEB_QOP_*, for seen first risk z */
    char      text[WEB_Q_TERM_LEN + 1];   /* text, mac and ip terms */
    long long num;             /* seen/first: a unix time; risk; src bit;
                                  has/anomaly: the index; random: 0/1 */
    long long num2;            /* seen/first on a day: its end */
    double    z;
} web_qterm_t;

typedef struct {
    web_qterm_t t[WEB_Q_TERMS];
    int         n;
} web_query_t;

/* Parse q against now_s (for the relative times). 0, or -1 with a
 * reason in err ("query_too_long", "too_many_terms", "term_too_long",
 * "bad_text", "bad_mac", "bad_ip", "bad_random", "bad_time", "bad_risk",
 * "bad_z", "bad_src", "bad_has", "bad_anomaly", "bad_pass", "empty_value",
 * "bad_quote"). */
int web_query_parse(const char *q, long long now_s, web_query_t *out,
                    char *err, size_t errsz);

/* What the reader found in the file: a missing table's conditions read
 * as false rather than naming a table that is not there. */
enum {
    WEB_QF_PNL    = 1 << 0,     /* pnl_clients and pnl_ssids */
    WEB_QF_DHCP   = 1 << 1,     /* dhcp_leases */
    WEB_QF_MDNS   = 1 << 2,     /* mdns_services */
    WEB_QF_NBNS   = 1 << 3,     /* nbns_names */
    WEB_QF_ALERTS = 1 << 4,     /* alerts */
    WEB_QF_ARP    = 1 << 5,     /* arp */
    /* The capture scope's tables (web_scope.h): which a scoped
     * statement may name for membership, signal and first/last seen. */
    WEB_QF_PROBE  = 1 << 6,     /* probe_clients */
    WEB_QF_BEACON = 1 << 7,     /* beacon_aps */
    WEB_QF_ASSOC  = 1 << 8,     /* assocs */
    WEB_QF_PNLC   = 1 << 9,     /* pnl_clients */
    WEB_QF_STA    = 1 << 10,    /* wifi_stas */
    WEB_QF_CAMSIG = 1 << 11     /* devices.cam_signals (v6) */
};

enum { WEB_QS_LAST = 0, WEB_QS_FIRST, WEB_QS_MAC, WEB_QS_RISK, WEB_QS_VENDOR,
       WEB_QS_IP, WEB_QS_SSID, WEB_QS_SIGNAL, WEB_QS_SOURCES, WEB_QS_COUNT };

/* A sort's direction (the page's sortable columns, owner request
 * 2026-10-26): WEB_SORT_DEFAULT keeps the sort's own order, ASC and
 * DESC set its first key's, an empty value last either way. Every
 * server-paged sort (/api/devices, /api/wifi/aps, /api/flows) takes it
 * as dir=asc|desc and passes it packed with the sort's index, which no
 * sort list reaches: WEB_SORT_PACK(sort, dir). The key itself is always
 * a constant column of the route's own list; nothing from the request
 * is ever part of the SQL. */
enum { WEB_SORT_DEFAULT = 0, WEB_SORT_ASC = 1, WEB_SORT_DESC = 2 };
#define WEB_SORT_PACK(s, d) ((s) | (d) << 8)
#define WEB_SORT_KEY(p)     ((p) & 0xff)
#define WEB_SORT_DIR(p)     (((p) >> 8) & 3)
/* "asc" or "desc" -> WEB_SORT_ASC or WEB_SORT_DESC, else -1. */
int web_sort_dir_find(const char *s);

typedef struct {
    int       type;            /* 0 text, 1 integer, 2 real */
    char      s[WEB_Q_BIND_TEXT];
    long long i;
    double    d;
} web_qbind_t;

typedef struct {
    char        sql[WEB_Q_SQL_MAX];
    web_qbind_t b[WEB_Q_BINDS];
    int         nb;            /* the last two are LIMIT and OFFSET */
} web_qsql_t;

/* The statement for q, ordered by sort, LIMIT limit OFFSET offset. Its
 * result columns are WEB_QCOL_* (web_slothdb.h reads them). 0, or -1
 * (the text did not fit: a bug, not an input). */
int web_query_compile(const web_query_t *q, unsigned feats, int sort,
                      long long limit, long long offset, web_qsql_t *out);
/* The same for a capture scope (web_scope.h WEB_SCOPE_*): only the
 * scope's devices, each column the scope's own (web_query.c says which
 * table each comes from). Hybrid (0) is web_query_compile() exactly. */
int web_query_compile_scoped(const web_query_t *q, unsigned feats, int scope,
                             int sort, long long limit, long long offset,
                             web_qsql_t *out);

/* "last", "first", "mac", "risk", "vendor", "ip", "ssid", "signal",
 * "sources" -> WEB_QS_*, or -1. */
int web_query_sort_find(const char *s);

/* The anomaly kind names, in web_anomaly_kind_find()'s order. */
extern const char *const web_query_anomaly_kinds[];

/* The result columns of every device row (the list and the one-device
 * lookup share them). */
enum {
    WEB_QCOL_MAC = 0, WEB_QCOL_IP, WEB_QCOL_HOSTNAME, WEB_QCOL_VENDOR,
    WEB_QCOL_SSID, WEB_QCOL_SIGNAL, WEB_QCOL_SOURCES, WEB_QCOL_RISK_SIGNALS,
    WEB_QCOL_RISK, WEB_QCOL_FIRST, WEB_QCOL_LAST, WEB_QCOL_IS_AP,
    WEB_QCOL_DHCP_NAME, WEB_QCOL_MDNS_NAME, WEB_QCOL_NBNS_NAME,
    WEB_QCOL_COUNT
};

/* The SELECT list and FROM of a device row, for the one-device and
 * lookup statements (web_slothdb.c), given the same feats; extra (a
 * constant of the caller's, or NULL) adds columns after WEB_QCOL_COUNT. */
int web_query_row_select(unsigned feats, const char *extra, char *out,
                         size_t cap);
int web_query_row_select_scoped(unsigned feats, int scope, const char *extra,
                                char *out, size_t cap);
/* A scope's membership predicate over `devices d` into out: "" for
 * Hybrid. 0, or -1 when it did not fit. */
int web_query_member(unsigned feats, int scope, char *out, size_t cap);

#endif
