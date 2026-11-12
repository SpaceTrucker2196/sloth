/* web_frrs.c, web_frrs_report.c and web_frrs_tacdb.c's shared insides:
 * the ledger's tables and the helpers the three files share. Not a
 * public header: nothing outside the three includes it. */
#ifndef SLOTHWEB_FRRS_INT_H
#define SLOTHWEB_FRRS_INT_H

#include "web_frrs.h"
#include "web_anomaly.h"

/* A distance estimate as the record carried it (jsonl-schema.md,
 * "Distance estimate fields"): all four or none. */
typedef struct {
    int    have;
    double m;
    char   band[12], trend[14], ptx[20];
} frrs_est_t;

/* One BSSID (or MLD address): the latest beacon, wifi_regulatory and
 * wifi_mld records that named it. */
typedef struct {
    char      mac[18];
    unsigned long long touch;
    /* beacon */
    int       has_b;
    long long ts_b;
    int       channel, primary_channel, secondary_offset, operating_width, channel_source;
    int       beacon_ms, signal_dbm, rssi_min, rssi_max, has_rssi60;
    char      ssid[33], phy[24], enc[12], pairwise[40], group[24], akm[40];
    long long akm_bits, downgrade_flags, fp_flags;
    int       mfp, has_wps, wps_state, wps_locked, ie_order_count;
    long long wps_config_methods, wps_device_pwd_id;
    char      wps_manufacturer[33], wps_model_name[33], wps_model_number[33];
    char      vendor_ies_hash[24], ie_order_hash[24];
    long long tbtt_jitter_us, tbtt_jitter_samples;
    frrs_est_t est;
    /* wifi_regulatory */
    int       has_r;
    long long ts_r;
    int       country_present, triplets_truncated, power_constraint_present;
    int       power_constraint_db, tpc_present, tpc_tx_power_dbm, tpc_link_margin_db;
    int       he6_present;
    char      country[8], env[16], he6_name[16];
    long long malformed_country;
    /* wifi_mld (keyed by mld_mac) */
    int       has_m;
    long long ts_m;
    int       link_count, links_truncated, nlinks;
    char      links[WEB_FRRS_MLD_LINKS][18];
} frrs_bss_t;

typedef struct {
    char      mac[18];
    int       confidence, fwd_gap, gap, earlier;   /* earlier: this side ran first */
    long long window_start, window_end, ts;
} frrs_seq_t;

/* One Wi-Fi station: wifi_assoc_req, probe_client, pnl_client and the
 * seqnum_correlation pairs that name it. */
typedef struct {
    char      mac[18];
    unsigned long long touch;
    int       has_ar;
    long long ts_ar;
    char      ar_bssid[18], ar_phy[24], ar_vie[24];
    int       listen_interval, requested_mfp;
    long long capability_info, akm_bits, pairwise_bits, supported_rates, downgrade_flags;
    int       has_p;
    long long ts_p, frame_count, burst_frames, burst_span_ms;
    int       flood, signal_dbm, channel;
    frrs_est_t est;
    int       has_pnl;
    long long ts_pnl, probe_count;
    int       mac_random, phy_confirmed;
    char      os_fp[24], phy[24];
    int       nseq;
    frrs_seq_t seq[WEB_FRRS_SEQ_PARTNERS];
} frrs_sta_t;

/* One BLE advertiser as one sensor heard it (ble_device's identity). */
typedef struct {
    char      addr[18];
    int       addr_type;
    char      iface[24];
    unsigned long long touch;
    long long ts, first_seen, last_seen, adv_count;
    int       adapter, sampled, channel, name_complete, tx_power, has_rssi, rssi, rssi_best;
    int       ext_adv, primary_phy, secondary_phy, adv_sid;
    long long pdu_mask, uuid16, mfr_id, mfr_subtype, svc_data_uuid16, appearance, hid, flags;
    char      last_pdu[16], name[33], watch[24];
    frrs_est_t est;
} frrs_ble_t;

/* One IP address: what the capture saw it send (counts and the last
 * TLS server names, the protocols seen in the clear). */
enum { FRRS_P_HTTP = 1, FRRS_P_QUIC = 2, FRRS_P_TLS = 4, FRRS_P_DNS = 8,
       FRRS_P_CRED = 16, FRRS_P_NTP = 32 };
typedef struct {
    char      ip[WEB_KEY_MAX + 1];
    unsigned long long touch;
    unsigned  proto;
    long long dns_n, tls_n, quic_n, http_n, cred_n, ts;
    int       nsni;
    char      sni[WEB_FRRS_SNI][WEB_FRRS_SNI_MAX + 1];
    unsigned long long sni_h[WEB_FRRS_SNI];
    char      tls_ver[12];
    char      cred_protos[48];
} frrs_ip_t;

typedef struct {
    int       ch;
    char      band[12];
    long long ctrl_total, ts;
    int       ap_count, assoc_count;
} frrs_chan_t;

struct web_frrs_led {
    unsigned long long clock;
    frrs_bss_t  bss[WEB_FRRS_LEDGER_BSSID];
    frrs_sta_t  sta[WEB_FRRS_LEDGER_STA];
    frrs_ble_t  ble[WEB_FRRS_LEDGER_BLE];
    frrs_ip_t   ip[WEB_FRRS_LEDGER_IP];
    frrs_chan_t chan[WEB_FRRS_LEDGER_CHAN];
    int         nbss, nsta, nble, nip, nchan;
    char        mon_iface[24], cap_iface[24];
    long long   ts_sh;
};

/* Ledger lookups, under f->lmu (the caller holds it). NULL when absent. */
const frrs_bss_t *frrs_led_bss(const web_frrs_t *f, const char *mac);
const frrs_sta_t *frrs_led_sta(const web_frrs_t *f, const char *mac);
/* The BLE rows of addr (any type when addr_type < 0), into out. */
int  frrs_led_ble(const web_frrs_t *f, const char *addr, int addr_type,
                  const frrs_ble_t **out, int max);
const frrs_ip_t  *frrs_led_ip(const web_frrs_t *f, const char *ip);
const frrs_chan_t *frrs_led_chan(const web_frrs_t *f, int ch);
/* The MLD whose link list holds mac (an AP's link BSSID or a client's
 * link address), or NULL. */
const frrs_bss_t *frrs_led_mld_of(const web_frrs_t *f, const char *mac);

/* Emitter kinds, as tacdb_emitter.kind stores them. */
enum { FRRS_K_STA = 0, FRRS_K_BSSID, FRRS_K_BLE, FRRS_K_COUNT };
const char *frrs_kind_word(int k);
int  frrs_kind_find(const char *w);
/* A canonical emitter address for kind k: a MAC (web_key_mac), or for
 * BLE "aa:bb:cc:dd:ee:ff/N" with N the addr_type 0..3 or 255. 0, or -1. */
int  frrs_addr_canon(int k, const char *in, char *out, size_t outsz);

/* The first MAC-shaped token in s, canonical, into out[18]; 1 or 0. */
int  frrs_mac_in(const char *s, char out[18]);

/* JSON helpers. */
void frrs_str_or_null(web_jw_t *w, const char *s);
/* The answer's error body {"error":why[,"member":m]}. */
int  frrs_error(int status, const char *why, const char *member, char *body,
                size_t cap, size_t *len, int *st);

/* The report (web_frrs_report.c): the record of one emitter into w,
 * one object. m carries sloth.db (may be unconfigured); live may be
 * NULL. */
void frrs_report_json(const web_m4_t *m, web_live_t *live, int kind, const char *addr,
                      long long now_s, web_jw_t *w);

/* TACDB (web_frrs_tacdb.c). Each a route: the body into body, *status
 * set; 0, or -1 when not even an error fit. */
int  frrs_tacdb_get(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status);
int  frrs_tacdb_view(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status);
int  frrs_suggest_get(const web_m4_t *m, const char *query, long long now_s,
                      char *body, size_t cap, size_t *len, int *status);
int  frrs_export(const web_m4_t *m, long long now_s, char **big, size_t *biglen,
                 char *body, size_t cap, size_t *len, int *status);
/* The POSTs: the decoded body r, the peer, the clock. */
int  frrs_tacdb_post(const web_m4_t *m, const char *path, const web_jrec_t *r,
                     const char *peer, long long now_s, char *body, size_t cap,
                     size_t *len, int *status);
int  frrs_import(const web_m4_t *m, const web_req_t *rq, long long now_s,
                 char *body, size_t cap, size_t *len, int *status);
/* The platform and unit an emitter is filed under, as the report's
 * "tacdb" member; null when none. */
void frrs_tacdb_of(web_frrs_t *f, int kind, const char *addr, web_jw_t *w);
/* The triage history's export lines (web_frrs.c), appended to w. */
void frrs_triage_export(web_frrs_t *f, web_jw_t *w, long long *rows);
/* An import's triage context (web_frrs.c): the table's counts read once
 * and the statements prepared once, for every line of one transaction.
 * Begun inside the transaction; ended with whether it committed (the
 * folds are counted only then). NULL: a store error. */
typedef struct frrs_tri_ctx frrs_tri_ctx_t;
frrs_tri_ctx_t *frrs_tri_begin(web_frrs_t *f, long long now_s);
void frrs_tri_end(frrs_tri_ctx_t *x, int committed);
/* One imported triage line, checked (write 0, x may be NULL) or merged
 * through x; 0 merged or would be, 1 skipped (why set), -1 a store
 * error. peer is the importer's: the file's by and peer are kept as
 * claims. */
int  frrs_triage_import(web_frrs_t *f, frrs_tri_ctx_t *x, const web_jrec_t *r, int write,
                        long long now_s, const char *peer, const char **why);

/* One finding as a request names it: the subject the row is filed
 * under, the finding's sloth.db rowid when known, the descriptor. An
 * anomaly's (anom 1) is its id as subject and as addr, type -1 (no
 * alert has it, so the descriptor clause of the triage match, which
 * wants a type of 0 or more, never joins an alert's rows to an
 * anomaly's or the reverse), port 0, and first the first_seen of the
 * episode held now (0 none): the id in addr keeps two anomalies whose
 * episodes began in the same second from reading as one descriptor to
 * the retention's "superseded" test. */
typedef struct {
    char      subject[40];
    char      alt[40];              /* the stream handle, when the id was one */
    long long finding;
    int       type, port;
    char      addr[WEB_FRRS_ADDR_MAX + 1];
    long long first;
    int       anom;
} tri_subj_t;

/* An alert id resolved to its subject (web_frrs.c), over c when the
 * caller has sloth.db open (NULL: it has none). *last, when not NULL,
 * gets the finding's newest last_seen (0 unknown). 1, 0 no such alert,
 * -1. */
int  frrs_resolve_alert(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c,
                        const char *id, long long now_s, tri_subj_t *s, long long *last);
/* The current triage of a subject: 1 with *out, 0 none, -1. */
int  frrs_tri_current(web_frrs_t *f, const tri_subj_t *s, web_tri_t *out);
void frrs_tri_json(web_jw_t *w, const web_tri_t *t, int full);
/* The module's counters, under its lock. */
void frrs_stat_inc(web_frrs_t *f, unsigned long *c);

/* ── anomalies and links (web_relate.c) ───────────────────────────── */

#define FRRS_METRIC_MAX 47
/* An anomaly a request names: what its id stands for, and the episode
 * of it the engine holds now, if any. */
typedef struct {
    char      id[WEB_ANOM_TID_MAX + 1];
    char      rule[8], metric[FRRS_METRIC_MAX + 1], key[WEB_KEY_MAX + 1];
    int       held, open;
    long long first, last;           /* the held episode's; 0 when none */
} frrs_anom_t;
/* "a" and sixteen lower-case hex digits. */
int  frrs_anom_id_ok(const char *id);
/* 1 resolved (from the engine, else from the store's anom_subject), 0
 * neither holds it, -1 a store error, -2 the engine's episode and the
 * store's row of that id disagree on what it names (a hash collision:
 * refused, never joined). */
int  frrs_anom_resolve(const web_m4_t *m, const char *id, frrs_anom_t *a);
/* Its descriptor kept in the store, once. 0, 1 refused (*why), -1. */
int  frrs_anom_register(web_frrs_t *f, const frrs_anom_t *a, long long now_s,
                        const char **why);
void frrs_anom_subj(const frrs_anom_t *a, tri_subj_t *s);
/* {"rule":..,"kind":..,"metric":..,"key":..,"held":..,"open":..,
 * "first_seen":..,"last_seen":..} */
void frrs_anom_json(web_jw_t *w, const frrs_anom_t *a);
/* GET /api/frrs/related and POST /api/frrs/relate. */
int  frrs_related_get(const web_m4_t *m, web_live_t *live, const char *query,
                      long long now_s, char *body, size_t cap, size_t *len, int *status);
int  frrs_relate_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r,
                      const char *peer, int via, long long now_s, char *body, size_t cap,
                      size_t *len, int *status);
/* Is mac a device anything here holds (an anomaly keyed by it, the
 * stream's latest pass, the ledger, sloth.db over c or NULL), and does
 * the ledger hold the BLE advertiser id ("addr/type")? For a note's
 * subject (web_notes.c). */
int  frrs_device_held(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c, const char *mac);
int  frrs_ble_held(const web_m4_t *m, const char *id);

/* ── bulk triage and the incidents (web_incident.c, #198) ────────── */

/* The incident a finding is a member of, over its own triage *t (as
 * tri_lookup() read it): the inc_* members set, and when the incident's
 * state governs (web_incident.h), the state, ts, via, note, who and
 * peer replaced by the incident's decision and prev_state by the
 * finding's own state. 1 a member, 0 none (t untouched), -1. Never an
 * anomaly's. */
int  frrs_inc_overlay(web_frrs_t *f, const tri_subj_t *s, web_tri_t *t);
/* A comma-separated list of alert and anomaly ids (as /api/frrs/states
 * takes them, a comma only), each once (a repeat is dropped), into ids:
 * 0, -1 malformed, -2 more than max distinct. */
int  frrs_ids_parse(const char *in, char ids[][32], int max, int *n);
/* sloth.db for a request that resolves many ids: 1 with *c open (the
 * caller closes it), 0 none (nothing to close). */
int  frrs_sdb_open(const web_m4_t *m, long long now_s, web_sdb_conn_t *c);

/* A member check: every member of r is in allowed (a NULL-ended list)
 * and none is a nested value; else *bad names the first that is not. */
int  frrs_members_ok(const web_jrec_t *r, const char *const *allowed, const char **bad);
/* A string member: absent (1, *out ""), present and fit (1), else 0
 * with *why "too_long" or "bad_text" (a control byte, a bidirectional
 * embedding or isolate control, or not a string). */
int  frrs_text(const web_jrec_t *r, const char *name, size_t max, char *out,
               const char **why);
/* The answer to a text member frrs_text() refused: for "too_long" the
 * member, the length sent and the limit, in bytes of UTF-8. */
int  frrs_text_refused(const web_jrec_t *r, const char *member, size_t max, const char *why,
                       char *body, size_t cap, size_t *len, int *status);

#endif
