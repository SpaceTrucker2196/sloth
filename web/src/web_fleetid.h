/* Identity across the owner's fleet (#192 I2, I3, I4, I8;
 * docs/wiki/fleet.md "Identity across the sites"): what one site's
 * devices, networks and verdicts say about another site's. slothweb
 * fleet findings, not sloth alerts; slothweb never writes sloth.db and
 * never writes a peer's verdict into this site's triage.
 *
 * The export (ident=1; an I7 export refuses it and the puller falls back
 * for WEB_FLEET_NOIDENT_S, as for adsb=1):
 *
 *   {"type":"own_net",...}   one line per network this site's operator
 *                            names as its own (slothweb's --my-ssid and
 *                            --my-bssid, the words sloth uses): ssid or
 *                            bssid, the other null. The whole export only,
 *                            whatever `since` says; the end line counts
 *                            them ("own_net"), and an answer that does
 *                            replaces what the peer named before. They
 *                            travel under the monitor-only rule (owner,
 *                            2026-11-12: configuration about what the
 *                            radio hears, which is "game"). A peer that
 *                            names none: the checks that take it as the
 *                            owner (I2, I3's own BSSID and own SSID)
 *                            answer not applicable,
 *                            "no_own_networks_shared", one finding per
 *                            peer and check.
 *   ap lines gain            ie_fp and vie_fp (the beacon's IE-order
 *                            and vendor-IE hashes, decimal, from the
 *                            stream's FRRS ledger; null when the ledger
 *                            holds no beacon of it or sloth decoded none),
 *                            wps_manuf, wps_model, wps_num (its WPS
 *                            strings, printable, at most 32 bytes), and
 *                            attacks, attack_first, attack_last: the
 *                            AP-impersonation alerts sloth.db holds
 *                            naming that BSSID as a transmitter in the
 *                            last WEB_FID_WINDOW_S, a comma list:
 *                            KARMA_AP; EVIL_TWIN when the stream's
 *                            twin_episode attributed it the impostor
 *                            half of a twin: or twin-fp: pair,
 *                            TWIN_UNATTRIBUTED when no pair naming it
 *                            was attributed (the real half of an
 *                            attributed pair carries neither); and the
 *                            kept kinds' earliest first seen and latest
 *                            last seen.
 *
 * The store: peer_sightings kind "own_net" (key "ssid:<ssid>" or
 * "bssid:<mac>", label the SSID), the ap rows' extra with the new
 * members added only when sent (the existing members unchanged); and
 * meta "fleet.ident.<peer>": "<generated> <own_net count>" of the
 * peer's newest ident answer. No schema step.
 *
 * The findings (web_fid_run()), every site against every other, times
 * in this site's clock (a peer's less its skew):
 *
 *   I2 probe_other_site      a client at site A whose probe list names an
 *                            SSID that site B names as its own (and A
 *                            does not): someone who has been at B. A
 *                            client a site has triaged known is
 *                            exonerated; a locally administered MAC (a
 *                            randomised probe address) is left out and
 *                            counted. A lead (an SSID is only as unique
 *                            as its name); not applicable ("co_located")
 *                            at sites within each other's reach, where
 *                            the client may live at both.
 *   I3 own_bssid_elsewhere   B hears a BSSID A names as its own (or one
 *                            A hears carrying A's own SSID) where A's AP
 *                            cannot reach: the distance between the sites
 *                            exceeds the AP's distance from A's sensor
 *                            (upper bound) plus B's reach.
 *   I3 own_ssid_foreign_bssid B hears A's own SSID from a BSSID that is
 *                            not A's (A names at least one BSSID) and
 *                            that A's network cannot reach: a lure of A's
 *                            network (KARMA / evil twin).
 *   I3 bssid_two_places      one BSSID heard at two sites within
 *                            WEB_FID_SIMUL_S of each other, the sites
 *                            further apart than both reaches together:
 *                            a cloned MAC. Listed only when applicable.
 *   I4 tool_travel           one beacon fingerprint (IE-order hash and
 *                            vendor-IE hash equal) on an AP sloth names
 *                            the attacker (EVIL_TWIN attributed, or
 *                            KARMA_AP) at two or more sites, in order of
 *                            each site's first attack. A lead, never a
 *                            detection. A fingerprint with no such alert
 *                            at a site counts for nothing there (common
 *                            router fingerprints co-occur everywhere),
 *                            nor does TWIN_UNATTRIBUTED (either half);
 *                            an own BSSID or one any site triaged known,
 *                            false or noise is left out.
 *   I8 verdict_conflict      one address triaged known at one site and
 *                            incident at another. Every peer verdict is
 *                            shown beside this site's for the same
 *                            address, labelled with its site; none is
 *                            ever applied here.
 *
 * Reach: an AP at sloth's assumed 20 dBm heard down to the site's floor
 * (the weakest AP signal it holds, -100 dBm when none) less a 20 dB
 * margin (twice the 2.4 GHz shadow-fading and assumed-power sigmas,
 * 8 and 6 dB, root-sum-squared), by src/rf_model.h's P.1238 model at
 * 2.4 GHz. A check that
 * needs distance says "co_located" (not applicable) when the sites are
 * within it, and "no_position" when a site has none. */
#ifndef SLOTHWEB_FLEETID_H
#define SLOTHWEB_FLEETID_H

#include "web_fleet.h"
#include "web_json.h"
#include "web_slothdb.h"

#define WEB_FID_SITES       (WEB_FLEET_PEERS + 1)
#define WEB_FID_WINDOW_S    (30LL * 86400)
#define WEB_FID_SIMUL_S     600
#define WEB_FID_MARGIN_DB   20.0
#define WEB_FID_FLOOR_DEF   (-100)
#define WEB_FID_FLOOR_MIN   (-100)
#define WEB_FID_FLOOR_MAX   (-40)
#define WEB_FID_AP_MAX      5000
#define WEB_FID_PROBE_MAX   2000       /* a site's probes of one SSID */
#define WEB_FID_VER_MAX     5000
#define WEB_FID_ATK_MAX     4096
#define WEB_FID_FIND_MAX    2000
#define WEB_FID_LIMIT_DEF   100
#define WEB_FID_LIMIT_MAX   500
#define WEB_FID_HASH_MAX    20
#define WEB_FID_WPS_MAX     32
#define WEB_FID_ATK_STR     96
#define WEB_FID_KEY         48

enum { WEB_FID_I2 = 0, WEB_FID_I3, WEB_FID_I4, WEB_FID_I8, WEB_FID_NCLASS };
enum { WEB_FID_PROBE_OTHER = 0, WEB_FID_OWN_BSSID, WEB_FID_FOREIGN_BSSID,
       WEB_FID_TWO_PLACES, WEB_FID_TOOL, WEB_FID_CONFLICT, WEB_FID_NSUB };

const char *web_fid_class_word(int c);
const char *web_fid_sub_word(int s);
/* "I2", "I3", "I4", "I8" -> the class; -1 otherwise. */
int  web_fid_class_find(const char *s, size_t n);

/* The AP-impersonation alerts naming one BSSID (web_fid_atk_read()).
 * An EVIL_TWIN key names both halves of its pair in canonical byte
 * order, so it does not say which is the impostor; the stream's
 * twin_episode does when sloth attributed it (web_chain.h). Bit 0
 * EVIL_TWIN: the impostor half of an attributed pair; bit 2
 * TWIN_UNATTRIBUTED: a half of a pair whose impostor sloth did not
 * attribute (either half may be the real AP); the real half of an
 * attributed pair carries neither. Bit 1 KARMA_AP: its key names the
 * one AP that answered. */
#define WEB_FID_ATK_TWIN      1u
#define WEB_FID_ATK_KARMA     2u
#define WEB_FID_ATK_UNATTR    4u
/* The bits that name the BSSID as the attacker (I4 counts only these). */
#define WEB_FID_ATK_ATTACKER  (WEB_FID_ATK_TWIN | WEB_FID_ATK_KARMA)
typedef struct {
    char      bssid[WEB_FLEET_MAC_SZ];
    unsigned  types;                     /* WEB_FID_ATK_* */
    long long first, last;               /* over the types kept */
    long long tf[2], tl[2];              /* per raw type (0 twin, 1 karma); 0 none */
} web_fid_atk_t;
struct web_chain;
/* Every beacon_aps BSSID an EVIL_TWIN or KARMA_AP key in [from, now]
 * names as a transmitter (web_sdb_ap_attacks()), each EVIL_TWIN one
 * attributed through chain (NULL: none is), sorted by BSSID, into a
 * heap array of at most WEB_FID_ATK_MAX. The count, -1 on an error. */
int  web_fid_atk_read(web_sdb_conn_t *c, long long from, struct web_chain *chain,
                      web_fid_atk_t **out);
const web_fid_atk_t *web_fid_atk_find(const web_fid_atk_t *a, int n, const char *bssid);
/* The type list of a mask, "EVIL_TWIN,KARMA_AP", into out. */
void web_fid_atk_words(unsigned types, char *out, size_t cap);
/* The mask of a list a peer sent: -1 when a word is not one of the
 * three, repeats, or EVIL_TWIN comes with TWIN_UNATTRIBUTED. */
int  web_fid_atk_parse(const char *s, unsigned *types);

/* One AP as a site holds it. */
typedef struct {
    char      bssid[WEB_FLEET_MAC_SZ];
    char      ssid[WEB_FLEET_SSID_MAX + 1];
    int       has_rssi, rssi;
    long long first, last;
    char      ie[WEB_FID_HASH_MAX + 1], vie[WEB_FID_HASH_MAX + 1];
    char      wps[3][WEB_FID_WPS_MAX + 1];
    unsigned  atk;
    long long atk_first, atk_last;
} web_fid_ap_t;

/* One client's probe for one SSID. */
typedef struct {
    char      mac[WEB_FLEET_MAC_SZ];
    char      ssid[WEB_FLEET_SSID_MAX + 1];
    long long first, last;
} web_fid_probe_t;

/* A site's current verdict on one address (the newest triaged subject
 * naming it). */
typedef struct {
    char      addr[48];
    char      type[48];
    int       state;                     /* WEB_TRI_* */
    long long ts;
} web_fid_ver_t;

/* One site, as the findings need it; arrays the caller owns, each
 * sorted (APs by BSSID, verdicts by address). */
typedef struct {
    char      name[WEB_FLEET_NAME_MAX + 1];
    char      label[WEB_FLEET_STR_MAX + 1];
    int       self;
    int       has_pos;
    double    lat, lon;
    int       offered;                   /* its own networks were offered (ident) */
    long long own_ts;                    /* when, in this site's clock */
    int       own_expired;               /* offered last more than
                                            WEB_FLEET_OWN_STALE_S ago: its own
                                            networks no longer counted (#196) */
    /* A peer that names no networks of its own (none sent, or expired):
     * the checks that take it as the owner (I2, I3's own BSSID and own
     * SSID) answer not applicable, "no_own_networks_shared", rather than
     * nothing. Never this site. */
    int       own_unshared;
    char      host[WEB_FLEET_HOST_MAX + 1];  /* its host name, "" unknown */
    web_fleet_mine_t mine;
    int       nap;
    web_fid_ap_t *ap;
    int       nprobe;
    web_fid_probe_t *probe;
    int       nver;
    web_fid_ver_t *ver;
    long long randomised;                /* probes left out: a random MAC */
} web_fid_site_t;

/* A site's floor (the weakest AP signal it holds, clamped to
 * WEB_FID_FLOOR_MIN..MAX; WEB_FID_FLOOR_DEF when none), its reach, and
 * the upper bound on an AP's distance from a sensor that heard it at
 * rssi. Finite, positive. */
int    web_fid_floor(const web_fid_site_t *s);
double web_fid_reach_m(int floor_dbm);
double web_fid_upper_m(int rssi_dbm);

/* One site's part in a finding. */
typedef struct {
    int       site;
    char      key[WEB_FID_KEY];          /* the address there */
    char      role[24];                  /* "prober", "owner", "observer", "tool" */
    int       has_t;
    long long first, last;
    int       has_rssi, rssi;
    int       state;                     /* that site's verdict on key, -1 none */
    unsigned  atk;
} web_fid_leg_t;

typedef struct {
    int       cls, sub;
    char      key[WEB_FID_KEY];          /* client MAC, BSSID, fingerprint, address */
    char      ssid[WEB_FLEET_SSID_MAX + 1];
    char      vtype[48];                 /* I8: the alert type of the newest verdict */
    int       applicable;
    int       lead;                      /* I2, I4: an inference to confirm, never a detection */
    const char *reason;                  /* why not applicable, or NULL */
    const char *note;
    int       exonerated;
    int       has_dist;
    double    dist_m, bound_m;
    long long first, last;
    int       nleg;
    web_fid_leg_t leg[WEB_FID_SITES];
} web_fid_t;

/* Every finding over sites[0..n), the first max found into out, then
 * sorted: applicable and not exonerated first, then not applicable,
 * then exonerated, each the newest first. The count found, which is
 * more than max when some were dropped. */
int  web_fid_run(const web_fid_site_t *sites, int n, web_fid_t *out, int max);

/* GET /api/fleet/findings?kind=I2|I3|I4|I8&limit=N (100, 1..500). A
 * heap body; 0 with *status, -1 out of memory. */
int  web_fleet_findings_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                              long long now_s, char **body, size_t *len, int *status);
/* /api/fleet/overview's "findings": the counts by class. */
void web_fid_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                           web_jw_t *w);

#endif
