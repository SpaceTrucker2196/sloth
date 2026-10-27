/* The sensor's pcap directories, read-only, for the alert page's
 * packet capture (owner request 2026-10-27): `--pcap-dir DIR`, at most
 * WEB_PCAP_DIRS of them (the sensor's own --pcap-dir and, when it runs
 * --collect-handshakes, its --eapol-dir), each indexed through the
 * manifests sloth writes beside its files (src/evidence_manifest.c,
 * docs/wiki/pcap-export.md §5).
 *
 * What is served, and what never is. A file is opened only through the
 * directory's descriptor (openat, O_NOFOLLOW, regular files only, at
 * most WEB_PCAP_FILE_MAX bytes) under a name that is exactly one of
 * sloth's two alert-pcap grammars (web_pcapdir_name_ok(): the --pcap-dir
 * shape of src/alert_pcap.c alert_pcap_is_name(), or the evidence
 * shape of src/evidence_export.c evidence_export_alert_name()), and only
 * when a manifest line with sink alert_pcap or evidence_pcap names it,
 * or the alert's own record named it. The per-handshake pcaps and
 * eapol.22000 that share an --eapol-dir are crackable material: their
 * names pass neither grammar and their sinks are not indexed, so they
 * are never opened, whatever directory they sit in. A path from a
 * record or a manifest is reduced to its basename first; '/', '.' and
 * '..' never reach openat.
 *
 * The index. readdir is bounded (WEB_PCAPDIR_READDIR entries; past it
 * the answer says the index is partial), manifests are the names of
 * sloth's shape (sloth-manifest-*.jsonl), read newest session first,
 * at most WEB_PCAPDIR_MANIFESTS of WEB_PCAPDIR_MANIFEST_MAX bytes each,
 * each newline-terminated line parsed and an unterminated tail dropped
 * (the writer truncates a failed append, so a tail is a crash's), into
 * at most WEB_PCAPDIR_ENTRIES entries, newest first. The scan runs on
 * the HTTP thread (routes are single-threaded) when a request needs it
 * and the directory's mtime or the newest manifest's size moved, at
 * most once per WEB_PCAPDIR_RESCAN_MS.
 *
 * The join from an alert to its files is sloth's incident_id (the
 * manifest's "incident_id"), which the stream carries and sloth.db's
 * v8 rows keep (web_live.h says why it is never rendered: it inverts to
 * the key's hash; here it is a lookup key and nothing else), then the
 * record's own pcap_path basename, then, labelled as such, the rule and
 * a time window. The manifest's "session" is not served either.
 *
 * Verification recomputes SHA-256 (FIPS 180-4, web/tools/sha256.c) over
 * the opened file and compares it with the manifest's. "verified" says
 * the bytes are the ones sloth hashed when it wrote the line, and no
 * more than that: pcap-export.md §5 "What a hash does not establish". */
#ifndef SLOTHWEB_PCAPDIR_H
#define SLOTHWEB_PCAPDIR_H

#include <stddef.h>

#define WEB_PCAP_DIRS             2
#define WEB_PCAP_FILE_MAX         (16u << 20)
#define WEB_PCAP_NAME_MAX         159         /* EVM_FILE_MAX - 1 */
#define WEB_PCAPDIR_ENTRIES       4096
#define WEB_PCAPDIR_READDIR       8192
#define WEB_PCAPDIR_MANIFESTS     32
#define WEB_PCAPDIR_MANIFEST_MAX  (1u << 20)
#define WEB_PCAPDIR_RESCAN_MS     2000
#define WEB_PCAPDIR_HITS          8
/* The rule+time fallback: written_at within [first_seen - this,
 * last_seen + this]; sloth's pcap.key_cooldown_secs is 3600. */
#define WEB_PCAPDIR_TIME_SLACK_S  3600

typedef struct {
    char      file[WEB_PCAP_NAME_MAX + 1];
    char      sink[16];               /* "alert_pcap" | "evidence_pcap" */
    char      rule[48];               /* "" when the line had none */
    char      incident_id[17];        /* lookup key only; never rendered */
    char      sha256[65];
    char      written_at[21];         /* "YYYY-MM-DDTHH:MM:SSZ" */
    long long size;
    long long written_at_epoch;
    int       dir;                    /* which --pcap-dir */
} web_pcap_entry_t;

typedef struct {
    char      path[4096];
    long long mtime_ns;               /* at the last scan; -1 unreadable */
    char      newest[WEB_PCAP_NAME_MAX + 1];  /* the newest manifest */
    long long newest_size;
    int       err;                    /* errno of the last open, 0 */
} web_pcapdir_dir_t;

typedef struct {
    web_pcapdir_dir_t d[WEB_PCAP_DIRS];
    int               ndir;
    web_pcap_entry_t *e;              /* WEB_PCAPDIR_ENTRIES */
    int               n;
    int               partial;        /* a bound was hit */
    long long         scanned_ms;     /* -1 never */
    unsigned long     scans;
} web_pcapdir_t;

/* dirs may be NULL with n 0 (no --pcap-dir). 0, or -1 out of memory. */
int  web_pcapdir_init(web_pcapdir_t *p, const char *const *dirs, int n);
void web_pcapdir_destroy(web_pcapdir_t *p);

/* Exactly sloth's two alert-pcap grammars; nothing else, and never a
 * name with '/', or "." or "..". */
int  web_pcapdir_name_ok(const char *name);
/* The basename of a record's pcap_path, into out, when it passes the
 * gate; "" otherwise. */
void web_pcapdir_basename(const char *path, char out[WEB_PCAP_NAME_MAX + 1]);

/* The directory, opened afresh (O_DIRECTORY|O_NOFOLLOW): fd, or -1
 * with *err errno. */
int  web_pcapdir_open_dir(const web_pcapdir_t *p, int dir, int *err);
/* name under dirfd through the gate: fd, or -1 with *why one of
 * "bad_name", "not_found", "not_regular", "too_large", "unreadable".
 * *size is the file's length. */
int  web_pcapdir_open_file(int dirfd, const char *name, long long *size,
                           const char **why);

/* Rescan when due (now_ms on the monotonic clock). */
void web_pcapdir_scan(web_pcapdir_t *p, long long now_ms);

typedef struct {
    const web_pcap_entry_t *e;        /* NULL: a record-named file with no line */
    char        file[WEB_PCAP_NAME_MAX + 1];
    int         dir;
    const char *matched_by;           /* "incident", "record", "rule_time" */
} web_pcap_hit_t;

/* The alert's files, newest first, at most max (WEB_PCAPDIR_HITS): by
 * incident_id, then by the record's pcap_name, and only when neither
 * found one, by rule and written_at in [first_seen - 60, last_seen +
 * WEB_PCAPDIR_TIME_SLACK_S].
 * incident_id, pcap_name and rule may be "" or NULL. A record-named
 * file with no manifest line is a hit with e NULL when it exists in a
 * directory. Returns the count. */
int  web_pcapdir_for_alert(web_pcapdir_t *p, long long now_ms,
                           const char *incident_id, const char *pcap_name,
                           const char *rule, long long first_seen,
                           long long last_seen, web_pcap_hit_t *out, int max);

/* Is file one of the alert's hits? The route binding: a name that is
 * not is 404 even when the file exists. */
const web_pcap_hit_t *web_pcapdir_hit_named(const web_pcap_hit_t *hits, int n,
                                            const char *file);

/* SHA-256 of the file's n bytes against the entry: "verified",
 * "MISMATCH" (hash or size differs), or "no_manifest_entry" (e NULL). */
const char *web_pcapdir_verify(const unsigned char *buf, size_t n,
                               const web_pcap_entry_t *e);
/* Read fd (size bytes, as web_pcapdir_open_file() gave it) whole into
 * a new buffer; NULL when it could not be read or is not size bytes. */
unsigned char *web_pcapdir_slurp(int fd, long long size);

/* Why the captures list may be short: "no --pcap-dir", "directory
 * unreadable: <errno word>", "index partial", or NULL. */
const char *web_pcapdir_note(const web_pcapdir_t *p, char *buf, size_t cap);

/* One manifest line (newline excluded) into *e: 1 taken, 0 not an
 * indexed line (another sink, a name off the gate, malformed). */
int  web_pcapdir_parse_line(const char *line, size_t len, web_pcap_entry_t *e);

#endif
