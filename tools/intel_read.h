#ifndef SLOTH_INTEL_READ_H
#define SLOTH_INTEL_READ_H

/* sloth's reader of its vendored intelligence-pack snapshot (#231,
 * Stage 2 of #184). Written in this tree against the public contract,
 * docs/wiki/pack-schema.md; build time only. tools/intel_gen.c turns
 * what this reads into the initialiser files the six table sources
 * #include, and tests/test_intel_pack.c drives its refusals.
 *
 * Every pack is verified before a byte of its data is parsed: the
 * manifest is read strictly (an unknown schema_version, field or
 * format, a duplicate member, a malformed path or hash is a refusal of
 * the whole pack), each listed file's length and SHA-256 must match,
 * the declared row count must match, and the pack directory may hold
 * nothing the manifest does not list. Then each CSV is read per RFC
 * 4180 against the exact header the table's C struct needs, and every
 * value is checked against the C type it lands in and the rule the
 * table's code depends on (the builtin OUI table is sorted for its
 * binary search, an MA-L OUI has neither the group nor the local bit,
 * a tool row's `unverified` agrees with its evidence, a string fits the
 * alert field it is copied into). A refusal names the file and record.
 *
 * Opens the paths it is given and nothing else; never the network. */

#include <stddef.h>
#include <stdint.h>

#define IR_SCHEMA_VERSION 1
#define IR_NPACKS         6
#define IR_MAX_FILES      16
#define IR_PATH_MAX       200
#define IR_FILE_MAX       (1L << 20)   /* no file of these packs is near it */
#define IR_ERR            512

/* The six packs sloth consumes, in byte order of name: the order the
 * snapshot hash is computed in. */
extern const char *const ir_pack_names[IR_NPACKS];

typedef struct {
    char      path[IR_PATH_MAX + 1];
    char      sha256[65];
    long long bytes;
    long long rows;          /* -1 when the manifest gives none */
    char      format[24];
} ir_file_t;

typedef struct {
    char      pack_name[64];
    char      pack_version[32];
    int       nfiles;
    ir_file_t files[IR_MAX_FILES];
} ir_manifest_t;

/* Parse one manifest.json. 0, or -1 with `err` set. */
int ir_manifest_parse(const char *json, size_t len, ir_manifest_t *m,
                      char *err, size_t errsz);

/* "MAJOR.MINOR.PATCH", each a decimal with no leading zero. */
int ir_semver_ok(const char *s);

/* RFC 4180 records of one CSV, header included as record 0. Cells are
 * NUL-terminated copies. */
typedef struct {
    int    nrec, ncol;
    char **cell;             /* nrec * ncol */
} ir_csv_t;

/* Parse `buf` and require its header to be exactly `cols` (ncols of
 * them). Every record must have ncols fields; an empty line, a bare CR,
 * an unterminated quote or a quote inside an unquoted field is refused.
 * The final newline is optional. */
int  ir_csv_parse(const char *buf, size_t len, const char *const *cols,
                  int ncols, ir_csv_t *c, char *err, size_t errsz);
/* Data records of a CSV without the header check: what `rows` counts. */
long ir_csv_count(const char *buf, size_t len);
void ir_csv_free(ir_csv_t *c);
#define IR_CELL(c, r, k) ((c)->cell[(size_t)(r) * (size_t)(c)->ncol + (size_t)(k)])

/* Typed rows, one struct per destination array. Strings are owned. */
typedef struct { uint32_t oui; char *vendor; } ir_oui_t;
typedef struct { uint8_t oui[3]; int family; char *note; } ir_attacker_t;
#define IR_FAM_HAK5      0
#define IR_FAM_ESPRESSIF 1
typedef struct { uint8_t oui[3]; char *vendor, *org; int mixed; } ir_cam_oui_t;
typedef struct { char *name, *label; int camera_specific; } ir_cam_svc_t;
typedef struct { char *prefix, *label, *brand; } ir_cam_ssid_t;
typedef struct { char *domain, *vendor, *family; } ir_endpoint_t;
typedef struct {
    int       tool;                  /* index into ir_tool_names */
    uint32_t  vendor_ie_hash;
    uint16_t  beacon_interval_ms;
    uint32_t  supported_rates;
    unsigned  require_flags, forbid_flags;   /* bit = index in ir_flag_names */
    uint8_t   requires_karma_echo, requires_pmkid, unverified;
    char     *human_label, *evidence, *id, *version;
} ir_tool_t;
typedef struct {
    char    *category;
    int      match;                  /* 1 mfr, 2 svc_data, 3 uuid16 */
    uint16_t id;
    int16_t  subtype, min_len, max_len;
    char    *source;
} ir_ble_t;

/* The identifiers a tool row may name, each paired with its value in
 * the sloth header that defines it, so a name sloth renames or drops
 * stops this file compiling rather than reaching a table. */
typedef struct { const char *name; long value; } ir_name_t;
extern const ir_name_t ir_tool_names[];
extern const int       ir_tool_names_n;
extern const ir_name_t ir_flag_names[];
extern const int       ir_flag_names_n;
extern const char *const ir_ble_match_names[4];   /* [1..3] */

typedef struct {
    ir_manifest_t  man[IR_NPACKS];
    char           man_sha[IR_NPACKS][65];
    char           hash[65];       /* the snapshot hash, below */
    ir_oui_t      *oui;    int n_oui;
    ir_attacker_t *att;    int n_att;
    ir_cam_oui_t  *cam;    int n_cam;
    char         **brand;  int n_brand;
    ir_cam_svc_t  *svc;    int n_svc;
    ir_cam_ssid_t *ssid;   int n_ssid;
    ir_endpoint_t *ep;     int n_ep;
    ir_tool_t     *tool;   int n_tool;
    ir_ble_t      *ble;    int n_ble;
} ir_snapshot_t;

/* Verify one pack directory (`dir`, whose last component must be the
 * manifest's pack_name) and fill its manifest and the manifest's own
 * SHA-256. */
int  ir_pack_verify(const char *dir, const char *name, ir_manifest_t *m,
                    char man_sha[65], char *err, size_t errsz);

/* Verify all six packs under `intel_dir` and parse their tables. On -1
 * nothing in `s` needs freeing. */
int  ir_snapshot_load(const char *intel_dir, ir_snapshot_t *s,
                      char *err, size_t errsz);
void ir_snapshot_free(ir_snapshot_t *s);

/* The snapshot hash `intel_pack` reports: SHA-256 over the text made of
 * one line per pack, in ir_pack_names order, "<pack_name> <manifest
 * sha256>\n". A manifest covers its files' hashes, so this covers every
 * byte of the six packs and nothing else (a pack sloth does not consume
 * cannot move it). */
void ir_snapshot_hash(const char man_sha[IR_NPACKS][65], char out[65]);

/* intel/LOCK: "key: value" lines, '#' comments. */
typedef struct {
    char pack_version[32];
    char hash[65];
    char comint_commit[41];
    char date[11];
} ir_lock_t;
int ir_lock_parse(const char *buf, size_t len, ir_lock_t *l,
                  char *err, size_t errsz);

/* Read a whole file of at most `max` bytes (NUL-terminated). */
char *ir_slurp(const char *path, long max, size_t *len,
               char *err, size_t errsz);

#endif /* SLOTH_INTEL_READ_H */
