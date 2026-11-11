/* Plain notes on devices, BLE advertisers, SSIDs, satellites, aircraft
 * and APRS stations (web_notes.c; owner request 2026-11-11): each
 * kind's id, the rule that a note is added only to a subject held now,
 * the append-only table with its retractions, its caps and what folds,
 * the text rules as the triage write has them, the batched marks, the
 * bundle and the glossary, the write over a socket, and subnotes.js.
 * The world is wt_world.h's.
 *
 * Every absence assertion here was seen red under the mutation its
 * comment names, in this tree, the source restored and the suite run
 * green again afterwards. */
#include "web_assets.h"
#include "web_metrics.h"
#include "wt_world.h"

static int note_add(const char *kind, const char *id, const char *text) {
    char b[1024];
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"kind\":\"%s\",\"id\":\"%s\",\"text\":\"%s\",\"by\":\"op\"}",
             kind, id, text);
    return w_post("/api/frrs/note", b);
}
#ifdef WITH_SQLITE
static int note_retract(const char *kind, const char *id, long long note, const char *why) {
    char b[1024];
    snprintf(b, sizeof(b), "{\"op\":\"retract\",\"kind\":\"%s\",\"id\":\"%s\",\"note\":%lld,"
             "\"text\":\"%s\",\"by\":\"boss\"}", kind, id, note, why);
    return w_post("/api/frrs/note", b);
}
#endif
static int notes_of(const char *kind, const char *id) {
    char q[160];
    snprintf(q, sizeof(q), "kind=%s&id=%s", kind, id);
    return w_get("/api/frrs/notes", q);
}
#ifdef WITH_SQLITE
static int marks_of(const char *kind, const char *ids) {
    char q[640];
    snprintf(q, sizeof(q), "kind=%s&ids=%s", kind, ids);
    return w_get("/api/frrs/notes/marks", q);
}
#endif

/* ── the id of each kind ───────────────────────────────────────────── */

static void canon_is(int kind, const char *in, const char *want) {
    char out[WEB_NOTE_ID_MAX + 1];
    int rc = web_note_canon(kind, in, out);
    if (want) {
        WT_EQ(rc, 0);
        WT_ASSERT(!strcmp(out, want));
    } else {
        WT_EQ(rc, -1);
        WT_EQ(out[0], 0);
    }
}

/* Each kind's id is validated whole to its own format and nothing else
 * is one; what is stored is the canonical spelling. Seen red with the
 * "255" test taken out of the BLE case (the anonymous address then an
 * id) and with gnss_parts()'s trailing-NUL test dropped ("0.5x" an id). */
static void test_ids(void) {
    WT_EQ(web_note_kind_find("device"), WEB_NOTE_DEVICE);
    WT_EQ(web_note_kind_find("aprs"), WEB_NOTE_APRS);
    WT_EQ(web_note_kind_find("alert"), -1);        /* an alert's note is its triage */
    WT_EQ(web_note_kind_find("anomaly"), -1);
    WT_EQ(web_note_kind_find(""), -1);
    WT_EQ(web_note_kind_find(NULL), -1);
    for (int k = 0; k < WEB_NOTE_KINDS; k++)
        WT_EQ(web_note_kind_find(web_note_kind_word(k)), k);
    canon_is(WEB_NOTE_DEVICE, "02:DE:00:00:00:16", W_MAC1);
    canon_is(WEB_NOTE_DEVICE, "02-de-00-00-00-16", W_MAC1);
    canon_is(WEB_NOTE_DEVICE, "02:de:00:00:00", NULL);
    canon_is(WEB_NOTE_DEVICE, "02:de:00:00:00:16/1", NULL);
    canon_is(WEB_NOTE_DEVICE, "", NULL);
    canon_is(WEB_NOTE_BLE, "02:DE:00:00:00:B1/1", W_BLE1 "/1");
    canon_is(WEB_NOTE_BLE, W_BLE1, NULL);
    canon_is(WEB_NOTE_BLE, W_BLE1 "/7", NULL);
    canon_is(WEB_NOTE_BLE, W_BLE1 "/255", NULL);    /* every anonymous advertiser */
    canon_is(WEB_NOTE_SSID, "ZXhhbXBsZS1ob21l", "ZXhhbXBsZS1ob21l");   /* example-home */
    canon_is(WEB_NOTE_SSID, "-", NULL);             /* every hidden network */
    canon_is(WEB_NOTE_SSID, "example.home", NULL);  /* not the alphabet */
    canon_is(WEB_NOTE_SSID, "caf\xc3\xa9", NULL);
    canon_is(WEB_NOTE_SSID, "ZXhhbXBsZS1ob21l=", NULL);
    canon_is(WEB_NOTE_SSID, "ZR", NULL);            /* not the one spelling of its octet */
    canon_is(WEB_NOTE_SSID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NULL);
    canon_is(WEB_NOTE_GNSS, "0.5", "0.5");
    canon_is(WEB_NOTE_GNSS, "6.73", "6.73");
    canon_is(WEB_NOTE_GNSS, "127.32767", "127.32767");
    canon_is(WEB_NOTE_GNSS, "128.1", NULL);
    canon_is(WEB_NOTE_GNSS, "0.32768", NULL);
    canon_is(WEB_NOTE_GNSS, "00.5", NULL);
    canon_is(WEB_NOTE_GNSS, "0.05", NULL);
    canon_is(WEB_NOTE_GNSS, "0.5x", NULL);
    canon_is(WEB_NOTE_GNSS, "0", NULL);
    canon_is(WEB_NOTE_GNSS, "-1.5", NULL);
    canon_is(WEB_NOTE_AIRCRAFT, "A1B2C3", W_HEX);
    canon_is(WEB_NOTE_AIRCRAFT, "~00ABCD", "~00abcd");
    canon_is(WEB_NOTE_AIRCRAFT, "a1b2c", NULL);
    canon_is(WEB_NOTE_AIRCRAFT, "a1b2c3d", NULL);
    canon_is(WEB_NOTE_AIRCRAFT, "a1b2cg", NULL);
    canon_is(WEB_NOTE_APRS, W_CALL, W_CALL);
    canon_is(WEB_NOTE_APRS, "n0test-5", NULL);
    canon_is(WEB_NOTE_APRS, "N0TEST-555", NULL);
    canon_is(WEB_NOTE_APRS, "N0 TEST", NULL);
    canon_is(WEB_NOTE_KINDS, W_MAC1, NULL);
}

/* ── a note, and taking one back ───────────────────────────────────── */

/* A note is a row; a second is listed above it; taking one back is a
 * third row, never a delete, and the note stays listed with who took it
 * back. Seen red with note_retract()'s INSERT replaced by a DELETE of
 * the note (the row count 1, not 3, and "retracted":{ absent). */
static void test_note_round_trip(void) {
    w_open(1);
    WT_EQ(notes_of("device", W_MAC1), 200);
    WT_HAS(w_body(), "{\"kind\":\"device\",\"id\":\"" W_MAC1 "\",\"held\":true");
    WT_HAS(w_body(), W.have_store ? "\"store\":\"open\",\"writes\":true,\"cap\":64,\"text_max\":240"
                                  : "\"store\":\"none\",\"writes\":false,\"cap\":64,\"text_max\":240");
    WT_HAS(w_body(), "\"notes\":[],\"more\":false,\"next\":null}");
    if (!W.have_store) {
        /* No store: nothing to write to, and it says so. */
        WT_HAS(w_body(), "\"rows\":null");
        WT_EQ(note_add("device", W_MAC1, "x"), 503);
        WT_HAS(w_body(), "{\"error\":\"no_store\"}");
        w_close();
        return;
    }
#ifdef WITH_SQLITE
    WT_EQ(note_add("device", W_MAC1, "the <b>printer</b> in the hall"), 200);
    WT_HAS(w_body(), "{\"ok\":true,\"unchanged\":false,\"note\":1,\"notes\":{\"kind\":\"device\"");
    WT_HAS(w_body(), "\"rows\":1,\"live\":1,\"folded\":0");
    WT_HAS(w_body(), "{\"note\":1,\"ts\":");
    /* Markup in a note is characters: escaped on the way out, stored as typed. */
    WT_HAS(w_body(), "\"text\":\"the \\u003cb\\u003eprinter\\u003c/b\\u003e in the hall\",\"by\":\"op\","
                     "\"peer\":\"127.0.0.1\",\"via\":\"manual\",\"retracted\":null}");
    WT_EQ(note_add("device", "02-DE-00-00-00-16", "second"), 200);     /* one subject, however spelled */
    WT_HAS(w_body(), "\"note\":2,\"notes\":");
    const char *two = strstr(w_body(), "{\"note\":2,"), *one = strstr(w_body(), "{\"note\":1,");
    WT_ASSERT(two && one && two < one);                                 /* newest first */
    WT_EQ(note_retract("device", W_MAC1, 1, "it moved"), 200);
    WT_HAS(w_body(), "\"unchanged\":false,\"note\":1,");
    WT_HAS(w_body(), "\"rows\":3,\"live\":1,\"folded\":0");
    WT_HAS(w_body(), "\"text\":\"the \\u003cb\\u003eprinter\\u003c/b\\u003e in the hall\",\"by\":\"op\","
                     "\"peer\":\"127.0.0.1\",\"via\":\"manual\",\"retracted\":{\"ts\":");
    WT_HAS(w_body(), "\"reason\":\"it moved\",\"by\":\"boss\",\"peer\":\"127.0.0.1\",\"via\":\"manual\"}}");
    WT_EQ(w_count(w_body(), "{\"note\":"), 2);        /* the retraction is not listed as a note */
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 3);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE id = 3 AND retracts = 1 AND kind = 0 AND"
                      " subject = '" W_MAC1 "' AND text = 'it moved' AND who = 'boss' AND via = 0"), 1);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE id = 1 AND retracts = 0 AND"
                      " text = 'the <b>printer</b> in the hall'"), 1);
    /* Taken back once: a second time is no row. A retraction is not a
     * note, so it cannot be taken back; nor can another subject's. */
    WT_EQ(note_retract("device", W_MAC1, 1, "again"), 200);
    WT_HAS(w_body(), "\"unchanged\":true");
    WT_EQ(note_retract("device", W_MAC1, 3, ""), 404);
    WT_HAS(w_body(), "{\"error\":\"no_such_note\",\"member\":\"note\"}");
    WT_EQ(note_retract("ble", W_BLE1 "/1", 2, ""), 404);
    WT_EQ(note_retract("device", W_MAC1, 99, ""), 404);
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"retract\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\"}"), 400);
    WT_HAS(w_body(), "\"bad_note\"");
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"retract\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\","
                 "\"note\":\"1\"}"), 400);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 3);
    /* The next page of a list: nothing below the first note. */
    WT_EQ(w_get("/api/frrs/notes", "kind=device&id=" W_MAC1 "&before=2"), 200);
    WT_EQ(w_count(w_body(), "{\"note\":"), 1);
    WT_HAS(w_body(), "{\"note\":1,");
    WT_EQ(w_get("/api/frrs/notes", "kind=device&id=" W_MAC1 "&before=0"), 400);
    WT_EQ(w_get("/api/frrs/notes", "kind=device&id=" W_MAC1 "&before=x"), 400);
    /* The health member: the table's rows and the counters. */
    WT_EQ(w_get("/api/health", ""), 200);
    WT_HAS(w_body(), ",\"notes\":{\"rows\":3,\"cap\":20000,\"added\":2,\"retracted\":1,\"folded\":0},");
#endif
    w_close();
}

#ifdef WITH_SQLITE
/* Every kind: a note on a subject slothweb holds is written, one on a
 * subject nothing holds is refused and writes nothing, and each can
 * still be read. Seen red with `if (held == 0)` made `if (0)` in
 * web_notes_post() (every 404 below a 200, eleven rows where six are). */
static void test_each_kind_needs_a_holder(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    static const struct { const char *kind, *held, *gone, *word; } K[] = {
        { "device", W_MAC1, W_MAC2, "no_such_device" },
        { "ble", W_BLE1 "/1", W_BLE1 "/0", "no_such_ble" },
        { "gnss", W_SAT, "0.6", "no_such_satellite" },
        { "aircraft", W_HEX, "0d0e0f", "no_such_aircraft" },
        { "aprs", W_CALL, "N0CALL", "no_such_station" },
    };
    for (size_t i = 0; i < sizeof(K) / sizeof(K[0]); i++) {
        char want[96];
        WT_EQ(note_add(K[i].kind, K[i].held, "held-note"), 200);
        WT_HAS(w_body(), "\"held\":true");
        WT_EQ(note_add(K[i].kind, K[i].gone, "gone-note"), 404);
        snprintf(want, sizeof(want), "{\"error\":\"%s\",\"member\":\"id\"}", K[i].word);
        WT_HAS(w_body(), want);
        WT_EQ(notes_of(K[i].kind, K[i].gone), 200);
        WT_HAS(w_body(), "\"held\":false");
        WT_HAS(w_body(), "\"notes\":[]");
    }
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 5);
    WT_ASSERT(!w_store_has("gone-note"));
    /* An SSID is checked against sloth.db's beacon and probe tables. */
    char id[48];
    snprintf(id, sizeof(id), "%s", w_ssid_id("example-home"));
    if (W.have_db) {
        WT_EQ(note_add("ssid", id, "ours"), 200);
        WT_HAS(w_body(), "{\"kind\":\"ssid\",\"id\":\"ZXhhbXBsZS1ob21l\",\"ssid\":\"example-home\","
                         "\"ssid_k\":");
        WT_HAS(w_body(), "\"ssid_np\":false,\"held\":true");
        WT_EQ(note_add("ssid", w_ssid_id("demo-cafe"), "probed for, never beaconed"), 200);
        WT_EQ(note_add("ssid", w_ssid_id("nobody-has-this"), "x"), 404);
        WT_HAS(w_body(), "{\"error\":\"no_such_ssid\",\"member\":\"id\"}");
        WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE kind = 2"), 2);
    }
    /* No sloth.db: nothing to check an SSID against, said as that. */
    W.m4.sdb = NULL;
    WT_EQ(note_add("ssid", id, "x"), 503);
    WT_HAS(w_body(), "{\"error\":\"no_sloth_db\"}");
    WT_EQ(notes_of("ssid", id), 200);
    WT_HAS(w_body(), "\"held\":null");
    W.m4.sdb = W.have_db ? &W.sdb : NULL;
    /* No panel attached: the same for its kind. */
    W.m4.adsb = NULL;
    WT_EQ(note_add("aircraft", W_HEX, "x"), 503);
    WT_HAS(w_body(), "{\"error\":\"no_holder\"}");
    W.m4.adsb = &W.adsb;
    w_close();
}

/* An SSID's identity is its octets, never its display form: the stored
 * subject is the base64url the route names it by, the display form is
 * made for the answer (with the non-printable flag) and is in no row.
 * Seen red with the stored subject replaced by the escaped form in
 * web_notes_post() (the display form then in the file). */
static void test_ssid_identity_is_its_octets(void) {
    w_open(1);
    if (!W.have_store || !W.have_db) { w_close(); return; }
    char id[48], sql[200];
    snprintf(id, sizeof(id), "%s", w_ssid_id("demo-\xff\xfe-legacy"));
    WT_EQ(note_add("ssid", id, "the old router"), 200);
    WT_HAS(w_body(), "\"ssid\":\"demo-\\\\xff\\\\xfe-legacy\"");     /* escaped, and flagged */
    WT_HAS(w_body(), "\"ssid_np\":true");
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM note WHERE kind = 2 AND subject = '%s'", id);
    WT_EQ(w_store_int(sql), 1);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE subject LIKE '%legacy%' OR subject LIKE '%xff%'"), 0);
    web_frrs_destroy(&W.f);
    web_store_close(&W.store);
    memset(&W.f, 0, sizeof(W.f));
    memset(&W.store, 0, sizeof(W.store));
    WT_ASSERT(!w_store_has("\\xff"));
    WT_ASSERT(!w_store_has("-legacy"));
    WT_ASSERT(w_store_has("the old router"));        /* the scan reads the file */
    w_close();
}

/* The text rules are the triage note's: over its bound refused with
 * both numbers and never cut, ill-formed UTF-8, a control character and
 * a bidirectional control refused, an unknown member refused; nothing
 * of a refused write is stored. Seen red with the note's bound doubled
 * in web_notes_post() (the 241-byte note a 200). */
static void test_text_rules(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    char big[400], b[1024];
    memset(big, 'n', 241);
    big[241] = '\0';
    WT_EQ(note_add("device", W_MAC1, big), 400);
    WT_HAS(w_body(), "{\"error\":\"too_long\",\"member\":\"text\",\"length\":241,\"limit\":240}");
    big[240] = '\0';
    WT_EQ(note_add("device", W_MAC1, big), 200);     /* exactly the bound */
    WT_EQ(note_add("device", W_MAC1, "bad \xff byte"), 400);
    WT_HAS(w_body(), "{\"error\":\"bad_body\"}");
    WT_EQ(note_add("device", W_MAC1, "a\\u0007bell"), 400);
    WT_HAS(w_body(), "{\"error\":\"bad_text\",\"member\":\"text\"}");
    WT_EQ(note_add("device", W_MAC1, "line\\nbreak"), 400);
    WT_EQ(note_add("device", W_MAC1, "rtl \xe2\x80\xae override"), 400);
    WT_HAS(w_body(), "{\"error\":\"bad_text\",\"member\":\"text\"}");
    WT_EQ(note_add("device", W_MAC1, ""), 400);
    WT_HAS(w_body(), "{\"error\":\"missing_text\",\"member\":\"text\"}");
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\",\"text\":\"x\","
             "\"by\":\"%s\"}", "a-name-that-is-longer-than-thirty-two-bytes");
    WT_EQ(w_post("/api/frrs/note", b), 400);
    WT_HAS(w_body(), "{\"error\":\"too_long\",\"member\":\"by\"");
    /* Nothing a request says decides how the row is marked. */
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\","
                 "\"text\":\"x\",\"via\":\"agent\"}"), 400);
    WT_HAS(w_body(), "{\"error\":\"unknown_member\",\"member\":\"via\"}");
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\","
                 "\"text\":\"x\",\"note\":1}"), 400);
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\","
                 "\"text\":{\"a\":1}}"), 400);
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"delete\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\"}"), 400);
    WT_HAS(w_body(), "\"bad_op\"");
    WT_EQ(note_add("alert", "d1", "x"), 400);        /* an alert's note is its triage */
    WT_HAS(w_body(), "{\"error\":\"bad_kind\",\"member\":\"kind\"}");
    WT_EQ(note_add("device", "not-a-mac", "x"), 400);
    WT_HAS(w_body(), "{\"error\":\"bad_id\",\"member\":\"id\"}");
    WT_EQ(w_post("/api/frrs/note", "{\"op\":\"add\",\"id\":\"" W_MAC1 "\",\"text\":\"x\"}"), 400);
    WT_HAS(w_body(), "\"missing_kind\"");
    WT_EQ(w_post("/api/frrs/note", "not json"), 400);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 1);
    /* The reads' own refusals. */
    WT_EQ(w_get("/api/frrs/notes", "kind=device"), 400);
    WT_EQ(w_get("/api/frrs/notes", "id=" W_MAC1), 400);
    WT_EQ(w_get("/api/frrs/notes", "kind=alert&id=d1"), 400);
    WT_EQ(w_get("/api/frrs/notes", "kind=device&id=zz"), 400);
    WT_EQ(w_get("/api/frrs/notes", "kind=device&id=" W_MAC1 "&limit=5"), 400);
    w_close();
}

/* The write path is the triage write's: POST only, the page's own
 * Origin, application/json, a GET never writes. Seen red with
 * "/api/frrs/note" taken out of POST_PATHS (the POST then answers the
 * read side's 405 for another reason, and a GET a 404, not Allow:
 * POST). */
static void test_write_path_guards(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    static const char B[] = "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\",\"text\":\"x\"}";
    WT_ASSERT(web_http_post_path("/api/frrs/note"));
    WT_ASSERT(!web_http_post_path("/api/frrs/notes"));
    WT_EQ(w_post_h("/api/frrs/note", B, "http://evil.example", "application/json"), 403);
    WT_HAS(w_body(), "bad_origin");
    WT_EQ(w_post_h("/api/frrs/note", B, NULL, "application/json"), 403);
    WT_EQ(w_post_h("/api/frrs/note", B, "http://127.0.0.1:8770", "text/plain"), 415);
    WT_EQ(w_get("/api/frrs/note", ""), 405);
    WT_HAS(w_out, "Allow: POST\r\n");
    web_req_t rq;
    w_rq(&rq, "/api/frrs/notes", "kind=device&id=" W_MAC1);
    rq.is_post = 1;
    WT_EQ(w_route(&rq), 405);
    WT_HAS(w_out, "Allow: GET, HEAD\r\n");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 0);
    WT_EQ(w_post("/api/frrs/note", B), 200);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 1);
    w_close();
}

/* --web-read-only: the notes are read, never written. */
static void test_read_only(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    WT_EQ(note_add("device", W_MAC1, "kept"), 200);
    W.f.writes = 0;
    WT_EQ(note_add("device", W_MAC1, "refused"), 405);
    WT_HAS(w_body(), "{\"error\":\"read_only\"}");
    WT_EQ(note_retract("device", W_MAC1, 1, ""), 405);
    WT_EQ(notes_of("device", W_MAC1), 200);
    WT_HAS(w_body(), "\"writes\":false");
    WT_HAS(w_body(), "\"text\":\"kept\"");
    WT_HAS(w_body(), "\"retracted\":null");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 1);
    w_close();
}

static void add_n(const char *kind, const char *id, int from, int n, int want) {
    for (int i = from; i < from + n; i++) {
        char t[32];
        snprintf(t, sizeof(t), "keep-%d", i);
        WT_EQ(note_add(kind, id, t), want);
    }
}

/* A subject at its cap: a new note is refused, and no note that was
 * not taken back is ever dropped to make room. Taking one back is
 * never refused: its pair folds at once (the count kept on the oldest
 * row left), and then there is room. Seen red with the EXISTS clause
 * (a row that takes it back) dropped from fold_retracted()'s
 * candidates: the fifth note then a 200 and "keep-1" gone. */
static void test_subject_cap_folds_only_retracted(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    W.f.note_per = 4;
    add_n("device", W_MAC1, 1, 4, 200);
    WT_EQ(note_add("device", W_MAC1, "one too many"), 507);
    WT_HAS(w_body(), "{\"error\":\"notes_full\"}");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 4);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE text LIKE 'keep-%'"), 4);
    WT_EQ(notes_of("device", W_MAC1), 200);
    WT_HAS(w_body(), "\"cap\":4,");
    WT_EQ(w_count(w_body(), "\"text\":\"keep-"), 4);
    /* Another subject is not at this one's cap. */
    WT_EQ(note_add("aircraft", W_HEX, "elsewhere"), 200);
    /* Taken back at the cap: the pair folds, three stand, one counted. */
    WT_EQ(note_retract("device", W_MAC1, 2, "wrong"), 200);
    WT_HAS(w_body(), "\"unchanged\":false");
    WT_HAS(w_body(), "\"rows\":3,\"live\":3,\"folded\":2");
    WT_EQ(w_count(w_body(), "\"text\":\"keep-"), 3);
    WT_LACKS(w_body(), "keep-2");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE kind = 0"), 3);
    WT_EQ(w_store_int("SELECT folded FROM note WHERE id = 1"), 2);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE text IN ('keep-1','keep-3','keep-4')"), 3);
    WT_EQ(note_add("device", W_MAC1, "keep-5"), 200);
    WT_EQ(note_add("device", W_MAC1, "again too many"), 507);
    /* Below the cap a retracted note stays listed until room is needed. */
    W.f.note_per = 8;
    WT_EQ(note_retract("device", W_MAC1, 3, "also wrong"), 200);
    WT_HAS(w_body(), "\"rows\":5,\"live\":3,\"folded\":2");
    WT_HAS(w_body(), "\"text\":\"keep-3\",\"by\":\"op\",\"peer\":\"127.0.0.1\",\"via\":\"manual\","
                     "\"retracted\":{");
    add_n("device", W_MAC1, 6, 3, 200);              /* eight rows: the cap */
    WT_EQ(note_add("device", W_MAC1, "keep-9"), 200); /* keep-3 and its retraction fold for it */
    WT_HAS(w_body(), "\"rows\":7,\"live\":7,\"folded\":4");
    WT_LACKS(w_body(), "keep-3");
    WT_EQ(w_get("/api/health", ""), 200);
    WT_HAS(w_body(), "\"retracted\":2,\"folded\":4},");
    w_close();
}

/* The table at its cap: the same, across subjects. Seen red with the
 * table's `total >= note_cap(f)` refusal taken out of note_add() (the
 * seventh note a 200, seven rows where the cap is six). */
static void test_table_cap(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    W.f.note_cap = 6;
    add_n("device", W_MAC1, 1, 3, 200);
    add_n("aircraft", W_HEX, 4, 3, 200);
    WT_EQ(note_add("aprs", W_CALL, "no room"), 507);
    WT_HAS(w_body(), "{\"error\":\"notes_full\"}");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 6);
    /* A retraction lands past the cap and folds its own pair. */
    WT_EQ(note_retract("aircraft", W_HEX, 5, ""), 200);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 5);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE text LIKE 'keep-%'"), 5);
    WT_EQ(w_store_int("SELECT folded FROM note WHERE id = 4"), 2);
    WT_EQ(note_add("aprs", W_CALL, "room now"), 200);
    WT_EQ(note_add("aprs", W_CALL, "no room again"), 507);
    w_close();
}

/* Which rows of a table have notes, in one read: an id with a standing
 * note is marked with its count, one whose only note was taken back is
 * not, one with none is not. Seen red with LIVE()'s NOT EXISTS dropped
 * from the marks statement (the retracted-only id then marked). */
static void test_marks(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    WT_EQ(note_add("device", W_MAC1, "a"), 200);
    WT_EQ(note_add("device", W_MAC1, "b"), 200);
    WT_EQ(note_add("device", "02:de:00:00:00:12", "c"), 200);
    WT_EQ(note_retract("device", "02:de:00:00:00:12", 3, ""), 200);
    WT_EQ(marks_of("device", W_MAC1 ",02:de:00:00:00:12," W_MAC2 "," W_MAC1), 200);
    WT_HAS(w_body(), "{\"kind\":\"device\",\"store\":\"open\",\"marks\":{\"" W_MAC1 "\":{\"n\":2,\"agent\":0,\"ts\":");
    WT_LACKS(w_body(), "02:de:00:00:00:12");
    WT_LACKS(w_body(), W_MAC2);
    WT_EQ(w_count(w_body(), "\"n\":"), 1);            /* a repeated id is one mark */
    WT_EQ(marks_of("ble", W_BLE1 "/1"), 200);
    WT_HAS(w_body(), "\"marks\":{}}");
    WT_EQ(marks_of("device", "nope"), 400);
    WT_EQ(marks_of("device", W_MAC1 ","), 400);
    WT_EQ(marks_of("device", W_MAC1 "%2C" W_MAC2), 400);
    WT_EQ(marks_of("alert", "d1"), 400);
    WT_EQ(w_get("/api/frrs/notes/marks", "ids=" W_MAC1), 400);
    WT_EQ(w_get("/api/frrs/notes/marks", "kind=device&ids=" W_MAC1 "&x=1"), 400);
    /* At most WEB_NOTE_MARK_IDS of them. */
    char q[640] = "";
    size_t o = 0;
    for (int i = 0; i < WEB_NOTE_MARK_IDS; i++)
        o += (size_t)snprintf(q + o, sizeof(q) - o, "%s%06x", i ? "," : "", 0xa00000 + i);
    WT_EQ(marks_of("aircraft", q), 200);
    snprintf(q + o, sizeof(q) - o, ",%06x", 0xb00000);
    WT_EQ(marks_of("aircraft", q), 400);
    WT_HAS(w_body(), "{\"error\":\"bad_ids\"}");
    w_close();
}

/* An id is read as its kind's and never guessed from its first
 * character: "a", "d" and "s" begin an anomaly's, a sloth.db alert's
 * and a stream alert's id elsewhere (web_relate.c took a MAC beginning
 * "d" for an alert id until 2026-11-11), and here the kind is a member
 * of its own. Every kind with an id that can begin with one of them. */
static void test_ids_beginning_a_d_s(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    static const char *const MACS[] = { "dc:a6:32:00:00:01", "a4:83:e7:00:00:02", "5c:cf:7f:00:00:03" };
    static const char *const HEXES[] = { "d0e0f0", "a0b0c0", "5a5a5a" };
    static const char *const CALLS[] = { "D0ABC", "S5XYZ-1", "A1AA" };
    char line[400], id[64];
    for (int i = 0; i < 3; i++) {
        w_ep(10 + i, "A3", WM_DEV_PRESENT, MACS[i], W_T - 600, W_T - 60, NULL);
        WT_EQ(note_add("device", MACS[i], "by-mac"), 200);
        w_ble_heard(MACS[i], 1, "x");
        snprintf(id, sizeof(id), "%s/1", MACS[i]);
        WT_EQ(note_add("ble", id, "by-ble"), 200);
        WT_EQ(notes_of("ble", id), 200);
        WT_HAS(w_body(), "\"text\":\"by-ble\"");
        snprintf(line, sizeof(line), "{\"type\":\"adsb_aircraft\",\"ts\":%lld,\"hex\":\"%s\","
                 "\"non_icao\":0,\"state\":\"live\"}", (long long)W_T, HEXES[i]);
        w_line(line, w_to_adsb);
        WT_EQ(note_add("aircraft", HEXES[i], "by-hex"), 200);
        snprintf(line, sizeof(line), "{\"type\":\"aprs_station\",\"ts\":%lld,\"call\":\"%s\","
                 "\"state\":\"live\",\"first_seen\":%lld,\"last_seen\":%lld,\"packets\":1}",
                 (long long)W_T, CALLS[i], (long long)W_T, (long long)W_T);
        w_line(line, w_to_aprs);
        WT_EQ(note_add("aprs", CALLS[i], "by-call"), 200);
        WT_EQ(marks_of("device", MACS[i]), 200);
        WT_HAS(w_body(), "\":{\"n\":1,");
    }
    /* SSIDs whose base64url begins d, a and s ("test", "home", "lab"). */
    static const char *const SSIDS[] = { "dGVzdA", "aG9tZQ", "bGFi" };
    for (int i = 0; i < 3; i++) {
        WT_EQ(notes_of("ssid", SSIDS[i]), 200);
        WT_HAS(w_body(), "{\"kind\":\"ssid\",\"id\":\"");
    }
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note"), 12);
    WT_EQ(w_store_int("SELECT COUNT(*) FROM note WHERE kind = 0 AND subject LIKE 'dc:%'"), 1);
    w_close();
}

/* A link says how it was written, and one made before the column was
 * there reads as the page's. */
static void test_links_carry_via(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    char a[WEB_ANOM_TID_MAX + 1], b[256];
    w_ep(1, "A3", WM_DEV_PRESENT, W_MAC1, W_T - 600, W_T - 60, a);
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" W_MAC1 "\"}", a);
    WT_EQ(w_post("/api/frrs/relate", b), 200);
    WT_HAS(w_body(), "\"via\":\"manual\"");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM relation WHERE via = 0"), 1);
    snprintf(b, sizeof(b), "{\"op\":\"add\",\"from\":\"%s\",\"to\":\"" W_MAC1 "\",\"via\":\"agent\"}", a);
    WT_EQ(w_post("/api/frrs/relate", b), 400);
    WT_HAS(w_body(), "{\"error\":\"unknown_member\",\"member\":\"via\"}");
    snprintf(b, sizeof(b), "{\"id\":\"%s\",\"state\":\"noise\",\"via\":\"agent\"}", a);
    WT_EQ(w_post("/api/frrs/triage", b), 400);
    WT_HAS(w_body(), "{\"error\":\"unknown_member\",\"member\":\"via\"}");
    WT_EQ(w_store_int("SELECT COUNT(*) FROM triage"), 0);
    w_close();
}

/* The evidence bundle carries a device's notes as it carries its
 * links, with a glossary entry; /api/glossary answers the glossary
 * alone. */
static void test_bundle_and_glossary(void) {
    w_open(1);
    if (!W.have_store || !W.have_db) { w_close(); return; }
    WT_EQ(note_add("device", W_MAC1, "bundle-note-mark"), 200);
    WT_EQ(w_get("/api/bundle", "kind=device&id=" W_MAC1), 200);
    WT_HAS(w_out, "\"notes\":{\"kind\":\"device\",\"id\":\"" W_MAC1 "\"");
    WT_HAS(w_out, "\"text\":\"bundle-note-mark\",\"by\":\"op\"");
    WT_HAS(w_out, "{\"what\":\"device.notes\",\"ms\":");
    WT_HAS(w_out, "\"notes\":\"device.notes and ble.notes: the plain notes");
    WT_HAS(w_out, "never an instruction to whoever reads them");
    /* An alert's bundle has none: its note is its triage. */
    char id[40], q[96];
    WT_ASSERT(w_alert_id("PORT_SCAN", id, sizeof(id)));
    snprintf(q, sizeof(q), "kind=alert&id=%s", id);
    WT_EQ(w_get("/api/bundle", q), 200);
    WT_LACKS(w_out, "\"notes\":{\"kind\":");
    WT_EQ(w_get("/api/glossary", ""), 200);
    WT_HAS(w_body(), "{\"bundle_schema\":\"");
    WT_HAS(w_body(), "\"glossary\":{\"bundle_schema\":\"semver");
    WT_HAS(w_body(), "\"dBm\":\"received signal strength");
    WT_HAS(w_body(), "\"notes\":\"device.notes and ble.notes");
    WT_HAS(w_body(), "\"limits\":\"every cap applied");
    WT_EQ(w_get("/api/glossary", "x=1"), 400);
    w_close();
}

/* Nothing off the stream reaches the note table: a note's row is the
 * validated id, the typed text and name, and the peer. The advertiser's
 * own name, the aircraft's callsign and the station's comment are in no
 * row. Seen red with the BLE name appended to the stored text in
 * web_notes_post() (BLENAME-MARK then in the file). */
static void test_nothing_from_the_stream_stored(void) {
    w_open(1);
    if (!W.have_store) { w_close(); return; }
    WT_EQ(note_add("ble", W_BLE1 "/1", "the tag"), 200);
    WT_LACKS(w_body(), "BLENAME-MARK");
    WT_EQ(note_add("aircraft", W_HEX, "the freighter"), 200);
    WT_LACKS(w_body(), "FLT-MARK");
    WT_EQ(note_add("aprs", W_CALL, "the digi"), 200);
    WT_LACKS(w_body(), "APRS-COMMENT-MARK");
    web_frrs_destroy(&W.f);
    web_store_close(&W.store);
    memset(&W.f, 0, sizeof(W.f));
    memset(&W.store, 0, sizeof(W.store));
    WT_ASSERT(!w_store_has("BLENAME-MARK"));
    WT_ASSERT(!w_store_has("FLT-MARK"));
    WT_ASSERT(!w_store_has("APRS-COMMENT-MARK"));
    WT_ASSERT(w_store_has("the freighter"));          /* the scan reads the file */
    w_close();
}
#endif /* WITH_SQLITE */

/* ── over a socket ─────────────────────────────────────────────────── */

/* The note's write end to end, and --web-read-only's 405 before a
 * header is checked. */
static void test_note_over_socket(void) {
    w_open(1);
    w_running_t r;
    web_config_t c;
    web_config_defaults(&c);
    WT_EQ(w_srv_start(&r, &c), 0);
    if (!r.s) { w_close(); return; }
    uint16_t port = web_server_port(r.s);
    static const char B[] = "{\"op\":\"add\",\"kind\":\"device\",\"id\":\"" W_MAC1 "\","
                            "\"text\":\"over a socket\",\"by\":\"sock\"}";
    char req[1024];
    int hl = snprintf(req, sizeof(req), "POST /api/frrs/note HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                      "Content-Length: %zu\r\n\r\n%s", port, port, sizeof(B) - 1, B);
    w_exchange(port, req, (size_t)hl);
    WT_HAS(w_out, W.have_store ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 503");
    if (W.have_store) WT_HAS(w_out, "\"text\":\"over a socket\",\"by\":\"sock\",\"peer\":\"127.0.0.1\"");
    hl = snprintf(req, sizeof(req), "GET /api/frrs/notes?kind=device&id=%s HTTP/1.1\r\n"
                  "Host: 127.0.0.1:%u\r\n\r\n", "02%3Ade%3A00%3A00%3A00%3A16", port);
    w_exchange(port, req, (size_t)hl);
    WT_HAS(w_out, "HTTP/1.1 200 OK");
    WT_EQ(w_count(w_out, "{\"note\":"), W.have_store ? 1 : 0);
    hl = snprintf(req, sizeof(req), "GET /api/frrs/notes/marks?kind=device&ids=" W_MAC1 " HTTP/1.1\r\n"
                  "Host: 127.0.0.1:%u\r\n\r\n", port);
    w_exchange(port, req, (size_t)hl);
    WT_HAS(w_out, "HTTP/1.1 200 OK");
    if (W.have_store) WT_HAS(w_out, "\"" W_MAC1 "\":{\"n\":1,");
    w_srv_stop(&r);
    web_config_defaults(&c);
    c.read_only = 1;
    WT_EQ(w_srv_start(&r, &c), 0);
    if (!r.s) { w_close(); return; }
    port = web_server_port(r.s);
    hl = snprintf(req, sizeof(req), "POST /api/frrs/note HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                  "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
                  "Content-Length: %zu\r\n\r\n%s", port, port, sizeof(B) - 1, B);
    w_exchange(port, req, (size_t)hl);
    WT_HAS(w_out, "HTTP/1.1 405");
    WT_HAS(w_out, "Allow: GET, HEAD\r\n");
    w_srv_stop(&r);
    w_close();
}

/* ── the page ──────────────────────────────────────────────────────── */

/* subnotes.js as test_notes.c holds notes.js: no sink that parses
 * markup, no attribute or link built from a value, the functions that
 * draw a note and make the write pinned whole, the hooks and the
 * containers. Seen red with `li.innerHTML = r.text;` added to draw()
 * (the sink list) and with `if (j.writes && num(r.note))` dropped
 * before the retract button (the pinned function). */
static void test_page_module(void) {
    const char *p = (const char *)web_page;
    const char *a = strstr(p, "var SlothSubNotes = (function () {");
    const char *b = a ? strstr(a, "\n})();") : NULL;
    WT_ASSERT(a != NULL && b != NULL);
    if (!a || !b) return;
    size_t n = (size_t)(b - a);
    char *m = malloc(n + 1);
    if (!m) return;
    memcpy(m, a, n);
    m[n] = '\0';
    static const char *const SINK[] = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "setAttribute(",
        "eval(", "new Function", ".href =", ".src =", "createElement(", "http://", "https://",
        "window.open", "location.assign", "fetch(", ".title =", ".className =",
    };
    for (size_t i = 0; i < sizeof(SINK) / sizeof(SINK[0]); i++) WT_LACKS(m, SINK[i]);
    /* One write path: SlothFrrs's post(), to the one route. */
    WT_EQ(w_count(m, "F.post("), 1);
    WT_HAS(m, "F.post(\"/api/frrs/note\", body)");
    /* The list of one subject's notes, whole. */
    WT_HAS(m,
        "    rows.forEach(function (r) {\n"
        "      var li = el(\"li\", \"notes-row\" + (r.retracted ? \" subnotes-gone\" : \"\"));\n"
        "      li.appendChild(el(\"span\", \"ts\", H.shortStamp(r.ts)));\n"
        "      var a = agent(r.via);\n"
        "      if (a) li.appendChild(a);\n"
        "      li.appendChild(el(\"span\", r.retracted ? \"d-dim subnotes-struck\" : \"d-bright\", r.text || \"-\"));\n"
        "      li.appendChild(el(\"span\", \"d-dim\", who(r)));\n"
        "      if (r.retracted) {\n"
        "        li.appendChild(el(\"span\", \"sev1\", \"retracted\"));\n"
        "        var ra = agent(r.retracted.via);\n"
        "        if (ra) li.appendChild(ra);\n"
        "        if (r.retracted.reason) li.appendChild(el(\"span\", \"d-normal\", r.retracted.reason));\n"
        "        li.appendChild(el(\"span\", \"d-dim\", who(r.retracted)));\n"
        "      } else if (j.writes && num(r.note)) {\n"
        "        li.appendChild(btn(\"retract\", function () { write(place, { op: \"retract\", note: r.note }); }));\n"
        "      }\n"
        "      ol.appendChild(li);\n"
        "    });\n");
    /* The write, whole: the subject is the panel's, never the form's;
     * nothing is drawn until the server answers, and then its answer. */
    WT_HAS(m,
        "  function write(place, body) {\n"
        "    var at = S.at[place], msg = $(\"subnotes-\" + place + \"-msg\");\n"
        "    if (!at || !msg) return;\n"
        "    var gen = at.gen;\n"
        "    body.kind = at.kind;\n"
        "    body.id = at.id;\n"
        "    if (by()) body.by = by();\n"
        "    // Nothing is drawn from the request: the list changes only once\n"
        "    // the server has the row, and from the server's answer.\n"
        "    msg.textContent = \"pending: not in the store until the server confirms it\";\n"
        "    F.post(\"/api/frrs/note\", body).then(function (j) {\n"
        "      if (!S.at[place] || S.at[place].gen !== gen) return;\n"
        "      msg.textContent = \"\";\n"
        "      if (body.op === \"add\") { $(\"subnotes-\" + place + \"-text\").value = \"\"; count(place); }\n"
        "      draw(place, j.notes || {});\n"
        "    }).catch(function (e) {\n"
        "      if (S.at[place] && S.at[place].gen === gen) msg.textContent = WHY[e && e.message] || F.why(e);\n"
        "    });\n"
        "  }\n");
    /* The agent mark is a fixed word, decided by the server's via. */
    WT_HAS(m, "  function agent(via) { return via === \"agent\" ? el(\"span\", \"subnotes-agent\", \"agent\") : null; }\n");
    /* A row's mark: a fixed word and the server's counts, from the
     * batched read, an id sent only when it is its kind's shape. */
    WT_HAS(m, "    cell.subMark = el(\"span\", \"subnotes-mark\", \"note \" + m.n + (m.agent > 0 ? \" agent\" : \"\"));\n");
    WT_HAS(m, "        H.getJSON(\"/api/frrs/notes/marks?kind=\" + kind + \"&ids=\" + part.join(\",\")).then(function (j) {\n");
    WT_HAS(m, "    if (!ok(kind, id)) { cell.subWant = \"\"; paint(cell, null); return; }\n");
    WT_HAS(m, "  var MARK_TTL_MS = 30000, MARK_BATCH = 24, REREAD_MS = 10000;\n");
    WT_EQ(WEB_NOTE_MARK_IDS, 24);                    /* MARK_BATCH */
    WT_HAS(m, "    if (!H || !F || !box || PLACES.indexOf(place) < 0 || !ok(kind, id)) { hide(place); return; }\n");
    free(m);
    /* After frrs.js (whose post it uses) and notes.js, before app.js. */
    const char *fr = strstr(p, "var SlothFrrs = (function () {");
    const char *ap = strstr(p, "if (window.SlothSubNotes) SlothSubNotes.init({");
    WT_ASSERT(fr && ap && fr < a && a < ap);
    static const char *const HOOK[] = {
        "      if (window.SlothSubNotes) SlothSubNotes.show(\"dev\", \"device\", mac);\n",
        "    if (window.SlothSubNotes) SlothSubNotes.show(\"ble\", \"ble\", String(addr) + \"/\" + String(type));\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.show(\"ssid\", \"ssid\", p === \"-\" ? null : p);\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.show(\"gnss\", \"gnss\", s.gnssid + \".\" + s.prn);\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.show(\"adsb\", \"aircraft\", a.hex);\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.show(\"aprs\", \"aprs\", a ? a.call : sel);\n",
        "    if (window.SlothSubNotes) SlothSubNotes.mark(r.cells[\"c-mac\"], \"device\", r.mac);\n",
        "    if (window.SlothSubNotes) SlothSubNotes.mark(row.firstChild, \"ble\", String(d.addr) + \"/\" + String(d.addr_type));\n",
        "      SlothSubNotes.mark(ss, \"ssid\", SlothSsid.param(String(a.ssid)));\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.mark(r.firstChild, \"gnss\", s.gnssid + \".\" + s.prn);\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.mark(r.firstChild, \"aircraft\", a.hex);\n",
        "    if (window.SlothSubNotes) window.SlothSubNotes.mark(r.firstChild, \"aprs\", a.call);\n",
        "  if (window.SlothSubNotes) SlothSubNotes.init({ el: el, getJSON: getJSON, prefGet: prefGet,\n"
        "    shortStamp: shortStamp });\n",
        /* The same mark on a link an agent made and on a state an agent set. */
        "      var am = window.SlothSubNotes ? window.SlothSubNotes.agent(l.via) : null;\n"
        "      if (am) li.appendChild(am);\n",
        "    if (st && st.via === \"agent\") c.appendChild(el(\"span\", \"d-dim\", \" (agent)\"));\n",
    };
    for (size_t i = 0; i < sizeof(HOOK) / sizeof(HOOK[0]); i++) WT_EQ(w_count(p, HOOK[i]), 1);
    static const char *const PLACE[] = { "dev", "ble", "ssid", "gnss", "adsb", "aprs" };
    for (size_t i = 0; i < sizeof(PLACE) / sizeof(PLACE[0]); i++) {
        static const char *const PART[] = {
            "<div class=\"subnotes\" id=\"subnotes-%s\" hidden>", "id=\"subnotes-%s-note\"",
            "<ol class=\"lst\" id=\"subnotes-%s-list\">", "id=\"subnotes-%s-text\" maxlength=\"240\"",
            "id=\"subnotes-%s-add\"", "id=\"subnotes-%s-msg\"", "id=\"subnotes-%s-n\"",
        };
        for (size_t k = 0; k < sizeof(PART) / sizeof(PART[0]); k++) {
            char want[96];
            snprintf(want, sizeof(want), PART[k], PLACE[i]);
            WT_EQ(w_count(p, want), 1);
        }
    }
    WT_EQ(WEB_FRRS_NOTE_MAX, 240);                   /* the fields' maxlength */
    /* In the drawer under the links and above the FRRS record; in each
     * detail panel under its key and value list. */
    const char *nd = strstr(p, "id=\"notes-drawer\"");
    const char *sd = strstr(p, "id=\"subnotes-dev\"");
    const char *fd = strstr(p, "id=\"frrs-drawer\"");
    WT_ASSERT(nd && sd && fd && nd < sd && sd < fd);
    const char *kv = strstr(p, "id=\"adsb-detail-kv\"");
    const char *sa = strstr(p, "id=\"subnotes-adsb\"");
    WT_ASSERT(kv && sa && kv < sa);
    WT_HAS(p, ".subnotes-struck { text-decoration: line-through; }");
}

void run_subnotes_tests(void) {
    WT_RUN(test_ids);
    WT_RUN(test_page_module);
    WT_RUN(test_note_round_trip);
#ifdef WITH_SQLITE
    WT_RUN(test_each_kind_needs_a_holder);
    WT_RUN(test_ssid_identity_is_its_octets);
    WT_RUN(test_text_rules);
    WT_RUN(test_write_path_guards);
    WT_RUN(test_read_only);
    WT_RUN(test_subject_cap_folds_only_retracted);
    WT_RUN(test_table_cap);
    WT_RUN(test_marks);
    WT_RUN(test_ids_beginning_a_d_s);
    WT_RUN(test_links_carry_via);
    WT_RUN(test_bundle_and_glossary);
    WT_RUN(test_nothing_from_the_stream_stored);
#endif
    WT_RUN(test_note_over_socket);
}
