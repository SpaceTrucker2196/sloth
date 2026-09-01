/* research_ingest — build research.db from research/**.md (#73 slice 1).
 *
 * Walks the corpus, parses each document with the pure parser beside
 * this file, and writes one FTS5 row per section. Deliberately thin:
 * everything worth testing lives in research_ingest.c, which is in the
 * test build; this is filesystem and SQLite plumbing.
 *
 * Determinism matters because research.db is committed. Documents are
 * visited in sorted path order and rows inserted in that order, which
 * makes repeated builds byte-identical — verified, not assumed. */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "research_ingest.h"

#define MAX_DOCS  512
#define MAX_PATH  512

static char  g_paths[MAX_DOCS][MAX_PATH];
static int   g_path_n;

static int path_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void walk(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[MAX_PATH];
        if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= (int)sizeof(p))
            continue;
        /* fixtures/ holds deliberately malformed documents for the
         * parser tests; indexing them would put known-bad rows in the
         * shipped corpus. */
        if (strstr(p, "/fixtures")) continue;
        if (strstr(p, "/ingest"))   continue;

        DIR *sub = opendir(p);
        if (sub) { closedir(sub); walk(p); continue; }

        size_t n = strlen(e->d_name);
        if (n < 4 || strcmp(e->d_name + n - 3, ".md") != 0) continue;
        if (g_path_n < MAX_DOCS)
            snprintf(g_paths[g_path_n++], MAX_PATH, "%s", p);
    }
    closedir(d);
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0 || len > 1 << 20) { fclose(f); return NULL; }
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)len, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Join a bounded list into "a b c" for the FTS5 column. Space-separated
 * so the tokenizer indexes each entry as its own term. */
static void join(char *out, size_t cap, char items[][RI_STR], int n) {
    out[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        int w = snprintf(out + off, cap - off, "%s%s", off ? " " : "",
                         items[i]);
        if (w < 0 || (size_t)w >= cap - off) break;
        off += (size_t)w;
    }
}

int main(int argc, char **argv) {
    const char *root = (argc > 1) ? argv[1] : "research";
    const char *out  = (argc > 2) ? argv[2] : "research.db";

    walk(root);
    /* Sorted, so a rebuild produces the same file byte for byte. */
    qsort(g_paths, (size_t)g_path_n, MAX_PATH, path_cmp);

    remove(out);
    sqlite3 *db = NULL;
    if (sqlite3_open(out, &db) != SQLITE_OK) {
        fprintf(stderr, "research_ingest: cannot open %s: %s\n",
                out, db ? sqlite3_errmsg(db) : "?");
        return 1;
    }
    const char *schema =
        "PRAGMA page_size=4096;"
        "CREATE VIRTUAL TABLE research USING fts5("
        "  title, body, source_url UNINDEXED, retrieved UNINDEXED,"
        "  topics, alert_kinds, path UNINDEXED,"
        "  tokenize = 'porter unicode61');";
    char *err = NULL;
    if (sqlite3_exec(db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "research_ingest: schema: %s\n", err ? err : "?");
        sqlite3_close(db);
        return 1;
    }

    sqlite3_stmt *ins = NULL;
    sqlite3_prepare_v2(db,
        "INSERT INTO research (title,body,source_url,retrieved,topics,"
        "alert_kinds,path) VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &ins, NULL);

    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    int rows = 0, bad = 0;
    for (int i = 0; i < g_path_n; i++) {
        char *text = slurp(g_paths[i]);
        if (!text) continue;
        ri_doc_t doc;
        ri_status_t st = ri_parse(text, &doc);
        if (st != RI_OK) {
            /* Loud and fatal. A corpus that silently skips the document
             * you just added is worse than one that refuses to build:
             * the guard downstream would report the alert kind as
             * uncited and nobody would know why. */
            fprintf(stderr, "research_ingest: %s: %s\n",
                    g_paths[i], ri_status_str(st));
            bad++;
            free(text);
            continue;
        }
        char topics[RI_MAX_TOPICS * RI_STR];
        char kinds[RI_MAX_ALERT_KINDS * RI_STR];
        join(topics, sizeof(topics), doc.fm.topics, doc.fm.topic_count);
        join(kinds,  sizeof(kinds),  doc.fm.alert_kinds,
             doc.fm.alert_kind_count);

        for (int s = 0; s < doc.section_count; s++) {
            sqlite3_bind_text(ins, 1, doc.sections[s].title, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 2, doc.sections[s].body,  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 3, doc.fm.source_url, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 4, doc.fm.retrieved,  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 5, topics, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 6, kinds,  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 7, g_paths[i], -1, SQLITE_TRANSIENT);
            sqlite3_step(ins);
            sqlite3_reset(ins);
            rows++;
        }
        free(text);
    }
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    sqlite3_finalize(ins);
    sqlite3_close(db);

    fprintf(stderr, "research_ingest: %d document(s), %d row(s) -> %s\n",
            g_path_n - bad, rows, out);
    if (bad) {
        fprintf(stderr, "research_ingest: %d document(s) failed to parse\n",
                bad);
        return 1;
    }
    return 0;
}
