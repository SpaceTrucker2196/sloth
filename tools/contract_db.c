/* contract-db: the SQLite half of `make contract` and `make
 * contract-check` (#185 item 4), so neither needs the sqlite3 shell
 * (CI's runner has the library and not the shell).
 *
 *   contract-db build OUT.db SCHEMA.sql   the golden empty database
 *   contract-db version FILE              meta.schema_version
 *   contract-db dump FILE                 sqlite_master, sorted
 *   contract-db libversion                sqlite3_libversion()
 *
 * FILE ending in ".sql" is loaded into an in-memory database first;
 * anything else is opened read-only, so the checks never change the
 * file they check.
 *
 * Why `build` applies schema.sql and does not run the daemon's own
 * db_open(): a database the daemon creates also gets a `sessions` row
 * stamped with the wall clock and a WAL journal, so no two would be the
 * same bytes, and the fixture is meant to be the schema and nothing
 * else. What it shares with db_open() is the statement text (the
 * daemon printed it, --print-schema) and auto_vacuum=INCREMENTAL, which
 * must be set before the first table and changes the file's header.
 * The rollback journal is left at its default: a WAL file needs its
 * -shm beside it to be read, and a fixture is copied around alone.
 * The bytes depend on the SQLite that writes them (the header carries
 * its version at offset 96), the reason MANIFEST.json records it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap);
    for (;;) {
        if (!b) { fclose(f); return NULL; }
        n += fread(b + n, 1, cap - n - 1, f);
        if (n < cap - 1) break;
        cap *= 2;
        char *nb = realloc(b, cap);
        if (!nb) { free(b); fclose(f); return NULL; }
        b = nb;
    }
    int bad = ferror(f);
    fclose(f);
    if (bad) { free(b); fprintf(stderr, "contract-db: read %s failed\n", path); return NULL; }
    b[n] = '\0';
    return b;
}

static int exec(sqlite3 *db, const char *sql, const char *what) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "contract-db: %s: %s\n", what, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}

static sqlite3 *open_any(const char *path) {
    sqlite3 *db = NULL;
    if (ends_with(path, ".sql")) {
        char *sql = slurp(path);
        if (!sql) return NULL;
        if (sqlite3_open(":memory:", &db) != SQLITE_OK || exec(db, sql, path) != 0) {
            free(sql);
            sqlite3_close(db);
            return NULL;
        }
        free(sql);
        return db;
    }
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "contract-db: %s: %s\n", path, db ? sqlite3_errmsg(db) : "?");
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static int build(const char *out, const char *schema) {
    FILE *probe = fopen(out, "rb");
    if (probe) {
        fclose(probe);
        fprintf(stderr, "contract-db: %s exists; refusing to add to it\n", out);
        return 1;
    }
    char *sql = slurp(schema);
    if (!sql) return 1;
    sqlite3 *db = NULL;
    int rc = 1;
    if (sqlite3_open_v2(out, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK &&
        exec(db, "PRAGMA auto_vacuum=INCREMENTAL", "auto_vacuum") == 0 &&
        exec(db, sql, schema) == 0)
        rc = 0;
    else if (db)
        fprintf(stderr, "contract-db: %s: %s\n", out, sqlite3_errmsg(db));
    if (sqlite3_close(db) != SQLITE_OK) rc = 1;
    free(sql);
    return rc;
}

static int version(const char *path) {
    sqlite3 *db = open_any(path);
    if (!db) return 1;
    sqlite3_stmt *st = NULL;
    int rc = 1;
    if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='schema_version'",
                           -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
        printf("%s\n", (const char *)sqlite3_column_text(st, 0));
        rc = 0;
    } else {
        fprintf(stderr, "contract-db: %s: no meta.schema_version\n", path);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

static int dump(const char *path) {
    sqlite3 *db = open_any(path);
    if (!db) return 1;
    sqlite3_stmt *st = NULL;
    int rc = 1;
    if (sqlite3_prepare_v2(db, "SELECT type, name, tbl_name, COALESCE(sql, '') "
                               "FROM sqlite_master ORDER BY type, name", -1, &st, NULL) == SQLITE_OK) {
        int r;
        while ((r = sqlite3_step(st)) == SQLITE_ROW)
            printf("%s\t%s\t%s\t%s\n", (const char *)sqlite3_column_text(st, 0),
                   (const char *)sqlite3_column_text(st, 1),
                   (const char *)sqlite3_column_text(st, 2),
                   (const char *)sqlite3_column_text(st, 3));
        rc = r == SQLITE_DONE ? 0 : 1;
    }
    if (rc) fprintf(stderr, "contract-db: %s: %s\n", path, sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "build")) return build(argv[2], argv[3]);
    if (argc == 3 && !strcmp(argv[1], "version")) return version(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "dump")) return dump(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "libversion")) {
        printf("%s\n", sqlite3_libversion());
        return 0;
    }
    fprintf(stderr, "usage: contract-db build OUT.db SCHEMA.sql | version FILE | "
                    "dump FILE | libversion\n");
    return 2;
}
