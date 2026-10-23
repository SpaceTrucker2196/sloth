/* A sloth.db for the reader's tests, generated from sloth's own DDL
 * (src/db_schema.c, linked into slothweb_test only), never a committed
 * fixture; and a small IEEE-format OUI table built by
 * web/tools/oui_csv.c from a CSV written into the test's own directory.
 * SQLite builds only, but for sdb_oui(). */
#ifndef SLOTHWEB_SDB_GEN_H
#define SLOTHWEB_SDB_GEN_H

#include <stddef.h>

#include "oui_csv.h"

/* src/db_schema.c's DB_SCHEMA_VERSION (src/db.h), linked into
 * slothweb_test in every build: the version sloth writes today. */
int db_schema_version(void);

/* The suite's pinned clock: 2026-10-22 00:00:00 UTC. */
#define SDB_NOW 1792627200LL

/* A sloth.db at path: sloth's meta and schema, stamped `version`, in
 * WAL mode when wal (closed cleanly: no -wal or -shm left), else in
 * rollback-journal mode. For a version below 7 the columns the later
 * steps added are dropped again, so the file has that version's shape.
 * 0, or -1. */
int  sdb_make(const char *path, int version, int wal);
/* Run sql on path read-write (the test playing sloth). 0, or -1. */
int  sdb_exec(const char *path, const char *sql);
/* The devices, names, SSIDs, ARP rows and alerts of the acceptance
 * scenario (sdb_gen.c says which row is which). */
int  sdb_seed(const char *path);

/* A table from a CSV with the test's MA-L, MA-M and MA-S rows, written
 * into dir. 0, or -1. */
int  sdb_oui(oui_build_t *b, const char *dir);

/* The bytes of a file (at most cap) and a directory's sorted listing,
 * for the "left as it was" assertions. */
size_t sdb_slurp(const char *path, unsigned char *buf, size_t cap);
void   sdb_listing(const char *dir, char *out, size_t cap);

#endif
