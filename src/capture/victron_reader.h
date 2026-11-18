#ifndef CAPTURE_VICTRON_READER_H
#define CAPTURE_VICTRON_READER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* The --victron reader (2026-11-15). The I/O half of src/victron.h: the
 * same tail as src/capture/rtl433_reader.h describes, against sloth-va's
 * victron.jsonl (sloth-va opens, appends and closes the path for every
 * record, so a rename-style logrotate needs no signal and copytruncate
 * works too). Every VICTRON_POLL_MS the path is opened afresh (O_RDONLY
 * | O_NONBLOCK, a regular file only): the first look starts at the end
 * (history is not replayed), a new inode or a later-appearing file is
 * read from 0, a shrunk one from 0; at most VICTRON_POLL_BYTES a poll; a
 * line over VICTRON_MAX_LINE is one bad line. A missing file is a
 * waiting state. sloth writes nothing and opens no Bluetooth socket.
 * Started after the privilege drop. */

int  victron_reader_configure(const char *spec, char *err, size_t errsz);
int  victron_reader_configured(void);
long victron_reader_poll_once(time_t wall);
void victron_reader_run(void);
void victron_reader_stop(void);

#endif /* CAPTURE_VICTRON_READER_H */
