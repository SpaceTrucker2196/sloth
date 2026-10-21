#ifndef SLOTH_PCAP_FORMAT_H
#define SLOTH_PCAP_FORMAT_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

/* ── The libpcap savefile format, in one place ────────────────────
 *
 * sloth writes pcap files from four sinks and reads them with libpcap.
 * It never writes them with libpcap: pcap_dump_open() needs a live
 * pcap_t, and three of the four sinks have no handle — they serialise
 * frames out of their own ring buffers, in builds that may not link
 * libpcap at all (`make WITH_PCAP=0`, `make embedded`). So the writer
 * is ours, and this is it.
 *
 * It is one module because it used to be four. Each of
 * src/pcap_write.c, src/alert_pcap.c, src/eapol_log.c and
 * src/evidence_export.c carried its own copy of the magic, the version
 * pair, a snaplen and a pair of integer-writing helpers. Four copies of
 * a wire format is four places for a fix to land in one of, and that
 * had already happened: #92 corrected the caplen-vs-origlen discipline
 * in eapol_log.c and the other three kept writing what they wrote.
 *
 * ── Byte order: little-endian, always ──
 *
 * libpcap reads the magic to decide a file's endianness, so native
 * order is equally valid and src/evidence_export.c used to write that
 * way while the other three wrote little-endian explicitly. One policy
 * now, and it is little-endian, for a forensic reason rather than a
 * stylistic one: sloth's output is evidence, and evidence that hashes
 * differently depending on the architecture that recorded it is harder
 * to attest to. Identical input bytes now give an identical file on
 * x86, ARM and a big-endian host, so a checksum travels with the
 * capture. The cost is a byte shuffle per field on a big-endian host,
 * which is nothing next to the write itself.
 *
 * ── What this module does NOT do ──
 *
 * No file creation, no error policy, no cleanup. The four callers differ in
 * ways that matter and must keep differing: pcap_write.c unlinks a
 * truncated export, alert_pcap.c routes failures through sfile_fail()
 * so the operator sees them on the !persist badge, eapol_log.c writes
 * to a temp name and renameat()s over the old capture, and
 * evidence_export.c writes to a raw descriptor with its own retry loop.
 * This module hands them bytes; they decide what a failure means. */

#define PCAP_FILE_HDR_LEN 24
#define PCAP_REC_HDR_LEN  16

/* Snaplens the callers declare. The field is advisory — it tells a
 * reader the largest frame the writer would have kept, and nothing
 * validates it — but it should not be a bare number at four call
 * sites. */
#define PCAP_SNAPLEN_FRAME  65535u    /* IP and 802.11 frame sinks */
#define PCAP_SNAPLEN_LARGE  262144u   /* the evidence ring (#92) */
/* The wired packet ring (s->packets[]) keeps min(caplen, 64) bytes per
 * packet (src/capture/capture.c), so a file written from it can never
 * hold more than 64 bytes of any frame. Its two writers - the per-alert
 * pcap and the `w` export - declared 65535 until #92 slice 3, claiming
 * a capture depth the file never had. Owner default (#145): keep 64 B
 * per entry and say so in the header. */
#define PCAP_SNAPLEN_WIRED_RING 64u

/* Link types, by their libpcap DLT_ numbers. Named here so a build
 * without libpcap still has them: pcap.h is where these normally come
 * from, and three of the four sinks compile without it. */
#define PCAP_DLT_EN10MB     1
#define PCAP_DLT_IEEE802_11 105   /* raw 802.11, no radiotap */
#define PCAP_DLT_RADIOTAP   127   /* radiotap followed by 802.11 */
#define PCAP_DLT_BT_MONITOR 254   /* Linux Bluetooth monitor (#144) */

/* Serialise the 24-byte file header. thiszone and sigfigs are written
 * zero: the timestamps are UTC and nothing in the format's history has
 * ever used sigfigs. */
void pcap_fmt_file_hdr(uint8_t out[PCAP_FILE_HDR_LEN],
                       uint32_t dlt, uint32_t snaplen);

/* Serialise a 16-byte record header.
 *
 * `origlen` is raised to `caplen` when a caller passes less. A record
 * claiming fewer original bytes than it carries captured bytes is
 * malformed, and because each record's length drives where the next one
 * starts, one such record corrupts every record after it — a reader
 * does not fail at the bad record, it silently misparses the rest of
 * the file. Clamping here rather than trusting four call sites is the
 * main reason this function exists. */
void pcap_fmt_rec_hdr(uint8_t out[PCAP_REC_HDR_LEN],
                      uint32_t ts_sec, uint32_t ts_usec,
                      uint32_t caplen, uint32_t origlen);

/* FILE* convenience for the three sinks that already hold a stream.
 *
 * Neither checks the fwrite return. That is deliberate and matches what
 * these call sites already did: a short write sets the stream's error
 * flag, and sfile_fclose() reports it once for the whole file rather
 * than at whichever field happened to fail. Checking per field would
 * report the same failure up to six times and tell the operator less. */
void pcap_fmt_put_file_hdr(FILE *f, uint32_t dlt, uint32_t snaplen);

/* Header plus `caplen` bytes of `data`, in one call, so a caller cannot
 * write a header and forget the payload. */
void pcap_fmt_put_rec(FILE *f, uint32_t ts_sec, uint32_t ts_usec,
                      const void *data, uint32_t caplen, uint32_t origlen);

/* The link type to declare for a capture whose observed linktype is
 * `linktype`, falling back to Ethernet when nothing was observed. Two
 * sinks had this ternary inline with the same magic 1. */
uint32_t pcap_fmt_dlt_or_default(int linktype);

#endif /* SLOTH_PCAP_FORMAT_H */
