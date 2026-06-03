#ifndef FORMATTER_H
#define FORMATTER_H

#include <stddef.h>

/* Output format selection for sloth's forensic stream. The same
 * record is built once as JSONL by every per-type emitter; at write
 * time emit_line() runs the result through formatter_transform()
 * which optionally rewrites it as CEF (ArcSight Common Event Format)
 * or RFC 5424 syslog before handing it to the file sink and the
 * data socket.
 *
 * Translating from JSONL — rather than refactoring every emitter to
 * be format-agnostic — keeps the surface area small: one transform
 * function, three formats, parsers stay in one file. */
typedef enum {
    OUT_FMT_JSONL  = 0,
    OUT_FMT_CEF    = 1,
    OUT_FMT_SYSLOG = 2,
} out_format_t;

/* Parse a user-facing format name. Returns 1 on success, 0 if name
 * was unrecognised (in which case *out is unchanged). */
int  formatter_parse_name(const char *name, out_format_t *out);

/* Current configured format. Defaults to OUT_FMT_JSONL. */
out_format_t formatter_get(void);
void         formatter_set(out_format_t fmt);

/* Transform a JSONL line (no trailing newline) into the configured
 * output format. Writes a NUL-terminated string to `out`; returns
 * length written (excluding NUL), or -1 if out_sz was too small or
 * the input couldn't be parsed.
 *
 * For OUT_FMT_JSONL this is a strncpy. For CEF/syslog we walk the
 * flat top-level keys of the JSON object and re-format. Nested
 * arrays/objects (e.g. beacon's `neighbors`) are stringified by
 * copying their raw JSON syntax — keeps the structure visible
 * without baking JSON parsing rules into the consumer's format. */
int  formatter_transform(const char *jsonl, char *out, int out_sz);

#endif /* FORMATTER_H */
