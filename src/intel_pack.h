#ifndef SLOTH_INTEL_PACK_H
#define SLOTH_INTEL_PACK_H

/* The intelligence-pack snapshot this binary's tables were generated
 * from (#231, #184 C6): intel/LOCK's pack_version, and the snapshot
 * hash over the six pack manifests sloth consumes (tools/intel_read.h,
 * ir_snapshot_hash(); docs/wiki/pack-schema.md says how to recompute
 * it from the files). Compile-time constants: the tables are compiled
 * in and nothing reloads them, so one process reports one snapshot.
 *
 * Reported as `intel_pack` on every sensor_health record and on every
 * alert whose rule consulted one of the tables (alert_t.intel_pack). */

#define INTEL_PACK_HASH_LEN 64

const char *intel_pack_version(void);
const char *intel_pack_hash(void);

#endif /* SLOTH_INTEL_PACK_H */
