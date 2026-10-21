#!/bin/sh
# Normalise a sloth JSONL stream for the replay golden diff (#119).
#
#   sh tests/replay/normalise.sh < out.jsonl > norm.jsonl
#
# What a replay SAW is deterministic; when it ran and on which host is
# not. This removes the second kind and keeps the first:
#
#   - timestamps (wall-clock stamps, and the frame clock, which
#     gen_replay.c anchors at "now"): a non-zero value becomes "T", so
#     "was stamped" is still distinguishable from 0 ("never") and -1
#     ("not measured");
#   - incident and event IDs, which are minted per run: "ID";
#   - process and library facts from sensor_health (#121, #142): RSS,
#     malloc and sqlite heap, open descriptors, the loaded library
#     versions, and the seconds-since-last-frame counters: "X";
#   - the alert pcap path, which names a per-run directory when
#     --pcap-dir is set.
#
# Not "host": that is the HTTP Host header, which is content. Every key
# here was checked against a real replay's output before it was listed.
#
# Then the stream is sorted (C locale). Records carry no tick number, so
# "sort within a tick" has no boundary to sort within; sorting the whole
# stream keeps every record and its multiplicity and drops only the
# order. A regression that moves a record from one tick to another is
# therefore NOT visible here — one that changes, adds or removes a record
# is.
#
# The edits are field-by-name, never positional, so a new field in a
# record shows up in the diff rather than being normalised away.

set -eu

TIME_KEYS='ts|ts_sec|first_seen|last_seen|first_detected|last_evaluated|first_observed|last_observed|flood_last|capture_last_frame_ts|monitor_last_frame_ts|btmon_last_frame_ts'
ID_KEYS='incident_id|event_id'
HOST_KEYS='rss_kb|rss_hwm_kb|sqlite_mem_kb|sqlite_mem_hwm_kb|malloc_kb|fd_count|libs|capture_stale_secs|monitor_stale_secs|btmon_stale_secs|ble_own_tx_secs|pcap_path'
STR='"([^"\\]|\\.)*"'

LC_ALL=C sed -E \
    -e "s/\"($TIME_KEYS)\":[1-9][0-9]*/\"\\1\":\"T\"/g" \
    -e "s/\"($ID_KEYS)\":$STR/\"\\1\":\"ID\"/g" \
    -e "s/\"($HOST_KEYS)\":($STR|-?[0-9]+)/\"\\1\":\"X\"/g" \
  | LC_ALL=C sort
