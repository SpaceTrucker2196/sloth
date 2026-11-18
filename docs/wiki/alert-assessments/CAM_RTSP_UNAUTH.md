---
type: CAM_RTSP_UNAUTH
technique: ""
rule_file: src/alerts/rules_wired.c:1718 of rule_cam_rtsp_unauth()
count_semantics: per poll tick (POLL_MS 250 ms) in which at least one `rtsp_stream_t` row for the server IP has `anon_ok > 0`; one incident per server IP (`cam-rtsp:<ip>`). `observations` rises only when the detail changes - a new anonymous path, or the eviction of one from the 32-row stream table. A repeat DESCRIBE on a known path moves neither the key nor the detail.
severity_assessment: agree - WARN; it corroborates anonymous stream access from one DESCRIBE/200 exchange and cannot see whether SETUP or PLAY was authenticated, so CRIT would overclaim. The same level as CAM_WS_DISCOVERY.
false_positive_risk: low-medium - the exchange itself is read exactly (CSeq-paired, Authorization presence checked, 401-before-200 excluded, credential URIs dropped), but "no authentication on the wire" can still be a server that authenticates later in the session or filters by source address.
noise_verdict: not seen on the reference host - no fires. When it does fire, the dedupe is per server and the detail is a function of the anonymous-path set, so it is quiet by construction; the only churn source is the 32-row STAB_OLDEST stream table (`evict_rtsp_stream`), and since `count` is an evaluation counter it will climb at 4/s for as long as the row stands (300 s after the stream row's last_seen it is still in the snapshot until evicted - see Assessment).
prevalence: common as an exposure - RTSP without authentication is the default or a one-click option on many cameras and NVRs, and the vendors concerned have actively exploited critical CVEs [8][9]; no independent count of unauthenticated RTSP endpoints was confirmed for this document (two candidate public reports could not be fetched).
tuning: [none specific to the rule; `pcap.min_severity` (default 2 = CRIT only) and `pcap.key_cooldown_secs` decide whether this WARN alert's match_ip/port produce a pcap under `--pcap-dir`; `camera.join_fresh_secs` governs how long the RTSP row stays joinable to a device record]
researched: 2026-10-27
---
## What the rule checks

Input is `s->rtsp_streams[]` (MAX_RTSP_STREAMS 32, include/sloth.h:239), filled by `src/rtsp_snoop.c` from TCP 554 and 8554 payloads [1][3]. The snoop:

- parses only RTSP/1.0 or RTSP/2.0 messages, one per TCP segment, no reassembly; interleaved `$`-framed media is skipped (`rtsp_parse()`, src/rtsp_snoop.c:275-325);
- remembers a **DESCRIBE** request against (client, client port, server, server port, CSeq) only when it has a CSeq, its header block is complete in the segment (`m.complete`), its Request-URI carries no userinfo or credential-shaped parameter (`!m.url_creds`; stems `user`, `usr`, `pass`, `pwd`, `login`, `account`, `token`, `auth`, src/rtsp_snoop.c:159-161), and it has a path (src/rtsp_snoop.c:422-435). `has_auth` records only the **presence** of `Authorization` or `Proxy-Authorization`; the value is never read (src/rtsp_snoop.c:249-254). At most RTSP_PENDING = 4 DESCRIBEs are held per connection, in a 32-connection STAB_OLDEST table (src/rtsp_snoop.c:41-42, 85-91);
- settles the request when a response with the same CSeq arrives the other way (`settle()`, src/rtsp_snoop.c:375-410): **401** sets `e->challenged` and bumps the (server, port, path) row's `challenged` with the `WWW-Authenticate` scheme token; **200** bumps `anon_ok` when `!p->has_auth && !e->challenged`, else `auth_ok`, and sets `sdp` when `Content-Type: application/sdp`; any other status retires the request and says nothing.

The rule (src/alerts/rules_wired.c:1572-1610) takes every row with `anon_ok > 0`, groups rows by `server`, counts the distinct anonymous (port, path) rows per server (`paths`) and picks the lexicographically smallest path (ties by lower port) as the example (lines 1585-1594). Key: `akey_begin(..., "cam-rtsp")` + `akey_ip(server)` (lines 1597-1599) - **one incident per server IP**. Detail: `RTSP server <ip> answered DESCRIBE with no authentication challenge on <n> path(s) (e.g. <path>) - anonymous stream access corroborated, not confirmed` (lines 1602-1606). `fire()` is given `match_ip = r->server` and `match_port = ex->port` (line 1607-1608), so this is one of the camera rules that *can* produce a per-alert pcap.

Severity is fixed WARN. The incident resolves 300 s after the rule stops asserting the key (ALERT_RESOLVE_AFTER_S, include/sloth.h:860), which happens when every `anon_ok` row for that server has been evicted from the stream table; rows are not aged by time, only displaced (STAB_OLDEST), so on a quiet LAN an incident can stand for the life of the run.

## The attack

RTSP is the control protocol cameras, NVRs and encoders use to hand a client a live stream. `DESCRIBE` returns the presentation description - in practice an SDP body naming the video and audio tracks - and is the first step before `SETUP` and `PLAY` [3][4]. RTSP borrows HTTP's authentication framework: a server that wants a credential answers **401** with a `WWW-Authenticate` challenge, and the client repeats the request with `Authorization` [3]. Responses carry no URI; the `CSeq` header, which "MUST be present in all requests and responses", is how a response is paired with its request, per direction of one TCP connection [3][4]. Default ports are 554, with 8554 registered as an alternative [3][4].

A server that answers DESCRIBE 200 to a request with no `Authorization`, having never challenged, has published its stream description to anyone who can reach the port. For a camera that means the viewer URL - `rtsp://<ip>:554/stream1` on TP-Link Tapo, for example [2] - is all an unauthenticated viewer needs, provided the server does not authenticate SETUP/PLAY instead. The adversary action is trivial (an `ffplay`/VLC open, or an internet-wide scanner); the exposure is the server's configuration [1]. It compounds the vendor-level risk: Hikvision's CVE-2021-36260 and Dahua's CVE-2021-33044 are both CVSS 9.8 and both in CISA's Known Exploited Vulnerabilities catalogue [8][9].

The `.def` entry gives this type an empty ATT&CK technique on purpose: T1078.001 (Default Accounts) needs an account and there was none; T1046 / T1595 describe an adversary enumerating, which sloth did not do and cannot attribute to whoever sent the DESCRIBE - often the operator's own VMS (include/sloth_alerts.def:286; [1]). It is on the cited-basis exemption list, not the own-state list (`test_uncitable_kinds_with_a_real_basis_are_still_cited`, tests/test_research_corpus.c:240-311, the entry at line 288).

## Evidence that proves it

What sloth records:

- the alert detail: server IP, the count of anonymous (port, path) rows, and one example path (src/alerts/rules_wired.c:1602-1606). The port is deliberately not in the text; it is in `match_port`;
- **pcap**: with `--pcap-dir`, the packets in the ring whose src or dst is the server IP are written (src/alert_pcap.c:20-22) - but only if `pcap.min_severity` is lowered to 0 or 1, since the default 2 exports CRIT only (the gate is `src/alerts/engine.c:865-874`; default in `src/tune.c:121`; docs/wiki/cli-reference.md:76). That file is what holds the DESCRIBE request, the 200 and the SDP body; it may also hold a credential if the client sent one on another path, which is one reason the default is CRIT-only;
- JSONL `alert.create` / `alert.update` / `alert.resolve` on `cam-rtsp:<ip>`; `packet` records with `info` `RTSP DESCRIBE` and `RTSP 200` between the client and server (src/rtsp_snoop.c:437, 445); the `device` record for the server with `cam_signals` bit 32 (`CAM_SIG_RTSP`), `cam_evidence` `rtsp_sdp` or `rtsp_server`, `device_class` (docs/wiki/jsonl-schema.md:699; [2]); the Devices detail panel's RTSP exposure line (docs/wiki/cli-reference.md:373);
- sensor_health: `evict_rtsp_exchange` (a connection's in-flight DESCRIBEs lost before the response - not judged) and `evict_rtsp_stream` (a path row lost with its counts) (docs/wiki/jsonl-schema.md:1121-1124).

To call it real a reader should see, in the pcap or the packet log: a `DESCRIBE rtsp://<server>/<path> RTSP/1.0` with a `CSeq: N` and **no** `Authorization` header, and on the same TCP connection a `RTSP/1.0 200 OK` with `CSeq: N` and `Content-Type: application/sdp` [3][4]; no `401` earlier on that connection; and, if the capture continued, a `SETUP` and `PLAY` on the same connection also answered 200 without a challenge - that last part is what the rule does not check and what turns "corroborated" into "confirmed" [1].

What refutes it: a 401 on the connection before the 200 (the snoop excludes this, so seeing one means the pairing went wrong, e.g. capture started mid-session or the table evicted the exchange); a `SETUP` or `PLAY` answered 401 after the open DESCRIBE (the server authenticates later - legitimate, and common); the client IP being an address the server is configured to admit (source filtering leaves no RTSP trace) [1]; the "server" being a VMS relay or media server rather than a camera [1].

## Benign causes

- **The server authenticates SETUP or PLAY, not DESCRIBE.** Permitted by the RFCs, which attach 401 to any request [3]; the snoop follows only DESCRIBE [1].
- **Source-address allow-listing on the server.** Looks identical on the wire [1].
- **An intentionally public stream** - a lobby display, a demo feed, a media server (`rtsp-simple-server`/`mediamtx`-style) the operator runs without auth on purpose. The detail says "RTSP server", not camera, for this reason [1].
- **The operator's own VMS pulling from a camera that has auth off by configuration** - the exposure is real, but the actor is the owner; the fix is on the camera (docs/wiki/alert-remediation.md:1722).
- **A credential carried in a URL parameter name the stem list does not cover.** Such a request is counted anonymous; the stem list "errs wide" but cannot be complete (src/rtsp_snoop.c:146-161) [1].
- Not a benign cause but a known blind spot: a DESCRIBE whose header block spans two segments is dropped, not counted, so an authenticated client with long Digest headers makes the server look *quieter*, never noisier (src/rtsp_snoop.c:422-435) [1].

## Assessment

**Severity.** WARN is correct. The exchange is read exactly and conservatively (presence of Authorization, 401-before-200, credential URIs excluded) and the remaining uncertainty - SETUP/PLAY auth, source filtering - is genuinely invisible to a passive observer. The repo places it with `CAM_WS_DISCOVERY` as an exposure with a cited basis and no honest technique, which is the right shape [1].

**Prevalence.** Unauthenticated RTSP is a configuration many cameras and NVRs allow and some ship with; the risk it enables is amplified by the KEV-listed critical CVEs on the dominant vendors [8][9]. Two public "exposed cameras" counts were attempted and could not be fetched, so no number is quoted here.

**Noise on the reference host.** Not seen (host null). Expected behaviour if it fires: one incident per server; `count` climbs at the poll rate (4/s at POLL_MS 250 ms) while any `anon_ok` row for the server stands, and because stream rows are evicted only by displacement from a 32-row table, on a quiet LAN the incident never resolves and `count` grows without bound while `observations` stays at 1 plus the number of path-set changes. Same recommendation as for CAM_SETUP_OUI: surface `observations`, not `count`. A possible refinement, not present today: age the `rtsp_stream_t` rows (or the rule's view of them) so a server that has not served an anonymous DESCRIBE for, say, `camera.join_fresh_secs` stops being asserted and the incident resolves.

**Sufficient to act on?** Yes, as a configuration finding: the operator can verify in one step whether the server challenges DESCRIBE, from a host they control, with their own client - and the fix (require authentication on the server) is one setting [4].

**First response.** Identify the server (the `device` record and Devices panel give vendor and class); identify the client that asked (`packet` records, the pcap) - if it is the operator's VMS the finding is still real; enable authentication on the RTSP server so DESCRIBE is answered with the RFC's 401 challenge; then watch for the incident to resolve, which with today's table semantics requires the row to be displaced (docs/wiki/alert-remediation.md:1722).

## Bibliography

1. research/rfc/2326-7826-rtsp.md - RFC 2326 / RFC 7826: RTSP DESCRIBE answered with no challenge; what `rtsp_snoop.c` reads and what the finding does not say (repo research corpus, accessed 2026-10-27)
2. research/papers/camera-router-role.md - the RTSP SDP answer as the class-deciding signal; TP-Link FAQ 2680's Tapo RTSP paths (`/stream1`, `/stream2`, port 554) (repo research corpus, accessed 2026-10-27). Background source: it names `CAM_SETUP_OUI`, not this type; the citing document is [1]
3. RFC 7826, Real-Time Streaming Protocol Version 2.0 (December 2016) - §13.2 DESCRIBE, §17.4.2 401 Unauthorized, §18.20 CSeq, §10.2 ports 554 / 8554 - https://www.rfc-editor.org/rfc/rfc7826 (text fetched 2026-10-27; §13.2, §17.4.2, §18.20 ("This field MUST be present in all requests and responses") and the §10.2 sentence "there is an alternative port 8554 registered" confirmed in the RFC text itself)
4. RFC 2326, Real Time Streaming Protocol (RTSP) (April 1998) - §3.2 "If the port is empty or not given, port 554 is assumed", §10.2 DESCRIBE, §12.17 CSeq - https://www.rfc-editor.org/rfc/rfc2326 (text fetched and confirmed 2026-10-27)
5. docs/views/alerts.md:156 - the `CAM_RTSP_UNAUTH` rule-table row (accessed 2026-10-27)
6. docs/wiki/alert-remediation.md:1722 - `CAM_RTSP_UNAUTH` investigate / fix (accessed 2026-10-27)
7. docs/wiki/cli-reference.md:54,76 - `--pcap-dir`, `pcap.min_severity`, `pcap.key_cooldown_secs` (accessed 2026-10-27)
8. NVD, CVE-2021-36260 - Hikvision web server command injection, CVSS 3.1 9.8, CISA KEV added 2022-01-10 - https://nvd.nist.gov/vuln/detail/CVE-2021-36260 (confirmed via the NVD 2.0 API, accessed 2026-10-27)
9. NVD, CVE-2021-33044 - Dahua identity authentication bypass, CVSS 3.1 9.8, CISA KEV added 2024-08-21 - https://nvd.nist.gov/vuln/detail/CVE-2021-33044 (confirmed via the NVD 2.0 API, accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD d70d394) and by fetching every external source.

- Code: rule is `src/alerts/rules_wired.c:1572-1610` (draft 1574; corrected). Most `src/rtsp_snoop.c` anchors were off by 20-50 lines and are corrected: `rtsp_parse()` `:275-325`, `has_auth` `:249-254`, credential stems `:159-161` (block `:146-161`), DESCRIBE gating `:422-435`, `settle()` `:375-410`, table sizes `:41-42`, STAB decls `:85-91`, `info` strings `:437`/`:445`. The corpus-test anchor `240-262` did not reach the RTSP entry; now `:240-311`, entry at `:288`. Added the actual pcap severity gate (`src/alerts/engine.c:865-874`, `src/tune.c:121`).
- Logic confirmed exactly as stated: DESCRIBE tracked only with CSeq, complete header block, no URL credentials, non-empty path; 401 sets connection-wide `challenged`; 200 counts `anon_ok` only with no Authorization and no earlier 401 on that connection; other statuses retire silently; one incident per server IP (`cam-rtsp` + `akey_ip`), path count and lexicographically smallest path (ties by lower port), `match_ip = server`, `match_port = ex->port`; fixed WARN. Stream rows are STAB_OLDEST with no age-out (`STAB_DECL`, not `STAB_DECL_AGE`), so the "never resolves on a quiet LAN" reading holds. Capture dispatches 554/8554 (`src/capture/capture.c:808`).
- Sources: [3] RFC 7826 and [4] RFC 2326 text fetched; section numbers (§13.2, §17.4.2, §18.20, §10.2; §3.2, §10.2, §12.17) and quotes confirmed directly, including the 8554 sentence previously taken via [1]. [8] [9] re-confirmed via the NVD 2.0 API.
- research/ paths: `research/rfc/2326-7826-rtsp.md` exists and names `ALERT_TYPE_CAM_RTSP_UNAUTH`; `research/papers/camera-router-role.md` exists but does not name this type (labelled background).
