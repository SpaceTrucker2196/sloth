#!/usr/bin/env python3
"""
docs-drift judge — does each per-view doc still match its source?

Usage:
    # Audit every configured (src, doc) pair, print verdicts to stdout,
    # open one GitHub issue per "stale" pair (scheduled mode).
    python docs_drift.py --mode schedule

    # Audit only pairs touched by the PR's changed files, comment on the
    # PR with the findings (per-PR mode).
    python docs_drift.py --mode pr --changed-files /tmp/changed.txt

    # Local dry-run against a single pair, no API calls (uses --no-llm)
    # or with a real API call (omit --no-llm). Prints JSON to stdout.
    python docs_drift.py --pair src/views/arp.c docs/views/arp.md --dry-run

Required environment (skipped gracefully when missing in CI):
    OPENAI_API_KEY   – the judge LLM
    GITHUB_TOKEN     – needed when --mode is schedule or pr
    GITHUB_REPO      – "owner/repo"
    GITHUB_PR_NUMBER – only in --mode pr (set by the workflow)

Optional:
    OPENAI_BASE_URL  – override (default: https://api.openai.com/v1)
    MODEL            – default: gpt-5.2-codex
"""

import argparse
import json
import os
import re
import sys
import textwrap
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_FILE = REPO_ROOT / ".github" / "scripts" / "docs_drift_prompt.md"

# ── Config from environment ────────────────────────────────────────
OPENAI_BASE_URL = os.environ.get(
    "OPENAI_BASE_URL", "https://api.openai.com/v1"
).rstrip("/")
MODEL          = os.environ.get("MODEL", "gpt-5.2-codex")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO    = os.environ.get("GITHUB_REPO", "")
GITHUB_PR      = os.environ.get("GITHUB_PR_NUMBER", "")

# Cap each file at 24 KB so the combined prompt comfortably fits inside
# the model's context window. Anything larger is truncated with a
# marker — the judge knows to flag "uncertain" if it suspects the
# truncation hid drift.
MAX_FILE_CHARS = 24_000

# ── (src, doc) pair catalogue ──────────────────────────────────────
#
# views/ docs auto-pair with views/ sources of the same basename. The
# extra pairs cover synthesis docs whose source isn't under views/
# (alerts engine, beacons / deauth / etc. snoop modules with their own
# dedicated docs). When a new view is added, the auto-pair logic
# below picks it up — only the synthesis docs need a one-line entry.
EXTRA_PAIRS = [
    # Synthesis docs whose code is an engine, not a view file:
    ("src/alerts.c",         "docs/views/alerts.md"),
    ("src/beacon_snoop.c",   "docs/views/beacons.md"),
    ("src/deauth_snoop.c",   "docs/views/deauth.md"),
    ("src/dns.c",            "docs/views/dns.md"),
    ("src/dhcp_snoop.c",     "docs/views/dhcp.md"),
    ("src/mdns_snoop.c",     "docs/views/mdns.md"),
    ("src/nbns_snoop.c",     "docs/views/nbns.md"),
    ("src/ssdp_snoop.c",     "docs/views/ssdp.md"),
    ("src/eapol_log.c",      "docs/views/eapol.md"),
    ("src/probe_pnl.c",      "docs/views/pnl.md"),
    ("src/seqnum_track.c",   "docs/views/seqnum.md"),
    ("src/assoc_track.c",    "docs/views/assoc.md"),
    ("src/twins.c",          "docs/views/twins.md"),
    # Views whose doc basename differs from the source basename
    # (historical naming — the doc is named after what the operator
    # sees in the TUI, the source is named after the kernel object
    # it reads). Keep explicit so renames are visible at PR time.
    ("src/views/iface.c",      "docs/views/interfaces.md"),
    ("src/views/conns.c",      "docs/views/connections.md"),
    ("src/views/procs.c",      "docs/views/processes.md"),
    ("src/views/dns_log.c",    "docs/views/dns.md"),
    ("src/views/beacon.c",     "docs/views/beacons.md"),
    ("src/views/dhcp_snoop.c", "docs/views/dhcp.md"),
]


def discover_pairs():
    """Return [(src_path, doc_path)] for every audit-able pair."""
    pairs = []
    views_dir = REPO_ROOT / "src" / "views"
    docs_dir  = REPO_ROOT / "docs" / "views"
    for src in sorted(views_dir.glob("*.c")):
        stem = src.stem
        doc  = docs_dir / f"{stem}.md"
        if doc.exists():
            pairs.append((
                src.relative_to(REPO_ROOT).as_posix(),
                doc.relative_to(REPO_ROOT).as_posix(),
            ))
    seen = {tuple(p) for p in pairs}
    for src, doc in EXTRA_PAIRS:
        if (src, doc) in seen:
            continue
        if (REPO_ROOT / src).exists() and (REPO_ROOT / doc).exists():
            pairs.append((src, doc))
    return pairs


# ── HTTP / API helpers (mirrored from code_review.py) ──────────────

def _http(method, url, headers, body=None):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code} from {url}:\n{payload}", file=sys.stderr)
        raise


def openai_chat(messages):
    url  = f"{OPENAI_BASE_URL}/chat/completions"
    body = json.dumps({
        "model":           MODEL,
        "temperature":     0.1,
        "messages":        messages,
        "response_format": {"type": "json_object"},
    }).encode()
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type":  "application/json",
    }
    resp = _http("POST", url, headers, body)
    return resp["choices"][0]["message"]["content"]


def gh_request(method, path, body=None):
    url  = f"https://api.github.com/repos/{GITHUB_REPO}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization":        f"Bearer {GITHUB_TOKEN}",
        "Accept":               "application/vnd.github+json",
        "Content-Type":         "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return _http(method, url, headers, data)


def ensure_label(name, color, description):
    """Idempotent label create — same shape as code_review.py."""
    quoted = urllib.parse.quote(name)
    try:
        gh_request("GET", f"/labels/{quoted}")
        return
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    gh_request("POST", "/labels", {
        "name": name, "color": color, "description": description,
    })


def existing_drift_issue_titles():
    """Open issues with the docs-drift label, by title — used to skip
    creating duplicates when the same pair is still flagged a week
    later. Returns a set of title strings."""
    out = set()
    page = 1
    while True:
        items = gh_request(
            "GET",
            f"/issues?state=open&labels=docs-drift&per_page=100&page={page}",
        )
        if not isinstance(items, list) or not items:
            break
        for it in items:
            t = it.get("title")
            if t:
                out.add(t)
        page += 1
    return out


def create_issue(title, body, labels):
    res = gh_request("POST", "/issues", {
        "title": title, "body": body, "labels": labels,
    })
    return res.get("html_url", "")


def post_pr_comment(body):
    if not GITHUB_PR:
        print("GITHUB_PR_NUMBER not set — skipping PR comment.")
        return
    gh_request("POST", f"/issues/{GITHUB_PR}/comments", {"body": body})


# ── Prompt loading ─────────────────────────────────────────────────

def load_prompt():
    """Extract the SYSTEM and USER sections from the prompt markdown.
    Versioning the prompt as a markdown file (rather than a Python
    triple-string) keeps prompt-only changes legible in PR diffs."""
    text = PROMPT_FILE.read_text(encoding="utf-8")
    sys_m = re.search(r"## System\s*\n(.*?)\n## User template", text, re.S)
    usr_m = re.search(r"## User template\s*\n(.*)\Z", text, re.S)
    if not sys_m or not usr_m:
        raise SystemExit(
            "docs_drift_prompt.md missing '## System' or '## User template'"
        )
    system = sys_m.group(1).strip()
    user_t = usr_m.group(1).strip()
    # The user template is fenced with ``` in the markdown for
    # readability; strip the outer fences when present.
    user_t = re.sub(r"^```\s*\n", "", user_t)
    user_t = re.sub(r"\n```\s*\Z", "", user_t)
    return system, user_t


# ── Audit one pair ─────────────────────────────────────────────────

def truncate(s, n):
    if len(s) <= n:
        return s
    return s[:n] + "\n\n[... truncated; the rest of the file was not sent to the judge ...]\n"


def audit_pair(system_msg, user_template, src_path, doc_path, no_llm=False):
    src_body = truncate(
        (REPO_ROOT / src_path).read_text(encoding="utf-8", errors="replace"),
        MAX_FILE_CHARS,
    )
    doc_body = truncate(
        (REPO_ROOT / doc_path).read_text(encoding="utf-8", errors="replace"),
        MAX_FILE_CHARS,
    )
    user = user_template.format(
        src_path=src_path, src_body=src_body,
        doc_path=doc_path, doc_body=doc_body,
    )

    if no_llm:
        # Stub for offline dry-runs — emits a synthetic in-sync verdict
        # so the rest of the pipeline (issue rendering, dedup) can be
        # exercised without API calls.
        return {
            "verdict": "in-sync",
            "confidence": 0.0,
            "findings": [],
            "_stub": True,
        }

    if not OPENAI_API_KEY:
        print(f"[skip] {src_path} <-> {doc_path}: OPENAI_API_KEY unset",
              file=sys.stderr)
        return None

    raw = openai_chat([
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": user},
    ])
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print(f"Judge returned non-JSON for {src_path}:\n{raw}",
              file=sys.stderr)
        return None


# ── Rendering ──────────────────────────────────────────────────────

def render_finding_block(src_path, doc_path, result):
    verdict    = result.get("verdict", "unknown")
    confidence = result.get("confidence", 0.0)
    findings   = result.get("findings", [])
    lines = [
        f"**Pair:** `{src_path}` ⇄ `{doc_path}`",
        f"**Verdict:** {verdict} (confidence {confidence:.2f})",
    ]
    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines)
    for i, f in enumerate(findings, 1):
        lines.append(textwrap.dedent(f"""\

            #### Finding {i} — {f.get('severity','?')} / {f.get('category','?')}

            {f.get('explanation','').strip()}

            <details><summary>Evidence</summary>

            **Code:**
            ```
            {f.get('evidence_code','').strip()}
            ```

            **Doc:**
            ```
            {f.get('evidence_doc','').strip()}
            ```

            </details>
        """).rstrip())
    return "\n".join(lines)


def issue_title_for(src_path, doc_path):
    return f"[docs-drift] {doc_path} may be stale vs {src_path}"


# ── Schedule mode ──────────────────────────────────────────────────

def run_schedule(no_llm=False):
    system_msg, user_t = load_prompt()
    pairs = discover_pairs()
    print(f"Auditing {len(pairs)} (src, doc) pairs in schedule mode.")

    if GITHUB_TOKEN and GITHUB_REPO and not no_llm:
        ensure_label("docs-drift", "8957e5",
                     "Per-view docs may be out of sync with the code")
        existing = existing_drift_issue_titles()
    else:
        existing = set()

    new_issues = 0
    for src, doc in pairs:
        result = audit_pair(system_msg, user_t, src, doc, no_llm=no_llm)
        if not result:
            continue
        verdict = result.get("verdict")
        print(f"  {src} <-> {doc}: {verdict}")
        if verdict != "stale":
            continue
        title = issue_title_for(src, doc)
        if title in existing:
            print(f"    (existing issue open — skipping duplicate)")
            continue
        body = render_finding_block(src, doc, result) + "\n\n---\n" + (
            "_Opened by the docs-drift judge. Comment "
            "`/docs-drift verified` and close to mark as reviewed; the next "
            "weekly sweep will re-open if the judge still sees drift._"
        )
        if GITHUB_TOKEN and not no_llm:
            url = create_issue(title, body, ["docs-drift"])
            print(f"    issue created: {url}")
            new_issues += 1
        else:
            print(f"    (dry-run — would have opened: {title})")
    print(f"\nSchedule run complete. {new_issues} new issue(s) opened.")
    return 0


# ── PR mode ────────────────────────────────────────────────────────

def changed_pairs_from_file(path):
    """Read the workflow's changed-files list (one path per line) and
    map each line to the (src, doc) pairs it could affect."""
    pairs = set(discover_pairs())
    touched = set()
    if not Path(path).exists():
        return []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        for src, doc in pairs:
            if line == src or line == doc:
                touched.add((src, doc))
    return sorted(touched)


def run_pr(changed_files_path, no_llm=False):
    system_msg, user_t = load_prompt()
    pairs = changed_pairs_from_file(changed_files_path) if changed_files_path \
        else discover_pairs()
    if not pairs:
        print("No pairs touched by this PR — nothing to audit.")
        return 0
    print(f"Auditing {len(pairs)} pair(s) touched by the PR.")

    blocks = []
    for src, doc in pairs:
        result = audit_pair(system_msg, user_t, src, doc, no_llm=no_llm)
        if not result:
            continue
        verdict = result.get("verdict")
        print(f"  {src} <-> {doc}: {verdict}")
        if verdict == "stale":
            blocks.append(render_finding_block(src, doc, result))

    if not blocks:
        print("No drift findings — skipping PR comment.")
        return 0

    summary = "## docs-drift judge — possible drift\n\n" + (
        "The LLM judge flagged one or more (source, doc) pairs in this PR "
        "as potentially stale. Findings are **advisory** — see "
        "[docs-drift-judge](../blob/main/docs/wiki/docs-drift-judge.md) "
        "for how to dismiss false positives.\n\n"
    ) + "\n\n---\n\n".join(blocks)

    if GITHUB_TOKEN and not no_llm:
        post_pr_comment(summary)
        print("Posted PR comment.")
    else:
        print("--- dry-run; would have posted PR comment ---")
        print(summary)
    return 0


# ── Entry ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["schedule", "pr"], default=None,
                    help="run mode: schedule (cron) or pr (per-PR)")
    ap.add_argument("--changed-files", default=None,
                    help="path to newline-separated list of PR-changed files")
    ap.add_argument("--pair", nargs=2, metavar=("SRC", "DOC"),
                    help="local dry-run: audit one pair and print JSON")
    ap.add_argument("--dry-run", action="store_true",
                    help="never open issues / comments; print to stdout")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip the API call (returns a stub verdict)")
    args = ap.parse_args()

    # Fail-open when secrets are missing. The workflow runs on forks /
    # contributors without secret access, and we don't want it to break
    # the build for them.
    if not OPENAI_API_KEY and not (args.no_llm or args.dry_run):
        print("OPENAI_API_KEY is not set — skipping docs-drift judge.",
              file=sys.stderr)
        return 0

    if args.pair:
        system_msg, user_t = load_prompt()
        src, doc = args.pair
        result = audit_pair(system_msg, user_t, src, doc,
                            no_llm=args.no_llm or args.dry_run)
        print(json.dumps(result, indent=2))
        return 0

    if not args.mode:
        ap.print_help()
        return 2

    if args.mode == "schedule":
        return run_schedule(no_llm=args.no_llm or args.dry_run)
    return run_pr(args.changed_files, no_llm=args.no_llm or args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
