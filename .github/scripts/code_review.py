#!/usr/bin/env python3
"""
GPT-5.2 Codex code-review script.

Reads the git diff from DIFF_FILE (or stdin), asks GPT-5.2 Codex for a
structured review, then opens a GitHub issue for every finding.

Required environment variables:
  OPENAI_API_KEY   – OpenAI API key with access to the model
  GITHUB_TOKEN     – token with issues:write on the repo
  GITHUB_REPO      – "owner/repo" (e.g. "SpaceTrucker2196/sloth")
  DIFF_FILE        – path to the file containing the git diff
  COMMIT_SHA       – short SHA for the review title
  COMMIT_URL       – HTML URL linking to the commit on GitHub

Optional:
  OPENAI_BASE_URL  – override the OpenAI API endpoint (default: https://api.openai.com/v1)
  MODEL            – model name (default: gpt-5.2-codex)
"""

import json
import os
import sys
import textwrap
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
MODEL           = os.environ.get("MODEL", "gpt-5.2-codex")
OPENAI_API_KEY  = os.environ["OPENAI_API_KEY"]
GITHUB_TOKEN    = os.environ["GITHUB_TOKEN"]
GITHUB_REPO     = os.environ["GITHUB_REPO"]          # owner/repo
DIFF_FILE       = os.environ.get("DIFF_FILE", "")
COMMIT_SHA      = os.environ.get("COMMIT_SHA", "unknown")
COMMIT_URL      = os.environ.get("COMMIT_URL", "")

MAX_DIFF_CHARS  = 32_000   # keep prompt within token limits

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _http(method: str, url: str, headers: dict, body: bytes | None = None) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code} from {url}:\n{payload}", file=sys.stderr)
        raise


def openai_chat(messages: list[dict]) -> str:
    url  = f"{OPENAI_BASE_URL}/chat/completions"
    body = json.dumps({
        "model":       MODEL,
        "temperature": 0.2,
        "messages":    messages,
        "response_format": {"type": "json_object"},
    }).encode()
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type":  "application/json",
    }
    resp = _http("POST", url, headers, body)
    return resp["choices"][0]["message"]["content"]


def create_github_issue(title: str, body: str, labels: list[str]) -> str:
    url  = f"https://api.github.com/repos/{GITHUB_REPO}/issues"
    data = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github+json",
        "Content-Type":  "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = _http("POST", url, headers, data)
    return resp.get("html_url", "")


def ensure_label(name: str, color: str, description: str) -> None:
    """Create label if it doesn't already exist."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/labels/{urllib.parse.quote(name)}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        _http("GET", url, headers)
        return  # already exists
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    # create it
    data = json.dumps({"name": name, "color": color, "description": description}).encode()
    _http("POST", f"https://api.github.com/repos/{GITHUB_REPO}/labels", headers, data)


import urllib.parse  # noqa: E402  (imported here so ensure_label can use it above)

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert C99 code reviewer specialising in security, correctness,
    and performance. You are reviewing a git diff for the 'sloth' project — a
    terminal-based passive network monitor for Linux.

    Return ONLY valid JSON in this exact schema (no markdown, no extra text):
    {
      "summary": "<one sentence describing the overall change>",
      "findings": [
        {
          "severity":    "critical|high|medium|low|info",
          "category":    "security|correctness|performance|style|documentation",
          "title":       "<short imperative title, ≤72 chars>",
          "description": "<detailed explanation of the problem>",
          "suggestion":  "<concrete fix or improvement>",
          "file":        "<filename or empty string if global>",
          "line":        <line number as int or 0 if unknown>
        }
      ]
    }

    Rules:
    - Only report genuine issues — no noise.
    - Severity "critical" = exploitable vulnerability or data corruption.
    - If there are no issues, return an empty findings array.
    - Do not comment on whitespace-only changes.
""")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Read diff
    if DIFF_FILE:
        with open(DIFF_FILE, "r", errors="replace") as fh:
            diff = fh.read()
    else:
        diff = sys.stdin.read()

    if not diff.strip():
        print("No diff content — nothing to review.")
        return 0

    if len(diff) > MAX_DIFF_CHARS:
        print(f"Diff truncated from {len(diff)} to {MAX_DIFF_CHARS} characters.")
        diff = diff[:MAX_DIFF_CHARS] + "\n\n[... diff truncated ...]"

    commit_ref = f"[`{COMMIT_SHA}`]({COMMIT_URL})" if COMMIT_URL else f"`{COMMIT_SHA}`"

    messages = [
        {"role": "system",  "content": SYSTEM_PROMPT},
        {"role": "user",    "content": f"Review the following diff for commit {commit_ref}:\n\n```diff\n{diff}\n```"},
    ]

    print(f"Sending diff ({len(diff)} chars) to {MODEL} for review…")
    raw = openai_chat(messages)

    try:
        review = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Model returned non-JSON response:\n{raw}", file=sys.stderr)
        raise exc

    findings = review.get("findings", [])
    summary  = review.get("summary", "")
    print(f"Summary: {summary}")
    print(f"Findings: {len(findings)}")

    if not findings:
        print("No issues found — no GitHub issues created.")
        return 0

    # Ensure labels exist
    severity_meta = {
        "critical":    ("b60205", "Critical severity finding from code review"),
        "high":        ("d93f0b", "High severity finding from code review"),
        "medium":      ("e4e669", "Medium severity finding from code review"),
        "low":         ("0075ca", "Low severity finding from code review"),
        "info":        ("cfd3d7", "Informational finding from code review"),
    }
    for label_name, (color, desc) in severity_meta.items():
        ensure_label(f"code-review:{label_name}", color, desc)
    ensure_label("code-review", "5319e7", "Opened automatically by GPT code review")

    created = 0
    for finding in findings:
        severity    = finding.get("severity", "info").lower()
        category    = finding.get("category", "")
        title       = finding.get("title", "Code review finding")
        description = finding.get("description", "")
        suggestion  = finding.get("suggestion", "")
        file_       = finding.get("file", "")
        line        = finding.get("line", 0)

        location = ""
        if file_:
            location = f"**File:** `{file_}`"
            if line:
                location += f" (line {line})"

        issue_body = textwrap.dedent(f"""\
            ## Code Review Finding

            **Commit:** {commit_ref}
            **Severity:** {severity}
            **Category:** {category}
            {location}

            ### Problem

            {description}

            ### Suggestion

            {suggestion}

            ---
            *Opened automatically by the GPT-5.2 Codex code-review workflow.*
        """).strip()

        issue_title = f"[code-review] {title}"
        labels = ["code-review", f"code-review:{severity}"]

        url = create_github_issue(issue_title, issue_body, labels)
        print(f"  Created issue ({severity}): {url}")
        created += 1

    print(f"\nDone — {created} issue(s) created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
