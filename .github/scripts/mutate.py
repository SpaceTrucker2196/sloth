#!/usr/bin/env python3
"""
Mutation-testing harness — verify the verifier.

Introduces small, well-defined faults into one or more `src/*.c` files,
rebuilds the test binary, and runs `make test`. Every mutant should be
killed (at least one assertion flips red). Surviving mutants are
concrete gaps in the test suite: either a missing assertion (write the
test that would have caught it) or genuinely dead/equivalent code
(document and ignore).

The product source tree is never modified in place. The script copies
the repo into a sandbox tmpdir and mutates there.

Run via `make mutate` or directly:

    python3 .github/scripts/mutate.py --files src/alerts.c
    python3 .github/scripts/mutate.py --files src/alerts.c --operators rel const
    python3 .github/scripts/mutate.py --files src/alerts.c --limit 20 --seed 1

Background: see issue #4 and docs/wiki/mutation-testing.md.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# ── Mutation operators ──────────────────────────────────────────────
# Each operator is a function: scan_line(line) -> list[Site].
# A Site is one applicable mutation in that line. Apply by string slice.

@dataclass
class Site:
    op: str            # operator family name (rel, arith, bool, const, return)
    col: int           # 0-based column in the line where replacement starts
    span: int          # length of the original token
    original: str      # original token text
    mutated: str       # replacement text
    note: str = ""     # short description shown in the report


# Relational and equality swaps. Each "→" is one mutation; we yield one
# Site per match per swap direction so the harness can pick them off
# independently.
_REL_SWAPS = [
    (">=", ">"), (">", ">="),
    ("<=", "<"), ("<", "<="),
    ("==", "!="), ("!=", "=="),
]


def _scan_rel(line: str, code_mask: list[bool]) -> list[Site]:
    out: list[Site] = []
    n = len(line)
    i = 0
    while i < n:
        if not code_mask[i]:
            i += 1
            continue
        # try 2-char operators first
        two = line[i:i+2]
        # `==` and `!=` must not be `===` style (not in C, but guard anyway)
        # and `>=`/`<=` must not be `>>=` or `<<=`
        if two in ("==", "!=", ">=", "<="):
            prev = line[i-1] if i > 0 else " "
            nxt  = line[i+2] if i+2 < n else " "
            # avoid `>>=`, `<<=`
            if not (prev in ("<", ">") and two in (">=", "<=")):
                # avoid being part of `===` (not C) — also guard `<==` shouldn't happen
                if nxt != "=":
                    for src, dst in _REL_SWAPS:
                        if two == src:
                            out.append(Site("rel", i, 2, src, dst,
                                            f"{src} -> {dst}"))
            i += 2
            continue
        one = line[i]
        if one in ("<", ">"):
            # skip if part of `<=`, `>=`, `<<`, `>>`
            nxt = line[i+1] if i+1 < n else " "
            if nxt in ("=", "<", ">"):
                i += 1
                continue
            # skip `->` (this is `>` after `-`) — actually `-` precedes,
            # so this catches `->` correctly only if we look at `-`.
            prev = line[i-1] if i > 0 else " "
            if one == ">" and prev == "-":
                i += 1
                continue
            for src, dst in _REL_SWAPS:
                if one == src:
                    out.append(Site("rel", i, 1, src, dst,
                                    f"{src} -> {dst}"))
            i += 1
            continue
        i += 1
    return out


def _scan_arith(line: str, code_mask: list[bool]) -> list[Site]:
    # `+` ↔ `-` only when used as binary infix on integers. To avoid
    # mangling `++`, `--`, `+=`, `-=`, `->`, unary `-N`, and pointer
    # arithmetic edge cases, we require: previous non-space char is an
    # identifier/digit/`)`/`]` AND next non-space is alnum/`_`/`(`.
    out: list[Site] = []
    n = len(line)
    for i, ch in enumerate(line):
        if ch not in ("+", "-"):
            continue
        if not code_mask[i]:
            continue
        # skip compound/inc/dec
        prev_ch = line[i-1] if i > 0 else ""
        next_ch = line[i+1] if i+1 < n else ""
        if next_ch in ("+", "-", "=", ">"):
            continue
        if prev_ch in ("+", "-"):
            continue
        # walk back to last non-space
        j = i - 1
        while j >= 0 and line[j] == " ":
            j -= 1
        if j < 0:
            continue
        pj = line[j]
        if not (pj.isalnum() or pj == "_" or pj == ")" or pj == "]"):
            continue
        # walk forward to next non-space
        k = i + 1
        while k < n and line[k] == " ":
            k += 1
        if k >= n:
            continue
        pk = line[k]
        if not (pk.isalnum() or pk == "_" or pk == "("):
            continue
        dst = "-" if ch == "+" else "+"
        out.append(Site("arith", i, 1, ch, dst, f"{ch} -> {dst}"))
    return out


def _scan_bool(line: str, code_mask: list[bool]) -> list[Site]:
    out: list[Site] = []
    n = len(line)
    i = 0
    while i < n - 1:
        if not code_mask[i]:
            i += 1
            continue
        two = line[i:i+2]
        if two == "&&":
            out.append(Site("bool", i, 2, "&&", "||", "&& -> ||"))
            i += 2
            continue
        if two == "||":
            out.append(Site("bool", i, 2, "||", "&&", "|| -> &&"))
            i += 2
            continue
        i += 1
    return out


_INT_LIT_RE = re.compile(r"\b(\d+)\b")


def _scan_const(line: str, code_mask: list[bool]) -> list[Site]:
    # Perturb integer literals by ±1. Skip 0 (too noisy: `return 0;`,
    # array index, sentinel). Skip values >= 1024 (likely sizes/buffers,
    # ±1 there rarely flips behaviour). Skip hex/oct/binary (different
    # semantic class — addresses, masks).
    out: list[Site] = []
    for m in _INT_LIT_RE.finditer(line):
        s, e = m.span(1)
        if not code_mask[s]:
            continue
        # skip if preceded by 0x / 0X / 0b / 0B (hex/binary already
        # filtered by the \b anchor for most cases, but `0x1A` matches
        # `0` then `1A`; guard explicitly)
        prev = line[s-1] if s > 0 else ""
        if prev in ("x", "X", "b", "B", "."):
            continue
        # skip if this is preceded by `0` (octal-style or part of hex)
        if s >= 2 and line[s-2] == "0" and line[s-1] in ("x", "X", "b", "B"):
            continue
        val = int(m.group(1))
        if val == 0:
            continue
        if val >= 1024:
            continue
        for delta, name in ((1, "+1"), (-1, "-1")):
            new = val + delta
            if new < 0:
                continue
            out.append(Site("const", s, e - s,
                            m.group(1), str(new),
                            f"{val} -> {new}"))
    return out


_RETURN_RE = re.compile(r"\breturn\s+(\d+)\s*;")


def _scan_return(line: str, code_mask: list[bool]) -> list[Site]:
    # `return N;` where N != 0  →  `return 0;`. Captures most boolean
    # and error-code returns. We skip `return 0;` (no-op) and any
    # `return` with a non-literal expression.
    out: list[Site] = []
    for m in _RETURN_RE.finditer(line):
        s, e = m.span()
        if not code_mask[s]:
            continue
        val = int(m.group(1))
        if val == 0:
            continue
        out.append(Site("return", s, e - s,
                        m.group(0), "return 0;",
                        f"return {val}; -> return 0;"))
    return out


OPERATORS = {
    "rel":    _scan_rel,
    "arith":  _scan_arith,
    "bool":   _scan_bool,
    "const":  _scan_const,
    "return": _scan_return,
}


# ── String / comment / preprocessor masking ─────────────────────────
# For each line we build a boolean mask: True at column i if that
# character is part of executable code (i.e. not inside a string, char
# literal, or comment, and not on a preprocessor line). State carries
# across lines for /* ... */ block comments.

def _code_mask_for_file(src: str) -> list[list[bool]]:
    masks: list[list[bool]] = []
    in_block_comment = False
    for line in src.splitlines(keepends=False):
        n = len(line)
        mask = [True] * n
        if line.lstrip().startswith("#"):
            # preprocessor line — entirely off-limits
            masks.append([False] * n)
            continue
        i = 0
        in_string = False
        in_char = False
        while i < n:
            c = line[i]
            if in_block_comment:
                mask[i] = False
                if c == "*" and i + 1 < n and line[i+1] == "/":
                    mask[i+1] = False
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                mask[i] = False
                if c == "\\" and i + 1 < n:
                    mask[i+1] = False
                    i += 2
                    continue
                if c == '"':
                    in_string = False
                i += 1
                continue
            if in_char:
                mask[i] = False
                if c == "\\" and i + 1 < n:
                    mask[i+1] = False
                    i += 2
                    continue
                if c == "'":
                    in_char = False
                i += 1
                continue
            # not in any quoted / commented region
            if c == "/" and i + 1 < n and line[i+1] == "/":
                # line comment — rest of line is off-limits
                for j in range(i, n):
                    mask[j] = False
                break
            if c == "/" and i + 1 < n and line[i+1] == "*":
                mask[i] = False
                mask[i+1] = False
                in_block_comment = True
                i += 2
                continue
            if c == '"':
                in_string = True
                mask[i] = False
                i += 1
                continue
            if c == "'":
                in_char = True
                mask[i] = False
                i += 1
                continue
            i += 1
        masks.append(mask)
    return masks


# ── Site discovery ──────────────────────────────────────────────────

@dataclass
class Mutant:
    file: str          # path relative to repo root, e.g. "src/alerts.c"
    line_no: int       # 1-based
    site: Site


def discover_sites(file_path: Path, operators: list[str]) -> list[Mutant]:
    src = file_path.read_text()
    masks = _code_mask_for_file(src)
    lines = src.splitlines(keepends=False)
    mutants: list[Mutant] = []
    rel_path = str(file_path)
    for idx, line in enumerate(lines):
        mask = masks[idx]
        for op in operators:
            for site in OPERATORS[op](line, mask):
                mutants.append(Mutant(rel_path, idx + 1, site))
    return mutants


def apply_mutation(file_path: Path, mutant: Mutant) -> None:
    """Apply one mutation in place; caller is responsible for restore."""
    src = file_path.read_text()
    lines = src.splitlines(keepends=True)
    line = lines[mutant.line_no - 1]
    # find original line content without the trailing newline
    has_nl = line.endswith("\n")
    body = line.rstrip("\n")
    col = mutant.site.col
    span = mutant.site.span
    if body[col:col + span] != mutant.site.original:
        raise RuntimeError(
            f"mutation site moved: {mutant.file}:{mutant.line_no} "
            f"expected {mutant.site.original!r} at col {col}, "
            f"got {body[col:col+span]!r}"
        )
    new_body = body[:col] + mutant.site.mutated + body[col + span:]
    lines[mutant.line_no - 1] = new_body + ("\n" if has_nl else "")
    file_path.write_text("".join(lines))


# ── Test runner ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class IgnoreKey:
    file: str       # repo-relative path, e.g. "src/alerts.c"
    line: int
    op: str
    original: str
    mutated: str


def load_ignore_file(path: Path) -> set:
    """Parse a mutate-equivalents file. Returns a set of IgnoreKey.

    Format: one entry per non-blank, non-comment line:

        src/alerts.c:23:const:6:7    # mac_to_str function-parameter array size

    Fields are split on `:` so `original` and `mutated` must not
    contain a literal colon. Trailing `# comment` is stripped.
    """
    out = set()
    text = path.read_text()
    for raw_lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 5:
            print(f"WARN: {path}:{raw_lineno}: expected "
                  f"file:line:op:original:mutated, got {raw!r}",
                  file=sys.stderr)
            continue
        try:
            ln = int(parts[1])
        except ValueError:
            print(f"WARN: {path}:{raw_lineno}: line field not integer",
                  file=sys.stderr)
            continue
        out.add(IgnoreKey(parts[0], ln, parts[2], parts[3], parts[4]))
    return out


def fingerprint(m) -> IgnoreKey:
    return IgnoreKey(m.file, m.line_no, m.site.op,
                     m.site.original, m.site.mutated)


def run_make_test(workdir: Path, timeout_s: float) -> tuple[bool, str]:
    """Returns (passed, short_stderr_tail).

    We use `make -B test` because mtime granularity on some filesystems
    (notably APFS via Python's write_text on macOS) lets a mutated
    source share the same second as the freshly built test binary,
    which make then treats as up-to-date and skips the rebuild.
    -B forces unconditional rebuild — exactly what mutation testing
    requires.
    """
    try:
        r = subprocess.run(
            ["make", "-B", "test"],
            cwd=workdir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
        )
        return r.returncode == 0, r.stderr.decode("utf-8", "replace")[-400:]
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"


# ── Main ────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_sandbox(repo: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="sloth-mutate-"))
    # Copy just what the test build needs. Exclude .git, build outputs,
    # editor cruft. Keep Makefile, src/, include/, tests/.
    for entry in ("Makefile", "src", "include", "tests"):
        src = repo / entry
        dst = tmp / entry
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    return tmp


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--files", nargs="+", default=["src/alerts.c"],
        help="repo-relative source files to mutate (default: src/alerts.c)",
    )
    parser.add_argument(
        "--operators", nargs="+", default=list(OPERATORS.keys()),
        choices=list(OPERATORS.keys()),
        help="which mutation operators to apply",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="cap total mutations (0 = no cap)",
    )
    parser.add_argument(
        "--seed", type=int, default=0,
        help="seed for shuffling when --limit is set",
    )
    parser.add_argument(
        "--timeout-mult", type=float, default=4.0,
        help="per-mutant timeout as multiple of baseline test time",
    )
    parser.add_argument(
        "--keep-sandbox", action="store_true",
        help="don't delete sandbox tmpdir on exit",
    )
    parser.add_argument(
        "--report", type=str, default="",
        help="also write report to this path",
    )
    parser.add_argument(
        "--ignore-file", type=str, default="",
        help="path to a mutate-equivalents file (one "
             "file:line:op:original:mutated entry per line). When set, "
             "matching mutations are skipped and reported as 'ignored' "
             "rather than 'survived'. Defaults to "
             ".github/scripts/mutate-equivalents.txt if that file exists.",
    )
    args = parser.parse_args()

    # Default ignore file if one ships in-tree.
    if not args.ignore_file:
        default_ignore = REPO_ROOT / ".github" / "scripts" / "mutate-equivalents.txt"
        if default_ignore.is_file():
            args.ignore_file = str(default_ignore)

    repo = REPO_ROOT
    files = [(repo / f).resolve() for f in args.files]
    for f in files:
        if not f.is_file():
            print(f"ERROR: {f} does not exist", file=sys.stderr)
            return 2
        if "src/" not in str(f):
            print(f"ERROR: {f} is not under src/ — refusing", file=sys.stderr)
            return 2

    # Load ignore set (may be empty).
    ignore = set()
    if args.ignore_file:
        ipath = Path(args.ignore_file)
        if not ipath.is_file():
            print(f"ERROR: ignore file {ipath} does not exist", file=sys.stderr)
            return 2
        ignore = load_ignore_file(ipath)

    print(f"== sloth mutation testing ==")
    print(f"repo:      {repo}")
    print(f"files:     {', '.join(args.files)}")
    print(f"operators: {', '.join(args.operators)}")
    if ignore:
        print(f"ignore:    {len(ignore)} entries from {args.ignore_file}")
    sys.stdout.flush()

    # 1. Sandbox.
    sandbox = make_sandbox(repo)
    print(f"sandbox:   {sandbox}")
    sys.stdout.flush()

    try:
        # 2. Baseline. Must be green; time it.
        print("baseline:  building & running make test ...", end=" ", flush=True)
        t0 = time.monotonic()
        ok, err = run_make_test(sandbox, timeout_s=300)
        baseline_s = time.monotonic() - t0
        if not ok:
            print("FAIL")
            print(err)
            print("baseline `make test` is not green; aborting.")
            return 3
        print(f"OK ({baseline_s:.1f}s)")

        # 3. Discover mutation sites.
        all_mutants: list[Mutant] = []
        for rel in args.files:
            sites = discover_sites(Path(rel), args.operators)
            all_mutants.extend(sites)
        print(f"sites:     {len(all_mutants)}")

        if args.limit and len(all_mutants) > args.limit:
            rng = random.Random(args.seed)
            rng.shuffle(all_mutants)
            all_mutants = all_mutants[: args.limit]
            all_mutants.sort(key=lambda m: (m.file, m.line_no, m.site.col))
            print(f"capped:    {len(all_mutants)} (seed={args.seed})")

        # 4. Apply each mutant, run tests, restore.
        timeout = max(15.0, baseline_s * args.timeout_mult)
        survivors: list[tuple[Mutant, str]] = []
        ignored: list = []
        killed = 0
        timed_out = 0
        build_broke = 0

        # Save originals so we can restore exactly.
        originals = {rel: (sandbox / rel).read_text() for rel in args.files}

        t_start = time.monotonic()
        for i, m in enumerate(all_mutants, 1):
            if fingerprint(m) in ignore:
                ignored.append(m)
                elapsed = time.monotonic() - t_start
                print(f"  [{i:4d}/{len(all_mutants)}] {m.file}:{m.line_no} "
                      f"{m.site.op}:{m.site.note}  -> IGNORED  "
                      f"({elapsed:.0f}s elapsed)")
                sys.stdout.flush()
                continue
            target = sandbox / m.file
            apply_mutation(target, m)
            ok, err = run_make_test(sandbox, timeout_s=timeout)
            # Restore just this file.
            target.write_text(originals[m.file])

            if ok:
                survivors.append((m, ""))
                marker = "SURVIVED"
            else:
                killed += 1
                marker = "killed"
                if "TIMEOUT" in err:
                    timed_out += 1
                    marker = "killed (timeout)"
                elif "error:" in err.lower() and "make:" in err.lower():
                    build_broke += 1
                    marker = "killed (build broke)"

            elapsed = time.monotonic() - t_start
            rate = i / elapsed if elapsed > 0 else 0
            print(f"  [{i:4d}/{len(all_mutants)}] {m.file}:{m.line_no} "
                  f"{m.site.op}:{m.site.note}  -> {marker}  "
                  f"({elapsed:.0f}s elapsed, {rate:.2f}/s)")
            sys.stdout.flush()

        # 5. Report.
        total = len(all_mutants)
        considered = total - len(ignored)
        raw_rate  = (killed / total * 100.0) if total else 0.0
        eff_rate  = (killed / considered * 100.0) if considered else 0.0
        lines_out: list[str] = []
        lines_out.append("")
        lines_out.append("== Mutation summary ==")
        lines_out.append(f"Files:     {', '.join(args.files)}")
        lines_out.append(f"Operators: {', '.join(args.operators)}")
        lines_out.append(f"Mutants:   {total}")
        if ignored:
            lines_out.append(f"Ignored:   {len(ignored)} "
                             f"(documented equivalence-class)")
            lines_out.append(f"Considered:{considered}")
            lines_out.append(f"Killed:    {killed} "
                             f"({eff_rate:.1f}% of considered, "
                             f"{raw_rate:.1f}% of total)")
        else:
            lines_out.append(f"Killed:    {killed} ({raw_rate:.1f}%)")
        lines_out.append(f"           ├─ by build break: {build_broke}")
        lines_out.append(f"           └─ by timeout:     {timed_out}")
        lines_out.append(f"Survived:  {len(survivors)}")
        if survivors:
            lines_out.append("")
            lines_out.append("Surviving mutants (test-suite gaps):")
            for m, _ in survivors:
                lines_out.append(f"  {m.file}:{m.line_no:5d}  "
                                 f"{m.site.op:7s}  {m.site.note}")
        report = "\n".join(lines_out)
        print(report)
        if args.report:
            Path(args.report).write_text(report + "\n")

        return 0 if not survivors else 1
    finally:
        if args.keep_sandbox:
            print(f"sandbox kept: {sandbox}")
        else:
            shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
