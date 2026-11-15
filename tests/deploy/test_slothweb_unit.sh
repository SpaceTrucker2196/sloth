#!/bin/sh
# packaging/systemd/slothweb.service's agent-secret keys (slothweb-mcp.md
# §7): the secret's directory is one the operator's user can pass
# through (the state directory is 0700 and stays so), and fchown, which
# --web-agent-group needs and ~@privileged takes away, is given back.
# The keys are read from the unit as systemd would see them. Where a
# user manager is running (`systemd-run --user`), the unit's own
# SystemCallFilter= lines are applied to a process that calls fchown(),
# so the filter is tested, not only its text; elsewhere (CI) that step
# says it is skipped.
set -u

top=$(pwd)
unit=$top/packaging/systemd/slothweb.service
[ -f "$unit" ] || { echo "test_slothweb_unit: run from the top of the tree" >&2; exit 2; }

pass=0
fail=0
has() {     # $1 = exact line, $2 = what
    if grep -qxF -- "$1" "$unit"; then pass=$((pass + 1));
    else fail=$((fail + 1)); echo "  FAIL $2: no line '$1'"; fi
}

has "RuntimeDirectory=slothweb" "the secret's directory"
has "RuntimeDirectoryMode=0711" "traversable by the operator, not listable"
has "StateDirectoryMode=0700" "the state directory unchanged"
has "UMask=0077" "the umask unchanged"
has "SystemCallFilter=fchown fchown32" "fchown given back"

# The fchown line after the line that takes it away: the later one wins.
priv=$(grep -n '^SystemCallFilter=~@privileged' "$unit" | head -n 1 | cut -d: -f1)
fch=$(grep -n '^SystemCallFilter=fchown' "$unit" | head -n 1 | cut -d: -f1)
if [ -n "$priv" ] && [ -n "$fch" ] && [ "$fch" -gt "$priv" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL fchown is not given back after ~@privileged ($priv, $fch)"; fi
# Nothing else taken back from the deny lists.
n=$(grep -c '^SystemCallFilter=[^~]' "$unit")
if [ "$n" -eq 2 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL $n allow lines, want 2 (@system-service, fchown)"; fi

# The unit and the slothweb it runs agree (#215 review). slothweb exits
# on an option it does not know, so a unit installed over an older
# binary is a web UI that never starts. `make install-service` compares
# every --flag on ExecStart with the installed slothweb and refuses,
# before writing anything, when one is missing; with no slothweb
# installed there is nothing to disagree with. Staged under a scratch
# DESTDIR; the "binary" is a text file holding the flags. Seen red with
# the check removed from the recipe (the unit was installed over the
# short binary), and with sloth-rf.service installed unconditionally.
flags=$(sed -n '/^ExecStart=/,/[^\\]$/p' "$unit" | grep -o -e '--[a-z][a-z0-9-]*')
last=$(printf '%s\n' "$flags" | tail -n 1)
stage=$(mktemp -d "${TMPDIR:-/tmp}/sloth-unit-stage.XXXXXX") || exit 2
svc() { make -s install-service DESTDIR="$stage/$1" > "$stage/$1.out" 2>&1; }
if [ "$(printf '%s\n' "$flags" | wc -l)" -ge 4 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the unit's ExecStart flags were not read: '$flags'"; fi
# No slothweb installed.
if svc none && [ -f "$stage/none/etc/systemd/system/slothweb.service" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service with no slothweb installed: $(cat "$stage/none.out")"; fi
# sloth-rf.service only beside its binary: slothweb.service Wants= it,
# and a unit with nothing to run fails at every start of slothweb.
if [ ! -e "$stage/none/etc/systemd/system/sloth-rf.service" ] &&
   grep -qF "sloth-rf.service was NOT installed" "$stage/none.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL sloth-rf.service installed with no sloth-rf binary, or not said: $(cat "$stage/none.out")"; fi
# An installed slothweb that lacks one flag.
mkdir -p "$stage/old/usr/local/bin"
printf '%s\n' "$flags" | grep -vxF -e "$last" > "$stage/old/usr/local/bin/slothweb"
if svc old; then fail=$((fail + 1)); echo "  FAIL install-service over a slothweb without $last succeeded";
else pass=$((pass + 1)); fi
if grep -qF -e "does not know $last" "$stage/old.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the refusal does not name $last: $(cat "$stage/old.out")"; fi
if [ ! -e "$stage/old/etc" ] && [ ! -e "$stage/old/usr/lib" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the refused install-service wrote: $(find "$stage/old" -type f)"; fi
# One that has them all, with sloth-rf beside it.
mkdir -p "$stage/new/usr/local/bin"
printf '%s\n' "$flags" > "$stage/new/usr/local/bin/slothweb"
printf '#!/bin/sh\n' > "$stage/new/usr/local/bin/sloth-rf"
chmod 755 "$stage/new/usr/local/bin/sloth-rf"
if svc new && [ -f "$stage/new/etc/systemd/system/slothweb.service" ] &&
   [ -f "$stage/new/etc/systemd/system/sloth-rf.service" ] &&
   [ ! -e "$stage/new/etc/systemd/system/sloth-rf.service.tmp" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service beside a current slothweb and sloth-rf: $(cat "$stage/new.out")"; fi
rm -rf "$stage"

# The filter itself, on a live user manager.
if command -v systemd-run >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 &&
   systemd-run --user --wait --quiet /bin/true >/dev/null 2>&1; then
    base=$(mktemp -d "${TMPDIR:-/tmp}/sloth-unit.XXXXXX")
    trap 'rm -rf "$base"' EXIT INT TERM HUP
    f=$base/secret
    : > "$f"
    chmod 600 "$f"
    gid=$(id -g)
    other=$(id -G | tr ' ' '\n' | grep -vx "$gid" | head -n 1)
    if [ -z "$other" ]; then
        echo "deploy-test: no supplementary group; the fchown step is skipped"
    else
        try() {     # $@ = extra -p properties; prints ok or err
            # shellcheck disable=SC2016
            systemd-run --user --wait --pipe --quiet -p NoNewPrivileges=yes "$@" \
                -p SystemCallErrorNumber=EPERM /usr/bin/python3 -c '
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fchown(fd, -1, int(sys.argv[2])); print("ok")
except OSError:
    print("err")' "$f" "$other" 2>/dev/null
        }
        set --
        while IFS= read -r line; do
            case $line in
                SystemCallFilter=*) set -- "$@" -p "$line" ;;
            esac
        done < "$unit"
        got=$(try "$@")
        if [ "$got" = ok ]; then pass=$((pass + 1));
        else fail=$((fail + 1)); echo "  FAIL fchown under the unit's filter: '$got'"; fi
        # The control: without the fchown line, the same call is refused.
        set --
        while IFS= read -r line; do
            case $line in
                SystemCallFilter=fchown*) ;;
                SystemCallFilter=*) set -- "$@" -p "$line" ;;
            esac
        done < "$unit"
        chgrp "$gid" "$f"
        got=$(try "$@")
        if [ "$got" = err ]; then pass=$((pass + 1));
        else fail=$((fail + 1)); echo "  FAIL fchown without the line: '$got', want err"; fi
    fi
else
    echo "deploy-test: no systemd user manager; the unit's filter is checked as text only"
fi

echo "slothweb-unit-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
