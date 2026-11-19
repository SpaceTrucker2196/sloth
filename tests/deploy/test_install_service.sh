#!/bin/sh
# `make install-service` against a scratch DESTDIR (#216, #215 review):
# the sensor's unit only beside the binary it runs, sloth-rf.service only
# beside its binary, and the upgrade warnings about /etc/default/sloth.
# Unprivileged: every install goes to a scratch DESTDIR and touches no
# real service. slothweb.service and its keys were tested here until
# #235 moved them to sloth-mesh (its tests/deploy/test_install.sh).
set -u

top=$(pwd)
[ -f "$top/packaging/systemd/sloth-sensor.service" ] || { echo "test_install_service: run from the top of the tree" >&2; exit 2; }

pass=0
fail=0
stage=$(mktemp -d "${TMPDIR:-/tmp}/sloth-unit-stage.XXXXXX") || exit 2
svc() { make -s install-service DESTDIR="$stage/$1" > "$stage/$1.out" 2>&1; }
# Nothing installed.
if svc none && [ -f "$stage/none/etc/systemd/system/sloth-sensor.service" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service with nothing installed: $(cat "$stage/none.out")"; fi
# slothweb's unit and defaults are sloth-mesh's now: never written here.
# Seen red against the parent's Makefile (5ef73c52), which wrote both.
if [ ! -e "$stage/none/etc/systemd/system/slothweb.service" ] && [ ! -e "$stage/none/etc/default/slothweb" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service wrote slothweb's unit or defaults"; fi
# sloth-rf.service only beside its binary: slothweb.service (sloth-mesh's)
# Wants= it, and a unit with nothing to run fails at every start of
# slothweb.
if [ ! -e "$stage/none/etc/systemd/system/sloth-rf.service" ] &&
   grep -qF "sloth-rf.service was NOT installed" "$stage/none.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL sloth-rf.service installed with no sloth-rf binary, or not said: $(cat "$stage/none.out")"; fi
# With sloth-rf installed beside it.
mkdir -p "$stage/new/usr/local/bin"
printf '#!/bin/sh\n' > "$stage/new/usr/local/bin/sloth-rf"
chmod 755 "$stage/new/usr/local/bin/sloth-rf"
if svc new && [ -f "$stage/new/etc/systemd/system/sloth-rf.service" ] &&
   [ ! -e "$stage/new/etc/systemd/system/sloth-rf.service.tmp" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service beside sloth-rf: $(cat "$stage/new.out")"; fi

# Upgrade safety (#216). sloth-sensor.service runs sloth-wifi, which
# refuses the six decoder flags and exits 2, so a host whose
# /etc/default/sloth still carries one has a sensor that will not start
# after this build. install-service never rewrites that file; it warns,
# prominently, before the summary and again as its last lines, names the
# flags it found and the command that moves them, and still exits 0.
# Staged under the same scratch DESTDIR. Seen red: the warning, with the
# $(warn_rf_flags_in_default) lines taken out of the recipe; the three
# "no warning" cases, with the comment filter dropped (the shipped
# file's own comments name every flag) and with the trailing
# [[:space:]=] taken off RF_MOVED_FLAGS_RE (--adsb-extra matched).
warned() { grep -c "WARNING: .*etc/default/sloth still passes an SDR decoder flag" "$stage/$1.out"; }
# The shipped file, installed fresh: flags in comments only.
if [ "$(warned none)" -eq 0 ] && ! grep -qF "WILL NOT START" "$stage/none.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service warned about the shipped /etc/default/sloth: $(cat "$stage/none.out")"; fi
# A site file from before the split.
mkdir -p "$stage/rfargs/etc/default"
printf '%s\n' '# site' 'SLOTH_IFACE=alfa0' \
    'SLOTH_ARGS=--site-label attic --adsb /run/readsb/aircraft.json --aprs-freq=144390000 --rtl433 /var/lib/rtl_433/events.jsonl' \
    > "$stage/rfargs/etc/default/sloth"
cp "$stage/rfargs/etc/default/sloth" "$stage/rfargs.before"
if svc rfargs; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service failed over a site file with decoder flags: $(cat "$stage/rfargs.out")"; fi
if [ "$(warned rfargs)" -eq 2 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the decoder-flag warning was printed $(warned rfargs) times, want 2: $(cat "$stage/rfargs.out")"; fi
for want in "      --adsb" "      --aprs-freq" "      --rtl433" "WILL NOT START" \
            "sloth-migrate-rf --apply" "section 11.4"; do
    if grep -qF -e "$want" "$stage/rfargs.out"; then pass=$((pass + 1));
    else fail=$((fail + 1)); echo "  FAIL the warning lacks '$want': $(cat "$stage/rfargs.out")"; fi
done
# Only the flags that are there: --aprs-freq is not --aprs.
if grep -qxF -e "      --aprs" "$stage/rfargs.out" || grep -qF -e "      --victron" "$stage/rfargs.out"; then
    fail=$((fail + 1)); echo "  FAIL the warning names a flag the file does not have: $(cat "$stage/rfargs.out")";
else pass=$((pass + 1)); fi
# The warning is the last thing printed, and the file is the site's still.
if tail -n 2 "$stage/rfargs.out" | grep -qF '****'; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the warning is not at the end: $(tail -n 5 "$stage/rfargs.out")"; fi
if cmp -s "$stage/rfargs.before" "$stage/rfargs/etc/default/sloth"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service changed the site's /etc/default/sloth"; fi
if [ -f "$stage/rfargs/etc/systemd/system/sloth-sensor.service" ] &&
   grep -q '^ExecStart=/usr/local/bin/sloth-wifi ' "$stage/rfargs/etc/systemd/system/sloth-sensor.service"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the sensor unit was not installed, or does not run sloth-wifi"; fi
# Look-alikes and a commented example are not the flags.
mkdir -p "$stage/alike/etc/default"
printf '%s\n' '#   SLOTH_ARGS=--adsb /nowhere/example.json' '# SLOTH_ARGS=--rtl433 /nowhere/commented.json' \
    'SLOTH_ARGS=--site-label attic --adsb-extra 1 --aprsx=2 --victronish 3 --gps gpsd://' \
    > "$stage/alike/etc/default/sloth"
if svc alike && [ "$(warned alike)" -eq 0 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service warned about look-alike or commented flags: $(cat "$stage/alike.out")"; fi
# A flag at the end of the line, and one by itself.
mkdir -p "$stage/eol/etc/default"
printf '%s\n' 'SLOTH_ARGS=--site-label attic --victron' > "$stage/eol/etc/default/sloth"
if svc eol && [ "$(warned eol)" -eq 2 ] && grep -qxF -e "      --victron" "$stage/eol.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL a decoder flag at the end of the line was not warned about: $(cat "$stage/eol.out")"; fi

# A receiver with no decoder (#216 review). --gps is not one of the six:
# sloth-wifi takes it and starts, so the warning above stays silent. But
# the GNSS_* alerts, the gnss_fix / gnss_sky / gnss_sat records and the
# gnss_* tables are sloth-rf's alone since the cutover, so a host whose
# sensor has --gps and whose sloth-rf has none stops raising and
# recording them without a word. install-service says so: a NOTE, not
# the WARNING (the sensor starts), naming what stopped and the command
# that copies the flag. Seen red (2026-11-15) with the
# $(note_gps_without_rf) line taken out of the recipe; the three "no
# note" cases with the sloth-rf test, the comment filter and the
# trailing [[:space:]=] each dropped from it in turn.
noted() { grep -c "NOTE: .*etc/default/sloth passes --gps and .*etc/default/sloth-rf does not" "$stage/$1.out"; }
if [ "$(noted alike)" -eq 1 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL --gps with no --gps for sloth-rf was not noted once: $(cat "$stage/alike.out")"; fi
for want in "GNSS_JAMMING" "gnss_fix" "sloth-migrate-rf --apply" "section 11.4"; do
    if grep -qF -e "$want" "$stage/alike.out"; then pass=$((pass + 1));
    else fail=$((fail + 1)); echo "  FAIL the --gps note lacks '$want': $(cat "$stage/alike.out")"; fi
done
# With the decoder warning too, the warning is still the last thing printed.
mkdir -p "$stage/gpsrf/etc/default"
printf '%s\n' 'SLOTH_ARGS=--gps=gpsd://127.0.0.1:2947 --adsb /run/readsb/aircraft.json' > "$stage/gpsrf/etc/default/sloth"
if svc gpsrf && [ "$(noted gpsrf)" -eq 1 ] && [ "$(warned gpsrf)" -eq 2 ] &&
   tail -n 2 "$stage/gpsrf.out" | grep -qF '****'; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL --gps beside a decoder flag: $(cat "$stage/gpsrf.out")"; fi
# sloth-rf already has it (the migration was run): nothing to say.
mkdir -p "$stage/gpsboth/etc/default"
printf '%s\n' 'SLOTH_ARGS=--gps gpsd://127.0.0.1:2947' > "$stage/gpsboth/etc/default/sloth"
printf '%s\n' '# SLOTH_RF_ARGS=--nothing' 'SLOTH_RF_ARGS=--adsb /run/readsb/aircraft.json --gps gpsd://127.0.0.1:2947' > "$stage/gpsboth/etc/default/sloth-rf"
if svc gpsboth && [ "$(noted gpsboth)" -eq 0 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL noted although sloth-rf has --gps: $(cat "$stage/gpsboth.out")"; fi
# No --gps at all, a commented one, and look-alikes (--gps-baud is not --gps).
if [ "$(noted none)" -eq 0 ] && [ "$(noted rfargs)" -eq 0 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL noted with no --gps in the file: $(cat "$stage/none.out" "$stage/rfargs.out")"; fi
mkdir -p "$stage/gpsalike/etc/default"
printf '%s\n' '# SLOTH_ARGS=--gps gpsd://' 'SLOTH_ARGS=--gps-baud 9600 --gpsx 1 --location 1,2' > "$stage/gpsalike/etc/default/sloth"
if svc gpsalike && [ "$(noted gpsalike)" -eq 0 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL noted for a commented or look-alike --gps: $(cat "$stage/gpsalike.out")"; fi
# A --gps commented out in sloth-rf's file is not sloth-rf having it.
mkdir -p "$stage/gpsrfc/etc/default"
printf '%s\n' 'SLOTH_ARGS=--gps gpsd://127.0.0.1:2947' > "$stage/gpsrfc/etc/default/sloth"
printf '%s\n' '# SLOTH_RF_ARGS=--gps gpsd://127.0.0.1:2947' 'SLOTH_RF_ARGS=' > "$stage/gpsrfc/etc/default/sloth-rf"
if svc gpsrfc && [ "$(noted gpsrfc)" -eq 1 ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL a commented --gps in sloth-rf's file silenced the note: $(cat "$stage/gpsrfc.out")"; fi

# The sensor's unit and the binary it runs (#216 review). The unit names
# bin/sloth-wifi since the cutover. A host upgraded from before it has
# bin/sloth, the old binary, and no bin/sloth-wifi until `make install`
# runs: install-service alone would replace a unit that starts with one
# that fails 203/EXEC at the next restart. It refuses, before writing
# anything; with nothing installed there is nothing to disagree with,
# and with the link and its target in place it goes ahead. Seen red (2026-11-15) with the
# check taken out of the recipe (the unit was installed).
mkdir -p "$stage/precut/usr/local/bin"
printf '#!/bin/sh\n' > "$stage/precut/usr/local/bin/sloth"
chmod 755 "$stage/precut/usr/local/bin/sloth"
if svc precut; then fail=$((fail + 1)); echo "  FAIL install-service over a pre-cutover bin/sloth with no bin/sloth-wifi succeeded";
else pass=$((pass + 1)); fi
if grep -qF "usr/local/bin/sloth-wifi" "$stage/precut.out" && grep -qF "'sudo make install'" "$stage/precut.out"; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the refusal does not name sloth-wifi and make install: $(cat "$stage/precut.out")"; fi
if [ ! -e "$stage/precut/etc" ] && [ ! -e "$stage/precut/usr/lib" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL the refused install-service wrote: $(find "$stage/precut" -type f)"; fi
mkdir -p "$stage/postcut/usr/local/bin"
printf '#!/bin/sh\n' > "$stage/postcut/usr/local/bin/sloth-wifi"
chmod 755 "$stage/postcut/usr/local/bin/sloth-wifi"
ln -s sloth-wifi "$stage/postcut/usr/local/bin/sloth"
if svc postcut && [ -f "$stage/postcut/etc/systemd/system/sloth-sensor.service" ]; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL install-service beside bin/sloth-wifi and its link: $(cat "$stage/postcut.out")"; fi
rm -rf "$stage"

echo "install-service-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
