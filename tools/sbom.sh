#!/bin/sh
# CycloneDX 1.5 SBOM for a sloth build (#142). Run as `make sbom`.
#
# The fallback for a host without CI's anchore/sbom-action: it names
# sloth itself and the five libraries the default build links
# (-lncursesw -lpcap -lsqlite3 -lpthread -lm), each at the version this
# host reports. Syft, which CI uses, catalogues package manifests and
# finds none in a C tree that links distro libraries, so this list is
# the one that actually says what a binary depends on.
#
# What it can and cannot claim: the versions are those of the
# development packages on the BUILD host, read with pkg-config. A binary
# copied to another host loads that host's libraries — `sloth --version`
# and sensor_health's `libs` field report what was loaded there.
# pthread and libm are part of the C library, so they carry its version
# (glibc via getconf; "unknown" elsewhere).
#
# Inputs, from the environment:
#   SLOTH_VERSION  required; the Makefile reads it from include/sloth.h
#   PKG_CONFIG     pkg-config binary, default `pkg-config`
#
# Output is deterministic for a given host: no timestamp, no random
# serial number, so two runs can be diffed.

set -eu

: "${SLOTH_VERSION:?SLOTH_VERSION must be set (make sbom sets it)}"
PKG_CONFIG=${PKG_CONFIG:-pkg-config}

# A version lands inside a JSON string. pkg-config output is trusted no
# further than the characters a version can contain; anything else is
# dropped, so a hostile .pc file cannot break out of the string.
clean() {
    printf '%s' "$1" | tr -cd 'A-Za-z0-9._+~-'
}

pc_version() {
    v=""
    if command -v "$PKG_CONFIG" >/dev/null 2>&1; then
        v=$("$PKG_CONFIG" --modversion "$1" 2>/dev/null | head -n 1) || v=""
    fi
    v=$(clean "$v")
    [ -n "$v" ] || v=unknown
    printf '%s' "$v"
}

libc_version() {
    v=$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n 's/^glibc //p') || v=""
    v=$(clean "$v")
    [ -n "$v" ] || v=unknown
    printf '%s' "$v"
}

component() {
    # name, version, what supplies it, trailing comma or not
    printf '    {\n'
    printf '      "type": "library",\n'
    printf '      "bom-ref": "%s",\n' "$1"
    printf '      "name": "%s",\n' "$1"
    printf '      "version": "%s",\n' "$2"
    printf '      "scope": "required",\n'
    printf '      "properties": [ { "name": "sloth:version-source", "value": "%s" } ]\n' "$3"
    printf '    }%s\n' "$4"
}

SV=$(clean "$SLOTH_VERSION")
NC=$(pc_version ncursesw)
PC=$(pc_version libpcap)
SQ=$(pc_version sqlite3)
LC=$(libc_version)

printf '{\n'
printf '  "bomFormat": "CycloneDX",\n'
printf '  "specVersion": "1.5",\n'
printf '  "version": 1,\n'
printf '  "metadata": {\n'
printf '    "component": {\n'
printf '      "type": "application",\n'
printf '      "bom-ref": "sloth",\n'
printf '      "name": "sloth",\n'
printf '      "version": "%s",\n' "$SV"
printf '      "licenses": [ { "license": { "name": "SLOTH SOURCE-AVAILABLE LICENSE 1.0" } } ]\n'
printf '    }\n'
printf '  },\n'
printf '  "components": [\n'
component ncursesw  "$NC" pkg-config ,
component libpcap   "$PC" pkg-config ,
component sqlite3   "$SQ" pkg-config ,
component libpthread "$LC" libc ,
component libm      "$LC" libc ""
printf '  ],\n'
printf '  "dependencies": [\n'
printf '    { "ref": "sloth", "dependsOn": [ "ncursesw", "libpcap", "sqlite3", "libpthread", "libm" ] }\n'
printf '  ]\n'
printf '}\n'
