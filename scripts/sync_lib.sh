#!/usr/bin/env bash
set -euo pipefail

LIB_REPO=${1:-git@github.com:ELF-Nigel/keyauth-cpp-library-1.3API.git}
DEST_X86=${2:-x86/lib}
DEST_X64=${3:-x64/lib}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git clone --depth 1 "$LIB_REPO" "$WORK"

mkdir -p "$DEST_X86" "$DEST_X64"
rm -rf "$DEST_X86"/* "$DEST_X64"/*
cp -R "$WORK"/* "$DEST_X86"/
cp -R "$WORK"/* "$DEST_X64"/

echo "Synced KeyAuth library into $DEST_X86 and $DEST_X64"
