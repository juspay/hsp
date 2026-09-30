#!/usr/bin/env bash
# `hsp symmap' reading IPE out of the ELF: that a zstd-compressed node (what
# GHC emits when built with HAVE_LIBZSTD=1) yields the same entries as the
# uncompressed one, and that the GHC version is recognised.  No root.
#
#   tests/ipe.sh [BINARY]        # default: the ghc984 smoke program
#
# A GHC configured without zstd never emits a compressed node, so the fixture
# is made by recompressing a real binary's node in place (tests/mkzstd-ipe.py):
# the frames are smaller than the blobs they replace, and a frame carries its
# own length, so the addresses and the DEcompressed sizes stay as they were --
# exactly the shape rts/IPE.c decompressIPEBufferListNodeIfCompressed expects.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HSP=${HSP:-$HERE/../build/hsp}
BIN=${1:-$HERE/smoke/build/ghc984/hsp-testprog}
[ -x "$HSP" ] || { echo "no $HSP -- run make first"; exit 1; }
[ -f "$BIN" ] || { echo "no $BIN -- run tests/smoke/build.sh, or pass a binary"; exit 0; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
check() { if [ "$1" = 0 ]; then echo "  ok   $2"; else echo "  FAIL $2"; fail=1; fi; }

"$HSP" symmap "$BIN" "$T/plain.hsm" > "$T/plain.out" 2>&1
grep -E "^(GHC|IPE) " "$T/plain.out"
base=$(sed -n 's/^IPE \([0-9]*\) entries.*/\1/p' "$T/plain.out")
ver=$(sed -n 's/^GHC \(.*\)$/\1/p' "$T/plain.out")
[ "${base:-0}" -gt 0 ] || { echo "$BIN has no IPE (built without -finfo-table-map?); nothing to test"; exit 0; }

check "$([ "$ver" != "0.0" ] && echo 0 || echo 1)" "GHC version recognised (got '$ver', not 0.0)"

python3 "$HERE/mkzstd-ipe.py" "$BIN" "$T/z" > "$T/mk.out" 2>&1
check $? "fixture built (node recompressed in place)"
sed -n 's/^  *entries/     entries/p' "$T/mk.out"

"$HSP" symmap "$T/z" "$T/z.hsm" > "$T/z.out" 2>&1
grep -E "^(GHC|IPE) " "$T/z.out"
got=$(sed -n 's/^IPE \([0-9]*\) entries.*/\1/p' "$T/z.out")
check "$([ "${got:-0}" = "$base" ] && echo 0 || echo 1)" "compressed node gives the same $base entries (got ${got:-0})"
check "$(grep -q '1 zstd-compressed (decompressed)\|[1-9][0-9]* zstd-compressed (decompressed)' "$T/z.out" && echo 0 || echo 1)" \
      "the node really was compressed (and was decompressed)"

# the two maps may differ only in the exe id (a SHA-256 of the file): 32 bytes
d=$(cmp -l "$T/plain.hsm" "$T/z.hsm" 2>/dev/null | wc -l)
check "$([ "$d" -le 32 ] && echo 0 || echo 1)" "maps differ only in the exe id ($d bytes)"

[ $fail = 0 ] && echo "tests/ipe.sh: all checks passed" || echo "tests/ipe.sh: FAILURES"
exit $fail
