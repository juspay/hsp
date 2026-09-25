#!/usr/bin/env bash
# Build the test program (tests/testprog, a haskell-flake package) for one or
# both GHCs, and its name map (no root).
#
#   tests/smoke/build.sh              # ghc984 (pinned) and ghc910
#   tests/smoke/build.sh ghc98 ...    # any of ghc984, ghc98, ghc910
#   GHC928=/path/to/ghc-9.2.8 tests/smoke/build.sh ghc928
#                                     # 9.2 is no longer in nixpkgs: built with that ghc directly
#
# Output: tests/smoke/build/<ghc>/{hsp-testprog, testprog.hsm}
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HSP=${HSP:-$HERE/../../build/hsp}
[ -x "$HSP" ] || { echo "build hsp first (nix develop -c make)"; exit 1; }
variants=("$@"); [ ${#variants[@]} -gt 0 ] || variants=(ghc984 ghc910)
for v in "${variants[@]}"; do
  d=$HERE/build/$v; mkdir -p "$d"
  if [ "$v" = ghc928 ]; then
    [ -x "${GHC928:-}/bin/ghc" ] || { echo "ghc928: set GHC928 to a GHC 9.2.8 installation"; exit 1; }
    # 9.2 has no -finfo-table-map-with-stack (its -finfo-table-map covers stack frames)
    "$GHC928/bin/ghc" -O2 -threaded -rtsopts -finfo-table-map -fexpose-internal-symbols -g1 \
      -outputdir "$d/o" -o "$d/hsp-testprog" "$HERE/../testprog/app/Main.hs" > "$d/ghc.log" 2>&1 || { cat "$d/ghc.log"; exit 1; }
    "$HSP" symmap "$d/hsp-testprog" "$d/testprog.hsm"
    echo "$v: $GHC928 -> $d/testprog.hsm"
    continue
  fi
  out=$(nix build "$HERE/../testprog#$v-hsp-testprog" --no-link --print-out-paths)
  ln -sfn "$out/bin/hsp-testprog" "$d/hsp-testprog"
  if [[ "$v" == ghc98* ]]; then
    # 9.8's static IPE nodes are read straight from the ELF
    "$HSP" symmap "$d/hsp-testprog" "$d/testprog.hsm"
  else
    # 9.10 lays its static IPE nodes out differently; take the table from an
    # eventlog instead: one short run with +RTS -l
    ( cd "$d" && rm -f hsp-testprog.eventlog && ./hsp-testprog smoke 0.1 +RTS -l -RTS > /dev/null )
    "$HSP" symmap "$d/hsp-testprog" "$d/testprog.hsm" --eventlog "$d/hsp-testprog.eventlog"
  fi
  echo "$v: $out -> $d/testprog.hsm"
done
