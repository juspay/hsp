#!/usr/bin/env bash
# Live test of `hsp record' on tests/testprog (needs root for BPF +
# perf_event): sample it, fold the capture, check the shape.
#
#   tests/smoke/build.sh                        # once: program + map per GHC (no root)
#   sudo tests/smoke.sh [ghc984|ghc98|ghc910|ghc928] [secs] [hz]
#
# Part 1, `hsp-testprog smoke': what must hold, and why each line matters:
#   labels     every walked sample carries rid:allocy|chatty|deep -- the
#              TSO label read (off_curtso, off_label) is right
#   chatty     `child' is a leaf under `chatty' -- the walk sees callers
#   deep       samples with depth >= 300 that reached STOP_FRAME -- the walk
#              crosses chunk boundaries and the depth cap is not in the way
#   alloc      bytes attributed to rid:allocy -- alloc_limit and the nursery
#              offsets are right
#   cost       median in-kernel cost per sample under 5 us
# Part 2, `hsp-testprog requests 24': each request thread prints its own
# exact allocation; the bytes hsp attributes to each rid:req-<i> label must
# track it (correlation >= 0.95, total within 30%: hsp misses what a thread
# allocates before its first and after its last sample).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HSP=${HSP:-$HERE/../build/hsp}
V=${1:-ghc984} SECS=${2:-2} HZ=${3:-499}
S=$HERE/smoke/build/$V
[ "$(id -u)" = 0 ] || { echo "needs root: sudo $0 $*"; exit 1; }
[ -x "$S/hsp-testprog" ] && [ -f "$S/testprog.hsm" ] || { echo "run tests/smoke/build.sh $V first"; exit 1; }
OUT=$S/live; rm -rf "$OUT"; mkdir -p "$OUT/smoke" "$OUT/requests"

fail=0
check() { if [ "$1" = 0 ]; then echo "  ok   $2"; else echo "  FAIL $2"; fail=1; fi; }
record_fold() {  # dir, program args...
  local d=$1; shift
  "$HSP" record -F "$HZ" -o "$d/cap.bin" -- "$S/hsp-testprog" "$@" 2> "$d/record.err" > "$d/prog.out"; local rc=$?
  cat "$d/record.err"
  [ $rc = 0 ] || { echo "record exited $rc"; exit 1; }
  "$HSP" fold "$d/cap.bin" "$S/testprog.hsm" "$d" --no-lines > "$d/agg.txt"; frc=$?
  grep -E '^samples in|status:|depth min|walk cost|green-thread|allocation \(' "$d/agg.txt"
}

echo "== $V: smoke ($SECS s per region, $HZ Hz)"
O=$OUT/smoke; record_fold "$O" smoke "$SECS"
n=$(grep -oE '^samples in .text: [0-9]+' "$O/agg.txt" | grep -oE '[0-9]+$')
check $(( n >= SECS * 3 * HZ / 4 ? 0 : 1 )) "samples: $n (expected >= $((SECS * 3 * HZ / 4)) for $((SECS*3)) s at $HZ Hz)"
# GHC 9.2 keeps no thread label in the TSO: its checks read the unlabelled files
LABELS=1; [ "$V" = ghc928 ] && LABELS=0
if [ $LABELS = 1 ]; then
  rid=$(grep -oE 'rid [0-9]+ \([0-9.]+%\)' "$O/agg.txt" | grep -oE '\([0-9.]+' | tr -d '(' | cut -d. -f1)
  check $(( ${rid:-0} >= 80 ? 0 : 1 )) "labels: ${rid:-0}% of samples on a rid: thread (expected >= 80)"
  for l in allocy chatty deep; do
    c=$(grep -c "^rid:$l;" "$O/collapsed-labelled.txt"); check $(( c > 0 ? 0 : 1 )) "rid:$l seen ($c stacks)"
  done
  CPU=$O/collapsed-labelled.txt ALLOC=$O/collapsed-alloc-labelled.txt
else
  echo "  (no thread labels on GHC 9.2: label checks skipped)"
  CPU=$O/collapsed.txt ALLOC=$O/collapsed-alloc.txt
fi
# child may appear as its worker $wchild (IPE name) or rolled up to child (symtab map)
c=$(grep -E 'Main\.chatty;Main\.(\$w)?child ' "$CPU" | awk '{s+=$NF} END{print s+0}')
check $(( c > 0 ? 0 : 1 )) "chatty: child is a leaf under chatty ($c samples)"
# a collapsed line is "f1;f2;...;leaf COUNT": the count follows the last space
d=$(grep -E 'Main\.deep' "$CPU" | awk -F';' 'NF>=300{n=split($NF,a," "); s+=a[n]} END{print s+0}')
check $(( d > 0 ? 0 : 1 )) "deep: stacks of >= 300 frames reached STOP ($d samples)"
a=$(grep -E 'Main\.allocy' "$ALLOC" | awk '{s+=$NF} END{print s+0}')
check $(( a > 1000000 ? 0 : 1 )) "alloc: $a bytes attributed to allocy (expected > 1 MB)"
p50=$(grep -oE 'walk cost ns +p50 [0-9]+' "$O/agg.txt" | awk '{print $NF}' | head -1)
check $(( ${p50:-999999} < 5000 ? 0 : 1 )) "cost: median walk ${p50:-?} ns (expected < 5000)"
check $frc "fold exit $frc (resolution gate)"

if [ $LABELS = 1 ]; then   # per-request attribution needs labels
echo "== $V: requests (24, 4 at a time)"
O=$OUT/requests; record_fold "$O" requests 24
res=$(python3 - "$O" <<'PY'
import collections, math, sys
d = sys.argv[1]
logged = {}
for line in open(f"{d}/prog.out"):
    p = line.split()
    if len(p) == 4 and p[0] == "request" and p[2] == "alloc_bytes":
        logged[p[1]] = int(p[3])
sampled = collections.Counter()
for line in open(f"{d}/collapsed-alloc-labelled.txt"):
    st, _, n = line.rstrip("\n").rpartition(" ")
    root = st.split(";", 1)[0]
    if root.startswith("rid:req-") and "|" not in root:      # the request thread, not its fork
        sampled[root[4:]] += int(n)
xs = [(sampled[k], v) for k, v in logged.items()]
if len(xs) < 4:
    print("0 0 0 0"); sys.exit()
mx = sum(a for a, _ in xs) / len(xs); my = sum(b for _, b in xs) / len(xs)
cov = sum((a - mx) * (b - my) for a, b in xs)
va = sum((a - mx) ** 2 for a, _ in xs); vb = sum((b - my) ** 2 for _, b in xs)
r = cov / math.sqrt(va * vb) if va and vb else 0
ratio = sum(a for a, _ in xs) / sum(b for _, b in xs)
print(f"{len(logged)} {sum(1 for k in logged if sampled[k])} {r:.3f} {ratio:.2f}")
PY
)
read -r nreq nseen r ratio <<< "$res"
check $(( nreq == 24 ? 0 : 1 )) "requests: $nreq/24 reported their allocation"
check $(( nseen == nreq && nreq > 0 ? 0 : 1 )) "requests: $nseen/$nreq have allocation attributed by hsp"
check $(python3 -c "print(0 if $r >= 0.95 else 1)") "per-request allocation, hsp vs the thread's own counter: r = $r (expected >= 0.95)"
check $(python3 -c "print(0 if 0.7 <= $ratio <= 1.3 else 1)") "per-request allocation total, hsp / counter = $ratio (expected 0.7-1.3)"
check $frc "fold exit $frc (resolution gate)"

fi
[ $fail = 0 ] && echo "SMOKE OK ($V)" || { echo "SMOKE FAILED ($V: $OUT)"; exit 1; }
