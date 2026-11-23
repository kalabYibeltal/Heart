#!/usr/bin/env bash
# run_defense_matrix.sh — timing-variant local POC under each defense config.
#
# For every defense in DEFENSES and every round, runs sike_local with flip=0
# and flip=1 (alternating, to cancel slow drift) and appends the per-iteration
# ALL_DURATION lines to $OUT/<defense>_f<flip>.txt. Then runs
# averaging_curve.py on each pair.
#
#   ./run_defense_matrix.sh                 # all defenses, defaults below
#   DEFENSES="none noise50us" ROUNDS=5 ./run_defense_matrix.sh
#   DRY=1 ./run_defense_matrix.sh           # print commands only
#
# Pre-req (see CLAUDE.md "Experiment protocol"): idle node, hbctl.sh quiet,
# RAPL set so the CPU throttles, warm-up. pstate_* defenses additionally need
# hbctl.sh pstate-check == HONORED (NOT the case on HPE m510).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=$ROOT/06-circl/circl/dh/sidh/POC_ATTACK/sike_local
AVG=$ROOT/defense/analysis/averaging_curve.py

KEY=${KEY:-1}; BIT=${BIT:-2}; THREADS=${THREADS:-300}; ITERS=${ITERS:-100}; ROUNDS=${ROUNDS:-10}
OUT=${OUT:-$ROOT/defense/data/matrix-$(hostname -s)-$(date +%m%d-%H%M)}
NCPU=$(nproc)

declare -A ENVS=(
  [none]=""
  [chunk14]="HB_STAGES=14"
  [pipeline14]="HB_STAGES=14 HB_WORKERS=$NCPU"
  [pipeline27]="HB_STAGES=27 HB_WORKERS=$NCPU"
  [pstate_rand14]="HB_STAGES=14 HB_WORKERS=$NCPU HB_PSTATE_RAND=1"
  [noise50us]="HB_NOISE_NS=50000"
  [noise1ms]="HB_NOISE_NS=1000000"
  [blind]="HB_BLIND=1"
)
DEFENSES=${DEFENSES:-"none chunk14 pipeline14 pipeline27 noise50us noise1ms blind"}

[[ -x $BIN ]] || { echo "build sike_local first (see CLAUDE.md)"; exit 1; }
mkdir -p "$OUT"
{ echo "host=$(hostname) date=$(date -Is) key=$KEY bit=$BIT threads=$THREADS iters=$ITERS rounds=$ROUNDS"
  "$HERE/hbctl.sh" status 2>/dev/null || true; } > "$OUT/meta.txt"

for d in $DEFENSES; do
  [[ -v ENVS[$d] ]] || { echo "unknown defense $d"; exit 1; }
  for r in $(seq 1 "$ROUNDS"); do
    for flip in 0 1; do
      cmd="env ${ENVS[$d]} $BIN $flip $KEY $BIT $THREADS $ITERS"
      [[ $d == pstate_* ]] && cmd="sudo $cmd"
      echo "[$d r$r f$flip] $cmd"
      [[ -n ${DRY:-} ]] && continue
      $cmd | tee -a "$OUT/${d}_f${flip}.log" | grep '^ALL_DURATION' >> "$OUT/${d}_f${flip}.txt"
    done
  done
  [[ -n ${DRY:-} ]] || python3 "$AVG" "$OUT/${d}_f0.txt" "$OUT/${d}_f1.txt" --label "$d" \
      --csv "$OUT/${d}_avg.csv" | tee "$OUT/${d}_avg.txt"
done
echo "results in $OUT"
