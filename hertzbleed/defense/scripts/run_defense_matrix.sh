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
#   DEFENSES="prand_8_30 prand_22_30" ...   # random P-state over ratios A..B
#   POWERLOG=1 ...                          # turbostat Busy%/MHz/PkgWatt per defense -> <d>_power.txt
#
# Pre-req (see CLAUDE.md "Experiment protocol"): idle node, hbctl.sh quiet,
# RAPL set so the CPU throttles, warm-up. pstate_* defenses additionally need
# hbctl.sh pstate-check == HONORED (NOT the case on HPE m510).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=$ROOT/06-circl/circl/dh/sidh/POC_ATTACK/sike_local
AVG=$ROOT/defense/analysis/averaging_curve.py
PY=$ROOT/venv/bin/python; [[ -x $PY ]] || PY=python3

KEY=${KEY:-1}; BIT=${BIT:-2}; THREADS=${THREADS:-300}; ITERS=${ITERS:-100}; ROUNDS=${ROUNDS:-10}
OUT=${OUT:-$ROOT/defense/data/matrix-$(hostname -s)-$(date +%m%d-%H%M)}
NCPU=$(nproc)
# P-state backend: hwp on HWP-enabled CPUs (IA32_PM_ENABLE=1, e.g. c220g5), else msr.
if [[ -z ${PSTATE_BACKEND:-} ]]; then
  PSTATE_BACKEND=msr
  (( 0x$(sudo rdmsr -p0 0x770 2>/dev/null || echo 0) & 1 )) && PSTATE_BACKEND=hwp
fi

declare -A ENVS=(
  [none]=""
  [chunk14]="HB_STAGES=14"
  [pipeline14]="HB_STAGES=14 HB_WORKERS=$NCPU"
  [pipeline27]="HB_STAGES=27 HB_WORKERS=$NCPU"
  [pstate_rand14]="HB_STAGES=14 HB_WORKERS=$NCPU HB_PSTATE_RAND=1 HB_PSTATE_BACKEND=$PSTATE_BACKEND"
  [pstate_rand14_nw]="HB_STAGES=14 HB_PSTATE_RAND=1 HB_PSTATE_BACKEND=$PSTATE_BACKEND"
  # ratios capped so the package stays under a lowered RAPL PL1 (forced P is only a ceiling)
  [pstate_rand14_lo]="HB_STAGES=14 HB_PSTATE_RAND=1 HB_PSTATE_BACKEND=$PSTATE_BACKEND HB_PSTATE_RATIOS=${LO_RATIOS:-8,9,10,11,12,13,14,15,16}"
  [noise50us]="HB_NOISE_NS=50000"
  [noise1ms]="HB_NOISE_NS=1000000"
  [blind]="HB_BLIND=1"
)
DEFENSES=${DEFENSES:-"none chunk14 pipeline14 pipeline27 noise50us noise1ms blind"}

[[ -x $BIN ]] || { echo "build sike_local first (see CLAUDE.md)"; exit 1; }
mkdir -p "$OUT"
{ echo "host=$(hostname) date=$(date -Is) key=$KEY bit=$BIT threads=$THREADS iters=$ITERS rounds=$ROUNDS pstate_backend=$PSTATE_BACKEND"
  "$HERE/hbctl.sh" status 2>/dev/null || true; } > "$OUT/meta.txt"

for d in $DEFENSES; do
  # prand_A_B = random P-state per chunk (14 chunks, no worker pool), ratios A..B
  if [[ $d =~ ^prand_([0-9]+)_([0-9]+)$ ]]; then
    ENVS[$d]="HB_STAGES=14 HB_PSTATE_RAND=1 HB_PSTATE_BACKEND=$PSTATE_BACKEND HB_PSTATE_RATIOS=$(seq -s, ${BASH_REMATCH[1]} ${BASH_REMATCH[2]})"
  fi
  [[ -v ENVS[$d] ]] || { echo "unknown defense $d"; exit 1; }
  tspid=
  if [[ -n ${POWERLOG:-} && -z ${DRY:-} ]]; then
    sudo turbostat -q -s Package,Busy%,Bzy_MHz,PkgWatt -i 5 > "$OUT/${d}_power.txt" 2>&1 & tspid=$!
  fi
  for r in $(seq 1 "$ROUNDS"); do
    for flip in 0 1; do
      cmd="env ${ENVS[$d]} $BIN $flip $KEY $BIT $THREADS $ITERS"
      [[ $d == pstate_* || $d == prand_* ]] && cmd="sudo $cmd"
      echo "[$d r$r f$flip] $cmd"
      [[ -n ${DRY:-} ]] && continue
      $cmd | tee -a "$OUT/${d}_f${flip}.log" | grep '^ALL_DURATION' >> "$OUT/${d}_f${flip}.txt"
    done
  done
  [[ -n $tspid ]] && { sudo pkill -f "turbostat -q -s Package" || true; wait $tspid 2>/dev/null || true; }
  [[ ($d == pstate_* || $d == prand_*) && $PSTATE_BACKEND == hwp && -z ${DRY:-} ]] && "$HERE/hbctl.sh" hwp-reset >/dev/null
  [[ -n ${DRY:-} ]] || $PY "$AVG" "$OUT/${d}_f0.txt" "$OUT/${d}_f1.txt" --label "$d" \
      --csv "$OUT/${d}_avg.csv" | tee "$OUT/${d}_avg.txt"
done
echo "results in $OUT"
