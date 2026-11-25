#!/usr/bin/env bash
# c220g5 Class 2 eval at the leaking RAPL point (45 W/package).
HB=~/Heart/hertzbleed/defense/scripts
$HB/hbctl.sh quiet; $HB/hbctl.sh rapl-set 45
trap '$HB/hbctl.sh hwp-reset; $HB/hbctl.sh rapl-restore' EXIT
OUT=${OUT:-~/Heart/hertzbleed/defense/data/matrix-c220g5-class2-$(date +%m%d-%H%M)} ROUNDS=6 \
  DEFENSES=${DEFENSES:-"none pstate_rand14_lo pstate_rand14_nw pstate_rand14"} $HB/run_defense_matrix.sh
