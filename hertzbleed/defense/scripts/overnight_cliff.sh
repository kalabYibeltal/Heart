#!/usr/bin/env bash
# Unattended finish of the 2026-11-25 cliff sweep (run inside tmux session "hb").
# Runs prand_12_30 + prand_14_30 into the existing dir, appends an AUTO summary to
# CLAUDE.md, commits locally, tries to push. Log: ~/overnight_cliff.log
D=/users/kalab/Heart/hertzbleed/defense/data/matrix-c220g5-cliff-1125-0107
H=~/Heart/hertzbleed
POWERLOG=1 OUT=$D DEFENSES="prand_12_30 prand_14_30" $H/defense/scripts/class2_eval.sh
{
  echo "- [x] $(date +%F) CLIFF SWEEP finished UNATTENDED (overnight_cliff.sh). AUTO-GENERATED,"
  echo "      NOT YET REVIEWED. Data: $D. Raw averaging_curve headers:"
  for d in none prand_10_30 prand_12_30 prand_14_30; do
    [[ -f $D/${d}_avg.txt ]] && echo "        $(head -1 $D/${d}_avg.txt | sed 's/^# //')  $(grep K99 $D/${d}_avg.txt | cut -d' ' -f1-3)"
  done
  echo "      Reminder: d's SE ≈ 0.058 at N=599, so d<~0.12 is not significant."
} > /tmp/cliff_summary.txt
python3 - "$H/CLAUDE.md" /tmp/cliff_summary.txt <<'PY'
import sys
p, s = sys.argv[1], open(sys.argv[2]).read()
t = open(p).read()
key = "- [ ] RUNNING 2026-11-25: CLIFF SWEEP"
i = t.find(key)
t = t[:i] + s + t[i:].replace(key, "- (done, see AUTO block above) 2026-11-25: CLIFF SWEEP", 1) if i >= 0 else t + "\n" + s
open(p, "w").write(t)
PY
cd ~/Heart && git add -A hertzbleed && git commit -q -m "c220g5: cliff sweep results (unattended run)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && echo "COMMITTED $(git log --oneline -1)"
timeout 30 git push && echo PUSHED || echo "PUSH FAILED (no GitHub credentials on node): run 'git push' in ~/Heart"
echo "DONE $(date)"
