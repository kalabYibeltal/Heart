# Hertzbleed Defense Characterization — Project Context
Following on the paper https://www.hertzbleed.com/hertzbleed.pdf

## Goal
Characterization + evaluation paper on the CLASS of defenses against
Hertzbleed (DVFS frequency side-channel, CVE-2022-24436). Target venues:
IISWC or ISPASS. Thesis: a four-axis characterization (performance,
security, developing effort, backward compatibility) of the defense space,
plus scoped formal results on why frequency-SCHEDULING defenses cannot
close the channel.

## What's already established (DO NOT re-derive, build on these)
- Baseline attack reproduced: local SIKE POC in CIRCL shows frequency
  separation between m_i==m_{i-1} (slower, lower freq) and m_i!=m_{i-1}
  (anomalous zero → less power → higher freq → faster).
- Hardware: tested on i5-8250U laptop (throttles naturally) and
  i7-10700K / Xeon E5-2640v4 (need RAPL power cap ~45W to force throttle).
- KEY PHYSICS FINDINGS (these drive the paper):
  1. Client CPUs share ONE voltage/frequency domain → no "quiet core"
     to hide low-power work on. Confirmed i5-8250U.
  2. DVFS reacts on ~1ms windows (running average), far coarser than a
     14-iteration ladder chunk (~22us) → sub-window scheduling is
     invisible to the channel.
  3. P-state transition latency ~20-70us > chunk runtime → per-chunk
     frequency randomization is physically too slow.
  4. Software P-state is a CEILING not a guarantee: high-power (normal)
     data gets throttled below a requested high P-state unless RAPL
     limit is raised. So forcing needs raised RAPL to actually hold.
  5. Any defense leaving the MEAN power/time secret-dependent is
     defeated by N-sample averaging (information-theoretic, à la
     Goldilocks).

## Defense taxonomy (5 classes, by which link in the chain they break)
chain: secret -> data-dependent power -> DVFS reaction -> freq change ->
       timing change -> observation
1. Make power secret-independent: masking, blinding, constant-weight,
   ciphertext validation (De Feo, deployed in CIRCL). ← root cause, works.
2. Make frequency secret-independent: disable turbo, Goldilocks (S&P'26,
   O(log t), ~2.75%), A-DVFS. Plus MY candidate: randomized forced-P-state
   scheduling (raise RAPL so it holds; random P per epoch; lower AVG
   latency than pinning).
3. Scheduling / work placement: pipeline core-interleave (I SHOWED FAILS),
   Gosched yield (I SHOWED WORSE), borrow-neighbor-entropy (fails under
   uniform attack), compensating dummy load (untested). RDVFS (2014,
   hardware analog, shown to fail). 
4. Reduce observation: restrict RAPL, rate-limit, noise injection
   (averageable/weak).
5. Key management: rotation/refresh (limits damage, doesn't close channel).

Further explanation 
## Class 3 — Scheduling / work placement (NO P-state control)
Split the 378-iteration Montgomery ladder into N chunks (N a divisor
of 378: 14/18/21/27), then pipeline/interleave chunks across cores,
letting hardware DVFS pick frequency normally. Goal: dilute any single
request's power contribution in the package aggregate.
Variants tried:
  - pipeline core-interleave → SHOWN FAILS (shared freq domain +
    ~1ms DVFS averaging)
  - Gosched cooperative yield → SHOWN WORSE (extends time in
    low-power state)
  - borrow-neighbor-entropy (resume chunk on a core whose freq was
    set by prior unrelated work) → fails under uniform attack traffic
    (all cores doing same secret-dependent work → correlated freqs)
  - compensating dummy high-power load in same ~1ms window → UNTESTED,
    could flatten package power, application-level
  - RDVFS (Avirneni/Somani 2014) = hardware analog, shown to fail due
    to one-to-one V-f mapping (= our shared-domain finding)
Core reason the pure-scheduling class cannot close the channel:
  you never change WHAT frequency the leaky work runs at — you only
  move it — and on a shared domain over a coarse window, moving it
  changes nothing the attacker observes.

## Class 2 addition — randomized FORCED P-state (my positive candidate)
This is SEPARATE from Class 3: here we explicitly SET frequency.
Split ladder into chunks/epochs; at each, set a RANDOM P-state
(requires raising RAPL limit so the forced P actually holds against
high-power data). Now time = Σ(const_cycles / my_random_f), which is
data-independent → closes the frequency channel like Goldilocks but
with lower AVERAGE latency via randomization vs pinning.
Open risks: transition latency bounds granularity; residual
power leaks (uncore/thermal/Thread Director); must verify the MEAN is
truly data-independent (else averageable).

## Class 1 — constant-weight coding (describe + cite, don't implement)
Encode data so every operand has fixed Hamming weight (e.g.
complementary/dual-rail: bit b → pair (b,¬b), so HW always = half the
bits). Makes the HW-component of power secret-independent.
Costs: 2x space, special HW-preserving arithmetic (brutal for SIKE
F_p² ops), breaks backward compat → high human effort.
IMPORTANT CAVEAT for our characterization: closes the Hamming-WEIGHT
channel but NOT the Hamming-DISTANCE (bit-transition) channel. Partial
defense. Good example of "which sub-channel does each defense actually
close" — a fine-grained axis reviewers will value.

## CloudLab quickstart (NEW NODE / NEW SESSION: START HERE)
Repo: github.com/kalabYibeltal/Heart (this file = Heart/hertzbleed/CLAUDE.md).
The patched CIRCL tree (1fc3638 + circl.patch + defense code) is committed
directly under 06-circl/circl/, so there is no need to clone or patch.
```sh
git clone https://github.com/kalabYibeltal/Heart.git ~/Heart
bash ~/Heart/hertzbleed/defense/setup-cloudlab.sh   # idempotent, ~3 min
```
setup-cloudlab.sh installs: apt `build-essential stress-ng msr-tools
cpufrequtils linux-tools-common linux-tools-$(uname -r) python3-venv`;
Go 1.21.13 to /usr/local/go (adds PATH to ~/.bashrc; Ubuntu 20.04's apt
golang is too old); `modprobe msr`; python venv at hertzbleed/venv from
defense/requirements.txt (numpy scipy matplotlib seaborn pandas). It then
builds 06-circl/local driver, sike_local/server/client, microbench, runs
the p751 tests, and runs `hbctl.sh pstate-check`.
Manual equivalents:
- `export PATH=$PATH:/usr/local/go/bin`
- Tests: `cd 06-circl/circl && go test -count=1 ./dh/sidh/internal/p751/`
  (the `dh/sidh` pkg itself needs `go test -vet=off`: the POC's Println calls fail Go 1.21 vet)
- POC: `cd 06-circl/circl/dh/sidh/POC_ATTACK && go build -o sike_local sike_local.go`
  (build ONE FILE at a time; the three POC mains share a package dir)
- Root + `sudo modprobe msr` are needed for MSR, RAPL sysfs, and P-state writes.
- To apply only the defense code onto a fresh upstream+circl.patch tree:
  `patch -p1 < ../defense.patch` (06-circl/defense.patch, regenerate with
  `git diff --relative=hertzbleed/06-circl/circl -- hertzbleed/06-circl/circl`).

## Code layout (defense project)
- `06-circl/circl/dh/sidh/internal/p751/defense.go`: ALL defense code.
  - `ScalarMul3Pt` is now a DISPATCHER; the untouched original is
    `scalarMul3PtRef` in curve.go (the oracle for tests). With no HB_* env
    set, behaviour is identical to upstream.
  - `LadderState`, `NewLadderState`, `ScalarMul3PtChunk(st,start,end)` (no
    final cswap), `FinishLadder` (final cswap, always in the CALLER),
    `ChunkBounds(nbits, stages)` (any stages works; 14/18/21/27 equal for 378).
  - Worker pool: per-worker queues, `runtime.LockOSThread` +
    `unix.SchedSetaffinity`; chunk k of request → worker (offset+k)%W
    (pipeline core-interleave). `StartWorkers(n)` wrapper kept.
  - Class 2 randomized forced P-state: random ratio (crypto/rand) before
    every chunk; backends `msr` (IA32_PERF_CTL 0x199) / `sysfs`
    (scaling_min/max) / `fake` (tests); default ratios = min..max non-turbo
    from MSR 0xCE; scope `cpu` or `all`.
  - Class 4 noise: busy-spin U[0, HB_NOISE_NS] after each top-level ladder.
  - Class 1 blinding: P'=P+[r]Q, m'=m−r mod ord(Q) (2^372 for A, 3^239
    for B), final ladder on x(P'), x(Q), x(P'−Q)=x(P+[r−1]Q); this costs 3 ladders.
    The big.Int scalar math is NOT constant-time (prototype).
  - `GetDefenseStats()` counters: ladders, chunks, P-state writes/errors.
- `.../p751/defense_test.go`: TestChunkedLadderMatchesOriginal (exact X/Z,
  stages 1..378, workers, P-state fake), TestBlindedLadderMatchesOriginal
  (projective eq, both sides), TestSharedSecretUnderDefenses (end-to-end
  SIDH ss), noise, chunk bounds, P-state write count. BenchmarkLadderDefenses.
- `POC_ATTACK/sike_local.go`, `sike_server.go`: call `GOMAXPROCS(NumCPU)` +
  `p751.ConfigureFromEnv()` at the top of main and print a `DEFENSE ...` line;
  sike_local prints `DEFENSE_STATS` at the end.
- `defense/scripts/hbctl.sh`: status | rapl-set W [W2] | rapl-raise |
  rapl-restore | turbo on|off | pin-min | unpin | pstate-passive |
  pstate-active | perfctl R | pstate-check | quiet
- `defense/scripts/freqlog.py`: per-CPU scaling_cur_freq + pkg energy_uj every N ms → CSV.
- `defense/scripts/run_defense_matrix.sh`: sike_local flip 0/1 alternating per defense
  → `defense/data/matrix-<host>-<date>/` (gitignored) + averaging curves. `DRY=1` prints commands only.
- `defense/analysis/averaging_curve.py`: accuracy vs K (bootstrap + Gaussian
  Φ(d√K/2)), Welch t, K99, time-to-key; parses ALL_DURATION lines or numbers.
- `defense/microbench/pstate_latency.c`: P-state transition latency via
  constant-cycle loop + rdtsc after PERF_CTL write (needs HONORED node).

## Defense selection (env vars, read by sike_local / sike_server)
HB_STAGES=N  HB_WORKERS=W  HB_WORKER_CPUS=0-7,..  HB_PSTATE_RAND=1
HB_PSTATE_RATIOS=8,12,20  HB_PSTATE_BACKEND=msr|sysfs  HB_PSTATE_SCOPE=cpu|all
HB_NOISE_NS=50000  HB_BLIND=1   (can be combined; P-state needs sudo)
e.g. `HB_STAGES=14 HB_WORKERS=16 ./sike_local 0 1 2 300 100`

## Correctness invariant
Every defense MUST produce the same result as the original ladder:
TestChunkedLadderMatchesOriginal (bit-identical R1.X/R1.Z) and
TestBlindedLadderMatchesOriginal / TestSharedSecretUnderDefenses
(projective / shared-secret equality). Keep them green; run with `-race` too.

## Measurement scripts that exist
- RAPL power cap to force throttling on high-TDP CPUs:
  `defense/scripts/hbctl.sh rapl-set 45` (saves the originals; `rapl-restore`).
- frequency logging: `defense/scripts/freqlog.py` (5 ms); also original
  06-circl/local driver (APERF/MPERF + PP0 energy every 1 ms).

## Node findings (CloudLab)
- **m510 (HPE ProLiant m510, Xeon D-1548 Broadwell-DE, 8C/16T, 2.0 GHz
  base, 2.6 GHz turbo, min 0.8 GHz, TDP/PL1 45 W, PL2 54 W, no HWP,
  intel_pstate active/powersave by default, Ubuntu 20.04, kernel 5.4).**
  FIRMWARE OWNS P-STATES: under load IA32_PERF_CTL is rewritten to ratio
  26 (max turbo). The kernel's msr:write_msr tracepoint shows no kernel
  writes, so the writer must be platform firmware (HPE Power Regulator via SMM).
  OS requests (PERF_CTL, scaling_setspeed, scaling_max_freq) are IGNORED.
  Only `no_turbo` is honored (busy core goes to 2.0 GHz). RAPL is presumably
  honored too (not yet verified).
  ⇒ m510 is OK for the baseline, Class 3, Class 4, Class 1 and turbo-off.
  It is NOT valid for Class 2 forced/randomized P-state, pin-min, or
  pstate_latency. Always run `hbctl.sh pstate-check` on a new node type.
  Candidate node types to try for Class 2: xl170 (E5-2640v4, same
  as the earlier server), c220g1/g2/d430 (Haswell E5-2630v3), c220g5
  (Skylake, HWP: boot with intel_pstate=no_hwp), c6525 (AMD, for the
  AMD generalization). Not yet verified.
- m510 ladder cost (idle box, powersave, Go bench, 378-bit B ladder):
  ref 3.65 ms, chunk14 3.73 ms (+2%), pipeline14×4 10.2 ms (2.8×, cross-
  core handoff), blind 8.8 ms (2.4×). One 27-iteration chunk ≈ 260 µs here.

## Milestones / status log (update as you go)
- [x] 2026-11-22 m510 node set up (Go 1.21.13, tools, venv); setup-cloudlab.sh written & verified.
- [x] 2026-11-22 Chunked ladder + pinned worker pool (Class 3) reconstructed; tests green.
- [x] 2026-11-22 Class 2 randomized forced-P-state implemented (msr/sysfs). Smoke-tested:
      392/392 MSR writes OK, but ineffective on m510 (firmware override, see above).
- [x] 2026-11-22 Class 4 noise injection implemented.
- [x] 2026-11-22 Class 1 blinding (P'=P+[r]Q) implemented; correct on both sides.
- [x] 2026-11-22 hbctl.sh, freqlog.py, run_defense_matrix.sh, averaging_curve.py,
      pstate_latency.c written (matrix NOT run yet; baseline deferred by request).
- [ ] BASELINE averaging curve (`DEFENSES=none run_defense_matrix.sh`), first with
      RAPL set so the D-1548 actually throttles (try `hbctl.sh rapl-set 25`).
      Verify the flip0/flip1 frequency separation exists on m510 first (06-circl/local driver).
- [ ] Run the matrix for chunk/pipeline/noise/blind on m510.
- [ ] Get a node where pstate-check = HONORED → pstate_latency + pstate_rand14 eval.
- [ ] DVFS reaction time τ microbenchmark (not written yet).
- [ ] Ciphertext validation: find the CIRCL commit that added SIKE pk validation
      (before SIDH was removed from CIRCL), port the timing harness to it, measure overhead.
- [ ] Turbo-off / pin-min Class 2 adopt runs (`hbctl.sh turbo off`).
- [ ] Compensating dummy-load (Class 3) still untested.

## Highest-value measurements still needed
1. DVFS reaction time τ and P-state transition latency on each CPU.
2. Averaging curve: signal distinguishability at K=1,10,100,1000,10000
   measurements (where does leakage emerge?).
3. Run on client + server + AMD (CloudLab) to generalize shared-domain claim.

## Full implementation plan across all 5 classes
IMPLEMENT (our code):
  - Class 3 pipeline interleave (have it; the NEGATIVE result)
  - Class 2 randomized forced-P-state (candidate; raise RAPL so it holds)
  - Class 4 noise injection (~20 lines; MEASURE its averaging curve to
    show it's defeated at high K — key "weak defense" evidence)
  - Class 1 blinding (SIKE coord randomization P'=P+[r]Q; hardest, best
    positive result; budget time)
ADOPT/REPRODUCE (run existing + measure overhead on our HW):
  - Class 1 ciphertext validation: diff unpatched CIRCL (1fc36...) vs
    current patched CIRCL main; confirm it blocks attack; measure 5-11%
    overhead. Doubles as the input-validation case study.
  - Class 2 disable turbo: echo 1 > .../intel_pstate/no_turbo
  - Class 2 fix min freq: set scaling_max_freq=min
  - Class 2 Goldilocks: reproduce if S&P'26 artifact public, else cite
DESCRIBE + CITE (no code):
  - Class 1 masking (algorithm-specific, high human-effort)
  - Class 4 rate-limiting (analyze via averaging curve → time-to-key)
  - Class 4 restrict RAPL (stops power-read variant, not timing variant)
  - Class 5 key rotation (rotate interval R < recovery K → attack fails)

## The reused measurement (do FIRST)
Baseline AVERAGING CURVE: signal distinguishability at K=1,10,100,1000,
10000 measurements. Powers: noise-injection eval, rate-limit analysis,
key-rotation analysis, the formal section, and the baseline anchor.
