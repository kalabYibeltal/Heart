# Hertzbleed Defense Characterization — Project Context
Following on the paper https://www.hertzbleed.com/hertzbleed.pdf

## Goal
Characterization + evaluation paper on the CLASS of defenses against
Hertzbleed (DVFS frequency side-channel, CVE-2022-24436). Target venues:
IISWC or ISPASS. Thesis: a four-axis characterization (performance,
security, developing effort, backward compatibility) of the defense space,
plus scoped formal results on why frequency-SCHEDULING defenses cannot
close the channel.

## Glossary (terms used in results below)
- ratio R = P-state = R × 100 MHz (8 = 0.8 GHz min, 22 = 2.2 GHz base, 30 = 3.0 GHz max turbo on c220g5).
- flip: 1st arg of sike_local. flip=0 = real key, flip=1 = target bit flipped. If flip0 and
  flip1 run times differ, the attacker learns the bit (= the leak). Defense goal: no difference.
- Cohen's d = (mean1−mean0)/pooled SD per measurement. K99 = measurements per bit for 99%
  correct guesses ≈ (4.65/d)². Baseline d=0.65 → K99≈51. Bigger K99 = better defense.
- epoch = interval between random P-state picks; currently 1 ladder chunk (HB_STAGES=14).
- worker pool (HB_WORKERS=N) = Class 3 pipeline: N threads pinned 1 per CPU, chunk k of a
  ladder runs on core (start+k) mod N.
- RAPL PL1 = package power cap (W, 1 s average). Lowering it is what makes the CPU throttle
  so Hertzbleed appears; a forced P-state above what the cap allows gets throttled anyway.

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
    every chunk; backends `msr` (IA32_PERF_CTL 0x199) / `hwp` (IA32_HWP_REQUEST
    0x774 min=max, all SMT siblings; for HWP CPUs like c220g5) / `sysfs`
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
  pstate-active | perfctl R | hwp R | hwp-reset | pstate-check (HWP-aware) | quiet.
  RAPL commands apply to every package (multi-socket).
- `defense/scripts/freqlog.py`: per-CPU scaling_cur_freq + pkg energy_uj every N ms → CSV.
- `defense/scripts/run_defense_matrix.sh`: sike_local flip 0/1 alternating per defense
  → `defense/data/matrix-<host>-<date>/` (COMMITTED: `!/defense/data/` in .gitignore,
  because nodes are ephemeral; ~0.5 MB per matrix) + averaging curves.
  Also there: `pstate-latency-c220g5-1124/`, `rapl-sweep-c220g5-1124/` (each has a README). `DRY=1` prints commands only.
- `defense/analysis/averaging_curve.py`: accuracy vs K (bootstrap + Gaussian
  Φ(d√K/2)), Welch t, K99, time-to-key; parses ALL_DURATION lines or numbers.
- `defense/microbench/pstate_latency.c`: P-state transition latency via
  constant-cycle loop + rdtsc after PERF_CTL write (needs HONORED node).

## Defense selection (env vars, read by sike_local / sike_server)
HB_STAGES=N  HB_WORKERS=W  HB_WORKER_CPUS=0-7,..  HB_PSTATE_RAND=1
HB_PSTATE_RATIOS=8,12,20  HB_PSTATE_BACKEND=msr|hwp|sysfs  HB_PSTATE_SCOPE=cpu|all
HB_NOISE_NS=50000  HB_BLIND=1   (can be combined; P-state needs sudo)
e.g. `HB_STAGES=14 HB_WORKERS=16 ./sike_local 0 1 2 300 100`

## CIRCL's deployed Hertzbleed patch = ciphertext validation (analysed 2026-11-25)
Upstream clone for reference: `~/circl-upstream` (github.com/cloudflare/circl, NOT in Heart).
- THE COMMIT: `10923e8` "sike mitigation of remote timing attack", 2022-06-03, author
  Yingchen Wang (USC, a Hertzbleed author). Our base `1fc3638` (2021-06-07) is BEFORE it, so
  06-circl/circl is unpatched (correct for the attack). Same change in p434/p503/p751 + templates.
  After 10923e8 upstream made only formatting and doc changes (SIDH is deprecated but still in the tree).
- In between: `5fa296f` (2021-10-10, armfazh, "Blinds the difference point…", bug reported
  by Hovav & Wang). This was the FIRST fix: inside the ladder, `cmov` a random point into R1
  whenever R1.X or R1.Z is zero (constant time). 10923e8 REMOVED that blinding and replaced it
  with validation. So CIRCL went from a constant-time in-ladder fix (Class 1, power) to an
  input-rejection fix (also Class 1, but it acts before the secret is touched). (c53fd24 = test-only.)
- WHERE: only `DeriveSecretB` (3-torsion side = SIKE decapsulator's STATIC key), before
  `ScalarMul3Pt`. DeriveSecretA (ephemeral side) is not validated. On failure, ss = crypto/rand
  bytes and it returns early. Decaps then fails the re-encryption compare and returns H(s‖ct)
  (implicit rejection), so the attacker gets no explicit error. Note that the REJECT path does NOT run
  the ladder/isogeny, so it is much faster than accept. That is fine because it depends only on the public ct.
- ALGORITHM = CLN test (Costello–Longa–Naehrig 2016), as suggested by De Feo et al., ePrint
  2022/054 "SIKE Channels". Input: ct/pk = x(P), x(Q), x(P−Q); curve A recovered from them.
  0. x(P−Q) ∉ {T=(0,0), O}  (X≠0 and Z≠0).
  1. e3 = floor((nbits+1)/log2 3) = 239 for p751 (nbits=378). Triple P and Q (e3−1) times
     (Pow3k, x-only). If either is O, it is not of full order. Reject.
  2. If [3^(e3−1)]P = ±[3^(e3−1)]Q (X_P·Z_Q − Z_P·X_Q = 0), P and Q are dependent. Reject.
  3. Triple once more: both must now be O (order exactly 3^e3). Otherwise reject.
  Pass ⇒ P,Q is a basis of E_A[3^e3] (CLN: then E_A is also supersingular).
  Data-dependent branches act only on PUBLIC input. e3 uses float math (fine).
- WHY IT KILLS HERTZBLEED: the attack ct (`Prep_ct` in our circl.patch) is built from
  P2+P3 (order 2^372·3^239) and T=(0,0) (order 2), i.e. points with 2-power components chosen
  so that the ladder hits the anomalous projective zero at the target bit. Those points cannot
  have order 3^239. VERIFIED on m510 (`cln_probe_test.go`): 5/5 honest Alice pks pass; 15/15
  attack cts (target bits 1,2,10,100,300) are rejected at CHECK 3 (order ≠ 3^e3).
  Characterization point: this does not make power constant. It makes the
  attacker-CONTROLLED secret-dependent zeros unreachable (it closes the amplifier, not the
  channel). Honest inputs still give normal HW/HD power variation, but without attacker control
  it is not amplified into a bit-distinguisher. It is also specific to the SIKE algorithm (high human
  effort, does not transfer to other primitives).
- COST (m510 D-1548, idle, powersave, Go bench 200×): CLN 3.9–4.5 ms vs DeriveSecretB 14.3 ms
  (≈+27–31% of that call); PublicKeyGenA (re-encryption) 14.7 ms ⇒ ≈ +13–15% of decaps
  (ESTIMATE from the parts, not an end-to-end decaps timing). The CIRCL/paper figure is ~5–11%. Next:
  measure end-to-end Decapsulate with vs. without validation, and run sike_local with validation
  in DeriveSecretB (expect d≈0: every attack ct is rejected).
- CLARIFICATIONS (Q&A 2026-11-25):
  * WHEN: the check runs ONCE, at the start of DeriveSecretB, on the input points (never inside the ladder).
    That is enough because every ladder register is aP+bQ; if P,Q is a basis of E[3^e3], every
    register has 3-power order, so it can never be T (order 2) or O at ANY step. The attacker
    PLANTS the zero via the choice of P,Q (Prep_ct solves for points that put T into R1/R2 at
    the target bit). A check at the zero itself would be a secret-dependent branch, which is why 5fa296f
    had to use a per-iteration constant-time cmov.
  * FALSE POSITIVES: none. An honest ct = 2^e2-isogeny image of the 3^e3 basis; the degree is
    coprime to 3, so the basis is kept. The check is deterministic. e3 via float is correct for all
    sets (137/159/239). Twist points: twist order (p−1)^2 has no factor of 3, so they are rejected.
  * FALSE NEGATIVES: none for the Hertzbleed zero (T/O). NOT ruled out: weaker power differences from
    valid-but-structured points (no zero persistence, no known attack) = the residual channel.
    Only the B side is checked; static-A raw SIDH users are unprotected.
  * OUTPUT on reject: ss = fresh random bytes, then re-encryption mismatch, then KEM returns H(s‖ct) =
    deterministic and identical to unpatched implicit rejection. There is no "correct" key for
    a crafted ct. NO TIME PADDING: reject skips the ~14 ms ladder+isogeny (≈18 vs ≈33 ms on m510,
    estimate), but rejection depends only on the public ct, so this leaks nothing about the key.
    Raw `sidh.DeriveSecret` callers get silent random bytes (different each call, no error).
  * 3^e3-TORSION: E[3^239] = {P : [3^239]P = O} ≅ (Z/3^239)^2 (a 2-D grid; a basis P,Q gives
    every point as aP+bQ; all orders are powers of 3). Alice's E[2^372] meets it only in O; T=(0,0)
    (order 2) lies in Alice's grid, NEVER in Bob's. Bob's kernel = P+[m]Q.
  * e3 FLOAT: floor((nbits+1)/log2 3) is exact in theory (value ∈ (e3, e3+0.63]). The margins
    above e3 are 0.54/0.63/0.12 (p434/p503/p751) ≫ 1e-13 double error ⇒ no rounding risk.
    It is a hard-codable constant (a style nit).
  * HONEST ct NEVER hits the zero: a valid basis ⇒ registers are [2^i]P or have coefficient ±1 on
    a basis element ⇒ never O; never T (wrong order). X=0 ⇔ T, Z=0 ⇔ O on a Montgomery curve.
    Only coincidental zero temporaries remain (~1/p ≈ 2^-751, which no attacker can steer).
- Probe: `06-circl/circl/dh/sidh/internal/p751/cln_probe_test.go` (TestCLNProbe,
  BenchmarkCLNVsLadder). Test-only; it does not change the decaps path.

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
- **c220g5 (2× Xeon Silver 4114 Skylake-SP, 10C/20T per socket, 40 CPUs,
  2.2 GHz base, 3.0 GHz max turbo, min 0.8 GHz, PL1 85 W / PL2 102 W PER
  PACKAGE, HWP ENABLED (IA32_PM_ENABLE=1 on all CPUs), intel_pstate
  active/powersave, kernel 5.4).** Verified 2026-11-24:
  - IA32_PERF_CTL is ignored (HWP owns P-states); passive mode refused (EBUSY,
    kernel 5.4 has no HWP+passive). NO REBOOT NEEDED: forcing works through
    IA32_HWP_REQUEST (0x774) with min=max=R, desired=0 → HONORED for R=8..30
    (busy core exactly R×100 MHz). Set intel_pstate/hwp_dynamic_boost=0 first
    (otherwise the first write got rewritten once).
  - SMT GOTCHA: the core resolves [max of siblings' mins, max of siblings'
    maxes], EVEN IF THE SIBLING IS IDLE. Writing only cpu4=8 with sibling cpu24
    at its default (8..30) → 2950 MHz. Both must be written. The `hwp` backend
    and pstate_latency now write all thread_siblings. (Paper point: an SMT
    co-tenant's HWP request raises your core's frequency ⇒ a cross-thread
    knob/leak; per-core forcing needs control of both hyperthreads.)
  - HWP TRANSITION LATENCY (pstate_latency, cpu4+24, 180 trials, pairs
    8↔22, 14↔22, 22→30, 30→8): ~UNIFORM over 30–550 µs (min 32, p25 172,
    median 338, p90 531, p99 770 µs) + ~13 µs halt during the switch.
    Interpretation: the PCU samples HWP requests on a ~500 µs tick. This is ~10×
    worse than finding 3's 20–70 µs (legacy PERF_CTL) ⇒ on HWP parts, per-chunk
    randomization is even more hopeless; epochs must be ≫0.5 ms (a whole ladder
    ≈ 3–4 ms is only ~6–8 epochs).
  - Default attack load (sike_local 300 thr) draws ~62 W/package at ~2.45 GHz
    (all-core turbo limit) → NOT power-limited → no leak at stock RAPL. Need
    `hbctl.sh rapl-set W` (now sets ALL packages). Setup phase of sike_local is
    ~10 s single-threaded before the ALL_DURATION loop (exclude from turbostat).
  - BASELINE RAPL SWEEP (sike_local 300 thr, key 1 bit 2, 3 alternating
    rounds × 40 iters × flip0/1, PL1 on both packages):
      60 W: 393.4 vs 391.0 ms (−0.6%, d=−0.32, p=0.014) marginal
      45 W: 516.1 vs 503.9 ms (−2.4%, d=−0.64, p=1e-6)  ← LEAKS, use this
      35 W: 781.6 vs 779.8 ms (−0.2%, p=0.55) gone (likely floored at 0.8 GHz)
    ⇒ the leak needs a power-limited regime that still has headroom above min
    frequency; too tight a cap kills the channel too (worth a figure).
  - CLASS 2 RANDOM-P MATRIX (2026-11-24, data/matrix-c220g5-class2-1124-2144,
    45 W/pkg, 6 rounds × 100 iters × flip0/1, N=599 each, epoch = 1 of 14 chunks):
      none            518.2 vs 510.0 ms  Δ=−1.59%  d=0.65  K99=51
      rand 8–16       839.8 vs 840.3 ms  Δ=+0.06%  d=0.04  (+62% time)
      rand 8–22 (nw)  694.5 vs 695.0 ms  Δ=+0.08%  d=0.04  (+34% time)
      rand 8–22 +pool 674.0 vs 674.2 ms  Δ=+0.04%  d=0.03  (+30% time)
    852,600 HWP writes, 0 errors per run. All three: leak NOT detectable
    (SE of d at N=599 ≈ 0.058, so d≈0.03–0.04 is noise; the script's K99 of
    11k–28k is an extrapolation of noise, NOT a measured residual leak).
    Honest bound: d < ~0.12 ⇒ K99 > ~1500 (≥30× more measurements than
    baseline). More data is needed to claim more.
    SURPRISE: 8–22 also held at 45 W (predicted throttling). Likely because
    the average ratio is 15 (~1.5 GHz), so 1 s-averaged package power stays
    under PL1.
    OPEN QUESTION FOR THE "randomized beats pinning" CLAIM: a FIXED ratio
    under the cap is also data-independent and may be faster than random
    8–22 (mean 1.5 GHz). Next: pin runs (`hbctl.sh hwp R`, R=8/15/18/22) at
    45 W, for security + time.
  - Use `hbctl.sh hwp R` / `hwp-reset`; HB_PSTATE_BACKEND=hwp leaves the forced
    ratio behind after exit, so always `hwp-reset` (run_defense_matrix does it).
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
- [x] 2026-11-24 c220g5: pstate-check = HONORED via HWP_REQUEST (`hwp` backend added,
      SMT-sibling aware); pstate_latency measured (HWP: 30–550 µs uniform, median 338 µs).
- [x] 2026-11-24 c220g5 RAPL sweep: baseline leaks at 45 W/pkg (d=0.65, K99=51),
      not at 60 W (marginal) or 35 W (gone). 45 W = the Class 2 test condition.
- [x] 2026-11-24 c220g5 Class 2 random-P matrix at 45 W (ranges 0.8–1.6 and 0.8–2.2 GHz,
      ±worker pool): ALL closed the leak to below detection (d≈0.03–0.04 = noise), +30–62% time.
      SUCCESS for the candidate, with the pinning caveat (see c220g5 findings).
- [x] 2026-11-25 RANGE SWEEP RESULT (data/matrix-c220g5-range-1124-2346, 45 W, N=599/side,
      PStateErrors 0). Fresh baseline this session: d=0.48, K99=95 (yesterday 0.65/51 →
      session-to-session drift; always run `none` in the same session).
        config        f0 / f1 ms        Δ        d      slowdown vs none
        none          520.3 / 514.0   −1.21%   0.48   —
        prand_8_30    596.5 / 595.6   −0.15%   0.07   +15%   ← CLOSED (not significant)
        prand_15_30   527.5 / 521.9   −1.06%   0.56   +1%    leaks like baseline
        prand_18_30   524.4 / 517.0   −1.42%   0.71   +1%    leaks
        prand_22_30   521.5 / 515.2   −1.20%   0.51   0%     leaks
        prand_26_30   517.4 / 509.0   −1.64%   0.68   −1%    leaks
      Power: ~89.5 W for both packages (= the 45 W cap) in EVERY config. Busy freq ≈1.85 GHz
      for 15_30..26_30 and for none → the cap, not our request, sets the frequency whenever
      the requested ratio > ~18 (f_cap ≈ 1.85 GHz at 45 W). Those epochs are RAPL-throttled
      = data-dependent = Hertzbleed is back.
      ⇒ NO SMOOTH DIAL in this sweep: a CLIFF between min ratio 8 and 15. Physics model:
      epochs requesting f < f_cap are truly forced (safe); epochs requesting f > f_cap are
      throttled (leak). Leak should scale with the fraction of TIME spent throttled.
      prand_8_30 is the best point so far: undetectable at only +15% (vs +34% for 8_22,
      +62% for 8_16, both from the 1124-2144 run). Honest bound for 8_30: d < 0.07+2·0.058
      ≈ 0.18 ⇒ K99 ≳ 650 (≈7× baseline); d=0.07 may be a real small leak, so it needs
      more N to tell.
- [x] 2026-11-25 FIRST DIAL POINT FOUND (cliff dir, reviewed by Claude):
        none          518.0 / 510.9 ms  Δ=−1.37%  d=0.56  K99≈69
        prand_10_30   562.6 / 560.1 ms  Δ=−0.46%  d=0.24  K99≈363  slowdown +8.6%
      d=0.24 is ≈4 SE from 0, so this is a REAL partial leak: ~5× more measurements per bit
      than baseline, at +8.6% time. Together with 8_30 (undetectable, +15%) and 15_30 (full
      leak, +1%), this is the security/performance dial. Next: plot K99 vs slowdown;
      more N at 8_30 and 10_30; try 9_30, 11_30.
- (abandoned) 2026-11-25 overnight_cliff.sh in tmux died during prand_12_30 (1 of 6 rounds saved
      in cliff-1125-0107, prand_14_30 never ran). Superseded by the 11-27 cliffpin run below.
      Long runs: ALWAYS start them in tmux (VS Code disconnect can kill Claude's children).
      Push needs the user's credentials (`cd ~/Heart && git push` from their own terminal).
- [x] 2026-11-27 CLIFF + PIN SWEEP on a DIFFERENT c220g5 node (node0.kalab-328425), one session,
      data/matrix-c220g5-cliffpin-1127-2004, 45 W/pkg, N=599/side, PStateErrors 0. Power/MHz =
      turbostat rows with Busy%>50 (both packages summed).
        config        f0 / f1 ms     Δ       d     K99    slowdown  Bzy MHz  PkgW
        none          577.2/568.6  −1.49%  0.59    62      —        1659    89.6
        prand_8_30    627.5/622.5  −0.80%  0.41   131    +9.1%     1575    89.6
        prand_10_30   604.1/597.3  −1.13%  0.70    45    +4.9%     1625    89.5
        prand_12_30   590.6/585.3  −0.90%  0.50    86    +2.6%     1654    89.6
        prand_14_30   580.6/573.7  −1.18%  0.58    64    +0.7%     1680    89.6
        pin 12        804.4/804.9  +0.06%  0.04  ≥1500  +40.5%     1200    75.3
        pin 15        645.8/646.0  +0.03%  0.02  ≥1500  +12.7%     1500    83.3   ← BEST
        pin 18        573.8/569.5  −0.74%  0.45   109    −0.2%     1694    88.9
      (pin R = prand_R_R, i.e. HB_PSTATE_RATIOS=R; same code path and write rate as random.)
      FINDINGS:
      1. f_cap MOVES BETWEEN NODES of the same type: ≈1.65–1.70 GHz here vs ≈1.85 GHz on the
         11-25 node (same SKU/RAPL setting → silicon/thermal variation). Pin 18 asked 1.8 GHz,
         got 1.69 (throttled) → leaks. Pin 15 holds exactly 1.5 GHz at 83 W < 90 W cap → closed.
      2. The random-range result does NOT transfer: prand_8_30 was undetectable on the old node
         (d=0.07) but leaks here (d=0.41, K99≈2× baseline); 10_30 (0.24 before) is a full leak
         now. Every config that is ever above f_cap and runs at the cap leaks.
      3. "RANDOMIZED BEATS PINNING" IS NOT SUPPORTED. Security needs every epoch ≤ f_cap; under
         that constraint the fastest data-independent schedule is a fixed pin just under f_cap
         (here 15: closed at +12.7%). Any random range ≤ f_cap has a lower mean f ⇒ slower
         (e.g. 8–16 was +62%, 8–22 +34% on the old node). Ranges that reach above f_cap gain
         speed only by spending time throttled = leaking. Paper framing: Class 2 forcing works,
         but the operating point must be calibrated PER NODE (f_cap depends on the part and its
         RAPL cap), and randomization adds no security over a correctly calibrated pin.
      Caveat: d varies by ~±0.1 run-to-run (10_30 0.70 > none 0.59), so the 12_30/14_30 numbers
      are "full leak", not a ranking. Next: pin 16/17 to locate the edge more precisely
      (pin 15 margin), and test whether a pin at f_cap−margin stays safe across thermal states.
- (superseded) 2026-11-24 RANGE SWEEP plan ("dream result" = a security/performance DIAL):
      raise the random range into turbo so the 45 W cap SOMETIMES throttles → partial
      leak with K99 between 51 and undetectable (e.g. 100, 500, …). Configs:
      none, prand_8_30, prand_15_30, prand_18_30, prand_22_30, prand_26_30
      (ratio A..B = A×100..B×100 MHz, no worker pool), POWERLOG=1 (turbostat per config →
      <d>_power.txt; keep rows with Busy%>50 = attack phase, not the ~10 s setup).
      Output: defense/data/matrix-c220g5-range-<date>/ . Plot K99 and slowdown vs range.
      Remember: K99 is only trustworthy while d ≫ 0.058 (its SE at N=599); for d<~0.12
      report "≥ ~1500", not the script's extrapolated number.
- [x] 2026-11-27 Pinning comparison: done (pins 12/15/18, see cliffpin entry). Pinning wins.
- [ ] DVFS reaction time τ microbenchmark (not written yet).
- [x] 2026-11-25 (m510 again; c220g5 unavailable) CIRCL patch found and analysed: 10923e8 = CLN
      ciphertext validation in DeriveSecretB. It rejects 15/15 attack cts. See the "CIRCL's deployed
      Hertzbleed patch" section. Go 1.21.13 installed by hand on this node (setup-cloudlab.sh not run).
- [ ] Ciphertext validation, remaining: end-to-end Decapsulate overhead + sike_local run with
      validation enabled (expect no leak).
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
    current patched CIRCL main (DONE: commit 10923e8, CLN test, blocks attack ct);
    measure overhead (component estimate ≈13–15% on m510). Doubles as the input-validation case study.
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
