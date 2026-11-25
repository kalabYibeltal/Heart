// Hertzbleed defense characterization project.
//
// This file replaces the public ScalarMul3Pt entry point with a dispatcher
// that can apply one or more defenses to the SIKE three-point Montgomery
// ladder (the operation the Hertzbleed SIKE attack targets). The original
// ladder is kept unchanged as scalarMul3PtRef in curve.go.
//
// Defenses (see hertzbleed/CLAUDE.md for the taxonomy):
//
//	Class 3  chunked ladder + pipeline core-interleave across pinned workers
//	         (Stages, Workers, WorkerCPUs). Expected NEGATIVE result.
//	Class 2  randomized forced P-state per chunk/epoch (PStateRand,
//	         PStateRatios, PStateBackend, PStateScope). Positive candidate.
//	Class 4  random-delay noise injection after the ladder (NoiseMaxNs).
//	         Expected to be defeated by averaging.
//	Class 1  scalar/point blinding: P' = P + [r]Q, m' = m - r mod ord(Q)
//	         (Blind). Positive candidate, ~3x ladder cost.
//
// Configuration is process-global. Call Configure / ConfigureFromEnv once at
// startup (before any decapsulation). With the zero config every call goes
// straight to scalarMul3PtRef, i.e. behaviour is identical to upstream.
package p751

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	. "github.com/cloudflare/circl/dh/sidh/internal/common"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// DefenseConfig selects which defenses are active. The zero value means "no
// defense" (reference ladder).
type DefenseConfig struct {
	// Stages splits the ladder into this many chunks (epochs). 0 or 1 means a
	// monolithic ladder. Divisors of 378 (14/18/21/27) give equal chunks for
	// the Bob/decapsulation ladder, but any value 1..nbits is correct.
	Stages int

	// Workers > 0 runs chunks on a pool of worker goroutines, each locked to
	// an OS thread pinned to one CPU (pipeline core-interleave, Class 3).
	// Chunk k of a request runs on worker (offset+k) % Workers, where offset
	// is a per-request round-robin counter.
	Workers int
	// WorkerCPUs lists the CPU for each worker. Default: 0..Workers-1.
	WorkerCPUs []int

	// PStateRand sets a uniformly random P-state ratio before every chunk
	// (Class 2 candidate). Requires root (MSR or sysfs writes).
	PStateRand bool
	// PStateRatios is the set of ratios (multiples of 100 MHz bus clock) to
	// draw from. Default (msr backend): min..max non-turbo from
	// MSR_PLATFORM_INFO (0xCE).
	PStateRatios []uint64
	// PStateBackend: "msr" (write IA32_PERF_CTL 0x199 via /dev/cpu/N/msr;
	// fast, needs intel_pstate=passive + userspace governor or
	// intel_pstate disabled so the kernel does not overwrite it; ignored when
	// HWP is enabled), "hwp" (write IA32_HWP_REQUEST 0x774 min=max=ratio; for
	// HWP-enabled CPUs, Skylake+) or "sysfs"
	// (write scaling_min_freq/scaling_max_freq; slow, works with intel_pstate
	// active).
	PStateBackend string
	// PStateScope: "cpu" (only the CPU running the chunk) or "all" (every
	// online CPU; use when the frequency domain is shared anyway).
	PStateScope string

	// NoiseMaxNs > 0 busy-spins for a uniformly random duration in
	// [0, NoiseMaxNs] ns after each top-level ladder (Class 4).
	NoiseMaxNs int64

	// Blind enables ladder blinding (Class 1): R = P' + [m']Q with
	// P' = P + [r]Q, m' = m - r mod ord(Q), fresh random r per call.
	Blind bool
}

// String renders the config in the same KEY=VALUE form ConfigureFromEnv reads.
func (c DefenseConfig) String() string {
	return fmt.Sprintf("HB_STAGES=%d HB_WORKERS=%d HB_WORKER_CPUS=%s HB_PSTATE_RAND=%t HB_PSTATE_RATIOS=%s HB_PSTATE_BACKEND=%s HB_PSTATE_SCOPE=%s HB_NOISE_NS=%d HB_BLIND=%t",
		c.Stages, c.Workers, joinInts(c.WorkerCPUs), c.PStateRand, joinU64(c.PStateRatios),
		c.PStateBackend, c.PStateScope, c.NoiseMaxNs, c.Blind)
}

// DefenseStats are cumulative counters, useful for sanity-checking a run
// (e.g. that P-state writes actually happened and did not fail).
type DefenseStats struct {
	Ladders        uint64 // top-level ScalarMul3Pt calls
	Chunks         uint64 // chunks executed
	PStateWrites   uint64 // successful ratio writes
	PStateErrors   uint64 // failed ratio writes
	BlindFallbacks uint64 // Blind requested but nbits had no known order
}

type defenseState struct {
	cfg    DefenseConfig
	setter pstateSetter
	allCPU []int
}

var (
	active     atomic.Value // *defenseState
	configMu   sync.Mutex
	pool       *workerPool
	stLadders  uint64
	stChunks   uint64
	stPWrites  uint64
	stPErrors  uint64
	stBlindFB  uint64
	firstPErr  sync.Once
	reqCounter uint64
)

func init() { active.Store(&defenseState{}) }

func current() *defenseState { return active.Load().(*defenseState) }

// ActiveDefense returns the currently active configuration.
func ActiveDefense() DefenseConfig { return current().cfg }

// GetDefenseStats returns the cumulative counters.
func GetDefenseStats() DefenseStats {
	return DefenseStats{
		Ladders:        atomic.LoadUint64(&stLadders),
		Chunks:         atomic.LoadUint64(&stChunks),
		PStateWrites:   atomic.LoadUint64(&stPWrites),
		PStateErrors:   atomic.LoadUint64(&stPErrors),
		BlindFallbacks: atomic.LoadUint64(&stBlindFB),
	}
}

// Configure installs cfg as the active defense, (re)starting the worker pool
// if needed. Not meant to be called concurrently with running ladders.
func Configure(cfg DefenseConfig) error {
	configMu.Lock()
	defer configMu.Unlock()

	if cfg.Stages < 0 || cfg.Workers < 0 || cfg.NoiseMaxNs < 0 {
		return errors.New("defense: negative Stages/Workers/NoiseMaxNs")
	}
	if cfg.Workers > 0 && cfg.Stages < 1 {
		cfg.Stages = 1
	}
	if cfg.PStateRand && cfg.Stages < 1 {
		cfg.Stages = 1
	}
	if cfg.PStateBackend == "" {
		cfg.PStateBackend = "msr"
	}
	if cfg.PStateScope == "" {
		cfg.PStateScope = "cpu"
	}
	if cfg.Workers > 0 && len(cfg.WorkerCPUs) == 0 {
		for i := 0; i < cfg.Workers; i++ {
			cfg.WorkerCPUs = append(cfg.WorkerCPUs, i%runtime.NumCPU())
		}
	}
	if cfg.Workers > 0 && len(cfg.WorkerCPUs) != cfg.Workers {
		return fmt.Errorf("defense: %d workers but %d WorkerCPUs", cfg.Workers, len(cfg.WorkerCPUs))
	}

	st := &defenseState{cfg: cfg}
	for i := 0; i < runtime.NumCPU(); i++ {
		st.allCPU = append(st.allCPU, i)
	}
	if cfg.PStateRand {
		var err error
		switch cfg.PStateBackend {
		case "msr":
			st.setter, err = newMSRSetter()
		case "hwp":
			st.setter, err = newHWPSetter()
		case "sysfs":
			st.setter = &sysfsSetter{}
		case "fake":
			st.setter = &FakeSetter{}
		default:
			err = fmt.Errorf("defense: unknown PStateBackend %q", cfg.PStateBackend)
		}
		if err != nil {
			return err
		}
		if len(cfg.PStateRatios) == 0 {
			lo, hi, err := platformRatios()
			if err != nil {
				return fmt.Errorf("defense: PStateRatios not set and MSR 0xCE unreadable: %v", err)
			}
			for r := lo; r <= hi; r++ {
				st.cfg.PStateRatios = append(st.cfg.PStateRatios, r)
			}
		}
	}

	if pool != nil {
		pool.stop()
		pool = nil
	}
	if cfg.Workers > 0 {
		p, err := startWorkerPool(cfg.WorkerCPUs)
		if err != nil {
			return err
		}
		pool = p
	}
	active.Store(st)
	return nil
}

// ConfigureFromEnv reads HB_* environment variables (see DefenseConfig.String)
// and calls Configure. Unset variables keep their zero value.
func ConfigureFromEnv() (DefenseConfig, error) {
	var c DefenseConfig
	var err error
	geti := func(k string) int {
		v := os.Getenv(k)
		if v == "" || err != nil {
			return 0
		}
		n, e := strconv.Atoi(v)
		if e != nil {
			err = fmt.Errorf("%s: %v", k, e)
		}
		return n
	}
	getb := func(k string) bool {
		v := strings.ToLower(os.Getenv(k))
		return v == "1" || v == "true" || v == "yes"
	}
	c.Stages = geti("HB_STAGES")
	c.Workers = geti("HB_WORKERS")
	c.NoiseMaxNs = int64(geti("HB_NOISE_NS"))
	c.PStateRand = getb("HB_PSTATE_RAND")
	c.Blind = getb("HB_BLIND")
	c.PStateBackend = os.Getenv("HB_PSTATE_BACKEND")
	c.PStateScope = os.Getenv("HB_PSTATE_SCOPE")
	if v := os.Getenv("HB_WORKER_CPUS"); v != "" && err == nil {
		c.WorkerCPUs, err = parseInts(v)
	}
	if v := os.Getenv("HB_PSTATE_RATIOS"); v != "" && err == nil {
		var xs []int
		xs, err = parseInts(v)
		for _, x := range xs {
			c.PStateRatios = append(c.PStateRatios, uint64(x))
		}
	}
	if err != nil {
		return c, err
	}
	if err = Configure(c); err != nil {
		return c, err
	}
	return ActiveDefense(), nil
}

// ---------------------------------------------------------------------------
// Public ladder entry point
// ---------------------------------------------------------------------------

// ScalarMul3Pt is a right-to-left point multiplication that given the
// x-coordinate of P, Q and P-Q calculates the x-coordinate of R=P+[scalar]Q,
// applying the active defense configuration.
func ScalarMul3Pt(cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, nbits uint, scalar []uint8) ProjectivePoint {
	st := current()
	atomic.AddUint64(&stLadders, 1)
	var R ProjectivePoint
	if st.cfg.Blind {
		R = scalarMul3PtBlinded(st, cparams, P, Q, PmQ, nbits, scalar)
	} else {
		R = ladderDispatch(st, cparams, P, Q, PmQ, nbits, scalar)
	}
	if st.cfg.NoiseMaxNs > 0 {
		injectNoise(st.cfg.NoiseMaxNs)
	}
	return R
}

func ladderDispatch(st *defenseState, cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, nbits uint, scalar []uint8) ProjectivePoint {
	if st.cfg.Stages <= 1 && st.cfg.Workers == 0 && !st.cfg.PStateRand {
		return scalarMul3PtRef(cparams, P, Q, PmQ, nbits, scalar)
	}
	return scalarMul3PtChunked(st, cparams, P, Q, PmQ, nbits, scalar)
}

// ---------------------------------------------------------------------------
// Chunked ladder (Class 3 base; also the epoch structure for Class 2)
// ---------------------------------------------------------------------------

// LadderState carries the three-point ladder between chunks.
type LadderState struct {
	R0, R1, R2  ProjectivePoint
	aPlus2Over4 Fp2
	prevBit     uint8
	scalar      []uint8
}

// NewLadderState initialises the ladder exactly like scalarMul3PtRef.
func NewLadderState(cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, scalar []uint8) *LadderState {
	return &LadderState{
		R0:          *Q,
		R1:          *P,
		R2:          *PmQ,
		aPlus2Over4: CalcAplus2Over4(cparams),
		scalar:      scalar,
	}
}

// ScalarMul3PtChunk runs ladder iterations [start, end). It does NOT perform
// the final conditional swap; that is done once by the caller (see
// FinishLadder) so a worker never handles the last secret-dependent swap.
func ScalarMul3PtChunk(st *LadderState, start, end uint) {
	for i := start; i < end; i++ {
		bit := (st.scalar[i>>3] >> (i & 7) & 1)
		swap := st.prevBit ^ bit
		st.prevBit = bit
		cswap(&st.R1.X, &st.R1.Z, &st.R2.X, &st.R2.Z, swap)
		st.R0, st.R2 = xDbladd(&st.R0, &st.R2, &st.R1, &st.aPlus2Over4)
	}
}

// FinishLadder performs the final conditional swap and returns R1.
func FinishLadder(st *LadderState) ProjectivePoint {
	cswap(&st.R1.X, &st.R1.Z, &st.R2.X, &st.R2.Z, st.prevBit)
	return st.R1
}

// ChunkBounds returns the iteration boundaries for splitting nbits into
// stages chunks: chunk k covers [b[k], b[k+1]).
func ChunkBounds(nbits uint, stages int) []uint {
	if stages < 1 {
		stages = 1
	}
	if uint(stages) > nbits && nbits > 0 {
		stages = int(nbits)
	}
	b := make([]uint, stages+1)
	for k := 0; k <= stages; k++ {
		b[k] = uint(k) * nbits / uint(stages)
	}
	return b
}

func scalarMul3PtChunked(st *defenseState, cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, nbits uint, scalar []uint8) ProjectivePoint {
	ls := NewLadderState(cparams, P, Q, PmQ, scalar)
	bounds := ChunkBounds(nbits, st.cfg.Stages)
	nchunks := len(bounds) - 1
	p := pool

	if st.cfg.Workers > 0 && p != nil {
		offset := int(atomic.AddUint64(&reqCounter, 1))
		done := make(chan struct{}, 1)
		for k := 0; k < nchunks; k++ {
			w := (offset + k) % len(p.queues)
			p.queues[w] <- chunkJob{ls: ls, start: bounds[k], end: bounds[k+1], st: st, done: done}
			<-done // chunks of one ladder are serially dependent
		}
	} else {
		if st.cfg.PStateRand {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
		}
		for k := 0; k < nchunks; k++ {
			if st.cfg.PStateRand {
				applyRandomPState(st, currentCPU())
			}
			ScalarMul3PtChunk(ls, bounds[k], bounds[k+1])
			atomic.AddUint64(&stChunks, 1)
		}
	}
	return FinishLadder(ls)
}

// ---------------------------------------------------------------------------
// Worker pool (pipeline core-interleave)
// ---------------------------------------------------------------------------

type chunkJob struct {
	ls         *LadderState
	start, end uint
	st         *defenseState
	done       chan struct{}
}

type workerPool struct {
	queues []chan chunkJob
	wg     sync.WaitGroup
}

// StartWorkers is a convenience wrapper: enable n pinned workers on CPUs
// 0..n-1 on top of the currently active configuration.
func StartWorkers(n int) error {
	cfg := ActiveDefense()
	cfg.Workers = n
	cfg.WorkerCPUs = nil
	return Configure(cfg)
}

func startWorkerPool(cpus []int) (*workerPool, error) {
	p := &workerPool{}
	ready := make(chan error, len(cpus))
	for _, cpu := range cpus {
		q := make(chan chunkJob, 1024)
		p.queues = append(p.queues, q)
		p.wg.Add(1)
		go p.worker(cpu, q, ready)
	}
	var firstErr error
	for range cpus {
		if err := <-ready; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		p.stop()
		return nil, firstErr
	}
	return p, nil
}

func (p *workerPool) worker(cpu int, q chan chunkJob, ready chan<- error) {
	defer p.wg.Done()
	// LockOSThread is required: affinity is per OS thread, and without it the
	// goroutine could move to an unpinned thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		ready <- fmt.Errorf("defense: pin worker to cpu %d: %v", cpu, err)
		return
	}
	ready <- nil
	for job := range q {
		if job.st.cfg.PStateRand {
			applyRandomPState(job.st, cpu)
		}
		ScalarMul3PtChunk(job.ls, job.start, job.end)
		atomic.AddUint64(&stChunks, 1)
		job.done <- struct{}{}
	}
}

func (p *workerPool) stop() {
	for _, q := range p.queues {
		close(q)
	}
	p.wg.Wait()
}

// ---------------------------------------------------------------------------
// Randomized forced P-state (Class 2)
// ---------------------------------------------------------------------------

type pstateSetter interface {
	SetRatio(cpu int, ratio uint64) error
}

const (
	msrPlatformInfo = 0xCE
	msrPerfCtl      = 0x199
	msrPMEnable     = 0x770
	msrHWPRequest   = 0x774
)

func applyRandomPState(st *defenseState, cpu int) {
	ratios := st.cfg.PStateRatios
	if len(ratios) == 0 || st.setter == nil {
		return
	}
	r := ratios[secureRand.intn(len(ratios))]
	cpus := []int{cpu}
	if st.cfg.PStateScope == "all" {
		cpus = st.allCPU
	}
	for _, c := range cpus {
		if err := st.setter.SetRatio(c, r); err != nil {
			atomic.AddUint64(&stPErrors, 1)
			firstPErr.Do(func() { fmt.Fprintln(os.Stderr, "defense: P-state write failed:", err) })
		} else {
			atomic.AddUint64(&stPWrites, 1)
		}
	}
}

type msrSetter struct {
	mu    sync.Mutex
	files map[int]*os.File
}

func newMSRSetter() (*msrSetter, error) {
	s := &msrSetter{files: map[int]*os.File{}}
	if _, err := s.file(0); err != nil {
		return nil, fmt.Errorf("defense: msr backend: %v (run as root after `modprobe msr`)", err)
	}
	return s, nil
}

func (s *msrSetter) file(cpu int) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.files[cpu]; ok {
		return f, nil
	}
	f, err := os.OpenFile(fmt.Sprintf("/dev/cpu/%d/msr", cpu), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	s.files[cpu] = f
	return f, nil
}

func (s *msrSetter) SetRatio(cpu int, ratio uint64) error {
	f, err := s.file(cpu)
	if err != nil {
		return err
	}
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], (ratio&0xff)<<8) // IA32_PERF_CTL[15:8]
	_, err = f.WriteAt(b[:], msrPerfCtl)
	return err
}

// hwpSetter forces a ratio on HWP-enabled CPUs (Skylake+ with IA32_PM_ENABLE=1,
// where IA32_PERF_CTL is ignored) by writing IA32_HWP_REQUEST (0x774) with
// minimum = maximum = ratio and desired = 0 (hardware-autonomous inside a
// zero-width window). The upper bits (EPP, activity window, package-control)
// are preserved from the value read at first use of each CPU. Set
// /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost=0 first, otherwise
// intel_pstate may rewrite the register. Verified HONORED on CloudLab c220g5
// (Xeon Silver 4114) for ratios 8..30.
//
// SMT: the core resolves its window as [max of sibling mins, max of sibling
// maxes] even when a sibling is idle, so the ratio is written to EVERY thread
// sibling of cpu (thread_siblings_list), not just cpu.
type hwpSetter struct {
	*msrSetter
	hmu  sync.Mutex
	base map[int]uint64
	sibs map[int][]int
}

func newHWPSetter() (*hwpSetter, error) {
	m, err := newMSRSetter()
	if err != nil {
		return nil, err
	}
	s := &hwpSetter{msrSetter: m, base: map[int]uint64{}, sibs: map[int][]int{}}
	f, _ := m.file(0)
	var b [8]byte
	if _, err := f.ReadAt(b[:], msrPMEnable); err != nil || binary.LittleEndian.Uint64(b[:])&1 == 0 {
		return nil, fmt.Errorf("defense: hwp backend: HWP not enabled (IA32_PM_ENABLE=0 or unreadable: %v); use the msr backend", err)
	}
	return s, nil
}

func (s *hwpSetter) SetRatio(cpu int, ratio uint64) error {
	s.hmu.Lock()
	sib, ok := s.sibs[cpu]
	s.hmu.Unlock()
	if !ok {
		sib = threadSiblings(cpu)
		s.hmu.Lock()
		s.sibs[cpu] = sib
		s.hmu.Unlock()
	}
	for _, c := range sib {
		if err := s.setOne(c, ratio); err != nil {
			return err
		}
	}
	return nil
}

// threadSiblings returns the SMT siblings of cpu (including cpu itself), or
// just {cpu} if the topology file is unreadable.
func threadSiblings(cpu int) []int {
	b, err := os.ReadFile(fmt.Sprintf("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu))
	if err != nil {
		return []int{cpu}
	}
	out, err := parseInts(strings.TrimSpace(string(b)))
	if err != nil || len(out) == 0 {
		return []int{cpu}
	}
	return out
}

func (s *hwpSetter) setOne(cpu int, ratio uint64) error {
	f, err := s.file(cpu)
	if err != nil {
		return err
	}
	s.hmu.Lock()
	base, ok := s.base[cpu]
	s.hmu.Unlock()
	var b [8]byte
	if !ok {
		if _, err := f.ReadAt(b[:], msrHWPRequest); err != nil {
			return err
		}
		base = binary.LittleEndian.Uint64(b[:]) &^ 0xffffff // drop min[7:0], max[15:8], desired[23:16]
		s.hmu.Lock()
		s.base[cpu] = base
		s.hmu.Unlock()
	}
	r := ratio & 0xff
	binary.LittleEndian.PutUint64(b[:], base|r<<8|r)
	_, err = f.WriteAt(b[:], msrHWPRequest)
	return err
}

type sysfsSetter struct{}

func (sysfsSetter) SetRatio(cpu int, ratio uint64) error {
	khz := strconv.FormatUint(ratio*100000, 10)
	base := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/", cpu)
	// Order matters: min must never exceed max. Try max-then-min, and if
	// that fails (lowering), min-then-max.
	maxF, minF := base+"scaling_max_freq", base+"scaling_min_freq"
	if err := os.WriteFile(maxF, []byte(khz), 0); err == nil {
		return os.WriteFile(minF, []byte(khz), 0)
	}
	if err := os.WriteFile(minF, []byte(khz), 0); err != nil {
		return err
	}
	return os.WriteFile(maxF, []byte(khz), 0)
}

// FakeSetter records writes; used by tests (PStateBackend "fake").
type FakeSetter struct {
	mu     sync.Mutex
	Writes []uint64
}

// SetRatio records the ratio.
func (f *FakeSetter) SetRatio(cpu int, ratio uint64) error {
	f.mu.Lock()
	f.Writes = append(f.Writes, ratio)
	f.mu.Unlock()
	return nil
}

// platformRatios returns (min, max non-turbo) ratio from MSR_PLATFORM_INFO.
func platformRatios() (uint64, uint64, error) {
	f, err := os.Open("/dev/cpu/0/msr")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var b [8]byte
	if _, err := f.ReadAt(b[:], msrPlatformInfo); err != nil {
		return 0, 0, err
	}
	v := binary.LittleEndian.Uint64(b[:])
	hi := (v >> 8) & 0xff
	lo := (v >> 40) & 0xff
	if lo == 0 || hi < lo {
		return 0, 0, fmt.Errorf("implausible MSR_PLATFORM_INFO %#x", v)
	}
	return lo, hi, nil
}

func currentCPU() int {
	var cpu, node uint32
	_, _, e := unix.RawSyscall(unix.SYS_GETCPU, uintptr(unsafe.Pointer(&cpu)), uintptr(unsafe.Pointer(&node)), 0)
	if e != 0 {
		return 0
	}
	return int(cpu)
}

// ---------------------------------------------------------------------------
// Noise injection (Class 4)
// ---------------------------------------------------------------------------

// injectNoise busy-spins for U[0, maxNs] ns. Busy-wait (not sleep) so the
// delay has sub-microsecond resolution and the core stays active.
func injectNoise(maxNs int64) {
	d := time.Duration(secureRand.uint64() % uint64(maxNs+1))
	start := time.Now()
	for time.Since(start) < d {
	}
}

// ---------------------------------------------------------------------------
// Blinding (Class 1): P' = P + [r]Q, m' = m - r mod ord(Q)
// ---------------------------------------------------------------------------

var (
	orderA = new(big.Int).Lsh(big.NewInt(1), 372)                  // 2^372
	orderB = new(big.Int).Exp(big.NewInt(3), big.NewInt(239), nil) // 3^239
)

func orderForBits(nbits uint) *big.Int {
	switch nbits {
	case params.A.SecretBitLen:
		return orderA
	case params.B.SecretBitLen:
		return orderB
	}
	return nil
}

// scalarMul3PtBlinded computes x(P + [m]Q) as x(P' + [m']Q) where
// P' = P + [r]Q and m' = m - r mod ord(Q), for fresh random r in [1, ord).
// Inputs to the final ladder: x(P'), x(Q), x(P' - Q) = x(P + [r-1]Q).
// Cost: three ladders. NOTE: the big.Int arithmetic on m is not constant
// time; acceptable for a characterization prototype, not for deployment.
func scalarMul3PtBlinded(st *defenseState, cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, nbits uint, scalar []uint8) ProjectivePoint {
	order := orderForBits(nbits)
	if order == nil {
		atomic.AddUint64(&stBlindFB, 1)
		return ladderDispatch(st, cparams, P, Q, PmQ, nbits, scalar)
	}
	obits := uint(new(big.Int).Sub(order, big.NewInt(1)).BitLen())
	nbytes := int(obits+7) / 8

	m := leToInt(scalar[:(nbits+7)/8])
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), nbits), big.NewInt(1))
	m.And(m, mask) // the ladder only ever reads the low nbits bits

	r, err := crand.Int(crand.Reader, new(big.Int).Sub(order, big.NewInt(1)))
	if err != nil {
		panic("defense: crypto/rand failed: " + err.Error())
	}
	r.Add(r, big.NewInt(1)) // r in [1, order-1]
	rm1 := new(big.Int).Sub(r, big.NewInt(1))
	mp := new(big.Int).Sub(m, r)
	mp.Mod(mp, order)

	Pp := ladderDispatch(st, cparams, P, Q, PmQ, obits, intToLE(r, nbytes))
	PpmQ := ladderDispatch(st, cparams, P, Q, PmQ, obits, intToLE(rm1, nbytes))
	return ladderDispatch(st, cparams, &Pp, Q, &PpmQ, obits, intToLE(mp, nbytes))
}

func leToInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

func intToLE(x *big.Int, n int) []byte {
	be := x.FillBytes(make([]byte, n))
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return be
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// secureRand is a buffered crypto/rand source: the P-state schedule and the
// noise delays must not be predictable by the attacker.
var secureRand = &bufRand{}

type bufRand struct {
	mu  sync.Mutex
	buf [4096]byte
	pos int
}

func (b *bufRand) uint64() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pos == 0 || b.pos+8 > len(b.buf) {
		if _, err := crand.Read(b.buf[:]); err != nil {
			panic("defense: crypto/rand failed: " + err.Error())
		}
		b.pos = 0
	}
	v := binary.LittleEndian.Uint64(b.buf[b.pos:])
	b.pos += 8
	return v
}

func (b *bufRand) intn(n int) int { return int(b.uint64() % uint64(n)) } // bias negligible for small n

func parseInts(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if i := strings.Index(f, "-"); i > 0 { // range a-b
			a, e1 := strconv.Atoi(f[:i])
			b, e2 := strconv.Atoi(f[i+1:])
			if e1 != nil || e2 != nil || b < a {
				return nil, fmt.Errorf("bad range %q", f)
			}
			for x := a; x <= b; x++ {
				out = append(out, x)
			}
			continue
		}
		x, err := strconv.Atoi(f)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}

func joinU64(xs []uint64) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.FormatUint(x, 10)
	}
	return strings.Join(s, ",")
}
