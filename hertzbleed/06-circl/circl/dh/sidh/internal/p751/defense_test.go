package p751

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	. "github.com/cloudflare/circl/dh/sidh/internal/common"
)

// bobInputs returns Bob's public basis x(P), x(Q), x(Q-P) on the start curve,
// i.e. valid points of order 3^239 (the decapsulation-side ladder).
func bobInputs() (ProjectiveCurveParameters, ProjectivePoint, ProjectivePoint, ProjectivePoint) {
	return params.InitCurve,
		ProjectivePoint{X: params.B.AffineP, Z: params.OneFp2},
		ProjectivePoint{X: params.B.AffineQ, Z: params.OneFp2},
		ProjectivePoint{X: params.B.AffineR, Z: params.OneFp2}
}

func aliceInputs() (ProjectiveCurveParameters, ProjectivePoint, ProjectivePoint, ProjectivePoint) {
	return params.InitCurve,
		ProjectivePoint{X: params.A.AffineP, Z: params.OneFp2},
		ProjectivePoint{X: params.A.AffineQ, Z: params.OneFp2},
		ProjectivePoint{X: params.A.AffineR, Z: params.OneFp2}
}

func randScalar(t *testing.T, nbits uint) []byte {
	s := make([]byte, 48)
	if _, err := crand.Read(s[:(nbits+7)/8]); err != nil {
		t.Fatal(err)
	}
	if nbits%8 != 0 {
		s[nbits/8] &= byte(1<<(nbits%8)) - 1
	}
	return s
}

func mustConfigure(t *testing.T, c DefenseConfig) {
	t.Helper()
	if err := Configure(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Configure(DefenseConfig{}) })
}

func exactEq(a, b *ProjectivePoint) bool { return a.X == b.X && a.Z == b.Z }

// TestChunkedLadderMatchesOriginal: the chunked / pipelined / P-state-epoch
// ladder must give bit-identical R1.X/R1.Z to the original ladder.
func TestChunkedLadderMatchesOriginal(t *testing.T) {
	curve, P, Q, PmQ := bobInputs()
	nbits := params.B.SecretBitLen
	configs := []DefenseConfig{
		{Stages: 1}, {Stages: 2}, {Stages: 5}, {Stages: 14}, {Stages: 18},
		{Stages: 21}, {Stages: 27}, {Stages: 378},
		{Stages: 14, Workers: 4},
		{Stages: 27, Workers: 2, WorkerCPUs: []int{0, 0}},
		{Stages: 14, PStateRand: true, PStateBackend: "fake", PStateRatios: []uint64{8, 12, 20}},
		{Stages: 14, Workers: 3, PStateRand: true, PStateBackend: "fake", PStateRatios: []uint64{8, 20}, PStateScope: "all"},
	}
	for _, c := range configs {
		mustConfigure(t, c)
		for i := 0; i < 8; i++ {
			s := randScalar(t, nbits)
			want := scalarMul3PtRef(&curve, &P, &Q, &PmQ, nbits, s)
			got := ScalarMul3Pt(&curve, &P, &Q, &PmQ, nbits, s)
			if !exactEq(&want, &got) {
				t.Fatalf("config %v: chunked ladder differs from original", c)
			}
		}
	}
}

func TestChunkBounds(t *testing.T) {
	for _, n := range []int{1, 14, 18, 21, 27, 5, 1000} {
		b := ChunkBounds(378, n)
		if b[0] != 0 || b[len(b)-1] != 378 {
			t.Fatalf("stages=%d: bad bounds %v", n, b)
		}
		for k := 1; k < len(b); k++ {
			if b[k] <= b[k-1] {
				t.Fatalf("stages=%d: empty chunk in %v", n, b)
			}
		}
	}
	if b := ChunkBounds(378, 14); b[1] != 27 {
		t.Fatalf("14 stages should give 27-iteration chunks, got %v", b)
	}
}

func TestPStateRandWritesPerChunk(t *testing.T) {
	curve, P, Q, PmQ := bobInputs()
	mustConfigure(t, DefenseConfig{Stages: 18, PStateRand: true, PStateBackend: "fake", PStateRatios: []uint64{8, 9, 10}})
	before := GetDefenseStats()
	ScalarMul3Pt(&curve, &P, &Q, &PmQ, params.B.SecretBitLen, randScalar(t, 378))
	fs := current().setter.(*FakeSetter)
	if len(fs.Writes) != 18 {
		t.Fatalf("want 18 P-state writes, got %d", len(fs.Writes))
	}
	for _, r := range fs.Writes {
		if r < 8 || r > 10 {
			t.Fatalf("ratio %d outside configured set", r)
		}
	}
	if d := GetDefenseStats().PStateWrites - before.PStateWrites; d != 18 {
		t.Fatalf("stats: want 18 writes, got %d", d)
	}
}

// Blinding changes the projective representative, so compare projectively.
func TestBlindedLadderMatchesOriginal(t *testing.T) {
	type side struct {
		name   string
		inputs func() (ProjectiveCurveParameters, ProjectivePoint, ProjectivePoint, ProjectivePoint)
		nbits  uint
	}
	for _, sd := range []side{{"B", bobInputs, params.B.SecretBitLen}, {"A", aliceInputs, params.A.SecretBitLen}} {
		for _, c := range []DefenseConfig{{Blind: true}, {Blind: true, Stages: 14, Workers: 2}} {
			mustConfigure(t, c)
			curve, P, Q, PmQ := sd.inputs()
			for i := 0; i < 6; i++ {
				s := randScalar(t, sd.nbits)
				want := scalarMul3PtRef(&curve, &P, &Q, &PmQ, sd.nbits, s)
				got := ScalarMul3Pt(&curve, &P, &Q, &PmQ, sd.nbits, s)
				if !vartimeEqProjFp2(&want, &got) {
					t.Fatalf("side %s config %v: blinded ladder differs", sd.name, c)
				}
			}
		}
	}
	if GetDefenseStats().BlindFallbacks != 0 {
		t.Fatal("unexpected blind fallback")
	}
}

func TestNoiseKeepsResult(t *testing.T) {
	curve, P, Q, PmQ := bobInputs()
	mustConfigure(t, DefenseConfig{NoiseMaxNs: 20000})
	s := randScalar(t, 378)
	want := scalarMul3PtRef(&curve, &P, &Q, &PmQ, 378, s)
	got := ScalarMul3Pt(&curve, &P, &Q, &PmQ, 378, s)
	if !exactEq(&want, &got) {
		t.Fatal("noise injection changed the result")
	}
}

// End-to-end: SIDH shared secret (Bob side = SIKE decapsulation ladder)
// must be identical under every defense.
func TestSharedSecretUnderDefenses(t *testing.T) {
	skA := randScalar(t, params.A.SecretBitLen)[:params.A.SecretByteLen]
	skB := randScalar(t, params.B.SecretBitLen)[:params.B.SecretByteLen]
	var pkA, pkB [3]Fp2
	PublicKeyGenA(&pkA, skA)
	PublicKeyGenB(&pkB, skB)
	ref := make([]byte, params.SharedSecretSize)
	DeriveSecretB(ref, skB, &pkA)
	refA := make([]byte, params.SharedSecretSize)
	DeriveSecretA(refA, skA, &pkB)
	if !bytes.Equal(ref, refA) {
		t.Fatal("reference SIDH shared secrets differ")
	}
	for _, c := range []DefenseConfig{
		{Stages: 14, Workers: 4},
		{Stages: 21, PStateRand: true, PStateBackend: "fake", PStateRatios: []uint64{8, 20}},
		{NoiseMaxNs: 1000},
		{Blind: true},
		{Blind: true, Stages: 27, Workers: 3, NoiseMaxNs: 1000},
	} {
		mustConfigure(t, c)
		ss := make([]byte, params.SharedSecretSize)
		DeriveSecretB(ss, skB, &pkA)
		if !bytes.Equal(ss, ref) {
			t.Fatalf("config %v: shared secret differs", c)
		}
	}
}

func TestParseInts(t *testing.T) {
	xs, err := parseInts("0-3, 8,10")
	if err != nil || len(xs) != 6 || xs[3] != 3 || xs[5] != 10 {
		t.Fatalf("got %v %v", xs, err)
	}
}

func BenchmarkLadderDefenses(b *testing.B) {
	curve, P, Q, PmQ := bobInputs()
	s := make([]byte, 48)
	_, _ = crand.Read(s[:47])
	for _, bc := range []struct {
		name string
		cfg  DefenseConfig
	}{
		{"ref", DefenseConfig{}},
		{"chunk14", DefenseConfig{Stages: 14}},
		{"pipeline14x4", DefenseConfig{Stages: 14, Workers: 4}},
		{"blind", DefenseConfig{Blind: true}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			if err := Configure(bc.cfg); err != nil {
				b.Fatal(err)
			}
			for n := 0; n < b.N; n++ {
				ScalarMul3Pt(&curve, &P, &Q, &PmQ, 378, s)
			}
		})
	}
	_ = Configure(DefenseConfig{})
}
