package p751

// Hertzbleed defense project, Class 1 "ciphertext validation" probe.
// Ports upstream CIRCL 10923e8 PublicKeyValidation (the CLN test) verbatim in
// logic and runs it on (a) honest public keys and (b) the Hertzbleed attack
// ciphertext produced by Prep_ct. Does not change the decaps path.
//   go test -count=1 -run TestCLNProbe -v ./dh/sidh/internal/p751/
//   go test -run XXX -bench CLNVsLadder -benchtime 200x ./dh/sidh/internal/p751/

import (
	"crypto/rand"
	"errors"
	"math"
	"testing"
	"time"

	. "github.com/cloudflare/circl/dh/sidh/internal/common"
)

func probeIsZero(x *Fp2) bool {
	var y Fp2
	FromMontgomery(&y, x)
	for i := range y.A {
		if y.A[i] != 0 || y.B[i] != 0 {
			return false
		}
	}
	return true
}

func probeCLN(cparams *ProjectiveCurveParameters, P, Q, PmQ *ProjectivePoint, nbits uint) error {
	if probeIsZero(&PmQ.X) || probeIsZero(&PmQ.Z) {
		return errors.New("check0: PmQ is T(0,0) or O")
	}
	cparam := CalcCurveParamsEquiv3(cparams)
	e3 := uint32(float64(int(nbits)+1) / math.Log2(3))
	tP, tQ := *P, *Q
	Pow3k(&tP, &cparam, e3-1)
	Pow3k(&tQ, &cparam, e3-1)
	if probeIsZero(&tP.Z) || probeIsZero(&tQ.Z) {
		return errors.New("check1: P or Q not of full order 3^e3 ([3^(e3-1)]P = O)")
	}
	var a, b, d Fp2
	mul(&a, &tP.X, &tQ.Z)
	mul(&b, &tP.Z, &tQ.X)
	sub(&d, &a, &b)
	if probeIsZero(&d) {
		return errors.New("check2: [3^(e3-1)]P = ±[3^(e3-1)]Q (not independent)")
	}
	Pow3k(&tP, &cparam, 1)
	Pow3k(&tQ, &cparam, 1)
	if !probeIsZero(&tP.Z) || !probeIsZero(&tQ.Z) {
		return errors.New("check3: [3^e3]P != O or [3^e3]Q != O (order not 3^e3)")
	}
	return nil
}

func probeValidate(pub *[3]Fp2) error {
	c := params.InitCurve
	RecoverCoordinateA(&c, &pub[0], &pub[1], &pub[2])
	P := ProjectivePoint{X: pub[0], Z: params.OneFp2}
	Q := ProjectivePoint{X: pub[1], Z: params.OneFp2}
	R := ProjectivePoint{X: pub[2], Z: params.OneFp2}
	return probeCLN(&c, &P, &Q, &R, params.B.SecretBitLen)
}

func TestCLNProbe(t *testing.T) {
	e3 := uint32(float64(int(params.B.SecretBitLen)+1) / math.Log2(3))
	t.Logf("B.SecretBitLen=%d  -> e3=%d", params.B.SecretBitLen, e3)

	// (a) honest Alice public keys (what Bob/decapsulator receives)
	for i := 0; i < 5; i++ {
		var pub [3]Fp2
		prv := make([]byte, params.A.SecretByteLen)
		_, _ = rand.Read(prv)
		prv[len(prv)-1] &= (1 << (params.A.SecretBitLen % 8)) - 1
		PublicKeyGenA(&pub, prv)
		t.Logf("honest key %d: %v", i, probeValidate(&pub))
	}

	// (b) Hertzbleed attack ciphertext, built as POC_ATTACK/sike_local.go does
	cparam := params.InitCurve // A=6, C=1: same constants the POC passes
	for _, bit := range []uint{1, 2, 10, 100, 300} {
		for trial := 0; trial < 3; trial++ {
			sk := make([]byte, params.B.SecretByteLen)
			_, _ = rand.Read(sk)
			x0, x1, x2 := Prep_ct(&cparam, params.B.SecretBitLen, sk, bit, 1)
			pub := [3]Fp2{x1, x0, x2} // Modify_PublicKey order
			t.Logf("attack ct bit=%3d trial=%d: %v", bit, trial, probeValidate(&pub))
		}
	}
}

func BenchmarkCLNVsLadder(b *testing.B) {
	var pub [3]Fp2
	prv := make([]byte, params.A.SecretByteLen)
	_, _ = rand.Read(prv)
	prv[len(prv)-1] &= (1 << (params.A.SecretBitLen % 8)) - 1
	PublicKeyGenA(&pub, prv)
	skB := make([]byte, params.B.SecretByteLen)
	_, _ = rand.Read(skB)
	var ss [2 * 94]byte

	b.Run("CLN", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = probeValidate(&pub)
		}
	})
	b.Run("DeriveSecretB", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			DeriveSecretB(ss[:], skB, &pub)
		}
	})
	b.Run("PublicKeyGenA", func(b *testing.B) {
		var p [3]Fp2
		for i := 0; i < b.N; i++ {
			PublicKeyGenA(&p, prv)
		}
	})
	_ = time.Now
}
