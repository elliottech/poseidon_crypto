package ecgfp5

import (
	"math/big"

	config "github.com/consensys/gnark-crypto/field/generator/config"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
)

// A curve point in short Weirstrass form (x, y). This is used by the in-circuit representation
type WeierstrassPoint struct {
	X     config.Element
	Y     config.Element
	IsInf bool
}

var (
	GENERATOR_WEIERSTRASS = WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(11712523173042564207),
			*new(big.Int).SetUint64(14090224426659529053),
			*new(big.Int).SetUint64(13197813503519687414),
			*new(big.Int).SetUint64(16280770174934269299),
			*new(big.Int).SetUint64(15998333998318935536),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(14639054205878357578),
			*new(big.Int).SetUint64(17426078571020221072),
			*new(big.Int).SetUint64(2548978194165003307),
			*new(big.Int).SetUint64(8663895577921260088),
			*new(big.Int).SetUint64(9793640284382595140),
		},
		IsInf: false,
	}
)

func (p WeierstrassPoint) Equals(q WeierstrassPoint) bool {
	if p.IsInf && q.IsInf {
		return true
	}
	return fp5.Fp5Equals(p.X, q.X) && fp5.Fp5Equals(p.Y, q.Y)
}

func (p WeierstrassPoint) Encode() config.Element {
	return fp5.Fp5Div(p.Y, fp5.Fp5Sub(fp5.Fp5Div(A_ECgFp5Point, fp5.Fp5FromUint64(3)), p.X))
}

func DecodeAsWeierstrass(w config.Element) (WeierstrassPoint, bool) {
	e := fp5.Fp5Sub(fp5.Fp5Square(w), A_ECgFp5Point)
	delta := fp5.Fp5Sub(fp5.Fp5Square(e), B_MUL4_ECgFp5Point)
	r, success := fp5.Fp5CanonicalSqrt(delta)
	if !success {
		r = fp5.Fp5DeepCopy(fp5.FP5_ZERO)
	}

	x1 := fp5.Fp5Div(fp5.Fp5Add(e, r), fp5.FP5_TWO)
	x2 := fp5.Fp5Div(fp5.Fp5Sub(e, r), fp5.FP5_TWO)

	x := x1
	x1Legendre := fp5.Fp5Legendre(x1)
	if !x1Legendre.IsOne() {
		x = x2
	}

	y := fp5.Fp5Neg(fp5.Fp5Mul(w, x))
	if success {
		x = fp5.Fp5Add(x, fp5.Fp5Div(A_ECgFp5Point, fp5.Fp5FromUint64(3)))
	} else {
		x = fp5.Fp5DeepCopy(fp5.FP5_ZERO)
	}

	isInf := !success

	// If w == 0 then this is in fact a success.
	if success || fp5.Fp5IsZero(w) {
		return WeierstrassPoint{X: x, Y: y, IsInf: isInf}, true
	}
	return WeierstrassPoint{}, false
}
