package ecgfp5

import (
	"math/big"

	config "github.com/consensys/gnark-crypto/field/generator/config"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
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

	A_WEIERSTRASS = config.Element{
		*new(big.Int).SetUint64(6148914689804861439),
		*new(big.Int).SetUint64(263),
		*new(big.Int).SetUint64(0),
		*new(big.Int).SetUint64(0),
		*new(big.Int).SetUint64(0),
	}

	NEUTRAL_WEIERSTRASS = WeierstrassPoint{
		X:     fp5.Fp5DeepCopy(fp5.FP5_ZERO),
		Y:     fp5.Fp5DeepCopy(fp5.FP5_ZERO),
		IsInf: true,
	}
)

func (p WeierstrassPoint) DeepCopy() WeierstrassPoint {
	return WeierstrassPoint{
		X:     fp5.Fp5DeepCopy(p.X),
		Y:     fp5.Fp5DeepCopy(p.Y),
		IsInf: p.IsInf,
	}
}

func (p WeierstrassPoint) Equals(q WeierstrassPoint) bool {
	if p.IsInf && q.IsInf {
		return true
	}
	return fp5.Fp5Equals(p.X, q.X) && fp5.Fp5Equals(p.Y, q.Y)
}

func (p WeierstrassPoint) Encode() config.Element {
	return fp5.Fp5Div(p.Y, fp5.Fp5Sub(fp5.Fp5Div(A_ECgFp5Point, fp5.Fp5FromUint64(3)), p.X))
}

func DecodeFp5AsWeierstrass(w config.Element) (WeierstrassPoint, bool) {
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

func (p WeierstrassPoint) Add(q WeierstrassPoint) WeierstrassPoint {
	if p.IsInf {
		return q.DeepCopy()
	}
	if q.IsInf {
		return p.DeepCopy()
	}

	x1, y1 := fp5.Fp5DeepCopy(p.X), fp5.Fp5DeepCopy(p.Y)
	x2, y2 := fp5.Fp5DeepCopy(q.X), fp5.Fp5DeepCopy(q.Y)

	// note: paper has a typo. sx == 1 when x1 != x2, not when x1 == x2
	xSame := fp5.Fp5Equals(x1, x2)
	yDiff := !fp5.Fp5Equals(y1, y2)

	var lambda0, lambda1 config.Element
	if xSame {
		lambda0 = fp5.Fp5Add(fp5.Fp5Triple(fp5.Fp5Square(x1)), fp5.Fp5DeepCopy(A_WEIERSTRASS))
		lambda1 = fp5.Fp5Double(y1)
	} else {
		lambda0 = fp5.Fp5Sub(y2, y1)
		lambda1 = fp5.Fp5Sub(x2, x1)
	}
	lambda := fp5.Fp5Div(lambda0, lambda1)

	x3 := fp5.Fp5Sub(fp5.Fp5Sub(fp5.Fp5Square(lambda), x1), x2)
	y3 := fp5.Fp5Sub(fp5.Fp5Mul(lambda, fp5.Fp5Sub(x1, x3)), y1)

	return WeierstrassPoint{X: x3, Y: y3, IsInf: xSame && yDiff}
}

func (p WeierstrassPoint) Double() WeierstrassPoint {
	x := fp5.Fp5DeepCopy(p.X)
	y := fp5.Fp5DeepCopy(p.Y)
	is_inf := p.IsInf

	if is_inf {
		return p.DeepCopy()
	}

	lambda0 := fp5.Fp5Square(x)
	lambda0 = fp5.Fp5Triple(lambda0)
	lambda0 = fp5.Fp5Add(lambda0, fp5.Fp5DeepCopy(A_WEIERSTRASS))

	lambda1 := fp5.Fp5Double(y)

	lambda := fp5.Fp5Div(lambda0, lambda1)

	x2 := fp5.Fp5Square(lambda)
	two_x := fp5.Fp5Double(x)
	x2 = fp5.Fp5Sub(x2, two_x)

	y2 := fp5.Fp5Sub(x, x2)
	y2 = fp5.Fp5Mul(lambda, y2)
	y2 = fp5.Fp5Sub(y2, y)

	return WeierstrassPoint{X: x2, Y: y2, IsInf: is_inf}
}

func (p WeierstrassPoint) PrecomputeWindow(windowBits uint32) []WeierstrassPoint {
	if windowBits < 2 {
		panic("windowBits in PrecomputeWindow for WeierstrassPoint must be at least 2")
	}
	multiples := []WeierstrassPoint{NEUTRAL_WEIERSTRASS.DeepCopy(), p.DeepCopy(), p.Double()}
	for i := 3; i < 1<<windowBits; i++ {
		multiples = append(multiples, p.Add(multiples[len(multiples)-1]))
	}
	return multiples
}

func MulAdd2(a, b WeierstrassPoint, scalarA, scalarB sf.ECgFp5Scalar) WeierstrassPoint {
	aWindow := a.PrecomputeWindow(4)
	aFourBitLimbs := scalarA.SplitTo4BitLimbs()

	bWindow := b.PrecomputeWindow(4)
	bFourBitLimbs := scalarB.SplitTo4BitLimbs()

	numLimbs := len(aFourBitLimbs)

	res := aWindow[aFourBitLimbs[numLimbs-1]].Add(bWindow[bFourBitLimbs[numLimbs-1]])
	for i := numLimbs - 2; i >= 0; i-- {
		for j := 0; j < 4; j++ {
			res = res.Double()
		}
		res = res.Add(aWindow[aFourBitLimbs[i]].Add(bWindow[bFourBitLimbs[i]]))
	}
	return res
}
