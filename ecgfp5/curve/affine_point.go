package ecgfp5

import (
	config "github.com/consensys/gnark-crypto/field/generator/config"
	utils "github.com/elliottech/poseidon_crypto"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
)

// A curve point in affine (x,u) coordinates. This is used internally
// to make "windows" that speed up point multiplications.
type AffinePoint struct {
	x, u config.Element
}

var AFFINE_NEUTRAL = AffinePoint{
	x: fp5.Fp5DeepCopy(fp5.FP5_ZERO),
	u: fp5.Fp5DeepCopy(fp5.FP5_ZERO),
}

func (p AffinePoint) DeepCopy() AffinePoint {
	return AffinePoint{
		x: fp5.Fp5DeepCopy(p.x),
		u: fp5.Fp5DeepCopy(p.u),
	}
}

func (p AffinePoint) ToPoint() ECgFp5Point {
	return ECgFp5Point{
		x: p.x,
		z: fp5.Fp5DeepCopy(fp5.FP5_ONE),
		u: p.u,
		t: fp5.Fp5DeepCopy(fp5.FP5_ONE),
	}
}

func (p *AffinePoint) SetNeg() {
	p.u = fp5.Fp5Neg(p.u)
}

// Lookup a point in a window. The win[] slice must contain values
// i*P for i = 1 to n (win[0] contains P, win[1] contains 2*P, and
// so on). Index value k is an integer in the -n to n range; returned
// point is k*P.
func (p *AffinePoint) SetLookup(win []AffinePoint, k int32) {
	// sign = 0xFFFFFFFF if k < 0, 0x00000000 otherwise
	sign := uint32(k >> 31)
	// ka = abs(k)
	ka := (uint32(k) ^ sign) - sign
	// km1 = ka - 1
	km1 := ka - 1

	x := fp5.Fp5DeepCopy(fp5.FP5_ZERO)
	u := fp5.Fp5DeepCopy(fp5.FP5_ZERO)
	for i := 0; i < len(win); i++ {
		m := km1 - uint32(i)
		c_1 := (m | utils.WrappingNegU32(m)) >> 31
		c := uint64(c_1) - 1
		if c != 0 {
			x = fp5.Fp5DeepCopy(win[i].x)
			u = fp5.Fp5DeepCopy(win[i].u)
		}

	}

	// If k < 0, then we must negate the point.
	c := uint64(sign) | (uint64(sign) << 32)
	p.x = x
	p.u = u

	if c != 0 {
		p.u = fp5.Fp5Neg(p.u)
	}
}

func Lookup(win []AffinePoint, k int32) AffinePoint {
	r := AFFINE_NEUTRAL.DeepCopy()
	r.SetLookup(win, k)
	return r
}

// Same as lookup(), except this implementation is variable-time.
func LookupVarTime(win []AffinePoint, k int32) AffinePoint {
	if k == 0 {
		return AFFINE_NEUTRAL.DeepCopy()
	} else if k > 0 {
		return win[k-1].DeepCopy()
	} else {
		res := win[-k-1].DeepCopy()
		res.SetNeg()
		return res
	}
}
