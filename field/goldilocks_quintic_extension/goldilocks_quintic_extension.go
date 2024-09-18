package goldilocks_quintic_extension

import (
	"math/big"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type Element [5]uint64

var (
	FP5_D = 5

	FP5_ZERO = Element{0, 0, 0, 0, 0}
	FP5_ONE  = Element{1, 0, 0, 0, 0}
	FP5_TWO  = Element{2, 0, 0, 0, 0}

	FP5_W        = g.FromUint64(3)
	FP5_DTH_ROOT = g.FromUint64(1041288259238279555)
)

func Fp5Sample() Element {
	arr := g.RandArray(5)
	return FArrayToFp5([5]g.Element{arr[0], arr[1], arr[2], arr[3], arr[4]})
}

func Fp5Equals(a, b Element) bool {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4]
}

func Fp5IsZero(e Element) bool {
	return e[0] == 0 && e[1] == 0 && e[2] == 0 && e[3] == 0 && e[4] == 0
}

func Fp5DeepCopy(e Element) Element {
	return Element{e[0], e[1], e[2], e[3], e[4]}
}

func Fp5FromF(elem g.Element) Element {
	return Element{elem.Uint64(), 0, 0, 0, 0}
}

func Fp5ToFArray(e Element) [5]g.Element {
	return [5]g.Element{
		g.FromUint64(e[0]),
		g.FromUint64(e[1]),
		g.FromUint64(e[2]),
		g.FromUint64(e[3]),
		g.FromUint64(e[4]),
	}
}

func FArrayToFp5(e [5]g.Element) Element {
	return Element{
		e[0].Uint64(),
		e[1].Uint64(),
		e[2].Uint64(),
		e[3].Uint64(),
		e[4].Uint64(),
	}
}

func Uint64ArrayToFp5(e1, e2, e3, e4, e5 uint64) Element {
	return Element{e1, e2, e3, e4, e5}
}

func Fp5Neg(e Element) Element {
	eCopy := Fp5ToFArray(e)
	return FArrayToFp5([5]g.Element{
		g.Neg(eCopy[0]),
		g.Neg(eCopy[1]),
		g.Neg(eCopy[2]),
		g.Neg(eCopy[3]),
		g.Neg(eCopy[4]),
	})
}

func Fp5Add(a, b Element) Element {
	aCopy := Fp5ToFArray(a)
	bCopy := Fp5ToFArray(b)

	return FArrayToFp5([5]g.Element{
		g.FAdd(aCopy[0], bCopy[0]),
		g.FAdd(aCopy[1], bCopy[1]),
		g.FAdd(aCopy[2], bCopy[2]),
		g.FAdd(aCopy[3], bCopy[3]),
		g.FAdd(aCopy[4], bCopy[4]),
	})
}

func Fp5Sub(a, b Element) Element {
	aCopy := Fp5ToFArray(a)
	bCopy := Fp5ToFArray(b)

	return FArrayToFp5([5]g.Element{
		g.FSub(&aCopy[0], &bCopy[0]),
		g.FSub(&aCopy[1], &bCopy[1]),
		g.FSub(&aCopy[2], &bCopy[2]),
		g.FSub(&aCopy[3], &bCopy[3]),
		g.FSub(&aCopy[4], &bCopy[4]),
	})
}

func Fp5Mul(a, b Element) Element {
	aCopy := Fp5ToFArray(a)
	bCopy := Fp5ToFArray(b)
	w := g.FDeepCopy(&FP5_W)

	a0b0 := g.FMul(&aCopy[0], &bCopy[0])
	a1b4 := g.FMul(&aCopy[1], &bCopy[4])
	a2b3 := g.FMul(&aCopy[2], &bCopy[3])
	a3b2 := g.FMul(&aCopy[3], &bCopy[2])
	a4b1 := g.FMul(&aCopy[4], &bCopy[1])
	added := g.FAdd(a1b4, a2b3, a3b2, a4b1)
	muld := g.FMul(&w, &added)
	c0 := g.FAdd(a0b0, muld)

	a0b1 := g.FMul(&aCopy[0], &bCopy[1])
	a1b0 := g.FMul(&aCopy[1], &bCopy[0])
	a2b4 := g.FMul(&aCopy[2], &bCopy[4])
	a3b3 := g.FMul(&aCopy[3], &bCopy[3])
	a4b2 := g.FMul(&aCopy[4], &bCopy[2])
	added = g.FAdd(a2b4, a3b3, a4b2)
	muld = g.FMul(&w, &added)
	c1 := g.FAdd(a0b1, a1b0, muld)

	a0b2 := g.FMul(&aCopy[0], &bCopy[2])
	a1b1 := g.FMul(&aCopy[1], &bCopy[1])
	a2b0 := g.FMul(&aCopy[2], &bCopy[0])
	a3b4 := g.FMul(&aCopy[3], &bCopy[4])
	a4b3 := g.FMul(&aCopy[4], &bCopy[3])
	added = g.FAdd(a3b4, a4b3)
	muld = g.FMul(&w, &added)
	c2 := g.FAdd(a0b2, a1b1, a2b0, muld)

	a0b3 := g.FMul(&aCopy[0], &bCopy[3])
	a1b2 := g.FMul(&aCopy[1], &bCopy[2])
	a2b1 := g.FMul(&aCopy[2], &bCopy[1])
	a3b0 := g.FMul(&aCopy[3], &bCopy[0])
	a4b4 := g.FMul(&aCopy[4], &bCopy[4])
	muld = g.FMul(&w, &a4b4)
	c3 := g.FAdd(a0b3, a1b2, a2b1, a3b0, muld)

	a0b4 := g.FMul(&aCopy[0], &bCopy[4])
	a1b3 := g.FMul(&aCopy[1], &bCopy[3])
	a2b2 := g.FMul(&aCopy[2], &bCopy[2])
	a3b1 := g.FMul(&aCopy[3], &bCopy[1])
	a4b0 := g.FMul(&aCopy[4], &bCopy[0])
	c4 := g.FAdd(a0b4, a1b3, a2b2, a3b1, a4b0)

	return FArrayToFp5([5]g.Element{c0, c1, c2, c3, c4})
}

func Fp5Div(a, b Element) Element {
	bInv := Fp5InverseOrZero(b)
	if Fp5IsZero(bInv) {
		panic("division by zero")
	}
	return Fp5Mul(a, bInv)
}

func Fp5ExpPowerOf2(x Element, power int) Element {
	res := Fp5DeepCopy(x)
	for i := 0; i < power; i++ {
		res = Fp5Square(res)
	}
	return res
}

func Fp5Square(a Element) Element {
	aCopy := Fp5ToFArray(a)
	w := g.FDeepCopy(&FP5_W)
	double_w := g.FAdd(w, w)

	a0s := g.FMul(&aCopy[0], &aCopy[0])
	a1a4 := g.FMul(&aCopy[1], &aCopy[4])
	a2a3 := g.FMul(&aCopy[2], &aCopy[3])
	added := g.FAdd(a1a4, a2a3)
	muld := g.FMul(&double_w, &added)
	c0 := g.FAdd(a0s, muld)

	a0Double := g.FAdd(aCopy[0], aCopy[0])
	a0Doublea1 := g.FMul(&a0Double, &aCopy[1])
	a2a4DoubleW := g.FMul(&aCopy[2], &aCopy[4], &double_w)
	a3a3w := g.FMul(&aCopy[3], &aCopy[3], &w)
	c1 := g.FAdd(a0Doublea1, a2a4DoubleW, a3a3w)

	a0Doublea2 := g.FMul(&a0Double, &aCopy[2])
	a1Square := g.FMul(&aCopy[1], &aCopy[1])
	a4a3DoubleW := g.FMul(&aCopy[4], &aCopy[3], &double_w)
	c2 := g.FAdd(a0Doublea2, a1Square, a4a3DoubleW)

	a1Double := g.FAdd(aCopy[1], aCopy[1])
	a0Doublea3 := g.FMul(&a0Double, &aCopy[3])
	a1Doublea2 := g.FMul(&a1Double, &aCopy[2])
	a4SquareW := g.FMul(&aCopy[4], &aCopy[4], &w)
	c3 := g.FAdd(a0Doublea3, a1Doublea2, a4SquareW)

	a0Doublea4 := g.FMul(&a0Double, &aCopy[4])
	a1Doublea3 := g.FMul(&a1Double, &aCopy[3])
	a2Square := g.FMul(&aCopy[2], &aCopy[2])
	c4 := g.FAdd(a0Doublea4, a1Doublea3, a2Square)

	return FArrayToFp5([5]g.Element{c0, c1, c2, c3, c4})
}

func Fp5Triple(a Element) Element {
	three := g.FromUint64(3)
	aCopy := Fp5ToFArray(a)

	return FArrayToFp5([5]g.Element{
		g.FMul(&aCopy[0], &three),
		g.FMul(&aCopy[1], &three),
		g.FMul(&aCopy[2], &three),
		g.FMul(&aCopy[3], &three),
		g.FMul(&aCopy[4], &three),
	})
}

func Fp5Sqrt(x Element) (Element, bool) {
	v := Fp5ExpPowerOf2(x, 31)
	d := Fp5Mul(Fp5Mul(x, Fp5ExpPowerOf2(v, 32)), Fp5InverseOrZero(v))
	e := Fp5Frobenius(Fp5Mul(d, Fp5RepeatedFrobenius(d, 2)))
	_f := Fp5Square(e)

	xArr := Fp5ToFArray(x)
	fArr := Fp5ToFArray(_f)

	x1f4 := g.FMul(&xArr[1], &fArr[4])
	x2f3 := g.FMul(&xArr[2], &fArr[3])
	x3f2 := g.FMul(&xArr[3], &fArr[2])
	x4f1 := g.FMul(&xArr[4], &fArr[1])
	added := g.FAdd(x1f4, x2f3, x3f2, x4f1)
	three := g.FromUint64(3)
	muld := g.FMul(&three, &added)
	x0f0 := g.FMul(&xArr[0], &fArr[0])
	_g := g.FAdd(x0f0, muld)
	s := g.FSqrt(&_g)
	if s == nil {
		return Element{}, false
	}

	eInv := Fp5InverseOrZero(e)
	sFp5 := Fp5FromF(*s)

	return Fp5Mul(sFp5, eInv), true
}

func Fp5Sgn0(x Element) bool {
	sign := false
	zero := true
	for _, limb := range x {
		sign_i := (limb & 1) == 0
		zero_i := limb == 0
		sign = sign || (zero && sign_i)
		zero = zero && zero_i
	}
	return sign
}

func Fp5CanonicalSqrt(x Element) (Element, bool) {
	sqrtX, exists := Fp5Sqrt(x)
	if !exists {
		return Element{}, false
	}

	if Fp5Sgn0(sqrtX) {
		return Fp5Neg(sqrtX), true
	}
	return sqrtX, true
}

func Fp5ScalarMul(a Element, scalar g.Element) Element {
	arr := Fp5ToFArray(a)
	for i := 0; i < len(arr); i++ {
		arr[i].Mul(&arr[i], &scalar)
	}
	return FArrayToFp5(arr)
}

func Fp5Double(a Element) Element {
	return Fp5Add(a, a)
}

func Fp5FromUint64(a uint64) Element {
	return Element{a, 0, 0, 0, 0}
}

func Fp5NegOne() Element {
	negOne := g.FNegOne()
	return Element{
		negOne.Uint64(),
		0,
		0,
		0,
		0,
	}
}

func Fp5InverseOrZero(a Element) Element {
	if Fp5IsZero(a) {
		return FP5_ZERO
	}

	d := Fp5Frobenius(a)
	e := Fp5Mul(d, Fp5Frobenius(d))
	f := Fp5Mul(e, Fp5RepeatedFrobenius(e, 2))

	aCopy := Fp5ToFArray(a)
	fCopy := Fp5ToFArray(f)

	a0b0 := g.FMul(&aCopy[0], &fCopy[0])
	a1b4 := g.FMul(&aCopy[1], &fCopy[4])
	a2b3 := g.FMul(&aCopy[2], &fCopy[3])
	a3b2 := g.FMul(&aCopy[3], &fCopy[2])
	a4b1 := g.FMul(&aCopy[4], &fCopy[1])
	added := g.FAdd(a1b4, a2b3, a3b2, a4b1)
	muld := g.FMul(&FP5_W, &added)
	g := g.FAdd(a0b0, muld)

	return Fp5ScalarMul(f, *g.Inverse(&g))
}

func Fp5Frobenius(x Element) Element {
	return Fp5RepeatedFrobenius(x, 1)
}

func Fp5RepeatedFrobenius(x Element, count int) Element {
	if count == 0 {
		return x
	} else if count >= FP5_D {
		return Fp5RepeatedFrobenius(x, count%FP5_D)
	}

	arr := Fp5ToFArray(x)

	z0 := g.FDeepCopy(&FP5_DTH_ROOT)
	for i := 1; i < count; i++ {
		z0 = g.FMul(&FP5_DTH_ROOT, &z0)
	}

	res := Fp5ToFArray(FP5_ZERO)
	for i, z := range g.FPowers(&z0, FP5_D) {
		muld := g.FMul(&arr[i], &z)
		res[i] = muld
	}

	return FArrayToFp5(res)
}

func Fp5Legendre(x Element) g.Element {
	frob1 := Fp5Frobenius(x)
	frob2 := Fp5Frobenius(frob1)

	frob1TimesFrob2 := Fp5Mul(frob1, frob2)
	frob2Frob1TimesFrob2 := Fp5RepeatedFrobenius(frob1TimesFrob2, 2)

	xrExt := Fp5Mul(Fp5Mul(x, frob1TimesFrob2), frob2Frob1TimesFrob2)
	xr := Fp5ToFArray(xrExt)[0]

	xr31 := xr.Exp(xr, new(big.Int).SetUint64(1<<31))
	xr31Copy := g.FDeepCopy(xr31)
	xr63 := xr31Copy.Exp(*xr31, new(big.Int).SetUint64(1<<32))

	xr31InvOrZero := g.FromUint64(0)
	xr31InvOrZero = *xr31InvOrZero.Inverse(xr31)

	return g.FMul(xr63, &xr31InvOrZero)
}
