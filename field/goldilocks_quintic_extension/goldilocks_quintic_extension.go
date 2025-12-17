package goldilocks_quintic_extension

import (
	"fmt"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type Element [5]g.GoldilocksField

type NumericalElement [5]uint64

const Bytes = g.Bytes * 5

var (
	FP5_D = 5

	FP5_ZERO = Element{g.ZeroF(), g.ZeroF(), g.ZeroF(), g.ZeroF(), g.ZeroF()}
	FP5_ONE  = Element{g.OneF(), g.ZeroF(), g.ZeroF(), g.ZeroF(), g.ZeroF()}
	FP5_TWO  = FromUint64(2)

	FP5_W        = g.GoldilocksField(3)
	FP5_DTH_ROOT = g.GoldilocksField(1041288259238279555)
)

func (e *Element) ToString() string {
	return fmt.Sprintf("%d,%d,%d,%d,%d", e[0].ToCanonicalUint64(), e[1].ToCanonicalUint64(), e[2].ToCanonicalUint64(), e[3].ToCanonicalUint64(), e[4].ToCanonicalUint64())
}

func (e Element) ToUint64Array() [5]uint64 {
	return [5]uint64{e[0].ToCanonicalUint64(), e[1].ToCanonicalUint64(), e[2].ToCanonicalUint64(), e[3].ToCanonicalUint64(), e[4].ToCanonicalUint64()}
}

func (e Element) ToBasefieldArray() [5]g.GoldilocksField {
	return e
}

func (e Element) ToLittleEndianBytes() []byte {
	elemBytes := [Bytes]byte{}
	for i, limb := range e {
		copy(elemBytes[i*g.Bytes:], g.ToLittleEndianBytesF(limb))
	}
	return elemBytes[:]
}

func FromCanonicalLittleEndianBytes(in []byte) (Element, error) {
	if len(in) != Bytes {
		return FP5_ZERO, fmt.Errorf("input bytes len should be 40 but is %d", len(in))
	}

	var elem Element
	for i := 0; i < 5; i++ {
		elem[i] = g.FromCanonicalLittleEndianBytesF(in[i*8 : (i+1)*8])
	}

	return elem, nil
}

func Sample() Element {
	return Element{g.SampleF(), g.SampleF(), g.SampleF(), g.SampleF(), g.SampleF()}
}

func Equals(a, b Element) bool {
	return a[0].ToCanonicalUint64() == b[0].ToCanonicalUint64() &&
		a[1].ToCanonicalUint64() == b[1].ToCanonicalUint64() &&
		a[2].ToCanonicalUint64() == b[2].ToCanonicalUint64() &&
		a[3].ToCanonicalUint64() == b[3].ToCanonicalUint64() &&
		a[4].ToCanonicalUint64() == b[4].ToCanonicalUint64()
}

func IsZero(e Element) bool {
	return e[0].IsZero() && e[1].IsZero() && e[2].IsZero() && e[3].IsZero() && e[4].IsZero()
}

func FromF(elem g.GoldilocksField) Element {
	return Element{elem, 0, 0, 0, 0}
}

func FromUint64(a uint64) Element {
	return Element{g.GoldilocksField(a), 0, 0, 0, 0}
}

func FromUint64Array(elems [5]uint64) Element {
	return Element{
		g.GoldilocksField(elems[0]),
		g.GoldilocksField(elems[1]),
		g.GoldilocksField(elems[2]),
		g.GoldilocksField(elems[3]),
		g.GoldilocksField(elems[4]),
	}
}

func Neg(e Element) Element {
	return Element{g.NegF(e[0]), g.NegF(e[1]), g.NegF(e[2]), g.NegF(e[3]), g.NegF(e[4])}
}

func Add(a, b Element) Element {
	return Element{
		g.AddF(a[0], b[0]),
		g.AddF(a[1], b[1]),
		g.AddF(a[2], b[2]),
		g.AddF(a[3], b[3]),
		g.AddF(a[4], b[4]),
	}
}

func Sub(a, b Element) Element {
	return Element{
		g.SubF(a[0], b[0]),
		g.SubF(a[1], b[1]),
		g.SubF(a[2], b[2]),
		g.SubF(a[3], b[3]),
		g.SubF(a[4], b[4]),
	}
}

func Mul(a, b Element) Element {
	w := FP5_W

	a0b0 := g.MulF(a[0], b[0])
	a1b4 := g.MulF(a[1], b[4])
	a2b3 := g.MulF(a[2], b[3])
	a3b2 := g.MulF(a[3], b[2])
	a4b1 := g.MulF(a[4], b[1])
	added := g.AddF(g.AddF(a1b4, a2b3), g.AddF(a3b2, a4b1))
	muld := g.MulF(w, added)
	c0 := g.AddF(a0b0, muld)

	a0b1 := g.MulF(a[0], b[1])
	a1b0 := g.MulF(a[1], b[0])
	a2b4 := g.MulF(a[2], b[4])
	a3b3 := g.MulF(a[3], b[3])
	a4b2 := g.MulF(a[4], b[2])
	added = g.AddF(g.AddF(a2b4, a3b3), a4b2)
	muld = g.MulF(w, added)
	c1 := g.AddF(g.AddF(a0b1, a1b0), muld)

	a0b2 := g.MulF(a[0], b[2])
	a1b1 := g.MulF(a[1], b[1])
	a2b0 := g.MulF(a[2], b[0])
	a3b4 := g.MulF(a[3], b[4])
	a4b3 := g.MulF(a[4], b[3])
	added = g.AddF(a3b4, a4b3)
	muld = g.MulF(w, added)
	c2 := g.AddF(g.AddF(a0b2, a1b1), g.AddF(a2b0, muld))

	a0b3 := g.MulF(a[0], b[3])
	a1b2 := g.MulF(a[1], b[2])
	a2b1 := g.MulF(a[2], b[1])
	a3b0 := g.MulF(a[3], b[0])
	a4b4 := g.MulF(a[4], b[4])
	muld = g.MulF(w, a4b4)
	c3 := g.AddF(g.AddF(g.AddF(a0b3, a1b2), g.AddF(a2b1, a3b0)), muld)

	a0b4 := g.MulF(a[0], b[4])
	a1b3 := g.MulF(a[1], b[3])
	a2b2 := g.MulF(a[2], b[2])
	a3b1 := g.MulF(a[3], b[1])
	a4b0 := g.MulF(a[4], b[0])
	c4 := g.AddF(g.AddF(g.AddF(a0b4, a1b3), g.AddF(a2b2, a3b1)), a4b0)

	return Element{c0, c1, c2, c3, c4}
}

func Div(a, b Element) Element {
	bInv := InverseOrZero(b)
	if IsZero(bInv) {
		panic("division by zero")
	}
	return Mul(a, bInv)
}

func ExpPowerOf2(x Element, power int) Element {
	res := Element{x[0], x[1], x[2], x[3], x[4]}
	for i := 0; i < power; i++ {
		res = Square(res)
	}
	return res
}

func Square(a Element) Element {
	w := FP5_W
	double_w := g.AddF(w, w)

	a0s := g.MulF(a[0], a[0])
	a1a4 := g.MulF(a[1], a[4])
	a2a3 := g.MulF(a[2], a[3])
	added := g.AddF(a1a4, a2a3)
	muld := g.MulF(double_w, added)
	c0 := g.AddF(a0s, muld)

	a0Double := g.AddF(a[0], a[0])
	a0Doublea1 := g.MulF(a0Double, a[1])
	a2a4DoubleW := g.MulF(g.MulF(a[2], a[4]), double_w)
	a3a3w := g.MulF(g.MulF(a[3], a[3]), w)
	c1 := g.AddF(g.AddF(a0Doublea1, a2a4DoubleW), a3a3w)

	a0Doublea2 := g.MulF(a0Double, a[2])
	a1Square := g.MulF(a[1], a[1])
	a4a3DoubleW := g.MulF(g.MulF(a[4], a[3]), double_w)
	c2 := g.AddF(g.AddF(a0Doublea2, a1Square), a4a3DoubleW)

	a1Double := g.AddF(a[1], a[1])
	a0Doublea3 := g.MulF(a0Double, a[3])
	a1Doublea2 := g.MulF(a1Double, a[2])
	a4SquareW := g.MulF(g.MulF(a[4], a[4]), w)
	c3 := g.AddF(g.AddF(a0Doublea3, a1Doublea2), a4SquareW)

	a0Doublea4 := g.MulF(a0Double, a[4])
	a1Doublea3 := g.MulF(a1Double, a[3])
	a2Square := g.MulF(a[2], a[2])
	c4 := g.AddF(g.AddF(a0Doublea4, a1Doublea3), a2Square)

	return Element{c0, c1, c2, c3, c4}
}

func Triple(a Element) Element {
	three := g.GoldilocksField(3)
	return Element{
		g.MulF(a[0], three),
		g.MulF(a[1], three),
		g.MulF(a[2], three),
		g.MulF(a[3], three),
		g.MulF(a[4], three),
	}
}

func Sqrt(x Element) (Element, bool) {
	three := g.GoldilocksField(3)

	v := ExpPowerOf2(x, 31)
	d := Mul(Mul(x, ExpPowerOf2(v, 32)), InverseOrZero(v))
	e := Frobenius(Mul(d, RepeatedFrobenius(d, 2)))
	_f := Square(e)

	x1f4 := g.MulF(x[1], _f[4])
	x2f3 := g.MulF(x[2], _f[3])
	x3f2 := g.MulF(x[3], _f[2])
	x4f1 := g.MulF(x[4], _f[1])
	added := g.AddF(g.AddF(x1f4, x2f3), g.AddF(x3f2, x4f1))
	muld := g.MulF(three, added)
	x0f0 := g.MulF(x[0], _f[0])
	_g := g.AddF(x0f0, muld)
	s := g.SqrtF(_g)
	if s == nil {
		return FP5_ZERO, false
	}

	eInv := InverseOrZero(e)
	sFp5 := FromF(*s)

	return Mul(sFp5, eInv), true
}

func Sgn0(x Element) bool {
	sign := false
	zero := true
	for _, limb := range x {
		sign_i := (limb.ToCanonicalUint64() & 1) == 0
		zero_i := limb.IsZero()
		sign = sign || (zero && sign_i)
		zero = zero && zero_i
	}
	return sign
}

func CanonicalSqrt(x Element) (Element, bool) {
	sqrtX, exists := Sqrt(x)
	if !exists {
		return FP5_ZERO, false
	}

	if Sgn0(sqrtX) {
		return Neg(sqrtX), true
	}
	return sqrtX, true
}

func ScalarMul(a Element, scalar g.GoldilocksField) Element {
	return Element{
		g.MulF(a[0], scalar),
		g.MulF(a[1], scalar),
		g.MulF(a[2], scalar),
		g.MulF(a[3], scalar),
		g.MulF(a[4], scalar),
	}
}

func Double(a Element) Element {
	return Add(a, a)
}

func InverseOrZero(a Element) Element {
	if IsZero(a) {
		return FP5_ZERO
	}

	d := Frobenius(a)
	e := Mul(d, Frobenius(d))
	f := Mul(e, RepeatedFrobenius(e, 2))

	a0b0 := g.MulF(a[0], f[0])
	a1b4 := g.MulF(a[1], f[4])
	a2b3 := g.MulF(a[2], f[3])
	a3b2 := g.MulF(a[3], f[2])
	a4b1 := g.MulF(a[4], f[1])
	added := g.AddF(g.AddF(a1b4, a2b3), g.AddF(a3b2, a4b1))
	muld := g.MulF(FP5_W, added)
	gg := g.AddF(a0b0, muld)

	return ScalarMul(f, gg.InverseOrZero())
}

func Frobenius(x Element) Element {
	return RepeatedFrobenius(x, 1)
}

func RepeatedFrobenius(x Element, count int) Element {
	if count == 0 {
		return x
	} else if count >= FP5_D {
		return RepeatedFrobenius(x, count%FP5_D)
	}

	z0 := FP5_DTH_ROOT
	for i := 1; i < count; i++ {
		z0 = g.MulF(FP5_DTH_ROOT, z0)
	}

	res := Element{}
	for i, z := range g.PowersF(z0, FP5_D) {
		res[i] = g.MulF(x[i], z)
	}
	return res
}

func Legendre(x Element) g.GoldilocksField {
	frob1 := Frobenius(x)
	frob2 := Frobenius(frob1)

	frob1TimesFrob2 := Mul(frob1, frob2)
	frob2Frob1TimesFrob2 := RepeatedFrobenius(frob1TimesFrob2, 2)

	xrExt := Mul(Mul(x, frob1TimesFrob2), frob2Frob1TimesFrob2)
	xr := xrExt[0]

	xr31 := g.ExpPowerOf2(xr, 31)
	xr31InvOrZero := xr31.InverseOrZero()

	xr63 := g.ExpPowerOf2(xr31, 32)

	return g.MulF(xr63, xr31InvOrZero)
}

func FromPlonky2GoldilocksField(f []g.GoldilocksField) Element {
	return Element{
		f[0],
		f[1],
		f[2],
		f[3],
		f[4],
	}
}

func FromGnarkGoldilocksField(f []g.Element) Element {
	return Element{
		g.GoldilocksField(f[0].Uint64()),
		g.GoldilocksField(f[1].Uint64()),
		g.GoldilocksField(f[2].Uint64()),
		g.GoldilocksField(f[3].Uint64()),
		g.GoldilocksField(f[4].Uint64()),
	}
}
