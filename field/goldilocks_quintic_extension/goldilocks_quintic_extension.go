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

	FP5_ZERO = Element{g.Zero(), g.Zero(), g.Zero(), g.Zero(), g.Zero()}
	FP5_ONE  = Element{g.One(), g.Zero(), g.Zero(), g.Zero(), g.Zero()}
	FP5_TWO  = FromF(g.NewElement(2))

	FP5_W        = g.NewElement(3)
	FP5_DTH_ROOT = g.NewElement(1041288259238279555)
)

func (e *Element) ToString() string {
	return fmt.Sprintf("%d,%d,%d,%d,%d", e[0].Uint64(), e[1].Uint64(), e[2].Uint64(), e[3].Uint64(), e[4].Uint64())
}

func (e Element) ToUint64Array() [5]uint64 {
	return [5]uint64{e[0].Uint64(), e[1].Uint64(), e[2].Uint64(), e[3].Uint64(), e[4].Uint64()}
}

func gFp5FromUint64Array(arr [5]uint64) Element {
	return Element{g.NewElement(arr[0]), g.NewElement(arr[1]), g.NewElement(arr[2]), g.NewElement(arr[3]), g.NewElement(arr[4])}
}

func (e Element) ToLittleEndianBytes() []byte {
	elemBytes := [Bytes]byte{}
	for i, limb := range e {
		copy(elemBytes[i*g.Bytes:], limb.ToLittleEndianBytes())
	}
	return elemBytes[:]
}

func FromCanonicalLittleEndianBytes(in []byte) (Element, error) {
	if len(in) != Bytes {
		return Element{}, fmt.Errorf("input bytes len should be 40 but is %d", len(in))
	}

	elemBytesLittleEndian := [5][]byte{
		{in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]},
		{in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15]},
		{in[16], in[17], in[18], in[19], in[20], in[21], in[22], in[23]},
		{in[24], in[25], in[26], in[27], in[28], in[29], in[30], in[31]},
		{in[32], in[33], in[34], in[35], in[36], in[37], in[38], in[39]},
	}

	var e1, e2, e3, e4, e5 g.GoldilocksField

	e1.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[0])
	e2.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[1])
	e3.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[2])
	e4.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[3])
	e5.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[4])

	return Element{e1, e2, e3, e4, e5}, nil
}

func Sample() Element {
	var e1, e2, e3, e4, e5 g.GoldilocksField
	return Element{*e1.Sample(), *e2.Sample(), *e3.Sample(), *e4.Sample(), *e5.Sample()}
}

func Equals(a, b Element) bool {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4]
}

func IsZero(e Element) bool {
	return e[0].IsZero() && e[1].IsZero() && e[2].IsZero() && e[3].IsZero() && e[4].IsZero()
}

func FromF(elem g.GoldilocksField) Element {
	return Element{elem, g.Zero(), g.Zero(), g.Zero(), g.Zero()}
}

func FromUint64(a uint64) Element {
	return Element{g.NewElement(a), g.Zero(), g.Zero(), g.Zero(), g.Zero()}
}

func FromUint64Array(elems [5]uint64) Element {
	return Element{
		g.NewElement(elems[0]),
		g.NewElement(elems[1]),
		g.NewElement(elems[2]),
		g.NewElement(elems[3]),
		g.NewElement(elems[4]),
	}
}

func Neg(e Element) Element {
	var e1, e2, e3, e4, e5 g.GoldilocksField
	return Element{*e1.Neg(&e[0]), *e2.Neg(&e[1]), *e3.Neg(&e[2]), *e4.Neg(&e[3]), *e5.Neg(&e[4])}
}

func Add(a, b Element) Element {
	var e1, e2, e3, e4, e5 g.GoldilocksField
	return Element{
		*e1.Add(&a[0], &b[0]),
		*e2.Add(&a[1], &b[1]),
		*e3.Add(&a[2], &b[2]),
		*e4.Add(&a[3], &b[3]),
		*e5.Add(&a[4], &b[4]),
	}
}

func Sub(a, b Element) Element {
	var e1, e2, e3, e4, e5 g.GoldilocksField

	return Element{
		*e1.Sub(&a[0], &b[0]),
		*e2.Sub(&a[1], &b[1]),
		*e3.Sub(&a[2], &b[2]),
		*e4.Sub(&a[3], &b[3]),
		*e5.Sub(&a[4], &b[4]),
	}
}

func Mul(a, b Element) Element {
	w := FP5_W

	var c0, c1, c2, c3, c4 g.GoldilocksField
	var added, muld g.GoldilocksField

	var a0b0, a1b4, a2b3, a3b2, a4b1, a1b4a2b3, a3b2a4b1 g.GoldilocksField

	a0b0.Mul(&a[0], &b[0])
	a1b4.Mul(&a[1], &b[4])
	a2b3.Mul(&a[2], &b[3])
	a3b2.Mul(&a[3], &b[2])
	a4b1.Mul(&a[4], &b[1])
	a1b4a2b3.Add(&a1b4, &a2b3)
	a3b2a4b1.Add(&a3b2, &a4b1)
	added.Add(&a1b4a2b3, &a3b2a4b1)
	muld.Mul(&w, &added)
	c0.Add(&a0b0, &muld)

	var a0b1, a1b0, a2b4, a3b3, a4b2, a2b4a3b3, a0b1a1b0 g.GoldilocksField
	a0b1.Mul(&a[0], &b[1])
	a1b0.Mul(&a[1], &b[0])
	a2b4.Mul(&a[2], &b[4])
	a3b3.Mul(&a[3], &b[3])
	a4b2.Mul(&a[4], &b[2])
	a2b4a3b3.Add(&a2b4, &a3b3)
	added.Add(&a2b4a3b3, &a4b2)
	muld.Mul(&w, &added)
	a0b1a1b0.Add(&a0b1, &a1b0)
	c1.Add(&a0b1a1b0, &muld)

	var a0b2, a1b1, a2b0, a3b4, a4b3, a0b2a1b1, a0b2a1b1a2b0 g.GoldilocksField
	a0b2.Mul(&a[0], &b[2])
	a1b1.Mul(&a[1], &b[1])
	a2b0.Mul(&a[2], &b[0])
	a3b4.Mul(&a[3], &b[4])
	a4b3.Mul(&a[4], &b[3])
	added.Add(&a3b4, &a4b3)
	muld.Mul(&w, &added)
	a0b2a1b1.Add(&a0b2, &a1b1)
	a0b2a1b1a2b0.Add(&a0b2a1b1, &a2b0)
	c2.Add(&a0b2a1b1a2b0, &muld)

	var a0b3, a1b2, a2b1, a3b0, a4b4, a0b3a1b2, a0b3a1b2a2b1, a0b3a1b2a2b1a3b0 g.GoldilocksField
	a0b3.Mul(&a[0], &b[3])
	a1b2.Mul(&a[1], &b[2])
	a2b1.Mul(&a[2], &b[1])
	a3b0.Mul(&a[3], &b[0])
	a4b4.Mul(&a[4], &b[4])
	muld.Mul(&w, &a4b4)
	a0b3a1b2.Add(&a0b3, &a1b2)
	a0b3a1b2a2b1.Add(&a0b3a1b2, &a2b1)
	a0b3a1b2a2b1a3b0.Add(&a0b3a1b2a2b1, &a3b0)
	c3.Add(&a0b3a1b2a2b1a3b0, &muld)

	var a0b4, a1b3, a2b2, a3b1, a4b0, a0b4a1b3, a0b4a1b3a2b2, a0b4a1b3a2b2a3b1 g.GoldilocksField
	a0b4.Mul(&a[0], &b[4])
	a1b3.Mul(&a[1], &b[3])
	a2b2.Mul(&a[2], &b[2])
	a3b1.Mul(&a[3], &b[1])
	a4b0.Mul(&a[4], &b[0])
	a0b4a1b3.Add(&a0b4, &a1b3)
	a0b4a1b3a2b2.Add(&a0b4a1b3, &a2b2)
	a0b4a1b3a2b2a3b1.Add(&a0b4a1b3a2b2, &a3b1)
	c4.Add(&a0b4a1b3a2b2a3b1, &a4b0)

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
	return Mul(a, a)
}

func Triple(a Element) Element {
	return ScalarMul(a, g.NewElement(3))
}

func Sqrt(x Element) (Element, bool) {
	three := g.NewElement(3)

	v := ExpPowerOf2(x, 31)
	d := Mul(Mul(x, ExpPowerOf2(v, 32)), InverseOrZero(v))
	e := Frobenius(Mul(d, RepeatedFrobenius(d, 2)))
	f := Square(e)

	var x1f4, x2f3, x3f2, x4f1, x0f0, added, muld, s g.GoldilocksField
	x0f0.Mul(&x[0], &f[0])
	x1f4.Mul(&x[1], &f[4])
	x2f3.Mul(&x[2], &f[3])
	x3f2.Mul(&x[3], &f[2])
	x4f1.Mul(&x[4], &f[1])
	added.Add(&x1f4, &x2f3).Add(&added, &x3f2).Add(&added, &x4f1)
	muld.Mul(&three, &added)
	s.Add(&x0f0, &muld).Sqrt(&s)
	if s == nil {
		return Element{}, false
	}

	eInv := InverseOrZero(e)
	sFp5 := FromF(*s)

	return Mul(sFp5, eInv), true
}

func Sgn0(x Element) bool {
	sign := false
	zero := true
	for _, limb := range x {
		sign_i := (limb.Uint64() & 1) == 0
		zero_i := limb.IsZero()
		sign = sign || (zero && sign_i)
		zero = zero && zero_i
	}
	return sign
}

func CanonicalSqrt(x Element) (Element, bool) {
	sqrtX, exists := Sqrt(x)
	if !exists {
		return Element{}, false
	}

	if Sgn0(sqrtX) {
		return Neg(sqrtX), true
	}
	return sqrtX, true
}

func ScalarMul(a Element, scalar g.GoldilocksField) (res Element) {
	res[0].Mul(&a[0], &scalar)
	res[1].Mul(&a[1], &scalar)
	res[2].Mul(&a[2], &scalar)
	res[3].Mul(&a[3], &scalar)
	res[4].Mul(&a[4], &scalar)

	return
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

	var g, a0b0, a1b4, a2b3, a3b2, a4b1, a1b4a2b3, a3b2a4b1, added, muld g.GoldilocksField
	a0b0.Mul(&a[0], &f[0])
	a1b4.Mul(&a[1], &f[4])
	a2b3.Mul(&a[2], &f[3])
	a3b2.Mul(&a[3], &f[2])
	a4b1.Mul(&a[4], &f[1])
	a1b4a2b3.Add(&a1b4, &a2b3)
	a3b2a4b1.Add(&a3b2, &a4b1)
	added.Add(&a1b4a2b3, &a3b2a4b1)
	muld.Mul(&FP5_W, &added)
	g.Add(&a0b0, &muld)

	return ScalarMul(f, *g.Inverse(&g))
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

	var z0 g.GoldilocksField
	z0.Set(&FP5_DTH_ROOT)
	for i := 1; i < count; i++ {
		z0.Mul(&z0, &FP5_DTH_ROOT)
	}

	res := Element{}
	for i, z := range g.Powers(&z0, FP5_D) {
		res[i].Mul(&x[i], &z)
	}
	return res
}

func Legendre(x Element) g.GoldilocksField {
	frob1 := Frobenius(x)
	frob2 := Frobenius(frob1)

	frob1TimesFrob2 := Mul(frob1, frob2)
	frob2Frob1TimesFrob2 := RepeatedFrobenius(frob1TimesFrob2, 2)

	xrExt := Mul(Mul(x, frob1TimesFrob2), frob2Frob1TimesFrob2)
	_xr := g.NewElement(xrExt[0].Uint64())
	xr := &(_xr)

	xr31 := xr.ExpPowerOf2(xr, 31)
	xr31InvOrZero := g.NewElement(0)
	xr31InvOrZero = *xr31InvOrZero.Inverse(xr31)

	xr63 := xr31.ExpPowerOf2(xr31, 32)

	return *xr63.Mul(xr63, &xr31InvOrZero)
}
