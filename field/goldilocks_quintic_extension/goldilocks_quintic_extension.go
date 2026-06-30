package goldilocks_quintic_extension

import (
	"errors"
	"math/bits"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type Element [5]g.GoldilocksField

const Bytes = g.Bytes * 5

var (
	FP5_D = 5

	FP5_ZERO = Element{0, 0, 0, 0, 0}
	FP5_ONE  = Element{1, 0, 0, 0, 0}
	FP5_TWO  = Element{2, 0, 0, 0, 0}

	FP5_W        = g.GoldilocksField(3)
	FP5_DTH_ROOT = g.GoldilocksField(1041288259238279555)
)

func (e Element) ToUint64Array() [5]uint64 {
	return [5]uint64{e[0].ToCanonicalUint64(), e[1].ToCanonicalUint64(), e[2].ToCanonicalUint64(), e[3].ToCanonicalUint64(), e[4].ToCanonicalUint64()}
}

func (e Element) ToLittleEndianBytes() []byte {
	elemBytes := make([]byte, Bytes)
	for i, limb := range e {
		copy(elemBytes[i*g.Bytes:], g.ToLittleEndianBytesF(limb))
	}
	return elemBytes
}

func FromCanonicalLittleEndianBytes(in []byte) (Element, error) {
	if len(in) != Bytes {
		return FP5_ZERO, errors.New("invalid input length. Expected 40 bytes")
	}

	var elem Element
	elem[0] = g.FromCanonicalLittleEndianBytesF(in[0:8])
	elem[1] = g.FromCanonicalLittleEndianBytesF(in[8:16])
	elem[2] = g.FromCanonicalLittleEndianBytesF(in[16:24])
	elem[3] = g.FromCanonicalLittleEndianBytesF(in[24:32])
	elem[4] = g.FromCanonicalLittleEndianBytesF(in[32:40])

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

// reduce128 reduces hi*2^64 + lo modulo the Goldilocks prime.
func reduce128(lo, hi uint64) uint64 {
	x_hi_hi := hi >> 32
	x_hi_lo := hi & g.EPSILON

	t0, borrow := bits.Sub64(lo, x_hi_hi, 0)
	t0 -= (g.EPSILON & -borrow)

	t1 := x_hi_lo * g.EPSILON

	resWrapped, carry := bits.Add64(t0, t1, 0)
	t2 := resWrapped + (g.EPSILON & -carry)
	return t2
}

// acc192 is a 192-bit accumulator of unreduced products
type acc192 struct{ lo, mid, hi uint64 }

func (s acc192) addProduct(a, b uint64) (res acc192) { // s += a*b   (no reduction)
	res = s
	hi, lo := bits.Mul64(a, b)
	var c uint64
	res.lo, c = bits.Add64(s.lo, lo, 0)
	res.mid, c = bits.Add64(s.mid, hi, c)
	res.hi += c
	return
}

func (s acc192) addProduct3(a, b uint64) (res acc192) { // s += 3*a*b  (the X^5 = 3 fold)
	res = s
	hi, lo := bits.Mul64(a, b)
	d0 := lo << 1 // 3*(hi:lo) = (hi:lo)<<1 + (hi:lo)
	d1 := (hi << 1) | (lo >> 63)
	d2 := hi >> 63
	var c uint64
	d0, c = bits.Add64(d0, lo, 0)
	d1, c = bits.Add64(d1, hi, c)
	d2 += c
	res.lo, c = bits.Add64(s.lo, d0, 0)
	res.mid, c = bits.Add64(s.mid, d1, c)
	res.hi += d2 + c
	return
}

func (s acc192) reduce() uint64 {
	// value = (lo + mid*2^64) + hi*2^128 ;  2^128 ≡ -2^32 (mod p)
	rLow := reduce128(s.lo, s.mid)
	r2 := reduce128(s.hi<<32, s.hi>>32) // = hi*2^32 mod p
	res, borrow := bits.Sub64(rLow, r2, 0)
	return res - (g.EPSILON & -borrow)
}

// Mul multiplies two F_{p^5} elements with lazy reduction
func Mul(a, b Element) Element {
	a0, a1, a2, a3, a4 := uint64(a[0]), uint64(a[1]), uint64(a[2]), uint64(a[3]), uint64(a[4])
	b0, b1, b2, b3, b4 := uint64(b[0]), uint64(b[1]), uint64(b[2]), uint64(b[3]), uint64(b[4])

	var s0, s1, s2, s3, s4 acc192

	// c0 = a0b0 + 3(a1b4 + a2b3 + a3b2 + a4b1)
	s0 = s0.addProduct(a0, b0)
	s0 = s0.addProduct3(a1, b4)
	s0 = s0.addProduct3(a2, b3)
	s0 = s0.addProduct3(a3, b2)
	s0 = s0.addProduct3(a4, b1)
	// c1 = a0b1 + a1b0 + 3(a2b4 + a3b3 + a4b2)
	s1 = s1.addProduct(a0, b1)
	s1 = s1.addProduct(a1, b0)
	s1 = s1.addProduct3(a2, b4)
	s1 = s1.addProduct3(a3, b3)
	s1 = s1.addProduct3(a4, b2)
	// c2 = a0b2 + a1b1 + a2b0 + 3(a3b4 + a4b3)
	s2 = s2.addProduct(a0, b2)
	s2 = s2.addProduct(a1, b1)
	s2 = s2.addProduct(a2, b0)
	s2 = s2.addProduct3(a3, b4)
	s2 = s2.addProduct3(a4, b3)
	// c3 = a0b3 + a1b2 + a2b1 + a3b0 + 3 a4b4
	s3 = s3.addProduct(a0, b3)
	s3 = s3.addProduct(a1, b2)
	s3 = s3.addProduct(a2, b1)
	s3 = s3.addProduct(a3, b0)
	s3 = s3.addProduct3(a4, b4)
	// c4 = a0b4 + a1b3 + a2b2 + a3b1 + a4b0
	s4 = s4.addProduct(a0, b4)
	s4 = s4.addProduct(a1, b3)
	s4 = s4.addProduct(a2, b2)
	s4 = s4.addProduct(a3, b1)
	s4 = s4.addProduct(a4, b0)

	return Element{
		g.GoldilocksField(s0.reduce()),
		g.GoldilocksField(s1.reduce()),
		g.GoldilocksField(s2.reduce()),
		g.GoldilocksField(s3.reduce()),
		g.GoldilocksField(s4.reduce()),
	}
}

// Returns a / b. Panics if b == 0.
func Div(a, b Element) Element {
	bInv := InverseOrZero(b)
	if IsZero(bInv) {
		panic("division by zero")
	}
	return Mul(a, bInv)
}

// x^(2^power)
func ExpPowerOf2(x Element, power int) Element {
	res := Element{x[0], x[1], x[2], x[3], x[4]}
	for i := 0; i < power; i++ {
		res = Square(res)
	}
	return res
}

// add3 adds the 3-limb value v2:v1:v0 into the accumulator.
func (s acc192) add3(v0, v1, v2 uint64) (res acc192) {
	res = s
	var c uint64
	res.lo, c = bits.Add64(s.lo, v0, 0)
	res.mid, c = bits.Add64(s.mid, v1, c)
	res.hi += v2 + c
	return
}

func (s acc192) addProduct2(a, b uint64) acc192 { // s += 2*a*b  (shift the product left 1)
	hi, lo := bits.Mul64(a, b)
	return s.add3(lo<<1, (hi<<1)|(lo>>63), hi>>63)
}

func (s acc192) addProduct6(a, b uint64) acc192 { // s += 6*a*b = 4*ab + 2*ab
	hi, lo := bits.Mul64(a, b)
	q0, q1, q2 := lo<<2, (hi<<2)|(lo>>62), hi>>62 // 4x
	r0, r1, r2 := lo<<1, (hi<<1)|(lo>>63), hi>>63 // 2x
	var c uint64
	q0, c = bits.Add64(q0, r0, 0)
	q1, c = bits.Add64(q1, r1, c)
	q2 += r2 + c
	return s.add3(q0, q1, q2)
}

// Square squares an F_{p^5} element with lazy reduction
func Square(a Element) Element {
	a0, a1, a2, a3, a4 := uint64(a[0]), uint64(a[1]), uint64(a[2]), uint64(a[3]), uint64(a[4])
	var s0, s1, s2, s3, s4 acc192

	// c0 = a0^2 + 6 a1a4 + 6 a2a3
	s0 = s0.addProduct(a0, a0)
	s0 = s0.addProduct6(a1, a4)
	s0 = s0.addProduct6(a2, a3)
	// c1 = 2 a0a1 + 6 a2a4 + 3 a3^2
	s1 = s1.addProduct2(a0, a1)
	s1 = s1.addProduct6(a2, a4)
	s1 = s1.addProduct3(a3, a3)
	// c2 = 2 a0a2 + a1^2 + 6 a3a4
	s2 = s2.addProduct2(a0, a2)
	s2 = s2.addProduct(a1, a1)
	s2 = s2.addProduct6(a3, a4)
	// c3 = 2 a0a3 + 2 a1a2 + 3 a4^2
	s3 = s3.addProduct2(a0, a3)
	s3 = s3.addProduct2(a1, a2)
	s3 = s3.addProduct3(a4, a4)
	// c4 = 2 a0a4 + 2 a1a3 + a2^2
	s4 = s4.addProduct2(a0, a4)
	s4 = s4.addProduct2(a1, a3)
	s4 = s4.addProduct(a2, a2)

	return Element{
		g.GoldilocksField(s0.reduce()),
		g.GoldilocksField(s1.reduce()),
		g.GoldilocksField(s2.reduce()),
		g.GoldilocksField(s3.reduce()),
		g.GoldilocksField(s4.reduce()),
	}
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

	return ScalarMul(f, gg.Inverse())
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
