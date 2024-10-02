package goldilocks_quintic_extension

import (
	"encoding/binary"
	"math/big"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type Element [5]uint64

const Bytes = g.Bytes * 5

var (
	FP5_D = 5

	FP5_ZERO = Element{0, 0, 0, 0, 0}
	FP5_ONE  = Element{1, 0, 0, 0, 0}
	FP5_TWO  = Element{2, 0, 0, 0, 0}

	FP5_W        = g.FromUint64(3)
	FP5_DTH_ROOT = g.FromUint64(1041288259238279555)
)

func ToBigEndianBytes(e Element) [Bytes]byte {
	elemBytes := [Bytes]byte{}
	for i, limb := range e {
		binary.BigEndian.PutUint64(elemBytes[i*g.Bytes:], limb)
	}
	return elemBytes
}

func FromCanonicalBigEndianBytes(in [Bytes]byte) Element {
	elemBytesBigEndian := [5][g.Bytes]byte{
		{in[7], in[6], in[5], in[4], in[3], in[2], in[1], in[0]},
		{in[15], in[14], in[13], in[12], in[11], in[10], in[9], in[8]},
		{in[23], in[22], in[21], in[20], in[19], in[18], in[17], in[16]},
		{in[31], in[30], in[29], in[28], in[27], in[26], in[25], in[24]},
		{in[39], in[38], in[37], in[36], in[35], in[34], in[33], in[32]},
	}
	return FromBasefieldArray([5]g.Element{
		g.FromCanonicalLittleEndianBytes(elemBytesBigEndian[0]),
		g.FromCanonicalLittleEndianBytes(elemBytesBigEndian[1]),
		g.FromCanonicalLittleEndianBytes(elemBytesBigEndian[2]),
		g.FromCanonicalLittleEndianBytes(elemBytesBigEndian[3]),
		g.FromCanonicalLittleEndianBytes(elemBytesBigEndian[4]),
	})
}

func ToLittleEndianBytes(e Element) [Bytes]byte {
	elemBytes := [Bytes]byte{}
	for i, limb := range e {
		binary.LittleEndian.PutUint64(elemBytes[i*g.Bytes:], limb)
	}
	return elemBytes
}

func FromCanonicalLittleEndianBytes(in [Bytes]byte) Element {
	elemBytesLittleEndian := [5][g.Bytes]byte{
		{in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]},
		{in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15]},
		{in[16], in[17], in[18], in[19], in[20], in[21], in[22], in[23]},
		{in[24], in[25], in[26], in[27], in[28], in[29], in[30], in[31]},
		{in[32], in[33], in[34], in[35], in[36], in[37], in[38], in[39]},
	}
	return FromBasefieldArray([5]g.Element{
		g.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[0]),
		g.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[1]),
		g.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[2]),
		g.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[3]),
		g.FromCanonicalLittleEndianBytes(elemBytesLittleEndian[4]),
	})
}

func Sample() Element {
	arr := g.RandArray(5)
	return FromBasefieldArray([5]g.Element{arr[0], arr[1], arr[2], arr[3], arr[4]})
}

func Equals(a, b Element) bool {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4]
}

func IsZero(e Element) bool {
	return e[0] == 0 && e[1] == 0 && e[2] == 0 && e[3] == 0 && e[4] == 0
}

func FromF(elem g.Element) Element {
	return Element{elem.Uint64(), 0, 0, 0, 0}
}

func ToBasefieldArray(e Element) [5]g.Element {
	return [5]g.Element{
		g.FromUint64(e[0]),
		g.FromUint64(e[1]),
		g.FromUint64(e[2]),
		g.FromUint64(e[3]),
		g.FromUint64(e[4]),
	}
}

func FromBasefieldArray(e [5]g.Element) Element {
	return Element{
		e[0].Uint64(),
		e[1].Uint64(),
		e[2].Uint64(),
		e[3].Uint64(),
		e[4].Uint64(),
	}
}

func FromUint64(a uint64) Element {
	return Element{a, 0, 0, 0, 0}
}

func FromUint64Array(e1, e2, e3, e4, e5 uint64) Element {
	return Element{e1, e2, e3, e4, e5}
}

func Neg(e Element) Element {
	eCopy := ToBasefieldArray(e)
	return FromBasefieldArray([5]g.Element{
		g.Neg(eCopy[0]),
		g.Neg(eCopy[1]),
		g.Neg(eCopy[2]),
		g.Neg(eCopy[3]),
		g.Neg(eCopy[4]),
	})
}

func Add(a, b Element) Element {
	aCopy := ToBasefieldArray(a)
	bCopy := ToBasefieldArray(b)

	return FromBasefieldArray([5]g.Element{
		g.Add(aCopy[0], bCopy[0]),
		g.Add(aCopy[1], bCopy[1]),
		g.Add(aCopy[2], bCopy[2]),
		g.Add(aCopy[3], bCopy[3]),
		g.Add(aCopy[4], bCopy[4]),
	})
}

func Sub(a, b Element) Element {
	aCopy := ToBasefieldArray(a)
	bCopy := ToBasefieldArray(b)
	return FromBasefieldArray([5]g.Element{
		g.Sub(&aCopy[0], &bCopy[0]),
		g.Sub(&aCopy[1], &bCopy[1]),
		g.Sub(&aCopy[2], &bCopy[2]),
		g.Sub(&aCopy[3], &bCopy[3]),
		g.Sub(&aCopy[4], &bCopy[4]),
	})
}

func Mul(a, b Element) Element {
	aCopy := ToBasefieldArray(a)
	bCopy := ToBasefieldArray(b)
	w := g.DeepCopy(&FP5_W)

	a0b0 := g.Mul(&aCopy[0], &bCopy[0])
	a1b4 := g.Mul(&aCopy[1], &bCopy[4])
	a2b3 := g.Mul(&aCopy[2], &bCopy[3])
	a3b2 := g.Mul(&aCopy[3], &bCopy[2])
	a4b1 := g.Mul(&aCopy[4], &bCopy[1])
	added := g.Add(a1b4, a2b3, a3b2, a4b1)
	muld := g.Mul(&w, &added)
	c0 := g.Add(a0b0, muld)

	a0b1 := g.Mul(&aCopy[0], &bCopy[1])
	a1b0 := g.Mul(&aCopy[1], &bCopy[0])
	a2b4 := g.Mul(&aCopy[2], &bCopy[4])
	a3b3 := g.Mul(&aCopy[3], &bCopy[3])
	a4b2 := g.Mul(&aCopy[4], &bCopy[2])
	added = g.Add(a2b4, a3b3, a4b2)
	muld = g.Mul(&w, &added)
	c1 := g.Add(a0b1, a1b0, muld)

	a0b2 := g.Mul(&aCopy[0], &bCopy[2])
	a1b1 := g.Mul(&aCopy[1], &bCopy[1])
	a2b0 := g.Mul(&aCopy[2], &bCopy[0])
	a3b4 := g.Mul(&aCopy[3], &bCopy[4])
	a4b3 := g.Mul(&aCopy[4], &bCopy[3])
	added = g.Add(a3b4, a4b3)
	muld = g.Mul(&w, &added)
	c2 := g.Add(a0b2, a1b1, a2b0, muld)

	a0b3 := g.Mul(&aCopy[0], &bCopy[3])
	a1b2 := g.Mul(&aCopy[1], &bCopy[2])
	a2b1 := g.Mul(&aCopy[2], &bCopy[1])
	a3b0 := g.Mul(&aCopy[3], &bCopy[0])
	a4b4 := g.Mul(&aCopy[4], &bCopy[4])
	muld = g.Mul(&w, &a4b4)
	c3 := g.Add(a0b3, a1b2, a2b1, a3b0, muld)

	a0b4 := g.Mul(&aCopy[0], &bCopy[4])
	a1b3 := g.Mul(&aCopy[1], &bCopy[3])
	a2b2 := g.Mul(&aCopy[2], &bCopy[2])
	a3b1 := g.Mul(&aCopy[3], &bCopy[1])
	a4b0 := g.Mul(&aCopy[4], &bCopy[0])
	c4 := g.Add(a0b4, a1b3, a2b2, a3b1, a4b0)

	return FromBasefieldArray([5]g.Element{c0, c1, c2, c3, c4})
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
	aCopy := ToBasefieldArray(a)
	w := g.DeepCopy(&FP5_W)
	double_w := g.Add(w, w)

	a0s := g.Mul(&aCopy[0], &aCopy[0])
	a1a4 := g.Mul(&aCopy[1], &aCopy[4])
	a2a3 := g.Mul(&aCopy[2], &aCopy[3])
	added := g.Add(a1a4, a2a3)
	muld := g.Mul(&double_w, &added)
	c0 := g.Add(a0s, muld)

	a0Double := g.Add(aCopy[0], aCopy[0])
	a0Doublea1 := g.Mul(&a0Double, &aCopy[1])
	a2a4DoubleW := g.Mul(&aCopy[2], &aCopy[4], &double_w)
	a3a3w := g.Mul(&aCopy[3], &aCopy[3], &w)
	c1 := g.Add(a0Doublea1, a2a4DoubleW, a3a3w)

	a0Doublea2 := g.Mul(&a0Double, &aCopy[2])
	a1Square := g.Mul(&aCopy[1], &aCopy[1])
	a4a3DoubleW := g.Mul(&aCopy[4], &aCopy[3], &double_w)
	c2 := g.Add(a0Doublea2, a1Square, a4a3DoubleW)

	a1Double := g.Add(aCopy[1], aCopy[1])
	a0Doublea3 := g.Mul(&a0Double, &aCopy[3])
	a1Doublea2 := g.Mul(&a1Double, &aCopy[2])
	a4SquareW := g.Mul(&aCopy[4], &aCopy[4], &w)
	c3 := g.Add(a0Doublea3, a1Doublea2, a4SquareW)

	a0Doublea4 := g.Mul(&a0Double, &aCopy[4])
	a1Doublea3 := g.Mul(&a1Double, &aCopy[3])
	a2Square := g.Mul(&aCopy[2], &aCopy[2])
	c4 := g.Add(a0Doublea4, a1Doublea3, a2Square)

	return FromBasefieldArray([5]g.Element{c0, c1, c2, c3, c4})
}

func Triple(a Element) Element {
	three := g.FromUint64(3)
	aCopy := ToBasefieldArray(a)

	return FromBasefieldArray([5]g.Element{
		g.Mul(&aCopy[0], &three),
		g.Mul(&aCopy[1], &three),
		g.Mul(&aCopy[2], &three),
		g.Mul(&aCopy[3], &three),
		g.Mul(&aCopy[4], &three),
	})
}

func Sqrt(x Element) (Element, bool) {
	v := ExpPowerOf2(x, 31)
	d := Mul(Mul(x, ExpPowerOf2(v, 32)), InverseOrZero(v))
	e := Frobenius(Mul(d, RepeatedFrobenius(d, 2)))
	_f := Square(e)

	xArr := ToBasefieldArray(x)
	fArr := ToBasefieldArray(_f)

	x1f4 := g.Mul(&xArr[1], &fArr[4])
	x2f3 := g.Mul(&xArr[2], &fArr[3])
	x3f2 := g.Mul(&xArr[3], &fArr[2])
	x4f1 := g.Mul(&xArr[4], &fArr[1])
	added := g.Add(x1f4, x2f3, x3f2, x4f1)
	three := g.FromUint64(3)
	muld := g.Mul(&three, &added)
	x0f0 := g.Mul(&xArr[0], &fArr[0])
	_g := g.Add(x0f0, muld)
	s := g.Sqrt(&_g)
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
		sign_i := (limb & 1) == 0
		zero_i := limb == 0
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

func ScalarMul(a Element, scalar g.Element) Element {
	arr := ToBasefieldArray(a)
	for i := 0; i < len(arr); i++ {
		arr[i].Mul(&arr[i], &scalar)
	}
	return FromBasefieldArray(arr)
}

func Double(a Element) Element {
	return Add(a, a)
}

func NegOne() Element {
	negOne := g.NegOne()
	return Element{negOne.Uint64(), 0, 0, 0, 0}
}

func InverseOrZero(a Element) Element {
	if IsZero(a) {
		return FP5_ZERO
	}

	d := Frobenius(a)
	e := Mul(d, Frobenius(d))
	f := Mul(e, RepeatedFrobenius(e, 2))

	aCopy := ToBasefieldArray(a)
	fCopy := ToBasefieldArray(f)

	a0b0 := g.Mul(&aCopy[0], &fCopy[0])
	a1b4 := g.Mul(&aCopy[1], &fCopy[4])
	a2b3 := g.Mul(&aCopy[2], &fCopy[3])
	a3b2 := g.Mul(&aCopy[3], &fCopy[2])
	a4b1 := g.Mul(&aCopy[4], &fCopy[1])
	added := g.Add(a1b4, a2b3, a3b2, a4b1)
	muld := g.Mul(&FP5_W, &added)
	g := g.Add(a0b0, muld)

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

	arr := ToBasefieldArray(x)

	z0 := g.DeepCopy(&FP5_DTH_ROOT)
	for i := 1; i < count; i++ {
		z0 = g.Mul(&FP5_DTH_ROOT, &z0)
	}

	res := ToBasefieldArray(FP5_ZERO)
	for i, z := range g.Powers(&z0, FP5_D) {
		muld := g.Mul(&arr[i], &z)
		res[i] = muld
	}

	return FromBasefieldArray(res)
}

func Legendre(x Element) g.Element {
	frob1 := Frobenius(x)
	frob2 := Frobenius(frob1)

	frob1TimesFrob2 := Mul(frob1, frob2)
	frob2Frob1TimesFrob2 := RepeatedFrobenius(frob1TimesFrob2, 2)

	xrExt := Mul(Mul(x, frob1TimesFrob2), frob2Frob1TimesFrob2)
	xr := ToBasefieldArray(xrExt)[0]

	xr31 := xr.Exp(xr, new(big.Int).SetUint64(1<<31))
	xr31Copy := g.DeepCopy(xr31)
	xr63 := xr31Copy.Exp(*xr31, new(big.Int).SetUint64(1<<32))

	xr31InvOrZero := g.FromUint64(0)
	xr31InvOrZero = *xr31InvOrZero.Inverse(xr31)

	return g.Mul(xr63, &xr31InvOrZero)
}
