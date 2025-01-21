package goldilocks

import (
	"encoding/binary"
	"math/bits"
	"math/rand/v2"
)

const Bytes = 8

type GoldilocksField struct {
	x uint64
}

const EPSILON = uint64((1 << 32) - 1)
const ORDER = uint64(0xffffffff00000001)

//go:noescape
func branchHint()

func NewElement(value uint64) GoldilocksField {
	return GoldilocksField{x: value}
}

func (z *GoldilocksField) Set(x *GoldilocksField) *GoldilocksField {
	z.x = x.x
	return z
}

func (z *GoldilocksField) SetZero() *GoldilocksField {
	z.x = 0
	return z
}

func (z *GoldilocksField) SetOne() *GoldilocksField {
	z.x = 1
	return z
}

func (z *GoldilocksField) Uint64() uint64 {
	return z.x
}

func (z *GoldilocksField) ToCanonicalUint64() uint64 {
	x := z.x
	if x >= ORDER {
		x -= ORDER
	}

	return x
}

func Zero() GoldilocksField {
	return GoldilocksField{x: 0}
}

func One() GoldilocksField {
	return GoldilocksField{x: 1}
}

func NegOne() GoldilocksField {
	return GoldilocksField{x: ORDER - 1}
}

func OverflowAdd(x, y uint64) (uint64, uint64) {
	sum := x + y
	// The sum will overflow if both top bits are set (x & y) or if one of them
	// is (x | y), and a carry from the lower place happened. If such a carry
	// happens, the top bit will be 1 + 0 + 1 = 0 (&^ sum).
	carryOut := ((x & y) | ((x | y) &^ sum)) >> 63
	return sum, carryOut
}

func OverflowSub(x, y uint64) (uint64, uint64) {
	diff := x - y
	// See Sub32 for the bit logic.
	borrowOut := ((^x & y) | (^(x ^ y) & diff)) >> 63
	return diff, borrowOut
}

func (z *GoldilocksField) Add(lhs, rhs *GoldilocksField) *GoldilocksField {
	sum, over := OverflowAdd(lhs.x, rhs.x)
	sum, over = OverflowAdd(sum, over*EPSILON)
	if over == 1 {
		branchHint()
		sum += EPSILON // this can't overflow
	}

	z.x = sum
	return lhs
}

func (z *GoldilocksField) Double(lhs *GoldilocksField) *GoldilocksField {
	return z.Add(lhs, lhs)
}

func (z *GoldilocksField) Sub(lhs, rhs *GoldilocksField) *GoldilocksField {
	diff, borrow := OverflowSub(lhs.x, rhs.x)
	diff, borrow = OverflowSub(diff, borrow*EPSILON)
	if borrow == 1 {
		branchHint()
		diff -= EPSILON // this can't underflow
	}

	z.x = diff
	return lhs
}

func (z *GoldilocksField) Mul(lhs, rhs *GoldilocksField) *GoldilocksField {
	x_hi, x_lo := bits.Mul64(lhs.x, rhs.x)

	x_hi_hi := x_hi >> 32
	x_hi_lo := x_hi & EPSILON

	t0, borrow := OverflowSub(x_lo, x_hi_hi)
	if borrow == 1 {
		branchHint()
		t0 -= EPSILON
	}
	t1 := x_hi_lo * EPSILON

	sum, over := OverflowAdd(t0, t1)
	t2 := sum + EPSILON*over

	z.x = t2
	return lhs
}

func (z *GoldilocksField) Square(x *GoldilocksField) *GoldilocksField {
	return z.Mul(x, x)
}

func (z *GoldilocksField) ExpPowerOf2(x *GoldilocksField, n uint) *GoldilocksField {
	z.Set(x)
	for i := uint(0); i < n; i++ {
		z.Square(z)
	}

	return z
}

func (z *GoldilocksField) ToLittleEndianBytes() []byte {
	res := make([]byte, Bytes)
	binary.LittleEndian.PutUint64(res, z.ToCanonicalUint64())
	return res
}

func (z *GoldilocksField) FromCanonicalLittleEndianBytes(b []byte) {
	z.x = binary.LittleEndian.Uint64(b)
}

func (z *GoldilocksField) Sample() *GoldilocksField {
	z.x = rand.Uint64N(ORDER)
	return z
}

func (z *GoldilocksField) IsZero() bool {
	return z.x == 0
}

func (z *GoldilocksField) IsOne() bool {
	return z.x == 1
}

func (z *GoldilocksField) Neg(x *GoldilocksField) *GoldilocksField {
	if x.IsZero() {
		z.x = 0
	} else {
		z.x = ORDER - x.x
	}

	return z
}

func (z *GoldilocksField) Inverse(x *GoldilocksField) *GoldilocksField {
	if x.IsZero() {
		z.SetZero()
		return z
	}

	var tmp *GoldilocksField

	t2 := *tmp.Square(x).Mul(tmp, x)
	t3 := *tmp.Square(&t2).Mul(tmp, x)
	t6 := *tmp.ExpPowerOf2(&t3, 3).Mul(tmp, &t3)
	t12 := *tmp.ExpPowerOf2(&t6, 6).Mul(tmp, &t6)
	t24 := *tmp.ExpPowerOf2(&t12, 12).Mul(tmp, &t12)
	t30 := *tmp.ExpPowerOf2(&t24, 6).Mul(tmp, &t6)
	t31 := *tmp.Square(&t30).Mul(tmp, x)
	t63 := *tmp.ExpPowerOf2(&t31, 32).Mul(tmp, &t31)

	z.Square(&t63).Mul(z, x)

	return z
}

// Powers starting from 1
func Powers(e *GoldilocksField, count int) []GoldilocksField {
	ret := make([]GoldilocksField, count)
	ret[0].SetOne()
	for i := 1; i < int(count); i++ {
		ret[i].Mul(&ret[i-1], e)
	}
	return ret
}
