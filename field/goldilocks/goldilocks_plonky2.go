package goldilocks

import (
	"encoding/binary"
	"math/bits"
)

type GoldilocksField uint64

const EPSILON = uint64((1 << 32) - 1)
const ORDER = uint64(0xffffffff00000001)

//go:noescape
func branchHint()

func (z GoldilocksField) ToCanonicalUint64() uint64 {
	x := uint64(z)
	if x >= ORDER {
		x -= ORDER
	}

	return x
}

func ZeroF() GoldilocksField {
	return 0
}

func OneF() GoldilocksField {
	return 1
}

func NegOneF() GoldilocksField {
	return GoldilocksField(ORDER - 1)
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

func AddF(lhs, rhs GoldilocksField) GoldilocksField {
	sum, over := OverflowAdd(uint64(lhs), uint64(rhs))
	sum, over = OverflowAdd(sum, over*EPSILON)
	if over == 1 {
		branchHint()
		sum += EPSILON // this can't overflow
	}

	return GoldilocksField(sum)
}

func DoubleF(lhs GoldilocksField) GoldilocksField {
	return AddF(lhs, lhs)
}

func SubF(lhs, rhs GoldilocksField) GoldilocksField {
	diff, borrow := OverflowSub(uint64(lhs), uint64(rhs))
	diff, borrow = OverflowSub(diff, borrow*EPSILON)
	if borrow == 1 {
		branchHint()
		diff -= EPSILON // this can't underflow
	}

	return GoldilocksField(diff)
}

func MulF(lhs, rhs GoldilocksField) GoldilocksField {
	x_hi, x_lo := bits.Mul64(uint64(lhs), uint64(rhs))

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
	return GoldilocksField(t2)
}

func SquareF(x GoldilocksField) GoldilocksField {
	return MulF(x, x)
}

func ExpPowerOf2(x GoldilocksField, n uint) GoldilocksField {
	z := x
	for i := uint(0); i < n; i++ {
		z = SquareF(z)
	}

	return z
}

func ToLittleEndianBytesF(z GoldilocksField) []byte {
	res := make([]byte, Bytes)
	binary.LittleEndian.PutUint64(res, z.ToCanonicalUint64())
	return res
}

func FromCanonicalLittleEndianBytesF(b []byte) GoldilocksField {
	return GoldilocksField(binary.LittleEndian.Uint64(b))
}

func (z GoldilocksField) IsZero() bool {
	return z == 0
}

func (z GoldilocksField) IsOne() bool {
	return z == 1
}

func NegF(x GoldilocksField) GoldilocksField {
	z := GoldilocksField(0)
	if !x.IsZero() {
		z = GoldilocksField(ORDER - uint64(x))
	}

	return z
}

// func (z *GoldilocksField) Inverse(x *GoldilocksField) *GoldilocksField {
// 	if x.IsZero() {
// 		z.SetZero()
// 		return z
// 	}

// 	var tmp *GoldilocksField

// 	t2 := *tmp.Square(x).Mul(tmp, x)
// 	t3 := *tmp.Square(&t2).Mul(tmp, x)
// 	t6 := *tmp.ExpPowerOf2(&t3, 3).Mul(tmp, &t3)
// 	t12 := *tmp.ExpPowerOf2(&t6, 6).Mul(tmp, &t6)
// 	t24 := *tmp.ExpPowerOf2(&t12, 12).Mul(tmp, &t12)
// 	t30 := *tmp.ExpPowerOf2(&t24, 6).Mul(tmp, &t6)
// 	t31 := *tmp.Square(&t30).Mul(tmp, x)
// 	t63 := *tmp.ExpPowerOf2(&t31, 32).Mul(tmp, &t31)

// 	z.Square(&t63).Mul(z, x)

// 	return z
// }
