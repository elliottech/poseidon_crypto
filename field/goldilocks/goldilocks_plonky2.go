package goldilocks

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"math/bits"
)

type GoldilocksField uint64

const EPSILON = uint64((1 << 32) - 1)
const ORDER = uint64(0xffffffff00000001)

var ORDER_BIG, _ = new(big.Int).SetString("0xffffffff00000001", 16)

func NonCannonicalGoldilocksField(x int64) GoldilocksField {
	if x < 0 {
		return NegF(GoldilocksField(-x))
	}

	return GoldilocksField(x)
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

func (z GoldilocksField) IsZero() bool {
	return z.ToCanonicalUint64() == 0
}

func (z GoldilocksField) ToCanonicalUint64() uint64 {
	x := uint64(z)
	if x >= ORDER {
		x -= ORDER
	}

	return x
}

// lhs, rhs in non-canonical form
func AddF(lhs, rhs GoldilocksField) GoldilocksField {
	sum, over := bits.Add64(uint64(lhs), uint64(rhs), 0)
	sum, over = bits.Add64(sum, over*EPSILON, 0)
	if over == 1 {
		branchHint()
		sum += EPSILON // this can't overflow
	}

	return GoldilocksField(sum)
}

// Assuming lhs or rhs is in the field, i.e. x < ORDER and other in non-canonical form(u64). This assumption can be used to remove second overflow check.
func AddCanonicalUint64(lhs GoldilocksField, rhs uint64) GoldilocksField {
	sum, over := bits.Add64(uint64(lhs), uint64(rhs), 0)
	// if overflowed, sum := lhs + rhs - 2^64 => sum + EPSILON = lhs + rhs - 2^64 + 2^32 -1 = lhs + rhs - ORDER < ORDER + 2^64 - ORDER = 2^64, so there is no overflow in this case.
	return GoldilocksField(sum + over*EPSILON)
}

func DoubleF(lhs GoldilocksField) GoldilocksField {
	return AddF(lhs, lhs)
}

// lhs, rhs in non-canonical form
func SubF(lhs, rhs GoldilocksField) GoldilocksField {
	diff, borrow := bits.Sub64(uint64(lhs), uint64(rhs), 0)
	diff, borrow = bits.Sub64(diff, borrow*EPSILON, 0)
	if borrow == 1 {
		branchHint()
		diff -= EPSILON // this can't underflow
	}

	return GoldilocksField(diff)
}

// lhs, rhs in non-canonical form
func MulF(lhs, rhs GoldilocksField) GoldilocksField {
	x_hi, x_lo := bits.Mul64(uint64(lhs), uint64(rhs))

	x_hi_hi := x_hi >> 32
	x_hi_lo := x_hi & EPSILON

	t0, borrow := bits.Sub64(x_lo, x_hi_hi, 0)
	if borrow == 1 {
		branchHint()
		t0 -= EPSILON
	}
	t1 := x_hi_lo * EPSILON

	sum, over := bits.Add64(t0, t1, 0)
	t2 := sum + EPSILON*over
	return GoldilocksField(t2)
}

func SquareF(x GoldilocksField) GoldilocksField {
	return MulF(x, x)
}

// Returns self + x * y
func MulAccF(self, x, y GoldilocksField) GoldilocksField {
	// u64 + u64 * u64 cannot overflow.
	return Reduce128Bit(AddUInt128(AsUInt128(self), MulUInt64(uint64(x), uint64(y))))
}

func ExpPowerOf2(x GoldilocksField, n uint) GoldilocksField {
	z := x
	for i := uint(0); i < n; i++ {
		z = SquareF(z)
	}

	return z
}

func NegF(x GoldilocksField) GoldilocksField {
	z := GoldilocksField(0)
	if !x.IsZero() {
		z = GoldilocksField(ORDER - x.ToCanonicalUint64())
	}

	return z
}

func SampleF() GoldilocksField {
	rng, err := rand.Int(rand.Reader, ORDER_BIG)
	if err != nil {
		panic("failed to read random bytes into buffer")
	}
	return GoldilocksField(rng.Uint64())
}

// Canonical representation
func ToLittleEndianBytesF(z GoldilocksField) []byte {
	res := make([]byte, Bytes)
	binary.LittleEndian.PutUint64(res, z.ToCanonicalUint64())
	return res
}

func FromCanonicalLittleEndianBytesF(b []byte) GoldilocksField {
	return GoldilocksField(binary.LittleEndian.Uint64(b))
}

type UInt128 struct {
	Hi, Lo uint64
}

// NonCanonical conversion
func AsUInt128(f GoldilocksField) UInt128 {
	u := uint64(f)
	return UInt128{0, u}
}

func AddUInt128(x, y UInt128) UInt128 {
	var carry uint64
	var z UInt128
	z.Lo, carry = bits.Add64(x.Lo, y.Lo, 0)
	z.Hi = x.Hi + y.Hi + carry
	return z
}

func MulUInt64(x, y uint64) UInt128 {
	hi, lo := bits.Mul64(x, y)
	return UInt128{hi, lo}
}

// Assumes x is 96-bit number
func Reduce96Bit(x UInt128) GoldilocksField {
	t1 := x.Hi * EPSILON
	resWrapped, carry := bits.Add64(x.Lo, t1, 0)

	return GoldilocksField(resWrapped) + GoldilocksField(carry*EPSILON)
}

func Reduce128Bit(x UInt128) GoldilocksField {
	x_hi_hi := x.Hi >> 32
	x_hi_lo := x.Hi & EPSILON

	t0, borrow := bits.Sub64(x.Lo, x_hi_hi, 0)
	if borrow == 1 {
		branchHint()
		t0 -= EPSILON
	}
	t1 := x_hi_lo * EPSILON

	resWrapped, carry := bits.Add64(t0, t1, 0)
	t2 := resWrapped + EPSILON*carry
	return GoldilocksField(t2)
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
