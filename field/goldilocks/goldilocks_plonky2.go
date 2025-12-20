package goldilocks

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"math/bits"

	. "github.com/elliottech/poseidon_crypto/int"
)

type GoldilocksField uint64

const Bytes = 8
const EPSILON = uint64((1 << 32) - 1)
const ORDER = uint64(0xffffffff00000001)
const TWO_ADICITY = 32
const POWER_OF_TWO_GENERATOR = GoldilocksField(7277203076849721926)

var ORDER_BIG = new(big.Int).SetUint64(ORDER)

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
	sum, over := bits.Add64(uint64(lhs), rhs, 0)
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

func ExpF(x GoldilocksField, exponent uint64) GoldilocksField {
	current := x
	product := OneF()

	for exponent > 0 {
		if exponent&1 == 1 {
			product = MulF(product, current)
		}
		current = SquareF(current)
		exponent >>= 1
	}

	return product
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

// NonCanonical conversion
func AsUInt128(f GoldilocksField) UInt128 {
	u := uint64(f)
	return UInt128{Hi: 0, Lo: u}
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

func SqrtF(self GoldilocksField) *GoldilocksField {
	if self.IsZero() {
		z := GoldilocksField(0)
		return &z
	}
	if IsQuadraticResidueF(self) {
		// reduce first
		self := GoldilocksField(self.ToCanonicalUint64())

		t := (ORDER - 1) / (1 << TWO_ADICITY)
		z := POWER_OF_TWO_GENERATOR
		w := ExpF(self, (t-1)/2)
		x := MulF(self, w)
		b := MulF(x, w)

		v := TWO_ADICITY

		for b.ToCanonicalUint64() != 1 {
			k := 0
			b2k := b
			for b2k.ToCanonicalUint64() != 1 {
				b2k = SquareF(b2k)
				k++
			}

			j := v - k - 1
			w = z
			for n := int(0); n < j; n++ {
				w = SquareF(w)
			}

			z = SquareF(w)
			b = MulF(b, z)
			x = MulF(x, w)
			v = k
		}

		return &x
	}

	return nil
}

func IsQuadraticResidueF(x GoldilocksField) bool {
	if x.IsZero() {
		return true
	}

	power := NegF(1).ToCanonicalUint64() >> 1
	exp := ExpF(x, power)
	switch exp.ToCanonicalUint64() {
	case 1:
		return true
	case ORDER - 1:
		return false
	default:
		panic("unreachable")
	}
}

func (self GoldilocksField) InverseOrZero() GoldilocksField {
	if self.IsZero() {
		return ZeroF()
	}

	// base.exp_power_of_2(N) * tail
	t2 := MulF(SquareF(self), self)
	t3 := MulF(SquareF(t2), self)
	t6 := MulF(ExpPowerOf2(t3, 3), t3)
	t12 := MulF(ExpPowerOf2(t6, 6), t6)
	t24 := MulF(ExpPowerOf2(t12, 12), t12)
	t30 := MulF(ExpPowerOf2(t24, 6), t6)
	t31 := MulF(SquareF(t30), self)

	t63 := MulF(ExpPowerOf2(t31, 32), t31)

	return MulF(SquareF(t63), self)
}

func (self GoldilocksField) Inverse() GoldilocksField {
	if self.IsZero() {
		panic("inverse of zero")
	}

	return self.InverseOrZero()
}

// Powers starting from 1
func PowersF(e GoldilocksField, count int) []GoldilocksField {
	ret := make([]GoldilocksField, count)
	ret[0] = OneF()
	for i := 1; i < count; i++ {
		ret[i] = MulF(ret[i-1], e)
	}
	return ret
}
