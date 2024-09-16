package ecgfp5

// TESTED

import (
	"math/big"
	"math/bits"

	config "github.com/consensys/gnark-crypto/field/generator/config"
)

/*
	TODO:
		- Add lagrange after signed161 and signed640
		- Get rid of all unused functions
		- Remove //tested comments
*/

// ECgFp5Scalar represents the scalar field of the ECgFP5 elliptic curve where
// p = 1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241
type ECgFp5Scalar struct {
	Value [5]big.Int
}

func (s ECgFp5Scalar) GetUint64Limbs() [5]uint64 {
	return [5]uint64{s.Value[0].Uint64(), s.Value[1].Uint64(), s.Value[2].Uint64(), s.Value[3].Uint64(), s.Value[4].Uint64()}
}

var (
	ORDER, _ = new(big.Int).SetString("1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241", 10)
	ZERO     = ECgFp5Scalar{[5]big.Int{}}
	ONE      = ECgFp5Scalar{[5]big.Int{*new(big.Int).SetUint64(1), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)}}
	TWO      = ECgFp5Scalar{[5]big.Int{*new(big.Int).SetUint64(2), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)}}
	NEG_ONE  = ECgFp5Scalar{[5]big.Int{
		*new(big.Int).SetUint64(0xE80FD996948BFFE0),
		*new(big.Int).SetUint64(0xE8885C39D724A09C),
		*new(big.Int).SetUint64(0x7FFFFFE6CFB80639),
		*new(big.Int).SetUint64(0x7FFFFFF100000016),
		*new(big.Int).SetUint64(0x7FFFFFFD80000007),
	}}
)

func (s ECgFp5Scalar) Order() *big.Int {
	return ORDER
}

// Only the null element will not have an inverse.
// Extended Euclidian would be more performant but we use Fermat's Little for ease.
func (s ECgFp5Scalar) TryInverse() *ECgFp5Scalar {
	if s.IsZero() {
		return nil
	}

	// Fermat's Little Theorem: a^(p-1) = 1 mod p  <==>  a * a^(p-2) = a^{-1} mod p
	order := s.Order()
	exp := new(big.Int).Sub(order, new(big.Int).SetUint64(2)) // p - 2

	inverse_big := s.ExpBigInt(exp)
	return &inverse_big
}

var (
	// Group order n is slightly below 2^319. We store values over five
	// 64-bit limbs. We use Montgomery multiplication to perform
	// computations; however, we keep the limbs in normal
	// (non-Montgomery) representation, so that operations that do not
	// require any multiplication of scalars, just encoding and
	// decoding, are fastest.

	// The modulus itself, stored in a Scalar structure (which
	// contravenes to the rules of a Scalar; this constant MUST NOT leak
	// outside the API).
	N = ECgFp5Scalar{[5]big.Int{
		*new(big.Int).SetUint64(0xE80FD996948BFFE1),
		*new(big.Int).SetUint64(0xE8885C39D724A09C),
		*new(big.Int).SetUint64(0x7FFFFFE6CFB80639),
		*new(big.Int).SetUint64(0x7FFFFFF100000016),
		*new(big.Int).SetUint64(0x7FFFFFFD80000007),
	}}
	// -1/N[0] mod 2^64
	N0I = new(big.Int).SetUint64(0xD78BEF72057B7BDF)
	// 2^640 mod n
	R2 = ECgFp5Scalar{[5]big.Int{
		*new(big.Int).SetUint64(0xA01001DCE33DC739),
		*new(big.Int).SetUint64(0x6C3228D33F62ACCF),
		*new(big.Int).SetUint64(0xD1D796CC91CF8525),
		*new(big.Int).SetUint64(0xAADFFF5D1574C1D8),
		*new(big.Int).SetUint64(0x4ACA13B28CA251F5),
	}}
	// 2^632 mod n
	T632 = ECgFp5Scalar{[5]big.Int{
		*new(big.Int).SetUint64(0x2B0266F317CA91B3),
		*new(big.Int).SetUint64(0xEC1D26528E984773),
		*new(big.Int).SetUint64(0x8651D7865E12DB94),
		*new(big.Int).SetUint64(0xDA2ADFF5941574D0),
		*new(big.Int).SetUint64(0x53CACA12110CA256),
	}}
)

func (s ECgFp5Scalar) IsZero() bool {
	for i := 0; i < 5; i++ {
		if s.Value[i].Sign() != 0 {
			return false
		}
	}
	return true
}

func (s ECgFp5Scalar) Equals(rhs ECgFp5Scalar) bool {
	for i := 0; i < 5; i++ {
		if s.Value[i].Cmp(&rhs.Value[i]) != 0 {
			return false
		}
	}
	return true
}

// raw addition (no reduction)
func (s ECgFp5Scalar) AddInner(a ECgFp5Scalar) ECgFp5Scalar {
	var r ECgFp5Scalar
	var c uint64 = 0
	for i := 0; i < 5; i++ {
		z := new(big.Int).SetUint64(s.Value[i].Uint64())
		z.Add(z, new(big.Int).SetUint64(a.Value[i].Uint64()))
		z.Add(z, new(big.Int).SetUint64(c))

		r.Value[i] = *new(big.Int).SetUint64(z.Uint64())
		c = new(big.Int).Rsh(z, 64).Uint64()
	}
	return r
}

// raw subtraction (no reduction)
// Final borrow is returned (0xFFFFFFFFFFFFFFFF if borrow, 0 otherwise).
func (s ECgFp5Scalar) SubInner(a ECgFp5Scalar) (ECgFp5Scalar, *big.Int) {
	var r ECgFp5Scalar
	c := big.NewInt(0)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128

	for i := 0; i < 5; i++ {
		sVal := new(big.Int).SetUint64(s.Value[i].Uint64())
		aVal := new(big.Int).SetUint64(a.Value[i].Uint64())
		cVal := new(big.Int).Set(c)

		aValPlusCval := new(big.Int).Add(aVal, cVal)
		z := new(big.Int).Sub(sVal, aValPlusCval)

		if z.Sign() < 0 {
			z.Add(z, two128) // TODO: try mod
		}

		r.Value[i] = *new(big.Int).SetUint64(z.Uint64())
		c.SetUint64(new(big.Int).Rsh(z, 64).Uint64() & 1)
	}

	if c.Uint64() != 0 {
		return r, new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF)
	}
	return r, new(big.Int).SetUint64(0)
}

// If c == 0, return a0.
// If c == 0xFFFFFFFFFFFFFFFF, return a1.
// c MUST be equal to 0 or 0xFFFFFFFFFFFFFFFF.
func Select(c *big.Int, a0, a1 ECgFp5Scalar) ECgFp5Scalar {
	var r ECgFp5Scalar
	for i := 0; i < 5; i++ {
		r.Value[i].Xor(&a0.Value[i], new(big.Int).And(c, new(big.Int).Xor(&a0.Value[i], &a1.Value[i])))
	}
	return r
}

func (s ECgFp5Scalar) Add(rhs ECgFp5Scalar) ECgFp5Scalar {
	r0 := s.AddInner(rhs)
	r1, c := r0.SubInner(N)
	return Select(c, r1, r0)
}

func (s ECgFp5Scalar) Sub(rhs ECgFp5Scalar) ECgFp5Scalar {
	r0, c := s.SubInner(rhs)
	r1 := r0.AddInner(N)
	return Select(c, r0, r1)
}

func (s ECgFp5Scalar) Neg() ECgFp5Scalar {
	return ZERO.Sub(s)
}

func (s ECgFp5Scalar) Mul(rhs ECgFp5Scalar) ECgFp5Scalar {
	return s.MontyMul(R2).MontyMul(rhs)
}

func (s ECgFp5Scalar) Square() ECgFp5Scalar {
	return s.Mul(s)
}

// Montgomery multiplication.
// Returns (self*rhs)/2^320 mod n.
// 'self' MUST be less than n (the other operand can be up to 2^320-1).
func (s ECgFp5Scalar) MontyMul(rhs ECgFp5Scalar) ECgFp5Scalar {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)   // 2^64
	var r ECgFp5Scalar
	for i := 0; i < 5; i++ {
		// Iteration i computes r <- (r + self*rhs_i + f*n)/2^64.
		// Factor f is at most 2^64-1 and set so that the division
		// is exact.
		// On input:
		//    r <= 2^320 - 1
		//    self <= n - 1
		//    rhs_i <= 2^64 - 1
		//    f <= 2^64 - 1
		// Therefore:
		//    r + self*rhs_i + f*n <= 2^320-1 + (2^64 - 1) * (n - 1)
		//                            + (2^64 - 1) * n
		//                         < 2^384
		// Thus, the new r fits on 320 bits.
		m := new(big.Int).Set(&rhs.Value[i])
		f := new(big.Int).Mul(&s.Value[0], m)
		f.Add(f, &r.Value[0])
		f.Mul(f, N0I)
		f.Mod(f, two64) // Simulate u64 wrapping
		var cc1, cc2 big.Int
		for j := 0; j < 5; j++ {
			z := new(big.Int).Mul(&s.Value[j], m)
			z.Add(z, &r.Value[j])
			z.Add(z, &cc1)

			z.Mod(z, two128) // Simulate u128 wrapping

			cc1.SetUint64(new(big.Int).Rsh(z, 64).Uint64())

			z = new(big.Int).Add(
				new(big.Int).Mul(f, &N.Value[j]),
				new(big.Int).Add(
					new(big.Int).SetUint64(z.Uint64()),
					&cc2,
				),
			)

			z.Mod(z, two128) // Simulate u128 wrapping
			cc2.SetUint64(new(big.Int).Rsh(z, 64).Uint64())

			if j > 0 {
				r.Value[j-1].SetUint64(z.Uint64())
			}
		}
		// No overflow here since the new r fits on 320 bits.
		r.Value[4].Add(&cc1, &cc2)
		r.Value[4].Mod(&r.Value[4], two64) // Simulate u64 wrapping
	}
	// We computed (self*rhs + ff*n) / 2^320, with:
	//    self < n
	//    rhs < 2^320
	//    ff < 2^320
	// Thus, the value we obtained is lower than 2*n. Subtracting n
	// once (conditionally) is sufficient to achieve full reduction.
	r2, c := r.SubInner(N)
	return Select(c, r2, r)
}

func (s ECgFp5Scalar) expU64(power uint64) ECgFp5Scalar {
	current := s
	product := ONE

	bitsU64 := 64 - bits.LeadingZeros64(power)
	for j := 0; j < bitsU64; j++ {
		if (power>>j)&1 != 0 {
			product = product.Mul(current)
		}
		current = current.Square()
	}
	return product
}

func (s ECgFp5Scalar) expPowerOf2(exp int) ECgFp5Scalar {
	result := s
	for i := 0; i < exp; i++ {
		result = result.Square()
	}
	return result
}

func (s ECgFp5Scalar) ExpBigInt(power *big.Int) ECgFp5Scalar {
	result := ONE
	digits := power.Bits()
	for i := len(digits) - 1; i >= 0; i-- {
		result = result.expPowerOf2(64)
		result = result.Mul(s.expU64(uint64(digits[i])))
	}
	return result
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

func FromGfp5(fp5 config.Element) ECgFp5Scalar {
	return FromNonCanonicalBigInt(BigIntFromArray([5]uint64{
		fp5[0].Uint64(),
		fp5[1].Uint64(),
		fp5[2].Uint64(),
		fp5[3].Uint64(),
		fp5[4].Uint64(),
	}))
}

func BigIntFromArray(arr [5]uint64) *big.Int {
	result := new(big.Int)
	for i := 4; i >= 0; i-- {
		result.Lsh(result, 64)
		result.Or(result, new(big.Int).SetUint64(arr[i]))
	}
	return result
}

func FromNonCanonicalBigInt(val *big.Int) ECgFp5Scalar {
	val = new(big.Int).Mod(val, ORDER)

	var value [5]big.Int
	limbs := val.Bits()
	for i := 0; i < len(limbs) && i < 5; i++ {
		value[i].SetUint64(uint64(limbs[i]))
	}

	return ECgFp5Scalar{value}
}

func (s ECgFp5Scalar) ToCanonicalBigInt() *big.Int {
	result := BigIntFromArray([5]uint64{
		s.Value[0].Uint64(),
		s.Value[1].Uint64(),
		s.Value[2].Uint64(),
		s.Value[3].Uint64(),
		s.Value[4].Uint64(),
	})

	order := ORDER
	if result.Cmp(order) >= 0 {
		result.Sub(result, order)
	}

	return result
}

// Recode a scalar into signed integers. For a window width of w
// bits, returned integers are in the -(2^w-1) to +2^w range. The
// provided slice is filled; if w*len(ss) >= 320, then the output
// encodes the complete scalar value, and the top (last) signed
// integer is nonnegative.
// Window width MUST be between 2 and 10.
func (s ECgFp5Scalar) RecodeSigned(ss []int32, w int32) {
	limbs := s.GetUint64Limbs()
	RecodeSignedFromLimbs(limbs[:], ss, w)
}

func RecodeSignedFromLimbs(limbs []uint64, ss []int32, w int32) {
	var acc uint64 = 0
	var accLen int32 = 0
	var j int = 0
	mw := (uint32(1) << w) - 1
	hw := uint32(1) << (w - 1)
	var cc uint32 = 0
	for i := 0; i < len(ss); i++ {
		// Get next w-bit chunk in bb.
		var bb uint32
		if accLen < w {
			if j < len(limbs) {
				nl := limbs[j]
				j++
				bb = (uint32(acc | (nl << accLen))) & mw
				acc = nl >> (w - accLen)
			} else {
				bb = uint32(acc) & mw
				acc = 0
			}
			accLen += 64 - w
		} else {
			bb = uint32(acc) & mw
			accLen -= w
			acc >>= w
		}

		// If bb is greater than 2^(w-1), subtract 2^w and propagate a carry.
		bb += cc

		cc = (hw - bb) >> 31
		ss[i] = int32(bb) - int32(cc<<w)
	}
}
