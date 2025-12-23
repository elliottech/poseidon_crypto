package field

import (
	"encoding/binary"
	"math"
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	. "github.com/elliottech/poseidon_crypto/int"

	"math/big"
	"math/rand/v2"
)

func TestBytes(t *testing.T) {
	e1 := g.Sample()

	leBytes := g.ToLittleEndianBytes(e1)
	beBytes := e1.Bytes()
	for i := 0; i < g.Bytes; i++ {
		if beBytes[i] != leBytes[g.Bytes-i-1] {
			t.Fatalf("Big endian and little endian bytes are not reversed")
		}
	}

	e1ReconstructedLE, _ := g.FromCanonicalLittleEndianBytes(leBytes)
	if !g.Equals(&e1, e1ReconstructedLE) {
		t.Fatalf("bytes do not match")
	}

	r := rand.Uint64N(g.ORDER) //nolint:gosec

	leBytesUint64 := make([]byte, 8)
	binary.LittleEndian.PutUint64(leBytesUint64, r)

	leBytesElem := g.ToLittleEndianBytes(g.FromUint64(r))
	for i := 0; i < 8; i++ {
		if leBytesUint64[i] != leBytesElem[i] {
			t.Fatalf("Little-endian bytes do not match at index %d: expected %x, got %x", i, leBytesUint64[i], leBytesElem[i])
		}
	}
}

func TestBytesF(t *testing.T) {
	r := rand.Uint64N(g.ORDER) //nolint:gosec
	f := g.GoldilocksField(r)

	rBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBytes, r)

	fBytes := g.ToLittleEndianBytesF(f)
	for i := 0; i < 8; i++ {
		if rBytes[i] != fBytes[i] {
			t.Fatalf("Little-endian bytes do not match at index %d: expected %x, got %x", i, rBytes[i], fBytes[i])
		}
	}

	ff := g.FromCanonicalLittleEndianBytesF(fBytes)
	if ff != f {
		t.Fatalf("bytes do not match")
	}
}

// Goldilocks field tests

// Inputs that covers several input ranges
var inputs = []uint64{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2147483638, 2147483639, 2147483640, 2147483641, 2147483642, 2147483643, 2147483644, 2147483645, 2147483646, 2147483647, 2147483648, 2147483649,
	2147483650, 2147483651, 2147483652, 2147483653, 2147483654, 2147483655, 2147483656, 2147483657, 4294967286, 4294967287, 4294967288, 4294967289, 4294967290, 4294967291,
	4294967292, 4294967293, 4294967294, 4294967295, 4294967296, 4294967297, 4294967298, 4294967299, 4294967300, 4294967301, 4294967302, 4294967303, 4294967304, 4294967305,
	9223372036854775798, 9223372036854775799, 9223372036854775800, 9223372036854775801, 9223372036854775802, 9223372036854775803, 9223372036854775804, 9223372036854775805,
	9223372036854775806, 9223372036854775807, 9223372036854775808, 9223372036854775809, 9223372036854775810, 9223372036854775811, 9223372036854775812, 9223372036854775813,
	9223372036854775814, 9223372036854775815, 9223372036854775816, 9223372036854775817, 18446744069414584311, 18446744069414584312, 18446744069414584313, 18446744069414584314,
	18446744069414584315, 18446744069414584316, 18446744069414584317, 18446744069414584318, 18446744069414584319, 18446744069414584320,
}

func NewBigInt(x uint64) *big.Int {
	return big.NewInt(0).SetUint64(x)
}

func SumMod(x, y uint64) uint64 {
	sum := NewBigInt(x).Add(NewBigInt(x), NewBigInt(y))
	res := sum.Mod(sum, NewBigInt(g.ORDER))
	if !res.IsUint64() {
		panic("sum is not uint64")
	}
	return res.Uint64()
}

func SubMod(x, y uint64) uint64 {
	sub := NewBigInt(x).Sub(NewBigInt(x), NewBigInt(y))
	res := sub.Mod(sub, NewBigInt(g.ORDER))
	if !res.IsUint64() {
		panic("difference is not uint64")
	}
	return res.Uint64()
}

func MulMod(x, y uint64) uint64 {
	mul := NewBigInt(x).Mul(NewBigInt(x), NewBigInt(y))
	res := mul.Mod(mul, NewBigInt(g.ORDER))
	if !res.IsUint64() {
		panic("product is not uint64")
	}
	return res.Uint64()
}

func NegMod(x uint64) uint64 {
	neg := NewBigInt(x).Neg(NewBigInt(x))
	res := neg.Mod(neg, NewBigInt(g.ORDER))
	if !res.IsUint64() {
		panic("negative number is not uint64")
	}
	return res.Uint64()
}

func SquareMod(x uint64) uint64 {
	square := NewBigInt(x).Mul(NewBigInt(x), NewBigInt(x))
	res := square.Mod(square, NewBigInt(g.ORDER))
	if !res.IsUint64() {
		panic("square is not uint64")
	}
	return res.Uint64()
}

func TestAddF(t *testing.T) {
	for _, lhs := range inputs {
		for _, rhs := range inputs {
			fLhs := g.GoldilocksField(lhs)
			fRhs := g.GoldilocksField(rhs)
			sum := g.AddF(fLhs, fRhs).ToCanonicalUint64()
			expected := SumMod(lhs, rhs)
			if sum != expected {
				t.Fatalf("Expected %d + %d = %d, but got %d", lhs, rhs, expected, sum)
			}
		}
	}
}

func TestSubF(t *testing.T) {
	for _, lhs := range inputs {
		for _, rhs := range inputs {
			fLhs := g.GoldilocksField(lhs)
			fRhs := g.GoldilocksField(rhs)
			diff := g.SubF(fLhs, fRhs).ToCanonicalUint64()
			expected := SubMod(lhs, rhs)
			if diff != expected {
				t.Fatalf("Expected %d - %d = %d, but got %d", lhs, rhs, expected, diff)
			}
		}
	}
}

func TestMulF(t *testing.T) {
	for _, lhs := range inputs {
		for _, rhs := range inputs {
			fLhs := g.GoldilocksField(lhs)
			fRhs := g.GoldilocksField(rhs)
			mul := g.MulF(fLhs, fRhs).ToCanonicalUint64()
			expected := MulMod(lhs, rhs)
			if mul != expected {
				t.Fatalf("Expected %d * %d = %d, but got %d", lhs, rhs, expected, mul)
			}
		}
	}
}

func TestNegF(t *testing.T) {
	for _, lhs := range inputs {
		fLhs := g.GoldilocksField(lhs)
		neg := g.NegF(fLhs).ToCanonicalUint64()
		expected := NegMod(lhs)
		if neg != expected {
			t.Fatalf("Expected Neg(%d) = %d, but got %d", lhs, expected, neg)
		}
	}
}

func TestSquareF(t *testing.T) {
	for _, lhs := range inputs {
		fLhs := g.GoldilocksField(lhs)
		sqr := g.SquareF(fLhs).ToCanonicalUint64()
		expected := SquareMod(lhs)
		if sqr != expected {
			t.Fatalf("Expected (%d)^2 = %d, but got %d", lhs, expected, sqr)
		}
	}
}

func TestMulAccF(t *testing.T) {
	for _, x := range inputs {
		for _, y := range inputs {
			for _, z := range inputs {
				fX := g.GoldilocksField(x)
				fY := g.GoldilocksField(y)
				fZ := g.GoldilocksField(z)
				mulAcc := g.MulAccF(fX, fY, fZ).ToCanonicalUint64()
				expected := SumMod(x, MulMod(y, z))
				if mulAcc != expected {
					t.Fatalf("Expected %d + %d * %d = %d, but got %d", x, y, z, expected, mulAcc)
				}
			}
		}
	}
}

func TestReduce128Bit(t *testing.T) {
	testValues := []UInt128{
		{0, 0},
		{1, 0},
		{math.MaxUint64, math.MaxUint64},
		{0, g.ORDER + 1},
		{0, g.ORDER - 1},
		{0, 1},
		{0, math.MaxUint64},
		{math.MaxUint64, 0},
	}

	for _, val := range testValues {
		reduced := g.Reduce128Bit(val)
		bigVal := new(big.Int).SetUint64(val.Hi)
		bigVal.Lsh(bigVal, 64)
		bigVal.Add(bigVal, new(big.Int).SetUint64(val.Lo))
		bigOrder := new(big.Int).SetUint64(g.ORDER)
		bigVal.Mod(bigVal, bigOrder)
		expected := bigVal.Uint64()
		if reduced.ToCanonicalUint64() != expected {
			t.Fatalf("Expected reduction of %v to be %d, but got %d", val, expected, reduced.ToCanonicalUint64())
		}
	}
}

func TestReduce96Bit(t *testing.T) {
	testValues := []UInt128{
		{0, 0},
		{1, 0},
		{math.MaxUint32, math.MaxUint64},
		{0, g.ORDER + 1},
		{0, g.ORDER - 1},
		{0, 1},
		{0, math.MaxUint64},
		{math.MaxUint32, 0},
	}

	for _, val := range testValues {
		reduced := g.Reduce96Bit(val)
		bigVal := new(big.Int).SetUint64(val.Hi)
		bigVal.Lsh(bigVal, 64)
		bigVal.Add(bigVal, new(big.Int).SetUint64(val.Lo))

		if bigVal.BitLen() > 96 {
			t.Fatalf("Input %v exceeds 96 bits", val)
		}

		bigOrder := new(big.Int).SetUint64(g.ORDER)
		bigVal.Mod(bigVal, bigOrder)
		expected := bigVal.Uint64()
		if reduced.ToCanonicalUint64() != expected {
			t.Fatalf("Expected reduction of %v to be %d, but got %d", val, expected, reduced.ToCanonicalUint64())
		}
	}
}

func TestSubFDoubleWraparound(t *testing.T) {
	/*
		let (a, b) = (F::from_canonical_u64((F::ORDER + 1u64) / 2u64), F::TWO);
		let x = a * b;
		assert_eq!(x, F::ONE);
		assert_eq!(F::ZERO - x, F::NEG_ONE);
	*/

	a := g.GoldilocksField((g.ORDER + 1) / 2)
	b := g.GoldilocksField(2)
	x := g.MulF(a, b)
	if x.ToCanonicalUint64() != g.OneF().ToCanonicalUint64() {
		t.Fatalf("Expected a*b to be 1, but got %v", x)
	}
	if g.SubF(g.ZeroF(), x).ToCanonicalUint64() != g.NegOneF().ToCanonicalUint64() {
		t.Fatalf("Expected 0 - x to be -1, but got %v", g.SubF(g.ZeroF(), x))
	}
}

func TestAddFDoubleWraparound(t *testing.T) {
	/*
		let a = F::from_canonical_u64(u64::MAX - F::ORDER);
		let b = F::NEG_ONE;

		let c = (a + a) + (b + b);
		let d = (a + b) + (a + b);

		assert_eq!(c, d);
	*/

	a := g.GoldilocksField(math.MaxUint64 - g.ORDER)
	b := g.NegOneF()

	c := g.AddF(g.AddF(a, a), g.AddF(b, b))
	d := g.AddF(g.AddF(a, b), g.AddF(a, b))

	if c.ToCanonicalUint64() != d.ToCanonicalUint64() {
		t.Fatalf("Expected c to be equal to d, but got %v and %v", c, d)
	}
}

func FuzzTestF(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(1))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64))
	f.Add(uint64(math.MaxUint32), uint64(math.MaxUint64))
	f.Add(g.ORDER-1, g.ORDER-1)
	f.Add(g.ORDER, g.ORDER)

	f.Fuzz(func(t *testing.T, lhs, rhs uint64) {
		// AddF
		{
			addF := g.AddF(g.GoldilocksField(lhs), g.GoldilocksField(rhs)).ToCanonicalUint64()
			expected := SumMod(lhs, rhs)
			if addF != expected {
				t.Fatalf("AddF: Expected %d + %d = %d, but got %d", lhs, rhs, expected, addF)
			}
		}

		// SubF
		{
			subF := g.SubF(g.GoldilocksField(lhs), g.GoldilocksField(rhs)).ToCanonicalUint64()
			expected := SubMod(lhs, rhs)
			if subF != expected {
				t.Fatalf("SubF: Expected %d - %d = %d, but got %d", lhs, rhs, expected, subF)
			}
		}

		// MulF
		{
			mulF := g.MulF(g.GoldilocksField(lhs), g.GoldilocksField(rhs)).ToCanonicalUint64()
			expected := MulMod(lhs, rhs)
			if mulF != expected {
				t.Fatalf("MulF: Expected %d * %d = %d, but got %d", lhs, rhs, expected, mulF)
			}
		}

		// NegF
		{
			negF := g.NegF(g.GoldilocksField(lhs)).ToCanonicalUint64()
			expected := NegMod(lhs)
			if negF != expected {
				t.Fatalf("NegF: Expected Neg(%d) = %d, but got %d", lhs, expected, negF)
			}
		}

		// SquareF
		{
			sqrF := g.SquareF(g.GoldilocksField(lhs)).ToCanonicalUint64()
			expected := SquareMod(lhs)
			if sqrF != expected {
				t.Fatalf("SquareF: Expected (%d)^2 = %d, but got %d", lhs, expected, sqrF)
			}
		}

		// AddCanonicalUint64
		{
			lhs := lhs & (g.ORDER - 1) // make sure lhs is in the field
			addCanonical := g.AddCanonicalUint64(g.GoldilocksField(lhs), rhs).ToCanonicalUint64()
			expected := SumMod(lhs, rhs)
			if addCanonical != expected {
				t.Fatalf("AddCanonicalUint64: Expected %d + %d = %d, but got %d", lhs, rhs, expected, addCanonical)
			}

		}

		// Reduce128Bit
		{
			val := UInt128{Hi: lhs, Lo: rhs}
			reduced := g.Reduce128Bit(val)
			bigVal := new(big.Int).SetUint64(val.Hi)
			bigVal.Lsh(bigVal, 64)
			bigVal.Add(bigVal, new(big.Int).SetUint64(val.Lo))
			bigOrder := new(big.Int).SetUint64(g.ORDER)
			bigVal.Mod(bigVal, bigOrder)
			expected := bigVal.Uint64()
			if reduced.ToCanonicalUint64() != expected {
				t.Fatalf("Reduce128Bit: Expected reduction of %v to be %d, but got %d", val, expected, reduced.ToCanonicalUint64())
			}
		}

		// Reduce96Bit
		{
			val := UInt128{Hi: uint64(uint32(lhs)), Lo: rhs}
			reduced := g.Reduce96Bit(val)
			bigVal := new(big.Int).SetUint64(val.Hi)
			bigVal.Lsh(bigVal, 64)
			bigVal.Add(bigVal, new(big.Int).SetUint64(val.Lo))
			bigOrder := new(big.Int).SetUint64(g.ORDER)
			bigVal.Mod(bigVal, bigOrder)
			expected := bigVal.Uint64()
			if reduced.ToCanonicalUint64() != expected {
				t.Fatalf("Reduce96Bit: Expected reduction of %v to be %d, but got %d", val, expected, reduced.ToCanonicalUint64())
			}
		}

		{ // InverseOrZero
			val := g.GoldilocksField(lhs)
			inv := val.InverseOrZero()
			if val.IsZero() {
				if !inv.IsZero() {
					t.Fatalf("InverseOrZero: Expected inverse of 0 to be 0, but got %v", inv)
				}
			} else {
				prod := g.MulF(val, inv).ToCanonicalUint64()
				if prod != 1 {
					t.Fatalf("InverseOrZero: Expected %d * inv(%d) = 1, but got %d", lhs, lhs, prod)
				}
			}
		}

		{ // SqrtF
			val := g.GoldilocksField(lhs)
			val2 := g.SquareF(val)
			s := g.SqrtF(val2)
			if s == nil {
				t.Fatalf("SqrtF: Expected sqrt to exist for square of %d, but got nil", lhs)
			}
			if g.SquareF(*s).ToCanonicalUint64() != val2.ToCanonicalUint64() {
				t.Fatalf("SqrtF: Expected sqrt^2 to be %d, but got %d", val2.ToCanonicalUint64(), g.SquareF(*s).ToCanonicalUint64())
			}
		}
	})
}

// Quintic extension tests

func TestQuinticExtensionAddSubMulSquare(t *testing.T) {
	val1 := gFp5.Element{
		g.GoldilocksField(0x1234567890ABCDEF),
		g.GoldilocksField(0x0FEDCBA987654321),
		g.GoldilocksField(0x1122334455667788),
		g.GoldilocksField(0x8877665544332211),
		g.GoldilocksField(0xAABBCCDDEEFF0011),
	}
	val2 := gFp5.Element{
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
	}

	add := gFp5.Add(val1, val2)
	expectedAdd := [5]uint64{1311768471589866989, 1147797413325783839, 1234605620731475846, 9833440832084189711, 12302652064957136911}
	for i := 0; i < 5; i++ {
		if add[i].ToCanonicalUint64() != expectedAdd[i] {
			t.Fatalf("Addition: Expected limb %d to be %x, but got %x", i, expectedAdd[i], add[i])
		}
	}

	sub := gFp5.Sub(val1, val2)
	expectedSub := [5]uint64{1311768462999932401, 1147797404735849251, 1234605612141541258, 9833440823494255123, 12302652056367202323}
	for i := 0; i < 5; i++ {
		if sub[i].ToCanonicalUint64() != expectedSub[i] {
			t.Fatalf("Subtraction: Expected limb %d to be %x, but got %x", i, expectedSub[i], sub[i])
		}
	}

	mul := gFp5.Mul(val1, val2)
	expectedMul := [5]uint64{12801331769143413385, 14031114708135177824, 4192851210753422088, 14031114723597060086, 4193451712464626164}
	for i := 0; i < 5; i++ {
		if mul[i].ToCanonicalUint64() != expectedMul[i] {
			t.Fatalf("Multiplication: Expected limb %d to be %x, but got %x", i, expectedMul[i], mul[i])
		}
	}

	square := gFp5.Square(val1)
	expectedSquare := [5]uint64{
		2711468769317614959,
		15562737284369360677,
		48874032493986270,
		11211402278708723253,
		2864528669572451733,
	}
	for i := 0; i < 5; i++ {
		if square[i].ToCanonicalUint64() != expectedSquare[i] {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expectedSquare[i], square[i])
		}
	}
}

func TestQuinticExtensionAddSubMulSquareF(t *testing.T) {
	val1 := gFp5.FromPlonky2GoldilocksField([]g.GoldilocksField{
		g.GoldilocksField(0x1234567890ABCDEF),
		g.GoldilocksField(0x0FEDCBA987654321),
		g.GoldilocksField(0x1122334455667788),
		g.GoldilocksField(0x8877665544332211),
		g.GoldilocksField(0xAABBCCDDEEFF0011),
	})
	val2 := gFp5.FromPlonky2GoldilocksField([]g.GoldilocksField{
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
		g.GoldilocksField(0xFFFFFFFFFFFFFFFF),
	})

	add := gFp5.Add(val1, val2)
	expectedAdd := [5]uint64{1311768471589866989, 1147797413325783839, 1234605620731475846, 9833440832084189711, 12302652064957136911}
	for i := 0; i < 5; i++ {
		if add[i].ToCanonicalUint64() != expectedAdd[i] {
			t.Fatalf("Addition: Expected limb %d to be %x, but got %x", i, expectedAdd[i], add[i])
		}
	}

	sub := gFp5.Sub(val1, val2)
	expectedSub := [5]uint64{1311768462999932401, 1147797404735849251, 1234605612141541258, 9833440823494255123, 12302652056367202323}
	for i := 0; i < 5; i++ {
		if sub[i].ToCanonicalUint64() != expectedSub[i] {
			t.Fatalf("Subtraction: Expected limb %d to be %x, but got %x", i, expectedSub[i], sub[i])
		}
	}

	mul := gFp5.Mul(val1, val2)
	expectedMul := [5]uint64{12801331769143413385, 14031114708135177824, 4192851210753422088, 14031114723597060086, 4193451712464626164}
	for i := 0; i < 5; i++ {
		if mul[i].ToCanonicalUint64() != expectedMul[i] {
			t.Fatalf("Multiplication: Expected limb %d to be %x, but got %x", i, expectedMul[i], mul[i])
		}
	}

	square := gFp5.Square(val1)
	expectedSquare := [5]uint64{
		2711468769317614959,
		15562737284369360677,
		48874032493986270,
		11211402278708723253,
		2864528669572451733,
	}
	for i := 0; i < 5; i++ {
		if square[i].ToCanonicalUint64() != expectedSquare[i] {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expectedSquare[i], square[i])
		}
	}
}

func TestRepeatedFrobeniusgFp5(t *testing.T) {
	val := gFp5.Element{
		g.GoldilocksField(0x1234567890ABCDEF),
		g.GoldilocksField(0x0FEDCBA987654321),
		g.GoldilocksField(0x1122334455667788),
		g.GoldilocksField(0x8877665544332211),
		g.GoldilocksField(0xAABBCCDDEEFF0011),
	}

	res := gFp5.RepeatedFrobenius(val, 1)

	expected := [5]uint64{
		1311768467294899695,
		5234265561494296110,
		6204816484784411482,
		8858034429214283719,
		17855579289599571296,
	}
	for i := 0; i < 5; i++ {
		if res[i] != g.GoldilocksField(expected[i]) {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], res[i])
		}
	}
}

func TestTryInverse(t *testing.T) {
	val := gFp5.Element{
		g.GoldilocksField(0x1234567890ABCDEF),
		g.GoldilocksField(0x0FEDCBA987654321),
		g.GoldilocksField(0x1122334455667788),
		g.GoldilocksField(0x8877665544332211),
		g.GoldilocksField(0xAABBCCDDEEFF0011),
	}
	result := gFp5.InverseOrZero(val)

	// Expected values
	expected := [5]uint64{
		10760985268447604442,
		1770001646280707407,
		826117924202660585,
		45414427571889187,
		8256636258983026155,
	}

	for i, elem := range result {
		if elem.ToCanonicalUint64() != expected[i] {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], elem)
		}
	}
}

func TestQuinticExtSgn0(t *testing.T) {
	if !gFp5.Sgn0(gFp5.Element{
		g.GoldilocksField(7146494650688613286),
		g.GoldilocksField(2524706331227574337),
		g.GoldilocksField(2805008444831673606),
		g.GoldilocksField(10342159727506097401),
		g.GoldilocksField(5582307593199735986),
	}) {
		t.Fatalf("Expected sign to be true, but got false")
	}
}

func TestSqrtFunctions(t *testing.T) {
	x := gFp5.Element{
		g.GoldilocksField(17397692312497920520),
		g.GoldilocksField(4597259071399531684),
		g.GoldilocksField(15835726694542307225),
		g.GoldilocksField(16979717054676631815),
		g.GoldilocksField(12876043227925845432),
	}

	expectedCanonical := gFp5.Element{
		g.GoldilocksField(16260118390353633405),
		g.GoldilocksField(2204473665618140400),
		g.GoldilocksField(10421517006653550782),
		g.GoldilocksField(4618467884536173852),
		g.GoldilocksField(15556190572415033139),
	}

	expected := gFp5.Element{
		g.GoldilocksField(2186625679060950916),
		g.GoldilocksField(16242270403796443921),
		g.GoldilocksField(8025227062761033539),
		g.GoldilocksField(13828276184878410469),
		g.GoldilocksField(2890553496999551182),
	}

	result, exists := gFp5.CanonicalSqrt(x)
	if !exists {
		t.Fatalf("Expected canonical sqrt to exist, but it does not")
	}

	if !gFp5.Equals(result, expectedCanonical) {
		t.Fatalf("Expected canonical sqrt to be %v, but got %v", expectedCanonical, result)
	}

	result2, exists2 := gFp5.Sqrt(x)
	if !exists2 {
		t.Fatalf("Expected sqrt to exist, but it does not")
	}

	if !gFp5.Equals(result2, expected) {
		t.Fatalf("Expected sqrt to be %v, but got %v", expected, result2)
	}
}

func TestSqrtNonExistent(t *testing.T) {
	_, exists := gFp5.Sqrt(gFp5.Element{
		g.GoldilocksField(3558249639744866495),
		g.GoldilocksField(2615658757916804776),
		g.GoldilocksField(14375546700029059319),
		g.GoldilocksField(16160052538060569780),
		g.GoldilocksField(8366525948816396307),
	})
	if exists {
		t.Fatalf("Expected sqrt not to exist, but it does")
	}

	_, exists = gFp5.Sqrt(gFp5.FromUint64(263)) // B of the curve, not a square
	if exists {
		t.Fatalf("Expected sqrt of -1 not to exist, but it does")
	}
}

func TestLegendre(t *testing.T) {
	// Test zero
	zeroLegendre := gFp5.Legendre(gFp5.FP5_ZERO)
	if !zeroLegendre.IsZero() {
		t.Fatalf("Expected Legendre symbol of zero to be zero")
	}

	// Test non-squares
	for i := 0; i < 32; i++ {
		var x gFp5.Element
		for {
			attempt := gFp5.Sample()
			if _, exists := gFp5.Sqrt(attempt); !exists {
				x = attempt
				break
			}
		}
		legendreSym := gFp5.Legendre(x)

		if legendreSym.ToCanonicalUint64() != g.ORDER-1 {
			t.Fatalf("Expected Legendre symbol of non-square to be -1, but got %v", legendreSym)
		}
	}

	// Test squares
	for i := 0; i < 32; i++ {
		x := gFp5.Sample()
		square := gFp5.Square(x)
		legendreSym := gFp5.Legendre(square)

		if legendreSym.ToCanonicalUint64() != 1 {
			t.Fatalf("Expected Legendre symbol of square to be 1, but got %v", legendreSym)
		}
	}

	// Test zero again
	x := gFp5.FP5_ZERO
	square := gFp5.Mul(x, x)
	legendreSym := gFp5.Legendre(square)
	if !legendreSym.IsZero() {
		t.Fatalf("Expected Legendre symbol of zero to be zero")
	}
}
