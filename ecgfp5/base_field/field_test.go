package ecgfp5

import (
	"math/big"
	"testing"

	config "github.com/consensys/gnark-crypto/field/generator/config"
)

func TestQuinticExtensionAddSubMulSquare(t *testing.T) {
	val1 := config.Element{
		*new(big.Int).SetUint64(0x1234567890ABCDEF),
		*new(big.Int).SetUint64(0x0FEDCBA987654321),
		*new(big.Int).SetUint64(0x1122334455667788),
		*new(big.Int).SetUint64(0x8877665544332211),
		*new(big.Int).SetUint64(0xAABBCCDDEEFF0011),
	}
	val2 := config.Element{
		*new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
		*new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
		*new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
		*new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
		*new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
	}

	add := Fp5Add(val1, val2)
	expectedAdd := [5]uint64{1311768471589866989, 1147797413325783839, 1234605620731475846, 9833440832084189711, 12302652064957136911}
	for i := 0; i < 5; i++ {
		if add[i].Uint64() != expectedAdd[i] {
			t.Fatalf("Addition: Expected limb %d to be %x, but got %x", i, expectedAdd[i], add[i].Uint64())
		}
	}

	sub := Fp5Sub(val1, val2)
	expectedSub := [5]uint64{1311768462999932401, 1147797404735849251, 1234605612141541258, 9833440823494255123, 12302652056367202323}
	for i := 0; i < 5; i++ {
		if sub[i].Uint64() != expectedSub[i] {
			t.Fatalf("Subtraction: Expected limb %d to be %x, but got %x", i, expectedSub[i], sub[i].Uint64())
		}
	}

	mul := Fp5Mul(val1, val2)
	expectedMul := [5]uint64{12801331769143413385, 14031114708135177824, 4192851210753422088, 14031114723597060086, 4193451712464626164}
	for i := 0; i < 5; i++ {
		if mul[i].Uint64() != expectedMul[i] {
			t.Fatalf("Multiplication: Expected limb %d to be %x, but got %x", i, expectedMul[i], mul[i].Uint64())
		}
	}

	square := Fp5Square(val1)
	expectedSquare := [5]uint64{
		2711468769317614959,
		15562737284369360677,
		48874032493986270,
		11211402278708723253,
		2864528669572451733,
	}
	for i := 0; i < 5; i++ {
		if square[i].Uint64() != expectedSquare[i] {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expectedSquare[i], square[i].Uint64())
		}
	}
}

func TestRepeatedFrobeniusFp5(t *testing.T) {
	val := config.Element{
		*new(big.Int).SetUint64(0x1234567890ABCDEF),
		*new(big.Int).SetUint64(0x0FEDCBA987654321),
		*new(big.Int).SetUint64(0x1122334455667788),
		*new(big.Int).SetUint64(0x8877665544332211),
		*new(big.Int).SetUint64(0xAABBCCDDEEFF0011),
	}

	res := Fp5RepeatedFrobenius(val, 1)

	expected := [5]uint64{
		1311768467294899695,
		5234265561494296110,
		6204816484784411482,
		8858034429214283719,
		17855579289599571296,
	}
	for i := 0; i < 5; i++ {
		if res[i].Uint64() != expected[i] {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], res[i].Uint64())
		}
	}
}

func TestFp5TryInverse(t *testing.T) {
	val := config.Element{
		*new(big.Int).SetUint64(0x1234567890ABCDEF),
		*new(big.Int).SetUint64(0x0FEDCBA987654321),
		*new(big.Int).SetUint64(0x1122334455667788),
		*new(big.Int).SetUint64(0x8877665544332211),
		*new(big.Int).SetUint64(0xAABBCCDDEEFF0011),
	}
	result := Fp5InverseOrZero(val)

	// Expected values
	expected := [5]uint64{
		10760985268447604442,
		1770001646280707407,
		826117924202660585,
		45414427571889187,
		8256636258983026155,
	}

	for i, elem := range Fp5ToFArray(result) {
		if elem.Uint64() != expected[i] {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], elem.Uint64())
		}
	}
}

func TestQuinticExtSgn0(t *testing.T) {
	if !Fp5Sgn0(config.Element{
		*new(big.Int).SetUint64(7146494650688613286),
		*new(big.Int).SetUint64(2524706331227574337),
		*new(big.Int).SetUint64(2805008444831673606),
		*new(big.Int).SetUint64(10342159727506097401),
		*new(big.Int).SetUint64(5582307593199735986),
	}) {
		t.Fatalf("Expected sign to be true, but got false")
	}
}

func TestSqrtFunctions(t *testing.T) {
	x := config.Element{
		*new(big.Int).SetUint64(17397692312497920520),
		*new(big.Int).SetUint64(4597259071399531684),
		*new(big.Int).SetUint64(15835726694542307225),
		*new(big.Int).SetUint64(16979717054676631815),
		*new(big.Int).SetUint64(12876043227925845432),
	}

	expected := config.Element{
		*new(big.Int).SetUint64(16260118390353633405),
		*new(big.Int).SetUint64(2204473665618140400),
		*new(big.Int).SetUint64(10421517006653550782),
		*new(big.Int).SetUint64(4618467884536173852),
		*new(big.Int).SetUint64(15556190572415033139),
	}

	result, exists := Fp5CanonicalSqrt(x)
	if !exists {
		t.Fatalf("Expected canonical sqrt to exist, but it does not")
	}

	if !Fp5Equals(result, expected) {
		t.Fatalf("Expected canonical sqrt to be %v, but got %v", expected, result)
	}

	result2, exists2 := Fp5Sqrt(x)
	if !exists2 {
		t.Fatalf("Expected sqrt to exist, but it does not")
	}

	if !Fp5Equals(result2, expected) {
		t.Fatalf("Expected sqrt to be %v, but got %v", expected, result2)
	}
}
