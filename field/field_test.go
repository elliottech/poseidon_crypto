package field

import (
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

func TestBytes(t *testing.T) {
	var e1 g.GoldilocksField
	e1.Sample()

	leBytes := e1.ToLittleEndianBytes()

	var e1ReconstructedLE g.GoldilocksField
	e1ReconstructedLE.FromCanonicalLittleEndianBytes(leBytes)
	if e1.Uint64() != e1ReconstructedLE.Uint64() {
		t.Fatalf("bytes do not match")
	}
}

func TestQuinticExtensionAddSubMulSquare(t *testing.T) {
	val1 := gFp5.Element{
		g.NewElement(0x1234567890ABCDEF),
		g.NewElement(0x0FEDCBA987654321),
		g.NewElement(0x1122334455667788),
		g.NewElement(0x8877665544332211),
		g.NewElement(0xAABBCCDDEEFF0011),
	}
	val2 := gFp5.Element{
		g.NewElement(0xFFFFFFFFFFFFFFFF),
		g.NewElement(0xFFFFFFFFFFFFFFFF),
		g.NewElement(0xFFFFFFFFFFFFFFFF),
		g.NewElement(0xFFFFFFFFFFFFFFFF),
		g.NewElement(0xFFFFFFFFFFFFFFFF),
	}

	add := gFp5.Add(val1, val2)
	expectedAdd := [5]uint64{1311768471589866989, 1147797413325783839, 1234605620731475846, 9833440832084189711, 12302652064957136911}
	for i := 0; i < 5; i++ {
		if add[i] != g.NewElement(expectedAdd[i]) {
			t.Fatalf("Addition: Expected limb %d to be %x, but got %x", i, expectedAdd[i], add[i])
		}
	}

	sub := gFp5.Sub(val1, val2)
	expectedSub := [5]uint64{1311768462999932401, 1147797404735849251, 1234605612141541258, 9833440823494255123, 12302652056367202323}
	for i := 0; i < 5; i++ {
		if sub[i] != g.NewElement(expectedSub[i]) {
			t.Fatalf("Subtraction: Expected limb %d to be %x, but got %x", i, expectedSub[i], sub[i])
		}
	}

	mul := gFp5.Mul(val1, val2)
	expectedMul := [5]uint64{12801331769143413385, 14031114708135177824, 4192851210753422088, 14031114723597060086, 4193451712464626164}
	for i := 0; i < 5; i++ {
		if mul[i] != g.NewElement(expectedMul[i]) {
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
		if square[i] != g.NewElement(expectedSquare[i]) {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expectedSquare[i], square[i])
		}
	}
}

func TestRepeatedFrobeniusgFp5(t *testing.T) {
	val := gFp5.Element{
		g.NewElement(0x1234567890ABCDEF),
		g.NewElement(0x0FEDCBA987654321),
		g.NewElement(0x1122334455667788),
		g.NewElement(0x8877665544332211),
		g.NewElement(0xAABBCCDDEEFF0011),
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
		if res[i] != g.NewElement(expected[i]) {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], res[i])
		}
	}
}

func TestTryInverse(t *testing.T) {
	val := gFp5.Element{
		g.NewElement(0x1234567890ABCDEF),
		g.NewElement(0x0FEDCBA987654321),
		g.NewElement(0x1122334455667788),
		g.NewElement(0x8877665544332211),
		g.NewElement(0xAABBCCDDEEFF0011),
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
		if elem.Uint64() != expected[i] {
			t.Fatalf("Assertion failed at index %d: expected %d, got %d", i, expected[i], elem)
		}
	}
}

func TestQuinticExtSgn0(t *testing.T) {
	if !gFp5.Sgn0(gFp5.Element{
		g.NewElement(7146494650688613286),
		g.NewElement(2524706331227574337),
		g.NewElement(2805008444831673606),
		g.NewElement(10342159727506097401),
		g.NewElement(5582307593199735986),
	}) {
		t.Fatalf("Expected sign to be true, but got false")
	}
}

func TestSqrtFunctions(t *testing.T) {
	x := gFp5.Element{
		g.NewElement(17397692312497920520),
		g.NewElement(4597259071399531684),
		g.NewElement(15835726694542307225),
		g.NewElement(16979717054676631815),
		g.NewElement(12876043227925845432),
	}

	expected := gFp5.Element{
		g.NewElement(16260118390353633405),
		g.NewElement(2204473665618140400),
		g.NewElement(10421517006653550782),
		g.NewElement(4618467884536173852),
		g.NewElement(15556190572415033139),
	}

	result, exists := gFp5.CanonicalSqrt(x)
	if !exists {
		t.Fatalf("Expected canonical sqrt to exist, but it does not")
	}

	if !gFp5.Equals(result, expected) {
		t.Fatalf("Expected canonical sqrt to be %v, but got %v", expected, result)
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
		g.NewElement(3558249639744866495),
		g.NewElement(2615658757916804776),
		g.NewElement(14375546700029059319),
		g.NewElement(16160052538060569780),
		g.NewElement(8366525948816396307),
	})
	if exists {
		t.Fatalf("Expected sqrt not to exist, but it does")
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

		negOne := g.NegOne()

		if negOne.Uint64() != legendreSym.Uint64() {
			t.Fatalf("Expected Legendre symbol of non-square to be -1, but got %v", legendreSym)
		}
	}

	// Test squares
	for i := 0; i < 32; i++ {
		x := gFp5.Sample()
		square := gFp5.Square(x)
		legendreSym := gFp5.Legendre(square)

		if !legendreSym.IsOne() {
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
