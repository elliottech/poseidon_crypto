package ecgfp5

import (
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

func TestSerdes(t *testing.T) {
	scalar := ECgFp5Scalar{
		6950590877883398434,
		17178336263794770543,
		11012823478139181320,
		16445091359523510936,
		5882925226143600273,
	}

	leBytes := scalar.ToLittleEndianBytes()
	result := ScalarElementFromLittleEndianBytes(leBytes)

	if !scalar.Equals(result) {
		t.Fatalf("Expected %v, but got %v", scalar, result)
	}
}

func TestSplitTo4LimbBits(t *testing.T) {
	scalar := ECgFp5Scalar{
		6950590877883398434,
		17178336263794770543,
		11012823478139181320,
		16445091359523510936,
		5882925226143600273,
	}

	limbs := scalar.SplitTo4BitLimbs()

	expectedValues := map[int]uint8{
		0: 2, 1: 2, 2: 9, 3: 7, 4: 15, 5: 4, 6: 15, 7: 13,
		8: 3, 9: 9, 10: 5, 11: 7, 12: 5, 13: 7, 14: 0, 15: 6,
		16: 15, 17: 6, 18: 2, 19: 12, 20: 2, 21: 11, 22: 3, 23: 3,
		24: 1, 25: 13, 26: 5, 27: 11, 28: 5, 29: 6, 30: 14, 31: 14,
		32: 8, 33: 0, 34: 9, 35: 5, 36: 1, 37: 9, 38: 12, 39: 13,
		40: 10, 41: 9, 42: 8, 43: 6, 44: 5, 45: 13, 46: 8, 47: 9,
		48: 8, 49: 9, 50: 10, 51: 9, 52: 14, 53: 3, 54: 15, 55: 2,
		56: 6, 57: 7, 58: 3, 59: 11, 60: 8, 61: 3, 62: 4, 63: 14,
		64: 1, 65: 9, 66: 14, 67: 4, 68: 9, 69: 7, 70: 8, 71: 15,
		72: 2, 73: 5, 74: 9, 75: 5, 76: 4, 77: 10, 78: 1, 79: 5,
	}

	for i, expected := range expectedValues {
		if limbs[i] != expected {
			t.Fatalf("Expected limbs[%d] to be %d, but got %d", i, expected, limbs[i])
		}
	}
}

func TestAddInner(t *testing.T) {
	scalar1 := ECgFp5Scalar{
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	scalar2 := ECgFp5Scalar{
		0xFFFFFFFFFeeFFF,
		12312321312,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFacdFFFFF,
		0xbcaFFFFFFFFFFFFF,
	}

	result := scalar1.AddInner(scalar2)
	expectedValues := ECgFp5Scalar{
		0xfffffffffeeffe,
		0x2dddf1d20,
		0xffffffffffffffff,
		0xffffffacdfffff,
		0xbcafffffffffffff,
	}

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected %v but got %v at index %d", expectedValues[i], result[i], i)
		}
	}
}

func TestSubInner(t *testing.T) {
	scalar1 := ECgFp5Scalar{0, 0, 0, 0, 0}
	scalar2 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	result, carry := scalar1.SubInner(scalar2)
	expectedValues := ECgFp5Scalar{1, 0, 0, 0, 0}
	expectedCarry := uint64(18446744073709551615)

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, expectedValues[i], result[i])
		}
	}
	if carry != expectedCarry {
		t.Fatalf("Expected carry to be %d, but got %d", expectedCarry, carry)
	}
}

func TestAddScalar(t *testing.T) {
	scalar1 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
	scalar2 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	result := scalar1.AddInner(scalar2)
	expectedValues := ECgFp5Scalar{0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected %v but got %v at index %d", expectedValues[i], result[i], i)
		}
	}
}

func TestSub(t *testing.T) {
	scalar1 := ECgFp5Scalar{1, 2, 0, 0, 0}
	scalar2 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	result := scalar1.Sub(scalar2)
	expectedValues := ECgFp5Scalar{0xe80fd996948bffe3, 0xe8885c39d724a09e, 0x7fffffe6cfb80639, 0x7ffffff100000016, 0x7ffffffd80000007}

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, expectedValues[i], result[i])
		}
	}
}

func TestSelect(t *testing.T) {
	a0 := ECgFp5Scalar{1, 2, 3, 4, 5}
	a1 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFB}

	result := Select(uint64(0), a0, a1)
	for i := 0; i < 5; i++ {
		if result[i] != a0[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, a0[i], result[i])
		}
	}

	result = Select(uint64(0xFFFFFFFFFFFFFFFF), a0, a1)
	for i := 0; i < 5; i++ {
		if result[i] != a1[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, a1[i], result[i])
		}
	}
}

func TestMontyMul(t *testing.T) {
	scalar1 := ECgFp5Scalar{1, 2, 3, 4, 5}
	scalar2 := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	result := scalar1.MontyMul(scalar2)
	expectedValues := ECgFp5Scalar{10974894505036100890, 7458803775930281466, 744239893213209819, 3396127080529349464, 5979369289905897562}

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, expectedValues[i], result[i])
		}
	}
}

func TestMul(t *testing.T) {
	scalar := ECgFp5Scalar{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

	result := scalar.Mul(scalar)
	expectedValues := ECgFp5Scalar{471447996674510360, 3520142298321118626, 17240611161823899731, 5610669884293437850, 1193611606749909414}

	for i := 0; i < 5; i++ {
		if result[i] != expectedValues[i] {
			t.Fatalf("Expected result[%d] to be %d, but got %d", i, expectedValues[i], result[i])
		}
	}
}

func TestRecodeSigned(t *testing.T) {
	var ss [50]int32
	scalar := ECgFp5Scalar{
		g.ORDER - 1,
		g.ORDER - 2,
		g.ORDER - 3,
		0xFFFFFFFFFFFFFFFF,
		g.ORDER - 5,
	}

	scalar.RecodeSigned(ss[:], 5)

	expectedValues := map[int]int32{
		6:  -4,
		19: -2,
		25: -8,
		32: -1,
	}

	for i, elem := range ss {
		if expected, exists := expectedValues[i]; exists {
			if elem != expected {
				t.Fatalf("Expected ss[%d] to be %d, but got %d", i, expected, elem)
			}
		} else if elem != 0 {
			t.Fatalf("Expected ss[%d] to be 0, but got %d", i, elem)
		}
	}
}

func TestFromQuinticExtension(t *testing.T) {
	scalar := FromGfp5(gFp5.Element{g.NegOneF(), g.NegOneF(), g.NegOneF(), g.NegOneF(), g.NegOneF()})

	expectedValues := ECgFp5Scalar{
		3449841778703204414,
		3382000508875488967,
		212073444237,
		124554051540,
		17179869170,
	}

	for i := 0; i < 5; i++ {
		if scalar[i] != expectedValues[i] {
			t.Fatalf("Expected scalar[%d] to be %d, but got %d", i, expectedValues[i], scalar[i])
		}
	}
}
