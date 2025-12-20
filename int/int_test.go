package int

import "testing"

func TestAddShiftedSmall161(t *testing.T) {
	scalar := Signed161{

		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	scalar.AddShiftedSmall([]uint64{1, 0xFFFFFFFFFFFFDDBB, 0xFFFFAACFFFFFDDBB}, 1231233)
	expectedValues := [3]uint64{
		1,
		18446744073709534070,
		18446556744415951735,
	}

	for i, elem := range scalar {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestAdd161(t *testing.T) {
	scalar := Signed161{

		0x10FFFFabcdFF1213,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	scalar.Add([]uint64{0x10FFFFabcdFF1213, 0xFFFFFFFFFFFFDDBB, 0xFFFFAACFFFFFDDBB})

	expectedValues := [3]uint64{
		2449957474057200678,
		18446744073709542842,
		18446650409062751675,
	}

	for i, elem := range scalar {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestAddShifted161(t *testing.T) {
	scalar1 := Signed161{

		0x10FFFFabcdFF1213,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
	}
	scalar2 := Signed161{
		0xabcdabcdabcdabcd,
		0xdef0def0def0def0,
		0x1234123412341234,
	}
	scalar1.AddShifted(&scalar2, 21423423)

	expectedValues := [3]uint64{
		1224978737028600339,
		18446744073709551615,
		18446744073709551615,
	}
	for i, elem := range scalar1 {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar1[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestRecodeSigned5_161(t *testing.T) {
	scalar1 := Signed161{
		0x1234567890abcdef,
		0xfedcba0987654321,
		0x0fedcba987654321,
	}

	expectedValues := [33]int32{
		15, 15, -13, -8, 11, 8, 2, 15, -10, 3, 13, 4, -15, -15, 13, 8, 5, -5, 2, -13, 1, -3, -13, -4, -1, 16, 8, 6, -12, -13, -2, -15, 0,
	}
	for i, elem := range RecodeSigned5(scalar1) {
		if elem != expectedValues[i] {
			t.Fatalf("Expected ss[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestSub161(t *testing.T) {
	scalar := Signed161{

		0x1010111112121313,
		0x10FFFFabcdFF1213,
		0xabcdef12345abcde,
	}

	scalar.Sub([]uint64{0xFFFFFFFFFFFFFFFF, 0x10FFFFabcdFF1213, 0xFFFFFFFFFFFFFFFF})

	expectedValues := [3]uint64{
		1157443869249508116,
		18446744073709551615,
		12379813812178173150,
	}

	for i, elem := range scalar {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestSubShiftedSmall161(t *testing.T) {
	scalar := Signed161{

		0x1010111112121313,
		0x10FFFFabcdFF1213,
		0xabcdef12345abcde,
	}

	scalar.SubShiftedSmall([]uint64{0xFFFFFFFFFFFFFFFF, 0x10FFFFabcdFF1213, 0xFFFFFFFFFFFFFFFF}, 5123142)

	expectedValues := [3]uint64{
		1157443869249508179,
		15060059935745936659,
		12379813812178173209,
	}

	for i, elem := range scalar {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestSubShifted161(t *testing.T) {
	scalar1 := Signed161{

		0x1010111112121313,
		0x10FFFFabcdFF1213,
		0xabcdef12345abcde,
	}

	scalar2 := Signed161{

		0xabcdabcdabcdabcd,
		0xdef0def0def0def0,
		0x1234123412341234,
	}

	scalar1.SubShifted(&scalar2, 12315523)

	expectedValues := [3]uint64{
		1157443869249508115,
		1224978737028600339,
		12379813812178173150,
	}

	for i, elem := range scalar1 {
		if elem != expectedValues[i] {
			t.Fatalf("Expected scalar1[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}

func TestAdd1_640(t *testing.T) {
	a := Signed640{

		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	a.Add1()

	expected := Signed640{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	for i, limb := range a {
		if limb != expected[i] {
			t.Fatalf("Test case 2: Expected limb %d to be %x, but got %x", i, expected[i], limb)
		}
	}
}

func TestIsNonnegative640(t *testing.T) {
	nonnegativeTest := Signed640{

		0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7FFFFFFFFFFFFFFF,
	}

	if !nonnegativeTest.IsNonnegative() {
		t.Fatalf("Expected nonnegativeTest to be nonnegative, but it is not")
	}
}

func TestLtUnsigned640(t *testing.T) {
	ltTest1 := Signed640{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	ltTest2 := Signed640{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	}

	if !ltTest1.LtUnsigned(&ltTest2) {
		t.Fatalf("Expected ltTest1 to be less than ltTest2, but it is not")
	}
	if ltTest2.LtUnsigned(&ltTest1) {
		t.Fatalf("Expected ltTest2 to be greater than ltTest1, but it is not")
	}
}

func TestBitlength(t *testing.T) {
	bitlengthTest := Signed640{

		0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8000000000000000,
	}

	bitlength := bitlengthTest.Bitlength()

	expectedBitlength := int32(639)
	if bitlength != expectedBitlength {
		t.Fatalf("Expected bit length to be %d, but got %d", expectedBitlength, bitlength)
	}

	bitlengthTest = Signed640{

		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
		0xFFFFFFFFFFFFFaFF,
	}

	bitlength = bitlengthTest.Bitlength()

	expectedBitlength = int32(587)
	if bitlength != expectedBitlength {
		t.Fatalf("Expected bit length to be %d, but got %d", expectedBitlength, bitlength)
	}
}

func TestAdd640(t *testing.T) {
	a := Signed640{

		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFaaaF,
	}

	b := Signed640{

		0xFFFFFabcdFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	a.AddShifted(&b, 5543242)

	expected := Signed640{

		18446744073709551615,
		0,
		18446744073709551615,
		0,
		18446744073709551615,
		0,
		18446744073709551615,
		0,
		18446744073709551615,
		18446744073709529775,
	}

	for i, limb := range a {
		if limb != expected[i] {
			t.Fatalf("Expected limb %d to be %x, but got %x", i, expected[i], limb)
		}
	}

	a.AddShifted(&b, 63)

	expected = Signed640{

		9223372036854775807,
		18446741180780642304,
		18446744073709551614,
		0,
		9223372004938743807,
		9223372036854775809,
		18446744073709551614,
		18446744041793519616,
		18446744073709551614,
		18446744041793497775,
	}

	for i, limb := range a {
		if limb != expected[i] {
			t.Fatalf("Expected limb %d to be %x, but got %x", i, expected[i], limb)
		}
	}

	a.AddShifted(&b, 0)

	expected = Signed640{

		9223366250996957182,
		18446741180780642304,
		18446744073709551614,
		18446744009877487616,
		9223372004938743807,
		9223372036854775808,
		18446744009877487614,
		18446744041793519616,
		18446744009877487614,
		18446744041793497775,
	}

	for i, limb := range a {
		if limb != expected[i] {
			t.Fatalf("Expected limb %d to be %x, but got %x", i, expected[i], limb)
		}
	}
}

func TestSubShifted640(t *testing.T) {
	// Create two Signed640 instances for the test
	a := Signed640{

		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFaaaF,
	}

	b := Signed640{

		0xFFFFFabcdFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFF1234FFFFF,
		0xFFFFFFFFFFFFFFFF,
	}

	a.SubShifted(&b, 313)
	expectedLargeShift := Signed640{

		18446744073709551615,
		0,
		18446744073709551615,
		0,
		18446744073709551615,
		144115188075855872,
		18446744073709551615,
		498688000,
		18446744073709551615,
		498666159,
	}

	for i, limb := range a {
		if limb != expectedLargeShift[i] {
			t.Fatalf("sub_shifted (large shift): Expected limb %d to be %x, but got %x", i, expectedLargeShift[i], limb)
		}
	}

	a.SubShifted(&b, 63)
	expectedSmallShift := Signed640{

		9223372036854775807,
		2892928909313,
		18446744073709551615,
		0,
		9223372068770807807,
		9367487224930631680,
		18446744073709551615,
		32414720000,
		18446744073709551615,
		32414698159,
	}

	for i, limb := range a {
		if limb != expectedSmallShift[i] {
			t.Fatalf("sub_shifted (small shift): Expected limb %d to be %x, but got %x", i, expectedSmallShift[i], limb)
		}
	}

	a.SubShifted(&b, 0)
	expectedZeroShift := Signed640{

		9223377822712594432,
		2892928909313,
		18446744073709551615,
		63832064000,
		9223372068770807806,
		9367487224930631681,
		63832063999,
		32414720001,
		63832063999,
		32414698160,
	}

	for i, limb := range a {
		if limb != expectedZeroShift[i] {
			t.Fatalf("sub: Expected limb %d to be %x, but got %x", i, expectedZeroShift[i], limb)
		}
	}
}
