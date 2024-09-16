package ecgfp5

import (
	"fmt"
	"math/big"
	"testing"

	config "github.com/consensys/gnark-crypto/field/generator/config"
	f "github.com/consensys/gnark-crypto/field/goldilocks"
)

func TestQuadraticExtensionField(t *testing.T) {
	goldilocks, _ := config.NewFieldConfig("goldilocks", "Element", "0xFFFFFFFF00000001", false)
	quadratic := config.NewTower(goldilocks, 2, -1)

	a := int64(112213)
	b := int64(4234324)
	c := int64(234234)
	d := int64(234324)

	mul := quadratic.Mul(
		quadratic.FromInt64(a, b),
		quadratic.FromInt64(c, d),
	)

	aF := f.NewElement(uint64(a))
	bF := f.NewElement(uint64(b))
	cF := f.NewElement(uint64(c))
	dF := f.NewElement(uint64(d))

	// ac - bd
	ac := f.NewElement(0)
	ac.Mul(&aF, &cF)
	bd := f.NewElement(0)
	bd.Mul(&bF, &dF)
	ac_minus_bd := f.NewElement(0)
	ac_minus_bd.Sub(&ac, &bd)

	if mul[0].Uint64() != ac_minus_bd.Bits()[0] {
		panic(fmt.Errorf("ac_minus_bd %d, mul[1] %d", ac_minus_bd.Bits()[0], mul[1].Uint64()))
	}

	// ad + bc
	ad := f.NewElement(0)
	ad.Mul(&aF, &dF)
	bc := f.NewElement(0)
	bc.Mul(&bF, &cF)
	ad_plus_bc := f.NewElement(0)
	ad_plus_bc.Add(&ad, &bc)

	if mul[1].Uint64() != ad_plus_bc.Bits()[0] {
		panic(fmt.Errorf("ad_plus_bc %d, mul[0] %d", ad_plus_bc.Bits()[0], mul[0].Uint64()))
	}
}

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
