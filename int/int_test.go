package int

import (
	"math"
	"math/big"
	"testing"
)

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

func FuzzTestAdd(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(1), uint64(1), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(0), uint64(1), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, a, b, c, d uint64) {
		i128a := UInt128{Hi: a, Lo: b}
		i128b := UInt128{Hi: c, Lo: d}
		result := AddUInt128(i128a, i128b)

		expected := new(big.Int).Add(new(big.Int).SetBits([]big.Word{big.Word(b), big.Word(a)}), new(big.Int).SetBits([]big.Word{big.Word(d), big.Word(c)}))
		expectedReduced := new(big.Int).And(expected, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))

		if !equalsBigInt(result, expectedReduced) {
			t.Errorf("Add(%d, %d): got %v, want %v",
				a, b, result.ToBigInt(), expected)
		}

		i128ab := AddUint64(a, b)
		expected = new(big.Int).Add(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
		if !equalsBigInt(i128ab, expected) {
			t.Errorf("AddUint64(%d, %d): got %v, want %v",
				a, b, i128ab.ToBigInt(), expected)
		}
	})
}

func FuzzTestAddUInt64(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(1), uint64(1))
	f.Add(uint64(math.MaxUint64), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, hi, lo uint64, b uint64) {
		i128 := UInt128{Hi: hi, Lo: lo}
		result := AddUint128AndUint64(i128, b)

		big128 := i128.ToBigInt()
		expected := new(big.Int).Add(big128, new(big.Int).SetUint64(b))

		if fitsInInt128(expected) {
			if !equalsBigInt(result, expected) {
				t.Errorf("AddInt64({%d, %d}, %d): got %v, want %v",
					hi, lo, b, result.ToBigInt(), expected)
			}
		} else {
			expectedReduced := new(big.Int).And(expected, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
			if !equalsBigInt(result, expectedReduced) {
				t.Errorf("AddInt64({%d, %d}, %d): got %v, want %v (reduced)",
					hi, lo, b, result.ToBigInt(), expectedReduced)
			}
		}
	})
}

func FuzzTestMulUInt64(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(1))
	f.Add(uint64(math.MaxUint64), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, a, b uint64) {
		result := MulUInt64(a, b)
		expected := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))

		if fitsInInt128(expected) {
			if !equalsBigInt(result, expected) {
				t.Errorf("MulInt64(%d, %d): got %v, want %v",
					a, b, result.ToBigInt(), expected)
			}
		}
	})
}

func FuzzTestMulUint128AndUint64(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(1), uint64(1))
	f.Add(uint64(math.MaxUint64), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, hi, lo uint64, b uint64) {
		i128 := UInt128{Hi: hi, Lo: lo}
		result := MulUint128AndUint64(i128, b)

		big128 := i128.ToBigInt()
		expected := new(big.Int).Mul(big128, new(big.Int).SetUint64(b))

		if fitsInInt128(expected) {
			if !equalsBigInt(result, expected) {
				t.Errorf("MulUint128AndUint64({%d, %d}, %d): got %v, want %v",
					hi, lo, b, result.ToBigInt(), expected)
			}
		} else {
			expectedReduced := new(big.Int).And(expected, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
			if !equalsBigInt(result, expectedReduced) {
				t.Errorf("MulUint128AndUint64({%d, %d}, %d): got %v, want %v (reduced)",
					hi, lo, b, result.ToBigInt(), expectedReduced)
			}
		}
	})
}

func FuzzTestSubUint128AndUint64(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(uint64(1), uint64(1), uint64(0))
	f.Add(uint64(0), uint64(1), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, hi, lo uint64, b uint64) {
		i128 := UInt128{Hi: hi, Lo: lo}
		result := SubUint128AndUint64(i128, b)

		expected := new(big.Int).Sub(new(big.Int).SetBits([]big.Word{big.Word(lo), big.Word(hi)}), new(big.Int).SetUint64(b))
		if expected.Sign() < 0 {
			expected.Add(expected, new(big.Int).Lsh(big.NewInt(1), 128))
		}

		if !equalsBigInt(result, expected) {
			t.Errorf("SubUint64({%d, %d}, %d): got %v, want %v",
				hi, lo, b, result.ToBigInt(), expected)
		}
	})
}

func equalsBigInt(a UInt128, b *big.Int) bool {
	return a.ToBigInt().Cmp(b) == 0
}

func fitsInInt128(b *big.Int) bool {
	max := new(big.Int).Lsh(big.NewInt(1), 127)
	max.Sub(max, big.NewInt(1))                  // (2^127) - 1
	min := new(big.Int).Lsh(big.NewInt(-1), 127) // -(2^127)

	return b.Cmp(min) >= 0 && b.Cmp(max) <= 0
}
