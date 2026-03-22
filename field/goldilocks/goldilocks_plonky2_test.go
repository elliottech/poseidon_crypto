package goldilocks

import (
	"math/bits"
	rand "math/rand/v2"
	"testing"
)

func getRandomGoldilocks() GoldilocksField {
	return GoldilocksField(rand.Uint64())
}

// Tests for multiplication

func MulF_Test1(lhs, rhs GoldilocksField) GoldilocksField {
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

func MulF_Test2(lhs, rhs GoldilocksField) GoldilocksField {
	x_hi, x_lo := bits.Mul64(uint64(lhs), uint64(rhs))

	x_hi_hi := x_hi >> 32
	x_hi_lo := x_hi & EPSILON

	t0, borrow := bits.Sub64(x_lo, x_hi_hi, 0)
	if borrow == 1 {
		t0 -= EPSILON
	}
	t1 := x_hi_lo * EPSILON

	sum, over := bits.Add64(t0, t1, 0)
	t2 := sum + EPSILON*over
	return GoldilocksField(t2)
}

func MulF_Test3(lhs, rhs GoldilocksField) GoldilocksField {
	x_hi, x_lo := bits.Mul64(uint64(lhs), uint64(rhs))

	x_hi_hi := x_hi >> 32
	x_hi_lo := x_hi & EPSILON

	t0, borrow := bits.Sub64(x_lo, x_hi_hi, 0)
	t0 -= EPSILON * borrow
	t1 := x_hi_lo * EPSILON

	sum, over := bits.Add64(t0, t1, 0)
	t2 := sum + EPSILON*over
	return GoldilocksField(t2)
}

func BenchmarkMulF(b *testing.B) {
	len := 10000000
	x := make([]GoldilocksField, len)
	y := make([]GoldilocksField, len)
	for i := 0; i < len; i++ {
		x[i] = getRandomGoldilocks()
		y[i] = getRandomGoldilocks()
	}
	var res GoldilocksField
	id := 0
	b.Run("Original-MulF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = MulF_Test1(x[id], y[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("No-BranchHint-MulF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = MulF_Test2(x[id], y[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("Branchless-MulF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = MulF_Test3(x[id], y[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
	_ = res
}
