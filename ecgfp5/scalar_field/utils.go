package ecgfp5

import "math/big"

func WrappingNegU64(v uint64) uint64 {
	return ^v + 1
}

func WrappingLhsU64(v uint64, shift uint32) uint64 {
	return v << (shift % 64)
}

func WrappingRhsU64(v uint64, shift uint32) uint64 {
	return v >> (shift % 64)
}

func uint128Add(elems ...uint64) *big.Int {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	res := new(big.Int)
	for _, elem := range elems {
		res.Add(res, new(big.Int).SetUint64(elem))
	}
	return new(big.Int).Mod(res, two128)
}

func uint128Sub(minuend uint64, subtrahends ...uint64) *big.Int {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	subtrahendsBig := new(big.Int).SetUint64(0)
	for _, subtrahend := range subtrahends {
		subtrahendsBig.Add(subtrahendsBig, new(big.Int).SetUint64(subtrahend))
	}
	res := new(big.Int).Sub(
		new(big.Int).SetUint64(minuend),
		subtrahendsBig,
	)
	return new(big.Int).Mod(res, two128)
}
