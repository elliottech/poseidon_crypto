package ecgfp5

import "math/big"

func Uint128Add(elems ...uint64) *big.Int {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	res := new(big.Int)
	for _, elem := range elems {
		res.Add(res, new(big.Int).SetUint64(elem))
	}
	return new(big.Int).Mod(res, two128)
}

func Uint128Sub(minuend uint64, subtrahends ...uint64) *big.Int {
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
