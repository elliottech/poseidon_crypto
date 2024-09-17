package schnorr

import (
	config "github.com/consensys/gnark-crypto/field/generator/config"
	f "github.com/consensys/gnark-crypto/field/goldilocks"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
	curve "github.com/elliottech/poseidon_crypto/ecgfp5/curve"
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
	poseidon2 "github.com/elliottech/poseidon_crypto/poseidon2_goldilocks"
)

type SchnorrSig struct {
	S sf.ECgFp5Scalar
	E sf.ECgFp5Scalar
}

var ZERO_SIG = SchnorrSig{
	S: sf.ZERO,
	E: sf.ZERO,
}

var ONE_SK = sf.ONE

func HashToQuinticExtension(m []f.Element) config.Element {
	p2 := poseidon2.Poseidon2{}
	res := p2.HashNToMNoPad(m, 5)
	return fp5.FArrayToFp5([5]*f.Element{&res[0], &res[1], &res[2], &res[3], &res[4]})
}

func SchnorrSignFArray(m []f.Element, sk sf.ECgFp5Scalar) SchnorrSig {
	return SchnorrSignHashedMessage(
		HashToQuinticExtension(m), // Compute H(m)
		sk,
	)
}

func SchnorrSignHashedMessage(mHashed config.Element, sk sf.ECgFp5Scalar) SchnorrSig {
	return SchnorrSignHashedMessageWithRandomScalar(mHashed, sk, sf.Sample()) // Sample random scalar `k`
}

func SchnorrSignHashedMessageWithRandomScalar(mHashed config.Element, sk, k sf.ECgFp5Scalar) SchnorrSig {
	// Compute `r = k * G`
	r := curve.GENERATOR_ECgFp5Point.Mul(&k)
	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]f.Element, 5+5)
	for i, elem := range fp5.Fp5ToFArray(r.Encode()) {
		preImage[i] = *elem
	}
	for i, elem := range fp5.Fp5ToFArray(mHashed) {
		preImage[i+5] = *elem
	}

	e := sf.FromGfp5(HashToQuinticExtension(preImage))

	return SchnorrSig{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}
