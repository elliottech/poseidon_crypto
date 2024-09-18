package schnorr

import (
	config "github.com/consensys/gnark-crypto/field/generator/config"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
	curve "github.com/elliottech/poseidon_crypto/ecgfp5/curve"
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
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

// Public key is actually an EC point (4 Fp5 elements), but it can be encoded as a single Fp5 element.
func SchnorrPkFromSk(sk sf.ECgFp5Scalar) config.Element {
	return curve.GENERATOR_ECgFp5Point.DeepCopy().Mul(&sk).Encode()
}

func HashToQuinticExtension(m []g.Element) config.Element {
	p2 := poseidon2.Poseidon2{}
	res := p2.HashNToMNoPad(m, 5)
	return fp5.FArrayToFp5([5]*g.Element{&res[0], &res[1], &res[2], &res[3], &res[4]})
}

func SchnorrSignHashedMessage(hashedMsg config.Element, sk sf.ECgFp5Scalar) SchnorrSig {
	// Sample random scalar `k` and compute `r = k * G`
	k := sf.Sample()
	r := curve.GENERATOR_ECgFp5Point.Mul(&k)

	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.Element, 5+5)
	for i, elem := range fp5.Fp5ToFArray(r.Encode()) {
		preImage[i] = *elem
	}
	for i, elem := range fp5.Fp5ToFArray(hashedMsg) {
		preImage[i+5] = *elem
	}

	e := sf.FromGfp5(HashToQuinticExtension(preImage))
	return SchnorrSig{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func SchnorrSignHashedMessage2(hashedMsg config.Element, sk, k sf.ECgFp5Scalar) SchnorrSig {
	r := curve.GENERATOR_ECgFp5Point.Mul(&k)
	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.Element, 5+5)
	for i, elem := range fp5.Fp5ToFArray(r.Encode()) {
		preImage[i] = *elem
	}
	for i, elem := range fp5.Fp5ToFArray(hashedMsg) {
		preImage[i+5] = *elem
	}

	e := sf.FromGfp5(HashToQuinticExtension(preImage))

	return SchnorrSig{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func IsSchnorrSignatureValid(pubKey, hashedMsg config.Element, sig SchnorrSig) bool {
	pubKeyWs, ok := curve.DecodeFp5AsWeierstrass(pubKey)
	if !ok {
		return false
	}

	rV := curve.MulAdd2(curve.GENERATOR_WEIERSTRASS, pubKeyWs, sig.S, sig.E) // r_v = s*G + e*pk

	preImage := make([]g.Element, 5+5)
	for i, elem := range fp5.Fp5ToFArray(rV.Encode()) {
		preImage[i] = *elem
	}
	for i, elem := range fp5.Fp5ToFArray(hashedMsg) {
		preImage[i+5] = *elem
	}
	eV := sf.FromGfp5(HashToQuinticExtension(preImage))

	return eV.Equals(sig.E) // e_v == e
}
