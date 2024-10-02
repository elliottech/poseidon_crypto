package signature

import (
	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	poseidon2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
)

type SchnorrSig struct {
	S curve.ECgFp5Scalar
	E curve.ECgFp5Scalar
}

// (s little endian) || (e little endian)
func (s SchnorrSig) ToBytes() [80]byte {
	sBytes := s.S.ToLittleEndianBytes()
	eBytes := s.E.ToLittleEndianBytes()
	var res [80]byte
	copy(res[:40], sBytes[:])
	copy(res[40:], eBytes[:])
	return res
}

func FromBytes(b [80]byte) SchnorrSig {
	var sBytes [40]byte
	var eBytes [40]byte
	copy(sBytes[:], b[:40])
	copy(eBytes[:], b[40:])
	return SchnorrSig{
		S: curve.FromLittleEndianBytes(sBytes),
		E: curve.FromLittleEndianBytes(eBytes),
	}
}

var ZERO_SIG = SchnorrSig{
	S: curve.ZERO,
	E: curve.ZERO,
}

var ONE_SK = curve.ONE

// Public key is actually an EC point (4 Fp5 elements), but it can be encoded as a single Fp5 element.
func SchnorrPkFromSk(sk curve.ECgFp5Scalar) gFp5.Element {
	return curve.GENERATOR_ECgFp5Point.Mul(&sk).Encode()
}

func HashToQuinticExtension(m []g.Element) gFp5.Element {
	p2 := poseidon2.Poseidon2{}
	res := p2.HashNToMNoPad(m, 5)
	return gFp5.FromBasefieldArray([5]g.Element{res[0], res[1], res[2], res[3], res[4]})
}

func SchnorrSignHashedMessage(hashedMsg gFp5.Element, sk curve.ECgFp5Scalar) SchnorrSig {
	// Sample random scalar `k` and compute `r = k * G`
	k := curve.Sample()
	r := curve.GENERATOR_ECgFp5Point.Mul(&k)

	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.Element, 5+5)
	for i, elem := range gFp5.ToBasefieldArray(r.Encode()) {
		preImage[i] = elem
	}
	for i, elem := range gFp5.ToBasefieldArray(hashedMsg) {
		preImage[i+5] = elem
	}

	e := curve.FromGfp5(HashToQuinticExtension(preImage))
	return SchnorrSig{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func SchnorrSignHashedMessage2(hashedMsg gFp5.Element, sk, k curve.ECgFp5Scalar) SchnorrSig {
	r := curve.GENERATOR_ECgFp5Point.Mul(&k)
	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.Element, 5+5)
	for i, elem := range gFp5.ToBasefieldArray(r.Encode()) {
		preImage[i] = elem
	}
	for i, elem := range gFp5.ToBasefieldArray(hashedMsg) {
		preImage[i+5] = elem
	}

	e := curve.FromGfp5(HashToQuinticExtension(preImage))
	return SchnorrSig{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func IsSchnorrSignatureValid(pubKey, hashedMsg gFp5.Element, sig SchnorrSig) bool {
	pubKeyWs, ok := curve.DecodeFp5AsWeierstrass(pubKey)
	if !ok {
		return false
	}

	rV := curve.MulAdd2(curve.GENERATOR_WEIERSTRASS, pubKeyWs, sig.S, sig.E) // r_v = s*G + e*pk

	preImage := make([]g.Element, 5+5)
	for i, elem := range gFp5.ToBasefieldArray(rV.Encode()) {
		preImage[i] = elem
	}
	for i, elem := range gFp5.ToBasefieldArray(hashedMsg) {
		preImage[i+5] = elem
	}
	eV := curve.FromGfp5(HashToQuinticExtension(preImage))

	return eV.Equals(sig.E) // e_v == e
}
