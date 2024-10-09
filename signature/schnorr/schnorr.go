package signature

import (
	"fmt"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
)

type Signature struct {
	S curve.ECgFp5Scalar
	E curve.ECgFp5Scalar
}

func (s Signature) DeepCopy() Signature {
	return Signature{
		S: s.S.DeepCopy(),
		E: s.E.DeepCopy(),
	}
}

// (s little endian) || (e little endian)
func (s Signature) ToBytes() []byte {
	sBytes := s.S.ToLittleEndianBytes()
	eBytes := s.E.ToLittleEndianBytes()
	res := make([]byte, 80)
	copy(res[:40], sBytes[:])
	copy(res[40:], eBytes[:])
	return res
}

func SigFromBytes(b []byte) (Signature, error) {
	if len(b) != 80 {
		return ZERO_SIG, fmt.Errorf("signature length should be 80 but is %d", len(b))
	}

	return Signature{
		S: *curve.ScalarElementFromLittleEndianBytes(b[:40]),
		E: *curve.ScalarElementFromLittleEndianBytes(b[40:]),
	}, nil
}

var ZERO_SIG = Signature{
	S: curve.ZERO,
	E: curve.ZERO,
}

var ONE_SK = curve.ONE

// Public key is actually an EC point (4 Fp5 elements), but it can be encoded as a single Fp5 element.
func SchnorrPkFromSk(sk curve.ECgFp5Scalar) gFp5.Element {
	res := curve.GENERATOR_ECgFp5Point.Mul(&sk)
	return res.Encode()
}

func SchnorrSignHashedMessage(hashedMsg gFp5.Element, sk curve.ECgFp5Scalar) Signature {
	// Sample random scalar `k` and compute `r = k * G`
	k := curve.SampleScalar(nil)
	r := curve.GENERATOR_ECgFp5Point.Mul(k)
	rEncoded := r.Encode()

	// Compute `e = H(r || H(m))`, which is a scalar point
	e := curve.FromGfp5(p2.HashToQuinticExtension([]g.Element{
		rEncoded[0], rEncoded[1], rEncoded[2], rEncoded[3], rEncoded[4],
		hashedMsg[0], hashedMsg[1], hashedMsg[2], hashedMsg[3], hashedMsg[4],
	}))
	return Signature{
		S: *k.Sub(e.Mul(&sk)),
		E: *e,
	}
}

func Validate(pubKey, hashedMsg, sig []byte) error {
	pk, err := gFp5.FromLittleEndianBytes(pubKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key bytes to field element: %w", err)
	}
	hashedMsgElem, err := gFp5.FromLittleEndianBytes(hashedMsg)
	if err != nil {
		return fmt.Errorf("failed to convert hashed message bytes to field element: %w", err)
	}
	s, err := SigFromBytes(sig)
	if err != nil {
		return fmt.Errorf("failed to convert signature bytes to Schnorr signature: %w", err)
	}

	if !isSchnorrSignatureValid(&pk, &hashedMsgElem, &s) {
		return fmt.Errorf("signature is invalid")
	}

	return nil
}

func isSchnorrSignatureValid(pubKey, hashedMsg *gFp5.Element, sig *Signature) bool {
	pubKeyWs, ok := curve.DecodeFp5AsWeierstrass(pubKey)
	if !ok {
		return false
	}

	rVEncoded := curve.MulAdd2(&curve.GENERATOR_WEIERSTRASS, &pubKeyWs, &sig.S, &sig.E).Encode() // r_v = s*G + e*pk

	return curve.FromGfp5(p2.HashToQuinticExtension([]g.Element{
		rVEncoded[0], rVEncoded[1], rVEncoded[2], rVEncoded[3], rVEncoded[4],
		hashedMsg[0], hashedMsg[1], hashedMsg[2], hashedMsg[3], hashedMsg[4],
	})).Equals(&sig.E) // e_v == e
}
