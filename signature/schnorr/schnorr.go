package signature

import (
	"errors"
	"fmt"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks_plonky2"
)

type Signature struct {
	S curve.ECgFp5Scalar
	E curve.ECgFp5Scalar
}

var ZERO_SIG = Signature{
	S: curve.ZERO,
	E: curve.ZERO,
}

var ONE_SK = curve.ONE

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
		return ZERO_SIG, errors.New("invalid signature length, must be 80 bytes")
	}

	return Signature{
		S: curve.ScalarElementFromLittleEndianBytes(b[:40]),
		E: curve.ScalarElementFromLittleEndianBytes(b[40:]),
	}, nil
}

// Public key is actually an EC point (4 Fp5 elements), but it can be encoded as a single Fp5 element.
func SchnorrPkFromSk(sk curve.ECgFp5Scalar) gFp5.Element {
	return curve.GENERATOR_ECgFp5Point.Mul(sk).Encode()
}

func SchnorrSignHashedMessage(hashedMsg gFp5.Element, sk curve.ECgFp5Scalar) Signature {
	// Sample random scalar `k` and compute `r = k * G`
	k := curve.SampleScalar()
	r := curve.GENERATOR_ECgFp5Point.Mul(k).Encode()

	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.GoldilocksField, 5+5)
	copy(preImage[:5], r[:])
	copy(preImage[5:], hashedMsg[:])

	e := curve.FromGfp5(p2.HashToQuinticExtension(preImage))
	return Signature{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func SchnorrSignHashedMessage2(hashedMsg gFp5.Element, sk, k curve.ECgFp5Scalar) Signature {
	r := curve.GENERATOR_ECgFp5Point.Mul(k).Encode()
	// Compute `e = H(r || H(m))`, which is a scalar point
	preImage := make([]g.GoldilocksField, 5+5)
	copy(preImage[:5], r[:])
	copy(preImage[5:], hashedMsg[:])

	e := curve.FromGfp5(p2.HashToQuinticExtension(preImage))
	return Signature{
		S: k.Sub(e.Mul(sk)),
		E: e,
	}
}

func Validate(pubKey, hashedMsg, sig []byte) error {
	pk, err := gFp5.FromCanonicalLittleEndianBytes(pubKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key bytes to field element: %w", err)
	}
	hashedMsgElem, err := gFp5.FromCanonicalLittleEndianBytes(hashedMsg)
	if err != nil {
		return fmt.Errorf("failed to convert hashed message bytes to field element: %w", err)
	}
	s, err := SigFromBytes(sig)
	if err != nil {
		return fmt.Errorf("failed to convert signature bytes to Schnorr signature: %w", err)
	}

	valid := IsSchnorrSignatureValid(pk, hashedMsgElem, s)
	if !valid {
		return errors.New("signature is invalid")
	}

	return nil
}

func IsSchnorrSignatureValid(pubKey, hashedMsg gFp5.Element, sig Signature) bool {
	pubKeyWs, ok := curve.DecodeFp5AsWeierstrass(pubKey)
	if !ok {
		return false
	}

	rV := curve.MulAdd2(curve.GENERATOR_WEIERSTRASS, pubKeyWs, sig.S, sig.E).Encode() // r_v = s*G + e*pk

	preImage := make([]g.GoldilocksField, 5+5)
	copy(preImage[:5], rV[:])
	copy(preImage[5:], hashedMsg[:])
	eV := curve.FromGfp5(p2.HashToQuinticExtension(preImage))

	return eV.Equals(sig.E) // e_v == e
}
