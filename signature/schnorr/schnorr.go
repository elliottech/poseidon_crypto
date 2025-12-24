// Package signature implements Schnorr signatures over the ECgFp5 elliptic curve.
//
// CURVE SECURITY PROPERTIES:
//
// ECgFp5 is an elliptic curve with PRIME ORDER (no cofactor), which provides:
// - No small subgroup attacks possible
// - No cofactor clearing needed
// - Canonical point encoding (prevents malleability)
// - All decoded points are valid group elements
//
// SIGNATURE SCHEME:
//
// This implementation uses:
// - Poseidon2 hash function for challenge generation
// - Pre-hashed messages (caller must hash messages to Fp5 elements)
// - Standard Schnorr signature equation: s = k - e·sk, where e = H(r || H(m))
//
// USAGE:
//
//	// Generate keypair
//	sk := curve.SampleScalar()
//	pk := SchnorrPkFromSk(sk)
//
//	// Hash message (caller's responsibility)
//	hashedMsg := p2.HashToQuinticExtension(messageFieldElements)
//
//	// Sign
//	sig := SchnorrSignHashedMessage(hashedMsg, sk)
//
//	// Verify
//	valid := IsSchnorrSignatureValid(pk, hashedMsg, sig)
//
// SECURITY CONSIDERATIONS:
//
// The lack of cofactor eliminates an entire class of attacks that affect
// other elliptic curves (e.g., Ed25519's cofactor of 8). No special validation
// is required beyond canonical encoding checks.
//
// Reference: https://github.com/pornin/ecgfp5
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

func (s Signature) IsCanonical() bool {
	return s.E.IsCanonical() && s.S.IsCanonical()
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
	copy(res[:40], sBytes)
	copy(res[40:], eBytes)
	return res
}

func SigFromBytes(b []byte) (Signature, error) {
	if len(b) != 80 {
		return ZERO_SIG, errors.New("invalid signature length, must be 80 bytes")
	}

	// ScalarElementFromLittleEndianBytes will check s and e are both in
	// canonical form
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

	// TODO: Something to be considered later (and require coordinate with Rust)
	//
	// It is possible that we only use 128 bits for e (instread of 320 bits)
	// That is, we can build e with the first 3 limbs of p2.HashToQuinticExtension(preImage)
	// This should improve the performance of schnorr signature.
	//
	// see
	//
	// - Hash Function Requirements for Schnorr Signatures
	//   Gregory Neven, Nigel P. Smart, and Bogdan Warinschi
	// - Short Schnorr Signatures Require a Hash Function with More Than Just Random-Prefix Resistance
	// 	 Daniel R. L. Brown

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

	// TODO: Something to be considered later (and require coordinate with Rust)
	//
	// It is possible that we only use 128 bits for e (instread of 320 bits)
	// That is, we can build e with the first 3 limbs of p2.HashToQuinticExtension(preImage)
	// This should improve the performance of schnorr signature.
	//
	// see
	//
	// - Hash Function Requirements for Schnorr Signatures
	//   Gregory Neven, Nigel P. Smart, and Bogdan Warinschi
	// - Short Schnorr Signatures Require a Hash Function with More Than Just Random-Prefix Resistance
	// 	 Daniel R. L. Brown

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

// IsSchnorrSignatureValid verifies a Schnorr signature over the ECgFp5 curve.
//
// SECURITY NOTE - No Subgroup Checks Required:
// Unlike many elliptic curve signature schemes, ECgFp5 has PRIME ORDER with no cofactor.
// This means all successfully decoded points are in the prime-order group and no cofactor clearing is needed
//
// The verification only needs to check:
// 1. Signature canonicality (S, E < group order)
// 2. Public key decodes successfully (canonical encoding)
// 3. Verification equation: s·G + e·pk = r, where e = H(r || H(m))
//
// Returns true if signature is valid, false otherwise.
func IsSchnorrSignatureValid(pubKey, hashedMsg gFp5.Element, sig Signature) bool {
	// Check signature canonicality (prevents malleability)
	if !sig.IsCanonical() {
		return false
	}

	// Decode public key (canonical decoding automatically ensures valid group element)
	// No subgroup check needed due to prime order!
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
