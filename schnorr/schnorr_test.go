package schnorr

import (
	"testing"

	f "github.com/consensys/gnark-crypto/field/goldilocks"
	fUtils "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
)

func TestHashToQuinticExtension(t *testing.T) {
	inputs := []f.Element{
		*new(f.Element).SetUint64(3451004116618606032),
		*new(f.Element).SetUint64(11263134342958518251),
		*new(f.Element).SetUint64(10957204882857370932),
		*new(f.Element).SetUint64(5369763041201481933),
		*new(f.Element).SetUint64(7695734348563036858),
		*new(f.Element).SetUint64(1393419330378128434),
		*new(f.Element).SetUint64(7387917082382606332),
	}

	expected := [5]uint64{
		17992684813643984528,
		5243896189906434327,
		7705560276311184368,
		2785244775876017560,
		14449776097783372302,
	}

	result := HashToQuinticExtension(inputs)
	for i := 0; i < 5; i++ {
		if result[i].Uint64() != expected[i] {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expected[i], result[i].Uint64())
		}
	}
}

func TestSchnorrSignAndVerify(t *testing.T) {
	sk := sf.Sample()             // Sample a secret key
	msg := fUtils.FRandArray(244) // Random message of 244 field elements (big)
	hashedMsg := HashToQuinticExtension(msg)

	sig := SchnorrSignHashedMessage(hashedMsg, sk)

	pk := SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(pk, hashedMsg, sig) {
		t.Fatalf("Signature is invalid")
	}
}
