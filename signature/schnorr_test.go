package signature

import (
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

func TestHashToQuinticExtension(t *testing.T) {
	result := HashToQuinticExtension([]g.Element{
		*new(g.Element).SetUint64(3451004116618606032),
		*new(g.Element).SetUint64(11263134342958518251),
		*new(g.Element).SetUint64(10957204882857370932),
		*new(g.Element).SetUint64(5369763041201481933),
		*new(g.Element).SetUint64(7695734348563036858),
		*new(g.Element).SetUint64(1393419330378128434),
		*new(g.Element).SetUint64(7387917082382606332),
	})
	expected := [5]uint64{
		17992684813643984528,
		5243896189906434327,
		7705560276311184368,
		2785244775876017560,
		14449776097783372302,
	}
	for i := 0; i < 5; i++ {
		if result[i] != expected[i] {
			t.Fatalf("Square: Expected limb %d to be %x, but got %x", i, expected[i], result[i])
		}
	}
}

func TestSchnorrSignAndVerify(t *testing.T) {
	sk := curve.SampleScalar(nil) // Sample a secret key
	msg := g.RandArray(244)       // Random message of 244 field elements (big)
	hashedMsg := HashToQuinticExtension(msg)

	sig := SchnorrSignHashedMessage(hashedMsg, sk)

	pk := SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(pk, hashedMsg, sig) {
		t.Fatalf("Signature is invalid")
	}
}
