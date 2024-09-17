package schnorr

import (
	"math/big"
	"testing"

	config "github.com/consensys/gnark-crypto/field/generator/config"
	f "github.com/consensys/gnark-crypto/field/goldilocks"
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

func TestSchnorrSignHashedMessage(t *testing.T) {
	// sk, hashedMessage, k generated beforehand

	sk := sf.ECgFp5Scalar{
		Value: [5]big.Int{
			*new(big.Int).SetUint64(12235002942052073545),
			*new(big.Int).SetUint64(1175977464658719998),
			*new(big.Int).SetUint64(8536934969147463310),
			*new(big.Int).SetUint64(6524687619313720391),
			*new(big.Int).SetUint64(2922072024880609112),
		},
	}

	hashedMessage := config.Element{
		*new(big.Int).SetUint64(8398652514106806347),
		*new(big.Int).SetUint64(11069112711939986896),
		*new(big.Int).SetUint64(9732488227085561369),
		*new(big.Int).SetUint64(18076754337204438535),
		*new(big.Int).SetUint64(17155407358725346236),
	}

	k := sf.ECgFp5Scalar{
		Value: [5]big.Int{
			*new(big.Int).SetUint64(5245666847777449560),
			*new(big.Int).SetUint64(15178169970799106939),
			*new(big.Int).SetUint64(4403065012435293749),
			*new(big.Int).SetUint64(15306540389399388999),
			*new(big.Int).SetUint64(8935555081913173844),
		},
	}

	sig := SchnorrSignHashedMessageWithRandomScalar(hashedMessage, sk, k)

	expectedS := [5]uint64{
		6950590877883398434,
		17178336263794770543,
		11012823478139181320,
		16445091359523510936,
		5882925226143600273,
	}
	for i := 0; i < 5; i++ {
		if sig.S.Value[i].Uint64() != expectedS[i] {
			t.Fatalf("sig.S[%d]: Expected %d, but got %d", i, expectedS[i], sig.S.Value[i].Uint64())
		}
	}

	expectedE := [5]uint64{
		4544744459434870309,
		4180764085957612004,
		3024669018778978615,
		15433417688859446606,
		6775027260348937828,
	}
	for i := 0; i < 5; i++ {
		if sig.E.Value[i].Uint64() != expectedE[i] {
			t.Fatalf("sig.E[%d]: Expected %d, but got %d", i, expectedE[i], sig.E.Value[i].Uint64())
		}
	}
}
