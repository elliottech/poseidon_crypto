package signature

import (
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
)

func TestHashToQuinticExtension(t *testing.T) {
	result := p2.HashToQuinticExtension([]g.Element{
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
	sk := curve.ECgFp5Scalar{

		12235002942052073545,
		1175977464658719998,
		8536934969147463310,
		6524687619313720391,
		2922072024880609112,
	}

	hashedMessage := gFp5.Element{
		8398652514106806347,
		11069112711939986896,
		9732488227085561369,
		18076754337204438535,
		17155407358725346236,
	}

	k := curve.ECgFp5Scalar{
		5245666847777449560,
		15178169970799106939,
		4403065012435293749,
		15306540389399388999,
		8935555081913173844,
	}

	sig := SchnorrSignHashedMessage2(hashedMessage, sk, k)

	expectedS := [5]uint64{
		6950590877883398434,
		17178336263794770543,
		11012823478139181320,
		16445091359523510936,
		5882925226143600273,
	}
	for i := 0; i < 5; i++ {
		if sig.S[i] != expectedS[i] {
			t.Fatalf("sig.S[%d]: Expected %d, but got %d", i, expectedS[i], sig.S[i])
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
		if sig.E[i] != expectedE[i] {
			t.Fatalf("sig.E[%d]: Expected %d, but got %d", i, expectedE[i], sig.E[i])
		}
	}

	pk := SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(&pk, &hashedMessage, sig) {
		t.Fatalf("Signature is invalid")
	}

	sk = curve.ECgFp5Scalar{

		14609471659974493146,
		15558617123161593410,
		853367204868339037,
		17594253198278631904,
		368396584122947478,
	}

	hashedMessage = gFp5.Element{
		14569490467507212064,
		2707063505563578676,
		7506743487465742335,
		12569771346154554175,
		4305083698940175790,
	}

	k = curve.ECgFp5Scalar{

		1980123857560067020,
		10696795398834097509,
		3211831869376171671,
		6194822139276031840,
		3482023782412490864,
	}

	sig = SchnorrSignHashedMessage2(hashedMessage, sk, k)

	expectedS = [5]uint64{
		15189311883262425203,
		16924634885527914505,
		11098200095411565797,
		11441434601417451505,
		2245797172600273048,
	}
	for i := 0; i < 5; i++ {
		if sig.S[i] != expectedS[i] {
			t.Fatalf("sig.S[%d]: Expected %d, but got %d", i, expectedS[i], sig.S[i])
		}
	}
	expectedE = [5]uint64{
		4905460437060282008,
		9275377852059362729,
		10383772785796962929,
		6858067464918579610,
		7078247668913970626,
	}
	for i := 0; i < 5; i++ {
		if sig.E[i] != expectedE[i] {
			t.Fatalf("sig.E[%d]: Expected %d, but got %d", i, expectedE[i], sig.E[i])
		}
	}

	pk = SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(&pk, &hashedMessage, sig) {
		t.Fatalf("Signature is invalid")
	}

	sk = curve.SampleScalar(nil) // Sample a secret key
	msg := g.RandArray(244)
	hashedMsg := p2.HashToQuinticExtension(msg)

	sig = SchnorrSignHashedMessage(hashedMsg, sk)

	pk = SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(&pk, &hashedMsg, sig) {
		t.Fatalf("Signature is invalid")
	}
}

func TestBytes(t *testing.T) {
	sk := curve.SampleScalar(nil) // Sample a secret key
	msg := g.RandArray(244)       // Random message of 244 field elements (big)
	hashedMsg := p2.HashToQuinticExtension(msg)

	sig := SchnorrSignHashedMessage(hashedMsg, sk)
	sig2, _ := SigFromBytes(sig.ToBytes())
	if !sig2.S.Equals(&sig.S) || !sig2.E.Equals(&sig.E) {
		t.Fatalf("bytes do not match")
	}

	pk := gFp5.FromCanonicalLittleEndianBytes(SchnorrPkFromSk(sk).ToLittleEndianBytes())

	if err := Validate(pk.ToLittleEndianBytes(), hashedMsg.ToLittleEndianBytes(), sig2.ToBytes()); err != nil {
		t.Fatalf("Signature is invalid")
	}
}
