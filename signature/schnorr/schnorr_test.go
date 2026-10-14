package signature

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks_plonky2"
)

func TestSchnorrSignAndVerify(t *testing.T) {
	sk := curve.SampleScalar() // Sample a secret key
	msg := make([]g.GoldilocksField, 244)
	for i := 0; i < 244; i++ {
		msg[i] = g.SampleF()
	}
	hashedMsg := p2.HashToQuinticExtension(msg)

	sig := SchnorrSignHashedMessage(hashedMsg, sk)
	pk := SchnorrPkFromSk(sk)
	if !IsSchnorrSignatureValid(pk, hashedMsg, sig) {
		t.Fatalf("Signature is invalid")
	}
}

func TestSchnorrMatchesGoldilocksCryptoKnownAnswers(t *testing.T) {
	// These vectors come from goldilocks-crypto v0.1.2, the independent Rust
	// reference used by elliottech/p3-lighter-circuits for witness fixtures.
	tests := []struct {
		index     byte
		publicKey string
		signature string
	}{
		{1, "04000000000000000000000000000000000000000000000000000000000000000000000000000000", "58d95fcb40e5f6d045329748301f36f844a1df56b43a6ef5f8922d3c6836c4fd2d35ae12eabe23319a432cc955f41817576e8d8e093d52f0f464d87832c5918a1d6dd2c388c93b82d9ca516d1341dc4e"},
		{2, "384c87fe1213197f4e1b457e9d43548fc00067c00ee5c1d872895e08ab103be54336d3d4b9d5bc8c", "76c92759ee9d1601fad7efdaf3398288c440a6d76f757f6d57990d7a65158c29516d57c2d403656f3738f8679f8a84e79fb4ace93f3f47a4d7e5e4e32e4540c96a33f9423ef539eb5e49d41e137e4d48"},
		{8, "c97b633e9b0098e743e5b9750cb8b3678cd2e9e3ca8d674b73ed76dc778701e5f743c0d67623f7a6", "63b0ac4aa52c5d937cb633fd48eb2eb430c6de871013f69ba56611e7abc44188adbf2f2d81a56b63f9065fce034c9a446b4507912c45ada08f29e97c943d81bc33d31de364c7f71e0d085aea4e8b9223"},
	}

	for _, test := range tests {
		var skBytes, nonceBytes, msgBytes [40]byte
		skBytes[0] = test.index
		nonceBytes[0] = test.index * 17
		nonceBytes[1] = test.index * 29
		msgBytes[0] = test.index
		msgBytes[8] = test.index * 3
		msgBytes[16] = test.index * 5

		sk := curve.ScalarElementFromLittleEndianBytes(skBytes[:])
		nonce := curve.ScalarElementFromLittleEndianBytes(nonceBytes[:])
		message, err := gFp5.FromCanonicalLittleEndianBytes(msgBytes[:])
		if err != nil {
			t.Fatalf("decode message: %v", err)
		}
		if got := hex.EncodeToString(SchnorrPkFromSk(sk).ToLittleEndianBytes()); got != test.publicKey {
			t.Fatalf("public key for vector %d = %s, want %s", test.index, got, test.publicKey)
		}
		if got := hex.EncodeToString(SchnorrSignHashedMessage2(message, sk, nonce).ToBytes()); got != test.signature {
			t.Fatalf("signature for vector %d = %s, want %s", test.index, got, test.signature)
		}
	}
}

func TestPreparedNonceSignsOnce(t *testing.T) {
	sk := curve.SampleScalar()
	hashedMsg := p2.HashToQuinticExtension([]g.GoldilocksField{1, 2, 3})
	nonce := PrepareNonce()
	alias := *nonce

	sig, err := SchnorrSignHashedMessagePrepared(hashedMsg, sk, nonce)
	if err != nil {
		t.Fatalf("prepared signing failed: %v", err)
	}
	if !IsSchnorrSignatureValid(SchnorrPkFromSk(sk), hashedMsg, sig) {
		t.Fatal("prepared signature is invalid")
	}

	if _, err := SchnorrSignHashedMessagePrepared(hashedMsg, sk, &alias); !errors.Is(err, ErrPreparedNonceConsumed) {
		t.Fatalf("copied nonce handle was reusable: %v", err)
	}
}

func TestPreparedNonceConcurrentConsumption(t *testing.T) {
	sk := curve.SampleScalar()
	hashedMsg := p2.HashToQuinticExtension([]g.GoldilocksField{4, 5, 6})
	nonce := PrepareNonce()

	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := SchnorrSignHashedMessagePrepared(hashedMsg, sk, nonce); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrPreparedNonceConsumed) {
				t.Errorf("unexpected signing error: %v", err)
			}
		}()
	}
	workers.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("prepared nonce succeeded %d times, want exactly 1", got)
	}
}

func TestNilPreparedNonce(t *testing.T) {
	_, err := SchnorrSignHashedMessagePrepared(gFp5.Element{}, curve.ONE, nil)
	if !errors.Is(err, ErrNilPreparedNonce) {
		t.Fatalf("nil nonce error = %v", err)
	}
}

func TestPreparedNonceCannotCrossProcessBoundary(t *testing.T) {
	nonce := PrepareNonce()
	nonce.state.processID = os.Getpid() + 1
	_, err := SchnorrSignHashedMessagePrepared(gFp5.Element{}, curve.ONE, nonce)
	if !errors.Is(err, ErrPreparedNonceForked) {
		t.Fatalf("cross-process nonce error = %v", err)
	}
}

func FuzzTestSchnorrSignAndVerify(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	f.Fuzz(func(t *testing.T, a, b []byte) {
		scalar := curve.FromNonCanonicalBigInt(new(big.Int).SetBytes(a))

		msgBytes := make([]g.GoldilocksField, 0)
		for i := 0; i < len(b); i += 8 {
			var chunk [8]byte
			copy(chunk[:], b[i:min(i+8, len(b))])
			msgBytes = append(msgBytes, g.GoldilocksField(binary.LittleEndian.Uint64(chunk[:])))
		}
		hashedMsg := p2.HashToQuinticExtension(msgBytes)

		sig := SchnorrSignHashedMessage(hashedMsg, scalar)
		pk := SchnorrPkFromSk(scalar)
		if !IsSchnorrSignatureValid(pk, hashedMsg, sig) {
			t.Fatalf("Signature is invalid")
		}
	})
}

func TestComparativeSchnorrSignAndVerify(t *testing.T) {
	sks := []curve.ECgFp5Scalar{
		curve.ECgFp5Scalar{
			12235002942052073545,
			1175977464658719998,
			8536934969147463310,
			6524687619313720391,
			2922072024880609112,
		},
		curve.ECgFp5Scalar{
			14609471659974493146,
			15558617123161593410,
			853367204868339037,
			17594253198278631904,
			368396584122947478,
		},
		curve.ECgFp5Scalar{
			846395111423676945, 1354180063821346280, 5751371120309175011, 4898038106472090654, 1076345918732914302,
		},
	}
	hashedMessages := []gFp5.Element{
		gFp5.Element{
			g.GoldilocksField(8398652514106806347),
			g.GoldilocksField(11069112711939986896),
			g.GoldilocksField(9732488227085561369),
			g.GoldilocksField(18076754337204438535),
			g.GoldilocksField(17155407358725346236),
		},
		gFp5.Element{
			g.GoldilocksField(14569490467507212064),
			g.GoldilocksField(2707063505563578676),
			g.GoldilocksField(7506743487465742335),
			g.GoldilocksField(12569771346154554175),
			g.GoldilocksField(4305083698940175790),
		},
		gFp5.Element{
			g.GoldilocksField(17529153479246803593),
			g.GoldilocksField(1743712677205511695),
			g.GoldilocksField(4834285972617397460),
			g.GoldilocksField(5486672566342530358),
			g.GoldilocksField(7254989001695704129),
		},
	}
	ks := []curve.ECgFp5Scalar{
		curve.ECgFp5Scalar{
			5245666847777449560,
			15178169970799106939,
			4403065012435293749,
			15306540389399388999,
			8935555081913173844,
		},
		curve.ECgFp5Scalar{
			1980123857560067020,
			10696795398834097509,
			3211831869376171671,
			6194822139276031840,
			3482023782412490864,
		},
		curve.ECgFp5Scalar{
			10299597990997564957, 8547298489021408803, 12250978550108858722, 5282281975236198197, 5328603554431393061,
		},
	}
	expectedSs := [][5]uint64{
		[5]uint64{
			6950590877883398434,
			17178336263794770543,
			11012823478139181320,
			16445091359523510936,
			5882925226143600273,
		},
		[5]uint64{
			15189311883262425203,
			16924634885527914505,
			11098200095411565797,
			11441434601417451505,
			2245797172600273048,
		},
		[5]uint64{
			1747989245728027396, 18083435619737379521, 18276259610811995786, 15101757397705334408, 5007814817019340642,
		},
	}
	expectedEs := [][5]uint64{
		[5]uint64{
			4544744459434870309,
			4180764085957612004,
			3024669018778978615,
			15433417688859446606,
			6775027260348937828,
		},
		[5]uint64{
			4905460437060282008,
			9275377852059362729,
			10383772785796962929,
			6858067464918579610,
			7078247668913970626,
		},
		[5]uint64{
			4911725746357568132, 12205663641120664338, 16433506899074513700, 14763562571101437023, 2547950465160283358,
		},
	}

	for i := 0; i < len(sks); i++ {
		sig := SchnorrSignHashedMessage2(hashedMessages[i], sks[i], ks[i])
		for j := 0; j < 5; j++ {
			if sig.S[j] != expectedSs[i][j] {
				t.Fatalf("sig.S[%d]: Expected %d, but got %d", j, expectedSs[i][j], sig.S[j])
			}
			if sig.E[j] != expectedEs[i][j] {
				t.Fatalf("sig.E[%d]: Expected %d, but got %d", j, expectedEs[i][j], sig.E[j])
			}
		}

		pk := SchnorrPkFromSk(sks[i])
		if !IsSchnorrSignatureValid(pk, hashedMessages[i], sig) {
			t.Fatalf("Signature is invalid")
		}
	}
}

func TestBytes(t *testing.T) {
	sk := curve.SampleScalar() // Sample a secret key
	msg := make([]g.GoldilocksField, 244)
	for i := 0; i < 244; i++ {
		msg[i] = g.SampleF()
	}
	hashedMsg := p2.HashToQuinticExtension(msg) // Random message

	sig := SchnorrSignHashedMessage(hashedMsg, sk)
	sig2, err := SigFromBytes(sig.ToBytes())
	if err != nil {
		t.Fatalf("Failed to convert signature bytes to Schnorr signature: %v", err)
	}
	if !sig2.S.Equals(sig.S) || !sig2.E.Equals(sig.E) {
		t.Fatalf("bytes do not match")
	}

	pk, err := gFp5.FromCanonicalLittleEndianBytes(SchnorrPkFromSk(sk).ToLittleEndianBytes())
	if err != nil {
		t.Fatalf("failed to convert public key bytes to field element: %v", err)
	}

	if err := Validate(pk.ToLittleEndianBytes(), hashedMsg.ToLittleEndianBytes(), sig2.ToBytes()); err != nil {
		t.Fatalf("Signature is invalid")
	}

	// Works with non-canonical inputs
	sig3 := sig2
	sig3.S = sig3.S.AddInner(curve.N)
	sig3.E = sig3.E.AddInner(curve.N)
	if err := Validate(pk.ToLittleEndianBytes(), hashedMsg.ToLittleEndianBytes(), sig3.ToBytes()); err != nil {
		t.Fatalf("Signature is invalid")
	}
}

func BenchmarkSignatureVerify(b *testing.B) {
	sk := curve.SampleScalar() // Sample a secret key
	msg := make([]g.GoldilocksField, 244)
	for i := 0; i < 244; i++ {
		msg[i] = g.SampleF()
	}
	hashedMsg := p2.HashToQuinticExtension(msg)
	hashedMsgBytes := hashedMsg.ToLittleEndianBytes()
	k := curve.SampleScalar()

	sig := SchnorrSignHashedMessage2(hashedMsg, sk, k).ToBytes()
	pk := SchnorrPkFromSk(sk).ToLittleEndianBytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Validate(pk, hashedMsgBytes, sig)
		if err != nil {
			b.Fatalf("Signature is invalid")
		}
	}
}

func BenchmarkSignatureSign(b *testing.B) {
	sk := curve.SampleScalar() // Sample a secret key
	msg := make([]g.GoldilocksField, 244)
	for i := 0; i < 244; i++ {
		msg[i] = g.SampleF()
	}
	hashedMsg := p2.HashToQuinticExtension(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SchnorrSignHashedMessage(hashedMsg, sk)
	}
}

func BenchmarkSignatureSignPreparedOnline(b *testing.B) {
	sk := curve.SampleScalar()
	msg := make([]g.GoldilocksField, 244)
	for i := range msg {
		msg[i] = g.SampleF()
	}
	hashedMsg := p2.HashToQuinticExtension(msg)
	k := curve.SampleScalar()
	r := curve.MulG(k).Encode()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = schnorrSignHashedMessageWithNonce(hashedMsg, sk, k, r)
	}
}

func BenchmarkPrepareNonce(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = PrepareNonce()
	}
}
