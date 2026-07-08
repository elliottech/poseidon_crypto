// Command fuzz_schnorr runs a standalone, deterministic differential fuzz test
// comparing the two Schnorr verification implementations:
//
//   - IsSchnorrSignatureValid  (old)
//   - IsSchnorrSignatureValid2 (new)
//
// For every generated case both functions must return the exact same result.
// Any divergence is a bug and aborts the run with the offending inputs.
//
// This is intentionally NOT a `go test` fuzz target: it is a plain loop whose
// iteration count is configurable (see run_fuzz_schnorr.sh). A rolling checksum
// is written to a file every CHECKPOINT iterations so long runs can be compared
// across machines/commits.
//
// Usage:
//
//	go run main.go -n 1000000 -seed 373731 -out checksums.txt
package main

import (
	"flag"
	"fmt"
	"hash"
	"hash/fnv"
	"math/rand"
	"os"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks_plonky2"
	schnorr "github.com/elliottech/poseidon_crypto/signature/schnorr"
)

// checkpoint is the number of iterations between checksum writes.
const checkpoint = 10000

func main() {
	n := flag.Uint64("n", 1000000, "number of fuzz iterations to run")
	seed := flag.Int64("seed", 1, "PRNG seed (deterministic runs for reproducible checksums)")
	out := flag.String("out", "schnorr_fuzz_checksums.txt", "file to append checksums to")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open output file %q: %v\n", *out, err)
		os.Exit(1)
	}
	defer f.Close()

	rng := rand.New(rand.NewSource(*seed))
	h := fnv.New64a()

	fmt.Printf("running %d iterations, seed=%d, checkpoint every %d, out=%s\n", *n, *seed, checkpoint, *out)

	for i := uint64(1); i <= *n; i++ {
		fuzzOnce(rng, h, i)

		if i%checkpoint == 0 {
			line := fmt.Sprintf("iter=%d seed=%d checksum=%016x\n", i, *seed, h.Sum64())
			if _, err := f.WriteString(line); err != nil {
				fmt.Fprintf(os.Stderr, "cannot write checksum: %v\n", err)
				os.Exit(1)
			}
			_ = f.Sync()
			fmt.Print(line)
		}
	}

	// Final checksum (covers the tail that did not land on a checkpoint boundary).
	final := fmt.Sprintf("final iter=%d seed=%d checksum=%016x\n", *n, *seed, h.Sum64())
	if _, err := f.WriteString(final); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write final checksum: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(final)
}

// fuzzOnce generates one random keypair/message/signature, checks that the old
// and new verifiers agree on the valid signature and on a tampered signature,
// and folds every input and result into the rolling checksum.
func fuzzOnce(rng *rand.Rand, h hash.Hash64, iter uint64) {
	sk := randomScalar(rng)
	pk := schnorr.SchnorrPkFromSk(sk)
	hashedMsg := randomHashedMessage(rng)

	sig := schnorr.SchnorrSignHashedMessage2(hashedMsg, sk, randomScalar(rng))

	// Valid signature: both verifiers must accept.
	compare(h, iter, "valid", pk, hashedMsg, sig)

	// Tampered signature: perturb E so verification must fail; both must reject.
	bad := sig
	bad.E = bad.E.AddInner(curve.ONE)
	compare(h, iter, "tampered-e", pk, hashedMsg, bad)

	// Tampered message: keep the signature, change the message; both must reject.
	badMsg := hashedMsg
	badMsg[0] = g.AddF(badMsg[0], g.OneF())
	compare(h, iter, "tampered-msg", pk, badMsg, sig)
}

// compare runs both verifiers and aborts if they disagree, then folds the
// inputs and the (agreed) result into the checksum.
func compare(h hash.Hash64, iter uint64, label string, pk, hashedMsg gFp5.Element, sig schnorr.Signature) {
	v1 := schnorr.IsSchnorrSignatureValid(pk, hashedMsg, sig)
	v2 := schnorr.IsSchnorrSignatureValid2(pk, hashedMsg, sig)

	if v1 != v2 {
		fmt.Fprintf(os.Stderr, "MISMATCH at iter=%d case=%q: IsSchnorrSignatureValid=%v IsSchnorrSignatureValid2=%v\n", iter, label, v1, v2)
		fmt.Fprintf(os.Stderr, "  pk=%v\n  hashedMsg=%v\n  sig.S=%v\n  sig.E=%v\n", pk, hashedMsg, sig.S, sig.E)
		os.Exit(2)
	}

	// Fold inputs + result so the checksum characterizes the whole run.
	h.Write(pk.ToLittleEndianBytes())
	h.Write(hashedMsg.ToLittleEndianBytes())
	h.Write(sig.ToBytes())
	if v1 {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}

// randomScalar draws a canonical scalar from the PRNG.
func randomScalar(rng *rand.Rand) curve.ECgFp5Scalar {
	b := make([]byte, 40)
	rng.Read(b)
	return curve.ScalarElementFromLittleEndianBytes(b)
}

// randomHashedMessage hashes a random-length slice of random field elements.
func randomHashedMessage(rng *rand.Rand) gFp5.Element {
	length := 1 + rng.Intn(256)
	msg := make([]g.GoldilocksField, length)
	for i := range msg {
		msg[i] = g.GoldilocksField(rng.Uint64())
	}
	return p2.HashToQuinticExtension(msg)
}
