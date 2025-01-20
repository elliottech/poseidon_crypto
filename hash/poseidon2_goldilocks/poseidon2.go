package poseidon2

import (
	"fmt"
	"hash"
	"math/big"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	link "github.com/elliottech/poseidon_crypto/link"
)

type HashOut [4]g.Element

type NumericalHashOut [4]uint64

func HashNToHashNoPad(input []g.Element) HashOut {
	in := make([]uint64, 0, len(input))
	for _, elem := range input {
		in = append(in, elem.Uint64())
	}

	return HashOutFromUint64Array(link.HashNToHashNoPad(in))
}

func (h HashOut) ToLittleEndianBytes() []byte {
	return g.ArrayToLittleEndianBytes([]g.Element{h[0], h[1], h[2], h[3]})
}

func (h HashOut) ToUint64Array() [4]uint64 {
	return [4]uint64{h[0].Uint64(), h[1].Uint64(), h[2].Uint64(), h[3].Uint64()}
}

func HashToQuinticExtension(m []g.Element) gFp5.Element {
	res := HashNToMNoPad(m, 5)
	return gFp5.Element(res[:])
}

func HashOutFromUint64Array(arr [4]uint64) HashOut {
	return HashOut{g.FromUint64(arr[0]), g.FromUint64(arr[1]), g.FromUint64(arr[2]), g.FromUint64(arr[3])}
}

func HashOutFromLittleEndianBytes(b []byte) (HashOut, error) {
	gArr, err := g.ArrayFromCanonicalLittleEndianBytes(b)
	if err != nil {
		return HashOut{}, fmt.Errorf("failed to convert bytes to field element. bytes: %v, error: %w", b, err)
	}

	return HashOut{gArr[0], gArr[1], gArr[2], gArr[3]}, nil
}

func EmptyHashOut() HashOut {
	return HashOut{g.Zero(), g.Zero(), g.Zero(), g.Zero()}
}

type Poseidon2 struct{}

func HashNoPad(input []g.Element) HashOut {
	return HashNToHashNoPadPureGo(input)
}

func HashNToOne(input []HashOut) HashOut {
	if len(input) == 1 {
		return input[0]
	}

	res := HashTwoToOne(input[0], input[1])
	for i := 2; i < len(input); i++ {
		res = HashTwoToOne(res, input[i])
	}

	return res
}

func HashTwoToOne(input1, input2 HashOut) HashOut {
	return HashNToHashNoPadPureGo([]g.Element{input1[0], input1[1], input1[2], input1[3], input2[0], input2[1], input2[2], input2[3]})
}

func HashNToHashNoPadPureGo(input []g.Element) HashOut {
	res := HashNToMNoPad(input, 4)
	return HashOut{res[0], res[1], res[2], res[3]}
}

func HashNToMNoPad(input []g.Element, numOutputs int) []g.Element {
	var perm [WIDTH]g.Element
	for i := 0; i < len(input); i += RATE {
		for j := 0; j < RATE && i+j < len(input); j++ {
			perm[j].Set(&input[i+j])
		}
		Permute(&perm)
	}

	outputs := make([]g.Element, 0, numOutputs)
	for {
		for i := 0; i < RATE; i++ {
			outputs = append(outputs, perm[i])
			if len(outputs) == numOutputs {
				return outputs
			}
		}
		Permute(&perm)
	}
}

func Permute(input *[WIDTH]g.Element) {
	externalLinearLayer(input)
	fullRounds(input, 0)
	partialRounds(input)
	fullRounds(input, ROUNDS_F_HALF)
}

func fullRounds(state *[WIDTH]g.Element, start int) {
	for r := start; r < start+ROUNDS_F_HALF; r++ {
		addRC(state, r)
		sbox(state)
		externalLinearLayer(state)
	}
}

func partialRounds(state *[WIDTH]g.Element) {
	for r := 0; r < ROUNDS_P; r++ {
		constant := g.FromUint64(INTERNAL_CONSTANTS[r])
		constant.Add(&state[0], &constant)
		state[0] = sboxP(&constant)
		internalLinearLayer(state)
	}
}

func externalLinearLayer(state *[WIDTH]g.Element) {
	for i := 0; i < WIDTH; i += 4 {
		window := [4]g.Element{state[i], state[i+1], state[i+2], state[i+3]}
		applyMat4(&window)
		copy(state[i:i+4], window[:])
	}
	sums := [4]g.Element{}
	for k := 0; k < 4; k++ {
		for j := 0; j < WIDTH; j += 4 {
			sums[k].Add(&sums[k], &state[j+k])
		}
	}
	for i := 0; i < WIDTH; i++ {
		state[i].Add(&state[i], &sums[i%4])
	}
}

func internalLinearLayer(state *[WIDTH]g.Element) {
	sum := g.FromUint64(0)
	for _, s := range state {
		sum.Add(&sum, &s)
	}
	for i := 0; i < WIDTH; i++ {
		constant := g.FromUint64(MATRIX_DIAG_12_U64[i])
		constant.Mul(&state[i], &constant)
		state[i].Add(&constant, &sum)
	}
}

func addRC(state *[WIDTH]g.Element, externalRound int) {
	for i := 0; i < WIDTH; i++ {
		constant := g.FromUint64(EXTERNAL_CONSTANTS[externalRound][i])
		state[i].Add(&state[i], &constant)
	}
}

func sbox(state *[WIDTH]g.Element) {
	for i := range state {
		state[i] = sboxP(&state[i])
	}
}

func sboxP(a *g.Element) g.Element {
	res := g.FromUint64(0)
	return *res.Exp(*a, big.NewInt(D))
}

func applyMat4(x *[4]g.Element) {
	t01 := g.FromUint64(0)
	t01.Add(&x[0], &x[1])

	t23 := g.FromUint64(0)
	t23.Add(&x[2], &x[3])

	t0123 := g.FromUint64(0)
	t0123.Add(&t01, &t23)

	t01123 := g.FromUint64(0)
	t01123.Add(&t0123, &x[1])

	t01233 := g.FromUint64(0)
	t01233.Add(&t0123, &x[3])

	x_0_sq := g.FromUint64(0)
	x_0_sq.Double(&x[0])
	x[3].Add(&t01233, &x_0_sq)
	x_2_sq := g.FromUint64(0)
	x_2_sq.Double(&x[2])
	x[1].Add(&t01123, &x_2_sq)
	x[0].Add(&t01123, &t01)
	x[2].Add(&t01233, &t23)
}

const BlockSize = g.Bytes // BlockSize size that poseidon consumes

type digest struct {
	data []g.Element
}

func NewPoseidon2() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
}

// Get element by element.
func (d *digest) Write(p []byte) (n int, err error) {
	gArr, err := g.ArrayFromCanonicalLittleEndianBytes(p)
	if err != nil {
		return 0, fmt.Errorf("failed to convert bytes to field element. bytes: %v, error: %w", p, err)
	}

	d.data = append(d.data, gArr...)
	return len(p), nil
}

func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	b = append(b, HashNToHashNoPadPureGo(d.data).ToLittleEndianBytes()...)
	d.data = nil
	return b
}
