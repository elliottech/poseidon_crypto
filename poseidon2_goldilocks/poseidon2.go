package poseidon2

import (
	"errors"
	"hash"
	"math/big"

	utils "github.com/elliottech/poseidon_crypto"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type Poseidon2 struct{}

func (p *Poseidon2) HashNToMNoPad(input []g.Element, numOutputs int) []g.Element {
	var perm [WIDTH]g.Element
	for i := 0; i < len(input); i += RATE {
		for j := 0; j < RATE && i+j < len(input); j++ {
			perm[j].Set(&input[i+j])
		}
		p.Permute(&perm)
	}

	outputs := make([]g.Element, 0, numOutputs)
	for {
		for i := 0; i < RATE; i++ {
			outputs = append(outputs, perm[i])
			if len(outputs) == numOutputs {
				return outputs
			}
		}
		p.Permute(&perm)
	}
}

func (p *Poseidon2) Permute(input *[WIDTH]g.Element) {
	p.externalLinearLayer(input)
	p.fullRounds(input, 0)
	p.partialRounds(input)
	p.fullRounds(input, ROUNDS_F_HALF)
}

func (p *Poseidon2) fullRounds(state *[WIDTH]g.Element, start int) {
	for r := start; r < start+ROUNDS_F_HALF; r++ {
		p.addRC(state, r)
		p.sbox(state)
		p.externalLinearLayer(state)
	}
}

func (p *Poseidon2) partialRounds(state *[WIDTH]g.Element) {
	for r := 0; r < ROUNDS_P; r++ {
		constant := g.FromUint64(INTERNAL_CONSTANTS[r])
		constant.Add(&state[0], &constant)
		state[0] = p.sboxP(&constant)
		p.internalLinearLayer(state)
	}
}

func (p *Poseidon2) externalLinearLayer(state *[WIDTH]g.Element) {
	for i := 0; i < WIDTH; i += 4 {
		window := [4]g.Element{state[i], state[i+1], state[i+2], state[i+3]}
		p.applyMat4(&window)
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

func (p *Poseidon2) internalLinearLayer(state *[WIDTH]g.Element) {
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

func (p *Poseidon2) addRC(state *[WIDTH]g.Element, externalRound int) {
	for i := 0; i < WIDTH; i++ {
		constant := g.FromUint64(EXTERNAL_CONSTANTS[externalRound][i])
		state[i].Add(&state[i], &constant)
	}
}

func (p *Poseidon2) sbox(state *[WIDTH]g.Element) {
	for i := range state {
		state[i] = p.sboxP(&state[i])
	}
}

func (p *Poseidon2) sboxP(a *g.Element) g.Element {
	res := g.FromUint64(0)
	return *res.Exp(*a, big.NewInt(D))
}

func (p *Poseidon2) applyMat4(x *[4]g.Element) {
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

func Poseidon2Bytes(input ...[]byte) []byte {
	inputElements := make([]g.Element, len(input))
	for i, ele := range input {
		num := utils.BigEndianBytesToUint64(ele)
		if num >= g.Modulus() {
			panic("not support bytes bigger than modulus")
		}

		inputElements[i] = g.FromUint64(num)
	}

	p := Poseidon2{}
	outputBytes := p.HashNToMNoPad(inputElements, 1)[0].Bytes()
	return outputBytes[:]
}

type digest struct {
	h    g.Element
	data [][]byte // data to hash
}

func NewPoseidon2() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
	d.h = g.Element{0}
}

// Only receive byte slice less than g.Modulus()
func (d *digest) Write(p []byte) (n int, err error) {
	x := utils.BigEndianBytesToUint64(p)

	if x >= g.Modulus() {
		return 0, errors.New("not support bytes bigger than modulus")
	}
	d.data = append(d.data, p)
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
	e := g.Element{0}
	e.SetBigInt(new(big.Int).SetBytes(Poseidon2Bytes(d.data...)))
	d.h = e
	d.data = nil // flush the data already hashed
	hash := d.h.Bytes()
	b = append(b, hash[:]...)
	return b
}
