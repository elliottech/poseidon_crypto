package poseidon2

import (
	"errors"
	"hash"
	"math/big"

	f "github.com/consensys/gnark-crypto/field/goldilocks"
)

type Poseidon2 struct{}

func (p *Poseidon2) HashNToMNoPad(input []f.Element, numOutputs int) []f.Element {
	var perm [WIDTH]f.Element
	for i := 0; i < len(input); i += RATE {
		for j := 0; j < RATE && i+j < len(input); j++ {
			perm[j].Set(&input[i+j])
		}
		p.Permute(&perm)
	}

	outputs := make([]f.Element, 0, numOutputs)
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

func (p *Poseidon2) Permute(input *[WIDTH]f.Element) {
	p.externalLinearLayer(input)
	p.fullRounds(input, 0)
	p.partialRounds(input)
	p.fullRounds(input, ROUNDS_F_HALF)
}

func (p *Poseidon2) fullRounds(state *[WIDTH]f.Element, start int) {
	for r := start; r < start+ROUNDS_F_HALF; r++ {
		p.addRC(state, r)
		p.sbox(state)
		p.externalLinearLayer(state)
	}
}

func (p *Poseidon2) partialRounds(state *[WIDTH]f.Element) {
	for r := 0; r < ROUNDS_P; r++ {
		constant := f.NewElement(INTERNAL_CONSTANTS[r])
		constant.Add(&state[0], &constant)
		state[0] = p.sboxP(&constant)
		p.internalLinearLayer(state)
	}
}

func (p *Poseidon2) externalLinearLayer(state *[WIDTH]f.Element) {
	for i := 0; i < WIDTH; i += 4 {
		window := [4]f.Element{state[i], state[i+1], state[i+2], state[i+3]}
		p.applyMat4(&window)
		copy(state[i:i+4], window[:])
	}
	sums := [4]f.Element{}
	for k := 0; k < 4; k++ {
		for j := 0; j < WIDTH; j += 4 {
			sums[k].Add(&sums[k], &state[j+k])
		}
	}
	for i := 0; i < WIDTH; i++ {
		state[i].Add(&state[i], &sums[i%4])
	}
}

func (p *Poseidon2) internalLinearLayer(state *[WIDTH]f.Element) {
	sum := f.NewElement(0)
	for _, s := range state {
		sum.Add(&sum, &s)
	}
	for i := 0; i < WIDTH; i++ {
		constant := f.NewElement(MATRIX_DIAG_12_U64[i])
		constant.Mul(&state[i], &constant)
		state[i].Add(&constant, &sum)
	}
}

func (p *Poseidon2) addRC(state *[WIDTH]f.Element, externalRound int) {
	for i := 0; i < WIDTH; i++ {
		constant := f.NewElement(EXTERNAL_CONSTANTS[externalRound][i])
		state[i].Add(&state[i], &constant)
	}
}

func (p *Poseidon2) sbox(state *[WIDTH]f.Element) {
	for i := range state {
		state[i] = p.sboxP(&state[i])
	}
}

func (p *Poseidon2) sboxP(a *f.Element) f.Element {
	res := f.NewElement(0)
	return *res.Exp(*a, big.NewInt(D))
}

func (p *Poseidon2) applyMat4(x *[4]f.Element) {
	t01 := f.NewElement(0)
	t01.Add(&x[0], &x[1])

	t23 := f.NewElement(0)
	t23.Add(&x[2], &x[3])

	t0123 := f.NewElement(0)
	t0123.Add(&t01, &t23)

	t01123 := f.NewElement(0)
	t01123.Add(&t0123, &x[1])

	t01233 := f.NewElement(0)
	t01233.Add(&t0123, &x[3])

	x_0_sq := f.NewElement(0)
	x_0_sq.Double(&x[0])
	x[3].Add(&t01233, &x_0_sq)
	x_2_sq := f.NewElement(0)
	x_2_sq.Double(&x[2])
	x[1].Add(&t01123, &x_2_sq)
	x[0].Add(&t01123, &t01)
	x[2].Add(&t01233, &t23)
}

const BlockSize = f.Bytes // BlockSize size that poseidon consumes

func Poseidon2Bytes(input ...[]byte) []byte {
	inputElements := make([]f.Element, len(input))
	for i, ele := range input {
		num := new(big.Int).SetBytes(ele)
		if num.Cmp(f.Modulus()) >= 0 {
			panic("not support bytes bigger than modulus")
		}
		e := f.Element{0}
		e.SetBigInt(num)
		inputElements[i] = e
	}

	p := Poseidon2{}
	outputBytes := p.HashNToMNoPad(inputElements, 1)[0].Bytes()
	return outputBytes[:]
}

type digest struct {
	h    f.Element
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
	d.h = f.Element{0}
}

// Only receive byte slice less than f.Modulus()
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	num := new(big.Int).SetBytes(p)
	if num.Cmp(f.Modulus()) >= 0 {
		return 0, errors.New("not support bytes bigger than modulus")
	}
	d.data = append(d.data, p)
	return n, nil
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
	e := f.Element{0}
	e.SetBigInt(new(big.Int).SetBytes(Poseidon2Bytes(d.data...)))
	d.h = e
	d.data = nil // flush the data already hashed
	hash := d.h.Bytes()
	b = append(b, hash[:]...)
	return b
}
