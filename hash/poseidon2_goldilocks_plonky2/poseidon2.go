package poseidon2_plonky2

import (
	"encoding/binary"
	"fmt"
	"hash"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	. "github.com/elliottech/poseidon_crypto/int"
)

type HashOut [4]g.GoldilocksField

func EmptyHashOut() HashOut {
	return HashOut{g.ZeroF(), g.ZeroF(), g.ZeroF(), g.ZeroF()}
}

func (h HashOut) ToLittleEndianBytes() []byte {
	res := make([]byte, 0, 4*g.Bytes)
	for _, elem := range h {
		res = append(res, g.ToLittleEndianBytesF(elem)...)
	}
	return res
}

func (h HashOut) ToLittleEndianBytesArray() [32]byte {
	var res [32]byte
	binary.LittleEndian.PutUint64(res[0:8], h[0].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(res[8:16], h[1].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(res[16:24], h[2].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(res[24:], h[3].ToCanonicalUint64())
	return res
}

func HashOutFromLittleEndianBytes(b []byte) (HashOut, error) {
	if len(b) != 4*g.Bytes {
		return HashOut{}, fmt.Errorf("input bytes len should be 32 but is %d", len(b))
	}
	var res HashOut
	for i := 0; i < 4; i++ {
		res[i] = g.FromCanonicalLittleEndianBytesF(b[i*g.Bytes : (i+1)*g.Bytes])
	}

	return res, nil
}

func HashOutFromLittleEndianBytesArray(b [32]byte) (HashOut, error) {
	var res HashOut
	res[0] = g.FromCanonicalLittleEndianBytesF(b[0:8])
	res[1] = g.FromCanonicalLittleEndianBytesF(b[8:16])
	res[2] = g.FromCanonicalLittleEndianBytesF(b[16:24])
	res[3] = g.FromCanonicalLittleEndianBytesF(b[24:32])
	return res, nil
}

func (h HashOut) ToUint64Array() [4]uint64 {
	return [4]uint64{uint64(h[0]), uint64(h[1]), uint64(h[2]), uint64(h[3])}
}

func HashOutFromUint64Array(arr [4]uint64) HashOut {
	return HashOut{g.GoldilocksField(arr[0]), g.GoldilocksField(arr[1]), g.GoldilocksField(arr[2]), g.GoldilocksField(arr[3])}
}

func HashToQuinticExtension(m []g.GoldilocksField) gFp5.Element {
	return gFp5.FromPlonky2GoldilocksField(HashNToMNoPad(m, 5))
}

type Poseidon2 struct{}

func HashNoPad(input []g.GoldilocksField) HashOut {
	return HashNToHashNoPad(input)
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
	return HashNToHashNoPad([]g.GoldilocksField{input1[0], input1[1], input1[2], input1[3], input2[0], input2[1], input2[2], input2[3]})
}

func HashNToHashNoPad(input []g.GoldilocksField) HashOut {
	res := HashNToMNoPad(input, 4)
	return HashOut{res[0], res[1], res[2], res[3]}
}

func HashNToMNoPad(input []g.GoldilocksField, numOutputs int) []g.GoldilocksField {
	var perm [WIDTH]g.GoldilocksField
	for i := 0; i < len(input); i += RATE {
		for j := 0; j < RATE && i+j < len(input); j++ {
			perm[j] = input[i+j]
		}
		Permute(&perm)
	}

	outputs := make([]g.GoldilocksField, 0, numOutputs)
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

func HashNToMNoPadBytes(input []byte, numOutputs int) []g.GoldilocksField {
	if len(input)%g.Bytes != 0 {
		panic("input length should be multiple of 8")
	}

	inputLen := len(input) / g.Bytes

	var perm [WIDTH]g.GoldilocksField
	for i := 0; i < inputLen; i += RATE {
		for j := 0; j < RATE && i+j < inputLen; j++ {
			index := (i + j) * g.Bytes
			perm[j] = g.FromCanonicalLittleEndianBytesF(input[index : index+g.Bytes])
		}
		Permute(&perm)
	}

	outputs := make([]g.GoldilocksField, 0, numOutputs)
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

// Output size is assumed to be 32 bytes.
// Input sizes can be only 0 or 32 bytes.
func HashPairBytes(left, right []byte) []byte {
	if !((len(left) == 0 || len(left) == 32) && (len(right) == 0 || len(right) == 32)) {
		panic("input lengths should be 32 or 0")
	}

	var perm [WIDTH]g.GoldilocksField

	if len(left) == 32 {
		for j := 0; j < 4; j++ {
			index := j * g.Bytes
			perm[j] = g.FromCanonicalLittleEndianBytesF(left[index : index+g.Bytes])
		}
	}
	if len(right) == 32 {
		for j := 0; j < 4; j++ {
			index := j * g.Bytes
			perm[j+4] = g.FromCanonicalLittleEndianBytesF(right[index : index+g.Bytes])
		}
	}

	Permute(&perm)

	output := make([]byte, 32)

	binary.LittleEndian.PutUint64(output[0:8], perm[0].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[8:16], perm[1].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[16:24], perm[2].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[24:], perm[3].ToCanonicalUint64())

	return output
}

func HashPair(left, right [32]byte) [32]byte {
	var perm [WIDTH]g.GoldilocksField

	perm[0] = g.GoldilocksField(binary.LittleEndian.Uint64(left[0:8]))
	perm[1] = g.GoldilocksField(binary.LittleEndian.Uint64(left[8:16]))
	perm[2] = g.GoldilocksField(binary.LittleEndian.Uint64(left[16:24]))
	perm[3] = g.GoldilocksField(binary.LittleEndian.Uint64(left[24:]))

	perm[4] = g.GoldilocksField(binary.LittleEndian.Uint64(right[0:8]))
	perm[5] = g.GoldilocksField(binary.LittleEndian.Uint64(right[8:16]))
	perm[6] = g.GoldilocksField(binary.LittleEndian.Uint64(right[16:24]))
	perm[7] = g.GoldilocksField(binary.LittleEndian.Uint64(right[24:]))

	Permute(&perm)

	var output [32]byte

	binary.LittleEndian.PutUint64(output[0:8], perm[0].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[8:16], perm[1].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[16:24], perm[2].ToCanonicalUint64())
	binary.LittleEndian.PutUint64(output[24:], perm[3].ToCanonicalUint64())

	return output
}

func Permute(input *[WIDTH]g.GoldilocksField) {
	externalLinearLayer(input)
	fullRounds(input, 0)
	partialRounds(input)
	fullRounds(input, ROUNDS_F_HALF)
}

func fullRounds(state *[WIDTH]g.GoldilocksField, start int) {
	for r := start; r < start+ROUNDS_F_HALF; r++ {
		addRC(state, r)
		sbox(state)
		externalLinearLayer(state)
	}
}

func partialRounds(state *[WIDTH]g.GoldilocksField) {
	for r := 0; r < ROUNDS_P; r++ {
		// addRCI
		state[0] = g.AddCanonicalUint64(state[0], uint64(INTERNAL_CONSTANTS[r]))
		// Manual-inlining for sboxP
		p := state[0]
		p2 := g.SquareF(p)       // x^2
		p4 := g.SquareF(p2)      // x^4
		p = g.MulF(p, p2)        // x^3
		state[0] = g.MulF(p, p4) // x^7
		// Internal Linear Layer - inlined
		v0 := g.AsUInt128(state[0])
		v1 := g.AsUInt128(state[1])
		v2 := g.AsUInt128(state[2])
		v3 := g.AsUInt128(state[3])
		v4 := g.AsUInt128(state[4])
		v5 := g.AsUInt128(state[5])
		v6 := g.AsUInt128(state[6])
		v7 := g.AsUInt128(state[7])
		v8 := g.AsUInt128(state[8])
		v9 := g.AsUInt128(state[9])
		v10 := g.AsUInt128(state[10])
		v11 := g.AsUInt128(state[11])

		// chunk 0
		t01 := AddUInt128(v0, v1)
		t23 := AddUInt128(v2, v3)
		t := AddUInt128(t01, t23)
		n0 := AddUInt128(AddUInt128(t, t01), v1)
		n1 := AddUInt128(AddUInt128(t, v1), AddUInt128(v2, v2))
		n2 := AddUInt128(AddUInt128(t, t23), v3)
		n3 := AddUInt128(AddUInt128(t, v3), AddUInt128(v0, v0))

		// chunk 1
		t01 = AddUInt128(v4, v5)
		t23 = AddUInt128(v6, v7)
		t = AddUInt128(t01, t23)
		n4 := AddUInt128(AddUInt128(t, t01), v5)
		n5 := AddUInt128(AddUInt128(t, v5), AddUInt128(v6, v6))
		n6 := AddUInt128(AddUInt128(t, t23), v7)
		n7 := AddUInt128(AddUInt128(t, v7), AddUInt128(v4, v4))

		// chunk 2
		t01 = AddUInt128(v8, v9)
		t23 = AddUInt128(v10, v11)
		t = AddUInt128(t01, t23)
		n8 := AddUInt128(AddUInt128(t, t01), v9)
		n9 := AddUInt128(AddUInt128(t, v9), AddUInt128(v10, v10))
		n10 := AddUInt128(AddUInt128(t, t23), v11)
		n11 := AddUInt128(AddUInt128(t, v11), AddUInt128(v8, v8))

		sum0 := AddUInt128(n0, AddUInt128(n4, n8))
		sum1 := AddUInt128(n1, AddUInt128(n5, n9))
		sum2 := AddUInt128(n2, AddUInt128(n6, n10))
		sum3 := AddUInt128(n3, AddUInt128(n7, n11))

		state[0] = g.Reduce96Bit(AddUInt128(n0, sum0))
		state[4] = g.Reduce96Bit(AddUInt128(n4, sum0))
		state[8] = g.Reduce96Bit(AddUInt128(n8, sum0))

		state[1] = g.Reduce96Bit(AddUInt128(n1, sum1))
		state[5] = g.Reduce96Bit(AddUInt128(n5, sum1))
		state[9] = g.Reduce96Bit(AddUInt128(n9, sum1))

		state[2] = g.Reduce96Bit(AddUInt128(n2, sum2))
		state[6] = g.Reduce96Bit(AddUInt128(n6, sum2))
		state[10] = g.Reduce96Bit(AddUInt128(n10, sum2))

		state[3] = g.Reduce96Bit(AddUInt128(n3, sum3))
		state[7] = g.Reduce96Bit(AddUInt128(n7, sum3))
		state[11] = g.Reduce96Bit(AddUInt128(n11, sum3))
	}
}

func externalLinearLayer(s *[WIDTH]g.GoldilocksField) {
	v0 := g.AsUInt128(s[0])
	v1 := g.AsUInt128(s[1])
	v2 := g.AsUInt128(s[2])
	v3 := g.AsUInt128(s[3])
	v4 := g.AsUInt128(s[4])
	v5 := g.AsUInt128(s[5])
	v6 := g.AsUInt128(s[6])
	v7 := g.AsUInt128(s[7])
	v8 := g.AsUInt128(s[8])
	v9 := g.AsUInt128(s[9])
	v10 := g.AsUInt128(s[10])
	v11 := g.AsUInt128(s[11])

	// chunk 0
	t01 := AddUInt128(v0, v1)
	t23 := AddUInt128(v2, v3)
	t := AddUInt128(t01, t23)
	n0 := AddUInt128(AddUInt128(t, t01), v1)
	n1 := AddUInt128(AddUInt128(t, v1), AddUInt128(v2, v2))
	n2 := AddUInt128(AddUInt128(t, t23), v3)
	n3 := AddUInt128(AddUInt128(t, v3), AddUInt128(v0, v0))

	// chunk 1
	t01 = AddUInt128(v4, v5)
	t23 = AddUInt128(v6, v7)
	t = AddUInt128(t01, t23)
	n4 := AddUInt128(AddUInt128(t, t01), v5)
	n5 := AddUInt128(AddUInt128(t, v5), AddUInt128(v6, v6))
	n6 := AddUInt128(AddUInt128(t, t23), v7)
	n7 := AddUInt128(AddUInt128(t, v7), AddUInt128(v4, v4))

	// chunk 2
	t01 = AddUInt128(v8, v9)
	t23 = AddUInt128(v10, v11)
	t = AddUInt128(t01, t23)
	n8 := AddUInt128(AddUInt128(t, t01), v9)
	n9 := AddUInt128(AddUInt128(t, v9), AddUInt128(v10, v10))
	n10 := AddUInt128(AddUInt128(t, t23), v11)
	n11 := AddUInt128(AddUInt128(t, v11), AddUInt128(v8, v8))

	sum0 := AddUInt128(n0, AddUInt128(n4, n8))
	sum1 := AddUInt128(n1, AddUInt128(n5, n9))
	sum2 := AddUInt128(n2, AddUInt128(n6, n10))
	sum3 := AddUInt128(n3, AddUInt128(n7, n11))

	s[0] = g.Reduce96Bit(AddUInt128(n0, sum0))
	s[4] = g.Reduce96Bit(AddUInt128(n4, sum0))
	s[8] = g.Reduce96Bit(AddUInt128(n8, sum0))

	s[1] = g.Reduce96Bit(AddUInt128(n1, sum1))
	s[5] = g.Reduce96Bit(AddUInt128(n5, sum1))
	s[9] = g.Reduce96Bit(AddUInt128(n9, sum1))

	s[2] = g.Reduce96Bit(AddUInt128(n2, sum2))
	s[6] = g.Reduce96Bit(AddUInt128(n6, sum2))
	s[10] = g.Reduce96Bit(AddUInt128(n10, sum2))

	s[3] = g.Reduce96Bit(AddUInt128(n3, sum3))
	s[7] = g.Reduce96Bit(AddUInt128(n7, sum3))
	s[11] = g.Reduce96Bit(AddUInt128(n11, sum3))
}

func internalLinearLayer(s *[WIDTH]g.GoldilocksField) {
	v0 := g.AsUInt128(s[0])
	v1 := g.AsUInt128(s[1])
	v2 := g.AsUInt128(s[2])
	v3 := g.AsUInt128(s[3])
	v4 := g.AsUInt128(s[4])
	v5 := g.AsUInt128(s[5])
	v6 := g.AsUInt128(s[6])
	v7 := g.AsUInt128(s[7])
	v8 := g.AsUInt128(s[8])
	v9 := g.AsUInt128(s[9])
	v10 := g.AsUInt128(s[10])
	v11 := g.AsUInt128(s[11])

	// chunk 0
	t01 := AddUInt128(v0, v1)
	t23 := AddUInt128(v2, v3)
	t := AddUInt128(t01, t23)
	n0 := AddUInt128(AddUInt128(t, t01), v1)
	n1 := AddUInt128(AddUInt128(t, v1), AddUInt128(v2, v2))
	n2 := AddUInt128(AddUInt128(t, t23), v3)
	n3 := AddUInt128(AddUInt128(t, v3), AddUInt128(v0, v0))

	// chunk 1
	t01 = AddUInt128(v4, v5)
	t23 = AddUInt128(v6, v7)
	t = AddUInt128(t01, t23)
	n4 := AddUInt128(AddUInt128(t, t01), v5)
	n5 := AddUInt128(AddUInt128(t, v5), AddUInt128(v6, v6))
	n6 := AddUInt128(AddUInt128(t, t23), v7)
	n7 := AddUInt128(AddUInt128(t, v7), AddUInt128(v4, v4))

	// chunk 2
	t01 = AddUInt128(v8, v9)
	t23 = AddUInt128(v10, v11)
	t = AddUInt128(t01, t23)
	n8 := AddUInt128(AddUInt128(t, t01), v9)
	n9 := AddUInt128(AddUInt128(t, v9), AddUInt128(v10, v10))
	n10 := AddUInt128(AddUInt128(t, t23), v11)
	n11 := AddUInt128(AddUInt128(t, v11), AddUInt128(v8, v8))

	sum0 := AddUInt128(n0, AddUInt128(n4, n8))
	sum1 := AddUInt128(n1, AddUInt128(n5, n9))
	sum2 := AddUInt128(n2, AddUInt128(n6, n10))
	sum3 := AddUInt128(n3, AddUInt128(n7, n11))

	s[0] = g.Reduce96Bit(AddUInt128(n0, sum0))
	s[4] = g.Reduce96Bit(AddUInt128(n4, sum0))
	s[8] = g.Reduce96Bit(AddUInt128(n8, sum0))

	s[1] = g.Reduce96Bit(AddUInt128(n1, sum1))
	s[5] = g.Reduce96Bit(AddUInt128(n5, sum1))
	s[9] = g.Reduce96Bit(AddUInt128(n9, sum1))

	s[2] = g.Reduce96Bit(AddUInt128(n2, sum2))
	s[6] = g.Reduce96Bit(AddUInt128(n6, sum2))
	s[10] = g.Reduce96Bit(AddUInt128(n10, sum2))

	s[3] = g.Reduce96Bit(AddUInt128(n3, sum3))
	s[7] = g.Reduce96Bit(AddUInt128(n7, sum3))
	s[11] = g.Reduce96Bit(AddUInt128(n11, sum3))
}

func addRC(state *[WIDTH]g.GoldilocksField, externalRound int) {
	for i := 0; i < WIDTH; i++ {
		state[i] = g.AddCanonicalUint64(state[i], uint64(EXTERNAL_CONSTANTS[externalRound][i]))
	}
}

func sbox(state *[WIDTH]g.GoldilocksField) {
	// group 0-5
	p0_2 := g.SquareF(state[0])
	p1_2 := g.SquareF(state[1])
	p2_2 := g.SquareF(state[2])
	p3_2 := g.SquareF(state[3])
	p4_2 := g.SquareF(state[4])
	p5_2 := g.SquareF(state[5])
	p0_3 := g.MulF(state[0], p0_2)
	p0_4 := g.SquareF(p0_2)
	p1_3 := g.MulF(state[1], p1_2)
	p1_4 := g.SquareF(p1_2)
	p2_3 := g.MulF(state[2], p2_2)
	p2_4 := g.SquareF(p2_2)
	p3_3 := g.MulF(state[3], p3_2)
	p3_4 := g.SquareF(p3_2)
	p4_3 := g.MulF(state[4], p4_2)
	p4_4 := g.SquareF(p4_2)
	p5_3 := g.MulF(state[5], p5_2)
	p5_4 := g.SquareF(p5_2)
	state[0] = g.MulF(p0_3, p0_4)
	state[1] = g.MulF(p1_3, p1_4)
	state[2] = g.MulF(p2_3, p2_4)
	state[3] = g.MulF(p3_3, p3_4)
	state[4] = g.MulF(p4_3, p4_4)
	state[5] = g.MulF(p5_3, p5_4)

	// group 6-11
	p6_2 := g.SquareF(state[6])
	p7_2 := g.SquareF(state[7])
	p8_2 := g.SquareF(state[8])
	p9_2 := g.SquareF(state[9])
	p10_2 := g.SquareF(state[10])
	p11_2 := g.SquareF(state[11])
	p6_3 := g.MulF(state[6], p6_2)
	p6_4 := g.SquareF(p6_2)
	p7_3 := g.MulF(state[7], p7_2)
	p7_4 := g.SquareF(p7_2)
	p8_3 := g.MulF(state[8], p8_2)
	p8_4 := g.SquareF(p8_2)
	p9_3 := g.MulF(state[9], p9_2)
	p9_4 := g.SquareF(p9_2)
	p10_3 := g.MulF(state[10], p10_2)
	p10_4 := g.SquareF(p10_2)
	p11_3 := g.MulF(state[11], p11_2)
	p11_4 := g.SquareF(p11_2)
	state[6] = g.MulF(p6_3, p6_4)
	state[7] = g.MulF(p7_3, p7_4)
	state[8] = g.MulF(p8_3, p8_4)
	state[9] = g.MulF(p9_3, p9_4)
	state[10] = g.MulF(p10_3, p10_4)
	state[11] = g.MulF(p11_3, p11_4)
}

func sboxP(state g.GoldilocksField) g.GoldilocksField {
	p2 := g.SquareF(state)    // x^2
	p4 := g.SquareF(p2)       // x^4
	state = g.MulF(state, p2) // x^3
	return g.MulF(state, p4)  // x^7
}

const BlockSize = g.Bytes * WIDTH // BlockSize size that poseidon consumes

type digest struct {
	data []byte
	len  int
}

func NewPoseidon2() hash.Hash {
	d := new(digest)
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = d.data[:0]
	d.len = 0
}

// Get element by element.
func (d *digest) Write(p []byte) (n int, err error) {
	d.data = append(d.data, p...)
	d.len += len(p)

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	h := HashNToMNoPadBytes(d.data, 4)
	d.Reset()

	for _, elem := range h {
		b = append(b, g.ToLittleEndianBytesF(elem)...)
	}

	return b
}

func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}
