package poseidon2

import (
	"fmt"
	"hash"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	link "github.com/elliottech/poseidon_crypto/link"
)

type HashOut [4]g.Element

type NumericalHashOut [4]uint64

func (h HashOut) ToLittleEndianBytes() []byte {
	return g.ArrayToLittleEndianBytes([]g.Element{h[0], h[1], h[2], h[3]})
}

func (h HashOut) ToUint64Array() [4]uint64 {
	return [4]uint64{h[0].Uint64(), h[1].Uint64(), h[2].Uint64(), h[3].Uint64()}
}

func HashToQuinticExtension(input []g.Element) gFp5.Element {
	in := make([]uint64, 0, len(input))
	for _, elem := range input {
		in = append(in, elem.Uint64())
	}

	res := link.HashToQuinticExtension(in)
	return gFp5.Element([5]g.Element{
		g.FromUint64(res[0]),
		g.FromUint64(res[1]),
		g.FromUint64(res[2]),
		g.FromUint64(res[3]),
		g.FromUint64(res[4]),
	})
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
	return HashNToHashNoPad([]g.Element{input1[0], input1[1], input1[2], input1[3], input2[0], input2[1], input2[2], input2[3]})
}

func HashNToHashNoPad(input []g.Element) HashOut {
	in := make([]uint64, 0, len(input))
	for _, elem := range input {
		in = append(in, elem.Uint64())
	}

	return HashOutFromUint64Array(link.HashNToHashNoPad(in))
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
	b = append(b, HashNToHashNoPad(d.data).ToLittleEndianBytes()...)
	d.data = nil
	return b
}
