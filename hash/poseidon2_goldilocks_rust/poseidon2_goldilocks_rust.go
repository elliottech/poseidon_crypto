package poseidon2rust

import (
	"fmt"
	"hash"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
	link "github.com/elliottech/poseidon_crypto/link"
)

func HashNToHashNoPadRust(input []g.Element) p2.HashOut {
	in := make([]uint64, 0, len(input))
	for _, elem := range input {
		in = append(in, elem.Uint64())
	}

	return p2.HashOutFromUint64Array(link.HashNToHashNoPad(in))
}

func HashNoPadRust(input []g.Element) p2.HashOut {
	return HashNToHashNoPadRust(input)
}

func HashToQuinticExtensionRust(input []g.Element) gFp5.Element {
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

func HashNToOneRust(input []p2.HashOut) p2.HashOut {
	if len(input) == 1 {
		return input[0]
	}

	res := HashTwoToOneRust(input[0], input[1])
	for i := 2; i < len(input); i++ {
		res = HashTwoToOneRust(res, input[i])
	}

	return res
}

func HashTwoToOneRust(input1, input2 p2.HashOut) p2.HashOut {
	return HashNToHashNoPadRust([]g.Element{
		input1[0], input1[1], input1[2], input1[3],
		input2[0], input2[1], input2[2], input2[3],
	})
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
	b = append(b, HashNToHashNoPadRust(d.data).ToLittleEndianBytes()...)
	d.data = nil
	return b
}
