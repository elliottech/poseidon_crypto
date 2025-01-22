package poseidon2

import (
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	link "github.com/elliottech/poseidon_crypto/link"
)

func HashNToHashNoPadRust(input []g.Element) HashOut {
	in := make([]uint64, 0, len(input))
	for _, elem := range input {
		in = append(in, elem.Uint64())
	}

	return HashOutFromUint64Array(link.HashNToHashNoPad(in))
}

func HashNoPadRust(input []g.Element) HashOut {
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

func HashNToOneRust(input []HashOut) HashOut {
	if len(input) == 1 {
		return input[0]
	}

	res := HashTwoToOneRust(input[0], input[1])
	for i := 2; i < len(input); i++ {
		res = HashTwoToOneRust(res, input[i])
	}

	return res
}

func HashTwoToOneRust(input1, input2 HashOut) HashOut {
	return HashNToHashNoPadRust([]g.Element{input1[0], input1[1], input1[2], input1[3], input2[0], input2[1], input2[2], input2[3]})
}
