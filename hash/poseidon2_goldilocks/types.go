package poseidon2

import (
	"fmt"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

type HashOut [4]g.Element

type NumericalHashOut [4]uint64

func EmptyHashOut() HashOut {
	return HashOut{g.Zero(), g.Zero(), g.Zero(), g.Zero()}
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
