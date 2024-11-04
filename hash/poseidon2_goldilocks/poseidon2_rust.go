package poseidon2

/*
#cgo LDFLAGS: ./rust/lib.a -ldl
#include "./rust/lib.h"
#include <stdlib.h>
#include <stdint.h>
*/
import "C"
import (
	"unsafe"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

func hash_no_pad(in []g.Element) HashOut {
	input := []uint64{}
	for _, el := range in {
		input = append(input, el.Uint64())
	}

	dst := [4]uint64{}
	C.hash_no_pad(
		(*C.uint64_t)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
		(*C.uint64_t)(unsafe.Pointer(&dst[0])),
	)

	return HashOutFromUint64Array(dst)
}
