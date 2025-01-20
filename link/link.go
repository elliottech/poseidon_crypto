package link

/*
#cgo darwin LDFLAGS: ./link/osx.a -ldl
#cgo linux LDFLAGS: ./link/linux.a -ldl
#include "./lib.h"
*/
import "C"
import (
	"unsafe"
)

func HashNToHashNoPad(input []uint64) [4]uint64 {
	inputLen := len(input)
	inputC := make([]C.uint64_t, inputLen)
	for i, elem := range input {
		inputC[i] = C.uint64_t(elem)
	}

	var outputC [4]C.uint64_t
	C.hash_n_to_hash_no_pad(
		(*C.uint64_t)(unsafe.Pointer(&inputC[0])),
		C.size_t(inputLen),
		(*C.uint64_t)(unsafe.Pointer(&outputC[0])),
	)

	return [4]uint64{
		uint64(outputC[0]),
		uint64(outputC[1]),
		uint64(outputC[2]),
		uint64(outputC[3]),
	}
}
