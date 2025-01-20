package link

/*
#cgo darwin LDFLAGS: ${SRCDIR}/osx.a -ldl
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/linux_amd64.a -ldl

#include <stdint.h>
#include <stddef.h>
void hash_n_to_hash_no_pad(const uint64_t *data, size_t len, uint64_t *dst);
void hash_no_pad(const uint64_t *input, size_t input_len, uint64_t *dst);
void schnorr_sign_hashed_message(const uint64_t *m_hashed, const uint64_t *sk, uint64_t *sig);
void hash_to_quintic_extension(const uint64_t *input, size_t input_len, uint64_t *dst);
void schnorr_pk_from_sk(const uint64_t *input, uint64_t *dst);
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
