package signature

/*
#cgo LDFLAGS: ./rust/lib.a -ldl
#include "./rust/lib.h"
#include <stdlib.h>
#include <stdint.h>
*/
import "C"
import (
	"unsafe"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
)

func HashToQuinticExtension(msg []uint64) QuinticExtension {
	dst := [5]uint64{}

	C.hash_to_quintic_extension(
		(*C.uint64_t)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.uint64_t)(unsafe.Pointer(&dst[0])),
	)

	return dst
}

func schnorr_sign_hashed_message(msgHash [5]uint64, sk curve.ECgFp5Scalar) Signature {
	sig := make([]uint64, 10)

	C.schnorr_sign_hashed_message(
		(*C.uint64_t)(unsafe.Pointer(&msgHash[0])),
		(*C.uint64_t)(unsafe.Pointer(&sk[0])),
		(*C.uint64_t)(unsafe.Pointer(&sig[0])),
	)

	return Signature{
		S: curve.ECgFp5Scalar{sig[0], sig[1], sig[2], sig[3], sig[4]},
		E: curve.ECgFp5Scalar{sig[5], sig[6], sig[7], sig[8], sig[9]},
	}
}
