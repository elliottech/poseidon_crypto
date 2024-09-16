package ecgfp5

// TESTED

import "math/big"

// A custom 640-bit integer type (signed).
// Elements are mutable containers.
// WARNING: everything in here is vartime; do not use on secret values.
type Signed640 struct {
	limbs [10]uint64
}

// Obtain an instance containing n^2.
func FromNsquared() Signed640 {
	return Signed640{
		limbs: [10]uint64{
			0x8E6B7A18061803C1,
			0x0AD8BDEE1594E2CF,
			0x17640E465F2598BC,
			0x90465B4214B27B1C,
			0xD308FECCB1878B88,
			0x3CC55EB2EAC07502,
			0x59F038FB784335CE,
			0xBFFFFE954FB808EA,
			0xBFFFFFCB80000099,
			0x3FFFFFFD8000000D,
		},
	}
}

// Obtain an instance containing a*b (both a and b are interpreted
// as integers in the 0..n-1 range).
func FromMulScalars(a, b ECgFp5Scalar) Signed640 {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	var r Signed640
	for i := 0; i < 5; i++ {
		aw := new(big.Int).Set(&a.Value[i])
		var cc uint64
		for j := 0; j < 5; j++ {
			limbs := new(big.Int).Mod(
				new(big.Int).Add(
					new(big.Int).Mul(
						aw,
						new(big.Int).Set(&b.Value[j]),
					),
					new(big.Int).Add(
						new(big.Int).SetUint64(r.limbs[i+j]),
						new(big.Int).SetUint64(cc),
					),
				),
				two128,
			).Bits()

			low := uint64(0)
			if len(limbs) > 0 {
				low = uint64(limbs[0])
			}
			r.limbs[i+j] = low

			high := uint64(0)
			if len(limbs) > 1 {
				high = uint64(limbs[1])
			}
			cc = high
		}
		r.limbs[i+5] = cc
	}
	return r
}

// Add 1 to this instance.
func (s *Signed640) Add1() {
	for i := 0; i < 10; i++ {
		s.limbs[i]++
		if s.limbs[i] != 0 {
			return
		}
	}
}

func (s *Signed640) IsNonnegative() bool {
	return (s.limbs[9] >> 63) == 0
}

func (s *Signed640) LtUnsigned(rhs *Signed640) bool {
	for i := 9; i >= 0; i-- {
		aw := s.limbs[i]
		bw := rhs.limbs[i]
		if aw < bw {
			return true
		}
		if aw > bw {
			return false
		}
	}
	return false
}

// Get the bit length of this value. The bit length is defined as the
// minimal size of the binary representation in two's complement,
// _excluding_ the sign bit (thus, -2^k has bit length k, whereas +2^k
// has bit length k+1).
func (s *Signed640) Bitlength() int32 {
	sm := WrappingNegU64(s.limbs[9] >> 63)
	for i := 9; i >= 0; i-- {
		w := s.limbs[i] ^ sm
		if w != 0 {
			return (int32(i) << 6) + U64Bitlength(w)
		}
	}
	return 0
}

func U64Bitlength(w uint64) int32 {
	// We use here a portable algorithm; some architectures have
	// dedicated opcodes that could speed up this operation
	// greatly (e.g. lzcnt on recent x86).
	var x = w
	var r int32
	if x > 0xFFFFFFFF {
		x >>= 32
		r += 32
	}
	if x > 0x0000FFFF {
		x >>= 16
		r += 16
	}
	if x > 0x000000FF {
		x >>= 8
		r += 8
	}
	if x > 0x0000000F {
		x >>= 4
		r += 4
	}
	if x > 0x00000003 {
		x >>= 2
		r += 2
	}
	return r + int32(x) - int32((x+1)>>2)
}

// Add v*2^s to this instance.
func (s *Signed640) AddShifted(v *Signed640, shift int32) {
	if shift == 0 {
		s.Add(v.limbs[:])
	} else if shift < 64 {
		s.AddShiftedSmall(v.limbs[:], shift)
	} else if shift < 640 {
		s.AddShiftedSmall(v.limbs[(shift>>6):], shift&63)
	}
}

func (s *Signed640) AddShiftedSmall(v []uint64, shift int32) {
	var cc uint64
	j := 10 - len(v)
	var vbits uint64
	for i := j; i < 10; i++ {
		vw := v[i-j]
		vws := WrappingLhsU64(vw, uint32(shift)) | vbits
		vbits = WrappingRhsU64(vw, 64-uint32(shift))
		z := uint128Add(s.limbs[i], vws, cc)
		limbs := z.Bits()

		low := uint64(0)
		if len(limbs) > 0 {
			low = uint64(limbs[0])
		}
		s.limbs[i] = low

		high := uint64(0)
		if len(limbs) > 1 {
			high = uint64(limbs[1])
		}
		cc = high
	}
}

func (s *Signed640) Add(v []uint64) {
	var cc uint64
	j := 10 - len(v)
	for i := j; i < 10; i++ {
		z := uint128Add(s.limbs[i], v[i-j], cc)
		limbs := z.Bits()

		low := uint64(0)
		if len(limbs) > 0 {
			low = uint64(limbs[0])
		}
		s.limbs[i] = low

		high := uint64(0)
		if len(limbs) > 1 {
			high = uint64(limbs[1])
		}
		cc = high
	}
}

// Subtract v*2^s from this instance.
func (s *Signed640) SubShifted(v *Signed640, shift int32) {
	if shift == 0 {
		s.Sub(v.limbs[:])
	} else if shift < 64 {
		s.SubShiftedSmall(v.limbs[:], shift)
	} else if shift < 640 {
		s.SubShiftedSmall(v.limbs[(shift>>6):], shift&63)
	}
}

func (s *Signed640) SubShiftedSmall(v []uint64, shift int32) {
	var cc uint64
	j := 10 - len(v)
	var vbits uint64
	for i := j; i < 10; i++ {
		vw := v[i-j]
		vws := WrappingLhsU64(vw, uint32(shift)) | vbits
		vbits = WrappingRhsU64(vw, 64-uint32(shift))
		z := uint128Sub(s.limbs[i], vws, cc)
		limbs := z.Bits()

		low := uint64(0)
		if len(limbs) > 0 {
			low = uint64(limbs[0])
		}
		s.limbs[i] = low

		high := uint64(0)
		if len(limbs) > 1 {
			high = uint64(limbs[1])
		}
		cc = uint64(high) & 1
	}
}

func (s *Signed640) Sub(v []uint64) {
	var cc uint64
	j := 10 - len(v)
	for i := j; i < 10; i++ {
		z := uint128Sub(s.limbs[i], v[i-j], cc)
		limbs := z.Bits()

		low := uint64(0)
		if len(limbs) > 0 {
			low = uint64(limbs[0])
		}
		s.limbs[i] = low

		high := uint64(0)
		if len(limbs) > 1 {
			high = uint64(limbs[1])
		}
		cc = uint64(high) & 1
	}
}
