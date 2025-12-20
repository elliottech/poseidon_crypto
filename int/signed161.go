package int

// A custom 161-bit integer type; used for splitting a scalar into a
// fraction. Negative values use two's complement notation; the value
// is truncated to 161 bits (upper bits in the top limb are ignored).
// Elements are mutable containers.
// WARNING: everything in here is vartime; do not use on secret values.
type Signed161 [3]uint64

// Export this value as a 192-bit integer (three 64-bit limbs, in little-endian order).
func (s Signed161) ToU192() [3]uint64 {
	x := s[2] & 0x00000001FFFFFFFF
	x |= (^(x >> 32) + 1) << 33
	return [3]uint64{s[0], s[1], x}
}

// Add v*2^s to this value.
func (s *Signed161) AddShifted(v *Signed161, shift int32) {
	if shift == 0 {
		s.Add(v[:])
	} else if shift < 64 {
		s.AddShiftedSmall(v[:], shift)
	} else if shift < 161 {
		s.AddShiftedSmall(v[(shift>>6):], shift&63)
	}
}

func (s *Signed161) AddShiftedSmall(v []uint64, shift int32) {
	cc, vbits, j := uint64(0), uint64(0), 3-len(v)
	for i := j; i < 3; i++ {
		vw := v[i-j]

		vws := (vw << (uint32(shift) % 64)) | vbits
		vbits = vw >> ((64 - uint32(shift)) % 64)

		z := AddUint128AndUint64(AddUint64(s[i], vws), cc)
		s[i] = z.Lo
		cc = z.Hi
	}
}

func (s *Signed161) Add(v []uint64) {
	cc, j := uint64(0), 3-len(v)
	for i := j; i < 3; i++ {
		z := AddUint128AndUint64(AddUint64(s[i], v[i-j]), cc)
		s[i] = z.Lo
		cc = z.Hi
	}
}

// Subtract v*2^s from this value.
func (s *Signed161) SubShifted(v *Signed161, shift int32) {
	if shift == 0 {
		s.Sub(v[:])
	} else if shift < 64 {
		s.SubShiftedSmall(v[:], shift)
	} else if shift < 161 {
		s.SubShiftedSmall(v[(shift>>6):], shift&63)
	}
}

func (s *Signed161) SubShiftedSmall(v []uint64, shift int32) {
	cc, vbits, j := uint64(0), uint64(0), 3-len(v)
	for i := j; i < 3; i++ {
		vw := v[i-j]
		vws := (vw << (uint32(shift) % 64)) | vbits
		vbits = vw >> ((64 - uint32(shift)) % 64)

		z := SubUint128AndUint64(SubUint128AndUint64(UInt128FromUint64(s[i]), vws), cc)
		s[i] = z.Lo
		cc = z.Hi & 1
	}
}

func (s *Signed161) Sub(v []uint64) {
	cc, j := uint64(0), 3-len(v)
	for i := j; i < 3; i++ {
		z := SubUint128AndUint64(SubUint128AndUint64(UInt128FromUint64(s[i]), v[i-j]), cc)
		s[i] = z.Lo
		cc = z.Hi & 1
	}
}

// Recode this integer into 33 signed digits for a 5-bit window.
func RecodeSigned5(s Signed161) [33]int32 {
	// We first sign-extend the value to 192 bits, then add
	// 2^160 to get a nonnegative value in the 0 to 2^161-1
	// range. We then recode that value; and finally we fix
	// the result by subtracting 1 from the top digit.
	tmp := s.ToU192()
	tmp[2] += 0x0000000100000000
	var ss [33]int32
	RecodeSignedFromLimbs(tmp[:], ss[:], 5)
	ss[32] -= 1
	return ss
}

func RecodeSignedFromLimbs(limbs []uint64, ss []int32, w int32) {
	var acc uint64 = 0
	var accLen int32 = 0
	var j int = 0
	mw := (uint32(1) << w) - 1
	hw := uint32(1) << (w - 1)
	var cc uint32 = 0
	for i := 0; i < len(ss); i++ {
		// Get next w-bit chunk in bb.
		var bb uint32
		if accLen < w {
			if j < len(limbs) {
				nl := limbs[j]
				j++
				bb = (uint32(acc | (nl << accLen))) & mw
				acc = nl >> (w - accLen)
			} else {
				bb = uint32(acc) & mw
				acc = 0
			}
			accLen += 64 - w
		} else {
			bb = uint32(acc) & mw
			accLen -= w
			acc >>= w
		}

		// If bb is greater than 2^(w-1), subtract 2^w and propagate a carry.
		bb += cc

		cc = (hw - bb) >> 31
		ss[i] = int32(bb) - int32(cc<<w)
	}
}
