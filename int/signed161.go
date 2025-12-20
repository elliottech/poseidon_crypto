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
				bb = (uint32(acc | (nl << accLen))) & mw //nolint:gosec
				acc = nl >> (w - accLen)
			} else {
				bb = uint32(acc) & mw //nolint:gosec
				acc = 0
			}
			accLen += 64 - w
		} else {
			bb = uint32(acc) & mw //nolint:gosec
			accLen -= w
			acc >>= w
		}

		// If bb is greater than 2^(w-1), subtract 2^w and propagate a carry.
		bb += cc

		cc = (hw - bb) >> 31
		ss[i] = int32(bb) - int32(cc<<w) //nolint:gosec
	}
}
