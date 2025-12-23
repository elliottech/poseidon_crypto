package int

import "math/bits"

type UInt128 struct {
	Hi, Lo uint64
}

func UInt128FromUint64(v uint64) UInt128 {
	return UInt128{Hi: 0, Lo: v}
}

func AddUInt128(x, y UInt128) UInt128 {
	var carry uint64
	var z UInt128
	z.Lo, carry = bits.Add64(x.Lo, y.Lo, 0)
	z.Hi = x.Hi + y.Hi + carry
	return z
}

func AddUint128AndUint64(x UInt128, y uint64) UInt128 {
	var carry uint64
	var v UInt128
	v.Lo, carry = bits.Add64(x.Lo, y, 0)
	v.Hi = x.Hi + carry
	return v
}

func SubUint128AndUint64(x UInt128, y uint64) UInt128 {
	var borrowed uint64
	var v UInt128
	v.Lo, borrowed = bits.Sub64(x.Lo, y, 0)
	v.Hi = x.Hi - borrowed
	return v
}

func MulUInt64(x, y uint64) UInt128 {
	hi, lo := bits.Mul64(x, y)
	return UInt128{hi, lo}
}

func AddUint64(x, y uint64) UInt128 {
	var carry uint64
	var v UInt128
	v.Lo, carry = bits.Add64(x, y, 0)
	v.Hi = carry
	return v
}

func MulUint128AndUint64(u UInt128, n uint64) (dest UInt128) {
	dest.Hi, dest.Lo = bits.Mul64(u.Lo, n)
	dest.Hi += u.Hi * n
	return dest
}
