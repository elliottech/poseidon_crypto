package goldilocks

// Partially wraps and extends the functionality of the goldilocks field package.

import (
	"fmt"

	g "github.com/consensys/gnark-crypto/field/goldilocks"
)

type Element = g.Element

const Bytes = 8

var (
	G_ZERO = g.NewElement(0)
	G_ONE  = g.NewElement(1)
)

func reverseBytes(b []byte) []byte {
	res := make([]byte, len(b))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = b[j], b[i]
	}
	return res
}

func ArrayFromCanonicalLittleEndianBytes(in []byte) ([]Element, error) {

	missing := 8 - len(in)%8
	if missing == 8 {
		missing = 0
	}

	ret := make([]Element, 0)
	for i := 0; i < len(in); {
		nextStart := i + 8

		if nextStart > len(in) {
			nextStart = len(in)
		}

		slice := make([]byte, 8)
		copy(slice[:], in[i:nextStart])
		if len(slice) < 8 {
			slice = append(slice, make([]byte, missing)...)
		}

		elem, err := FromCanonicalLittleEndianBytes(slice)
		if err != nil {
			return nil, fmt.Errorf("failed to convert bytes to field element. bytes: %v, error: %w", slice, err)
		}
		ret = append(ret, *elem)
		i = nextStart
	}
	return ret, nil
}

func ToLittleEndianBytes(e ...Element) []byte {
	res := make([]byte, 0)
	for _, elem := range e {
		bytes := elem.Bytes()
		res = append(res, reverseBytes(bytes[:])...)
	}
	return res
}

func FromCanonicalLittleEndianBytes(in []byte) (*Element, error) {
	elem := G_ZERO
	err := elem.SetBytesCanonical(reverseBytes(in))
	if err != nil {
		return nil, fmt.Errorf("failed to convert bytes to field element: %w", err)
	}
	return &elem, nil
}

func ArrayToLittleEndianBytes(e []Element) []byte {
	res := make([]byte, 0)
	for _, elem := range e {
		res = append(res, ToLittleEndianBytes(elem)...)
	}
	return res
}

func ToString(e ...Element) string {
	res := ""
	for _, elem := range e {
		res += elem.String() + " "
	}
	return res
}

func FromBool(value bool) Element {
	if value {
		return One()
	}
	return Zero()
}

func FromInt64Abs(value int64) Element {
	return FromUint64(uint64(value & 0x7FFFFFFFFFFFFFFF))
}

func FromInt64(value int64) Element {
	elem := G_ZERO
	elem.SetInt64(value)
	return elem
}

func FromUint64(value uint64) Element {
	elem := G_ZERO
	elem.SetUint64(value)
	return elem
}

func FromUint32(value uint32) Element {
	return FromUint64(uint64(value))
}

func Equals(a, b *Element) bool {
	return a.Equal(b)
}

func Modulus() uint64 {
	return g.Modulus().Uint64()
}

func Zero() Element {
	return Element{0}
}

func One() Element {
	return Element{4294967295}
}

func Neg(e Element) Element {
	res := G_ZERO
	res.Neg(&e)
	return res
}

func NegOne() *Element {
	res := Neg(One())
	return &res
}

func Sample() Element {
	elem := G_ZERO
	elem.SetRandom()
	return elem
}

func RandArray(count int) []Element {
	ret := make([]Element, count)
	for i := 0; i < count; i++ {
		ret[i] = Sample()
	}
	return ret
}

func Add(a, b Element) Element {
	a.Add(&a, &b)
	return a
}

func AddThree(a, b, c Element) Element {
	a.Add(&a, &b)
	a.Add(&a, &c)
	return a
}

func AddFour(a, b, c, d Element) Element {
	a.Add(&a, &b)
	c.Add(&c, &d)
	a.Add(&a, &c)
	return a
}

func AddFive(a, b, c, d, e Element) Element {
	a.Add(&a, &b)
	c.Add(&c, &d)
	a.Add(&a, &c)
	a.Add(&a, &e)
	return a
}

func Sub(a, b *Element) Element {
	res := G_ZERO
	res.Sub(a, b)
	return res
}

func MulThree(a, b, c *Element) Element {
	res := G_ONE
	res.Mul(a, b)
	res.Mul(&res, c)
	return res
}

func Mul(a, b *Element) Element {
	res := G_ONE
	res.Mul(a, b)
	return res
}

func Sqrt(elem *Element) *Element {
	elemCopy := *elem
	return elemCopy.Sqrt(&elemCopy)
}

// Powers starting from 1
func Powers(e *Element, count int) []Element {
	ret := make([]Element, count)
	ret[0] = g.One()
	for i := 1; i < int(count); i++ {
		ret[i].Mul(&ret[i-1], e)
	}
	return ret
}
