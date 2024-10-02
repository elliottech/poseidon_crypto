package goldilocks

// Partially wraps and extends the functionality of the goldilocks field package.

import (
	g "github.com/consensys/gnark-crypto/field/goldilocks"
)

type Element = g.Element

const Bytes = 8

func reverseBytes(b [Bytes]byte) [Bytes]byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func ToBigEndianBytes(e Element) [Bytes]byte {
	return e.Bytes()
}

func FromCanonicalBigEndianBytes(in [Bytes]byte) Element {
	elem := g.NewElement(0)
	elem.SetBytesCanonical(in[:])
	return elem
}

func ToLittleEndianBytes(e Element) [Bytes]byte {
	return reverseBytes(e.Bytes())
}

func FromCanonicalLittleEndianBytes(in [Bytes]byte) Element {
	elem := g.NewElement(0)
	reversedBytes := reverseBytes(in)
	elem.SetBytesCanonical(reversedBytes[:])
	return elem
}

func FromUint64(value uint64) Element {
	elem := g.NewElement(0)
	elem.SetUint64(value)
	return elem
}

func Equals(a, b *Element) bool {
	return a.Equal(b)
}

func Modulus() uint64 {
	return g.Modulus().Uint64()
}

func Zero() Element {
	return g.NewElement(0)
}

func One() Element {
	return g.NewElement(1)
}

func Neg(e Element) Element {
	res := g.NewElement(0)
	res.Neg(&e)
	return res
}

func NegOne() Element {
	return Neg(One())
}

func Sample() Element {
	elem := g.NewElement(0)
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

func Add(elems ...Element) Element {
	res := g.NewElement(0)
	for _, elem := range elems {
		res.Add(&res, &elem)
	}
	return res
}

func Sub(a, b *Element) Element {
	res := g.NewElement(0)
	res.Sub(a, b)
	return res
}

func Mul(elems ...*Element) Element {
	res := g.NewElement(1)
	for _, elem := range elems {
		res.Mul(&res, elem)
	}
	return res
}

func Sqrt(elem *Element) *Element {
	elemCopy := DeepCopy(elem)
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

func DeepCopy(source *Element) Element {
	return Element{source[0]}
}
