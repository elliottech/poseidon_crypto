package goldilocks

// Partially wraps and extends the functionality of the goldilocks field package.

import f "github.com/consensys/gnark-crypto/field/goldilocks"

type Element = f.Element

const Bytes = f.Bytes

func FromUint64(value uint64) Element {
	elem := f.NewElement(0)
	elem.SetUint64(value)
	return elem
}

func Modulus() uint64 {
	return f.Modulus().Uint64()
}

func Zero() Element {
	return f.NewElement(0)
}

func One() Element {
	return f.NewElement(1)
}

func Neg(e Element) Element {
	res := f.NewElement(0)
	res.Neg(&e)
	return res
}

func NegOne() Element {
	return Neg(One())
}

func Rand() Element {
	elem := f.NewElement(0)
	elem.SetRandom()
	return elem
}

func RandArray(count int) []Element {
	ret := make([]Element, count)
	for i := 0; i < count; i++ {
		ret[i] = Rand()
	}
	return ret
}

func FAdd(elems ...Element) Element {
	res := f.NewElement(0)
	for _, elem := range elems {
		res.Add(&res, &elem)
	}
	return res
}

func FSub(a, b *Element) Element {
	res := f.NewElement(0)
	res.Sub(a, b)
	return res
}

func FMul(elems ...*Element) Element {
	res := f.NewElement(1)
	for _, elem := range elems {
		res.Mul(&res, elem)
	}
	return res
}

func FSqrt(elem *Element) *Element {
	elemCopy := FDeepCopy(elem)
	retVal := elemCopy.Sqrt(&elemCopy)
	if retVal == nil {
		return nil
	}
	return &elemCopy
}

// Powers starting from 1
func FPowers(e *Element, count int) []Element {
	ret := make([]Element, count)
	ret[0] = f.One()
	for i := 1; i < int(count); i++ {
		ret[i].Mul(&ret[i-1], e)
	}
	return ret
}

func FDeepCopy(source *Element) Element {
	ret := Element{
		source[0],
	}
	return ret
}

func FNegOne() *Element {
	res := f.One()
	res.Neg(&res)
	return &res
}
