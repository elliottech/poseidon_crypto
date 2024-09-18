package ecgfp5

// Utilities missing in gnark-crypto

import f "github.com/consensys/gnark-crypto/field/goldilocks"

func FRand() f.Element {
	elem := f.NewElement(0)
	elem.SetRandom()
	return elem
}

func FRandArray(count int) []f.Element {
	ret := make([]f.Element, count)
	for i := 0; i < count; i++ {
		ret[i] = FRand()
	}
	return ret
}

func FNeg(e *f.Element) f.Element {
	res := f.NewElement(0)
	res.Neg(e)
	return res
}

func FAdd(elems ...*f.Element) f.Element {
	res := f.NewElement(0)
	for _, elem := range elems {
		res.Add(&res, elem)
	}
	return res
}

func FSub(a, b *f.Element) f.Element {
	res := f.NewElement(0)
	res.Sub(a, b)
	return res
}

func FMul(elems ...*f.Element) f.Element {
	res := f.NewElement(1)
	for _, elem := range elems {
		res.Mul(&res, elem)
	}
	return res
}

func FSqrt(elem *f.Element) *f.Element {
	elemCopy := FDeepCopy(elem)
	retVal := elemCopy.Sqrt(&elemCopy)
	if retVal == nil {
		return nil
	}
	return &elemCopy
}

// Powers starting from 1
func FPowers(e *f.Element, count int) []f.Element {
	ret := make([]f.Element, count)
	ret[0] = f.One()
	for i := 1; i < int(count); i++ {
		ret[i].Mul(&ret[i-1], e)
	}
	return ret
}

func FDeepCopy(source *f.Element) f.Element {
	ret := f.Element{
		source[0],
	}
	return ret
}

func FNegOne() *f.Element {
	res := f.One()
	res.Neg(&res)
	return &res
}
