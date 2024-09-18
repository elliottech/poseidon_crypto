package ecgfp5

import (
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

// A curve point.
type ECgFp5Point struct {
	// Internally, we use the (x,u) fractional coordinates: for curve
	// point (x,y), we have (x,u) = (x,x/y) = (X/Z,U/T) (for the neutral
	// N, the u coordinate is 0).
	x, z, u, t gFp5.Element
}

// Constants for ECgFp5Point
var (
	A_ECgFp5Point = gFp5.Uint64ArrayToFp5(2, 0, 0, 0, 0)

	B1                  = uint64(263)
	B_ECgFp5Point       = gFp5.Uint64ArrayToFp5(0, B1, 0, 0, 0)
	B_MUL2_ECgFp5Point  = gFp5.Uint64ArrayToFp5(0, 2*B1, 0, 0, 0)
	B_MUL4_ECgFp5Point  = gFp5.Uint64ArrayToFp5(0, 4*B1, 0, 0, 0)
	B_MUL16_ECgFp5Point = gFp5.Uint64ArrayToFp5(0, 16*B1, 0, 0, 0)

	NEUTRAL_ECgFp5Point = ECgFp5Point{
		x: gFp5.Fp5DeepCopy(gFp5.FP5_ZERO),
		z: gFp5.Fp5DeepCopy(gFp5.FP5_ONE),
		u: gFp5.Fp5DeepCopy(gFp5.FP5_ZERO),
		t: gFp5.Fp5DeepCopy(gFp5.FP5_ONE),
	}

	GENERATOR_ECgFp5Point = ECgFp5Point{
		x: gFp5.Uint64ArrayToFp5(
			12883135586176881569,
			4356519642755055268,
			5248930565894896907,
			2165973894480315022,
			2448410071095648785,
		),
		z: gFp5.Fp5DeepCopy(gFp5.FP5_ONE),
		u: gFp5.Fp5DeepCopy(gFp5.FP5_ONE),
		t: gFp5.Uint64ArrayToFp5(4, 0, 0, 0, 0),
	}
)

func (p ECgFp5Point) DeepCopy() ECgFp5Point {
	return ECgFp5Point{
		x: gFp5.Fp5DeepCopy(p.x),
		z: gFp5.Fp5DeepCopy(p.z),
		u: gFp5.Fp5DeepCopy(p.u),
		t: gFp5.Fp5DeepCopy(p.t),
	}
}

func (p ECgFp5Point) Equals(rhs ECgFp5Point) bool {
	return gFp5.Fp5Equals(
		gFp5.Fp5Mul(p.u, rhs.t),
		gFp5.Fp5Mul(rhs.u, p.t),
	)
}

// Test whether a field element can be decoded into a point.
// returns `true` if decoding would work, `false` otherwise.
func Validate(w gFp5.Element) bool {
	// Value w can be decoded if and only if it is zero, or
	// (w^2 - a)^2 - 4*b is a quadratic residue.
	e := gFp5.Fp5Sub(gFp5.Fp5Square(w), A_ECgFp5Point)
	delta := gFp5.Fp5Sub(gFp5.Fp5Square(e), B_MUL4_ECgFp5Point)
	deltaLegendre := gFp5.Fp5Legendre(delta)
	return gFp5.Fp5IsZero(w) || deltaLegendre.IsOne()
}

func (p ECgFp5Point) Encode() gFp5.Element {
	return gFp5.Fp5Mul(p.t, gFp5.Fp5InverseOrZero(p.u))
}

// Attempt to decode a point from an gFp5 element
func Decode(w gFp5.Element) (ECgFp5Point, bool) {
	// Curve equation is y^2 = x*(x^2 + a*x + b); encoded value
	// is w = y/x. Dividing by x, we get the equation:
	//   x^2 - (w^2 - a)*x + b = 0
	// We solve for x and keep the solution which is not itself a
	// square (if there are solutions, exactly one of them will be
	// a square, and the other will not be a square).

	e := gFp5.Fp5Sub(gFp5.Fp5Square(w), A_ECgFp5Point)
	delta := gFp5.Fp5Sub(gFp5.Fp5Square(e), B_MUL4_ECgFp5Point)
	r, c := gFp5.Fp5CanonicalSqrt(delta)
	if !c {
		r = gFp5.Fp5DeepCopy(gFp5.FP5_ZERO)
	}

	x1 := gFp5.Fp5Div(gFp5.Fp5Add(e, r), gFp5.Fp5DeepCopy(gFp5.FP5_TWO))
	x2 := gFp5.Fp5Div(gFp5.Fp5Sub(e, r), gFp5.Fp5DeepCopy(gFp5.FP5_TWO))
	x := x2

	x1Legendre := gFp5.Fp5Legendre(x1)
	one := g.One()
	if !one.Equal(&x1Legendre) {
		x = x1
	}

	// If c == true (delta is not a sqrt) then we want to get the neutral here; note that if
	// w == 0, then delta = a^2 - 4*b, which is not a square, and
	// thus we also get c == 0.
	if !c {
		x = gFp5.Fp5DeepCopy(gFp5.FP5_ZERO)
	}
	z := gFp5.Fp5DeepCopy(gFp5.FP5_ONE)
	u := gFp5.Fp5DeepCopy(gFp5.FP5_ONE)
	if !c {
		u = gFp5.Fp5DeepCopy(gFp5.FP5_ZERO)
	}
	t := gFp5.Fp5DeepCopy(w)
	if !c {
		t = gFp5.Fp5DeepCopy(gFp5.FP5_ONE)
	}

	// If w == 0 then this is in fact a success.
	if c || gFp5.Fp5IsZero(w) {
		return ECgFp5Point{x: x, z: z, u: u, t: t}, true
	}

	return ECgFp5Point{}, false
}

func (p ECgFp5Point) IsNeutral() bool {
	return gFp5.Fp5IsZero(p.u)
}

func (p ECgFp5Point) Neg() ECgFp5Point {
	newPoint := p.DeepCopy()
	newPoint.u = gFp5.Fp5Neg(p.u)
	return newPoint
}

// General point addition. formulas are complete (no special case).
func (p ECgFp5Point) Add(rhs ECgFp5Point) ECgFp5Point {
	// cost: 10M

	x1 := gFp5.Fp5DeepCopy(p.x)
	z1 := gFp5.Fp5DeepCopy(p.z)
	u1 := gFp5.Fp5DeepCopy(p.u)
	_t1 := gFp5.Fp5DeepCopy(p.t)

	x2 := gFp5.Fp5DeepCopy(rhs.x)
	z2 := gFp5.Fp5DeepCopy(rhs.z)
	u2 := gFp5.Fp5DeepCopy(rhs.u)
	_t2 := gFp5.Fp5DeepCopy(rhs.t)

	// let t1 = x1 * x2;
	t1 := gFp5.Fp5Mul(x1, x2)
	// let t2 = z1 * z2;
	t2 := gFp5.Fp5Mul(z1, z2)
	// let t3 = u1 * u2;
	t3 := gFp5.Fp5Mul(u1, u2)
	// let t4 = _t1 * _t2;
	t4 := gFp5.Fp5Mul(_t1, _t2)
	// let t5 = (x1 + z1) * (x2 + z2) - t1 - t2;
	t5 := gFp5.Fp5Sub(
		gFp5.Fp5Mul(gFp5.Fp5Add(x1, z1), gFp5.Fp5Add(x2, z2)),
		gFp5.Fp5Add(t1, t2),
	)
	// let t6 = (u1 + _t1) * (u2 + _t2) - t3 - t4;
	t6 := gFp5.Fp5Sub(
		gFp5.Fp5Mul(gFp5.Fp5Add(u1, _t1), gFp5.Fp5Add(u2, _t2)),
		gFp5.Fp5Add(t3, t4),
	)
	// let t7 = t1 + t2 * Self::B;
	t7 := gFp5.Fp5Add(t1, gFp5.Fp5Mul(t2, B_ECgFp5Point))
	// let t8 = t4 * t7;
	t8 := gFp5.Fp5Mul(t4, t7)
	// let t9 = t3 * (t5 * Self::B_MUL2 + t7.double());
	t9 := gFp5.Fp5Mul(
		t3,
		gFp5.Fp5Add(gFp5.Fp5Mul(t5, B_MUL2_ECgFp5Point), gFp5.Fp5Double(t7)),
	)
	// let t10 = (t4 + t3.double()) * (t5 + t7);
	t10 := gFp5.Fp5Mul(
		gFp5.Fp5Add(t4, gFp5.Fp5Double(t3)),
		gFp5.Fp5Add(t5, t7),
	)

	xNew := gFp5.Fp5Mul(gFp5.Fp5Sub(t10, t8), B_ECgFp5Point)
	zNew := gFp5.Fp5Sub(t8, t9)
	uNew := gFp5.Fp5Mul(t6, gFp5.Fp5Sub(gFp5.Fp5Mul(t2, B_ECgFp5Point), t1))
	tNew := gFp5.Fp5Add(t8, t9)

	return ECgFp5Point{x: xNew, z: zNew, u: uNew, t: tNew}
}

func (p ECgFp5Point) Sub(rhs ECgFp5Point) ECgFp5Point {
	return p.Add(rhs.Neg())
}

func (p ECgFp5Point) Double() ECgFp5Point {
	newPoint := p.DeepCopy()
	newPoint.SetDouble()
	return newPoint
}

func (p *ECgFp5Point) MDouble(n uint32) ECgFp5Point {
	newPoint := p.DeepCopy()
	newPoint.SetMDouble(n)
	return newPoint
}

func (p *ECgFp5Point) SetDouble() {
	// cost: 4M+5S
	x := gFp5.Fp5DeepCopy(p.x)
	z := gFp5.Fp5DeepCopy(p.z)
	u := gFp5.Fp5DeepCopy(p.u)
	t := gFp5.Fp5DeepCopy(p.t)

	t1 := gFp5.Fp5Mul(z, t)
	t2 := gFp5.Fp5Mul(t1, t)
	x1 := gFp5.Fp5Square(t2)
	z1 := gFp5.Fp5Mul(t1, u)
	t3 := gFp5.Fp5Square(u)
	w1 := gFp5.Fp5Sub(
		t2,
		gFp5.Fp5Mul(
			t3,
			gFp5.Fp5Double(gFp5.Fp5Add(x, z)),
		),
	)
	t4 := gFp5.Fp5Square(z1)

	xNew := gFp5.Fp5Mul(t4, B_MUL4_ECgFp5Point)
	zNew := gFp5.Fp5Square(w1)
	uNew := gFp5.Fp5Sub(
		gFp5.Fp5Square(gFp5.Fp5Add(w1, z1)),
		gFp5.Fp5Add(t4, zNew),
	)
	tNew := gFp5.Fp5Sub(
		gFp5.Fp5Double(x1),
		gFp5.Fp5Add(
			gFp5.Fp5Mul(t4, gFp5.Uint64ArrayToFp5(4, 0, 0, 0, 0)),
			zNew,
		),
	)

	p.x = xNew
	p.z = zNew
	p.u = uNew
	p.t = tNew
}

func (p *ECgFp5Point) SetMDouble(n uint32) {
	if n == 0 {
		return
	}
	if n == 1 {
		p.SetDouble()
		return
	}

	// cost: n*(2M+5S) + 2M+1S
	x0 := gFp5.Fp5DeepCopy(p.x)
	z0 := gFp5.Fp5DeepCopy(p.z)
	u0 := gFp5.Fp5DeepCopy(p.u)
	t0 := gFp5.Fp5DeepCopy(p.t)

	t1 := gFp5.Fp5Mul(z0, t0)
	t2 := gFp5.Fp5Mul(t1, t0)
	x1 := gFp5.Fp5Square(t2)
	z1 := gFp5.Fp5Mul(t1, u0)
	t3 := gFp5.Fp5Square(u0)
	w1 := gFp5.Fp5Sub(
		t2,
		gFp5.Fp5Mul(
			gFp5.Fp5Double(gFp5.Fp5Add(x0, z0)),
			t3,
		),
	)
	t4 := gFp5.Fp5Square(w1)
	t5 := gFp5.Fp5Square(z1)
	x := gFp5.Fp5Mul(gFp5.Fp5Square(t5), B_MUL16_ECgFp5Point)
	w := gFp5.Fp5Sub(
		gFp5.Fp5Double(x1),
		gFp5.Fp5Add(
			gFp5.Fp5Mul(t5, gFp5.Uint64ArrayToFp5(4, 0, 0, 0, 0)),
			t4,
		),
	)
	z := gFp5.Fp5Sub(
		gFp5.Fp5Square(gFp5.Fp5Add(w1, z1)),
		gFp5.Fp5Add(t4, t5),
	)

	for i := 2; i < int(n); i++ {
		t1 = gFp5.Fp5Square(z)
		t2 = gFp5.Fp5Square(t1)
		t3 = gFp5.Fp5Square(w)
		t4 = gFp5.Fp5Square(t3)
		t5 = gFp5.Fp5Sub(
			gFp5.Fp5Square(gFp5.Fp5Add(w, z)),
			gFp5.Fp5Add(t1, t3),
		)
		z = gFp5.Fp5Mul(
			t5,
			gFp5.Fp5Sub(
				gFp5.Fp5Double(gFp5.Fp5Add(x, t1)),
				t3,
			),
		)
		x = gFp5.Fp5Mul(gFp5.Fp5Mul(t2, t4), B_MUL16_ECgFp5Point)
		w = gFp5.Fp5Neg(
			gFp5.Fp5Add(
				t4,
				gFp5.Fp5Mul(
					t2,
					gFp5.Fp5Sub(
						B_MUL4_ECgFp5Point,
						gFp5.Uint64ArrayToFp5(4, 0, 0, 0, 0),
					),
				),
			),
		)
	}

	t1 = gFp5.Fp5Square(w)
	t2 = gFp5.Fp5Square(z)
	t3 = gFp5.Fp5Sub(
		gFp5.Fp5Square(gFp5.Fp5Add(w, z)),
		gFp5.Fp5Add(t1, t2),
	)
	w1 = gFp5.Fp5Sub(
		t1,
		gFp5.Fp5Double(gFp5.Fp5Add(x, t2)),
	)

	p.x = gFp5.Fp5Mul(gFp5.Fp5Square(t3), B_ECgFp5Point)
	p.z = gFp5.Fp5Square(w1)
	p.u = gFp5.Fp5Mul(t3, w1)
	p.t = gFp5.Fp5Sub(
		gFp5.Fp5Mul(
			gFp5.Fp5Double(t1),
			gFp5.Fp5Sub(t1, gFp5.Fp5Double(t2)),
		),
		p.z,
	)
}

/*  Interactions with Affine Points */

// Add a point in affine coordinates to this one.
func (p ECgFp5Point) AddAffine(rhs AffinePoint) ECgFp5Point {
	// cost: 8M
	x1, z1, u1, _t1 := gFp5.Fp5DeepCopy(p.x), gFp5.Fp5DeepCopy(p.z), gFp5.Fp5DeepCopy(p.u), gFp5.Fp5DeepCopy(p.t)
	x2, u2 := gFp5.Fp5DeepCopy(rhs.x), gFp5.Fp5DeepCopy(rhs.u)

	t1 := gFp5.Fp5Mul(x1, x2)
	t2 := gFp5.Fp5DeepCopy(z1)
	t3 := gFp5.Fp5Mul(u1, u2)
	t4 := gFp5.Fp5DeepCopy(_t1)
	t5 := gFp5.Fp5Add(x1, gFp5.Fp5Mul(x2, z1))
	t6 := gFp5.Fp5Add(u1, gFp5.Fp5Mul(u2, _t1))
	t7 := gFp5.Fp5Add(t1, gFp5.Fp5Mul(t2, B_ECgFp5Point))
	t8 := gFp5.Fp5Mul(t4, t7)
	t9 := gFp5.Fp5Mul(t3, gFp5.Fp5Add(gFp5.Fp5Mul(t5, B_MUL2_ECgFp5Point), gFp5.Fp5Double(t7)))
	t10 := gFp5.Fp5Mul(gFp5.Fp5Add(t4, gFp5.Fp5Double(t3)), gFp5.Fp5Add(t5, t7))

	return ECgFp5Point{
		x: gFp5.Fp5Mul(gFp5.Fp5Sub(t10, t8), B_ECgFp5Point),
		u: gFp5.Fp5Mul(t6, gFp5.Fp5Sub(gFp5.Fp5Mul(t2, B_ECgFp5Point), t1)),
		z: gFp5.Fp5Sub(t8, t9),
		t: gFp5.Fp5Add(t8, t9),
	}
}

func (p ECgFp5Point) SubAffine(rhs AffinePoint) ECgFp5Point {
	rhsCopy := rhs.DeepCopy()
	rhsCopy.SetNeg()
	return p.AddAffine(rhsCopy)
}

const (
	WINDOW   = 5
	WIN_SIZE = 1 << (WINDOW - 1)
)

// Convert points to affine coordinates.
func BatchToAffine(src []ECgFp5Point) []AffinePoint {
	// We use a trick due to Montgomery: to compute the inverse of
	// x and of y, a single inversion suffices, with:
	//    1/x = y*(1/(x*y))
	//    1/y = x*(1/(x*y))
	// This extends to the case of inverting n values, with a total
	// cost of 1 inversion and 3*(n-1) multiplications.
	n := len(src)
	if n == 0 {
		return []AffinePoint{}
	}
	if n == 1 {
		p := src[0].DeepCopy()
		m1 := gFp5.Fp5InverseOrZero(gFp5.Fp5Mul(p.z, p.t))
		return []AffinePoint{
			{
				x: gFp5.Fp5Mul(gFp5.Fp5Mul(p.x, p.t), m1),
				u: gFp5.Fp5Mul(gFp5.Fp5Mul(p.u, p.z), m1),
			},
		}
	}

	res := make([]AffinePoint, n)
	// Compute product of all values to invert, and invert it.
	// We also use the x and u coordinates of the points in the
	// destination slice to keep track of the partial products.
	m := gFp5.Fp5Mul(src[0].z, src[0].t)
	for i := 1; i < n; i++ {
		x := gFp5.Fp5DeepCopy(m)
		m = gFp5.Fp5Mul(m, src[i].z)
		u := gFp5.Fp5DeepCopy(m)
		m = gFp5.Fp5Mul(m, src[i].t)

		res[i] = AffinePoint{x: x, u: u}
	}

	m = gFp5.Fp5InverseOrZero(m)

	// Propagate back inverses.
	for i := n - 1; i > 0; i-- {
		res[i].u = gFp5.Fp5Mul(gFp5.Fp5Mul(src[i].u, res[i].u), m)
		m = gFp5.Fp5Mul(m, src[i].t)
		res[i].x = gFp5.Fp5Mul(gFp5.Fp5Mul(src[i].x, res[i].x), m)
		m = gFp5.Fp5Mul(m, src[i].z)
	}
	res[0].u = gFp5.Fp5Mul(gFp5.Fp5Mul(src[0].u, src[0].z), m)
	m = gFp5.Fp5Mul(m, src[0].t)
	res[0].x = gFp5.Fp5Mul(src[0].x, m)

	return res
}

func (p ECgFp5Point) MakeWindowAffine() []AffinePoint {
	tmp := make([]ECgFp5Point, WIN_SIZE)
	tmp[0] = p.DeepCopy()
	for i := 1; i < WIN_SIZE; i++ {
		if (i & 1) == 0 {
			tmp[i] = tmp[i-1].Add(p)
		} else {
			tmp[i] = tmp[i>>1].Double()
		}
	}
	return BatchToAffine(tmp)
}

// Multiply this point by a scalar.
func (p *ECgFp5Point) SetMul(s *sf.ECgFp5Scalar) {
	// Make a window with affine points.
	win := p.MakeWindowAffine()
	digits := make([]int32, (319+WINDOW)/WINDOW)
	s.RecodeSigned(digits, int32(WINDOW))

	*p = LookupVarTime(win, digits[len(digits)-1]).ToPoint()
	for i := len(digits) - 2; i >= 0; i-- {
		p.SetMDouble(uint32(WINDOW))
		lookup := Lookup(win, digits[i])
		*p = p.AddAffine(lookup)
	}
}

func (p ECgFp5Point) Mul(s *sf.ECgFp5Scalar) ECgFp5Point {
	newPoint := p.DeepCopy()
	newPoint.SetMul(s)
	return newPoint
}
