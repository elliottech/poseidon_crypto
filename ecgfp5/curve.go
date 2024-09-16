package ecgfp5

// import (
// 	"math/big"

// 	config "github.com/consensys/gnark-crypto/field/generator/config"
// )

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

//*
// 	TODOs:
// 		- Add frobenius for quintic extension
// 		- Add legendre for quintic extension
// 		- Add encode & decode functions for WeierrstrassPoint and ECgFp5Point
// */

/// A curve point in affine (x,u) coordinates. This is used internally
/// to make "windows" that speed up point multiplications.
// type AffinePoint struct {
// 	X config.Element
// 	U config.Element
// }

/// A curve point.
// type ECgFp5Point struct {
// 	// Internally, we use the (x,u) fractional coordinates: for curve
// 	// point (x,y), we have (x,u) = (x,x/y) = (X/Z,U/T) (for the neutral
// 	// N, the u coordinate is 0).
// 	X config.Element
// 	Z config.Element
// 	U config.Element
// 	T config.Element
// }

// func ECgFp5PointDeepCopy(p ECgFp5Point) ECgFp5Point {
// 	return ECgFp5Point{
// 		X: Fp5DeepCopy(p.X),
// 		Z: Fp5DeepCopy(p.Z),
// 		U: Fp5DeepCopy(p.U),
// 		T: Fp5DeepCopy(p.T),
// 	}
// }

/// Constants for ECgFp5Point
// var (
// 	// Curve equation 'a' constant.
// 	A = config.Element{
// 		*new(big.Int).SetUint64(2),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	B1 = uint64(263)

// 	B = config.Element{
// 		*new(big.Int),
// 		*new(big.Int).SetUint64(B1),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	// 2*b
// 	B_MUL2 = config.Element{
// 		*new(big.Int),
// 		*new(big.Int).SetUint64(2 * B1),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	// 4*b
// 	B_MUL4 = config.Element{
// 		*new(big.Int),
// 		*new(big.Int).SetUint64(4 * B1),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	// 16*b
// 	B_MUL16 = config.Element{
// 		*new(big.Int),
// 		*new(big.Int).SetUint64(16 * B1),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	// The neutral point (neutral of the group law).
// 	NEUTRAL = ECgFp5Point{
// 		X: config.Element{*new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		Z: config.Element{*new(big.Int).SetUint64(1), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		U: config.Element{*new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		T: config.Element{*new(big.Int).SetUint64(1), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 	}

// 	// The conventional generator (corresponding to encoding w = 4).
// 	GENERATOR = ECgFp5Point{
// 		X: config.Element{
// 			*new(big.Int).SetUint64(12883135586176881569),
// 			*new(big.Int).SetUint64(4356519642755055268),
// 			*new(big.Int).SetUint64(5248930565894896907),
// 			*new(big.Int).SetUint64(2165973894480315022),
// 			*new(big.Int).SetUint64(2448410071095648785),
// 		},
// 		Z: config.Element{*new(big.Int).SetUint64(1), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		U: config.Element{
// 			*new(big.Int).SetUint64(1),
// 			*new(big.Int),
// 			*new(big.Int),
// 			*new(big.Int),
// 			*new(big.Int),
// 		},
// 		T: config.Element{
// 			*new(big.Int).SetUint64(4),
// 			*new(big.Int),
// 			*new(big.Int),
// 			*new(big.Int),
// 			*new(big.Int),
// 		},
// 	}
// )

/// Optimal window size should be 4 or 5 bits, depending on target
/// architecture. On an Intel i5-8259U ("Coffee Lake" core), a 5-bit
/// window seems very slightly better.
// const (
// 	WINDOW   = 5
// 	WIN_SIZE = 1 << (WINDOW - 1)
// )

/// General point addition. formulas are complete (no special case).
// func (p *ECgFp5Point) SetAdd(rhs *ECgFp5Point) {
// 	fp5 := Fp5()

// 	// cost: 10M
// 	x1, z1, u1, _t1 := Fp5DeepCopy(p.X), Fp5DeepCopy(p.Z), Fp5DeepCopy(p.U), Fp5DeepCopy(p.T)
// 	x2, z2, u2, _t2 := Fp5DeepCopy(rhs.X), Fp5DeepCopy(rhs.Z), Fp5DeepCopy(rhs.U), Fp5DeepCopy(rhs.T)

// 	t1 := fp5.Mul(x1, x2)
// 	t2 := fp5.Mul(z1, z2)
// 	t3 := fp5.Mul(u1, u2)
// 	t4 := fp5.Mul(_t1, _t2)

// 	// let t5 = (x1 + z1) * (x2 + z2) - t1 - t2;
// 	x1_plus_z1 := fp5.Add(x1, z1)
// 	x2_plus_z2 := fp5.Add(x2, z2)
// 	t1_plus_t2 := fp5.Add(t1, t2)
// 	t5 := Fp5Sub(fp5, fp5.Mul(x1_plus_z1, x2_plus_z2), t1_plus_t2)

// 	// let t6 = (u1 + _t1) * (u2 + _t2) - t3 - t4;
// 	u1_plus__t1 := fp5.Add(u1, _t1)
// 	u2_plus__t2 := fp5.Add(u2, _t2)
// 	t3_plus_t4 := fp5.Add(t3, t4)
// 	t6 := Fp5Sub(fp5, fp5.Mul(u1_plus__t1, u2_plus__t2), t3_plus_t4)

// 	// let t7 = t1 + t2 * Self::B;
// 	t2_mul_B := fp5.Mul(t2, B)
// 	t7 := fp5.Add(t1, t2_mul_B)
// 	// let t8 = t4 * t7;
// 	t8 := fp5.Mul(t4, t7)
// 	// let t9 = t3 * (t5 * Self::B_MUL2 + t7.double());
// 	t7_doubled := Fp5Double(fp5, t7)
// 	t5_mul_B_MUL2 := fp5.Mul(t5, B_MUL2)
// 	t9 := fp5.Mul(t3, fp5.Add(t5_mul_B_MUL2, t7_doubled))
// 	// let t10 = (t4 + t3.double()) * (t5 + t7);
// 	t3_doubled := Fp5Double(fp5, t3)
// 	t10 := fp5.Mul(
// 		fp5.Add(t4, t3_doubled),
// 		fp5.Add(t5, t7),
// 	)

// 	// self.x = (t10 - t8) * Self::B;
// 	t10_minus_t8 := Fp5Sub(fp5, t10, t8)
// 	p.X = fp5.Mul(t10_minus_t8, B)
// 	// self.z = t8 - t9;
// 	p.Z = Fp5Sub(fp5, t8, t9)
// 	// self.u = t6 * ((t2 * Self::B) - t1);
// 	t2_mul_B = fp5.Mul(t2, B)
// 	t2_mul_B_minus_t1 := Fp5Sub(fp5, t2_mul_B, t1)
// 	p.U = fp5.Mul(t6, t2_mul_B_minus_t1)
// 	// self.t = t8 + t9;
// 	p.T = fp5.Add(t8, t9)
// }

/// Add a point in affine coordinates to this one.
// func (p *ECgFp5Point) SetAddAffine(rhs *AffinePoint) {
// 	fp5 := Fp5()

// 	// cost: 8M
// 	x1, z1, u1, _t1 := Fp5DeepCopy(p.X), Fp5DeepCopy(p.Z), Fp5DeepCopy(p.U), Fp5DeepCopy(p.T)
// 	x2, u2 := Fp5DeepCopy(rhs.X), Fp5DeepCopy(rhs.U)

// 	// let t1 = x1 * x2;
// 	t1 := fp5.Mul(x1, x2)
// 	// let t2 = z1;
// 	t2 := Fp5DeepCopy(z1)
// 	// let t3 = u1 * u2;
// 	t3 := fp5.Mul(u1, u2)
// 	// let t4 = _t1;
// 	t4 := Fp5DeepCopy(_t1)
// 	// let t5 = x1 + x2 * z1;
// 	t5 := fp5.Add(x1, fp5.Mul(x2, z1))
// 	// let t6 = u1 + u2 * _t1;
// 	t6 := fp5.Add(u1, fp5.Mul(u2, _t1))
// 	// let t7 = t1 + t2 * Self::B;
// 	t7 := fp5.Add(t1, fp5.Mul(t2, B))
// 	// let t8 = t4 * t7;
// 	t8 := fp5.Mul(t4, t7)
// 	// let t9 = t3 * (t5 * Self::B_MUL2 + t7.double());
// 	t7_doubled := Fp5Double(fp5, t7)
// 	t5_mul_B_MUL2 := fp5.Mul(t5, B_MUL2)
// 	t9 := fp5.Mul(t3, fp5.Add(t5_mul_B_MUL2, t7_doubled))
// 	// let t10 = (t4 + t3.double()) * (t5 + t7);
// 	t3_doubled := Fp5Double(fp5, t3)
// 	t10 := fp5.Mul(
// 		fp5.Add(t4, t3_doubled),
// 		fp5.Add(t5, t7),
// 	)

// 	// self.x = (t10 - t8) * Self::B;
// 	t10_minus_t8 := Fp5Sub(fp5, t10, t8)
// 	p.X = fp5.Mul(t10_minus_t8, B)
// 	// self.u = t6 * (t2 * Self::B - t1);
// 	t2_mul_B := fp5.Mul(t2, B)
// 	t2_mul_B_minus_t1 := Fp5Sub(fp5, t2_mul_B, t1)
// 	p.U = fp5.Mul(t6, t2_mul_B_minus_t1)
// 	// self.z = t8 - t9;
// 	p.Z = Fp5Sub(fp5, t8, t9)
// 	// self.t = t8 + t9;
// 	p.T = fp5.Add(t8, t9)
// }

/// Subtract a point in affine coordinates from this one.
// func (p *ECgFp5Point) SetSubAffine(rhs *AffinePoint) {
// 	fp5 := Fp5()
// 	p.SetAddAffine(&AffinePoint{
// 		X: Fp5DeepCopy(rhs.X),
// 		U: fp5.Neg(Fp5DeepCopy(rhs.U)),
// 	})
// }

// func (p *ECgFp5Point) SetNeg() {
// 	fp5 := Fp5()
// 	p.U = fp5.Neg(p.U)
// }

// func (p *ECgFp5Point) SetSub(rhs *ECgFp5Point) {
// 	negRhs := ECgFp5PointDeepCopy(*rhs)
// 	negRhs.SetNeg()
// 	p.SetAdd(&negRhs)
// }

/// Specialized point doubling function (faster than using general
/// addition on the point and itself).
// func (p *ECgFp5Point) Double() *ECgFp5Point {
// 	r := ECgFp5PointDeepCopy(*p)
// 	r.SetDouble()
// 	return &r
// }

// func (p *ECgFp5Point) SetDouble() {
// 	fp5 := Fp5()

// 	// cost: 4M+5S
// 	x, z, u, t := Fp5DeepCopy(p.X), Fp5DeepCopy(p.Z), Fp5DeepCopy(p.U), Fp5DeepCopy(p.T)

// 	// let t1 = z * t;
// 	t1 := fp5.Mul(z, t)
// 	// let t2 = t1 * t;
// 	t2 := fp5.Mul(t1, t)
// 	// let x1 = t2.square();
// 	x1 := Fp5Square(fp5, t2)
// 	// let z1 = t1 * u;
// 	z1 := fp5.Mul(t1, u)
// 	// let t3 = u.square();
// 	t3 := Fp5Square(fp5, u)
// 	// let w1 = t2 - (x + z).double() * t3;
// 	x_plus_z := fp5.Add(x, z)
// 	x_plus_z_doubled := Fp5Double(fp5, x_plus_z)
// 	x_plus_z_doubled_mul_t3 := fp5.Mul(x_plus_z_doubled, t3)
// 	w1 := Fp5Sub(fp5, t2, x_plus_z_doubled_mul_t3)
// 	// let t4 = z1.square();
// 	t4 := Fp5Square(fp5, z1)

// 	// self.x = t4 * Self::B_MUL4;
// 	p.X = fp5.Mul(t4, B_MUL4)
// 	// self.z = w1.square();
// 	p.Z = Fp5Square(fp5, w1)
// 	// self.u = (w1 + z1).square() - t4 - self.z;
// 	w1_plus_z1 := fp5.Add(w1, z1)
// 	w1_plus_z1_square := Fp5Square(fp5, w1_plus_z1)
// 	t4_plus_z := fp5.Add(t4, p.Z)
// 	p.U = Fp5Sub(fp5, w1_plus_z1_square, t4_plus_z)
// 	// self.t = x1.double() - t4 * QuinticExtension::<F>::from_canonical_u64(4) - self.z;
// 	x1_doubled := Fp5Double(fp5, x1)
// 	quintic_4 := Fp5FromUint64(fp5, 4)
// 	t4_mul_4 := fp5.Mul(t4, quintic_4)
// 	t4_mul_4_plus_z := fp5.Add(t4_mul_4, p.Z)
// 	p.T = Fp5Sub(fp5, x1_doubled, t4_mul_4_plus_z)
// }

// func (p *ECgFp5Point) SetMDouble(n uint32) {
// 	// Handle corner cases (0 or 1 double).
// 	if n == 0 {
// 		return
// 	}
// 	if n == 1 {
// 		p.SetDouble()
// 		return
// 	}

// 	fp5 := Fp5()

// 	// cost: n*(2M+5S) + 2M+1S

// 	// let (x0, z0, u0, t0) = (self.x, self.z, self.u, self.t);
// 	x0, z0, u0, t0 := Fp5DeepCopy(p.X), Fp5DeepCopy(p.Z), Fp5DeepCopy(p.U), Fp5DeepCopy(p.T)

// 	// let mut t1 = z0 * t0;
// 	t1 := fp5.Mul(z0, t0)
// 	// let mut t2 = t1 * t0;
// 	t2 := fp5.Mul(t1, t0)
// 	// let x1 = t2.square();
// 	x1 := Fp5Square(fp5, t2)
// 	// let z1 = t1 * u0;
// 	z1 := fp5.Mul(t1, u0)
// 	// let mut t3 = u0.square();
// 	t3 := Fp5Square(fp5, u0)
// 	// let mut w1 = t2 - (x0 + z0).double() * t3;
// 	w1 := Fp5Sub(fp5, t2, fp5.Mul(Fp5Double(fp5, fp5.Add(x0, z0)), t3))
// 	// let mut t4 = w1.square();
// 	t4 := Fp5Square(fp5, w1)
// 	// let mut t5 = z1.square();
// 	t5 := Fp5Square(fp5, z1)
// 	// let mut x = t5.square() * Self::B_MUL16;
// 	x := fp5.Mul(Fp5Square(fp5, t5), B_MUL16)
// 	// let mut w = x1.double() - t5 * QuinticExtension::<F>::from_canonical_u16(4) - t4;
// 	w := Fp5Sub(fp5, Fp5Double(fp5, x1), fp5.Add(fp5.Mul(t5, Fp5FromUint64(fp5, 4)), t4))
// 	// let mut z = (w1 + z1).square() - t4 - t5;
// 	z := Fp5Sub(fp5, Fp5Square(fp5, fp5.Add(w1, z1)), fp5.Add(t4, t5))

// 	for i := uint32(2); i < n; i++ {
// 		// t1 = z.square();
// 		t1 = Fp5Square(fp5, z)
// 		// t2 = t1.square();
// 		t2 = Fp5Square(fp5, t1)
// 		// t3 = w.square();
// 		t3 = Fp5Square(fp5, w)
// 		// t4 = t3.square();
// 		t4 = Fp5Square(fp5, t3)
// 		// t5 = (w + z).square() - t1 - t3;
// 		t5 = Fp5Sub(fp5, Fp5Square(fp5, fp5.Add(w, z)), fp5.Add(t1, t3))
// 		// z = t5 * ((x + t1).double() - t3);
// 		z = fp5.Mul(t5, Fp5Sub(fp5, Fp5Double(fp5, fp5.Add(x, t1)), t3))
// 		// x = (t2 * t4) * Self::B_MUL16;
// 		x = fp5.Mul(fp5.Mul(t2, t4), B_MUL16)
// 		// w = -t4 - t2 * (Self::B_MUL4 - QuinticExtension::<F>::from_canonical_u16(4));
// 		w = Fp5Sub(fp5, fp5.Neg(t4), fp5.Mul(t2, Fp5Sub(fp5, B_MUL4, Fp5FromUint64(fp5, 4))))
// 	}

// 	// t1 = w.square();
// 	t1 = Fp5Square(fp5, w)
// 	// t2 = z.square();
// 	t2 = Fp5Square(fp5, z)
// 	// t3 = (w + z).square() - t1 - t2;
// 	t3 = Fp5Sub(fp5, Fp5Square(fp5, fp5.Add(w, z)), fp5.Add(t1, t2))
// 	// w1 = t1 - (x + t2).double();
// 	w1 = Fp5Sub(fp5, t1, Fp5Double(fp5, fp5.Add(x, t2)))
// 	// self.x = t3.square() * Self::B;
// 	p.X = fp5.Mul(Fp5Square(fp5, t3), B)
// 	// self.z = w1.square();
// 	p.Z = Fp5Square(fp5, w1)
// 	// self.u = t3 * w1;
// 	p.U = fp5.Mul(t3, w1)
// 	// self.t = t1.double() * (t1 - t2.double()) - self.z;
// 	p.T = Fp5Sub(fp5, fp5.Mul(Fp5Double(fp5, t1), Fp5Sub(fp5, t1, Fp5Double(fp5, t2))), p.Z)
// }

/// Return `true` if this point is the neutral, `false` otherwise.
// func (p *ECgFp5Point) IsNeutral() bool {
// 	fp5 := Fp5()
// 	return fp5.IsZero(p.U)
// }

/// Compare this point with another return `true` if they're equal`, `false` otherwise
// func (p *ECgFp5Point) Equals(rhs *ECgFp5Point) bool {
// 	fp5 := Fp5()
// 	return fp5.Equal(fp5.Mul(p.U, rhs.T), fp5.Mul(rhs.U, p.T))
// }

/// Convert points to affine coordinates.
// func BatchToAffine(src []ECgFp5Point) []AffinePoint {
// 	// We use a trick due to Montgomery: to compute the inverse of
// 	// x and of y, a single inversion suffices, with:
// 	//    1/x = y*(1/(x*y))
// 	//    1/y = x*(1/(x*y))
// 	// This extends to the case of inverting n values, with a total
// 	// cost of 1 inversion and 3*(n-1) multiplications.

// 	n := len(src)
// 	if n == 0 {
// 		return []AffinePoint{}
// 	}

// 	fp5 := Fp5()
// 	if n == 1 {
// 		p := ECgFp5PointDeepCopy(src[0])
// 		m1 := fp5.Inverse(fp5.Mul(p.Z, p.T))
// 		return []AffinePoint{
// 			{
// 				X: fp5.Mul(fp5.Mul(p.X, p.T), m1),
// 				U: fp5.Mul(fp5.Mul(p.U, p.Z), m1),
// 			},
// 		}
// 	}

// 	res := make([]AffinePoint, n)
// 	// Compute product of all values to invert, and invert it.
// 	// We also use the x and u coordinates of the points in the
// 	// destination slice to keep track of the partial products.
// 	m := fp5.Mul(src[0].Z, src[0].T)
// 	for i := 1; i < n; i++ {
// 		x := Fp5DeepCopy(m)
// 		m = fp5.Mul(m, src[i].Z)
// 		u := Fp5DeepCopy(m)
// 		m = fp5.Mul(m, src[i].T)

// 		res[i] = AffinePoint{X: x, U: u}
// 	}

// 	m = fp5.Inverse(m)

// 	// Propagate back inverses.
// 	for i := n - 1; i > 0; i-- {
// 		res[i].U = fp5.Mul(fp5.Mul(src[i].U, res[i].U), m)
// 		m = fp5.Mul(m, src[i].T)
// 		res[i].X = fp5.Mul(fp5.Mul(src[i].X, res[i].X), m)
// 		m = fp5.Mul(m, src[i].Z)
// 	}

// 	res[0].U = fp5.Mul(fp5.Mul(src[0].U, src[0].Z), m)
// 	m = fp5.Mul(m, src[0].T)
// 	res[0].X = fp5.Mul(src[0].X, m)

// 	return res
// }

// func (p *ECgFp5Point) MakeWindowAffine() []AffinePoint {
// 	tmp := make([]ECgFp5Point, WIN_SIZE)

// 	tmp[0] = ECgFp5PointDeepCopy(*p)
// 	for i := 1; i < WIN_SIZE; i++ {
// 		if (i & 1) == 0 {
// 			tmp[i] = ECgFp5PointDeepCopy(tmp[i-1])
// 			tmp[i].SetAdd(p)
// 		} else {
// 			tmp[i] = ECgFp5PointDeepCopy(tmp[i>>1])
// 			tmp[i].SetDouble()
// 		}
// 	}

// 	return BatchToAffine(tmp)
// }

/// Multiply this point by a scalar.
// func (p *ECgFp5Point) SetMul(s *ECgFp5Scalar) {
// 	// Make a window with affine points.
// 	win := p.MakeWindowAffine()
// 	digits := make([]int8, (319+WINDOW)/WINDOW)
// 	s.RecodeSigned(digits, WINDOW)

// 	*p = AffinePointLookupVartime(win, digits[len(digits)-1]).ToPoint()
// 	for i := len(digits) - 2; i >= 0; i-- {
// 		p.SetMDouble(WINDOW)
// 		p.SetAdd(AffinePointLookup(win, digits[i]).ToPoint())
// 	}
// }

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

/// A curve point in short Weirstrass form (x, y). This is used by the in-circuit representation
// type WeierstrassPoint struct {
// 	X     config.Element
// 	Y     config.Element
// 	IsInf bool
// }

/// Constants for WeierstrassPoint
// var (
// 	// curve equation `A` constants when in short Weierstrass form
// 	A_WEIERSTRASS = config.Element{
// 		*new(big.Int).SetUint64(6148914689804861439),
// 		*new(big.Int).SetUint64(263),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	B_WEIERSTRASS = config.Element{
// 		*new(big.Int).SetUint64(15713893096167979237),
// 		*new(big.Int).SetUint64(6148914689804861265),
// 		*new(big.Int),
// 		*new(big.Int),
// 		*new(big.Int),
// 	}

// 	NEUTRAL_WEIERSTRASS = WeierstrassPoint{
// 		X:     config.Element{*new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		Y:     config.Element{*new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int), *new(big.Int)},
// 		IsInf: true,
// 	}

// 	GENERATOR_WEIERSTRASS = WeierstrassPoint{
// 		X: config.Element{
// 			*new(big.Int).SetUint64(11712523173042564207),
// 			*new(big.Int).SetUint64(14090224426659529053),
// 			*new(big.Int).SetUint64(13197813503519687414),
// 			*new(big.Int).SetUint64(16280770174934269299),
// 			*new(big.Int).SetUint64(15998333998318935536),
// 		},
// 		Y: config.Element{
// 			*new(big.Int).SetUint64(14639054205878357578),
// 			*new(big.Int).SetUint64(17426078571020221072),
// 			*new(big.Int).SetUint64(2548978194165003307),
// 			*new(big.Int).SetUint64(8663895577921260088),
// 			*new(big.Int).SetUint64(9793640284382595140),
// 		},
// 		IsInf: false,
// 	}
// )
