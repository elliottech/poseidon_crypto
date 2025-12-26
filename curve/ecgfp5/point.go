package ecgfp5

import (
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

// ECgFp5 is an elliptic curve group defined over the quintic extension of the Goldilocks field.
//
// CURVE PROPERTIES (Important for cryptographic security):
//
//  1. PRIME ORDER (No Cofactor):
//     The group has prime order n ≈ 2^319, with NO small subgroups.
//     This eliminates the need for cofactor clearing or subgroup checks.
//
//  2. CANONICAL ENCODING:
//     Each group element has exactly one valid encoding as an Fp5 element.
//     Decoding succeeds only for canonical representations.
//
//  3. COMPLETE FORMULAS:
//     Point addition uses complete formulas with no special cases (10M cost).
//
//  4. NEUTRAL ELEMENT AND GROUP LAW:
//     The neutral element is N = (0, 0), the unique point of order 2 on the curve.
//     The group law is defined as: P ⊕ Q = P + Q + N (on the underlying curve).
//     NOTE: The Add() function formulas already implement this group law - callers
//     do not need to explicitly add N, as it's built into the complete formulas.
//
// Reference: https://github.com/pornin/ecgfp5
//
// A curve point.
type ECgFp5Point struct {
	// Internally, we use the (x,u) fractional coordinates: for curve
	// point (x,y), we have (x,u) = (x,x/y) = (X/Z,U/T) (for the neutral
	// N, the u coordinate is 0).
	x, z, u, t gFp5.Element
}

// Constants for ECgFp5Point
var (
	A_ECgFp5Point = gFp5.Element{2, 0, 0, 0, 0}

	B1                  = g.GoldilocksField(263)
	B_ECgFp5Point       = gFp5.Element{0, B1, 0, 0, 0}
	B_MUL2_ECgFp5Point  = gFp5.Element{0, 2 * B1, 0, 0, 0}
	B_MUL4_ECgFp5Point  = gFp5.Element{0, 4 * B1, 0, 0, 0}
	B_MUL16_ECgFp5Point = gFp5.Element{0, 16 * B1, 0, 0, 0}

	NEUTRAL_ECgFp5Point = ECgFp5Point{
		x: gFp5.FP5_ZERO,
		z: gFp5.FP5_ONE,
		u: gFp5.FP5_ZERO,
		t: gFp5.FP5_ONE,
	}

	GENERATOR_ECgFp5Point = ECgFp5Point{
		x: gFp5.Element{
			12883135586176881569,
			4356519642755055268,
			5248930565894896907,
			2165973894480315022,
			2448410071095648785,
		},
		z: gFp5.FP5_ONE,
		u: gFp5.FP5_ONE,
		t: gFp5.Element{4, 0, 0, 0, 0},
	}

	// GENERATOR_WINDOW_AFFINE is a precomputed window table for the generator point.
	// This table contains affine points [G, 2G, 3G, ..., 16G] where G is the generator.
	// Using this precomputed table eliminates the need to compute the window on-the-fly
	// during scalar multiplication with the generator, improving performance by ~15-20%.
	// Generated with WINDOW=5, WIN_SIZE=16.
	GENERATOR_WINDOW_AFFINE = []AffinePoint{
		{ // 1G
			x: gFp5.Element{
				12883135586176881569,
				4356519642755055268,
				5248930565894896907,
				2165973894480315022,
				2448410071095648785,
			},
			u: gFp5.Element{
				13835058052060938241,
				18446744069414584321,
				18446744069414584321,
				18446744069414584321,
				18446744069414584321,
			},
		},
		{ // 2G
			x: gFp5.Element{
				16517537419581740386,
				6962630169123120981,
				12147752690379666704,
				16637325971742264607,
				2335078582315237010,
			},
			u: gFp5.Element{
				8457587110646932172,
				138591869800252458,
				3187444967472352324,
				18179149801168653736,
				9453003655195557048,
			},
		},
		{ // 3G
			x: gFp5.Element{
				4546139357324501584,
				1393728687664685160,
				15208040286522119521,
				7903224051455420834,
				12463930627278381774,
			},
			u: gFp5.Element{
				16373828487211693378,
				5899455736915524900,
				17616512450102495476,
				17643201028570366669,
				2833280130550676525,
			},
		},
		{ // 4G
			x: gFp5.Element{
				4341836049185169731,
				9111482874850194930,
				7798994609726992878,
				12619124383509403661,
				13047834166950680886,
			},
			u: gFp5.Element{
				3584786391427904733,
				1717626083626375072,
				16549008311909030594,
				17550175197111849143,
				18374971670674568416,
			},
		},
		{ // 5G
			x: gFp5.Element{
				18121072711119258927,
				3394315639035318724,
				2648370499809919556,
				13348924736921714137,
				3428166646246873447,
			},
			u: gFp5.Element{
				9264305576790077869,
				7426254234280836405,
				5107777768036114824,
				9390769538758625122,
				9788182195111344062,
			},
		},
		{ // 6G
			x: gFp5.Element{
				11080635543643017332,
				3122290570793204485,
				16632474826839786439,
				14883711538614796285,
				10396852362099782295,
			},
			u: gFp5.Element{
				14253916706639980511,
				15728038457561632290,
				3947138785484546318,
				4740958322851071718,
				17384736114265519442,
			},
		},
		{ // 7G
			x: gFp5.Element{
				4763058716218401568,
				17879823368956058516,
				13578954599286698938,
				8634670560943921567,
				13706660844700767685,
			},
			u: gFp5.Element{
				3354778288360932917,
				13842278303693121409,
				4717821645259836467,
				7978743897613094276,
				10118963888992569394,
			},
		},
		{ // 8G
			x: gFp5.Element{
				4026958896735257282,
				13595990041314210204,
				11499471878438064392,
				10019455879458851233,
				11986847968355927330,
			},
			u: gFp5.Element{
				14532821659997761913,
				9582789969382797985,
				3082219099923033594,
				2859656980617778370,
				3746047816071136016,
			},
		},
		{ // 9G
			x: gFp5.Element{
				15935900828168308224,
				8668680449802005535,
				491315506768012688,
				6584881037682113026,
				12386385009372860460,
			},
			u: gFp5.Element{
				13217832923050551864,
				51671271962049328,
				15400792709153778477,
				6752203529649104660,
				2855313280735340066,
			},
		},
		{ // 10G
			x: gFp5.Element{
				8473506523195244465,
				2446964921175324878,
				17962771942831363202,
				6949608686158330138,
				9315492999547366751,
			},
			u: gFp5.Element{
				5171814696081600409,
				3025466154945175207,
				453302446979841822,
				14135305892339872079,
				2556388051049291052,
			},
		},
		{ // 11G
			x: gFp5.Element{
				3960231187580500028,
				3695840168764199059,
				2914577777792670911,
				9249939676680902688,
				17553522813502241416,
			},
			u: gFp5.Element{
				3015152305907361949,
				10730034543155667220,
				3314242046485170944,
				1984395553885795852,
				13781645774758249860,
			},
		},
		{ // 12G
			x: gFp5.Element{
				11575997426281090678,
				1534495174840625570,
				7539338128385981583,
				10393042019577161985,
				10667466219175771157,
			},
			u: gFp5.Element{
				16681365912970185037,
				11287896019745355117,
				11069899752345274504,
				15487604769605237513,
				13467978440572613228,
			},
		},
		{ // 13G
			x: gFp5.Element{
				11192179397773394280,
				3555953455665397909,
				5346523552109387121,
				4514445299325204396,
				3932728981135688453,
			},
			u: gFp5.Element{
				5421638117266109845,
				204299445119713184,
				6067390115784997081,
				16191134954342419157,
				4139938600224417293,
			},
		},
		{ // 14G
			x: gFp5.Element{
				13189785832536261642,
				8777097377506996162,
				17497140949916325738,
				15140279769427597032,
				15517274717131999881,
			},
			u: gFp5.Element{
				1040464435413162742,
				9262701069034606854,
				2990438819650713743,
				18129195737333990255,
				12490074042478236606,
			},
		},
		{ // 15G
			x: gFp5.Element{
				17716508479149156535,
				14351380558651795729,
				3644546258883003807,
				5171318241596472386,
				294806796132518330,
			},
			u: gFp5.Element{
				7535225611936271281,
				14682077054502188499,
				784215514926156349,
				5280586574139275596,
				14407528916988559545,
			},
		},
		{ // 16G
			x: gFp5.Element{
				8681294642569802563,
				7751765660802747503,
				16382129702876313971,
				7447155060842833278,
				6859908403876474879,
			},
			u: gFp5.Element{
				9674486254207846385,
				5248970165164951259,
				3611784478790504991,
				18437168019170350173,
				3537959913875671086,
			},
		},
	}
)

func (p ECgFp5Point) Equals(rhs ECgFp5Point) bool {
	return gFp5.Equals(
		gFp5.Mul(p.u, rhs.t),
		gFp5.Mul(rhs.u, p.t),
	)
}

func (p ECgFp5Point) Encode() gFp5.Element {
	return gFp5.Mul(p.t, gFp5.InverseOrZero(p.u))
}

// Decode attempts to decode a point from an Fp5 element.
//
// CANONICAL DECODING PROPERTY:
// This function implements canonical decoding - each valid group element has
// exactly ONE valid encoding. Invalid encodings are rejected, preventing
// point malleability attacks.
//
// SECURITY IMPLICATION:
// Since ECgFp5 has prime order (no cofactor), there is NO need to check for
// small subgroup membership. Any successfully decoded point is guaranteed to
// be in the prime-order group.
//
// Returns (point, true) on success, (NEUTRAL, false) on invalid encoding.
func Decode(w gFp5.Element) (ECgFp5Point, bool) {
	// Curve equation is y^2 = x*(x^2 + a*x + b); encoded value
	// is w = y/x. Dividing by x, we get the equation:
	//   x^2 - (w^2 - a)*x + b = 0
	// We solve for x and keep the solution which is not itself a
	// square (if there are solutions, exactly one of them will be
	// a square, and the other will not be a square).

	e := gFp5.Sub(gFp5.Square(w), A_ECgFp5Point)
	delta := gFp5.Sub(gFp5.Square(e), B_MUL4_ECgFp5Point)
	r, c := gFp5.CanonicalSqrt(delta)
	if !c {
		r = gFp5.FP5_ZERO
	}

	x1 := gFp5.Div(gFp5.Add(e, r), gFp5.FP5_TWO)
	x2 := gFp5.Div(gFp5.Sub(e, r), gFp5.FP5_TWO)
	x := x1

	x1Legendre := gFp5.Legendre(x1)
	if x1Legendre.ToCanonicalUint64() == 1 {
		x = x2
	}

	// If c == true (delta is not a sqrt) then we want to get the neutral here; note that if
	// w == 0, then delta = a^2 - 4*b, which is not a square, and
	// thus we also get c == 0.
	if !c {
		x = gFp5.FP5_ZERO
	}
	z := gFp5.FP5_ONE
	u := gFp5.FP5_ONE
	if !c {
		u = gFp5.FP5_ZERO
	}
	t := w
	if !c {
		t = gFp5.FP5_ONE
	}

	// If w == 0 then this is in fact a success.
	if c || gFp5.IsZero(w) {
		return ECgFp5Point{x: x, z: z, u: u, t: t}, true
	}

	return NEUTRAL_ECgFp5Point, false
}

func (p ECgFp5Point) IsNeutral() bool {
	return gFp5.IsZero(p.u)
}

// Add computes the group sum P ⊕ Q using complete addition formulas.
//
// These formulas implement the ECgFp5 group law: P ⊕ Q = P + Q + N (on the curve),
// where N = (0,0) is the neutral element. The formulas are "complete" (no special cases)
// and automatically handle all point combinations including the neutral element.
//
// Cost: 10 field multiplications (10M).
func (p ECgFp5Point) Add(rhs ECgFp5Point) ECgFp5Point {

	x1 := p.x
	z1 := p.z
	u1 := p.u
	_t1 := p.t

	x2 := rhs.x
	z2 := rhs.z
	u2 := rhs.u
	_t2 := rhs.t

	// let t1 = x1 * x2;
	t1 := gFp5.Mul(x1, x2)
	// let t2 = z1 * z2;
	t2 := gFp5.Mul(z1, z2)
	// let t3 = u1 * u2;
	t3 := gFp5.Mul(u1, u2)
	// let t4 = _t1 * _t2;
	t4 := gFp5.Mul(_t1, _t2)
	// let t5 = (x1 + z1) * (x2 + z2) - t1 - t2;
	t5 := gFp5.Sub(
		gFp5.Mul(gFp5.Add(x1, z1), gFp5.Add(x2, z2)),
		gFp5.Add(t1, t2),
	)
	// let t6 = (u1 + _t1) * (u2 + _t2) - t3 - t4;
	t6 := gFp5.Sub(
		gFp5.Mul(gFp5.Add(u1, _t1), gFp5.Add(u2, _t2)),
		gFp5.Add(t3, t4),
	)
	// let t7 = t1 + t2 * Self::B;
	t7 := gFp5.Add(t1, gFp5.Mul(t2, B_ECgFp5Point))
	// let t8 = t4 * t7;
	t8 := gFp5.Mul(t4, t7)
	// let t9 = t3 * (t5 * Self::B_MUL2 + t7.double());
	t9 := gFp5.Mul(
		t3,
		gFp5.Add(gFp5.Mul(t5, B_MUL2_ECgFp5Point), gFp5.Double(t7)),
	)
	// let t10 = (t4 + t3.double()) * (t5 + t7);
	t10 := gFp5.Mul(
		gFp5.Add(t4, gFp5.Double(t3)),
		gFp5.Add(t5, t7),
	)

	xNew := gFp5.Mul(gFp5.Sub(t10, t8), B_ECgFp5Point)
	zNew := gFp5.Sub(t8, t9)
	uNew := gFp5.Mul(t6, gFp5.Sub(gFp5.Mul(t2, B_ECgFp5Point), t1))
	tNew := gFp5.Add(t8, t9)

	return ECgFp5Point{x: xNew, z: zNew, u: uNew, t: tNew}
}

func (p ECgFp5Point) Double() ECgFp5Point {
	newPoint := p
	newPoint.SetDouble()
	return newPoint
}

func (p *ECgFp5Point) SetDouble() {
	// cost: 4M+5S
	x := p.x
	z := p.z
	u := p.u
	t := p.t

	t1 := gFp5.Mul(z, t)
	t2 := gFp5.Mul(t1, t)
	x1 := gFp5.Square(t2)
	z1 := gFp5.Mul(t1, u)
	t3 := gFp5.Square(u)
	w1 := gFp5.Sub(
		t2,
		gFp5.Mul(
			t3,
			gFp5.Double(gFp5.Add(x, z)),
		),
	)
	t4 := gFp5.Square(z1)

	xNew := gFp5.Mul(t4, B_MUL4_ECgFp5Point)
	zNew := gFp5.Square(w1)
	uNew := gFp5.Sub(
		gFp5.Square(gFp5.Add(w1, z1)),
		gFp5.Add(t4, zNew),
	)
	tNew := gFp5.Sub(
		gFp5.Double(x1),
		gFp5.Add(
			gFp5.Mul(t4, gFp5.Element{4, 0, 0, 0, 0}),
			zNew,
		),
	)

	p.x = xNew
	p.z = zNew
	p.u = uNew
	p.t = tNew
}

func (p *ECgFp5Point) MDouble(n uint32) ECgFp5Point {
	newPoint := ECgFp5Point{x: p.x, z: p.z, u: p.u, t: p.t}
	newPoint.SetMDouble(n)
	return newPoint
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
	x0 := p.x
	z0 := p.z
	u0 := p.u
	t0 := p.t

	t1 := gFp5.Mul(z0, t0)
	t2 := gFp5.Mul(t1, t0)
	x1 := gFp5.Square(t2)
	z1 := gFp5.Mul(t1, u0)
	t3 := gFp5.Square(u0)
	w1 := gFp5.Sub(
		t2,
		gFp5.Mul(
			gFp5.Double(gFp5.Add(x0, z0)),
			t3,
		),
	)
	t4 := gFp5.Square(w1)
	t5 := gFp5.Square(z1)
	x := gFp5.Mul(gFp5.Square(t5), B_MUL16_ECgFp5Point)
	w := gFp5.Sub(
		gFp5.Double(x1),
		gFp5.Add(
			gFp5.Mul(t5, gFp5.Element{4, 0, 0, 0, 0}),
			t4,
		),
	)
	z := gFp5.Sub(
		gFp5.Square(gFp5.Add(w1, z1)),
		gFp5.Add(t4, t5),
	)

	for i := 2; i < int(n); i++ {
		t1 = gFp5.Square(z)
		t2 = gFp5.Square(t1)
		t3 = gFp5.Square(w)
		t4 = gFp5.Square(t3)
		t5 = gFp5.Sub(
			gFp5.Square(gFp5.Add(w, z)),
			gFp5.Add(t1, t3),
		)
		z = gFp5.Mul(
			t5,
			gFp5.Sub(
				gFp5.Double(gFp5.Add(x, t1)),
				t3,
			),
		)
		x = gFp5.Mul(gFp5.Mul(t2, t4), B_MUL16_ECgFp5Point)
		w = gFp5.Neg(
			gFp5.Add(
				t4,
				gFp5.Mul(
					t2,
					gFp5.Sub(
						B_MUL4_ECgFp5Point,
						gFp5.Element{4, 0, 0, 0, 0},
					),
				),
			),
		)
	}

	t1 = gFp5.Square(w)
	t2 = gFp5.Square(z)
	t3 = gFp5.Sub(
		gFp5.Square(gFp5.Add(w, z)),
		gFp5.Add(t1, t2),
	)
	w1 = gFp5.Sub(
		t1,
		gFp5.Double(gFp5.Add(x, t2)),
	)

	p.x = gFp5.Mul(gFp5.Square(t3), B_ECgFp5Point)
	p.z = gFp5.Square(w1)
	p.u = gFp5.Mul(t3, w1)
	p.t = gFp5.Sub(
		gFp5.Mul(
			gFp5.Double(t1),
			gFp5.Sub(t1, gFp5.Double(t2)),
		),
		p.z,
	)
}

// Add a point in affine coordinates to this one.
func (p ECgFp5Point) AddAffine(rhs AffinePoint) ECgFp5Point {
	// cost: 8M
	x1, z1, u1, _t1 := p.x, p.z, p.u, p.t
	x2, u2 := rhs.x, rhs.u

	t1 := gFp5.Mul(x1, x2)
	t2 := z1
	t3 := gFp5.Mul(u1, u2)
	t4 := _t1
	t5 := gFp5.Add(x1, gFp5.Mul(x2, z1))
	t6 := gFp5.Add(u1, gFp5.Mul(u2, _t1))
	t7 := gFp5.Add(t1, gFp5.Mul(t2, B_ECgFp5Point))
	t8 := gFp5.Mul(t4, t7)
	t9 := gFp5.Mul(t3, gFp5.Add(gFp5.Mul(t5, B_MUL2_ECgFp5Point), gFp5.Double(t7)))
	t10 := gFp5.Mul(gFp5.Add(t4, gFp5.Double(t3)), gFp5.Add(t5, t7))

	return ECgFp5Point{
		x: gFp5.Mul(gFp5.Sub(t10, t8), B_ECgFp5Point),
		u: gFp5.Mul(t6, gFp5.Sub(gFp5.Mul(t2, B_ECgFp5Point), t1)),
		z: gFp5.Sub(t8, t9),
		t: gFp5.Add(t8, t9),
	}
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
		return nil
	}
	if n == 1 {
		p := src[0]
		m1 := gFp5.InverseOrZero(gFp5.Mul(p.z, p.t))
		return []AffinePoint{
			{
				x: gFp5.Mul(gFp5.Mul(p.x, p.t), m1),
				u: gFp5.Mul(gFp5.Mul(p.u, p.z), m1),
			},
		}
	}

	res := make([]AffinePoint, n)
	// Compute product of all values to invert, and invert it.
	// We also use the x and u coordinates of the points in the
	// destination slice to keep track of the partial products.
	m := gFp5.Mul(src[0].z, src[0].t)
	for i := 1; i < n; i++ {
		x := m
		m = gFp5.Mul(m, src[i].z)
		u := m
		m = gFp5.Mul(m, src[i].t)

		res[i] = AffinePoint{x: x, u: u}
	}

	m = gFp5.InverseOrZero(m)

	// Propagate back inverses.
	for i := n - 1; i > 0; i-- {
		res[i].u = gFp5.Mul(gFp5.Mul(src[i].u, res[i].u), m)
		m = gFp5.Mul(m, src[i].t)
		res[i].x = gFp5.Mul(gFp5.Mul(src[i].x, res[i].x), m)
		m = gFp5.Mul(m, src[i].z)
	}
	res[0].u = gFp5.Mul(gFp5.Mul(src[0].u, src[0].z), m)
	m = gFp5.Mul(m, src[0].t)
	res[0].x = gFp5.Mul(src[0].x, m)

	return res
}

func (p ECgFp5Point) MakeWindowAffine() []AffinePoint {
	tmp := make([]ECgFp5Point, WIN_SIZE)
	tmp[0] = p
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
func (r ECgFp5Point) Mul(s ECgFp5Scalar) ECgFp5Point {
	p := r

	// Make a window with affine points.
	win := p.MakeWindowAffine()
	digits := make([]int32, (319+WINDOW)/WINDOW)
	s.RecodeSigned(digits, int32(WINDOW))

	p = LookupVarTime(win, digits[len(digits)-1]).ToPoint()
	for i := len(digits) - 2; i >= 0; i-- {
		p.SetMDouble(uint32(WINDOW))
		lookup := Lookup(win, digits[i])
		p = p.AddAffine(lookup)
	}

	return p
}

// MulGenerator multiplies the generator point by a scalar using the precomputed window table.
// This is significantly faster than the generic Mul() function for the generator point,
// as it avoids recomputing the window table on every call.
func MulGenerator(s ECgFp5Scalar) ECgFp5Point {
	// Use the precomputed window table
	digits := make([]int32, (319+WINDOW)/WINDOW)
	s.RecodeSigned(digits, int32(WINDOW))

	p := LookupVarTime(GENERATOR_WINDOW_AFFINE, digits[len(digits)-1]).ToPoint()
	for i := len(digits) - 2; i >= 0; i-- {
		p.SetMDouble(uint32(WINDOW))
		lookup := Lookup(GENERATOR_WINDOW_AFFINE, digits[i])
		p = p.AddAffine(lookup)
	}

	return p
}
