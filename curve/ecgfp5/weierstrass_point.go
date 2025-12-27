package ecgfp5

import (
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

// A curve point in short Weierstrass form (x, y). This is used by the in-circuit representation
type WeierstrassPoint struct {
	X     gFp5.Element
	Y     gFp5.Element
	IsInf bool
}

// WeierstrassPointJacobian represents a point in Jacobian coordinates (X:Y:Z).
// The affine point (x, y) corresponds to (X/Z^2, Y/Z^3) in Jacobian coordinates.
// This representation avoids expensive field divisions during point doubling and addition.
//
// Curve equation in Jacobian coordinates: Y^2 = X^3 + a*X*Z^4 + b*Z^6
// where a and b are the Weierstrass curve parameters.
type WeierstrassPointJacobian struct {
	X gFp5.Element
	Y gFp5.Element
	Z gFp5.Element
}

var (
	GENERATOR_WEIERSTRASS = WeierstrassPoint{
		X: gFp5.Element{
			g.GoldilocksField(11712523173042564207),
			g.GoldilocksField(14090224426659529053),
			g.GoldilocksField(13197813503519687414),
			g.GoldilocksField(16280770174934269299),
			g.GoldilocksField(15998333998318935536),
		},
		Y: gFp5.Element{
			g.GoldilocksField(14639054205878357578),
			g.GoldilocksField(17426078571020221072),
			g.GoldilocksField(2548978194165003307),
			g.GoldilocksField(8663895577921260088),
			g.GoldilocksField(9793640284382595140),
		},
		IsInf: false,
	}

	A_WEIERSTRASS = gFp5.Element{
		g.GoldilocksField(6148914689804861439),
		g.GoldilocksField(263),
		g.GoldilocksField(0),
		g.GoldilocksField(0),
		g.GoldilocksField(0),
	}

	NEUTRAL_WEIERSTRASS = WeierstrassPoint{
		X:     gFp5.FP5_ZERO,
		Y:     gFp5.FP5_ZERO,
		IsInf: true,
	}

	// GENERATOR_WEIERSTRASS_WINDOW is a precomputed window table for the Weierstrass generator.
	// This table contains points [0, G, 2G, 3G, ..., 15G] where G is the generator.
	// Window size = 4 bits (16 points), matching the window size used in MulAdd2.
	GENERATOR_WEIERSTRASS_WINDOW = []WeierstrassPoint{
		{ // 0G (neutral/infinity)
			X:     gFp5.FP5_ZERO,
			Y:     gFp5.FP5_ZERO,
			IsInf: true,
		},
		{ // 1G
			X: gFp5.Element{
				g.GoldilocksField(11712523173042564207),
				g.GoldilocksField(14090224426659529053),
				g.GoldilocksField(13197813503519687414),
				g.GoldilocksField(16280770174934269299),
				g.GoldilocksField(15998333998318935536),
			},
			Y: gFp5.Element{
				g.GoldilocksField(14639054205878357578),
				g.GoldilocksField(17426078571020221072),
				g.GoldilocksField(2548978194165003307),
				g.GoldilocksField(8663895577921260088),
				g.GoldilocksField(9793640284382595140),
			},
			IsInf: false,
		},
		{ // 2G
			X: gFp5.Element{
				g.GoldilocksField(4995993185466449924),
				g.GoldilocksField(8070450530368880624),
				g.GoldilocksField(0),
				g.GoldilocksField(0),
				g.GoldilocksField(0),
			},
			Y: gFp5.Element{
				g.GoldilocksField(2802119724609112643),
				g.GoldilocksField(15148449414430609716),
				g.GoldilocksField(8946200504603803264),
				g.GoldilocksField(5543440903273420636),
				g.GoldilocksField(6411036242926574856),
			},
			IsInf: false,
		},
		{ // 3G
			X: gFp5.Element{
				g.GoldilocksField(3584413360476155897),
				g.GoldilocksField(993598265149929043),
				g.GoldilocksField(9118536478120200325),
				g.GoldilocksField(4545548208597017001),
				g.GoldilocksField(16640886554632444604),
			},
			Y: gFp5.Element{
				g.GoldilocksField(6661501719066134017),
				g.GoldilocksField(7261582874957064446),
				g.GoldilocksField(6574521784608599777),
				g.GoldilocksField(12238551638203620304),
				g.GoldilocksField(17669239050955015918),
			},
			IsInf: false,
		},
		{ // 4G
			X: gFp5.Element{
				g.GoldilocksField(9282840482488766010),
				g.GoldilocksField(7670229098880965645),
				g.GoldilocksField(25756965035764252),
				g.GoldilocksField(10944135151651407527),
				g.GoldilocksField(15078023484304541970),
			},
			Y: gFp5.Element{
				g.GoldilocksField(15988355102403940463),
				g.GoldilocksField(1809048417599341589),
				g.GoldilocksField(9752679401098140192),
				g.GoldilocksField(1027677142437244621),
				g.GoldilocksField(14872299814084012259),
			},
			IsInf: false,
		},
		{ // 5G
			X: gFp5.Element{
				g.GoldilocksField(10037045936767333522),
				g.GoldilocksField(7212327770703274352),
				g.GoldilocksField(14197565700005564722),
				g.GoldilocksField(1466131595743240707),
				g.GoldilocksField(4503357798619727992),
			},
			Y: gFp5.Element{
				g.GoldilocksField(15228537545328408645),
				g.GoldilocksField(17691374870506013863),
				g.GoldilocksField(8726579212570326203),
				g.GoldilocksField(13461166066247559397),
				g.GoldilocksField(4831297304748274887),
			},
			IsInf: false,
		},
		{ // 6G
			X: gFp5.Element{
				g.GoldilocksField(332395843075433045),
				g.GoldilocksField(10665969052223652357),
				g.GoldilocksField(11920163782655219894),
				g.GoldilocksField(3755254504629367542),
				g.GoldilocksField(857907235975123551),
			},
			Y: gFp5.Element{
				g.GoldilocksField(10110871223324115440),
				g.GoldilocksField(6786631856288315347),
				g.GoldilocksField(18202356207216917090),
				g.GoldilocksField(9960519192610597361),
				g.GoldilocksField(16755099300489516367),
			},
			IsInf: false,
		},
		{ // 7G
			X: gFp5.Element{
				g.GoldilocksField(1402190480421472576),
				g.GoldilocksField(13676834587540684798),
				g.GoldilocksField(17321958444468468343),
				g.GoldilocksField(1669201366653940801),
				g.GoldilocksField(5982097004065554850),
			},
			Y: gFp5.Element{
				g.GoldilocksField(15760894881285235192),
				g.GoldilocksField(15255658932026822340),
				g.GoldilocksField(5186042200108657016),
				g.GoldilocksField(6691897350347039497),
				g.GoldilocksField(12315888321054861899),
			},
			IsInf: false,
		},
		{ // 8G
			X: gFp5.Element{
				g.GoldilocksField(2205929769302012371),
				g.GoldilocksField(17668483040439559877),
				g.GoldilocksField(13076178836696757062),
				g.GoldilocksField(2532936817859748627),
				g.GoldilocksField(17783524755602309127),
			},
			Y: gFp5.Element{
				g.GoldilocksField(14046467842125791992),
				g.GoldilocksField(10795235810481476126),
				g.GoldilocksField(2090567768530031361),
				g.GoldilocksField(11502138396108766053),
				g.GoldilocksField(1683624141157938622),
			},
			IsInf: false,
		},
		{ // 9G
			X: gFp5.Element{
				g.GoldilocksField(4243697618618426882),
				g.GoldilocksField(15029233049254488484),
				g.GoldilocksField(7287320105319691822),
				g.GoldilocksField(15271967690518258800),
				g.GoldilocksField(300801540855821790),
			},
			Y: gFp5.Element{
				g.GoldilocksField(13660058816890878826),
				g.GoldilocksField(10736847607882197421),
				g.GoldilocksField(11856578546981347999),
				g.GoldilocksField(3546545376256270329),
				g.GoldilocksField(12340884375561056853),
			},
			IsInf: false,
		},
		{ // 10G
			X: gFp5.Element{
				g.GoldilocksField(6151446031198676778),
				g.GoldilocksField(7222195312675198802),
				g.GoldilocksField(977026731260491588),
				g.GoldilocksField(323560339095679757),
				g.GoldilocksField(13494363605214619357),
			},
			Y: gFp5.Element{
				g.GoldilocksField(17562652790996657564),
				g.GoldilocksField(15358425015585963145),
				g.GoldilocksField(11024114727955300307),
				g.GoldilocksField(17103121416318729918),
				g.GoldilocksField(9745186746360435881),
			},
			IsInf: false,
		},
		{ // 11G
			X: gFp5.Element{
				g.GoldilocksField(2222284182771461234),
				g.GoldilocksField(7083547735719287414),
				g.GoldilocksField(13810817060940019759),
				g.GoldilocksField(11065758014246087634),
				g.GoldilocksField(16890879405831235919),
			},
			Y: gFp5.Element{
				g.GoldilocksField(16923613901246854100),
				g.GoldilocksField(1087971415524797897),
				g.GoldilocksField(9862001244277932157),
				g.GoldilocksField(950861443070919371),
				g.GoldilocksField(4749733880944624821),
			},
			IsInf: false,
		},
		{ // 12G
			X: gFp5.Element{
				g.GoldilocksField(4332019580543340814),
				g.GoldilocksField(6780596873437114286),
				g.GoldilocksField(463377514382282136),
				g.GoldilocksField(8670488912542116919),
				g.GoldilocksField(10249780939976682277),
			},
			Y: gFp5.Element{
				g.GoldilocksField(6736723456380141874),
				g.GoldilocksField(7433616997294738891),
				g.GoldilocksField(6506989996408978681),
				g.GoldilocksField(6488161771841026520),
				g.GoldilocksField(2794356282872202287),
			},
			IsInf: false,
		},
		{ // 13G
			X: gFp5.Element{
				g.GoldilocksField(4656402027835103656),
				g.GoldilocksField(10340241948432258175),
				g.GoldilocksField(1879862133467786213),
				g.GoldilocksField(4024699081225169417),
				g.GoldilocksField(15191118081497010869),
			},
			Y: gFp5.Element{
				g.GoldilocksField(4960090698839800784),
				g.GoldilocksField(14073145533440882315),
				g.GoldilocksField(5728054597904758200),
				g.GoldilocksField(3120306818043091805),
				g.GoldilocksField(17843967306504490387),
			},
			IsInf: false,
		},
		{ // 14G
			X: gFp5.Element{
				g.GoldilocksField(14328588549379046447),
				g.GoldilocksField(8393196260341919881),
				g.GoldilocksField(3167413324966371340),
				g.GoldilocksField(892362790877599229),
				g.GoldilocksField(7895697185980001523),
			},
			Y: gFp5.Element{
				g.GoldilocksField(13644331648162453509),
				g.GoldilocksField(2801150355068105324),
				g.GoldilocksField(6218544128987252500),
				g.GoldilocksField(16615509488709912385),
				g.GoldilocksField(1542389909367238639),
			},
			IsInf: false,
		},
		{ // 15G
			X: gFp5.Element{
				g.GoldilocksField(7303643336576901621),
				g.GoldilocksField(8532985260071751438),
				g.GoldilocksField(17499262162356878114),
				g.GoldilocksField(12120230959921439585),
				g.GoldilocksField(6980061276094786517),
			},
			Y: gFp5.Element{
				g.GoldilocksField(6573854693643977971),
				g.GoldilocksField(1189330380832395395),
				g.GoldilocksField(8517590411271342553),
				g.GoldilocksField(10808978523526506928),
				g.GoldilocksField(16428039417982239089),
			},
			IsInf: false,
		},
	}
)

func (p WeierstrassPoint) Equals(q WeierstrassPoint) bool {
	if p.IsInf && q.IsInf {
		return true
	}
	return gFp5.Equals(p.X, q.X) && gFp5.Equals(p.Y, q.Y)
}

func (p WeierstrassPoint) Encode() gFp5.Element {
	return gFp5.Div(p.Y, gFp5.Sub(gFp5.Div(A_ECgFp5Point, gFp5.FromUint64(3)), p.X))
}

func DecodeFp5AsWeierstrass(w gFp5.Element) (WeierstrassPoint, bool) {
	e := gFp5.Sub(gFp5.Square(w), A_ECgFp5Point)
	delta := gFp5.Sub(gFp5.Square(e), B_MUL4_ECgFp5Point)
	r, success := gFp5.CanonicalSqrt(delta)
	if !success {
		r = gFp5.FP5_ZERO
	}

	x1 := gFp5.Div(gFp5.Add(e, r), gFp5.FP5_TWO)
	x2 := gFp5.Div(gFp5.Sub(e, r), gFp5.FP5_TWO)

	x := x2
	x1Legendre := gFp5.Legendre(x1)
	if x1Legendre.ToCanonicalUint64() == 1 {
		x = x1
	}

	y := gFp5.Neg(gFp5.Mul(w, x))
	if success {
		x = gFp5.Add(x, gFp5.Div(A_ECgFp5Point, gFp5.FromUint64(3)))
	} else {
		x = gFp5.FP5_ZERO
	}

	isInf := !success

	// If w == 0 then this is in fact a success.
	if success || gFp5.IsZero(w) {
		return WeierstrassPoint{X: x, Y: y, IsInf: isInf}, true
	}
	return NEUTRAL_WEIERSTRASS, false
}

func (p WeierstrassPoint) Add(q WeierstrassPoint) WeierstrassPoint {
	if p.IsInf {
		return q
	}
	if q.IsInf {
		return p
	}

	x1, y1 := p.X, p.Y
	x2, y2 := q.X, q.Y

	// note: paper has a typo. sx == 1 when x1 != x2, not when x1 == x2
	xSame := gFp5.Equals(x1, x2)
	yDiff := !gFp5.Equals(y1, y2)

	var lambda0, lambda1 gFp5.Element
	if xSame {
		lambda0 = gFp5.Add(gFp5.Triple(gFp5.Square(x1)), A_WEIERSTRASS)
		lambda1 = gFp5.Double(y1)
	} else {
		lambda0 = gFp5.Sub(y2, y1)
		lambda1 = gFp5.Sub(x2, x1)
	}
	lambda := gFp5.Div(lambda0, lambda1)

	x3 := gFp5.Sub(gFp5.Sub(gFp5.Square(lambda), x1), x2)
	y3 := gFp5.Sub(gFp5.Mul(lambda, gFp5.Sub(x1, x3)), y1)

	return WeierstrassPoint{X: x3, Y: y3, IsInf: xSame && yDiff}
}

func (p WeierstrassPoint) Double() WeierstrassPoint {
	x := p.X
	y := p.Y
	is_inf := p.IsInf

	if is_inf {
		return p
	}

	lambda0 := gFp5.Square(x)
	lambda0 = gFp5.Triple(lambda0)
	lambda0 = gFp5.Add(lambda0, A_WEIERSTRASS)

	lambda1 := gFp5.Double(y)

	lambda := gFp5.Div(lambda0, lambda1)

	x2 := gFp5.Square(lambda)
	two_x := gFp5.Double(x)
	x2 = gFp5.Sub(x2, two_x)

	y2 := gFp5.Sub(x, x2)
	y2 = gFp5.Mul(lambda, y2)
	y2 = gFp5.Sub(y2, y)

	return WeierstrassPoint{X: x2, Y: y2, IsInf: is_inf}
}

// ToJacobian converts an affine Weierstrass point to Jacobian coordinates.
// Affine (x, y) -> Jacobian (x, y, 1)
func (p WeierstrassPoint) ToJacobian() WeierstrassPointJacobian {
	if p.IsInf {
		// Point at infinity: (1, 1, 0)
		return WeierstrassPointJacobian{
			X: gFp5.FP5_ONE,
			Y: gFp5.FP5_ONE,
			Z: gFp5.FP5_ZERO,
		}
	}
	return WeierstrassPointJacobian{
		X: p.X,
		Y: p.Y,
		Z: gFp5.FP5_ONE,
	}
}

// ToAffine converts a Jacobian point back to affine coordinates.
// Jacobian (X, Y, Z) -> Affine (X/Z^2, Y/Z^3)
func (p WeierstrassPointJacobian) ToAffine() WeierstrassPoint {
	if gFp5.IsZero(p.Z) {
		return NEUTRAL_WEIERSTRASS
	}

	zInv := gFp5.InverseOrZero(p.Z) // 1/Z
	zInv2 := gFp5.Square(zInv)      // 1/Z^2
	zInv3 := gFp5.Mul(zInv2, zInv)  // 1/Z^3

	return WeierstrassPoint{
		X:     gFp5.Mul(p.X, zInv2),
		Y:     gFp5.Mul(p.Y, zInv3),
		IsInf: false,
	}
}

// IsInfinity checks if the Jacobian point is the point at infinity.
func (p WeierstrassPointJacobian) IsInfinity() bool {
	return gFp5.IsZero(p.Z)
}

// DoubleJacobian performs point doubling in Jacobian coordinates.
// This is faster than affine doubling as it avoids field divisions.
//
// Algorithm: dbl-2007-bl from https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
// Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*4 + 1*8
func (p WeierstrassPointJacobian) DoubleJacobian() WeierstrassPointJacobian {
	if p.IsInfinity() {
		return p
	}

	// XX = X^2
	XX := gFp5.Square(p.X)
	// YY = Y^2
	YY := gFp5.Square(p.Y)
	// YYYY = YY^2
	YYYY := gFp5.Square(YY)
	// ZZ = Z^2
	ZZ := gFp5.Square(p.Z)

	// S = 2*((X+YY)^2-XX-YYYY)
	tmp := gFp5.Add(p.X, YY)
	tmp = gFp5.Square(tmp)
	tmp = gFp5.Sub(tmp, XX)
	tmp = gFp5.Sub(tmp, YYYY)
	S := gFp5.Double(tmp)

	// M = 3*XX + a*ZZ^2
	M := gFp5.Triple(XX)
	ZZZZ := gFp5.Square(ZZ)
	M = gFp5.Add(M, gFp5.Mul(A_WEIERSTRASS, ZZZZ))

	// T = M^2 - 2*S
	T := gFp5.Square(M)
	T = gFp5.Sub(T, gFp5.Double(S))

	// X' = T
	X3 := T

	// Y' = M*(S-T) - 8*YYYY
	Y3 := gFp5.Sub(S, T)
	Y3 = gFp5.Mul(M, Y3)
	eight_YYYY := gFp5.Double(gFp5.Double(gFp5.Double(YYYY)))
	Y3 = gFp5.Sub(Y3, eight_YYYY)

	// Z' = (Y+Z)^2 - YY - ZZ
	Z3 := gFp5.Add(p.Y, p.Z)
	Z3 = gFp5.Square(Z3)
	Z3 = gFp5.Sub(Z3, YY)
	Z3 = gFp5.Sub(Z3, ZZ)

	return WeierstrassPointJacobian{X: X3, Y: Y3, Z: Z3}
}

// AddMixed performs mixed addition: Jacobian + Affine -> Jacobian.
// This is more efficient than full Jacobian addition when one point is in affine form.
//
// Algorithm: madd-2007-bl from https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
// Cost: 7M + 4S + 9add + 3*2 + 1*4
func (p WeierstrassPointJacobian) AddMixed(q WeierstrassPoint) WeierstrassPointJacobian {
	if p.IsInfinity() {
		return q.ToJacobian()
	}
	if q.IsInf {
		return p
	}

	// Z1Z1 = Z1^2
	Z1Z1 := gFp5.Square(p.Z)

	// U2 = X2*Z1Z1
	U2 := gFp5.Mul(q.X, Z1Z1)

	// S2 = Y2*Z1*Z1Z1
	S2 := gFp5.Mul(q.Y, p.Z)
	S2 = gFp5.Mul(S2, Z1Z1)

	// H = U2 - X1
	H := gFp5.Sub(U2, p.X)
	// HH = H^2
	HH := gFp5.Square(H)
	// I = 4*HH
	I := gFp5.Double(gFp5.Double(HH))
	// J = H*I
	J := gFp5.Mul(H, I)

	// r = 2*(S2 - Y1)
	r := gFp5.Sub(S2, p.Y)
	r = gFp5.Double(r)

	// V = X1*I
	V := gFp5.Mul(p.X, I)

	// X3 = r^2 - J - 2*V
	X3 := gFp5.Square(r)
	X3 = gFp5.Sub(X3, J)
	X3 = gFp5.Sub(X3, gFp5.Double(V))

	// Y3 = r*(V - X3) - 2*Y1*J
	Y3 := gFp5.Sub(V, X3)
	Y3 = gFp5.Mul(r, Y3)
	tmp := gFp5.Mul(p.Y, J)
	Y3 = gFp5.Sub(Y3, gFp5.Double(tmp))

	// Z3 = (Z1 + H)^2 - Z1Z1 - HH
	Z3 := gFp5.Add(p.Z, H)
	Z3 = gFp5.Square(Z3)
	Z3 = gFp5.Sub(Z3, Z1Z1)
	Z3 = gFp5.Sub(Z3, HH)

	// Check if points were equal (H = 0)
	if gFp5.IsZero(H) {
		// Points are equal, use doubling
		return p.DoubleJacobian()
	}

	return WeierstrassPointJacobian{X: X3, Y: Y3, Z: Z3}
}

func (p WeierstrassPoint) PrecomputeWindow(windowBits uint32) []WeierstrassPoint {
	if windowBits < 2 {
		panic("windowBits in PrecomputeWindow for WeierstrassPoint must be at least 2")
	}
	multiples := []WeierstrassPoint{NEUTRAL_WEIERSTRASS, p, p.Double()}
	for i := 3; i < 1<<windowBits; i++ {
		multiples = append(multiples, p.Add(multiples[len(multiples)-1]))
	}
	return multiples
}

func MulAdd2(a, b WeierstrassPoint, scalarA, scalarB ECgFp5Scalar) WeierstrassPoint {
	aWindow := a.PrecomputeWindow(4)
	aFourBitLimbs := scalarA.SplitTo4BitLimbs()

	bWindow := b.PrecomputeWindow(4)
	bFourBitLimbs := scalarB.SplitTo4BitLimbs()

	numLimbs := len(aFourBitLimbs)

	res := aWindow[aFourBitLimbs[numLimbs-1]].Add(bWindow[bFourBitLimbs[numLimbs-1]])
	for i := numLimbs - 2; i >= 0; i-- {
		for j := 0; j < 4; j++ {
			res = res.Double()
		}
		res = res.Add(aWindow[aFourBitLimbs[i]].Add(bWindow[bFourBitLimbs[i]]))
	}
	return res
}

// MulAdd2WithGenJacobian computes scalarA * G + scalarB * b using Jacobian coordinates.
// This avoids expensive field divisions by keeping the accumulator in Jacobian form throughout
// the computation, only converting back to affine at the end.
//
// Algorithm: Jacobian-optimized dual-scalar multiplication with mixed addition.
func MulAdd2WithGenJacobian(b WeierstrassPoint, scalarA, scalarB ECgFp5Scalar) WeierstrassPoint {
	// Use precomputed table for generator, compute window for b
	bWindow := b.PrecomputeWindow(4)

	// Split both scalars into 4-bit limbs (80 limbs each for 320-bit scalars)
	aFourBitLimbs := scalarA.SplitTo4BitLimbs()
	bFourBitLimbs := scalarB.SplitTo4BitLimbs()

	numLimbs := len(aFourBitLimbs)

	// Initialize result in Jacobian coordinates with the most significant limbs
	// Convert first point to Jacobian, then use mixed addition with second point
	res := GENERATOR_WEIERSTRASS_WINDOW[aFourBitLimbs[numLimbs-1]].ToJacobian()
	res = res.AddMixed(bWindow[bFourBitLimbs[numLimbs-1]])

	// Process remaining limbs from most to least significant
	for i := numLimbs - 2; i >= 0; i-- {
		// Double the accumulator 4 times in Jacobian coordinates (much faster than affine)
		for j := 0; j < 4; j++ {
			res = res.DoubleJacobian()
		}

		// Add the next window using mixed addition
		// First add the generator contribution, then add the b contribution
		res = res.AddMixed(GENERATOR_WEIERSTRASS_WINDOW[aFourBitLimbs[i]])
		res = res.AddMixed(bWindow[bFourBitLimbs[i]])
	}

	// Convert final result back to affine coordinates
	return res.ToAffine()
}
