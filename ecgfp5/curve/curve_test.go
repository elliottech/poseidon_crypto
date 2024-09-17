package ecgfp5

import (
	"math/big"
	"testing"

	config "github.com/consensys/gnark-crypto/field/generator/config"
	fp5 "github.com/elliottech/poseidon_crypto/ecgfp5/base_field"
	sf "github.com/elliottech/poseidon_crypto/ecgfp5/scalar_field"
)

func TestEncode(t *testing.T) {
	point := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			8219099146870311261,
			1751466925979295147,
			7427996218561204331,
			5499363376829590386,
			17146362437196146248,
		),
		z: fp5.Uint64ArrayToFp5(
			9697849239028047855,
			5846309906783017685,
			10545493423738651463,
			2054382452661947581,
			7470471124463677860,
		),
		u: fp5.Uint64ArrayToFp5(
			2901139745109740356,
			15850005224840060392,
			3464972059371886732,
			15264046134718393739,
			9208307769190416697,
		),
		t: fp5.Uint64ArrayToFp5(
			4691886900801030369,
			14793814721360336872,
			14452533794393275351,
			3652664841353278369,
			4894903405053011144,
		),
	}

	encoded := point.Encode()
	expected := [5]uint64{
		11698180777452980608,
		17225201015770513568,
		2048901991804183462,
		12372738397545947475,
		13773458998102781339,
	}

	for i := 0; i < 5; i++ {
		if encoded[i].Uint64() != expected[i] {
			t.Fatalf("Encode: Expected limb %d to be %x, but got %x", i, expected[i], encoded[i].Uint64())
		}
	}
}

func TestNeg(t *testing.T) {
	point := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			8219099146870311261,
			1751466925979295147,
			7427996218561204331,
			5499363376829590386,
			17146362437196146248,
		),
		z: fp5.Uint64ArrayToFp5(
			9697849239028047855,
			5846309906783017685,
			10545493423738651463,
			2054382452661947581,
			7470471124463677860,
		),
		u: fp5.Uint64ArrayToFp5(
			2901139745109740356,
			15850005224840060392,
			3464972059371886732,
			15264046134718393739,
			9208307769190416697,
		),
		t: fp5.Uint64ArrayToFp5(
			4691886900801030369,
			14793814721360336872,
			14452533794393275351,
			3652664841353278369,
			4894903405053011144,
		),
	}

	if !point.Add(point.Neg()).IsNeutral() {
		t.Fatalf("Neg: Expected point to be neutral, but got %v", point)
	}
}

func TestAdd(t *testing.T) {
	a := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			6598630105941849408,
			1859688128646629097,
			17294281002801957241,
			14913942670710662913,
			10914775081841233526,
		),
		z: fp5.Uint64ArrayToFp5(
			5768577777379827814,
			1670898087452303151,
			149395834104961848,
			10215820955974196778,
			12220782198555404872,
		),
		u: fp5.Uint64ArrayToFp5(
			8222038236695704789,
			7213480445243459136,
			12261234501547702974,
			16991275954331307770,
			13268460265795104226,
		),
		t: fp5.Uint64ArrayToFp5(
			13156365331881093743,
			1228071764139434927,
			12765463901361527883,
			708052950516284594,
			2091843551884526165,
		),
	}
	b := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			12601734882931894875,
			8567855799503419472,
			10972305351681971938,
			10379631676278166937,
			14389591363895654229,
		),
		z: fp5.Uint64ArrayToFp5(
			7813541982583063146,
			5326831614826269688,
			674248499729254112,
			6075985944329658642,
			4509699573536613779,
		),
		u: fp5.Uint64ArrayToFp5(
			18059989919748409029,
			4197498098921379230,
			8619952860870967373,
			4771999616217997413,
			18075221430709764120,
		),
		t: fp5.Uint64ArrayToFp5(
			14710659590503370792,
			13425914726164358056,
			15027060927285830507,
			17361235517359536873,
			1738580404337116326,
		),
	}

	c := a.Add(b)
	expectedX := [5]uint64{
		2091129225269376836,
		9405624996184206232,
		3901502046808513894,
		17705383837126423407,
		9421907235969101682,
	}
	expectedZ := [5]uint64{
		5829667370837222420,
		11237187675958101957,
		1807194474973812009,
		15957008761806494676,
		16213732873017933964,
	}
	expectedU := [5]uint64{
		17708743171457526148,
		7256550674326982355,
		4002326258245501339,
		5920160861215573533,
		6620019694807786845,
	}
	expectedT := [5]uint64{
		8994820555257560065,
		3865139429644955984,
		222111198601608498,
		5080186348564946426,
		910404641634132272,
	}

	for i := 0; i < 5; i++ {
		if c.x[i].Uint64() != expectedX[i] {
			t.Fatalf("Add: Expected c.x[%d] to be %x, but got %x", i, expectedX[i], c.x[i].Uint64())
		}
		if c.z[i].Uint64() != expectedZ[i] {
			t.Fatalf("Add: Expected c.z[%d] to be %x, but got %x", i, expectedZ[i], c.z[i].Uint64())
		}
		if c.u[i].Uint64() != expectedU[i] {
			t.Fatalf("Add: Expected c.u[%d] to be %x, but got %x", i, expectedU[i], c.u[i].Uint64())
		}
		if c.t[i].Uint64() != expectedT[i] {
			t.Fatalf("Add: Expected c.t[%d] to be %x, but got %x", i, expectedT[i], c.t[i].Uint64())
		}
	}
}

func TestDouble(t *testing.T) {
	point := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			2091129225269376836,
			9405624996184206232,
			3901502046808513894,
			17705383837126423407,
			9421907235969101682,
		),
		z: fp5.Uint64ArrayToFp5(
			5829667370837222420,
			11237187675958101957,
			1807194474973812009,
			15957008761806494676,
			16213732873017933964,
		),
		u: fp5.Uint64ArrayToFp5(
			17708743171457526148,
			7256550674326982355,
			4002326258245501339,
			5920160861215573533,
			6620019694807786845,
		),
		t: fp5.Uint64ArrayToFp5(
			8994820555257560065,
			3865139429644955984,
			222111198601608498,
			5080186348564946426,
			910404641634132272,
		),
	}

	point.SetDouble()

	expected := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			17841786997947248136,
			6795260826091178564,
			17040031878202156690,
			17452087436690889171,
			3812897545652133031,
		),
		z: fp5.Uint64ArrayToFp5(
			11020726505488657009,
			1091762938184204841,
			4410430720558219763,
			4363379995258938087,
			13994951776877072532,
		),
		u: fp5.Uint64ArrayToFp5(
			9442293568698796309,
			11629160327398360345,
			1740514571594869537,
			1168842489343203981,
			5537908027019165338,
		),
		t: fp5.Uint64ArrayToFp5(
			14684689082562511355,
			9795998745315395469,
			11643703245601798489,
			9164627329631566444,
			14463660178939261073,
		),
	}

	if !point.Equals(expected) {
		t.Fatalf("Double: Expected %v, but got %v", expected, point)
	}
}

func TestMDouble(t *testing.T) {
	point := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			2091129225269376836,
			9405624996184206232,
			3901502046808513894,
			17705383837126423407,
			9421907235969101682,
		),
		z: fp5.Uint64ArrayToFp5(
			5829667370837222420,
			11237187675958101957,
			1807194474973812009,
			15957008761806494676,
			16213732873017933964,
		),
		u: fp5.Uint64ArrayToFp5(
			17708743171457526148,
			7256550674326982355,
			4002326258245501339,
			5920160861215573533,
			6620019694807786845,
		),
		t: fp5.Uint64ArrayToFp5(
			8994820555257560065,
			3865139429644955984,
			222111198601608498,
			5080186348564946426,
			910404641634132272,
		),
	}

	point.SetMDouble(35)

	expectedDouble := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			5913227576680434070,
			7982325190863789325,
			996872074809285515,
			13250982632111464330,
			12283818425722177845,
		),
		z: fp5.Uint64ArrayToFp5(
			11109298682748378964,
			10740549672355474144,
			8575099619865922741,
			7569981484002838575,
			8334331076253814622,
		),
		u: fp5.Uint64ArrayToFp5(
			2081907484718321711,
			2871920152785433924,
			16079876071712475691,
			12304725828108396137,
			5091453661983356959,
		),
		t: fp5.Uint64ArrayToFp5(
			16573251802693900474,
			18328109793157914401,
			5893679867263862011,
			8243272292726266031,
			9080497760919830159,
		),
	}

	for i := 0; i < 5; i++ {
		if point.x[i].Uint64() != expectedDouble.x[i].Uint64() {
			t.Fatalf("MDouble: Expected point.x[%d] to be %x, but got %x", i, expectedDouble.x[i].Uint64(), point.x[i].Uint64())
		}
		if point.z[i].Uint64() != expectedDouble.z[i].Uint64() {
			t.Fatalf("MDouble: Expected point.z[%d] to be %x, but got %x", i, expectedDouble.z[i].Uint64(), point.z[i].Uint64())
		}
		if point.u[i].Uint64() != expectedDouble.u[i].Uint64() {
			t.Fatalf("MDouble: Expected point.u[%d] to be %x, but got %x", i, expectedDouble.u[i].Uint64(), point.u[i].Uint64())
		}
		if point.t[i].Uint64() != expectedDouble.t[i].Uint64() {
			t.Fatalf("MDouble: Expected point.t[%d] to be %x, but got %x", i, expectedDouble.t[i].Uint64(), point.t[i].Uint64())
		}
	}
}

func TestToAffineAndLookup(t *testing.T) {
	point := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			6641938805100417611,
			4637251792794046952,
			9680215716198734904,
			7124887799004433445,
			3695446893682682870,
		),
		z: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		u: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		t: fp5.Uint64ArrayToFp5(
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		),
	}

	tab1 := make([]ECgFp5Point, 8)
	tab1[0] = point.Double()
	for i := 1; i < len(tab1); i++ {
		tab1[i] = tab1[0].Add(tab1[i-1])
	}

	for n := 1; n <= len(tab1); n++ {
		tab2 := BatchToAffine(tab1)
		for i := 0; i < n; i++ {
			if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i].z, tab2[i].x), tab1[i].x) {
				t.Fail()
			}
			if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i].t, tab2[i].u), tab1[i].u) {
				t.Fail()
			}
		}
	}

	// Test lookup
	win := BatchToAffine(tab1)
	p1Affine := Lookup(win, 72)

	if !fp5.Fp5Equals(p1Affine.x, fp5.FP5_ZERO) {
		t.Fatalf("Lookup failed for 72: expected %v, got %v", fp5.FP5_ZERO, p1Affine.x)
	}
	if !fp5.Fp5Equals(p1Affine.u, fp5.FP5_ZERO) {
		t.Fatalf("Lookup failed for 72: expected %v, got %v", fp5.FP5_ZERO, p1Affine.u)
	}

	for i := 1; i <= 8; i++ {
		p2Affine := Lookup(win, int32(i))
		if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i-1].z, p2Affine.x), tab1[i-1].x) {
			t.Fatalf("Lookup failed for %d: expected %v, got %v", i, tab1[i-1].x, fp5.Fp5Mul(tab1[i-1].z, p2Affine.x))
		}
		if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i-1].t, p2Affine.u), tab1[i-1].u) {
			t.Fatalf("Lookup failed for %d: expected %v, got %v", i, tab1[i-1].u, fp5.Fp5Mul(tab1[i-1].t, p2Affine.u))
		}

		p3Affine := Lookup(win, int32(-i))
		if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i-1].z, p3Affine.x), tab1[i-1].x) {
			t.Fatalf("Lookup failed for -%d: expected %v, got %v", i, tab1[i-1].x, fp5.Fp5Mul(tab1[i-1].z, p3Affine.x))
		}
		if !fp5.Fp5Equals(fp5.Fp5Mul(tab1[i-1].t, p3Affine.u), fp5.Fp5Neg(tab1[i-1].u)) {
			t.Fatalf("Lookup failed for -%d: expected %v, got %v", i, fp5.Fp5Neg(tab1[i-1].u), fp5.Fp5Mul(tab1[i-1].t, p3Affine.u))
		}
	}
}

func TestScalarMul(t *testing.T) {
	p1 := ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			16818074783491816710,
			5830279414330569119,
			3449083115922675783,
			1268145320872323641,
			12614816166275380125,
		),
		z: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		u: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		t: fp5.Uint64ArrayToFp5(
			7534507442095725921,
			16658460051907528927,
			12417574136563175256,
			2750788641759288856,
			620002843272906439,
		),
	}

	if !p1.Mul(&sf.ECgFp5Scalar{
		Value: [5]big.Int{
			*new(big.Int).SetUint64(996458928865875995),
			*new(big.Int).SetUint64(7368213710557165165),
			*new(big.Int).SetUint64(8553572641065079816),
			*new(big.Int).SetUint64(15282443801767955752),
			*new(big.Int).SetUint64(251150557732720826),
		},
	}).Equals(ECgFp5Point{
		x: fp5.Uint64ArrayToFp5(
			16885333682092300432,
			5595343485914691669,
			13188593663496831978,
			10414629856394645794,
			5668658507670629815,
		),
		z: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		u: fp5.Uint64ArrayToFp5(
			1,
			0,
			0,
			0,
			0,
		),
		t: fp5.Uint64ArrayToFp5(
			9486104512504676657,
			14312981644741144668,
			5159846406177847664,
			15978863787033795628,
			3249948839313771192,
		),
	}) {
		t.Fail()
	}
}

func testVectors() [8]config.Element {
	// P0 is neutral of G.
	// P1 is a random point in G (encoded as w1)
	// P2 = e*P1 in G (encoded as w2)
	// P3 = P1 + P2 (in G) (encoded as w3)
	// P4 = 2*P1 (in G) (encoded as w4)
	// P5 = 2*P2 (in G) (encoded as w5)
	// P6 = 2*P1 + P2 (in G) (encoded as w6)
	// P7 = P1 + 2*P2 (in G) (encoded as w7)

	w0 := fp5.Fp5DeepCopy(fp5.FP5_ZERO)
	w1 := config.Element{
		*new(big.Int).SetUint64(12539254003028696409),
		*new(big.Int).SetUint64(15524144070600887654),
		*new(big.Int).SetUint64(15092036948424041984),
		*new(big.Int).SetUint64(11398871370327264211),
		*new(big.Int).SetUint64(10958391180505708567),
	}
	w2 := config.Element{
		*new(big.Int).SetUint64(11001943240060308920),
		*new(big.Int).SetUint64(17075173755187928434),
		*new(big.Int).SetUint64(3940989555384655766),
		*new(big.Int).SetUint64(15017795574860011099),
		*new(big.Int).SetUint64(5548543797011402287),
	}
	w3 := config.Element{
		*new(big.Int).SetUint64(246872606398642312),
		*new(big.Int).SetUint64(4900963247917836450),
		*new(big.Int).SetUint64(7327006728177203977),
		*new(big.Int).SetUint64(13945036888436667069),
		*new(big.Int).SetUint64(3062018119121328861),
	}
	w4 := config.Element{
		*new(big.Int).SetUint64(8058035104653144162),
		*new(big.Int).SetUint64(16041715455419993830),
		*new(big.Int).SetUint64(7448530016070824199),
		*new(big.Int).SetUint64(11253639182222911208),
		*new(big.Int).SetUint64(6228757819849640866),
	}
	w5 := config.Element{
		*new(big.Int).SetUint64(10523134687509281194),
		*new(big.Int).SetUint64(11148711503117769087),
		*new(big.Int).SetUint64(9056499921957594891),
		*new(big.Int).SetUint64(13016664454465495026),
		*new(big.Int).SetUint64(16494247923890248266),
	}
	w6 := config.Element{
		*new(big.Int).SetUint64(12173306542237620),
		*new(big.Int).SetUint64(6587231965341539782),
		*new(big.Int).SetUint64(17027985748515888117),
		*new(big.Int).SetUint64(17194831817613584995),
		*new(big.Int).SetUint64(10056734072351459010),
	}
	w7 := config.Element{
		*new(big.Int).SetUint64(9420857400785992333),
		*new(big.Int).SetUint64(4695934009314206363),
		*new(big.Int).SetUint64(14471922162341187302),
		*new(big.Int).SetUint64(13395190104221781928),
		*new(big.Int).SetUint64(16359223219913018041),
	}

	return [8]config.Element{w0, w1, w2, w3, w4, w5, w6, w7}
}

func TestBasicOps(t *testing.T) {
	// Values that should not decode successfully.
	bww := [6]config.Element{
		{
			*new(big.Int).SetUint64(13557832913345268708),
			*new(big.Int).SetUint64(15669280705791538619),
			*new(big.Int).SetUint64(8534654657267986396),
			*new(big.Int).SetUint64(12533218303838131749),
			*new(big.Int).SetUint64(5058070698878426028),
		},
		{
			*new(big.Int).SetUint64(135036726621282077),
			*new(big.Int).SetUint64(17283229938160287622),
			*new(big.Int).SetUint64(13113167081889323961),
			*new(big.Int).SetUint64(1653240450380825271),
			*new(big.Int).SetUint64(520025869628727862),
		},
		{
			*new(big.Int).SetUint64(6727960962624180771),
			*new(big.Int).SetUint64(17240764188796091916),
			*new(big.Int).SetUint64(3954717247028503753),
			*new(big.Int).SetUint64(1002781561619501488),
			*new(big.Int).SetUint64(4295357288570643789),
		},
		{
			*new(big.Int).SetUint64(4578929270179684956),
			*new(big.Int).SetUint64(3866930513245945042),
			*new(big.Int).SetUint64(7662265318638150701),
			*new(big.Int).SetUint64(9503686272550423634),
			*new(big.Int).SetUint64(12241691520798116285),
		},
		{
			*new(big.Int).SetUint64(16890297404904119082),
			*new(big.Int).SetUint64(6169724643582733633),
			*new(big.Int).SetUint64(9725973298012340311),
			*new(big.Int).SetUint64(5977049210035183790),
			*new(big.Int).SetUint64(11379332130141664883),
		},
		{
			*new(big.Int).SetUint64(13777379982711219130),
			*new(big.Int).SetUint64(14715168412651470168),
			*new(big.Int).SetUint64(17942199593791635585),
			*new(big.Int).SetUint64(6188824164976547520),
			*new(big.Int).SetUint64(15461469634034461986),
		},
	}
	for _, w := range bww {
		if Validate(w) {
			t.Fatalf("Validation should fail for element: %v", w)
		}
		if _, success := Decode(w); success {
			t.Fatalf("Decoding should fail for element: %v", w)
		}
	}

	vectors := testVectors()
	for _, w := range vectors {
		if !Validate(w) {
			t.Fatalf("Validation failed for element: %v", w)
		}
	}

	p0, s := Decode(vectors[0])
	if !s {
		t.Fatalf("Decoding failed for p0")
	}
	p1, s := Decode(vectors[1])
	if !s {
		t.Fatalf("Decoding failed for p1")
	}
	p2, s := Decode(vectors[2])
	if !s {
		t.Fatalf("Decoding failed for p2")
	}
	p3, s := Decode(vectors[3])
	if !s {
		t.Fatalf("Decoding failed for p3")
	}
	p4, s := Decode(vectors[4])
	if !s {
		t.Fatalf("Decoding failed for p4")
	}
	p5, s := Decode(vectors[5])
	if !s {
		t.Fatalf("Decoding failed for p5")
	}
	p6, s := Decode(vectors[6])
	if !s {
		t.Fatalf("Decoding failed for p6")
	}
	p7, s := Decode(vectors[7])
	if !s {
		t.Fatalf("Decoding failed for p7")
	}

	if !p0.IsNeutral() {
		t.Fatalf("p0 should be neutral")
	}
	if p1.IsNeutral() || p2.IsNeutral() || p3.IsNeutral() || p4.IsNeutral() || p5.IsNeutral() || p6.IsNeutral() || p7.IsNeutral() {
		t.Fatalf("p1...p7 should not be neutral")
	}
	if !p0.Equals(p0) || !p1.Equals(p1) || p0.Equals(p1) || p1.Equals(p0) || p1.Equals(p2) {
		t.Fatalf("Equality checks failed")
	}

	if !fp5.Fp5Equals(p0.Encode(), vectors[0]) || !fp5.Fp5Equals(p1.Encode(), vectors[1]) || !fp5.Fp5Equals(p2.Encode(), vectors[2]) || !fp5.Fp5Equals(p3.Encode(), vectors[3]) || !fp5.Fp5Equals(p4.Encode(), vectors[4]) || !fp5.Fp5Equals(p5.Encode(), vectors[5]) || !fp5.Fp5Equals(p6.Encode(), vectors[6]) || !fp5.Fp5Equals(p7.Encode(), vectors[7]) {
		t.Fatalf("Encoding checks failed")
	}

	if !fp5.Fp5Equals(p1.Add(p2).Encode(), vectors[3]) || !fp5.Fp5Equals(p1.Add(p1).Encode(), vectors[4]) || !fp5.Fp5Equals(p2.Double().Encode(), vectors[5]) || !fp5.Fp5Equals(p1.Double().Add(p2).Encode(), vectors[6]) || !fp5.Fp5Equals(p1.Add(p2).Add(p2).Encode(), vectors[7]) {
		t.Fatalf("Addition and doubling checks failed")
	}

	if !fp5.Fp5Equals(p0.Double().Encode(), fp5.FP5_ZERO) || !fp5.Fp5Equals(p0.Add(p0).Encode(), fp5.FP5_ZERO) || !fp5.Fp5Equals(p0.Add(p1).Encode(), vectors[1]) || !fp5.Fp5Equals(p1.Add(p0).Encode(), vectors[1]) {
		t.Fatalf("Zero addition and doubling checks failed")
	}

	for i := uint32(0); i < 10; i++ {
		q1 := p1.MDouble(i)
		q2 := p1.DeepCopy()
		for j := uint32(0); j < i; j++ {
			q2 = q2.Double()
		}
		if !q1.Equals(q2) {
			t.Fatalf("MDouble check failed for i=%d", i)
		}
	}

	p2Affine := AffinePoint{
		x: fp5.Fp5Mul(p2.x, fp5.Fp5InverseOrZero(p2.z)),
		u: fp5.Fp5Mul(p2.u, fp5.Fp5InverseOrZero(p2.t)),
	}
	if !p1.AddAffine(p2Affine).Equals(p1.Add(p2)) {
		t.Fatalf("Affine addition check failed")
	}
}

func TestDecodeAsWeierstrass(t *testing.T) {
	vectors := testVectors()

	p0Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(6148914689804861440),
			*new(big.Int).SetUint64(0),
			*new(big.Int).SetUint64(0),
			*new(big.Int).SetUint64(0),
			*new(big.Int).SetUint64(0),
		},
		Y:     fp5.FP5_ZERO,
		IsInf: true,
	}
	p0, success := DecodeAsWeierstrass(vectors[0])
	if !success {
		t.Fatalf("w0 should successfully decode")
	}
	if !p0.Equals(p0Expected) {
		t.Fatalf("p0 does not match expected value")
	}

	p1Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(7887569478949190020),
			*new(big.Int).SetUint64(11586418388990522938),
			*new(big.Int).SetUint64(13676447623055915878),
			*new(big.Int).SetUint64(5945168854809921881),
			*new(big.Int).SetUint64(16291886980725359814),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(7556511254681645335),
			*new(big.Int).SetUint64(17611929280367064763),
			*new(big.Int).SetUint64(9410908488141053806),
			*new(big.Int).SetUint64(11351540010214108766),
			*new(big.Int).SetUint64(4846226015431423207),
		},
		IsInf: false,
	}
	p1, success := DecodeAsWeierstrass(vectors[1])
	if !success {
		t.Fatalf("w1 should successfully decode")
	}
	if !p1.Equals(p1Expected) {
		t.Fatalf("p1 does not match expected value")
	}

	p2Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(11231216549003316587),
			*new(big.Int).SetUint64(17312878720767554617),
			*new(big.Int).SetUint64(5614299211412933260),
			*new(big.Int).SetUint64(2256199868722187419),
			*new(big.Int).SetUint64(14229722163821261464),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(11740132275098847128),
			*new(big.Int).SetUint64(18250632754932612452),
			*new(big.Int).SetUint64(6988589976052950880),
			*new(big.Int).SetUint64(13612651576898186637),
			*new(big.Int).SetUint64(16040252831112129154),
		},
		IsInf: false,
	}
	p2, success := DecodeAsWeierstrass(vectors[2])
	if !success {
		t.Fatalf("w2 should successfully decode")
	}
	if !p2.Equals(p2Expected) {
		t.Fatalf("p2 does not match expected value")
	}

	p3Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(567456832026211571),
			*new(big.Int).SetUint64(6401615614732569674),
			*new(big.Int).SetUint64(7303004494044972219),
			*new(big.Int).SetUint64(4332356015409706768),
			*new(big.Int).SetUint64(4663512734739523713),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(13838792670272995877),
			*new(big.Int).SetUint64(11742686110311813089),
			*new(big.Int).SetUint64(17972799251722850796),
			*new(big.Int).SetUint64(8534723577625674697),
			*new(big.Int).SetUint64(3138422718990519265),
		},
		IsInf: false,
	}
	p3, success := DecodeAsWeierstrass(vectors[3])
	if !success {
		t.Fatalf("w3 should successfully decode")
	}
	if !p3.Equals(p3Expected) {
		t.Fatalf("p3 does not match expected value")
	}

	p4Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(2626390539619063455),
			*new(big.Int).SetUint64(3069873143820007175),
			*new(big.Int).SetUint64(16481805966921623903),
			*new(big.Int).SetUint64(2169403494164322467),
			*new(big.Int).SetUint64(15849876939764656634),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(8052493994140007067),
			*new(big.Int).SetUint64(12476750341447220703),
			*new(big.Int).SetUint64(7297584762312352412),
			*new(big.Int).SetUint64(4456043296886321460),
			*new(big.Int).SetUint64(17416054515469523789),
		},
		IsInf: false,
	}
	p4, success := DecodeAsWeierstrass(vectors[4])
	if !success {
		t.Fatalf("w4 should successfully decode")
	}
	if !p4.Equals(p4Expected) {
		t.Fatalf("p4 does not match expected value")
	}

	p5Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(3378618241466923429),
			*new(big.Int).SetUint64(1600085176765664645),
			*new(big.Int).SetUint64(8450735902517439914),
			*new(big.Int).SetUint64(879305481131694650),
			*new(big.Int).SetUint64(9249368002914244868),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(7063301786803892166),
			*new(big.Int).SetUint64(16450112846546843898),
			*new(big.Int).SetUint64(13291990378137922105),
			*new(big.Int).SetUint64(17122501309646837992),
			*new(big.Int).SetUint64(13551174888872382132),
		},
		IsInf: false,
	}
	p5, success := DecodeAsWeierstrass(vectors[5])
	if !success {
		t.Fatalf("w5 should successfully decode")
	}
	if !p5.Equals(p5Expected) {
		t.Fatalf("p5 does not match expected value")
	}

	p6Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(12792842147978866906),
			*new(big.Int).SetUint64(10605017725125541653),
			*new(big.Int).SetUint64(7515179057747849898),
			*new(big.Int).SetUint64(4244613931017322576),
			*new(big.Int).SetUint64(5015379385130367832),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(11618884250209642346),
			*new(big.Int).SetUint64(14788516166813429253),
			*new(big.Int).SetUint64(7317520700234795285),
			*new(big.Int).SetUint64(12825292405177435802),
			*new(big.Int).SetUint64(17658454967394645353),
		},
		IsInf: false,
	}
	p6, success := DecodeAsWeierstrass(vectors[6])
	if !success {
		t.Fatalf("w6 should successfully decode")
	}
	if !p6.Equals(p6Expected) {
		t.Fatalf("p6 does not match expected value")
	}

	p7Expected := WeierstrassPoint{
		X: config.Element{
			*new(big.Int).SetUint64(10440794216646581227),
			*new(big.Int).SetUint64(13992847258701590930),
			*new(big.Int).SetUint64(11213401763785319360),
			*new(big.Int).SetUint64(12830171931568113117),
			*new(big.Int).SetUint64(6220154342199499160),
		},
		Y: config.Element{
			*new(big.Int).SetUint64(7971683838841472962),
			*new(big.Int).SetUint64(1639066249976938469),
			*new(big.Int).SetUint64(15015315060237521031),
			*new(big.Int).SetUint64(10847769264696425470),
			*new(big.Int).SetUint64(9177491810370773777),
		},
		IsInf: false,
	}
	p7, success := DecodeAsWeierstrass(vectors[7])
	if !success {
		t.Fatalf("w7 should successfully decode")
	}
	if !p7.Equals(p7Expected) {
		t.Fatalf("p7 does not match expected value")
	}

	wGen := fp5.Fp5FromUint64(4)
	g, success := DecodeAsWeierstrass(wGen)
	if !success {
		t.Fatalf("w_gen should successfully decode")
	}
	if !g.Equals(GENERATOR_WEIERSTRASS) {
		t.Fatalf("g does not match GENERATOR")
	}
}
