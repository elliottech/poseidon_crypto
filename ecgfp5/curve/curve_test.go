package ecgfp5

import (
	"math/big"
	"testing"

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
