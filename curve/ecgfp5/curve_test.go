package ecgfp5

// func TestEncode(t *testing.T) {
// 	point := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			8219099146870311261,
// 			1751466925979295147,
// 			7427996218561204331,
// 			5499363376829590386,
// 			17146362437196146248,
// 		),
// 		z: gFp5.FromUint64Array(
// 			9697849239028047855,
// 			5846309906783017685,
// 			10545493423738651463,
// 			2054382452661947581,
// 			7470471124463677860,
// 		),
// 		u: gFp5.FromUint64Array(
// 			2901139745109740356,
// 			15850005224840060392,
// 			3464972059371886732,
// 			15264046134718393739,
// 			9208307769190416697,
// 		),
// 		t: gFp5.FromUint64Array(
// 			4691886900801030369,
// 			14793814721360336872,
// 			14452533794393275351,
// 			3652664841353278369,
// 			4894903405053011144,
// 		),
// 	}

// 	encoded := point.Encode()
// 	expected := [5]uint64{
// 		11698180777452980608,
// 		17225201015770513568,
// 		2048901991804183462,
// 		12372738397545947475,
// 		13773458998102781339,
// 	}

// 	for i := 0; i < 5; i++ {
// 		if encoded[i] != expected[i] {
// 			t.Fatalf("Encode: Expected limb %d to be %x, but got %x", i, expected[i], encoded[i])
// 		}
// 	}
// }

// func TestAdd(t *testing.T) {
// 	a := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			6598630105941849408,
// 			1859688128646629097,
// 			17294281002801957241,
// 			14913942670710662913,
// 			10914775081841233526,
// 		),
// 		z: gFp5.FromUint64Array(
// 			5768577777379827814,
// 			1670898087452303151,
// 			149395834104961848,
// 			10215820955974196778,
// 			12220782198555404872,
// 		),
// 		u: gFp5.FromUint64Array(
// 			8222038236695704789,
// 			7213480445243459136,
// 			12261234501547702974,
// 			16991275954331307770,
// 			13268460265795104226,
// 		),
// 		t: gFp5.FromUint64Array(
// 			13156365331881093743,
// 			1228071764139434927,
// 			12765463901361527883,
// 			708052950516284594,
// 			2091843551884526165,
// 		),
// 	}
// 	b := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			12601734882931894875,
// 			8567855799503419472,
// 			10972305351681971938,
// 			10379631676278166937,
// 			14389591363895654229,
// 		),
// 		z: gFp5.FromUint64Array(
// 			7813541982583063146,
// 			5326831614826269688,
// 			674248499729254112,
// 			6075985944329658642,
// 			4509699573536613779,
// 		),
// 		u: gFp5.FromUint64Array(
// 			18059989919748409029,
// 			4197498098921379230,
// 			8619952860870967373,
// 			4771999616217997413,
// 			18075221430709764120,
// 		),
// 		t: gFp5.FromUint64Array(
// 			14710659590503370792,
// 			13425914726164358056,
// 			15027060927285830507,
// 			17361235517359536873,
// 			1738580404337116326,
// 		),
// 	}

// 	c := a.Add(b)
// 	expectedX := [5]uint64{
// 		2091129225269376836,
// 		9405624996184206232,
// 		3901502046808513894,
// 		17705383837126423407,
// 		9421907235969101682,
// 	}
// 	expectedZ := [5]uint64{
// 		5829667370837222420,
// 		11237187675958101957,
// 		1807194474973812009,
// 		15957008761806494676,
// 		16213732873017933964,
// 	}
// 	expectedU := [5]uint64{
// 		17708743171457526148,
// 		7256550674326982355,
// 		4002326258245501339,
// 		5920160861215573533,
// 		6620019694807786845,
// 	}
// 	expectedT := [5]uint64{
// 		8994820555257560065,
// 		3865139429644955984,
// 		222111198601608498,
// 		5080186348564946426,
// 		910404641634132272,
// 	}

// 	for i := 0; i < 5; i++ {
// 		if c.x[i] != expectedX[i] {
// 			t.Fatalf("Add: Expected c.x[%d] to be %x, but got %x", i, expectedX[i], c.x[i])
// 		}
// 		if c.z[i] != expectedZ[i] {
// 			t.Fatalf("Add: Expected c.z[%d] to be %x, but got %x", i, expectedZ[i], c.z[i])
// 		}
// 		if c.u[i] != expectedU[i] {
// 			t.Fatalf("Add: Expected c.u[%d] to be %x, but got %x", i, expectedU[i], c.u[i])
// 		}
// 		if c.t[i] != expectedT[i] {
// 			t.Fatalf("Add: Expected c.t[%d] to be %x, but got %x", i, expectedT[i], c.t[i])
// 		}
// 	}
// }

// func TestDouble(t *testing.T) {
// 	point := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			2091129225269376836,
// 			9405624996184206232,
// 			3901502046808513894,
// 			17705383837126423407,
// 			9421907235969101682,
// 		),
// 		z: gFp5.FromUint64Array(
// 			5829667370837222420,
// 			11237187675958101957,
// 			1807194474973812009,
// 			15957008761806494676,
// 			16213732873017933964,
// 		),
// 		u: gFp5.FromUint64Array(
// 			17708743171457526148,
// 			7256550674326982355,
// 			4002326258245501339,
// 			5920160861215573533,
// 			6620019694807786845,
// 		),
// 		t: gFp5.FromUint64Array(
// 			8994820555257560065,
// 			3865139429644955984,
// 			222111198601608498,
// 			5080186348564946426,
// 			910404641634132272,
// 		),
// 	}

// 	point.SetDouble()

// 	expected := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			17841786997947248136,
// 			6795260826091178564,
// 			17040031878202156690,
// 			17452087436690889171,
// 			3812897545652133031,
// 		),
// 		z: gFp5.FromUint64Array(
// 			11020726505488657009,
// 			1091762938184204841,
// 			4410430720558219763,
// 			4363379995258938087,
// 			13994951776877072532,
// 		),
// 		u: gFp5.FromUint64Array(
// 			9442293568698796309,
// 			11629160327398360345,
// 			1740514571594869537,
// 			1168842489343203981,
// 			5537908027019165338,
// 		),
// 		t: gFp5.FromUint64Array(
// 			14684689082562511355,
// 			9795998745315395469,
// 			11643703245601798489,
// 			9164627329631566444,
// 			14463660178939261073,
// 		),
// 	}

// 	if !point.Equals(expected) {
// 		t.Fatalf("Double: Expected %v, but got %v", expected, point)
// 	}
// }

// func TestMDouble(t *testing.T) {
// 	point := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			2091129225269376836,
// 			9405624996184206232,
// 			3901502046808513894,
// 			17705383837126423407,
// 			9421907235969101682,
// 		),
// 		z: gFp5.FromUint64Array(
// 			5829667370837222420,
// 			11237187675958101957,
// 			1807194474973812009,
// 			15957008761806494676,
// 			16213732873017933964,
// 		),
// 		u: gFp5.FromUint64Array(
// 			17708743171457526148,
// 			7256550674326982355,
// 			4002326258245501339,
// 			5920160861215573533,
// 			6620019694807786845,
// 		),
// 		t: gFp5.FromUint64Array(
// 			8994820555257560065,
// 			3865139429644955984,
// 			222111198601608498,
// 			5080186348564946426,
// 			910404641634132272,
// 		),
// 	}

// 	point.SetMDouble(35)

// 	expectedDouble := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			5913227576680434070,
// 			7982325190863789325,
// 			996872074809285515,
// 			13250982632111464330,
// 			12283818425722177845,
// 		),
// 		z: gFp5.FromUint64Array(
// 			11109298682748378964,
// 			10740549672355474144,
// 			8575099619865922741,
// 			7569981484002838575,
// 			8334331076253814622,
// 		),
// 		u: gFp5.FromUint64Array(
// 			2081907484718321711,
// 			2871920152785433924,
// 			16079876071712475691,
// 			12304725828108396137,
// 			5091453661983356959,
// 		),
// 		t: gFp5.FromUint64Array(
// 			16573251802693900474,
// 			18328109793157914401,
// 			5893679867263862011,
// 			8243272292726266031,
// 			9080497760919830159,
// 		),
// 	}

// 	for i := 0; i < 5; i++ {
// 		if point.x[i] != expectedDouble.x[i] {
// 			t.Fatalf("MDouble: Expected point.x[%d] to be %x, but got %x", i, expectedDouble.x[i], point.x[i])
// 		}
// 		if point.z[i] != expectedDouble.z[i] {
// 			t.Fatalf("MDouble: Expected point.z[%d] to be %x, but got %x", i, expectedDouble.z[i], point.z[i])
// 		}
// 		if point.u[i] != expectedDouble.u[i] {
// 			t.Fatalf("MDouble: Expected point.u[%d] to be %x, but got %x", i, expectedDouble.u[i], point.u[i])
// 		}
// 		if point.t[i] != expectedDouble.t[i] {
// 			t.Fatalf("MDouble: Expected point.t[%d] to be %x, but got %x", i, expectedDouble.t[i], point.t[i])
// 		}
// 	}
// }

// func TestToAffineAndLookup(t *testing.T) {
// 	point := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			6641938805100417611,
// 			4637251792794046952,
// 			9680215716198734904,
// 			7124887799004433445,
// 			3695446893682682870,
// 		),
// 		z: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		u: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		t: gFp5.FromUint64Array(
// 			12539254003028696409,
// 			15524144070600887654,
// 			15092036948424041984,
// 			11398871370327264211,
// 			10958391180505708567,
// 		),
// 	}

// 	tab1 := make([]ECgFp5Point, 8)
// 	tab1[0] = point.Double()
// 	for i := 1; i < len(tab1); i++ {
// 		tab1[i] = tab1[0].Add(tab1[i-1])
// 	}

// 	for n := 1; n <= len(tab1); n++ {
// 		tab2 := BatchToAffine(tab1)
// 		for i := 0; i < n; i++ {
// 			if !gFp5.Equals(gFp5.Mul(tab1[i].z, tab2[i].x), tab1[i].x) {
// 				t.Fail()
// 			}
// 			if !gFp5.Equals(gFp5.Mul(tab1[i].t, tab2[i].u), tab1[i].u) {
// 				t.Fail()
// 			}
// 		}
// 	}

// 	// Test lookup
// 	win := BatchToAffine(tab1)
// 	p1Affine := Lookup(win, 72)

// 	if !gFp5.Equals(p1Affine.x, gFp5.FP5_ZERO) {
// 		t.Fatalf("Lookup failed for 72: expected %v, got %v", gFp5.FP5_ZERO, p1Affine.x)
// 	}
// 	if !gFp5.Equals(p1Affine.u, gFp5.FP5_ZERO) {
// 		t.Fatalf("Lookup failed for 72: expected %v, got %v", gFp5.FP5_ZERO, p1Affine.u)
// 	}

// 	for i := 1; i <= 8; i++ {
// 		p2Affine := Lookup(win, int32(i))
// 		if !gFp5.Equals(gFp5.Mul(tab1[i-1].z, p2Affine.x), tab1[i-1].x) {
// 			t.Fatalf("Lookup failed for %d: expected %v, got %v", i, tab1[i-1].x, gFp5.Mul(tab1[i-1].z, p2Affine.x))
// 		}
// 		if !gFp5.Equals(gFp5.Mul(tab1[i-1].t, p2Affine.u), tab1[i-1].u) {
// 			t.Fatalf("Lookup failed for %d: expected %v, got %v", i, tab1[i-1].u, gFp5.Mul(tab1[i-1].t, p2Affine.u))
// 		}

// 		p3Affine := Lookup(win, int32(-i))
// 		if !gFp5.Equals(gFp5.Mul(tab1[i-1].z, p3Affine.x), tab1[i-1].x) {
// 			t.Fatalf("Lookup failed for -%d: expected %v, got %v", i, tab1[i-1].x, gFp5.Mul(tab1[i-1].z, p3Affine.x))
// 		}
// 		if !gFp5.Equals(gFp5.Mul(tab1[i-1].t, p3Affine.u), gFp5.Neg(tab1[i-1].u)) {
// 			t.Fatalf("Lookup failed for -%d: expected %v, got %v", i, gFp5.Neg(tab1[i-1].u), gFp5.Mul(tab1[i-1].t, p3Affine.u))
// 		}
// 	}
// }

// func TestScalarMul(t *testing.T) {
// 	p1 := ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			16818074783491816710,
// 			5830279414330569119,
// 			3449083115922675783,
// 			1268145320872323641,
// 			12614816166275380125,
// 		),
// 		z: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		u: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		t: gFp5.FromUint64Array(
// 			7534507442095725921,
// 			16658460051907528927,
// 			12417574136563175256,
// 			2750788641759288856,
// 			620002843272906439,
// 		),
// 	}

// 	if !p1.Mul(&ECgFp5Scalar{
// 		Value: [5]big.Int{
// 			*new(big.Int).SetUint64(996458928865875995),
// 			*new(big.Int).SetUint64(7368213710557165165),
// 			*new(big.Int).SetUint64(8553572641065079816),
// 			*new(big.Int).SetUint64(15282443801767955752),
// 			*new(big.Int).SetUint64(251150557732720826),
// 		},
// 	}).Equals(ECgFp5Point{
// 		x: gFp5.FromUint64Array(
// 			16885333682092300432,
// 			5595343485914691669,
// 			13188593663496831978,
// 			10414629856394645794,
// 			5668658507670629815,
// 		),
// 		z: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		u: gFp5.FromUint64Array(
// 			1,
// 			0,
// 			0,
// 			0,
// 			0,
// 		),
// 		t: gFp5.FromUint64Array(
// 			9486104512504676657,
// 			14312981644741144668,
// 			5159846406177847664,
// 			15978863787033795628,
// 			3249948839313771192,
// 		),
// 	}) {
// 		t.Fail()
// 	}
// }

// func testVectors() [8]gFp5.Element {
// 	// P0 is neutral of G.
// 	// P1 is a random point in G (encoded as w1)
// 	// P2 = e*P1 in G (encoded as w2)
// 	// P3 = P1 + P2 (in G) (encoded as w3)
// 	// P4 = 2*P1 (in G) (encoded as w4)
// 	// P5 = 2*P2 (in G) (encoded as w5)
// 	// P6 = 2*P1 + P2 (in G) (encoded as w6)
// 	// P7 = P1 + 2*P2 (in G) (encoded as w7)

// 	w0 := gFp5.FP5_ZERO
// 	w1 := gFp5.Element{
// 		12539254003028696409,
// 		15524144070600887654,
// 		15092036948424041984,
// 		11398871370327264211,
// 		10958391180505708567,
// 	}
// 	w2 := gFp5.Element{
// 		11001943240060308920,
// 		17075173755187928434,
// 		3940989555384655766,
// 		15017795574860011099,
// 		5548543797011402287,
// 	}
// 	w3 := gFp5.Element{
// 		246872606398642312,
// 		4900963247917836450,
// 		7327006728177203977,
// 		13945036888436667069,
// 		3062018119121328861,
// 	}
// 	w4 := gFp5.Element{
// 		8058035104653144162,
// 		16041715455419993830,
// 		7448530016070824199,
// 		11253639182222911208,
// 		6228757819849640866,
// 	}
// 	w5 := gFp5.Element{
// 		10523134687509281194,
// 		11148711503117769087,
// 		9056499921957594891,
// 		13016664454465495026,
// 		16494247923890248266,
// 	}
// 	w6 := gFp5.Element{
// 		12173306542237620,
// 		6587231965341539782,
// 		17027985748515888117,
// 		17194831817613584995,
// 		10056734072351459010,
// 	}
// 	w7 := gFp5.Element{
// 		9420857400785992333,
// 		4695934009314206363,
// 		14471922162341187302,
// 		13395190104221781928,
// 		16359223219913018041,
// 	}

// 	return [8]gFp5.Element{w0, w1, w2, w3, w4, w5, w6, w7}
// }

// func TestBasicOps(t *testing.T) {
// 	// Values that should not decode succeslly.
// 	bww := [6]gFp5.Element{
// 		{
// 			13557832913345268708,
// 			15669280705791538619,
// 			8534654657267986396,
// 			12533218303838131749,
// 			5058070698878426028,
// 		},
// 		{
// 			135036726621282077,
// 			17283229938160287622,
// 			13113167081889323961,
// 			1653240450380825271,
// 			520025869628727862,
// 		},
// 		{
// 			6727960962624180771,
// 			17240764188796091916,
// 			3954717247028503753,
// 			1002781561619501488,
// 			4295357288570643789,
// 		},
// 		{
// 			4578929270179684956,
// 			3866930513245945042,
// 			7662265318638150701,
// 			9503686272550423634,
// 			12241691520798116285,
// 		},
// 		{
// 			16890297404904119082,
// 			6169724643582733633,
// 			9725973298012340311,
// 			5977049210035183790,
// 			11379332130141664883,
// 		},
// 		{
// 			13777379982711219130,
// 			14715168412651470168,
// 			17942199593791635585,
// 			6188824164976547520,
// 			15461469634034461986,
// 		},
// 	}
// 	for _, w := range bww {
// 		if CanBeDecodedIntoPoint(w) {
// 			t.Fatalf("Validation should fail for element: %v", w)
// 		}
// 		if _, success := Decode(w); success {
// 			t.Fatalf("Decoding should fail for element: %v", w)
// 		}
// 	}

// 	vectors := testVectors()
// 	for _, w := range vectors {
// 		if !CanBeDecodedIntoPoint(w) {
// 			t.Fatalf("Validation failed for element: %v", w)
// 		}
// 	}

// 	p0, s := Decode(vectors[0])
// 	if !s {
// 		t.Fatalf("Decoding failed for p0")
// 	}
// 	p1, s := Decode(vectors[1])
// 	if !s {
// 		t.Fatalf("Decoding failed for p1")
// 	}
// 	p2, s := Decode(vectors[2])
// 	if !s {
// 		t.Fatalf("Decoding failed for p2")
// 	}
// 	p3, s := Decode(vectors[3])
// 	if !s {
// 		t.Fatalf("Decoding failed for p3")
// 	}
// 	p4, s := Decode(vectors[4])
// 	if !s {
// 		t.Fatalf("Decoding failed for p4")
// 	}
// 	p5, s := Decode(vectors[5])
// 	if !s {
// 		t.Fatalf("Decoding failed for p5")
// 	}
// 	p6, s := Decode(vectors[6])
// 	if !s {
// 		t.Fatalf("Decoding failed for p6")
// 	}
// 	p7, s := Decode(vectors[7])
// 	if !s {
// 		t.Fatalf("Decoding failed for p7")
// 	}

// 	if !p0.IsNeutral() {
// 		t.Fatalf("p0 should be neutral")
// 	}
// 	if p1.IsNeutral() || p2.IsNeutral() || p3.IsNeutral() || p4.IsNeutral() || p5.IsNeutral() || p6.IsNeutral() || p7.IsNeutral() {
// 		t.Fatalf("p1...p7 should not be neutral")
// 	}
// 	if !p0.Equals(p0) || !p1.Equals(p1) || p0.Equals(p1) || p1.Equals(p0) || p1.Equals(p2) {
// 		t.Fatalf("Equality checks failed")
// 	}

// 	if !gFp5.Equals(p0.Encode(), vectors[0]) || !gFp5.Equals(p1.Encode(), vectors[1]) || !gFp5.Equals(p2.Encode(), vectors[2]) || !gFp5.Equals(p3.Encode(), vectors[3]) || !gFp5.Equals(p4.Encode(), vectors[4]) || !gFp5.Equals(p5.Encode(), vectors[5]) || !gFp5.Equals(p6.Encode(), vectors[6]) || !gFp5.Equals(p7.Encode(), vectors[7]) {
// 		t.Fatalf("Encoding checks failed")
// 	}

// 	if !gFp5.Equals(p1.Add(p2).Encode(), vectors[3]) || !gFp5.Equals(p1.Add(p1).Encode(), vectors[4]) || !gFp5.Equals(p2.Double().Encode(), vectors[5]) || !gFp5.Equals(p1.Double().Add(p2).Encode(), vectors[6]) || !gFp5.Equals(p1.Add(p2).Add(p2).Encode(), vectors[7]) {
// 		t.Fatalf("Addition and doubling checks failed")
// 	}

// 	if !gFp5.Equals(p0.Double().Encode(), gFp5.FP5_ZERO) || !gFp5.Equals(p0.Add(p0).Encode(), gFp5.FP5_ZERO) || !gFp5.Equals(p0.Add(p1).Encode(), vectors[1]) || !gFp5.Equals(p1.Add(p0).Encode(), vectors[1]) {
// 		t.Fatalf("Zero addition and doubling checks failed")
// 	}

// 	for i := uint32(0); i < 10; i++ {
// 		q1 := p1.MDouble(i)
// 		q2 := p1
// 		for j := uint32(0); j < i; j++ {
// 			q2 = q2.Double()
// 		}
// 		if !q1.Equals(q2) {
// 			t.Fatalf("MDouble check failed for i=%d", i)
// 		}
// 	}

// 	p2Affine := AffinePoint{
// 		x: gFp5.Mul(p2.x, gFp5.InverseOrZero(p2.z)),
// 		u: gFp5.Mul(p2.u, gFp5.InverseOrZero(p2.t)),
// 	}
// 	if !p1.AddAffine(p2Affine).Equals(p1.Add(p2)) {
// 		t.Fatalf("Affine addition check failed")
// 	}
// }

// func TestDecodeAsWeierstrass(t *testing.T) {
// 	vectors := testVectors()

// 	p0Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			6148914689804861440,
// 			0,
// 			0,
// 			0,
// 			0,
// 		},
// 		Y:     gFp5.FP5_ZERO,
// 		IsInf: true,
// 	}
// 	p0, success := DecodeFp5AsWeierstrass(vectors[0])
// 	if !success {
// 		t.Fatalf("w0 should succeslly decode")
// 	}
// 	if !p0.Equals(p0Expected) {
// 		t.Fatalf("p0 does not match expected value")
// 	}

// 	p1Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			7887569478949190020,
// 			11586418388990522938,
// 			13676447623055915878,
// 			5945168854809921881,
// 			16291886980725359814,
// 		},
// 		Y: gFp5.Element{
// 			7556511254681645335,
// 			17611929280367064763,
// 			9410908488141053806,
// 			11351540010214108766,
// 			4846226015431423207,
// 		},
// 		IsInf: false,
// 	}
// 	p1, success := DecodeFp5AsWeierstrass(vectors[1])
// 	if !success {
// 		t.Fatalf("w1 should succeslly decode")
// 	}
// 	if !p1.Equals(p1Expected) {
// 		t.Fatalf("p1 does not match expected value")
// 	}

// 	p2Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			11231216549003316587,
// 			17312878720767554617,
// 			5614299211412933260,
// 			2256199868722187419,
// 			14229722163821261464,
// 		},
// 		Y: gFp5.Element{
// 			11740132275098847128,
// 			18250632754932612452,
// 			6988589976052950880,
// 			13612651576898186637,
// 			16040252831112129154,
// 		},
// 		IsInf: false,
// 	}
// 	p2, success := DecodeFp5AsWeierstrass(vectors[2])
// 	if !success {
// 		t.Fatalf("w2 should succeslly decode")
// 	}
// 	if !p2.Equals(p2Expected) {
// 		t.Fatalf("p2 does not match expected value")
// 	}

// 	p3Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			567456832026211571,
// 			6401615614732569674,
// 			7303004494044972219,
// 			4332356015409706768,
// 			4663512734739523713,
// 		},
// 		Y: gFp5.Element{
// 			13838792670272995877,
// 			11742686110311813089,
// 			17972799251722850796,
// 			8534723577625674697,
// 			3138422718990519265,
// 		},
// 		IsInf: false,
// 	}
// 	p3, success := DecodeFp5AsWeierstrass(vectors[3])
// 	if !success {
// 		t.Fatalf("w3 should succeslly decode")
// 	}
// 	if !p3.Equals(p3Expected) {
// 		t.Fatalf("p3 does not match expected value")
// 	}

// 	p4Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			2626390539619063455,
// 			3069873143820007175,
// 			16481805966921623903,
// 			2169403494164322467,
// 			15849876939764656634,
// 		},
// 		Y: gFp5.Element{
// 			8052493994140007067,
// 			12476750341447220703,
// 			7297584762312352412,
// 			4456043296886321460,
// 			17416054515469523789,
// 		},
// 		IsInf: false,
// 	}
// 	p4, success := DecodeFp5AsWeierstrass(vectors[4])
// 	if !success {
// 		t.Fatalf("w4 should succeslly decode")
// 	}
// 	if !p4.Equals(p4Expected) {
// 		t.Fatalf("p4 does not match expected value")
// 	}

// 	p5Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			3378618241466923429,
// 			1600085176765664645,
// 			8450735902517439914,
// 			879305481131694650,
// 			9249368002914244868,
// 		},
// 		Y: gFp5.Element{
// 			7063301786803892166,
// 			16450112846546843898,
// 			13291990378137922105,
// 			17122501309646837992,
// 			13551174888872382132,
// 		},
// 		IsInf: false,
// 	}
// 	p5, success := DecodeFp5AsWeierstrass(vectors[5])
// 	if !success {
// 		t.Fatalf("w5 should succeslly decode")
// 	}
// 	if !p5.Equals(p5Expected) {
// 		t.Fatalf("p5 does not match expected value")
// 	}

// 	p6Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			12792842147978866906,
// 			10605017725125541653,
// 			7515179057747849898,
// 			4244613931017322576,
// 			5015379385130367832,
// 		},
// 		Y: gFp5.Element{
// 			11618884250209642346,
// 			14788516166813429253,
// 			7317520700234795285,
// 			12825292405177435802,
// 			17658454967394645353,
// 		},
// 		IsInf: false,
// 	}
// 	p6, success := DecodeFp5AsWeierstrass(vectors[6])
// 	if !success {
// 		t.Fatalf("w6 should succeslly decode")
// 	}
// 	if !p6.Equals(p6Expected) {
// 		t.Fatalf("p6 does not match expected value")
// 	}

// 	p7Expected := WeierstrassPoint{
// 		X: gFp5.Element{
// 			10440794216646581227,
// 			13992847258701590930,
// 			11213401763785319360,
// 			12830171931568113117,
// 			6220154342199499160,
// 		},
// 		Y: gFp5.Element{
// 			7971683838841472962,
// 			1639066249976938469,
// 			15015315060237521031,
// 			10847769264696425470,
// 			9177491810370773777,
// 		},
// 		IsInf: false,
// 	}
// 	p7, success := DecodeFp5AsWeierstrass(vectors[7])
// 	if !success {
// 		t.Fatalf("w7 should succeslly decode")
// 	}
// 	if !p7.Equals(p7Expected) {
// 		t.Fatalf("p7 does not match expected value")
// 	}

// 	wGen := gFp5.FromUint64(4)
// 	g, success := DecodeFp5AsWeierstrass(wGen)
// 	if !success {
// 		t.Fatalf("w_gen should succeslly decode")
// 	}
// 	if !g.Equals(GENERATOR_WEIERSTRASS) {
// 		t.Fatalf("g does not match GENERATOR")
// 	}
// }

// func TestWeierstrassPrecomputeWindow(t *testing.T) {
// 	qwe := WeierstrassPoint{
// 		X: gFp5.Element{
// 			7887569478949190020,
// 			11586418388990522938,
// 			13676447623055915878,
// 			5945168854809921881,
// 			16291886980725359814,
// 		},
// 		Y: gFp5.Element{
// 			7556511254681645335,
// 			17611929280367064763,
// 			9410908488141053806,
// 			11351540010214108766,
// 			4846226015431423207,
// 		},
// 		IsInf: false,
// 	}

// 	window := qwe.PrecomputeWindow(4)

// 	expectedWindow := []WeierstrassPoint{
// 		{
// 			X: gFp5.Element{
// 				0,
// 				0,
// 				0,
// 				0,
// 				0,
// 			},
// 			Y:     gFp5.FP5_ZERO,
// 			IsInf: true,
// 		},
// 		{
// 			X: gFp5.Element{
// 				7887569478949190020,
// 				11586418388990522938,
// 				13676447623055915878,
// 				5945168854809921881,
// 				16291886980725359814,
// 			},
// 			Y: gFp5.Element{
// 				7556511254681645335,
// 				17611929280367064763,
// 				9410908488141053806,
// 				11351540010214108766,
// 				4846226015431423207,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				2626390539619063455,
// 				3069873143820007175,
// 				16481805966921623903,
// 				2169403494164322467,
// 				15849876939764656634,
// 			},
// 			Y: gFp5.Element{
// 				8052493994140007067,
// 				12476750341447220703,
// 				7297584762312352412,
// 				4456043296886321460,
// 				17416054515469523789,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				18176398362578182379,
// 				4436023520237554199,
// 				3215180516398562719,
// 				6557371017655524187,
// 				5543821526507387228,
// 			},
// 			Y: gFp5.Element{
// 				13231520129332295641,
// 				12272620923537119667,
// 				2190001779233679631,
// 				17429746542415208975,
// 				3337887399771893342,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				5948298497167270001,
// 				15488083211069840053,
// 				7462878240499130449,
// 				5465845052061152523,
// 				14272165321414720409,
// 			},
// 			Y: gFp5.Element{
// 				7229037630209827809,
// 				10702348517645256990,
// 				8760795746058875829,
// 				9846744510637391346,
// 				3236820900223784510,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				568906556912793428,
// 				12270416106652192091,
// 				17277438866839882878,
// 				18290317522638929974,
// 				7546670826452401067,
// 			},
// 			Y: gFp5.Element{
// 				1322178101989677577,
// 				18254974566546618836,
// 				1119202239871436890,
// 				13885721715120393435,
// 				7665289671288386226,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				6854724460063782323,
// 				7010495484231564745,
// 				15016688843001273184,
// 				9083584169580443423,
// 				6530832684770892589,
// 			},
// 			Y: gFp5.Element{
// 				13188019294905205452,
// 				9894649816252217734,
// 				4035350096343221693,
// 				9024914229517462288,
// 				14523942737067589623,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				173069451201741305,
// 				16407881748070922395,
// 				1843877769060049981,
// 				8394477401224475023,
// 				15455323212667110231,
// 			},
// 			Y: gFp5.Element{
// 				7073462480600858335,
// 				1218835901499910502,
// 				4884985224204572316,
// 				8579676009424088446,
// 				8272242895251038218,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				1164943004740104550,
// 				6494467951550829605,
// 				11394395084895053958,
// 				11002214393170970880,
// 				6198152590137047423,
// 			},
// 			Y: gFp5.Element{
// 				6293376713015748154,
// 				3978302408397307263,
// 				10305750348797825360,
// 				2653356225991763726,
// 				18032604437344362964,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				8412524841879898340,
// 				5906329857715512849,
// 				7781506052219784033,
// 				747934326178282629,
// 				9789520974115787951,
// 			},
// 			Y: gFp5.Element{
// 				16402983360046062715,
// 				2610048768344810351,
// 				1409991662255990973,
// 				8262322794139104006,
// 				17162526866400736394,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				10048515622314644986,
// 				12205112414027757400,
// 				6798899797395644410,
// 				5508399081833065246,
// 				2545381917899893146,
// 			},
// 			Y: gFp5.Element{
// 				13967674179646477901,
// 				7464072417461755698,
// 				10620790885582225633,
// 				2124420630858145666,
// 				1715438731398823203,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				8945074870943081799,
// 				6323068672198034776,
// 				628757110948609554,
// 				463667364946291331,
// 				18333500614767793034,
// 			},
// 			Y: gFp5.Element{
// 				1585562137944898917,
// 				6965134006182209177,
// 				7287494396640097306,
// 				6989295600772373751,
// 				4694512086109041789,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				1353084308423766252,
// 				9017409530297494922,
// 				17666541873916336431,
// 				11263790843735091100,
// 				8436577988671463853,
// 			},
// 			Y: gFp5.Element{
// 				2338633593176970866,
// 				2404810229101070877,
// 				16146490466464907277,
// 				5696273511305368024,
// 				15148244810777170464,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				1474147635627813906,
// 				11643377203770626355,
// 				9314121941510315318,
// 				9763644728022466505,
// 				17192017882693797779,
// 			},
// 			Y: gFp5.Element{
// 				4381200527555648826,
// 				13015101990350251010,
// 				16047910726372959546,
// 				11605287252021821360,
// 				10725156729712381290,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				14169389411955179775,
// 				18405651482817201996,
// 				13913583073406638188,
// 				7468262161993545065,
// 				14000137716301361841,
// 			},
// 			Y: gFp5.Element{
// 				14787739045021338943,
// 				4141115345494939173,
// 				10070258119240548823,
// 				11477026875407130857,
// 				6299768551826493717,
// 			},
// 			IsInf: false,
// 		},
// 		{
// 			X: gFp5.Element{
// 				2020949939443349975,
// 				4576727228132381036,
// 				11685880123997658374,
// 				10781236098739931544,
// 				354959600421572530,
// 			},
// 			Y: gFp5.Element{
// 				2226472037177585493,
// 				8680432113228524002,
// 				5532575929311408085,
// 				17286717775780223599,
// 				7476327786946640228,
// 			},
// 			IsInf: false,
// 		},
// 	}

// 	for i, p := range window {
// 		if !p.Equals(expectedWindow[i]) {
// 			t.Fatalf("Window point %d does not match expected value. Got: %v, Expected: %v", i, p, expectedWindow[i])
// 		}
// 	}
// }

// func TestWeierstrassDoubleAndWeierstrassAdd(t *testing.T) {
// 	qwe := WeierstrassPoint{
// 		X: gFp5.Element{
// 			7887569478949190020,
// 			11586418388990522938,
// 			13676447623055915878,
// 			5945168854809921881,
// 			16291886980725359814,
// 		},
// 		Y: gFp5.Element{
// 			7556511254681645335,
// 			17611929280367064763,
// 			9410908488141053806,
// 			11351540010214108766,
// 			4846226015431423207,
// 		},
// 		IsInf: false,
// 	}
// 	doubled := qwe.Double()

// 	expectedX := gFp5.Element{
// 		2626390539619063455,
// 		3069873143820007175,
// 		16481805966921623903,
// 		2169403494164322467,
// 		15849876939764656634,
// 	}
// 	expectedY := gFp5.Element{
// 		8052493994140007067,
// 		12476750341447220703,
// 		7297584762312352412,
// 		4456043296886321460,
// 		17416054515469523789,
// 	}

// 	for i := 0; i < len(expectedX); i++ {
// 		if expectedX[i] != doubled.X[i] {
// 			t.Logf("X coordinate does not match at index %d. Expected: %v, Got: %v", i, expectedX[i], doubled.X[i])
// 			t.Fail()
// 		}
// 	}

// 	for i := 0; i < len(expectedY); i++ {
// 		if expectedY[i] != doubled.Y[i] {
// 			t.Logf("Y coordinate does not match at index %d. Expected: %v, Got: %v", i, expectedY[i], doubled.Y[i])
// 			t.Fail()
// 		}
// 	}

// 	if doubled.IsInf {
// 		t.Logf("IsInf should be false")
// 		t.Fail()
// 	}

// 	abc := WeierstrassPoint{
// 		X: gFp5.Element{
// 			10440794216646581227,
// 			13992847258701590930,
// 			11213401763785319360,
// 			12830171931568113117,
// 			6220154342199499160,
// 		},
// 		Y: gFp5.Element{
// 			7971683838841472962,
// 			1639066249976938469,
// 			15015315060237521031,
// 			10847769264696425470,
// 			9177491810370773777,
// 		},
// 		IsInf: false,
// 	}

// 	added := qwe.Add(abc)

// 	expectedAddedX := gFp5.Element{
// 		15147435967142035350,
// 		4142330994743253079,
// 		5589541853421788480,
// 		8174056014411977160,
// 		6779289104727130815,
// 	}
// 	expectedAddedY := gFp5.Element{
// 		6941633164497114792,
// 		102684445415310288,
// 		3954903931673222082,
// 		5355092272832152159,
// 		15982629021221531228,
// 	}

// 	for i := 0; i < len(expectedAddedX); i++ {
// 		if expectedAddedX[i] != added.X[i] {
// 			t.Logf("X coordinate does not match at index %d. Expected: %v, Got: %v", i, expectedAddedX[i], added.X[i])
// 			t.Fail()
// 		}
// 	}

// 	for i := 0; i < len(expectedAddedY); i++ {
// 		if expectedAddedY[i] != added.Y[i] {
// 			t.Logf("Y coordinate does not match at index %d. Expected: %v, Got: %v", i, expectedAddedY[i], added.Y[i])
// 			t.Fail()
// 		}
// 	}

// 	if added.IsInf {
// 		t.Logf("IsInf should be false")
// 		t.Fail()
// 	}

// 	a := WeierstrassPoint{
// 		X: gFp5.Element{
// 			568906556912793428,
// 			12270416106652192091,
// 			17277438866839882878,
// 			18290317522638929974,
// 			7546670826452401067,
// 		},
// 		Y: gFp5.Element{
// 			1322178101989677577,
// 			18254974566546618836,
// 			1119202239871436890,
// 			13885721715120393435,
// 			7665289671288386226,
// 		},
// 		IsInf: false,
// 	}

// 	b := WeierstrassPoint{
// 		X: gFp5.Element{
// 			6853785572863472834,
// 			11312233137032236241,
// 			10155632987885765027,
// 			761788325161687206,
// 			10399811161072514291,
// 		},
// 		Y: gFp5.Element{
// 			7631903676079326707,
// 			10538051161007880093,
// 			515356923921201259,
// 			2139317767893795964,
// 			17894501390404592328,
// 		},
// 		IsInf: false,
// 	}

// 	added = a.Add(b)
// 	expectedAdded := WeierstrassPoint{
// 		X: gFp5.Element{
// 			14961006762295990506,
// 			17765806093265157085,
// 			6029983000119323104,
// 			14198599897861826986,
// 			2432992229534936263,
// 		},
// 		Y: gFp5.Element{
// 			9056990811557987042,
// 			5949732889787570233,
// 			5696931170027194764,
// 			9998144444122976852,
// 			13118328774200361975,
// 		},
// 		IsInf: false,
// 	}

// 	if added.IsInf != expectedAdded.IsInf {
// 		t.Fatalf("Expected IsInf to be %v, but got %v", expectedAdded.IsInf, added.IsInf)
// 	}

// 	for i := 0; i < 5; i++ {
// 		if added.X[i] != expectedAdded.X[i] {
// 			t.Fatalf("Expected X[%d] to be %v, but got %v", i, expectedAdded.X[i], added.X[i])
// 		}
// 		if added.Y[i] != expectedAdded.Y[i] {
// 			t.Fatalf("Expected Y[%d] to be %v, but got %v", i, expectedAdded.Y[i], added.Y[i])
// 		}
// 	}
// }

// func TestWeierstrassMulAdd2(t *testing.T) {
// 	qwe := WeierstrassPoint{
// 		X: gFp5.Element{
// 			7887569478949190020,
// 			11586418388990522938,
// 			13676447623055915878,
// 			5945168854809921881,
// 			16291886980725359814,
// 		},
// 		Y: gFp5.Element{
// 			7556511254681645335,
// 			17611929280367064763,
// 			9410908488141053806,
// 			11351540010214108766,
// 			4846226015431423207,
// 		},
// 		IsInf: false,
// 	}
// 	abc := WeierstrassPoint{
// 		X: gFp5.Element{
// 			10440794216646581227,
// 			13992847258701590930,
// 			11213401763785319360,
// 			12830171931568113117,
// 			6220154342199499160,
// 		},
// 		Y: gFp5.Element{
// 			7971683838841472962,
// 			1639066249976938469,
// 			15015315060237521031,
// 			10847769264696425470,
// 			9177491810370773777,
// 		},
// 		IsInf: false,
// 	}

// 	s := ECgFp5Scalar{
// 		Value: [5]big.Int{
// 			*new(big.Int).SetUint64(6950590877883398434),
// 			*new(big.Int).SetUint64(17178336263794770543),
// 			*new(big.Int).SetUint64(11012823478139181320),
// 			*new(big.Int).SetUint64(16445091359523510936),
// 			*new(big.Int).SetUint64(5882925226143600273),
// 		},
// 	}
// 	e := ECgFp5Scalar{
// 		Value: [5]big.Int{
// 			*new(big.Int).SetUint64(4544744459434870309),
// 			*new(big.Int).SetUint64(4180764085957612004),
// 			*new(big.Int).SetUint64(3024669018778978615),
// 			*new(big.Int).SetUint64(15433417688859446606),
// 			*new(big.Int).SetUint64(6775027260348937828),
// 		},
// 	}

// 	muladd := MulAdd2(qwe, abc, s, e)
// 	expectedMulAdd := WeierstrassPoint{
// 		X: gFp5.Element{
// 			16860216879980764002,
// 			13774182223913431169,
// 			3778637410337906635,
// 			7996647345600328210,
// 			17994036749345991288,
// 		},
// 		Y: gFp5.Element{
// 			2325740112090595939,
// 			18412478076524955076,
// 			8648800055674409134,
// 			7238972640284452927,
// 			17572285593460315724,
// 		},
// 		IsInf: false,
// 	}

// 	if muladd.IsInf != expectedMulAdd.IsInf {
// 		t.Fatalf("Expected IsInf to be %v, but got %v", expectedMulAdd.IsInf, muladd.IsInf)
// 	}

// 	for i := 0; i < 5; i++ {
// 		if muladd.X[i] != expectedMulAdd.X[i] {
// 			t.Fatalf("Expected X[%d] to be %v, but got %v", i, expectedMulAdd.X[i], muladd.X[i])
// 		}
// 		if muladd.Y[i] != expectedMulAdd.Y[i] {
// 			t.Fatalf("Expected Y[%d] to be %v, but got %v", i, expectedMulAdd.Y[i], muladd.Y[i])
// 		}
// 	}
// }