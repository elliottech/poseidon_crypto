package poseidon2_plonky2

import (
	"bytes"
	"crypto/rand"
	"math"
	"math/big"
	"math/bits"
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	. "github.com/elliottech/poseidon_crypto/int"
)

func getRandomGoldilocks() g.GoldilocksField {
	mx := new(big.Int).SetUint64(0xFFFFFFFF00000000) // ORDER - 1
	a, _ := rand.Int(rand.Reader, mx)
	return g.GoldilocksField(a.Uint64())
}

func TestPermute(t *testing.T) {
	inp := [WIDTH]g.GoldilocksField{
		5417613058500526590,
		2481548824842427254,
		6473243198879784792,
		1720313757066167274,
		2806320291675974571,
		7407976414706455446,
		1105257841424046885,
		7613435757403328049,
		3376066686066811538,
		5888575799323675710,
		6689309723188675948,
		2468250420241012720,
	}

	Permute(&inp)

	expected := [WIDTH]g.GoldilocksField{
		5364184781011389007,
		15309475861242939136,
		5983386513087443499,
		886942118604446276,
		14903657885227062600,
		7742650891575941298,
		1962182278500985790,
		10213480816595178755,
		3510799061817443836,
		4610029967627506430,
		7566382334276534836,
		2288460879362380348,
	}

	for i := 0; i < WIDTH; i++ {
		if inp[i] != expected[i] {
			t.Logf("Expected: %d, got: %d\n", expected[i], inp[i])
			t.Fail()
		}
	}
}

func TestHashNToMNoPad(t *testing.T) {
	inp := [WIDTH]g.GoldilocksField{
		2963773914414780088,
		8389525300242074234,
		3700959901615818008,
		6116199383751757212,
		3418607418699599889,
		8793277256263635044,
		448623437464918480,
		1857310021116627925,
		6145634616307237342,
		1548353948794474539,
		2318110128254703527,
		8347759953730634762,
	}

	res := HashNToMNoPad(inp[:], 12)

	expected := [WIDTH]g.GoldilocksField{
		3627923032009111551,
		1460752551327577353,
		1084214837491058067,
		1841622875286057462,
		3996252440506437984,
		1276718204392552803,
		8564515621134952155,
		9252927025993202701,
		1147435538714642916,
		16407277821156164797,
		11997661877740155273,
		12485021000320141292,
	}

	for i := 0; i < 12; i++ {
		if res[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestDigest(t *testing.T) {
	hFunc := NewPoseidon2()

	inputs := make([][]byte, 2)
	inputs[0] = make([]byte, 8)
	inputs[0][0] = 1
	inputs[0][1] = 2
	inputs[0][2] = 3
	inputs[0][3] = 4
	inputs[0][4] = 5
	inputs[0][5] = 6
	inputs[0][6] = 7
	inputs[0][7] = 0
	inputs[1] = make([]byte, 8)
	inputs[1][0] = 7
	inputs[1][1] = 6
	inputs[1][2] = 5
	inputs[1][3] = 4
	inputs[1][4] = 3
	inputs[1][5] = 2
	inputs[1][6] = 1
	inputs[1][7] = 0

	g1 := g.FromCanonicalLittleEndianBytesF(inputs[0]) // 289077004332300282
	g2 := g.FromCanonicalLittleEndianBytesF(inputs[1]) // 289644378102298614

	hFunc.Write(inputs[0])
	hFunc.Write(inputs[1])

	hash := hFunc.Sum(nil)

	hash2Elems := HashNoPad([]g.GoldilocksField{g1, g2})
	hash2 := hash2Elems.ToLittleEndianBytes()

	if !bytes.Equal(hash, hash2) {
		t.Logf("Expected: %v, got: %v\n", hash2, hash)
		t.Fail()
	}

	reconstructed, err := HashOutFromLittleEndianBytes(hash)
	if err != nil {
		t.Logf("Error: %v\n", err)
		t.FailNow()
	}

	for i := 0; i < 4; i++ {
		if hash2Elems[i] != reconstructed[i] {
			t.Logf("Expected: %d, got: %d\n", hash2Elems[i], reconstructed[i])
			t.Fail()
		}
	}
}

func TestHashNToHashNoPad(t *testing.T) {
	res := HashNToHashNoPad([]g.GoldilocksField{
		11295517158488612626,
		10669470463693797151,
		17232114065640264171,
		4175927072186299193,
		13985285184240204531,
		7901017084268693144,
		4326299618263946178,
		14787024750292535041,
		894520636503353046,
		12556655399058578835,
		3097737892474696200,
		7515335668060050861,
	})

	expected := HashOut{
		15396602476382546759,
		12422280135166335470,
		8165681190607828974,
		3475588160239961712,
	}

	for i := 0; i < 4; i++ {
		if res[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestHashNToHashNoPadLarge(t *testing.T) {
	res := HashNToHashNoPad([]g.GoldilocksField{
		g.GoldilocksField(g.ORDER + 1),
		g.GoldilocksField(g.ORDER + 2),
		g.GoldilocksField(g.ORDER + 3),
		g.GoldilocksField(math.MaxUint64),
		g.GoldilocksField(math.MaxUint64 - 1),
	})

	expected := HashOut{
		14216040864787980138,
		17275303675000904868,
		11831395338463193314,
		281267649235863375,
	}

	for i := 0; i < 4; i++ {
		if res[i] != expected[i] {
			t.Logf("Expected: %v, got: %v\n", expected, res)
			t.FailNow()
		}
	}
}

func TestHashTwoToOne(t *testing.T) {
	input1 := HashOut{
		3777312593917610528,
		6858608920877200812,
		5269611035257552853,
		10607733449481270434,
	}

	input2 := HashOut{
		10355703322562521155,
		1039917189921776884,
		10844249567941924238,
		14291130953945924124,
	}

	expected := HashOut{
		1453933811752520343,
		16186418140372484281,
		9207215809524681813,
		10182182911172027974,
	}

	res := HashTwoToOne(input1, input2)
	for i := 0; i < 4; i++ {
		if res[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestHashNToOne(t *testing.T) {
	hashIns := []HashOut{HashNToHashNoPad([]g.GoldilocksField{
		18231458557829081414,
		16449039301999856654,
		14758090268883299362,
		10271725147130672875,
		6253304685402495037,
		16079709420464120062,
		10838593640248082543,
		2974225335734585509,
		6365466669981419503,
		12964544245312854826,
		3161534615047618958,
		15109271288782125222,
	})}
	for i := 1; i < 12; i++ {
		hashIns = append(hashIns, HashTwoToOne(hashIns[i-1], hashIns[i-1]))
	}

	res := HashNToOne(hashIns)
	expected := HashOut{
		3346041518891302234,
		10181430332820953144,
		14852547783810217847,
		17043509806476508794,
	}
	for i := 0; i < 4; i++ {
		if res[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestHashToQuinticExtension(t *testing.T) {
	result := HashToQuinticExtension([]g.GoldilocksField{
		3451004116618606032,
		11263134342958518251,
		10957204882857370932,
		5369763041201481933,
		7695734348563036858,
		1393419330378128434,
		7387917082382606332,
	})
	expected := [5]uint64{
		17992684813643984528,
		5243896189906434327,
		7705560276311184368,
		2785244775876017560,
		14449776097783372302,
	}
	for i := 0; i < 5; i++ {
		if result[i].ToCanonicalUint64() != expected[i] {
			t.Logf("Expected limb %d to be %x, but got %x", i, expected[i], result[i])
			t.Fail()
		}
	}
}

func TestConstantsAreInTheField(t *testing.T) {
	for r := 0; r < ROUNDS_F; r++ {
		for i := 0; i < WIDTH; i++ {
			if uint64(EXTERNAL_CONSTANTS[r][i]) >= g.ORDER {
				t.Logf("External constant at round %d, index %d is not in the field: %d", r, i, EXTERNAL_CONSTANTS[r][i])
				t.Fail()
			}
		}
	}

	for r := 0; r < ROUNDS_P; r++ {
		if uint64(INTERNAL_CONSTANTS[r]) >= g.ORDER {
			t.Logf("Internal constant at round %d is not in the field: %d", r, INTERNAL_CONSTANTS[r])
			t.Fail()
		}
	}
}

func mulAccF_test1(self, x, y g.GoldilocksField) g.GoldilocksField {
	// u64 + u64 * u64 cannot overflow.
	return g.Reduce128Bit(AddUInt128(g.AsUInt128(self), MulUInt64(uint64(x), uint64(y))))
}

func mulAccF_test2(self, x, y g.GoldilocksField) g.GoldilocksField {
	hi, lo := bits.Mul64(uint64(x), uint64(y))
	lo, c := bits.Add64(lo, uint64(self), 0)
	hi += c

	t0, borrow := bits.Sub64(lo, hi>>32, 0)
	t0 -= g.EPSILON * borrow
	resWrapped, c := bits.Add64(t0, (hi&g.EPSILON)*g.EPSILON, 0)
	return g.GoldilocksField(resWrapped + g.EPSILON*c)
}

func mulAccF_test3(self, x, y g.GoldilocksField) g.GoldilocksField {
	hi, lo := bits.Mul64(uint64(x), uint64(y))
	lo, c := bits.Add64(lo, uint64(self), 0)
	hi += c
	return g.Reduce128Bit(UInt128{Hi: hi, Lo: lo})
}

func BenchmarkMulAccF(b *testing.B) {
	len := 100000000
	x := make([]g.GoldilocksField, len)
	y := make([]g.GoldilocksField, len)
	z := make([]g.GoldilocksField, len)
	for i := 0; i < len; i++ {
		x[i] = getRandomGoldilocks()
		y[i] = getRandomGoldilocks()
		z[i] = getRandomGoldilocks()
	}
	var res g.GoldilocksField
	id := 0
	b.Run("Original-MulAccF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = mulAccF_test1(x[id], y[id], z[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("Half-Inlined-MulF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = mulAccF_test3(x[id], y[id], z[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("Full-Inlined-MulF", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = mulAccF_test2(x[id], y[id], z[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
	_ = res
}

func sbox_test1(state *[12]g.GoldilocksField) {
	// fully unrolled 3 passes
	p2_0 := g.SquareF(state[0])
	p2_1 := g.SquareF(state[1])
	p2_2 := g.SquareF(state[2])
	p2_3 := g.SquareF(state[3])
	p2_4 := g.SquareF(state[4])
	p2_5 := g.SquareF(state[5])
	p2_6 := g.SquareF(state[6])
	p2_7 := g.SquareF(state[7])
	p2_8 := g.SquareF(state[8])
	p2_9 := g.SquareF(state[9])
	p2_10 := g.SquareF(state[10])
	p2_11 := g.SquareF(state[11])

	p3_0 := g.MulF(state[0], p2_0)
	p4_0 := g.SquareF(p2_0)
	p3_1 := g.MulF(state[1], p2_1)
	p4_1 := g.SquareF(p2_1)
	p3_2 := g.MulF(state[2], p2_2)
	p4_2 := g.SquareF(p2_2)
	p3_3 := g.MulF(state[3], p2_3)
	p4_3 := g.SquareF(p2_3)
	p3_4 := g.MulF(state[4], p2_4)
	p4_4 := g.SquareF(p2_4)
	p3_5 := g.MulF(state[5], p2_5)
	p4_5 := g.SquareF(p2_5)
	p3_6 := g.MulF(state[6], p2_6)
	p4_6 := g.SquareF(p2_6)
	p3_7 := g.MulF(state[7], p2_7)
	p4_7 := g.SquareF(p2_7)
	p3_8 := g.MulF(state[8], p2_8)
	p4_8 := g.SquareF(p2_8)
	p3_9 := g.MulF(state[9], p2_9)
	p4_9 := g.SquareF(p2_9)
	p3_10 := g.MulF(state[10], p2_10)
	p4_10 := g.SquareF(p2_10)
	p3_11 := g.MulF(state[11], p2_11)
	p4_11 := g.SquareF(p2_11)

	state[0] = g.MulF(p3_0, p4_0)
	state[1] = g.MulF(p3_1, p4_1)
	state[2] = g.MulF(p3_2, p4_2)
	state[3] = g.MulF(p3_3, p4_3)
	state[4] = g.MulF(p3_4, p4_4)
	state[5] = g.MulF(p3_5, p4_5)
	state[6] = g.MulF(p3_6, p4_6)
	state[7] = g.MulF(p3_7, p4_7)
	state[8] = g.MulF(p3_8, p4_8)
	state[9] = g.MulF(p3_9, p4_9)
	state[10] = g.MulF(p3_10, p4_10)
	state[11] = g.MulF(p3_11, p4_11)
}

func sbox_test2(state *[12]g.GoldilocksField) {
	// original single loop unroll
	state[0] = sboxP(state[0])
	state[1] = sboxP(state[1])
	state[2] = sboxP(state[2])
	state[3] = sboxP(state[3])
	state[4] = sboxP(state[4])
	state[5] = sboxP(state[5])
	state[6] = sboxP(state[6])
	state[7] = sboxP(state[7])
	state[8] = sboxP(state[8])
	state[9] = sboxP(state[9])
	state[10] = sboxP(state[10])
	state[11] = sboxP(state[11])
}

func sbox_group3(state *[WIDTH]g.GoldilocksField) {
	// group 0-3
	p2_0 := g.SquareF(state[0])
	p2_1 := g.SquareF(state[1])
	p2_2 := g.SquareF(state[2])
	p2_3 := g.SquareF(state[3])
	p3_0 := g.MulF(state[0], p2_0)
	p4_0 := g.SquareF(p2_0)
	p3_1 := g.MulF(state[1], p2_1)
	p4_1 := g.SquareF(p2_1)
	p3_2 := g.MulF(state[2], p2_2)
	p4_2 := g.SquareF(p2_2)
	p3_3 := g.MulF(state[3], p2_3)
	p4_3 := g.SquareF(p2_3)
	state[0] = g.MulF(p3_0, p4_0)
	state[1] = g.MulF(p3_1, p4_1)
	state[2] = g.MulF(p3_2, p4_2)
	state[3] = g.MulF(p3_3, p4_3)

	// group 4-7
	p2_4 := g.SquareF(state[4])
	p2_5 := g.SquareF(state[5])
	p2_6 := g.SquareF(state[6])
	p2_7 := g.SquareF(state[7])
	p3_4 := g.MulF(state[4], p2_4)
	p4_4 := g.SquareF(p2_4)
	p3_5 := g.MulF(state[5], p2_5)
	p4_5 := g.SquareF(p2_5)
	p3_6 := g.MulF(state[6], p2_6)
	p4_6 := g.SquareF(p2_6)
	p3_7 := g.MulF(state[7], p2_7)
	p4_7 := g.SquareF(p2_7)
	state[4] = g.MulF(p3_4, p4_4)
	state[5] = g.MulF(p3_5, p4_5)
	state[6] = g.MulF(p3_6, p4_6)
	state[7] = g.MulF(p3_7, p4_7)

	// group 8-11
	p2_8 := g.SquareF(state[8])
	p2_9 := g.SquareF(state[9])
	p2_10 := g.SquareF(state[10])
	p2_11 := g.SquareF(state[11])
	p3_8 := g.MulF(state[8], p2_8)
	p4_8 := g.SquareF(p2_8)
	p3_9 := g.MulF(state[9], p2_9)
	p4_9 := g.SquareF(p2_9)
	p3_10 := g.MulF(state[10], p2_10)
	p4_10 := g.SquareF(p2_10)
	p3_11 := g.MulF(state[11], p2_11)
	p4_11 := g.SquareF(p2_11)
	state[8] = g.MulF(p3_8, p4_8)
	state[9] = g.MulF(p3_9, p4_9)
	state[10] = g.MulF(p3_10, p4_10)
	state[11] = g.MulF(p3_11, p4_11)
}

func sbox_group4(state *[WIDTH]g.GoldilocksField) {
	// group 0-5
	p0_2 := g.SquareF(state[0])
	p1_2 := g.SquareF(state[1])
	p2_2 := g.SquareF(state[2])
	p3_2 := g.SquareF(state[3])
	p4_2 := g.SquareF(state[4])
	p5_2 := g.SquareF(state[5])
	p0_3 := g.MulF(state[0], p0_2)
	p0_4 := g.SquareF(p0_2)
	p1_3 := g.MulF(state[1], p1_2)
	p1_4 := g.SquareF(p1_2)
	p2_3 := g.MulF(state[2], p2_2)
	p2_4 := g.SquareF(p2_2)
	p3_3 := g.MulF(state[3], p3_2)
	p3_4 := g.SquareF(p3_2)
	p4_3 := g.MulF(state[4], p4_2)
	p4_4 := g.SquareF(p4_2)
	p5_3 := g.MulF(state[5], p5_2)
	p5_4 := g.SquareF(p5_2)
	state[0] = g.MulF(p0_3, p0_4)
	state[1] = g.MulF(p1_3, p1_4)
	state[2] = g.MulF(p2_3, p2_4)
	state[3] = g.MulF(p3_3, p3_4)
	state[4] = g.MulF(p4_3, p4_4)
	state[5] = g.MulF(p5_3, p5_4)

	// group 6-11
	p6_2 := g.SquareF(state[6])
	p7_2 := g.SquareF(state[7])
	p8_2 := g.SquareF(state[8])
	p9_2 := g.SquareF(state[9])
	p10_2 := g.SquareF(state[10])
	p11_2 := g.SquareF(state[11])
	p6_3 := g.MulF(state[6], p6_2)
	p6_4 := g.SquareF(p6_2)
	p7_3 := g.MulF(state[7], p7_2)
	p7_4 := g.SquareF(p7_2)
	p8_3 := g.MulF(state[8], p8_2)
	p8_4 := g.SquareF(p8_2)
	p9_3 := g.MulF(state[9], p9_2)
	p9_4 := g.SquareF(p9_2)
	p10_3 := g.MulF(state[10], p10_2)
	p10_4 := g.SquareF(p10_2)
	p11_3 := g.MulF(state[11], p11_2)
	p11_4 := g.SquareF(p11_2)
	state[6] = g.MulF(p6_3, p6_4)
	state[7] = g.MulF(p7_3, p7_4)
	state[8] = g.MulF(p8_3, p8_4)
	state[9] = g.MulF(p9_3, p9_4)
	state[10] = g.MulF(p10_3, p10_4)
	state[11] = g.MulF(p11_3, p11_4)
}

func BenchmarkSboxLoop(b *testing.B) {
	len := 10000000
	states := make([][12]g.GoldilocksField, len)
	for i := range states {
		for j := 0; j < 12; j++ {
			states[i][j] = getRandomGoldilocks()
		}
	}
	id := 0
	b.Run("Linear-Unroll-Sbox", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sbox_test1(&states[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
	id = 0
	b.Run("Original-Sbox", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sbox_test2(&states[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
	id = 0
	b.Run("Grouping-4-Sbox", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sbox_group3(&states[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
	id = 0
	b.Run("Grouping-6-Sbox", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sbox_group4(&states[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
}

func externalLayerOriginal(s *[WIDTH]UInt128) {
	for i := 0; i < WIDTH; i += 4 {
		t01 := AddUInt128(s[i], s[i+1])
		t23 := AddUInt128(s[i+2], s[i+3])
		t0123 := AddUInt128(t01, t23)

		x0 := s[i]
		x2 := s[i+2]

		s[i] = AddUInt128(AddUInt128(t0123, t01), s[i+1])
		s[i+1] = AddUInt128(AddUInt128(AddUInt128(t0123, s[i+1]), x2), x2)
		s[i+2] = AddUInt128(AddUInt128(t0123, t23), s[i+3])
		s[i+3] = AddUInt128(AddUInt128(AddUInt128(t0123, s[i+3]), x0), x0)
	}
}

func externalLayerUnrolled(s *[WIDTH]UInt128) {
	x0, x1, x2, x3 := s[0], s[1], s[2], s[3]
	t01 := AddUInt128(x0, x1)
	t23 := AddUInt128(x2, x3)
	t0123 := AddUInt128(t01, t23)
	s[0] = AddUInt128(AddUInt128(t0123, t01), x1)
	s[1] = AddUInt128(AddUInt128(t0123, x1), AddUInt128(x2, x2))
	s[2] = AddUInt128(AddUInt128(t0123, t23), x3)
	s[3] = AddUInt128(AddUInt128(t0123, x3), AddUInt128(x0, x0))

	x0, x1, x2, x3 = s[4], s[5], s[6], s[7]
	t01 = AddUInt128(x0, x1)
	t23 = AddUInt128(x2, x3)
	t0123 = AddUInt128(t01, t23)
	s[4] = AddUInt128(AddUInt128(t0123, t01), x1)
	s[5] = AddUInt128(AddUInt128(t0123, x1), AddUInt128(x2, x2))
	s[6] = AddUInt128(AddUInt128(t0123, t23), x3)
	s[7] = AddUInt128(AddUInt128(t0123, x3), AddUInt128(x0, x0))

	x0, x1, x2, x3 = s[8], s[9], s[10], s[11]
	t01 = AddUInt128(x0, x1)
	t23 = AddUInt128(x2, x3)
	t0123 = AddUInt128(t01, t23)
	s[8] = AddUInt128(AddUInt128(t0123, t01), x1)
	s[9] = AddUInt128(AddUInt128(t0123, x1), AddUInt128(x2, x2))
	s[10] = AddUInt128(AddUInt128(t0123, t23), x3)
	s[11] = AddUInt128(AddUInt128(t0123, x3), AddUInt128(x0, x0))
}

func externalLayerParallel(s *[WIDTH]UInt128) {
	x0, x1, x2, x3 := s[0], s[1], s[2], s[3]
	t := AddUInt128(AddUInt128(x0, x1), AddUInt128(x2, x3))
	s[0] = AddUInt128(AddUInt128(t, x0), AddUInt128(x1, x1))
	s[1] = AddUInt128(AddUInt128(t, x1), AddUInt128(x2, x2))
	s[2] = AddUInt128(AddUInt128(t, x2), AddUInt128(x3, x3))
	s[3] = AddUInt128(AddUInt128(t, x3), AddUInt128(x0, x0))

	x0, x1, x2, x3 = s[4], s[5], s[6], s[7]
	t = AddUInt128(AddUInt128(x0, x1), AddUInt128(x2, x3))
	s[4] = AddUInt128(AddUInt128(t, x0), AddUInt128(x1, x1))
	s[5] = AddUInt128(AddUInt128(t, x1), AddUInt128(x2, x2))
	s[6] = AddUInt128(AddUInt128(t, x2), AddUInt128(x3, x3))
	s[7] = AddUInt128(AddUInt128(t, x3), AddUInt128(x0, x0))

	x0, x1, x2, x3 = s[8], s[9], s[10], s[11]
	t = AddUInt128(AddUInt128(x0, x1), AddUInt128(x2, x3))
	s[8] = AddUInt128(AddUInt128(t, x0), AddUInt128(x1, x1))
	s[9] = AddUInt128(AddUInt128(t, x1), AddUInt128(x2, x2))
	s[10] = AddUInt128(AddUInt128(t, x2), AddUInt128(x3, x3))
	s[11] = AddUInt128(AddUInt128(t, x3), AddUInt128(x0, x0))
}

func BenchmarkExternalLayer(b *testing.B) {
	size := 10000000
	states := make([][WIDTH]UInt128, size)
	for i := range states {
		for j := 0; j < WIDTH; j++ {
			states[i][j] = UInt128{Lo: uint64(getRandomGoldilocks()), Hi: uint64(getRandomGoldilocks())}
		}
	}

	id := 0
	b.Run("Original-ExternalLayer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			externalLayerOriginal(&states[id])
			id++
			if id == size {
				id -= size
			}
		}
	})

	b.Run("Unrolled-ExternalLayer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			externalLayerUnrolled(&states[id])
			id++
			if id == size {
				id -= size
			}
		}
	})

	b.Run("Parallel-ExternalLayer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			externalLayerParallel(&states[id])
			id++
			if id == size {
				id -= size
			}
		}
	})
}

func BenchmarkArray(b *testing.B) {
	len := 100000
	x1 := make([]HashOut, len)
	x2 := make([]HashOut, len)
	y1 := make([][32]byte, len)
	y2 := make([][32]byte, len)
	z1 := make([][]byte, len)
	z2 := make([][]byte, len)
	for i := 0; i < len; i++ {
		for j := 0; j < 4; j++ {
			x1[i][j] = getRandomGoldilocks()
			x2[i][j] = getRandomGoldilocks()
		}
		z1[i] = make([]byte, 32)
		z2[i] = make([]byte, 32)
		for j := 0; j < 32; j++ {
			z1[i][j] = byte(getRandomGoldilocks())
			z2[i][j] = byte(getRandomGoldilocks())
			y1[i][j] = byte(getRandomGoldilocks())
			y2[i][j] = byte(getRandomGoldilocks())
		}
	}
	var res1 HashOut
	var res2 [32]byte
	var res3 []byte
	id := 0
	b.Run("Original-HashPair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res1 = HashTwoToOne(x1[id], x2[id])
			_ = res1
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("HashArrayPair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res2 = HashPair(y1[id], y2[id])
			_ = res2
			id++
			if id == len {
				id -= len
			}
		}
	})

	b.Run("HashPair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res3 = HashPairBytes(z1[id], z2[id])
			_ = res3
			id++
			if id == len {
				id -= len
			}
		}
	})
}

func TestHashPair(t *testing.T) {
	len := 100000
	for i := 0; i < len; i++ {
		var X1, Y1 [32]byte
		var X2, Y2 []byte
		X2 = make([]byte, 32)
		Y2 = make([]byte, 32)
		for j := 0; j < 32; j++ {
			X1[j] = byte(getRandomGoldilocks())
			Y1[j] = byte(getRandomGoldilocks())
			X2[j] = X1[j]
			Y2[j] = Y1[j]
		}
		res1 := HashPair(X1, Y1)
		res2 := HashPairBytes(X2, Y2)
		for j := 0; j < 32; j++ {
			if res1[j] != res2[j] {
				t.Errorf("Hashes don't match %d %d", res1, res2)
			}
		}
	}

}

func externalLinearLayer_2(s *[WIDTH]g.GoldilocksField) {
	v0 := g.AsUInt128(s[0])
	v1 := g.AsUInt128(s[1])
	v2 := g.AsUInt128(s[2])
	v3 := g.AsUInt128(s[3])
	v4 := g.AsUInt128(s[4])
	v5 := g.AsUInt128(s[5])
	v6 := g.AsUInt128(s[6])
	v7 := g.AsUInt128(s[7])
	v8 := g.AsUInt128(s[8])
	v9 := g.AsUInt128(s[9])
	v10 := g.AsUInt128(s[10])
	v11 := g.AsUInt128(s[11])

	// chunk 0
	t01 := AddUInt128(v0, v1)
	t23 := AddUInt128(v2, v3)
	t := AddUInt128(t01, t23)
	n0 := AddUInt128(AddUInt128(t, t01), v1)
	n1 := AddUInt128(AddUInt128(t, v1), AddUInt128(v2, v2))
	n2 := AddUInt128(AddUInt128(t, t23), v3)
	n3 := AddUInt128(AddUInt128(t, v3), AddUInt128(v0, v0))

	// chunk 1
	t01 = AddUInt128(v4, v5)
	t23 = AddUInt128(v6, v7)
	t = AddUInt128(t01, t23)
	n4 := AddUInt128(AddUInt128(t, t01), v5)
	n5 := AddUInt128(AddUInt128(t, v5), AddUInt128(v6, v6))
	n6 := AddUInt128(AddUInt128(t, t23), v7)
	n7 := AddUInt128(AddUInt128(t, v7), AddUInt128(v4, v4))

	// chunk 2
	t01 = AddUInt128(v8, v9)
	t23 = AddUInt128(v10, v11)
	t = AddUInt128(t01, t23)
	n8 := AddUInt128(AddUInt128(t, t01), v9)
	n9 := AddUInt128(AddUInt128(t, v9), AddUInt128(v10, v10))
	n10 := AddUInt128(AddUInt128(t, t23), v11)
	n11 := AddUInt128(AddUInt128(t, v11), AddUInt128(v8, v8))

	sum0 := AddUInt128(n0, AddUInt128(n4, n8))
	sum1 := AddUInt128(n1, AddUInt128(n5, n9))
	sum2 := AddUInt128(n2, AddUInt128(n6, n10))
	sum3 := AddUInt128(n3, AddUInt128(n7, n11))

	s[0] = g.Reduce96Bit(AddUInt128(n0, sum0))
	s[4] = g.Reduce96Bit(AddUInt128(n4, sum0))
	s[8] = g.Reduce96Bit(AddUInt128(n8, sum0))

	s[1] = g.Reduce96Bit(AddUInt128(n1, sum1))
	s[5] = g.Reduce96Bit(AddUInt128(n5, sum1))
	s[9] = g.Reduce96Bit(AddUInt128(n9, sum1))

	s[2] = g.Reduce96Bit(AddUInt128(n2, sum2))
	s[6] = g.Reduce96Bit(AddUInt128(n6, sum2))
	s[10] = g.Reduce96Bit(AddUInt128(n10, sum2))

	s[3] = g.Reduce96Bit(AddUInt128(n3, sum3))
	s[7] = g.Reduce96Bit(AddUInt128(n7, sum3))
	s[11] = g.Reduce96Bit(AddUInt128(n11, sum3))
}

func BenchmarkExternalLayer_2(b *testing.B) {
	len := 100000
	s := make([][WIDTH]g.GoldilocksField, len)
	for i := 0; i < len; i++ {
		for j := 0; j < 12; j++ {
			s[i][j] = getRandomGoldilocks()
		}
	}
	id := 0
	b.Run("Original-ExternalLayer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			externalLinearLayer(&s[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("Inlined-Version", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			externalLinearLayer_2(&s[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
}

func internalLinearLayer_2(s *[WIDTH]g.GoldilocksField) {
	// Load state into locals (register-resident, no pointer-indexed scratch).
	v0 := g.AsUInt128(s[0])
	v1 := g.AsUInt128(s[1])
	v2 := g.AsUInt128(s[2])
	v3 := g.AsUInt128(s[3])
	v4 := g.AsUInt128(s[4])
	v5 := g.AsUInt128(s[5])
	v6 := g.AsUInt128(s[6])
	v7 := g.AsUInt128(s[7])
	v8 := g.AsUInt128(s[8])
	v9 := g.AsUInt128(s[9])
	v10 := g.AsUInt128(s[10])
	v11 := g.AsUInt128(s[11])

	// --- M4 on each 4-lane chunk: out = circ(2,3,1,1) * in ---
	// chunk 0
	t01 := AddUInt128(v0, v1)
	t23 := AddUInt128(v2, v3)
	t := AddUInt128(t01, t23)
	n0 := AddUInt128(AddUInt128(t, t01), v1)
	n1 := AddUInt128(AddUInt128(t, v1), AddUInt128(v2, v2))
	n2 := AddUInt128(AddUInt128(t, t23), v3)
	n3 := AddUInt128(AddUInt128(t, v3), AddUInt128(v0, v0))

	// chunk 1
	t01 = AddUInt128(v4, v5)
	t23 = AddUInt128(v6, v7)
	t = AddUInt128(t01, t23)
	n4 := AddUInt128(AddUInt128(t, t01), v5)
	n5 := AddUInt128(AddUInt128(t, v5), AddUInt128(v6, v6))
	n6 := AddUInt128(AddUInt128(t, t23), v7)
	n7 := AddUInt128(AddUInt128(t, v7), AddUInt128(v4, v4))

	// chunk 2
	t01 = AddUInt128(v8, v9)
	t23 = AddUInt128(v10, v11)
	t = AddUInt128(t01, t23)
	n8 := AddUInt128(AddUInt128(t, t01), v9)
	n9 := AddUInt128(AddUInt128(t, v9), AddUInt128(v10, v10))
	n10 := AddUInt128(AddUInt128(t, t23), v11)
	n11 := AddUInt128(AddUInt128(t, v11), AddUInt128(v8, v8))

	sum0 := AddUInt128(n0, AddUInt128(n4, n8))
	sum1 := AddUInt128(n1, AddUInt128(n5, n9))
	sum2 := AddUInt128(n2, AddUInt128(n6, n10))
	sum3 := AddUInt128(n3, AddUInt128(n7, n11))

	s[0] = g.Reduce96Bit(AddUInt128(n0, sum0))
	s[4] = g.Reduce96Bit(AddUInt128(n4, sum0))
	s[8] = g.Reduce96Bit(AddUInt128(n8, sum0))

	s[1] = g.Reduce96Bit(AddUInt128(n1, sum1))
	s[5] = g.Reduce96Bit(AddUInt128(n5, sum1))
	s[9] = g.Reduce96Bit(AddUInt128(n9, sum1))

	s[2] = g.Reduce96Bit(AddUInt128(n2, sum2))
	s[6] = g.Reduce96Bit(AddUInt128(n6, sum2))
	s[10] = g.Reduce96Bit(AddUInt128(n10, sum2))
	s[3] = g.Reduce96Bit(AddUInt128(n3, sum3))
	s[7] = g.Reduce96Bit(AddUInt128(n7, sum3))
	s[11] = g.Reduce96Bit(AddUInt128(n11, sum3))
}

func BenchmarkInternalLinearLayer(b *testing.B) {
	len := 100000
	s := make([][WIDTH]g.GoldilocksField, len)
	for i := 0; i < len; i++ {
		for j := 0; j < 12; j++ {
			s[i][j] = getRandomGoldilocks()
		}
	}
	id := 0
	b.Run("Original-InternalLayer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			partialRounds(&s[id])
			id++
			if id == len {
				id -= len
			}
		}
	})

	id = 0
	b.Run("Inlined-Version", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// partialRounds_2(&s[id])
			id++
			if id == len {
				id -= len
			}
		}
	})
}
