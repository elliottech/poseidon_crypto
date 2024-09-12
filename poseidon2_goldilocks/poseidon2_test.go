package poseidon2

import (
	"testing"

	f "github.com/consensys/gnark-crypto/field/goldilocks"

	"github.com/stretchr/testify/assert"
)

func TestPermute(t *testing.T) {
	inp := [WIDTH]f.Element{
		f.NewElement(5417613058500526590),
		f.NewElement(2481548824842427254),
		f.NewElement(6473243198879784792),
		f.NewElement(1720313757066167274),
		f.NewElement(2806320291675974571),
		f.NewElement(7407976414706455446),
		f.NewElement(1105257841424046885),
		f.NewElement(7613435757403328049),
		f.NewElement(3376066686066811538),
		f.NewElement(5888575799323675710),
		f.NewElement(6689309723188675948),
		f.NewElement(2468250420241012720),
	}

	p := Poseidon2{}
	p.Permute(&inp)

	expected := [WIDTH]f.Element{
		f.NewElement(5364184781011389007),
		f.NewElement(15309475861242939136),
		f.NewElement(5983386513087443499),
		f.NewElement(886942118604446276),
		f.NewElement(14903657885227062600),
		f.NewElement(7742650891575941298),
		f.NewElement(1962182278500985790),
		f.NewElement(10213480816595178755),
		f.NewElement(3510799061817443836),
		f.NewElement(4610029967627506430),
		f.NewElement(7566382334276534836),
		f.NewElement(2288460879362380348),
	}

	for i := 0; i < WIDTH; i++ {
		if inp[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestHashNToMNoPad(t *testing.T) {
	inp := [WIDTH]f.Element{
		f.NewElement(2963773914414780088),
		f.NewElement(8389525300242074234),
		f.NewElement(3700959901615818008),
		f.NewElement(6116199383751757212),
		f.NewElement(3418607418699599889),
		f.NewElement(8793277256263635044),
		f.NewElement(448623437464918480),
		f.NewElement(1857310021116627925),
		f.NewElement(6145634616307237342),
		f.NewElement(1548353948794474539),
		f.NewElement(2318110128254703527),
		f.NewElement(8347759953730634762),
	}

	p := Poseidon2{}
	res := p.HashNToMNoPad(inp[:], 12)

	expected := [WIDTH]f.Element{
		f.NewElement(3627923032009111551),
		f.NewElement(1460752551327577353),
		f.NewElement(1084214837491058067),
		f.NewElement(1841622875286057462),
		f.NewElement(3996252440506437984),
		f.NewElement(1276718204392552803),
		f.NewElement(8564515621134952155),
		f.NewElement(9252927025993202701),
		f.NewElement(1147435538714642916),
		f.NewElement(16407277821156164797),
		f.NewElement(11997661877740155273),
		f.NewElement(12485021000320141292),
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
	inputs[0] = make([]byte, 1)
	inputs[0][0] = 1
	inputs[1] = make([]byte, 1)
	inputs[1][0] = 2

	hFunc.Write(inputs[0])
	hFunc.Write(inputs[1])

	hash1 := f.Element{}
	hash1.SetBytes(hFunc.Sum(nil))

	one := f.Element{0}
	one.SetBytes(inputs[0])
	two := f.Element{0}
	two.SetBytes(inputs[1])

	p := Poseidon2{}
	hash2 := p.HashNToMNoPad([]f.Element{one, two}, 1)[0]

	assert.True(t, hash1.Equal(&hash2), "%s != %s", hash1, hash2)
}
