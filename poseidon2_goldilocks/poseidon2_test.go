package poseidon2

import (
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	"github.com/stretchr/testify/assert"
)

func TestPermute(t *testing.T) {
	inp := [WIDTH]g.Element{
		g.FromUint64(5417613058500526590),
		g.FromUint64(2481548824842427254),
		g.FromUint64(6473243198879784792),
		g.FromUint64(1720313757066167274),
		g.FromUint64(2806320291675974571),
		g.FromUint64(7407976414706455446),
		g.FromUint64(1105257841424046885),
		g.FromUint64(7613435757403328049),
		g.FromUint64(3376066686066811538),
		g.FromUint64(5888575799323675710),
		g.FromUint64(6689309723188675948),
		g.FromUint64(2468250420241012720),
	}

	p := Poseidon2{}
	p.Permute(&inp)

	expected := [WIDTH]g.Element{
		g.FromUint64(5364184781011389007),
		g.FromUint64(15309475861242939136),
		g.FromUint64(5983386513087443499),
		g.FromUint64(886942118604446276),
		g.FromUint64(14903657885227062600),
		g.FromUint64(7742650891575941298),
		g.FromUint64(1962182278500985790),
		g.FromUint64(10213480816595178755),
		g.FromUint64(3510799061817443836),
		g.FromUint64(4610029967627506430),
		g.FromUint64(7566382334276534836),
		g.FromUint64(2288460879362380348),
	}

	for i := 0; i < WIDTH; i++ {
		if inp[i] != expected[i] {
			t.Fail()
		}
	}
}

func TestHashNToMNoPad(t *testing.T) {
	inp := [WIDTH]g.Element{
		g.FromUint64(2963773914414780088),
		g.FromUint64(8389525300242074234),
		g.FromUint64(3700959901615818008),
		g.FromUint64(6116199383751757212),
		g.FromUint64(3418607418699599889),
		g.FromUint64(8793277256263635044),
		g.FromUint64(448623437464918480),
		g.FromUint64(1857310021116627925),
		g.FromUint64(6145634616307237342),
		g.FromUint64(1548353948794474539),
		g.FromUint64(2318110128254703527),
		g.FromUint64(8347759953730634762),
	}

	p := Poseidon2{}
	res := p.HashNToMNoPad(inp[:], 12)

	expected := [WIDTH]g.Element{
		g.FromUint64(3627923032009111551),
		g.FromUint64(1460752551327577353),
		g.FromUint64(1084214837491058067),
		g.FromUint64(1841622875286057462),
		g.FromUint64(3996252440506437984),
		g.FromUint64(1276718204392552803),
		g.FromUint64(8564515621134952155),
		g.FromUint64(9252927025993202701),
		g.FromUint64(1147435538714642916),
		g.FromUint64(16407277821156164797),
		g.FromUint64(11997661877740155273),
		g.FromUint64(12485021000320141292),
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

	hash1 := g.Element{}
	hash1.SetBytes(hFunc.Sum(nil))

	one := g.Element{0}
	one.SetBytes(inputs[0])
	two := g.Element{0}
	two.SetBytes(inputs[1])

	p := Poseidon2{}
	hash2 := p.HashNToMNoPad([]g.Element{one, two}, 1)[0]

	assert.True(t, hash1.Equal(&hash2), "%s != %s", hash1, hash2)
}
