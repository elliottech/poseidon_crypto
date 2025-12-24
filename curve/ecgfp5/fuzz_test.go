package ecgfp5

import (
	"math/big"
	"testing"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
)

// FuzzPointAddition fuzzes point addition with random inputs
func FuzzPointAddition(f *testing.F) {
	// Seed with valid point encoded as Weierstrass
	G := GENERATOR_ECgFp5Point
	O := NEUTRAL_ECgFp5Point
	gEncoded := G.Encode()
	oEncoded := O.Encode()
	f.Add(gEncoded.ToLittleEndianBytes(), oEncoded.ToLittleEndianBytes())

	// Seed with zeros
	zeroBytes := make([]byte, 40)
	f.Add(zeroBytes, zeroBytes)

	f.Fuzz(func(t *testing.T, data1, data2 []byte) {
		if len(data1) != 40 || len(data2) != 40 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Point addition panicked with: %v", r)
			}
		}()

		// Try to create points from encoded bytes
		elem1, err1 := gFp5.FromCanonicalLittleEndianBytes(data1)
		elem2, err2 := gFp5.FromCanonicalLittleEndianBytes(data2)

		if err1 != nil || err2 != nil {
			return // Invalid encoding
		}

		// Try to decode as points
		p1, ok1 := Decode(elem1)
		p2, ok2 := Decode(elem2)

		if !ok1 || !ok2 {
			return // Not valid curve points
		}

		// Should not panic
		_ = p1.Add(p2)
	})
}

// FuzzScalarMultiplication fuzzes scalar multiplication with random scalars
func FuzzScalarMultiplication(f *testing.F) {
	// Seed with valid scalar
	s := SampleScalar()
	f.Add(s.ToLittleEndianBytes())

	// Seed with zero
	f.Add(make([]byte, 40))

	// Seed with max values
	maxBytes := make([]byte, 40)
	for i := range maxBytes {
		maxBytes[i] = 0xFF
	}
	f.Add(maxBytes)

	f.Fuzz(func(t *testing.T, scalarData []byte) {
		if len(scalarData) != 40 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Scalar multiplication panicked with: %v", r)
			}
		}()

		scalar := ScalarElementFromLittleEndianBytes(scalarData)

		// Skip zero scalar (would create neutral element which is fine but not interesting)
		if scalar[0] == 0 && scalar[1] == 0 && scalar[2] == 0 && scalar[3] == 0 && scalar[4] == 0 {
			return
		}

		// Should not panic
		result := GENERATOR_ECgFp5Point.Mul(scalar)
		_ = result
	})
}

// FuzzPointDoubling fuzzes point doubling operations
func FuzzPointDoubling(f *testing.F) {
	// Seed with generator
	G := GENERATOR_ECgFp5Point
	gEncoded := G.Encode()
	f.Add(gEncoded.ToLittleEndianBytes())

	// Seed with neutral
	O := NEUTRAL_ECgFp5Point
	oEncoded := O.Encode()
	f.Add(oEncoded.ToLittleEndianBytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 40 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Point doubling panicked with: %v", r)
			}
		}()

		elem, err := gFp5.FromCanonicalLittleEndianBytes(data)
		if err != nil {
			return
		}

		p, ok := Decode(elem)
		if !ok {
			return // Not a valid curve point
		}

		// Should not panic
		_ = p.Double()
	})
}

// FuzzPointEncoding fuzzes point encoding/decoding round-trips
func FuzzPointEncoding(f *testing.F) {
	// Seed with generator
	G := GENERATOR_ECgFp5Point
	encoded := G.Encode()
	f.Add(encoded.ToLittleEndianBytes())

	// Seed with zeros
	f.Add(make([]byte, 40))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 40 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Point encoding panicked with: %v", r)
			}
		}()

		elem, err := gFp5.FromCanonicalLittleEndianBytes(data)
		if err != nil {
			return
		}

		// Try to decode as point
		point, ok := Decode(elem)
		if !ok {
			return // Not a valid point, which is fine
		}

		// If decoding succeeded, round-trip should work
		reencoded := point.Encode()
		point2, ok2 := Decode(reencoded)
		if !ok2 {
			t.Error("Round-trip encoding failed")
			return
		}

		// Points should be equal
		if !point.Equals(point2) {
			t.Error("Round-trip produced different point")
		}
	})
}

// FuzzScalarArithmetic fuzzes scalar field arithmetic operations
func FuzzScalarArithmetic(f *testing.F) {
	// Seed with valid scalars
	s1 := SampleScalar()
	s2 := SampleScalar()
	f.Add(s1.ToLittleEndianBytes(), s2.ToLittleEndianBytes())

	// Seed with zeros
	f.Add(make([]byte, 40), make([]byte, 40))

	f.Fuzz(func(t *testing.T, data1, data2 []byte) {
		if len(data1) != 40 || len(data2) != 40 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Scalar arithmetic panicked with: %v", r)
			}
		}()

		s1 := ScalarElementFromLittleEndianBytes(data1)
		s2 := ScalarElementFromLittleEndianBytes(data2)

		// Test basic operations don't panic
		_ = s1.Add(s2)
		_ = s1.Sub(s2)
		_ = s1.Mul(s2)
		_ = ZERO.Sub(s1)

		// Test commutativity of addition
		add12 := s1.Add(s2)
		add21 := s2.Add(s1)
		if !add12.Equals(add21) {
			t.Error("Addition should be commutative")
		}
	})
}

// TestPointAtInfinityOperations tests that the point at infinity (neutral element) behaves correctly
// Inspired by Wycheproof's PointDuplication and edge case tests
// Bug reference: CVE-2020-12607, CVE-2015-2730
func TestPointAtInfinityOperations(t *testing.T) {
	neutral := NEUTRAL_ECgFp5Point
	generator := GENERATOR_ECgFp5Point

	tests := []struct {
		name     string
		op       func() ECgFp5Point
		expected ECgFp5Point
	}{
		{
			name:     "O  O = O",
			op:       func() ECgFp5Point { return neutral.Add(neutral) },
			expected: neutral,
		},
		{
			name:     "O  G = G",
			op:       func() ECgFp5Point { return neutral.Add(generator) },
			expected: generator,
		},
		{
			name:     "G  O = G",
			op:       func() ECgFp5Point { return generator.Add(neutral) },
			expected: generator,
		},
		{
			name:     "2*O = O",
			op:       func() ECgFp5Point { return neutral.Double() },
			expected: neutral,
		},
		{
			name:     "O * scalar = O",
			op:       func() ECgFp5Point { return neutral.Mul(ONE) },
			expected: neutral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.op()
			if !result.Equals(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
			if !result.IsNeutral() && tt.expected.IsNeutral() {
				t.Error("Result should be neutral but isn't")
			}
		})
	}
}

// TestPointAdditionIdentities tests group law identities
func TestPointAdditionIdentities(t *testing.T) {
	scalar := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(scalar)

	// Test P  O = P
	result := P.Add(NEUTRAL_ECgFp5Point)
	if !result.Equals(P) {
		t.Error("P  O should equal P")
	}

	// Test O  P = P
	result = NEUTRAL_ECgFp5Point.Add(P)
	if !result.Equals(P) {
		t.Error("O  P should equal P")
	}

	// Test P  P = 2P
	doubleDirect := P.Double()
	doubleViaAdd := P.Add(P)
	if !doubleDirect.Equals(doubleViaAdd) {
		t.Error("P.Double() should equal P.Add(P)")
	}
}

// TestScalarMultiplicationByZero tests that multiplying any point by zero gives the neutral element
func TestScalarMultiplicationByZero(t *testing.T) {
	s1 := SampleScalar()
	points := []ECgFp5Point{
		GENERATOR_ECgFp5Point,
		NEUTRAL_ECgFp5Point,
		GENERATOR_ECgFp5Point.Mul(TWO),
		GENERATOR_ECgFp5Point.Mul(s1),
	}

	zero := ZERO

	for i, P := range points {
		t.Run("point_"+string(rune('0'+i)), func(t *testing.T) {
			result := P.Mul(zero)
			if !result.IsNeutral() {
				t.Errorf("P * 0 should be neutral, got %v", result)
			}
		})
	}
}

// TestScalarMultiplicationByOne tests that multiplying any point by one returns the same point
func TestScalarMultiplicationByOne(t *testing.T) {
	s1 := SampleScalar()
	points := []ECgFp5Point{
		GENERATOR_ECgFp5Point,
		GENERATOR_ECgFp5Point.Mul(TWO),
		GENERATOR_ECgFp5Point.Mul(s1),
	}

	one := ONE

	for i, P := range points {
		t.Run("point_"+string(rune('0'+i)), func(t *testing.T) {
			result := P.Mul(one)
			if !result.Equals(P) {
				t.Errorf("P * 1 should equal P")
			}
		})
	}
}

// TestScalarMultiplicationByOrder tests that multiplying the generator by the group order gives neutral
func TestScalarMultiplicationByOrder(t *testing.T) {
	// ORDER * G should = O (point at infinity)
	orderScalar := FromNonCanonicalBigInt(ORDER)
	result := GENERATOR_ECgFp5Point.Mul(orderScalar)

	if !result.IsNeutral() {
		t.Error("G * ORDER should be neutral element")
	}
}

// TestScalarMultiplicationEdgeCases tests scalar multiplication with boundary values
// Inspired by Wycheproof's ArithmeticError test case
func TestScalarMultiplicationEdgeCases(t *testing.T) {
	P := GENERATOR_ECgFp5Point

	tests := []struct {
		name   string
		scalar ECgFp5Scalar
	}{
		{"ONE", ONE},
		{"TWO", TWO},
		{"NEG_ONE", NEG_ONE},
		{"ORDER-1", FromNonCanonicalBigInt(new(big.Int).Sub(ORDER, big.NewInt(1)))},
		{"ORDER-2", FromNonCanonicalBigInt(new(big.Int).Sub(ORDER, big.NewInt(2)))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These should not panic and should produce valid points
			result := P.Mul(tt.scalar)

			// Verify the result encodes and decodes correctly
			encoded := result.Encode()
			decoded, ok := Decode(encoded)
			if !ok {
				t.Errorf("Failed to decode point from %s scalar multiplication", tt.name)
			}
			if !decoded.Equals(result) {
				t.Errorf("Decoded point doesn't match original for %s", tt.name)
			}
		})
	}
}

// TestPointDoubleConsistency tests that repeated doubling matches scalar multiplication by powers of 2
func TestPointDoubleConsistency(t *testing.T) {
	P := GENERATOR_ECgFp5Point

	// Test for powers of 2: 2, 4, 8, 16, 32, 64
	for i := 1; i <= 6; i++ {
		power := 1 << i // 2^i
		scalar := FromNonCanonicalBigInt(big.NewInt(int64(power)))

		// Method 1: Repeated doubling
		doubled := P
		for j := 0; j < i; j++ {
			doubled = doubled.Double()
		}

		// Method 2: Scalar multiplication
		multiplied := P.Mul(scalar)

		if !doubled.Equals(multiplied) {
			t.Errorf("Repeated doubling (%d times) doesn't match scalar multiplication by %d", i, power)
		}
	}
}

// TestMDoubleConsistency tests that MDouble matches repeated Double
func TestMDoubleConsistency(t *testing.T) {
	s := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(s)

	for n := uint32(0); n <= 10; n++ {
		// Method 1: MDouble
		mDoubled := P.MDouble(n)

		// Method 2: Repeated Double
		repeated := P
		for i := uint32(0); i < n; i++ {
			repeated = repeated.Double()
		}

		if !mDoubled.Equals(repeated) {
			t.Errorf("MDouble(%d) doesn't match %d repeated Doubles", n, n)
		}
	}
}

// TestInvalidPointDecoding tests that invalid encodings are properly rejected
// Inspired by Wycheproof's InvalidEncoding test case
func TestInvalidPointDecoding(t *testing.T) {
	// Test with known invalid encodings
	invalidEncodings := []gFp5.Element{
		{
			g.GoldilocksField(13557832913345268708),
			g.GoldilocksField(15669280705791538619),
			g.GoldilocksField(8534654657267986396),
			g.GoldilocksField(12533218303838131749),
			g.GoldilocksField(5058070698878426028),
		},
		{
			g.GoldilocksField(135036726621282077),
			g.GoldilocksField(17283229938160287622),
			g.GoldilocksField(13113167081889323961),
			g.GoldilocksField(1653240450380825271),
			g.GoldilocksField(520025869628727862),
		},
	}

	for i, encoding := range invalidEncodings {
		t.Run("invalid_"+string(rune('0'+i)), func(t *testing.T) {
			if CanBeDecodedIntoPoint(encoding) {
				t.Error("CanBeDecodedIntoPoint should return false for invalid encoding")
			}

			_, ok := Decode(encoding)
			if ok {
				t.Error("Decode should fail for invalid encoding")
			}
		})
	}
}

// TestBoundaryFieldValues tests points with extreme field element values
func TestBoundaryFieldValues(t *testing.T) {
	// Test encoding/decoding with boundary field values
	boundaryElements := []gFp5.Element{
		gFp5.FP5_ZERO,
		gFp5.FP5_ONE,
		gFp5.FP5_TWO,
		// Maximum valid goldilocks values in each limb
		{g.GoldilocksField(g.ORDER - 1), g.GoldilocksField(0), g.GoldilocksField(0), g.GoldilocksField(0), g.GoldilocksField(0)},
	}

	for i, elem := range boundaryElements {
		t.Run("boundary_"+string(rune('0'+i)), func(t *testing.T) {
			canDecode := CanBeDecodedIntoPoint(elem)
			point, decodeOk := Decode(elem)

			if canDecode != decodeOk {
				t.Error("CanBeDecodedIntoPoint and Decode return inconsistent results")
			}

			if decodeOk {
				// If it decoded, it should encode back
				encoded := point.Encode()
				if !gFp5.Equals(encoded, elem) {
					// For zero, encoding might differ
					if !gFp5.IsZero(elem) {
						t.Error("Encode(Decode(x)) should equal x for valid encodings")
					}
				}
			}
		})
	}
}

// TestScalarMultiplicationDistributivity tests that scalar multiplication is distributive
// k*(PQ) = k*P  k*Q
func TestScalarMultiplicationDistributivity(t *testing.T) {
	k := SampleScalar()
	s1 := SampleScalar()
	s2 := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(s1)
	Q := GENERATOR_ECgFp5Point.Mul(s2)

	// k*(PQ)
	lhs := P.Add(Q).Mul(k)

	// k*P  k*Q
	rhs := P.Mul(k).Add(Q.Mul(k))

	if !lhs.Equals(rhs) {
		t.Error("Scalar multiplication should be distributive: k*(PQ) = k*P  k*Q")
	}
}

// TestScalarMultiplicationAssociativity tests (k*m)*P = k*(m*P)
func TestScalarMultiplicationAssociativity(t *testing.T) {
	k := SampleScalar()
	m := SampleScalar()
	P := GENERATOR_ECgFp5Point

	// (k*m)*P
	km := k.Mul(m)
	lhs := P.Mul(km)

	// k*(m*P)
	mP := P.Mul(m)
	rhs := mP.Mul(k)

	if !lhs.Equals(rhs) {
		t.Error("Scalar multiplication should be associative: (k*m)*P = k*(m*P)")
	}
}

// TestPointAdditionCommutativity tests that P  Q = Q  P
func TestPointAdditionCommutativity(t *testing.T) {
	s1 := SampleScalar()
	s2 := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(s1)
	Q := GENERATOR_ECgFp5Point.Mul(s2)

	pq := P.Add(Q)
	qp := Q.Add(P)

	if !pq.Equals(qp) {
		t.Error("Point addition should be commutative: P  Q = Q  P")
	}
}

// TestPointAdditionAssociativity tests that (P  Q)  R = P  (Q  R)
func TestPointAdditionAssociativity(t *testing.T) {
	s1 := SampleScalar()
	s2 := SampleScalar()
	s3 := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(s1)
	Q := GENERATOR_ECgFp5Point.Mul(s2)
	R := GENERATOR_ECgFp5Point.Mul(s3)

	// (P  Q)  R
	lhs := P.Add(Q).Add(R)

	// P  (Q  R)
	rhs := P.Add(Q.Add(R))

	if !lhs.Equals(rhs) {
		t.Error("Point addition should be associative: (P  Q)  R = P  (Q  R)")
	}
}

// TestAffineAdditionConsistency tests that AddAffine matches regular Add
func TestAffineAdditionConsistency(t *testing.T) {
	s1 := SampleScalar()
	s2 := SampleScalar()
	P := GENERATOR_ECgFp5Point.Mul(s1)
	Q := GENERATOR_ECgFp5Point.Mul(s2)

	// Convert Q to affine
	qAffine := BatchToAffine([]ECgFp5Point{Q})[0]

	// Regular addition
	regularAdd := P.Add(Q)

	// Affine addition
	affineAdd := P.AddAffine(qAffine)

	if !regularAdd.Equals(affineAdd) {
		t.Error("AddAffine should produce same result as regular Add")
	}
}

// TestBatchToAffineCorrectness tests that batch conversion preserves point identity
func TestBatchToAffineCorrectness(t *testing.T) {
	// Create multiple points
	points := make([]ECgFp5Point, 5)
	for i := range points {
		s := SampleScalar()
		points[i] = GENERATOR_ECgFp5Point.Mul(s)
	}

	// Convert to affine
	affinePoints := BatchToAffine(points)

	// Verify each point
	for i := range points {
		// Convert affine back to projective and compare
		projected := affinePoints[i].ToPoint()
		if !projected.Equals(points[i]) {
			t.Errorf("Affine conversion doesn't preserve point %d", i)
		}
	}
}

// TestGeneratorOrderValidation tests that the generator has the expected order
func TestGeneratorOrderValidation(t *testing.T) {
	G := GENERATOR_ECgFp5Point

	// G should not be neutral
	if G.IsNeutral() {
		t.Error("Generator should not be neutral")
	}

	// ORDER * G should be neutral
	orderScalar := FromNonCanonicalBigInt(ORDER)
	result := G.Mul(orderScalar)
	if !result.IsNeutral() {
		t.Error("ORDER * G should be neutral")
	}

	// (ORDER-1) * G should NOT be neutral
	orderMinus1 := FromNonCanonicalBigInt(new(big.Int).Sub(ORDER, big.NewInt(1)))
	result = G.Mul(orderMinus1)
	if result.IsNeutral() {
		t.Error("(ORDER-1) * G should not be neutral")
	}
}

// TestEncodingRoundTrip tests that encoding and decoding are inverses
func TestEncodingRoundTrip(t *testing.T) {
	// Test with multiple random points
	for i := 0; i < 10; i++ {
		s := SampleScalar()
		P := GENERATOR_ECgFp5Point.Mul(s)

		// Encode then decode
		encoded := P.Encode()
		decoded, ok := Decode(encoded)

		if !ok {
			t.Errorf("Failed to decode point %d", i)
			continue
		}

		if !decoded.Equals(P) {
			t.Errorf("Decode(Encode(P)) != P for point %d", i)
		}

		// Encode the decoded point again
		reencoded := decoded.Encode()
		if !gFp5.Equals(reencoded, encoded) {
			t.Errorf("Re-encoding doesn't match original encoding for point %d", i)
		}
	}
}
