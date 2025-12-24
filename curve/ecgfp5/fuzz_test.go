package ecgfp5

import (
	"testing"

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
