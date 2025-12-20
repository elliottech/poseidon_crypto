package int

import "testing"

func TestRecodeSigned5_161(t *testing.T) {
	scalar1 := Signed161{
		0x1234567890abcdef,
		0xfedcba0987654321,
		0x0fedcba987654321,
	}

	expectedValues := [33]int32{
		15, 15, -13, -8, 11, 8, 2, 15, -10, 3, 13, 4, -15, -15, 13, 8, 5, -5, 2, -13, 1, -3, -13, -4, -1, 16, 8, 6, -12, -13, -2, -15, 0,
	}
	for i, elem := range RecodeSigned5(scalar1) {
		if elem != expectedValues[i] {
			t.Fatalf("Expected ss[%d] to be %d, but got %d", i, expectedValues[i], elem)
		}
	}
}
