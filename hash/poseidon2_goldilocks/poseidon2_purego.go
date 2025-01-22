package poseidon2

import (
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

func HashNToMNoPad(input []g.Element, numOutputs int) []g.Element {
	var perm [WIDTH]g.Element
	for i := 0; i < len(input); i += RATE {
		for j := 0; j < RATE && i+j < len(input); j++ {
			perm[j].Set(&input[i+j])
		}
		Permute(&perm)
	}

	outputs := make([]g.Element, 0, numOutputs)
	for {
		for i := 0; i < RATE; i++ {
			outputs = append(outputs, perm[i])
			if len(outputs) == numOutputs {
				return outputs
			}
		}
		Permute(&perm)
	}
}

func Permute(input *[WIDTH]g.Element) {
	externalLinearLayer(input)
	fullRounds(input, 0)
	partialRounds(input)
	fullRounds(input, ROUNDS_F_HALF)
}

func fullRounds(state *[WIDTH]g.Element, start int) {
	for r := start; r < start+ROUNDS_F_HALF; r++ {
		addRC(state, r)
		sbox(state)
		externalLinearLayer(state)
	}
}

func partialRounds(state *[WIDTH]g.Element) {
	for r := 0; r < ROUNDS_P; r++ {
		addRCI(state, r)
		sboxP(0, state)
		internalLinearLayer(state)
	}
}

func externalLinearLayer(s *[WIDTH]g.Element) {
	for i := 0; i < 3; i++ { // 4 size window
		var t0, t1, t2, t3, t4, t5, t6 g.Element
		t0.Add(&s[4*i], &s[4*i+1])   // s0+s1
		t1.Add(&s[4*i+2], &s[4*i+3]) // s2+s3
		t2.Add(&t0, &t1)             // t0+t1 = s0+s1+s2+s3
		t3.Add(&t2, &s[4*i+1])       // t2+s1 = s0+2s1+s2+s3
		t4.Add(&t2, &s[4*i+3])       // t2+s3 = s0+s1+s2+2s3
		t5.Double(&s[4*i])           // 2s0
		t6.Double(&s[4*i+2])         // 2s2
		s[4*i].Add(&t3, &t0)
		s[4*i+1].Add(&t6, &t3)
		s[4*i+2].Add(&t1, &t4)
		s[4*i+3].Add(&t5, &t4)
	}

	sums := [4]g.Element{}
	for k := 0; k < 4; k++ {
		for j := 0; j < WIDTH; j += 4 {
			sums[k].Add(&sums[k], &s[j+k])
		}
	}
	for i := 0; i < WIDTH; i++ {
		s[i].Add(&s[i], &sums[i%4])
	}
}

func internalLinearLayer(state *[WIDTH]g.Element) {
	var sum g.Element
	sum.Set(&state[0])
	for i := 1; i < WIDTH; i++ {
		sum.Add(&sum, &state[i])
	}
	for i := 0; i < WIDTH; i++ {
		state[i].Mul(&state[i], &MATRIX_DIAG_12_U64[i]).
			Add(&state[i], &sum)
	}
}

func addRC(state *[WIDTH]g.Element, externalRound int) {
	for i := 0; i < WIDTH; i++ {
		state[i].Add(&state[i], &EXTERNAL_CONSTANTS[externalRound][i])
	}
}

func addRCI(state *[WIDTH]g.Element, round int) {
	state[0].Add(&state[0], &INTERNAL_CONSTANTS[round])
}

func sbox(state *[WIDTH]g.Element) {
	for i := range state {
		sboxP(i, state)
	}
}

func sboxP(index int, state *[WIDTH]g.Element) {
	var tmp g.Element
	tmp.Set(&state[index])

	var tmpSquare g.Element
	tmpSquare.Square(&tmp)

	var tmpSixth g.Element
	tmpSixth.Mul(&tmpSquare, &tmp)
	tmpSixth.Square(&tmpSixth)

	state[index].Mul(&tmpSixth, &tmp)
}
