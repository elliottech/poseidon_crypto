package poseidon2

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
)

func TestPoseidon2Bench(t *testing.T) {
	inputs, err := readBenchInputs("bench_vector")
	totalInputs := len(inputs)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	const sleepTime = 1 * time.Second
	// Pure go
	time.Sleep(sleepTime)
	start := time.Now()
	for _, input := range inputs {
		HashNToHashNoPadPureGo(input)
	}
	duration := time.Since(start)
	t.Logf("HashNToHashNoPadPureGo took %s for %d inputs", duration, totalInputs)

	// Rust link with uint64<->goldilocks conversion included
	time.Sleep(sleepTime)
	start = time.Now()
	for _, input := range inputs {
		HashNToHashNoPad(input)
	}
	duration = time.Since(start)
	t.Logf("HashNToHashNoPad took %s for %d inputs", duration, totalInputs)
}

func readBenchInputs(filename string) ([][]g.Element, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var inputs [][]g.Element

	for scanner.Scan() {
		line := scanner.Text()
		strVals := strings.Split(line, ",")
		var input []g.Element
		for _, strVal := range strVals {
			val, err := strconv.ParseUint(strVal, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse uint64: %v", err)
			}
			input = append(input, g.FromUint64(val))
		}
		inputs = append(inputs, input)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	return inputs, nil
}

// func _generateBenchInputs(filename string, totalInputs int) {
// 	inputs := make([][]g.Element, totalInputs)
// 	inputsUint64 := make([][]uint64, totalInputs)
// 	for i := range inputs {
// 		inputLen := rand.Intn(111) + 10
// 		inputs[i] = make([]g.Element, inputLen)
// 		inputsUint64[i] = make([]uint64, inputLen)
// 		for j := range inputs[i] {
// 			r := rand.Uint64()
// 			inputs[i][j] = g.FromUint64(r)
// 			inputsUint64[i][j] = r
// 		}
// 	}

// 	file, err := os.Create(filename)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer file.Close()

// 	writer := csv.NewWriter(file)
// 	defer writer.Flush()

// 	for _, input := range inputsUint64 {
// 		strInput := make([]string, len(input))
// 		for i, val := range input {
// 			strInput[i] = strconv.FormatUint(val, 10)
// 		}
// 		if err := writer.Write(strInput); err != nil {
// 			panic(err)
// 		}
// 	}
// }
