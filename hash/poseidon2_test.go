package hash

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	poseidon2_gnark "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
	poseidon2_plonky2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks_plonky2"
)

func TestPoseidon2Bench(t *testing.T) {
	inputs, err := readBenchInputs("bench_vector")
	totalInputs := len(inputs)
	if err != nil {
		t.Logf("Error: %v\n", err)
		t.FailNow()
	}

	results := make([]g.GoldilocksField, 0, 4*len(inputs))
	start := time.Now()
	for _, input := range inputs {
		res := poseidon2_plonky2.HashNToHashNoPad(input)
		results = append(results, res[:]...)
	}
	duration := time.Since(start)
	t.Logf("HashNToHashNoPad plonky2 took %s for %d inputs", duration, totalInputs)

	sha2 := sha256.New()
	for _, res := range results {
		sha2.Write(g.ToLittleEndianBytesF(res))
	}
	hash := sha2.Sum(nil)
	t.Logf("Hash: %x\n", hash)
}

func TestPoseidon2BenchOld(t *testing.T) {
	inputs, err := readBenchInputsOld("bench_vector")
	totalInputs := len(inputs)
	if err != nil {
		t.Logf("Error: %v\n", err)
		t.FailNow()
	}

	results := make([]g.Element, 0, 4*len(inputs))
	start := time.Now()
	for _, input := range inputs {
		res := poseidon2_gnark.HashNToHashNoPad(input)
		results = append(results, res[:]...)
	}
	duration := time.Since(start)
	t.Logf("HashNToHashNoPadPure gnark took %s for %d inputs", duration, totalInputs)

	sha2 := sha256.New()
	for _, res := range results {
		sha2.Write(g.ToLittleEndianBytes(res))
	}
	hash := sha2.Sum(nil)
	t.Logf("Hash: %x\n", hash)
}

func readBenchInputs(filename string) ([][]g.GoldilocksField, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var inputs [][]g.GoldilocksField

	for scanner.Scan() {
		line := scanner.Text()
		strVals := strings.Split(line, ",")
		var input []g.GoldilocksField
		for _, strVal := range strVals {
			val, err := strconv.ParseUint(strVal, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse uint64: %v", err)
			}
			input = append(input, g.GoldilocksField(val))
		}
		inputs = append(inputs, input)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	return inputs, nil
}

func readBenchInputsOld(filename string) ([][]g.Element, error) {
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
			input = append(input, g.NewElement(val))
		}
		inputs = append(inputs, input)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	return inputs, nil
}
