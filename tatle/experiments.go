package tatle

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func measureAggKeySize(key map[string]kyber.Point) int {
	size := 0
	for _, value := range key {
		size += value.MarshalSize()
	}
	return size
}

func measureProofSize(proof map[string]SchnorrProof) int {
	size := 0
	for _, pi := range proof {
		len := pi.c.MarshalSize() + pi.u0.MarshalSize() + pi.u1.MarshalSize()
		size += len
	}
	return size
}

func measureCtxtSize(ctxt AtleCiphertext) int {
	size := 0
	size += ctxt.U0.MarshalSize()
	fmt.Printf("U0: %d\n", ctxt.U0.MarshalSize())
	for _, Ui := range ctxt.Us {
		size += Ui.MarshalSize()
		fmt.Printf("Ui: %d\n", Ui.MarshalSize())
	}
	size += ctxt.V.MarshalSize()
	fmt.Printf("V: %d\n", ctxt.V.MarshalSize())
	return size
}

func randSample(min int, max int) int {
	return rand.Intn(max-min) + min
}

func RunTestKeySize(depth int, trials int) {
	suite := bn256.NewSuite()
	_, sk, g, h, com := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)
	//fixedTrials := 100
	arr := make([]int, trials)
	cache := make(map[string]kyber.Point)

	for i := 0; i < 100; i++ {
		epoch := lifetime - (i + 1)
		key, proof := TimedKeyGenIterative(true, suite, sk, g, h, com, epoch, lifetime, nil, cache, nil)
		arr[i] = measureAggKeySize(key) + measureProofSize(proof)
	}

	for i := 100; i < trials; i++ {
		epoch := randSample(1, lifetime)
		key, proof := TimedKeyGenIterative(true, suite, sk, g, h, com, epoch, lifetime, nil, cache, nil)
		arr[i] = measureAggKeySize(key) + measureProofSize(proof)
	}

	sort.Ints(arr[:])
	min := arr[0]
	max := arr[len(arr)-1]
	med := arr[len(arr)/2]

	fmt.Println("-------------")
	fmt.Printf("depth: %d, lifetime: %d\n", depth, lifetime)
	fmt.Printf("min: %d\n", min)
	fmt.Printf("max: %d\n", max)
	fmt.Printf("med: %d\n", med)
}

func RunKeyGenHonest(depth int, totalTrials int) []int64 {
	suite := bn256.NewSuite()
	_, sk, g, h, com := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)

	arr := make([]int64, totalTrials)
	var output map[string]kyber.Point

	cache := make(map[string]kyber.Point)
	for i := 0; i < totalTrials; i++ {
		//epoch := randSample(1, lifetime)
		epoch := i + 1
		start := time.Now()
		output, _ = TimedKeyGenIterative(false, suite, sk, g, h, com, epoch, lifetime, output, cache, nil)
		//fmt.Println(output)
		elapsed := time.Since(start)
		arr[i] = elapsed.Microseconds()
		//arr[trial] = measureAggKeySize(key)
	}

	return arr
}

func RunKeyGenMalicious(depth int, totalTrials int) []int64 {
	suite := bn256.NewSuite()
	_, sk, g, h, com := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)

	arr := make([]int64, totalTrials)
	var output map[string]kyber.Point
	var proof map[string]SchnorrProof

	cache := make(map[string]kyber.Point)
	for i := 0; i < totalTrials; i++ {
		//epoch := randSample(1, lifetime)
		epoch := i + 1
		start := time.Now()
		output, proof = TimedKeyGenIterative(true, suite, sk, g, h, com, epoch, lifetime, output, cache, proof)
		//fmt.Println(output)
		elapsed := time.Since(start)
		arr[i] = elapsed.Microseconds()
		//arr[trial] = measureAggKeySize(key)
	}

	return arr
}

func RunTestCtxtSize(depth int, totalTrials int) {
	suite := bn256.NewSuite()
	pk, _, _, _, _ := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)

	arr := make([]int, totalTrials)

	const input = "Hello Future! This is the past"

	for i := 0; i < 100; i++ {
		epoch := lifetime - (i + 1)
		ctxt := Encrypt(suite, pk, epoch, lifetime, []byte(input))
		arr[i] = (measureCtxtSize(ctxt))
	}

	for i := 100; i < totalTrials; i++ {
		epoch := randSample(1, lifetime)
		ctxt := Encrypt(suite, pk, epoch, lifetime, []byte(input))
		arr[i] = (measureCtxtSize(ctxt))
	}

	sort.Ints(arr[:])
	min := arr[0]
	max := arr[len(arr)-1]
	avg := average(arr)

	fmt.Println("-------------")
	fmt.Printf("depth: %d, lifetime: %d\n", depth, lifetime)
	fmt.Printf("min: %d\n", min)
	fmt.Printf("max: %d\n", max)
	fmt.Printf("avg: %f\n", avg)

}

func average(arr []int) float64 {
	sum := 0.0
	for _, x := range arr {
		sum += float64(x)
	}
	return sum / float64(len(arr))
}

func RunEnc(depth int, totalTrials int) []int64 {
	suite := bn256.NewSuite()
	pk, _, _, _, _ := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)

	arr := make([]int64, totalTrials)
	const input = "Hello Future! This is the past"

	for i := 0; i < totalTrials; i++ {
		epoch := randSample(1, lifetime)
		start := time.Now()
		_ = Encrypt(suite, pk, epoch, lifetime, []byte(input))
		//fmt.Println(output)
		elapsed := time.Since(start)
		arr[i] = elapsed.Microseconds()
		//arr[trial] = measureAggKeySize(key)
	}

	return arr
}

func RunDec(depth int, totalTrials int) []int64 {
	suite := bn256.NewSuite()
	pk, sk, _, _, _ := Setup(suite)

	lifetime := int(math.Pow(2, float64(depth)) - 1)

	arr := make([]int64, totalTrials)
	const input = "Hello Future! This is the past"

	for i := 0; i < totalTrials; i++ {
		keyEpoch := randSample(2, lifetime)
		//ctxtEpoch := randSample(1, keyEpoch)
		ctxt := Encrypt(suite, pk, keyEpoch, lifetime, []byte(input))
		aggKey := TimedKeyGen(suite, sk, keyEpoch, lifetime)
		start := time.Now()
		_, err := DecryptAggKey(suite, aggKey, pk, keyEpoch, lifetime, ctxt)
		elapsed := time.Since(start)
		if err != nil {
			panic(err)
		}
		arr[i] = elapsed.Microseconds()
		//arr[trial] = measureAggKeySize(key)
	}

	return arr
}
