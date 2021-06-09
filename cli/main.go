package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/rsinha/goturtle/tatle"
)

func totalTrials(depth int, ideal int) int {
	lifetime := int(math.Pow(2, float64(depth)) - 1)
	if ideal > lifetime {
		return lifetime - 1
	} else {
		return ideal
	}
}

func writeToFile(data []int64, filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)
	for _, val := range data {
		_, _ = datawriter.WriteString(fmt.Sprint(val) + "\n")
	}
	datawriter.Flush()
	file.Close()
}

func TestKeyGenHonest() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		out := tatle.RunKeyGenHonest(l, totalTrials(l, 10000))
		writeToFile(out, "data/keygen_"+fmt.Sprint(l)+"_honest.txt")
	}
}

func TestKeyGenMalicious() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		out := tatle.RunKeyGenMalicious(l, totalTrials(l, 10000))
		writeToFile(out, "data/keygen_"+fmt.Sprint(l)+"_malicious.txt")
	}
}

func TestEnc() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		out := tatle.RunEnc(l, totalTrials(l, 10000))
		writeToFile(out, "data/enc_"+fmt.Sprint(l)+".txt")
	}
}

func TestDec() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		out := tatle.RunDec(l, totalTrials(l, 10000))
		writeToFile(out, "data/dec_"+fmt.Sprint(l)+".txt")
	}
}

func TestKeySize() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		tatle.RunTestKeySize(l, 1000)
	}
}

func TestCtxtSize() {
	depths := []int{10, 15, 20, 30}
	for _, l := range depths {
		tatle.RunTestCtxtSize(l, 100000)
	}
}

func main() {
	TestCtxtSize()
}
