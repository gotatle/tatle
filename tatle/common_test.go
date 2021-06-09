package tatle

import (
	"fmt"
	"testing"
)

func TestPathId(t *testing.T) {
	lifetime := 15
	for i := 1; i <= lifetime; i++ {
		fmt.Printf("%d: %s\n", i, epochIdToPathId(lifetime, i))
	}
}

func TestEpochIdToHistory(t *testing.T) {
	lifetime := 15
	for i := 1; i <= lifetime; i++ {
		fmt.Printf("%d: %s\n", i, epochIdToHistory(lifetime, i))
	}
}

func TestAllPrefixes(t *testing.T) {
	fmt.Println(allPrefixes("010"))
	fmt.Println(allPrefixes("0110"))
	fmt.Println(allPrefixes("1"))
}

func TestLeftSibling(t *testing.T) {
	fmt.Println(leftSibling("010"))
	fmt.Println(leftSibling("0110"))
	fmt.Println(leftSibling("0100100"))
	fmt.Println(leftSibling("1"))
}
