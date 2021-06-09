package tatle

import (
	"fmt"
	"testing"

	//"time"
	"github.com/stretchr/testify/assert"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestATLE1(t *testing.T) {
	input := []byte("Hello Future")
	suite := bn256.NewSuite()

	lifetime := 15
	pk, sk, _, _, _ := Setup(suite)

	for i := 1; i < lifetime; i++ {
		s := NodeKeyGen(suite, sk, i, lifetime)
		sserialized, err := s.MarshalBinary()
		if err != nil {
			panic(err)
		}
		fmt.Printf("size of s: %d\n", len(sserialized))
		ctxt := Encrypt(suite, pk, i, lifetime, input)
		msg := DecryptNodeKey(suite, s, pk, i, lifetime, ctxt)
		assert.Equal(t, msg, input, "The two strings should be the same.")
		fmt.Printf("output: %s\n", msg)
	}
}

func TestATLE2(t *testing.T) {
	input := []byte("Hello Future")
	suite := bn256.NewSuite()

	lifetime := 15
	pk, sk, _, _, _ := Setup(suite)
	for i := 1; i < lifetime; i++ {
		for j := 1; j <= i; j++ {
			aggkey := TimedKeyGen(suite, sk, i, lifetime)
			ctxt := Encrypt(suite, pk, j, lifetime, input)
			msg, err := DecryptAggKey(suite, aggkey, pk, j, lifetime, ctxt)
			assert.Equal(t, err, nil, "decryption failed")
			assert.Equal(t, msg, input, "The two strings should be the same.")
			fmt.Printf("output: %s\n", msg)
		}
	}
}

func TestATLE3(t *testing.T) {
	const input = "Hello Future"
	suite := bn256.NewSuite()

	lifetime := 15
	pk, sk, g, h, com := Setup(suite)
	var output map[string]kyber.Point
	cache := make(map[string]kyber.Point)
	for i := 1; i < lifetime; i++ {
		aggKey, _ := TimedKeyGenIterative(false, suite, sk, g, h, com, i, lifetime, output, cache, nil)

		for j := 1; j <= i; j++ {
			ctxt := Encrypt(suite, pk, j, lifetime, []byte(input))
			fmt.Println(aggKey)
			msg, err := DecryptAggKey(suite, aggKey, pk, j, lifetime, ctxt)
			assert.Equal(t, err, nil, "decryption failed")
			assert.Equal(t, []byte(input), msg, "The two strings should be the same.")
			fmt.Printf("output: %s\n", msg)
		}

		output = aggKey
	}
}
