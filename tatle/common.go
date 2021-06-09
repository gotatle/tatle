package tatle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"

	proto "github.com/golang/protobuf/proto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

func failOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func pointToBytes(x kyber.Point) []byte {
	xBytes, err := x.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return xBytes
}

func scalarToBytes(x kyber.Scalar) []byte {
	xBytes, err := x.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return xBytes
}

func hashToG1(suite pairing.Suite, msg []byte) kyber.Point {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		panic("point needs to implement hashablePoint")
	}

	return hashable.Hash(msg)
}

// HACK: just returns g^msg
func hashToG2(suite pairing.Suite, msg []byte) kyber.Point {
	x := suite.G2().Scalar().SetBytes(msg)
	xG := suite.G2().Point().Mul(x, nil)
	return xG
}

//false on all zeros
func hasLeftSibling(id string) bool {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '1' {
			return true
		}
	}
	return false
}

func leftSibling(id string) string {
	output := ""
	foundOne := false
	for i := len(id) - 1; i >= 0; i-- {
		if !foundOne {
			if id[i] == '0' {
				output = "1" + output
			} else {
				output = "0" + output
				foundOne = true
			}
		} else {
			output = string(id[i]) + output
		}
	}
	return output
}

//assumes that the input is a valid lifetime (i.e. power of 2 minus 1)
func lifetimeToLevels(lifetime int) int {
	//we won't allow more than 2^64
	for i := 1; i < 64; i++ {
		if float64(lifetime) == (math.Pow(2, float64(i)) - 1) {
			return i
		}
	}
	return 0
}

// checks that lifetime = 2^n - 1, where n is a natural number
func validLifetime(lifetime int) bool {
	//we won't allow more than 2^64
	for i := 1; i < 64; i++ {
		if float64(lifetime) == (math.Pow(2, float64(i)) - 1) {
			return true
		}
	}
	return false
}

// this function assumes that lifetime = 2^n - 1, where n is a natural number
// we will label nodes from 0 to lifetime - 1 using a post-order traversal
// the output is the binary path (denoting left or right edges from the root) to the node labelled epoch
func epochIdToPathId(lifetime int, epoch int) string {
	if !validLifetime(lifetime) {
		panic("unexpected lifetime")
	}

	levels := lifetimeToLevels(lifetime)
	id := ""
	root := lifetime
	low := 1
	high := root - 1
	for level := 0; level < levels; level++ {
		//at the parent node, figure out ranges of left and right child
		if root == epoch {
			return id
		}

		left_low := low
		left_high := low + ((high - low + 1) / 2) - 1
		right_low := left_high + 1
		right_high := high
		if epoch <= left_high {
			//go left
			root = left_high
			low = left_low
			high = left_high - 1
			id += "0"
		} else {
			//go right
			root = right_high
			low = right_low
			high = right_high - 1
			id += "1"
		}
	}
	return id
}

func epochIdToHistory(lifetime int, epoch int) []string {
	if !validLifetime(lifetime) {
		panic("unexpected lifetime")
	}

	output := []string{}
	levels := lifetimeToLevels(lifetime)
	id := ""
	root := lifetime
	low := 1
	high := root - 1
	for level := 0; level < levels; level++ {
		//at the parent node, figure out ranges of left and right child
		if root == epoch {
			output = append(output, id)
			return output
		}

		left_low := low
		left_high := low + ((high - low + 1) / 2) - 1
		right_low := left_high + 1
		right_high := high
		if epoch <= left_high {
			//go left
			root = left_high
			low = left_low
			high = left_high - 1
			id += "0"
		} else {
			//when you go right, you add the left
			output = append(output, id+"0")

			//go right
			root = right_high
			low = right_low
			high = right_high - 1
			id += "1"
		}
	}
	return output
}

func allPrefixes(id string) []string {
	output := []string{}
	for i := 1; i <= len(id); i++ {
		s := id[:i]
		output = append(output, s)
	}
	return output
}

func printHex(src []byte) {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	fmt.Printf("%s\n", dst)
}

// returns the pb encoding of DEMCiphertext
func aeadEncrypt(key []byte, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ctxt := DEMCiphertext{Nonce: nonce, Ctxt: aesgcm.Seal(nil, nonce, msg, nil)}
	output, err := proto.Marshal(&ctxt)
	if err != nil {
		panic(err.Error())
	}

	return output
}

// takes pb encoding of DEMCiphertext, and returns the msg
func aeadDecrypt(key []byte, encoded []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ctxt := DEMCiphertext{}
	if err := proto.Unmarshal(encoded, &ctxt); err != nil {
		panic(err.Error())
	}

	msg, err := aesgcm.Open(nil, ctxt.GetNonce(), ctxt.GetCtxt(), nil)
	if err != nil {
		panic(err.Error())
	}
	return msg
}
