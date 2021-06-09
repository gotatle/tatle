package tatle

import (
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

// Helper for prfApu: evaluates a pseudo-random function.
// Using secret key k and input x (which is also a point on curve G),
// PRF_k(x) produces k * x, which is a point on curve G.
func prfArith(k kyber.Scalar, x kyber.Point) kyber.Point {
	var kx = x.Clone()
	kx = kx.Mul(k, x)
	return kx
}

func Test1PRF(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	key := suite.G2().Scalar().Pick(random.New())

	HM := hashToG1(suite, msg)
	kHM := prfArith(key, HM)
	left := suite.Pair(kHM, suite.G2().Point().Base()) //e(H(m)^k, g)

	eHMg := suite.Pair(HM, suite.G2().Point().Base()) //e(H(m), g)
	right := prfArith(key, eHMg)                      //e(H(m), g)^k

	if !left.Equal(right) {
		t.FailNow()
	}
}

func Test2PRF(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	id := []byte("1")

	suite := bn256.NewSuite()
	key := suite.G2().Scalar().Pick(random.New())

	HM := hashToG1(suite, msg)   //locally compute H(msg); TODO com(m;r)
	Hid := hashToG2(suite, id)   //locally evaluate H(id)
	kHid := prfArith(key, Hid)   //H(id)^k
	left := suite.Pair(HM, kHid) //e(H(id)^k, H(m))

	eHMHid := suite.Pair(HM, Hid)  //e(H(id), H(m))
	right := prfArith(key, eHMHid) //e(H(id), H(m))^k

	if !left.Equal(right) {
		t.FailNow()
	}
}
