package tatle

import (
	"fmt"
	"math/big"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestDPRF(t *testing.T) {
	suite := bn256.NewSuite()
	id := []byte("bull")
	Hid := hashToG2(suite, id) //locally evaluate H(id)

	secret := mod.NewInt(big.NewInt(0), prime).Pick(random.New())
	key := suite.G2().Scalar().Set(secret)

	shares := makeRandomShares(3, 6, secret)
	//compute each server's response
	responses := make([]kyber.Point, len(shares))
	xs := make([]kyber.Scalar, len(shares))
	for i := 0; i < len(responses); i++ {
		responses[i] = prfArith(shares[i].y, Hid)
		xs[i] = shares[i].x
	}

	//combine using lagrange coeffs
	zero := mod.NewInt(big.NewInt(0), prime)
	l := lagrangeCoefficients(zero, xs)
	var remote kyber.Point
	for i := 0; i < len(l); i++ {
		tmp := prfArith(l[i], responses[i])
		if i == 0 {
			remote = tmp
		} else {
			remote = remote.Add(remote, tmp)
		}
	}

	local := prfArith(key, Hid) //H(id)^key

	if !local.Equal(remote) {
		t.FailNow()
	}
}

func TestRemotePRF(t *testing.T) {
	suite := bn256.NewSuite()
	id := []byte("bull")
	Hid := hashToG2(suite, id) //locally evaluate H(id)

	secret := mod.NewInt(big.NewInt(0), prime).Pick(random.New())
	key := suite.G2().Scalar().Set(secret)

	shares := makeRandomShares(3, 6, secret)
	recoveredSecret := recoverSecret(shares[1:4])

	local := prfArith(key, Hid)              //H(id)^key
	remote := prfArith(recoveredSecret, Hid) //H(id)^secret

	if !local.Equal(remote) {
		t.FailNow()
	}
}

func TestShamirSecretSharing(t *testing.T) {
	secret := mod.NewInt(big.NewInt(0), prime).Pick(random.New())
	fmt.Println("secret: " + secret.String())
	shares := makeRandomShares(3, 10, secret)
	for _, point := range shares {
		fmt.Println(point.x.String() + "," + point.y.String())
	}
	recovered := recoverSecret(shares[1:4])
	fmt.Println("recovered secret: " + recovered.String())
	if !recovered.Equal(secret) {
		t.FailNow()
	}
}

func TestMakeRandomShares(t *testing.T) {
	var secret kyber.Scalar = mod.NewInt(big.NewInt(42), prime)
	shares := makeRandomShares(3, 6, secret)
	for _, point := range shares {
		fmt.Println(point.x.String() + "," + point.y.String())
	}
}

func TestEvalPoly(t *testing.T) {
	//minimum := 3
	shares := 6
	poly := []kyber.Scalar{mod.NewInt64(42, prime), mod.NewInt64(531, prime), mod.NewInt64(112, prime)}
	points := make([]polyPoint, shares)
	for i := 0; i < shares; i++ {
		x := mod.NewInt64(int64(i+1), prime)
		y := evalPoly(poly, x)
		point := polyPoint{x: x, y: y}
		points[i] = point
	}

	//print stuff
	for _, point := range points {
		fmt.Println(point.x.String() + "," + point.y.String())
	}
}
