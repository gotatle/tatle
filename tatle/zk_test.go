package tatle

import (
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

func protZK(grp kyber.Group) bool {
	s := grp.Scalar().Pick(random.New())
	r := grp.Scalar().Pick(random.New())
	g, h := getGenerators(grp)
	w := grp.Point().Pick(random.New())
	prfW := w.Clone().Mul(s, w)

	y := pedersonCommit(s, r, g, h)
	pi := generateProof(s, r, y, w, prfW, grp, g, h)
	success := verifyProof(*pi, y, w, prfW, grp, g, h)

	return success
}

func TestZK(t *testing.T) {
	success := protZK(bn256.NewSuite().G2())

	if !success {
		t.FailNow()
	}

	success = protZK(bn256.NewSuite().GT())

	if !success {
		t.FailNow()
	}
}

func TestZKState(t *testing.T) {
	DPRFSetup(2, 2, "/tmp/pp", []string{"/tmp/rus.key", "/tmp/gus.key"})
	pp, secret := DPRFSetupReload("/tmp/pp", "/tmp/rus.key")

	suite := bn256.NewSuite()
	m := suite.G2().Point().Pick(random.New())
	grp := suite.G2()
	g, h := pp.genG2g, pp.genG2h
	com := pp.commitmentsG2[secret.id]

	km := m.Clone().Mul(secret.keyY, m) //m^key
	pi := generateProof(secret.keyY, secret.rnd, com, m, km, grp, g, h)

	//TODO: remove this sanity check after sufficient testing
	if !verifyProof(*pi, com, m, km, grp, g, h) {
		t.FailNow()
	}
}
