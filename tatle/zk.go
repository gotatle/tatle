// Primitives for strongly secure version of the protocol
// We use zero-knowledge proof based on Pederson commitments and schnorr style proof (via Fiat-Shamir)

package tatle

import (
	"crypto/sha256"

	"github.com/golang/protobuf/proto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

// Generators refers to a pair of points, and we can use this struct for any group
type Generators struct {
	g, h kyber.Point
}

// SchnorrProof contains elements of a Schnorr style proof based on Pederson commitments and Fiat-Shamir transform
type SchnorrProof struct {
	c, u0, u1 kyber.Scalar
}

func getDegeneratePoint(grp kyber.Group) kyber.Point {
	g := grp.Point().Base()
	return g.Mul(grp.Scalar().SetInt64(0), g)
}

// g and h are random points. Any point in a prime order group can act as a generator!
func getGenerators(grp kyber.Group) (kyber.Point, kyber.Point) {
	degenerate := getDegeneratePoint(grp)

	var g, h kyber.Point
	for { //extremely likely that we only need one iteration as only point is degnerate
		g = grp.Point().Base()
		h = grp.Point().Pick(random.New())

		retry := g.Equal(degenerate) || h.Equal(degenerate)
		if !retry { //we successfully got valid points.
			break
		}
	}

	return g, h
}

func marshalSchnorrProof(pi *SchnorrProof) []byte {
	piCBytes, err := pi.c.MarshalBinary()
	failOnError(err)
	piU0Bytes, err := pi.u0.MarshalBinary()
	failOnError(err)
	piU1Bytes, err := pi.u1.MarshalBinary()
	failOnError(err)
	piPbBytes, err := proto.Marshal(&SchnorrProofPb{C: piCBytes, U0: piU0Bytes, U1: piU1Bytes})
	failOnError(err)
	return piPbBytes
}

func extractSchnorrProof(rsp *RPCResponsePb, reqTyp PRFRequestType) SchnorrProof {
	piPb := SchnorrProofPb{}
	if err := proto.Unmarshal(rsp.Proof, &piPb); err != nil {
		failOnError(err)
	}

	var grp kyber.Group

	switch reqTyp {
	case FINE:
		grp = bn256.NewSuite().GT()
	case BULK:
		grp = bn256.NewSuite().G2()
	}

	c := grp.Scalar().SetInt64(0)
	err := c.UnmarshalBinary(piPb.C)
	failOnError(err)

	u0 := grp.Scalar().SetInt64(0)
	err = u0.UnmarshalBinary(piPb.U0)
	failOnError(err)

	u1 := grp.Scalar().SetInt64(0)
	err = u1.UnmarshalBinary(piPb.U1)
	failOnError(err)

	pi := SchnorrProof{c: c, u0: u0, u1: u1}
	return pi
}

// computes commitment to s and r by computing g^s . h^r
func pedersonCommit(s, r kyber.Scalar, grpg, grph kyber.Point) kyber.Point {
	g, h := grpg.Clone(), grph.Clone()
	//y = g^s * h ^ r
	gS := g.Mul(s, g)
	hR := h.Mul(r, h)
	com := gS.Add(gS, hR)
	return com
}

// s is secret key, r is the randomness used for Pederson commitment,
// com is the Pederson commitment computed using s and r (during the setup phase)
// w is H(x) where x is the input to the DPRF and H maps x to group element
// prfW is w^s (but we don't compute it here as it is already computed elsewhere)
// grpg and grph are random generators of the group grp
func generateProof(s, r kyber.Scalar, com, w, prfW kyber.Point, grp kyber.Group, grpg, grph kyber.Point) *SchnorrProof {
	g, h := grpg.Clone(), grph.Clone()

	v0 := grp.Scalar().Pick(random.New()) //v <- Zp
	v1 := grp.Scalar().Pick(random.New()) //v' <- Zp

	t0 := w.Clone().Mul(v0, w)                        // t = w^v
	t1 := grp.Point().Add(g.Mul(v0, g), h.Mul(v1, h)) // t' = g^v . h ^ v'

	hashArg := []byte{}
	// y = H(h_i, w, y_i, g, h, t, t')
	for _, point := range []kyber.Point{prfW, w, com, grpg, grph, t0, t1} {
		hashArg = append(hashArg, pointToBytes(point)...)
	}
	hash := sha256.Sum256(hashArg)

	c := grp.Scalar().SetBytes(hash[:])
	u0 := v0.Sub(v0, s.Clone().Mul(s, c)) //u = v - c.s
	u1 := v1.Sub(v1, r.Clone().Mul(r, c)) //u' = v' - c.r

	return &SchnorrProof{c: c, u0: u0, u1: u1} //return pi = (c, u, u')
}

// w is H(x) where x is the input to the DPRF and H maps x to group element
// prfW is w^s where s is the server's secret key, and com is the pederson commitment
// pi is the Schnorr proof and it contains c, u0, u1 (see schnorrProof defn)
func verifyProof(pi SchnorrProof, com, w, prfW kyber.Point, grp kyber.Group, grpg, grph kyber.Point) bool {
	g, h := grpg.Clone(), grph.Clone()

	wU0 := w.Clone().Mul(pi.u0, w)
	prfWC := prfW.Clone().Mul(pi.c, prfW)
	t0 := wU0.Add(wU0, prfWC) //t = w^u . h_i^c

	gU0 := g.Clone().Mul(pi.u0, g) // g^u
	hU1 := h.Clone().Mul(pi.u1, h) // h ^ u'
	comC := com.Clone().Mul(pi.c, com)
	tmp := gU0.Add(gU0, hU1) // g ^ u . h ^ u' . y ^ c
	t1 := tmp.Add(tmp, comC)

	hashArg := []byte{}
	// y = H(h_i, w, y_i, g, h, t, t')
	for _, point := range []kyber.Point{prfW, w, com, grpg, grph, t0, t1} {
		hashArg = append(hashArg, pointToBytes(point)...)
	}
	hash := sha256.Sum256(hashArg)

	c := grp.Scalar().SetBytes(hash[:])
	return c.Equal(pi.c)
}
