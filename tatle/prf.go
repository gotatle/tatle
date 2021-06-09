package tatle

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"sync"

	proto "github.com/golang/protobuf/proto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

const (
	//FINE refers to Fine-grained operations
	FINE = iota // Fine-grained encryption, which will use group GT
	//BULK refers to bulk operations
	BULK // Bulk encryption, which will use group G2
)

// PRFRequestType should be set to either FINE or BULK
type PRFRequestType uint

// KeyMaterial holds the key material
type KeyMaterial struct {
	id   uint64
	keyX kyber.Scalar
	keyY kyber.Scalar
	rnd  kyber.Scalar
}

// PublicParams are used by both the client and the server
type PublicParams struct {
	t             uint64
	n             uint64
	genG2g        kyber.Point
	genG2h        kyber.Point
	commitmentsG2 []kyber.Point
	genGTg        kyber.Point
	genGTh        kyber.Point
	commitmentsGT []kyber.Point
}

func writeBytesToFile(filename string, buf []byte) {
	err := ioutil.WriteFile(filename, buf, 0644)
	failOnError(err)
	//fmt.Printf("wrote %d bytes to file %s\n", len(buf), filename)
}

func saveKeyMaterial(km *KeyMaterial, filename string) {
	keyXBytes, err := km.keyX.MarshalBinary()
	failOnError(err)

	keyYBytes, err := km.keyY.MarshalBinary()
	failOnError(err)

	rndBytes, err := km.rnd.MarshalBinary()
	failOnError(err)

	buf, err := proto.Marshal(&KeyMaterialPb{Id: km.id, KeyX: keyXBytes, KeyY: keyYBytes, Rnd: rndBytes})
	failOnError(err)

	writeBytesToFile(filename, buf)
}

func savePublicParams(pp *PublicParams, filename string) {
	ppPb := PublicParamsPb{}
	var err error

	ppPb.N = pp.n
	ppPb.T = pp.t

	ppPb.GeneratorG2G, err = pp.genG2g.MarshalBinary()
	failOnError(err)

	ppPb.GeneratorG2H, err = pp.genG2h.MarshalBinary()
	failOnError(err)

	ppPb.GeneratorGTg, err = pp.genGTg.MarshalBinary()
	failOnError(err)

	ppPb.GeneratorGTh, err = pp.genGTh.MarshalBinary()
	failOnError(err)

	ppPb.CommitmentsG2 = make([][]byte, len(pp.commitmentsG2))
	ppPb.CommitmentsGT = make([][]byte, len(pp.commitmentsGT))
	for i := range pp.commitmentsG2 {
		ppPb.CommitmentsG2[i], err = pp.commitmentsG2[i].MarshalBinary()
		failOnError(err)
		ppPb.CommitmentsGT[i], err = pp.commitmentsGT[i].MarshalBinary()
		failOnError(err)
	}

	buf, err := proto.Marshal(&ppPb)
	failOnError(err)
	writeBytesToFile(filename, buf)
}

// DPRFSetup initializes the key material for all servers
// Note that this must be called during the trusted setup phase
func DPRFSetup(t, n uint, ppFile string, secretFiles []string) {
	//sanity checks
	if uint(len(secretFiles)) != n {
		panic("Expected " + fmt.Sprint(n) + " filenames")
	}

	//gnerate public parameters
	pp := PublicParams{}
	pp.t, pp.n = uint64(t), uint64(n)
	pp.genG2g, pp.genG2h = getGenerators(bn256.NewSuite().G2())
	pp.genGTg, pp.genGTh = getGenerators(bn256.NewSuite().GT())
	pp.commitmentsG2 = make([]kyber.Point, n)
	pp.commitmentsGT = make([]kyber.Point, n)

	//generate secret key material for each of the n servers
	points := chooseKeyAndMakeRandomShares(t, n) //choose n random shares using SSS
	for i, point := range points {
		r := bn256.NewSuite().G2().Scalar().Pick(random.New()) //choose r_i
		pp.commitmentsG2[i] = pedersonCommit(point.y, r, pp.genG2g, pp.genG2h)
		pp.commitmentsGT[i] = pedersonCommit(point.y, r, pp.genGTg, pp.genGTh)
		saveKeyMaterial(&KeyMaterial{id: uint64(i), keyX: point.x, keyY: point.y, rnd: r}, secretFiles[i])
	}

	savePublicParams(&pp, ppFile)
}

// LoadKeyMaterial reads persistent storage and places key material in memory
func loadKeyMaterial(filename string) *KeyMaterial {
	keyMaterialBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		panic("Unable to read key from file: " + filename)
	}
	keyMaterialPb := KeyMaterialPb{}
	if err := proto.Unmarshal(keyMaterialBytes, &keyMaterialPb); err != nil {
		panic(err.Error())
	}

	id := keyMaterialPb.GetId()
	keyX := bn256.NewSuite().G2().Scalar().SetInt64(0)
	keyY := bn256.NewSuite().G2().Scalar().SetInt64(0)
	rnd := bn256.NewSuite().G2().Scalar().SetInt64(0)
	if err := keyX.UnmarshalBinary(keyMaterialPb.GetKeyX()); err != nil {
		panic("Unable to parse key from byte slice")
	}
	if err := keyY.UnmarshalBinary(keyMaterialPb.GetKeyY()); err != nil {
		panic("Unable to parse key from byte slice")
	}
	if err := rnd.UnmarshalBinary(keyMaterialPb.GetRnd()); err != nil {
		panic("Unable to parse rnd from byte slice")
	}

	return &KeyMaterial{id: id, keyX: keyX, keyY: keyY, rnd: rnd}
}

func loadPublicParams(filename string) *PublicParams {
	ppBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		panic("Unable to read params from file: " + filename)
	}
	ppPb := PublicParamsPb{}
	if err := proto.Unmarshal(ppBytes, &ppPb); err != nil {
		panic(err.Error())
	}

	n := ppPb.GetN()
	t := ppPb.GetT()

	genG2g := bn256.NewSuite().G2().Point().Base()
	err = genG2g.UnmarshalBinary(ppPb.GetGeneratorG2G())
	failOnError(err)
	genG2h := bn256.NewSuite().G2().Point().Base()
	err = genG2h.UnmarshalBinary(ppPb.GetGeneratorG2H())
	failOnError(err)
	genGTg := bn256.NewSuite().GT().Point().Base()
	err = genGTg.UnmarshalBinary(ppPb.GetGeneratorGTg())
	failOnError(err)
	genGTh := bn256.NewSuite().GT().Point().Base()
	err = genGTh.UnmarshalBinary(ppPb.GetGeneratorGTh())
	failOnError(err)

	commitmentsG2 := make([]kyber.Point, len(ppPb.GetCommitmentsG2()))
	for i, buf := range ppPb.GetCommitmentsG2() {
		pt := bn256.NewSuite().G2().Point()
		err = pt.UnmarshalBinary(buf)
		failOnError(err)
		commitmentsG2[i] = pt
	}
	commitmentsGT := make([]kyber.Point, len(ppPb.GetCommitmentsGT()))
	for i, buf := range ppPb.GetCommitmentsGT() {
		pt := bn256.NewSuite().GT().Point()
		err = pt.UnmarshalBinary(buf)
		failOnError(err)
		commitmentsGT[i] = pt
	}

	return &PublicParams{
		t:             t,
		n:             n,
		genG2g:        genG2g,
		genG2h:        genG2h,
		commitmentsG2: commitmentsG2,
		genGTg:        genGTg,
		genGTh:        genGTh,
		commitmentsGT: commitmentsGT,
	}
}

// DPRFSetupReload needs better documentation
func DPRFSetupReload(ppFile, keyFile string) (*PublicParams, *KeyMaterial) {
	if keyFile == "" {
		return loadPublicParams(ppFile), nil
	}
	return loadPublicParams(ppFile), loadKeyMaterial(keyFile)
}

// DPRFEval computes the pseudo-random function on incoming point (either on G2 or GT)
// incoming message is deserialized, converted to point, PRF'd, then serialized out
// server side
func DPRFEval(reqTyp PRFRequestType, pp *PublicParams, secret *KeyMaterial, msg []byte) (*RPCResponsePb, error) {
	suite := bn256.NewSuite()

	var m kyber.Point
	var grp kyber.Group
	var g, h kyber.Point
	var com kyber.Point
	switch reqTyp {
	case FINE:
		m = suite.GT().Point()
		grp = suite.GT()
		g, h = pp.genGTg, pp.genGTh
		com = pp.commitmentsGT[secret.id]
	case BULK:
		m = suite.G2().Point()
		grp = suite.G2()
		g, h = pp.genG2g, pp.genG2h
		com = pp.commitmentsG2[secret.id]
	}

	//com = pedersonCommit(secret.keyY, secret.rnd, g, h)

	if err := m.UnmarshalBinary(msg); err != nil {
		return &RPCResponsePb{Id: nil, Point: nil, Proof: nil}, err
	}

	km := m.Clone().Mul(secret.keyY, m) //m^key
	pi := generateProof(secret.keyY, secret.rnd, com, m, km, grp, g, h)

	//TODO: remove this sanity check after sufficient testing
	// if !verifyProof(*pi, com, m, km, grp, g, h) {
	// 	panic(errors.New("UHOH"))
	// }

	proofBytes := marshalSchnorrProof(pi)

	outputY, err := km.MarshalBinary()
	if err != nil {
		return &RPCResponsePb{Id: nil, Point: nil, Proof: nil}, err
	}
	outputX, err := secret.keyX.MarshalBinary()
	if err != nil {
		return &RPCResponsePb{Id: nil, Point: nil, Proof: nil}, err
	}
	return &RPCResponsePb{Id: outputX, Point: outputY, Proof: proofBytes}, nil
}

// DPRFCombine must do lagragnge interpolation on server responses to compute x^k
// client-side
func DPRFCombine(pp *PublicParams, reqTyp PRFRequestType, rpcRequest kyber.Point, rpcResponses []*RPCResponsePb) []byte {
	n := pp.n
	t := pp.t

	if uint64(len(rpcResponses)) != n {
		s := fmt.Sprintf("incorrect number of responses. expected %d, got %d", pp.n, n)
		panic(s)
	}
	suite := bn256.NewSuite()

	//parse each server's response as a point
	hs := make([]kyber.Point, t)
	xs := make([]kyber.Scalar, t)
	for i := 0; i < int(t); i++ {
		var point kyber.Point
		var id kyber.Scalar
		switch reqTyp {
		case FINE:
			point = suite.GT().Point()
			id = suite.GT().Scalar().SetInt64(0)
		case BULK:
			point = suite.G2().Point()
			id = suite.G2().Scalar().SetInt64(0)
		}
		if err := point.UnmarshalBinary(rpcResponses[i].Point); err != nil {
			panic("unable to unmarshal server's response point")
		}
		if err := id.UnmarshalBinary(rpcResponses[i].Id); err != nil {
			panic("unable to unmarshal server's response point")
		}
		hs[i] = point //h_i = H(x)^sk_i
		xs[i] = id    //x_i from (x_i, sk_i) given to each server
	}

	//parallel verification
	var wg sync.WaitGroup
	for i, rsp := range rpcResponses[0:t] {
		wg.Add(1)
		go func(wg *sync.WaitGroup, i int, rsp *RPCResponsePb) {
			defer wg.Done()
			pi := extractSchnorrProof(rsp, reqTyp)

			var com kyber.Point
			var grp kyber.Group
			var g, h kyber.Point
			switch reqTyp {
			case FINE:
				com = pp.commitmentsGT[i]
				grp = suite.GT()
				g, h = pp.genGTg, pp.genGTh
			case BULK:
				com = pp.commitmentsG2[i]
				grp = suite.G2()
				g, h = pp.genG2g, pp.genG2h
			}

			if !verifyProof(pi, com, rpcRequest, hs[i], grp, g, h) {
				panic(errors.New("SERVER LIED"))
			}
		}(&wg, i, rsp)
	}
	wg.Wait()

	//combine using lagrange coeffs
	l := lagrangeCoefficients(mod.NewInt(big.NewInt(0), prime), xs[0:t])
	var result kyber.Point
	for i := 0; i < len(l); i++ {
		tmp := hs[i].Mul(l[i], hs[i])
		if i == 0 {
			result = tmp
		} else {
			result = result.Add(result, tmp)
		}
	}

	output, err := result.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return output
}
