package tatle

import (
	"crypto/sha256"
	"errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
)

type SecretKey struct {
	alpha, rho kyber.Scalar
}

type PublicKey kyber.Point

type AtleCiphertext struct {
	U0 kyber.Point
	Us []kyber.Point
	V  kyber.Point
	C  []byte
}

func Setup(suite pairing.Suite) (PublicKey, SecretKey, kyber.Point, kyber.Point, kyber.Point) {

	alpha := suite.GT().Scalar().Pick(random.New())
	rho := suite.GT().Scalar().Pick(random.New())

	sk := SecretKey{alpha: alpha, rho: rho}

	//get generators
	//g1 := suite.G1().Point().Base()
	g2 := suite.G2().Point().Base()

	//g2^alpha
	pk := g2.Mul(alpha, g2)

	g1, h1 := getGenerators(suite.G1())
	com := pedersonCommit(alpha, rho, g1, h1)

	return pk, sk, g1, h1, com
}

func hash1(suite pairing.Suite, m string) kyber.Point {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		panic(errors.New("point needs to implement hashablePoint"))
	}
	hm := hashable.Hash([]byte(m))
	return hm
}

// computes H1(m)^k (H1 hashes to G1)
func hash1Prf(suite pairing.Suite, m string, k kyber.Scalar) kyber.Point {
	hm := hash1(suite, m)
	hmk := hm.Mul(k, hm)
	return hmk
}

func sValue(suite pairing.Suite,
	alpha kyber.Scalar,
	id string) kyber.Point {
	if len(id) == 0 {
		return hash1Prf(suite, "epsilon", alpha)
	} else {
		result := sValue(suite, alpha, id[:len(id)-1])
		this := hash1Prf(suite, id, alpha)
		result = result.Add(result, this)
		return result
	}
}

func sValueIterative(suite pairing.Suite,
	alpha kyber.Scalar,
	id string,
	cache map[string]kyber.Point) kyber.Point {

	s, ok := cache[id]
	if ok {
		return s.Clone()
	} else {
		//we have to compute S_id
		if len(id) == 0 {
			s = hash1Prf(suite, "epsilon", alpha)
		} else {
			sPrefix := sValueIterative(suite, alpha, id[:len(id)-1], cache)
			sThis := hash1Prf(suite, id, alpha)
			s = suite.G1().Point().Add(sPrefix, sThis)

			//remove left sibling from cache
			if hasLeftSibling(id) {
				delete(cache, leftSibling(id))
			}
		}
		cache[id] = s
		return s.Clone()
	}
}

func proveS(suite pairing.Suite, key SecretKey, id string, sValue kyber.Point, g, h, com kyber.Point) SchnorrProof {
	grp := suite.G1()
	base := hash1(suite, "epsilon")
	for _, idprefix := range allPrefixes(id) {
		tmp := hash1(suite, idprefix)
		base = base.Add(base, tmp)
	}
	return *generateProof(key.alpha, key.rho, com, base, sValue, grp, g, h)
}

func TimedKeyGenIterative(
	verifiable bool,
	suite pairing.Suite,
	key SecretKey,
	g, h, com kyber.Point,
	epoch int,
	lifetime int,
	prevS map[string]kyber.Point,
	cacheS map[string]kyber.Point,
	prevProof map[string]SchnorrProof) (map[string]kyber.Point, map[string]SchnorrProof) {

	newS := make(map[string]kyber.Point)
	newProof := make(map[string]SchnorrProof)

	ids := epochIdToHistory(lifetime, epoch)
	for _, id := range ids {
		//avoid recomputing if previous output had the s value
		s, ok_s := prevS[id]
		if !ok_s {
			s = sValueIterative(suite, key.alpha, id, cacheS)
		}
		newS[id] = s

		if verifiable {
			pi, ok_pi := prevProof[id]
			if !ok_pi {
				pi = proveS(suite, key, id, s, g, h, com)
			}
			newProof[id] = pi
		}
	}
	return newS, newProof
}

func NodeKeyGen(suite pairing.Suite,
	key SecretKey,
	epoch int,
	lifetime int) kyber.Point {
	id := epochIdToPathId(lifetime, epoch)
	s := sValue(suite, key.alpha, id)
	return s
}

func TimedKeyGen(suite pairing.Suite,
	key SecretKey,
	epoch int,
	lifetime int) map[string]kyber.Point {
	output := make(map[string]kyber.Point)
	ids := epochIdToHistory(lifetime, epoch)
	for _, id := range ids {
		s := sValue(suite, key.alpha, id)
		output[id] = s
	}
	return output
}

func DecryptNodeKey(suite pairing.Suite,
	s kyber.Point, //s value
	pk kyber.Point, //r value
	epoch int,
	lifetime int,
	C AtleCiphertext) []byte {

	//compute num of d
	numerator := suite.Pair(s, C.U0)
	//compute den of d
	var denominator kyber.Point
	for i := 0; i < len(C.Us); i++ {
		t := suite.Pair(C.Us[i], pk)
		if i == 0 {
			denominator = t
		} else {
			denominator = denominator.Add(denominator, t)
		}
	}

	d := suite.GT().Point().Sub(numerator, denominator)

	M := suite.GT().Point().Sub(C.V, d)

	Mserialized, err := M.MarshalBinary()
	if err != nil {
		panic(err)
	}
	aeskey := sha256.Sum256(Mserialized)
	printHex(aeskey[:])

	return aeadDecrypt(aeskey[:], C.C)
}

func DecryptAggKey(suite pairing.Suite,
	key map[string]kyber.Point,
	pk kyber.Point, //r value
	epoch int,
	lifetime int,
	C AtleCiphertext) ([]byte, error) {

	id := epochIdToPathId(lifetime, epoch)

	//is there a prefix of id in key
	var prefId string
	var prefKey kyber.Point
	foundPref := false
	for i := 1; i <= len(id); i++ {
		nodekey, exists := key[id[:i]]
		if exists {
			prefId = id[:i]
			prefKey = nodekey
			foundPref = true
		}
	}

	if !foundPref {
		return nil, errors.New("don't have the key")
	}

	//compute num of d
	numerator := suite.Pair(prefKey, C.U0)
	//compute den of d
	var denominator kyber.Point
	for i := 0; i < len(prefId); i++ {
		t := suite.Pair(C.Us[i], pk)
		if i == 0 {
			denominator = t
		} else {
			denominator = denominator.Add(denominator, t)
		}
	}

	d := suite.GT().Point().Sub(numerator, denominator)

	M := suite.GT().Point().Sub(C.V, d)

	Mserialized, err := M.MarshalBinary()
	if err != nil {
		panic(err)
	}
	aeskey := sha256.Sum256(Mserialized)
	//printHex(aeskey[:])

	return aeadDecrypt(aeskey[:], C.C), nil
}

func Encrypt(suite pairing.Suite,
	pk PublicKey,
	epoch int,
	lifetime int,
	msg []byte) AtleCiphertext {

	id := epochIdToPathId(lifetime, epoch)

	//sample gamma
	gamma := suite.G1().Scalar().Pick(random.New())

	//compute U0 = g2^gamma
	g2 := suite.G2().Point().Base()
	U0 := g2.Mul(gamma, g2)

	//compute Ui = H(id|_i)^gamma
	Us := []kyber.Point{}
	for _, idprefix := range allPrefixes(id) {
		hidprefix := hash1Prf(suite, idprefix, gamma)
		Us = append(Us, hidprefix)
	}

	//compute H(epsilon)
	heps := hash1(suite, "epsilon")
	q := pk
	//d = e(H(eps), Q)^gamma
	tmp := suite.Pair(heps, q)
	d := tmp.Mul(gamma, tmp)

	//sample a random point in GT to use as M
	M := suite.GT().Point().Pick(random.New())
	//last element of ciphertext (U0, U1, ..., Ut, V)
	V := suite.GT().Point().Add(M, d)

	//DEM ciphertext
	Mserialized, err := M.MarshalBinary()
	if err != nil {
		panic(err)
	}
	aeskey := sha256.Sum256(Mserialized)
	//printHex(aeskey[:])

	demctxt := aeadEncrypt(aeskey[:], msg)

	return AtleCiphertext{U0: U0, Us: Us, V: V, C: demctxt}
}
