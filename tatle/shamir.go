package tatle

import (
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/util/random"
)

type polyPoint struct {
	x kyber.Scalar
	y kyber.Scalar
}

// this is the same
var prime = bigFromBase10("65000549695646603732796438742359905742570406053903786389881062969044166799969")

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// evaluate f(x), where f(.) = a_0 + a_1 * x + ...
func evalPoly(poly []kyber.Scalar, x kyber.Scalar) kyber.Scalar {
	var accum kyber.Scalar = mod.NewInt(big.NewInt(0), prime)
	for i := len(poly) - 1; i >= 0; i-- {
		coeff := poly[i] //a_i
		accum = accum.Mul(accum, x)
		accum = accum.Add(accum, coeff)
	}
	return accum
}

func lagrangeCoefficients(x kyber.Scalar, xs []kyber.Scalar) []kyber.Scalar {
	coeffs := make([]kyber.Scalar, len(xs))
	for i := 0; i < len(xs); i++ {
		var l kyber.Scalar = mod.NewInt(big.NewInt(1), prime)
		for j := 0; j < len(xs); j++ {
			if i != j {
				var num, den kyber.Scalar = mod.NewInt(big.NewInt(1), prime), mod.NewInt(big.NewInt(1), prime)
				num = num.Sub(x, xs[j])
				den = den.Sub(xs[i], xs[j])
				l = l.Mul(l, num.Div(num, den))
			}
		}
		coeffs[i] = l
	}
	return coeffs
}

// find the y-value for the given x, given at least t (x, y) points
// we assume that the points are distinct, and won't check them here
// f(x) = l0*y0 + l1*y1 + l2*y2 + ...
func lagrangeInterpolate(x kyber.Scalar, points []*polyPoint) kyber.Scalar {
	xs := make([]kyber.Scalar, len(points))
	for i, point := range points {
		xs[i] = point.x
	}
	coeffs := lagrangeCoefficients(x, xs)
	var result kyber.Scalar = mod.NewInt(big.NewInt(0), prime)
	for i, point := range points {
		result = result.Add(result, coeffs[i].Mul(coeffs[i], point.y))
	}
	return result
}

func recoverSecret(points []*polyPoint) kyber.Scalar {
	zero := mod.NewInt(big.NewInt(0), prime)
	return lagrangeInterpolate(zero, points)
}

func makeRandomShares(t, n uint, secret kyber.Scalar) []*polyPoint {
	if t > n {
		panic("t > n. Secret would be irrecoverable")
	}

	poly := make([]kyber.Scalar, t)
	poly[0] = secret
	for i := 1; uint(i) < t; i++ {
		var coeff kyber.Scalar = mod.NewInt(big.NewInt(0), prime)
		poly[i] = coeff.Pick(random.New())
	}
	//choose t - 1 random scalars, and assign poly[0] to be secret

	points := make([]*polyPoint, n)
	for i := 0; uint(i) < n; i++ {
		x := mod.NewInt64(int64(i+1), prime)
		y := evalPoly(poly, x)
		point := polyPoint{x: x, y: y}
		points[i] = &point
	}

	return points
}

func chooseKeyAndMakeRandomShares(t, n uint) []*polyPoint {
	//TODO sanity check of t and n. E.g. is t <= n
	secret := mod.NewInt(big.NewInt(0), prime).Pick(random.New())
	if n == 1 {
		x := mod.NewInt(big.NewInt(1), prime)
		return []*polyPoint{&polyPoint{x: x, y: secret}}
	}

	return makeRandomShares(t, n, secret)
}
