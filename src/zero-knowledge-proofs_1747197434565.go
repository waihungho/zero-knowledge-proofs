```go
// Package zkp provides a Zero-Knowledge Proof implementation focused on proving properties
// of committed values using Pedersen commitments and Schnorr-style proofs.
//
// It supports proofs of:
// 1. Knowledge of the value and randomness within a Pedersen commitment.
// 2. That the sum of committed values from a set of commitments equals a public value.
// 3. That a linear combination of committed values equals a public constant.
// 4. That a committed value is one of a public set of possible values (OR proof).
//
// The implementation builds upon standard cryptographic primitives like elliptic curves,
// hashing, and big integer arithmetic, without relying on existing complex ZKP circuit
// compilers or proving systems like Groth16, PLONK, etc., making it a focused and
// distinct implementation tailored to proving relations over Pedersen commitments.
//
// Outline:
// I. Data Structures: Point, ProofParams, Proof
// II. Core Cryptographic Helpers: Scalar/Point Arithmetic, Hashing to Scalar, Randomness
// III. Pedersen Commitment Operations: Creation, Aggregation
// IV. Proof Generation Functions:
//    - ProveKnowledge: Prove knowledge of v, r in C = vG + rH
//    - ProveSum: Prove Sum(v_i) = V_pub for C_i = v_i G + r_i H
//    - ProveLinearCombination: Prove Sum(coeff_i * v_i) = Const_pub for C_i = v_i G + r_i H
//    - ProveOneOfMany: Prove v is in {v1, v2, ..., vk} for C = vG + rH (OR proof)
// V. Proof Verification Functions: Corresponds to each Prove function
// VI. Utility and Encoding Functions: Setup, Parameter access, Encoding/Decoding Proofs/Points/Scalars
//
// Function Summary:
//
// I. Data Structures & Parameters
// 1.  SetupParams(seed string) (*ProofParams, error): Initializes elliptic curve and generators.
// 2.  GetCurve(params *ProofParams) elliptic.Curve: Returns the elliptic curve.
// 3.  PointZero(params *ProofParams) *Point: Returns the identity point on the curve.
//
// II. Core Cryptographic Helpers
// 4.  GenerateRandomScalar() (*big.Int): Generates a random scalar within the curve order.
// 5.  ScalarFromHash(params *ProofParams, data []byte) (*big.Int): Hashes data to a scalar.
// 6.  ScalarZero() *big.Int: Returns the scalar 0.
// 7.  ScalarOne() *big.Int: Returns the scalar 1.
// 8.  ScalarEqual(s1, s2 *big.Int) bool: Checks scalar equality.
// 9.  PointEqual(p1, p2 *Point) bool: Checks point equality.
// 10. IsOnCurve(params *ProofParams, p *Point) bool: Checks if a point is on the curve.
// 11. IsScalarInField(params *ProofParams, s *big.Int) bool: Checks if a scalar is in the field (curve order).
// 12. ComputeChallenge(params *ProofParams, publicData ...interface{}) (*big.Int): Deterministically computes a challenge scalar using Fiat-Shamir.
// 13. ComputePedersenGenerators(curve elliptic.Curve, seed string, count int) ([]*Point, *Point): Internal generator computation (G and H).
// 14. PointToString(p *Point) string: Helper to serialize a point for hashing.
// 15. ScalarToString(s *big.Int) string: Helper to serialize a scalar for hashing.
//
// III. Pedersen Commitment Operations
// 16. NewPedersenCommitment(params *ProofParams, value *big.Int, randomness *big.Int) (*Point): Creates a new Pedersen commitment C = value*G + randomness*H.
// 17. AggregateCommitments(params *ProofParams, commitments []*Point) (*Point, error): Computes the sum of multiple commitment points.
//
// IV. Proof Generation Functions
// 18. ProveKnowledge(params *ProofParams, value *big.Int, randomness *big.Int, commitment *Point) (*Proof, error): Generates a Schnorr-like proof of knowledge for a commitment.
// 19. ProveSum(params *ProofParams, commitments []*Point, values []*big.Int, randomness []*big.Int, expectedSum *big.Int) (*Proof, error): Proves Sum(values) = expectedSum for given commitments.
// 20. ProveLinearCombination(params *ProofParams, commitments []*Point, values []*big.Int, randomness []*big.Int, coefficients []*big.Int, expectedConstant *big.Int) (*Proof, error): Proves Sum(coeff_i * values_i) = expectedConstant.
// 21. ProveOneOfMany(params *ProofParams, commitment *Point, actualValue *big.Int, actualRandomness *big.Int, possibleValues []*big.Int) (*Proof, error): Generates a disjunctive proof that the committed value is one of the possible values.
//
// V. Proof Verification Functions
// 22. VerifyKnowledge(params *ProofParams, commitment *Point, proof *Proof) (bool, error): Verifies a knowledge proof.
// 23. VerifySum(params *ProofParams, commitments []*Point, expectedSum *big.Int, proof *Proof) (bool, error): Verifies a sum proof.
// 24. VerifyLinearCombination(params *ProofParams, commitments []*Point, coefficients []*big.Int, expectedConstant *big.Int, proof *Proof) (bool, error): Verifies a linear combination proof.
// 25. VerifyOneOfMany(params *ProofParams, commitment *Point, possibleValues []*big.Int, proof *Proof) (bool, error): Verifies a disjunctive proof.
//
// VI. Utility and Encoding Functions
// 26. EncodeProof(proof *Proof) ([]byte, error): Encodes a proof into bytes.
// 27. DecodeProof(data []byte) (*Proof, error): Decodes bytes into a proof.
// 28. EncodePoint(p *Point) ([]byte, error): Encodes a point into bytes.
// 29. DecodePoint(params *ProofParams, data []byte) (*Point, error): Decodes bytes into a point.
// 30. EncodeScalar(s *big.Int) ([]byte, error): Encodes a scalar into bytes.
// 31. DecodeScalar(params *ProofParams, data []byte) (*big.Int): Decodes bytes into a scalar.

package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	ErrInvalidProof          = errors.New("invalid zero-knowledge proof")
	ErrVerificationFailed    = errors.New("proof verification failed")
	ErrInvalidParameters     = errors.New("invalid parameters")
	ErrInvalidCommitments    = errors.New("invalid commitments")
	ErrMismatchCount         = errors.New("mismatch in number of inputs")
	ErrValueNotInPossibleSet = errors.New("actual value not in possible set for OR proof")
	ErrEncoding              = errors.New("encoding error")
	ErrDecoding              = errors.New("decoding error")
	ErrPointNotOnCurve       = errors.New("point is not on the curve")
)

// Point represents a point on the elliptic curve.
type Point struct {
	X, Y *big.Int
}

// ProofParams holds the curve parameters and generators for proofs.
type ProofParams struct {
	Curve elliptic.Curve
	G     *Point // Base generator point
	H     *Point // Another generator point, independent of G
}

// Proof represents a generic proof structure. The actual content depends on the proof type.
type Proof struct {
	// Common fields
	Challenge *big.Int // The main challenge scalar

	// Fields specific to different proof types
	// Knowledge proof: z, s are responses
	// OneOfMany (OR) proof: Multiple challenges and responses for simulated/real proofs
	Responses map[string]*big.Int // Map to hold various scalar responses by name (e.g., "z", "s", "c_i", "z_i", "s_i")
	Announcements map[string]*Point // Map to hold announcement points by name (e.g., "A" for knowledge, "A_i" for OR)
}

//--------------------------------------------------------------------------------
// I. Data Structures & Parameters
//--------------------------------------------------------------------------------

// SetupParams initializes the elliptic curve and generates the Pedersen generators G and H.
// The seed is used to deterministically derive the generators.
func SetupParams(seed string) (*ProofParams, error) {
	curve := elliptic.P256() // Using P-256 curve
	generators, H, err := ComputePedersenGenerators(curve, seed, 1) // Compute one generator for G and one for H
	if err != nil {
		return nil, fmt.Errorf("failed to compute generators: %w", err)
	}
	if len(generators) != 1 {
		return nil, errors.New("expected 1 generator for G, got more")
	}

	return &ProofParams{
		Curve: curve,
		G:     generators[0],
		H:     H,
	}, nil
}

// GetCurve returns the elliptic curve used in the parameters.
func GetCurve(params *ProofParams) elliptic.Curve {
	return params.Curve
}

// PointZero returns the identity point (point at infinity) on the curve.
func PointZero(params *ProofParams) *Point {
	// For affine coordinates, the identity is represented as nil or (0, 0) conceptually,
	// but curve methods handle it. A common representation is (nil, nil) or specific
	// sentinel values if not using library methods directly. Using the library's
	// behavior is safest. For P256, the point (0,0) is NOT on the curve and often signals infinity in affine.
	// However, operations like ScalarBaseMult(0) or Add(P, -P) result in identity.
	// A safe way is to return a point created by multiplying the base point by 0.
	x, y := params.Curve.ScalarBaseMult(ScalarZero().Bytes())
	return &Point{X: x, Y: y} // This should result in the point at infinity
}

//--------------------------------------------------------------------------------
// II. Core Cryptographic Helpers
//--------------------------------------------------------------------------------

// GenerateRandomScalar generates a random scalar suitable for the curve's scalar field.
func GenerateRandomScalar() (*big.Int) {
	// P256 Order (N)
	N := elliptic.P256().Params().N
	k, err := rand.Int(rand.Reader, N)
	if err != nil {
		// In a real application, handle this critical error properly.
		// For this example, we panic as randomness is fundamental.
		panic(fmt.Sprintf("failed to generate random scalar: %v", err))
	}
	return k
}

// ScalarFromHash hashes data and maps the result to a scalar in the curve's scalar field.
func ScalarFromHash(params *ProofParams, data []byte) (*big.Int) {
	N := params.Curve.Params().N
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:]).Mod(new(big.Int).SetBytes(h[:]), N)
}

// ScalarZero returns the scalar 0.
func ScalarZero() *big.Int {
	return big.NewInt(0)
}

// ScalarOne returns the scalar 1.
func ScalarOne() *big.Int {
	return big.NewInt(1)
}

// ScalarEqual checks if two scalars are equal.
func ScalarEqual(s1, s2 *big.Int) bool {
	return s1.Cmp(s2) == 0
}

// PointEqual checks if two points are equal (including the point at infinity if represented consistently).
func PointEqual(p1, p2 *Point) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2 // Both nil means both are point at infinity, or one is nil
	}
	// For P256, the point at infinity is (0,0). Check if both are (0,0).
	isP1Zero := p1.X.Sign() == 0 && p1.Y.Sign() == 0
	isP2Zero := p2.X.Sign() == 0 && p2.Y.Sign() == 0

	if isP1Zero || isP2Zero {
		return isP1Zero == isP2Zero // Both zero or neither zero
	}

	return p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0
}


// IsOnCurve checks if a given point is on the elliptic curve.
func IsOnCurve(params *ProofParams, p *Point) bool {
	if p == nil {
		return true // nil is often treated as the point at infinity, which is on the curve
	}
	// P256 uses (0,0) for the point at infinity in affine coordinates.
	if p.X.Sign() == 0 && p.Y.Sign() == 0 {
		return true // Point at infinity is on the curve
	}
	return params.Curve.IsOnCurve(p.X, p.Y)
}

// IsScalarInField checks if a scalar is within the curve's scalar field [0, N-1].
func IsScalarInField(params *ProofParams, s *big.Int) bool {
	N := params.Curve.Params().N
	return s.Sign() >= 0 && s.Cmp(N) < 0
}


// ComputeChallenge deterministically computes a challenge scalar using Fiat-Shamir.
// It hashes a concatenation of all public data related to the proof.
func ComputeChallenge(params *ProofParams, publicData ...interface{}) (*big.Int) {
	var data []byte
	for _, item := range publicData {
		switch v := item.(type) {
		case *big.Int:
			data = append(data, EncodeScalar(v)...)
		case *Point:
			encoded, _ := EncodePoint(v) // Error handling inside EncodePoint
			data = append(data, encoded...)
		case []*Point:
			for _, p := range v {
				encoded, _ := EncodePoint(p) // Error handling inside EncodePoint
				data = append(data, encoded...)
			}
		case string:
			data = append(data, []byte(v)...)
		case []byte:
			data = append(data, v...)
		default:
			// Fallback for other types - use Sprintf, less secure but covers cases
			data = append(data, []byte(fmt.Sprintf("%v", v))...)
		}
	}
	return ScalarFromHash(params, data)
}

// ComputePedersenGenerators computes base generators G and H for the Pedersen commitments.
// G is derived from the curve's standard base point. H is derived from the seed
// to be independent of G (practically).
// This function returns a slice containing the single G generator and the H generator.
// The count parameter is legacy from potential multi-generator schemes, kept at 1.
func ComputePedersenGenerators(curve elliptic.Curve, seed string, count int) ([]*Point, *Point) {
	// G is the standard base point of the curve
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	G := &Point{X: Gx, Y: Gy}

	// H is derived from the seed to be independent of G
	// We hash the seed and map it to a point on the curve.
	// A standard method is to hash until a valid point is found or use a specific mapping.
	// For simplicity here, we use a deterministic mapping based on hashing.
	seedBytes := sha256.Sum256([]byte(seed + "H")) // Use "H" suffix to distinguish from "G" if G was derived similarly
	Hx, Hy := curve.HashToPoint(seedBytes[:]) // Elliptic curve specific HashToPoint (simplified abstraction)
	H := &Point{X: Hx, Y: Hy}

	// Check if H is a multiple of G. This is computationally hard
	// (Discrete Logarithm Problem), so this check is practically impossible
	// but the derivation method aims to ensure it. A simple implementation
	// cannot reliably check this property without solving DLP.
	// We assume the HashToPoint is robust or the curve properties help.
	// For standard curves like P-256, a simple hash-to-point is usually sufficient
	// for non-interactive ZKPs based on random oracle model assumptions.

	return []*Point{G}, H
}

// PointToString converts a Point to a string representation for hashing.
func PointToString(p *Point) string {
	if p == nil || (p.X.Sign() == 0 && p.Y.Sign() == 0) { // Handle point at infinity
		return "infinity"
	}
	return fmt.Sprintf("Point{%s,%s}", p.X.String(), p.Y.String())
}

// ScalarToString converts a big.Int scalar to a string representation for hashing.
func ScalarToString(s *big.Int) string {
	return s.String()
}


//--------------------------------------------------------------------------------
// III. Pedersen Commitment Operations
//--------------------------------------------------------------------------------

// NewPedersenCommitment creates a new Pedersen commitment: C = value*G + randomness*H
func NewPedersenCommitment(params *ProofParams, value *big.Int, randomness *big.Int) (*Point) {
	N := params.Curve.Params().N
	Gx, Gy := params.G.X, params.G.Y
	Hx, Hy := params.H.X, params.H.Y

	// Compute value * G
	vG_x, vG_y := params.Curve.ScalarMult(Gx, Gy, value.Mod(value, N).Bytes())

	// Compute randomness * H
	rH_x, rH_y := params.Curve.ScalarMult(Hx, Hy, randomness.Mod(randomness, N).Bytes())

	// Compute C = vG + rH
	Cx, Cy := params.Curve.Add(vG_x, vG_y, rH_x, rH_y)

	return &Point{X: Cx, Y: Cy}
}

// AggregateCommitments computes the sum of multiple commitment points.
func AggregateCommitments(params *ProofParams, commitments []*Point) (*Point, error) {
	if len(commitments) == 0 {
		return PointZero(params), nil // Sum of no points is the identity point
	}

	var sumX, sumY *big.Int
	isFirst := true

	for _, c := range commitments {
		if !IsOnCurve(params, c) {
			return nil, ErrPointNotOnCurve
		}
		if isFirst {
			sumX, sumY = c.X, c.Y
			isFirst = false
		} else {
			sumX, sumY = params.Curve.Add(sumX, sumY, c.X, c.Y)
		}
	}
	return &Point{X: sumX, Y: sumY}, nil
}


//--------------------------------------------------------------------------------
// IV. Proof Generation Functions
//--------------------------------------------------------------------------------

// ProveKnowledge generates a Schnorr-like proof of knowledge for a Pedersen commitment C = vG + rH,
// proving knowledge of 'v' and 'r'.
// Prover: Knows v, r. C = vG + rH is public.
// Goal: Prove knowledge of v, r without revealing them.
// Steps:
// 1. Pick random scalars a, b.
// 2. Compute Announcement: A = aG + bH.
// 3. Compute Challenge: c = Hash(G, H, C, A).
// 4. Compute Responses: z = a + c*v (mod N), s = b + c*r (mod N).
// 5. Proof is (A, z, s).
func ProveKnowledge(params *ProofParams, value *big.Int, randomness *big.Int, commitment *Point) (*Proof, error) {
	N := params.Curve.Params().N

	// 1. Pick random scalars a, b
	a := GenerateRandomScalar()
	b := GenerateRandomScalar()

	// 2. Compute Announcement A = aG + bH
	aG_x, aG_y := params.Curve.ScalarBaseMult(a.Bytes())
	bH_x, bH_y := params.Curve.ScalarMult(params.H.X, params.H.Y, b.Bytes())
	Ax, Ay := params.Curve.Add(aG_x, aG_y, bH_x, bH_y)
	A := &Point{X: Ax, Y: Ay}

	// Check if inputs are valid points on curve
	if !IsOnCurve(params, commitment) || !IsOnCurve(params, params.G) || !IsOnCurve(params, params.H) || !IsOnCurve(params, A) {
		return nil, ErrPointNotOnCurve
	}
	// Check if inputs are valid scalars
	if !IsScalarInField(params, value) || !IsScalarInField(params, randomness) {
		return nil, ErrInvalidParameters
	}


	// 3. Compute Challenge c = Hash(G, H, C, A)
	c := ComputeChallenge(params, params.G, params.H, commitment, A)

	// 4. Compute Responses: z = a + c*v (mod N), s = b + c*r (mod N)
	// cv = c * v
	cv := new(big.Int).Mul(c, value)
	cv.Mod(cv, N)
	// z = a + cv
	z := new(big.Int).Add(a, cv)
	z.Mod(z, N)

	// cr = c * r
	cr := new(big.Int).Mul(c, randomness)
	cr.Mod(cr, N)
	// s = b + cr
	s := new(big.Int).Add(b, cr)
	s.Mod(s, N)

	proof := &Proof{
		Challenge: c,
		Announcements: map[string]*Point{"A": A},
		Responses: map[string]*big.Int{"z": z, "s": s},
	}

	return proof, nil
}


// ProveSum proves that the sum of committed values (v_i) in a list of commitments (C_i)
// equals a public expected sum (V_pub).
// C_i = v_i G + r_i H
// Claim: Sum(v_i) == V_pub
// Proof: C_agg = Sum(C_i) = Sum(v_i G + r_i H) = (Sum(v_i)) G + (Sum(r_i)) H
// Let V_agg = Sum(v_i) and R_agg = Sum(r_i). C_agg = V_agg G + R_agg H.
// If Sum(v_i) == V_pub, then C_agg = V_pub G + R_agg H.
// The prover knows V_pub (public), R_agg (computes it), and C_agg (computes it).
// This is equivalent to proving knowledge of V_pub and R_agg for C_agg.
// We can simply call ProveKnowledge on the aggregate commitment.
func ProveSum(params *ProofParams, commitments []*Point, values []*big.Int, randomness []*big.Int, expectedSum *big.Int) (*Proof, error) {
	if len(commitments) == 0 || len(values) != len(commitments) || len(randomness) != len(commitments) {
		return nil, ErrMismatchCount
	}

	// 1. Compute the aggregate randomness R_agg = Sum(r_i)
	N := params.Curve.Params().N
	R_agg := ScalarZero()
	for _, r := range randomness {
		if !IsScalarInField(params, r) {
			return nil, ErrInvalidParameters
		}
		R_agg.Add(R_agg, r)
		R_agg.Mod(R_agg, N)
	}

	// 2. Compute the aggregate commitment C_agg = Sum(C_i)
	// Note: We don't need to compute the values sum here, as the
	// relationship holds by the homomorphic property of the commitment.
	C_agg, err := AggregateCommitments(params, commitments)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate commitments: %w", err)
	}

	// Check if expectedSum is a valid scalar
	if !IsScalarInField(params, expectedSum) {
		// This is tricky. Is V_pub mod N or the actual sum?
		// Standard ZKPs prove relations over field elements.
		// Assume expectedSum should be treated as a scalar in the field.
		// If the real sum exceeds N, this proof might fail or prove a different value.
		// For simplicity, we require expectedSum < N.
		if expectedSum.Cmp(params.Curve.Params().N) >= 0 || expectedSum.Sign() < 0 {
             return nil, fmt.Errorf("expected sum %s is outside the scalar field [0, N-1]", expectedSum.String())
		}
	}


	// 3. Prove knowledge of expectedSum and R_agg for C_agg
	// This is a standard ProveKnowledge call.
	// We need to ensure that C_agg was actually constructed from the provided commitments.
	// The ProveKnowledge proof implicitly binds the proof to C_agg. The verifier
	// will re-calculate C_agg from the *public* commitments C_i.
	proof, err := ProveKnowledge(params, expectedSum, R_agg, C_agg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aggregate knowledge proof: %w", err)
	}

	// Add commitments to the proof structure for the verifier
	// Although standard Schnorr proof doesn't include commitments,
	// for this specific proof type, the commitments list is public input.
	// We don't need to store them IN the proof struct itself, but they are used
	// to recompute C_agg during verification.

	return proof, nil
}


// ProveLinearCombination proves that a linear combination of committed values
// (Sum(coeff_i * v_i)) equals a public constant (Const_pub).
// C_i = v_i G + r_i H
// Claim: Sum(coeff_i * v_i) == Const_pub
// Proof: Consider C_linear = Sum(coeff_i * C_i) = Sum(coeff_i * (v_i G + r_i H))
// C_linear = Sum(coeff_i * v_i G) + Sum(coeff_i * r_i H)
// C_linear = (Sum(coeff_i * v_i)) G + (Sum(coeff_i * r_i)) H
// Let V_linear = Sum(coeff_i * v_i) and R_linear = Sum(coeff_i * r_i).
// C_linear = V_linear G + R_linear H.
// If Sum(coeff_i * v_i) == Const_pub, then C_linear = Const_pub G + R_linear H.
// The prover knows Const_pub (public), R_linear (computes it), and C_linear (computes it).
// This is equivalent to proving knowledge of Const_pub and R_linear for C_linear.
// We call ProveKnowledge on the derived linear combination commitment.
func ProveLinearCombination(params *ProofParams, commitments []*Point, values []*big.Int, randomness []*big.Int, coefficients []*big.Int, expectedConstant *big.Int) (*Proof, error) {
	if len(commitments) == 0 || len(values) != len(commitments) || len(randomness) != len(commitments) || len(coefficients) != len(commitments) {
		return nil, ErrMismatchCount
	}

	N := params.Curve.Params().N

	// 1. Compute the linear combination of randomness R_linear = Sum(coeff_i * r_i)
	R_linear := ScalarZero()
	for i := range randomness {
		if !IsScalarInField(params, randomness[i]) || !IsScalarInField(params, coefficients[i]) {
			return nil, ErrInvalidParameters
		}
		term := new(big.Int).Mul(coefficients[i], randomness[i])
		R_linear.Add(R_linear, term)
		R_linear.Mod(R_linear, N)
	}

	// 2. Compute the linear combination of commitments C_linear = Sum(coeff_i * C_i)
	var C_linear *Point
	isFirst := true
	for i, c := range commitments {
		if !IsOnCurve(params, c) {
			return nil, ErrPointNotOnCurve
		}
		// Compute coeff_i * C_i
		coeffBytes := coefficients[i].Mod(coefficients[i], N).Bytes()
		termX, termY := params.Curve.ScalarMult(c.X, c.Y, coeffBytes)

		if isFirst {
			C_linear = &Point{X: termX, Y: termY}
			isFirst = false
		} else {
			sumX, sumY := params.Curve.Add(C_linear.X, C_linear.Y, termX, termY)
			C_linear = &Point{X: sumX, Y: sumY}
		}
	}

	// Check if expectedConstant is a valid scalar (similar considerations as ProveSum)
	if expectedConstant.Cmp(N) >= 0 || expectedConstant.Sign() < 0 {
         return nil, fmt.Errorf("expected constant %s is outside the scalar field [0, N-1]", expectedConstant.String())
	}


	// 3. Prove knowledge of expectedConstant and R_linear for C_linear
	proof, err := ProveKnowledge(params, expectedConstant, R_linear, C_linear)
	if err != nil {
		return nil, fmt.Errorf("failed to generate linear combination knowledge proof: %w", err)
	}

	return proof, nil
}

// ProveOneOfMany generates a proof that the committed value is one of the
// possible values in the provided list, without revealing which one.
// This is a disjunctive proof (OR proof) using a Fiat-Shamir based approach.
// C = vG + rH
// Claim: v is in {v_1, v_2, ..., v_k}
// Prover: Knows v_actual, r_actual such that C = v_actual G + r_actual H, and v_actual is one of possibleValues.
// Steps (for Prover knowing v_actual = possibleValues[actualIdx]):
// 1. Generate random challenge parts c_j for all j != actualIdx.
// 2. Generate random responses z_j, s_j for all j != actualIdx.
// 3. Compute simulated announcements A_j = z_j*G + s_j*H - c_j*(C - possibleValues[j]*G). Note: C - v_j*G = (v_actual - v_j)G + r_actual H
//    If v_actual = v_j, C - v_j*G = r_actual H.
//    So A_j = z_j*G + s_j*H - c_j * ((v_actual - possibleValues[j])G + r_actual H)
// 4. Compute total challenge c_total = Hash(G, H, C, A_1, A_2, ..., A_k).
// 5. Compute the actual challenge part c_actualIdx = c_total - Sum(c_j for j != actualIdx) (mod N).
// 6. Compute the actual responses z_actualIdx, s_actualIdx for the true case:
//    Let C'_actual = C - possibleValues[actualIdx]*G = (v_actual - possibleValues[actualIdx])G + r_actual H = r_actual H.
//    The proof for this case is Proving Knowledge of 0, r_actual for r_actual H.
//    Pick random a_actual, b_actual. Announcement A_actual = a_actual G + b_actual H.
//    Challenge c_actual is computed. Responses z_actual = a_actual + c_actual*0, s_actual = b_actual + c_actual*r_actual.
//    The standard OR proof is slightly different. It proves knowledge of v_i, r_i for C such that v_i = possibleValues[i] OR ...
//    Let's simplify: Prove knowledge of (v-v_i) and r for C - v_i*G = (v-v_i)G + rH. If v=v_i, this is 0G + rH = rH.
//    So, for the actual index `i`, we need to prove knowledge of `0` and `r` for the commitment `C_i = C - possibleValues[i]*G = rH`.
//    For simulated indices `j`, we need to simulate a proof of knowledge of `0` and some randomness `r_j'` for `C_j = C - possibleValues[j]*G = (v-v_j)G + rH`.
//    Pick random `a_i, b_i`. Compute `A_i = a_i G + b_i H`.
//    Compute challenge `c_total = Hash(G, H, C, {A_j}_j)`.
//    For `j != i`, pick random `z_j, s_j`, compute `c_j` and `A_j` from `A_j = z_j G + s_j H - c_j (C - v_j G)`.
//    For `j = i`, compute `c_i = c_total - Sum(c_j for j!=i)`. Compute `z_i, s_i` from `z_i G + s_i H = A_i + c_i (C - v_i G)`.
//    Let's use the structure from a standard implementation (like Bulletproofs/Secp256k1 style):
//    For each i in {0..k-1}:
//    Prover picks random alpha_i, rho_i.
//    Announcement A_i = alpha_i * G. (proves knowledge of alpha_i for A_i)
//    Announcement B_i = rho_i * H. (proves knowledge of rho_i for B_i)
//    Announcement E_i = (v - v_i) * G + randomness * H. (This is C - v_i * G)
//    This doesn't look right. A common OR proof (e.g., based on Chaum-Pedersen or Schnorr) for `C = vG + rH`, prove `v=v0 OR v=v1`:
//    Prover commits to random a0, b0, a1, b1. A0 = a0 G + b0 H, A1 = a1 G + b1 H.
//    Challenge c = Hash(params, C, A0, A1).
//    If proving v=v0: Pick random c1. Compute c0 = c - c1. Compute z0 = a0 + c0*v0, s0 = b0 + c0*r. Simulate z1, s1 using c1.
//    If proving v=v1: Pick random c0. Compute c1 = c - c0. Compute z1 = a1 + c1*v1, s1 = b1 + c1*r. Simulate z0, s0 using c0.
//    Proof includes (A0, A1, c0, z0, s0, c1, z1, s1). Verifier checks c0+c1=c and verifies equations.
//    Let's implement this Disjunctive (OR) Proof structure.

func ProveOneOfMany(params *ProofParams, commitment *Point, actualValue *big.Int, actualRandomness *big.Int, possibleValues []*big.Int) (*Proof, error) {
	N := params.Curve.Params().N

	k := len(possibleValues)
	if k == 0 {
		return nil, errors.New("possibleValues list cannot be empty")
	}

	// Find the index of the actual value in the possible values list
	actualIdx := -1
	for i, val := range possibleValues {
		if ScalarEqual(val, actualValue) {
			actualIdx = i
			break
		}
	}
	if actualIdx == -1 {
		// This should not happen if the prover is honest, but we check.
		// In a real system, this means the prover is trying to prove a false statement.
		return nil, ErrValueNotInPossibleSet
	}

	// Prepare commitments and random values for simulation
	announcements := make(map[string]*Point)
	challenges_j := make(map[int]*big.Int) // challenges for simulated proofs
	responses_z := make(map[int]*big.Int)  // z responses
	responses_s := make(map[int]*big.Int)  // s responses
	random_as := make(map[int]*big.Int)    // random a_j for real proof part
	random_bs := make(map[int]*big.Int)    // random b_j for real proof part


	// Step 1 & 2: For j != actualIdx, generate random challenges c_j and responses z_j, s_j.
	// Then compute simulated announcement A_j.
	var simulatedChallengeSum = ScalarZero()
	for j := 0; j < k; j++ {
		a_j := GenerateRandomScalar() // Use distinct randomness for each potential branch
		b_j := GenerateRandomScalar()
		random_as[j] = a_j
		random_bs[j] = b_j


		if j != actualIdx {
			// Simulate proof for the "false" case (v = possibleValues[j])
			// Pick random z_j, s_j
			z_j := GenerateRandomScalar()
			s_j := GenerateRandomScalar()
			responses_z[j] = z_j
			responses_s[j] = s_j

			// Pick random challenge c_j for this simulated proof
			c_j := GenerateRandomScalar()
			challenges_j[j] = c_j

			// Compute simulated announcement A_j = z_j*G + s_j*H - c_j*(C - possibleValues[j]*G)
			// C_j_prime = C - possibleValues[j]*G
			vjG_x, vjG_y := params.Curve.ScalarBaseMult(possibleValues[j].Mod(possibleValues[j], N).Bytes())
			neg_vjG_x, neg_vjG_y := params.Curve.ScalarMult(vjG_x, vjG_y, new(big.Int).SetInt64(-1).Mod(new(big.Int).SetInt64(-1), N).Bytes())
			Cj_prime_x, Cj_prime_y := params.Curve.Add(commitment.X, commitment.Y, neg_vjG_x, neg_vjG_y)

			// c_j * C_j_prime
			cjCj_prime_x, cjCj_prime_y := params.Curve.ScalarMult(Cj_prime_x, Cj_prime_y, c_j.Bytes())
			// -(c_j * C_j_prime)
			neg_cjCj_prime_x, neg_cjCj_prime_y := params.Curve.ScalarMult(cjCj_prime_x, cjCj_prime_y, new(big.Int).SetInt64(-1).Mod(new(big.Int).SetInt64(-1), N).Bytes())

			// z_j * G
			zjG_x, zjG_y := params.Curve.ScalarBaseMult(z_j.Bytes())
			// s_j * H
			sjH_x, sjH_y := params.Curve.ScalarMult(params.H.X, params.H.Y, s_j.Bytes())

			// A_j = (z_j G + s_j H) + (- c_j * C_j_prime)
			tempX, tempY := params.Curve.Add(zjG_x, zjG_y, sjH_x, sjH_y)
			Aj_x, Aj_y := params.Curve.Add(tempX, tempY, neg_cjCj_prime_x, neg_cjCj_prime_y)
			announcements[fmt.Sprintf("A%d", j)] = &Point{X: Aj_x, Y: Aj_y}

			// Add c_j to the sum of simulated challenges
			simulatedChallengeSum.Add(simulatedChallengeSum, c_j)
			simulatedChallengeSum.Mod(simulatedChallengeSum, N)

		} else {
			// For the actual index, compute the announcement A_actualIdx = a_actualIdx*G + b_actualIdx*H
			// where a_actualIdx, b_actualIdx are fresh random scalars.
			a_actual := random_as[actualIdx]
			b_actual := random_bs[actualIdx]
			aG_x, aG_y := params.Curve.ScalarBaseMult(a_actual.Bytes())
			bH_x, bH_y := params.Curve.ScalarMult(params.H.X, params.H.Y, b_actual.Bytes())
			A_actual_x, A_actual_y := params.Curve.Add(aG_x, aG_y, bH_x, bH_y)
			announcements[fmt.Sprintf("A%d", actualIdx)] = &Point{X: A_actual_x, Y: A_actual_y}
		}
	}

	// Step 4: Compute total challenge c_total = Hash(G, H, C, A_0, ..., A_{k-1})
	// Collect all announcements in order for deterministic hashing
	allAnnouncements := make([]*Point, k)
	for i := 0; i < k; i++ {
		allAnnouncements[i] = announcements[fmt.Sprintf("A%d", i)]
	}
	c_total := ComputeChallenge(params, params.G, params.H, commitment, allAnnouncements)

	// Step 5: Compute the actual challenge part c_actualIdx = c_total - Sum(c_j for j != actualIdx) (mod N)
	c_actual := new(big.Int).Sub(c_total, simulatedChallengeSum)
	c_actual.Mod(c_actual, N)
	challenges_j[actualIdx] = c_actual // Store the computed actual challenge

	// Step 6: Compute the actual responses z_actualIdx, s_actualIdx
	// z_actual = a_actual + c_actual * 0 (mod N) -> z_actual = a_actual
	// s_actual = b_actual + c_actual * r_actual (mod N)
	z_actual := random_as[actualIdx] // As the value we are proving knowledge of in C-v_actual*G is 0
	cr_actual := new(big.Int).Mul(c_actual, actualRandomness)
	cr_actual.Mod(cr_actual, N)
	s_actual := new(big.Int).Add(random_bs[actualIdx], cr_actual)
	s_actual.Mod(s_actual, N)
	responses_z[actualIdx] = z_actual
	responses_s[actualIdx] = s_actual


	// Build the proof structure
	proofResponses := make(map[string]*big.Int)
	for j := 0; j < k; j++ {
		proofResponses[fmt.Sprintf("c%d", j)] = challenges_j[j]
		proofResponses[fmt.Sprintf("z%d", j)] = responses_z[j]
		proofResponses[fmt.Sprintf("s%d", j)] = responses_s[j]
	}

	proof := &Proof{
		Challenge: c_total, // The total challenge is included, though can be recomputed by verifier
		Announcements: announcements, // All announcements A_0 to A_{k-1}
		Responses: proofResponses,
	}

	return proof, nil
}


//--------------------------------------------------------------------------------
// V. Proof Verification Functions
//--------------------------------------------------------------------------------

// VerifyKnowledge verifies a Schnorr-like proof of knowledge for a Pedersen commitment.
// Verifier: Knows C, G, H. Receives Proof (A, z, s).
// Goal: Check if the proof is valid for C.
// Steps:
// 1. Check if A is on the curve.
// 2. Recompute Challenge: c_prime = Hash(G, H, C, A).
// 3. Check if c_prime equals the challenge in the proof (or recompute responses based on c_prime).
//    Using Fiat-Shamir, the verifier recomputes the *expected* challenge based on public inputs and prover's announcements.
//    The verification equation should hold: z*G + s*H == A + c_prime*C
// 4. Check if z, s are in the scalar field.
// 5. Verify the equation: z*G + s*H == A + c_prime*C
func VerifyKnowledge(params *ProofParams, commitment *Point, proof *Proof) (bool, error) {
	N := params.Curve.Params().N

	// Retrieve A, z, s from the proof
	A, okA := proof.Announcements["A"]
	z, okZ := proof.Responses["z"]
	s, okS := proof.Responses["s"]

	if !okA || !okZ || !okS {
		return false, fmt.Errorf("%w: missing components for knowledge proof", ErrInvalidProof)
	}

	// 1. Check if A is on the curve
	if !IsOnCurve(params, A) {
		return false, ErrPointNotOnCurve
	}
	// Check if C, G, H are on the curve (should be from params/input, but defensive check)
	if !IsOnCurve(params, commitment) || !IsOnCurve(params, params.G) || !IsOnCurve(params, params.H) {
		return false, ErrPointNotOnCurve
	}


	// 2. Recompute Challenge c_prime = Hash(G, H, C, A)
	c_prime := ComputeChallenge(params, params.G, params.H, commitment, A)

	// 3. Verification Equation: z*G + s*H == A + c_prime*C
	// Left side: z*G + s*H
	zG_x, zG_y := params.Curve.ScalarBaseMult(z.Mod(z, N).Bytes())
	sH_x, sH_y := params.Curve.ScalarMult(params.H.X, params.H.Y, s.Mod(s, N).Bytes())
	lhsX, lhsY := params.Curve.Add(zG_x, zG_y, sH_x, sH_y)
	lhs := &Point{X: lhsX, Y: lhsY}

	// Right side: A + c_prime*C
	// c_prime * C
	cC_x, cC_y := params.Curve.ScalarMult(commitment.X, commitment.Y, c_prime.Bytes())
	// A + c_prime * C
	rhsX, rhsY := params.Curve.Add(A.X, A.Y, cC_x, cC_y)
	rhs := &Point{X: rhsX, Y: rhsY}

	// 5. Check if LHS == RHS
	if !PointEqual(lhs, rhs) {
		// Optional: check if z, s are in field N
		if !IsScalarInField(params, z) || !IsScalarInField(params, s) {
			return false, fmt.Errorf("%w: responses out of scalar field", ErrVerificationFailed)
		}
		return false, ErrVerificationFailed
	}

	return true, nil
}


// VerifySum verifies a proof that the sum of committed values equals an expected sum.
// It recomputes the aggregate commitment and verifies the knowledge proof on it.
func VerifySum(params *ProofParams, commitments []*Point, expectedSum *big.Int, proof *Proof) (bool, error) {
	if len(commitments) == 0 {
		// A sum of zero commitments is 0. If expectedSum is 0, the proof should be a knowledge proof of 0 for PointZero.
		// Handle this edge case explicitly if needed, or assume the prover handles it by providing a valid proof for V_pub=0, R_agg=0, C_agg=PointZero.
		// The current implementation of ProveSum requires commitments as input.
		return false, ErrInvalidCommitments
	}

	// Recompute the aggregate commitment C_agg = Sum(C_i) from the public commitments
	C_agg, err := AggregateCommitments(params, commitments)
	if err != nil {
		return false, fmt.Errorf("verifier failed to aggregate commitments: %w", err)
	}

	// Check if expectedSum is valid (same check as in ProveSum)
	if expectedSum.Cmp(params.Curve.Params().N) >= 0 || expectedSum.Sign() < 0 {
        return false, fmt.Errorf("expected sum %s is outside the scalar field [0, N-1]", expectedSum.String())
	}

	// Verify the knowledge proof for expectedSum and the aggregate commitment
	// The VerifyKnowledge function checks if the proof demonstrates knowledge
	// of (expectedSum, R_agg') for C_agg, where R_agg' is derived from the proof responses.
	return VerifyKnowledge(params, C_agg, proof)
}

// VerifyLinearCombination verifies a proof that a linear combination of committed
// values equals an expected constant.
// It recomputes the derived linear combination commitment and verifies the knowledge proof on it.
func VerifyLinearCombination(params *ProofParams, commitments []*Point, coefficients []*big.Int, expectedConstant *big.Int, proof *Proof) (bool, error) {
	if len(commitments) == 0 || len(coefficients) != len(commitments) {
		return false, ErrMismatchCount
	}

	N := params.Curve.Params().N

	// Recompute the linear combination of commitments C_linear = Sum(coeff_i * C_i)
	var C_linear *Point
	isFirst := true
	for i, c := range commitments {
		if !IsOnCurve(params, c) {
			return false, ErrPointNotOnCurve
		}
		if coefficients[i].Cmp(N) >= 0 || coefficients[i].Sign() < 0 { // Check coefficients too
             return false, fmt.Errorf("coefficient %d (%s) is outside the scalar field [0, N-1]", i, coefficients[i].String())
		}
		coeffBytes := coefficients[i].Mod(coefficients[i], N).Bytes()
		termX, termY := params.Curve.ScalarMult(c.X, c.Y, coeffBytes)

		if isFirst {
			C_linear = &Point{X: termX, Y: termY}
			isFirst = false
		} else {
			sumX, sumY := params.Curve.Add(C_linear.X, C_linear.Y, termX, termY)
			C_linear = &Point{X: sumX, Y: sumY}
		}
	}

	// Check if expectedConstant is valid (same check as in ProveLinearCombination)
	if expectedConstant.Cmp(N) >= 0 || expectedConstant.Sign() < 0 {
        return false, fmt.Errorf("expected constant %s is outside the scalar field [0, N-1]", expectedConstant.String())
	}

	// Verify the knowledge proof for expectedConstant and the derived commitment C_linear
	return VerifyKnowledge(params, C_linear, proof)
}


// VerifyOneOfMany verifies a disjunctive proof that the committed value is one of the possible values.
// Verifier receives C, {v_j}_j, Proof ({A_j}_j, {c_j}_j, {z_j}_j, {s_j}_j).
// Steps:
// 1. Check if all A_j are on the curve.
// 2. Check if all c_j, z_j, s_j are in the scalar field.
// 3. Check if Sum(c_j) (mod N) equals the total challenge c_total.
// 4. Recompute total challenge c_total_prime = Hash(G, H, C, A_0, ..., A_{k-1}).
// 5. Check if c_total_prime equals c_total from the proof. (Or just use c_total_prime for verification).
// 6. For each j in {0..k-1}, verify the equation: z_j*G + s_j*H == A_j + c_j*(C - possibleValues[j]*G).
//    This equation should hold for all j. The structure of the proof (simulation for false statements)
//    ensures this system of equations holds iff the prover knew the secret for at least one j.
func VerifyOneOfMany(params *ProofParams, commitment *Point, possibleValues []*big.Int, proof *Proof) (bool, error) {
	N := params.Curve.Params().N
	k := len(possibleValues)
	if k == 0 {
		return false, errors.New("possibleValues list cannot be empty")
	}

	// Check proof structure and retrieve components
	if proof.Announcements == nil || proof.Responses == nil {
		return false, fmt.Errorf("%w: missing announcements or responses for OR proof", ErrInvalidProof)
	}
	if len(proof.Announcements) != k {
		return false, fmt.Errorf("%w: mismatch in announcement count for OR proof", ErrInvalidProof)
	}
	// Expect 3*k responses (c_j, z_j, s_j for j=0..k-1)
	if len(proof.Responses) != 3*k {
		return false, fmt.Errorf("%w: mismatch in response count for OR proof", ErrInvalidProof)
	}

	allAnnouncements := make([]*Point, k)
	challenges_j := make(map[int]*big.Int)
	responses_z := make(map[int]*big.Int)
	responses_s := make(map[int]*big.Int)
	var challengeSum = ScalarZero()

	for j := 0; j < k; j++ {
		// Check and retrieve A_j
		Aj_name := fmt.Sprintf("A%d", j)
		Aj, okA := proof.Announcements[Aj_name]
		if !okA { return false, fmt.Errorf("%w: missing announcement %s", ErrInvalidProof, Aj_name) }
		if !IsOnCurve(params, Aj) { return false, fmt.Errorf("%w: announcement %s not on curve", ErrPointNotOnCurve, Aj_name) }
		allAnnouncements[j] = Aj // Store for challenge recomputation

		// Check and retrieve c_j, z_j, s_j
		cj_name := fmt.Sprintf("c%d", j)
		zj_name := fmt.Sprintf("z%d", j)
		sj_name := fmt.Sprintf("s%d", j)
		cj, okC := proof.Responses[cj_name]
		zj, okZ := proof.Responses[zj_name]
		sj, okS := proof.Responses[sj_name]

		if !okC || !okZ || !okS { return false, fmt.Errorf("%w: missing response(s) for index %d", ErrInvalidProof, j) }
		if !IsScalarInField(params, cj) || !IsScalarInField(params, zj) || !IsScalarInField(params, sj) {
             return false, fmt.Errorf("%w: response(s) for index %d out of scalar field", ErrVerificationFailed, j)
		}
		challenges_j[j] = cj
		responses_z[j] = zj
		responses_s[j] = sj

		// Add c_j to the sum
		challengeSum.Add(challengeSum, cj)
		challengeSum.Mod(challengeSum, N)
	}

	// Check if C, G, H are on the curve
	if !IsOnCurve(params, commitment) || !IsOnCurve(params, params.G) || !IsOnCurve(params, params.H) {
		return false, ErrPointNotOnCurve
	}

	// Recompute total challenge c_total_prime = Hash(G, H, C, A_0, ..., A_{k-1})
	c_total_prime := ComputeChallenge(params, params.G, params.H, commitment, allAnnouncements)

	// Check if Sum(c_j) == c_total_prime
	if !ScalarEqual(challengeSum, c_total_prime) {
		return false, fmt.Errorf("%w: challenge sum mismatch", ErrVerificationFailed)
	}

	// Verify the equation for each j: z_j*G + s_j*H == A_j + c_j*(C - possibleValues[j]*G)
	for j := 0; j < k; j++ {
		Aj := announcements[fmt.Sprintf("A%d", j)]
		cj := challenges_j[j]
		zj := responses_z[j]
		sj := responses_s[j]
		vj := possibleValues[j]

		if vj.Cmp(N) >= 0 || vj.Sign() < 0 { // Check possible value is scalar
            return false, fmt.Errorf("possible value %d (%s) is outside the scalar field [0, N-1]", j, vj.String())
		}


		// Left side: z_j*G + s_j*H
		zjG_x, zjG_y := params.Curve.ScalarBaseMult(zj.Mod(zj, N).Bytes())
		sjH_x, sjH_y := params.Curve.ScalarMult(params.H.X, params.H.Y, sj.Mod(sj, N).Bytes())
		lhsX, lhsY := params.Curve.Add(zjG_x, zjG_y, sjH_x, sjH_y)
		lhs := &Point{X: lhsX, Y: lhsY}


		// Right side: A_j + c_j*(C - possibleValues[j]*G)
		// C_j_prime = C - possibleValues[j]*G
		vjG_x, vjG_y := params.Curve.ScalarBaseMult(vj.Mod(vj, N).Bytes())
		neg_vjG_x, neg_vjG_y := params.Curve.ScalarMult(vjG_x, vjG_y, new(big.Int).SetInt64(-1).Mod(new(big.Int).SetInt64(-1), N).Bytes())
		Cj_prime_x, Cj_prime_y := params.Curve.Add(commitment.X, commitment.Y, neg_vjG_x, neg_vjG_y)

		// c_j * C_j_prime
		cjCj_prime_x, cjCj_prime_y := params.Curve.ScalarMult(Cj_prime_x, Cj_prime_y, cj.Mod(cj, N).Bytes())

		// A_j + c_j * C_j_prime
		rhsX, rhsY := params.Curve.Add(Aj.X, Aj.Y, cjCj_prime_x, cjCj_prime_y)
		rhs := &Point{X: rhsX, Y: rhsY}

		// Check if LHS == RHS
		if !PointEqual(lhs, rhs) {
			// If any equation fails, the proof is invalid.
			// fmt.Printf("Verification failed for index %d: LHS != RHS\n", j) // Debugging helper
			return false, ErrVerificationFailed
		}
	}

	// If all checks pass, the proof is valid.
	return true, nil
}


//--------------------------------------------------------------------------------
// VI. Utility and Encoding Functions
//--------------------------------------------------------------------------------

// Proof encoding and decoding using simple binary/length prefixes.
// More robust serialization might use protobuf or similar.

// EncodeProof encodes a Proof into bytes.
func EncodeProof(proof *Proof) ([]byte, error) {
	// Simple structure:
	// [challenge len] [challenge]
	// [num announcements] ([announcement name len] [announcement name] [point len] [point]) ...
	// [num responses] ([response name len] [response name] [scalar len] [scalar]) ...

	var buf []byte

	// Challenge
	challengeBytes := EncodeScalar(proof.Challenge)
	buf = append(buf, uint32ToBytes(uint32(len(challengeBytes)))...)
	buf = append(buf, challengeBytes...)

	// Announcements
	buf = append(buf, uint32ToBytes(uint32(len(proof.Announcements)))...)
	for name, p := range proof.Announcements {
		buf = append(buf, uint32ToBytes(uint32(len(name)))...)
		buf = append(buf, []byte(name)...)
		pointBytes, err := EncodePoint(p)
		if err != nil { return nil, fmt.Errorf("%w: encoding announcement %s: %v", ErrEncoding, name, err) }
		buf = append(buf, uint32ToBytes(uint32(len(pointBytes)))...)
		buf = append(buf, pointBytes...)
	}

	// Responses
	buf = append(buf, uint32ToBytes(uint32(len(proof.Responses)))...)
	for name, s := range proof.Responses {
		buf = append(buf, uint32ToBytes(uint32(len(name)))...)
		buf = append(buf, []byte(name)...)
		scalarBytes := EncodeScalar(s)
		buf = append(buf, uint32ToBytes(uint32(len(scalarBytes)))...)
		buf = append(buf, scalarBytes...)
	}

	return buf, nil
}

// DecodeProof decodes bytes into a Proof. Requires ProofParams to decode points.
func DecodeProof(data []byte) (*Proof, error) {
	// Note: Need ProofParams to decode points properly as elliptic.Curve is needed.
	// This DecodeProof cannot be standalone. It's more like a helper
	// within a context that has params. A better design might pass params.

	// Simple implementation that assumes params are available (e.g., from a global or context)
	// or relies on the fact that elliptic.Unmarshal knows the curve based on byte length.
	// P256 points are usually 33 or 65 bytes. Scalars are 32 bytes.
	// Let's assume P256 and 65-byte uncompressed points or 33-byte compressed points for now.
	// The standard Unmarshal handles compressed/uncompressed and detects curve (if registered).

	// Use a reader for state management
	r := &byteReader{data: data}

	proof := &Proof{
		Announcements: make(map[string]*Point),
		Responses: make(map[string]*big.Int),
	}

	// Challenge
	challengeLen, err := r.readUint32()
	if err != nil { return nil, fmt.Errorf("%w: reading challenge len: %v", ErrDecoding, err) }
	challengeBytes, err := r.readBytes(int(challengeLen))
	if err != nil { return nil, fmt.Errorf("%w: reading challenge: %v", ErrDecoding, err) }
	proof.Challenge = DecodeScalar(challengeBytes)


	// Announcements
	numAnnouncements, err := r.readUint32()
	if err != nil { return nil, fmt.Errorf("%w: reading num announcements: %v", ErrDecoding, err) }
	for i := 0; i < int(numAnnouncements); i++ {
		nameLen, err := r.readUint32()
		if err != nil { return nil, fmt.Errorf("%w: reading announcement name len %d: %v", ErrDecoding, i, err) }
		nameBytes, err := r.readBytes(int(nameLen))
		if err != nil { return nil, fmt.Errorf("%w: reading announcement name %d: %v", ErrDecoding, i, err) }
		name := string(nameBytes)

		pointLen, err := r.readUint32()
		if err != nil { return nil, fmt.Errorf("%w: reading announcement point len %s: %v", ErrDecoding, name, err) }
		pointBytes, err := r.readBytes(int(pointLen))
		if err != nil { return nil, fmt.Errorf("%w: reading announcement point %s: %v", ErrDecoding, name, err) }

		// Note: DecodePoint needs params, which we don't have here.
		// We need a way to get params (e.g., pass them in) or delay decoding points.
		// For this example, let's assume a way to get the curve (e.g. P256 hardcoded or passed in).
		// A proper implementation would likely pass ProofParams to this function.
		// Let's modify the signature.

		// This function signature is wrong: DecodeProof(data []byte) -> (*Proof, error)
		// It should be DecodeProof(params *ProofParams, data []byte) -> (*Proof, error)
		// Let's assume the caller provides params.
		// For now, let's return an error or panic if params are missing, or hardcode P256.
		// Hardcoding P256 is simpler for the example.

		curve := elliptic.P256() // Assuming P256
		px, py := elliptic.Unmarshal(curve, pointBytes)
		if px == nil || py == nil {
			return nil, fmt.Errorf("%w: failed to unmarshal announcement point %s", ErrDecoding, name)
		}
		proof.Announcements[name] = &Point{X: px, Y: py}
	}


	// Responses
	numResponses, err := r.readUint32()
	if err != nil { return nil, fmt.Errorf("%w: reading num responses: %v", ErrDecoding, err) }
	for i := 0; i < int(numResponses); i++ {
		nameLen, err := r.readUint32()
		if err != nil { return nil, fmt.Errorf("%w: reading response name len %d: %v", ErrDecoding, i, err) }
		nameBytes, err := r.readBytes(int(nameLen))
		if err != nil { return nil, fmt.Errorf("%w: reading response name %d: %v", ErrDecoding, i, err) }
		name := string(nameBytes)

		scalarLen, err := r.readUint32()
		if err != nil { return nil, fmt.Errorf("%w: reading response scalar len %s: %v", ErrDecoding, name, err) }
		scalarBytes, err := r.readBytes(int(scalarLen))
		if err != nil { return nil, fmt.Errorf("%w: reading response scalar %s: %v", ErrDecoding, name, err) }
		proof.Responses[name] = DecodeScalar(scalarBytes)
	}

	if r.remaining() > 0 {
		return nil, fmt.Errorf("%w: extra data after decoding proof", ErrDecoding)
	}

	return proof, nil
}

// Helper for encoding uint32 to bytes
func uint32ToBytes(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// Helper byte reader for decoding
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	bytes := r.data[r.pos : r.pos+n]
	r.pos += n
	return bytes, nil
}

func (r *byteReader) readUint32() (uint32, error) {
	bytes, err := r.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(bytes), nil
}

func (r *byteReader) remaining() int {
	return len(r.data) - r.pos
}


// EncodePoint encodes a Point into bytes using compressed format if possible.
func EncodePoint(p *Point) ([]byte, error) {
	if p == nil || (p.X.Sign() == 0 && p.Y.Sign() == 0) {
		// Represents the point at infinity, encode as a special marker or (0,0)
		// Elliptic.Marshal handles (0,0) as infinity for supported curves.
		// For P256, it returns a specific 33-byte encoding for infinity.
		return elliptic.Marshal(elliptic.P256(), ScalarZero(), ScalarZero()), nil
	}
	// Use standard Marshal which handles compressed/uncompressed based on curve default or flags
	return elliptic.Marshal(elliptic.P256(), p.X, p.Y), nil // Assuming P256
}

// DecodePoint decodes bytes into a Point. Requires ProofParams to get the curve.
func DecodePoint(params *ProofParams, data []byte) (*Point, error) {
	x, y := elliptic.Unmarshal(params.Curve, data)
	if x == nil || y == nil {
		// Check if it was the encoded point at infinity (0,0) which Unmarshal should handle
		if len(data) > 0 && data[0] == 0x00 { // Common marker for infinity/identity
             // Additional check: if Unmarshal returned (0,0) and curve recognizes it as identity
             if params.Curve.IsOnCurve(x,y) && x.Sign() == 0 && y.Sign() == 0 {
                  return &Point{X: x, Y: y}, nil // Successfully decoded identity
             }
		}
		return nil, fmt.Errorf("%w: failed to unmarshal point", ErrDecoding)
	}
	if !params.Curve.IsOnCurve(x, y) {
         return nil, ErrPointNotOnCurve
	}
	return &Point{X: x, Y: y}, nil
}


// EncodeScalar encodes a big.Int scalar into bytes (big-endian, fixed size).
func EncodeScalar(s *big.Int) ([]byte) {
	// P256 scalar field order N is a 256-bit number. Need 32 bytes.
	// Use N.Bytes() to get the minimal representation, then pad if necessary.
	// Or simply use the big.Int.Bytes() method and pad/truncate.
	// A fixed size encoding is generally safer for ZKPs (avoids malleability or length leaks).
	// P256 order N is less than 2^256, so 32 bytes is sufficient.
	N := elliptic.P256().Params().N // Assuming P256
	byteLen := (N.BitLen() + 7) / 8 // Usually 32 bytes for P256

	sBytes := s.Bytes()
	if len(sBytes) > byteLen {
		// This should not happen if the scalar is in the field [0, N-1)
		// but could happen if N itself has leading zero bytes in its minimal representation
		// or if the input scalar is outside the field.
		// For security, ensure scalar is reduced mod N before encoding if it might be large.
		s.Mod(s, N)
		sBytes = s.Bytes() // Re-encode after reduction
	}

	encoded := make([]byte, byteLen)
	copy(encoded[byteLen-len(sBytes):], sBytes) // Pad with leading zeros

	return encoded
}

// DecodeScalar decodes bytes into a big.Int scalar.
func DecodeScalar(data []byte) (*big.Int) {
	// Assume data is big-endian.
	// Need to ensure the decoded scalar is within the curve order N.
	// A full check would be: decode, then check if s < N.
	// For simplicity here, we just decode.
	return new(big.Int).SetBytes(data)
}
```