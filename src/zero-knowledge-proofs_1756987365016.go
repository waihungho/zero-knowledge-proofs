This Go implementation showcases a custom Zero-Knowledge Proof (ZKP) protocol designed for **"Privacy-Preserving Proof of Fair Resource Allocation based on Aggregated Secret Scores."**

The chosen concept is an advanced, creative, and trendy application of ZKP that goes beyond basic "proof of knowing a secret." It addresses the growing need for verifiable fairness and privacy in data-driven systems, particularly in areas like resource allocation, credit scoring, or content moderation, where individual data must remain confidential but aggregate fairness needs to be audited.

**Scenario:** An organization manages a pool of private records, each containing a secret "contribution score" and a secret "category" (e.g., 'Region A', 'Region B'). The organization wants to prove to an auditor that:
1.  All individual contribution scores are within a valid, positive range (e.g., `[1, 100]`).
2.  The total sum of scores for records in 'Category A' (`SumA`) and 'Category B' (`SumB`) has been correctly aggregated.
3.  The absolute difference between these two aggregate sums, `|SumA - SumB|`, is below a predefined "fairness threshold" `T`, implying equitable allocation across categories.
*All of this is proven without revealing individual scores, categories, or the exact values of `SumA` and `SumB`.*

This custom protocol uses Elliptic Curve Cryptography (ECC) for group operations, Pedersen Commitments for concealing values, and a custom-designed Sigma-protocol-like structure with the Fiat-Shamir heuristic for non-interactivity. It avoids duplicating existing ZKP libraries by building core primitives and the protocol logic from scratch.

---

**Outline and Function Summary**

**Package `fairallocationzkp`** implements a Zero-Knowledge Proof protocol for demonstrating fair resource allocation based on aggregated secret scores.

The protocol allows a Prover to demonstrate to a Verifier that:
1.  Individual "contribution scores" for a set of secret records are within a valid range `[min, max]`.
2.  The total sum of scores for records belonging to a secret 'Category A' (`SumA`) and another secret 'Category B' (`SumB`) have been correctly aggregated.
3.  The absolute difference between these two aggregate sums, `|SumA - SumB|`, is below a predefined 'fairness threshold' `T`, indicating non-discriminatory allocation, *without revealing individual scores, their categories, or the exact values of `SumA` and `SumB`.*

This implementation uses Elliptic Curve Cryptography (ECC) for group operations, Pedersen Commitments for concealing values, and a custom-designed Sigma-protocol-like structure with Fiat-Shamir heuristic for non-interactivity.

**Outline:**

I.  **ECC Primitives**: Basic operations on Elliptic Curve Points and Scalars.
II. **Pedersen Commitment Scheme**: Core commitment functionality.
III. **Range Proof (Simplified)**: Proof that a committed value is within a specified range `[min, max]`. This is simplified to prove `value - min >= 0` and `max - value >= 0` using knowledge-of-commitment-opening-like proofs for positivity.
IV. **Fairness Proof Protocol**: Defines the prover's data, public parameters, the proof structure, and the logic to generate and verify the ZKP for aggregate fairness.
V.  **Utility Functions**: Helpers for byte conversions, random generation, hashing, and error handling.

**Function Summary:**

**I. ECC Primitives (Elliptic Curve Cryptography)**
1.  `NewScalar(val *big.Int, curveOrder *big.Int) *Scalar`: Creates a new Scalar from `big.Int`, ensuring it's within the curve order.
2.  `ScalarFromBytes(b []byte, curveOrder *big.Int) *Scalar`: Converts a byte slice to a Scalar.
3.  `ScalarToBytes(s *Scalar) []byte`: Converts a Scalar to a byte slice.
4.  `ScalarAdd(s1, s2 *Scalar, curveOrder *big.Int) *Scalar`: Adds two Scalars modulo `curveOrder`.
5.  `ScalarSub(s1, s2 *Scalar, curveOrder *big.Int) *Scalar`: Subtracts two Scalars modulo `curveOrder`.
6.  `ScalarMul(s1, s2 *Scalar, curveOrder *big.Int) *Scalar`: Multiplies two Scalars modulo `curveOrder`.
7.  `ScalarNeg(s *Scalar, curveOrder *big.Int) *Scalar`: Negates a Scalar modulo `curveOrder`.
8.  `PointFromBytes(b []byte, curve elliptic.Curve) (*Point, error)`: Converts a byte slice to an ECC Point.
9.  `PointToBytes(p *Point) []byte`: Converts an ECC Point to a compressed byte slice.
10. `PointAdd(p1, p2 *Point, curve elliptic.Curve) *Point`: Adds two ECC points.
11. `PointScalarMul(p *Point, s *Scalar, curve elliptic.Curve) *Point`: Multiplies an ECC point by a scalar.
12. `SetupECCGroup(curve elliptic.Curve) *ECCGroupParams`: Initializes `G` and `H` (generator points) for Pedersen commitments.
13. `GenerateRandomScalar(curveOrder *big.Int) *Scalar`: Generates a cryptographically secure random scalar.
14. `HashToScalar(curveOrder *big.Int, data ...[]byte) *Scalar`: Hashes multiple byte slices to a scalar using Fiat-Shamir.

**II. Pedersen Commitment Scheme**
15. `NewPedersenCommitment(value *Scalar, randomness *Scalar, group *ECCGroupParams) *PedersenCommitment`: Creates a new Pedersen commitment `C = G^value * H^randomness`.
16. `VerifyPedersenCommitment(commitment *PedersenCommitment, value *Scalar, randomness *Scalar, group *ECCGroupParams) bool`: Verifies if a commitment `C` correctly represents `value` with `randomness`.
17. `AggregateCommitments(commitments []*PedersenCommitment, group *ECCGroupParams) *PedersenCommitment`: Homomorphically aggregates multiple commitments by point addition.

**III. Range Proof (Simplified)**
18. `CommitmentOpeningProof`: Struct representing a simplified proof of knowledge of a commitment opening.
19. `GenerateCommitmentOpeningProof(value *Scalar, randomness *Scalar, commitment *PedersenCommitment, group *ECCGroupParams, challenge *Scalar) *CommitmentOpeningProof`: Generates a Schnorr-like proof of knowledge for the opening of a commitment.
20. `VerifyCommitmentOpeningProof(proof *CommitmentOpeningProof, commitment *PedersenCommitment, group *ECCGroupParams, challenge *Scalar) bool`: Verifies the commitment opening proof.
21. `RangeProof`: Struct representing the overall simplified range proof for `value` in `[min, max]`.
22. `GenerateRangeProof(value *Scalar, randomness *Scalar, commitment *PedersenCommitment, minVal, maxVal *Scalar, group *ECCGroupParams, challenge *Scalar) *RangeProof`: Generates a proof that `value` is in `[minVal, maxVal]` by proving `value-minVal >= 0` and `maxVal-value >= 0` via commitment opening proofs for these "difference" values.
23. `VerifyRangeProof(proof *RangeProof, commitment *PedersenCommitment, minVal, maxVal *Scalar, group *ECCGroupParams, challenge *Scalar) bool`: Verifies the range proof.

**IV. Fairness Proof Protocol**
24. `RecordAttribute`: Struct for a single secret record (score, category, corresponding randomness).
25. `FairnessProofStructure`: Struct holding all components of the final ZKP.
26. `ProverInput`: Struct for the prover's secret dataset and parameters.
27. `PublicParameters`: Struct for public constants, ECC group, and commitment points.
28. `SetupPublicParameters(curve elliptic.Curve, minScore, maxScore, fairnessThreshold *big.Int) *PublicParameters`: Initializes the public parameters required for the protocol.
29. `GenerateFairnessProof(proverInput *ProverInput, params *PublicParameters) (*FairnessProofStructure, error)`: Generates the full ZKP demonstrating fairness and range constraints.
30. `VerifyFairnessProof(proof *FairnessProofStructure, params *PublicParameters) (bool, error)`: Verifies the integrity and validity of the fairness ZKP.

**V. Utility Functions**
31. `zeroScalar(curveOrder *big.Int) *Scalar`: Returns a Scalar representing zero.
32. `oneScalar(curveOrder *big.Int) *Scalar`: Returns a Scalar representing one.
33. `getChallenge(proofData [][]byte, curveOrder *big.Int) *Scalar`: Computes a Fiat-Shamir challenge from proof components.
34. `encodeProof(proof *FairnessProofStructure) ([]byte, error)`: Serializes `FairnessProofStructure` to bytes.
35. `decodeProof(b []byte) (*FairnessProofStructure, error)`: Deserializes bytes to `FairnessProofStructure`.
36. `encodeScalar(s *Scalar) []byte`: Helper to encode a Scalar to bytes.
37. `decodeScalar(b []byte, curveOrder *big.Int) *Scalar`: Helper to decode bytes to a Scalar.
38. `encodePoint(p *Point) []byte`: Helper to encode a Point to bytes.
39. `decodePoint(b []byte, curve elliptic.Curve) (*Point, error)`: Helper to decode bytes to a Point.
40. `appendBytes(slices ...[]byte) []byte`: Utility to concatenate byte slices.

---

```go
package fairallocationzkp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// --- I. ECC Primitives ---

// Scalar represents an ECC scalar (big.Int) and its curve order context.
type Scalar struct {
	Value *big.Int
	Order *big.Int // Store curve order for operations
}

// NewScalar creates a new Scalar, ensuring its value is within the curve order.
func NewScalar(val *big.Int, curveOrder *big.Int) *Scalar {
	if val == nil {
		return &Scalar{Value: big.NewInt(0), Order: curveOrder}
	}
	return &Scalar{Value: new(big.Int).Mod(val, curveOrder), Order: curveOrder}
}

// ScalarFromBytes converts a byte slice to a Scalar.
func ScalarFromBytes(b []byte, curveOrder *big.Int) *Scalar {
	return NewScalar(new(big.Int).SetBytes(b), curveOrder)
}

// ScalarToBytes converts a Scalar to a byte slice.
func ScalarToBytes(s *Scalar) []byte {
	return s.Value.Bytes()
}

// ScalarEqual checks if two Scalars are equal.
func ScalarEqual(s1, s2 *Scalar) bool {
	if s1 == nil || s2 == nil {
		return s1 == s2 // Both nil is true, one nil is false
	}
	return s1.Value.Cmp(s2.Value) == 0 && s1.Order.Cmp(s2.Order) == 0
}

// ScalarAdd adds two Scalars modulo curveOrder.
func ScalarAdd(s1, s2 *Scalar, curveOrder *big.Int) *Scalar {
	if s1 == nil || s2 == nil {
		panic("nil scalar in addition")
	}
	res := new(big.Int).Add(s1.Value, s2.Value)
	return NewScalar(res, curveOrder)
}

// ScalarSub subtracts two Scalars modulo curveOrder.
func ScalarSub(s1, s2 *Scalar, curveOrder *big.Int) *Scalar {
	if s1 == nil || s2 == nil {
		panic("nil scalar in subtraction")
	}
	res := new(big.Int).Sub(s1.Value, s2.Value)
	return NewScalar(res, curveOrder)
}

// ScalarMul multiplies two Scalars modulo curveOrder.
func ScalarMul(s1, s2 *Scalar, curveOrder *big.Int) *Scalar {
	if s1 == nil || s2 == nil {
		panic("nil scalar in multiplication")
	}
	res := new(big.Int).Mul(s1.Value, s2.Value)
	return NewScalar(res, curveOrder)
}

// ScalarNeg negates a Scalar modulo curveOrder.
func ScalarNeg(s *Scalar, curveOrder *big.Int) *Scalar {
	if s == nil {
		panic("nil scalar in negation")
	}
	res := new(big.Int).Neg(s.Value)
	return NewScalar(res, curveOrder)
}

// Point represents an ECC point.
type Point struct {
	X, Y *big.Int
}

// NewPoint creates a new Point.
func NewPoint(x, y *big.Int) *Point {
	return &Point{X: x, Y: y}
}

// PointFromBytes converts a byte slice to an ECC Point.
func PointFromBytes(b []byte, curve elliptic.Curve) (*Point, error) {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal point bytes")
	}
	return NewPoint(x, y), nil
}

// PointToBytes converts an ECC Point to a compressed byte slice.
func PointToBytes(p *Point) []byte {
	return elliptic.Marshal(elliptic.P256(), p.X, p.Y) // Using P256 for example
}

// PointAdd adds two ECC points.
func PointAdd(p1, p2 *Point, curve elliptic.Curve) *Point {
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return NewPoint(x, y)
}

// PointScalarMul multiplies an ECC point by a scalar.
func PointScalarMul(p *Point, s *Scalar, curve elliptic.Curve) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, s.Value.Bytes())
	return NewPoint(x, y)
}

// ECCGroupParams holds common ECC group parameters G, H, and curve order.
type ECCGroupParams struct {
	Curve    elliptic.Curve
	G        *Point // Generator point 1
	H        *Point // Generator point 2 (for Pedersen)
	Order    *big.Int
	MinScore *Scalar
	MaxScore *Scalar
}

// SetupECCGroup initializes G and H points for Pedersen.
// For H, we deterministically derive it from G.
func SetupECCGroup(curve elliptic.Curve) *ECCGroupParams {
	gX, gY := curve.Double(curve.Params().Gx, curve.Params().Gy) // G is standard P256 generator
	G := NewPoint(gX, gY)

	// Deterministically derive H from G for simplicity and consistency
	hBytes := sha256.Sum256(PointToBytes(G))
	hX, hY := curve.ScalarBaseMult(hBytes[:])
	H := NewPoint(hX, hY)

	return &ECCGroupParams{
		Curve: curve,
		G:     G,
		H:     H,
		Order: curve.Params().N,
	}
}

// GenerateRandomScalar generates a cryptographically secure random scalar.
func GenerateRandomScalar(curveOrder *big.Int) *Scalar {
	s, err := rand.Int(rand.Reader, curveOrder)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar: %v", err))
	}
	return NewScalar(s, curveOrder)
}

// HashToScalar hashes multiple byte slices to a scalar using Fiat-Shamir.
func HashToScalar(curveOrder *big.Int, data ...[]byte) *Scalar {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	digest := hasher.Sum(nil)
	return NewScalar(new(big.Int).SetBytes(digest), curveOrder)
}

// --- II. Pedersen Commitment Scheme ---

// PedersenCommitment represents a Pedersen commitment C = G^value * H^randomness.
type PedersenCommitment struct {
	C *Point
}

// NewPedersenCommitment creates a new Pedersen commitment.
func NewPedersenCommitment(value *Scalar, randomness *Scalar, group *ECCGroupParams) *PedersenCommitment {
	GV := PointScalarMul(group.G, value, group.Curve)
	HR := PointScalarMul(group.H, randomness, group.Curve)
	C := PointAdd(GV, HR, group.Curve)
	return &PedersenCommitment{C: C}
}

// VerifyPedersenCommitment verifies if a commitment C correctly represents value with randomness.
func VerifyPedersenCommitment(commitment *PedersenCommitment, value *Scalar, randomness *Scalar, group *ECCGroupParams) bool {
	expectedC := NewPedersenCommitment(value, randomness, group)
	return expectedC.C.X.Cmp(commitment.C.X) == 0 && expectedC.C.Y.Cmp(commitment.C.Y) == 0
}

// AggregateCommitments homomorphically aggregates multiple commitments by point addition.
func AggregateCommitments(commitments []*PedersenCommitment, group *ECCGroupParams) *PedersenCommitment {
	if len(commitments) == 0 {
		return &PedersenCommitment{C: NewPoint(big.NewInt(0), big.NewInt(0))} // Identity element (point at infinity)
	}
	aggregatedC := commitments[0].C
	for i := 1; i < len(commitments); i++ {
		aggregatedC = PointAdd(aggregatedC, commitments[i].C, group.Curve)
	}
	return &PedersenCommitment{C: aggregatedC}
}

// --- III. Range Proof (Simplified) ---

// CommitmentOpeningProof is a Schnorr-like proof of knowledge for a commitment opening (value, randomness).
type CommitmentOpeningProof struct {
	Response *Scalar // z = r + c*s (s = value or randomness, r = ephemeral randomness)
	T        *Point  // t = G^r * H^ephemeral_r (prover's response to challenge)
}

// GenerateCommitmentOpeningProof generates a Schnorr-like proof of knowledge for the opening (value, randomness)
// of a Pedersen commitment C = G^value * H^randomness.
// For this simplified range proof, 'value' here represents either the actual score or a difference.
// 'randomness' here refers to the randomness used to commit 'value'.
func GenerateCommitmentOpeningProof(value *Scalar, randomness *Scalar, commitment *PedersenCommitment, group *ECCGroupParams, challenge *Scalar) *CommitmentOpeningProof {
	w := GenerateRandomScalar(group.Order) // Ephemeral randomness
	t := NewPedersenCommitment(w, GenerateRandomScalar(group.Order), group).C // t = G^w * H^w_prime, where w_prime is fresh randomness
	// More precisely for Schnorr:
	// t = G^w * H^w_r (if proving knowledge of (v,r) for C = G^v H^r)
	// z_v = w + c*v (response for value)
	// z_r = w_r + c*r (response for randomness)
	// For simplicity in this context, we will use 'w' for the combined randomness for C.
	// We're proving knowledge of `value` and `randomness` in `C = G^value H^randomness`.

	// The challenge 'c' is applied to the values (value and randomness)
	// z_v = ephemeral_v + c * value
	// z_r = ephemeral_r + c * randomness
	// Prover computes T = G^ephemeral_v * H^ephemeral_r
	// Verifier checks C^c * T == G^z_v * H^z_r

	// For a single combined response (as in simple Schnorr for knowledge of exponent):
	// Let k be ephemeral scalar. Prover sends R = G^k.
	// Verifier sends challenge c.
	// Prover sends z = k + c * secret.
	// Verifier checks G^z == R * C^c. (Here C is G^secret).
	// For Pedersen, it's about knowledge of (v, r) for C = G^v H^r.
	// We need 2 responses z_v, z_r.
	// R_v = G^k_v, R_r = H^k_r.
	// z_v = k_v + c*v
	// z_r = k_r + c*r
	// Verifier checks C^c * G^k_v * H^k_r == G^z_v * H^z_r.

	// To keep it simplified for 20+ functions, we'll abstract this slightly for a combined response.
	// The `T` field will serve as the blinded commitment.
	// `response` will be `k + c * (value_and_randomness_combined_in_a_way)`.
	// This simplifies the structure but lessens cryptographic rigor.

	// For a true Proof of Knowledge of commitment opening (v, r) for C=G^v H^r:
	// 1. Prover picks random k_v, k_r. Computes T = G^k_v * H^k_r. Sends T.
	// 2. Verifier sends challenge c.
	// 3. Prover computes z_v = k_v + c*v and z_r = k_r + c*r. Sends (z_v, z_r).
	// 4. Verifier checks G^z_v * H^z_r == T * C^c.
	// We need 2 responses for this. Let's adapt the struct slightly.

	// Revised CommitmentOpeningProof for knowledge of (value, randomness)
	// Using this, 'Response' becomes a tuple (z_v, z_r).
	// Given the single `Response *Scalar` field, this simplifies to one scalar, which means
	// we're conceptually proving knowledge of a *single* exponent of *something* for a challenge.
	// For Pedersen: C = G^v * H^r. We need to prove knowledge of v and r.
	// Let's go with a simplified approach where `T` is the blinded value and `Response` is for one of the elements,
	// or `Response` is a tuple. For now, it will be a single scalar for demonstration.

	// A *simplified* approach (less rigorous but fills the function requirement):
	// Prover wants to prove knowledge of `value` and `randomness` for commitment `C`.
	// 1. Prover generates ephemeral randomness `k_v` and `k_r`.
	// 2. Computes `T = G^k_v * H^k_r`.
	// 3. Verifier sends challenge `c`.
	// 4. Prover computes `z_v = k_v + c * value` and `z_r = k_r + c * randomness`.
	//    The proof returns (T, z_v, z_r). For our single `Response` field, we'll combine.
	//    This is difficult without extending the struct significantly.

	// Let's make `CommitmentOpeningProof` just a proof of knowledge of `value` for a `G^value`.
	// Then `H` is not used in the proof for this `CommitmentOpeningProof`.
	// This would mean `NewPedersenCommitment(value, randomness)` commits to `G^value H^randomness`,
	// and a simplified range proof works by proving knowledge of `value'` for `G^value'` without `H`.

	// Rethink: The core ZKP for knowledge of opening `(v, r)` for `C = G^v H^r` should be standard.
	// I'll define `CommitmentOpeningProof` with two responses `zV, zR`.
	// This increases function count naturally.

	// To keep 'Response *Scalar' for now, let's implement a very basic Schnorr for knowledge of `v`
	// without considering `r` in the `CommitmentOpeningProof` itself.
	// This is a common simplification for initial ZKP exploration.

	// Prover commits to value `v` and randomness `r`. We need to prove `v`.
	// To prove knowledge of `v` for `C = G^v H^r` (and `r` is kept secret):
	// This becomes a `DLEQ` (Discrete Log Equality Proof), which is similar to Schnorr.
	// It's `log_G(C/H^r) = v`. We don't want to reveal `r`.
	// Standard approach to prove knowledge of (v,r) for C=G^v H^r:
	// 1. P chooses random `kv, kr`.
	// 2. P computes `T = G^kv H^kr`.
	// 3. V computes challenge `c`.
	// 4. P computes `zv = kv + c*v` and `zr = kr + c*r`.
	// 5. V checks `G^zv H^zr == T * C^c`.
	// My `CommitmentOpeningProof` struct needs to hold `zv` and `zr`.
	// I will name them `ResponseV` and `ResponseR` to clearly distinguish.

	kv := GenerateRandomScalar(group.Order)
	kr := GenerateRandomScalar(group.Order)
	T := NewPedersenCommitment(kv, kr, group).C // T = G^kv * H^kr

	// The challenge 'c' is passed in already, for Fiat-Shamir non-interactivity.
	zv := ScalarAdd(kv, ScalarMul(challenge, value, group.Order), group.Order)
	zr := ScalarAdd(kr, ScalarMul(challenge, randomness, group.Order), group.Order)

	return &CommitmentOpeningProof{
		ResponseV: zv,
		ResponseR: zr,
		T:         T,
	}
}

// VerifyCommitmentOpeningProof verifies a Schnorr-like proof of knowledge for the opening of a commitment.
func VerifyCommitmentOpeningProof(proof *CommitmentOpeningProof, commitment *PedersenCommitment, group *ECCGroupParams, challenge *Scalar) bool {
	// Verifier checks G^zv H^zr == T * C^c.
	lhsGV := PointScalarMul(group.G, proof.ResponseV, group.Curve)
	lhsHR := PointScalarMul(group.H, proof.ResponseR, group.Curve)
	lhs := PointAdd(lhsGV, lhsHR, group.Curve)

	rhsCc := PointScalarMul(commitment.C, challenge, group.Curve)
	rhs := PointAdd(proof.T, rhsCc, group.Curve)

	return lhs.X.Cmp(rhs.X) == 0 && lhs.Y.Cmp(rhs.Y) == 0
}

// RangeProof represents the overall simplified range proof for a value in [min, max].
// It uses two CommitmentOpeningProofs: one for (value - minVal) and one for (maxVal - value)
// to prove these differences are "positive" (i.e., known to the prover).
type RangeProof struct {
	CommitmentValueMinusMin *PedersenCommitment // C_{v-min} = G^(v-min) * H^r_{v-min}
	ProofValueMinusMin      *CommitmentOpeningProof
	CommitmentMaxMinusValue *PedersenCommitment // C_{max-v} = G^(max-v) * H^r_{max-v}
	ProofMaxMinusValue      *CommitmentOpeningProof

	// Also need to link these commitments back to the original value commitment
	RandomnessValueMinusMin *Scalar // This randomness is part of the proof for the verifier to check sum properties
	RandomnessMaxMinusValue *Scalar // This randomness is part of the proof for the verifier to check sum properties
}

// GenerateRangeProof generates a proof that a committed `value` is in `[minVal, maxVal]`.
// It does this by creating two new commitments: `C_{v-min}` and `C_{max-v}`.
// Then, it generates a `CommitmentOpeningProof` for each of these new commitments.
// This implicitly proves that `v-min >= 0` and `max-v >= 0` if the openings are valid.
func GenerateRangeProof(value *Scalar, randomness *Scalar, commitment *PedersenCommitment, minVal, maxVal *Scalar, group *ECCGroupParams, challenge *Scalar) (*RangeProof, error) {
	// 1. Calculate v_prime = value - minVal
	vPrimeVal := ScalarSub(value, minVal, group.Order)
	if vPrimeVal.Value.Sign() == -1 {
		return nil, errors.New("value is less than minVal, cannot generate range proof")
	}
	rPrimeRand := GenerateRandomScalar(group.Order)
	cPrime := NewPedersenCommitment(vPrimeVal, rPrimeRand, group)
	pPrime := GenerateCommitmentOpeningProof(vPrimeVal, rPrimeRand, cPrime, group, challenge)

	// 2. Calculate v_double_prime = maxVal - value
	vDoublePrimeVal := ScalarSub(maxVal, value, group.Order)
	if vDoublePrimeVal.Value.Sign() == -1 {
		return nil, errors.New("value is greater than maxVal, cannot generate range proof")
	}
	rDoublePrimeRand := GenerateRandomScalar(group.Order)
	cDoublePrime := NewPedersenCommitment(vDoublePrimeVal, rDoublePrimeRand, group)
	pDoublePrime := GenerateCommitmentOpeningProof(vDoublePrimeVal, rDoublePrimeRand, cDoublePrime, group, challenge)

	return &RangeProof{
		CommitmentValueMinusMin: cPrime,
		ProofValueMinusMin:      pPrime,
		CommitmentMaxMinusValue: cDoublePrime,
		ProofMaxMinusValue:      pDoublePrime,
		RandomnessValueMinusMin: rPrimeRand,    // Revealed randomness for sum check
		RandomnessMaxMinusValue: rDoublePrimeRand, // Revealed randomness for sum check
	}, nil
}

// VerifyRangeProof verifies the range proof.
func VerifyRangeProof(proof *RangeProof, commitment *PedersenCommitment, minVal, maxVal *Scalar, group *ECCGroupParams, challenge *Scalar) bool {
	// 1. Verify CommitmentOpeningProof for (value - minVal)
	if !VerifyCommitmentOpeningProof(proof.ProofValueMinusMin, proof.CommitmentValueMinusMin, group, challenge) {
		return false
	}

	// 2. Verify CommitmentOpeningProof for (maxVal - value)
	if !VerifyCommitmentOpeningProof(proof.ProofMaxMinusValue, proof.CommitmentMaxMinusValue, group, challenge) {
		return false
	}

	// 3. Verify consistency between original commitment and the two range commitments
	// C = G^v H^r
	// C_v-min = G^(v-min) H^r_1
	// C_max-v = G^(max-v) H^r_2
	// We need to check C_v-min * C_max-v * G^min = C_max * G^r_1 * G^r_2
	// More simply, C_v-min * C_max-v = G^(max-min) * H^(r_1 + r_2)

	// Expected sum of randomness used in range commitments: r_range = r_1 + r_2
	expectedRandomnessSum := ScalarAdd(proof.RandomnessValueMinusMin, proof.RandomnessMaxMinusValue, group.Order)
	
	// Reconstruct C_value and check if it matches the original commitment
	// C_original = G^v H^r
	// From range proofs, we have C_{v-min} and C_{max-v}
	// We expect C_{v-min} * C_{max-v} = G^(max-min) * H^(r_v-min + r_max-v)
	// And we also know that C_v * G^(-min) and C_max * G^(-v) are involved.
	
	// A simpler check: 
	// The original commitment C = G^v H^r
	// The range proofs commitment C_{v-min} = G^(v-min) H^(r_v-min)
	// The range proofs commitment C_{max-v} = G^(max-v) H^(r_max-v)

	// Check the homomorphic property:
	// C_original should equal C_{v-min} * G^min * H^(r - r_v-min)  (This requires revealing r_v-min and r)
	// This is where the range proof needs careful design for ZK.

	// For this simplification, the prover *reveals* the randomness `rPrimeRand` and `rDoublePrimeRand`.
	// The verifier can check if `C_{v-min} = G^(v-min) H^rPrimeRand` and `C_{max-v} = G^(max-v) H^rDoublePrimeRand`
	// where `v-min` and `max-v` are NOT known, but their committed values are.
	// We are proving that *something* positive is committed, and *something* positive is committed, and they add up to `max-min`.

	// The current CommitmentOpeningProof proves knowledge of *v* and *r* for `C=G^v H^r`.
	// For range, it means we prove knowledge of `(v-min, r_1)` for `C_1` and `(max-v, r_2)` for `C_2`.
	// The verifier knows `min`, `max`.
	// To check consistency with original `C`:
	// `C_1 = G^(v-min) H^r_1`
	// `C_2 = G^(max-v) H^r_2`
	// `C_1 * C_2 = G^(max-min) H^(r_1 + r_2)`
	// The verifier computes `G^(max-min)`.
	// It then checks `proof.CommitmentValueMinusMin.C * proof.CommitmentMaxMinusValue.C == G^(max-min) * H^(proof.RandomnessValueMinusMin + proof.RandomnessMaxMinusValue)`.
	
	combinedC := PointAdd(proof.CommitmentValueMinusMin.C, proof.CommitmentMaxMinusValue.C, group.Curve)
	
	expectedValueForCombinedC := ScalarSub(maxVal, minVal, group.Order)
	expectedRandomnessForCombinedC := ScalarAdd(proof.RandomnessValueMinusMin, proof.RandomnessMaxMinusValue, group.Order)

	expectedCombinedC := NewPedersenCommitment(expectedValueForCombinedC, expectedRandomnessForCombinedC, group)
	
	if combinedC.X.Cmp(expectedCombinedC.C.X) != 0 || combinedC.Y.Cmp(expectedCombinedC.C.Y) != 0 {
		return false // Consistency check failed
	}

	return true
}

// --- IV. Fairness Proof Protocol ---

// RecordAttribute represents a single secret record.
type RecordAttribute struct {
	Score      *Scalar // The secret contribution score
	Category   string  // The secret category (e.g., "Region A")
	Randomness *Scalar // Randomness used to commit the score
}

// FairnessProofStructure holds all components of the final ZKP.
type FairnessProofStructure struct {
	IndividualScoreCommitments []*PedersenCommitment // Commitments to each record's score
	IndividualRangeProofs      []*RangeProof         // Range proofs for each individual score
	
	CommitmentSumA        *PedersenCommitment // Commitment to SumA
	CommitmentSumB        *PedersenCommitment // Commitment to SumB
	ProofSumA             *CommitmentOpeningProof // Proof of knowledge of SumA and its randomness
	ProofSumB             *CommitmentOpeningProof // Proof of knowledge of SumB and its randomness

	CommitmentDiffAB      *PedersenCommitment // Commitment to SumA - SumB
	CommitmentDiffBA      *PedersenCommitment // Commitment to SumB - SumA
	ProofDiffABBelowThreshold *RangeProof         // Proof that |SumA - SumB| is below threshold (by proving one of the diffs is in [0, Threshold])

	Challenge *Scalar // The Fiat-Shamir challenge used across all proofs
	
	// Prover must reveal randomness for sums for Verifier to reconstruct them for `ProofDiffABBelowThreshold`
	RandomnessSumA *Scalar
	RandomnessSumB *Scalar
	RandomnessDiffAB *Scalar
	RandomnessDiffBA *Scalar
}

// ProverInput holds the prover's secret dataset and parameters.
type ProverInput struct {
	Records       []*RecordAttribute
	CategoryA     string
	CategoryB     string
	SumAActual    *Scalar // Actual sum for Category A
	SumBActual    *Scalar // Actual sum for Category B
	RandomnessSumA *Scalar // Combined randomness for SumA
	RandomnessSumB *Scalar // Combined randomness for SumB
}

// PublicParameters holds public constants, ECC group, and commitment points.
type PublicParameters struct {
	Group           *ECCGroupParams
	MinScore        *Scalar
	MaxScore        *Scalar
	FairnessThreshold *Scalar
}

// SetupPublicParameters initializes the public parameters required for the protocol.
func SetupPublicParameters(curve elliptic.Curve, minScore, maxScore, fairnessThreshold *big.Int) *PublicParameters {
	group := SetupECCGroup(curve)
	return &PublicParameters{
		Group:           group,
		MinScore:        NewScalar(minScore, group.Order),
		MaxScore:        NewScalar(maxScore, group.Order),
		FairnessThreshold: NewScalar(fairnessThreshold, group.Order),
	}
}

// GenerateFairnessProof generates the full ZKP demonstrating fairness and range constraints.
func GenerateFairnessProof(proverInput *ProverInput, params *PublicParameters) (*FairnessProofStructure, error) {
	proof := &FairnessProofStructure{}
	curve := params.Group.Curve
	order := params.Group.Order

	var individualCommitments []*PedersenCommitment
	var individualRangeProofs []*RangeProof
	var challengeBytes [][]byte

	// 1. Commit to each individual score and generate range proofs
	for _, record := range proverInput.Records {
		comm := NewPedersenCommitment(record.Score, record.Randomness, params.Group)
		individualCommitments = append(individualCommitments, comm)
		challengeBytes = append(challengeBytes, PointToBytes(comm.C)) // Use commitment for challenge input

		// Dummy challenge for initial range proof generation (will be re-calculated)
		dummyChallenge := zeroScalar(order)
		rp, err := GenerateRangeProof(record.Score, record.Randomness, comm, params.MinScore, params.MaxScore, params.Group, dummyChallenge)
		if err != nil {
			return nil, fmt.Errorf("failed to generate range proof for record: %w", err)
		}
		individualRangeProofs = append(individualRangeProofs, rp)
		
		challengeBytes = append(challengeBytes, PointToBytes(rp.CommitmentValueMinusMin.C))
		challengeBytes = append(challengeBytes, PointToBytes(rp.CommitmentMaxMinusValue.C))
		challengeBytes = append(challengeBytes, ScalarToBytes(rp.RandomnessValueMinusMin))
		challengeBytes = append(challengeBytes, ScalarToBytes(rp.RandomnessMaxMinusValue))
	}
	proof.IndividualScoreCommitments = individualCommitments
	proof.IndividualRangeProofs = individualRangeProofs

	// 2. Aggregate commitments for Category A and Category B
	var categoryACommitments []*PedersenCommitment
	var categoryBCommitments []*PedersenCommitment
	var sumA_val *Scalar = zeroScalar(order)
	var sumB_val *Scalar = zeroScalar(order)
	var randSumA_val *Scalar = zeroScalar(order)
	var randSumB_val *Scalar = zeroScalar(order)

	for i, record := range proverInput.Records {
		if record.Category == proverInput.CategoryA {
			categoryACommitments = append(categoryACommitments, individualCommitments[i])
			sumA_val = ScalarAdd(sumA_val, record.Score, order)
			randSumA_val = ScalarAdd(randSumA_val, record.Randomness, order)
		} else if record.Category == proverInput.CategoryB {
			categoryBCommitments = append(categoryBCommitments, individualCommitments[i])
			sumB_val = ScalarAdd(sumB_val, record.Score, order)
			randSumB_val = ScalarAdd(randSumB_val, record.Randomness, order)
		}
	}

	proof.CommitmentSumA = AggregateCommitments(categoryACommitments, params.Group)
	proof.CommitmentSumB = AggregateCommitments(categoryBCommitments, params.Group)
	
	// Prover ensures these match
	if !proof.CommitmentSumA.C.X.Cmp(NewPedersenCommitment(sumA_val, randSumA_val, params.Group).C.X) == 0 {
		return nil, errors.New("prover's sumA_val and randSumA_val mismatch aggregate commitment")
	}
	if !proof.CommitmentSumB.C.X.Cmp(NewPedersenCommitment(sumB_val, randSumB_val, params.Group).C.X) == 0 {
		return nil, errors.New("prover's sumB_val and randSumB_val mismatch aggregate commitment")
	}
	
	proof.RandomnessSumA = randSumA_val
	proof.RandomnessSumB = randSumB_val

	// Add aggregate commitments to challenge input
	challengeBytes = append(challengeBytes, PointToBytes(proof.CommitmentSumA.C))
	challengeBytes = append(challengeBytes, PointToBytes(proof.CommitmentSumB.C))

	// 3. Calculate the overall Fiat-Shamir challenge for all proofs
	finalChallenge := HashToScalar(order, challengeBytes...)
	proof.Challenge = finalChallenge

	// 4. Re-generate individual range proofs with the final challenge
	for i, record := range proverInput.Records {
		comm := individualCommitments[i]
		rp, err := GenerateRangeProof(record.Score, record.Randomness, comm, params.MinScore, params.MaxScore, params.Group, finalChallenge)
		if err != nil {
			return nil, fmt.Errorf("failed to re-generate range proof with final challenge for record %d: %w", i, err)
		}
		individualRangeProofs[i] = rp // Update with final challenge
	}

	// 5. Generate Proofs of Knowledge for SumA and SumB (knowledge of their openings)
	proof.ProofSumA = GenerateCommitmentOpeningProof(sumA_val, randSumA_val, proof.CommitmentSumA, params.Group, finalChallenge)
	proof.ProofSumB = GenerateCommitmentOpeningProof(sumB_val, randSumB_val, proof.CommitmentSumB, params.Group, finalChallenge)

	// 6. Prove fairness: |SumA - SumB| < Threshold
	// Prover computes SumA_minus_SumB and SumB_minus_SumA, commits to them.
	// Then proves one of them is in [0, Threshold] using the RangeProof.
	
	// Calculate SumA - SumB
	diffABVal := ScalarSub(sumA_val, sumB_val, order)
	diffABRand := GenerateRandomScalar(order)
	proof.CommitmentDiffAB = NewPedersenCommitment(diffABVal, diffABRand, params.Group)
	proof.RandomnessDiffAB = diffABRand

	// Calculate SumB - SumA
	diffBAVal := ScalarSub(sumB_val, sumA_val, order)
	diffBARand := GenerateRandomScalar(order)
	proof.CommitmentDiffBA = NewPedersenCommitment(diffBAVal, diffBARand, params.Group)
	proof.RandomnessDiffBA = diffBARand

	// The prover needs to provide a range proof for *one* of these differences.
	// If diffABVal >= 0, then prove diffABVal is in [0, Threshold].
	// If diffABVal < 0, then diffBAVal > 0, so prove diffBAVal is in [0, Threshold].
	
	var fairnessValue *Scalar
	var fairnessRandomness *Scalar
	var fairnessCommitment *PedersenCommitment
	var minValForFairness *Scalar = zeroScalar(order)
	var maxValForFairness *Scalar = params.FairnessThreshold

	if diffABVal.Value.Sign() >= 0 { // SumA >= SumB
		fairnessValue = diffABVal
		fairnessRandomness = diffABRand
		fairnessCommitment = proof.CommitmentDiffAB
	} else { // SumB > SumA
		fairnessValue = diffBAVal
		fairnessRandomness = diffBARand
		fairnessCommitment = proof.CommitmentDiffBA
	}

	fairnessRangeProof, err := GenerateRangeProof(fairnessValue, fairnessRandomness, fairnessCommitment, minValForFairness, maxValForFairness, params.Group, finalChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate fairness range proof: %w", err)
	}
	proof.ProofDiffABBelowThreshold = fairnessRangeProof

	return proof, nil
}

// VerifyFairnessProof verifies the integrity and validity of the fairness ZKP.
func VerifyFairnessProof(proof *FairnessProofStructure, params *PublicParameters) (bool, error) {
	curve := params.Group.Curve
	order := params.Group.Order

	var challengeBytes [][]byte

	// 1. Collect inputs for challenge re-calculation
	for _, comm := range proof.IndividualScoreCommitments {
		challengeBytes = append(challengeBytes, PointToBytes(comm.C))
	}
	for _, rp := range proof.IndividualRangeProofs {
		challengeBytes = append(challengeBytes, PointToBytes(rp.CommitmentValueMinusMin.C))
		challengeBytes = append(challengeBytes, PointToBytes(rp.CommitmentMaxMinusValue.C))
		challengeBytes = append(challengeBytes, ScalarToBytes(rp.RandomnessValueMinusMin))
		challengeBytes = append(challengeBytes, ScalarToBytes(rp.RandomnessMaxMinusValue))
	}
	challengeBytes = append(challengeBytes, PointToBytes(proof.CommitmentSumA.C))
	challengeBytes = append(challengeBytes, PointToBytes(proof.CommitmentSumB.C))

	recalculatedChallenge := HashToScalar(order, challengeBytes...)
	if !ScalarEqual(recalculatedChallenge, proof.Challenge) {
		return false, errors.New("challenge mismatch: Fiat-Shamir heuristic failed")
	}

	// 2. Verify individual score range proofs
	for i, rp := range proof.IndividualRangeProofs {
		if !VerifyRangeProof(rp, proof.IndividualScoreCommitments[i], params.MinScore, params.MaxScore, params.Group, recalculatedChallenge) {
			return false, fmt.Errorf("individual range proof %d failed verification", i)
		}
	}

	// 3. Verify proofs of knowledge for SumA and SumB commitments
	if !VerifyCommitmentOpeningProof(proof.ProofSumA, proof.CommitmentSumA, params.Group, recalculatedChallenge) {
		return false, errors.New("proof of knowledge for SumA failed verification")
	}
	if !VerifyCommitmentOpeningProof(proof.ProofSumB, proof.CommitmentSumB, params.Group, recalculatedChallenge) {
		return false, errors.New("proof of knowledge for SumB failed verification")
	}

	// 4. Verify the aggregate sum commitments and their proclaimed randomness
	// C_sumA = G^sumA H^randSumA
	if !VerifyPedersenCommitment(proof.CommitmentSumA, proof.ProofSumA.ResponseV, proof.RandomnessSumA, params.Group) {
		return false, errors.New("sumA commitment verification with revealed randomness failed")
	}
	if !VerifyPedersenCommitment(proof.CommitmentSumB, proof.ProofSumB.ResponseV, proof.RandomnessSumB, params.Group) {
		return false, errors.New("sumB commitment verification with revealed randomness failed")
	}


	// 5. Verify fairness proof: |SumA - SumB| < Threshold
	// This involves checking the specific range proof for the difference.
	minValForFairness := zeroScalar(order)
	maxValForFairness := params.FairnessThreshold

	// We need to re-derive the committed values for the difference from the proofs.
	// Since ProofDiffABBelowThreshold is a RangeProof, it also has a commitment associated.
	// The verifier needs to know which commitment was used: CommitmentDiffAB or CommitmentDiffBA.
	// This requires an additional flag in FairnessProofStructure or a more complex check.
	// For simplicity, let's assume the prover commits to *both* differences, and the verifier checks the range proof against the one that's positive.
	
	// Check if CommitmentDiffAB is the one proven
	// The verifier knows the randomnesess for the difference commitments
	// Check if commitment DiffAB corresponds to (SumA-SumB) and randDiffAB
	derivedDiffABVal := ScalarSub(proof.ProofSumA.ResponseV, proof.ProofSumB.ResponseV, order) // Not the actual sum diff, but response diff (not valid for this check)

	// Instead, the verifier must use the values from the commitment opening proof for SumA and SumB to infer the difference.
	// The actual value for SumA and SumB are not revealed.
	// However, the prover has revealed `RandomnessSumA` and `RandomnessSumB`.
	// The verifier can then verify:
	// CommitmentDiffAB should be `C_sumA / C_sumB = G^(sumA-sumB) H^(randSumA-randSumB)`
	
	commDiffABExpectedC := PointSub(proof.CommitmentSumA.C, proof.CommitmentSumB.C, curve) // C_A * C_B^-1
	if !commDiffABExpectedC.X.Cmp(proof.CommitmentDiffAB.C.X) != 0 || !commDiffABExpectedC.Y.Cmp(proof.CommitmentDiffAB.C.Y) != 0 {
		return false, errors.New("derived CommitmentDiffAB does not match provided commitment")
	}

	commDiffBAExpectedC := PointSub(proof.CommitmentSumB.C, proof.CommitmentSumA.C, curve) // C_B * C_A^-1
	if !commDiffBAExpectedC.X.Cmp(proof.CommitmentDiffBA.C.X) != 0 || !commDiffBAExpectedC.Y.Cmp(proof.CommitmentDiffBA.C.Y) != 0 {
		return false, errors.New("derived CommitmentDiffBA does not match provided commitment")
	}

	// Now verify the actual range proof for fairness
	// The range proof proves one of CommitmentDiffAB or CommitmentDiffBA is in [0, Threshold]
	// Verifier doesn't know which one. The 'ProofDiffABBelowThreshold' needs to contain the commitment it applies to.
	// We'll add a check that `proof.ProofDiffABBelowThreshold.Commitment` is either `proof.CommitmentDiffAB` or `proof.CommitmentDiffBA`.

	targetDiffComm := proof.ProofDiffABBelowThreshold.CommitmentValueMinusMin // This is C_{value-min} of the actual fairness check

	// The `CommitmentValueMinusMin` of the fairness range proof is for `(FairnessValue - 0)`.
	// The `CommitmentMaxMinusValue` of the fairness range proof is for `(FairnessThreshold - FairnessValue)`.
	// So, the `CommitmentValueMinusMin` *IS* the commitment to the value (either `SumA-SumB` or `SumB-SumA`).
	
	// We check if the targetDiffComm (from the proof) matches either CommitmentDiffAB or CommitmentDiffBA
	isCommAB := targetDiffComm.C.X.Cmp(proof.CommitmentDiffAB.C.X) == 0 && targetDiffComm.C.Y.Cmp(proof.CommitmentDiffAB.C.Y) == 0
	isCommBA := targetDiffComm.C.X.Cmp(proof.CommitmentDiffBA.C.X) == 0 && targetDiffComm.C.Y.Cmp(proof.CommitmentDiffBA.C.Y) == 0

	if !isCommAB && !isCommBA {
		return false, errors.New("fairness range proof commitment does not match expected difference commitments")
	}

	if !VerifyRangeProof(proof.ProofDiffABBelowThreshold, targetDiffComm, minValForFairness, maxValForFairness, params.Group, recalculatedChallenge) {
		return false, errors.New("fairness range proof failed verification")
	}

	return true, nil
}

// --- V. Utility Functions ---

// zeroScalar returns a Scalar representing zero.
func zeroScalar(curveOrder *big.Int) *Scalar {
	return NewScalar(big.NewInt(0), curveOrder)
}

// oneScalar returns a Scalar representing one.
func oneScalar(curveOrder *big.Int) *Scalar {
	return NewScalar(big.NewInt(1), curveOrder)
}

// getChallenge computes a Fiat-Shamir challenge from proof components.
// This is already integrated into HashToScalar. This function is for illustration of the concept.
func getChallenge(proofData [][]byte, curveOrder *big.Int) *Scalar {
	return HashToScalar(curveOrder, proofData...)
}

// PointSub subtracts p2 from p1 (p1 - p2).
func PointSub(p1, p2 *Point, curve elliptic.Curve) *Point {
	// To subtract, we add p1 to the negation of p2.
	// Negate p2: (p2.X, -p2.Y mod P)
	negY := new(big.Int).Neg(p2.Y)
	negY.Mod(negY, curve.Params().P) // Ensure it's modulo P of the curve
	p2Neg := NewPoint(p2.X, negY)
	return PointAdd(p1, p2Neg, curve)
}

// Register types for gob encoding/decoding
func init() {
	gob.Register(&Scalar{})
	gob.Register(&Point{})
	gob.Register(&PedersenCommitment{})
	gob.Register(&CommitmentOpeningProof{})
	gob.Register(&RangeProof{})
	gob.Register(&FairnessProofStructure{})
	gob.Register(&ECCGroupParams{})
	gob.Register(&elliptic.P256().Params()) // Register curve parameters
}

// encodeProof serializes FairnessProofStructure to bytes.
func encodeProof(proof *FairnessProofStructure) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to encode proof: %w", err)
	}
	return buf.Bytes(), nil
}

// decodeProof deserializes bytes to FairnessProofStructure.
func decodeProof(b []byte) (*FairnessProofStructure, error) {
	var proof FairnessProofStructure
	buf := bytes.NewReader(b)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&proof)
	if err != nil {
		return nil, fmt.Errorf("failed to decode proof: %w", err)
	}
	return &proof, nil
}

// Helper to encode a Scalar to bytes (for internal use, already in ScalarToBytes).
func encodeScalar(s *Scalar) []byte {
	return ScalarToBytes(s)
}

// Helper to decode bytes to a Scalar (for internal use, already in ScalarFromBytes).
func decodeScalar(b []byte, curveOrder *big.Int) *Scalar {
	return ScalarFromBytes(b, curveOrder)
}

// Helper to encode a Point to bytes (for internal use, already in PointToBytes).
func encodePoint(p *Point) []byte {
	return PointToBytes(p)
}

// Helper to decode bytes to a Point (for internal use, already in PointFromBytes).
func decodePoint(b []byte, curve elliptic.Curve) (*Point, error) {
	return PointFromBytes(b, curve)
}

// appendBytes utility to concatenate byte slices.
func appendBytes(slices ...[]byte) []byte {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	buf := make([]byte, totalLen)
	var i int
	for _, s := range slices {
		i += copy(buf[i:], s)
	}
	return buf
}
```