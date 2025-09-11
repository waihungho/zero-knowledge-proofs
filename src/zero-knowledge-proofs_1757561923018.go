The following Golang code implements a custom Zero-Knowledge Proof (ZKP) system for "Collective Feature Agreement & Threshold Compliance." This ZKP allows a group of provers to collaboratively prove two aggregate properties about their private data without revealing individual contributions.

**Outline:**

This package provides a custom Zero-Knowledge Proof (ZKP) system designed to prove two aggregate properties over privately held data attributes from a group of "N" provers, without revealing individual data or even the exact "N".

The specific scenario proven is:
1.  **Collective Feature Agreement Threshold**: At least 'T' provers among the group possess a specific (private) binary feature 'a_kj' set to '1'.
2.  **Aggregate Sum Threshold**: The total sum of another specific (private) numerical feature 'a_ks' across *all* provers in the group is greater than or equal to 'S_total'.

The ZKP relies on:
*   **Pedersen Commitments**: For hiding individual and aggregated values.
*   **Homomorphic Properties**: Of commitments for secure aggregation.
*   **Custom Bit-Decomposition Range Proof**: To demonstrate that aggregated values meet non-negative thresholds, and individual bits are valid.
*   **Custom Disjunctive Zero-Knowledge Proof**: For proving that a committed value is either 0 or 1 (i.e., a valid bit).
*   **Fiat-Shamir Heuristic**: For converting interactive proofs into non-interactive ones.

This implementation avoids common ZKP libraries to provide a novel, custom approach for this specific problem, emphasizing privacy-preserving consensus and aggregation in multi-party scenarios.

**Function Summary:**

**I. Core Cryptographic Primitives (ECC, Commitments, Hashes)**
*   `SetupCurve()`: Initializes the elliptic curve (P256) and common reference string (G, H points). `G` is the standard generator, `H` is a deterministically derived independent generator.
*   `GenerateRandomScalar(curve elliptic.Curve)`: Generates a cryptographically secure random scalar within the curve's order.
*   `Commit(value, randomness, config *ZKPConfig)`: Creates a Pedersen commitment `C = value*G + randomness*H`.
*   `VerifyCommitment(commitment, value, randomness, config *ZKPConfig)`: Verifies a Pedersen commitment against a known value and randomness.
*   `AggregateCommitments(commitments []*elliptic.Point, config *ZKPConfig)`: Homomorphically combines multiple commitments by point addition: `C_total = sum(C_i)`.
*   `AggregateBlindingFactors(factors []*big.Int, config *ZKPConfig)`: Sums multiple blinding factors modulo the curve order: `R_total = sum(r_i)`.
*   `GenerateChallenge(proofData ...[]byte)`: Computes a Fiat-Shamir challenge by hashing concatenated proof components, then converting to a scalar modulo the curve order.

**II. ZKP Building Blocks (Schnorr-like proofs for knowledge of value, linear combinations)**
*   `SchnorrProofV2`: Struct to hold components of a Schnorr-like proof for knowledge of `(value, randomness)` in `Commit(value, randomness)`.
*   `ProveKnowledgeOfValue(value, randomness *big.Int, com *elliptic.Point, config *ZKPConfig)`: Generates a Schnorr-like proof that the prover knows `(value, randomness)` for a given commitment `com`.
*   `VerifyKnowledgeOfValue(com *elliptic.Point, proof *SchnorrProofV2, config *ZKPConfig)`: Verifies the knowledge-of-value proof.
*   `LinearCombinationProof`: Struct for a proof that a target commitment is a linear combination of other commitments.
*   `ProveLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int, targetRandomness *big.Int, componentRandomness []*big.Int, config *ZKPConfig)`: Proves that `targetCom` is the correct linear combination `sum(coeff_i * component_i)` by showing `targetCom - sum(coeff_i * component_i) = Com(0, randomness_difference)`.
*   `VerifyLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int, proof *LinearCombinationProof, config *ZKPConfig)`: Verifies the linear combination proof.

**III. Range Proof (Bit Decomposition for Non-Negativity and Bit Validity)**
*   `DecomposeToBits(value *big.Int, numBits int)`: Decomposes a `big.Int` into its binary representation (slice of 0s and 1s).
*   `DisjunctiveProof`: Struct for a disjunctive OR proof, specifically for proving a committed value is either 0 or 1.
*   `ProveBitIsZeroOrOne(bitVal, bitRand *big.Int, comBit *elliptic.Point, config *ZKPConfig)`: Generates a ZKP that `comBit` is a commitment to either 0 or 1, using a customized Chaum-Pedersen-like OR proof strategy.
*   `VerifyBitIsZeroOrOne(comBit *elliptic.Point, proof *DisjunctiveProof, config *ZKPConfig)`: Verifies the disjunctive OR proof for a bit's validity.
*   `BitDecompositionProof`: Struct to hold all components of a bit decomposition proof.
*   `ProveBitDecomposition(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, numBits int)`: Proves that a committed value `comValue` is correctly represented by its bit decomposition (`value = sum(b_i * 2^i)`) and that each `b_i` is a valid bit.
*   `VerifyBitDecomposition(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig)`: Verifies the bit decomposition proof.
*   `ProveNonNegative(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, maxBits int)`: Proves a committed value is non-negative by providing a bit decomposition proof up to `maxBits`.
*   `VerifyNonNegative(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig)`: Verifies the non-negativity proof.

**IV. Collective Feature Agreement ZKP (High-level functions)**
*   `ProverMemberData`: Struct to hold a single prover's private data (feature values and their randomness/commitments).
*   `NewProverMember(id string, agreedFeature bool, sumFeature int64)`: Creates a new `ProverMemberData` instance.
*   `GenerateIndividualCommitments(member *ProverMemberData, config *ZKPConfig)`: Generates Pedersen commitments for an individual prover's features.
*   `AggregatedProverData`: Struct to hold the homomorphically aggregated commitments and sums of randomness from all provers.
*   `AggregateProverCommitments(members []*ProverMemberData, config *ZKPConfig)`: Aggregates individual commitments and blinding factors from all provers to form the group's total commitments and randomness.
*   `CollectiveProof`: Struct to hold the complete bundle of ZKP proofs for the collective agreement and sum thresholds.
*   `GenerateCollectiveProof(aggregated *AggregatedProverData, thresholdAgreement, thresholdSum int64, numBitsAgreement, numBitsSum int, config *ZKPConfig)`: Generates the entire collective proof, encompassing knowledge proofs and non-negativity proofs for the threshold conditions.
*   `VerifyCollectiveProof(aggregated *AggregatedProverData, proof *CollectiveProof, thresholdAgreement, thresholdSum int64, config *ZKPConfig)`: Verifies the entire collective proof against the public thresholds and aggregated commitments.

**V. Auxiliary / Helper Functions (Marshaling/Unmarshaling & Scalar/Point Arithmetic)**
*   `ScalarToBytes(scalar *big.Int)`: Converts `big.Int` scalar to a fixed-size byte slice.
*   `BytesToScalar(curve elliptic.Curve, b []byte)`: Converts a byte slice back to a `big.Int` scalar.
*   `PointToBytes(p *elliptic.Point)`: Converts an elliptic curve point to an uncompressed byte slice.
*   `BytesToPoint(curve elliptic.Curve, b []byte)`: Converts a byte slice back to an elliptic curve point.
*   `AddPoints(curve elliptic.Curve, p1, p2 *elliptic.Point)`: Wrapper for `curve.Add`.
*   `ScalarMult(curve elliptic.Curve, p *elliptic.Point, k *big.Int)`: Wrapper for `curve.ScalarMult`.
*   `MultiplyScalars(s1, s2 *big.Int, order *big.Int)`: Performs scalar multiplication modulo curve order.
*   `AddScalars(s1, s2 *big.Int, order *big.Int)`: Performs scalar addition modulo curve order.
*   `NegateScalar(s *big.Int, order *big.Int)`: Performs scalar negation modulo curve order.
*   `SubScalars(s1, s2 *big.Int, order *big.Int)`: Performs scalar subtraction modulo curve order.

```go
package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ZKPConfig holds the elliptic curve parameters and common reference string elements.
type ZKPConfig struct {
	Curve elliptic.Curve
	G     *elliptic.Point // Generator point
	H     *elliptic.Point // Random point on curve, unrelated to G, for commitments
}

// Outline:
// This package provides a custom Zero-Knowledge Proof (ZKP) system
// designed to prove two aggregate properties over privately held data attributes
// from a group of "N" provers, without revealing individual data or even the exact "N".
//
// The specific scenario proven is:
// 1.  **Collective Feature Agreement Threshold**: At least 'T' provers
//     among the group possess a specific (private) binary feature 'a_kj' set to '1'.
// 2.  **Aggregate Sum Threshold**: The total sum of another specific
//     (private) numerical feature 'a_ks' across *all* provers in the group
//     is greater than or equal to 'S_total'.
//
// The ZKP relies on:
// -   Pedersen Commitments for hiding individual and aggregated values.
// -   Homomorphic properties of commitments for secure aggregation.
// -   A custom, simplified Bit-Decomposition Range Proof to demonstrate
//     that aggregated values meet non-negative thresholds, and individual bits are valid.
// -   A custom Disjunctive Zero-Knowledge Proof for proving bit validity (0 or 1).
// -   Fiat-Shamir heuristic for converting interactive proofs into non-interactive ones.
//
// This implementation avoids common ZKP libraries to provide a novel,
// custom approach for this specific problem, emphasizing privacy-preserving
// consensus and aggregation in multi-party scenarios.
//
// Function Summary:
//
// I. Core Cryptographic Primitives (ECC, Commitments, Hashes)
//    - SetupCurve(): Initializes the elliptic curve and common reference string (G, H points).
//    - GenerateRandomScalar(curve elliptic.Curve): Generates a cryptographically secure random scalar within the curve's order.
//    - Commit(value, randomness, config *ZKPConfig): Creates a Pedersen commitment to a value.
//    - VerifyCommitment(commitment, value, randomness, config *ZKPConfig): Verifies a Pedersen commitment.
//    - AggregateCommitments(commitments []*elliptic.Point, config *ZKPConfig): Homomorphically combines multiple commitments by point addition.
//    - AggregateBlindingFactors(factors []*big.Int, config *ZKPConfig): Sums multiple blinding factors modulo curve order.
//    - GenerateChallenge(proofData ...[]byte): Computes a Fiat-Shamir challenge from a hash of proof components.
//
// II. ZKP Building Blocks (Schnorr-like proofs for knowledge of value, linear combinations)
//    - SchnorrProofV2: Struct to hold components of a Schnorr-like proof for knowledge of (value, randomness) in Commit(value, randomness).
//    - ProveKnowledgeOfValue(value, randomness *big.Int, com *elliptic.Point, config *ZKPConfig): Proves knowledge of (value, randomness) for 'com'.
//    - VerifyKnowledgeOfValue(com *elliptic.Point, proof *SchnorrProofV2, config *ZKPConfig): Verifies the knowledge-of-value proof.
//    - LinearCombinationProof: Struct for linear combination proof.
//    - ProveLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int, targetRandomness *big.Int, componentRandomness []*big.Int, config *ZKPConfig): Proves targetCom is a linear combination of component commitments.
//    - VerifyLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int, proof *LinearCombinationProof, config *ZKPConfig): Verifies the linear combination proof.
//
// III. Range Proof (Bit Decomposition for Non-Negativity and Bit Validity)
//    - DecomposeToBits(value *big.Int, numBits int): Decomposes a big.Int into its bit representation.
//    - DisjunctiveProof: Struct for a disjunctive OR proof.
//    - ProveBitIsZeroOrOne(bitVal, bitRand *big.Int, comBit *elliptic.Point, config *ZKPConfig): Proves a committed value is 0 or 1 using a custom disjunctive OR proof.
//    - VerifyBitIsZeroOrOne(comBit *elliptic.Point, proof *DisjunctiveProof, config *ZKPConfig): Verifies a bit is 0 or 1.
//    - BitDecompositionProof: Struct for bit decomposition proof components.
//    - ProveBitDecomposition(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, numBits int): Proves a committed value is composed of specific bits.
//    - VerifyBitDecomposition(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig): Verifies the bit decomposition and individual bit validity.
//    - ProveNonNegative(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, maxBits int): Proves a committed value is non-negative using bit decomposition.
//    - VerifyNonNegative(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig): Verifies a non-negative proof.
//
// IV. Collective Feature Agreement ZKP (High-level functions)
//    - ProverMemberData: Struct to hold a single prover's private data and commitments.
//    - NewProverMember(id string, agreedFeature bool, sumFeature int64): Creates a new prover's data.
//    - GenerateIndividualCommitments(member *ProverMemberData, config *ZKPConfig): Generates commitments for a member's features.
//    - AggregatedProverData: Struct to hold aggregated commitments and blinding factors.
//    - AggregateProverCommitments(members []*ProverMemberData, config *ZKPConfig): Aggregates commitments and blinding factors from all provers.
//    - CollectiveProof: Struct to hold the aggregated proof bundle.
//    - GenerateCollectiveProof(aggregated *AggregatedProverData, thresholdAgreement, thresholdSum int64, numBitsAgreement, numBitsSum int, config *ZKPConfig): Generates the full collective proof.
//    - VerifyCollectiveProof(aggregated *AggregatedProverData, proof *CollectiveProof, thresholdAgreement, thresholdSum int64, config *ZKPConfig): Verifies the entire collective proof.
//
// V. Auxiliary / Helper Functions (Marshaling/Unmarshaling)
//    - ScalarToBytes(scalar *big.Int): Converts big.Int scalar to byte slice.
//    - BytesToScalar(curve elliptic.Curve, b []byte): Converts byte slice to big.Int scalar.
//    - PointToBytes(p *elliptic.Point): Converts elliptic.Point to byte slice.
//    - BytesToPoint(curve elliptic.Curve, b []byte): Converts byte slice to elliptic.Point.
//    - AddPoints(curve elliptic.Curve, p1, p2 *elliptic.Point): Wrapper for curve.Add.
//    - ScalarMult(curve elliptic.Curve, p *elliptic.Point, k *big.Int): Wrapper for curve.ScalarMult.
//    - MultiplyScalars(s1, s2 *big.Int, order *big.Int): Performs scalar multiplication modulo curve order.
//    - AddScalars(s1, s2 *big.Int, order *big.Int): Performs scalar addition modulo curve order.
//    - NegateScalar(s *big.Int, order *big.Int): Performs scalar negation modulo curve order.
//    - SubScalars(s1, s2 *big.Int, order *big.Int): Performs scalar subtraction modulo curve order.

// SetupCurve initializes the elliptic curve parameters and generates common reference string elements G and H.
func SetupCurve() *ZKPConfig {
	curve := elliptic.P256()
	G_x, G_y := curve.Params().Gx, curve.Params().Gy
	G := elliptic.Point{X: G_x, Y: G_y} // G is the base point of P256

	// H needs to be a random point on the curve, independent of G.
	// For reproducibility in a non-production setting, we'll hash a known string to a point.
	hasher := sha256.New()
	hasher.Write([]byte("ZKP_H_GENERATOR"))
	seed := hasher.Sum(nil)
	H_x, H_y := curve.ScalarBaseMult(seed) // Use ScalarBaseMult as a pseudo-random point generator from seed

	H := elliptic.Point{X: H_x, Y: H_y}

	return &ZKPConfig{
		Curve: curve,
		G:     &G,
		H:     &H,
	}
}

// GenerateRandomScalar generates a cryptographically secure random scalar within the curve's order.
func GenerateRandomScalar(curve elliptic.Curve) *big.Int {
	n := curve.Params().N // Curve order
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar: %v", err))
	}
	return r
}

// Commit creates a Pedersen commitment C = value*G + randomness*H.
func Commit(value, randomness *big.Int, config *ZKPConfig) *elliptic.Point {
	// value*G
	vG := ScalarMult(config.Curve, config.G, value)

	// randomness*H
	rH := ScalarMult(config.Curve, config.H, randomness)

	// C = vG + rH
	return AddPoints(config.Curve, vG, rH)
}

// VerifyCommitment verifies a Pedersen commitment: commitment == value*G + randomness*H.
func VerifyCommitment(commitment *elliptic.Point, value, randomness *big.Int, config *ZKPConfig) bool {
	expectedCommitment := Commit(value, randomness, config)
	return expectedCommitment.X.Cmp(commitment.X) == 0 && expectedCommitment.Y.Cmp(commitment.Y) == 0
}

// AggregateCommitments homomorphically combines multiple commitments by point addition.
// C_total = C1 + C2 + ... + Cn
func AggregateCommitments(commitments []*elliptic.Point, config *ZKPConfig) *elliptic.Point {
	if len(commitments) == 0 {
		return &elliptic.Point{X: big.NewInt(0), Y: big.NewInt(0)} // Point at infinity / identity element
	}

	agg := commitments[0]
	for i := 1; i < len(commitments); i++ {
		agg = AddPoints(config.Curve, agg, commitments[i])
	}
	return agg
}

// AggregateBlindingFactors sums multiple blinding factors modulo curve order.
// R_total = r1 + r2 + ... + rn (mod N)
func AggregateBlindingFactors(factors []*big.Int, config *ZKPConfig) *big.Int {
	order := config.Curve.Params().N
	total := big.NewInt(0)
	for _, f := range factors {
		total = AddScalars(total, f, order)
	}
	return total
}

// GenerateChallenge computes a Fiat-Shamir challenge from a hash of proof components.
func GenerateChallenge(proofData ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, data := range proofData {
		if data != nil { // Ensure nil data slices don't cause issues
			hasher.Write(data)
		}
	}
	hashBytes := hasher.Sum(nil)

	// Convert hash bytes to a big.Int
	challenge := new(big.Int).SetBytes(hashBytes)
	return challenge
}

// ScalarToBytes converts big.Int scalar to byte slice.
func ScalarToBytes(scalar *big.Int) []byte {
	// Pad to 32 bytes for P256 scalar length
	return scalar.FillBytes(make([]byte, 32))
}

// BytesToScalar converts byte slice to big.Int scalar.
func BytesToScalar(curve elliptic.Curve, b []byte) *big.Int {
	scalar := new(big.Int).SetBytes(b)
	// Ensure scalar is within the curve's order
	scalar.Mod(scalar, curve.Params().N)
	return scalar
}

// PointToBytes converts elliptic.Point to byte slice (uncompressed format).
func PointToBytes(p *elliptic.Point) []byte {
	if p == nil || p.X == nil || p.Y == nil {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), p.X, p.Y)
}

// BytesToPoint converts byte slice to elliptic.Point.
func BytesToPoint(curve elliptic.Curve, b []byte) *elliptic.Point {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil
	}
	return &elliptic.Point{X: x, Y: y}
}

// AddPoints is a wrapper for curve.Add.
func AddPoints(curve elliptic.Curve, p1, p2 *elliptic.Point) *elliptic.Point {
	if p1 == nil || p2 == nil {
		if p1 == nil {
			return p2
		}
		return p1
	}
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return &elliptic.Point{X: x, Y: y}
}

// ScalarMult is a wrapper for curve.ScalarMult.
func ScalarMult(curve elliptic.Curve, p *elliptic.Point, k *big.Int) *elliptic.Point {
	if p == nil || k == nil || k.Cmp(big.NewInt(0)) == 0 {
		// Return point at infinity if point is nil or scalar is zero
		return &elliptic.Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}
	x, y := curve.ScalarMult(p.X, p.Y, k.Bytes())
	return &elliptic.Point{X: x, Y: y}
}

// MultiplyScalars performs scalar multiplication modulo curve order.
func MultiplyScalars(s1, s2 *big.Int, order *big.Int) *big.Int {
	res := new(big.Int).Mul(s1, s2)
	return res.Mod(res, order)
}

// AddScalars performs scalar addition modulo curve order.
func AddScalars(s1, s2 *big.Int, order *big.Int) *big.Int {
	res := new(big.Int).Add(s1, s2)
	return res.Mod(res, order)
}

// NegateScalar performs scalar negation modulo curve order.
func NegateScalar(s *big.Int, order *big.Int) *big.Int {
	res := new(big.Int).Neg(s)
	return res.Mod(res, order)
}

// SubScalars performs scalar subtraction modulo curve order.
func SubScalars(s1, s2 *big.Int, order *big.Int) *big.Int {
	res := new(big.Int).Sub(s1, s2)
	return res.Mod(res, order)
}

// SchnorrProofV2 for proving knowledge of (value, randomness) for C = value*G + randomness*H
type SchnorrProofV2 struct {
	Rv *elliptic.Point // R_v = kv * G
	Rr *elliptic.Point // R_r = kr * H
	Sv *big.Int        // s_v = kv + e*value (mod N)
	Sr *big.Int        // s_r = kr + e*randomness (mod N)
}

// ProveKnowledgeOfValue generates a Schnorr-like proof for knowledge of (value, randomness) for com.
func ProveKnowledgeOfValue(value, randomness *big.Int, com *elliptic.Point, config *ZKPConfig) *SchnorrProofV2 {
	order := config.Curve.Params().N

	kv := GenerateRandomScalar(config.Curve)
	kr := GenerateRandomScalar(config.Curve)

	// Rv = kv*G, Rr = kr*H
	Rv := ScalarMult(config.Curve, config.G, kv)
	Rr := ScalarMult(config.Curve, config.H, kr)

	// Challenge e = H(com || Rv || Rr)
	e := GenerateChallenge(PointToBytes(com), PointToBytes(Rv), PointToBytes(Rr))
	e.Mod(e, order)

	// Responses
	Sv := AddScalars(kv, MultiplyScalars(e, value, order), order)
	Sr := AddScalars(kr, MultiplyScalars(e, randomness, order), order)

	return &SchnorrProofV2{Rv: Rv, Rr: Rr, Sv: Sv, Sr: Sr}
}

// VerifyKnowledgeOfValue verifies the Schnorr-like proof for knowledge of (value, randomness).
func VerifyKnowledgeOfValue(com *elliptic.Point, proof *SchnorrProofV2, config *ZKPConfig) bool {
	order := config.Curve.Params().N

	// Recompute challenge e
	e := GenerateChallenge(PointToBytes(com), PointToBytes(proof.Rv), PointToBytes(proof.Rr))
	e.Mod(e, order)

	// Check Sv*G + Sr*H = Rv + Rr + e*Com
	// L.H.S: Sv*G + Sr*H
	lhsG := ScalarMult(config.Curve, config.G, proof.Sv)
	lhsH := ScalarMult(config.Curve, config.H, proof.Sr)
	lhs := AddPoints(config.Curve, lhsG, lhsH)

	// R.H.S: Rv + Rr + e*Com
	rhs := AddPoints(config.Curve, proof.Rv, proof.Rr)
	eCom := ScalarMult(config.Curve, com, e)
	rhs = AddPoints(config.Curve, rhs, eCom)

	return lhs.X.Cmp(rhs.X) == 0 && lhs.Y.Cmp(rhs.Y) == 0
}

// LinearCombinationProof holds components of a linear combination proof.
type LinearCombinationProof struct {
	Proof *SchnorrProofV2 // Proof that the difference commitment is for (0, r_diff)
}

// ProveLinearCombination proves that targetCom = sum(coeff_i * components[i]) by showing that
// targetCom - sum(coeff_i * components[i]) is a commitment to 0 with specific randomness.
// targetRandomness is the randomness for targetCom.
// componentRandomness are the randomness values for components.
func ProveLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int,
	targetRandomness *big.Int, componentRandomness []*big.Int, config *ZKPConfig) *LinearCombinationProof {

	order := config.Curve.Params().N

	// Compute the expected combined commitment from components and coefficients
	expectedCom := ScalarMult(config.Curve, components[0], coefficients[0])
	for i := 1; i < len(components); i++ {
		term := ScalarMult(config.Curve, components[i], coefficients[i])
		expectedCom = AddPoints(config.Curve, expectedCom, term)
	}

	// Calculate the difference commitment: diffCom = targetCom - expectedCom
	negExpectedComY := new(big.Int).Sub(order, expectedCom.Y)
	negExpectedCom := elliptic.Point{X: expectedCom.X, Y: negExpectedComY}
	diffCom := AddPoints(config.Curve, targetCom, &negExpectedCom)

	// Calculate the difference in blinding factors: r_diff = targetRandomness - sum(coeff_i * componentRandomness_i)
	rDiff := new(big.Int).Set(targetRandomness)
	for i := 0; i < len(componentRandomness); i++ {
		scaledRand := MultiplyScalars(coefficients[i], componentRandomness[i], order)
		rDiff = SubScalars(rDiff, scaledRand, order)
	}

	// Prove that diffCom is a commitment to 0 with randomness rDiff
	proof := ProveKnowledgeOfValue(big.NewInt(0), rDiff, diffCom, config)
	return &LinearCombinationProof{Proof: proof}
}

// VerifyLinearCombination verifies the linear combination proof.
func VerifyLinearCombination(targetCom *elliptic.Point, components []*elliptic.Point, coefficients []*big.Int,
	proof *LinearCombinationProof, config *ZKPConfig) bool {

	// Recompute the expected combined commitment from components and coefficients
	expectedCom := ScalarMult(config.Curve, components[0], coefficients[0])
	for i := 1; i < len(components); i++ {
		term := ScalarMult(config.Curve, components[i], coefficients[i])
		expectedCom = AddPoints(config.Curve, expectedCom, term)
	}

	// Calculate the difference commitment: diffCom = targetCom - expectedCom
	negExpectedComY := new(big.Int).Sub(config.Curve.Params().N, expectedCom.Y)
	negExpectedCom := elliptic.Point{X: expectedCom.X, Y: negExpectedComY}
	diffCom := AddPoints(config.Curve, targetCom, &negExpectedCom)

	// Verify that diffCom is a commitment to 0 using the provided proof
	return VerifyKnowledgeOfValue(diffCom, proof.Proof, config)
}

// DecomposeToBits decomposes a big.Int into its bit representation.
// Returns a slice of big.Ints, where each element is 0 or 1.
func DecomposeToBits(value *big.Int, numBits int) []*big.Int {
	bits := make([]*big.Int, numBits)
	for i := 0; i < numBits; i++ {
		if value.Bit(i) == 1 {
			bits[i] = big.NewInt(1)
		} else {
			bits[i] = big.NewInt(0)
		}
	}
	return bits
}

// DisjunctiveProof for proving a committed value is either 0 or 1.
// Uses a Chaum-Pedersen-like OR proof structure adapted to NIZKP with Fiat-Shamir.
type DisjunctiveProof struct {
	// Responses and challenges for the "0" branch
	R0 *elliptic.Point // Commitment to k0*G + l0*H
	E0 *big.Int        // Challenge share e0
	S0 *big.Int        // Response s0
	T0 *big.Int        // Response t0

	// Responses and challenges for the "1" branch
	R1 *elliptic.Point // Commitment to k1*G + l1*H
	E1 *big.Int        // Challenge share e1
	S1 *big.Int        // Response s1
	T1 *big.Int        // Response t1

	// Total challenge (from Fiat-Shamir hash)
	E *big.Int
}

// ProveBitIsZeroOrOne generates a ZKP that `comBit` is a commitment to either 0 or 1.
func ProveBitIsZeroOrOne(bitVal, bitRand *big.Int, comBit *elliptic.Point, config *ZKPConfig) *DisjunctiveProof {
	order := config.Curve.Params().N
	proof := &DisjunctiveProof{}

	var k_real, l_real *big.Int // For the actual (real) branch
	var e_sim, s_sim, t_sim *big.Int // For the simulated (false) branch

	if bitVal.Cmp(big.NewInt(0)) == 0 { // Proving bitVal = 0
		// Real branch (b=0) - choose k0, l0 for R0. S0, T0 will be derived later.
		k_real = GenerateRandomScalar(config.Curve)
		l_real = GenerateRandomScalar(config.Curve)

		// Simulated branch (b=1) - choose e1, s1, t1 randomly. R1 will be derived.
		e_sim = GenerateRandomScalar(config.Curve)
		s_sim = GenerateRandomScalar(config.Curve)
		t_sim = GenerateRandomScalar(config.Curve)

		// Compute R1 for the simulated branch using the equation R1 = s1*G + t1*H - e1*(ComBit - 1*G)
		val1G := ScalarMult(config.Curve, config.G, big.NewInt(1))
		comBitMinusVal1G := AddPoints(config.Curve, comBit, ScalarMult(config.Curve, val1G, NegateScalar(big.NewInt(1), order)))
		term1_sim := AddPoints(config.Curve, ScalarMult(config.Curve, config.G, s_sim), ScalarMult(config.Curve, config.H, t_sim))
		term2_sim := ScalarMult(config.Curve, comBitMinusVal1G, e_sim)
		
		proof.R1 = AddPoints(config.Curve, term1_sim, ScalarMult(config.Curve, term2_sim, NegateScalar(big.NewInt(1), order)))
		proof.E1 = e_sim
		proof.S1 = s_sim
		proof.T1 = t_sim

	} else { // Proving bitVal = 1
		// Real branch (b=1) - choose k1, l1 for R1. S1, T1 will be derived later.
		k_real = GenerateRandomScalar(config.Curve)
		l_real = GenerateRandomScalar(config.Curve)

		// Simulated branch (b=0) - choose e0, s0, t0 randomly. R0 will be derived.
		e_sim = GenerateRandomScalar(config.Curve)
		s_sim = GenerateRandomScalar(config.Curve)
		t_sim = GenerateRandomScalar(config.Curve)

		// Compute R0 for the simulated branch using the equation R0 = s0*G + t0*H - e0*(ComBit - 0*G)
		val0G := ScalarMult(config.Curve, config.G, big.NewInt(0))
		comBitMinusVal0G := AddPoints(config.Curve, comBit, ScalarMult(config.Curve, val0G, NegateScalar(big.NewInt(1), order)))
		term1_sim := AddPoints(config.Curve, ScalarMult(config.Curve, config.G, s_sim), ScalarMult(config.Curve, config.H, t_sim))
		term2_sim := ScalarMult(config.Curve, comBitMinusVal0G, e_sim)

		proof.R0 = AddPoints(config.Curve, term1_sim, ScalarMult(config.Curve, term2_sim, NegateScalar(big.NewInt(1), order)))
		proof.E0 = e_sim
		proof.S0 = s_sim
		proof.T0 = t_sim
	}

	// Compute total challenge E
	// This must be done after R0 and R1 are determined.
	proof.E = GenerateChallenge(PointToBytes(comBit), PointToBytes(proof.R0), PointToBytes(proof.R1))
	proof.E.Mod(proof.E, order)

	// Compute the challenge for the real branch, and derive real responses
	var e_real *big.Int
	if bitVal.Cmp(big.NewInt(0)) == 0 { // Real branch is 0
		e_real = SubScalars(proof.E, proof.E1, order) // e0 = E - e1
		proof.E0 = e_real

		proof.S0 = AddScalars(k_real, MultiplyScalars(e_real, big.NewInt(0), order), order)
		proof.T0 = AddScalars(l_real, MultiplyScalars(e_real, bitRand, order), order)
		proof.R0 = AddPoints(config.Curve, ScalarMult(config.Curve, config.G, k_real), ScalarMult(config.Curve, config.H, l_real))

	} else { // Real branch is 1
		e_real = SubScalars(proof.E, proof.E0, order) // e1 = E - e0
		proof.E1 = e_real

		proof.S1 = AddScalars(k_real, MultiplyScalars(e_real, big.NewInt(1), order), order)
		proof.T1 = AddScalars(l_real, MultiplyScalars(e_real, bitRand, order), order)
		proof.R1 = AddPoints(config.Curve, ScalarMult(config.Curve, config.G, k_real), ScalarMult(config.Curve, config.H, l_real))
	}

	return proof
}

// VerifyBitIsZeroOrOne verifies a ZKP that `comBit` is a commitment to either 0 or 1.
func VerifyBitIsZeroOrOne(comBit *elliptic.Point, proof *DisjunctiveProof, config *ZKPConfig) bool {
	order := config.Curve.Params().N

	// Recompute overall challenge E
	recomputedE := GenerateChallenge(PointToBytes(comBit), PointToBytes(proof.R0), PointToBytes(proof.R1))
	recomputedE.Mod(recomputedE, order)

	if recomputedE.Cmp(proof.E) != 0 {
		return false // Challenge mismatch
	}

	// Check E0 + E1 == E
	sumE := AddScalars(proof.E0, proof.E1, order)
	if sumE.Cmp(proof.E) != 0 {
		return false
	}

	// Verify branch 0: S0*G + T0*H == R0 + E0*(ComBit - 0*G)
	lhs0 := AddPoints(config.Curve, ScalarMult(config.Curve, config.G, proof.S0), ScalarMult(config.Curve, config.H, proof.T0))
	val0G := ScalarMult(config.Curve, config.G, big.NewInt(0))
	comBitMinusVal0G := AddPoints(config.Curve, comBit, ScalarMult(config.Curve, val0G, NegateScalar(big.NewInt(1), order)))
	rhs0 := AddPoints(config.Curve, proof.R0, ScalarMult(config.Curve, comBitMinusVal0G, proof.E0))

	if lhs0.X.Cmp(rhs0.X) != 0 || lhs0.Y.Cmp(rhs0.Y) != 0 {
		return false
	}

	// Verify branch 1: S1*G + T1*H == R1 + E1*(ComBit - 1*G)
	lhs1 := AddPoints(config.Curve, ScalarMult(config.Curve, config.G, proof.S1), ScalarMult(config.Curve, config.H, proof.T1))
	val1G := ScalarMult(config.Curve, config.G, big.NewInt(1))
	comBitMinusVal1G := AddPoints(config.Curve, comBit, ScalarMult(config.Curve, val1G, NegateScalar(big.NewInt(1), order)))
	rhs1 := AddPoints(config.Curve, proof.R1, ScalarMult(config.Curve, comBitMinusVal1G, proof.E1))

	if lhs1.X.Cmp(rhs1.X) != 0 || lhs1.Y.Cmp(rhs1.Y) != 0 {
		return false
	}

	return true
}

// BitDecompositionProof holds components for a bit decomposition proof.
type BitDecompositionProof struct {
	BitCommitments []*elliptic.Point   // C_bi = Com(b_i, r_bi) for each bit
	BitRandomness  []*big.Int          // Randomness for each bit commitment (needed for LinearCombinationProof)
	BitProofs      []*DisjunctiveProof // Proofs that each b_i is 0 or 1
	LinComProof    *LinearCombinationProof // Proof that Com(value, randomness) is a linear combination of bit commitments
}

// ProveBitDecomposition proves that a committed value `comValue` is composed of specific bits.
// Specifically, it proves `value = sum(b_i * 2^i)` and that each `b_i` is 0 or 1.
// The `randomness` parameter is the randomness `r` in `Com(value, r)`.
func ProveBitDecomposition(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, numBits int) *BitDecompositionProof {
	order := config.Curve.Params().N
	bits := DecomposeToBits(value, numBits)

	bitCommitments := make([]*elliptic.Point, numBits)
	bitRandomness := make([]*big.Int, numBits)
	bitProofs := make([]*DisjunctiveProof, numBits)

	// 1. Commit to each bit and prove each bit is 0 or 1.
	for i := 0; i < numBits; i++ {
		r_bi := GenerateRandomScalar(config.Curve)
		bitCommitments[i] = Commit(bits[i], r_bi, config)
		bitRandomness[i] = r_bi // Store for LinearCombinationProof
		bitProofs[i] = ProveBitIsZeroOrOne(bits[i], r_bi, bitCommitments[i], config)
	}

	// 2. Prove that the original `comValue` is equal to the sum of bit commitments, appropriately scaled.
	// This means proving `comValue == Sum(coeffs[i] * Com(bits[i], bitRandomness[i]))`.
	// The coefficients are `2^i`.
	coeffs := make([]*big.Int, numBits)
	for i := 0; i < numBits; i++ {
		coeffs[i] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil) // 2^i
	}

	// The `ProveLinearCombination` takes `targetCom`, `components`, `coefficients`, `targetRandomness`, `componentRandomness`.
	// Here, `targetCom` is `comValue`.
	// `components` are `bitCommitments`.
	// `coefficients` are `coeffs` (2^i).
	// `targetRandomness` is `randomness`.
	// `componentRandomness` are `bitRandomness`.
	linComProof := ProveLinearCombination(comValue, bitCommitments, coeffs, randomness, bitRandomness, config)

	return &BitDecompositionProof{
		BitCommitments: bitCommitments,
		BitRandomness:  bitRandomness, // Included for clarity/completeness in proof struct, though not directly verified by `VerifyBitDecomposition`
		BitProofs:      bitProofs,
		LinComProof:    linComProof,
	}
}

// VerifyBitDecomposition verifies a bit decomposition proof.
func VerifyBitDecomposition(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig) bool {
	// 1. Verify each bit commitment is to 0 or 1.
	for i := 0; i < len(proof.BitCommitments); i++ {
		if !VerifyBitIsZeroOrOne(proof.BitCommitments[i], proof.BitProofs[i], config) {
			return false
		}
	}

	// 2. Verify the linear combination relation: comValue = sum(2^i * C_bi)
	numBits := len(proof.BitCommitments)
	coeffs := make([]*big.Int, numBits)
	for i := 0; i < numBits; i++ {
		coeffs[i] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil)
	}

	// The `VerifyLinearCombination` reconstructs `diffCom = comValue - expectedCom`
	// and verifies `diffCom` is a commitment to 0. It does not need `targetRandomness`
	// or `componentRandomness` directly in its verification step.
	return VerifyLinearCombination(comValue, proof.BitCommitments, coeffs, proof.LinComProof, config)
}

// ProveNonNegative proves that a committed value `comValue` is non-negative using bit decomposition.
// This is essentially proving `value >= 0`. It proves `value` can be represented as a sum of positive powers of 2 (bits).
// The `maxBits` defines the maximum possible value range for the non-negative proof (e.g., for a value < 100, 7 bits is enough as 2^7 = 128).
func ProveNonNegative(value, randomness *big.Int, comValue *elliptic.Point, config *ZKPConfig, maxBits int) *BitDecompositionProof {
	// A value is non-negative if its bit decomposition (up to `maxBits`) is valid.
	// This is a direct application of `ProveBitDecomposition`.
	// Note: This only proves `value >= 0` *within the range representable by `maxBits`*.
	return ProveBitDecomposition(value, randomness, comValue, config, maxBits)
}

// VerifyNonNegative verifies a non-negative proof (i.e., a bit decomposition proof).
func VerifyNonNegative(comValue *elliptic.Point, proof *BitDecompositionProof, config *ZKPConfig) bool {
	return VerifyBitDecomposition(comValue, proof, config)
}

// ProverMemberData holds a single prover's private data and its commitments.
type ProverMemberData struct {
	ID                 string
	AgreedFeature      bool
	SumFeature         int64
	RandomnessAgreed   *big.Int
	RandomnessSum      *big.Int
	CommitmentAgreed   *elliptic.Point
	CommitmentSum      *elliptic.Point
}

// NewProverMember creates a new prover's data structure.
func NewProverMember(id string, agreedFeature bool, sumFeature int64) *ProverMemberData {
	return &ProverMemberData{
		ID:            id,
		AgreedFeature: agreedFeature,
		SumFeature:    sumFeature,
	}
}

// GenerateIndividualCommitments generates commitments for a member's features.
func GenerateIndividualCommitments(member *ProverMemberData, config *ZKPConfig) {
	member.RandomnessAgreed = GenerateRandomScalar(config.Curve)
	agreedVal := big.NewInt(0)
	if member.AgreedFeature {
		agreedVal = big.NewInt(1)
	}
	member.CommitmentAgreed = Commit(agreedVal, member.RandomnessAgreed, config)

	member.RandomnessSum = GenerateRandomScalar(config.Curve)
	member.CommitmentSum = Commit(big.NewInt(member.SumFeature), member.RandomnessSum, config)
}

// AggregatedProverData holds aggregated commitments and blinding factors from all provers.
type AggregatedProverData struct {
	TotalCommitmentAgreed *elliptic.Point
	TotalRandomnessAgreed *big.Int // Sum of r_kj
	TotalAgreementValue   *big.Int // Actual sum of a_kj (for proving internal consistency)

	TotalCommitmentSum    *elliptic.Point
	TotalRandomnessSum    *big.Int // Sum of r_ks
	TotalSumValue         *big.Int // Actual sum of a_ks (for proving internal consistency)
}

// AggregateProverCommitments aggregates commitments and blinding factors from all provers.
func AggregateProverCommitments(members []*ProverMemberData, config *ZKPConfig) *AggregatedProverData {
	var commitmentsAgreed []*elliptic.Point
	var randomnessAgreed []*big.Int
	var valuesAgreed []*big.Int

	var commitmentsSum []*elliptic.Point
	var randomnessSum []*big.Int
	var valuesSum []*big.Int

	for _, member := range members {
		if member.CommitmentAgreed == nil || member.CommitmentSum == nil {
			panic("Individual commitments not generated for all members. Call GenerateIndividualCommitments first.")
		}
		commitmentsAgreed = append(commitmentsAgreed, member.CommitmentAgreed)
		randomnessAgreed = append(randomnessAgreed, member.RandomnessAgreed)
		if member.AgreedFeature {
			valuesAgreed = append(valuesAgreed, big.NewInt(1))
		} else {
			valuesAgreed = append(valuesAgreed, big.NewInt(0))
		}

		commitmentsSum = append(commitmentsSum, member.CommitmentSum)
		randomnessSum = append(randomnessSum, member.RandomnessSum)
		valuesSum = append(valuesSum, big.NewInt(member.SumFeature))
	}

	aggData := &AggregatedProverData{}
	aggData.TotalCommitmentAgreed = AggregateCommitments(commitmentsAgreed, config)
	aggData.TotalRandomnessAgreed = AggregateBlindingFactors(randomnessAgreed, config)
	
	// Calculate total actual value for agreed features (for prover's use in proof generation)
	aggData.TotalAgreementValue = big.NewInt(0)
	for _, v := range valuesAgreed {
		aggData.TotalAgreementValue.Add(aggData.TotalAgreementValue, v)
	}

	aggData.TotalCommitmentSum = AggregateCommitments(commitmentsSum, config)
	aggData.TotalRandomnessSum = AggregateBlindingFactors(randomnessSum, config)
	
	// Calculate total actual value for sum features (for prover's use in proof generation)
	aggData.TotalSumValue = big.NewInt(0)
	for _, v := range valuesSum {
		aggData.TotalSumValue.Add(aggData.TotalSumValue, v)
	}

	return aggData
}

// CollectiveProof holds the aggregated proof bundle.
type CollectiveProof struct {
	ProofAgreedKnowledge *SchnorrProofV2
	ProofAgreedThreshold *BitDecompositionProof // Proves (TotalAgreementValue - thresholdAgreement) is non-negative

	ProofSumKnowledge    *SchnorrProofV2
	ProofSumThreshold    *BitDecompositionProof // Proves (TotalSumValue - thresholdSum) is non-negative
}

// GenerateCollectiveProof generates the full collective proof.
// `aggregated` contains the aggregated (but still hidden) values and randomness.
// `thresholdAgreement` and `thresholdSum` are the public thresholds.
// `numBitsAgreement` and `numBitsSum` specify the maximum bit length for the respective range proofs.
func GenerateCollectiveProof(aggregated *AggregatedProverData, thresholdAgreement, thresholdSum int64, numBitsAgreement, numBitsSum int, config *ZKPConfig) *CollectiveProof {
	proof := &CollectiveProof{}

	// Proof for Collective Feature Agreement Threshold: sum(a_kj) >= thresholdAgreement
	// 1. Prove knowledge of total value and randomness for TotalCommitmentAgreed.
	proof.ProofAgreedKnowledge = ProveKnowledgeOfValue(aggregated.TotalAgreementValue, aggregated.TotalRandomnessAgreed, aggregated.TotalCommitmentAgreed, config)

	// 2. Prove (TotalAgreementValue - thresholdAgreement) is non-negative.
	// The value to prove non-negative is `diffAgreedVal = TotalAgreementValue - thresholdAgreement`.
	// The commitment for this value should be `Com(diffAgreedVal, TotalRandomnessAgreed)`.
	// This commitment can be reconstructed by the verifier as `TotalCommitmentAgreed - Commit(thresholdAgreement, 0)`.
	diffAgreedVal := new(big.Int).Sub(aggregated.TotalAgreementValue, big.NewInt(thresholdAgreement))
	comDiffAgreed := Commit(diffAgreedVal, aggregated.TotalRandomnessAgreed, config) // Prover uses actual values to commit

	proof.ProofAgreedThreshold = ProveNonNegative(diffAgreedVal, aggregated.TotalRandomnessAgreed, comDiffAgreed, config, numBitsAgreement)

	// Proof for Aggregate Sum Threshold: sum(a_ks) >= thresholdSum
	// 1. Prove knowledge of total value and randomness for TotalCommitmentSum.
	proof.ProofSumKnowledge = ProveKnowledgeOfValue(aggregated.TotalSumValue, aggregated.TotalRandomnessSum, aggregated.TotalCommitmentSum, config)

	// 2. Prove (TotalSumValue - thresholdSum) is non-negative.
	// Similar to above, `diffSumVal = TotalSumValue - thresholdSum`.
	// The commitment for this is `Com(diffSumVal, TotalRandomnessSum)`.
	diffSumVal := new(big.Int).Sub(aggregated.TotalSumValue, big.NewInt(thresholdSum))
	comDiffSum := Commit(diffSumVal, aggregated.TotalRandomnessSum, config) // Prover uses actual values to commit

	proof.ProofSumThreshold = ProveNonNegative(diffSumVal, aggregated.TotalRandomnessSum, comDiffSum, config, numBitsSum)

	return proof
}

// VerifyCollectiveProof verifies the entire collective proof.
// `aggregated` here contains only the *commitments* from the prover group, not the hidden values/randomness.
// The verifier reconstructs these commitments for verification.
func VerifyCollectiveProof(aggregatedCommitments *AggregatedProverData, proof *CollectiveProof, thresholdAgreement, thresholdSum int64, config *ZKPConfig) bool {
	// 1. Verify knowledge of total value and randomness for TotalCommitmentAgreed.
	if !VerifyKnowledgeOfValue(aggregatedCommitments.TotalCommitmentAgreed, proof.ProofAgreedKnowledge, config) {
		fmt.Println("Verification failed: ProofAgreedKnowledge")
		return false
	}

	// 2. Reconstruct commitment for (TotalAgreementValue - thresholdAgreement) and verify non-negativity.
	// The verifier computes `C_diff = TotalCommitmentAgreed - Commit(thresholdAgreement, 0)`.
	threshAgreedValG := ScalarMult(config.Curve, config.G, big.NewInt(thresholdAgreement))
	negThreshAgreedValG := ScalarMult(config.Curve, threshAgreedValG, NegateScalar(big.NewInt(1), config.Curve.Params().N))
	expectedComDiffAgreed := AddPoints(config.Curve, aggregatedCommitments.TotalCommitmentAgreed, negThreshAgreedValG)

	if !VerifyNonNegative(expectedComDiffAgreed, proof.ProofAgreedThreshold, config) {
		fmt.Println("Verification failed: ProofAgreedThreshold non-negativity")
		return false
	}

	// 3. Verify knowledge of total value and randomness for TotalCommitmentSum.
	if !VerifyKnowledgeOfValue(aggregatedCommitments.TotalCommitmentSum, proof.ProofSumKnowledge, config) {
		fmt.Println("Verification failed: ProofSumKnowledge")
		return false
	}

	// 4. Reconstruct commitment for (TotalSumValue - thresholdSum) and verify non-negativity.
	threshSumValG := ScalarMult(config.Curve, config.G, big.NewInt(thresholdSum))
	negThreshSumValG := ScalarMult(config.Curve, threshSumValG, NegateScalar(big.NewInt(1), config.Curve.Params().N))
	expectedComDiffSum := AddPoints(config.Curve, aggregatedCommitments.TotalCommitmentSum, negThreshSumValG)

	if !VerifyNonNegative(expectedComDiffSum, proof.ProofSumThreshold, config) {
		fmt.Println("Verification failed: ProofSumThreshold non-negativity")
		return false
	}

	return true
}

```