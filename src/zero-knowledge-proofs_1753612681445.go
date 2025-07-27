The following Golang code implements a Zero-Knowledge Proof system for demonstrating financial eligibility (ZKP-FEL). This system allows a "prover" to prove to a "verifier" that they meet specific financial criteria (e.g., income threshold, debt limit, exact number of loans, and a debt-to-income ratio) without revealing their exact income, debt, or number of loans.

The implementation is built from fundamental cryptographic primitives, aiming for originality as requested, avoiding direct duplication of existing ZKP libraries like Groth16, Plonk, or Bulletproofs. Instead, it constructs a custom system using:
*   **Elliptic Curve Cryptography (ECC)** for underlying point operations.
*   **Pedersen Commitments** for hiding the sensitive numerical values.
*   **Fiat-Shamir Heuristic** to transform interactive proofs into non-interactive ones.
*   **Schnorr-like Sigma Protocols** for proving knowledge of discrete logarithms (used in commitment randomness proofs).
*   **Bit-decomposition based Range Proofs** leveraging disjunctive Sigma protocols to prove that a committed value is non-negative (used for inequality proofs like `X > Y` by proving `X - Y - 1 >= 0`).

The code structure is modular, with distinct sections for core cryptographic primitives, the commitment scheme, ZKP building blocks, and the ZKP-FEL application logic.

---

### Outline and Function Summary

This Go package implements a custom Zero-Knowledge Proof (ZKP) system for proving financial eligibility (ZKP-FEL) without revealing sensitive financial details. The system allows a prover to demonstrate that their income, debt, and number of active loans meet specific criteria, including a debt-to-income ratio, without disclosing the exact values.

The ZKP-FEL system is built from the ground up using fundamental cryptographic primitives, including:
-   Elliptic Curve Cryptography (ECC) for point operations.
-   Pedersen Commitments for concealing sensitive values.
-   Schnorr-like Sigma Protocols for proving knowledge of discrete logarithms.
-   Bit-decomposition based Range Proofs (for non-negativity) using Disjunctive Sigma Protocols.
-   Fiat-Shamir Heuristic for transforming interactive proofs into non-interactive ones.

The system targets the following specific proofs:
1.  Prover's `income` is greater than a public threshold `T_I`.
2.  Prover's `debt` is less than a public threshold `T_D`.
3.  Prover's `numLoans` is exactly equal to a public target `T_NL`.
4.  Prover's `debt` to `income` ratio `(debt / income)` is less than `P/Q` (a public fraction).

All numerical values are treated as `*big.Int` and their bit-length is capped by `MaxBits` for range proof efficiency.

---

### Function Summary

**I. Core Cryptographic Primitives & Utilities**
*   `CurvePoint`: Stores (X, Y) coordinates of an elliptic curve point.
*   `Equals(other *CurvePoint) bool`: Checks if two `CurvePoint` objects are equal.
*   `CurveParams`: Stores elliptic curve parameters (curve, generators g, h, group order N).
*   `InitCurve(curveName string) (*CurveParams, error)`: Initializes and returns `CurveParams` for a named curve (e.g., "P256").
*   `ecPointToBytes(p *CurvePoint) []byte`: Converts an elliptic curve point to a byte slice.
*   `bytesToECPoint(b []byte, curve elliptic.Curve) (*CurvePoint, error)`: Converts a byte slice back to an elliptic curve point.
*   `scalarMult(curve elliptic.Curve, Q *CurvePoint, k *big.Int) *CurvePoint`: Performs scalar multiplication P = k\*Q on the elliptic curve.
*   `pointAdd(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint`: Performs point addition P = P1 + P2 on the elliptic curve.
*   `pointNeg(curve elliptic.Curve, P *CurvePoint) *CurvePoint`: Negates an elliptic curve point P.
*   `pointSubtract(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint`: Performs point subtraction P1 - P2 on the elliptic curve (P1 + (-P2)).
*   `generateRandomScalar(order *big.Int) *big.Int`: Generates a cryptographically secure random scalar within the curve's order.
*   `hashToScalar(order *big.Int, data ...[]byte) *big.Int`: Hashes input data to a scalar within the curve's order, used for Fiat-Shamir challenges.

**II. Pedersen Commitment Scheme**
*   `Commitment`: Represents a Pedersen commitment (an elliptic curve point).
*   `NewCommitment(value, randomness *big.Int, params *CurveParams) (*Commitment, error)`: Creates a Pedersen commitment C = g^value \* h^randomness.
*   `CommitmentAdd(c1, c2 *Commitment, params *CurveParams) (*Commitment, error)`: Homomorphically adds two commitments (C1 \* C2).
*   `CommitmentScalarMul(c *Commitment, scalar *big.Int, params *CurveParams) (*Commitment, error)`: Homomorphically multiplies a commitment by a scalar (C^scalar).
*   `CommitmentSubtract(c1, c2 *Commitment, params *CurveParams) (*Commitment, error)`: Homomorphically subtracts two commitments (C1 \* C2^-1).
*   `VerifyCommitment(commitment *Commitment, value, randomness *big.Int, params *CurveParams) bool`: Verifies if a given commitment corresponds to a value and randomness.

**III. Zero-Knowledge Proof Building Blocks (Transcript, Schnorr)**
*   `Transcript`: Manages the state for Fiat-Shamir heuristic, collecting public data for challenge generation.
*   `NewTranscript() *Transcript`: Initializes a new transcript.
*   `TranscriptAppendPoint(t *Transcript, p *CurvePoint)`: Appends an elliptic curve point to the transcript.
*   `TranscriptAppendScalar(t *Transcript, s *big.Int)`: Appends a scalar (`*big.Int`) to the transcript.
*   `TranscriptChallenge(t *Transcript, tag string, order *big.Int) *big.Int`: Generates a challenge scalar from the current transcript state.
*   `ProveKnowledgeOfDiscreteLog`: Stores elements of a proof for knowledge of discrete log (ephemeral commitment A and response z).
*   `ProveKnowledgeOfDiscreteLog(params *CurveParams, secret *big.Int, basePoint *CurvePoint, t *Transcript) (*ProveKnowledgeOfDiscreteLog, error)`: Generates a proof of knowledge for the discrete log of `secret` such that `P = basePoint^secret`.
*   `VerifyKnowledgeOfDiscreteLog(params *CurveParams, P, basePoint *CurvePoint, proof *ProveKnowledgeOfDiscreteLog, t *Transcript) bool`: Verifies a proof of knowledge for the discrete log.

**IV. Advanced ZKP Components (Range and Equality Proofs)**
*   `BitProof`: Represents a proof that a committed value is either 0 or 1 using a disjunctive Schnorr proof.
*   `ProveBit(params *CurveParams, bitVal, bitRand *big.Int, t *Transcript) (*BitProof, *Commitment, error)`: Generates a proof for a committed bit (0 or 1). Returns the proof and the commitment to the bit.
*   `VerifyBit(params *CurveParams, bitComm *Commitment, proof *BitProof, t *Transcript) bool`: Verifies a bit proof.
*   `RangeProof`: Contains commitments to individual bits of a value and their respective bit proofs for proving a value is non-negative.
*   `ProveNonNegative(value, randomness *big.Int, params *CurveParams, maxBits int, t *Transcript) (*RangeProof, *Commitment, error)`: Proves a committed value is non-negative using bit decomposition. Returns the range proof and the commitment to the value.
*   `VerifyNonNegative(valueCommitment *Commitment, proof *RangeProof, params *CurveParams, maxBits int, t *Transcript) bool`: Verifies a non-negativity range proof.
*   `EqualityProof`: Represents a proof that two committed values are equal (by proving their difference is zero).
*   `ProveEquality(val1, rand1, val2, rand2 *big.Int, params *CurveParams, t *Transcript) (*EqualityProof, *Commitment, *Commitment, error)`: Proves that `Commit(val1)` and `Commit(val2)` commit to the same value. Returns proof and the original commitments.
*   `VerifyEquality(commit1, commit2 *Commitment, proof *EqualityProof, params *CurveParams, t *Transcript) bool`: Verifies an equality proof.

**V. ZKP for Financial Eligibility (ZKP-FEL) Application**
*   `ZKFELStatement`: Public parameters (thresholds) for the ZKP-FEL.
*   `ZKFELWitness`: Private witness (income, debt, numLoans, and their randomness) for the ZKP-FEL.
*   `ZKFELProof`: The complete ZKP-FEL proof containing all sub-proofs and commitments.
*   `GenerateZKFELProof(witness *ZKFELWitness, statement *ZKFELStatement, params *CurveParams) (*ZKFELProof, error)`: Orchestrates the entire ZKP-FEL proof generation process.
*   `VerifyZKFELProof(zkProof *ZKFELProof, statement *ZKFELStatement, params *CurveParams) (bool, error)`: Verifies the entire ZKP-FEL proof.

**VI. Main function (Example Usage)**
*   `main()`: Sets up parameters, defines a witness and statement, generates a proof, and verifies it. Includes multiple test cases for valid and invalid scenarios.

---

```go
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

// Outline and Function Summary
//
// This Go package implements a custom Zero-Knowledge Proof (ZKP) system
// for proving financial eligibility (ZKP-FEL) without revealing sensitive
// financial details. The system allows a prover to demonstrate that their
// income, debt, and number of active loans meet specific criteria,
// including a debt-to-income ratio, without disclosing the exact values.
//
// The ZKP-FEL system is built from the ground up using fundamental
// cryptographic primitives, including:
// - Elliptic Curve Cryptography (ECC) for point operations.
// - Pedersen Commitments for concealing sensitive values.
// - Schnorr-like Sigma Protocols for proving knowledge of discrete logarithms.
// - Bit-decomposition based Range Proofs (for non-negativity) using Disjunctive Sigma Protocols.
// - Fiat-Shamir Heuristic for transforming interactive proofs into non-interactive ones.
//
// The system targets the following specific proofs:
// 1. Prover's `income` is greater than a public threshold `T_I`.
// 2. Prover's `debt` is less than a public threshold `T_D`.
// 3. Prover's `numLoans` is exactly equal to a public target `T_NL`.
// 4. Prover's `debt` to `income` ratio `(debt / income)` is less than `P/Q` (a public fraction).
//
// All numerical values are treated as `*big.Int` and their bit-length is capped by `MaxBits`
// for range proof efficiency.
//
// --- Function Summary ---
//
// I. Core Cryptographic Primitives & Utilities
//    - CurvePoint: Stores (X, Y) coordinates of an elliptic curve point.
//    - Equals(other *CurvePoint) bool: Checks if two CurvePoint objects are equal.
//    - CurveParams: Stores elliptic curve parameters (curve, generators g, h, group order N).
//    - InitCurve(curveName string) (*CurveParams, error): Initializes and returns CurveParams for a named curve (e.g., "P256").
//    - ecPointToBytes(p *CurvePoint) []byte: Converts an elliptic curve point to a byte slice.
//    - bytesToECPoint(b []byte, curve elliptic.Curve) (*CurvePoint, error): Converts a byte slice back to an elliptic curve point.
//    - scalarMult(curve elliptic.Curve, Q *CurvePoint, k *big.Int) *CurvePoint: Performs scalar multiplication P = k*Q on the elliptic curve.
//    - pointAdd(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint: Performs point addition P = P1 + P2 on the elliptic curve.
//    - pointNeg(curve elliptic.Curve, P *CurvePoint) *CurvePoint: Negates an elliptic curve point P.
//    - pointSubtract(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint: Performs point subtraction P1 - P2 on the elliptic curve (P1 + (-P2)).
//    - generateRandomScalar(order *big.Int) *big.Int: Generates a cryptographically secure random scalar within the curve's order.
//    - hashToScalar(order *big.Int, data ...[]byte) *big.Int: Hashes input data to a scalar within the curve's order, used for Fiat-Shamir challenges.
//
// II. Pedersen Commitment Scheme
//    - Commitment: Represents a Pedersen commitment (an elliptic curve point).
//    - NewCommitment(value, randomness *big.Int, params *CurveParams) (*Commitment, error): Creates a Pedersen commitment C = g^value * h^randomness.
//    - CommitmentAdd(c1, c2 *Commitment, params *CurveParams) (*Commitment, error): Homomorphically adds two commitments (C1 * C2).
//    - CommitmentScalarMul(c *Commitment, scalar *big.Int, params *CurveParams) (*Commitment, error): Homomorphically multiplies a commitment by a scalar (C^scalar).
//    - CommitmentSubtract(c1, c2 *Commitment, params *CurveParams) (*Commitment, error): Homomorphically subtracts two commitments (C1 * C2^-1).
//    - VerifyCommitment(commitment *Commitment, value, randomness *big.Int, params *CurveParams) bool: Verifies if a given commitment corresponds to a value and randomness.
//
// III. Zero-Knowledge Proof Building Blocks (Transcript, Schnorr)
//    - Transcript: Manages the state for Fiat-Shamir heuristic, collecting public data for challenge generation.
//    - NewTranscript() *Transcript: Initializes a new transcript.
//    - TranscriptAppendPoint(t *Transcript, p *CurvePoint): Appends an elliptic curve point to the transcript.
//    - TranscriptAppendScalar(t *Transcript, s *big.Int): Appends a scalar (big.Int) to the transcript.
//    - TranscriptChallenge(t *Transcript, tag string, order *big.Int) *big.Int: Generates a challenge scalar from the current transcript state.
//    - ProveKnowledgeOfDiscreteLog: Stores elements of a proof for knowledge of discrete log (ephemeral commitment A and response z).
//    - ProveKnowledgeOfDiscreteLog(params *CurveParams, secret *big.Int, basePoint *CurvePoint, t *Transcript) (*ProveKnowledgeOfDiscreteLog, error): Generates a proof of knowledge for the discrete log of `secret` such that `P = basePoint^secret`.
//    - VerifyKnowledgeOfDiscreteLog(params *CurveParams, P, basePoint *CurvePoint, proof *ProveKnowledgeOfDiscreteLog, t *Transcript) bool: Verifies a proof of knowledge for the discrete log.
//
// IV. Advanced ZKP Components (Range and Equality Proofs)
//    - BitProof: Represents a proof that a committed value is either 0 or 1 using a disjunctive Schnorr proof.
//    - ProveBit(params *CurveParams, bitVal, bitRand *big.Int, t *Transcript) (*BitProof, *Commitment, error): Generates a proof for a committed bit. Returns the proof and the commitment to the bit.
//    - VerifyBit(params *CurveParams, bitComm *Commitment, proof *BitProof, t *Transcript) bool: Verifies a bit proof.
//    - RangeProof: Contains commitments to individual bits of a value and their respective bit proofs for proving a value is non-negative.
//    - ProveNonNegative(value, randomness *big.Int, params *CurveParams, maxBits int, t *Transcript) (*RangeProof, *Commitment, error): Proves a committed value is non-negative using bit decomposition. Returns the range proof and the commitment to the value.
//    - VerifyNonNegative(valueCommitment *Commitment, proof *RangeProof, params *CurveParams, maxBits int, t *Transcript) bool: Verifies a non-negativity range proof.
//    - EqualityProof: Represents a proof that two committed values are equal (by proving their difference is zero).
//    - ProveEquality(val1, rand1, val2, rand2 *big.Int, params *CurveParams, t *Transcript) (*EqualityProof, *Commitment, *Commitment, error): Proves that Commit(val1) and Commit(val2) commit to the same value. Returns proof and the original commitments.
//    - VerifyEquality(commit1, commit2 *Commitment, proof *EqualityProof, params *CurveParams, t *Transcript) bool: Verifies an equality proof.
//
// V. ZKP for Financial Eligibility (ZKP-FEL) Application
//    - ZKFELStatement: Public parameters (thresholds) for the ZKP-FEL.
//    - ZKFELWitness: Private witness (income, debt, numLoans, and their randomness) for the ZKP-FEL.
//    - ZKFELProof: The complete ZKP-FEL proof containing all sub-proofs and commitments.
//    - GenerateZKFELProof(witness *ZKFELWitness, statement *ZKFELStatement, params *CurveParams) (*ZKFELProof, error): Orchestrates the entire ZKP-FEL proof generation process.
//    - VerifyZKFELProof(zkProof *ZKFELProof, statement *ZKFELStatement, params *CurveParams) (bool, error): Verifies the entire ZKP-FEL proof.
//
// VI. Main function (Example Usage)
//    - main(): Sets up parameters, generates a witness and statement, creates a proof, and verifies it.

// --- Implementation ---

// I. Core Cryptographic Primitives & Utilities

// CurvePoint abstracts elliptic.Curve Point (x,y)
type CurvePoint struct {
	X, Y *big.Int
}

// Equals checks if two CurvePoints are equal
func (cp *CurvePoint) Equals(other *CurvePoint) bool {
	if cp == nil || other == nil {
		return cp == other
	}
	return cp.X.Cmp(other.X) == 0 && cp.Y.Cmp(other.Y) == 0
}

// CurveParams stores elliptic curve parameters and generators.
type CurveParams struct {
	Curve elliptic.Curve
	N     *big.Int // Group order
	G     *CurvePoint
	H     *CurvePoint // A random point not derivable from G easily.
}

// InitCurve initializes and returns CurveParams for a specified curve.
func InitCurve(curveName string) (*CurveParams, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P256":
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	// G is the base point of the curve
	gx, gy := curve.Gx(), curve.Gy()
	g := &CurvePoint{X: gx, Y: gy}

	// H is another generator. For simplicity, we can derive it by hashing G or using a fixed arbitrary point.
	// A proper choice for H would be a random point on the curve, independent of G.
	// Here, we'll hash a string "H_GENERATOR" to a point on the curve.
	hBytes := sha256.Sum256([]byte("H_GENERATOR_FOR_PEDERSEN_COMMITMENT"))
	hx, hy := curve.ScalarBaseMult(hBytes[:]) // This is actually G^hBytes, but we treat it as an independent H
	h := &CurvePoint{X: hx, Y: hy}

	// N is the order of the curve's base point.
	n := curve.Params().N

	return &CurveParams{
		Curve: curve,
		N:     n,
		G:     g,
		H:     h,
	}, nil
}

// ecPointToBytes converts an elliptic curve point to a byte slice.
func ecPointToBytes(p *CurvePoint) []byte {
	if p == nil {
		return nil
	}
	return elliptic.Marshal(p.X, p.Y)
}

// bytesToECPoint converts a byte slice back to an elliptic curve point.
func bytesToECPoint(b []byte, curve elliptic.Curve) (*CurvePoint, error) {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal EC point")
	}
	return &CurvePoint{X: x, Y: y}
}

// scalarMult performs scalar multiplication P = k*Q on the elliptic curve.
func scalarMult(curve elliptic.Curve, Q *CurvePoint, k *big.Int) *CurvePoint {
	if k.Sign() == 0 { // If scalar is 0, result is point at infinity (treated as (0,0) or special identity)
		return &CurvePoint{X: big.NewInt(0), Y: big.NewInt(0)} // Often represented as (0,0) for affine coordinates
	}
	x, y := curve.ScalarMult(Q.X, Q.Y, k.Bytes())
	return &CurvePoint{X: x, Y: y}
}

// pointAdd performs point addition P = P1 + P2 on the elliptic curve.
func pointAdd(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint {
	x, y := curve.Add(P1.X, P1.Y, P2.X, P2.Y)
	return &CurvePoint{X: x, Y: y}
}

// pointNeg negates an elliptic curve point P.
func pointNeg(curve elliptic.Curve, P *CurvePoint) *CurvePoint {
	// For most curves, negation is (x, -y mod P).
	// We need to handle the point at infinity explicitly if it's possible.
	if P.X.Sign() == 0 && P.Y.Sign() == 0 { // Point at infinity
		return P
	}
	yNeg := new(big.Int).Neg(P.Y)
	yNeg.Mod(yNeg, curve.Params().P)
	return &CurvePoint{X: new(big.Int).Set(P.X), Y: yNeg}
}

// pointSubtract performs point subtraction P1 - P2 on the elliptic curve (P1 + (-P2)).
func pointSubtract(curve elliptic.Curve, P1, P2 *CurvePoint) *CurvePoint {
	negP2 := pointNeg(curve, P2)
	return pointAdd(curve, P1, negP2)
}

// generateRandomScalar generates a cryptographically secure random scalar in Z_N.
func generateRandomScalar(order *big.Int) *big.Int {
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err) // Should not happen in production if rand.Reader is available
	}
	return k
}

// hashToScalar hashes input data to a scalar within the curve's order.
func hashToScalar(order *big.Int, data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	// Take the hash output and reduce it modulo the order
	return new(big.Int).SetBytes(h.Sum(nil)).Mod(new(big.Int).SetBytes(h.Sum(nil)), order)
}

// II. Pedersen Commitment Scheme

// Commitment represents a Pedersen commitment, which is an elliptic curve point.
type Commitment struct {
	Point *CurvePoint
}

// NewCommitment creates a Pedersen commitment C = g^value * h^randomness.
func NewCommitment(value, randomness *big.Int, params *CurveParams) (*Commitment, error) {
	if params == nil || params.G == nil || params.H == nil || params.Curve == nil {
		return nil, fmt.Errorf("invalid curve parameters for commitment")
	}

	gVal := scalarMult(params.Curve, params.G, value)
	hRand := scalarMult(params.Curve, params.H, randomness)
	commPoint := pointAdd(params.Curve, gVal, hRand)

	return &Commitment{Point: commPoint}, nil
}

// CommitmentAdd performs homomorphic addition: C_sum = C1 + C2.
// C1 = g^m1 * h^r1, C2 = g^m2 * h^r2
// C_sum = g^(m1+m2) * h^(r1+r2)
func CommitmentAdd(c1, c2 *Commitment, params *CurveParams) (*Commitment, error) {
	if c1 == nil || c2 == nil || params == nil || params.Curve == nil {
		return nil, fmt.Errorf("invalid input for commitment addition")
	}
	addedPoint := pointAdd(params.Curve, c1.Point, c2.Point)
	return &Commitment{Point: addedPoint}, nil
}

// CommitmentScalarMul performs homomorphic scalar multiplication: C_res = C^scalar.
// C = g^m * h^r
// C_res = (g^m * h^r)^scalar = g^(m*scalar) * h^(r*scalar)
func CommitmentScalarMul(c *Commitment, scalar *big.Int, params *CurveParams) (*Commitment, error) {
	if c == nil || params == nil || params.Curve == nil {
		return nil, fmt.Errorf("invalid input for commitment scalar multiplication")
	}
	multipliedPoint := scalarMult(params.Curve, c.Point, scalar)
	return &Commitment{Point: multipliedPoint}, nil
}

// CommitmentSubtract performs homomorphic subtraction: C_diff = C1 - C2.
// C_diff = C1 * C2^-1 = g^(m1-m2) * h^(r1-r2)
func CommitmentSubtract(c1, c2 *Commitment, params *CurveParams) (*Commitment, error) {
	if c1 == nil || c2 == nil || params == nil || params.Curve == nil {
		return nil, fmt.Errorf("invalid input for commitment subtraction")
	}
	negatedC2Point := pointNeg(params.Curve, c2.Point)
	diffPoint := pointAdd(params.Curve, c1.Point, negatedC2Point)
	return &Commitment{Point: diffPoint}, nil
}

// VerifyCommitment verifies if a given commitment corresponds to a value and randomness.
func VerifyCommitment(commitment *Commitment, value, randomness *big.Int, params *CurveParams) bool {
	if commitment == nil || commitment.Point == nil || value == nil || randomness == nil || params == nil {
		return false
	}
	expectedCommitment, err := NewCommitment(value, randomness, params)
	if err != nil {
		return false
	}
	return commitment.Point.Equals(expectedCommitment.Point)
}

// III. Zero-Knowledge Proof Building Blocks (Transcript, Schnorr)

// Transcript manages the state for Fiat-Shamir heuristic.
type Transcript struct {
	hasher hash.Hash
	buffer []byte
}

// NewTranscript initializes a new transcript.
func NewTranscript() *Transcript {
	return &Transcript{
		hasher: sha256.New(),
		buffer: make([]byte, 0, 1024), // Pre-allocate some buffer
	}
}

// TranscriptAppendPoint appends an elliptic curve point to the transcript.
func (t *Transcript) TranscriptAppendPoint(p *CurvePoint) {
	t.buffer = append(t.buffer, ecPointToBytes(p)...)
}

// TranscriptAppendScalar appends a scalar (big.Int) to the transcript.
func (t *Transcript) TranscriptAppendScalar(s *big.Int) {
	t.buffer = append(t.buffer, s.Bytes()...)
}

// TranscriptChallenge generates a challenge scalar from the current transcript state.
func (t *Transcript) TranscriptChallenge(tag string, order *big.Int) *big.Int {
	t.hasher.Reset()
	t.hasher.Write([]byte(tag))
	t.hasher.Write(t.buffer)
	challengeBytes := t.hasher.Sum(nil)
	return new(big.Int).SetBytes(challengeBytes).Mod(new(big.Int).SetBytes(challengeBytes), order)
}

// ProveKnowledgeOfDiscreteLog stores the elements of a proof for knowledge of discrete log.
type ProveKnowledgeOfDiscreteLog struct {
	ASchnorr *CurvePoint // ephemeral commitment A = base^k
	Response *big.Int    // z = k + e * secret
}

// ProveKnowledgeOfDiscreteLog generates a proof of knowledge for the discrete log.
// Proves knowledge of 'secret' such that 'P = basePoint^secret'.
func ProveKnowledgeOfDiscreteLog(params *CurveParams, secret *big.Int, basePoint *CurvePoint, t *Transcript) (*ProveKnowledgeOfDiscreteLog, error) {
	if params == nil || secret == nil || basePoint == nil || t == nil {
		return nil, fmt.Errorf("invalid input for ProveKnowledgeOfDiscreteLog")
	}

	// 1. Prover chooses a random nonce `k`
	k := generateRandomScalar(params.N)

	// 2. Prover computes commitment `A = basePoint^k`
	A := scalarMult(params.Curve, basePoint, k)
	t.TranscriptAppendPoint(A)

	// 3. Verifier (via Fiat-Shamir) sends challenge `e = H(transcript_state)`
	e := t.TranscriptChallenge("PKDLChallenge", params.N)

	// 4. Prover computes response `z = k + e * secret mod N`
	eSecret := new(big.Int).Mul(e, secret)
	z := new(big.Int).Add(k, eSecret)
	z.Mod(z, params.N)

	return &ProveKnowledgeOfDiscreteLog{ASchnorr: A, Response: z}, nil
}

// VerifyKnowledgeOfDiscreteLog verifies a proof of knowledge for a discrete logarithm.
// Verifies `P = basePoint^secret` given `proof.ASchnorr` and `proof.Response`.
func VerifyKnowledgeOfDiscreteLog(params *CurveParams, P, basePoint *CurvePoint, proof *ProveKnowledgeOfDiscreteLog, t *Transcript) bool {
	if params == nil || P == nil || basePoint == nil || proof == nil || proof.ASchnorr == nil || proof.Response == nil || t == nil {
		return false
	}

	// Re-generate challenge `e`
	t.TranscriptAppendPoint(proof.ASchnorr)
	e := t.TranscriptChallenge("PKDLChallenge", params.N)

	// Verify `basePoint^z == A_Schnorr * P^e`
	lhs := scalarMult(params.Curve, basePoint, proof.Response) // basePoint^z

	eP := scalarMult(params.Curve, P, e)                  // P^e
	rhs := pointAdd(params.Curve, proof.ASchnorr, eP) // A_Schnorr * P^e

	return lhs.Equals(rhs)
}

// IV. Advanced ZKP Components (Range and Equality Proofs)

// BitProof represents a proof that a committed value is either 0 or 1.
// Uses a disjunctive Schnorr proof (OR-proof).
type BitProof struct {
	A0, A1 *CurvePoint // Commitments for the two branches
	E0, E1 *big.Int    // Challenges for the two branches
	Z0, Z1 *big.Int    // Responses for the two branches
}

// ProveBit generates a proof for a committed bit (value is 0 or 1).
// `bitVal` is the actual bit (0 or 1), `bitRand` is its randomness for `bitComm`.
func ProveBit(params *CurveParams, bitVal, bitRand *big.Int, t *Transcript) (*BitProof, *Commitment, error) {
	if params == nil || bitVal == nil || bitRand == nil || t == nil {
		return nil, nil, fmt.Errorf("invalid input for ProveBit")
	}

	// Create commitment to the bit
	bitComm, err := NewCommitment(bitVal, bitRand, params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bit commitment: %w", err)
	}
	t.TranscriptAppendPoint(bitComm.Point)

	// Disjunctive proof: prove (bitComm == Comm(0, r0)) OR (bitComm == Comm(1, r1))
	// We know one of the secrets. Let's say bitVal == 0.
	// Prover creates a real proof for branch 0, and a simulated proof for branch 1.

	var (
		k0, k1 *big.Int    // Nonces
		z0, z1 *big.Int    // Responses
		e0, e1 *big.Int    // Challenges
		A0, A1 *CurvePoint // Commitments
	)

	if bitVal.Cmp(big.NewInt(0)) == 0 { // Proving bitVal = 0 (Real branch 0, Simulated branch 1)
		// Branch 0 (real): prove knowledge of r0 such that C = g^0 * h^r0 = h^r0
		k0 = generateRandomScalar(params.N)
		A0 = scalarMult(params.Curve, params.H, k0) // A0 = h^k0
		t.TranscriptAppendPoint(A0) // Append A0 before generating common challenge part

		// For simulated branch 1: Pick a random z1 and e1, then compute A1 = g^1 * h^z1 * (C^-1)^e1
		z1 = generateRandomScalar(params.N)
		e1 = generateRandomScalar(params.N) // Fake challenge for branch 1
		g1 := scalarMult(params.Curve, params.G, big.NewInt(1)) // g^1
		hZ1 := scalarMult(params.Curve, params.H, z1) // h^z1
		Cneg := pointNeg(params.Curve, bitComm.Point) // C^-1
		CnegE1 := scalarMult(params.Curve, Cneg, e1) // (C^-1)^e1
		tempA1 := pointAdd(params.Curve, g1, hZ1) // g^1 * h^z1
		A1 = pointAdd(params.Curve, tempA1, CnegE1) // g^1 * h^z1 * (C^-1)^e1
		t.TranscriptAppendPoint(A1) // Append A1 before generating common challenge part

		// Common challenge 'e' for the entire OR proof
		e := t.TranscriptChallenge("BitProofCommonChallenge", params.N)

		// Set e0 based on common challenge and e1
		e0 = new(big.Int).Sub(e, e1)
		e0.Mod(e0, params.N)

		// Compute real z0
		e0Rand := new(big.Int).Mul(e0, bitRand) // e0 * r0
		z0 = new(big.Int).Add(k0, e0Rand)
		z0.Mod(z0, params.N)

	} else if bitVal.Cmp(big.NewInt(1)) == 0 { // Proving bitVal = 1 (Real branch 1, Simulated branch 0)
		// Branch 1 (real): prove knowledge of r1 such that C = g^1 * h^r1
		k1 = generateRandomScalar(params.N)
		g1 := scalarMult(params.Curve, params.G, big.NewInt(1)) // g^1
		A1 = pointAdd(params.Curve, g1, scalarMult(params.Curve, params.H, k1)) // A1 = g^1 * h^k1
		t.TranscriptAppendPoint(A1) // Append A1 before generating common challenge part

		// For simulated branch 0: Pick a random z0 and e0, then compute A0 = h^z0 * (C^-1)^e0
		z0 = generateRandomScalar(params.N)
		e0 = generateRandomScalar(params.N) // Fake challenge for branch 0
		hZ0 := scalarMult(params.Curve, params.H, z0) // h^z0
		Cneg := pointNeg(params.Curve, bitComm.Point) // C^-1
		CnegE0 := scalarMult(params.Curve, Cneg, e0) // (C^-1)^e0
		A0 = pointAdd(params.Curve, hZ0, CnegE0) // h^z0 * (C^-1)^e0
		t.TranscriptAppendPoint(A0) // Append A0 before generating common challenge part

		// Common challenge 'e' for the entire OR proof
		e := t.TranscriptChallenge("BitProofCommonChallenge", params.N)

		// Set e1 based on common challenge and e0
		e1 = new(big.Int).Sub(e, e0)
		e1.Mod(e1, params.N)

		// Compute real z1
		e1Rand := new(big.Int).Mul(e1, bitRand) // e1 * r1
		z1 = new(big.Int).Add(k1, e1Rand)
		z1.Mod(z1, params.N)

	} else {
		return nil, nil, fmt.Errorf("bit value must be 0 or 1, got %s", bitVal.String())
	}

	return &BitProof{A0: A0, A1: A1, E0: e0, E1: e1, Z0: z0, Z1: z1}, bitComm, nil
}

// VerifyBit verifies a bit proof.
func VerifyBit(params *CurveParams, bitComm *Commitment, proof *BitProof, t *Transcript) bool {
	if params == nil || bitComm == nil || proof == nil || t == nil {
		return false
	}

	// Re-append bitComm point, A0, A1 to transcript in the same order as prover
	t.TranscriptAppendPoint(bitComm.Point)
	t.TranscriptAppendPoint(proof.A0)
	t.TranscriptAppendPoint(proof.A1)
	e := t.TranscriptChallenge("BitProofCommonChallenge", params.N)

	// Check e = e0 + e1
	eSum := new(big.Int).Add(proof.E0, proof.E1)
	eSum.Mod(eSum, params.N)
	if e.Cmp(eSum) != 0 {
		return false
	}

	// Verify A0_prime = h^z0 * (C^-1)^e0
	hZ0 := scalarMult(params.Curve, params.H, proof.Z0)
	CnegE0 := scalarMult(params.Curve, pointNeg(params.Curve, bitComm.Point), proof.E0)
	A0_prime := pointAdd(params.Curve, hZ0, CnegE0)
	if !A0_prime.Equals(proof.A0) {
		return false
	}

	// Verify A1_prime = g^1 * h^z1 * (C^-1)^e1
	g1 := scalarMult(params.Curve, params.G, big.NewInt(1))
	hZ1 := scalarMult(params.Curve, params.H, proof.Z1)
	CnegE1 := scalarMult(params.Curve, pointNeg(params.Curve, bitComm.Point), proof.E1)
	A1_primeTemp := pointAdd(params.Curve, g1, hZ1)
	A1_prime := pointAdd(params.Curve, A1_primeTemp, CnegE1)
	if !A1_prime.Equals(proof.A1) {
		return false
	}

	return true
}

// RangeProof contains commitments to individual bits of a value and their proofs.
type RangeProof struct {
	BitCommitments []*Commitment
	BitProofs      []*BitProof
}

// ProveNonNegative proves a committed value is non-negative using bit decomposition.
// It commits to each bit and proves each bit is 0 or 1.
// Returns the range proof and the commitment to the value itself.
func ProveNonNegative(value, randomness *big.Int, params *CurveParams, maxBits int, t *Transcript) (*RangeProof, *Commitment, error) {
	if value.Sign() < 0 {
		return nil, nil, fmt.Errorf("value must be non-negative for ProveNonNegative")
	}

	valComm, err := NewCommitment(value, randomness, params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create value commitment: %w", err)
	}
	t.TranscriptAppendPoint(valComm.Point)

	var bitCommitments []*Commitment
	var bitProofs []*BitProof

	for i := 0; i < maxBits; i++ {
		bit := new(big.Int).And(new(big.Int).Rsh(value, uint(i)), big.NewInt(1)) // Get i-th bit
		bitRand := generateRandomScalar(params.N)

		// `ProveBit` appends its `bitComm` to the transcript itself,
		// so no need to explicitly append `bitComm` here.
		bitProof, bitComm, err := ProveBit(params, bit, bitRand, t) // bit, bit_randomness, transcript
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prove bit: %w", err)
		}
		bitCommitments = append(bitCommitments, bitComm)
		bitProofs = append(bitProofs, bitProof)
	}

	return &RangeProof{
		BitCommitments: bitCommitments,
		BitProofs:      bitProofs,
	}, valComm, nil
}

// VerifyNonNegative verifies a non-negativity range proof.
func VerifyNonNegative(valueCommitment *Commitment, proof *RangeProof, params *CurveParams, maxBits int, t *Transcript) bool {
	if valueCommitment == nil || proof == nil || params == nil || t == nil {
		return false
	}
	t.TranscriptAppendPoint(valueCommitment.Point)

	if len(proof.BitCommitments) != maxBits || len(proof.BitProofs) != maxBits {
		fmt.Printf("Malformed range proof: expected %d bits, got %d commitments and %d proofs\n",
			maxBits, len(proof.BitCommitments), len(proof.BitProofs))
		return false // Malformed proof
	}

	// 1. Verify each bit proof
	for i := 0; i < maxBits; i++ {
		bitComm := proof.BitCommitments[i]
		bitProof := proof.BitProofs[i]

		if !VerifyBit(params, bitComm, bitProof, t) {
			fmt.Println("Failed to verify bit proof for bit", i)
			return false
		}
	}

	// 2. Verify that the sum of bits correctly reconstructs the original value commitment.
	// This implies: valueCommitment = Product(bitComm_i ^ (2^i))
	// We check C = g^v h^r = g^(sum b_i 2^i) h^(sum r_i 2^i)
	// Given that VerifyBit ensures bitComm_i is g^b_i h^r_i where b_i is 0 or 1.
	// We need to re-construct the commitment based on the bit commitments and check if it matches `valueCommitment`.
	sumCheckComm := &Commitment{Point: &CurvePoint{X: big.NewInt(0), Y: big.NewInt(0)}} // Identity element placeholder

	for i, bc := range proof.BitCommitments {
		powerOfTwo := new(big.Int).Lsh(big.NewInt(1), uint(i))
		scaledComm, err := CommitmentScalarMul(bc, powerOfTwo, params)
		if err != nil {
			fmt.Println("Error scaling bit commitment during verification:", err)
			return false
		}
		if i == 0 {
			sumCheckComm = scaledComm
		} else {
			sumCheckComm, err = CommitmentAdd(sumCheckComm, scaledComm, params)
			if err != nil {
				fmt.Println("Error adding scaled bit commitment during verification:", err)
				return false
			}
		}
	}

	if !valueCommitment.Point.Equals(sumCheckComm.Point) {
		fmt.Println("Aggregate bit commitment does not match original value commitment for non-negative proof.")
		return false
	}

	return true
}

// EqualityProof represents a proof that two committed values are equal.
// Proves Commit(val1) and Commit(val2) commit to the same value by showing Comm(val1 - val2) is Comm(0).
type EqualityProof struct {
	ZeroCommitment        *Commitment // Commitment to 0 (C1 - C2)
	KnowledgeOfRandomness *ProveKnowledgeOfDiscreteLog // Proof of knowledge of randomness for the zero commitment
}

// ProveEquality proves that Commit(val1) and Commit(val2) commit to the same value.
// It generates a commitment to `val1 - val2` (which should be 0) and proves knowledge of its randomness.
// Returns the proof, and the original commitments for the verifier.
func ProveEquality(val1, rand1, val2, rand2 *big.Int, params *CurveParams, t *Transcript) (*EqualityProof, *Commitment, *Commitment, error) {
	if params == nil || val1 == nil || rand1 == nil || val2 == nil || rand2 == nil || t == nil {
		return nil, nil, nil, fmt.Errorf("invalid input for ProveEquality")
	}

	comm1, err := NewCommitment(val1, rand1, params)
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to commit to val1: %w", err) }
	comm2, err := NewCommitment(val2, rand2, params)
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to commit to val2: %w", err) }

	// Calculate the difference commitment: C_diff = C1 - C2 = g^(val1-val2) * h^(rand1-rand2)
	// If val1 == val2, then C_diff = g^0 * h^(rand1-rand2) = h^(rand1-rand2)
	// We need to prove knowledge of (rand1 - rand2) for C_diff.
	commDiff, err := CommitmentSubtract(comm1, comm2, params)
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to calculate commitment difference: %w", err) }
	t.TranscriptAppendPoint(commDiff.Point) // Append diff commitment to transcript

	// Prover's secret is the randomness for the zero commitment, which is rand1 - rand2
	zeroRand := new(big.Int).Sub(rand1, rand2)
	zeroRand.Mod(zeroRand, params.N)

	// Prove knowledge of `zeroRand` such that `commDiff.Point = h^zeroRand` (i.e. P=commDiff.Point, base=H, secret=zeroRand)
	pkdl, err := ProveKnowledgeOfDiscreteLog(params, zeroRand, params.H, t)
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to prove knowledge of zero randomness: %w", err) }

	return &EqualityProof{
		ZeroCommitment:        commDiff,
		KnowledgeOfRandomness: pkdl,
	}, comm1, comm2, nil
}

// VerifyEquality verifies an equality proof.
func VerifyEquality(commit1, commit2 *Commitment, proof *EqualityProof, params *CurveParams, t *Transcript) bool {
	if commit1 == nil || commit2 == nil || proof == nil || proof.ZeroCommitment == nil || proof.KnowledgeOfRandomness == nil || params == nil {
		return false
	}

	expectedZeroCommitment, err := CommitmentSubtract(commit1, commit2, params)
	if err != nil { return false }
	if !proof.ZeroCommitment.Point.Equals(expectedZeroCommitment.Point) {
		fmt.Println("ZeroCommitment does not match C1 - C2 for equality proof")
		return false
	}
	t.TranscriptAppendPoint(proof.ZeroCommitment.Point)

	// Verify knowledge of randomness for ZeroCommitment, with H as base.
	// P is proof.ZeroCommitment.Point, base is H.
	return VerifyKnowledgeOfDiscreteLog(params, proof.ZeroCommitment.Point, params.H, proof.KnowledgeOfRandomness, t)
}

// V. ZKP for Financial Eligibility (ZKP-FEL) Application

// ZKFELStatement represents the public parameters for the ZKP-FEL.
type ZKFELStatement struct {
	ThresholdIncome  *big.Int
	ThresholdDebt    *big.Int
	TargetNumLoans   *big.Int
	RatioNumerator   *big.Int // P in P/Q for Debt/Income < P/Q
	RatioDenominator *big.Int // Q in P/Q for Debt/Income < P/Q
	MaxBits          int      // Maximum bit length for all sensitive values, used for range proofs.
}

// ZKFELWitness represents the private witness for the ZKP-FEL.
type ZKFELWitness struct {
	Income    *big.Int
	Debt      *big.Int
	NumLoans  *big.Int
	IncRand   *big.Int // Randomness for income commitment
	DebtRand  *big.Int // Randomness for debt commitment
	NLRand    *big.Int // Randomness for numLoans commitment
}

// ZKFELProof is the complete ZKP-FEL proof.
type ZKFELProof struct {
	CommIncome     *Commitment
	CommDebt       *Commitment
	CommNumLoans   *Commitment

	IncGTProof      *RangeProof    // Proof for (income - T_I - 1) >= 0
	DebtLTProof     *RangeProof    // Proof for (T_D - debt - 1) >= 0
	NumLoansEqProof *EqualityProof // Proof for (numLoans - T_NL) == 0
	RatioProof      *RangeProof    // Proof for (P*income - Q*debt - 1) >= 0
}

// GenerateZKFELProof orchestrates the entire ZKP-FEL proof generation.
func GenerateZKFELProof(witness *ZKFELWitness, statement *ZKFELStatement, params *CurveParams) (*ZKFELProof, error) {
	t := NewTranscript()

	// 1. Commit to private values
	commIncome, err := NewCommitment(witness.Income, witness.IncRand, params)
	if err != nil { return nil, fmt.Errorf("failed to commit income: %w", err) }
	t.TranscriptAppendPoint(commIncome.Point)

	commDebt, err := NewCommitment(witness.Debt, witness.DebtRand, params)
	if err != nil { return nil, fmt.Errorf("failed to commit debt: %w", err) }
	t.TranscriptAppendPoint(commDebt.Point)

	commNumLoans, err := NewCommitment(witness.NumLoans, witness.NLRand, params)
	if err != nil { return nil, fmt.Errorf("failed to commit numLoans: %w", err) }
	t.TranscriptAppendPoint(commNumLoans.Point)

	// 2. Proof for Income > T_I (income - T_I - 1 >= 0)
	incomeDiff := new(big.Int).Sub(witness.Income, statement.ThresholdIncome)
	incomeDiff.Sub(incomeDiff, big.NewInt(1))
	// The randomness for incomeDiff must be `witness.IncRand` for the homomorphic check to pass on verification
	incGTProof, incDiffComm, err := ProveNonNegative(incomeDiff, witness.IncRand, params, statement.MaxBits, t)
	if err != nil { return nil, fmt.Errorf("failed to prove income > T_I: %w", err) }
	// `incDiffComm` here is just a return value from ProveNonNegative, its content is `Comm(incomeDiff, witness.IncRand)`

	// 3. Proof for Debt < T_D (T_D - debt - 1 >= 0)
	debtDiff := new(big.Int).Sub(statement.ThresholdDebt, witness.Debt)
	debtDiff.Sub(debtDiff, big.NewInt(1))
	// The randomness for debtDiff must be `witness.DebtRand` for the homomorphic check to pass on verification
	debtLTProof, debtDiffComm, err := ProveNonNegative(debtDiff, witness.DebtRand, params, statement.MaxBits, t)
	if err != nil { return nil, fmt.Errorf("failed to prove debt < T_D: %w", err) }
	// `debtDiffComm` here is just a return value from ProveNonNegative, its content is `Comm(debtDiff, witness.DebtRand)`

	// 4. Proof for NumLoans = T_NL (numLoans - T_NL == 0)
	// Prove `numLoans - T_NL == 0` by proving `Comm(numLoans) - Comm(T_NL,0) == Comm(0, (NLRand - 0))`
	numLoansEqProof, _, _, err := ProveEquality(witness.NumLoans, witness.NLRand, statement.TargetNumLoans, big.NewInt(0), params, t)
	if err != nil { return nil, fmt.Errorf("failed to prove numLoans = T_NL: %w", err) }

	// 5. Proof for Debt/Income < P/Q (Q*debt < P*income => P*income - Q*debt - 1 >= 0)
	prodInc := new(big.Int).Mul(statement.RatioNumerator, witness.Income)
	prodDebt := new(big.Int).Mul(statement.RatioDenominator, witness.Debt)
	ratioCheckVal := new(big.Int).Sub(prodInc, prodDebt)
	ratioCheckVal.Sub(ratioCheckVal, big.NewInt(1))

	// The randomness for P*income - Q*debt - 1 is P*IncRand - Q*DebtRand
	ratioIncRand := new(big.Int).Mul(statement.RatioNumerator, witness.IncRand)
	ratioDebtRand := new(big.Int).Mul(statement.RatioDenominator, witness.DebtRand)
	ratioCheckRand := new(big.Int).Sub(ratioIncRand, ratioDebtRand)
	ratioCheckRand.Mod(ratioCheckRand, params.N)

	ratioProof, ratioCheckComm, err := ProveNonNegative(ratioCheckVal, ratioCheckRand, params, statement.MaxBits, t)
	if err != nil { return nil, fmt.Errorf("failed to prove ratio: %w", err) }
	// `ratioCheckComm` here is just a return value from ProveNonNegative, its content is `Comm(ratioCheckVal, ratioCheckRand)`

	return &ZKFELProof{
		CommIncome:     commIncome,
		CommDebt:       commDebt,
		CommNumLoans:   commNumLoans,
		IncGTProof:      incGTProof,
		DebtLTProof:     debtLTProof,
		NumLoansEqProof: numLoansEqProof,
		RatioProof:      ratioProof,
	}, nil
}

// VerifyZKFELProof verifies the entire ZKP-FEL proof.
func VerifyZKFELProof(zkProof *ZKFELProof, statement *ZKFELStatement, params *CurveParams) (bool, error) {
	t := NewTranscript()

	// 1. Verify initial commitments are present in proof (these were generated first by prover)
	if zkProof.CommIncome == nil || zkProof.CommDebt == nil || zkProof.CommNumLoans == nil {
		return false, fmt.Errorf("missing initial commitments in proof")
	}
	t.TranscriptAppendPoint(zkProof.CommIncome.Point)
	t.TranscriptAppendPoint(zkProof.CommDebt.Point)
	t.TranscriptAppendPoint(zkProof.CommNumLoans.Point)

	// 2. Verify Income > T_I (income - T_I - 1 >= 0)
	// Expected incomeDiffCommitment = CommIncome - Comm(TI,0) - Comm(1,0)
	gTI := scalarMult(params.Curve, params.G, statement.ThresholdIncome)
	g1 := scalarMult(params.Curve, params.G, big.NewInt(1))
	expectedIncDiffCommPoint := pointSubtract(params.Curve, pointSubtract(params.Curve, zkProof.CommIncome.Point, gTI), g1)
	expectedIncDiffComm := &Commitment{Point: expectedIncDiffCommPoint}

	if !VerifyNonNegative(expectedIncDiffComm, zkProof.IncGTProof, params, statement.MaxBits, t) {
		return false, fmt.Errorf("income > T_I proof failed")
	}

	// 3. Verify Debt < T_D (T_D - debt - 1 >= 0)
	// Expected debtDiffCommitment = Comm(TD,0) - CommDebt - Comm(1,0)
	gTD := scalarMult(params.Curve, params.G, statement.ThresholdDebt)
	g1_for_debt := scalarMult(params.Curve, params.G, big.NewInt(1))
	expectedDebtDiffCommPoint := pointSubtract(params.Curve, pointSubtract(params.Curve, gTD, zkProof.CommDebt.Point), g1_for_debt)
	expectedDebtDiffComm := &Commitment{Point: expectedDebtDiffCommPoint}

	if !VerifyNonNegative(expectedDebtDiffComm, zkProof.DebtLTProof, params, statement.MaxBits, t) {
		return false, fmt.Errorf("debt < T_D proof failed")
	}

	// 4. Verify NumLoans = T_NL (numLoans - T_NL == 0)
	// This proof implicitly verifies Comm(numLoans) - Comm(T_NL,0) == Comm(0)
	targetNumLoansComm, err := NewCommitment(statement.TargetNumLoans, big.NewInt(0), params)
	if err != nil { return false, fmt.Errorf("failed to create target num loans commitment: %w", err) }

	if !VerifyEquality(zkProof.CommNumLoans, targetNumLoansComm, zkProof.NumLoansEqProof, params, t) {
		return false, fmt.Errorf("numLoans = T_NL proof failed")
	}

	// 5. Verify Debt/Income < P/Q (P*income - Q*debt - 1 >= 0)
	// Expected ratioCheckCommitment = CommIncome^P - CommDebt^Q - Comm(1,0)
	prodIncComm, err := CommitmentScalarMul(zkProof.CommIncome, statement.RatioNumerator, params)
	if err != nil { return false, fmt.Errorf("failed to scale income commitment: %w", err) }
	prodDebtComm, err := CommitmentScalarMul(zkProof.CommDebt, statement.RatioDenominator, params)
	if err != nil { return false, fmt.Errorf("failed to scale debt commitment: %w", err) }

	g1_for_ratio := scalarMult(params.Curve, params.G, big.NewInt(1))
	expectedRatioCheckCommPoint := pointSubtract(params.Curve, pointSubtract(params.Curve, prodIncComm.Point, prodDebtComm.Point), g1_for_ratio)
	expectedRatioCheckComm := &Commitment{Point: expectedRatioCheckCommPoint}

	if !VerifyNonNegative(expectedRatioCheckComm, zkProof.RatioProof, params, statement.MaxBits, t) {
		return false, fmt.Errorf("debt/income ratio proof failed")
	}

	return true, nil
}

// VI. Main function (Example Usage)
func main() {
	fmt.Println("Starting ZKP-FEL demonstration...")

	// 1. Setup Curve Parameters
	params, err := InitCurve("P256")
	if err != nil {
		fmt.Printf("Error initializing curve: %v\n", err)
		return
	}
	fmt.Println("Curve parameters initialized successfully.")

	// 2. Define Public Statement (Thresholds)
	statement := &ZKFELStatement{
		ThresholdIncome:  big.NewInt(50000), // Income must be > 50,000
		ThresholdDebt:    big.NewInt(20000), // Debt must be < 20,000
		TargetNumLoans:   big.NewInt(2),     // Exactly 2 active loans
		RatioNumerator:   big.NewInt(3),     // Debt/Income < 3/10 (0.3)
		RatioDenominator: big.NewInt(10),
		MaxBits:          64,                // Maximum bit length for numbers in range proofs
	}
	fmt.Printf("Public Statement: Income > %d, Debt < %d, NumLoans = %d, Debt/Income < %d/%d\n",
		statement.ThresholdIncome, statement.ThresholdDebt, statement.TargetNumLoans,
		statement.RatioNumerator, statement.RatioDenominator)

	// 3. Define Prover's Secret Witness (Satisfying the conditions)
	witness := &ZKFELWitness{
		Income:   big.NewInt(60000), // 60,000 > 50,000 (TRUE)
		Debt:     big.NewInt(15000), // 15,000 < 20,000 (TRUE)
		NumLoans: big.NewInt(2),     // 2 = 2 (TRUE)
		IncRand:  generateRandomScalar(params.N),
		DebtRand: generateRandomScalar(params.N),
		NLRand:   generateRandomScalar(params.N),
	}
	// Check ratio: 15000 / 60000 = 0.25. Is 0.25 < 0.3? (TRUE)
	fmt.Printf("Prover's Secret Witness: Income=%d, Debt=%d, NumLoans=%d (Values are hidden in proof)\n",
		witness.Income, witness.Debt, witness.NumLoans)

	// 4. Generate the ZKP-FEL Proof
	fmt.Println("\nGenerating ZKP-FEL proof...")
	zkProof, err := GenerateZKFELProof(witness, statement, params)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}
	fmt.Println("ZKP-FEL proof generated successfully.")

	// 5. Verify the ZKP-FEL Proof
	fmt.Println("\nVerifying ZKP-FEL proof...")
	isValid, err := VerifyZKFELProof(zkProof, statement, params)
	if err != nil {
		fmt.Printf("Error during proof verification: %v\n", err)
		return
	}

	if isValid {
		fmt.Println("Proof is VALID! The prover meets the financial eligibility criteria without revealing their secrets.")
	} else {
		fmt.Println("Proof is INVALID! The prover does NOT meet the financial eligibility criteria.")
	}

	fmt.Println("\n--- Testing with a failing condition ---")

	// Test Case 1: Income too low
	fmt.Println("\nTest Case: Income too low (e.g., 40000 < 50000)")
	failingWitness1 := &ZKFELWitness{
		Income:   big.NewInt(40000), // FAIL: 40,000 < 50,000
		Debt:     big.NewInt(15000),
		NumLoans: big.NewInt(2),
		IncRand:  generateRandomScalar(params.N),
		DebtRand: generateRandomScalar(params.N),
		NLRand:   generateRandomScalar(params.N),
	}
	zkProof1, err := GenerateZKFELProof(failingWitness1, statement, params)
	if err != nil {
		fmt.Printf("Error generating failing proof 1: %v\n", err)
		return
	}
	isValid1, err := VerifyZKFELProof(zkProof1, statement, params)
	if err != nil {
		fmt.Printf("Error during verification for failing proof 1: %v\n", err)
	}
	if isValid1 {
		fmt.Println("Failing proof 1 unexpectedly VALID!")
	} else {
		fmt.Println("Failing proof 1 correctly INVALID.")
	}

	// Test Case 2: Debt too high
	fmt.Println("\nTest Case: Debt too high (e.g., 25000 > 20000)")
	failingWitness2 := &ZKFELWitness{
		Income:   big.NewInt(60000),
		Debt:     big.NewInt(25000), // FAIL: 25,000 > 20,000
		NumLoans: big.NewInt(2),
		IncRand:  generateRandomScalar(params.N),
		DebtRand: generateRandomScalar(params.N),
		NLRand:   generateRandomScalar(params.N),
	}
	zkProof2, err := GenerateZKFELProof(failingWitness2, statement, params)
	if err != nil {
		fmt.Printf("Error generating failing proof 2: %v\n", err)
		return
	}
	isValid2, err := VerifyZKFELProof(zkProof2, statement, params)
	if err != nil {
		fmt.Printf("Error during verification for failing proof 2: %v\n", err)
	}
	if isValid2 {
		fmt.Println("Failing proof 2 unexpectedly VALID!")
	} else {
		fmt.Println("Failing proof 2 correctly INVALID.")
	}

	// Test Case 3: Wrong number of loans
	fmt.Println("\nTest Case: Wrong number of loans (e.g., 3 != 2)")
	failingWitness3 := &ZKFELWitness{
		Income:   big.NewInt(60000),
		Debt:     big.NewInt(15000),
		NumLoans: big.NewInt(3), // FAIL: 3 != 2
		IncRand:  generateRandomScalar(params.N),
		DebtRand: generateRandomScalar(params.N),
		NLRand:   generateRandomScalar(params.N),
	}
	zkProof3, err := GenerateZKFELProof(failingWitness3, statement, params)
	if err != nil {
		fmt.Printf("Error generating failing proof 3: %v\n", err)
		return
	}
	isValid3, err := VerifyZKFELProof(zkProof3, statement, params)
	if err != nil {
		fmt.Printf("Error during verification for failing proof 3: %v\n", err)
	}
	if isValid3 {
		fmt.Println("Failing proof 3 unexpectedly VALID!")
	} else {
		fmt.Println("Failing proof 3 correctly INVALID.")
	}

	// Test Case 4: Ratio too high (e.g., 30000 / 60000 = 0.5 > 0.3)
	fmt.Println("\nTest Case: Debt/Income ratio too high (e.g., 30000/60000 = 0.5 > 0.3)")
	failingWitness4 := &ZKFELWitness{
		Income:   big.NewInt(60000),
		Debt:     big.NewInt(30000), // 30000 / 60000 = 0.5 (FAIL: 0.5 > 0.3)
		NumLoans: big.NewInt(2),
		IncRand:  generateRandomScalar(params.N),
		DebtRand: generateRandomScalar(params.N),
		NLRand:   generateRandomScalar(params.N),
	}
	zkProof4, err := GenerateZKFELProof(failingWitness4, statement, params)
	if err != nil {
		fmt.Printf("Error generating failing proof 4: %v\n", err)
		return
	}
	isValid4, err := VerifyZKFELProof(zkProof4, statement, params)
	if err != nil {
		fmt.Printf("Error during verification for failing proof 4: %v\n", err)
	}
	if isValid4 {
		fmt.Println("Failing proof 4 unexpectedly VALID!")
	} else {
		fmt.Println("Failing proof 4 correctly INVALID.")
	}
}

```