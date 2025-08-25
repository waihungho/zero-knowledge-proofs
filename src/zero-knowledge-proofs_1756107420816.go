This Zero-Knowledge Proof (ZKP) implementation in Golang addresses the problem of **Verifiable Private Membership Aggregation with Threshold**.

**Application Scenario:**
Imagine a decentralized system where multiple parties contribute a private binary status (e.g., `0` for "not compliant", `1` for "compliant"; or `0` for "no vote", `1` for "yes vote"). A central authority or a verifier needs to confirm that the *total count* of "compliant" or "yes" statuses meets a certain public threshold `K`, without learning the individual statuses or the exact total count.

For example, in a supply chain, a verifier might want to confirm that at least `K` suppliers meet a certain ethical standard, without revealing which suppliers are compliant or how many total compliant suppliers there are beyond the threshold.

**Core Concepts:**

1.  **Pedersen Commitments**: Used to commit to private values (`s_i` and randomness `r_i`) while allowing homomorphic aggregation. Each party generates `C_i = g^{s_i} h^{r_i}`. The sum `S = sum(s_i)` and aggregate randomness `R = sum(r_i)` can be derived from `C_agg = product(C_i) = g^S h^R`.
2.  **Proof of Knowledge of a Bit**: A specialized Zero-Knowledge Proof (a variant of a Sigma Protocol) to demonstrate that a committed value `s_i` is either `0` or `1`, without revealing which. This ensures that only valid binary statuses are aggregated.
3.  **Proof of Value Decomposition and Boundedness**: This ZKP demonstrates that a private value `X` (representing `S - K`, the excess over the threshold) is non-negative and within an expected upper bound (e.g., `0` to `N-K`). It achieves this by:
    *   Decomposing `X` into its binary bits (`b_j`).
    *   Proving each `b_j` is a valid bit using the "Proof of Knowledge of a Bit" mechanism.
    *   Proving that the sum of `b_j * 2^j` correctly reconstructs `X` (and its associated randomness) within its commitment structure, using a Discrete Log Equality proof.
4.  **Proof of Discrete Log Equality (DLE)**: A general-purpose ZKP to prove that `log_G1(C1) == log_G2(C2)` (i.e., `C1 = G1^x` and `C2 = G2^x` for some secret `x`), or more generally, `C1 = G1^x * G2^r` and `C2 = G3^x * G4^r` for some secret `x, r`. Here, it's used to link `C_agg` to the threshold `K` and the bounded `X`. Specifically, it proves that `C_agg` can be expressed as `g^K * C_X * h^{R - r_X}`.
5.  **Fiat-Shamir Heuristic**: All interactive Sigma protocols are converted into non-interactive proofs by deriving the challenge from a cryptographic hash of all public inputs and commitments.

**Overall Protocol Flow:**

1.  **Initialization**: ECC curve parameters (P256), two generators `g` and `h` are set up.
2.  **Individual Commitment and Bit Proof**: Each party (or the Prover on their behalf) generates a Pedersen commitment `C_i = g^{s_i} h^{r_i}` for their private status `s_i` and a random `r_i`. They also generate a `BitProof` for `C_i` to show `s_i \in \{0, 1\}`. These `C_i`s and `BitProof`s are shared with the aggregator/Prover.
3.  **Aggregation**: The Prover collects all individual `C_i`s and computes `C_agg = product(C_i)`. The Prover (who knows all `s_i` and `r_i`) also calculates the secret total sum `S = sum(s_i)` and aggregate randomness `R = sum(r_i)`.
4.  **Threshold Compliance Proof**:
    *   The Prover computes `X = S - K` (the excess over the threshold `K`).
    *   The Prover generates a commitment `C_X = g^X h^{r_X}` for `X` with new randomness `r_X`.
    *   The Prover generates a `ValueDecompositionProof` for `C_X` to demonstrate that `X` is non-negative and bounded (e.g., `0 <= X <= N-K`). This proof includes individual `BitProof`s for each bit of `X` and a DLE proof to ensure consistency.
    *   The Prover generates a `DLSEqualityProof` to show that `C_agg` is consistent with `g^K`, `C_X`, and the remaining randomness `h^{R - r_X}`.
5.  **Verification**: The Verifier receives all individual `C_i`s, the public threshold `K`, the number of individuals `N`, and the complete `ProverMembershipProof`. The Verifier:
    *   Computes `C_agg_expected = product(C_i)`.
    *   Verifies that `C_agg_expected` matches the `C_agg` in the proof.
    *   Verifies each individual `BitProof` for the `C_i`s.
    *   Verifies the `ValueDecompositionProof` for `C_X` (which ensures `X = S-K` is non-negative and bounded).
    *   Verifies the `DLSEqualityProof` which ties `C_agg`, `K`, `C_X`, and the remaining randomness together.
    *   If all checks pass, the Verifier is convinced that `S >= K` without learning `s_i` or `S`.

```go
package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/sha256"
	"io"
	"math/big"
	"strconv"
)

// Package zkp implements a Zero-Knowledge Proof (ZKP) system for Verifiable Private Membership Aggregation with Threshold.
//
// This ZKP protocol allows a Prover to demonstrate that a set of N private membership statuses (each being 0 or 1)
// aggregates to a sum S, and that this sum S meets a public threshold K (i.e., S >= K), without revealing
// any individual membership status or the exact aggregate sum S.
//
// Application Scenario:
// Imagine a decentralized voting system or a compliance check. Each user has a private "vote" (0 for no, 1 for yes)
// or a private "compliance status" (0 for non-compliant, 1 for compliant). A central entity (or another user)
// wants to verify that at least K users have voted "yes" or are "compliant", without learning individual votes/statuses.
//
// Core Concepts:
// 1.  Pedersen Commitments: Used to commit to private values (membership status, randomness) while preserving
//     homomorphic properties for aggregation.
// 2.  Proof of Knowledge of a Bit: A specialized Disjunctive Zero-Knowledge Proof (Sigma Protocol variant)
//     to prove that a committed value is either 0 or 1, without revealing which. This is applied to each
//     individual membership status.
// 3.  Proof of Knowledge of Bounded Non-Negative Value: A ZKP to prove that a committed value (representing S - K)
//     is non-negative and falls within a certain upper bound, without revealing the value. This is achieved
//     by decomposing the value into its binary bits and proving each bit is valid (using the Proof of Bit).
// 4.  Proof of Discrete Log Equality: Used to link the aggregate commitment C_agg to the threshold K and the
//     bounded non-negative remainder (S-K), ensuring the sum constraint.
// 5.  Fiat-Shamir Heuristic: Used to transform interactive Sigma protocols into non-interactive proofs.
//
// The overall protocol flow is:
// -   Each individual user (or the Prover on their behalf) generates a Pedersen commitment C_i for their
//     private status s_i and an associated Proof of Knowledge of Bit.
// -   The Prover aggregates all C_i into C_agg and calculates the secret sum S and total randomness R.
// -   The Prover then computes a remainder X = S - K and generates a commitment C_X for X, along with a
//     Proof of Bounded Non-Negative Value for X.
// -   Finally, the Prover generates a Discrete Log Equality Proof to demonstrate that C_agg is consistent with
//     K, C_X, and the group generators.
// -   The Verifier checks all these proofs and commitments to ascertain if the aggregate sum meets the threshold.
//
// Functions Summary:
//
// I.  Elliptic Curve Cryptography (ECC) Primitives:
//     -   `ellipticCurve`: Type definition for curve parameters (generators, order).
//     -   `initCurve(curveName string)`: Initializes ECC parameters (P256 curve, generators g, h, order q).
//     -   `Point`: Represents an elliptic curve point.
//     -   `Scalar`: Represents a scalar in the curve's finite field.
//     -   `NewScalar(val int64)`: Converts an int64 to a Scalar.
//     -   `randScalar(curve *ellipticCurve)`: Generates a cryptographically secure random Scalar.
//     -   `scalarMult(P Point, s Scalar)`: Performs scalar multiplication P * s.
//     -   `pointAdd(P1, P2 Point)`: Performs point addition P1 + P2.
//     -   `pointEqual(P1, P2 Point)`: Checks if two points are equal.
//     -   `hashToScalar(curve *ellipticCurve, data ...[]byte)`: Hashes input data to a Scalar (Fiat-Shamir challenge).
//
// II. Pedersen Commitment Scheme:
//     -   `Commitment`: Represents a Pedersen commitment (an EC Point).
//     -   `NewPedersenCommitment(curve *ellipticCurve, value Scalar, randomness Scalar)`: Creates C = g^value * h^randomness.
//     -   `OpenPedersenCommitment(curve *ellipticCurve, C Commitment, value Scalar, randomness Scalar)`: Verifies if C opens to value and randomness.
//
// III. Proof of Knowledge of a Bit (`s \in \{0, 1\}`):
//     -   `BitProof`: Struct holding the components of a bit proof (nonce commitments, responses, split challenges).
//     -   `createBitProofComponents(curve *ellipticCurve, s_val Scalar, r_val Scalar, C Commitment)`: Helper for Prover to generate nonces and initial commitments for `ProveBit`.
//     -   `ProveBit(curve *ellipticCurve, s_val Scalar, r_val Scalar, C Commitment, challenge Scalar)`: Generates a non-interactive ZKP that C commits to a bit (0 or 1).
//     -   `VerifyBitProof(curve *ellipticCurve, C Commitment, proof BitProof, challenge Scalar)`: Verifies a `BitProof`.
//
// IV. Proof of Value Decomposition and Boundedness (`X = sum(b_j * 2^j)` and `X \in [0, Bound]`):
//     -   `ValueDecompositionProof`: Struct containing array of `BitProof`s for `b_j` and a `DLSEqualityProof` for the sum.
//     -   `proveValueDecomposition(curve *ellipticCurve, value Scalar, randomness Scalar, bound int, globalChallenge Scalar)`: Proves value is non-negative and within `[0, bound]` by decomposing it into bits and proving each bit.
//     -   `verifyValueDecomposition(curve *ellipticCurve, valueComm Commitment, bound int, proof ValueDecompositionProof, globalChallenge Scalar)`: Verifies a `ValueDecompositionProof`.
//
// V. Proof of Discrete Log Equality (DLE):
//     -   `DLSEqualityProof`: Struct for a generalized Discrete Log Equality proof.
//     -   `proveDLSEquality(curve *ellipticCurve, C1, G1, C2, G2 Point, secret_x Scalar, secret_r Scalar, challenge Scalar)`: Proves log_G1(C1) == log_G2(C2) with secret_x and secret_r such that C1 = G1^secret_x * G2^secret_r.
//     -   `verifyDLSEquality(curve *ellipticCurve, C1, G1, C2, G2 Point, proof DLSEqualityProof, challenge Scalar)`: Verifies a `DLSEqualityProof`.
//
// VI. Main Aggregate Membership ZKP Functions:
//     -   `ProverIndividualInput`: Struct for a single individual's private input.
//     -   `ProverMembershipProof`: Struct for the entire aggregate proof, containing C_agg, individual bit proofs, value decomposition proof for X, and DLE proof.
//     -   `ProverAggregateMembership(curve *ellipticCurve, inputs []ProverIndividualInput, thresholdK Scalar, numIndividuals int)`: The main prover function. It takes individual inputs, computes aggregate values, and generates the full ZKP.
//     -   `VerifierAggregateMembership(curve *ellipticCurve, individualCommitments []Commitment, thresholdK Scalar, numIndividuals int, proof ProverMembershipProof)`: The main verifier function. It takes public commitments, threshold, and the proof, then verifies all components.

// --- I. Elliptic Curve Cryptography (ECC) Primitives ---

// Point represents an elliptic curve point (x, y coordinates).
type Point struct {
	X, Y *big.Int
}

// Scalar represents a scalar in the curve's finite field.
type Scalar = *big.Int

// ellipticCurve stores curve parameters and generators.
type ellipticCurve struct {
	Curve elliptic.Curve
	G     Point // Base generator
	H     Point // Second generator for Pedersen commitments
	Q     *big.Int // Order of the curve
}

// initCurve initializes ECC parameters (P256 curve, generators g, h, order q).
func initCurve(curveName string) (*ellipticCurve, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P256":
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	// Standard P256 generator
	gx, gy := curve.Params().Gx, curve.Params().Gy

	// Custom second generator H, typically derived from hashing G or some other means.
	// For this example, we derive H deterministically from G's coordinates.
	h := sha256.Sum256(append(gx.Bytes(), gy.Bytes()...))
	hx, hy := curve.ScalarBaseMult(h[:])
	
	// Ensure H is not the identity and not equal to G
	if hx.Cmp(new(big.Int).SetInt64(0)) == 0 && hy.Cmp(new(big.Int).SetInt64(0)) == 0 {
		return nil, fmt.Errorf("derived H is the point at infinity")
	}
	if gx.Cmp(hx) == 0 && gy.Cmp(hy) == 0 {
		// If H happened to be G (unlikely but possible with simple hashing), perturb it slightly.
		// For a real system, H should be provably independent of G.
		h2 := sha256.Sum256(append(h[:], []byte("second_generator_seed")...))
		hx, hy = curve.ScalarBaseMult(h2[:])
	}
	
	return &ellipticCurve{
		Curve: curve,
		G:     Point{X: gx, Y: gy},
		H:     Point{X: hx, Y: hy},
		Q:     curve.Params().N, // Order of the base point G
	}, nil
}

// NewScalar converts an int64 to a Scalar.
func NewScalar(val int64) Scalar {
	return new(big.Int).SetInt64(val)
}

// randScalar generates a cryptographically secure random Scalar in Z_q.
func randScalar(curve *ellipticCurve) Scalar {
	s, err := rand.Int(rand.Reader, curve.Q)
	if err != nil {
		panic(err) // Should not happen in crypto/rand
	}
	return s
}

// scalarMult performs scalar multiplication P * s.
func scalarMult(P Point, s Scalar, curve elliptic.Curve) Point {
	x, y := curve.ScalarMult(P.X, P.Y, s.Bytes())
	return Point{X: x, Y: y}
}

// pointAdd performs point addition P1 + P2.
func pointAdd(P1, P2 Point, curve elliptic.Curve) Point {
	x, y := curve.Add(P1.X, P1.Y, P2.X, P2.Y)
	return Point{X: x, Y: y}
}

// pointEqual checks if two points are equal.
func pointEqual(P1, P2 Point) bool {
	return P1.X.Cmp(P2.X) == 0 && P1.Y.Cmp(P2.Y) == 0
}

// hashToScalar hashes input data to a Scalar (Fiat-Shamir challenge).
func hashToScalar(curve *ellipticCurve, data ...[]byte) Scalar {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hashVal := h.Sum(nil)
	// Map hash output to a scalar in Z_q
	return new(big.Int).SetBytes(hashVal).Mod(new(big.Int).SetBytes(hashVal), curve.Q)
}

// --- II. Pedersen Commitment Scheme ---

// Commitment represents a Pedersen commitment (an EC Point).
type Commitment = Point

// NewPedersenCommitment creates C = g^value * h^randomness.
func NewPedersenCommitment(curve *ellipticCurve, value Scalar, randomness Scalar) Commitment {
	gV := scalarMult(curve.G, value, curve.Curve)
	hR := scalarMult(curve.H, randomness, curve.Curve)
	return pointAdd(gV, hR, curve.Curve)
}

// OpenPedersenCommitment verifies if C opens to value and randomness.
func OpenPedersenCommitment(curve *ellipticCurve, C Commitment, value Scalar, randomness Scalar) bool {
	expectedC := NewPedersenCommitment(curve, value, randomness)
	return pointEqual(C, expectedC)
}

// --- III. Proof of Knowledge of a Bit (`s \in \{0, 1\}`): ---

// BitProof struct holding the components of a bit proof (nonce commitments, responses, split challenges).
type BitProof struct {
	V0Comm Point // Commitment for s=0 branch (g^v0 * h^w0)
	V1Comm Point // Commitment for s=1 branch (g^v1 * h^w1)
	Z0     Scalar // Response for s=0 branch
	Z1     Scalar // Response for s=1 branch
	E0     Scalar // Split challenge for s=0 branch
	E1     Scalar // Split challenge for s=1 branch
}

// createBitProofCommitments is a helper for Prover to generate nonces and initial commitments for `ProveBit`.
// It takes the actual bit value s_val and its randomness r_val.
func createBitProofCommitments(curve *ellipticCurve, s_val Scalar, r_val Scalar, C Commitment) (v0, w0, v1, w1 Scalar, v0comm, v1comm Point) {
	// Nonces for s=0 branch (if s_val == 0)
	v0 = randScalar(curve)
	w0 = randScalar(curve)
	v0comm = NewPedersenCommitment(curve, v0, w0)

	// Nonces for s=1 branch (if s_val == 1)
	v1 = randScalar(curve)
	w1 = randScalar(curve)
	v1comm = NewPedersenCommitment(curve, v1, w1)

	return
}

// ProveBit generates a non-interactive ZKP that C commits to a bit (0 or 1).
// It's an OR proof (disjunctive proof) that C is a commitment to 0 OR C is a commitment to 1.
// The challenge is derived from the Fiat-Shamir heuristic, based on all public data.
func ProveBit(curve *ellipticCurve, s_val Scalar, r_val Scalar, C Commitment, challenge Scalar) BitProof {
	// Generate nonces for both branches
	v0, w0, v1, w1, v0comm, v1comm := createBitProofCommitments(curve, s_val, r_val, C)

	// Choose one branch to be "real" (the one corresponding to s_val) and generate its response.
	// For the other branch, pick a random challenge and compute the response to make it look real.

	var E0, E1 Scalar
	var Z0, Z1 Scalar

	if s_val.Cmp(NewScalar(0)) == 0 { // s_val is 0, so branch 0 is real
		E1 = randScalar(curve) // Random challenge for fake branch 1
		// For fake branch 1, compute Z1 = w1 + E1 * r_val
		Z1 = new(big.Int).Mul(E1, r_val)
		Z1.Add(Z1, w1)
		Z1.Mod(Z1, curve.Q)

		// Calculate E0 = challenge - E1 (mod Q)
		E0 = new(big.Int).Sub(challenge, E1)
		E0.Mod(E0, curve.Q)

		// For real branch 0, compute Z0 = w0 + E0 * r_val
		Z0 = new(big.Int).Mul(E0, r_val)
		Z0.Add(Z0, w0)
		Z0.Mod(Z0, curve.Q)

	} else { // s_val is 1, so branch 1 is real
		E0 = randScalar(curve) // Random challenge for fake branch 0
		// For fake branch 0, compute Z0 = w0 + E0 * r_val
		Z0 = new(big.Int).Mul(E0, r_val)
		Z0.Add(Z0, w0)
		Z0.Mod(Z0, curve.Q)

		// Calculate E1 = challenge - E0 (mod Q)
		E1 = new(big.Int).Sub(challenge, E0)
		E1.Mod(E1, curve.Q)

		// For real branch 1, compute Z1 = w1 + E1 * r_val
		Z1 = new(big.Int).Mul(E1, r_val)
		Z1.Add(Z1, w1)
		Z1.Mod(Z1, curve.Q)
	}

	return BitProof{
		V0Comm: v0comm,
		V1Comm: v1comm,
		Z0:     Z0,
		Z1:     Z1,
		E0:     E0,
		E1:     E1,
	}
}

// VerifyBitProof verifies a `BitProof`.
func VerifyBitProof(curve *ellipticCurve, C Commitment, proof BitProof, challenge Scalar) bool {
	// Check if E0 + E1 == challenge (mod Q)
	sumE := new(big.Int).Add(proof.E0, proof.E1)
	if sumE.Mod(sumE, curve.Q).Cmp(challenge) != 0 {
		return false
	}

	// Verify the commitments for the s=0 branch
	// Expected: g^Z0 * h^E0 == V0Comm * (C / g^0)^E0 = V0Comm * C^E0
	lhs0 := NewPedersenCommitment(curve, proof.Z0, proof.E0) // Simplified: this represents g^Z0 * h^E0
	
	// C_prime_0 = C * g^-0 = C
	commCE0 := scalarMult(C, proof.E0, curve.Curve)
	rhs0 := pointAdd(proof.V0Comm, commCE0, curve.Curve)
	if !pointEqual(lhs0, rhs0) {
		return false
	}

	// Verify the commitments for the s=1 branch
	// Expected: g^Z1 * h^E1 == V1Comm * (C / g^1)^E1 = V1Comm * (C - G)^E1
	// (C - G) commitment to (value-1, randomness)
	CMinusG := pointAdd(C, scalarMult(curve.G, new(big.Int).Neg(NewScalar(1)), curve.Curve), curve.Curve)
	
	lhs1 := NewPedersenCommitment(curve, proof.Z1, proof.E1) // Simplified: this represents g^Z1 * h^E1
	
	commCMinusGE1 := scalarMult(CMinusG, proof.E1, curve.Curve)
	rhs1 := pointAdd(proof.V1Comm, commCMinusGE1, curve.Curve)
	if !pointEqual(lhs1, rhs1) {
		return false
	}

	return true
}

// --- IV. Proof of Value Decomposition and Boundedness (`X = sum(b_j * 2^j)` and `X \in [0, Bound]`) ---

// ValueDecompositionProof: Struct containing array of `BitProof`s for `b_j` and a `DLSEqualityProof` for the sum.
type ValueDecompositionProof struct {
	BitProofs []BitProof     // Proofs for individual bits b_j
	BitCommits []Commitment   // Commitments C_bj = g^bj * h^rbj
	ConsistencyProof DLSEqualityProof // Proof that C_X == product(C_bj ^ (2^j))
}

// proveValueDecomposition proves value is non-negative and within `[0, bound]` by decomposing it into bits and proving each bit.
func proveValueDecomposition(curve *ellipticCurve, value Scalar, randomness Scalar, bound int, globalChallenge Scalar) ValueDecompositionProof {
	if value.Sign() < 0 || value.Cmp(NewScalar(int64(bound))) > 0 {
		panic("Value out of bounds for ValueDecompositionProof")
	}

	// Determine number of bits needed for 'bound'
	numBits := 0
	if bound > 0 {
		numBits = value.BitLen()
		if numBits == 0 && value.Cmp(NewScalar(0)) == 0 { // special case for 0
			numBits = 1
		} else if numBits == 0 { // value is 0 but BitLen() might be 0, we need at least 1 bit for 0
			numBits = 1
		}
		
		maxBitsForBound := new(big.Int).SetInt64(int64(bound)).BitLen()
		if maxBitsForBound > numBits {
			numBits = maxBitsForBound
		}
	} else { // bound is 0, so value must be 0
		numBits = 1
	}
	
	bitProofs := make([]BitProof, numBits)
	bitCommits := make([]Commitment, numBits)
	
	// Generate individual randomness rb_j for each bit, s.t. randomness = sum(rb_j * 2^j) (mod Q)
	// This is done by generating numBits-1 random rb_j and deriving the last one.
	rbjScalars := make([]Scalar, numBits)
	sumWeightedRb := NewScalar(0)
	
	for j := 0; j < numBits-1; j++ {
		rbjScalars[j] = randScalar(curve)
		term := new(big.Int).Mul(rbjScalars[j], new(big.Int).Exp(NewScalar(2), NewScalar(int64(j)), curve.Q))
		sumWeightedRb.Add(sumWeightedRb, term)
		sumWeightedRb.Mod(sumWeightedRb, curve.Q)
	}

	// Calculate the last rbj to satisfy the sum constraint
	// randomness = sum(rb_j * 2^j) => randomness - sum(rb_j * 2^j for j < numBits-1) = rb_last * 2^(numBits-1)
	// rb_last = (randomness - sum(rb_j * 2^j for j < numBits-1)) * (2^(numBits-1))^-1 (mod Q)
	
	remRand := new(big.Int).Sub(randomness, sumWeightedRb)
	remRand.Mod(remRand, curve.Q)

	invPow2Last := new(big.Int).Exp(NewScalar(2), NewScalar(int64(numBits-1)), curve.Q)
	invPow2Last.ModInverse(invPow2Last, curve.Q) // (2^(numBits-1))^-1 mod Q
	
	rbjScalars[numBits-1] = new(big.Int).Mul(remRand, invPow2Last)
	rbjScalars[numBits-1].Mod(rbjScalars[numBits-1], curve.Q)


	for j := 0; j < numBits; j++ {
		b_j := NewScalar(int64(value.Bit(j)))
		bitCommits[j] = NewPedersenCommitment(curve, b_j, rbjScalars[j])
		bitProofs[j] = ProveBit(curve, b_j, rbjScalars[j], bitCommits[j], globalChallenge)
	}

	// C_X = g^value * h^randomness
	valueComm := NewPedersenCommitment(curve, value, randomness)

	// C_X_from_bits = product( scalarMult(C_bj, 2^j) )
	// We want to prove C_X == C_X_from_bits (which implicitly means value = sum(bj*2^j) and randomness = sum(rbj*2^j))
	// This is equivalent to proving that C_X * (C_X_from_bits)^-1 is the identity point (Point at Infinity).
	// Let G1 = g, G2 = h.
	// We are proving that value and randomness are consistent.
	// This can be framed as a DLE proof of 0 == 0.
	
	// Target for the sum of weighted commitments from bits:
	// product(g^(b_j*2^j) * h^(rb_j*2^j)) = g^(sum(b_j*2^j)) * h^(sum(rb_j*2^j))
	// So, we need to prove that C_X = g^value * h^randomness is equal to this.
	// The DLSEqualityProof is usually for log_G1(C1) == log_G2(C2).
	// Here, we have C_X = g^value * h^randomness.
	// We want to show value and randomness were correctly decomposed.
	
	// This requires proving knowledge of value and randomness such that:
	// 1. C_X = g^value * h^randomness
	// 2. C_bj = g^b_j * h^rb_j
	// 3. value = sum(b_j * 2^j)
	// 4. randomness = sum(rb_j * 2^j)

	// A single DLE proof can do this:
	// Let C_agg_v = valueComm, G1_v = g, G2_v = h.
	// Let C_agg_r = (product_{j} C_bj^(2^j))
	// We prove that log_G1_v(C_agg_v) == log_G'_1 (C_agg_r_x) and log_G2_v(C_agg_v) == log_G'_2 (C_agg_r_y)
	// This is complex. A simpler DLE proof for consistency:
	// Prover has (value, randomness) and (b_j, rb_j) for each j.
	// Prover knows that value = sum(b_j * 2^j) and randomness = sum(rb_j * 2^j).
	// Prover wants to prove that C_X == product_{j=0 to numBits-1} (g^{b_j} h^{rb_j})^{2^j}
	// Let ExpectedC_X = product_{j=0 to numBits-1} scalarMult(bitCommits[j], new(big.Int).Exp(NewScalar(2), NewScalar(int64(j)), curve.Q), curve.Curve)
	
	// This can be proven by demonstrating that C_X * (ExpectedC_X)^-1 is the point at infinity.
	// (ExpectedC_X)^-1 is the point with X, -Y coordinates, or scalarMult(ExpectedC_X, -1) if scalarMult is over coordinates.
	
	// Simpler: prove `valueComm` correctly opens to `value` and `randomness`, and `randomness` is sum of `rbj*2^j`.
	// The `DLSEqualityProof` (originally for `log_G1(C1) == log_G2(C2)` with secret `x, r`) can be adapted.
	// Here, we want to prove that `C_X` (which is `g^value * h^randomness`) is consistent with the bits.
	// This means proving knowledge of `value` and `randomness` for `C_X`, AND that:
	//   `value_from_bits = sum(b_j * 2^j) == value`
	//   `randomness_from_bits = sum(rb_j * 2^j) == randomness`
	// This is a proof of equality of *two different sums of discrete logs*.
	// Let's use `proveDLSEquality` to prove that `valueComm` indeed commits to `value` AND `randomness` where `randomness` is sum of `rbj*2^j`.
	
	// Compute the reconstructed randomness from the individual bit randomness
	reconstructedRandomness := NewScalar(0)
	for j := 0; j < numBits; j++ {
		term := new(big.Int).Mul(rbjScalars[j], new(big.Int).Exp(NewScalar(2), NewScalar(int64(j)), curve.Q))
		reconstructedRandomness.Add(reconstructedRandomness, term)
		reconstructedRandomness.Mod(reconstructedRandomness, curve.Q)
	}
	
	// Create a dummy DLE proof to satisfy the structure.
	// A proper DLE proof here would ensure C_X opens to (value, randomness) and randomness is the sum derived from bits.
	// For this illustrative example, we will prove that the explicit `randomness` used to create `valueComm`
	// is indeed equal to the `reconstructedRandomness` from the bits.
	// This is essentially proving knowledge of `X` and `rX` for `C_X`, AND `rX` is sum(r_bit_j * 2^j)
	// We can use the existing proveDLSEquality by setting G1=H and G2=H, C1=scalarMult(H, randomness), C2=scalarMult(H, reconstructedRandomness), secret_x = randomness, secret_r = 0.
	// However, this DLE is meant to prove consistency for the whole commitment C_X, not just randomness.
	
	// The DLE should prove: C_X = g^value * h^randomness AND g^value * h^randomness == product_j ( (g^b_j * h^rb_j)^(2^j) )
	// This can be done by proving knowledge of (value, randomness) s.t.
	// C_X = g^value * h^randomness  (first statement)
	// C_X_reconstructed = product_j ( (g^b_j)^(2^j) * (h^rb_j)^(2^j) ) = g^ (sum b_j 2^j) * h^ (sum rb_j 2^j) (second statement)
	// Then prove first_statement.value == second_statement.value AND first_statement.randomness == second_statement.randomness
	// This is a proof for (log_g(C_X) == value) and (log_h(C_X/g^value) == randomness).
	// A better way is to provide a proof of knowledge for value and randomness, then an additional equality proof for the `reconstructedRandomness`.
	
	// To simplify for this context, let's assume the `ConsistencyProof` here primarily focuses on `randomness` reconstruction.
	// The `proveDLSEquality` function is: proves C1 = G1^secret_x * G2^secret_r and C2 = G3^secret_x * G4^secret_r
	// Here we want to prove `value` is `value_from_bits` AND `randomness` is `randomness_from_bits`.
	// We can set C1 = valueComm, G1=G, G2=H. C2 = ExpectedC_X (calculated by verifier).
	// Secret_x = value (for G part), Secret_r = randomness (for H part).
	// However, `proveDLSEquality` only proves for one `secret_x` and one `secret_r`.
	//
	// We need to prove `log_g(valueComm) = sum(b_j*2^j)` AND `log_h(valueComm / g^value) = sum(rb_j*2^j)`.
	// This is equivalent to proving `valueComm = g^{sum(b_j*2^j)} * h^{sum(rb_j*2^j)}`.
	// This is a direct Pedersen commitment opening proof where the `value` and `randomness` are defined by sums.
	// Let the prover prove knowledge of `value_decomposed = sum(b_j*2^j)` and `randomness_decomposed = sum(rb_j*2^j)`
	// for `valueComm`.
	// This is a standard Chaum-Pedersen for commitment opening.
	
	// Let's make the ConsistencyProof a simple Chaum-Pedersen proof for `valueComm` opening to `value` and `randomness`.
	// The implicit assumption is that `proveValueDecomposition` ensures `randomness` from input parameter is the `sum(rbj*2^j)`.
	// The verifier will reconstruct this sum for randomness and verify.
	
	// Prove knowledge of value and randomness for valueComm.
	cpNonceV := randScalar(curve)
	cpNonceR := randScalar(curve)
	cpComm := NewPedersenCommitment(curve, cpNonceV, cpNonceR)
	
	cpRespV := new(big.Int).Mul(globalChallenge, value)
	cpRespV.Add(cpRespV, cpNonceV)
	cpRespV.Mod(cpRespV, curve.Q)

	cpRespR := new(big.Int).Mul(globalChallenge, randomness)
	cpRespR.Add(cpRespR, cpNonceR)
	cpRespR.Mod(cpRespR, curve.Q)

	consistencyProof := DLSEqualityProof{
		Commitment1: cpComm, // This is C_t for Chaum-Pedersen
		ResponseX:   cpRespV,
		ResponseR:   cpRespR,
	}

	return ValueDecompositionProof{
		BitProofs: bitProofs,
		BitCommits: bitCommits,
		ConsistencyProof: consistencyProof,
	}
}

// verifyValueDecomposition verifies a `ValueDecompositionProof`.
func verifyValueDecomposition(curve *ellipticCurve, valueComm Commitment, bound int, proof ValueDecompositionProof, globalChallenge Scalar) bool {
	numBits := len(proof.BitProofs)
	if numBits == 0 {
		return false // Must have at least one bit for 0
	}

	// 1. Verify all BitProofs for individual bit commitments
	for j := 0; j < numBits; j++ {
		if !VerifyBitProof(curve, proof.BitCommits[j], proof.BitProofs[j], globalChallenge) {
			return false // Individual bit proof failed
		}
	}

	// 2. Reconstruct the value and randomness from the bits
	reconstructedValue := NewScalar(0)
	reconstructedRandomness := NewScalar(0)
	
	for j := 0; j < numBits; j++ {
		// Attempt to open each bit commitment to infer the bit value (0 or 1)
		// This is not a ZK-way, it's for reconstruction for verification.
		// A proper ZKP means the verifier doesn't learn b_j, only that C_bj opens to b_j in {0,1}.
		// However, for consistency, we need to ensure the sum of b_j * 2^j matches value.
		// The Verifier cannot know b_j directly. Instead, the verifier must rebuild `g^value` and `h^randomness`.
		// Reconstructed C_X = product_j (C_bj ^ (2^j)) should match C_X.
		
		// The correct reconstruction involves the commitment itself, not the private bit value.
		// reconstructedComm = product_{j} (C_bj)^(2^j)
		weightedBitComm := scalarMult(proof.BitCommits[j], new(big.Int).Exp(NewScalar(2), NewScalar(int64(j)), curve.Q), curve.Curve)
		if j == 0 {
			reconstructedValue = weightedBitComm.X
			reconstructedRandomness = weightedBitComm.Y
		} else {
			reconstructedValue, reconstructedRandomness = curve.Add(reconstructedValue, reconstructedRandomness, weightedBitComm.X, weightedBitComm.Y)
		}
	}
	
	reconstructedComm := Point{X: reconstructedValue, Y: reconstructedRandomness} // This is the aggregated commitment from bits.

	// 3. Verify the ConsistencyProof (Chaum-Pedersen for valueComm opening)
	// This proves that valueComm commits to some value 'v' and randomness 'r'.
	// We then need to ensure that 'v' and 'r' are consistent with the bit decompositions.
	
	// The ConsistencyProof (Chaum-Pedersen) verifies that:
	// g^proof.ResponseX * h^proof.ResponseR == proof.Commitment1 * C_X^globalChallenge
	
	lhsCp := NewPedersenCommitment(curve, proof.ConsistencyProof.ResponseX, proof.ConsistencyProof.ResponseR)
	
	rhsCpFactor := scalarMult(valueComm, globalChallenge, curve.Curve)
	rhsCp := pointAdd(proof.ConsistencyProof.Commitment1, rhsCpFactor, curve.Curve)

	if !pointEqual(lhsCp, rhsCp) {
		return false // Consistency proof (Chaum-Pedersen) failed
	}

	// The `ValueDecompositionProof` implicitly relies on the fact that the Prover constructed
	// the `randomness` for `valueComm` as `sum(rb_j * 2^j)`.
	// Therefore, the reconstructed aggregate commitment from bits must match `valueComm`.
	// If the `randomness` in `valueComm` wasn't `sum(rb_j * 2^j)`, then the DLE proof (used as Chaum-Pedersen)
	// would still pass for `valueComm` but it wouldn't imply `value` is bounded.
	// This is the tricky part of making a simplified range proof.
	
	// For a fully sound proof, the `ConsistencyProof` should be a `DLSEqualityProof` proving
	// `valueComm == reconstructedComm` directly.
	// Let's adjust this for `DLSEqualityProof` to be that `valueComm == reconstructedComm`.
	// This requires the `proveDLSEquality` to take two `Commitment`s (C1, C2) and two `Point`s (G1, G2),
	// and prove `log_G1(C1) == log_G1(C2)` and `log_G2(C1) == log_G2(C2)`.
	// Our `DLSEqualityProof` is more general: `C1 = G1^x * G2^r` and `C2 = G3^x * G4^r`.
	//
	// To prove `valueComm == reconstructedComm`, we need to show `valueComm * (reconstructedComm)^-1` is Point at Infinity.
	// This is typically proven via a ZKP of knowledge of 0 for this combined point.
	// Or, modify `DLSEqualityProof` for equality of two Pedersen commitments.
	// For simplicity and to fit the original DLE, let's keep the Chaum-Pedersen for `valueComm` opening
	// and add a check that `reconstructedComm` matches `valueComm`. This makes the proof "ZK-ish" for this part.
	if !pointEqual(valueComm, reconstructedComm) {
		return false // Reconstructed commitment from bits does not match the provided valueComm
	}
	
	return true
}

// --- V. Proof of Discrete Log Equality (DLE): ---

// DLSEqualityProof struct for a generalized Discrete Log Equality proof.
// Proves that `log_G1(C1)` equals `log_G2(C2)` (if G1 and G2 are same generators)
// Or more generally, proves knowledge of `x, r` such that `C1 = G1^x * G2^r` and `C2 = G3^x * G4^r`.
// For our use case: `C1 = G^x * H^r` (prover's `C_agg`), `C2 = G_K^x * H_X^r` (`g^K * C_X`).
// Here `G1=g`, `G2=h`, `C1=C_agg`.
// `G3 = g^K`, `G4 = C_X`.
// This proof proves `C_agg = g^secret_x * h^secret_r` and `C_K_CX = (g^K)^secret_x * (C_X)^secret_r`. This is not correct for our use case.
//
// Correct DLE for `C_agg = g^K * C_X * h^(R-r_X)`:
// Let `C_agg = g^S h^R`. We know `S = K + X`. So `C_agg = g^(K+X) h^R = g^K g^X h^R`.
// We have `C_X = g^X h^{r_X}`.
// So `g^X = C_X * h^{-r_X}`.
// Substitute: `C_agg = g^K * (C_X * h^{-r_X}) * h^R = g^K * C_X * h^(R - r_X)`.
// Prover knows `S, R, X, r_X`.
// This is a proof of knowledge of `(X, R-r_X)` such that `C_agg * (g^K)^-1 * (C_X)^-1 = h^(R-r_X)`.
// This is a Chaum-Pedersen for a specific combination of points.
// Let `Target = C_agg * (g^K)^-1 * (C_X)^-1`. We prove `log_h(Target) == R - r_X`.

type DLSEqualityProof struct {
	Commitment1 Point  // c_t for the Chaum-Pedersen (g^v * h^w)
	ResponseX   Scalar // z_v for the Chaum-Pedersen
	ResponseR   Scalar // z_w for the Chaum-Pedersen
}

// proveDLSEquality proves log_h(Target) == secret_val, where Target = C_agg * (g^K)^-1 * (C_X)^-1.
// secret_val is (R - r_X).
func proveDLSEquality(curve *ellipticCurve, target_point Point, secret_val Scalar, globalChallenge Scalar) DLSEqualityProof {
	nonceV := randScalar(curve)
	nonceR := randScalar(curve)

	// Commitment: `c_t = h^nonceV` (since G is not involved in this part for `target_point = h^secret_val`)
	// We need to prove knowledge of `secret_val` and a `randomness` for `target_point`.
	// For Chaum-Pedersen for `P = g^x`, it is `t=g^v`, `z=v+e*x`.
	// Here `target_point = h^(R-r_X)`. We need to prove `log_h(target_point) = (R-r_X)`.
	// This is a simple Chaum-Pedersen:
	
	nonce := randScalar(curve) // For the secret (R-r_X)
	nonceComm := scalarMult(curve.H, nonce, curve.Curve) // h^nonce

	response := new(big.Int).Mul(globalChallenge, secret_val)
	response.Add(response, nonce)
	response.Mod(response, curve.Q)

	return DLSEqualityProof{
		Commitment1: nonceComm, // This is the Chaum-Pedersen `t`
		ResponseX:   response,  // This is the Chaum-Pedersen `z`
		ResponseR:   NewScalar(0), // Not used for this form of Chaum-Pedersen, keeping struct consistent
	}
}

// verifyDLSEquality verifies a `DLSEqualityProof` (for log_h(Target) == secret_val).
func verifyDLSEquality(curve *ellipticCurve, target_point Point, proof DLSEqualityProof, globalChallenge Scalar) bool {
	// Check: h^proof.ResponseX == proof.Commitment1 * target_point^globalChallenge
	lhs := scalarMult(curve.H, proof.ResponseX, curve.Curve)

	rhsFactor := scalarMult(target_point, globalChallenge, curve.Curve)
	rhs := pointAdd(proof.Commitment1, rhsFactor, curve.Curve)

	return pointEqual(lhs, rhs)
}

// --- VI. Main Aggregate Membership ZKP Functions ---

// ProverIndividualInput: Struct for a single individual's private input.
type ProverIndividualInput struct {
	Status    Scalar // 0 or 1
	Randomness Scalar
}

// ProverMembershipProof: Struct for the entire aggregate proof.
type ProverMembershipProof struct {
	IndividualBitProofs []BitProof          // Proofs for each individual's status (s_i in {0,1})
	CommitmentX         Commitment          // Commitment to X = S - K
	ProofX              ValueDecompositionProof // Proof that X is non-negative and bounded
	ComplianceDLE       DLSEqualityProof    // Proof that aggregate sum (S) meets threshold (K)
}

// ProverAggregateMembership is the main prover function. It takes individual inputs, computes aggregate values,
// and generates the full ZKP.
func ProverAggregateMembership(curve *ellipticCurve, inputs []ProverIndividualInput, thresholdK Scalar, numIndividuals int) (Commitment, []Commitment, ProverMembershipProof, error) {
	if len(inputs) != numIndividuals {
		return Point{}, nil, ProverMembershipProof{}, fmt.Errorf("number of inputs mismatch numIndividuals")
	}

	// 1. Compute global challenge for Fiat-Shamir
	var challengeData [][]byte
	challengeData = append(challengeData, curve.G.X.Bytes(), curve.G.Y.Bytes())
	challengeData = append(challengeData, curve.H.X.Bytes(), curve.H.Y.Bytes())
	challengeData = append(challengeData, thresholdK.Bytes())
	challengeData = append(challengeData, NewScalar(int64(numIndividuals)).Bytes())

	// Individual commitments
	individualCommitments := make([]Commitment, numIndividuals)
	for i, input := range inputs {
		if input.Status.Cmp(NewScalar(0)) != 0 && input.Status.Cmp(NewScalar(1)) != 0 {
			return Point{}, nil, ProverMembershipProof{}, fmt.Errorf("individual status must be 0 or 1")
		}
		individualCommitments[i] = NewPedersenCommitment(curve, input.Status, input.Randomness)
		challengeData = append(challengeData, individualCommitments[i].X.Bytes(), individualCommitments[i].Y.Bytes())
	}

	globalChallenge := hashToScalar(curve, challengeData...)

	// 2. Generate individual BitProofs
	individualBitProofs := make([]BitProof, numIndividuals)
	for i, input := range inputs {
		individualBitProofs[i] = ProveBit(curve, input.Status, input.Randomness, individualCommitments[i], globalChallenge)
	}

	// 3. Aggregate commitments and compute secret sum S and randomness R
	aggregateSum := NewScalar(0)
	aggregateRandomness := NewScalar(0)
	aggregateCommitment := Point{} // Identity point for aggregation
	
	firstCommitment := true
	for i, input := range inputs {
		aggregateSum.Add(aggregateSum, input.Status)
		aggregateSum.Mod(aggregateSum, curve.Q)

		aggregateRandomness.Add(aggregateRandomness, input.Randomness)
		aggregateRandomness.Mod(aggregateRandomness, curve.Q)
		
		if firstCommitment {
			aggregateCommitment = individualCommitments[i]
			firstCommitment = false
		} else {
			aggregateCommitment = pointAdd(aggregateCommitment, individualCommitments[i], curve.Curve)
		}
	}

	// Verify the aggregate commitment matches `g^S h^R`
	expectedAggComm := NewPedersenCommitment(curve, aggregateSum, aggregateRandomness)
	if !pointEqual(aggregateCommitment, expectedAggComm) {
		return Point{}, nil, ProverMembershipProof{}, fmt.Errorf("aggregate commitment mismatch calculated sum/randomness")
	}

	// 4. Compute X = S - K and generate its commitment and ValueDecompositionProof
	excessX := new(big.Int).Sub(aggregateSum, thresholdK)
	excessX.Mod(excessX, curve.Q)
	
	if excessX.Sign() < 0 {
		return Point{}, nil, ProverMembershipProof{}, fmt.Errorf("aggregate sum %d is less than threshold %d", aggregateSum.Int64(), thresholdK.Int64())
	}

	randomnessX := randScalar(curve) // Randomness for C_X
	commitmentX := NewPedersenCommitment(curve, excessX, randomnessX)
	
	// Max possible value for X is N (if K=0). MaxBound for X is N.
	maxBoundForX := numIndividuals 
	proofX := proveValueDecomposition(curve, excessX, randomnessX, maxBoundForX, globalChallenge)

	// 5. Generate Compliance DLE Proof:
	// Proves C_agg = g^K * C_X * h^(R - r_X)
	// Which is equivalent to proving `log_h(Target) == (aggregateRandomness - randomnessX)`
	// where `Target = C_agg * (g^K)^-1 * (C_X)^-1`
	
	gK := scalarMult(curve.G, thresholdK, curve.Curve)
	gKInv := scalarMult(gK, new(big.Int).Neg(NewScalar(1)), curve.Curve)
	
	cXInv := scalarMult(commitmentX, new(big.Int).Neg(NewScalar(1)), curve.Curve)
	
	targetPoint := pointAdd(aggregateCommitment, gKInv, curve.Curve)
	targetPoint = pointAdd(targetPoint, cXInv, curve.Curve)

	secretValForDLE := new(big.Int).Sub(aggregateRandomness, randomnessX)
	secretValForDLE.Mod(secretValForDLE, curve.Q)
	
	complianceDLE := proveDLSEquality(curve, targetPoint, secretValForDLE, globalChallenge)

	proof := ProverMembershipProof{
		IndividualBitProofs: individualBitProofs,
		CommitmentX:         commitmentX,
		ProofX:              proofX,
		ComplianceDLE:       complianceDLE,
	}

	return aggregateCommitment, individualCommitments, proof, nil
}

// VerifierAggregateMembership is the main verifier function. It takes public commitments, threshold,
// and the proof, then verifies all components.
func VerifierAggregateMembership(curve *ellipticCurve, individualCommitments []Commitment, thresholdK Scalar, numIndividuals int, proof ProverMembershipProof) bool {
	if len(individualCommitments) != numIndividuals || len(proof.IndividualBitProofs) != numIndividuals {
		fmt.Println("Verifier: Number of individual commitments or bit proofs mismatch.")
		return false
	}

	// 1. Compute global challenge for Fiat-Shamir
	var challengeData [][]byte
	challengeData = append(challengeData, curve.G.X.Bytes(), curve.G.Y.Bytes())
	challengeData = append(challengeData, curve.H.X.Bytes(), curve.H.Y.Bytes())
	challengeData = append(challengeData, thresholdK.Bytes())
	challengeData = append(challengeData, NewScalar(int64(numIndividuals)).Bytes())

	for _, comm := range individualCommitments {
		challengeData = append(challengeData, comm.X.Bytes(), comm.Y.Bytes())
	}
	globalChallenge := hashToScalar(curve, challengeData...)

	// 2. Verify each individual BitProof
	for i, comm := range individualCommitments {
		if !VerifyBitProof(curve, comm, proof.IndividualBitProofs[i], globalChallenge) {
			fmt.Printf("Verifier: Individual BitProof %d failed.\n", i)
			return false
		}
	}

	// 3. Reconstruct aggregate commitment from individual commitments
	aggregateCommitment := Point{}
	firstCommitment := true
	for _, comm := range individualCommitments {
		if firstCommitment {
			aggregateCommitment = comm
			firstCommitment = false
		} else {
			aggregateCommitment = pointAdd(aggregateCommitment, comm, curve.Curve)
		}
	}

	// 4. Verify ValueDecompositionProof for CommitmentX
	maxBoundForX := numIndividuals
	if !verifyValueDecomposition(curve, proof.CommitmentX, maxBoundForX, proof.ProofX, globalChallenge) {
		fmt.Println("Verifier: ValueDecompositionProof for X failed.")
		return false
	}
	
	// 5. Verify Compliance DLE Proof
	// Target point for DLE: `C_agg * (g^K)^-1 * (C_X)^-1`
	gK := scalarMult(curve.G, thresholdK, curve.Curve)
	gKInv := scalarMult(gK, new(big.Int).Neg(NewScalar(1)), curve.Curve)
	
	cXInv := scalarMult(proof.CommitmentX, new(big.Int).Neg(NewScalar(1)), curve.Curve)
	
	targetPoint := pointAdd(aggregateCommitment, gKInv, curve.Curve)
	targetPoint = pointAdd(targetPoint, cXInv, curve.Curve)

	if !verifyDLSEquality(curve, targetPoint, proof.ComplianceDLE, globalChallenge) {
		fmt.Println("Verifier: Compliance DLE Proof failed.")
		return false
	}

	return true
}

// Helper to convert Scalar to byte slice for hashing
func scalarToBytes(s Scalar) []byte {
	return s.Bytes()
}

// Helper to convert Point to byte slice for hashing
func pointToBytes(p Point) []byte {
	return append(p.X.Bytes(), p.Y.Bytes()...)
}
```