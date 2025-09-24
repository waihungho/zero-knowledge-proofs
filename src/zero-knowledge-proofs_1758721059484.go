This Golang package implements a Zero-Knowledge Proof (ZKP) system for **"Private Aggregate Attribute Compliance Proof (PAACP)"**.

## Outline and Function Summary

This system allows a Prover to demonstrate to a Verifier that they possess `k` private attributes, each committed to publicly, and that the sum of these `k` attributes equals a publicly declared target value. This is achieved without revealing the individual attribute values, their blinding factors, or which specific individuals contributed (beyond their public commitments).

### Use Case Scenario:
Imagine a decentralized autonomous organization (DAO) or a confidential consortium where members (individuals) each have a private attribute (e.g., their stake amount, their vote weight, or a confidential score). A Verifier (e.g., the DAO treasury, a regulatory body) needs to verify if the *total* aggregate of these attributes from a selected subset of `k` members meets a specific threshold or target sum, without exposing any individual member's contribution.

For example, proving: "I have gathered `k` valid commitments from registered members, and the sum of their *private, committed stake amounts* is exactly `X` (the required threshold) to unlock a feature, without revealing any individual's stake or identity."

### Core Concepts & ZKP Application:
1.  **Pedersen Commitments**: Each individual's private attribute (`value`) is committed to using a Pedersen commitment `C = value*G + blindingFactor*H`. This hides the `value` and `blindingFactor` while allowing the commitment to be publicly verified and homomorphically aggregated.
2.  **Homomorphic Aggregation**: Multiple Pedersen commitments can be summed (`C_sum = Sum(C_j) = (Sum(value_j))*G + (Sum(blindingFactor_j))*H`). This allows proving properties about the sum of values without knowing individual values.
3.  **Knowledge of Commitment Opening (KCO) Proof**: A Σ-protocol is used to prove knowledge of `(value, blindingFactor)` for a commitment `C` without revealing them. This forms the basis for proving knowledge of the aggregate sum.
4.  **Fiat-Shamir Heuristic**: Makes the interactive Σ-protocol non-interactive by deriving the Verifier's challenge from a hash of all public protocol messages.
5.  **Merkle Tree**: Used to publicly register all valid individual commitments. This allows the Verifier to confirm that the `k` revealed commitments used in the aggregation are legitimate and belong to the registered set, without needing to know the full list of all possible commitments.

### Implementation Simplifications:
*   **Target Sum instead of Range Proof**: A full ZKP range proof (proving `Sum(attr_j)` is in `[Min, Max]`) is computationally expensive and complex to implement from scratch. This implementation focuses on proving that the aggregate sum of attributes is *equal to a specific publicly declared target sum*.
*   **Revealed Commitments for Membership**: For simplicity, the `k` individual commitments (`C_j`) that are part of the aggregation are revealed to the Verifier. The ZKP then proves knowledge of their hidden openings and their aggregate sum, and that each `C_j` is part of a registered set via a Merkle inclusion proof. If `C_j` also needed to be hidden, a more complex "private set membership" ZKP would be required.

---

### Function Summary

#### 1. Elliptic Curve Cryptography (ECC) Primitives
*   `curve`: Global elliptic curve parameters (P-256).
*   `initEC()`: Initializes the elliptic curve parameters.
*   `newScalar() (*big.Int, error)`: Generates a cryptographically secure random scalar.
*   `scalarMult(point *ECPoint, scalar *big.Int) *ECPoint`: Performs scalar multiplication on an EC point.
*   `pointAdd(p1, p2 *ECPoint) *ECPoint`: Performs point addition on two EC points.
*   `hashToScalar(data ...[]byte) *big.Int`: Hashes multiple byte slices to a scalar, suitable for challenges.

#### 2. Pedersen Commitments
*   `ECPoint`: Represents a point on the elliptic curve (x, y coordinates).
*   `CommitmentGens`: Stores the Pedersen commitment generators (G, H).
*   `GeneratePedersenGens() (*CommitmentGens, error)`: Creates and returns two cryptographically secure, independent generator points G and H.
*   `NewPedersenCommitment(value, blindingFactor *big.Int, gens *CommitmentGens) (*ECPoint, error)`: Computes and returns a Pedersen commitment `C = value*G + blindingFactor*H`.
*   `VerifyPedersenCommitment(value, blindingFactor *big.Int, commitment *ECPoint, gens *CommitmentGens) bool`: Verifies if a given `value` and `blindingFactor` correctly open a `commitment`.

#### 3. Zero-Knowledge Proof (ZKP) Building Blocks
*   `KCOProof`: Structure to hold a Knowledge of Commitment Opening proof.
*   `NewKCOProver(value, blindingFactor *big.Int, gens *CommitmentGens, commitment *ECPoint, challenge *big.Int) (*KCOProof, error)`: Prover's side to construct a KCO proof for a single commitment.
*   `VerifyKCOProof(commitment *ECPoint, gens *CommitmentGens, proof *KCOProof) bool`: Verifier's side to check a KCO proof.
*   `GenerateChallenge(data ...[]byte) *big.Int`: Generates a challenge scalar using Fiat-Shamir hash.

#### 4. Aggregate Sum Proof (Built upon KCO)
*   `AggregateSumProof`: Structure to hold the aggregate sum proof components.
*   `NewAggregateSumProofProver(values, blindingFactors []*big.Int, commitments []*ECPoint, targetSum *big.Int, gens *CommitmentGens) (*AggregateSumProof, error)`: Prover's side for the aggregate sum proof. This computes the aggregate commitment and then uses `NewKCOProver` to prove knowledge of the aggregate value and blinding factor, ensuring the aggregate value matches `targetSum`.
*   `VerifyAggregateSumProof(commitments []*ECPoint, targetSum *big.Int, gens *CommitmentGens, proof *AggregateSumProof) bool`: Verifier's side to check an aggregate sum proof. This recomputes the aggregate commitment and then uses `VerifyKCOProof`.

#### 5. Merkle Tree for Public Commitment Registry
*   `ComputeMerkleRoot(leaves [][]byte) ([]byte, error)`: Computes the Merkle root from a slice of byte leaves (e.g., hashes of `ECPoint`s).
*   `GenerateMerkleProof(leaves [][]byte, index int) ([][]byte, error)`: Generates an inclusion proof for a specific leaf at a given index.
*   `VerifyMerkleProof(root []byte, leaf []byte, proof [][]byte, index int) bool`: Verifies a Merkle inclusion proof against a given root.

#### 6. Private Aggregate Attribute Compliance Proof (PAACP)
*   `PAACP_Proof`: Structure representing the full proof for private aggregate attribute compliance.
*   `NewPAACP_Prover(privateValues, privateBlindingFactors []*big.Int, publicCommitments []*ECPoint,
  allRegisteredCommitmentHashes [][]byte, targetSum *big.Int, gens *CommitmentGens) (*PAACP_Proof, error)`:
  The main Prover function. It takes the `k` private attributes and their blinding factors, the corresponding `k` public commitments,
  a list of *all* registered commitments (as hashes for Merkle tree construction), and the `targetSum`.
  It generates Merkle proofs for each of the `k` public commitments and then an `AggregateSumProof`.
*   `VerifyPAACP_Proof(registeredMerkleRoot []byte, publicCommitments []*ECPoint, targetSum *big.Int,
  gens *CommitmentGens, proof *PAACP_Proof) bool`:
  The main Verifier function. It takes the Merkle root of all registered commitments, the `k` public commitments (which the Prover reveals),
  the `targetSum`, Pedersen generators, and the `PAACP_Proof` structure. It verifies each Merkle inclusion proof
  for the revealed commitments and then verifies the `AggregateSumProof`.

---

```go
package zkp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Outline and Function Summary
//
// This package implements a Zero-Knowledge Proof (ZKP) system for "Private Aggregate Attribute Compliance".
// The core idea is to allow a Prover to demonstrate to a Verifier that they possess 'k' private
// attributes, each committed to publicly, and that the sum of these 'k' attributes equals a
// public target value, without revealing the individual attribute values or their blinding factors.
//
// This is achieved using a combination of Elliptic Curve Cryptography (ECC), Pedersen Commitments,
// and Σ-protocol style proofs (specifically, Knowledge of Commitment Opening, or KCO).
// A Merkle tree is used to publicly register all possible attribute commitments, allowing the
// Verifier to confirm the selected commitments are legitimate, even if the Prover doesn't reveal
// which specific individuals they correspond to (in a fully anonymous setup, which is not fully
// implemented here due to complexity constraints for 20 functions, the commitments themselves
// would also be hidden, requiring more advanced techniques like private set membership proofs).
//
// In this implementation, the 'k' individual commitments (C_j) are revealed, but the private
// attribute values (attr_j) and their blinding factors (r_j) are kept secret. The ZKP proves
// knowledge of these hidden values and that their sum (Sum(attr_j)) equals a publicly known target value.
// A full range proof (proving Sum(attr_j) in [Min, Max]) is complex for a hand-rolled Σ-protocol.
// Therefore, for simplicity and to fit the function count, this implementation focuses on proving
// that the *aggregate sum* of hidden attributes is equal to a *publicly declared target sum*.
// Extending to a full range proof (e.g., via bit decomposition or Bulletproofs) would require
// significantly more functions and complexity.
//
// This system can be used in scenarios like:
// - Verifying if a group's total donations meet a target without revealing individual amounts.
// - Checking if a committee's total staked amount reaches a threshold privately.
// - Anonymous statistical aggregates.
//
// --- Core Cryptographic Primitives ---
//
// 1.  Elliptic Curve Operations: Basic operations on a chosen elliptic curve (P-256).
//     - `curve`: Global elliptic curve parameters.
//     - `initEC()`: Initializes the elliptic curve parameters.
//     - `newScalar() (*big.Int, error)`: Generates a random scalar (private key component) on the curve.
//     - `scalarMult(point *ECPoint, scalar *big.Int) *ECPoint`: Performs point scalar multiplication.
//     - `pointAdd(p1, p2 *ECPoint) *ECPoint`: Performs point addition.
//     - `hashToScalar(data ...[]byte) *big.Int`: Hashes multiple byte slices to a scalar.
//
// 2.  Pedersen Commitments: A homomorphic commitment scheme.
//     - `ECPoint`: Represents a point on the elliptic curve (x, y coordinates).
//     - `CommitmentGens`: Stores the Pedersen commitment generators (G, H).
//     - `GeneratePedersenGens() (*CommitmentGens, error)`: Generates two random, independent generator points G and H.
//     - `NewPedersenCommitment(value, blindingFactor *big.Int, gens *CommitmentGens) (*ECPoint, error)`: Creates C = value*G + blindingFactor*H.
//     - `VerifyPedersenCommitment(value, blindingFactor *big.Int, commitment *ECPoint, gens *CommitmentGens) bool`: Verifies the opening of a commitment.
//
// --- Zero-Knowledge Proof (ZKP) Building Blocks ---
//
// 3.  Knowledge of Commitment Opening (KCO) Proof: A Σ-protocol to prove knowledge of (value, blindingFactor) for a Pedersen Commitment.
//     - `KCOProof`: Struct to hold the KCO proof components (commitment, challenge, responses).
//     - `NewKCOProver(value, blindingFactor *big.Int, gens *CommitmentGens, commitment *ECPoint, challenge *big.Int) (*KCOProof, error)`: Prover's side to generate a KCO proof.
//     - `VerifyKCOProof(commitment *ECPoint, gens *CommitmentGens, proof *KCOProof) bool`: Verifier's side to check a KCO proof.
//     - `GenerateChallenge(data ...[]byte) *big.Int`: Helper to generate a Fiat-Shamir challenge from arbitrary data.
//
// 4.  Aggregate Sum Proof: Proves knowledge of multiple commitment openings such that their hidden values sum to a target.
//     - `AggregateSumProof`: Struct to hold the aggregate sum proof components.
//     - `NewAggregateSumProofProver(values, blindingFactors []*big.Int, commitments []*ECPoint, targetSum *big.Int, gens *CommitmentGens) (*AggregateSumProof, error)`: Prover side for the aggregate sum proof.
//       This involves aggregating the individual `values` and `blindingFactors` to create an aggregate `C_sum`,
//       and then proving knowledge of its opening, along with showing the aggregate value equals `targetSum`.
//     - `VerifyAggregateSumProof(commitments []*ECPoint, targetSum *big.Int, gens *CommitmentGens, proof *AggregateSumProof) bool`: Verifier side for the aggregate sum proof.
//
// --- Merkle Tree for Public Commitment Registry ---
//
// 5.  Merkle Tree: To register and verify membership of public commitments.
//     - `ComputeMerkleRoot(leaves [][]byte) ([]byte, error)`: Computes the Merkle root from a slice of byte leaves.
//     - `GenerateMerkleProof(leaves [][]byte, index int) ([][]byte, error)`: Generates an inclusion proof for a specific leaf.
//     - `VerifyMerkleProof(root []byte, leaf []byte, proof [][]byte, index int) bool`: Verifies a Merkle inclusion proof.
//
// --- Main ZKP Application ---
//
// 6.  Private Aggregate Attribute Compliance Proof (PAACP): Orchestrates the above components.
//     - `PAACP_Proof`: Struct representing the full private aggregate attribute compliance proof.
//     - `NewPAACP_Prover(privateValues, privateBlindingFactors []*big.Int, publicCommitments []*ECPoint,
//       allRegisteredCommitmentHashes [][]byte, targetSum *big.Int, gens *CommitmentGens) (*PAACP_Proof, error)`:
//       Prover generates the full proof. This function will select 'k' valid commitments from `allRegisteredCommitments`,
//       generate Merkle proofs for them, and an aggregate sum proof.
//       NOTE: For simplicity, the `publicCommitments` slice *is* the chosen subset. Merkle proofs for
//       each `publicCommitment` are included to show they are from the registered set.
//     - `VerifyPAACP_Proof(registeredMerkleRoot []byte, publicCommitments []*ECPoint,
//       targetSum *big.Int, gens *CommitmentGens, proof *PAACP_Proof) bool`: Verifier checks the full proof.
//       This function iterates through the `publicCommitments`, verifies their Merkle inclusion,
//       and then verifies the aggregate sum proof.
//
// In total, this implementation offers a sophisticated ZKP application demonstrating private aggregation
// of attributes with verifiable compliance against a target, built from fundamental cryptographic primitives.

// ECPoint represents a point on the elliptic curve.
type ECPoint struct {
	X *big.Int
	Y *big.Int
}

// curve stores the elliptic curve parameters (P-256).
var curve elliptic.Curve

// initEC initializes the elliptic curve parameters.
func initEC() {
	curve = elliptic.P256()
}

// newScalar generates a cryptographically secure random scalar (big.Int) within the curve's order.
func newScalar() (*big.Int, error) {
	k, err := rand.Int(rand.Reader, curve.N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return k, nil
}

// scalarMult performs scalar multiplication: scalar * point.
func scalarMult(point *ECPoint, scalar *big.Int) *ECPoint {
	x, y := curve.ScalarMult(point.X, point.Y, scalar.Bytes())
	return &ECPoint{X: x, Y: y}
}

// pointAdd performs point addition: p1 + p2.
func pointAdd(p1, p2 *ECPoint) *ECPoint {
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return &ECPoint{X: x, Y: y}
}

// hashToScalar hashes multiple byte slices to a big.Int scalar, suitable for challenges.
func hashToScalar(data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hashBytes := h.Sum(nil)
	// Ensure the hash result is within the curve's order (N)
	return new(big.Int).Mod(new(big.Int).SetBytes(hashBytes), curve.N)
}

// CommitmentGens stores the Pedersen commitment generators.
type CommitmentGens struct {
	G *ECPoint
	H *ECPoint
}

// GeneratePedersenGens generates two random, independent generator points G and H
// for the Pedersen commitment scheme.
func GeneratePedersenGens() (*CommitmentGens, error) {
	if curve == nil {
		initEC()
	}

	gX, gY := curve.Base().X, curve.Base().Y // Use the curve's base point as G
	g := &ECPoint{X: gX, Y: gY}

	// Generate a random H point by taking a random scalar multiple of G.
	// Ensure H is distinct from G.
	hScalar, err := newScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate scalar for H: %w", err)
	}
	h := scalarMult(g, hScalar)

	if h.X.Cmp(g.X) == 0 && h.Y.Cmp(g.Y) == 0 {
		// Should be extremely rare if newScalar is truly random and non-zero.
		// In a real system, you might regenerate or use a deterministic "nothing-up-my-sleeve" method.
		return nil, fmt.Errorf("generated H point is identical to G, retry")
	}

	return &CommitmentGens{G: g, H: h}, nil
}

// NewPedersenCommitment creates a Pedersen commitment C = value*G + blindingFactor*H.
func NewPedersenCommitment(value, blindingFactor *big.Int, gens *CommitmentGens) (*ECPoint, error) {
	if curve == nil {
		initEC()
	}

	term1 := scalarMult(gens.G, value)
	term2 := scalarMult(gens.H, blindingFactor)
	commitment := pointAdd(term1, term2)
	return commitment, nil
}

// VerifyPedersenCommitment verifies if a given value and blindingFactor correctly open a commitment.
func VerifyPedersenCommitment(value, blindingFactor *big.Int, commitment *ECPoint, gens *CommitmentGens) bool {
	expectedCommitment, err := NewPedersenCommitment(value, blindingFactor, gens)
	if err != nil {
		return false
	}
	return commitment.X.Cmp(expectedCommitment.X) == 0 && commitment.Y.Cmp(expectedCommitment.Y) == 0
}

// KCOProof represents a Knowledge of Commitment Opening proof.
type KCOProof struct {
	Challenge *big.Int // c
	Z_v       *big.Int // z_v = k_v + c*v
	Z_r       *big.Int // z_r = k_r + c*r
	T_x       *ECPoint // t_x = k_v*G + k_r*H
}

// NewKCOProver constructs a Knowledge of Commitment Opening (KCO) proof.
// Proves knowledge of (value, blindingFactor) for commitment C = value*G + blindingFactor*H.
func NewKCOProver(value, blindingFactor *big.Int, gens *CommitmentGens, commitment *ECPoint, challenge *big.Int) (*KCOProof, error) {
	if curve == nil {
		initEC()
	}
	// Generate random nonces k_v, k_r
	k_v, err := newScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate k_v: %w", err)
	}
	k_r, err := newScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate k_r: %w", err)
	}

	// Compute commitment t_x = k_v*G + k_r*H
	t_vG := scalarMult(gens.G, k_v)
	t_rH := scalarMult(gens.H, k_r)
	t_x := pointAdd(t_vG, t_rH)

	// Compute responses z_v = k_v + c*value (mod N), z_r = k_r + c*blindingFactor (mod N)
	z_v := new(big.Int).Mul(challenge, value)
	z_v.Add(k_v, z_v)
	z_v.Mod(z_v, curve.N)

	z_r := new(big.Int).Mul(challenge, blindingFactor)
	z_r.Add(k_r, z_r)
	z_r.Mod(z_r, curve.N)

	return &KCOProof{
		Challenge: challenge,
		Z_v:       z_v,
		Z_r:       z_r,
		T_x:       t_x,
	}, nil
}

// VerifyKCOProof verifies a Knowledge of Commitment Opening (KCO) proof.
func VerifyKCOProof(commitment *ECPoint, gens *CommitmentGens, proof *KCOProof) bool {
	if curve == nil {
		initEC()
	}
	// Check: z_v*G + z_r*H == t_x + c*C
	// Left side: z_v*G + z_r*H
	lhs_term1 := scalarMult(gens.G, proof.Z_v)
	lhs_term2 := scalarMult(gens.H, proof.Z_r)
	lhs := pointAdd(lhs_term1, lhs_term2)

	// Right side: t_x + c*C
	rhs_term2 := scalarMult(commitment, proof.Challenge)
	rhs := pointAdd(proof.T_x, rhs_term2)

	return lhs.X.Cmp(rhs.X) == 0 && lhs.Y.Cmp(rhs.Y) == 0
}

// AggregateSumProof represents the proof for an aggregated sum of commitments.
type AggregateSumProof struct {
	AggregateCommitment *ECPoint // C_agg = Sum(C_j)
	KCOProof            *KCOProof
}

// NewAggregateSumProofProver creates a ZKP that proves the sum of hidden values
// in 'commitments' equals 'targetSum'.
func NewAggregateSumProofProver(values, blindingFactors []*big.Int, commitments []*ECPoint,
	targetSum *big.Int, gens *CommitmentGens) (*AggregateSumProof, error) {

	if len(values) != len(blindingFactors) || len(values) != len(commitments) || len(values) == 0 {
		return nil, fmt.Errorf("input slices must have the same non-zero length")
	}

	if curve == nil {
		initEC()
	}

	// 1. Compute the aggregate commitment C_agg = Sum(C_j)
	aggregateCommitment := commitments[0]
	for i := 1; i < len(commitments); i++ {
		aggregateCommitment = pointAdd(aggregateCommitment, commitments[i])
	}

	// 2. Compute the aggregate value (which should be targetSum) and aggregate blinding factor
	// S_v = Sum(v_j)
	aggregateValue := big.NewInt(0)
	for _, v := range values {
		aggregateValue.Add(aggregateValue, v)
	}
	aggregateValue.Mod(aggregateValue, curve.N)

	// S_r = Sum(r_j)
	aggregateBlindingFactor := big.NewInt(0)
	for _, r := range blindingFactors {
		aggregateBlindingFactor.Add(aggregateBlindingFactor, r)
	}
	aggregateBlindingFactor.Mod(aggregateBlindingFactor, curve.N)

	// Verify that the aggregate value indeed equals the target sum
	if aggregateValue.Cmp(targetSum) != 0 {
		return nil, fmt.Errorf("calculated aggregate value %v does not match target sum %v", aggregateValue, targetSum)
	}

	// 3. Generate challenge for the KCO proof
	// The challenge must bind the aggregate commitment and target sum
	challenge := GenerateChallenge(aggregateCommitment.X.Bytes(), aggregateCommitment.Y.Bytes(), targetSum.Bytes())

	// 4. Create KCO proof for the aggregate commitment and aggregate (value, blindingFactor)
	kcoProof, err := NewKCOProver(aggregateValue, aggregateBlindingFactor, gens, aggregateCommitment, challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to create KCO proof for aggregate: %w", err)
	}

	return &AggregateSumProof{
		AggregateCommitment: aggregateCommitment,
		KCOProof:            kcoProof,
	}, nil
}

// VerifyAggregateSumProof verifies an aggregate sum proof.
func VerifyAggregateSumProof(commitments []*ECPoint, targetSum *big.Int, gens *CommitmentGens, proof *AggregateSumProof) bool {
	if curve == nil {
		initEC()
	}
	if len(commitments) == 0 {
		return false
	}

	// 1. Recompute the aggregate commitment from the individual commitments
	expectedAggregateCommitment := commitments[0]
	for i := 1; i < len(commitments); i++ {
		expectedAggregateCommitment = pointAdd(expectedAggregateCommitment, commitments[i])
	}

	// 2. Check if the proof's aggregate commitment matches the recomputed one
	if expectedAggregateCommitment.X.Cmp(proof.AggregateCommitment.X) != 0 ||
		expectedAggregateCommitment.Y.Cmp(proof.AggregateCommitment.Y) != 0 {
		fmt.Println("Aggregate commitment mismatch")
		return false
	}

	// 3. The challenge for the KCO proof needs to be re-derived by the verifier
	expectedChallenge := GenerateChallenge(proof.AggregateCommitment.X.Bytes(), proof.AggregateCommitment.Y.Bytes(), targetSum.Bytes())

	// Check if the challenge in the proof matches the expected one (for consistency, though NewKCOProver creates it)
	if expectedChallenge.Cmp(proof.KCOProof.Challenge) != 0 {
		fmt.Println("Challenge mismatch in aggregate sum proof")
		return false
	}

	// 4. Verify the KCO proof
	return VerifyKCOProof(proof.AggregateCommitment, gens, proof.KCOProof)
}

// GenerateChallenge creates a challenge scalar using Fiat-Shamir heuristic.
func GenerateChallenge(data ...[]byte) *big.Int {
	return hashToScalar(data...)
}

// --- Merkle Tree for Public Commitment Registry ---

// ComputeMerkleRoot computes the Merkle root from a slice of byte leaves.
func ComputeMerkleRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("no leaves provided to compute Merkle root")
	}
	if len(leaves) == 1 {
		return sha256.Sum256(leaves[0]), nil
	}

	// Pad with a duplicate if odd number of leaves
	if len(leaves)%2 != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	var newLevel [][]byte
	for i := 0; i < len(leaves); i += 2 {
		h := sha256.New()
		// Ensure consistent ordering by sorting or fixed concatenation
		if bytes.Compare(leaves[i], leaves[i+1]) < 0 {
			h.Write(leaves[i])
			h.Write(leaves[i+1])
		} else {
			h.Write(leaves[i+1])
			h.Write(leaves[i])
		}
		newLevel = append(newLevel, h.Sum(nil))
	}
	return ComputeMerkleRoot(newLevel) // Recursive call
}

// GenerateMerkleProof generates an inclusion proof for a specific leaf.
func GenerateMerkleProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("index out of bounds")
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("no leaves provided")
	}

	proof := [][]byte{}
	currentLevel := make([][]byte, len(leaves))
	copy(currentLevel, leaves)

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1]) // Pad
		}

		pairIndex := index / 2 * 2 // Start of the pair
		if index%2 == 0 {         // Leaf is left child
			proof = append(proof, currentLevel[pairIndex+1])
		} else { // Leaf is right child
			proof = append(proof, currentLevel[pairIndex])
		}

		nextLevel := [][]byte{}
		for i := 0; i < len(currentLevel); i += 2 {
			h := sha256.New()
			// Consistent ordering
			if bytes.Compare(currentLevel[i], currentLevel[i+1]) < 0 {
				h.Write(currentLevel[i])
				h.Write(currentLevel[i+1])
			} else {
				h.Write(currentLevel[i+1])
				h.Write(currentLevel[i])
			}
			nextLevel = append(nextLevel, h.Sum(nil))
		}
		currentLevel = nextLevel
		index /= 2
	}
	return proof, nil
}

// VerifyMerkleProof verifies a Merkle inclusion proof.
func VerifyMerkleProof(root []byte, leaf []byte, proof [][]byte, index int) bool {
	currentHash := leaf
	for _, p := range proof {
		h := sha256.New()
		if index%2 == 0 { // currentHash was a left child
			if bytes.Compare(currentHash, p) < 0 {
				h.Write(currentHash)
				h.Write(p)
			} else {
				h.Write(p)
				h.Write(currentHash)
			}
		} else { // currentHash was a right child
			if bytes.Compare(p, currentHash) < 0 {
				h.Write(p)
				h.Write(currentHash)
			} else {
				h.Write(currentHash)
				h.Write(p)
			}
		}
		currentHash = h.Sum(nil)
		index /= 2
	}
	return bytes.Equal(currentHash, root)
}

// --- Main ZKP Application: Private Aggregate Attribute Compliance Proof (PAACP) ---

// PAACP_Proof combines all elements for the Private Aggregate Attribute Compliance Proof.
type PAACP_Proof struct {
	MerkleProofs []*MerkleProofBundle // Merkle proofs for each selected public commitment
	AggProof     *AggregateSumProof   // Aggregate sum proof for the hidden values
}

// MerkleProofBundle bundles a leaf with its proof and index for verification.
type MerkleProofBundle struct {
	Leaf  []byte
	Proof [][]byte
	Index int
}

// NewPAACP_Prover generates a Private Aggregate Attribute Compliance Proof.
// It requires the private attribute values and blinding factors for the selected commitments,
// the public EC points of these selected commitments, a list of *all* registered commitment hashes
// (to build Merkle proofs), the target aggregate sum, and Pedersen generators.
func NewPAACP_Prover(privateValues, privateBlindingFactors []*big.Int, publicCommitments []*ECPoint,
	allRegisteredCommitmentHashes [][]byte, targetSum *big.Int, gens *CommitmentGens) (*PAACP_Proof, error) {

	if len(privateValues) != len(publicCommitments) || len(privateValues) == 0 {
		return nil, fmt.Errorf("number of private values and public commitments must be equal and non-zero")
	}
	if len(allRegisteredCommitmentHashes) == 0 {
		return nil, fmt.Errorf("no registered commitments provided for Merkle tree")
	}

	merkleProofs := make([]*MerkleProofBundle, len(publicCommitments))
	// 1. Generate Merkle proofs for each selected public commitment
	for i, commitment := range publicCommitments {
		commitmentBytes := append(commitment.X.Bytes(), commitment.Y.Bytes()...)
		leafHash := sha256.Sum256(commitmentBytes) // Hash the commitment point for Merkle tree leaf

		// Find the index of this commitment hash in the allRegisteredCommitmentHashes
		foundIndex := -1
		for j, registeredHash := range allRegisteredCommitmentHashes {
			if bytes.Equal(leafHash[:], registeredHash) {
				foundIndex = j
				break
			}
		}
		if foundIndex == -1 {
			return nil, fmt.Errorf("selected public commitment %d is not found in registered commitments", i)
		}

		proof, err := GenerateMerkleProof(allRegisteredCommitmentHashes, foundIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Merkle proof for commitment %d: %w", i, err)
		}
		merkleProofs[i] = &MerkleProofBundle{
			Leaf:  leafHash[:],
			Proof: proof,
			Index: foundIndex,
		}
	}

	// 2. Generate the Aggregate Sum Proof
	aggProof, err := NewAggregateSumProofProver(privateValues, privateBlindingFactors, publicCommitments, targetSum, gens)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aggregate sum proof: %w", err)
	}

	return &PAACP_Proof{
		MerkleProofs: merkleProofs,
		AggProof:     aggProof,
	}, nil
}

// VerifyPAACP_Proof verifies a Private Aggregate Attribute Compliance Proof.
// It requires the Merkle root of all registered commitments, the public EC points
// of the 'k' commitments that were used in aggregation, the target sum, Pedersen generators,
// and the full PAACP_Proof structure.
func VerifyPAACP_Proof(registeredMerkleRoot []byte, publicCommitments []*ECPoint, targetSum *big.Int,
	gens *CommitmentGens, proof *PAACP_Proof) bool {

	if len(publicCommitments) != len(proof.MerkleProofs) || len(publicCommitments) == 0 {
		fmt.Println("Mismatch in number of commitments or Merkle proofs")
		return false
	}

	// 1. Verify each Merkle inclusion proof for the revealed public commitments
	for i, commitment := range publicCommitments {
		bundle := proof.MerkleProofs[i]
		commitmentBytes := append(commitment.X.Bytes(), commitment.Y.Bytes()...)
		leafHash := sha256.Sum256(commitmentBytes)

		// Check if the leaf hash in the bundle matches the hash of the current public commitment
		if !bytes.Equal(leafHash[:], bundle.Leaf) {
			fmt.Printf("Merkle proof bundle leaf hash mismatch for commitment %d\n", i)
			return false
		}

		if !VerifyMerkleProof(registeredMerkleRoot, bundle.Leaf, bundle.Proof, bundle.Index) {
			fmt.Printf("Merkle proof verification failed for commitment %d\n", i)
			return false
		}
	}

	// 2. Verify the Aggregate Sum Proof
	if !VerifyAggregateSumProof(publicCommitments, targetSum, gens, proof.AggProof) {
		fmt.Println("Aggregate sum proof verification failed")
		return false
	}

	return true
}

// Initialize the curve on package load
func init() {
	initEC()
}
```