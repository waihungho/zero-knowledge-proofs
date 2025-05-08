Okay, this is an ambitious request! Creating a *completely novel* ZKP construction or system from scratch that is also "advanced, creative, and trendy" and has 20+ distinct functions is beyond the scope of a single code example without duplicating concepts found in existing libraries (which are often the result of years of research and development).

However, I can provide a *custom implementation* of a specific, non-trivial Zero-Knowledge Proof protocol tailored to an interesting problem, using standard cryptographic primitives implemented via `math/big` to avoid direct reliance on external ZKP libraries. This will demonstrate the *principles* and structure of a ZKP system for a specific task, fulfilling the spirit of the request.

The problem we will address:

**Zero-Knowledge Proof of Knowledge of a Private Value Matching One of Public Qualifying Tiers.**

**Concept:** A Prover has a private numerical score or value (`x`). A Verifier has a public list of acceptable "qualifying tiers" or target values (`T_1, T_2, ..., T_m`). The Prover wants to prove to the Verifier that their private score `x` is equal to *at least one* of the public target values `T_j`, without revealing `x` or *which* `T_j` it matches.

**Advanced/Creative/Trendy Aspects:**
*   **Application:** Represents a common scenario in credentialing, access control, or verifiable eligibility where the exact reason for qualification must remain private (e.g., "I qualify for a discount" without revealing *which* specific eligibility criterion was met, or "I am in an allowed risk tier" without revealing the exact score).
*   **Protocol:** We will implement a tailored Sigma-protocol based ZK proof for proving knowledge of a commitment opening value being part of a public set. This involves commitment schemes, a Fiat-Shamir transform for non-interactivity, and a specific "OR" proof construction to hide which target value was matched. Implementing the "OR" proof simulation correctly adds significant complexity and requires careful management of secret values.
*   **Implementation:** Using `math/big` for modular arithmetic and cryptographic operations avoids relying on dedicated elliptic curve or ZKP libraries, demonstrating the ZKP logic using more fundamental building blocks (albeit in a conceptual modular arithmetic group rather than a standard elliptic curve).

**Outline:**

1.  **System Parameters:** Structures and functions for generating and managing public parameters (modulus, generators).
2.  **Commitment Scheme:** A simple Pedersen-like commitment using modular exponentiation. Functions for creating and conceptually verifying commitments.
3.  **Problem Definition:** Structures for public targets and the private value/randomness.
4.  **Prover State & Proof:** Structures holding prover's secrets, intermediate values, and the final proof components. Functions for each step of the proving process.
5.  **Verifier State & Verification:** Structures for verifier's inputs and intermediate checks. Functions for each step of the verification process.
6.  **Core ZKP Protocol Steps:** Functions implementing the specific steps of the Sigma-protocol based OR proof (commitment difference, challenge generation, response calculation, response verification).
7.  **Utility Functions:** Modular arithmetic helpers, hashing, randomness generation.

**Function Summary (targeting 20+):**

*   `GenerateSystemParameters`: Creates `P`, `G`, `H` (modulus, generators).
*   `NewCommitment`: Creates a `Commitment` struct.
*   `Commit`: Computes `G^value * H^randomness mod P`.
*   `VerifyCommitment`: Conceptually verifies `C = G^value * H^randomness mod P` (mostly for testing; ZKPs verify relations *on* commitments).
*   `GenerateRandomBigInt`: Helper to get a cryptographically secure random `big.Int`.
*   `Hash`: Helper for Fiat-Shamir challenge.
*   `ModExp`: Helper for modular exponentiation.
*   `ModInverse`: Helper for modular inverse (needed for exponent arithmetic mod P-1).
*   `ModAdd`, `ModSub`, `ModMul`: Helpers for modular arithmetic.
*   `NewProverState`: Initializes prover state with private data and public targets.
*   `ProverComputeValueCommitment`: Prover commits to their secret value `x`.
*   `ProverComputeTargetDiffCommitments`: For each target `T_j`, compute `C_diff_j = C - T_j*G mod P`.
*   `ProverGenerateRandomSecretsForORProof`: For each target, Prover generates random `v_j` (commitments for the OR proof).
*   `ProverComputeIntermediateProofElements`: Computes `A_j = v_j * H mod P` for each target.
*   `ProverPrepareChallengeInput`: Collects commitments and intermediate elements for hashing.
*   `GenerateFiatShamirChallenge`: Computes the challenge `e` from hash of input.
*   `ProverComputeResponseSecrets`: Computes the response values `s_j` based on challenge, secrets, and intermediate values, handling the OR structure (real response for the match, simulated for others).
*   `FinalizeProof`: Bundles all proof components into a `Proof` struct.
*   `NewVerifierState`: Initializes verifier state with public data.
*   `VerifierProcessCommitment`: Verifier receives and stores the prover's value commitment.
*   `VerifierComputeTargetDiffCommitments`: Verifier computes `C_diff_j` using the received commitment and public targets.
*   `VerifierRecomputeChallengeElements`: Verifier recomputes the `A_j` values from the received proof components and `C_diff_j` using the verification equation `s_j H = A_j + e_j C_diff_j`.
*   `VerifierPrepareChallengeInput`: Verifier collects elements to recompute the challenge.
*   `VerifierCheckChallenge`: Verifier recomputes the challenge and compares it to the one in the proof.
*   `VerifyOverallProof`: Verifier performs the final check `s_j H == A_j + e_j C_diff_j mod P` for all `j`, combined with the challenge check.

This list already exceeds 20 functions dedicated to different logical units of the ZKP protocol and its supporting infrastructure.

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// --- Outline ---
// 1. System Parameters Management
// 2. Commitment Scheme (Pedersen-like over modular arithmetic)
// 3. Problem Definition (Private Value, Public Targets)
// 4. Prover State and Logic (Multi-step Sigma Protocol OR Proof)
// 5. Verifier State and Logic (Multi-step Verification)
// 6. Proof Structure
// 7. Utility Functions (Modular Arithmetic, Hashing, Randomness)

// --- Function Summary ---
// 1.  GenerateSystemParameters: Creates the modulus P, and generators G, H.
// 2.  NewCommitment: Factory function for Commitment struct.
// 3.  Commit: Computes C = (G^value * H^randomness) mod P.
// 4.  VerifyCommitment: Checks if C == (G^value * H^randomness) mod P. (For internal consistency/testing, not part of ZKP verify).
// 5.  GenerateRandomBigInt: Creates a cryptographically secure random big.Int within a range.
// 6.  Hash: Computes SHA256 hash of concatenated big.Ints.
// 7.  ModExp: Computes base^exponent mod modulus.
// 8.  ModInverse: Computes modular multiplicative inverse.
// 9.  ModAdd, ModSub, ModMul: Computes modular addition, subtraction, multiplication.
// 10. NewProverState: Initializes a prover with their private data and public targets.
// 11. ProverComputeValueCommitment: Computes the initial commitment C = Commit(x, rx).
// 12. ProverComputeTargetDiffCommitments: Computes C_diff_j = (C - T_j*G) mod P for all targets.
// 13. ProverGenerateRandomSecretsForORProof: Generates random blinding values v_j and simulation challenges e_j_sim for the OR proof.
// 14. ProverComputeIntermediateProofElements: Computes A_j = v_j * H mod P for each target using the random secrets.
// 15. ProverPrepareChallengeInput: Prepares the collective input for the Fiat-Shamir hash challenge.
// 16. GenerateFiatShamirChallenge: Computes the challenge e from the prepared input.
// 17. ProverComputeResponseSecrets: Computes the response secrets s_j based on the challenge, handling the disjunction logic (real for the true match, simulated for others).
// 18. FinalizeProof: Bundles the challenges e_j and responses s_j into the final Proof structure.
// 19. NewVerifierState: Initializes a verifier with public targets and parameters.
// 20. VerifierProcessCommitment: Verifier receives the prover's value commitment.
// 21. VerifierComputeTargetDiffCommitments: Verifier computes C_diff_j based on the received commitment and public targets.
// 22. VerifierRecomputeChallengeElements: Verifier recomputes the A_j values using the verification equation and proof components.
// 23. VerifierPrepareChallengeInput: Prepares input for the verifier's challenge recomputation.
// 24. VerifierCheckChallenge: Verifier recomputes the challenge and verifies it matches the one implied by the proof.
// 25. VerifyOverallProof: Performs the final check s_j H == A_j + e_j C_diff_j mod P for all j.

// --- 1. System Parameters Management ---

// SystemParams holds the public parameters for the ZKP system.
type SystemParams struct {
	P *big.Int // Prime modulus
	G *big.Int // Generator 1
	H *big.Int // Generator 2
	Q *big.Int // Subgroup order for exponents (P-1 for simplicity here)
}

// GenerateSystemParameters creates cryptographic parameters for the ZKP.
// In a real system, these would be securely generated and distributed.
func GenerateSystemParameters(bitSize int) (*SystemParams, error) {
	// Generate a large prime P
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime P: %w", err)
	}

	// Q = P-1 for simplicity in this example (using Z_p* group)
	q := new(big.Int).Sub(p, big.NewInt(1))

	// Generate generators G and H. In a real system, these should be chosen
	// carefully (e.g., random elements raised to Q/some_factor power).
	// For this example, we pick random numbers and ensure they are in the group.
	// A simple way is to pick random between 2 and P-2.
	g, err := GenerateRandomBigInt(new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil || g.Cmp(big.NewInt(1)) <= 0 {
		return nil, fmt.Errorf("failed to generate generator G: %w", err)
	}

	h, err := GenerateRandomBigInt(new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil || h.Cmp(big.NewInt(1)) <= 0 {
		return nil, fmt.Errorf("failed to generate generator H: %w", err)
	}

	return &SystemParams{P: p, G: g, H: h, Q: q}, nil
}

// --- 2. Commitment Scheme ---

// Commitment represents a Pedersen-like commitment C = G^value * H^randomness mod P.
type Commitment struct {
	C *big.Int
}

// NewCommitment creates a new Commitment struct.
func NewCommitment(c *big.Int) *Commitment {
	return &Commitment{C: c}
}

// Commit computes the commitment for a value and randomness.
// C = (params.G^value * params.H^randomness) mod params.P
func Commit(params *SystemParams, value, randomness *big.Int) (*Commitment, error) {
	if value == nil || randomness == nil {
		return nil, fmt.Errorf("value or randomness cannot be nil")
	}

	// Compute G^value mod P
	gPowValue := new(big.Int).Exp(params.G, value, params.P)

	// Compute H^randomness mod P
	hPowRandomness := new(big.Int).Exp(params.H, randomness, params.P)

	// Compute C = (gPowValue * hPowRandomness) mod P
	c := new(big.Int).Mul(gPowValue, hPowRandomness)
	c.Mod(c, params.P)

	return NewCommitment(c), nil
}

// VerifyCommitment checks if the commitment C matches the given value and randomness.
// This reveals the value, so it's NOT used in the ZKP verification process itself,
// but can be used for testing or in non-ZK contexts.
func VerifyCommitment(params *SystemParams, commitment *Commitment, value, randomness *big.Int) (bool, error) {
	if commitment == nil || value == nil || randomness == nil {
		return false, fmt.Errorf("commitment, value, or randomness cannot be nil")
	}
	computedC, err := Commit(params, value, randomness)
	if err != nil {
		return false, err
	}
	return commitment.C.Cmp(computedC.C) == 0, nil
}

// --- 3. Problem Definition ---

// PrivateProverData holds the prover's secrets.
type PrivateProverData struct {
	Value    *big.Int // The private score/value
	Randomness *big.Int // The randomness used in the commitment
	MatchingTargetIndex int // The index of the target value that matches (private knowledge)
}

// PublicVerifierData holds the public information.
type PublicVerifierData struct {
	Targets []*big.Int // The list of qualifying tiers/targets
}

// --- 6. Proof Structure ---

// Proof holds the components generated by the prover for verification.
type Proof struct {
	ValueCommitment *Commitment // Commitment to the prover's private value
	Challenges []*big.Int // e_j values for each target (Fiat-Shamir challenges)
	Responses []*big.Int // s_j values for each target (Schnorr-like responses)
}

// --- 4. Prover State and Logic ---

// ProverState maintains state during the proving process.
type ProverState struct {
	Params *SystemParams
	PrivateData *PrivateProverData
	PublicData *PublicVerifierData

	ValueCommitment *Commitment             // C = Commit(x, rx)
	TargetDiffCommitments []*big.Int        // C_diff_j = C - T_j*G mod P
	RandomSecrets []*big.Int                // v_j for j=k, random s_j for j!=k
	SimulatedChallenges []*big.Int          // e_j for j!=k
	IntermediateProofElements []*big.Int    // A_j = v_j * H mod P or (s_j*H - e_j*C_diff_j) mod P
	FinalChallenges []*big.Int              // e_j values included in the proof
	FinalResponses []*big.Int               // s_j values included in the proof
}

// NewProverState initializes a new prover state.
func NewProverState(params *SystemParams, privateData *PrivateProverData, publicData *PublicVerifierData) (*ProverState, error) {
	if params == nil || privateData == nil || publicData == nil {
		return nil, fmt.Errorf("nil inputs not allowed for NewProverState")
	}
	if privateData.MatchingTargetIndex < 0 || privateData.MatchingTargetIndex >= len(publicData.Targets) {
		return nil, fmt.Errorf("matching target index %d is out of bounds for %d targets", privateData.MatchingTargetIndex, len(publicData.Targets))
	}

	return &ProverState{
		Params: params,
		PrivateData: privateData,
		PublicData: publicData,
		TargetDiffCommitments: make([]*big.Int, len(publicData.Targets)),
		RandomSecrets: make([]*big.Int, len(publicData.Targets)),
		SimulatedChallenges: make([]*big.Int, len(publicData.Targets)),
		IntermediateProofElements: make([]*big.Int, len(publicData.Targets)),
		FinalChallenges: make([]*big.Int, len(publicData.Targets)),
		FinalResponses: make([]*big.Int, len(publicData.Targets)),
	}, nil
}

// ProverComputeValueCommitment computes the commitment to the private value.
func (ps *ProverState) ProverComputeValueCommitment() error {
	if ps.PrivateData.Value == nil || ps.PrivateData.Randomness == nil {
		return fmt.Errorf("private value or randomness not set")
	}
	comm, err := Commit(ps.Params, ps.PrivateData.Value, ps.PrivateData.Randomness)
	if err != nil {
		return fmt.Errorf("failed to compute value commitment: %w", err)
	}
	ps.ValueCommitment = comm
	return nil
}

// ProverComputeTargetDiffCommitments computes C_diff_j = (C - T_j*G) mod P for all targets.
func (ps *ProverState) ProverComputeTargetDiffCommitments() error {
	if ps.ValueCommitment == nil {
		return fmt.Errorf("value commitment not computed yet")
	}
	c := ps.ValueCommitment.C
	g := ps.Params.G
	p := ps.Params.P

	for i, target := range ps.PublicData.Targets {
		// Compute T_j * G mod P (conceptual multiplication in Z_P, not group op)
		// In a real group, this would be T_j * G (scalar multiplication).
		// For big.Ints, it's G raised to T_j power.
		tPowG := new(big.Int).Exp(g, target, p)

		// Compute C_diff_j = (C - T_j*G) mod P
		// This is C * (T_j*G)^-1 mod P, or C * ModInverse(T_j*G, P) mod P
		// Let's correct the math for this example: C - T_j*G implies Commit(x, rx) - Commit(T_j, 0)
		// Which should conceptually be Commit(x-T_j, rx).
		// (x*G + rx*H) - T_j*G ... this structure doesn't directly work with modular exponentiation.
		// Let's use the simpler structure where C_diff_j is meant to be a commitment to (x - T_j) with randomness rx.
		// i.e., C_diff_j should equal (G^(x-T_j) * H^rx) mod P
		// Which is (G^x * G^-T_j * H^rx) mod P
		// = (G^x * H^rx * G^-T_j) mod P = (C * G^(-T_j)) mod P
		// G^(-T_j) mod P is ModInverse(G^T_j, P) mod P
		gPowT := new(big.Int).Exp(g, target, p)
		gInvPowT := new(big.Int).ModInverse(gPowT, p)
		cDiff := new(big.Int).Mul(c, gInvPowT)
		cDiff.Mod(cDiff, p)

		ps.TargetDiffCommitments[i] = cDiff
	}
	return nil
}

// ProverGenerateRandomSecretsForORProof generates the v_j and e_j_sim values.
func (ps *ProverState) ProverGenerateRandomSecretsForORProof() error {
	numTargets := len(ps.PublicData.Targets)
	q := ps.Params.Q // Order of the exponent group (P-1)

	// Generate random v_j for each j (needed for A_j calculation)
	for i := 0; i < numTargets; i++ {
		vj, err := GenerateRandomBigInt(q) // Random between 0 and Q-1
		if err != nil {
			return fmt.Errorf("failed to generate random v_%d: %w", i, err)
		}
		ps.RandomSecrets[i] = vj
		ps.SimulatedChallenges[i] = big.NewInt(0) // Initialize simulated challenges
	}

	// Generate random challenges e_j_sim for all j != matching_index
	matchingIndex := ps.PrivateData.MatchingTargetIndex
	totalChallengesSum := big.NewInt(0)
	for i := 0; i < numTargets; i++ {
		if i != matchingIndex {
			ejSim, err := GenerateRandomBigInt(q) // Random between 0 and Q-1
			if err != nil {
				return fmt.Errorf("failed to generate simulated challenge e_%d: %w", i, err)
			}
			ps.SimulatedChallenges[i] = ejSim
			totalChallengesSum = ModAdd(totalChallengesSum, ejSim, q)
		}
	}

	// We need to leave ps.RandomSecrets[matchingIndex] as the actual random v_k
	// and ps.SimulatedChallenges[matchingIndex] will be computed later based on the real challenge.

	return nil
}

// ProverComputeIntermediateProofElements computes A_j based on generated secrets.
// For j=k (matching index): A_k = v_k * H mod P (commit to v_k)
// For j!=k: A_j = (s_j * H - e_j_sim * C_diff_j) mod P (derived from simulation equation)
func (ps *ProverState) ProverComputeIntermediateProofElements() error {
	numTargets := len(ps.PublicData.Targets)
	h := ps.Params.H
	p := ps.Params.P
	q := ps.Params.Q

	matchingIndex := ps.PrivateData.MatchingTargetIndex
	rx := ps.PrivateData.Randomness // Actual randomness for value commitment C

	for i := 0; i < numTargets; i++ {
		if i == matchingIndex {
			// For the correct target, A_k = v_k * H mod P
			vk := ps.RandomSecrets[i] // This is the actual v_k chosen randomly
			ak := new(big.Int).Exp(h, vk, p)
			ps.IntermediateProofElements[i] = ak
		} else {
			// For incorrect targets, A_j is computed from simulated e_j and random s_j
			// The s_j for j!=k were generated randomly in ProverGenerateRandomSecretsForORProof,
			// but stored temporarily in ps.RandomSecrets (bad naming, fix maybe?)
			// Let's adjust: ps.RandomSecrets holds v_j for all j initially.
			// We need *separate* storage for simulated s_j. Let's call them SimulatedResponses.
			// Re-designing step 13 and 17 slightly:
			// Step 13: Generate v_j for all j. Generate e_j_sim and s_j_sim for j!=k.
			// Step 17: Compute e_k based on sum(e_j_sim). Compute s_k based on v_k, e_k, rx.
			// This requires separate storage for v_j, e_j_sim, s_j_sim.

			// Let's rethink the state structure to be clearer about what's random vs computed.
			// Initial: value, rx, k, params, targets
			// Step 11: C
			// Step 12: C_diff_j
			// Step 13 (Pre-challenge): Generate v_j (all j), e_j_sim (j!=k), s_j_sim (j!=k)
			// Step 14 (Compute A_j): A_k = v_k * H. A_j = (s_j_sim * H - e_j_sim * C_diff_j) for j!=k.
			// Step 15/16 (Challenge): e = Hash(C, C_diff_vec, A_vec)
			// Step 17 (Post-challenge): Compute e_k = e - sum(e_j_sim). Compute s_k = (v_k + e_k * rx) mod Q.
			// Proof: C, all e_j, all s_j.

			// Ok, let's assume the v_j are in ps.RandomSecrets. Need SimulatedResponses.
			// Add SimulatedResponses to ProverState struct.
			// Modify ProverGenerateRandomSecretsForORProof to populate SimulatedResponses for j!=k.
			// Modify ProverComputeIntermediateProofElements.

			ejSim := ps.SimulatedChallenges[i]
			sjSim := ps.SimulatedResponses[i] // Need to add SimulatedResponses [] big.Int to struct

			// A_j = (s_j * H - e_j * C_diff_j) mod P
			// s_j * H mod P
			sjH := new(big.Int).Exp(h, sjSim, p)
			// e_j * C_diff_j mod P (scalar multiply commitment C_diff_j by e_j)
			// C_diff_j = G^(x-T_j) * H^rx. Need (C_diff_j)^e_j mod P
			eTimesCDiff := new(big.Int).Exp(ps.TargetDiffCommitments[i], ejSim, p)
			// A_j = sjH * (eTimesCDiff)^-1 mod P
			eTimesCDiffInv := new(big.Int).ModInverse(eTimesCDiff, p)
			aj := new(big.Int).Mul(sjH, eTimesCDiffInv)
			aj.Mod(aj, p)
			ps.IntermediateProofElements[i] = aj
		}
	}
	return nil
}

// Adding SimulatedResponses field to ProverState
type ProverState struct {
	Params *SystemParams
	PrivateData *PrivateProverData
	PublicData *PublicVerifierData

	ValueCommitment *Commitment             // C = Commit(x, rx)
	TargetDiffCommitments []*big.Int        // C_diff_j = C - T_j*G mod P (conceptual)
	RandomVj []*big.Int                     // v_j values generated randomly for all j
	SimulatedChallenges []*big.Int          // e_j values generated randomly for j!=k
	SimulatedResponses []*big.Int           // s_j values generated randomly for j!=k
	IntermediateProofElements []*big.Int    // A_j computed from v_j, e_j_sim, s_j_sim
	FinalChallenges []*big.Int              // All e_j (simulated and real)
	FinalResponses []*big.Int               // All s_j (simulated and real)
}

// NewProverState - Updated
func NewProverState(params *SystemParams, privateData *PrivateProverData, publicData *PublicVerifierData) (*ProverState, error) {
	// ... (same checks as before)
	numTargets := len(publicData.Targets)
	return &ProverState{
		Params: params,
		PrivateData: privateData,
		PublicData: publicData,
		TargetDiffCommitments: make([]*big.Int, numTargets),
		RandomVj: make([]*big.Int, numTargets),
		SimulatedChallenges: make([]*big.Int, numTargets),
		SimulatedResponses: make([]*big.Int, numTargets),
		IntermediateProofElements: make([]*big.Int, numTargets),
		FinalChallenges: make([]*big.Int, numTargets),
		FinalResponses: make([]*big.Int, numTargets),
	}, nil
}

// ProverGenerateRandomSecretsForORProof - Updated
func (ps *ProverState) ProverGenerateRandomSecretsForORProof() error {
	numTargets := len(ps.PublicData.Targets)
	q := ps.Params.Q // Order of the exponent group (P-1)

	// Generate random v_j for each j
	for i := 0; i < numTargets; i++ {
		vj, err := GenerateRandomBigInt(q) // Random between 0 and Q-1
		if err != nil {
			return fmt.Errorf("failed to generate random v_%d: %w", i, err)
		}
		ps.RandomVj[i] = vj
	}

	// Generate random simulated challenges e_j_sim and responses s_j_sim for all j != matching_index
	matchingIndex := ps.PrivateData.MatchingTargetIndex
	for i := 0; i < numTargets; i++ {
		if i != matchingIndex {
			ejSim, err := GenerateRandomBigInt(q) // Random between 0 and Q-1
			if err != nil {
				return fmt.Errorf("failed to generate simulated challenge e_%d: %w", i, err)
			}
			ps.SimulatedChallenges[i] = ejSim

			sjSim, err := GenerateRandomBigInt(q) // Random between 0 and Q-1
			if err != nil {
				return fmt.Errorf("failed to generate simulated response s_%d: %w", i, err)
			}
			ps.SimulatedResponses[i] = sjSim
		}
	}
	// SimulatedChallenges[k] and SimulatedResponses[k] remain 0 for now
	return nil
}

// ProverComputeIntermediateProofElements - Updated
func (ps *ProverState) ProverComputeIntermediateProofElements() error {
	numTargets := len(ps.PublicData.Targets)
	h := ps.Params.H
	p := ps.Params.P

	matchingIndex := ps.PrivateData.MatchingTargetIndex

	for i := 0; i < numTargets; i++ {
		if i == matchingIndex {
			// For the correct target, A_k = v_k * H mod P
			vk := ps.RandomVj[i] // This is the actual v_k chosen randomly
			ak := new(big.Int).Exp(h, vk, p)
			ps.IntermediateProofElements[i] = ak
		} else {
			// For incorrect targets, A_j is computed from simulated e_j_sim and s_j_sim
			ejSim := ps.SimulatedChallenges[i]
			sjSim := ps.SimulatedResponses[i]
			cDiff := ps.TargetDiffCommitments[i]

			// A_j = (s_j_sim * H - e_j_sim * C_diff_j) mod P
			// Compute s_j_sim * H mod P
			sjH := new(big.Int).Exp(h, sjSim, p)
			// Compute e_j_sim * C_diff_j mod P (scalar multiply commitment C_diff_j by e_j_sim)
			eTimesCDiff := new(big.Int).Exp(cDiff, ejSim, p)
			// Compute modular inverse of eTimesCDiff mod P
			eTimesCDiffInv := new(big.Int).ModInverse(eTimesCDiff, p)
			// Compute A_j = (sjH * eTimesCDiffInv) mod P
			aj := new(big.Int).Mul(sjH, eTimesCDiffInv)
			aj.Mod(aj, p)
			ps.IntermediateProofElements[i] = aj
		}
	}
	return nil
}

// ProverPrepareChallengeInput collects elements to hash for the challenge.
func (ps *ProverState) ProverPrepareChallengeInput() [][]byte {
	var inputs [][]byte
	inputs = append(inputs, ps.ValueCommitment.C.Bytes())
	for _, cd := range ps.TargetDiffCommitments {
		inputs = append(inputs, cd.Bytes())
	}
	for _, a := range ps.IntermediateProofElements {
		inputs = append(inputs, a.Bytes())
	}
	return inputs
}

// GenerateFiatShamirChallenge computes the challenge.
func GenerateFiatShamirChallenge(inputs [][]byte, q *big.Int) (*big.Int, error) {
	hasher := sha256.New()
	for _, input := range inputs {
		hasher.Write(input)
	}
	hashBytes := hasher.Sum(nil)
	// Convert hash to a big.Int and take modulo Q (order of the exponent group)
	// Using new(big.Int).SetBytes might result in a value larger than Q.
	// Use Mod(q) to bring it into the correct range [0, q-1].
	challenge := new(big.Int).SetBytes(hashBytes)
	challenge.Mod(challenge, q)
	return challenge, nil
}


// ProverComputeResponseSecrets computes the final response secrets s_j.
// Total challenge e is distributed among e_j such that sum(e_j) = e mod Q.
// e_k is computed from e and simulated e_j (j!=k).
// s_k is computed using the standard Schnorr equation: s_k = (v_k + e_k * rx) mod Q.
// s_j for j!=k are the simulated responses.
func (ps *ProverState) ProverComputeResponseSecrets(challenge *big.Int) error {
	numTargets := len(ps.PublicData.Targets)
	q := ps.Params.Q
	matchingIndex := ps.PrivateData.MatchingTargetIndex
	rx := ps.PrivateData.Randomness

	// Calculate e_k = (challenge - sum(e_j_sim for j!=k)) mod Q
	sumEjSim := big.NewInt(0)
	for i := 0; i < numTargets; i++ {
		if i != matchingIndex {
			sumEjSim = ModAdd(sumEjSim, ps.SimulatedChallenges[i], q)
		}
	}
	ekReal := ModSub(challenge, sumEjSim, q)

	// Populate FinalChallenges and FinalResponses
	for i := 0; i < numTargets; i++ {
		if i == matchingIndex {
			// For the correct target (k):
			// Set final challenge e_k
			ps.FinalChallenges[i] = ekReal
			// Compute final response s_k = (v_k + e_k * rx) mod Q
			vk := ps.RandomVj[i]
			ekRx := ModMul(ekReal, rx, q)
			skReal := ModAdd(vk, ekRx, q)
			ps.FinalResponses[i] = skReal
		} else {
			// For incorrect targets (j!=k):
			// Final challenge e_j is the simulated challenge e_j_sim
			ps.FinalChallenges[i] = ps.SimulatedChallenges[i]
			// Final response s_j is the simulated response s_j_sim
			ps.FinalResponses[i] = ps.SimulatedResponses[i]
		}
	}
	return nil
}

// FinalizeProof bundles the results into a Proof structure.
func (ps *ProverState) FinalizeProof() (*Proof, error) {
	if len(ps.FinalChallenges) == 0 || len(ps.FinalResponses) == 0 || ps.ValueCommitment == nil {
		return nil, fmt.Errorf("proving steps not completed")
	}
	return &Proof{
		ValueCommitment: ps.ValueCommitment,
		Challenges: ps.FinalChallenges,
		Responses: ps.FinalResponses,
	}, nil
}

// --- 5. Verifier State and Logic ---

// VerifierState maintains state during the verification process.
type VerifierState struct {
	Params *SystemParams
	PublicData *PublicVerifierData

	ValueCommitment *Commitment             // C received from prover
	TargetDiffCommitments []*big.Int        // C_diff_j = C - T_j*G mod P
	IntermediateProofElements []*big.Int    // Recomputed A_j from proof components
	Proof *Proof                          // Received proof structure
}

// NewVerifierState initializes a new verifier state.
func NewVerifierState(params *SystemParams, publicData *PublicVerifierData) (*VerifierState, error) {
	if params == nil || publicData == nil {
		return nil, fmt.Errorf("nil inputs not allowed for NewVerifierState")
	}
	return &VerifierState{
		Params: params,
		PublicData: publicData,
		TargetDiffCommitments: make([]*big.Int, len(publicData.Targets)),
		IntermediateProofElements: make([]*big.Int, len(publicData.Targets)),
	}, nil
}

// VerifierProcessCommitment stores the commitment received from the prover.
func (vs *VerifierState) VerifierProcessCommitment(commitment *Commitment) error {
	if commitment == nil {
		return fmt.Errorf("received commitment is nil")
	}
	vs.ValueCommitment = commitment
	return nil
}

// VerifierComputeTargetDiffCommitments computes C_diff_j = (C - T_j*G) mod P.
// This is the same logic as the prover's step 12, but performed by the verifier
// using the received commitment C.
func (vs *VerifierState) VerifierComputeTargetDiffCommitments() error {
	if vs.ValueCommitment == nil {
		return fmt.Errorf("value commitment not received yet")
	}
	c := vs.ValueCommitment.C
	g := vs.Params.G
	p := vs.Params.P

	for i, target := range vs.PublicData.Targets {
		// Compute C_diff_j = (C * G^(-T_j)) mod P
		gPowT := new(big.Int).Exp(g, target, p)
		gInvPowT := new(big.Int).ModInverse(gPowT, p)
		cDiff := new(big.Int).Mul(c, gInvPowT)
		cDiff.Mod(cDiff, p)
		vs.TargetDiffCommitments[i] = cDiff
	}
	return nil
}

// VerifierRecomputeChallengeElements recomputes A_j using the verification equation:
// A_j = (s_j * H - e_j * C_diff_j) mod P
// This is performed for all j.
func (vs *VerifierState) VerifierRecomputeChallengeElements(proof *Proof) error {
	if proof == nil || len(proof.Challenges) != len(vs.PublicData.Targets) || len(proof.Responses) != len(vs.PublicData.Targets) {
		return fmt.Errorf("invalid or incomplete proof provided")
	}
	if len(vs.TargetDiffCommitments) == 0 {
		return fmt.Errorf("target difference commitments not computed yet")
	}

	h := vs.Params.H
	p := vs.Params.P
	numTargets := len(vs.PublicData.Targets)

	for i := 0; i < numTargets; i++ {
		ej := proof.Challenges[i]
		sj := proof.Responses[i]
		cDiff := vs.TargetDiffCommitments[i]

		// Compute s_j * H mod P
		sjH := new(big.Int).Exp(h, sj, p)

		// Compute e_j * C_diff_j mod P (scalar multiply C_diff_j by e_j)
		eTimesCDiff := new(big.Int).Exp(cDiff, ej, p)

		// Compute modular inverse of eTimesCDiff mod P
		eTimesCDiffInv := new(big.Int).ModInverse(eTimesCDiff, p)

		// Compute A_j = (sjH * eTimesCDiffInv) mod P
		aj := new(big.Int).Mul(sjH, eTimesCDiffInv)
		aj.Mod(aj, p)
		vs.IntermediateProofElements[i] = aj
	}
	return nil
}

// VerifierPrepareChallengeInput collects elements to hash for recomputing the challenge.
// This should be the same set of elements the prover hashed.
func (vs *VerifierState) VerifierPrepareChallengeInput() [][]byte {
	var inputs [][]byte
	inputs = append(inputs, vs.ValueCommitment.C.Bytes())
	for _, cd := range vs.TargetDiffCommitments {
		inputs = append(inputs, cd.Bytes())
	}
	for _, a := range vs.IntermediateProofElements {
		inputs = append(inputs, a.Bytes())
	}
	return inputs
}

// VerifierCheckChallenge verifies if the recomputed challenge matches the expected total challenge.
func (vs *VerifierState) VerifierCheckChallenge(proof *Proof) (bool, error) {
	if proof == nil || len(proof.Challenges) != len(vs.PublicData.Targets) {
		return false, fmt.Errorf("invalid or incomplete proof provided")
	}
	if len(vs.IntermediateProofElements) == 0 {
		return false, fmt.Errorf("intermediate proof elements not recomputed yet")
	}

	// Recompute the challenge from the commitments and recomputed A_j values
	challengeInput := vs.VerifierPrepareChallengeInput()
	recomputedChallenge, err := GenerateFiatShamirChallenge(challengeInput, vs.Params.Q)
	if err != nil {
		return false, fmt.Errorf("failed to recompute challenge: %w", err)
	}

	// Sum the e_j values from the proof
	sumEjProof := big.NewInt(0)
	q := vs.Params.Q
	for _, ej := range proof.Challenges {
		sumEjProof = ModAdd(sumEjProof, ej, q)
	}

	// The total challenge derived from the proof challenges (sumEjProof) must equal
	// the challenge recomputed from the commitment and A_j values (recomputedChallenge).
	return sumEjProof.Cmp(recomputedChallenge) == 0, nil
}

// VerifyOverallProof orchestrates the verification steps.
func VerifyOverallProof(params *SystemParams, publicData *PublicVerifierData, proof *Proof) (bool, error) {
	if params == nil || publicData == nil || proof == nil {
		return false, fmt.Errorf("nil inputs not allowed for VerifyOverallProof")
	}
	if len(publicData.Targets) != len(proof.Challenges) || len(publicData.Targets) != len(proof.Responses) {
		return false, fmt.Errorf("proof structure does not match public data")
	}

	vs, err := NewVerifierState(params, publicData)
	if err != nil {
		return false, fmt.Errorf("failed to create verifier state: %w", err)
	}

	// Step 1: Process the commitment from the proof
	if err := vs.VerifierProcessCommitment(proof.ValueCommitment); err != nil {
		return false, fmt.Errorf("verifier failed to process commitment: %w", err)
	}

	// Step 2: Compute C_diff_j for all targets
	if err := vs.VerifierComputeTargetDiffCommitments(); err != nil {
		return false, fmt.Errorf("verifier failed to compute target diff commitments: %w", err)
	}

	// Step 3: Recompute A_j using the verification equation and proof components
	// Note: This implementation uses the *received* e_j and s_j from the proof
	// to recompute A_j, then checks if the hash of these recomputed A_j (along with C and C_diff_j)
	// results in the *sum* of the e_j values. This is the structure of the OR proof verification.
	if err := vs.VerifierRecomputeChallengeElements(proof); err != nil {
		return false, fmt.Errorf("verifier failed to recompute intermediate proof elements: %w", err)
	}

	// Step 4: Verify the challenge consistency
	// The sum of e_j from the proof must equal the challenge computed from C, C_diff_j, and the *recomputed* A_j.
	challengeOk, err := vs.VerifierCheckChallenge(proof)
	if err != nil {
		return false, fmt.Errorf("verifier failed challenge check: %w", err)
	}
	if !challengeOk {
		return false, fmt.Errorf("challenge verification failed")
	}

	// If the challenge check passes, it implies that for each j, the equation
	// s_j * H == A_j + e_j * C_diff_j mod P holds, because A_j was *derived* from this equation.
	// And, due to the simulation by the prover, this set of equations can ONLY hold
	// collectively in a way that passes the challenge check if *at least one* of the
	// C_diff_j values was actually a commitment to 0 (i.e., C = Commit(T_j, rx) for some j).

	// Therefore, the challenge check is the final verification step in this OR proof.
	return true, nil
}


// --- 7. Utility Functions ---

// GenerateRandomBigInt creates a cryptographically secure random big.Int up to max.
// The result is in the range [0, max).
func GenerateRandomBigInt(max *big.Int) (*big.Int, error) {
	if max == nil || max.Sign() <= 0 {
		return nil, fmt.Errorf("max must be a positive big.Int")
	}
	// big.Int.Rand returns a value in [0, max)
	return rand.Int(rand.Reader, max)
}

// Hash computes SHA256 hash of concatenated big.Ints.
func Hash(inputs ...*big.Int) ([]byte) {
	hasher := sha256.New()
	for _, input := range inputs {
		if input != nil {
			hasher.Write(input.Bytes())
		}
	}
	return hasher.Sum(nil)
}

// ModExp computes base^exponent mod modulus.
func ModExp(base, exponent, modulus *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent, modulus)
}

// ModInverse computes modular multiplicative inverse of a mod n.
// Returns nil if inverse does not exist.
func ModInverse(a, n *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, n)
}

// ModAdd computes (a + b) mod n.
func ModAdd(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Add(a, b)
	res.Mod(res, n)
	// Ensure positive result for modular arithmetic
	if res.Sign() < 0 {
		res.Add(res, n)
	}
	return res
}

// ModSub computes (a - b) mod n.
func ModSub(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	res.Mod(res, n)
	// Ensure positive result for modular arithmetic
	if res.Sign() < 0 {
		res.Add(res, n)
	}
	return res
}

// ModMul computes (a * b) mod n.
func ModMul(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	res.Mod(res, n)
	// Ensure positive result for modular arithmetic
	if res.Sign() < 0 {
		res.Add(res, n)
	}
	return res
}

// --- Example Usage ---

func main() {
	// 1. Setup System Parameters
	fmt.Println("Setting up system parameters...")
	bitSize := 512 // Use a reasonable bit size for cryptographic parameters
	params, err := GenerateSystemParameters(bitSize)
	if err != nil {
		fmt.Println("Error setting up parameters:", err)
		return
	}
	fmt.Printf("Parameters generated (P, G, H of size %d bits)\n", bitSize)

	// 2. Define Public Data (Qualifying Tiers)
	publicTargets := []*big.Int{
		big.NewInt(100), // Tier 1: score is 100
		big.NewInt(250), // Tier 2: score is 250
		big.NewInt(500), // Tier 3: score is 500
	}
	publicData := &PublicVerifierData{Targets: publicTargets}
	fmt.Printf("\nPublic Qualifying Tiers: %v\n", publicTargets)

	// 3. Prover's Private Data
	// Prover has a secret score. Let's say their score is 250 (matches Tier 2).
	proverScore := big.NewInt(250) // This matches publicTargets[1]
	matchingIndex := -1
	for i, target := range publicTargets {
		if proverScore.Cmp(target) == 0 {
			matchingIndex = i
			break
		}
	}
	if matchingIndex == -1 {
		fmt.Println("Error: Prover's score does not match any public target.")
		return // Score must match at least one target for a valid proof
	}

	// Prover needs a random number for their commitment.
	proverRandomness, err := GenerateRandomBigInt(params.Q) // Randomness in [0, Q)
	if err != nil {
		fmt.Println("Error generating prover randomness:", err)
		return
	}

	privateData := &PrivateProverData{
		Value:    proverScore,
		Randomness: proverRandomness,
		MatchingTargetIndex: matchingIndex,
	}
	fmt.Printf("Prover's private score (not revealed): %v\n", proverScore)
	fmt.Printf("Prover knows their score matches target index: %d (%v)\n", matchingIndex, publicTargets[matchingIndex])


	// --- Proving Process ---
	fmt.Println("\n--- Proving Process ---")
	prover, err := NewProverState(params, privateData, publicData)
	if err != nil {
		fmt.Println("Error creating prover state:", err)
		return
	}

	// Step 1: Commit to the private value
	fmt.Println("Prover: Step 1 - Committing to private value...")
	if err := prover.ProverComputeValueCommitment(); err != nil {
		fmt.Println("Error in ProverComputeValueCommitment:", err)
		return
	}
	fmt.Printf("Prover's Value Commitment (C): %v...\n", prover.ValueCommitment.C.Text(16)[:20]) // Print partial hash

	// Step 2: Compute C_diff_j for all targets
	fmt.Println("Prover: Step 2 - Computing C_diff_j...")
	if err := prover.ProverComputeTargetDiffCommitments(); err != nil {
		fmt.Println("Error in ProverComputeTargetDiffCommitments:", err)
		return
	}
	// fmt.Printf("Prover's Target Difference Commitments (C_diff_j): %v\n", prover.TargetDiffCommitments) // Don't print large numbers

	// Step 3: Generate random secrets (v_j, simulated e_j, simulated s_j) for OR proof
	fmt.Println("Prover: Step 3 - Generating random secrets for OR proof...")
	if err := prover.ProverGenerateRandomSecretsForORProof(); err != nil {
		fmt.Println("Error in ProverGenerateRandomSecretsForORProof:", err)
		return
	}

	// Step 4: Compute intermediate proof elements A_j
	fmt.Println("Prover: Step 4 - Computing intermediate proof elements A_j...")
	if err := prover.ProverComputeIntermediateProofElements(); err != nil {
		fmt.Println("Error in ProverComputeIntermediateProofElements:", err)
		return
	}
	// fmt.Printf("Prover's Intermediate Proof Elements (A_j): %v\n", prover.IntermediateProofElements) // Don't print large numbers

	// Step 5: Prepare input for challenge hashing
	fmt.Println("Prover: Step 5 - Preparing challenge input...")
	challengeInput := prover.ProverPrepareChallengeInput()

	// Step 6: Generate Fiat-Shamir challenge (Simulating Verifier's Challenge)
	fmt.Println("Prover: Step 6 - Generating Fiat-Shamir challenge...")
	challenge, err := GenerateFiatShamirChallenge(challengeInput, params.Q)
	if err != nil {
		fmt.Println("Error generating challenge:", err)
		return
	}
	fmt.Printf("Generated Challenge (e): %v...\n", challenge.Text(16)[:20]) // Print partial hash

	// Step 7: Compute response secrets s_j using the challenge
	fmt.Println("Prover: Step 7 - Computing response secrets s_j...")
	if err := prover.ProverComputeResponseSecrets(challenge); err != nil {
		fmt.Println("Error in ProverComputeResponseSecrets:", err)
		return
	}

	// Step 8: Finalize the proof
	fmt.Println("Prover: Step 8 - Finalizing proof...")
	proof, err := prover.FinalizeProof()
	if err != nil {
		fmt.Println("Error finalizing proof:", err)
		return
	}
	fmt.Println("Proof finalized.")
	// fmt.Printf("Proof: %+v\n", proof) // Don't print large numbers

	// --- Verification Process ---
	fmt.Println("\n--- Verification Process ---")
	fmt.Println("Verifier: Starting verification...")

	// Verifier receives the proof and has public data (params, targets)
	// The verifier does NOT have proverScore or proverRandomness.

	verified, err := VerifyOverallProof(params, publicData, proof)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}

	if verified {
		fmt.Println("\nVerification SUCCESS: The prover knows a private value that matches one of the public qualifying tiers.")
		fmt.Printf("Crucially, the verifier does NOT know the private value (%v) or WHICH tier (%v) was matched.\n", proverScore, publicTargets[matchingIndex])
	} else {
		fmt.Println("\nVerification FAILED: The prover could not prove knowledge of a value matching a tier.")
	}

	// --- Test a failing case (score doesn't match) ---
	fmt.Println("\n--- Testing a Failing Case ---")
	proverScoreBad := big.NewInt(999) // Doesn't match any target
	matchingIndexBad := -1
	for i, target := range publicTargets {
		if proverScoreBad.Cmp(target) == 0 {
			matchingIndexBad = i
			break
		}
	}
	if matchingIndexBad != -1 {
		fmt.Println("Error in test setup: Bad score unexpectedly matched a target.")
		return
	}

	fmt.Printf("Attempting to prove with non-matching score (not revealed): %v\n", proverScoreBad)
	privateDataBad := &PrivateProverData{
		Value:    proverScoreBad,
		Randomness: proverRandomness, // Use same randomness for simplicity
		MatchingTargetIndex: -1, // No match found
	}

	proverBad, err := NewProverState(params, privateDataBad, publicData)
	if err != nil {
		// Expected error because index is -1
		fmt.Printf("Expected Error creating prover state for bad data: %v\n", err)
		// To run the failing proof attempt, we need to bypass the check in NewProverState
		// In a real scenario, the prover simply wouldn't be able to *construct* a valid proof.
		// Here, for demonstration, let's manually create a state assuming *no* match is found.
		// This simulation isn't perfect, as a real prover *cannot* run steps 3-8 without a match.
		// We'll fake the state to run the steps and show verification failure.

		// Manual State creation for bad data (this bypasses the core ZKP logic requirement)
		// A real prover *cannot* generate a valid proof if no target matches.
		// The code below attempts to run the prover steps anyway, which would require
		// generating a fully simulated proof, which is different from the OR proof structure
		// implemented here (where one branch is real).
		// The most accurate failing test is simply trying to create the state with no match,
		// or trying to run the steps when no match was found (which the implemented steps
		// implicitly rely on via privateData.MatchingTargetIndex).

		// Let's simulate a prover trying to prove *something* when their data doesn't qualify.
		// They would fail at the step where they need to compute the real s_k or e_k,
		// because they don't know a valid 'k'. Or, if they attempt a full simulation,
		// the structure of A_j and the challenge/response calculation won't align with the
		// required structure of the OR proof that the verifier expects.
		// Our current code will likely panic or error if matchingIndex is -1 when running steps 3-7.
		// The ZKP *inherently* relies on knowledge of a valid 'k'.

		// Let's simulate a slightly different failure: Prover constructs a proof but it's invalid (e.g., wrong responses).
		// We can reuse the valid proof structure and just alter some values.
		fmt.Println("Simulating verification of an invalid proof...")
		invalidProof := &Proof{
			ValueCommitment: proof.ValueCommitment, // Use same commitment
			Challenges: make([]*big.Int, len(proof.Challenges)),
			Responses: make([]*big.Int, len(proof.Responses)),
		}
		// Copy valid challenges
		copy(invalidProof.Challenges, proof.Challenges)
		// Modify responses
		for i := range invalidProof.Responses {
			invalidProof.Responses[i] = new(big.Int).Add(proof.Responses[i], big.NewInt(1)) // Add 1 to each response mod Q
			invalidProof.Responses[i].Mod(invalidProof.Responses[i], params.Q)
		}

		verifiedInvalid, err := VerifyOverallProof(params, publicData, invalidProof)
		if err != nil {
			fmt.Println("Verification of invalid proof resulted in error:", err)
			// It's possible the error is caught before the final check, e.g., if modular inverse fails due to a zero value.
			// If the error is caught and indicates invalidity, that's also a successful test.
		} else if verifiedInvalid {
			fmt.Println("Verification of invalid proof unexpectedly SUCCEEDED!") // This indicates a bug
		} else {
			fmt.Println("Verification of invalid proof correctly FAILED.")
		}
		return // Exit after failing test simulation
	}


	// If we reached here with privateDataBad, something is wrong with the logic/test flow.
	// The prover should not be able to *create* the state/proof without a match.
	// The successful test above demonstrates the valid flow.

}

// Need to add a helper function to ensure positive results from big.Int.Mod
// for operations like subtraction where the result could be negative before modulo.
func ensurePositive(x, modulus *big.Int) *big.Int {
	res := new(big.Int).Set(x)
	res.Mod(res, modulus)
	if res.Sign() < 0 {
		res.Add(res, modulus)
	}
	return res
}

// Update ModAdd, ModSub, ModMul to use ensurePositive
func ModAdd(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Add(a, b)
	return ensurePositive(res, n)
}

func ModSub(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	return ensurePositive(res, n)
}

func ModMul(a, b, n *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	return ensurePositive(res, n)
}
```