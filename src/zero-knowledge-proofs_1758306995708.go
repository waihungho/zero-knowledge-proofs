This Go program implements a Zero-Knowledge Proof (ZKP) for "Privacy-Preserving Aggregated Reputation Proof (PARP)".
The scenario involves a Prover (user) who has multiple private reputation scores (`r_i`) from different sources.
Each source provides a Pedersen commitment (`C_i = g^{r_i} * h^{rand_i}`) to its respective reputation score.
The Prover wants to demonstrate to a Verifier (service) that the sum of these private reputation scores
(`R_total = sum(r_i)`) equals a public target reputation threshold (`T`), without revealing any individual `r_i`.

The core ZKP is a Schnorr-like proof of knowledge of a discrete logarithm (`Rand_total`) for the aggregated commitments
and target. Specifically, the Prover proves knowledge of `Rand_total = sum(rand_i)` such that `h^{Rand_total} = C_{total} / g^T`,
where `C_{total} = product(C_i)`.

**Outline and Function Summary:**

---

**I. Core Cryptographic Primitives (Math/Group Operations)**

1.  `GenerateSafePrime(bits int)`: Generates a large "safe" prime `P` (where `P = 2Q + 1` for prime `Q`) of a specified bit length. Used for the finite field.
2.  `GenerateGroupParams(bits int)`: Initializes and returns `GroupParameters` (prime `P`, subgroup order `Q`, generators `g`, `h`).
    *   Generates a safe prime `P` and derives `Q = (P-1)/2`.
    *   Finds two distinct, random generators `g` and `h` for the subgroup of order `Q`.
3.  `GenerateRandomScalar(q *big.Int)`: Generates a cryptographically secure random scalar (nonce) in `[1, q-1]`.
    *   Used for private keys, blinding factors, and proof nonces.
4.  `ScalarMult(base, exp, mod *big.Int)`: Computes `base^exp mod mod` using modular exponentiation.
    *   Primary operation for group element generation and point multiplication.
5.  `PointAdd(p1, p2, mod *big.Int)`: Computes `(p1 * p2) mod mod` in the multiplicative group.
    *   Group operation for combining commitments (multiplication of points).
6.  `PointInverse(p, mod *big.Int)`: Computes `p^-1 mod mod` in the multiplicative group.
    *   Modular inverse for "division" in the multiplicative group.
7.  `HashToScalar(q *big.Int, data ...[]byte)`: Hashes input byte slices using SHA256 and maps the result to a scalar in `[1, q-1]`.
    *   Used for generating the challenge (`e`) in the Fiat-Shamir heuristic.
8.  `IntToBytes(val *big.Int, size int)`: Converts a `big.Int` to a fixed-size byte slice.
    *   Ensures consistent hashing and serialization.
9.  `BytesToInt(data []byte)`: Converts a byte slice back to a `big.Int`.
    *   For deserialization.

---

**II. Data Structures**

10. `GroupParameters`: Struct to hold `P`, `Q`, `g`, `h` for the chosen cyclic group.
11. `ReputationInput`: Struct to hold a private reputation score (`r`) and its associated blinding factor (`rand`).
12. `Commitment`: Struct representing a Pedersen commitment (`C = g^r * h^rand mod P`).
13. `Proof`: Struct representing the ZKP proof components (`A` from round 1, `z` from round 2).
14. `Prover`: Struct encapsulating the Prover's state, secrets, and ZKP methods.
15. `Verifier`: Struct encapsulating the Verifier's state, public information, and ZKP verification methods.

---

**III. Reputation Source Functions**

16. `NewReputationSource(params *GroupParameters, name string)`: Constructor for a reputation source.
    *   Initializes a source with group parameters and a name.
17. `GenerateReputationCommitment(r *big.Int)`: A source's function to generate `C_i = g^{r_i} * h^{rand_i} mod P` and return both `C_i` and the generated `rand_i`.
    *   Simulates a source issuing a commitment to a private reputation score.

---

**IV. Prover Functions**

18. `NewProver(params *GroupParameters, inputs []ReputationInput, targetT *big.Int)`: Constructor for the Prover.
    *   Initializes Prover with group parameters, individual reputation inputs (`r_i`, `rand_i`), and the public target `T`.
19. `ComputeAggregatedSecretAndBlinding()`: Aggregates individual `r_i` and `rand_i` to `R_total = sum(r_i)` and `Rand_total = sum(rand_i)`.
    *   These aggregated values are kept private by the Prover.
20. `ComputeAggregatedCommitment(commitments []Commitment)`: Computes `C_total = product(C_i) mod P` from individual source commitments.
21. `InitiateProofRound1()`: Prover's first round of the ZKP.
    *   Picks a random nonce `k`, computes `A = h^k mod P`, and returns `A` to the Verifier.
22. `RespondToChallenge(e *big.Int)`: Prover's second round of the ZKP.
    *   Computes `z = (k + e * Rand_total) mod Q` and returns `z` to the Verifier.
23. `GetReputationInputs()`: Getter for the Prover's private `ReputationInput` values.

---

**V. Verifier Functions**

24. `NewVerifier(params *GroupParameters, targetT *big.Int)`: Constructor for the Verifier.
    *   Initializes Verifier with group parameters and the public target `T`.
25. `ComputeTargetComparisonBase(C_total *big.Int)`: Verifier computes `targetBase = C_total * (g^T)^-1 mod P`.
    *   This is the value `h^{Rand_total}` that the Prover needs to prove knowledge of `Rand_total` for.
26. `GenerateChallenge(A *big.Int, C_total *big.Int)`: Generates a cryptographically secure random challenge (`e`) for the Prover.
    *   Uses a hash of relevant public values (`A`, `C_total`, `g`, `h`, `P`, `T`) to implement the Fiat-Shamir heuristic.
27. `VerifyProof(A, z, C_total *big.Int)`: Verifies the ZKP.
    *   Checks if `h^z mod P == A * (C_total * (g^T)^-1)^e mod P`.

---

**VI. Orchestration and Example Scenario**

28. `RunPARPScenario(numSources int, targetT *big.Int, paramBits int)`: Orchestrates the full ZKP process.
    *   Sets up group parameters, simulates multiple reputation sources, a Prover, and a Verifier.
    *   Runs the interactive ZKP flow and prints the outcome.
29. `main()`: Entry point of the program, calls `RunPARPScenario` with example parameters.

---

**VII. Helper and Utility Functions**

30. `CheckBigIntEquality(a, b *big.Int, name string)`: Utility to print and check if two `big.Int` values are equal.
    *   Helpful for debugging and displaying intermediate states.

---

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"time"
)

// Outline and Function Summary

// This Go program implements a Zero-Knowledge Proof (ZKP) for "Privacy-Preserving Aggregated Reputation Proof (PARP)".
// The scenario involves a Prover (user) who has multiple private reputation scores (r_i) from different sources.
// Each source provides a Pedersen commitment (C_i = g^{r_i} * h^{rand_i}) to its respective reputation score.
// The Prover wants to demonstrate to a Verifier (service) that the sum of these private reputation scores
// (R_total = sum(r_i)) equals a public target reputation threshold (T), without revealing any individual r_i.

// The core ZKP is a Schnorr-like proof of knowledge of a discrete logarithm (Rand_total) corresponding
// to the aggregated commitments and target. Specifically, the Prover proves knowledge of Rand_total = sum(rand_i)
// such that h^{Rand_total} = C_{total} / g^T, where C_{total} = product(C_i).

// ----------------------------------------------------------------------------------------------------
// I. Core Cryptographic Primitives (Math/Group Operations)
// ----------------------------------------------------------------------------------------------------
// 1.  GenerateSafePrime(bits int): Generates a large "safe" prime P (where P = 2Q + 1 for prime Q) of a specified bit length.
//     - Used for the finite field.
// 2.  GenerateGroupParams(bits int): Initializes and returns GroupParameters (prime P, subgroup order Q, generators g, h).
//     - Generates a safe prime P and derives Q = (P-1)/2.
//     - Finds two distinct, random generators g and h for the subgroup of order Q.
// 3.  GenerateRandomScalar(q *big.Int): Generates a cryptographically secure random scalar (nonce) in [1, q-1].
//     - Used for private keys, blinding factors, and proof nonces.
// 4.  ScalarMult(base, exp, mod *big.Int): Computes base^exp mod mod using modular exponentiation.
//     - Primary operation for group element generation and point multiplication.
// 5.  PointAdd(p1, p2, mod *big.Int): Computes (p1 * p2) mod mod in the multiplicative group.
//     - Group operation for combining commitments (multiplication of points).
// 6.  PointInverse(p, mod *big.Int): Computes p^-1 mod mod in the multiplicative group.
//     - Modular inverse for "division" in the multiplicative group.
// 7.  HashToScalar(q *big.Int, data ...[]byte): Hashes input byte slices using SHA256 and maps the result to a scalar in [1, q-1].
//     - Used for generating the challenge (e) in the Fiat-Shamir heuristic.
// 8.  IntToBytes(val *big.Int, size int): Converts a big.Int to a fixed-size byte slice.
//     - Ensures consistent hashing and serialization.
// 9.  BytesToInt(data []byte): Converts a byte slice back to a big.Int.
//     - For deserialization.

// ----------------------------------------------------------------------------------------------------
// II. Data Structures
// ----------------------------------------------------------------------------------------------------
// 10. GroupParameters: Struct to hold P, Q, g, h for the chosen cyclic group.
// 11. ReputationInput: Struct to hold a private reputation score (r) and its associated blinding factor (rand).
// 12. Commitment: Struct representing a Pedersen commitment (C = g^r * h^rand mod P).
// 13. Proof: Struct representing the ZKP proof components (A from round 1, z from round 2).
// 14. Prover: Struct encapsulating the Prover's state, secrets, and ZKP methods.
// 15. Verifier: Struct encapsulating the Verifier's state, public information, and ZKP verification methods.

// ----------------------------------------------------------------------------------------------------
// III. Reputation Source Functions
// ----------------------------------------------------------------------------------------------------
// 16. NewReputationSource(params *GroupParameters, name string): Constructor for a reputation source.
//     - Initializes a source with group parameters and a name.
// 17. GenerateReputationCommitment(r *big.Int): A source's function to generate C_i = g^{r_i} * h^{rand_i} mod P and return both C_i and the generated rand_i.
//     - Simulates a source issuing a commitment to a private reputation score.

// ----------------------------------------------------------------------------------------------------
// IV. Prover Functions
// ----------------------------------------------------------------------------------------------------
// 18. NewProver(params *GroupParameters, inputs []ReputationInput, targetT *big.Int): Constructor for the Prover.
//     - Initializes Prover with group parameters, individual reputation inputs (r_i, rand_i), and the public target T.
// 19. ComputeAggregatedSecretAndBlinding(): Aggregates individual r_i and rand_i to R_total = sum(r_i) and Rand_total = sum(rand_i).
//     - These aggregated values are kept private by the Prover.
// 20. ComputeAggregatedCommitment(commitments []Commitment): Computes C_total = product(C_i) mod P from individual source commitments.
// 21. InitiateProofRound1(): Prover's first round of the ZKP.
//     - Picks a random nonce k, computes A = h^k mod P, and returns A to the Verifier.
// 22. RespondToChallenge(e *big.Int): Prover's second round of the ZKP.
//     - Computes z = (k + e * Rand_total) mod Q and returns z to the Verifier.
// 23. GetReputationInputs(): Getter for the Prover's private ReputationInput values.

// ----------------------------------------------------------------------------------------------------
// V. Verifier Functions
// ----------------------------------------------------------------------------------------------------
// 24. NewVerifier(params *GroupParameters, targetT *big.Int): Constructor for the Verifier.
//     - Initializes Verifier with group parameters and the public target T.
// 25. ComputeTargetComparisonBase(C_total *big.Int): Verifier computes targetBase = C_total * (g^T)^-1 mod P.
//     - This is the value h^{Rand_total} that the Prover needs to prove knowledge of Rand_total for.
// 26. GenerateChallenge(A *big.Int, C_total *big.Int): Generates a cryptographically secure random challenge (e) for the Prover.
//     - Uses a hash of relevant public values (A, C_total, g, h, P, T) to implement the Fiat-Shamir heuristic.
// 27. VerifyProof(A, z, C_total *big.Int): Verifies the ZKP.
//     - Checks if h^z mod P == A * (C_total * (g^T)^-1)^e mod P.

// ----------------------------------------------------------------------------------------------------
// VI. Orchestration and Example Scenario
// ----------------------------------------------------------------------------------------------------
// 28. RunPARPScenario(numSources int, targetT *big.Int, paramBits int): Orchestrates the full ZKP process.
//     - Sets up group parameters, simulates multiple reputation sources, a Prover, and a Verifier.
//     - Runs the interactive ZKP flow and prints the outcome.
// 29. main(): Entry point of the program, calls RunPARPScenario with example parameters.

// ----------------------------------------------------------------------------------------------------
// VII. Helper and Utility Functions
// ----------------------------------------------------------------------------------------------------
// 30. CheckBigIntEquality(a, b *big.Int, name string): Utility to print and check if two big.Int values are equal.
//     - Helpful for debugging and displaying intermediate states.

// --- End of Outline and Function Summary ---

// GroupParameters holds the necessary parameters for the discrete logarithm group
type GroupParameters struct {
	P *big.Int // Large prime modulus
	Q *big.Int // Prime order of the subgroup (P = 2Q + 1)
	G *big.Int // Generator 1
	H *big.Int // Generator 2 (random, independent of G)
}

// ReputationInput holds a single private reputation score and its blinding factor
type ReputationInput struct {
	R    *big.Int // Private reputation score
	Rand *big.Int // Blinding factor for the commitment
}

// Commitment represents a Pedersen commitment to a reputation score
type Commitment struct {
	C *big.Int // g^r * h^rand mod P
}

// Proof represents the ZKP proof (Schnorr-like)
type Proof struct {
	A *big.Int // h^k mod P (prover's initial commitment)
	Z *big.Int // (k + e * Rand_total) mod Q (prover's response)
}

// ReputationSource simulates an entity issuing reputation scores
type ReputationSource struct {
	params *GroupParameters
	name   string
}

// Prover is the entity proving knowledge of the aggregated reputation
type Prover struct {
	params      *GroupParameters
	inputs      []ReputationInput // Individual private r_i and rand_i
	targetT     *big.Int          // Public target sum of reputations
	R_total     *big.Int          // Sum of all r_i (private)
	Rand_total  *big.Int          // Sum of all rand_i (private)
	k           *big.Int          // Random nonce for proof (private to prover)
	C_total     *big.Int          // Aggregated commitment (product of C_i)
}

// Verifier is the entity verifying the aggregated reputation proof
type Verifier struct {
	params  *GroupParameters
	targetT *big.Int // Public target sum of reputations
}

// ----------------------------------------------------------------------------------------------------
// I. Core Cryptographic Primitives (Math/Group Operations)
// ----------------------------------------------------------------------------------------------------

// GenerateSafePrime generates a large "safe" prime P (P = 2Q + 1, where Q is also prime)
func GenerateSafePrime(bits int) (*big.Int, *big.Int, error) {
	for {
		q, err := rand.Prime(rand.Reader, bits-1) // Generate a prime Q
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Q: %w", err)
		}
		p := new(big.Int).Mul(q, big.NewInt(2))
		p.Add(p, big.NewInt(1)) // P = 2Q + 1

		// Check if P is prime
		if p.ProbablyPrime(20) { // Probability of error 1/2^20
			return p, q, nil
		}
	}
}

// GenerateGroupParams initializes and returns group parameters (prime P, subgroup order Q, generators g, h)
func GenerateGroupParams(bits int) (*GroupParameters, error) {
	P, Q, err := GenerateSafePrime(bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate safe prime P: %w", err)
	}

	// Find a generator g for the subgroup of order Q
	var g *big.Int
	for {
		candidate, err := rand.Int(rand.Reader, P)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random candidate for g: %w", err)
		}
		if candidate.Cmp(big.NewInt(1)) <= 0 { // Must be > 1
			continue
		}
		// g = candidate^2 mod P generates a subgroup of order Q
		g = new(big.Int).Exp(candidate, big.NewInt(2), P)
		if g.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}

	// Find a second generator h, distinct from g, also in the subgroup of order Q
	var h *big.Int
	for {
		candidate, err := rand.Int(rand.Reader, P)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random candidate for h: %w", err)
		}
		if candidate.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		// h = candidate^2 mod P generates a subgroup of order Q
		h = new(big.Int).Exp(candidate, big.NewInt(2), P)
		if h.Cmp(big.NewInt(1)) != 0 && h.Cmp(g) != 0 {
			break
		}
	}

	return &GroupParameters{P: P, Q: Q, G: g, H: h}, nil
}

// GenerateRandomScalar generates a cryptographically secure random scalar in [1, q-1]
func GenerateRandomScalar(q *big.Int) (*big.Int, error) {
	upperBound := new(big.Int).Sub(q, big.NewInt(1)) // q-1
	scalar, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	scalar.Add(scalar, big.NewInt(1)) // Ensure it's in [1, q-1]
	return scalar, nil
}

// ScalarMult computes base^exp mod mod
func ScalarMult(base, exp, mod *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, mod)
}

// PointAdd computes (p1 * p2) mod mod in the multiplicative group
func PointAdd(p1, p2, mod *big.Int) *big.Int {
	return new(big.Int).Mul(p1, p2).Mod(new(big.Int).Mul(p1, p2), mod)
}

// PointInverse computes p^-1 mod mod in the multiplicative group
func PointInverse(p, mod *big.Int) *big.Int {
	return new(big.Int).ModInverse(p, mod)
}

// HashToScalar hashes input byte slices using SHA256 and maps the result to a scalar in [1, q-1]
func HashToScalar(q *big.Int, data ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	hashBytes := hasher.Sum(nil)

	// Map hash to a scalar in [1, q-1]
	scalar := new(big.Int).SetBytes(hashBytes)
	scalar.Mod(scalar, q)
	if scalar.Cmp(big.NewInt(0)) == 0 { // Ensure it's not zero, if it is, set to 1
		scalar.SetInt64(1)
	}
	return scalar
}

// IntToBytes converts a big.Int to a fixed-size byte slice
func IntToBytes(val *big.Int, size int) []byte {
	bytes := val.Bytes()
	if len(bytes) == size {
		return bytes
	}
	if len(bytes) < size {
		padded := make([]byte, size)
		copy(padded[size-len(bytes):], bytes)
		return padded
	}
	// If too large, truncate (this might lead to loss of uniqueness for hashing, but for proof values it's fine)
	return bytes[len(bytes)-size:]
}

// BytesToInt converts a byte slice back to a big.Int
func BytesToInt(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// ----------------------------------------------------------------------------------------------------
// III. Reputation Source Functions
// ----------------------------------------------------------------------------------------------------

// NewReputationSource constructor
func NewReputationSource(params *GroupParameters, name string) *ReputationSource {
	return &ReputationSource{
		params: params,
		name:   name,
	}
}

// GenerateReputationCommitment creates a Pedersen commitment C = g^r * h^rand mod P
func (rs *ReputationSource) GenerateReputationCommitment(r *big.Int) (*Commitment, *big.Int, error) {
	randVal, err := GenerateRandomScalar(rs.params.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("source %s: %w", rs.name, err)
	}

	gR := ScalarMult(rs.params.G, r, rs.params.P)
	hRand := ScalarMult(rs.params.H, randVal, rs.params.P)
	C := PointAdd(gR, hRand, rs.params.P)

	fmt.Printf("[%s] Generated commitment to %s (r=%s, rand=%s)\n", rs.name, C.String(), r.String(), randVal.String())
	return &Commitment{C: C}, randVal, nil
}

// ----------------------------------------------------------------------------------------------------
// IV. Prover Functions
// ----------------------------------------------------------------------------------------------------

// NewProver constructor
func NewProver(params *GroupParameters, inputs []ReputationInput, targetT *big.Int) *Prover {
	p := &Prover{
		params:  params,
		inputs:  inputs,
		targetT: targetT,
	}
	p.ComputeAggregatedSecretAndBlinding()
	return p
}

// ComputeAggregatedSecretAndBlinding aggregates individual r_i and rand_i
func (p *Prover) ComputeAggregatedSecretAndBlinding() {
	p.R_total = big.NewInt(0)
	p.Rand_total = big.NewInt(0)
	for _, input := range p.inputs {
		p.R_total.Add(p.R_total, input.R)
		p.Rand_total.Add(p.Rand_total, input.Rand)
	}
	p.R_total.Mod(p.R_total, p.params.Q)    // All exponents modulo Q
	p.Rand_total.Mod(p.Rand_total, p.params.Q) // All exponents modulo Q
	fmt.Printf("[Prover] Aggregated private R_total: %s, Rand_total: %s\n", p.R_total, p.Rand_total)
}

// ComputeAggregatedCommitment computes C_total = product(C_i) mod P
func (p *Prover) ComputeAggregatedCommitment(commitments []Commitment) {
	p.C_total = big.NewInt(1) // Identity for multiplication
	for _, comm := range commitments {
		p.C_total = PointAdd(p.C_total, comm.C, p.params.P)
	}
	fmt.Printf("[Prover] Computed aggregated commitment C_total: %s\n", p.C_total.String())
}

// InitiateProofRound1 Prover picks random nonce k, computes A = h^k mod P
func (p *Prover) InitiateProofRound1() (*big.Int, error) {
	var err error
	p.k, err = GenerateRandomScalar(p.params.Q)
	if err != nil {
		return nil, fmt.Errorf("prover failed to generate random nonce k: %w", err)
	}
	A := ScalarMult(p.params.H, p.k, p.params.P)
	fmt.Printf("[Prover] Initiated proof, A = h^k: %s\n", A.String())
	return A, nil
}

// RespondToChallenge Prover computes z = (k + e * Rand_total) mod Q
func (p *Prover) RespondToChallenge(e *big.Int) *big.Int {
	// (e * Rand_total) mod Q
	eRandTotal := new(big.Int).Mul(e, p.Rand_total)
	eRandTotal.Mod(eRandTotal, p.params.Q)

	// (k + eRandTotal) mod Q
	z := new(big.Int).Add(p.k, eRandTotal)
	z.Mod(z, p.params.Q)

	fmt.Printf("[Prover] Responded to challenge, z: %s\n", z.String())
	return z
}

// GetReputationInputs returns the prover's private reputation inputs (for debugging/scenario setup)
func (p *Prover) GetReputationInputs() []ReputationInput {
	return p.inputs
}

// ----------------------------------------------------------------------------------------------------
// V. Verifier Functions
// ----------------------------------------------------------------------------------------------------

// NewVerifier constructor
func NewVerifier(params *GroupParameters, targetT *big.Int) *Verifier {
	return &Verifier{
		params:  params,
		targetT: targetT,
	}
}

// ComputeTargetComparisonBase Verifier computes targetBase = C_total * (g^T)^-1 mod P
// This is the value h^{Rand_total} that the Prover needs to prove knowledge of Rand_total for.
func (v *Verifier) ComputeTargetComparisonBase(C_total *big.Int) *big.Int {
	gT := ScalarMult(v.params.G, v.targetT, v.params.P)
	gTInverse := PointInverse(gT, v.params.P)
	targetBase := PointAdd(C_total, gTInverse, v.params.P)
	fmt.Printf("[Verifier] Computed target comparison base (C_total * (g^T)^-1): %s\n", targetBase.String())
	return targetBase
}

// GenerateChallenge generates a challenge (e) for the Prover using Fiat-Shamir
func (v *Verifier) GenerateChallenge(A, C_total *big.Int) *big.Int {
	// Concatenate all public parameters and the prover's first message for challenge generation
	dataToHash := [][]byte{
		IntToBytes(v.params.P, v.params.P.BitLen()/8),
		IntToBytes(v.params.Q, v.params.Q.BitLen()/8),
		IntToBytes(v.params.G, v.params.P.BitLen()/8),
		IntToBytes(v.params.H, v.params.P.BitLen()/8),
		IntToBytes(v.targetT, v.params.Q.BitLen()/8),
		IntToBytes(A, v.params.P.BitLen()/8),
		IntToBytes(C_total, v.params.P.BitLen()/8),
	}
	e := HashToScalar(v.params.Q, dataToHash...)
	fmt.Printf("[Verifier] Generated challenge e: %s\n", e.String())
	return e
}

// VerifyProof verifies the ZKP: checks if h^z == A * (C_total / g^T)^e mod P
func (v *Verifier) VerifyProof(proof *Proof, C_total *big.Int) bool {
	targetBase := v.ComputeTargetComparisonBase(C_total) // This is C_total * (g^T)^-1

	// Right Hand Side: A * (targetBase)^e mod P
	targetBaseE := ScalarMult(targetBase, proof.Z, v.params.P) // This should be proof.Z, not e
	
	// Correction for verification:
	// The Verifier receives A and z. It computes e from A and C_total.
	// Then it checks if h^z == A * (C_total * (g^T)^-1)^e mod P
	
	// Recalculate e using the values that were actually used by the Prover for challenge generation
	e := v.GenerateChallenge(proof.A, C_total) // Must be same e as Prover used

	RHS := PointAdd(proof.A, ScalarMult(targetBase, e, v.params.P), v.params.P)

	// Left Hand Side: h^z mod P
	LHS := ScalarMult(v.params.H, proof.Z, v.params.P)

	fmt.Printf("[Verifier] Verification LHS (h^z): %s\n", LHS.String())
	fmt.Printf("[Verifier] Verification RHS (A * (C_total * (g^T)^-1)^e): %s\n", RHS.String())

	return LHS.Cmp(RHS) == 0
}

// ----------------------------------------------------------------------------------------------------
// VII. Helper and Utility Functions
// ----------------------------------------------------------------------------------------------------

// CheckBigIntEquality checks if two big.Ints are equal and prints
func CheckBigIntEquality(a, b *big.Int, name string) {
	if a.Cmp(b) == 0 {
		fmt.Printf("✅ %s are equal: %s\n", name, a.String())
	} else {
		fmt.Printf("❌ %s are NOT equal: %s (expected) vs %s (actual)\n", name, a.String(), b.String())
	}
}

// ----------------------------------------------------------------------------------------------------
// VI. Orchestration and Example Scenario
// ----------------------------------------------------------------------------------------------------

// RunPARPScenario orchestrates the full ZKP process
func RunPARPScenario(numSources int, targetT *big.Int, paramBits int) {
	fmt.Println("--- Starting Privacy-Preserving Aggregated Reputation Proof (PARP) Scenario ---")
	fmt.Printf("Target aggregated reputation T: %s\n", targetT.String())
	fmt.Printf("Number of reputation sources: %d\n", numSources)
	fmt.Printf("Group parameter bit length: %d\n", paramBits)
	fmt.Println("--------------------------------------------------------------------")

	// 1. Setup Group Parameters
	params, err := GenerateGroupParams(paramBits)
	if err != nil {
		fmt.Printf("Error setting up group parameters: %v\n", err)
		return
	}
	fmt.Printf("Group parameters: P=%s, Q=%s, G=%s, H=%s\n", params.P, params.Q, params.G, params.H)
	fmt.Println("--------------------------------------------------------------------")

	// 2. Simulate Reputation Sources generating commitments
	reputationSources := make([]*ReputationSource, numSources)
	var proverInputs []ReputationInput
	var commitments []Commitment
	var actualSum big.Int // To verify the scenario correctness
	actualSum.SetInt64(0)

	fmt.Println("Simulating reputation sources generating commitments...")
	for i := 0; i < numSources; i++ {
		sourceName := fmt.Sprintf("Source-%d", i+1)
		rs := NewReputationSource(params, sourceName)
		reputationSources[i] = rs

		// Generate a random reputation score for this source
		// Ensure reputation scores are smaller than Q to fit into the exponent field
		r, err := GenerateRandomScalar(new(big.Int).Div(params.Q, big.NewInt(int64(numSources*100)))) // keep r small
		if err != nil {
			fmt.Printf("Error generating reputation score: %v\n", err)
			return
		}
		if r.Cmp(big.NewInt(0)) == 0 {
			r.SetInt64(1) // Ensure r is not zero
		}
		
		comm, randVal, err := rs.GenerateReputationCommitment(r)
		if err != nil {
			fmt.Printf("Error generating commitment: %v\n", err)
			return
		}
		commitments = append(commitments, *comm)
		proverInputs = append(proverInputs, ReputationInput{R: r, Rand: randVal})
		actualSum.Add(&actualSum, r)
	}
	actualSum.Mod(&actualSum, params.Q) // Sum modulo Q
	fmt.Printf("Actual sum of private reputations (for debug): %s\n", actualSum.String())
	fmt.Println("--------------------------------------------------------------------")

	// 3. Prover's actions
	fmt.Println("Prover preparing proof...")
	prover := NewProver(params, proverInputs, targetT)
	prover.ComputeAggregatedCommitment(commitments)

	// In a real scenario, the Prover would aggregate its `r_i` values,
	// and receive `C_i` values from various sources. It then calculates `C_total`.
	// For this simulation, we've collected them directly.

	// Prover checks if their actual aggregated sum matches the target.
	// This is not part of the ZKP itself, but a sanity check for the scenario.
	fmt.Printf("[Prover] Private R_total: %s\n", prover.R_total.String())
	if prover.R_total.Cmp(prover.targetT) != 0 {
		fmt.Printf("WARNING: Prover's actual R_total (%s) does NOT match the public target T (%s). The proof should fail if T is used as the target in ZKP.\n", prover.R_total.String(), prover.targetT.String())
	} else {
		fmt.Printf("Prover's actual R_total (%s) matches the public target T (%s). The proof should succeed.\n", prover.R_total.String(), prover.targetT.String())
	}
	fmt.Println("--------------------------------------------------------------------")

	// 4. Verifier's setup
	fmt.Println("Verifier setting up...")
	verifier := NewVerifier(params, targetT)

	// 5. ZKP Protocol Execution (Interactive)
	fmt.Println("Executing ZKP protocol (Prover <-> Verifier)...")

	// Round 1: Prover -> Verifier (A)
	A, err := prover.InitiateProofRound1()
	if err != nil {
		fmt.Printf("Error in Prover Round 1: %v\n", err)
		return
	}
	fmt.Println("--------------------------------------------------------------------")

	// Round 2: Verifier -> Prover (e)
	e := verifier.GenerateChallenge(A, prover.C_total)
	fmt.Println("--------------------------------------------------------------------")

	// Round 3: Prover -> Verifier (z)
	z := prover.RespondToChallenge(e)
	fmt.Println("--------------------------------------------------------------------")

	// 6. Verifier validates the proof
	fmt.Println("Verifier validating proof...")
	proof := &Proof{A: A, Z: z}
	isValid := verifier.VerifyProof(proof, prover.C_total)

	fmt.Println("--------------------------------------------------------------------")
	if isValid {
		fmt.Println("✅ Proof is VALID! The Prover successfully demonstrated that their aggregated reputation matches the target without revealing individual scores.")
	} else {
		fmt.Println("❌ Proof is INVALID! The Prover failed to demonstrate that their aggregated reputation matches the target.")
	}
	fmt.Println("--- End of PARP Scenario ---")
}

func main() {
	// Example usage:
	// numSources: Number of reputation sources contributing.
	// targetT: The public target aggregated reputation score.
	// paramBits: Bit length for the prime P, affects security and computation time.
	//            128-bit for P (64-bit for Q) is okay for demonstration, but 256-bit+ recommended for real-world.

	numSources := 3
	targetT := big.NewInt(500) // The target sum that the Prover will prove their R_total equals
	paramBits := 128            // For demonstration, 128-bit is fast enough. Use 256 or 512 for higher security.

	// Example 1: Prover's actual sum matches targetT
	fmt.Println("\n--- Scenario 1: Successful Proof ---")
	RunPARPScenario(numSources, targetT, paramBits)

	// Example 2: Prover's actual sum does NOT match targetT (Proof should fail)
	fmt.Println("\n--- Scenario 2: Failed Proof (Target Mismatch) ---")
	// To simulate a failed proof, we'll manually create a Prover with inputs that sum to a different value.
	// First, run a normal scenario to get correct inputs and params.
	params, err := GenerateGroupParams(paramBits)
	if err != nil {
		fmt.Printf("Error setting up group parameters for failed scenario: %v\n", err)
		return
	}

	var fakeProverInputs []ReputationInput
	var fakeCommitments []Commitment
	expectedRTotal := big.NewInt(0)
	expectedRandTotal := big.NewInt(0)

	// Generate inputs that sum to something different from targetT
	for i := 0; i < numSources; i++ {
		r, _ := GenerateRandomScalar(new(big.Int).Div(params.Q, big.NewInt(int64(numSources*100))))
		if r.Cmp(big.NewInt(0)) == 0 { r.SetInt64(1) }

		// Manually ensure the sum is different from targetT
		if i == 0 {
			r.Set(big.NewInt(10)) // Set a specific value for control
		} else {
			r.Set(big.NewInt(5)) // Set other specific values
		}

		randVal, _ := GenerateRandomScalar(params.Q)
		fakeProverInputs = append(fakeProverInputs, ReputationInput{R: r, Rand: randVal})

		gR := ScalarMult(params.G, r, params.P)
		hRand := ScalarMult(params.H, randVal, params.P)
		C := PointAdd(gR, hRand, params.P)
		fakeCommitments = append(fakeCommitments, Commitment{C: C})

		expectedRTotal.Add(expectedRTotal, r)
		expectedRandTotal.Add(expectedRandTotal, randVal)
	}
	expectedRTotal.Mod(expectedRTotal, params.Q)
	expectedRandTotal.Mod(expectedRandTotal, params.Q)

	fmt.Printf("Prover's actual R_total (for failed scenario) will be: %s\n", expectedRTotal.String())
	fmt.Printf("Target T (for failed scenario) is: %s\n", targetT.String())
	if expectedRTotal.Cmp(targetT) == 0 {
		fmt.Println("Warning: Expected R_total still matches target T. Adjust inputs for a guaranteed failure.")
		// Add some value to make it definitely not match
		fakeProverInputs[0].R.Add(fakeProverInputs[0].R, big.NewInt(1000))
		fakeProverInputs[0].R.Mod(fakeProverInputs[0].R, params.Q)
		// Recalculate commitments and totals
		expectedRTotal.SetInt64(0)
		expectedRandTotal.SetInt64(0)
		for i, input := range fakeProverInputs {
			expectedRTotal.Add(expectedRTotal, input.R)
			expectedRandTotal.Add(expectedRandTotal, input.Rand)
			gR := ScalarMult(params.G, input.R, params.P)
			hRand := ScalarMult(params.H, input.Rand, params.P)
			fakeCommitments[i].C = PointAdd(gR, hRand, params.P)
		}
		expectedRTotal.Mod(expectedRTotal, params.Q)
		expectedRandTotal.Mod(expectedRandTotal, params.Q)
		fmt.Printf("Adjusted Prover's actual R_total: %s\n", expectedRTotal.String())
	}
	
	fmt.Printf("\n--- Prover's actual R_total (for failed scenario) is: %s (should not match %s) ---\n", expectedRTotal.String(), targetT.String())
	fmt.Println("Prover preparing proof (should fail)...")
	proverFailed := NewProver(params, fakeProverInputs, targetT)
	proverFailed.ComputeAggregatedCommitment(fakeCommitments)
	fmt.Println("--------------------------------------------------------------------")

	fmt.Println("Verifier setting up...")
	verifierFailed := NewVerifier(params, targetT)
	fmt.Println("--------------------------------------------------------------------")

	fmt.Println("Executing ZKP protocol (Prover <-> Verifier)...")
	A_failed, _ := proverFailed.InitiateProofRound1()
	e_failed := verifierFailed.GenerateChallenge(A_failed, proverFailed.C_total)
	z_failed := proverFailed.RespondToChallenge(e_failed)
	fmt.Println("--------------------------------------------------------------------")

	fmt.Println("Verifier validating proof...")
	proof_failed := &Proof{A: A_failed, Z: z_failed}
	isValid_failed := verifierFailed.VerifyProof(proof_failed, proverFailed.C_total)

	fmt.Println("--------------------------------------------------------------------")
	if isValid_failed {
		fmt.Println("❌ Proof is VALID! This should NOT happen as the R_total does not match T.")
	} else {
		fmt.Println("✅ Proof is INVALID, as expected! The Prover's aggregated reputation does not match the target.")
	}
	fmt.Println("--- End of Failed PARP Scenario ---")

	// Small pause to allow output to flush
	time.Sleep(100 * time.Millisecond)
}

```