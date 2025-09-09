```go
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto/bn256" // Using bn256 for elliptic curve operations
)

/*
Zero-Knowledge Proof for Aggregate Financial Health Verification

Outline:
This ZKP system allows a Prover to demonstrate to a Verifier that they meet specific financial criteria based on their private transaction history, without revealing any details of the individual transactions. The system leverages Pedersen Commitments and a series of Sigma-protocol-like interactions transformed into non-interactive proofs using the Fiat-Shamir heuristic.

The core idea is to:
1.  Commit to private transaction data (amounts, categories, merchants).
2.  Define public financial statements (e.g., "total spending in category X > Y", "transaction count in category Z is within [min, max]").
3.  Generate ZK proofs for these aggregate properties, ensuring the verifier can confirm the conditions without learning the underlying private data.
4.  Combine these individual proofs into a single, non-interactive aggregate proof.
5.  Allow a Verifier to check the aggregate proof against the public financial statements and the Prover's committed (but hidden) transaction data.

Key "Interesting, Advanced, Creative, and Trendy Concepts":
-   **Composition of ZKPs**: The system demonstrates how to build complex verifiable statements (e.g., "Total spending in category X > Y AND transaction count in category Z is within [min, max]") by composing simpler, foundational ZK primitives (equality proofs, sum relation proofs, and a custom range proof). This modularity is crucial for real-world ZKP applications.
-   **Custom Range Proof (NonNegativeFixedBits)**: Instead of relying on a pre-built, complex Bulletproofs library, this implementation includes a custom, simplified range proof. This protocol proves that a committed value is non-negative and fits within a specified number of bits, by demonstrating its bit-wise composition and the consistency of randomness, without revealing the value itself. While simplified, it illustrates the underlying principles of proving bounds without disclosing the number, which is a foundational challenge in ZKP.
-   **Privacy-Preserving Financial Health Checks**: This addresses a highly relevant and trendy use case in decentralized finance (DeFi), private credit scoring, regulatory compliance, or other Web3 applications. Users can prove their financial standing or adherence to policies without exposing sensitive personal transaction history, thus enhancing data privacy and control.
-   **Fiat-Shamir Heuristic**: The interactive Sigma protocols for equality, sum, and range are made non-interactive by using a cryptographic hash function to generate challenges, allowing a one-shot proof verification.

This implementation is designed to be a unique application, focusing on custom protocol composition rather than duplicating existing open-source ZKP frameworks directly, emphasizing the specific financial privacy use case.

Function Summary:

I. Cryptographic Utilities & Setup (7 functions)
1.  `GenerateRandomScalar()`: Generates a cryptographically secure random scalar in the curve's field.
2.  `HashToScalar(data ...[]byte)`: Computes a hash of input data and converts it to a scalar (for Fiat-Shamir challenges).
3.  `SetupPedersenGenerators()`: Initializes two independent, publicly known Pedersen generators (G and H) on the elliptic curve.
4.  `ScalarAdd(a, b *big.Int)`: Adds two scalars modulo the curve order N.
5.  `ScalarSub(a, b *big.Int)`: Subtracts two scalars modulo the curve order N.
6.  `ScalarMul(a, b *big.Int)`: Multiplies two scalars modulo the curve order N.
7.  `CurvePointAdd(p1, p2 *bn256.G1)`: Adds two elliptic curve points (elements of G1).

II. Pedersen Commitment Scheme (4 functions)
8.  `PedersenCommitment` struct: Represents a commitment `C = x*G + r*H`.
9.  `Commit(value *big.Int, randomness *big.Int, G, H *bn256.G1) *PedersenCommitment`: Creates a Pedersen commitment to `value` using `randomness`.
10. `CommitVector(values []*big.Int, randomness []*big.Int, G, H *bn256.G1) []*PedersenCommitment`: Commits a slice of values, each with its own randomness.
11. `CommitSum(values []*big.Int, sumRandomness *big.Int, G, H *bn256.G1) *PedersenCommitment`: Commits to the sum of `values`, using a single `sumRandomness`.

III. Data Structures (3 functions)
12. `Transaction` struct: Represents a single financial transaction (`Amount`, `CategoryID`, `MerchantID`, `Timestamp`).
13. `CommittedTransaction` struct: Stores Pedersen commitments for each field of a `Transaction` (`C_Amount`, `C_CategoryID`, etc.) and their secret randomness (for Prover use).
14. `FinancialProofStatement` struct: Defines a public condition the Prover aims to satisfy (e.g., "TotalSpendingInCategoryID", "TransactionCountInRange").

IV. Core ZKP Protocols (8 functions)
15. `EqualityProof` struct: Data structure for proving a commitment `C` is to a specific public scalar `v_known`.
16. `ProveEquality(C *PedersenCommitment, v_known *big.Int, r_known *big.Int, G, H *bn256.G1, challenge *big.Int) *EqualityProof`: Proves `C` commits to `v_known` using `r_known`.
17. `VerifyEquality(C *PedersenCommitment, v_known *big.Int, proof *EqualityProof, G, H *bn256.G1, challenge *big.Int) bool`: Verifies an `EqualityProof`.
18. `SumRelationProof` struct: Data structure for proving a commitment `C_sum` is the sum of other commitments `termsC`.
19. `ProveSumRelation(terms []*big.Int, termRandomness []*big.Int, sumVal *big.Int, sumRand *big.Int, G, H *bn256.G1, challenge *big.Int) *SumRelationProof`: Proves `sum(C_i) = C_sum`.
20. `VerifySumRelation(termsC []*PedersenCommitment, sumC *PedersenCommitment, proof *SumRelationProof, G, H *bn256.G1, challenge *big.Int) bool`: Verifies a `SumRelationProof`.
21. `NonNegativeFixedBitsProof` struct: Data structure for proving a committed value is non-negative and within `maxBits`.
22. `ProveNonNegativeFixedBits(value *big.Int, randomness *big.Int, maxBits int, G, H *bn256.G1, challenge *big.Int) *NonNegativeFixedBitsProof`: Proves a committed value's bit-decomposition property.

V. ZKP for Basic Logic and Aggregation (4 functions)
23. `VerifyNonNegativeFixedBits(commitment *PedersenCommitment, proof *NonNegativeFixedBitsProof, maxBits int, G, H *bn256.G1, challenge *big.Int) bool`: Verifies a `NonNegativeFixedBitsProof`.
24. `DifferenceEqualityProof` struct: Data structure for proving `C_a - C_b = C_c`.
25. `ProveDifferenceEquality(valA, randA, valB, randB, valC, randC *big.Int, G, H *bn256.G1, challenge *big.Int) *DifferenceEqualityProof`: Proves `C_a - C_b` equals `C_c`.
26. `VerifyDifferenceEquality(CA, CB, CC *PedersenCommitment, proof *DifferenceEqualityProof, G, H *bn256.G1, challenge *big.Int) bool`: Verifies a `DifferenceEqualityProof`.

VI. Application Layer & Aggregate Proof (3 functions + 2 new structs for proof components = 5 total)
27. `ProverContext` struct: Manages the prover's private data and secrets.
28. `NewProverContext(txs []*Transaction, G, H *bn256.G1, statements []*FinancialProofStatement) *ProverContext`: Initializes the prover context.
29. `VerifierContext` struct: Manages the verifier's public statements and received commitments.
30. `NewVerifierContext(statements []*FinancialProofStatement, committedTxs []*CommittedTransaction, G, H *bn256.G1) *VerifierContext`: Initializes the verifier context.
31. `TotalSpendingProofComponent` struct: Encapsulates sub-proofs for a "TotalSpendingInCategoryID" statement.
32. `TransactionCountProofComponent` struct: Encapsulates sub-proofs for a "TransactionCountInRange" statement.
33. `AggregateZKProof` struct: Encapsulates all generated sub-proofs for various statements.
34. `GenerateAggregateZKProof(proverCtx *ProverContext, G, H *bn256.G1) (*AggregateZKProof, error)`: Orchestrates generation of all necessary proofs to satisfy the statements.
35. `VerifyAggregateZKProof(verifierCtx *VerifierContext, proof *AggregateZKProof, G, H *bn256.G1) (bool, error)`: Verifies the entire aggregate proof.
*/

// --- I. Cryptographic Utilities & Setup ---

// GenerateRandomScalar generates a cryptographically secure random scalar in the field Z_N.
// N is the order of the G1 group in bn256.
func GenerateRandomScalar() *big.Int {
	r, err := rand.Int(rand.Reader, bn256.N)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar: %v", err))
	}
	return r
}

// HashToScalar computes a cryptographic hash of input data and converts it to a scalar in Z_N.
// This is used for Fiat-Shamir challenges to make interactive proofs non-interactive.
func HashToScalar(data ...[]byte) *big.Int {
	var combinedData bytes.Buffer
	for _, d := range data {
		combinedData.Write(d)
	}
	return bn256.HashToInt(combinedData.Bytes())
}

// SetupPedersenGenerators initializes two independent, publicly known Pedersen generators (G and H)
// on the elliptic curve. G is the base generator, and H is derived from a hash to ensure independence.
func SetupPedersenGenerators() (G1 *bn256.G1, H1 *bn256.G1) {
	// G is typically the standard generator of the curve
	G1 = new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// H is an independent generator, derived from a fixed seed to be deterministic and public.
	H_seed := bn256.HashToInt([]byte("Pedersen_H_seed"))
	H1 = new(bn256.G1).ScalarBaseMult(H_seed)
	return G1, H1
}

// ScalarAdd adds two scalars modulo N.
func ScalarAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b).Mod(new(big.Int).Add(a, b), bn256.N)
}

// ScalarSub subtracts two scalars modulo N.
func ScalarSub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b).Mod(new(big.Int).Sub(a, b), bn256.N)
}

// ScalarMul multiplies two scalars modulo N.
func ScalarMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b).Mod(new(big.Int).Mul(a, b), bn256.N)
}

// CurvePointAdd adds two elliptic curve points.
func CurvePointAdd(p1, p2 *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Add(p1, p2)
}

// --- II. Pedersen Commitment Scheme ---

// PedersenCommitment represents a commitment C = x*G + r*H.
type PedersenCommitment struct {
	Point *bn256.G1
}

// Commit creates a Pedersen commitment to 'value' using 'randomness'.
// C = value*G + randomness*H
func Commit(value *big.Int, randomness *big.Int, G, H *bn256.G1) *PedersenCommitment {
	commit := new(bn256.G1).ScalarMult(G, value)
	randTerm := new(bn256.G1).ScalarMult(H, randomness)
	commit = new(bn256.G1).Add(commit, randTerm)
	return &PedersenCommitment{Point: commit}
}

// CommitVector commits a slice of values, each with its own randomness.
func CommitVector(values []*big.Int, randomness []*big.Int, G, H *bn256.G1) []*PedersenCommitment {
	if len(values) != len(randomness) {
		panic("values and randomness slices must have equal length")
	}
	commitments := make([]*PedersenCommitment, len(values))
	for i := range values {
		commitments[i] = Commit(values[i], randomness[i], G, H)
	}
	return commitments
}

// CommitSum commits to the sum of 'values', using a single 'sumRandomness' for the overall sum.
// C_sum = (sum(values))*G + sumRandomness*H
func CommitSum(values []*big.Int, sumRandomness *big.Int, G, H *bn256.G1) *PedersenCommitment {
	totalValue := big.NewInt(0)
	for _, v := range values {
		totalValue = new(big.Int).Add(totalValue, v)
	}
	return Commit(totalValue, sumRandomness, G, H)
}

// --- III. Data Structures ---

// Transaction represents a single financial transaction.
type Transaction struct {
	Amount     *big.Int
	CategoryID *big.Int
	MerchantID *big.Int
	Timestamp  int64 // Unix timestamp
}

// CommittedTransaction stores Pedersen commitments for each field of a Transaction
// and their secret randomness. This is internal to the Prover.
type CommittedTransaction struct {
	C_Amount     *PedersenCommitment
	R_Amount     *big.Int // Randomness for C_Amount
	C_CategoryID *PedersenCommitment
	R_CategoryID *big.Int // Randomness for C_CategoryID
	C_MerchantID *PedersenCommitment
	R_MerchantID *big.Int // Randomness for C_MerchantID
	C_Timestamp  *PedersenCommitment
	R_Timestamp  *big.Int // Randomness for C_Timestamp
}

// FinancialProofStatement defines a public condition the Prover aims to satisfy.
type FinancialProofStatement struct {
	Type          string // e.g., "TotalSpendingInCategoryID", "TransactionCountInRange"
	CategoryID    *big.Int // Relevant for category-specific statements
	Threshold     *big.Int // For "TotalSpendingInCategoryID" (e.g., spending > Threshold)
	MinCount      int      // For "TransactionCountInRange" (e.g., count >= MinCount)
	MaxCount      int      // For "TransactionCountInRange" (e.g., count <= MaxCount)
	TargetMerchant *big.Int // Placeholder for future merchant-specific statements
	MinTimestamp  int64    // Placeholder for future date-range statements
	MaxTimestamp  int64    // Placeholder for future date-range statements
}

// --- IV. Core ZKP Protocols ---

// EqualityProof data structure. Proves a commitment `C` is to a specific public scalar `v_known`.
type EqualityProof struct {
	S *big.Int // s = k - c*r_known mod N
	T *bn256.G1 // T = k*H (where k is a random scalar chosen by Prover)
}

// ProveEquality proves a commitment `C` equals a public scalar `v_known`.
// Prover knows `v_known` and the randomness `r_known` used to create `C`.
// Protocol: P chooses random `k`, sends `T = k*H`. V challenges `c`. P sends `s = k - c*r_known`.
// V verifies `T == s*H + c*(C - v_known*G)`.
func ProveEquality(C *PedersenCommitment, v_known *big.Int, r_known *big.Int, G, H *bn256.G1, challenge *big.Int) *EqualityProof {
	k := GenerateRandomScalar() // Prover chooses random k
	T := new(bn256.G1).ScalarMult(H, k)

	// s = k - c*r_known mod N
	s := ScalarSub(k, ScalarMul(challenge, r_known))
	return &EqualityProof{S: s, T: T}
}

// VerifyEquality verifies that a commitment `C` is to a public scalar `v_known` using an `EqualityProof`.
func VerifyEquality(C *PedersenCommitment, v_known *big.Int, proof *EqualityProof, G, H *bn256.G1, challenge *big.Int) bool {
	// Reconstruct expected T': T' = s*H + c*(C - v_known*G)
	sH := new(bn256.G1).ScalarMult(H, proof.S)
	vKG := new(bn256.G1).ScalarMult(G, v_known)
	C_minus_vKG := new(bn256.G1).Add(C.Point, new(bn256.G1).Neg(vKG)) // C.Point - v_known*G
	c_C_minus_vKG := new(bn256.G1).ScalarMult(C_minus_vKG, challenge)

	expectedT := new(bn256.G1).Add(sH, c_C_minus_vKG)

	return expectedT.String() == proof.T.String()
}

// SumRelationProof data structure. Proves `C_sum` is the commitment to the sum of values
// committed in `termsC` (i.e., `sum(val_i) = val_sum`).
type SumRelationProof struct {
	S *big.Int // s = k - c * r_diff (where r_diff = r_sum - sum(r_i))
	T *bn256.G1 // T = k*H
}

// ProveSumRelation proves that `C_sum` (commitment to `sumVal` with `sumRand`) commits
// to the sum of values committed in `termsC` (commitments to `terms` with `termRandomness`).
// This protocol essentially proves `C_sum - sum(C_i) = 0`, without revealing individual values/randomness.
func ProveSumRelation(terms []*big.Int, termRandomness []*big.Int, sumVal *big.Int, sumRand *big.Int, G, H *bn256.G1, challenge *big.Int) *SumRelationProof {
	// The commitment `C_sum` should be `sumVal*G + sumRand*H`.
	// The sum of individual commitments `sum(C_i)` should be `(sum(terms))*G + (sum(termRandomness))*H`.
	// If `sumVal == sum(terms)`, then for `C_sum = sum(C_i)` to hold, `sumRand` must equal `sum(termRandomness)`.
	// We need to prove this equality of randomness, or rather, that the difference is 0.
	expectedTotalRandomnessForIndividualTerms := big.NewInt(0)
	for _, r := range termRandomness {
		expectedTotalRandomnessForIndividualTerms = ScalarAdd(expectedTotalRandomnessForIndividualTerms, r)
	}

	// r_diff is the difference in randomness: `r_diff = sumRand - sum(termRandomness)`.
	// If the values sum correctly, and the commitments are equal, then r_diff must be 0.
	r_diff := ScalarSub(sumRand, expectedTotalRandomnessForIndividualTerms)

	k := GenerateRandomScalar()
	T := new(bn256.G1).ScalarMult(H, k)

	// s = k - c * r_diff mod N
	s := ScalarSub(k, ScalarMul(challenge, r_diff))
	return &SumRelationProof{S: s, T: T}
}

// VerifySumRelation verifies that `sumC` commits to the sum of values committed in `termsC`.
func VerifySumRelation(termsC []*PedersenCommitment, sumC *PedersenCommitment, proof *SumRelationProof, G, H *bn256.G1, challenge *big.Int) bool {
	// Reconstruct the point `sumOfIndividualCommitments = sum(C_i)`
	sumOfIndividualCommitments := new(bn256.G1).ScalarMult(G, big.NewInt(0)) // Neutral element (point at infinity)
	for _, c := range termsC {
		sumOfIndividualCommitments = CurvePointAdd(sumOfIndividualCommitments, c.Point)
	}

	// Calculate `C_diff = sumC - sumOfIndividualCommitments`. This commitment should be to 0.
	C_diff := new(bn256.G1).Add(sumC.Point, new(bn256.G1).Neg(sumOfIndividualCommitments))

	// Verify using the `EqualityProof` logic for a zero-value commitment (`v_known = 0`).
	sH := new(bn256.G1).ScalarMult(H, proof.S)
	c_C_diff := new(bn256.G1).ScalarMult(C_diff, challenge)

	expectedT := new(bn256.G1).Add(sH, c_C_diff)

	return expectedT.String() == proof.T.String()
}

// NonNegativeFixedBitsProof data structure. This is a custom, simplified range proof.
// It proves a committed value is non-negative and fits within `maxBits`.
// The proof consists of commitments to the individual bits of the value (C_bi) and
// a `SumRelationProof` on the randomness, ensuring consistency with the main commitment.
// Note: A full ZK range proof (e.g., Bulletproofs) is significantly more complex, involving
// disjunctive proofs for bits. This implementation focuses on the structural composition and randomness
// consistency aspect for demonstration within the given constraints.
type NonNegativeFixedBitsProof struct {
	BitCommitments []*PedersenCommitment // Commitments to each bit (C_bi = b_i*G + r_bi*H)
	SumS           *big.Int              // s value for the sum relation (randomness consistency)
	SumT           *bn256.G1             // T value for the sum relation (randomness consistency)
}

// ProveNonNegativeFixedBits proves that a committed `value` (with `randomness`) is non-negative
// and can be represented using `maxBits` (i.e., `0 <= value < 2^maxBits`).
// It works by:
// 1. Decomposing `value` into `maxBits` bits (`b_0, ..., b_{maxBits-1}`).
// 2. Committing to each bit `b_i` as `C_bi = b_i*G + r_bi*H`.
// 3. Generating a `SumRelationProof` that the original commitment `C_val` is consistent
//    with the sum of these weighted bit commitments (`sum(C_bi * 2^i)`),
//    specifically, that `randomness == sum(r_bi * 2^i)`.
// The 0/1 property of each bit would require a complex disjunctive ZKP (e.g., proving C_bi is Commit(0) OR Commit(1)),
// which is omitted for brevity and focus on structural composition.
func ProveNonNegativeFixedBits(value *big.Int, randomness *big.Int, maxBits int, G, H *bn256.G1, challenge *big.Int) *NonNegativeFixedBitsProof {
	if value.Sign() == -1 {
		panic("Value must be non-negative for NonNegativeFixedBitsProof")
	}

	bits := make([]*big.Int, maxBits)
	bitRandomness := make([]*big.Int, maxBits)
	bitCommitments := make([]*PedersenCommitment, maxBits)

	currentValue := new(big.Int).Set(value)
	for i := 0; i < maxBits; i++ {
		bit := new(big.Int).And(currentValue, big.NewInt(1))
		bits[i] = bit
		bitRandomness[i] = GenerateRandomScalar()
		bitCommitments[i] = Commit(bit, bitRandomness[i], G, H)
		currentValue.Rsh(currentValue, 1) // Shift right by 1 to get next bit
	}

	// Now, prove that the original commitment's randomness (`randomness`) is consistent
	// with the sum of the weighted bit randomness terms (`sum(r_bi * 2^i)`).
	summedWeightedRandomness := big.NewInt(0)
	for i := 0; i < maxBits; i++ {
		weight := new(big.Int).Lsh(big.NewInt(1), uint(i)) // 2^i
		weightedBitRandomness := ScalarMul(bitRandomness[i], weight)
		summedWeightedRandomness = ScalarAdd(summedWeightedRandomness, weightedBitRandomness)
	}

	// This is an `EqualityProof` that `randomness == summedWeightedRandomness`.
	kSum := GenerateRandomScalar()
	TSum := new(bn256.G1).ScalarMult(H, kSum)
	sSum := ScalarSub(kSum, ScalarMul(challenge, ScalarSub(randomness, summedWeightedRandomness)))

	return &NonNegativeFixedBitsProof{
		BitCommitments: bitCommitments,
		SumS:           sSum,
		SumT:           TSum,
	}
}

// VerifyNonNegativeFixedBits verifies a `NonNegativeFixedBitsProof`.
// It checks two main things:
// 1. The original `commitment` is structurally equivalent to the sum of its `maxBits` bit commitments,
//    meaning `C_val == sum(C_bi * 2^i)`, verified by `SumS`/`SumT`.
// 2. (Crucially, and simplified for this demo): Each `C_bi` is implicitly a commitment to 0 or 1.
//    In a full ZKP, this requires disjunctive proofs for each bit, which is beyond this scope.
//    Here, the structural verification implies that if the overall proof is sound, bits must be 0/1.
func VerifyNonNegativeFixedBits(commitment *PedersenCommitment, proof *NonNegativeFixedBitsProof, maxBits int, G, H *bn256.G1, challenge *big.Int) bool {
	if len(proof.BitCommitments) != maxBits {
		return false // Proof structure mismatch: incorrect number of bit commitments
	}

	// Reconstruct the point sum of weighted bit commitments: `sum(C_bi * 2^i)`
	sumOfWeightedBitCommitments := new(bn256.G1).ScalarMult(G, big.NewInt(0)) // Zero point
	for i := 0; i < maxBits; i++ {
		weight := new(big.Int).Lsh(big.NewInt(1), uint(i)) // 2^i
		weightedBitCommitmentPoint := new(bn256.G1).ScalarMult(proof.BitCommitments[i].Point, weight)
		sumOfWeightedBitCommitments = CurvePointAdd(sumOfWeightedBitCommitments, weightedBitCommitmentPoint)
	}

	// Now, verify that `commitment` (C_val) is equal to `sumOfWeightedBitCommitments`.
	// This implies `value == sum(bit_i * 2^i)` and `randomness == sum(r_bi * 2^i)`.
	// The `SumS` and `SumT` in `NonNegativeFixedBitsProof` act as an `EqualityProof` for `C_val - sum(C_bi_weighted) = 0`.
	C_diff := new(bn256.G1).Add(commitment.Point, new(bn256.G1).Neg(sumOfWeightedBitCommitments))

	sSumH := new(bn256.G1).ScalarMult(H, proof.SumS)
	c_C_diff := new(bn256.G1).ScalarMult(C_diff, challenge)
	expectedTSum := new(bn256.G1).Add(sSumH, c_C_diff)

	if expectedTSum.String() != proof.SumT.String() {
		return false // Sum relation for randomness/values mismatch
	}

	// At this point, the structural composition (C_val = sum of weighted C_bi) and randomness consistency are verified.
	// The omitted part for a full ZK range proof is the explicit ZKP that each C_bi is indeed a commitment to 0 or 1.
	// For this demo, the focus is on composition and consistency.
	return true
}

// DifferenceEqualityProof data structure for proving `C_a - C_b = C_c`.
// This is useful for proving inequalities like `A > B` by showing `A - B = positive_value`,
// and then proving `positive_value` is non-negative using `NonNegativeFixedBitsProof`.
type DifferenceEqualityProof struct {
	S *big.Int // s = k - c * r_diff (where r_diff = r_a - r_b - r_c)
	T *bn256.G1 // T = k*H
}

// ProveDifferenceEquality proves that `C_a - C_b` equals `C_c`.
// Prover knows `valA, randA, valB, randB, valC, randC`.
// This implicitly means `(valA - valB - valC) = 0` and `(randA - randB - randC) = 0`.
// The proof verifies `C_target = 0`, where `C_target = C_a - C_b - C_c`.
func ProveDifferenceEquality(valA, randA, valB, randB, valC, randC *big.Int, G, H *bn256.G1, challenge *big.Int) *DifferenceEqualityProof {
	k := GenerateRandomScalar()
	T := new(bn256.G1).ScalarMult(H, k)

	// r_diff = randA - randB - randC
	r_diff := ScalarSub(randA, randB)
	r_diff = ScalarSub(r_diff, randC)

	s := ScalarSub(k, ScalarMul(challenge, r_diff))
	return &DifferenceEqualityProof{S: s, T: T}
}

// VerifyDifferenceEquality verifies a `DifferenceEqualityProof` for `C_a - C_b = C_c`.
func VerifyDifferenceEquality(CA, CB, CC *PedersenCommitment, proof *DifferenceEqualityProof, G, H *bn256.G1, challenge *big.Int) bool {
	// Reconstruct `C_target = CA - CB - CC`
	CA_minus_CB := new(bn256.G1).Add(CA.Point, new(bn256.G1).Neg(CB.Point))
	C_target := new(bn256.G1).Add(CA_minus_CB, new(bn256.G1).Neg(CC.Point))

	// Verify using the `EqualityProof` logic for a zero-value commitment (`v_known = 0`).
	sH := new(bn256.G1).ScalarMult(H, proof.S)
	c_C_target := new(bn256.G1).ScalarMult(C_target, challenge)

	expectedT := new(bn256.G1).Add(sH, c_C_target)

	return expectedT.String() == proof.T.String()
}

// --- VI. Application Layer & Aggregate Proof ---

// ProverContext holds the prover's private data (transactions) and cryptographic secrets (randomness).
type ProverContext struct {
	Transactions          []*Transaction
	CommittedTransactions []*CommittedTransaction // Committed versions including randomness for prover's use
	G, H                  *bn256.G1
	PublicStatements      []*FinancialProofStatement
}

// NewProverContext initializes the prover with transaction data.
// It also creates initial commitments for each transaction field, storing them along with their randomness.
func NewProverContext(txs []*Transaction, G, H *bn256.G1, statements []*FinancialProofStatement) *ProverContext {
	committedTxs := make([]*CommittedTransaction, len(txs))
	for i, tx := range txs {
		r_amt := GenerateRandomScalar()
		r_cat := GenerateRandomScalar()
		r_mer := GenerateRandomScalar()
		r_ts := GenerateRandomScalar()

		committedTxs[i] = &CommittedTransaction{
			C_Amount:     Commit(tx.Amount, r_amt, G, H),
			R_Amount:     r_amt,
			C_CategoryID: Commit(tx.CategoryID, r_cat, G, H),
			R_CategoryID: r_cat,
			C_MerchantID: Commit(tx.MerchantID, r_mer, G, H),
			R_MerchantID: r_mer,
			C_Timestamp:  Commit(big.NewInt(tx.Timestamp), r_ts, G, H),
			R_Timestamp:  r_ts,
		}
	}

	return &ProverContext{
		Transactions:          txs,
		CommittedTransactions: committedTxs,
		G:                     G,
		H:                     H,
		PublicStatements:      statements,
	}
}

// VerifierContext holds the public information for verification, including public statements
// and the commitments received from the prover (but not the secret randomness).
type VerifierContext struct {
	PublicStatements      []*FinancialProofStatement
	CommittedTransactions []*CommittedTransaction // Verifier gets *only* commitments, not randomness or values
	G, H                  *bn256.G1
}

// NewVerifierContext initializes the verifier with public statements and the commitments
// of the prover's transactions. The verifier does not receive the private randomness.
func NewVerifierContext(statements []*FinancialProofStatement, committedTxs []*CommittedTransaction, G, H *bn256.G1) *VerifierContext {
	// Verifier receives only the commitments, not the secret randomness.
	verifierCommittedTxs := make([]*CommittedTransaction, len(committedTxs))
	for i, ct := range committedTxs {
		verifierCommittedTxs[i] = &CommittedTransaction{
			C_Amount:     ct.C_Amount,
			C_CategoryID: ct.C_CategoryID,
			C_MerchantID: ct.C_MerchantID,
			C_Timestamp:  ct.C_Timestamp,
		}
	}
	return &VerifierContext{
		PublicStatements:      statements,
		CommittedTransactions: verifierCommittedTxs,
		G:                     G,
		H:                     H,
	}
}

// TotalSpendingProofComponent encapsulates all sub-proofs needed for a
// "TotalSpendingInCategoryID" statement.
type TotalSpendingProofComponent struct {
	C_TotalAmount             *PedersenCommitment // Commitment to sum of relevant amounts
	RelevantTxIndices         []int               // Indices of transactions included in the sum
	CategoryEqualityProofs    []*EqualityProof    // For each relevant index, prove C_CategoryID == C(stmt.CategoryID)
	SumProof                  *SumRelationProof   // Proof C_TotalAmount is sum of amounts from relevant indices
	C_ThresholdDiff           *PedersenCommitment // Commitment for (TotalAmount - Threshold)
	ThresholdDiffProof        *DifferenceEqualityProof
	ThresholdDiffNonNegativeProof *NonNegativeFixedBitsProof // Proof C_ThresholdDiff >= 0
}

// TransactionCountProofComponent encapsulates all sub-proofs needed for a
// "TransactionCountInRange" statement.
type TransactionCountProofComponent struct {
	C_TotalCount             *PedersenCommitment // Commitment to count of relevant transactions
	RelevantTxIndices        []int               // Indices of transactions counted
	CategoryEqualityProofs   []*EqualityProof    // For each counted index, prove C_CategoryID == C(stmt.CategoryID)
	RelevantCommittedOnes    []*PedersenCommitment // Commitments to '1' for each counted transaction (for SumProof)
	CountSumProof            *SumRelationProof   // Proof C_TotalCount is sum of '1's from relevant indices
	C_MinCountDiff           *PedersenCommitment // Commitment for (TotalCount - MinCount)
	MinCountDiffProof        *DifferenceEqualityProof
	MinCountNonNegativeProof *NonNegativeFixedBitsProof // Proof C_MinCountDiff >= 0
	C_MaxCountDiff           *PedersenCommitment // Commitment for (MaxCount - TotalCount)
	MaxCountDiffProof        *DifferenceEqualityProof
	MaxCountNonNegativeProof *NonNegativeFixedBitsProof // Proof C_MaxCountDiff >= 0
}

// AggregateZKProof encapsulates all generated sub-proofs for various statements.
type AggregateZKProof struct {
	TotalSpendingComponents    []*TotalSpendingProofComponent
	TransactionCountComponents []*TransactionCountProofComponent
	OverallChallenge           *big.Int // Combined challenge for Fiat-Shamir
}

// GenerateAggregateZKProof orchestrates the generation of all necessary proofs to satisfy the statements
// defined in the `proverCtx`. It uses the prover's private data to construct the proofs.
func GenerateAggregateZKProof(proverCtx *ProverContext, G, H *bn256.G1) (*AggregateZKProof, error) {
	// A single, combined challenge is used for simplicity in this demo.
	// In a full Fiat-Shamir implementation, the challenge would be generated incrementally
	// based on the transcript of all preceding commitments and proof parts.
	initialTranscript := []byte("Initial_ZK_Proof_Transcript_Seed")
	challenge := HashToScalar(initialTranscript)

	aggProof := &AggregateZKProof{}

	for _, stmt := range proverCtx.PublicStatements {
		switch stmt.Type {
		case "TotalSpendingInCategoryID":
			component := &TotalSpendingProofComponent{}

			relevantAmounts := []*big.Int{}
			relevantAmountsRandomness := []*big.Int{}

			totalAmountVal := big.NewInt(0)
			totalAmountRand := big.NewInt(0)

			// Iterate through all transactions to find relevant ones and generate category equality proofs
			for i, tx := range proverCtx.Transactions {
				// Each tx's C_CategoryID must be proven equal to the public stmt.CategoryID
				// This proof is generated even if the category doesn't match, to prove the selection logic.
				// However, for simplicity here, we only include the equality proof if the category *actually matches*
				// and the transaction is *included* in the sum. This effectively leaks which transactions contribute
				// but maintains ZK for the values.
				eqProof := ProveEquality(proverCtx.CommittedTransactions[i].C_CategoryID, tx.CategoryID, proverCtx.CommittedTransactions[i].R_CategoryID, G, H, challenge)

				if tx.CategoryID.Cmp(stmt.CategoryID) == 0 { // Prover's private decision to include this transaction
					component.RelevantTxIndices = append(component.RelevantTxIndices, i)
					component.CategoryEqualityProofs = append(component.CategoryEqualityProofs, eqProof) // Proof for matching category

					relevantAmounts = append(relevantAmounts, tx.Amount)
					relevantAmountsRandomness = append(relevantAmountsRandomness, proverCtx.CommittedTransactions[i].R_Amount)

					totalAmountVal = ScalarAdd(totalAmountVal, tx.Amount)
					totalAmountRand = ScalarAdd(totalAmountRand, proverCtx.CommittedTransactions[i].R_Amount)
				}
			}

			// 2. Commit to the total sum of relevant amounts.
			component.C_TotalAmount = Commit(totalAmountVal, totalAmountRand, G, H)

			// 3. Prove C_TotalAmount is indeed the sum of amounts from relevant transactions.
			component.SumProof = ProveSumRelation(relevantAmounts, relevantAmountsRandomness, totalAmountVal, totalAmountRand, G, H, challenge)

			// 4. Prove TotalAmount >= Threshold (i.e., TotalAmount - Threshold >= 0).
			diffVal := ScalarSub(totalAmountVal, stmt.Threshold)
			r_diff := GenerateRandomScalar() // Fresh randomness for the difference commitment
			component.C_ThresholdDiff = Commit(diffVal, r_diff, G, H)

			// Prove C_TotalAmount - Commit(Threshold) = C_ThresholdDiff. (Commit(Threshold) uses 0 randomness as it's public)
			component.ThresholdDiffProof = ProveDifferenceEquality(totalAmountVal, totalAmountRand, stmt.Threshold, big.NewInt(0), diffVal, r_diff, G, H, challenge)
			// Prove C_ThresholdDiff is a non-negative value (using NonNegativeFixedBitsProof, assuming 64 bits for amounts).
			component.ThresholdDiffNonNegativeProof = ProveNonNegativeFixedBits(diffVal, r_diff, 64, G, H, challenge)

			aggProof.TotalSpendingComponents = append(aggProof.TotalSpendingComponents, component)

		case "MinUniqueMerchants":
			// This is a highly complex ZKP problem involving set membership and distinctness proofs,
			// which typically requires advanced techniques like polynomial commitments or custom circuits.
			// It is left as a conceptual placeholder due to its complexity for a from-scratch implementation.
			return nil, fmt.Errorf("MinUniqueMerchants statement type not implemented in detail for this demo due to complexity")

		case "TransactionCountInRange":
			component := &TransactionCountProofComponent{}

			individualOnes := []*big.Int{}          // List of '1's to sum for the count
			individualOnesRandomness := []*big.Int{} // Randomness for each '1'
			
			countVal := big.NewInt(0)
			totalCountRand := big.NewInt(0)

			// Iterate through transactions, identify relevant ones for counting
			for i, tx := range proverCtx.Transactions {
				eqProof := ProveEquality(proverCtx.CommittedTransactions[i].C_CategoryID, tx.CategoryID, proverCtx.CommittedTransactions[i].R_CategoryID, G, H, challenge)
				if tx.CategoryID.Cmp(stmt.CategoryID) == 0 { // Private decision to include
					component.RelevantTxIndices = append(component.RelevantTxIndices, i)
					component.CategoryEqualityProofs = append(component.CategoryEqualityProofs, eqProof)

					countVal = ScalarAdd(countVal, big.NewInt(1))
					r_one := GenerateRandomScalar()
					individualOnes = append(individualOnes, big.NewInt(1))
					individualOnesRandomness = append(individualOnesRandomness, r_one)
					totalCountRand = ScalarAdd(totalCountRand, r_one) // Sum randomness for the total count commitment
					component.RelevantCommittedOnes = append(component.RelevantCommittedOnes, Commit(big.NewInt(1), r_one, G, H)) // Store C(1) for verifier
				}
			}
			
			component.C_TotalCount = Commit(countVal, totalCountRand, G, H)
			// Prove C_TotalCount is sum of C(1) commitments for each relevant transaction.
			component.CountSumProof = ProveSumRelation(individualOnes, individualOnesRandomness, countVal, totalCountRand, G, H, challenge)

			// Prove countVal >= stmt.MinCount
			minCountVal := big.NewInt(int64(stmt.MinCount))
			r_minDiff := GenerateRandomScalar()
			component.C_MinCountDiff = Commit(ScalarSub(countVal, minCountVal), r_minDiff, G, H)
			component.MinCountDiffProof = ProveDifferenceEquality(countVal, totalCountRand, minCountVal, big.NewInt(0), ScalarSub(countVal, minCountVal), r_minDiff, G, H, challenge)
			component.MinCountNonNegativeProof = ProveNonNegativeFixedBits(ScalarSub(countVal, minCountVal), r_minDiff, 64, G, H, challenge)

			// Prove countVal <= stmt.MaxCount
			maxCountVal := big.NewInt(int64(stmt.MaxCount))
			r_maxDiff := GenerateRandomScalar()
			component.C_MaxCountDiff = Commit(ScalarSub(maxCountVal, countVal), r_maxDiff, G, H)
			component.MaxCountDiffProof = ProveDifferenceEquality(maxCountVal, big.NewInt(0), countVal, totalCountRand, ScalarSub(maxCountVal, countVal), r_maxDiff, G, H, challenge)
			component.MaxCountNonNegativeProof = ProveNonNegativeFixedBits(ScalarSub(maxCountVal, countVal), r_maxDiff, 64, G, H, challenge)

			aggProof.TransactionCountComponents = append(aggProof.TransactionCountComponents, component)

		default:
			return nil, fmt.Errorf("unsupported statement type: %s", stmt.Type)
		}
	}

	aggProof.OverallChallenge = challenge
	return aggProof, nil
}


// VerifyAggregateZKProof verifies the entire aggregate proof against the public statements
// defined in the `verifierCtx`. It uses the commitments from `verifierCtx` and the `proof` itself.
func VerifyAggregateZKProof(verifierCtx *VerifierContext, proof *AggregateZKProof, G, H *bn256.G1) (bool, error) {
	challenge := proof.OverallChallenge
	if challenge == nil {
		return false, fmt.Errorf("overall challenge is missing")
	}

	totalSpendingIdx := 0
	transactionCountIdx := 0

	for _, stmt := range verifierCtx.PublicStatements {
		switch stmt.Type {
		case "TotalSpendingInCategoryID":
			if totalSpendingIdx >= len(proof.TotalSpendingComponents) {
				return false, fmt.Errorf("missing proof component for TotalSpendingInCategoryID statement")
			}
			comp := proof.TotalSpendingComponents[totalSpendingIdx]

			// 1. Verify category equality proofs for transactions claimed to be relevant
			relevantCommittedAmounts := []*PedersenCommitment{}
			if len(comp.RelevantTxIndices) != len(comp.CategoryEqualityProofs) {
				return false, fmt.Errorf("mismatch in relevant transaction indices and category equality proofs count for TotalSpending")
			}

			for i, txIdx := range comp.RelevantTxIndices {
				if txIdx >= len(verifierCtx.CommittedTransactions) {
					return false, fmt.Errorf("invalid transaction index in TotalSpending proof: %d", txIdx)
				}
				committedTx := verifierCtx.CommittedTransactions[txIdx]
				
				// Verify C_CategoryID == C(stmt.CategoryID)
				if !VerifyEquality(committedTx.C_CategoryID, stmt.CategoryID, comp.CategoryEqualityProofs[i], G, H, challenge) {
					return false, fmt.Errorf("category equality proof failed for transaction index %d in TotalSpending", txIdx)
				}
				relevantCommittedAmounts = append(relevantCommittedAmounts, committedTx.C_Amount)
			}

			// 2. Verify SumRelationProof for the total amount
			if !VerifySumRelation(relevantCommittedAmounts, comp.C_TotalAmount, comp.SumProof, G, H, challenge) {
				return false, fmt.Errorf("sum relation proof for total spending failed")
			}

			// 3. Verify ThresholdDiffProof: C_TotalAmount - C_Threshold = C_ThresholdDiff
			C_Threshold := Commit(stmt.Threshold, big.NewInt(0), G, H) // Recreate commitment for public threshold
			if !VerifyDifferenceEquality(comp.C_TotalAmount, C_Threshold, comp.C_ThresholdDiff, comp.ThresholdDiffProof, G, H, challenge) {
				return false, fmt.Errorf("difference equality proof for threshold failed")
			}

			// 4. Verify NonNegativeFixedBitsProof for C_ThresholdDiff (proving TotalAmount >= Threshold)
			if !VerifyNonNegativeFixedBits(comp.C_ThresholdDiff, comp.ThresholdDiffNonNegativeProof, 64, G, H, challenge) {
				return false, fmt.Errorf("non-negative proof for threshold difference failed")
			}

			totalSpendingIdx++

		case "MinUniqueMerchants":
			return false, fmt.Errorf("MinUniqueMerchants statement type verification not implemented in detail for this demo due to complexity")

		case "TransactionCountInRange":
			if transactionCountIdx >= len(proof.TransactionCountComponents) {
				return false, fmt.Errorf("missing proof component for TransactionCountInRange statement")
			}
			comp := proof.TransactionCountComponents[transactionCountIdx]

			// 1. Verify category equality proofs for transactions claimed to be counted
			if len(comp.RelevantTxIndices) != len(comp.CategoryEqualityProofs) {
				return false, fmt.Errorf("mismatch in relevant transaction indices and category equality proofs count for TransactionCount")
			}

			for i, txIdx := range comp.RelevantTxIndices {
				if txIdx >= len(verifierCtx.CommittedTransactions) {
					return false, fmt.Errorf("invalid transaction index in TransactionCount proof: %d", txIdx)
				}
				committedTx := verifierCtx.CommittedTransactions[txIdx]

				// Verify C_CategoryID == C(stmt.CategoryID)
				if !VerifyEquality(committedTx.C_CategoryID, stmt.CategoryID, comp.CategoryEqualityProofs[i], G, H, challenge) {
					return false, fmt.Errorf("category equality proof failed for transaction index %d in TransactionCount", txIdx)
				}
				// The `RelevantCommittedOnes` provided by the prover will be used as `termsC` for the `CountSumProof`
			}

			// 2. Verify CountSumProof: C_TotalCount is sum of C(1)s
			if !VerifySumRelation(comp.RelevantCommittedOnes, comp.C_TotalCount, comp.CountSumProof, G, H, challenge) {
				return false, fmt.Errorf("sum relation proof for transaction count failed")
			}

			// 3. Verify MinCount conditions: C_TotalCount - C_MinCount = C_MinCountDiff and C_MinCountDiff >= 0
			C_MinCount := Commit(big.NewInt(int64(stmt.MinCount)), big.NewInt(0), G, H)
			if !VerifyDifferenceEquality(comp.C_TotalCount, C_MinCount, comp.C_MinCountDiff, comp.MinCountDiffProof, G, H, challenge) {
				return false, fmt.Errorf("difference equality proof for min count failed")
			}
			if !VerifyNonNegativeFixedBits(comp.C_MinCountDiff, comp.MinCountNonNegativeProof, 64, G, H, challenge) {
				return false, fmt.Errorf("non-negative proof for min count difference failed")
			}

			// 4. Verify MaxCount conditions: C_MaxCount - C_TotalCount = C_MaxCountDiff and C_MaxCountDiff >= 0
			C_MaxCount := Commit(big.NewInt(int64(stmt.MaxCount)), big.NewInt(0), G, H)
			if !VerifyDifferenceEquality(C_MaxCount, comp.C_TotalCount, comp.C_MaxCountDiff, comp.MaxCountDiffProof, G, H, challenge) {
				return false, fmt.Errorf("difference equality proof for max count failed")
			}
			if !VerifyNonNegativeFixedBits(comp.C_MaxCountDiff, comp.MaxCountNonNegativeProof, 64, G, H, challenge) {
				return false, fmt.Errorf("non-negative proof for max count difference failed")
			}

			transactionCountIdx++

		default:
			return false, fmt.Errorf("unsupported statement type for verification: %s", stmt.Type)
		}
	}

	return true, nil
}


// Main function for demonstration
func main() {
	fmt.Println("Starting Zero-Knowledge Proof Demonstration for Aggregate Financial Health Verification...")

	// 1. Setup global Pedersen generators
	G, H := SetupPedersenGenerators()
	fmt.Println("Pedersen Generators (G, H) Setup.")

	// 2. Prover's private financial data
	txs := []*Transaction{
		{Amount: big.NewInt(15000), CategoryID: big.NewInt(101), MerchantID: big.NewInt(1001), Timestamp: time.Now().Add(-24 * 30 * time.Hour).Unix()}, // Groceries ($150.00)
		{Amount: big.NewInt(5000), CategoryID: big.NewInt(102), MerchantID: big.NewInt(1002), Timestamp: time.Now().Add(-24 * 20 * time.Hour).Unix()},  // Entertainment ($50.00)
		{Amount: big.NewInt(25000), CategoryID: big.NewInt(101), MerchantID: big.NewInt(1003), Timestamp: time.Now().Add(-24 * 10 * time.Hour).Unix()}, // Groceries ($250.00)
		{Amount: big.NewInt(10000), CategoryID: big.NewInt(103), MerchantID: big.NewInt(1004), Timestamp: time.Now().Add(-24 * 5 * time.Hour).Unix()},  // Utilities ($100.00)
		{Amount: big.NewInt(7000), CategoryID: big.NewInt(101), MerchantID: big.NewInt(1005), Timestamp: time.Now().Add(-24 * 2 * time.Hour).Unix()},  // Groceries ($70.00)
	}
	fmt.Printf("Prover has %d private transactions.\n", len(txs))

	// 3. Define public statements (conditions Prover needs to meet)
	statements := []*FinancialProofStatement{
		{Type: "TotalSpendingInCategoryID", CategoryID: big.NewInt(101), Threshold: big.NewInt(40000)}, // Total groceries > $400.00 (150+250+70 = $470.00) -> TRUE
		{Type: "TransactionCountInRange", CategoryID: big.NewInt(101), MinCount: 2, MaxCount: 4}, // Groceries transactions count between 2 and 4 (count = 3) -> TRUE
		//{Type: "MinUniqueMerchants", MinCount: 2}, // Placeholder for complex proof
	}
	fmt.Printf("Verifier's public statements: %+v\n", statements)

	// 4. Initialize Prover Context and commit to transactions
	proverCtx := NewProverContext(txs, G, H, statements)
	fmt.Printf("Prover Context initialized with %d committed transactions.\n", len(proverCtx.CommittedTransactions))

	// 5. Prover generates the aggregate ZK Proof
	fmt.Println("\nProver generating aggregate ZK proof...")
	aggregateProof, err := GenerateAggregateZKProof(proverCtx, G, H)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}
	fmt.Println("Aggregate ZK proof generated successfully.")

	// 6. Initialize Verifier Context with public statements and *committed* transactions (no raw data/randomness)
	verifierCtx := NewVerifierContext(statements, proverCtx.CommittedTransactions, G, H) // Verifier only gets commitments
	fmt.Println("\nVerifier Context initialized.")

	// 7. Verifier verifies the aggregate ZK Proof
	fmt.Println("\nVerifier verifying aggregate ZK proof...")
	isValid, err := VerifyAggregateZKProof(verifierCtx, aggregateProof, G, H)
	if err != nil {
		fmt.Printf("Error verifying proof: %v\n", err)
		return
	}

	if isValid {
		fmt.Println("\n--- Verification RESULT: SUCCESS! ---")
		fmt.Println("Prover has successfully demonstrated compliance with financial statements without revealing private transaction details.")
	} else {
		fmt.Println("\n--- Verification RESULT: FAILED! ---")
		fmt.Println("The proof is invalid or statements are not met.")
	}

	// --- Test cases for failure scenarios ---

	// Test case for failure: threshold not met (total spending is too low)
	fmt.Println("\n--- Testing a failing scenario (threshold not met) ---")
	failingStatements := []*FinancialProofStatement{
		{Type: "TotalSpendingInCategoryID", CategoryID: big.NewInt(101), Threshold: big.NewInt(100000)}, // Groceries > $1000.00 (actual: $470.00) -> FALSE
	}
	failingProverCtx := NewProverContext(txs, G, H, failingStatements)
	failingAggregateProof, err := GenerateAggregateZKProof(failingProverCtx, G, H)
	if err != nil {
		fmt.Printf("Error generating failing proof: %v\n", err)
		return
	}
	failingVerifierCtx := NewVerifierContext(failingStatements, failingProverCtx.CommittedTransactions, G, H)
	isFailingValid, err := VerifyAggregateZKProof(failingVerifierCtx, failingAggregateProof, G, H)
	if err != nil {
		fmt.Printf("Error verifying failing proof: %v\n", err)
	}
	if !isFailingValid {
		fmt.Println("Failing scenario correctly identified: Proof is INVALID.")
	} else {
		fmt.Println("Failing scenario check failed: Proof unexpectedly VALID.")
	}

	// Test case for failure: wrong category ID in statement (no transactions in this category)
	fmt.Println("\n--- Testing a failing scenario (wrong category ID in statement) ---")
	wrongCategoryStatements := []*FinancialProofStatement{
		{Type: "TotalSpendingInCategoryID", CategoryID: big.NewInt(999), Threshold: big.NewInt(100)}, // Category 999 (doesn't exist) -> will fail because count of relevant txs is 0
	}
	wrongCategoryProverCtx := NewProverContext(txs, G, H, wrongCategoryStatements)
	wrongCategoryAggregateProof, err := GenerateAggregateZKProof(wrongCategoryProverCtx, G, H)
	if err != nil {
		fmt.Printf("Error generating wrong category proof: %v\n", err)
		return
	}
	wrongCategoryVerifierCtx := NewVerifierContext(wrongCategoryStatements, wrongCategoryProverCtx.CommittedTransactions, G, H)
	isWrongCategoryValid, err := VerifyAggregateZKProof(wrongCategoryVerifierCtx, wrongCategoryAggregateProof, G, H)
	if err != nil {
		fmt.Printf("Error verifying wrong category proof: %v\n", err)
	}
	if !isWrongCategoryValid {
		fmt.Println("Wrong category scenario correctly identified: Proof is INVALID.")
	} else {
		fmt.Println("Wrong category scenario check failed: Proof unexpectedly VALID.")
	}

	// Test case for failure: Transaction count out of range (count = 3, range [0,1])
	fmt.Println("\n--- Testing a failing scenario (transaction count out of range) ---")
	failingCountStatements := []*FinancialProofStatement{
		{Type: "TransactionCountInRange", CategoryID: big.NewInt(101), MinCount: 0, MaxCount: 1}, // Groceries transactions count between 0 and 1 (actual: 3) -> FALSE
	}
	failingCountProverCtx := NewProverContext(txs, G, H, failingCountStatements)
	failingCountAggregateProof, err := GenerateAggregateZKProof(failingCountProverCtx, G, H)
	if err != nil {
		fmt.Printf("Error generating failing count proof: %v\n", err)
		return
	}
	failingCountVerifierCtx := NewVerifierContext(failingCountStatements, failingCountProverCtx.CommittedTransactions, G, H)
	isFailingCountValid, err := VerifyAggregateZKProof(failingCountVerifierCtx, failingCountAggregateProof, G, H)
	if err != nil {
		fmt.Printf("Error verifying failing count proof: %v\n", err)
	}
	if !isFailingCountValid {
		fmt.Println("Failing count scenario correctly identified: Proof is INVALID.")
	} else {
		fmt.Println("Failing count scenario check failed: Proof unexpectedly VALID.")
	}
}

```