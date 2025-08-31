This Zero-Knowledge Proof (ZKP) implementation in Golang focuses on a "Secure Aggregation of Encrypted Sensor Readings" scenario. This is an advanced, trendy concept applicable in IoT, federated learning, and confidential computing.

**The Problem:** Multiple IoT sensors report private data readings (`d_1, ..., d_N`). A central gateway needs to compute the sum and average of these readings (`Sum_D = sum(d_i)`, `Avg = Sum_D / N`) and prove that these aggregated results are correct, *without revealing any individual sensor reading `d_i`*.

**The ZKP Solution:**
Each sensor uses Pedersen commitments to commit to its reading `d_i`. The central gateway then computes the sum and average of the readings, and generates Pedersen commitments for `Sum_D` and `Avg`. The gateway then creates two Zero-Knowledge proofs:
1.  **Proof of Sum:** Proves that `Sum_D` is indeed the sum of all `d_i` values. This leverages the additive homomorphic property of Pedersen commitments and a Schnorr-like proof for the exponent of the blinding factor.
2.  **Proof of Average:** Proves that `Avg` is `Sum_D / N`. This leverages the homomorphic property where `Commit(A*k) = Commit(A)^k` for a public `k` (here `N`), again with a Schnorr-like proof for the blinding factor.

This implementation provides a conceptual ZKP. While it uses standard cryptographic primitives (Pedersen commitments, Schnorr-like proofs, Fiat-Shamir heuristic) built from `big.Int` modular arithmetic, it simplifies certain aspects compared to production-grade ZKP systems (e.g., assumes trust in system parameters, fixed prime field, no explicit range proofs for values). The primary goal is to demonstrate the *principles* and *structure* of a ZKP for a complex application.

---

### Outline and Function Summary

**I. Core Cryptographic Primitives (Modular Arithmetic & Pedersen Commitments)**
These functions implement the foundational arithmetic operations over a large prime field and the Pedersen commitment scheme.

1.  `SystemParams`: Struct holding system-wide cryptographic parameters (prime `P`, generators `G, H`, order `Q`).
2.  `GenerateSystemParams()`: Initializes and returns `SystemParams` with a large prime, two generators, and their order.
3.  `GenerateRandomScalar(max *big.Int)`: Generates a cryptographically secure random `big.Int` less than `max`.
4.  `ScalarAdd(a, b, P *big.Int)`: Performs modular addition `(a + b) mod P`.
5.  `ScalarSub(a, b, P *big.Int)`: Performs modular subtraction `(a - b) mod P`.
6.  `ScalarMul(a, b, P *big.Int)`: Performs modular multiplication `(a * b) mod P`.
7.  `ScalarExp(base, exp, P *big.Int)`: Performs modular exponentiation `base^exp mod P`.
8.  `ScalarInverse(a, P *big.Int)`: Computes the modular multiplicative inverse `a^-1 mod P`.
9.  `PedersenCommit(value, randomness, G, H, P *big.Int)`: Computes a Pedersen commitment `G^value * H^randomness mod P`.
10. `VerifyPedersenCommit(commitment, value, randomness, G, H, P *big.Int)`: Checks if a `commitment` opens to `value` with `randomness`.
11. `HashToScalar(data []byte, P *big.Int)`: Hashes arbitrary byte data to a scalar within `[0, P-1]` using SHA256 and modulo arithmetic, essential for Fiat-Shamir.

**II. ZKP Data Structures for Secure Aggregation**
These structs organize the data involved in the secure aggregation protocol.

12. `SensorReading`: Represents a single sensor's data with its value and commitment.
13. `SensorCommitment`: Public part of `SensorReading` to be shared.
14. `AggregatedData`: Stores the final sum and average values.
15. `AggregatedCommitments`: Public commitments for `Sum_D` and `Avg`.
16. `AggregationProof`: Contains all elements of the ZKP for both sum and average (challenge and responses).

**III. ZKP Protocol - Prover's Steps**
These functions describe how the prover (central gateway) computes the aggregate values and generates the proofs.

17. `SensorProverCommitData(params *SystemParams, d_val *big.Int)`: A sensor commits to its private reading.
18. `AggregatorProverComputeAndCommit(params *SystemParams, sensorReadings []SensorReading, N int)`: The aggregator computes `Sum_D` and `Avg` from secret sensor readings and commits to them.
19. `GenerateCommonChallenge(params *SystemParams, commitments ...*big.Int)`: Generates a common challenge `e` for all proofs using the Fiat-Shamir heuristic over all commitments.
20. `ProverGenerateSumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, r_d_vals []*big.Int, r_Sum_D *big.Int, e *big.Int)`: Generates the Schnorr-like proof that `Sum_D` is the correct sum of `d_i` values, leveraging Pedersen's additive homomorphic property.
21. `ProverGenerateAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, r_Sum_D *big.Int, r_Avg *big.Int, e *big.Int)`: Generates the Schnorr-like proof that `Avg` is `Sum_D / N`, leveraging Pedersen's multiplicative homomorphic property for a public scalar.

**IV. ZKP Protocol - Verifier's Steps**
These functions describe how a verifier verifies the proofs without learning the secret values.

22. `VerifierVerifySumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, s_sum, T_sum, e *big.Int)`: Verifies the `Sum_D` proof.
23. `VerifierVerifyAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, s_avg, T_avg, e *big.Int)`: Verifies the `Avg` proof.

**V. Utility Functions**
Helper functions for logging and `big.Int` manipulation.

24. `NewBigInt(val int64)`: Convenience function to create a new `big.Int` from an `int64`.
25. `ProductOfCommitments(commitments []*big.Int, P *big.Int)`: Helper to compute the product of multiple commitments.
26. `CombineCommitmentsBytes(commitments ...*big.Int)`: Helper to concatenate byte representations of commitments for hashing.
27. `PrintCommitment(name string, c *big.Int)`: Prints a commitment value for debugging.
28. `PrintScalar(name string, s *big.Int)`: Prints a scalar value for debugging.
29. `main()`: The main entry point demonstrating the full ZKP flow.

---

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
)

// --- Outline and Function Summary ---
//
// I. Core Cryptographic Primitives (Modular Arithmetic & Pedersen Commitments)
//    These functions implement the foundational arithmetic operations over a large prime field
//    and the Pedersen commitment scheme.
//
// 1. SystemParams: Struct holding system-wide cryptographic parameters (prime P, generators G, H, order Q).
// 2. GenerateSystemParams(): Initializes and returns SystemParams with a large prime, two generators, and their order.
// 3. GenerateRandomScalar(max *big.Int): Generates a cryptographically secure random big.Int less than max.
// 4. ScalarAdd(a, b, P *big.Int): Performs modular addition (a + b) mod P.
// 5. ScalarSub(a, b, P *big.Int): Performs modular subtraction (a - b) mod P.
// 6. ScalarMul(a, b, P *big.Int): Performs modular multiplication (a * b) mod P.
// 7. ScalarExp(base, exp, P *big.Int): Performs modular exponentiation base^exp mod P.
// 8. ScalarInverse(a, P *big.Int): Computes the modular multiplicative inverse a^-1 mod P.
// 9. PedersenCommit(value, randomness, G, H, P *big.Int): Computes a Pedersen commitment G^value * H^randomness mod P.
// 10. VerifyPedersenCommit(commitment, value, randomness, G, H, P *big.Int): Checks if a commitment opens to value with randomness.
// 11. HashToScalar(data []byte, P *big.Int): Hashes arbitrary byte data to a scalar within [0, P-1] using SHA256 and modulo arithmetic, essential for Fiat-Shamir.
//
// II. ZKP Data Structures for Secure Aggregation
//     These structs organize the data involved in the secure aggregation protocol.
//
// 12. SensorReading: Represents a single sensor's data with its value and commitment.
// 13. SensorCommitment: Public part of SensorReading to be shared.
// 14. AggregatedData: Stores the final sum and average values.
// 15. AggregatedCommitments: Public commitments for Sum_D and Avg.
// 16. AggregationProof: Contains all elements of the ZKP for both sum and average (challenge and responses).
//
// III. ZKP Protocol - Prover's Steps
//      These functions describe how the prover (central gateway) computes the aggregate values and generates the proofs.
//
// 17. SensorProverCommitData(params *SystemParams, d_val *big.Int): A sensor commits to its private reading.
// 18. AggregatorProverComputeAndCommit(params *SystemParams, sensorReadings []SensorReading, N int): The aggregator computes Sum_D and Avg from secret sensor readings and commits to them.
// 19. GenerateCommonChallenge(params *SystemParams, commitments ...*big.Int): Generates a common challenge e for all proofs using the Fiat-Shamir heuristic over all commitments.
// 20. ProverGenerateSumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, r_d_vals []*big.Int, r_Sum_D *big.Int, e *big.Int): Generates the Schnorr-like proof that Sum_D is the correct sum of d_i values, leveraging Pedersen's additive homomorphic property.
// 21. ProverGenerateAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, r_Sum_D *big.Int, r_Avg *big.Int, e *big.Int): Generates the Schnorr-like proof that Avg is Sum_D / N, leveraging Pedersen's multiplicative homomorphic property for a public scalar.
//
// IV. ZKP Protocol - Verifier's Steps
//     These functions describe how a verifier verifies the proofs without learning the secret values.
//
// 22. VerifierVerifySumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, s_sum, T_sum, e *big.Int): Verifies the Sum_D proof.
// 23. VerifierVerifyAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, s_avg, T_avg, e *big.Int): Verifies the Avg proof.
//
// V. Utility Functions
//    Helper functions for logging and big.Int manipulation.
//
// 24. NewBigInt(val int64): Convenience function to create a new big.Int from an int64.
// 25. ProductOfCommitments(commitments []*big.Int, P *big.Int): Helper to compute the product of multiple commitments.
// 26. CombineCommitmentsBytes(commitments ...*big.Int): Helper to concatenate byte representations of commitments for hashing.
// 27. PrintCommitment(name string, c *big.Int): Prints a commitment value for debugging.
// 28. PrintScalar(name string, s *big.Int): Prints a scalar value for debugging.
// 29. main(): The main entry point demonstrating the full ZKP flow.

// I. Core Cryptographic Primitives
type SystemParams struct {
	P *big.Int // Large prime field modulus
	G *big.Int // Generator 1
	H *big.Int // Generator 2
	Q *big.Int // Order of the generators (subgroup order)
}

// GenerateSystemParams generates a set of public parameters for the ZKP system.
// P: a large prime number for the field.
// G, H: two distinct random generators of a subgroup of Z_P^*.
// Q: the order of the subgroup generated by G and H.
func GenerateSystemParams() *SystemParams {
	// For demonstration, use a moderately sized prime. In practice, this should be much larger (e.g., 2048+ bits).
	// P = 2^256 - 2^32 - 977 (a common prime in ECC, simplified here for modular arithmetic)
	P_hex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F" // Example large prime
	P, _ := new(big.Int).SetString(P_hex, 16)

	// Q should be a large prime factor of P-1.
	// For simplicity, let's assume Q = P-1 for this setup, or a large prime factor of P-1.
	// In a real system, we'd pick a safe prime P (P = 2q+1 where q is prime) or use ECC groups.
	// Here, we take Q as a large prime, usually the order of the group, which means G and H are elements of a group of order Q.
	// For Schnorr-like proofs, responses are modulo Q.
	Q_hex := "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001" // Example large prime for Q
	Q, _ := new(big.Int).SetString(Q_hex, 16)

	// G, H: random generators (should be in the subgroup of order Q).
	// For simplicity, pick random numbers and ensure they are < P.
	// In a proper setup, these would be derived from the curve parameters or field specifics.
	G, _ := new(big.Int).SetString("2", 10)
	H, _ := new(big.Int).SetString("3", 10) // Should be distinct and random

	// Ensure G and H are actual generators of a group of order Q.
	// For this conceptual exercise, we use small, distinct integers and assume P, Q are chosen to make them suitable.
	// A proper setup would involve finding elements of a specific prime-order subgroup.
	
	// Ensure G, H are smaller than P and not 0 or 1.
	if G.Cmp(P) >= 0 || H.Cmp(P) >= 0 || G.Cmp(big.NewInt(1)) <= 0 || H.Cmp(big.NewInt(1)) <= 0 {
		fmt.Println("Warning: Generators G or H are not suitable for the prime P. Using default or generating new.")
		G = new(big.Int).SetUint64(4) // Fallback if issues
		H = new(big.Int).SetUint64(5) // Fallback if issues
	}
	
	fmt.Printf("System Parameters Initialized:\n  P: %s\n  Q: %s\n  G: %s\n  H: %s\n", P.String(), Q.String(), G.String(), H.String())

	return &SystemParams{P: P, G: G, H: H, Q: Q}
}

// GenerateRandomScalar generates a cryptographically secure random big.Int < max.
func GenerateRandomScalar(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

// ScalarAdd performs modular addition (a + b) mod P.
func ScalarAdd(a, b, P *big.Int) *big.Int {
	return new(big.Int).Add(a, b).Mod(new(big.Int).Add(a, b), P)
}

// ScalarSub performs modular subtraction (a - b) mod P.
func ScalarSub(a, b, P *big.Int) *big.Int {
	return new(big.Int).Sub(a, b).Mod(new(big.Int).Sub(a, b), P)
}

// ScalarMul performs modular multiplication (a * b) mod P.
func ScalarMul(a, b, P *big.Int) *big.Int {
	return new(big.Int).Mul(a, b).Mod(new(big.Int).Mul(a, b), P)
}

// ScalarExp performs modular exponentiation base^exp mod P.
func ScalarExp(base, exp, P *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, P)
}

// ScalarInverse computes the modular multiplicative inverse a^-1 mod P.
func ScalarInverse(a, P *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, P)
}

// PedersenCommit computes a Pedersen commitment C = G^value * H^randomness mod P.
func PedersenCommit(value, randomness, G, H, P *big.Int) *big.Int {
	term1 := ScalarExp(G, value, P)
	term2 := ScalarExp(H, randomness, P)
	return ScalarMul(term1, term2, P)
}

// VerifyPedersenCommit checks if a commitment opens to value with randomness.
func VerifyPedersenCommit(commitment, value, randomness, G, H, P *big.Int) bool {
	expectedCommitment := PedersenCommit(value, randomness, G, H, P)
	return commitment.Cmp(expectedCommitment) == 0
}

// HashToScalar hashes arbitrary byte data to a scalar within [0, P-1] (for Fiat-Shamir).
func HashToScalar(data []byte, P *big.Int) *big.Int {
	h := sha256.New()
	h.Write(data)
	hashBytes := h.Sum(nil)
	return new(big.Int).SetBytes(hashBytes).Mod(new(big.Int).SetBytes(hashBytes), P)
}

// II. ZKP Data Structures for Secure Aggregation
type SensorReading struct {
	Value     *big.Int // Private sensor reading
	Randomness *big.Int // Blinding factor for commitment
	Commitment *big.Int // Public commitment to the reading
}

type SensorCommitment struct {
	Commitment *big.Int // Public commitment to the reading
}

type AggregatedData struct {
	SumD       *big.Int // Sum of all readings
	Avg        *big.Int // Average of all readings
	RandomnessSum *big.Int // Blinding factor for SumD commitment
	RandomnessAvg *big.Int // Blinding factor for Avg commitment
}

type AggregatedCommitments struct {
	CSumD *big.Int // Commitment to the sum
	CAvg  *big.Int // Commitment to the average
}

type AggregationProof struct {
	Challenge *big.Int // Fiat-Shamir challenge
	SSum      *big.Int // Response for sum proof
	TSum      *big.Int // Commitment to randomness for sum proof
	SAvg      *big.Int // Response for average proof
	TAvg      *big.Int // Commitment to randomness for average proof
}

// III. ZKP Protocol - Prover's Steps

// SensorProverCommitData - A single sensor commits to its private reading.
func SensorProverCommitData(params *SystemParams, d_val *big.Int) (*SensorReading, error) {
	r_d, err := GenerateRandomScalar(params.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to generate randomness for sensor: %w", err)
	}
	C_d := PedersenCommit(d_val, r_d, params.G, params.H, params.P)
	return &SensorReading{Value: d_val, Randomness: r_d, Commitment: C_d}, nil
}

// AggregatorProverComputeAndCommit - The aggregator computes Sum_D and Avg from secret sensor readings
// and commits to them. It needs all individual sensor readings and their randomness *secretly*.
func AggregatorProverComputeAndCommit(params *SystemParams, sensorReadings []SensorReading, N int) (*AggregatedData, *AggregatedCommitments, error) {
	if N == 0 || len(sensorReadings) != N {
		return nil, nil, fmt.Errorf("number of sensors N must match sensorReadings slice length")
	}

	totalSumD := big.NewInt(0)
	for _, sr := range sensorReadings {
		totalSumD = ScalarAdd(totalSumD, sr.Value, params.Q) // Sum values over Q, or P depending on interpretation
	}

	// Calculate average (Sum_D / N)
	N_big := big.NewInt(int64(N))
	avg := new(big.Int).Div(totalSumD, N_big) // Integer division for simplicity

	// Generate randomness for aggregated commitments
	r_SumD, err := GenerateRandomScalar(params.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness for sum: %w", err)
	}
	r_Avg, err := GenerateRandomScalar(params.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness for average: %w", err)
	}

	// Commit to Sum_D and Avg
	C_SumD := PedersenCommit(totalSumD, r_SumD, params.G, params.H, params.P)
	C_Avg := PedersenCommit(avg, r_Avg, params.G, params.H, params.P)

	aggData := &AggregatedData{SumD: totalSumD, Avg: avg, RandomnessSum: r_SumD, RandomnessAvg: r_Avg}
	aggCommits := &AggregatedCommitments{CSumD: C_SumD, CAvg: C_Avg}

	return aggData, aggCommits, nil
}

// GenerateCommonChallenge - Generates a common challenge `e` using Fiat-Shamir heuristic.
func GenerateCommonChallenge(params *SystemParams, commitments ...*big.Int) *big.Int {
	combinedBytes := CombineCommitmentsBytes(commitments...)
	return HashToScalar(combinedBytes, params.P) // Hash to a scalar in Z_P
}

// ProverGenerateSumProof - Proves Sum_D = sum(d_i) using Schnorr-like proof for exponents.
// It leverages Pedersen's additive homomorphic property: C(sum(d_i), sum(r_d_i)) = product(C(d_i, r_d_i)).
// So, Prover proves knowledge of `r_SumD - sum(r_d_i)`.
func ProverGenerateSumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, r_d_vals []*big.Int, r_Sum_D *big.Int, e *big.Int) (s_sum, T_sum *big.Int, err error) {
	// Calculate product of C_d_vals
	productC_d := ProductOfCommitments(C_d_vals, params.P)

	// Calculate expected randomness difference: r_sum_check = r_SumD - sum(r_d_i)
	sum_r_d := big.NewInt(0)
	for _, r := range r_d_vals {
		sum_r_d = ScalarAdd(sum_r_d, r, params.Q)
	}
	r_sum_check := ScalarSub(r_SumD, sum_r_d, params.Q) // Modulo Q for randomness

	// Calculate C_sum_check = C_Sum_D / product(C_d_vals) = H^(r_SumD - sum(r_d_i))
	C_sum_check_num := C_Sum_D
	C_sum_check_den_inv := ScalarInverse(productC_d, params.P)
	C_sum_check := ScalarMul(C_sum_check_num, C_sum_check_den_inv, params.P)

	// Schnorr-like proof for knowledge of r_sum_check (the exponent of H in C_sum_check)
	k_sum, err := GenerateRandomScalar(params.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random k_sum: %w", err)
	}
	T_sum = ScalarExp(params.H, k_sum, params.P) // T_sum = H^k_sum

	// s_sum = k_sum + e * r_sum_check mod Q
	s_sum = ScalarAdd(k_sum, ScalarMul(e, r_sum_check, params.Q), params.Q)

	return s_sum, T_sum, nil
}

// ProverGenerateAverageProof - Proves Avg = Sum_D / N using Schnorr-like proof for exponents.
// It leverages Pedersen's multiplicative homomorphic property: C(A*k, r*k) = C(A, r)^k.
// So, Prover proves knowledge of `r_SumD - N*r_Avg`.
func ProverGenerateAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, r_Sum_D *big.Int, r_Avg *big.Int, e *big.Int) (s_avg, T_avg *big.Int, err error) {
	N_big := big.NewInt(int64(N))

	// Calculate expected randomness difference: r_avg_check = r_SumD - N*r_Avg
	N_r_Avg := ScalarMul(N_big, r_Avg, params.Q)
	r_avg_check := ScalarSub(r_SumD, N_r_Avg, params.Q) // Modulo Q for randomness

	// Calculate C_avg_check = C_Sum_D / (C_Avg^N) = H^(r_SumD - N*r_Avg)
	C_avg_check_num := C_Sum_D
	C_Avg_exp_N := ScalarExp(C_Avg, N_big, params.P)
	C_avg_check_den_inv := ScalarInverse(C_Avg_exp_N, params.P)
	C_avg_check := ScalarMul(C_avg_check_num, C_avg_check_den_inv, params.P)

	// Schnorr-like proof for knowledge of r_avg_check (the exponent of H in C_avg_check)
	k_avg, err := GenerateRandomScalar(params.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random k_avg: %w", err)
	}
	T_avg = ScalarExp(params.H, k_avg, params.P) // T_avg = H^k_avg

	// s_avg = k_avg + e * r_avg_check mod Q
	s_avg = ScalarAdd(k_avg, ScalarMul(e, r_avg_check, params.Q), params.Q)

	return s_avg, T_avg, nil
}

// IV. ZKP Protocol - Verifier's Steps

// VerifierVerifySumProof - Verifies the sum proof.
func VerifierVerifySumProof(params *SystemParams, C_d_vals []*big.Int, C_Sum_D *big.Int, s_sum, T_sum, e *big.Int) bool {
	// Reconstruct C_sum_check = C_Sum_D / product(C_d_vals)
	productC_d := ProductOfCommitments(C_d_vals, params.P)
	C_sum_check_den_inv := ScalarInverse(productC_d, params.P)
	C_sum_check := ScalarMul(C_Sum_D, C_sum_check_den_inv, params.P)

	// Check H^s_sum == T_sum * (C_sum_check)^e mod P
	leftSide := ScalarExp(params.H, s_sum, params.P)
	rightSideTerm2 := ScalarExp(C_sum_check, e, params.P)
	rightSide := ScalarMul(T_sum, rightSideTerm2, params.P)

	return leftSide.Cmp(rightSide) == 0
}

// VerifierVerifyAverageProof - Verifies the average proof.
func VerifierVerifyAverageProof(params *SystemParams, C_Sum_D *big.Int, C_Avg *big.Int, N int, s_avg, T_avg, e *big.Int) bool {
	N_big := big.NewInt(int64(N))

	// Reconstruct C_avg_check = C_Sum_D / (C_Avg^N)
	C_Avg_exp_N := ScalarExp(C_Avg, N_big, params.P)
	C_avg_check_den_inv := ScalarInverse(C_Avg_exp_N, params.P)
	C_avg_check := ScalarMul(C_Sum_D, C_avg_check_den_inv, params.P)

	// Check H^s_avg == T_avg * (C_avg_check)^e mod P
	leftSide := ScalarExp(params.H, s_avg, params.P)
	rightSideTerm2 := ScalarExp(C_avg_check, e, params.P)
	rightSide := ScalarMul(T_avg, rightSideTerm2, params.P)

	return leftSide.Cmp(rightSide) == 0
}

// V. Utility Functions

// NewBigInt creates a new big.Int from an int64.
func NewBigInt(val int64) *big.Int {
	return big.NewInt(val)
}

// ProductOfCommitments computes the product of a slice of commitments.
func ProductOfCommitments(commitments []*big.Int, P *big.Int) *big.Int {
	product := big.NewInt(1)
	for _, c := range commitments {
		product = ScalarMul(product, c, P)
	}
	return product
}

// CombineCommitmentsBytes concatenates the byte representation of multiple commitments.
func CombineCommitmentsBytes(commitments ...*big.Int) []byte {
	var combined []byte
	for _, c := range commitments {
		combined = append(combined, c.Bytes()...)
	}
	return combined
}

// PrintCommitment prints a commitment value.
func PrintCommitment(name string, c *big.Int) {
	fmt.Printf("%s Commitment: %s\n", name, c.String())
}

// PrintScalar prints a scalar value.
func PrintScalar(name string, s *big.Int) {
	fmt.Printf("%s Scalar: %s\n", name, s.String())
}

func main() {
	fmt.Println("Starting Zero-Knowledge Proof for Secure Aggregation of Sensor Readings")
	start := time.Now()

	// 1. System Setup
	params := GenerateSystemParams()

	// 2. Sensor Readings (Private to each sensor/prover)
	numSensors := 5
	sensorValues := []*big.Int{NewBigInt(10), NewBigInt(25), NewBigInt(15), NewBigInt(30), NewBigInt(20)}
	if len(sensorValues) != numSensors {
		panic("Mismatch between numSensors and sensorValues count")
	}

	fmt.Printf("\n--- Prover Side (Sensors & Aggregator) ---\n")

	// 3. Each Sensor Commits to its Data (Prover part 1)
	var allSensorReadings []*SensorReading
	var C_d_vals []*big.Int // Public commitments to be shared
	var r_d_vals []*big.Int  // Private randomness for each sensor
	for i := 0; i < numSensors; i++ {
		sensorReading, err := SensorProverCommitData(params, sensorValues[i])
		if err != nil {
			fmt.Printf("Error committing data for sensor %d: %v\n", i+1, err)
			return
		}
		allSensorReadings = append(allSensorReadings, sensorReading)
		C_d_vals = append(C_d_vals, sensorReading.Commitment)
		r_d_vals = append(r_d_vals, sensorReading.Randomness)
		fmt.Printf("Sensor %d (Value: %s) committed. Commitment: %s\n", i+1, sensorReading.Value.String(), sensorReading.Commitment.String())
	}

	// 4. Aggregator Computes Aggregate Data and Commits (Prover part 2)
	aggData, aggCommits, err := AggregatorProverComputeAndCommit(params, allSensorReadings, numSensors)
	if err != nil {
		fmt.Printf("Error aggregating data: %v\n", err)
		return
	}
	fmt.Printf("\nAggregator calculated Sum: %s, Avg: %s\n", aggData.SumD.String(), aggData.Avg.String())
	PrintCommitment("Aggregator Sum D", aggCommits.CSumD)
	PrintCommitment("Aggregator Avg", aggCommits.CAvg)

	// Verify aggregator's own commitments (for internal consistency check, not part of ZKP)
	if !VerifyPedersenCommit(aggCommits.CSumD, aggData.SumD, aggData.RandomnessSum, params.G, params.H, params.P) {
		fmt.Println("Aggregator's SumD commitment is invalid!")
		return
	}
	if !VerifyPedersenCommit(aggCommits.CAvg, aggData.Avg, aggData.RandomnessAvg, params.G, params.H, params.P) {
		fmt.Println("Aggregator's Avg commitment is invalid!")
		return
	}

	// 5. Generate Common Challenge for Proofs (Fiat-Shamir)
	// The challenge is generated from all public commitments (C_d_vals, C_SumD, C_Avg)
	allPublicCommitments := make([]*big.Int, 0, numSensors+2)
	allPublicCommitments = append(allPublicCommitments, C_d_vals...)
	allPublicCommitments = append(allPublicCommitments, aggCommits.CSumD, aggCommits.CAvg)
	commonChallenge := GenerateCommonChallenge(params, allPublicCommitments...)
	PrintScalar("Common Challenge", commonChallenge)

	// 6. Aggregator Generates ZKP (Prover part 3)
	s_sum, T_sum, err := ProverGenerateSumProof(params, C_d_vals, aggCommits.CSumD, r_d_vals, aggData.RandomnessSum, commonChallenge)
	if err != nil {
		fmt.Printf("Error generating sum proof: %v\n", err)
		return
	}
	s_avg, T_avg, err := ProverGenerateAverageProof(params, aggCommits.CSumD, aggCommits.CAvg, numSensors, aggData.RandomnessSum, aggData.RandomnessAvg, commonChallenge)
	if err != nil {
		fmt.Printf("Error generating average proof: %v\n", err)
		return
	}

	proof := &AggregationProof{
		Challenge: commonChallenge,
		SSum:      s_sum,
		TSum:      T_sum,
		SAvg:      s_avg,
		TAvg:      T_avg,
	}

	fmt.Printf("\n--- Verifier Side ---\n")

	// 7. Verifier Verifies the Proofs
	fmt.Println("Verifier received public commitments and the proof.")

	// Verify Sum Proof
	isSumValid := VerifierVerifySumProof(params, C_d_vals, aggCommits.CSumD, proof.SSum, proof.TSum, proof.Challenge)
	if isSumValid {
		fmt.Println("Sum proof is VALID!")
	} else {
		fmt.Println("Sum proof is INVALID!")
	}

	// Verify Average Proof
	isAvgValid := VerifierVerifyAverageProof(params, aggCommits.CSumD, aggCommits.CAvg, numSensors, proof.SAvg, proof.TAvg, proof.Challenge)
	if isAvgValid {
		fmt.Println("Average proof is VALID!")
	} else {
		fmt.Println("Average proof is INVALID!")
	}

	fmt.Printf("\n--- ZKP Result ---\n")
	if isSumValid && isAvgValid {
		fmt.Println("All proofs are valid! The aggregator correctly calculated the sum and average without revealing individual sensor data.")
	} else {
		fmt.Println("One or more proofs failed. The aggregation might be incorrect or tampered with.")
	}

	elapsed := time.Since(start)
	fmt.Printf("\nTotal execution time: %s\n", elapsed)
}

```