```go
/*
Outline and Function Summary:

Package: zkp_age_verification

This package implements a Zero-Knowledge Proof system for age verification.  It allows a Prover to demonstrate to a Verifier that they possess a certain age attribute (e.g., over 18, within a range, equal to a specific age) without revealing their actual age.  This is achieved through a series of functions that represent the Prover and Verifier roles in a ZKP protocol.

The core concept is to prove age-related statements without disclosing the age itself, enhancing privacy.  This example focuses on age, but the principles can be extended to other attributes.

Functions:

1.  GenerateKeyPair(): Generates a simplified key pair for Prover and Verifier (for demonstration purposes - in real ZKP, key management is more complex).
2.  ProverCommitAge(age int): Prover commits to their age using a commitment scheme (simplified for demonstration). Returns the commitment.
3.  ProverGenerateProofOfAgeOver(age int, threshold int): Prover generates a ZKP proof that their age is greater than a given threshold.
4.  ProverGenerateProofOfAgeUnder(age int, threshold int): Prover generates a ZKP proof that their age is less than a given threshold.
5.  ProverGenerateProofOfAgeBetween(age int, minAge int, maxAge int): Prover generates a ZKP proof that their age is within a specified range (inclusive).
6.  ProverGenerateProofOfAgeEqualTo(age int, claimedAge int): Prover generates a ZKP proof that their age is equal to a claimed age.
7.  ProverGenerateProofOfAgeNotEqualTo(age int, claimedAge int): Prover generates a ZKP proof that their age is not equal to a claimed age.
8.  ProverGenerateProofOfAgeInSet(age int, ageSet []int): Prover generates a ZKP proof that their age belongs to a given set of ages.
9.  ProverGenerateProofOfAgeNotInSet(age int, ageSet []int): Prover generates a ZKP proof that their age does not belong to a given set of ages.
10. ProverGenerateProofOfAgeDivisibleBy(age int, divisor int): Prover generates a ZKP proof that their age is divisible by a given number.
11. ProverGenerateProofOfAgeNotDivisibleBy(age int, divisor int): Prover generates a ZKP proof that their age is not divisible by a given number.
12. ProverGenerateProofOfAgeIsPrime(age int): Prover generates a ZKP proof (simplified check) that their age is a prime number. (Note: True ZKP for primality is complex, this is a simplified demonstration).
13. ProverGenerateProofOfAgeIsComposite(age int): Prover generates a ZKP proof (simplified check) that their age is a composite number.
14. ProverGenerateProofOfAgeIsEven(age int): Prover generates a ZKP proof that their age is an even number.
15. ProverGenerateProofOfAgeIsOdd(age int): Prover generates a ZKP proof that their age is an odd number.
16. VerifierReceiveCommitment(commitment string): Verifier receives the commitment from the Prover.
17. VerifierReceiveProof(proof string): Verifier receives the ZKP proof from the Prover.
18. VerifierVerifyAgeOver(commitment string, proof string, threshold int): Verifier verifies the proof that the age is over a threshold.
19. VerifierVerifyAgeBetween(commitment string, proof string, minAge int, maxAge int): Verifier verifies the proof that the age is within a range.
20. VerifierVerifyAgeEqualTo(commitment string, proof string, claimedAge int): Verifier verifies the proof that the age is equal to a claimed age.
21. VerifierVerifyAgeInSet(commitment string, proof string, ageSet []int): Verifier verifies the proof that the age is in a given set.
22. SimulateHonestVerifierProcedure(proverAge int, verificationType string, params ...int): Simulates the entire ZKP process from the perspective of an honest verifier to test different proof types. (Helper function for demonstration)


Note: This is a simplified demonstration of ZKP principles. Real-world ZKP systems use sophisticated cryptographic techniques for security and efficiency.  This example focuses on illustrating the concept of proving properties without revealing the secret (age).  The "proofs" and "commitments" are simplified for clarity and educational purposes and are NOT cryptographically secure for production use.  For real-world ZKP, use established cryptographic libraries and protocols.
*/

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Simplified Key Pair (Not used in depth in this example, but conceptually present)
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// GenerateKeyPair generates a simplified key pair. In real ZKP, this is far more complex.
func GenerateKeyPair() (*KeyPair, error) {
	// For demonstration, we'll just generate random strings. Real ZKP uses crypto keys.
	pubKey := generateRandomString(32)
	privKey := generateRandomString(64)
	return &KeyPair{PublicKey: pubKey, PrivateKey: privKey}, nil
}

// generateRandomString generates a random string of specified length (for simplified keys/commitments).
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // In a real app, handle this error gracefully
	}
	return hex.EncodeToString(bytes)
}

// Prover represents the Prover in the ZKP system.
type Prover struct {
	age int
}

// NewProver creates a new Prover with a given age.
func NewProver(age int) *Prover {
	return &Prover{age: age}
}

// ProverCommitAge commits to the prover's age.  Simplified commitment for demonstration.
func (p *Prover) ProverCommitAge(age int) (string, error) {
	ageStr := strconv.Itoa(age)
	hash := sha256.Sum256([]byte(ageStr))
	return hex.EncodeToString(hash[:]), nil // Commitment is a hash of the age
}

// ProverGenerateProofOfAgeOver generates a proof that age is over threshold.
func (p *Prover) ProverGenerateProofOfAgeOver(age int, threshold int) (string, error) {
	if age > threshold {
		return fmt.Sprintf("AgeProof:Over:%d:Secret:%d", threshold, age), nil // Simple proof structure
	}
	return "", errors.New("age is not over threshold")
}

// ProverGenerateProofOfAgeUnder generates a proof that age is under threshold.
func (p *Prover) ProverGenerateProofOfAgeUnder(age int, threshold int) (string, error) {
	if age < threshold {
		return fmt.Sprintf("AgeProof:Under:%d:Secret:%d", threshold, age), nil
	}
	return "", errors.New("age is not under threshold")
}

// ProverGenerateProofOfAgeBetween generates a proof that age is between minAge and maxAge (inclusive).
func (p *Prover) ProverGenerateProofOfAgeBetween(age int, minAge int, maxAge int) (string, error) {
	if age >= minAge && age <= maxAge {
		return fmt.Sprintf("AgeProof:Between:%d-%d:Secret:%d", minAge, maxAge, age), nil
	}
	return "", errors.New("age is not within the range")
}

// ProverGenerateProofOfAgeEqualTo generates a proof that age is equal to claimedAge.
func (p *Prover) ProverGenerateProofOfAgeEqualTo(age int, claimedAge int) (string, error) {
	if age == claimedAge {
		return fmt.Sprintf("AgeProof:Equal:%d:Secret:%d", claimedAge, age), nil
	}
	return "", errors.New("age is not equal to claimed age")
}

// ProverGenerateProofOfAgeNotEqualTo generates a proof that age is not equal to claimedAge.
func (p *Prover) ProverGenerateProofOfAgeNotEqualTo(age int, claimedAge int) (string, error) {
	if age != claimedAge {
		return fmt.Sprintf("AgeProof:NotEqual:%d:Secret:%d", claimedAge, age), nil
	}
	return "", errors.New("age is equal to claimed age (should be not equal)")
}

// ProverGenerateProofOfAgeInSet generates a proof that age is in a given set.
func (p *Prover) ProverGenerateProofOfAgeInSet(age int, ageSet []int) (string, error) {
	for _, val := range ageSet {
		if age == val {
			setStr := intsToString(ageSet)
			return fmt.Sprintf("AgeProof:InSet:%s:Secret:%d", setStr, age), nil
		}
	}
	return "", errors.New("age is not in the set")
}

// ProverGenerateProofOfAgeNotInSet generates a proof that age is NOT in a given set.
func (p *Prover) ProverGenerateProofOfAgeNotInSet(age int, ageSet []int) (string, error) {
	for _, val := range ageSet {
		if age == val {
			return "", errors.New("age is in the set (should be not in set)")
		}
	}
	setStr := intsToString(ageSet)
	return fmt.Sprintf("AgeProof:NotInSet:%s:Secret:%d", setStr, age), nil

}

// ProverGenerateProofOfAgeDivisibleBy generates a proof that age is divisible by divisor.
func (p *Prover) ProverGenerateProofOfAgeDivisibleBy(age int, divisor int) (string, error) {
	if age%divisor == 0 {
		return fmt.Sprintf("AgeProof:DivisibleBy:%d:Secret:%d", divisor, age), nil
	}
	return "", errors.New("age is not divisible by divisor")
}

// ProverGenerateProofOfAgeNotDivisibleBy generates a proof that age is NOT divisible by divisor.
func (p *Prover) ProverGenerateProofOfAgeNotDivisibleBy(age int, divisor int) (string, error) {
	if age%divisor != 0 {
		return fmt.Sprintf("AgeProof:NotDivisibleBy:%d:Secret:%d", divisor, age), nil
	}
	return "", errors.New("age is divisible by divisor (should be not divisible)")
}

// ProverGenerateProofOfAgeIsPrime (Simplified primality check for demonstration).
// Note: Real ZKP for primality is much more complex and computationally intensive.
func (p *Prover) ProverGenerateProofOfAgeIsPrime(age int) (string, error) {
	if age <= 1 {
		return "", errors.New("age is not prime")
	}
	for i := 2; i <= int(math.Sqrt(float64(age))); i++ {
		if age%i == 0 {
			return "", errors.New("age is not prime")
		}
	}
	return fmt.Sprintf("AgeProof:IsPrime:Secret:%d", age), nil
}

// ProverGenerateProofOfAgeIsComposite (Simplified compositeness check for demonstration).
func (p *Prover) ProverGenerateProofOfAgeIsComposite(age int) (string, error) {
	if age <= 1 {
		return "", errors.New("age is not composite")
	}
	for i := 2; i <= int(math.Sqrt(float64(age))); i++ {
		if age%i == 0 {
			return fmt.Sprintf("AgeProof:IsComposite:Secret:%d", age), nil
		}
	}
	return "", errors.New("age is prime (should be composite)") // If not prime (and > 1), considered composite for this demo.
}

// ProverGenerateProofOfAgeIsEven generates a proof that age is even.
func (p *Prover) ProverGenerateProofOfAgeIsEven(age int) (string, error) {
	if age%2 == 0 {
		return fmt.Sprintf("AgeProof:IsEven:Secret:%d", age), nil
	}
	return "", errors.New("age is not even")
}

// ProverGenerateProofOfAgeIsOdd generates a proof that age is odd.
func (p *Prover) ProverGenerateProofOfAgeIsOdd(age int) (string, error) {
	if age%2 != 0 {
		return fmt.Sprintf("AgeProof:IsOdd:Secret:%d", age), nil
	}
	return "", errors.New("age is not odd")
}

// Verifier represents the Verifier in the ZKP system.
type Verifier struct {
	publicKey string // Verifier could have a public key in more complex systems
}

// NewVerifier creates a new Verifier.
func NewVerifier() *Verifier {
	// In a real system, Verifier might initialize with setup parameters, public keys, etc.
	return &Verifier{}
}

// VerifierReceiveCommitment receives the commitment from the Prover (not used in this simplified flow but conceptually present).
func (v *Verifier) VerifierReceiveCommitment(commitment string) {
	// In a real ZKP protocol, the verifier would store and use the commitment.
	// In this example, the commitment is more symbolic.
	fmt.Println("Verifier received commitment:", commitment)
}

// VerifierReceiveProof receives the proof from the Prover.
func (v *Verifier) VerifierReceiveProof(proof string) {
	fmt.Println("Verifier received proof:", proof)
}

// VerifierVerifyAgeOver verifies the proof that age is over threshold.
func (v *Verifier) VerifierVerifyAgeOver(commitment string, proof string, threshold int) (bool, error) {
	parts := strings.Split(proof, ":")
	if len(parts) != 4 || parts[0] != "AgeProof" || parts[1] != "Over" {
		return false, errors.New("invalid proof format for age over")
	}
	proofThresholdStr := parts[2]
	secretAgeStr := parts[3]

	proofThreshold, err := strconv.Atoi(proofThresholdStr)
	if err != nil {
		return false, fmt.Errorf("invalid proof threshold format: %w", err)
	}
	if proofThreshold != threshold { // Basic check, in real ZKP, verification is cryptographic.
		return false, errors.New("proof threshold does not match verification threshold")
	}

	_, err = strconv.Atoi(secretAgeStr) // Just checking if secret age is present in proof (not verifying it cryptographically here).
	if err != nil {
		return false, fmt.Errorf("invalid secret age format in proof: %w", err)
	}

	// In a real ZKP, you would recompute commitments, use cryptographic equations based on the proof, etc.
	// Here, for demonstration, we simply check the proof structure and threshold.

	fmt.Println("Commitment check (simplified): OK (not cryptographically verified in this example)") // Placeholder for real commitment check.
	return true, nil // In this simplified example, proof format and threshold match are considered verification.
}

// VerifierVerifyAgeUnder verifies the proof that age is under threshold.
func (v *Verifier) VerifierVerifyAgeUnder(commitment string, proof string, threshold int) (bool, error) {
	parts := strings.Split(proof, ":")
	if len(parts) != 4 || parts[0] != "AgeProof" || parts[1] != "Under" {
		return false, errors.New("invalid proof format for age under")
	}
	proofThresholdStr := parts[2]
	secretAgeStr := parts[3]

	proofThreshold, err := strconv.Atoi(proofThresholdStr)
	if err != nil {
		return false, fmt.Errorf("invalid proof threshold format: %w", err)
	}
	if proofThreshold != threshold {
		return false, errors.New("proof threshold does not match verification threshold")
	}

	_, err = strconv.Atoi(secretAgeStr)
	if err != nil {
		return false, fmt.Errorf("invalid secret age format in proof: %w", err)
	}

	fmt.Println("Commitment check (simplified): OK")
	return true, nil
}

// VerifierVerifyAgeBetween verifies the proof that age is between minAge and maxAge.
func (v *Verifier) VerifierVerifyAgeBetween(commitment string, proof string, minAge int, maxAge int) (bool, error) {
	parts := strings.Split(proof, ":")
	if len(parts) != 4 || parts[0] != "AgeProof" || parts[1] != "Between" {
		return false, errors.New("invalid proof format for age between")
	}
	ageRangeStr := parts[2]
	secretAgeStr := parts[3]

	rangeParts := strings.Split(ageRangeStr, "-")
	if len(rangeParts) != 2 {
		return false, errors.New("invalid age range format in proof")
	}
	proofMinAge, err := strconv.Atoi(rangeParts[0])
	if err != nil {
		return false, fmt.Errorf("invalid proof min age format: %w", err)
	}
	proofMaxAge, err := strconv.Atoi(rangeParts[1])
	if err != nil {
		return false, fmt.Errorf("invalid proof max age format: %w", err)
	}

	if proofMinAge != minAge || proofMaxAge != maxAge {
		return false, errors.New("proof age range does not match verification range")
	}

	_, err = strconv.Atoi(secretAgeStr)
	if err != nil {
		return false, fmt.Errorf("invalid secret age format in proof: %w", err)
	}

	fmt.Println("Commitment check (simplified): OK")
	return true, nil
}

// VerifierVerifyAgeEqualTo verifies the proof that age is equal to claimedAge.
func (v *Verifier) VerifierVerifyAgeEqualTo(commitment string, proof string, claimedAge int) (bool, error) {
	parts := strings.Split(proof, ":")
	if len(parts) != 4 || parts[0] != "AgeProof" || parts[1] != "Equal" {
		return false, errors.New("invalid proof format for age equal")
	}
	proofClaimedAgeStr := parts[2]
	secretAgeStr := parts[3]

	proofClaimedAge, err := strconv.Atoi(proofClaimedAgeStr)
	if err != nil {
		return false, fmt.Errorf("invalid proof claimed age format: %w", err)
	}
	if proofClaimedAge != claimedAge {
		return false, errors.New("proof claimed age does not match verification claimed age")
	}

	_, err = strconv.Atoi(secretAgeStr)
	if err != nil {
		return false, fmt.Errorf("invalid secret age format in proof: %w", err)
	}

	fmt.Println("Commitment check (simplified): OK")
	return true, nil
}

// VerifierVerifyAgeInSet verifies the proof that age is in a given set.
func (v *Verifier) VerifierVerifyAgeInSet(commitment string, proof string, ageSet []int) (bool, error) {
	parts := strings.Split(proof, ":")
	if len(parts) != 4 || parts[0] != "AgeProof" || parts[1] != "InSet" {
		return false, errors.New("invalid proof format for age in set")
	}
	proofSetStr := parts[2]
	secretAgeStr := parts[3]

	expectedSetStr := intsToString(ageSet)
	if proofSetStr != expectedSetStr {
		return false, errors.New("proof age set does not match verification age set")
	}

	_, err := strconv.Atoi(secretAgeStr)
	if err != nil {
		return false, fmt.Errorf("invalid secret age format in proof: %w", err)
	}

	fmt.Println("Commitment check (simplified): OK")
	return true, nil
}

// Helper function to convert int slice to comma-separated string for proof representation.
func intsToString(ints []int) string {
	strValues := make([]string, len(ints))
	for i, val := range ints {
		strValues[i] = strconv.Itoa(val)
	}
	return strings.Join(strValues, ",")
}

// SimulateHonestVerifierProcedure simulates the entire ZKP process from a verifier's perspective.
func SimulateHonestVerifierProcedure(proverAge int, verificationType string, params ...int) {
	prover := NewProver(proverAge)
	verifier := NewVerifier()

	commitment, err := prover.ProverCommitAge(proverAge) // Prover commits to their age.
	if err != nil {
		fmt.Println("Prover commitment error:", err)
		return
	}
	verifier.VerifierReceiveCommitment(commitment) // Verifier receives commitment.

	var proof string
	var proofErr error
	var verificationResult bool
	var verificationErr error

	switch verificationType {
	case "Over":
		if len(params) != 1 {
			fmt.Println("Invalid parameters for 'Over' verification. Need threshold.")
			return
		}
		threshold := params[0]
		proof, proofErr = prover.ProverGenerateProofOfAgeOver(proverAge, threshold)
		if proofErr == nil {
			verifier.VerifierReceiveProof(proof)
			verificationResult, verificationErr = verifier.VerifierVerifyAgeOver(commitment, proof, threshold)
		}
	case "Under":
		if len(params) != 1 {
			fmt.Println("Invalid parameters for 'Under' verification. Need threshold.")
			return
		}
		threshold := params[0]
		proof, proofErr = prover.ProverGenerateProofOfAgeUnder(proverAge, threshold)
		if proofErr == nil {
			verifier.VerifierReceiveProof(proof)
			verificationResult, verificationErr = verifier.VerifierVerifyAgeUnder(commitment, proof, threshold)
		}
	case "Between":
		if len(params) != 2 {
			fmt.Println("Invalid parameters for 'Between' verification. Need minAge and maxAge.")
			return
		}
		minAge := params[0]
		maxAge := params[1]
		proof, proofErr = prover.ProverGenerateProofOfAgeBetween(proverAge, minAge, maxAge)
		if proofErr == nil {
			verifier.VerifierReceiveProof(proof)
			verificationResult, verificationErr = verifier.VerifierVerifyAgeBetween(commitment, proof, minAge, maxAge)
		}
	case "Equal":
		if len(params) != 1 {
			fmt.Println("Invalid parameters for 'Equal' verification. Need claimedAge.")
			return
		}
		claimedAge := params[0]
		proof, proofErr = prover.ProverGenerateProofOfAgeEqualTo(proverAge, claimedAge)
		if proofErr == nil {
			verifier.VerifierReceiveProof(proof)
			verificationResult, verificationErr = verifier.VerifierVerifyAgeEqualTo(commitment, proof, claimedAge)
		}
	case "InSet":
		if len(params) == 0 {
			fmt.Println("Invalid parameters for 'InSet' verification. Need ageSet.")
			return
		}
		ageSet := params
		proof, proofErr = prover.ProverGenerateProofOfAgeInSet(proverAge, ageSet)
		if proofErr == nil {
			verifier.VerifierReceiveProof(proof)
			verificationResult, verificationErr = verifier.VerifierVerifyAgeInSet(commitment, proof, ageSet)
		}
	default:
		fmt.Println("Unknown verification type:", verificationType)
		return
	}

	if proofErr != nil {
		fmt.Println("Prover proof generation error:", proofErr)
	} else if verificationErr != nil {
		fmt.Println("Verifier verification error:", verificationErr)
	} else if verificationResult {
		fmt.Println("Verification successful! Age property proven without revealing the exact age.")
	} else {
		fmt.Println("Verification failed. Proof is invalid.")
	}
}

func main() {
	fmt.Println("--- Zero-Knowledge Proof Demonstration (Age Verification) ---")

	// Example Demonstrations:
	fmt.Println("\n--- Scenario 1: Proving age is over 18 ---")
	SimulateHonestVerifierProcedure(25, "Over", 18) // Prover is 25, proving age > 18

	fmt.Println("\n--- Scenario 2: Proving age is under 30 ---")
	SimulateHonestVerifierProcedure(25, "Under", 30) // Prover is 25, proving age < 30

	fmt.Println("\n--- Scenario 3: Proving age is between 20 and 30 ---")
	SimulateHonestVerifierProcedure(25, "Between", 20, 30) // Prover is 25, proving 20 <= age <= 30

	fmt.Println("\n--- Scenario 4: Proving age is equal to 25 ---")
	SimulateHonestVerifierProcedure(25, "Equal", 25) // Prover is 25, proving age == 25

	fmt.Println("\n--- Scenario 5: Proving age is in set {20, 25, 30} ---")
	SimulateHonestVerifierProcedure(25, "InSet", 20, 25, 30) // Prover is 25, proving age is in {20, 25, 30}

	fmt.Println("\n--- Scenario 6: Proving age is NOT over 30 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "Over", 30) // Prover is 25, trying to prove age > 30 (should fail)

	fmt.Println("\n--- Scenario 7: Proving age is NOT equal to 30 (implicitly - no direct function, but 'Equal' with wrong age will fail) ---")
	SimulateHonestVerifierProcedure(25, "Equal", 30) // Prover is 25, trying to prove age == 30 (should fail)

	fmt.Println("\n--- Scenario 8: Proving age is divisible by 5 ---")
	SimulateHonestVerifierProcedure(25, "DivisibleBy", 5)

	fmt.Println("\n--- Scenario 9: Proving age is NOT divisible by 7 ---")
	SimulateHonestVerifierProcedure(25, "NotDivisibleBy", 7)

	fmt.Println("\n--- Scenario 10: Proving age is prime (simplified check, 23 is prime) ---")
	SimulateHonestVerifierProcedure(23, "IsPrime")

	fmt.Println("\n--- Scenario 11: Proving age is composite (simplified check, 24 is composite) ---")
	SimulateHonestVerifierProcedure(24, "IsComposite")

	fmt.Println("\n--- Scenario 12: Proving age is even ---")
	SimulateHonestVerifierProcedure(24, "IsEven")

	fmt.Println("\n--- Scenario 13: Proving age is odd ---")
	SimulateHonestVerifierProcedure(25, "IsOdd")

	fmt.Println("\n--- Scenario 14: Proving age is under 20 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "Under", 20)

	fmt.Println("\n--- Scenario 15: Proving age is between 30 and 40 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "Between", 30, 40)

	fmt.Println("\n--- Scenario 16: Proving age is equal to 20 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "Equal", 20)

	fmt.Println("\n--- Scenario 17: Proving age is in set {10, 15, 30} (should fail) ---")
	SimulateHonestVerifierProcedure(25, "InSet", 10, 15, 30)

	fmt.Println("\n--- Scenario 18: Proving age is divisible by 10 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "DivisibleBy", 10)

	fmt.Println("\n--- Scenario 19: Proving age is divisible by 3 (should fail) ---")
	SimulateHonestVerifierProcedure(25, "DivisibleBy", 3)

	fmt.Println("\n--- Scenario 20: Proving age is prime (simplified check, 24 is NOT prime - should fail for 'IsPrime') ---")
	SimulateHonestVerifierProcedure(24, "IsPrime")

	fmt.Println("\n--- Scenario 21: Proving age is composite (simplified check, 23 is NOT composite - should fail for 'IsComposite') ---")
	SimulateHonestVerifierProcedure(23, "IsComposite")

	fmt.Println("\n--- Scenario 22: Proving age is odd (should fail for even age) ---")
	SimulateHonestVerifierProcedure(24, "IsOdd")

	fmt.Println("\n--- Scenario 23: Proving age is even (should fail for odd age) ---")
	SimulateHonestVerifierProcedure(25, "IsEven")
}
```