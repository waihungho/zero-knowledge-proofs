```go
/*
Outline and Function Summary:

Package zkproof demonstrates various Zero-Knowledge Proof (ZKP) concepts in Go.
This package provides a conceptual framework for advanced ZKP applications,
focusing on privacy-preserving operations and verifiable computations without revealing
underlying data.  It avoids direct duplication of existing open-source libraries and
aims for creative and trendy applications relevant in modern contexts like
decentralized finance, privacy-preserving machine learning, and secure data sharing.

**Core ZKP Functions (Primitives):**

1.  Commitment(data []byte) (commitment, opening []byte, error):
    - Prover commits to data without revealing it. Returns a commitment and an opening.

2.  VerifyCommitment(commitment, data, opening []byte) bool:
    - Verifier checks if the opening reveals the committed data for a given commitment.

3.  RangeProof(value int, min int, max int) (proof []byte, err):
    - Prover proves that a value is within a specified range [min, max] without revealing the value itself.

4.  VerifyRangeProof(proof []byte, min int, max int) bool:
    - Verifier checks if the range proof is valid, confirming the value is within the range.

5.  SetMembershipProof(value string, set []string) (proof []byte, err):
    - Prover proves that a value is a member of a predefined set without revealing the value or other set elements.

6.  VerifySetMembershipProof(proof []byte, set []string) bool:
    - Verifier checks if the set membership proof is valid, confirming the value belongs to the set.

7.  EqualityProof(commitment1, commitment2 []byte) (proof []byte, opening1, opening2 []byte, err):
    - Prover proves that two committed values are equal without revealing the values.

8.  VerifyEqualityProof(proof []byte, commitment1, commitment2 []byte, opening1, opening2 []byte) bool:
    - Verifier checks if the equality proof is valid, confirming the underlying values are equal.

9.  SumProof(commitments [][]byte, targetSum int) (proof []byte, openings [][]byte, err):
    - Prover proves that the sum of multiple committed values equals a target sum, without revealing individual values.

10. VerifySumProof(proof []byte, commitments [][]byte, targetSum int, openings [][]byte) bool:
    - Verifier checks if the sum proof is valid, confirming the sum of underlying values is the target.

**Advanced ZKP Applications (Built upon Primitives):**

11. PrivateDataComparisonProof(commitment1, commitment2 []byte, threshold int) (proof []byte, opening1, opening2 []byte, err):
    - Prover proves that the value behind commitment1 is greater than the value behind commitment2 by at least a certain threshold, without revealing the actual values.

12. VerifyPrivateDataComparisonProof(proof []byte, commitment1, commitment2 []byte, threshold int, opening1, opening2 []byte) bool:
    - Verifier checks if the private data comparison proof is valid.

13. PrivateDataAggregationProof(commitments [][]byte, aggregationFunction string, expectedResult interface{}) (proof []byte, openings [][]byte, err):
    - Prover proves that applying a specific aggregation function (e.g., average, median) to committed values results in the expected result, without revealing individual values.

14. VerifyPrivateDataAggregationProof(proof []byte, commitments [][]byte, aggregationFunction string, expectedResult interface{}, openings [][]byte) bool:
    - Verifier checks if the private data aggregation proof is valid.

15. VerifiableMachineLearningInferenceProof(modelCommitment []byte, inputCommitment []byte, expectedOutputCommitment []byte) (proof []byte, modelOpening, inputOpening, outputOpening []byte, err):
    - Prover proves that a machine learning model (committed) applied to a committed input produces a specific committed output, without revealing the model, input, or output directly (proof of correct inference).

16. VerifyVerifiableMachineLearningInferenceProof(proof []byte, modelCommitment []byte, inputCommitment []byte, expectedOutputCommitment []byte, modelOpening, inputOpening, outputOpening []byte) bool:
    - Verifier checks if the verifiable ML inference proof is valid.

17. AnonymousCredentialVerificationProof(credentialCommitment []byte, attributeName string, attributeValue string) (proof []byte, credentialOpening []byte, err):
    - Prover proves they possess a credential (committed) containing a specific attribute name and value, without revealing the entire credential or other attributes.

18. VerifyAnonymousCredentialVerificationProof(proof []byte, credentialCommitment []byte, attributeName string, attributeValue string, credentialOpening []byte) bool:
    - Verifier checks if the anonymous credential verification proof is valid.

19. FairRandomnessVerificationProof(randomnessCommitment []byte, seedOpening []byte, expectedOutput string) (proof []byte, err):
    - Prover proves that a committed randomness source, when opened with a seed, generates a specific expected output (e.g., a verifiable lottery or game outcome).

20. VerifyFairRandomnessVerificationProof(proof []byte, randomnessCommitment []byte, expectedOutput string) bool:
    - Verifier checks if the fair randomness verification proof is valid.

**Helper Functions (Illustrative):**

21. HashData(data []byte) []byte:
    -  A simple placeholder for a cryptographic hash function.

22. GenerateRandomBytes(n int) ([]byte, error):
    - A placeholder for generating random bytes, crucial for ZKP.

**Important Notes:**

- This code provides conceptual outlines and simplified structures for demonstrating ZKP ideas.
- The actual ZKP logic (commented with `// ... ZKP logic here ...`) is intentionally left unimplemented.
- For real-world ZKP implementations, robust cryptographic libraries and established ZKP protocols (like Schnorr, Pedersen, Bulletproofs, zk-SNARKs, zk-STARKs) would be necessary.
- Error handling and security considerations are simplified for clarity in this illustrative example.
- The function signatures and data types are chosen to be illustrative and can be adapted based on specific ZKP schemes.
*/
package zkproof

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// --- Core ZKP Functions (Primitives) ---

// Commitment creates a commitment to data.
func Commitment(data []byte) (commitment, opening []byte, err error) {
	// In a real ZKP scheme, this would involve cryptographic operations
	// like hashing, encryption, or using specific commitment schemes (e.g., Pedersen commitment).
	opening = make([]byte, len(data))
	copy(opening, data) // Placeholder: Opening is the data itself.

	commitment = HashData(data) // Placeholder: Commitment is a hash of the data.

	return commitment, opening, nil
}

// VerifyCommitment verifies if the opening reveals the committed data.
func VerifyCommitment(commitment, data, opening []byte) bool {
	// In a real ZKP scheme, this would involve reversing the commitment process
	// using the opening and verifying it against the original commitment.

	verifiedCommitment := HashData(opening) // Placeholder: Re-hash the opening (which is the data in this example).
	return string(commitment) == string(verifiedCommitment) && string(data) == string(opening) // Check if re-hashed opening matches the commitment and opening matches data.
}

// RangeProof creates a proof that a value is within a specified range.
func RangeProof(value int, min int, max int) (proof []byte, err error) {
	if value < min || value > max {
		return nil, errors.New("value is not within the specified range")
	}
	// ... ZKP logic here to create a range proof ...
	// In a real ZKP scheme, this would involve cryptographic protocols
	// like Bulletproofs or using range proof constructions based on other primitives.
	proof = []byte(fmt.Sprintf("RangeProof for value in [%d, %d]", min, max)) // Placeholder proof.
	return proof, nil
}

// VerifyRangeProof verifies if the range proof is valid.
func VerifyRangeProof(proof []byte, min int, max int) bool {
	// ... ZKP logic here to verify the range proof ...
	// In a real ZKP scheme, this would involve cryptographic verification
	// based on the specific range proof protocol used.
	// For this placeholder, we simply check the proof message.
	expectedProof := fmt.Sprintf("RangeProof for value in [%d, %d]", min, max)
	return string(proof) == expectedProof // Placeholder verification.
}

// SetMembershipProof creates a proof that a value is in a set.
func SetMembershipProof(value string, set []string) (proof []byte, err error) {
	found := false
	for _, element := range set {
		if element == value {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("value is not in the set")
	}
	// ... ZKP logic here to create a set membership proof ...
	// In a real ZKP scheme, this could involve Merkle trees, polynomial commitments,
	// or other set membership proof constructions.
	proof = []byte(fmt.Sprintf("SetMembershipProof for value in set")) // Placeholder proof.
	return proof, nil
}

// VerifySetMembershipProof verifies if the set membership proof is valid.
func VerifySetMembershipProof(proof []byte, set []string) bool {
	// ... ZKP logic here to verify the set membership proof ...
	// In a real ZKP scheme, this would involve cryptographic verification.
	expectedProof := fmt.Sprintf("SetMembershipProof for value in set")
	return string(proof) == expectedProof // Placeholder verification.
}

// EqualityProof proves that two committed values are equal.
func EqualityProof(commitment1, commitment2 []byte) (proof []byte, opening1, opening2 []byte, err error) {
	// For simplicity, assume commitments are based on the same data.
	// In a real scenario, you'd need to relate openings to commitments and then prove equality.
	opening1 = make([]byte, len(commitment1))
	copy(opening1, commitment1) // Placeholder opening.
	opening2 = make([]byte, len(commitment2))
	copy(opening2, commitment2) // Placeholder opening.

	if string(commitment1) != string(commitment2) { // In a real scenario, we wouldn't know the underlying values to compare directly.
		return nil, nil, nil, errors.New("commitments are not equal (based on placeholder comparison)")
	}

	// ... ZKP logic here to create an equality proof ...
	// In a real ZKP scheme, this would involve cryptographic protocols to prove
	// equality of the values behind the commitments without revealing them.
	proof = []byte("EqualityProof for commitments") // Placeholder proof.
	return proof, opening1, opening2, nil
}

// VerifyEqualityProof verifies if the equality proof is valid.
func VerifyEqualityProof(proof []byte, commitment1, commitment2 []byte, opening1, opening2 []byte) bool {
	// ... ZKP logic here to verify the equality proof ...
	// In a real ZKP scheme, this would involve cryptographic verification.
	expectedProof := "EqualityProof for commitments"
	return string(proof) == expectedProof && VerifyCommitment(commitment1, opening1, opening1) && VerifyCommitment(commitment2, opening2, opening2) // Placeholder verification + commitment verification.
}

// SumProof proves that the sum of committed values equals a target sum.
func SumProof(commitments [][]byte, targetSum int) (proof []byte, openings [][]byte, err error) {
	openings = make([][]byte, len(commitments))
	actualSum := 0
	for i, commitment := range commitments {
		// Placeholder: Assume commitments represent integer values as strings.
		var val int
		_, err := fmt.Sscan(string(commitment), &val) // Try to parse commitment as int string (placeholder).
		if err != nil {
			return nil, nil, fmt.Errorf("invalid commitment format (not integer string): %w", err)
		}
		actualSum += val
		openings[i] = commitment // Placeholder opening (commitment itself).
	}

	if actualSum != targetSum { // In a real scenario, we wouldn't directly sum the commitments.
		return nil, nil, errors.New("sum of commitments does not match target sum (based on placeholder)")
	}

	// ... ZKP logic here to create a sum proof ...
	// In a real ZKP scheme, this would involve cryptographic protocols to prove
	// the sum of the values behind commitments without revealing them individually.
	proof = []byte(fmt.Sprintf("SumProof for target sum: %d", targetSum)) // Placeholder proof.
	return proof, openings, nil
}

// VerifySumProof verifies if the sum proof is valid.
func VerifySumProof(proof []byte, commitments [][]byte, targetSum int, openings [][]byte) bool {
	// ... ZKP logic here to verify the sum proof ...
	// In a real ZKP scheme, this would involve cryptographic verification.
	expectedProof := fmt.Sprintf("SumProof for target sum: %d", targetSum)
	if string(proof) != expectedProof {
		return false
	}
	sumCheck := 0
	for i, commitment := range commitments {
		if !VerifyCommitment(commitment, openings[i], openings[i]) { // Verify individual commitments.
			return false
		}
		var val int
		_, err := fmt.Sscan(string(commitments[i]), &val)
		if err != nil {
			return false // Commitment format error during verification.
		}
		sumCheck += val
	}
	return sumCheck == targetSum // Placeholder verification + commitment verification.
}

// --- Advanced ZKP Applications ---

// PrivateDataComparisonProof proves commitment1 > commitment2 + threshold without revealing values.
func PrivateDataComparisonProof(commitment1, commitment2 []byte, threshold int) (proof []byte, opening1, opening2 []byte, err error) {
	var val1, val2 int
	_, err1 := fmt.Sscan(string(commitment1), &val1) // Placeholder: Commitments are integer strings.
	_, err2 := fmt.Sscan(string(commitment2), &val2)

	if err1 != nil || err2 != nil {
		return nil, nil, nil, errors.New("invalid commitment format (not integer string)")
	}

	if !(val1 > val2+threshold) { // In a real scenario, we wouldn't compare values directly.
		return nil, nil, nil, errors.New("condition not met (based on placeholder comparison)")
	}

	opening1 = commitment1 // Placeholder openings.
	opening2 = commitment2

	// ... ZKP logic here for private data comparison ...
	// In a real ZKP scheme, this would involve cryptographic protocols
	// to prove the comparison relation without revealing val1 and val2.
	proof = []byte(fmt.Sprintf("PrivateComparisonProof: commitment1 > commitment2 + %d", threshold)) // Placeholder proof.
	return proof, opening1, opening2, nil
}

// VerifyPrivateDataComparisonProof verifies the PrivateDataComparisonProof.
func VerifyPrivateDataComparisonProof(proof []byte, commitment1, commitment2 []byte, threshold int, opening1, opening2 []byte) bool {
	// ... ZKP logic here to verify private data comparison proof ...
	// In a real ZKP scheme, cryptographic verification.
	expectedProof := fmt.Sprintf("PrivateComparisonProof: commitment1 > commitment2 + %d", threshold)
	if string(proof) != expectedProof {
		return false
	}
	var val1, val2 int
	_, err1 := fmt.Sscan(string(commitment1), &val1)
	_, err2 := fmt.Sscan(string(commitment2), &val2)
	if err1 != nil || err2 != nil {
		return false // Commitment format error during verification.
	}

	return VerifyCommitment(commitment1, opening1, opening1) && VerifyCommitment(commitment2, opening2, opening2) && (val1 > val2+threshold) // Placeholder verification + commitment verification + direct comparison (for this placeholder).
}

// PrivateDataAggregationProof proves aggregation result on committed values.
func PrivateDataAggregationProof(commitments [][]byte, aggregationFunction string, expectedResult interface{}) (proof []byte, openings [][]byte, err error) {
	openings = make([][]byte, len(commitments))
	values := []int{}
	for i, commitment := range commitments {
		var val int
		_, err := fmt.Sscan(string(commitment), &val)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid commitment format (not integer string): %w", err)
		}
		values = append(values, val)
		openings[i] = commitment // Placeholder opening.
	}

	var actualResult interface{}
	switch aggregationFunction {
	case "sum":
		sum := 0
		for _, v := range values {
			sum += v
		}
		actualResult = sum
	case "average":
		if len(values) == 0 {
			actualResult = 0.0
		} else {
			sum := 0
			for _, v := range values {
				sum += v
			}
			actualResult = float64(sum) / float64(len(values))
		}
	default:
		return nil, nil, fmt.Errorf("unsupported aggregation function: %s", aggregationFunction)
	}

	if actualResult != expectedResult { // In a real scenario, we wouldn't directly compute.
		return nil, nil, errors.New("aggregation result does not match expected result (based on placeholder)")
	}

	// ... ZKP logic for private data aggregation ...
	// Cryptographic protocols to prove aggregation results without revealing individual values.
	proof = []byte(fmt.Sprintf("AggregationProof: %s = %v", aggregationFunction, expectedResult)) // Placeholder proof.
	return proof, openings, nil
}

// VerifyPrivateDataAggregationProof verifies the PrivateDataAggregationProof.
func VerifyPrivateDataAggregationProof(proof []byte, commitments [][]byte, aggregationFunction string, expectedResult interface{}, openings [][]byte) bool {
	// ... ZKP logic to verify private data aggregation proof ...
	// Cryptographic verification.
	expectedProof := fmt.Sprintf("AggregationProof: %s = %v", aggregationFunction, expectedResult)
	if string(proof) != expectedProof {
		return false
	}

	values := []int{}
	for i, commitment := range commitments {
		if !VerifyCommitment(commitment, openings[i], openings[i]) {
			return false
		}
		var val int
		_, err := fmt.Sscan(string(commitments[i]), &val)
		if err != nil {
			return false // Commitment format error during verification.
		}
		values = append(values, val)
	}

	var actualResult interface{}
	switch aggregationFunction {
	case "sum":
		sum := 0
		for _, v := range values {
			sum += v
		}
		actualResult = sum
	case "average":
		if len(values) == 0 {
			actualResult = 0.0
		} else {
			sum := 0
			for _, v := range values {
				sum += v
			}
			actualResult = float64(sum) / float64(len(values))
		}
	default:
		return false // Unsupported aggregation function in verification.
	}

	return actualResult == expectedResult // Placeholder verification + commitment verification + direct result comparison (for this placeholder).
}

// VerifiableMachineLearningInferenceProof proves correct ML inference.
func VerifiableMachineLearningInferenceProof(modelCommitment []byte, inputCommitment []byte, expectedOutputCommitment []byte) (proof []byte, modelOpening, inputOpening, outputOpening []byte, err error) {
	// Placeholder: Assume model is a function that adds input to a model parameter.
	modelParam := 5 // Example model parameter.
	var inputVal int
	_, err = fmt.Sscan(string(inputCommitment), &inputVal)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid input commitment format")
	}
	expectedOutputVal := inputVal + modelParam

	outputCommitment := []byte(fmt.Sprintf("%d", expectedOutputVal)) // Re-calculate expected output commitment.

	if string(outputCommitment) != string(expectedOutputCommitment) { // Check if recalculated output matches expected.
		return nil, nil, nil, nil, errors.New("inference output mismatch (based on placeholder model)")
	}

	modelOpening = modelCommitment // Placeholder openings
	inputOpening = inputCommitment
	outputOpening = outputCommitment

	// ... ZKP logic for verifiable ML inference ...
	// Cryptographic protocols to prove correct ML inference without revealing model/input/output.
	proof = []byte("VerifiableMLInferenceProof") // Placeholder proof.
	return proof, modelOpening, inputOpening, outputOpening, nil
}

// VerifyVerifiableMachineLearningInferenceProof verifies VerifiableMachineLearningInferenceProof.
func VerifyVerifiableMachineLearningInferenceProof(proof []byte, modelCommitment []byte, inputCommitment []byte, expectedOutputCommitment []byte, modelOpening, inputOpening, outputOpening []byte) bool {
	// ... ZKP logic to verify verifiable ML inference proof ...
	// Cryptographic verification.
	expectedProof := "VerifiableMLInferenceProof"
	if string(proof) != expectedProof {
		return false
	}

	if !VerifyCommitment(modelCommitment, modelOpening, modelOpening) || !VerifyCommitment(inputCommitment, inputOpening, inputOpening) || !VerifyCommitment(expectedOutputCommitment, outputOpening, outputOpening) {
		return false // Verify all commitments.
	}

	modelParam := 5 // Same example model parameter for verification.
	var inputVal int
	_, err := fmt.Sscan(string(inputCommitment), &inputVal)
	if err != nil {
		return false // Input commitment format error during verification.
	}
	expectedOutputVal := inputVal + modelParam
	outputCommitment := []byte(fmt.Sprintf("%d", expectedOutputVal))

	return string(outputCommitment) == string(expectedOutputCommitment) // Placeholder verification + commitment verification + direct inference check (for this placeholder).
}

// AnonymousCredentialVerificationProof proves possession of a credential attribute.
func AnonymousCredentialVerificationProof(credentialCommitment []byte, attributeName string, attributeValue string) (proof []byte, credentialOpening []byte, err error) {
	// Placeholder: Assume credential is a string like "name:Alice,age:30,country:USA".
	credential := string(credentialCommitment) // Placeholder credential.
	attributePairs := map[string]string{}
	pairs := stringSplit(credential, ",") // Simple split for attribute parsing.
	for _, pair := range pairs {
		parts := stringSplit(pair, ":")
		if len(parts) == 2 {
			attributePairs[parts[0]] = parts[1]
		}
	}

	if attributePairs[attributeName] != attributeValue { // Check if attribute exists and matches.
		return nil, nil, errors.New("credential does not contain the specified attribute and value (based on placeholder)")
	}

	credentialOpening = credentialCommitment // Placeholder opening.

	// ... ZKP logic for anonymous credential verification ...
	// Cryptographic protocols to prove attribute existence in a committed credential
	// without revealing the entire credential or other attributes.
	proof = []byte(fmt.Sprintf("AnonymousCredentialProof: %s=%s", attributeName, attributeValue)) // Placeholder proof.
	return proof, credentialOpening, nil
}

// VerifyAnonymousCredentialVerificationProof verifies AnonymousCredentialVerificationProof.
func VerifyAnonymousCredentialVerificationProof(proof []byte, credentialCommitment []byte, attributeName string, attributeValue string, credentialOpening []byte) bool {
	// ... ZKP logic to verify anonymous credential verification proof ...
	// Cryptographic verification.
	expectedProof := fmt.Sprintf("AnonymousCredentialProof: %s=%s", attributeName, attributeValue)
	if string(proof) != expectedProof {
		return false
	}
	if !VerifyCommitment(credentialCommitment, credentialOpening, credentialOpening) {
		return false // Verify credential commitment.
	}

	credential := string(credentialCommitment) // Placeholder credential for verification.
	attributePairs := map[string]string{}
	pairs := stringSplit(credential, ",")
	for _, pair := range pairs {
		parts := stringSplit(pair, ":")
		if len(parts) == 2 {
			attributePairs[parts[0]] = parts[1]
		}
	}

	return attributePairs[attributeName] == attributeValue // Placeholder verification + commitment verification + direct attribute check (for this placeholder).
}

// FairRandomnessVerificationProof proves randomness generation produced expected output.
func FairRandomnessVerificationProof(randomnessCommitment []byte, seedOpening []byte, expectedOutput string) (proof []byte, err error) {
	// Placeholder: Assume randomness is a simple hash of the seed.
	seed := seedOpening // Placeholder seed.
	generatedRandomness := HashData(seed)
	output := fmt.Sprintf("%x", generatedRandomness) // Hex representation of hash as output.

	if output != expectedOutput { // Check if generated output matches expected.
		return nil, errors.New("randomness generation output mismatch (based on placeholder)")
	}

	// ... ZKP logic for fair randomness verification ...
	// Cryptographic protocols to prove randomness generation is fair and predictable
	// based on a committed randomness source and a seed, without revealing the randomness source itself.
	proof = []byte("FairRandomnessProof") // Placeholder proof.
	return proof, nil
}

// VerifyFairRandomnessVerificationProof verifies FairRandomnessVerificationProof.
func VerifyFairRandomnessVerificationProof(proof []byte, randomnessCommitment []byte, expectedOutput string) bool {
	// ... ZKP logic to verify fair randomness verification proof ...
	// Cryptographic verification.
	expectedProof := "FairRandomnessProof"
	if string(proof) != expectedProof {
		return false
	}

	// We can't verify commitment to randomness source directly in this simple example
	// without more defined setup for randomness commitment.
	// For now, just re-calculate the randomness based on a hypothetical seed opening (which we don't have in verifier in this example).
	// In a real scenario, the verifier would have some form of information related to the committed randomness source
	// or a way to reconstruct/verify the generation process without knowing the seed directly.

	// For this simplified placeholder, we'll assume the verifier somehow knows the seed opening (not ZKP in true sense for seed privacy).
	hypotheticalSeedOpening := []byte("example-seed") // **In a real ZKP, verifier wouldn't know this directly!**
	generatedRandomness := HashData(hypotheticalSeedOpening)
	output := fmt.Sprintf("%x", generatedRandomness)

	return output == expectedOutput // Placeholder verification + direct output comparison (based on hypothetical seed).
}

// --- Helper Functions ---

// HashData is a placeholder for a cryptographic hash function (e.g., SHA-256).
func HashData(data []byte) []byte {
	// In a real application, use a secure hash function from crypto/sha256 or similar.
	placeholderHash := append([]byte("PLACEHOLDER_HASH_PREFIX_"), data...) // Simple prefixing as placeholder.
	return placeholderHash
}

// GenerateRandomBytes is a placeholder for generating cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	// In a real application, use crypto/rand.Reader for secure randomness.
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// stringSplit is a simple string split function for placeholder parsing.
func stringSplit(s, delimiter string) []string {
	result := []string{}
	current := ""
	for _, char := range s {
		if string(char) == delimiter {
			result = append(result, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	result = append(result, current)
	return result
}
```