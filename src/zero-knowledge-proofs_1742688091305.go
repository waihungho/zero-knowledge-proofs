```go
package zkplib

/*
Outline and Function Summary:

This Go package, `zkplib`, provides a collection of functions for implementing Zero-Knowledge Proofs (ZKPs) focusing on a "Private Data Verification Service."
This service allows a Prover to demonstrate properties of their private data to a Verifier without revealing the data itself.
The functions cover various aspects of ZKP, from basic commitment schemes to more advanced concepts like range proofs, set membership proofs, aggregation proofs, and selective disclosure.

The functions are categorized as follows:

1. **Setup & Key Generation:** Functions for setting up the ZKP system and generating necessary keys.
    - `GenerateKeys()`: Generates proving and verification keys for the ZKP system.
    - `SerializeKeys()`: Serializes keys for storage or transmission.
    - `DeserializeKeys()`: Deserializes keys from storage or transmission.
    - `GeneratePublicParameters()`: Generates common public parameters for the ZKP system.

2. **Data Commitment & Encoding:** Functions for preparing data for ZKP protocols.
    - `CommitToData()`: Creates a commitment to private data.
    - `OpenCommitment()`: Opens a commitment to reveal the original data (used in setup, not in ZKP itself).
    - `HashData()`: Hashes data for use in ZKP protocols.
    - `EncodeData()`: Encodes data into a format suitable for cryptographic operations.

3. **Basic ZKP Proofs:** Functions for simple ZKP proofs like existence and hash verification.
    - `ProveDataExists()`: Generates a ZKP that data exists without revealing its value.
    - `VerifyDataExistsProof()`: Verifies a ZKP that data exists.
    - `ProveDataIsCorrectHash()`: Generates a ZKP that data hashes to a specific value without revealing the data.
    - `VerifyDataHashProof()`: Verifies a ZKP that data hashes to a specific value.

4. **Advanced ZKP Proofs (Range, Set Membership, Comparison):** Functions for more complex ZKP proofs.
    - `ProveDataInRange()`: Generates a ZKP that data falls within a specified numerical range without revealing the exact value.
    - `VerifyDataRangeProof()`: Verifies a ZKP that data is within a specific range.
    - `ProveDataIsMemberOfSet()`: Generates a ZKP that data is a member of a predefined set without revealing which member.
    - `VerifyDataSetMembershipProof()`: Verifies a ZKP that data is a member of a set.
    - `ProveDataGreaterThan()`: Generates a ZKP that data is greater than a public value without revealing the exact data.
    - `VerifyDataGreaterThanProof()`: Verifies a ZKP that data is greater than a public value.

5. **Aggregation & Statistical Proofs:** Functions for proving aggregated properties of data.
    - `ProveDataAggregation()`: Generates a ZKP about an aggregation (e.g., sum, average) of multiple private data points without revealing individual values.
    - `VerifyDataAggregationProof()`: Verifies a ZKP about data aggregation.
    - `ProveStatisticalProperty()`: Generates a ZKP about a statistical property of data (e.g., variance, distribution) without full data disclosure.
    - `VerifyStatisticalPropertyProof()`: Verifies a ZKP about a statistical property.

6. **Privacy & Selective Disclosure Proofs:** Functions for enhancing privacy and enabling selective information release.
    - `ProveDataWithoutRevealingValue()`: Generates a ZKP about a property of data while ensuring the data value itself is never revealed even to the verifier during the proof process.
    - `VerifyDataPrivacyProof()`: Verifies a ZKP generated with full privacy preservation.
    - `ProveDataWithSelectiveDisclosure()`: Generates a ZKP that allows selectively revealing certain aspects of data while keeping others private.
    - `VerifySelectiveDisclosureProof()`: Verifies a ZKP with selective data disclosure.
    - `AnonymousDataVerification()`: Enables verification of data properties without revealing the identity of the data owner (prover).
    - `VerifyAnonymousDataProof()`: Verifies a ZKP in an anonymous setting.

Each function outline includes placeholders for actual ZKP logic. This is a conceptual framework; the actual implementation of ZKP protocols requires significant cryptographic expertise and choice of specific ZKP schemes (e.g., zk-SNARKs, zk-STARKs, Bulletproofs, etc.), which are beyond the scope of this outline.  The focus is on demonstrating a diverse set of ZKP functionalities in a practical context.
*/

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// --- 1. Setup & Key Generation ---

// GenerateKeys generates proving and verification keys.
// In a real ZKP system, this would involve complex cryptographic key generation.
// For demonstration, we'll use placeholder keys.
func GenerateKeys() (provingKey []byte, verificationKey []byte, err error) {
	provingKey = make([]byte, 32)
	verificationKey = make([]byte, 32)
	_, err = rand.Read(provingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate proving key: %w", err)
	}
	_, err = rand.Read(verificationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate verification key: %w", err)
	}
	return provingKey, verificationKey, nil
}

// SerializeKeys serializes keys to byte arrays.
// In a real system, this might involve encoding to specific formats (e.g., ASN.1).
func SerializeKeys(key []byte) (serializedKey string, err error) {
	serializedKey = hex.EncodeToString(key)
	return serializedKey, nil
}

// DeserializeKeys deserializes keys from byte arrays.
func DeserializeKeys(serializedKey string) (key []byte, err error) {
	key, err = hex.DecodeString(serializedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key: %w", err)
	}
	return key, nil
}

// GeneratePublicParameters generates common public parameters for the ZKP system.
// Public parameters are often used in more complex ZKP schemes.
// For simplicity, we'll just return nil for now as many basic ZKPs don't explicitly need them.
func GeneratePublicParameters() (params []byte, err error) {
	// In a real system, this could involve generating group parameters, etc.
	return nil, nil
}

// --- 2. Data Commitment & Encoding ---

// CommitToData creates a commitment to private data.
// A simple commitment can be a hash of the data concatenated with a random nonce.
func CommitToData(data []byte) (commitment []byte, revealNonce []byte, err error) {
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce for commitment: %w", err)
	}
	dataWithNonce := append(data, nonce...)
	hasher := sha256.New()
	hasher.Write(dataWithNonce)
	commitment = hasher.Sum(nil)
	return commitment, nonce, nil
}

// OpenCommitment opens a commitment to reveal the original data and nonce.
// This is used to verify the commitment scheme itself, not in the actual ZKP process.
func OpenCommitment(commitment []byte, data []byte, revealNonce []byte) bool {
	dataWithNonce := append(data, revealNonce...)
	hasher := sha256.New()
	hasher.Write(dataWithNonce)
	expectedCommitment := hasher.Sum(nil)
	return hex.EncodeToString(commitment) == hex.EncodeToString(expectedCommitment)
}

// HashData hashes data using SHA256.
func HashData(data []byte) (hash []byte, err error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash = hasher.Sum(nil)
	return hash, nil
}

// EncodeData encodes data into a format suitable for cryptographic operations.
// For simplicity, we'll just return the data as is, but in real ZKP, encoding to fields or groups is common.
func EncodeData(data []byte) (encodedData []byte, err error) {
	return data, nil
}

// --- 3. Basic ZKP Proofs ---

// ProveDataExists generates a ZKP that data exists without revealing its value.
// This is a very basic example, often achieved through commitment schemes.
// In a real ZKP, this function would generate a cryptographic proof.
func ProveDataExists(data []byte, provingKey []byte) (proof []byte, err error) {
	// Placeholder: In a real ZKP, generate a proof here.
	// For example, using a commitment to the data could serve as a simple "existence" proof.
	commitment, _, err := CommitToData(data) // Use commitment as a simple proof for demonstration
	if err != nil {
		return nil, fmt.Errorf("failed to create commitment for existence proof: %w", err)
	}
	return commitment, nil // Commitment acts as the proof
}

// VerifyDataExistsProof verifies a ZKP that data exists.
// For our simple example, verifying the commitment is the "proof verification."
func VerifyDataExistsProof(proof []byte, verificationKey []byte) (isValid bool, err error) {
	// Placeholder: In a real ZKP, verify the proof against the verification key.
	// For our simple commitment-based proof, verification is inherently "always true" if a valid commitment was created.
	// In a more robust system, this would verify the cryptographic proof.
	if len(proof) > 0 { // Simply check if the proof (commitment) is not empty for this basic example
		return true, nil
	}
	return false, nil
}

// ProveDataIsCorrectHash generates a ZKP that data hashes to a specific value without revealing the data.
// This can be achieved using pre-image resistance of hash functions and revealing the hash.
func ProveDataIsCorrectHash(data []byte, targetHash []byte, provingKey []byte) (proof []byte, err error) {
	dataHash, err := HashData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}
	if hex.EncodeToString(dataHash) != hex.EncodeToString(targetHash) {
		return nil, fmt.Errorf("data hash does not match target hash")
	}
	// The proof here is simply revealing the target hash itself, as the verifier can hash the *claimed* data and check.
	// In a real ZKP for hash correctness, more sophisticated techniques might be used, but for this basic example, revealing the hash suffices.
	return targetHash, nil // Target hash serves as the proof
}

// VerifyDataHashProof verifies a ZKP that data hashes to a specific value.
// The verifier would receive the claimed data and the hash (proof) and verify the hash.
// In a real ZKP, this function would verify a cryptographic proof, not just re-hashing.
func VerifyDataHashProof(claimedData []byte, hashProof []byte, verificationKey []byte) (isValid bool, err error) {
	calculatedHash, err := HashData(claimedData)
	if err != nil {
		return false, fmt.Errorf("failed to hash claimed data for verification: %w", err)
	}
	return hex.EncodeToString(calculatedHash) == hex.EncodeToString(hashProof), nil
}

// --- 4. Advanced ZKP Proofs (Range, Set Membership, Comparison) ---

// ProveDataInRange generates a ZKP that data falls within a specified numerical range without revealing the exact value.
// Requires more advanced ZKP techniques like range proofs (e.g., Bulletproofs concept).
// Placeholder for demonstration.
func ProveDataInRange(data int64, minRange int64, maxRange int64, provingKey []byte) (proof []byte, err error) {
	if data < minRange || data > maxRange {
		return nil, fmt.Errorf("data is not within the specified range")
	}
	// ... ZKP logic for Range Proof using cryptographic techniques ...
	proof = []byte(fmt.Sprintf("RangeProof: Data is in [%d, %d]", minRange, maxRange)) // Placeholder proof
	return proof, nil
}

// VerifyDataRangeProof verifies a ZKP that data is within a specific range.
// Placeholder for demonstration.
func VerifyDataRangeProof(proof []byte, minRange int64, maxRange int64, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify Range Proof ...
	if string(proof) == fmt.Sprintf("RangeProof: Data is in [%d, %d]", minRange, maxRange) { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("range proof verification failed")
}

// ProveDataIsMemberOfSet generates a ZKP that data is a member of a predefined set without revealing which member.
// Requires techniques like set membership proofs (e.g., Merkle Tree based or polynomial commitments).
// Placeholder for demonstration.
func ProveDataIsMemberOfSet(data int64, set []int64, provingKey []byte) (proof []byte, err error) {
	isMember := false
	for _, member := range set {
		if data == member {
			isMember = true
			break
		}
	}
	if !isMember {
		return nil, fmt.Errorf("data is not a member of the set")
	}
	// ... ZKP logic for Set Membership Proof using cryptographic techniques ...
	proof = []byte("SetMembershipProof: Data is in the set") // Placeholder proof
	return proof, nil
}

// VerifyDataSetMembershipProof verifies a ZKP that data is a member of a set.
// Placeholder for demonstration.
func VerifyDataSetMembershipProof(proof []byte, set []int64, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify Set Membership Proof ...
	if string(proof) == "SetMembershipProof: Data is in the set" { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("set membership proof verification failed")
}

// ProveDataGreaterThan generates a ZKP that data is greater than a public value without revealing the exact data.
// Can be achieved using comparison protocols in ZKP.
// Placeholder for demonstration.
func ProveDataGreaterThan(data int64, threshold int64, provingKey []byte) (proof []byte, err error) {
	if data <= threshold {
		return nil, fmt.Errorf("data is not greater than the threshold")
	}
	// ... ZKP logic for Greater Than Proof using cryptographic techniques ...
	proof = []byte(fmt.Sprintf("GreaterThanProof: Data > %d", threshold)) // Placeholder proof
	return proof, nil
}

// VerifyDataGreaterThanProof verifies a ZKP that data is greater than a public value.
// Placeholder for demonstration.
func VerifyDataGreaterThanProof(proof []byte, threshold int64, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify Greater Than Proof ...
	if string(proof) == fmt.Sprintf("GreaterThanProof: Data > %d", threshold) { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("greater than proof verification failed")
}

// --- 5. Aggregation & Statistical Proofs ---

// ProveDataAggregation generates a ZKP about an aggregation (e.g., sum, average) of multiple private data points without revealing individual values.
// Requires techniques like homomorphic encryption combined with ZKP or specialized aggregation ZKP schemes.
// Placeholder for demonstration.
func ProveDataAggregation(dataPoints []int64, aggregationType string, targetValue int64, provingKey []byte) (proof []byte, err error) {
	var calculatedValue int64
	switch aggregationType {
	case "sum":
		for _, val := range dataPoints {
			calculatedValue += val
		}
	case "average":
		if len(dataPoints) == 0 {
			calculatedValue = 0
		} else {
			sum := int64(0)
			for _, val := range dataPoints {
				sum += val
			}
			calculatedValue = sum / int64(len(dataPoints))
		}
	default:
		return nil, fmt.Errorf("unsupported aggregation type: %s", aggregationType)
	}

	if calculatedValue != targetValue {
		return nil, fmt.Errorf("aggregation value does not match target")
	}

	// ... ZKP logic for Aggregation Proof using cryptographic techniques ...
	proof = []byte(fmt.Sprintf("AggregationProof: %s is %d", aggregationType, targetValue)) // Placeholder proof
	return proof, nil
}

// VerifyDataAggregationProof verifies a ZKP about data aggregation.
// Placeholder for demonstration.
func VerifyDataAggregationProof(proof []byte, aggregationType string, targetValue int64, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify Aggregation Proof ...
	if string(proof) == fmt.Sprintf("AggregationProof: %s is %d", aggregationType, targetValue) { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("aggregation proof verification failed")
}

// ProveStatisticalProperty generates a ZKP about a statistical property of data (e.g., variance, distribution) without full data disclosure.
// Advanced ZKP, potentially involving techniques like range proofs or MPC in the exponent.
// Placeholder for demonstration.
func ProveStatisticalProperty(dataPoints []int64, propertyType string, propertyValue float64, provingKey []byte) (proof []byte, err error) {
	// ... Calculate statistical property and verify against propertyValue ...
	// Example: Simple Variance (not statistically robust, just for illustration)
	if propertyType == "variance" {
		if len(dataPoints) < 2 {
			return nil, fmt.Errorf("variance requires at least two data points")
		}
		mean := 0.0
		for _, val := range dataPoints {
			mean += float64(val)
		}
		mean /= float64(len(dataPoints))
		variance := 0.0
		for _, val := range dataPoints {
			diff := float64(val) - mean
			variance += diff * diff
		}
		variance /= float64(len(dataPoints) - 1) // Sample variance

		if variance != propertyValue { // In real ZKP, compare with tolerance or range
			return nil, fmt.Errorf("calculated variance does not match target")
		}
	} else {
		return nil, fmt.Errorf("unsupported statistical property: %s", propertyType)
	}

	// ... ZKP logic for Statistical Property Proof using cryptographic techniques ...
	proof = []byte(fmt.Sprintf("StatisticalPropertyProof: %s is %.2f", propertyType, propertyValue)) // Placeholder proof
	return proof, nil
}

// VerifyStatisticalPropertyProof verifies a ZKP about a statistical property.
// Placeholder for demonstration.
func VerifyStatisticalPropertyProof(proof []byte, propertyType string, propertyValue float64, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify Statistical Property Proof ...
	if string(proof) == fmt.Sprintf("StatisticalPropertyProof: %s is %.2f", propertyType, propertyValue) { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("statistical property proof verification failed")
}

// --- 6. Privacy & Selective Disclosure Proofs ---

// ProveDataWithoutRevealingValue generates a ZKP about a property of data while ensuring the data value itself is never revealed even to the verifier during the proof process.
// This is the core concept of ZKP, and real implementations require sophisticated cryptographic protocols.
// Placeholder demonstrating the *intent*.
func ProveDataWithoutRevealingValue(data []byte, propertyToProve string, provingKey []byte) (proof []byte, err error) {
	// Example: Proving "data is within a certain format" without revealing the format or data itself in detail.
	if propertyToProve == "isPhoneNumberFormat" {
		// ... Assume some validation logic to check if data is in phone number format ...
		isValidFormat := len(data) > 8 && len(data) < 15 // Very basic format check
		if !isValidFormat {
			return nil, fmt.Errorf("data is not in phone number format")
		}
		// ... ZKP logic to prove format without revealing actual digits ...
		proof = []byte("PrivacyProof: Data is in phone number format (without revealing number)") // Placeholder
		return proof, nil
	}
	return nil, fmt.Errorf("unsupported privacy property to prove: %s", propertyToProve)
}

// VerifyDataPrivacyProof verifies a ZKP generated with full privacy preservation.
// Placeholder demonstrating the *intent*.
func VerifyDataPrivacyProof(proof []byte, propertyToProve string, verificationKey []byte) (isValid bool, err error) {
	// ... ZKP logic to verify the privacy-preserving proof ...
	if string(proof) == "PrivacyProof: Data is in phone number format (without revealing number)" { // Placeholder
		return true, nil
	}
	return false, fmt.Errorf("privacy proof verification failed")
}

// ProveDataWithSelectiveDisclosure generates a ZKP that allows selectively revealing certain aspects of data while keeping others private.
// Requires techniques that allow for partial disclosure within ZKP frameworks.
// Placeholder for demonstration.
func ProveDataWithSelectiveDisclosure(data map[string]interface{}, publicFields []string, privateFields []string, provingKey []byte) (proof []byte, disclosedData map[string]interface{}, err error) {
	disclosedData = make(map[string]interface{})
	for _, field := range publicFields {
		if val, ok := data[field]; ok {
			disclosedData[field] = val
		}
	}
	// For private fields, generate ZKP that properties hold without revealing values.
	// Example: Prove "age is above 18" (private field) and reveal "country" (public field).
	if contains(privateFields, "age") {
		if age, ok := data["age"].(int); ok {
			if age < 18 {
				return nil, nil, fmt.Errorf("age is not above 18, cannot prove")
			}
			// ... ZKP logic to prove "age >= 18" without revealing exact age ...
			proof = []byte("SelectiveDisclosureProof: Age is >= 18 (age itself not disclosed)") // Placeholder
		} else {
			return nil, nil, fmt.Errorf("age field is not an integer")
		}
	} else {
		proof = []byte("SelectiveDisclosureProof: No private fields to prove (only public fields disclosed)") // Placeholder if only public fields
	}

	return proof, disclosedData, nil
}

// VerifySelectiveDisclosureProof verifies a ZKP with selective data disclosure.
// Placeholder for demonstration.
func VerifySelectiveDisclosureProof(proof []byte, disclosedData map[string]interface{}, publicFields []string, privateFields []string, verificationKey []byte) (isValid bool, err error) {
	// ... Verify that disclosed data matches publicFields ...
	for _, field := range publicFields {
		if _, ok := disclosedData[field]; !ok {
			return false, fmt.Errorf("disclosed data missing public field: %s", field)
		}
	}
	// ... Verify ZKP for private fields ...
	if contains(privateFields, "age") {
		if string(proof) != "SelectiveDisclosureProof: Age is >= 18 (age itself not disclosed)" { // Placeholder verification
			return false, fmt.Errorf("selective disclosure proof for age failed")
		}
	} else if string(proof) != "SelectiveDisclosureProof: No private fields to prove (only public fields disclosed)" { // Placeholder verification for no private fields
		return false, fmt.Errorf("selective disclosure proof verification failed for no private fields case")
	}

	return true, nil
}

// AnonymousDataVerification enables verification of data properties without revealing the identity of the data owner (prover).
// This requires anonymous credentials, ring signatures, or other anonymity-preserving techniques in ZKP.
// Placeholder for demonstration.
func AnonymousDataVerification(data []byte, propertyToProve string, anonymityKey []byte) (anonymousProof []byte, err error) {
	// ... Generate anonymous proof using anonymityKey that proves 'propertyToProve' about 'data' ...
	//  Techniques: Ring Signatures, Group Signatures, Anonymous Credentials etc.
	anonymousProof = []byte("AnonymousProof: Property verified without revealing identity") // Placeholder
	return anonymousProof, nil
}

// VerifyAnonymousDataProof verifies a ZKP in an anonymous setting.
// Placeholder for demonstration.
func VerifyAnonymousDataProof(anonymousProof []byte, propertyToProve string, verificationAnonymityKey []byte) (isAnonymousValid bool, err error) {
	// ... Verify the anonymous proof without being able to identify the prover ...
	if string(anonymousProof) == "AnonymousProof: Property verified without revealing identity" { // Placeholder verification
		return true, nil
	}
	return false, fmt.Errorf("anonymous data proof verification failed")
}

// --- Utility Functions ---

// contains helper function to check if a string is in a slice
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

// Example usage (Illustrative - not runnable ZKP due to placeholders)
func main() {
	fmt.Println("Zero-Knowledge Proof Library Example (Outline)")

	// 1. Setup
	provingKey, verificationKey, _ := GenerateKeys()
	serializedProvingKey, _ := SerializeKeys(provingKey)
	deserializedProvingKey, _ := DeserializeKeys(serializedProvingKey)
	fmt.Println("Keys Generated and Serialized/Deserialized:", len(deserializedProvingKey) == len(provingKey))

	// 2. Commitment
	originalData := []byte("secret data")
	commitment, nonce, _ := CommitToData(originalData)
	isCommitmentValid := OpenCommitment(commitment, originalData, nonce)
	fmt.Println("Commitment Created and Opened:", isCommitmentValid)

	// 3. Basic ZKP - Data Existence
	existenceProof, _ := ProveDataExists(originalData, provingKey)
	isExistenceProofValid, _ := VerifyDataExistsProof(existenceProof, verificationKey)
	fmt.Println("Data Existence Proof Verified:", isExistenceProofValid)

	// 4. Advanced ZKP - Range Proof (Placeholder Verification)
	rangeProof, _ := ProveDataInRange(50, 10, 100, provingKey)
	isRangeProofValid, _ := VerifyDataRangeProof(rangeProof, 10, 100, verificationKey)
	fmt.Println("Range Proof Verified (Placeholder):", isRangeProofValid)

	// 5. Aggregation Proof (Placeholder Verification)
	dataPoints := []int64{10, 20, 30}
	aggregationProof, _ := ProveDataAggregation(dataPoints, "sum", 60, provingKey)
	isAggregationProofValid, _ := VerifyDataAggregationProof(aggregationProof, "sum", 60, verificationKey)
	fmt.Println("Aggregation Proof Verified (Placeholder):", isAggregationProofValid)

	// 6. Privacy Proof (Placeholder Verification)
	privacyProof, _ := ProveDataWithoutRevealingValue([]byte("123-456-7890"), "isPhoneNumberFormat", provingKey)
	isPrivacyProofValid, _ := VerifyDataPrivacyProof(privacyProof, "isPhoneNumberFormat", verificationKey)
	fmt.Println("Privacy Proof Verified (Placeholder):", isPrivacyProofValid)

	fmt.Println("Note: This is an outline with placeholder ZKP logic. Real ZKP implementation requires cryptographic libraries and protocols.")
}
```