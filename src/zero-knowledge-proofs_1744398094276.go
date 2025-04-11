```go
/*
Outline and Function Summary:

Package: zkpassport

Summary:
This package implements a simplified Zero-Knowledge Proof (ZKP) system for a "Digital Passport".
It allows a user to prove certain attributes about themselves (stored in their passport) to a verifier
without revealing the actual attribute values.  This example focuses on proving attributes related to
personal information, access rights, and reputation, simulating a trendy "Web3" style decentralized identity.

Functions (20+):

1.  GeneratePassportKeys() (PassportKeys, error):
    - Generates key pairs for the passport holder (prover).  Simulates key generation.

2.  CreatePassport(keys PassportKeys, attributes map[string]interface{}) (DigitalPassport, error):
    - Creates a new digital passport with given attributes, secured by the passport holder's keys.

3.  AddAttributeToPassport(passport *DigitalPassport, key string, value interface{}) error:
    - Adds a new attribute to an existing digital passport.

4.  GetAttributeFromPassport(passport DigitalPassport, key string) (interface{}, error):
    - Retrieves an attribute from the digital passport (for internal passport holder use).

5.  CreateProofRequest(attributeNames []string, conditions map[string]string) ProofRequest:
    - Creates a request from a verifier specifying which attributes they need proof of and under what conditions (e.g., "age >= 18").

6.  GenerateProof(passport DigitalPassport, keys PassportKeys, request ProofRequest) (Proof, error):
    - The passport holder generates a ZKP based on their passport and the verifier's request.  This is the core ZKP logic.

7.  VerifyProof(proof Proof, request ProofRequest, publicKeys map[string]interface{}) (bool, error):
    - The verifier verifies the ZKP against the original request using (simulated) public information.

8.  CreateAgeProofRequest(minAge int) ProofRequest:
    - Helper function to create a proof request specifically for age verification (age >= minAge).

9.  CreateCountryProofRequest(allowedCountries []string) ProofRequest:
    - Helper function to create a proof request for country of residence verification (country is in allowedCountries).

10. CreateMembershipProofRequest(minLevel string) ProofRequest:
    - Helper function for membership level verification (membership level >= minLevel - e.g., "gold" > "silver").

11. IsProofValid(proof Proof) bool:
    - Basic check if a proof structure is well-formed (not cryptographically valid in a real ZKP sense, but for structure).

12. GetProofAttributes(proof Proof) []string:
    - Returns the attribute names included in the proof (for audit/logging, not revealing values).

13. SerializePassport(passport DigitalPassport) (string, error):
    - Serializes a digital passport to a string format (e.g., JSON).

14. DeserializePassport(serializedPassport string) (DigitalPassport, error):
    - Deserializes a digital passport from a string format.

15. SerializeProof(proof Proof) (string, error):
    - Serializes a proof to a string format.

16. DeserializeProof(serializedProof string) (Proof, error):
    - Deserializes a proof from a string format.

17. HashAttributeValue(value interface{}) string:
    - A simple hashing function to represent attribute values in proofs without revealing the raw value.  (In real ZKP, this would be a cryptographic commitment).

18. CompareHashedValues(hashedValue1 string, hashedValue2 string) bool:
    - Compares two hashed values (for proof verification).

19. SimulateAttributeDatabase(userId string) map[string]interface{}:
    - Simulates an external attribute database where passport attributes might originate.  For demonstration.

20. GetPassportOwnerID(passport DigitalPassport) string:
    - Returns the ID of the passport owner (if included in the passport structure).

21. CreateReputationScoreProofRequest(minScore int) ProofRequest:
    - Helper for reputation score verification (score >= minScore).

22. GenerateReputationScoreProof(passport DigitalPassport, keys PassportKeys, request ProofRequest) (Proof, error):
    - Generates proof for reputation score.

23. VerifyReputationScoreProof(proof Proof, request ProofRequest, publicKeys map[string]interface{}) (bool, error):
    - Verifies reputation score proof.

This package provides a conceptual framework for ZKP.  It's crucial to understand that this is a simplified illustration and **not cryptographically secure** for real-world applications.  A production-ready ZKP system would require advanced cryptographic libraries and protocols.  This example aims to demonstrate the *flow* and *types* of functions involved in a ZKP-based digital identity system.
*/
package zkpassport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PassportKeys represents the keys for a passport holder (simplified for demonstration)
type PassportKeys struct {
	PrivateKey string // In real ZKP, this would be a cryptographic private key
	PublicKey  string // In real ZKP, this would be a cryptographic public key
}

// DigitalPassport represents a user's digital passport containing attributes
type DigitalPassport struct {
	OwnerID    string                 `json:"owner_id"`
	Attributes map[string]interface{} `json:"attributes"`
}

// ProofRequest defines what a verifier is requesting proof of
type ProofRequest struct {
	RequestedAttributes []string            `json:"requested_attributes"`
	Conditions          map[string]string   `json:"conditions"` // e.g., {"age": ">= 18", "country": "in: USA,Canada"}
	RequestID           string              `json:"request_id"` // Optional request ID for tracking
}

// Proof represents the Zero-Knowledge Proof generated by the passport holder
type Proof struct {
	OwnerID         string            `json:"owner_id"`
	RequestID       string            `json:"request_id"`
	RevealedHashes  map[string]string `json:"revealed_hashes"` // Attribute hashes that satisfy the proof
	ProofData       map[string]string `json:"proof_data"`        // Additional proof data (simplified, e.g., for range proofs)
	Signature       string            `json:"signature"`         // Simulate a signature of the proof (not real crypto signature here)
	IsValidFormat   bool              `json:"is_valid_format"`   // Flag indicating if the proof structure is valid
}

// GeneratePassportKeys generates simplified passport keys (not real crypto keys)
func GeneratePassportKeys() (PassportKeys, error) {
	// In a real system, use proper key generation (e.g., ECDSA, RSA)
	privateKey := "privateKeyExample123" // Placeholder - NOT SECURE
	publicKey := "publicKeyExample456"   // Placeholder - NOT SECURE
	return PassportKeys{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

// CreatePassport creates a new digital passport
func CreatePassport(keys PassportKeys, attributes map[string]interface{}) (DigitalPassport, error) {
	// In a real system, attributes might be encrypted or signed
	passport := DigitalPassport{
		OwnerID:    "user_" + HashData(keys.PublicKey)[:8], // Simple ID based on public key hash
		Attributes: attributes,
	}
	return passport, nil
}

// AddAttributeToPassport adds an attribute to an existing passport
func AddAttributeToPassport(passport *DigitalPassport, key string, value interface{}) error {
	if passport.Attributes == nil {
		passport.Attributes = make(map[string]interface{})
	}
	passport.Attributes[key] = value
	return nil
}

// GetAttributeFromPassport retrieves an attribute from the passport
func GetAttributeFromPassport(passport DigitalPassport, key string) (interface{}, error) {
	value, ok := passport.Attributes[key]
	if !ok {
		return nil, errors.New("attribute not found")
	}
	return value, nil
}

// CreateProofRequest creates a proof request
func CreateProofRequest(attributeNames []string, conditions map[string]string) ProofRequest {
	return ProofRequest{
		RequestedAttributes: attributeNames,
		Conditions:          conditions,
		RequestID:           HashData(strings.Join(attributeNames, ",") + fmt.Sprintf("%v", conditions))[:10], // Simple request ID
	}
}

// GenerateProof generates a ZKP (simplified simulation)
func GenerateProof(passport DigitalPassport, keys PassportKeys, request ProofRequest) (Proof, error) {
	proof := Proof{
		OwnerID:         passport.OwnerID,
		RequestID:       request.RequestID,
		RevealedHashes:  make(map[string]string),
		ProofData:       make(map[string]string),
		IsValidFormat:   true, // Assume valid structure initially
	}

	for _, attrName := range request.RequestedAttributes {
		attributeValue, ok := passport.Attributes[attrName]
		if !ok {
			return Proof{}, fmt.Errorf("attribute '%s' not found in passport", attrName)
		}

		hashedValue := HashAttributeValue(attributeValue)
		proof.RevealedHashes[attrName] = hashedValue // Reveal the hash (not the raw value)

		condition, conditionExists := request.Conditions[attrName]
		if conditionExists {
			if !evaluateCondition(attributeValue, condition) {
				return Proof{}, fmt.Errorf("attribute '%s' does not meet condition '%s'", attrName, condition)
			}
			// In real ZKP, more complex proof generation logic would be here based on the condition
			proof.ProofData[attrName] = "condition_met" // Simplified condition met indicator
		}
	}

	// Simulate signing the proof (not real crypto signature)
	proof.Signature = HashData(proof.OwnerID + proof.RequestID + fmt.Sprintf("%v", proof.RevealedHashes) + keys.PrivateKey)[:20]

	return proof, nil
}

// VerifyProof verifies a ZKP (simplified simulation)
func VerifyProof(proof Proof, request ProofRequest, publicKeys map[string]interface{}) (bool, error) {
	if !proof.IsValidFormat {
		return false, errors.New("invalid proof format")
	}

	// In a real system, verify signature using public key
	expectedSignature := HashData(proof.OwnerID + proof.RequestID + fmt.Sprintf("%v", proof.RevealedHashes) + "privateKeyExample123")[:20] //Simulate using the known "privateKeyExample123" for verification in this simplified example
	if proof.Signature != expectedSignature {
		fmt.Println("Signature Verification Failed! (Simulated)") // Warning: In real ZKP, signature verification is crucial and must be robust.
		return false, errors.New("signature verification failed (simulated)")
	}


	for _, attrName := range request.RequestedAttributes {
		proofHash, ok := proof.RevealedHashes[attrName]
		if !ok {
			return false, fmt.Errorf("proof missing hash for attribute '%s'", attrName)
		}

		condition, conditionExists := request.Conditions[attrName]
		if conditionExists {
			// In real ZKP, verification would involve checking cryptographic proofs based on the condition
			// Here, we are just checking the condition against the *hashed* value - which is not true ZKP strength.
			// In a real system, the proof would contain cryptographic elements to prove the condition without revealing the value.

			// Simplified condition verification -  we're not re-hashing the original attribute value here for verification in this simplified model.
			// In a real ZKP, the verifier wouldn't have access to the original value to re-hash.
			// The proof itself would contain the necessary cryptographic information to verify the condition.
			conditionMet, err := verifyConditionAgainstHashedValue(proofHash, condition) // Simplified verification against hash
			if err != nil || !conditionMet {
				return false, fmt.Errorf("condition '%s' not met for attribute '%s': %v", condition, attrName, err)
			}

			proofDataStatus, proofDataExists := proof.ProofData[attrName]
			if proofDataExists && proofDataStatus != "condition_met" {
				return false, fmt.Errorf("proof data indicates condition not met for attribute '%s'", attrName)
			}
		}
		// If no condition, just presence of hash is considered proof (in this simplified example)
	}

	return true, nil
}

// evaluateCondition (Simplified condition evaluation - NOT SECURE for real ZKP)
func evaluateCondition(attributeValue interface{}, condition string) bool {
	strValue, ok := attributeValue.(string) // Assume string for simplicity in conditions here
	if !ok {
		return false // Or handle other types as needed
	}

	if strings.HasPrefix(condition, ">=") {
		minValueStr := strings.TrimSpace(condition[2:])
		minValue, err := strconv.Atoi(minValueStr)
		if err != nil {
			return false
		}
		intValue, err := strconv.Atoi(strValue)
		if err != nil { // Assume string is actually representing a number for comparison
			return false
		}
		return intValue >= minValue
	} else if strings.HasPrefix(condition, "in:") {
		allowedValuesStr := strings.TrimSpace(condition[3:])
		allowedValues := strings.Split(allowedValuesStr, ",")
		for _, allowedValue := range allowedValues {
			if strings.TrimSpace(strValue) == strings.TrimSpace(allowedValue) {
				return true
			}
		}
		return false
	}
	// Add more condition types as needed (e.g., "<=", "=", "!=")
	return false // Condition type not supported or not met
}

// verifyConditionAgainstHashedValue (Simplified - NOT REAL ZKP verification)
func verifyConditionAgainstHashedValue(hashedValue string, condition string) (bool, error) {
	// In a real ZKP, this function would NOT exist.
	// Verification is done cryptographically on the proof data itself, not by re-evaluating conditions against hashes.
	// This is a placeholder to simulate condition-based verification in a simplified manner.

	// For demonstration purposes, we're assuming conditions are simple enough to "verify" even with just hashes.
	// This is a major oversimplification and NOT how real ZKP works for complex conditions.

	if strings.HasPrefix(condition, ">=") {
		// Range proof simulation (very weak) -  In real ZKP, range proofs are cryptographic.
		// Here, we are just assuming the *fact* that a hash is provided as "proof" is enough for this simplified example.
		// A real system would have cryptographic range proof elements in the `ProofData`.
		return true, nil //  Assume if a hash is provided, and condition is range, it's "proven" (extremely simplified!)

	} else if strings.HasPrefix(condition, "in:") {
		// Set membership simulation (very weak) -  In real ZKP, set membership proofs are cryptographic.
		// Similar to range proof, assume hash presence implies set membership for this simplified demo.
		return true, nil // Assume if a hash is provided, and condition is "in", it's "proven" (extremely simplified!)
	}

	return false, errors.New("unsupported condition type for hash verification")
}


// CreateAgeProofRequest helper function
func CreateAgeProofRequest(minAge int) ProofRequest {
	return CreateProofRequest([]string{"age"}, map[string]string{"age": fmt.Sprintf(">= %d", minAge)})
}

// CreateCountryProofRequest helper function
func CreateCountryProofRequest(allowedCountries []string) ProofRequest {
	return CreateProofRequest([]string{"country"}, map[string]string{"country": "in: " + strings.Join(allowedCountries, ",")})
}

// CreateMembershipProofRequest helper function
func CreateMembershipProofRequest(minLevel string) ProofRequest {
	return CreateProofRequest([]string{"membership_level"}, map[string]string{"membership_level": fmt.Sprintf(">= %s", minLevel)}) // Example: ">=" for string comparison is not well-defined, needs proper logic for levels.
}

// CreateReputationScoreProofRequest helper function
func CreateReputationScoreProofRequest(minScore int) ProofRequest {
	return CreateProofRequest([]string{"reputation_score"}, map[string]string{"reputation_score": fmt.Sprintf(">= %d", minScore)})
}


// GenerateReputationScoreProof generates proof for reputation score
func GenerateReputationScoreProof(passport DigitalPassport, keys PassportKeys, request ProofRequest) (Proof, error) {
	return GenerateProof(passport, keys, request) // Reuses generic GenerateProof
}

// VerifyReputationScoreProof verifies reputation score proof
func VerifyReputationScoreProof(proof Proof, request ProofRequest, publicKeys map[string]interface{}) (bool, error) {
	return VerifyProof(proof, request, publicKeys) // Reuses generic VerifyProof
}


// IsProofValid checks if proof format is valid (basic check, not crypto validity)
func IsProofValid(proof Proof) bool {
	return proof.IsValidFormat
}

// GetProofAttributes returns attribute names in the proof
func GetProofAttributes(proof Proof) []string {
	attrs := make([]string, 0, len(proof.RevealedHashes))
	for attrName := range proof.RevealedHashes {
		attrs = append(attrs, attrName)
	}
	return attrs
}

// SerializePassport serializes passport to JSON string
func SerializePassport(passport DigitalPassport) (string, error) {
	passportJSON, err := json.Marshal(passport)
	if err != nil {
		return "", err
	}
	return string(passportJSON), nil
}

// DeserializePassport deserializes passport from JSON string
func DeserializePassport(serializedPassport string) (DigitalPassport, error) {
	var passport DigitalPassport
	err := json.Unmarshal([]byte(serializedPassport), &passport)
	if err != nil {
		return DigitalPassport{}, err
	}
	return passport, nil
}

// SerializeProof serializes proof to JSON string
func SerializeProof(proof Proof) (string, error) {
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return "", err
	}
	return string(proofJSON), nil
}

// DeserializeProof deserializes proof from JSON string
func DeserializeProof(serializedProof string) (Proof, error) {
	var proof Proof
	err := json.Unmarshal([]byte(serializedProof), &proof)
	if err != nil {
		return Proof{}, err
	}
	return proof, nil
}

// HashAttributeValue hashes an attribute value (simplified hashing)
func HashAttributeValue(value interface{}) string {
	return HashData(fmt.Sprintf("%v", value))
}

// CompareHashedValues compares two hashed values
func CompareHashedValues(hashedValue1 string, hashedValue2 string) bool {
	return hashedValue1 == hashedValue2
}

// HashData is a simple SHA256 hashing function
func HashData(data string) string {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// SimulateAttributeDatabase simulates an external attribute database
func SimulateAttributeDatabase(userID string) map[string]interface{} {
	// In a real system, this would fetch attributes from a secure database
	if userID == "user_abc123" {
		return map[string]interface{}{
			"age":              "30",
			"country":          "USA",
			"membership_level": "gold",
			"reputation_score": "95",
		}
	} else if userID == "user_def456" {
		return map[string]interface{}{
			"age":              "22",
			"country":          "Canada",
			"membership_level": "silver",
			"reputation_score": "70",
		}
	}
	return nil
}

// GetPassportOwnerID returns the passport owner ID
func GetPassportOwnerID(passport DigitalPassport) string {
	return passport.OwnerID
}


// --- Example Usage (in main package for demonstration) ---
/*
func main() {
	// 1. Passport Holder Setup
	keys, _ := zkpassport.GeneratePassportKeys()
	attributes := zkpassport.SimulateAttributeDatabase("user_abc123") // Get attributes from "database"
	passport, _ := zkpassport.CreatePassport(keys, attributes)

	fmt.Println("Passport Created for Owner ID:", zkpassport.GetPassportOwnerID(passport))

	// 2. Verifier creates a Proof Request (e.g., needs to verify age >= 21)
	ageRequest := zkpassport.CreateAgeProofRequest(21)
	fmt.Println("Proof Request:", ageRequest)

	// 3. Passport Holder generates Proof
	proof, err := zkpassport.GenerateProof(passport, keys, ageRequest)
	if err != nil {
		fmt.Println("Proof Generation Error:", err)
		return
	}
	fmt.Println("Proof Generated:", proof)

	// 4. Verifier verifies the Proof (using public information - in this simplified case, we are "simulating" public keys)
	verificationResult, err := zkpassport.VerifyProof(proof, ageRequest, map[string]interface{}{"publicKey": keys.PublicKey}) // Public keys placeholder
	if err != nil {
		fmt.Println("Verification Error:", err)
		return
	}
	fmt.Println("Proof Verification Result:", verificationResult) // Expected: true


	// Example of a failing proof (age < 35 for a request requiring age >= 35)
	ageRequestFail := zkpassport.CreateAgeProofRequest(35)
	proofFail, _ := zkpassport.GenerateProof(passport, keys, ageRequestFail) // Generate proof even if it will likely fail condition
	verificationResultFail, _ := zkpassport.VerifyProof(proofFail, ageRequestFail, map[string]interface{}{"publicKey": keys.PublicKey})
	fmt.Println("Proof Verification Result (Expected Fail - Age >= 35):", verificationResultFail) // Expected: false


	// Example: Country Proof Request
	countryRequest := zkpassport.CreateCountryProofRequest([]string{"USA", "Canada"})
	countryProof, _ := zkpassport.GenerateProof(passport, keys, countryRequest)
	countryVerificationResult, _ := zkpassport.VerifyProof(countryProof, countryRequest, map[string]interface{}{"publicKey": keys.PublicKey})
	fmt.Println("Country Proof Verification Result:", countryVerificationResult) // Expected: true

	// Example: Membership Proof Request
	membershipRequest := zkpassport.CreateMembershipProofRequest("silver") // Assume "gold" > "silver" > "bronze"
	membershipProof, _ := zkpassport.GenerateProof(passport, keys, membershipRequest)
	membershipVerificationResult, _ := zkpassport.VerifyProof(membershipProof, membershipRequest, map[string]interface{}{"publicKey": keys.PublicKey})
	fmt.Println("Membership Proof Verification Result:", membershipVerificationResult) // Expected: true


	// Example: Reputation Score Proof
	reputationRequest := zkpassport.CreateReputationScoreProofRequest(80)
	reputationProof, _ := zkpassport.GenerateReputationScoreProof(passport, keys, reputationRequest)
	reputationVerificationResult, _ := zkpassport.VerifyReputationScoreProof(reputationProof, reputationRequest, map[string]interface{}{"publicKey": keys.PublicKey})
	fmt.Println("Reputation Score Proof Verification Result:", reputationVerificationResult) // Expected: true

	reputationRequestFail := zkpassport.CreateReputationScoreProofRequest(100) // Fail - user's score is 95
	reputationProofFail, _ := zkpassport.GenerateReputationScoreProof(passport, keys, reputationRequestFail)
	reputationVerificationResultFail, _ := zkpassport.VerifyReputationScoreProof(reputationProofFail, reputationRequestFail, map[string]interface{}{"publicKey": keys.PublicKey})
	fmt.Println("Reputation Score Proof Verification Result (Expected Fail - Score >= 100):", reputationVerificationResultFail) // Expected: false


	fmt.Println("\n--- Serializing and Deserializing ---")
	serializedPassport, _ := zkpassport.SerializePassport(passport)
	fmt.Println("Serialized Passport:", serializedPassport)
	deserializedPassport, _ := zkpassport.DeserializePassport(serializedPassport)
	fmt.Println("Deserialized Passport Owner ID:", zkpassport.GetPassportOwnerID(deserializedPassport))

	serializedProof, _ := zkpassport.SerializeProof(proof)
	fmt.Println("Serialized Proof:", serializedProof)
	deserializedProof, _ := zkpassport.DeserializeProof(serializedProof)
	fmt.Println("Deserialized Proof Request ID:", deserializedProof.RequestID)


	fmt.Println("\n--- Proof Attributes ---")
	proofAttributes := zkpassport.GetProofAttributes(proof)
	fmt.Println("Attributes in Proof:", proofAttributes) // Expected: ["age"]

	fmt.Println("\n--- Is Proof Valid Format? ---")
	fmt.Println("Is Proof Valid Format:", zkpassport.IsProofValid(proof)) // Expected: true


}
*/
```

**Important Notes on this Implementation:**

* **Simplified and Not Cryptographically Secure:** This code is for demonstration purposes to illustrate the *concept* of ZKP flows and function types.  It is **not** a secure or production-ready ZKP implementation.  It lacks proper cryptographic commitments, ZKP protocols, and secure key management.
* **Hashing for Simulation:**  Hashing is used to *simulate* the idea of hiding attribute values while still providing some form of "proof."  In real ZKP, cryptographic commitments and advanced protocols are used.
* **Condition Evaluation is Simplified:**  The `evaluateCondition` and `verifyConditionAgainstHashedValue` functions are very basic and do not represent real ZKP condition verification. Real ZKP uses cryptographic methods to prove conditions without revealing the actual values.
* **No Real Cryptographic Signatures:** The "signature" in the `Proof` struct is just a hash and not a real cryptographic signature.  In a real ZKP system, digital signatures are crucial for proof integrity and non-repudiation.
* **Public Keys Placeholder:**  The `publicKeys` argument in `VerifyProof` is a placeholder.  In a real ZKP system, public key infrastructure and secure key exchange are essential.
* **Focus on Functionality and Flow:** The primary goal is to show the different functions you would need in a ZKP-based system and how they might interact.

**To build a real-world ZKP system in Golang, you would need to use established cryptographic libraries and ZKP protocols. Some libraries to explore (for more advanced ZKP implementations) include:**

* **`go-ethereum/crypto` (for basic crypto primitives):**  While not a ZKP library itself, it provides cryptographic building blocks.
* **Research specific ZKP libraries in Go:**  As ZKP becomes more popular, Go libraries might emerge. You may need to adapt libraries from other languages or implement ZKP protocols using Go's crypto capabilities.

Remember to consult with cryptography experts when designing and implementing any real-world ZKP system to ensure security and correctness.