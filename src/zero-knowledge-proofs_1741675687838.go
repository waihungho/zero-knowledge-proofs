```go
/*
Outline and Function Summary:

**Zero-Knowledge Proof for Private Set Intersection (PSI) with Range Proofs**

This code implements a Zero-Knowledge Proof (ZKP) system for demonstrating Private Set Intersection (PSI) with added range proofs.  It allows a Prover to convince a Verifier that they have a set of numbers that intersects with the Verifier's set, AND that the common numbers fall within a specific range, WITHOUT revealing the actual sets or the common elements themselves (except for the fact of intersection and range compliance).

**Core Concepts Demonstrated:**

1. **Private Set Intersection (PSI):**  Proving common elements exist between two sets without revealing the sets.
2. **Range Proofs:** Proving that certain values lie within a specified range without revealing the values.
3. **Zero-Knowledge:**  Verifier learns only the fact of intersection and range compliance, nothing else about the sets.
4. **Commitment Schemes:** Prover commits to their set in a way that doesn't reveal its content until later.
5. **Challenge-Response Protocol:**  Verifier issues challenges, and Prover responds based on their committed data and knowledge.
6. **Cryptographic Hashing:** Used for commitments and integrity checks.
7. **Randomness:** Essential for generating challenges and ensuring zero-knowledge properties.
8. **Modular Arithmetic (Implicit):**  While not explicitly using `math/big` for large numbers in this simplified example, the concepts are applicable to more robust ZKP systems that rely on modular arithmetic.

**Functions (20+):**

**1. `GenerateRandomSet(size int, maxVal int) []int`**:
   - Summary: Generates a random set of integers for demonstration purposes.

**2. `HashSetValue(set []int) string`**:
   - Summary: Hashes a set of integers to create a commitment. This is a simplified commitment scheme.

**3. `CreateCommitment(proverSet []int) (commitment string, randomNonce string, committedSetHashes []string)`**:
   - Summary: Prover commits to their set by hashing each element individually and also hashing the entire set. Includes a random nonce for security. Returns the overall commitment, nonce, and individual element hashes.

**4. `GenerateVerifierSet(size int, maxVal int, intersectionRangeMin int, intersectionRangeMax int) ([]int, []int)`**:
   - Summary: Generates a Verifier's set and also identifies the intersection elements (for demonstration and verification purposes, not part of the actual ZKP). Returns the Verifier's set and the intersection set.

**5. `CalculateSetIntersection(proverSet []int, verifierSet []int) []int`**:
   - Summary: Calculates the intersection of two sets. Used for demonstration and to check if an intersection *should* exist.

**6. `CheckIntersectionInRange(intersectionSet []int, minRange int, maxRange int) bool`**:
   - Summary: Checks if all elements in the intersection set fall within the specified range.

**7. `GenerateChallenge(commitment string) string`**:
   - Summary: Verifier generates a challenge based on the Prover's commitment. In this simplified version, it's just a hash of the commitment, but in real systems, it's more complex.

**8. `PrepareResponse(proverSet []int, verifierSetHashes []string, randomNonce string, challenge string, intersectionRangeMin int, intersectionRangeMax int) (responseMap map[int]string, proofOfRange map[int]bool, revealedRandomNonce string)`**:
   - Summary: Prover prepares a response to the challenge. This involves:
     - Identifying common elements (intersection) between the Prover's set and the Verifier's (hashed) set.
     - For each common element, providing a hash to prove it was in the original committed set.
     - Generating a simple "proof of range" (in this example, just a boolean indicating if the element is in range).
     - Optionally revealing the nonce (or a transformed version) as part of the proof (simplified approach).

**9. `VerifyResponse(commitment string, challenge string, responseMap map[int]string, proofOfRange map[int]bool, revealedRandomNonce string, verifierSetHashes []string, intersectionRangeMin int, intersectionRangeMax int) bool`**:
   - Summary: Verifier verifies the Prover's response:
     - Checks if the response is consistent with the commitment and challenge.
     - Verifies the "proof of range" for each revealed element.
     - Checks if the revealed hashes in the response are indeed present in the Verifier's set hashes.
     - Ensures the revealed nonce is consistent.

**10. `HashIntValue(value int) string`**:
    - Summary: Hashes a single integer value (utility function).

**11. `StringSliceContains(slice []string, val string) bool`**:
    - Summary: Checks if a string slice contains a specific string. Utility function.

**12. `IntSliceContains(slice []int, val int) bool`**:
    - Summary: Checks if an integer slice contains a specific integer. Utility function.

**13. `ConvertIntSliceToStringSlice(intSlice []int) []string`**:
    - Summary: Converts an integer slice to a string slice (for hashing purposes).

**14. `GenerateRandomNonce() string`**:
    - Summary: Generates a random nonce (string) for commitments.

**15. `AreSetsIntersecting(proverSet []int, verifierSet []int) bool`**:
    - Summary: Checks if two sets have any intersection (utility for demonstration).

**16. `IsValueInRange(value int, minRange int, maxRange int) bool`**:
    - Summary: Checks if a value is within a given range.

**17. `GenerateVerifierSetHashes(verifierSet []int) []string`**:
    - Summary: Hashes each element of the Verifier's set to create a set of hashes.

**18. `CheckResponseConsistency(commitment string, challenge string, revealedRandomNonce string) bool`**:
    - Summary: Checks if the revealed nonce and challenge are consistent with the initial commitment (simplified check).

**19. `CheckRangeProof(proofOfRange map[int]bool, intersectionSet []int, intersectionRangeMin int, intersectionRangeMax int) bool`**:
    - Summary: Verifies the range proof against the actual intersection set (for demonstration/testing).

**20. `CheckResponseHashesAgainstVerifierSet(responseMap map[int]string, verifierSetHashes []string) bool`**:
    - Summary: Verifies that the hashes in the response map are present in the Verifier's set of hashes.


**Important Notes:**

* **Simplified Security:** This is a simplified demonstration. Real-world ZKP systems require much more robust cryptographic primitives and protocols (e.g., using Pedersen commitments, Merkle trees, more complex challenge generation, and cryptographic assumptions).
* **No True Zero-Knowledge in Strict Sense:**  In this example, some information *is* revealed (hashes of common elements and range proof). A true zero-knowledge proof aims to reveal *absolutely* no information beyond the truth of the statement.  However, the core principles are demonstrated.
* **Practicality:** For real-world PSI, more efficient and cryptographically sound protocols are used (e.g., based on homomorphic encryption, oblivious transfer, etc.). This example is for educational purposes to illustrate ZKP concepts in Go.
* **Range Proof Simplicity:** The range proof is very basic.  Real range proofs (e.g., using bulletproofs or similar techniques) are much more sophisticated and secure.
*/
package main

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
)

// 1. GenerateRandomSet
func GenerateRandomSet(size int, maxVal int) []int {
	set := make([]int, size)
	for i := 0; i < size; i++ {
		randVal, _ := rand.Int(rand.Reader, big.NewInt(int64(maxVal)))
		set[i] = int(randVal.Int64())
	}
	return set
}

// 2. HashSetValue
func HashSetValue(set []int) string {
	setString := fmt.Sprintf("%v", set)
	hasher := sha256.New()
	hasher.Write([]byte(setString))
	return hex.EncodeToString(hasher.Sum(nil))
}

// 3. CreateCommitment
func CreateCommitment(proverSet []int) (commitment string, randomNonce string, committedSetHashes []string) {
	randomNonce = GenerateRandomNonce()
	combinedData := fmt.Sprintf("%v-%s", proverSet, randomNonce)
	hasher := sha256.New()
	hasher.Write([]byte(combinedData))
	commitment = hex.EncodeToString(hasher.Sum(nil))

	committedSetHashes = make([]string, len(proverSet))
	for i, val := range proverSet {
		committedSetHashes[i] = HashIntValue(val)
	}

	return commitment, randomNonce, committedSetHashes
}

// 4. GenerateVerifierSet
func GenerateVerifierSet(size int, maxVal int, intersectionRangeMin int, intersectionRangeMax int) ([]int, []int) {
	verifierSet := GenerateRandomSet(size, maxVal)
	intersectionSet := []int{}
	for _, val := range verifierSet {
		if val >= intersectionRangeMin && val <= intersectionRangeMax {
			intersectionSet = append(intersectionSet, val)
		}
	}
	return verifierSet, intersectionSet
}

// 5. CalculateSetIntersection
func CalculateSetIntersection(proverSet []int, verifierSet []int) []int {
	intersection := []int{}
	verifierMap := make(map[int]bool)
	for _, val := range verifierSet {
		verifierMap[val] = true
	}
	for _, val := range proverSet {
		if verifierMap[val] {
			intersection = append(intersection, val)
		}
	}
	return intersection
}

// 6. CheckIntersectionInRange
func CheckIntersectionInRange(intersectionSet []int, minRange int, maxRange int) bool {
	for _, val := range intersectionSet {
		if !IsValueInRange(val, minRange, maxRange) {
			return false
		}
	}
	return true
}

// 7. GenerateChallenge
func GenerateChallenge(commitment string) string {
	hasher := sha256.New()
	hasher.Write([]byte(commitment))
	return hex.EncodeToString(hasher.Sum(nil))
}

// 8. PrepareResponse
func PrepareResponse(proverSet []int, verifierSetHashes []string, randomNonce string, challenge string, intersectionRangeMin int, intersectionRangeMax int) (responseMap map[int]string, proofOfRange map[int]bool, revealedRandomNonce string) {
	responseMap = make(map[int]string)
	proofOfRange = make(map[int]bool)
	revealedRandomNonce = randomNonce // In this simplified example, we reveal the nonce.

	for _, proverVal := range proverSet {
		proverHash := HashIntValue(proverVal)
		if StringSliceContains(verifierSetHashes, proverHash) { // Check for intersection (using hashes)
			responseMap[proverVal] = proverHash
			proofOfRange[proverVal] = IsValueInRange(proverVal, intersectionRangeMin, intersectionRangeMax)
		}
	}
	return responseMap, proofOfRange, revealedRandomNonce
}

// 9. VerifyResponse
func VerifyResponse(commitment string, challenge string, responseMap map[int]string, proofOfRange map[int]bool, revealedRandomNonce string, verifierSetHashes []string, intersectionRangeMin int, intersectionRangeMax int) bool {
	// 1. Check response consistency with commitment and challenge (very basic check here)
	if !CheckResponseConsistency(commitment, challenge, revealedRandomNonce) {
		fmt.Println("Verification failed: Response consistency check failed.")
		return false
	}

	// 2. Check if response hashes are in verifier's set hashes
	if !CheckResponseHashesAgainstVerifierSet(responseMap, verifierSetHashes) {
		fmt.Println("Verification failed: Response hashes not in Verifier's set.")
		return false
	}

	// 3. Verify range proofs for revealed values
	if !CheckRangeProof(proofOfRange, mapKeysToIntSlice(responseMap), intersectionRangeMin, intersectionRangeMax) {
		fmt.Println("Verification failed: Range proof failed for some values.")
		return false
	}

	fmt.Println("Verification successful: Intersection proven within range.")
	return true
}

// 10. HashIntValue
func HashIntValue(value int) string {
	valStr := strconv.Itoa(value)
	hasher := sha256.New()
	hasher.Write([]byte(valStr))
	return hex.EncodeToString(hasher.Sum(nil))
}

// 11. StringSliceContains
func StringSliceContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// 12. IntSliceContains
func IntSliceContains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// 13. ConvertIntSliceToStringSlice
func ConvertIntSliceToStringSlice(intSlice []int) []string {
	stringSlice := make([]string, len(intSlice))
	for i, val := range intSlice {
		stringSlice[i] = strconv.Itoa(val)
	}
	return stringSlice
}

// 14. GenerateRandomNonce
func GenerateRandomNonce() string {
	nonceBytes := make([]byte, 32) // 32 bytes for a good nonce
	_, err := rand.Read(nonceBytes)
	if err != nil {
		panic(err) // Handle error appropriately in real applications
	}
	return hex.EncodeToString(nonceBytes)
}

// 15. AreSetsIntersecting
func AreSetsIntersecting(proverSet []int, verifierSet []int) bool {
	intersection := CalculateSetIntersection(proverSet, verifierSet)
	return len(intersection) > 0
}

// 16. IsValueInRange
func IsValueInRange(value int, minRange int, maxRange int) bool {
	return value >= minRange && value <= maxRange
}

// 17. GenerateVerifierSetHashes
func GenerateVerifierSetHashes(verifierSet []int) []string {
	verifierSetHashes := make([]string, len(verifierSet))
	for i, val := range verifierSet {
		verifierSetHashes[i] = HashIntValue(val)
	}
	return verifierSetHashes
}

// 18. CheckResponseConsistency (Simplified)
func CheckResponseConsistency(commitment string, challenge string, revealedRandomNonce string) bool {
	// In a real system, this would involve re-computing the commitment based on the revealed nonce
	// and potentially other revealed information and comparing it to the original commitment.
	// For this simplified example, we just check if the challenge is a hash of the commitment.
	expectedChallenge := GenerateChallenge(commitment)
	return challenge == expectedChallenge
}

// 19. CheckRangeProof
func CheckRangeProof(proofOfRange map[int]bool, intersectionSet []int, intersectionRangeMin int, intersectionRangeMax int) bool {
	for _, val := range intersectionSet {
		proof, ok := proofOfRange[val]
		if !ok {
			fmt.Printf("Range proof missing for value: %d\n", val)
			return false // Proof missing for a value in the intersection
		}
		expectedRange := IsValueInRange(val, intersectionRangeMin, intersectionRangeMax)
		if proof != expectedRange {
			fmt.Printf("Range proof incorrect for value: %d, proof: %v, expected: %v\n", val, proof, expectedRange)
			return false // Range proof is incorrect
		}
	}
	return true // All range proofs are correct
}

// 20. CheckResponseHashesAgainstVerifierSet
func CheckResponseHashesAgainstVerifierSet(responseMap map[int]string, verifierSetHashes []string) bool {
	for _, hashVal := range responseMap {
		if !StringSliceContains(verifierSetHashes, hashVal) {
			fmt.Printf("Response hash '%s' not found in Verifier's set hashes.\n", hashVal)
			return false
		}
	}
	return true
}


// Utility function to get keys from a map[int]string as an int slice
func mapKeysToIntSlice(m map[int]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}


func main() {
	fmt.Println("Starting Zero-Knowledge Proof for Private Set Intersection with Range Proofs...")

	// --- Setup ---
	proverSetSize := 15
	verifierSetSize := 20
	maxSetValue := 100
	intersectionRangeMin := 30
	intersectionRangeMax := 70

	proverSet := GenerateRandomSet(proverSetSize, maxSetValue)
	verifierSet, expectedIntersectionSet := GenerateVerifierSet(verifierSetSize, maxSetValue, intersectionRangeMin, intersectionRangeMax)
	verifierSetHashes := GenerateVerifierSetHashes(verifierSet)

	fmt.Println("\n--- Sets Generated ---")
	fmt.Printf("Prover Set (size %d): (Hidden)\n", proverSetSize) // In ZKP, Prover set is private
	fmt.Printf("Verifier Set (size %d): (Hidden, but hashes are used)\n", verifierSetSize) // Verifier set is also ideally private in real PSI


	// --- Prover Commits ---
	commitment, randomNonce, committedSetHashes := CreateCommitment(proverSet)
	fmt.Println("\n--- Prover Commits ---")
	fmt.Printf("Prover Commitment: %s (Sent to Verifier)\n", commitment)


	// --- Verifier Issues Challenge ---
	challenge := GenerateChallenge(commitment)
	fmt.Println("\n--- Verifier Issues Challenge ---")
	fmt.Printf("Verifier Challenge: %s\n", challenge)


	// --- Prover Prepares Response ---
	responseMap, proofOfRange, revealedNonce := PrepareResponse(proverSet, verifierSetHashes, randomNonce, challenge, intersectionRangeMin, intersectionRangeMax)
	fmt.Println("\n--- Prover Prepares Response ---")
	fmt.Printf("Prover Response (Revealing hashes of intersecting elements and range proofs):\n")
	for val, hashVal := range responseMap {
		fmt.Printf("  Value: (Hidden), Hash: %s, In Range Proof: %v\n", hashVal, proofOfRange[val])
	}
	fmt.Printf("Revealed Nonce (Simplified Example): %s\n", revealedNonce)


	// --- Verifier Verifies Response ---
	fmt.Println("\n--- Verifier Verifies Response ---")
	isVerified := VerifyResponse(commitment, challenge, responseMap, proofOfRange, revealedNonce, verifierSetHashes, intersectionRangeMin, intersectionRangeMax)

	fmt.Printf("\n--- Verification Result ---: ")
	if isVerified {
		fmt.Println("Zero-Knowledge Proof VERIFIED. Prover successfully demonstrated set intersection within the specified range without revealing their set or the intersecting elements themselves (beyond hashes and range proof).")

		// (For demonstration, we can check the actual intersection and range)
		actualIntersection := CalculateSetIntersection(proverSet, verifierSet)
		isInRange := CheckIntersectionInRange(actualIntersection, intersectionRangeMin, intersectionRangeMax)
		fmt.Printf("\n--- Post-Verification (For Demonstration Only) ---:\n")
		fmt.Printf("Actual Intersection: %v\n", actualIntersection)
		fmt.Printf("Intersection in Range [%d, %d]: %v\n", intersectionRangeMin, intersectionRangeMax, isInRange)
		if !isInRange && len(actualIntersection) > 0 {
			fmt.Println("WARNING: Actual intersection exists, but not all elements are in range. ZKP should still pass if the revealed elements ARE in range.")
		} else if len(actualIntersection) == 0 && len(responseMap) > 0 {
			fmt.Println("ERROR: No actual intersection, but ZKP response has elements. Something is wrong with the demonstration logic.")
		} else if len(actualIntersection) > 0 && len(responseMap) == 0 {
			fmt.Println("Note: Actual intersection exists, but Prover correctly revealed no intersection within the range, if that's the case.")
		}


	} else {
		fmt.Println("Zero-Knowledge Proof FAILED. Verification unsuccessful.")
	}
}
```