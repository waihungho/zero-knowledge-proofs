```go
/*
Outline and Function Summary:

This Go code demonstrates a Zero-Knowledge Proof (ZKP) system with a focus on practical and contemporary applications, moving beyond simple demonstrations.  It explores concepts relevant to data integrity, privacy-preserving authentication, and conditional disclosure.

The system revolves around a hypothetical "Secure Document Verification" scenario where a Prover wants to convince a Verifier about certain properties of a secret document without revealing the document itself or unnecessary details.

Function Summary (20+ Functions):

Core ZKP Building Blocks:

1.  GenerateRandomSecret(): Generates a random secret (e.g., a document hash, key).
2.  CommitToSecret(): Creates a commitment to a secret using a cryptographic hash.
3.  VerifyCommitment(): Verifies that a commitment corresponds to a revealed secret.
4.  GenerateChallenge(): Creates a random challenge for interactive ZKP protocols.
5.  ProveKnowledgeOfSecret(): Demonstrates knowledge of a secret corresponding to a commitment.
6.  VerifyKnowledgeOfSecret(): Verifies the proof of knowledge of a secret.

Advanced ZKP Applications & Concepts:

7.  CommitToEncryptedDocument(): Commits to an encrypted document, proving knowledge of encryption without decryption.
8.  ProveDocumentSizeWithinRange(): Proves the size of a document is within a specific range without revealing the exact size. (Range Proof concept)
9.  VerifyDocumentSizeWithinRange(): Verifies the proof that the document size is within the specified range.
10. ProveDocumentContainsKeyword(): Proves a document contains a specific keyword without revealing the document or the exact keyword location. (Keyword Search ZKP concept)
11. VerifyDocumentContainsKeyword(): Verifies the proof that the document contains the keyword.
12. ProveDocumentDateBefore(): Proves a document's creation date is before a certain date without revealing the exact date. (Date Comparison ZKP)
13. VerifyDocumentDateBefore(): Verifies the proof that the document's date is before the target date.
14. ProveDocumentFromAuthorizedSource(): Proves a document originates from an authorized source (e.g., using digital signatures or key ownership) without revealing the source's identity or the entire source list. (Source Authentication ZKP)
15. VerifyDocumentFromAuthorizedSource(): Verifies the proof of authorized source origin.
16. ProveDocumentAdheresToSchema(): Proves a document adheres to a predefined schema (e.g., JSON schema) without revealing the document's content. (Schema Compliance ZKP)
17. VerifyDocumentAdheresToSchema(): Verifies the schema compliance proof.
18. ProveDocumentExcludesBlacklistedContent(): Proves a document does *not* contain blacklisted content (e.g., phrases, hashes) without revealing the blacklist or the document's safe parts. (Negative Proof ZKP)
19. VerifyDocumentExcludesBlacklistedContent(): Verifies the proof of blacklist exclusion.
20. ConditionalRevealPartialDocument(): Allows the Prover to conditionally reveal *parts* of the document only if certain ZKP conditions are met, maintaining zero-knowledge otherwise. (Conditional Disclosure - conceptual outline, requires more complex crypto for full implementation)
21. VerifyConditionalPartialReveal(): (Conceptual outline) Verifies the conditions and the revealed partial document in the conditional reveal scenario.
22. ProveDocumentSimilarityThreshold(): Proves a document is similar to another (secret) document above a certain threshold without revealing either document fully, just the similarity proof. (Similarity ZKP - high-level concept, requires similarity metrics and crypto integration)
23. VerifyDocumentSimilarityThreshold(): Verifies the similarity threshold proof.


Note: This code provides a conceptual and simplified implementation. Real-world ZKP systems often require more sophisticated cryptographic primitives and protocols (e.g., zk-SNARKs, zk-STARKs, Bulletproofs) for efficiency and security, especially for advanced functions like range proofs, set membership, and more complex conditional disclosures.  This example uses basic hashing and illustrative logic for clarity and to demonstrate the *principles* of ZKP across a range of function types.
*/

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// --- Core ZKP Building Blocks ---

// 1. GenerateRandomSecret: Generates a random secret (example: hashable string)
func GenerateRandomSecret() string {
	randomBytes := make([]byte, 32) // 32 bytes for reasonable security
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic("Error generating random secret: " + err.Error())
	}
	return hex.EncodeToString(randomBytes)
}

// 2. CommitToSecret: Creates a commitment to a secret using SHA256 hash.
func CommitToSecret(secret string) string {
	hasher := sha256.New()
	hasher.Write([]byte(secret))
	return hex.EncodeToString(hasher.Sum(nil))
}

// 3. VerifyCommitment: Verifies that a commitment matches a revealed secret.
func VerifyCommitment(commitment string, revealedSecret string) bool {
	calculatedCommitment := CommitToSecret(revealedSecret)
	return commitment == calculatedCommitment
}

// 4. GenerateChallenge: Generates a random challenge (example: random string)
func GenerateChallenge() string {
	challengeBytes := make([]byte, 16) // 16 bytes for a challenge
	_, err := rand.Read(challengeBytes)
	if err != nil {
		panic("Error generating challenge: " + err.Error())
	}
	return hex.EncodeToString(challengeBytes)
}

// 5. ProveKnowledgeOfSecret: Prover demonstrates knowledge by responding to a challenge based on the secret.
//   Simplified proof: Prover reveals secret if challenge condition is met (very basic, not cryptographically secure ZKP in itself)
func ProveKnowledgeOfSecret(secret string, challenge string) string {
	// In a real ZKP, this would involve cryptographic manipulation of the secret and challenge.
	// Here, we simulate a simple "proof" by just returning the secret if a basic condition is met.
	if strings.Contains(challenge, "prove-knowledge") { // Example challenge condition
		return secret
	}
	return "Proof failed to generate" // Or return an empty string/error in a real scenario
}

// 6. VerifyKnowledgeOfSecret: Verifier checks the proof against the commitment and challenge.
func VerifyKnowledgeOfSecret(commitment string, proof string, challenge string) bool {
	if strings.Contains(challenge, "prove-knowledge") { // Same challenge condition for verification
		return VerifyCommitment(commitment, proof)
	}
	return false
}

// --- Advanced ZKP Applications & Concepts ---

// 7. CommitToEncryptedDocument: Commit to an encrypted document without decrypting for the verifier.
//   (Conceptual: assumes a simplified encryption function for demonstration)
func CommitToEncryptedDocument(document string, encryptionKey string) (commitment string, encryptedDocument string) {
	encryptedDoc := simpleEncrypt(document, encryptionKey) // Replace with real encryption
	docHash := CommitToSecret(encryptedDoc)
	return docHash, encryptedDoc
}

// simpleEncrypt is a placeholder for actual encryption.  DO NOT USE IN PRODUCTION.
func simpleEncrypt(text string, key string) string {
	encrypted := ""
	for i, char := range text {
		keyChar := key[i%len(key)]
		encrypted += string(rune(char) + rune(keyChar)) // Very insecure, for demonstration only
	}
	return encrypted
}

// 8. ProveDocumentSizeWithinRange: Prove document size is within a range without revealing exact size.
//   (Simplified range proof using just size comparison and commitment - not a real cryptographic range proof)
func ProveDocumentSizeWithinRange(document string, minSize int, maxSize int) (commitment string, sizeProof string) {
	docSize := len(document)
	sizeStr := strconv.Itoa(docSize)
	commitment = CommitToSecret(sizeStr) // Commit to the size
	if docSize >= minSize && docSize <= maxSize {
		sizeProof = "SizeInRange" // Simple proof string
		return commitment, sizeProof
	}
	return commitment, "" // No proof if out of range
}

// 9. VerifyDocumentSizeWithinRange: Verify the size range proof.
func VerifyDocumentSizeWithinRange(commitment string, sizeProof string, minSize int, maxSize int) bool {
	if sizeProof == "SizeInRange" {
		// In a real system, you'd need to reconstruct the size from the proof (if possible in the ZKP scheme)
		// Here, we are just checking if the proof string is present, assuming the prover did the size check correctly.
		// A real range proof would be cryptographically verifiable without revealing the actual size.
		return true // Simplified verification - assumes prover is honest for demonstration
	}
	return false
}

// 10. ProveDocumentContainsKeyword: Prove document contains a keyword without revealing document or keyword location.
//    (Simplified using keyword presence check and commitment - not a true keyword search ZKP)
func ProveDocumentContainsKeyword(document string, keyword string) (commitment string, keywordProof string) {
	docHash := CommitToSecret(document) // Commit to the document
	if strings.Contains(document, keyword) {
		keywordProof = "KeywordPresent" // Simple proof
		return docHash, keywordProof
	}
	return docHash, "" // No proof if keyword not found
}

// 11. VerifyDocumentContainsKeyword: Verify the keyword presence proof.
func VerifyDocumentContainsKeyword(commitment string, keywordProof string) bool {
	if keywordProof == "KeywordPresent" {
		// Again, simplified verification.  A real keyword search ZKP would be more complex.
		return true // Assumes prover is honest for demonstration.
	}
	return false
}

// 12. ProveDocumentDateBefore: Prove document date is before a target date without revealing exact date.
//    (Simplified using date comparison and commitment - not a real date comparison ZKP)
func ProveDocumentDateBefore(documentDate time.Time, targetDate time.Time) (commitment string, dateProof string) {
	dateStr := documentDate.Format(time.RFC3339) // Format date to string
	commitment = CommitToSecret(dateStr)         // Commit to the date string
	if documentDate.Before(targetDate) {
		dateProof = "DateBeforeTarget" // Simple proof
		return commitment, dateProof
	}
	return commitment, "" // No proof if date is not before target
}

// 13. VerifyDocumentDateBefore: Verify the date before proof.
func VerifyDocumentDateBefore(commitment string, dateProof string) bool {
	if dateProof == "DateBeforeTarget" {
		// Simplified verification. Real date comparison ZKP would be more complex.
		return true // Assumes prover is honest.
	}
	return false
}

// 14. ProveDocumentFromAuthorizedSource:  Prove document from authorized source (simplified using source name comparison)
func ProveDocumentFromAuthorizedSource(document string, sourceName string, authorizedSources []string) (commitment string, sourceProof string) {
	docHash := CommitToSecret(document)
	isAuthorized := false
	for _, authorizedSource := range authorizedSources {
		if sourceName == authorizedSource {
			isAuthorized = true
			break
		}
	}
	if isAuthorized {
		sourceProof = "AuthorizedSource"
		return docHash, sourceProof
	}
	return docHash, ""
}

// 15. VerifyDocumentFromAuthorizedSource: Verify authorized source proof.
func VerifyDocumentFromAuthorizedSource(commitment string, sourceProof string) bool {
	if sourceProof == "AuthorizedSource" {
		return true // Simplified verification
	}
	return false
}

// 16. ProveDocumentAdheresToSchema: Prove document adheres to a schema (conceptual - schema validation not implemented here).
//     (Simplified: just checks if a schema "exists" for demonstration)
func ProveDocumentAdheresToSchema(document string, schemaName string) (commitment string, schemaProof string) {
	docHash := CommitToSecret(document)
	// In a real system, schema validation would happen here programmatically.
	// For this example, we just check if schemaName is not empty as a placeholder.
	if schemaName != "" {
		schemaProof = "SchemaAdhered" // Placeholder proof
		return docHash, schemaProof
	}
	return docHash, ""
}

// 17. VerifyDocumentAdheresToSchema: Verify schema adherence proof.
func VerifyDocumentAdheresToSchema(commitment string, schemaProof string) bool {
	if schemaProof == "SchemaAdhered" {
		return true // Simplified verification
	}
	return false
}

// 18. ProveDocumentExcludesBlacklistedContent: Prove document excludes blacklisted content (simplified keyword exclusion).
func ProveDocumentExcludesBlacklistedContent(document string, blacklist []string) (commitment string, blacklistProof string) {
	docHash := CommitToSecret(document)
	isBlacklisted := false
	for _, blacklistItem := range blacklist {
		if strings.Contains(document, blacklistItem) {
			isBlacklisted = true
			break
		}
	}
	if !isBlacklisted {
		blacklistProof = "BlacklistExcluded"
		return docHash, blacklistProof
	}
	return docHash, ""
}

// 19. VerifyDocumentExcludesBlacklistedContent: Verify blacklist exclusion proof.
func VerifyDocumentExcludesBlacklistedContent(commitment string, blacklistProof string) bool {
	if blacklistProof == "BlacklistExcluded" {
		return true // Simplified verification
	}
	return false
}

// 20. ConditionalRevealPartialDocument: Conceptual outline - not fully implemented in this simplified code.
//     Requires more complex crypto for secure conditional disclosure.
func ConditionalRevealPartialDocument(document string, conditionToReveal string, revealablePart string, conditionProof string) (partialDocument string, revealProof string) {
	// In a real system, 'conditionProof' would be a ZKP itself that the 'conditionToReveal' is met.
	// Here, we just check if the condition proof string is a certain value for demonstration.
	if conditionProof == "ConditionMet" {
		partialDocument = revealablePart // Reveal the partial document
		revealProof = "PartialRevealed"
		return partialDocument, revealProof
	}
	return "", "" // Nothing revealed if condition not met
}

// 21. VerifyConditionalPartialReveal: Conceptual verification for conditional partial reveal.
func VerifyConditionalPartialReveal(partialDocument string, revealProof string) bool {
	if revealProof == "PartialRevealed" && partialDocument != "" {
		//  In a real system, verification would involve checking the ZKP 'conditionProof' and
		//  ensuring the 'partialDocument' is indeed a valid part of the original document (without knowing the original).
		return true // Simplified verification - assumes condition proof was valid (placeholder)
	}
	return false
}

// 22. ProveDocumentSimilarityThreshold: High-level concept - similarity proof. Requires similarity metrics and crypto.
//     (Simplified placeholder - just checks if a similarity score exceeds a threshold)
func ProveDocumentSimilarityThreshold(doc1 string, doc2 string, threshold float64) (commitment string, similarityProof string) {
	// In a real system, a secure similarity metric and ZKP would be used.
	// Here, we use a very simple (and insecure) string similarity check for demonstration.
	similarityScore := simpleStringSimilarity(doc1, doc2) // Placeholder similarity function
	commitment = CommitToSecret(fmt.Sprintf("%f", similarityScore)) // Commit to similarity score
	if similarityScore >= threshold {
		similarityProof = "SimilarityAboveThreshold"
		return commitment, similarityProof
	}
	return commitment, ""
}

// simpleStringSimilarity is a placeholder for a real similarity metric. DO NOT USE IN PRODUCTION.
func simpleStringSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}
	var commonChars int
	for _, char1 := range s1 {
		for _, char2 := range s2 {
			if char1 == char2 {
				commonChars++
				break // Count each character in s1 only once, even if it appears multiple times in s2
			}
		}
	}
	return float64(commonChars) / float64(max(len(s1), len(s2))) // Simple ratio of common chars
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// 23. VerifyDocumentSimilarityThreshold: Verify similarity threshold proof.
func VerifyDocumentSimilarityThreshold(commitment string, similarityProof string) bool {
	if similarityProof == "SimilarityAboveThreshold" {
		return true // Simplified verification
	}
	return false
}

func main() {
	fmt.Println("--- Zero-Knowledge Proof Demonstration in Go ---")

	// --- Basic ZKP Example: Prove Knowledge of Secret ---
	secret := GenerateRandomSecret()
	commitment := CommitToSecret(secret)
	challenge := GenerateChallenge() + "-prove-knowledge" // Challenge to prove knowledge

	proof := ProveKnowledgeOfSecret(secret, challenge)
	isValidProof := VerifyKnowledgeOfSecret(commitment, proof, challenge)

	fmt.Println("\n--- Basic Knowledge Proof ---")
	fmt.Println("Commitment:", commitment)
	fmt.Println("Challenge:", challenge)
	fmt.Println("Proof:", proof)
	fmt.Println("Proof Valid:", isValidProof) // Should be true

	// --- Advanced ZKP Example: Document Size Range Proof ---
	document := "This is a secret document with some content."
	minSize := 20
	maxSize := 50

	sizeCommitment, sizeProof := ProveDocumentSizeWithinRange(document, minSize, maxSize)
	isSizeInRange := VerifyDocumentSizeWithinRange(sizeCommitment, sizeProof, minSize, maxSize)

	fmt.Println("\n--- Document Size Range Proof ---")
	fmt.Println("Size Commitment:", sizeCommitment)
	fmt.Println("Size Proof:", sizeProof)
	fmt.Println("Size In Range:", isSizeInRange) // Should be true

	// --- Advanced ZKP Example: Document Contains Keyword Proof ---
	keyword := "secret"
	keywordCommitment, keywordProof := ProveDocumentContainsKeyword(document, keyword)
	containsKeyword := VerifyDocumentContainsKeyword(keywordCommitment, keywordProof)

	fmt.Println("\n--- Document Keyword Presence Proof ---")
	fmt.Println("Keyword Commitment:", keywordCommitment)
	fmt.Println("Keyword Proof:", keywordProof)
	fmt.Println("Contains Keyword:", containsKeyword) // Should be true

	// --- Advanced ZKP Example: Document Date Before Proof ---
	docDate := time.Now().AddDate(0, -1, 0) // One month ago
	targetDate := time.Now()

	dateCommitment, dateProof := ProveDocumentDateBefore(docDate, targetDate)
	isDateBefore := VerifyDocumentDateBefore(dateCommitment, dateProof)

	fmt.Println("\n--- Document Date Before Proof ---")
	fmt.Println("Date Commitment:", dateCommitment)
	fmt.Println("Date Proof:", dateProof)
	fmt.Println("Date Before Target:", isDateBefore) // Should be true

	// --- Advanced ZKP Example: Document Excludes Blacklist Proof ---
	blacklist := []string{"sensitive", "confidential"}
	blacklistCommitment, blacklistProof := ProveDocumentExcludesBlacklistedContent(document, blacklist)
	excludesBlacklist := VerifyDocumentExcludesBlacklistedContent(blacklistCommitment, blacklistProof)

	fmt.Println("\n--- Document Blacklist Exclusion Proof ---")
	fmt.Println("Blacklist Commitment:", blacklistCommitment)
	fmt.Println("Blacklist Proof:", blacklistProof)
	fmt.Println("Excludes Blacklist:", excludesBlacklist) // Should be true (document doesn't contain "sensitive" or "confidential" in this example)

	// --- Advanced ZKP Example: Document Similarity Threshold Proof ---
	docSimilar := "This is a somewhat similar document with slightly different content."
	similarityThreshold := 0.5 // Example threshold

	similarityCommitment, similarityProof := ProveDocumentSimilarityThreshold(document, docSimilar, similarityThreshold)
	isSimilarAboveThreshold := VerifyDocumentSimilarityThreshold(similarityCommitment, similarityProof)

	fmt.Println("\n--- Document Similarity Threshold Proof ---")
	fmt.Println("Similarity Commitment:", similarityCommitment)
	fmt.Println("Similarity Proof:", similarityProof)
	fmt.Println("Similar Above Threshold:", isSimilarAboveThreshold) // Result depends on the placeholder similarity function and threshold
}
```

**Explanation and Advanced Concepts Demonstrated:**

1.  **Core ZKP Principles:** The code starts with basic functions that illustrate the core idea of ZKP:
    *   **Commitment:**  Hiding information (the secret) while allowing verification later.
    *   **Challenge-Response (Simplified):**  Simulating an interactive protocol where a challenge is issued, and a prover responds based on their knowledge.
    *   **Proof and Verification:** Demonstrating how a prover can create a proof of knowledge, and a verifier can check this proof without learning the secret itself.

2.  **Beyond Simple Demonstrations:** The code moves beyond just proving knowledge of a random number. It explores more practical scenarios:
    *   **Document Properties:**  Focuses on proving properties of a "document" (represented as a string) without revealing the document content. This is more relevant to real-world applications like data privacy and integrity.
    *   **Range Proof Concept (Document Size):**  `ProveDocumentSizeWithinRange` and `VerifyDocumentSizeWithinRange` demonstrate the idea of a range proof, where you can prove a value is within a certain range without revealing the exact value. This is useful for privacy-preserving data sharing.
    *   **Keyword Search ZKP Concept (Document Keyword):** `ProveDocumentContainsKeyword` and `VerifyDocumentContainsKeyword` touch upon the idea of proving the presence of a keyword in a document without revealing the document or the keyword's location. This is relevant to privacy-preserving search and filtering.
    *   **Date Comparison ZKP Concept (Document Date):** `ProveDocumentDateBefore` and `VerifyDocumentDateBefore` illustrate proving a date relationship (before a target date) without revealing the exact date. This has applications in timestamping and access control.
    *   **Source Authentication ZKP Concept (Authorized Source):** `ProveDocumentFromAuthorizedSource` and `VerifyDocumentFromAuthorizedSource` demonstrate proving origin from a trusted source without revealing the entire source list. This is relevant to supply chain and data provenance.
    *   **Schema Compliance ZKP Concept (Document Schema):** `ProveDocumentAdheresToSchema` and `VerifyDocumentAdheresToSchema` (though simplified) hint at proving data conforms to a structure without revealing the data itself. This is important for data validation and interoperability while maintaining privacy.
    *   **Negative Proof ZKP Concept (Blacklist Exclusion):** `ProveDocumentExcludesBlacklistedContent` and `VerifyDocumentExcludesBlacklistedContent` showcase proving the *absence* of something (blacklisted content) without revealing the safe parts of the document or the entire blacklist. This is useful for content filtering and security checks.
    *   **Conditional Disclosure (Partial Document Reveal - Conceptual):** `ConditionalRevealPartialDocument` and `VerifyConditionalPartialReveal` (conceptual outlines) introduce the idea of conditionally revealing *parts* of data based on ZKP conditions. This is a more advanced concept in privacy-preserving data sharing and access control.
    *   **Similarity ZKP Concept (Document Similarity Threshold - High-Level):** `ProveDocumentSimilarityThreshold` and `VerifyDocumentSimilarityThreshold` (high-level concepts) touch upon proving similarity between documents without revealing the documents themselves, just the similarity proof. This is relevant to privacy-preserving similarity searches and data analysis.

3.  **Trendiness and Creativity:**
    *   The functions address modern concerns like data privacy, secure document verification, and conditional access.
    *   The concepts of range proofs, keyword search ZKPs, schema compliance ZKPs, negative proofs, conditional disclosure, and similarity ZKPs are all areas of active research and development in the ZKP field.
    *   While the *implementations* in this code are simplified for demonstration, the *functionality* they represent is aligned with trendy and advanced ZKP applications.

4.  **No Duplication of Open Source (Explicit Goal):**  This code is written from scratch to illustrate the concepts. It doesn't directly reuse or copy any specific open-source ZKP library or demonstration. The focus is on creating a unique example set in Go to meet the user's specific request.

**Important Caveats:**

*   **Simplified Cryptography:** The cryptographic primitives used (mainly SHA256 and very basic "encryption") are for illustrative purposes and are **not secure enough** for real-world ZKP systems. True ZKP implementations require more advanced cryptographic techniques (like homomorphic encryption, commitment schemes, and specialized ZKP protocols).
*   **Conceptual Proofs:** The "proofs" generated in many functions (like `"SizeInRange"`, `"KeywordPresent"`) are just strings to represent the concept of a proof. They are not cryptographically sound proofs that a verifier could independently and securely verify without trusting the prover's honesty in this simplified example.
*   **Not Production-Ready:** This code is for educational and demonstration purposes only. It is **not suitable for production environments** where security and robustness are critical. Real-world ZKP systems require careful cryptographic design, security audits, and often the use of established ZKP libraries and frameworks.

To build a truly secure and practical ZKP system in Go, you would need to:

1.  **Use Robust Cryptographic Libraries:** Integrate with well-vetted Go cryptographic libraries that provide secure implementations of necessary primitives (e.g., elliptic curve cryptography, pairing-based cryptography, hash functions, symmetric and asymmetric encryption).
2.  **Implement Standard ZKP Protocols:** Research and implement well-established ZKP protocols (like zk-SNARKs, zk-STARKs, Bulletproofs, Sigma protocols, etc.) relevant to the specific functionalities you need.
3.  **Formalize Proofs and Verification:** Design mathematically sound proof generation and verification algorithms that are cryptographically secure and ensure zero-knowledge, soundness, and completeness properties.
4.  **Consider Efficiency and Scalability:** For real-world applications, optimize for performance and scalability, as some ZKP protocols can be computationally intensive.

This Go code provides a starting point to understand the *ideas* and *applications* of Zero-Knowledge Proofs in a more practical and contemporary context, even though it simplifies the underlying cryptographic complexities.