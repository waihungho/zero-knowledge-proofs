```go
/*
Outline and Function Summary:

This Go code demonstrates a collection of Zero-Knowledge Proof (ZKP) functions, focusing on creative and trendy applications beyond basic demonstrations.  These functions are designed to showcase the *concept* of ZKP in different scenarios, not to be cryptographically secure implementations for real-world use. They aim to be conceptually advanced and illustrate the potential of ZKP in various domains.

**Function Categories:**

1.  **Range Proofs (Simplified ZKP concept):**
    *   `ProveAgeRange(age int, minAge int, maxAge int) (proof string, publicInfo string)`: Proves age is within a range without revealing the exact age.
    *   `VerifyAgeRange(proof string, publicInfo string) bool`: Verifies the age range proof.
    *   `ProveSalaryRange(salary float64, minSalary float64, maxSalary float64) (proof string, publicInfo string)`: Proves salary is within a range without revealing the exact salary.
    *   `VerifySalaryRange(proof string, publicInfo string) bool`: Verifies the salary range proof.

2.  **Membership Proofs (Simplified ZKP concept):**
    *   `ProveEmailDomainMembership(email string, allowedDomains []string) (proof string, publicInfo string)`: Proves an email belongs to an allowed domain without revealing the full email.
    *   `VerifyEmailDomainMembership(proof string, publicInfo string) bool`: Verifies the email domain membership proof.
    *   `ProveIPLocationMembership(ipAddress string, allowedCountries []string, locationDB map[string]string) (proof string, publicInfo string)`: Proves an IP address originates from an allowed country without revealing the exact IP or country. (Uses a simplified location DB).
    *   `VerifyIPLocationMembership(proof string, publicInfo string) bool`: Verifies the IP location membership proof.

3.  **Property Proofs (Simplified ZKP concept):**
    *   `ProveNumberIsEven(number int) (proof string, publicInfo string)`: Proves a number is even without revealing the number itself.
    *   `VerifyNumberIsEven(proof string, publicInfo string) bool`: Verifies the number is even proof.
    *   `ProveStringLengthThreshold(text string, minLength int) (proof string, publicInfo string)`: Proves a string's length is above a threshold without revealing the string.
    *   `VerifyStringLengthThreshold(proof string, publicInfo string) bool`: Verifies the string length threshold proof.

4.  **Conditional Proofs (Simplified ZKP concept):**
    *   `ProveTransactionAmountAbove(transactionAmount float64, threshold float64, transactionID string) (proof string, publicInfo string)`:  Conditionally proves a transaction is above a threshold, revealing only transaction ID if true.
    *   `VerifyTransactionAmountAbove(proof string, publicInfo string) bool`: Verifies the conditional transaction amount proof.
    *   `ProveUserHasPremiumAccount(userID string, accountType string) (proof string, publicInfo string)`:  Proves a user has a premium account without revealing specific account details.
    *   `VerifyUserHasPremiumAccount(proof string, publicInfo string) bool`: Verifies the premium account proof.

5.  **Combined Proofs (Simplified ZKP concept):**
    *   `ProveAgeAndEmailDomain(age int, email string, minAge int, allowedDomains []string) (proof string, publicInfo string)`:  Combines age range and email domain membership proofs.
    *   `VerifyAgeAndEmailDomain(proof string, publicInfo string) bool`: Verifies the combined age and email domain proof.
    *   `ProveSalaryRangeAndLocation(salary float64, ipAddress string, minSalary float64, allowedCountries []string, locationDB map[string]string) (proof string, publicInfo string)`: Combines salary range and IP location proofs.
    *   `VerifySalaryRangeAndLocation(proof string, publicInfo string) bool`: Verifies the combined salary range and location proof.

**Important Notes:**

*   **Simplified Concept:** These functions are *not* cryptographically secure ZKP implementations. They demonstrate the *idea* of proving something without revealing underlying information using simple Go logic.  Real ZKPs require complex cryptography (e.g., zk-SNARKs, zk-STARKs, Bulletproofs).
*   **No Cryptographic Libraries:**  This code intentionally avoids external cryptographic libraries to keep the example focused on the conceptual logic of ZKP.
*   **Creative and Trendy Applications:** The functions are designed to be more imaginative than basic examples, touching upon areas like data privacy, conditional access, and verifiable credentials, which are relevant in today's tech landscape.
*   **Not Open Source Duplication:** These functions are designed to be unique examples for demonstration and learning purposes, not copies of existing open-source ZKP implementations.
*/

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// --- 1. Range Proofs ---

// ProveAgeRange proves that 'age' is within the range [minAge, maxAge] without revealing the exact age.
func ProveAgeRange(age int, minAge int, maxAge int) (proof string, publicInfo string) {
	if age >= minAge && age <= maxAge {
		proof = "AgeRangeProofValid" // Simplified proof, in real ZKP, this would be a complex cryptographic structure
		publicInfo = fmt.Sprintf("Range: [%d, %d]", minAge, maxAge)
		return proof, publicInfo
	}
	return "", "" // Proof failed
}

// VerifyAgeRange verifies the proof generated by ProveAgeRange.
func VerifyAgeRange(proof string, publicInfo string) bool {
	return proof == "AgeRangeProofValid" && strings.Contains(publicInfo, "Range:") // Basic verification
}

// ProveSalaryRange proves that 'salary' is within the range [minSalary, maxSalary] without revealing the exact salary.
func ProveSalaryRange(salary float64, minSalary float64, maxSalary float64) (proof string, publicInfo string) {
	if salary >= minSalary && salary <= maxSalary {
		proof = "SalaryRangeProofValid"
		publicInfo = fmt.Sprintf("Salary Range: [%.2f, %.2f]", minSalary, maxSalary)
		return proof, publicInfo
	}
	return "", ""
}

// VerifySalaryRange verifies the proof generated by ProveSalaryRange.
func VerifySalaryRange(proof string, publicInfo string) bool {
	return proof == "SalaryRangeProofValid" && strings.Contains(publicInfo, "Salary Range:")
}

// --- 2. Membership Proofs ---

// ProveEmailDomainMembership proves that the email belongs to one of the allowed domains without revealing the full email.
func ProveEmailDomainMembership(email string, allowedDomains []string) (proof string, publicInfo string) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", "" // Invalid email format
	}
	domain := parts[1]
	for _, allowedDomain := range allowedDomains {
		if domain == allowedDomain {
			proof = "EmailDomainMembershipProofValid"
			publicInfo = fmt.Sprintf("Allowed Domains: %v", allowedDomains)
			return proof, publicInfo
		}
	}
	return "", ""
}

// VerifyEmailDomainMembership verifies the proof generated by ProveEmailDomainMembership.
func VerifyEmailDomainMembership(proof string, publicInfo string) bool {
	return proof == "EmailDomainMembershipProofValid" && strings.Contains(publicInfo, "Allowed Domains:")
}

// ProveIPLocationMembership proves that the IP address is from an allowed country based on a simplified location DB.
func ProveIPLocationMembership(ipAddress string, allowedCountries []string, locationDB map[string]string) (proof string, publicInfo string) (string, string) {
	country, found := locationDB[ipAddress]
	if !found {
		return "", "" // IP not found in DB
	}
	for _, allowedCountry := range allowedCountries {
		if country == allowedCountry {
			proof = "IPLocationMembershipProofValid"
			publicInfo = fmt.Sprintf("Allowed Countries: %v", allowedCountries)
			return proof, publicInfo
		}
	}
	return "", ""
}

// VerifyIPLocationMembership verifies the proof generated by ProveIPLocationMembership.
func VerifyIPLocationMembership(proof string, publicInfo string) bool {
	return proof == "IPLocationMembershipProofValid" && strings.Contains(publicInfo, "Allowed Countries:")
}

// --- 3. Property Proofs ---

// ProveNumberIsEven proves that a number is even without revealing the number itself.
func ProveNumberIsEven(number int) (proof string, publicInfo string) {
	if number%2 == 0 {
		proof = "NumberIsEvenProofValid"
		publicInfo = "Property: Even Number"
		return proof, publicInfo
	}
	return "", ""
}

// VerifyNumberIsEven verifies the proof generated by ProveNumberIsEven.
func VerifyNumberIsEven(proof string, publicInfo string) bool {
	return proof == "NumberIsEvenProofValid" && strings.Contains(publicInfo, "Property: Even Number")
}

// ProveStringLengthThreshold proves that a string's length is above a minimum threshold without revealing the string.
func ProveStringLengthThreshold(text string, minLength int) (proof string, publicInfo string) {
	if len(text) >= minLength {
		proof = "StringLengthThresholdProofValid"
		publicInfo = fmt.Sprintf("Minimum Length: %d", minLength)
		return proof, publicInfo
	}
	return "", ""
}

// VerifyStringLengthThreshold verifies the proof generated by ProveStringLengthThreshold.
func VerifyStringLengthThreshold(proof string, publicInfo string) bool {
	return proof == "StringLengthThresholdProofValid" && strings.Contains(publicInfo, "Minimum Length:")
}

// --- 4. Conditional Proofs ---

// ProveTransactionAmountAbove conditionally proves a transaction is above a threshold, revealing only transaction ID if true.
func ProveTransactionAmountAbove(transactionAmount float64, threshold float64, transactionID string) (proof string, publicInfo string) {
	if transactionAmount > threshold {
		proof = "TransactionAmountAboveProofValid"
		publicInfo = fmt.Sprintf("Threshold: %.2f, Transaction ID: %s", threshold, transactionID) // Publicly reveal transaction ID if condition met
		return proof, publicInfo
	}
	return "", "" // Don't reveal transaction ID if condition not met
}

// VerifyTransactionAmountAbove verifies the proof generated by ProveTransactionAmountAbove.
func VerifyTransactionAmountAbove(proof string, publicInfo string) bool {
	return proof == "TransactionAmountAboveProofValid" && strings.Contains(publicInfo, "Threshold:") && strings.Contains(publicInfo, "Transaction ID:")
}

// ProveUserHasPremiumAccount proves a user has a premium account without revealing specific account details.
func ProveUserHasPremiumAccount(userID string, accountType string) (proof string, publicInfo string) {
	if accountType == "premium" {
		proof = "PremiumAccountProofValid"
		publicInfo = fmt.Sprintf("User ID Hash: %s", hashUserID(userID)) // Reveal a hash of user ID for audit purposes, not real ID
		return proof, publicInfo
	}
	return "", ""
}

// VerifyUserHasPremiumAccount verifies the proof generated by ProveUserHasPremiumAccount.
func VerifyUserHasPremiumAccount(proof string, publicInfo string) bool {
	return proof == "PremiumAccountProofValid" && strings.Contains(publicInfo, "User ID Hash:")
}

// Simplified hashing for UserID (not cryptographically secure for real use)
func hashUserID(userID string) string {
	// In real ZKP and security, use a proper cryptographic hash function.
	// This is just a simple example.
	var hashValue int = 0
	for _, char := range userID {
		hashValue = hashValue*31 + int(char) // Simple polynomial rolling hash
	}
	return strconv.Itoa(hashValue)
}

// --- 5. Combined Proofs ---

// ProveAgeAndEmailDomain combines age range and email domain membership proofs.
func ProveAgeAndEmailDomain(age int, email string, minAge int, allowedDomains []string) (proof string, publicInfo string) {
	ageProof, agePublicInfo := ProveAgeRange(age, minAge, 120) // Assuming max age 120 for demonstration
	emailProof, emailPublicInfo := ProveEmailDomainMembership(email, allowedDomains)

	if ageProof != "" && emailProof != "" {
		proof = "CombinedAgeEmailProofValid"
		publicInfo = fmt.Sprintf("Combined Proof: %s, %s", agePublicInfo, emailPublicInfo)
		return proof, publicInfo
	}
	return "", ""
}

// VerifyAgeAndEmailDomain verifies the proof generated by ProveAgeAndEmailDomain.
func VerifyAgeAndEmailDomain(proof string, publicInfo string) bool {
	return proof == "CombinedAgeEmailProofValid" && strings.Contains(publicInfo, "Combined Proof:") && strings.Contains(publicInfo, "Range:") && strings.Contains(publicInfo, "Allowed Domains:")
}

// ProveSalaryRangeAndLocation combines salary range and IP location proofs.
func ProveSalaryRangeAndLocation(salary float64, ipAddress string, minSalary float64, allowedCountries []string, locationDB map[string]string) (proof string, publicInfo string) {
	salaryProof, salaryPublicInfo := ProveSalaryRange(salary, minSalary, 1000000) // Assuming max salary for demo
	locationProof, locationPublicInfo := ProveIPLocationMembership(ipAddress, allowedCountries, locationDB)

	if salaryProof != "" && locationProof != "" {
		proof = "CombinedSalaryLocationProofValid"
		publicInfo = fmt.Sprintf("Combined Proof: %s, %s", salaryPublicInfo, locationPublicInfo)
		return proof, publicInfo
	}
	return "", ""
}

// VerifySalaryRangeAndLocation verifies the proof generated by ProveSalaryRangeAndLocation.
func VerifySalaryRangeAndLocation(proof string, publicInfo string) bool {
	return proof == "CombinedSalaryLocationProofValid" && strings.Contains(publicInfo, "Combined Proof:") && strings.Contains(publicInfo, "Salary Range:") && strings.Contains(publicInfo, "Allowed Countries:")
}

func main() {
	// Example Usage

	// Range Proofs
	ageProof, agePublicInfo := ProveAgeRange(30, 18, 65)
	fmt.Printf("Age Proof: %s, Public Info: %s, Verified: %t\n", ageProof, agePublicInfo, VerifyAgeRange(ageProof, agePublicInfo))
	salaryProof, salaryPublicInfo := ProveSalaryRange(75000.00, 50000.00, 150000.00)
	fmt.Printf("Salary Proof: %s, Public Info: %s, Verified: %t\n", salaryProof, salaryPublicInfo, VerifySalaryRange(salaryProof, salaryPublicInfo))

	// Membership Proofs
	emailProof, emailPublicInfo := ProveEmailDomainMembership("user@example.com", []string{"example.com", "domain.org"})
	fmt.Printf("Email Domain Proof: %s, Public Info: %s, Verified: %t\n", emailProof, emailPublicInfo, VerifyEmailDomainMembership(emailProof, emailPublicInfo))
	locationDB := map[string]string{"192.168.1.1": "USA", "10.0.0.1": "Canada"}
	ipProof, ipPublicInfo := ProveIPLocationMembership("192.168.1.1", []string{"USA", "UK"}, locationDB)
	fmt.Printf("IP Location Proof: %s, Public Info: %s, Verified: %t\n", ipProof, ipPublicInfo, VerifyIPLocationMembership(ipProof, ipPublicInfo))

	// Property Proofs
	evenProof, evenPublicInfo := ProveNumberIsEven(24)
	fmt.Printf("Even Number Proof: %s, Public Info: %s, Verified: %t\n", evenProof, evenPublicInfo, VerifyNumberIsEven(evenProof, evenPublicInfo))
	lengthProof, lengthPublicInfo := ProveStringLengthThreshold("long string", 10)
	fmt.Printf("String Length Proof: %s, Public Info: %s, Verified: %t\n", lengthProof, lengthPublicInfo, VerifyStringLengthThreshold(lengthProof, lengthPublicInfo))

	// Conditional Proofs
	transactionProof, transactionPublicInfo := ProveTransactionAmountAbove(1000.00, 500.00, "TXN123")
	fmt.Printf("Transaction Above Threshold Proof: %s, Public Info: %s, Verified: %t\n", transactionProof, transactionPublicInfo, VerifyTransactionAmountAbove(transactionProof, transactionPublicInfo))
	premiumProof, premiumPublicInfo := ProveUserHasPremiumAccount("user42", "premium")
	fmt.Printf("Premium Account Proof: %s, Public Info: %s, Verified: %t\n", premiumProof, premiumPublicInfo, VerifyUserHasPremiumAccount(premiumProof, premiumPublicInfo))

	// Combined Proofs
	combinedAgeEmailProof, combinedAgeEmailPublicInfo := ProveAgeAndEmailDomain(25, "test@domain.org", 21, []string{"domain.org", "otherdomain.net"})
	fmt.Printf("Combined Age & Email Proof: %s, Public Info: %s, Verified: %t\n", combinedAgeEmailProof, combinedAgeEmailPublicInfo, VerifyAgeAndEmailDomain(combinedAgeEmailProof, combinedAgeEmailPublicInfo))
	combinedSalaryLocationProof, combinedSalaryLocationPublicInfo := ProveSalaryRangeAndLocation(80000.00, "10.0.0.1", 60000.00, []string{"Canada", "USA"}, locationDB)
	fmt.Printf("Combined Salary & Location Proof: %s, Public Info: %s, Verified: %t\n", combinedSalaryLocationProof, combinedSalaryLocationPublicInfo, VerifySalaryRangeAndLocation(combinedSalaryLocationProof, combinedSalaryLocationPublicInfo))

	// Negative cases (proof should fail)
	failAgeProof, _ := ProveAgeRange(15, 18, 65)
	fmt.Printf("Failed Age Proof (Expected Fail): Proof: %s, Verified: %t\n", failAgeProof, VerifyAgeRange(failAgeProof, ""))
	failEmailProof, _ := ProveEmailDomainMembership("user@wrongdomain.net", []string{"example.com"})
	fmt.Printf("Failed Email Domain Proof (Expected Fail): Proof: %s, Verified: %t\n", failEmailProof, VerifyEmailDomainMembership(failEmailProof, ""))
}
```

**Explanation of the Code and ZKP Concepts Demonstrated:**

1.  **Simplified Proof Structure:** In each `Prove...` function, a simple string like `"AgeRangeProofValid"` is used as a "proof."  In real ZKP, this would be replaced with complex cryptographic data structures generated using algorithms like zk-SNARKs, zk-STARKs, or Bulletproofs.

2.  **Public Information:**  `publicInfo` is used to convey publicly known parameters related to the proof (e.g., the age range, allowed domains). This is analogous to public parameters in real ZKP systems.  Crucially, `publicInfo` does *not* reveal the secret itself (e.g., the exact age, the full email).

3.  **Verification Logic:**  `Verify...` functions check if the `proof` string is the expected value and if the `publicInfo` contains the expected parameters.  In a real ZKP system, verification would involve complex cryptographic calculations to mathematically ensure the proof's validity without needing to know the secret.

4.  **Zero-Knowledge Principle (Demonstrated Conceptually):**
    *   **Completeness:** If the statement is true (e.g., age is in range), the prover can generate a proof that the verifier will accept. (The `Prove...` functions return a valid proof string when conditions are met).
    *   **Soundness:** If the statement is false (e.g., age is *not* in range), it is computationally infeasible for a dishonest prover to create a proof that the verifier will accept (In our simplified example, the `Prove...` functions return an empty string when conditions are not met, so verification will fail).
    *   **Zero-Knowledge:** The verifier learns *only* whether the statement is true or false (e.g., age is within range), and learns *nothing* about the secret itself (e.g., the exact age).  Our `Verify...` functions only check the proof and public information, not the original secret data.

5.  **Trendy and Creative Functions:** The functions are designed to be more imaginative and relevant to modern applications than basic examples:
    *   **Range Proofs for Privacy:** Age and Salary range proofs are relevant in scenarios where you need to verify eligibility without revealing exact sensitive data.
    *   **Membership Proofs for Access Control:** Email domain and IP location membership proofs are useful for controlling access to resources based on group membership or geographic location without revealing full identities or locations.
    *   **Property Proofs for Data Integrity:** Proving properties like string length or number parity can be used in data validation and integrity checks without revealing the actual data.
    *   **Conditional Proofs for Dynamic Access:** Transaction amount and premium account proofs showcase conditional access and revealing limited information based on meeting certain criteria.
    *   **Combined Proofs for Complex Scenarios:** Combining multiple proofs allows for more complex and nuanced access control and verification scenarios.

**To reiterate, this code is for conceptual demonstration only.  For real-world secure Zero-Knowledge Proofs, you would need to use established cryptographic libraries and protocols like libsodium, go-ethereum/crypto (for some elliptic curve operations), and implement or use existing ZKP libraries and frameworks.**