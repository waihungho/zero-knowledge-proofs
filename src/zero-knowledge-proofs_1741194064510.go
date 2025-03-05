```go
/*
Outline and Function Summary:

This Go program demonstrates a Zero-Knowledge Proof (ZKP) system for a "Private Data Range Compliance" scenario.
Imagine a system where users need to prove their private data (e.g., credit score, income, age) falls within a specific range to comply with certain regulations or access services, WITHOUT revealing the exact data itself.

This system utilizes a simplified ZKP protocol based on commitments and hash functions for demonstration purposes.
It's NOT intended for production cryptographic security but to illustrate the functional flow and concept of ZKP in a creative application.

**Core Concept:** Proving data is within a range without revealing the data.

**Actors:**
- Prover: The entity with the private data who wants to prove compliance.
- Verifier: The entity that needs to verify compliance without learning the private data.

**Functions (20+):**

**1. Setup and Initialization:**
    - GenerateParameters(): Generates necessary cryptographic parameters (in this simplified example, mainly for demonstration, could be expanded for real crypto).
    - CreateProver(): Initializes a Prover struct.
    - CreateVerifier(): Initializes a Verifier struct.

**2. Prover-Side Functions:**
    - PreparePrivateData(data int): Prepares the private data for the ZKP process (e.g., encoding, could be more complex in real scenarios).
    - CommitToPrivateData(data int, params Parameters): Creates a commitment to the private data. This hides the data from the verifier initially.
    - GenerateRangeProof(data int, lowerBound int, upperBound int, params Parameters, commitment Commitment): Generates the core ZKP proof that the data is within the specified range.
    - CreateProofRequest(commitment Commitment, proof RangeProof, rangeSpec RangeSpec): Packages the commitment, proof, and range specification into a request for the verifier.
    - SendProofRequest(request ProofRequest, verifier Verifier): Simulates sending the proof request to the verifier. (In a real system, this would be network communication).

**3. Verifier-Side Functions:**
    - ReceiveProofRequest(request ProofRequest): Simulates receiving the proof request from the prover. (In a real system, this would be network reception).
    - ExtractCommitmentFromRequest(request ProofRequest): Extracts the commitment from the received request.
    - ExtractRangeSpecFromRequest(request ProofRequest): Extracts the range specification from the received request.
    - ExtractProofFromRequest(request ProofRequest): Extracts the range proof from the received request.
    - VerifyRangeProof(commitment Commitment, proof RangeProof, rangeSpec RangeSpec, params Parameters): Verifies the ZKP proof against the commitment and range specification. This is the core verification logic.
    - CheckCommitmentValidity(commitment Commitment, params Parameters): Optional: Checks if the commitment itself is valid (e.g., well-formed).
    - IsProofRequestValid(request ProofRequest, params Parameters): Orchestrates the entire proof request validation process on the verifier side.
    - ProcessComplianceResult(isValid bool): Processes the result of the compliance verification (e.g., grant access if valid).

**4. Data Structures and Helpers:**
    - Parameters: Struct to hold cryptographic parameters (currently simplified).
    - Commitment: Struct to represent a commitment to private data.
    - RangeProof: Struct to represent the Zero-Knowledge Range Proof.
    - RangeSpec: Struct to define the allowed data range (lower and upper bounds).
    - ProofRequest: Struct to encapsulate the proof request sent from Prover to Verifier.
    - hashData(data string): Helper function to hash data (using SHA-256 for simplicity).
    - generateRandomValue(): Helper to generate random values (for demonstration, could be more robust in real crypto).


**Important Notes:**

- **Simplified ZKP:** This is a highly simplified and conceptual ZKP implementation for educational and illustrative purposes. It does NOT use advanced cryptographic techniques like zk-SNARKs, zk-STARKs, or Bulletproofs which are used in real-world ZKP systems for efficiency and security.
- **Security:** This example is NOT cryptographically secure for real-world applications.  A real ZKP system would require careful cryptographic design and implementation using well-established ZKP protocols and libraries.
- **Focus on Functionality:** The primary goal is to demonstrate the *flow* of a ZKP system and how different functions interact to achieve zero-knowledge range proof functionality, not to build a production-ready secure system.
- **Creative Application:** The "Private Data Range Compliance" scenario is a creative and trendy application area for ZKP as privacy-preserving data handling becomes increasingly important.
*/

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

// --- Data Structures ---

// Parameters represent cryptographic parameters (simplified in this example)
type Parameters struct {
	// In a real ZKP system, this would contain group parameters, generators, etc.
	Salt string // Just a salt for demonstration
}

// Commitment represents a commitment to private data
type Commitment struct {
	CommitmentValue string // Hash of the data + salt (simplified commitment)
}

// RangeProof represents the Zero-Knowledge Range Proof (simplified and not cryptographically secure)
type RangeProof struct {
	ChallengeResponse string //  Simplified response based on data and range
}

// RangeSpec defines the allowed data range
type RangeSpec struct {
	LowerBound int
	UpperBound int
}

// ProofRequest encapsulates the proof request sent from Prover to Verifier
type ProofRequest struct {
	Commitment Commitment
	Proof      RangeProof
	RangeSpec  RangeSpec
}

// --- Actors ---

// Prover represents the entity with private data
type Prover struct {
	ID string
}

// Verifier represents the entity that verifies compliance
type Verifier struct {
	ID string
}

// --- 1. Setup and Initialization ---

// GenerateParameters creates simplified parameters
func GenerateParameters() Parameters {
	return Parameters{
		Salt: generateRandomValue(), // Simple salt for demonstration
	}
}

// CreateProver initializes a Prover
func CreateProver(id string) Prover {
	return Prover{ID: id}
}

// CreateVerifier initializes a Verifier
func CreateVerifier(id string) Verifier {
	return Verifier{ID: id}
}

// --- 2. Prover-Side Functions ---

// PreparePrivateData prepares the private data (currently just returns the data itself)
func (p Prover) PreparePrivateData(data int) int {
	// In a real system, this might involve encoding, formatting, etc.
	return data
}

// CommitToPrivateData creates a commitment to the private data (simplified hashing)
func (p Prover) CommitToPrivateData(data int, params Parameters) Commitment {
	dataStr := strconv.Itoa(data)
	combinedData := dataStr + params.Salt // Simple combination with salt
	commitmentValue := hashData(combinedData)
	return Commitment{CommitmentValue: commitmentValue}
}

// GenerateRangeProof generates a simplified range proof
func (p Prover) GenerateRangeProof(data int, lowerBound int, upperBound int, params Parameters, commitment Commitment) RangeProof {
	// Simplified proof generation:  Hash of (data, lowerBound, upperBound, salt) if data is in range
	if data >= lowerBound && data <= upperBound {
		proofData := strconv.Itoa(data) + strconv.Itoa(lowerBound) + strconv.Itoa(upperBound) + params.Salt
		challengeResponse := hashData(proofData)
		return RangeProof{ChallengeResponse: challengeResponse}
	}
	return RangeProof{ChallengeResponse: ""} // Empty proof if out of range (for simplicity, real system would handle this differently)
}

// CreateProofRequest packages the proof components
func (p Prover) CreateProofRequest(commitment Commitment, proof RangeProof, rangeSpec RangeSpec) ProofRequest {
	return ProofRequest{
		Commitment: commitment,
		Proof:      proof,
		RangeSpec:  rangeSpec,
	}
}

// SendProofRequest simulates sending the request to the verifier
func (p Prover) SendProofRequest(request ProofRequest, verifier Verifier) {
	fmt.Printf("Prover '%s' sending Proof Request to Verifier '%s'\n", p.ID, verifier.ID)
	verifier.ReceiveProofRequest(request)
}

// --- 3. Verifier-Side Functions ---

// ReceiveProofRequest simulates receiving a proof request
func (v Verifier) ReceiveProofRequest(request ProofRequest) {
	fmt.Printf("Verifier '%s' received Proof Request.\n", v.ID)
	v.IsProofRequestValid(request, GenerateParameters()) // In real system, parameters should be shared securely
}

// ExtractCommitmentFromRequest extracts the commitment
func (v Verifier) ExtractCommitmentFromRequest(request ProofRequest) Commitment {
	return request.Commitment
}

// ExtractRangeSpecFromRequest extracts the range specification
func (v Verifier) ExtractRangeSpecFromRequest(request ProofRequest) RangeSpec {
	return request.RangeSpec
}

// ExtractProofFromRequest extracts the proof
func (v Verifier) ExtractProofFromRequest(request ProofRequest) RangeProof {
	return request.Proof
}

// VerifyRangeProof verifies the range proof (simplified verification)
func (v Verifier) VerifyRangeProof(commitment Commitment, proof RangeProof, rangeSpec RangeSpec, params Parameters) bool {
	fmt.Println("Verifier: Verifying Range Proof...")

	// In a real ZKP, verification would be based on cryptographic properties, not just re-hashing

	// For this simplified example, we re-calculate the expected proof if data was in range
	expectedProofData := "DATA_VALUE_NOT_KNOWN_BY_VERIFIER" + strconv.Itoa(rangeSpec.LowerBound) + strconv.Itoa(rangeSpec.UpperBound) + params.Salt // Verifier doesn't know the actual data
	// We need a way to check range without knowing data.  This simplified example is inherently flawed for true ZKP security.

	// **Simplified Verification Logic (Illustrative, NOT SECURE):**
	// We cannot directly re-compute the proof without knowing the data.
	// In a real ZKP, the proof itself would contain information that allows verification *without* revealing the data.

	// Let's simulate a very weak verification for demonstration:
	// We'll just check if the proof is non-empty, and assume it's valid if it is (highly insecure!)

	if proof.ChallengeResponse != "" {
		fmt.Println("Verifier: Simplified Proof Check - Proof is not empty. Assuming valid (INSECURE!).")
		return true // Insecure simplification for demonstration
	} else {
		fmt.Println("Verifier: Simplified Proof Check - Proof is empty. Invalid.")
		return false
	}

	// In a real ZKP range proof:
	// 1. Verifier would use the commitment and the proof to perform cryptographic checks.
	// 2. These checks would mathematically guarantee (with high probability) that the prover knows a value within the range that corresponds to the commitment, without revealing the value itself.

	// return false // Replace the insecure logic with proper ZKP verification in a real system
}

// CheckCommitmentValidity (Optional, for more complex commitments)
func (v Verifier) CheckCommitmentValidity(commitment Commitment, params Parameters) bool {
	// In a more complex system, you might check if the commitment is well-formed
	// For this simplified example, we skip this check.
	return true
}

// IsProofRequestValid orchestrates the verification process
func (v Verifier) IsProofRequestValid(request ProofRequest, params Parameters) bool {
	fmt.Println("Verifier: Starting Proof Request Validation...")

	commitment := v.ExtractCommitmentFromRequest(request)
	rangeSpec := v.ExtractRangeSpecFromRequest(request)
	proof := v.ExtractProofFromRequest(request)

	if !v.CheckCommitmentValidity(commitment, params) {
		fmt.Println("Verifier: Commitment is invalid.")
		return false
	}

	isValidRangeProof := v.VerifyRangeProof(commitment, proof, rangeSpec, params)
	if isValidRangeProof {
		fmt.Println("Verifier: Range Proof is valid.")
		return true
	} else {
		fmt.Println("Verifier: Range Proof is invalid.")
		return false
	}
}

// ProcessComplianceResult handles the outcome of verification
func (v Verifier) ProcessComplianceResult(isValid bool) {
	if isValid {
		fmt.Printf("Verifier '%s': Compliance VERIFIED. Access GRANTED.\n", v.ID)
		// Grant access or proceed with the compliant action
	} else {
		fmt.Printf("Verifier '%s': Compliance NOT VERIFIED. Access DENIED.\n", v.ID)
		// Deny access or handle non-compliance
	}
}

// --- 4. Helper Functions ---

// hashData hashes a string using SHA-256
func hashData(data string) string {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// generateRandomValue generates a random string (for salt demonstration)
func generateRandomValue() string {
	rand.Seed(time.Now().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 16)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// --- Main Function (Example Usage) ---
func main() {
	params := GenerateParameters()
	prover := CreateProver("Alice")
	verifier := CreateVerifier("Bank")

	privateData := 750 // Example credit score
	dataRange := RangeSpec{LowerBound: 700, UpperBound: 800}

	preparedData := prover.PreparePrivateData(privateData)
	commitment := prover.CommitToPrivateData(preparedData, params)
	proof := prover.GenerateRangeProof(preparedData, dataRange.LowerBound, dataRange.UpperBound, params, commitment)
	proofRequest := prover.CreateProofRequest(commitment, proof, dataRange)

	fmt.Println("\n--- ZKP Process Initiated ---")
	prover.SendProofRequest(proofRequest, verifier)

	isValidRequest := verifier.IsProofRequestValid(proofRequest, params) // Verification is already done in ReceiveProofRequest in this example flow
	verifier.ProcessComplianceResult(isValidRequest)

	fmt.Println("\n--- ZKP Process Completed ---")

	// Example of out-of-range data:
	fmt.Println("\n--- ZKP Process with Out-of-Range Data ---")
	privateDataOutOfRange := 650
	preparedDataOutOfRange := prover.PreparePrivateData(privateDataOutOfRange)
	commitmentOutOfRange := prover.CommitToPrivateData(preparedDataOutOfRange, params)
	proofOutOfRange := prover.GenerateRangeProof(preparedDataOutOfRange, dataRange.LowerBound, dataRange.UpperBound, params, commitmentOutOfRange)
	proofRequestOutOfRange := prover.CreateProofRequest(commitmentOutOfRange, proofOutOfRange, dataRange)

	prover.SendProofRequest(proofRequestOutOfRange, verifier)
	isValidRequestOutOfRange := verifier.IsProofRequestValid(proofRequestOutOfRange, params)
	verifier.ProcessComplianceResult(isValidRequestOutOfRange)

	fmt.Println("\n--- ZKP Process with Out-of-Range Data Completed ---")
}
```