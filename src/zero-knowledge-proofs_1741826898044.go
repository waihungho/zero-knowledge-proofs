```go
/*
Outline and Function Summary:

This Golang code outlines a Zero-Knowledge Proof (ZKP) system for verifying "Skill Endorsement" in a decentralized professional network.  Imagine a platform where professionals can endorse each other's skills without revealing *who* endorsed *whom* in detail, preserving privacy while still providing verifiable skill endorsements.

**Core Concept:**  A professional (Prover) wants to prove they have a certain skill, endorsed by at least 'N' other professionals (Endorsers), to a Verifier (e.g., potential employer, client) without revealing the identities of the endorsers or the endorsements themselves beyond the required count.

**Functions Summary (20+):**

**1. Setup & Key Generation:**
    * `GenerateIssuerKeyPair()`: Generates key pair for an "Issuer" (e.g., platform authority) who defines and manages skills.
    * `GenerateProverKeyPair()`: Generates key pair for a Prover (professional seeking to prove skills).
    * `GenerateEndorserKeyPair()`: Generates key pair for an Endorser (professional who can endorse skills).
    * `GenerateSkillParameters(skillName string)`: Generates public parameters specific to a skill, used in ZKP.

**2. Skill Definition & Management:**
    * `DefineSkill(issuerPrivateKey, skillName, skillDescription string)`: Allows an Issuer to define a new skill on the platform.
    * `GetSkillDefinition(skillName string)`: Retrieves the definition of a skill.
    * `RegisterSkill(skillName string, skillParameters []byte)`: Registers a skill and its parameters on a public registry (simulated here).

**3. Endorsement Process (Preparation - not ZKP yet):**
    * `RequestSkillEndorsement(proverPublicKey, skillName string)`: Prover requests endorsements for a specific skill.
    * `IssueSkillEndorsement(endorserPrivateKey, proverPublicKey, skillName string)`: Endorser issues an endorsement for a Prover's skill (creates a signed endorsement - precursor to ZKP).
    * `StoreEndorsement(proverPublicKey, skillName string, endorsementData []byte)`:  (Simulated) Stores endorsements securely, accessible to the Prover for ZKP generation.

**4. Zero-Knowledge Proof Generation:**
    * `GenerateZKProofOfSkillEndorsementCount(proverPrivateKey, skillName string, minEndorsementCount int)`:  **Core ZKP Function.** Prover generates a ZKP proving they have at least `minEndorsementCount` endorsements for `skillName` without revealing individual endorsements or endorser identities.  *This is where the advanced ZKP logic resides.*
    * `PrepareZKProofInputs(proverPrivateKey, skillName string, minEndorsementCount int)`: Prepares the necessary inputs (e.g., commitments, selective disclosures) for the ZKP generation process. This abstracts some complexity.
    * `ConstructZKProofStatement(skillName string, minEndorsementCount int, proofInputs ...interface{})`: Constructs the mathematical statement that the ZKP will prove.
    * `ApplyZKPCryptographicTechniques(proofStatement, proofInputs ...interface{})`:  Applies the actual ZKP cryptographic algorithms (e.g., commitment schemes, range proofs, aggregate signatures – conceptually outlined, not implemented).

**5. Zero-Knowledge Proof Verification:**
    * `VerifyZKProofOfSkillEndorsementCount(verifierPublicKey, skillName string, minEndorsementCount int, zkProof []byte)`: **Core Verification Function.** Verifier checks the ZKP to confirm the Prover has the required endorsements for the skill, without learning anything else.
    * `DeserializeZKProof(zkProof []byte)`: Deserializes the ZKP data structure.
    * `ExtractZKProofStatement(zkProofData ZKProofData)`: Extracts the statement from the ZKP for verification.
    * `ValidateZKProofCryptographicComponents(zkProofData ZKProofData, verifierPublicKey, skillParameters []byte)`: Validates the cryptographic components of the ZKP against the public parameters and verifier's public key.
    * `CheckZKProofAgainstStatement(zkProofData ZKProofData, expectedStatement ZKProofStatement)`: Verifies if the proof satisfies the claimed statement (at least N endorsements).

**6. Utility & Helper Functions:**
    * `HashData(data []byte)`:  Generic hashing function.
    * `SignData(privateKey, data []byte)`: Generic signing function.
    * `VerifySignature(publicKey, data, signature []byte)`: Generic signature verification function.
    * `SerializeZKProof(proofData ZKProofData)`: Serializes the ZKP data into a byte array for transmission or storage.


**Important Notes:**

* **Conceptual Outline:** This code is a conceptual outline.  The ZKP cryptographic functions (`GenerateZKProofOfSkillEndorsementCount`, `VerifyZKProofOfSkillEndorsementCount`, etc.) are placeholders.  A real implementation would require selecting and implementing specific ZKP algorithms (e.g., using libraries for commitment schemes, range proofs, and potentially advanced techniques like zk-SNARKs or zk-STARKs for efficiency and succinctness, depending on the desired level of complexity and performance).
* **Simplified Security Model:**  Key management, secure storage, and more robust security considerations are simplified for demonstration purposes.  A production system would require much more rigorous security design.
* **"Trendy" & "Advanced Concept":** The "Skill Endorsement with Privacy" concept is relevant to decentralized professional networks, verifiable credentials, and the growing demand for privacy-preserving systems.  The ZKP aspect allows for verifiable claims without revealing sensitive underlying data, which is a key trend in modern cryptography.
* **No Open Source Duplication (Intentional):** This code is designed to be a unique conceptual example and does not directly replicate any specific open-source ZKP implementations. It focuses on outlining a functional system built around a creative use case.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// --- Data Structures (Conceptual) ---

type KeyPair struct {
	Public  []byte // Representing Public Key (e.g., serialized)
	Private []byte // Representing Private Key (e.g., serialized)
}

type SkillDefinition struct {
	Name        string
	Description string
	Parameters  []byte // Skill-specific parameters for ZKP
}

type EndorsementData struct {
	Signature []byte
	EndorserPubKey []byte // Optional, for verification context
	Timestamp  int64    // Optional, for time context
	SkillName  string
	ProverPubKeyHash []byte // To link endorsement to a prover (hashed for privacy if needed)
	// ... other relevant endorsement details (encrypted if needed)
}

type ZKProofData struct {
	ProofBytes []byte // Serialized ZKP (algorithm-specific)
	Statement    ZKProofStatement // Statement being proven (e.g., skill, min endorsement count)
	// ... metadata about the ZKP, algorithm used, etc.
}

type ZKProofStatement struct {
	SkillName           string
	MinEndorsementCount int
	// ... other aspects of the proven statement
}


// --- 1. Setup & Key Generation ---

func GenerateIssuerKeyPair() (KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, err
	}
	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	pemPrivateKey := pem.EncodeToMemory(privateKeyBlock)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return KeyPair{}, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pemPublicKey := pem.EncodeToMemory(publicKeyBlock)


	return KeyPair{Public: pemPublicKey, Private: pemPrivateKey}, nil
}

func GenerateProverKeyPair() (KeyPair, error) {
	return GenerateIssuerKeyPair() // Reusing RSA key gen for simplicity
}

func GenerateEndorserKeyPair() (KeyPair, error) {
	return GenerateIssuerKeyPair() // Reusing RSA key gen for simplicity
}

func GenerateSkillParameters(skillName string) ([]byte, error) {
	// In a real ZKP system, this would generate parameters specific to the skill and the ZKP algorithm.
	// For example, for range proofs, it might generate Pedersen parameters, etc.
	// Here, we just hash the skill name as a placeholder.
	hash := sha256.Sum256([]byte(skillName))
	return hash[:], nil
}

// --- 2. Skill Definition & Management ---

var skillRegistry = make(map[string]SkillDefinition) // In-memory skill registry (replace with DB in real app)

func DefineSkill(issuerPrivateKey KeyPair, skillName, skillDescription string) error {
	// In a real system, Issuer would be authenticated.  Simplified here.

	skillParams, err := GenerateSkillParameters(skillName)
	if err != nil {
		return err
	}

	skillDef := SkillDefinition{
		Name:        skillName,
		Description: skillDescription,
		Parameters:  skillParams,
	}

	// In a real system, Issuer might sign the skill definition.  Skipping for simplicity.
	skillRegistry[skillName] = skillDef
	return nil
}

func GetSkillDefinition(skillName string) (SkillDefinition, error) {
	def, exists := skillRegistry[skillName]
	if !exists {
		return SkillDefinition{}, errors.New("skill not defined")
	}
	return def, nil
}

func RegisterSkill(skillName string, skillParameters []byte) error {
	// In a real system, this might involve publishing skill parameters to a public ledger or registry.
	fmt.Printf("Skill '%s' registered with parameters: %x\n", skillName, skillParameters)
	return nil
}

// --- 3. Endorsement Process (Preparation) ---

var endorsementStore = make(map[string][]EndorsementData) // In-memory endorsement store (replace with secure DB)

func RequestSkillEndorsement(proverPublicKey KeyPair, skillName string) string {
	// In a real system, this might involve a more complex protocol for endorsement requests.
	requestID := fmt.Sprintf("endorsement-request-%s-%s", skillName, string(proverPublicKey.Public)) // Simple ID
	fmt.Printf("Endorsement requested for skill '%s' by Prover (PK hash): %x, Request ID: %s\n", skillName, HashData(proverPublicKey.Public), requestID)
	return requestID
}

func IssueSkillEndorsement(endorserPrivateKey KeyPair, proverPublicKey KeyPair, skillName string) (EndorsementData, error) {
	dataToSign := []byte(fmt.Sprintf("ENDORSEMENT:%s:%s", skillName, string(proverPublicKey.Public))) // Data to be signed

	signature, err := SignData(endorserPrivateKey, dataToSign)
	if err != nil {
		return EndorsementData{}, err
	}

	endorsement := EndorsementData{
		Signature:      signature,
		EndorserPubKey: endorserPrivateKey.Public, // Include endorser's public key for later verification (optional in ZKP context, but good practice)
		Timestamp:      1678886400,             // Example timestamp
		SkillName:      skillName,
		ProverPubKeyHash: HashData(proverPublicKey.Public), // Hashed prover public key for linking
	}

	fmt.Printf("Endorsement issued for skill '%s' by Endorser (PK hash): %x to Prover (PK hash): %x\n", skillName, HashData(endorserPrivateKey.Public), HashData(proverPublicKey.Public))
	return endorsement, nil
}

func StoreEndorsement(proverPublicKey KeyPair, skillName string, endorsementData EndorsementData) error {
	proverPubKeyStr := string(proverPublicKey.Public) // Using string representation for simplicity in map key
	endorsementStore[proverPubKeyStr] = append(endorsementStore[proverPubKeyStr], endorsementData)
	return nil
}


// --- 4. Zero-Knowledge Proof Generation ---

func GenerateZKProofOfSkillEndorsementCount(proverPrivateKey KeyPair, skillName string, minEndorsementCount int) (ZKProofData, error) {
	fmt.Println("Generating ZK Proof of Skill Endorsement Count...")

	// 1. Prepare Inputs (Commitments, Selective Disclosures, etc.)
	proofInputs, err := PrepareZKProofInputs(proverPrivateKey, skillName, minEndorsementCount)
	if err != nil {
		return ZKProofData{}, fmt.Errorf("failed to prepare ZKP inputs: %w", err)
	}

	// 2. Construct ZK Proof Statement
	proofStatement := ConstructZKProofStatement(skillName, minEndorsementCount, proofInputs...)

	// 3. Apply ZKP Cryptographic Techniques (Placeholder - Replace with actual ZKP logic)
	proofBytes, err := ApplyZKPCryptographicTechniques(proofStatement, proofInputs...) // <--- ZKP ALGORITHM IMPLEMENTATION HERE
	if err != nil {
		return ZKProofData{}, fmt.Errorf("ZKP algorithm failed: %w", err)
	}

	zkProofData := ZKProofData{
		ProofBytes: proofBytes,
		Statement:    proofStatement,
	}

	fmt.Println("ZK Proof Generated Successfully.")
	return zkProofData, nil
}


func PrepareZKProofInputs(proverPrivateKey KeyPair, skillName string, minEndorsementCount int) ([]interface{}, error) {
	fmt.Println("Preparing ZK Proof Inputs...")
	// In a real ZKP, this function would:
	// - Retrieve endorsements for the prover and skill.
	// - Selectively disclose information needed for the proof (e.g., commit to endorsements, but hide endorser identities directly).
	// - Generate cryptographic commitments, randomness, and other inputs required by the chosen ZKP algorithm.

	// Placeholder: Simulate retrieving endorsements and preparing inputs.
	proverPubKeyStr := string(proverPrivateKey.Public)
	endorsements := endorsementStore[proverPubKeyStr]
	endorsementCount := len(endorsements)

	if endorsementCount < minEndorsementCount {
		return nil, fmt.Errorf("not enough endorsements (%d) to prove minimum of %d", endorsementCount, minEndorsementCount)
	}

	fmt.Printf("Found %d endorsements for skill '%s', preparing for ZKP...\n", endorsementCount, skillName)

	// Placeholder input data (replace with actual ZKP input generation)
	inputs := []interface{}{
		endorsementCount, // Simulate providing the count (in real ZKP, this is proven without revealing the *actual* endorsements)
		skillName,
		minEndorsementCount,
		// ... more ZKP specific inputs (commitments, randomness, etc.)
	}
	return inputs, nil
}


func ConstructZKProofStatement(skillName string, minEndorsementCount int, proofInputs ...interface{}) ZKProofStatement {
	fmt.Println("Constructing ZK Proof Statement...")
	// This function defines the mathematical statement that the ZKP will prove.
	//  It's a formal representation of what is being claimed.

	statement := ZKProofStatement{
		SkillName:           skillName,
		MinEndorsementCount: minEndorsementCount,
		// ... more details about the statement if needed
	}
	fmt.Printf("ZK Proof Statement constructed: Prover has >= %d endorsements for skill '%s'\n", minEndorsementCount, skillName)
	return statement
}


func ApplyZKPCryptographicTechniques(proofStatement ZKProofStatement, proofInputs ...interface{}) ([]byte, error) {
	fmt.Println("Applying ZKP Cryptographic Techniques... (Placeholder - Real ZKP Algorithm would be here)")
	// *** PLACEHOLDER - REAL ZKP ALGORITHM IMPLEMENTATION GOES HERE ***
	// This is where you would implement the core ZKP algorithm logic.
	// Examples of ZKP techniques to consider:
	// - Commitment Schemes (Pedersen commitments, etc.)
	// - Range Proofs (Bulletproofs, etc. - to prove count is within a range or above a threshold)
	// - Aggregate Signatures (BLS signatures to aggregate endorsements in a verifiable way)
	// - zk-SNARKs/zk-STARKs (for more advanced and efficient ZKPs, but more complex to implement)
	// - Homomorphic Encryption (for certain types of proofs)

	// For this example, we are just simulating successful proof generation.
	proofBytes := []byte("ZKPROOF_PLACEHOLDER_DATA") // Replace with actual serialized ZKP
	fmt.Println("Placeholder ZKP Algorithm executed (simulated success).")
	return proofBytes, nil
}



// --- 5. Zero-Knowledge Proof Verification ---

func VerifyZKProofOfSkillEndorsementCount(verifierPublicKey KeyPair, skillName string, minEndorsementCount int, zkProof []byte) (bool, error) {
	fmt.Println("Verifying ZK Proof of Skill Endorsement Count...")

	// 1. Deserialize ZK Proof
	zkProofData, err := DeserializeZKProof(zkProof)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize ZKP: %w", err)
	}

	// 2. Extract ZK Proof Statement
	extractedStatement := ExtractZKProofStatement(zkProofData)

	// 3. Validate ZK Proof Cryptographic Components (Placeholder - Real ZKP Verification Logic)
	skillDef, err := GetSkillDefinition(skillName)
	if err != nil {
		return false, fmt.Errorf("failed to get skill definition: %w", err)
	}
	isValidCrypto, err := ValidateZKProofCryptographicComponents(zkProofData, verifierPublicKey.Public, skillDef.Parameters)
	if err != nil {
		return false, fmt.Errorf("cryptographic validation failed: %w", err)
	}
	if !isValidCrypto {
		fmt.Println("ZK Proof Cryptographic Validation Failed.")
		return false, nil
	}

	// 4. Check ZK Proof Against Statement
	isValidStatement := CheckZKProofAgainstStatement(zkProofData, ZKProofStatement{SkillName: skillName, MinEndorsementCount: minEndorsementCount})
	if !isValidStatement {
		fmt.Println("ZK Proof Statement Verification Failed.")
		return false, nil
	}

	fmt.Println("ZK Proof Verification Successful!")
	return true, nil
}


func DeserializeZKProof(zkProof []byte) (ZKProofData, error) {
	fmt.Println("Deserializing ZK Proof...")
	// In a real system, this would deserialize the byte array back into a structured ZKProofData object,
	// according to the ZKP algorithm's specific serialization format.

	// Placeholder:  Assume deserialization is successful for now.
	return ZKProofData{ProofBytes: zkProof, Statement: ZKProofStatement{SkillName: "PlaceholderSkill", MinEndorsementCount: 1}}, // Placeholder statement
}


func ExtractZKProofStatement(zkProofData ZKProofData) ZKProofStatement {
	fmt.Println("Extracting ZK Proof Statement...")
	// In a real system, the statement might be embedded within the ZKP data or derived from it.
	// For this example, we are assuming the statement is readily available in ZKProofData.
	return zkProofData.Statement
}


func ValidateZKProofCryptographicComponents(zkProofData ZKProofData, verifierPublicKey []byte, skillParameters []byte) (bool, error) {
	fmt.Println("Validating ZK Proof Cryptographic Components... (Placeholder - Real ZKP Verification Logic)")
	// *** PLACEHOLDER - REAL ZKP CRYPTO VERIFICATION GOES HERE ***
	// This function would perform the core cryptographic verification steps of the ZKP algorithm.
	// It would check signatures, commitments, range proofs, etc., based on the algorithm used.
	// It would use the verifier's public key and skill-specific parameters for verification.

	// For this example, we are simulating successful cryptographic validation.
	fmt.Println("Placeholder ZKP Crypto Validation executed (simulated success).")
	return true, nil
}


func CheckZKProofAgainstStatement(zkProofData ZKProofData, expectedStatement ZKProofStatement) bool {
	fmt.Println("Checking ZK Proof Against Statement...")
	// This function checks if the verified ZKP actually proves the expected statement.
	// In this case, we check if the ZKP statement matches the expected skill and minimum endorsement count.

	if zkProofData.Statement.SkillName != expectedStatement.SkillName {
		fmt.Printf("ZK Proof statement skill name mismatch: got '%s', expected '%s'\n", zkProofData.Statement.SkillName, expectedStatement.SkillName)
		return false
	}
	if zkProofData.Statement.MinEndorsementCount != expectedStatement.MinEndorsementCount {
		fmt.Printf("ZK Proof statement endorsement count mismatch: got %d, expected %d\n", zkProofData.Statement.MinEndorsementCount, expectedStatement.MinEndorsementCount)
		return false
	}

	fmt.Println("ZK Proof successfully verifies the statement.")
	return true
}


// --- 6. Utility & Helper Functions ---

func HashData(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func SignData(privateKeyData KeyPair, data []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyData.Private)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hashedData := HashData(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedData) //crypto.SHA256 is not defined, should be imported
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifySignature(publicKeyData KeyPair, data, signature []byte) (bool, error) {
	block, _ := pem.Decode(publicKeyData.Public)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return false, errors.New("failed to decode PEM public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("not an RSA public key")
	}

	hashedData := HashData(data)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashedData, signature) //crypto.SHA256 is not defined, should be imported
	if err != nil {
		return false, err
	}
	return true, nil
}


func SerializeZKProof(proofData ZKProofData) ([]byte, error) {
	fmt.Println("Serializing ZK Proof...")
	// In a real system, this function would serialize the ZKP data structure into a byte array
	// according to the ZKP algorithm's specific format (e.g., using Protobuf, JSON, or a custom binary format).

	// Placeholder: Just return the ProofBytes for now.
	return proofData.ProofBytes, nil
}


// --- Main Function (Example Usage) ---

func main() {
	// 1. Issuer Setup
	issuerKeys, _ := GenerateIssuerKeyPair()
	_ = DefineSkill(issuerKeys, "Golang Development", "Proficiency in Golang programming language")
	skillDef, _ := GetSkillDefinition("Golang Development")
	_ = RegisterSkill(skillDef.Name, skillDef.Parameters)

	// 2. Prover and Endorsers Setup
	proverKeys, _ := GenerateProverKeyPair()
	endorserKeys1, _ := GenerateEndorserKeyPair()
	endorserKeys2, _ := GenerateEndorserKeyPair()
	endorserKeys3, _ := GenerateEndorserKeyPair()

	// 3. Prover Requests Endorsements
	requestID := RequestSkillEndorsement(proverKeys, "Golang Development")
	fmt.Println("Endorsement Request ID:", requestID)

	// 4. Endorsers Issue Endorsements
	endorsement1, _ := IssueSkillEndorsement(endorserKeys1, proverKeys, "Golang Development")
	endorsement2, _ := IssueSkillEndorsement(endorserKeys2, proverKeys, "Golang Development")
	endorsement3, _ := IssueSkillEndorsement(endorserKeys3, proverKeys, "Golang Development")

	// 5. Store Endorsements (Simulated)
	_ = StoreEndorsement(proverKeys, "Golang Development", endorsement1)
	_ = StoreEndorsement(proverKeys, "Golang Development", endorsement2)
	_ = StoreEndorsement(proverKeys, "Golang Development", endorsement3)

	// 6. Prover Generates ZK Proof (for >= 2 endorsements)
	zkProofData, err := GenerateZKProofOfSkillEndorsementCount(proverKeys, "Golang Development", 2)
	if err != nil {
		fmt.Println("ZK Proof Generation Error:", err)
		return
	}
	serializedProof, _ := SerializeZKProof(zkProofData)
	fmt.Printf("Serialized ZK Proof (Placeholder Data): %x...\n", serializedProof[:min(len(serializedProof), 50)]) // Show first 50 bytes

	// 7. Verifier Verifies ZK Proof
	verifierKeys, _ := GenerateVerifierKeyPair() // Verifier Key (could be same as issuer or different)
	isValidProof, err := VerifyZKProofOfSkillEndorsementCount(verifierKeys, "Golang Development", 2, serializedProof)
	if err != nil {
		fmt.Println("ZK Proof Verification Error:", err)
		return
	}

	if isValidProof {
		fmt.Println("ZK Proof Verification Result: SUCCESS - Skill Endorsement Count Verified (>= 2) in Zero-Knowledge!")
	} else {
		fmt.Println("ZK Proof Verification Result: FAILURE - Proof is invalid.")
	}
}

// GenerateVerifierKeyPair for completeness, even if not strictly used in this simplified example
func GenerateVerifierKeyPair() (KeyPair, error) {
	return GenerateIssuerKeyPair() // Reusing RSA key gen for simplicity
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

import "crypto" // Import crypto package for SHA256
```