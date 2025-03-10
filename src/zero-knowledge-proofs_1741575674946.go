```go
/*
Outline and Function Summary:

**Zero-Knowledge Proof for Secure Medical Data Sharing with Selective Disclosure**

This Go program outlines a zero-knowledge proof system for secure medical data sharing.
It allows a patient (Holder) to prove certain health attributes to a doctor (Verifier)
without revealing their entire medical record to the doctor or any third party.
This is achieved using Zero-Knowledge Proofs to ensure:

1. **Completeness:** If the patient's claims are true, the verifier will be convinced.
2. **Soundness:** If the patient's claims are false, the verifier will not be convinced (except with negligible probability).
3. **Zero-Knowledge:** The verifier learns nothing beyond the validity of the claims.

**Actors:**

* **Issuer (Hospital/Lab):** Issues verifiable credentials (medical reports) to patients.
* **Holder (Patient):** Holds verifiable credentials and wants to prove specific attributes.
* **Verifier (Doctor):** Needs to verify specific health attributes of the patient.

**Core Concepts:**

* **Verifiable Credentials (VCs):** Digitally signed documents containing claims about the patient's health.
* **Selective Disclosure:**  The ability to reveal only specific attributes from a VC, not the entire document.
* **Zero-Knowledge Proof (ZKP):** Cryptographic protocol to prove the truth of a statement without revealing any information beyond the truth itself.
* **Attribute-Based ZKP:**  Focuses on proving attributes within a VC, rather than the entire VC.

**Functions (20+):**

**1. Issuer Functions (Credential Issuance and Management):**

* `GenerateIssuerKeyPair()`: Generates public and private key pair for the Issuer. (Setup)
* `DefineCredentialSchema(schemaName string, attributes []string) CredentialSchema`: Defines the structure and attributes of a medical credential type. (Schema Definition)
* `IssueMedicalCredential(schema CredentialSchema, patientID string, attributes map[string]interface{}, issuerPrivateKey KeyPair) (VerifiableCredential, error)`: Creates and signs a verifiable medical credential for a patient based on a schema and attributes. (Credential Creation)
* `RevokeCredential(credentialID string, issuerPrivateKey KeyPair) (RevocationStatus, error)`: Revokes a credential, making it invalid. (Credential Revocation)
* `CheckCredentialRevocationStatus(credentialID string, issuerPublicKey KeyPair) (RevocationStatus, error)`: Checks if a credential has been revoked. (Revocation Status Check)
* `PublishCredentialSchema(schema CredentialSchema) error`:  Makes the credential schema publicly available (e.g., on a decentralized registry). (Schema Publication)

**2. Holder Functions (Credential Management and Proof Generation):**

* `StoreCredential(credential VerifiableCredential) error`: Stores a verifiable credential securely in the patient's wallet/system. (Credential Storage)
* `SelectCredentialForProof(credentials []VerifiableCredential, credentialID string) (VerifiableCredential, error)`: Selects a specific credential from the holder's stored credentials. (Credential Selection)
* `GenerateDisclosureProofRequest(verifierPublicKey KeyPair, requestedAttributes []string, credentialSchema CredentialSchema) (ProofRequest, error)`: Creates a request for a zero-knowledge proof for specific attributes, targeted to a verifier. (Proof Request Generation)
* `GenerateZeroKnowledgeProof(credential VerifiableCredential, proofRequest ProofRequest, holderPrivateKey KeyPair) (ZeroKnowledgeProof, error)`: Generates a zero-knowledge proof based on the credential and the verifier's request, revealing only the requested attributes. (ZKP Generation - Core)
* `SelectAttributesForDisclosure(credential VerifiableCredential, requestedAttributes []string) (map[string]interface{}, error)`: Selects the attributes from the credential that are requested for disclosure in the proof. (Attribute Selection)
* `EncryptSelectiveAttributes(attributes map[string]interface{}, verifierPublicKey KeyPair) (EncryptedAttributes, error)`:  Optionally encrypts the selectively disclosed attributes using the verifier's public key for added privacy during transmission. (Attribute Encryption)
* `PresentProofToVerifier(proof ZeroKnowledgeProof, encryptedAttributes EncryptedAttributes, verifierEndpoint string) error`: Sends the generated ZKP and optionally encrypted attributes to the verifier. (Proof Presentation)

**3. Verifier Functions (Proof Request and Verification):**

* `GenerateVerifierKeyPair()`: Generates public and private key pair for the Verifier (Doctor). (Verifier Setup)
* `DefineVerificationPolicy(policyName string, requiredAttributes []string, credentialSchema CredentialSchema) VerificationPolicy`: Defines a policy specifying the attributes required for verification. (Verification Policy Definition)
* `CreateProofRequestFromPolicy(policy VerificationPolicy, verifierPublicKey KeyPair, credentialSchema CredentialSchema) (ProofRequest, error)`: Creates a proof request based on a defined verification policy. (Proof Request from Policy)
* `RequestZeroKnowledgeProofFromHolder(proofRequest ProofRequest, holderEndpoint string) error`: Sends a proof request to the patient (Holder). (Proof Request to Holder)
* `VerifyZeroKnowledgeProof(proof ZeroKnowledgeProof, proofRequest ProofRequest, issuerPublicKey KeyPair, verifierPublicKey KeyPair) (bool, error)`: Verifies the received zero-knowledge proof against the proof request, issuer's public key, and verifier's public key. (ZKP Verification - Core)
* `DecryptDisclosedAttributes(encryptedAttributes EncryptedAttributes, verifierPrivateKey KeyPair) (map[string]interface{}, error)`: Decrypts the selectively disclosed attributes if they were encrypted by the holder. (Attribute Decryption)
* `EvaluateProofAgainstPolicy(proof ZeroKnowledgeProof, policy VerificationPolicy, issuerPublicKey KeyPair, verifierPublicKey KeyPair) (bool, error)`: Evaluates the verified proof against a predefined verification policy. (Policy Evaluation)
* `AuditProofVerification(proof ZeroKnowledgeProof, proofRequest ProofRequest, issuerPublicKey KeyPair, verifierPublicKey KeyPair, auditLogEndpoint string) error`: Optionally logs or audits the proof verification process for compliance or record-keeping. (Proof Auditing)


**Data Structures (Conceptual - Implementation details will vary):**

* `KeyPair`:  Represents a public and private key pair (e.g., using ECDSA).
* `CredentialSchema`: Defines the schema of a credential (name, attributes, types).
* `VerifiableCredential`: Represents a signed credential document (schema, attributes, signature, issuer info).
* `ProofRequest`:  Specifies the attributes requested by the verifier, challenge, and other proof parameters.
* `ZeroKnowledgeProof`: The cryptographic proof generated by the holder.
* `RevocationStatus`:  Indicates whether a credential is revoked or not.
* `VerificationPolicy`: Defines rules for verifying proofs (required attributes, issuer, etc.).
* `EncryptedAttributes`:  Represents encrypted attributes for added privacy.


**Note:** This is a conceptual outline and a simplified representation.  A real-world ZKP system for medical data would require significantly more complex cryptographic implementations, robust error handling, security considerations, and adherence to relevant healthcare regulations (like HIPAA in the US).  This example focuses on illustrating the functional components and flow of a ZKP system for selective disclosure in a medical context, rather than providing production-ready cryptographic code.  The actual ZKP algorithms and cryptographic primitives are abstracted here for clarity of the overall system design.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// --- Data Structures (Simplified) ---

type KeyPair struct {
	PublicKey  string
	PrivateKey string // In real system, use crypto.PrivateKey type and secure storage
}

type CredentialSchema struct {
	Name       string
	Attributes []string
}

type VerifiableCredential struct {
	Schema      CredentialSchema
	PatientID   string
	Attributes  map[string]interface{}
	Issuer      string // Issuer identifier
	Signature   string
	CredentialID string
}

type ProofRequest struct {
	RequestedAttributes []string
	VerifierPublicKey   string
	CredentialSchemaName string
	Challenge           string // For non-interactive ZKP, challenge could be pre-defined or omitted in simplified example
}

type ZeroKnowledgeProof struct {
	DisclosedAttributes map[string]interface{} // In real ZKP, this wouldn't be directly disclosed in the proof structure itself, but proven to exist
	ProofData         string                  // Placeholder for actual ZKP data (e.g., commitments, responses)
	CredentialID      string
	ProofRequestHash  string
}

type RevocationStatus struct {
	IsRevoked bool
	RevocationTime time.Time
}

type VerificationPolicy struct {
	Name              string
	RequiredAttributes []string
	IssuerPublicKey     string
	CredentialSchemaName string
}

type EncryptedAttributes struct {
	Ciphertext string
	EncryptionKey string // In real system, key management would be more complex
}

// --- Utility Functions ---

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // Handle error properly in production
	}
	return hex.EncodeToString(bytes)
}

func hashData(data string) string {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// --- 1. Issuer Functions ---

func GenerateIssuerKeyPair() KeyPair {
	// In a real system, use crypto.GenerateKey and secure key storage
	publicKey := generateRandomString(32)
	privateKey := generateRandomString(64)
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}
}

func DefineCredentialSchema(schemaName string, attributes []string) CredentialSchema {
	return CredentialSchema{Name: schemaName, Attributes: attributes}
}

func IssueMedicalCredential(schema CredentialSchema, patientID string, attributes map[string]interface{}, issuerPrivateKey KeyPair) (VerifiableCredential, error) {
	credentialID := generateRandomString(20)
	credentialData := fmt.Sprintf("%s-%s-%v", schema.Name, patientID, attributes)
	signature := hashData(credentialData + issuerPrivateKey.PrivateKey) // Simplified signature
	return VerifiableCredential{
		Schema:      schema,
		PatientID:   patientID,
		Attributes:  attributes,
		Issuer:      issuerPrivateKey.PublicKey,
		Signature:   signature,
		CredentialID: credentialID,
	}, nil
}

func RevokeCredential(credentialID string, issuerPrivateKey KeyPair) (RevocationStatus, error) {
	// In a real system, this would involve updating a revocation list or using a more sophisticated revocation mechanism
	fmt.Printf("Credential %s revoked by Issuer\n", credentialID)
	return RevocationStatus{IsRevoked: true, RevocationTime: time.Now()}, nil
}

func CheckCredentialRevocationStatus(credentialID string, issuerPublicKey KeyPair) (RevocationStatus, error) {
	// In a real system, check against a revocation list or mechanism associated with the issuerPublicKey
	// This is a placeholder - in a real ZKP system, revocation checking needs to be efficient and verifiable.
	fmt.Printf("Checking revocation status for credential %s (Issuer: %s) - Assuming not revoked for simplicity.\n", credentialID, issuerPublicKey.PublicKey)
	return RevocationStatus{IsRevoked: false}, nil
}

func PublishCredentialSchema(schema CredentialSchema) error {
	// In a real system, this might involve publishing to a decentralized registry or public database.
	fmt.Printf("Published Credential Schema: %s with attributes %v\n", schema.Name, schema.Attributes)
	return nil
}

// --- 2. Holder Functions ---

func StoreCredential(credential VerifiableCredential) error {
	// In a real application, credentials would be stored securely (e.g., encrypted wallet).
	fmt.Printf("Credential stored for Patient %s, Credential ID: %s\n", credential.PatientID, credential.CredentialID)
	return nil
}

func SelectCredentialForProof(credentials []VerifiableCredential, credentialID string) (VerifiableCredential, error) {
	for _, cred := range credentials {
		if cred.CredentialID == credentialID {
			return cred, nil
		}
	}
	return VerifiableCredential{}, errors.New("credential not found")
}

func GenerateDisclosureProofRequest(verifierPublicKey KeyPair, requestedAttributes []string, credentialSchema CredentialSchema) (ProofRequest, error) {
	challenge := generateRandomString(16) // Simple challenge
	return ProofRequest{
		RequestedAttributes: requestedAttributes,
		VerifierPublicKey:   verifierPublicKey.PublicKey,
		CredentialSchemaName: credentialSchema.Name,
		Challenge:           challenge,
	}, nil
}

func GenerateZeroKnowledgeProof(credential VerifiableCredential, proofRequest ProofRequest, holderPrivateKey KeyPair) (ZeroKnowledgeProof, error) {
	if credential.Schema.Name != proofRequest.CredentialSchemaName {
		return ZeroKnowledgeProof{}, errors.New("credential schema mismatch with proof request")
	}

	disclosedAttributes := make(map[string]interface{})
	for _, reqAttr := range proofRequest.RequestedAttributes {
		if val, ok := credential.Attributes[reqAttr]; ok {
			disclosedAttributes[reqAttr] = val
		} else {
			return ZeroKnowledgeProof{}, fmt.Errorf("requested attribute '%s' not found in credential", reqAttr)
		}
	}

	proofData := hashData(credential.Signature + proofRequest.Challenge + holderPrivateKey.PrivateKey) // Simplified proof data

	proofRequestHash := hashData(fmt.Sprintf("%v-%s-%s", proofRequest.RequestedAttributes, proofRequest.VerifierPublicKey, proofRequest.CredentialSchemaName))

	return ZeroKnowledgeProof{
		DisclosedAttributes: disclosedAttributes, // In real ZKP, this would be proven, not directly disclosed in the proof.
		ProofData:         proofData,
		CredentialID:      credential.CredentialID,
		ProofRequestHash:  proofRequestHash,
	}, nil
}

func SelectAttributesForDisclosure(credential VerifiableCredential, requestedAttributes []string) (map[string]interface{}, error) {
	selectedAttributes := make(map[string]interface{})
	for _, attrName := range requestedAttributes {
		if value, ok := credential.Attributes[attrName]; ok {
			selectedAttributes[attrName] = value
		} else {
			return nil, fmt.Errorf("attribute '%s' not found in credential", attrName)
		}
	}
	return selectedAttributes, nil
}

func EncryptSelectiveAttributes(attributes map[string]interface{}, verifierPublicKey KeyPair) (EncryptedAttributes, error) {
	// Placeholder for encryption using verifier's public key (e.g., RSA encryption).
	// In a real system, use crypto libraries for secure encryption.
	encryptedData := fmt.Sprintf("Encrypted: %v using Verifier Public Key: %s", attributes, verifierPublicKey.PublicKey) // Simulation
	encryptionKey := generateRandomString(16) // Placeholder - real encryption would handle key generation
	return EncryptedAttributes{Ciphertext: encryptedData, EncryptionKey: encryptionKey}, nil
}

func PresentProofToVerifier(proof ZeroKnowledgeProof, encryptedAttributes EncryptedAttributes, verifierEndpoint string) error {
	// In a real system, this would involve sending data over a secure channel (e.g., HTTPS) to the verifier's endpoint.
	fmt.Printf("Presenting ZKP to Verifier at %s:\n", verifierEndpoint)
	fmt.Printf("  Proof Data Hash: %s\n", hashData(proof.ProofData)) // Show hash of proof for demonstration
	if encryptedAttributes.Ciphertext != "" {
		fmt.Printf("  Encrypted Attributes (Ciphertext Hash): %s\n", hashData(encryptedAttributes.Ciphertext))
	} else {
		fmt.Println("  No Attributes Encrypted.")
	}
	fmt.Println("  Credential ID in Proof:", proof.CredentialID)
	fmt.Println("  Proof Request Hash in Proof:", proof.ProofRequestHash)
	return nil
}

// --- 3. Verifier Functions ---

func GenerateVerifierKeyPair() KeyPair {
	// In a real system, use crypto.GenerateKey and secure key storage
	publicKey := generateRandomString(32)
	privateKey := generateRandomString(64)
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}
}

func DefineVerificationPolicy(policyName string, requiredAttributes []string, credentialSchema CredentialSchema) VerificationPolicy {
	return VerificationPolicy{
		Name:              policyName,
		RequiredAttributes: requiredAttributes,
		IssuerPublicKey:     "", // In real system, specify expected issuer public key
		CredentialSchemaName: credentialSchema.Name,
	}
}

func CreateProofRequestFromPolicy(policy VerificationPolicy, verifierPublicKey KeyPair, credentialSchema CredentialSchema) (ProofRequest, error) {
	return GenerateDisclosureProofRequest(verifierPublicKey, policy.RequiredAttributes, credentialSchema)
}

func RequestZeroKnowledgeProofFromHolder(proofRequest ProofRequest, holderEndpoint string) error {
	// In a real system, send the proof request to the holder's endpoint.
	fmt.Printf("Verifier requesting ZKP from Holder at %s for attributes: %v\n", holderEndpoint, proofRequest.RequestedAttributes)
	fmt.Printf("  Proof Request Hash: %s\n", hashData(fmt.Sprintf("%v-%s-%s", proofRequest.RequestedAttributes, proofRequest.VerifierPublicKey, proofRequest.CredentialSchemaName)))
	return nil
}

func VerifyZeroKnowledgeProof(proof ZeroKnowledgeProof, proofRequest ProofRequest, issuerPublicKey KeyPair, verifierPublicKey KeyPair) (bool, error) {
	// Simplified verification logic. In real ZKP, this would involve complex cryptographic checks.

	expectedProofRequestHash := hashData(fmt.Sprintf("%v-%s-%s", proofRequest.RequestedAttributes, proofRequest.VerifierPublicKey, proofRequest.CredentialSchemaName))
	if proof.ProofRequestHash != expectedProofRequestHash {
		return false, errors.New("proof request hash mismatch")
	}

	// Placeholder: Verify proof data against expected structure and cryptographic properties.
	// In a real ZKP system, this is where the core cryptographic verification happens.
	isValidProof := true // Assuming proof is valid for this simplified example. In real system, implement actual ZKP verification.

	if isValidProof {
		fmt.Println("Zero-Knowledge Proof Verification Successful!")
		return true, nil
	} else {
		fmt.Println("Zero-Knowledge Proof Verification Failed!")
		return false, errors.New("invalid zero-knowledge proof")
	}
}

func DecryptDisclosedAttributes(encryptedAttributes EncryptedAttributes, verifierPrivateKey KeyPair) (map[string]interface{}, error) {
	// Placeholder for decryption using verifier's private key (e.g., RSA decryption).
	// In a real system, use crypto libraries for secure decryption.
	if encryptedAttributes.Ciphertext == "" {
		return nil, errors.New("no encrypted attributes to decrypt")
	}
	fmt.Printf("Decrypting attributes using Verifier Private Key: %s\n", verifierPrivateKey.PrivateKey) // Simulation
	decryptedData := fmt.Sprintf("Decrypted: %s (Original Encryption Key was: %s)", encryptedAttributes.Ciphertext, encryptedAttributes.EncryptionKey) // Simulation
	fmt.Println("Decrypted Data:", decryptedData) // Just printing decrypted string for demonstration
	// In a real system, you'd parse the decrypted data back into a map[string]interface{}
	return map[string]interface{}{"decrypted_data": decryptedData}, nil // Simplified return
}

func EvaluateProofAgainstPolicy(proof ZeroKnowledgeProof, policy VerificationPolicy, issuerPublicKey KeyPair, verifierPublicKey KeyPair) (bool, error) {
	isValid, err := VerifyZeroKnowledgeProof(proof, ProofRequest{RequestedAttributes: policy.RequiredAttributes, VerifierPublicKey: verifierPublicKey.PublicKey, CredentialSchemaName: policy.CredentialSchemaName}, issuerPublicKey, verifierPublicKey)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, errors.New("proof is not valid")
	}

	// Additional policy checks can be implemented here (e.g., issuer verification, credential schema validation, etc.)
	fmt.Printf("Proof evaluated against policy '%s' - Policy Requirements Met.\n", policy.Name)
	return true, nil
}

func AuditProofVerification(proof ZeroKnowledgeProof, proofRequest ProofRequest, issuerPublicKey KeyPair, verifierPublicKey KeyPair, auditLogEndpoint string) error {
	verificationStatus, err := VerifyZeroKnowledgeProof(proof, proofRequest, issuerPublicKey, verifierPublicKey)
	auditLog := fmt.Sprintf("Proof Verification Audit:\n  Status: %v\n  Proof Request Attributes: %v\n  Credential ID: %s\n  Verifier Public Key: %s\n  Issuer Public Key: %s\n  Timestamp: %s\n",
		verificationStatus, proofRequest.RequestedAttributes, proof.CredentialID, verifierPublicKey.PublicKey, issuerPublicKey.PublicKey, time.Now().Format(time.RFC3339))

	if err != nil {
		auditLog += fmt.Sprintf("  Verification Error: %v\n", err)
	}

	// In a real system, send the audit log to the auditLogEndpoint (e.g., using HTTP POST).
	fmt.Printf("Auditing Proof Verification - Sending log to %s:\n%s", auditLogEndpoint, auditLog)
	return nil
}

func main() {
	// --- Setup ---
	issuerKeys := GenerateIssuerKeyPair()
	holderKeys := GenerateIssuerKeyPair() // Using same function for simplicity, in real system, holder would have their own key generation
	verifierKeys := GenerateVerifierKeyPair()

	medicalRecordSchema := DefineCredentialSchema("MedicalRecord", []string{"patientName", "bloodType", "allergies", "medicalHistorySummary", "lastVisitDate"})
	PublishCredentialSchema(medicalRecordSchema)

	patient1MedicalData := map[string]interface{}{
		"patientName":           "Alice Smith",
		"bloodType":             "O+",
		"allergies":             "None known",
		"medicalHistorySummary": "Generally healthy",
		"lastVisitDate":         "2023-10-26",
	}

	medicalCredential, _ := IssueMedicalCredential(medicalRecordSchema, "patient123", patient1MedicalData, issuerKeys)
	StoreCredential(medicalCredential)

	// --- Holder wants to prove Blood Type to Verifier (Doctor) ---
	verifierPolicy := DefineVerificationPolicy("BloodTypeCheck", []string{"bloodType"}, medicalRecordSchema)
	proofRequest, _ := CreateProofRequestFromPolicy(verifierPolicy, verifierKeys, medicalRecordSchema)
	RequestZeroKnowledgeProofFromHolder(proofRequest, "holder-endpoint-placeholder") // Simulate request to holder

	// Holder generates ZKP
	selectedCredential, _ := SelectCredentialForProof([]VerifiableCredential{medicalCredential}, medicalCredential.CredentialID) // Assume holder selects the correct credential
	zkProof, _ := GenerateZeroKnowledgeProof(selectedCredential, proofRequest, holderKeys)
	encryptedAttrs, _ := EncryptSelectiveAttributes(zkProof.DisclosedAttributes, verifierKeys) // Optional encryption

	// Holder presents proof to Verifier
	PresentProofToVerifier(zkProof, encryptedAttrs, "verifier-endpoint-placeholder")

	// --- Verifier Verifies the Proof ---
	isValidProof, _ := VerifyZeroKnowledgeProof(zkProof, proofRequest, issuerKeys, verifierKeys)
	fmt.Println("Proof Valid:", isValidProof)

	if isValidProof {
		decryptedAttributes, _ := DecryptDisclosedAttributes(encryptedAttrs, verifierKeys) // Decrypt if attributes were encrypted
		fmt.Println("Verifier obtained disclosed attributes (if any):", decryptedAttributes)
		proofPolicyValid, _ := EvaluateProofAgainstPolicy(zkProof, verifierPolicy, issuerKeys, verifierKeys)
		fmt.Println("Proof Policy Valid:", proofPolicyValid)
		AuditProofVerification(zkProof, proofRequest, issuerKeys, verifierKeys, "audit-log-endpoint")
	} else {
		fmt.Println("Proof Verification Failed - No attributes decrypted or policy evaluated.")
	}
}
```