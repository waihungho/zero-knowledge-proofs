The following Golang implementation presents a Zero-Knowledge Proof (ZKP) system for "ZK-Verified Data Processing Eligibility for Healthcare AI." This advanced concept addresses the challenge of accessing sensitive AI models while maintaining data privacy and regulatory compliance.

**Outline and Function Summary**

The system allows a Prover (e.g., a medical professional) to demonstrate two key conditions to a Verifier (e.g., an AI service provider) without revealing sensitive underlying data:

1.  **Professional Credential Proof:** The Prover is a licensed professional, evidenced by knowledge of a secret derived from their license ID.
2.  **Data Identifier Proof:** The Prover's private input data (e.g., patient records) conforms to a specific privacy-preserving schema. This is proven by demonstrating knowledge of a secret identifier derived from the data, which matches a publicly known expected identifier, without revealing the patient data itself.

The ZKP protocol is custom-built, based on an aggregated Schnorr-like Proof of Knowledge of Discrete Logarithm (PoKDL), combined with elliptic curve cryptography (using Go's `crypto/elliptic` and `math/big`) and finite field arithmetic.

---

**I. Cryptographic Primitives (10 functions)**
These functions handle elliptic curve point operations, finite field arithmetic, and secure random number generation, providing the foundational cryptographic operations.

1.  `newFieldElement(val *big.Int)`: Creates a new field element (scalar modulo curve.N).
2.  `fieldAdd(a, b FieldElement)`: Adds two field elements modulo the curve's order.
3.  `fieldSub(a, b FieldElement)`: Subtracts two field elements modulo the curve's order.
4.  `fieldMul(a, b FieldElement)`: Multiplies two field elements modulo the curve's order.
5.  `fieldInv(a FieldElement)`: Computes the modular multiplicative inverse of a field element.
6.  `newPoint(x, y *big.Int)`: Creates a new elliptic curve point (or point at infinity if x, y are nil).
7.  `pointScalarMult(p Point, scalar FieldElement)`: Performs scalar multiplication of an elliptic curve point.
8.  `pointAdd(p1, p2 Point)`: Adds two elliptic curve points.
9.  `generateRandomScalar()`: Generates a cryptographically secure random scalar within the field [1, N-1].
10. `hashToField(data []byte)`: Hashes arbitrary byte data to a field element.

**II. ZKP Core Components (4 functions/structs)**
These functions implement the core building blocks of the ZKP, including distinct generators and the Schnorr PoKDL.

11. `setupGenerators()`: Generates and returns two independent curve generators (G and H) from the P256 curve.
12. `SchnorrPoKDLProof` struct: Defines the structure for a Schnorr Proof of Knowledge of Discrete Logarithm, containing the commitment point `R` and response scalar `S`.
13. `generateSchnorrPoKDLProof(secret FieldElement, G Point, challenge FieldElement)`: Generates a Schnorr proof for knowledge of a secret `x` such that `P = x*G`.
14. `verifySchnorrPoKDLProof(proof *SchnorrPoKDLProof, G, P Point, challenge FieldElement)`: Verifies a given Schnorr proof against the public point `P` and challenge `e`.

**III. Application Specific Structures & Protocol (9 functions/structs)**
These functions integrate the core ZKP components into the "ZK-Verified Data Processing Eligibility for Healthcare AI" application scenario, defining the prover/verifier contexts and the main proof generation/verification logic.

15. `EligibilityProof` struct: Encapsulates the complete aggregated ZKP, including individual Schnorr proofs and the shared challenge.
16. `ProverContext` struct: Holds the Prover's secret credentials, raw patient data, and derived data identifier scalar.
17. `VerifierContext` struct: Holds the Verifier's public parameters and the expected public points for license and data identifiers.
18. `computeCombinedChallenge(licProofCommitmentR, dataIDProofCommitmentR Point, verifierParams *VerifierContext)`: Generates a deterministic, shared challenge scalar for the aggregate proof by hashing all relevant public parameters and commitment points.
19. `generateEligibilityProof(prover *ProverContext, verifierParams *VerifierContext)`: The main function for the Prover to generate the combined ZKP based on their private data and the Verifier's requirements.
20. `verifyEligibilityProof(proof *EligibilityProof, verifierParams *VerifierContext)`: The main function for the Verifier to verify the combined ZKP against their public expectations.
21. `simulateLicenseCredentialSetup(licenseSecret FieldElement, G_lic Point)`: A helper function to simulate the issuance of a license credential, returning its public key/point.
22. `deriveDataIdentifierScalar(patientData []byte)`: A helper for the Prover to compute a secret scalar identifier from raw patient data, representing its schema compliance.
23. `createExpectedDataIdentifierPoint(expectedDataIdentifierScalar FieldElement, G_data Point)`: A helper for the Verifier to compute the public point representing the expected data identifier based on an approved data schema.

---
**Total Functions: 23**

```go
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"hash/sha256"
	"io"
	"math/big"
)

// --- I. Cryptographic Primitives ---

// curve stores the elliptic curve parameters for P256, a commonly used curve.
var curve = elliptic.P256()

// FieldElement represents an element in the finite field modulo curve.N.
type FieldElement struct {
	val *big.Int
}

// newFieldElement creates a new FieldElement from a big.Int, reducing it modulo curve.N.
func newFieldElement(val *big.Int) FieldElement {
	return FieldElement{new(big.Int).Mod(val, curve.N)}
}

// fieldAdd adds two field elements modulo curve.N.
func fieldAdd(a, b FieldElement) FieldElement {
	return newFieldElement(new(big.Int).Add(a.val, b.val))
}

// fieldSub subtracts two field elements modulo curve.N.
func fieldSub(a, b FieldElement) FieldElement {
	return newFieldElement(new(big.Int).Sub(a.val, b.val))
}

// fieldMul multiplies two field elements modulo curve.N.
func fieldMul(a, b FieldElement) FieldElement {
	return newFieldElement(new(big.Int).Mul(a.val, b.val))
}

// fieldInv computes the modular multiplicative inverse of a field element modulo curve.N.
func fieldInv(a FieldElement) FieldElement {
	// A new big.Int is created for the result to avoid modifying 'a.val' in place.
	return newFieldElement(new(big.Int).ModInverse(a.val, curve.N))
}

// Point represents an elliptic curve point.
type Point struct {
	X, Y *big.Int
}

// newPoint creates a new Point. Handles the point at infinity if X,Y are nil.
func newPoint(x, y *big.Int) Point {
	return Point{X: x, Y: y}
}

// pointScalarMult performs scalar multiplication of an elliptic curve point P by a scalar.
// Returns scalar * P.
func pointScalarMult(p Point, scalar FieldElement) Point {
	x, y := curve.ScalarMult(p.X, p.Y, scalar.val.Bytes())
	return newPoint(x, y)
}

// pointAdd adds two elliptic curve points P1 and P2.
// Returns P1 + P2.
func pointAdd(p1, p2 Point) Point {
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return newPoint(x, y)
}

// generateRandomScalar generates a cryptographically secure random scalar within the field [1, N-1].
func generateRandomScalar() FieldElement {
	k, err := rand.Int(rand.Reader, curve.N)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
	}
	// We want scalars in [1, N-1], so if it's 0, generate again.
	for k.Cmp(big.NewInt(0)) == 0 {
		k, err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate non-zero random scalar: %v", err))
		}
	}
	return newFieldElement(k)
}

// hashToField hashes arbitrary byte data to a field element.
// It uses SHA256 and then reduces the hash digest modulo curve.N.
func hashToField(data []byte) FieldElement {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Convert the hash digest bytes to a big.Int, then reduce modulo N.
	return newFieldElement(new(big.Int).SetBytes(digest))
}

// --- II. ZKP Core Components ---

// setupGenerators generates and returns two independent curve generators G and H.
// G is the standard base point of P256. H is derived from a hash to provide
// another distinct, publicly verifiable generator.
func setupGenerators() (G, H Point) {
	// G is the standard base point of the P256 curve.
	G = newPoint(curve.Gx, curve.Gy)

	// H is derived by hashing a seed to a scalar and multiplying G by that scalar.
	// This ensures H is a public, verifiable point on the curve, distinct from G.
	hSeed := hashToField([]byte("ZK_Eligibility_Generator_H_Seed"))
	H = pointScalarMult(G, hSeed)

	// Basic check to ensure H is not G (highly unlikely) and not the point at infinity.
	if H.X == nil || (H.X.Cmp(G.X) == 0 && H.Y.Cmp(G.Y) == 0) {
		panic("Failed to generate independent generator H")
	}

	return G, H
}

// SchnorrPoKDLProof represents a Schnorr Proof of Knowledge of Discrete Logarithm.
// It consists of a commitment point R and a response scalar S.
type SchnorrPoKDLProof struct {
	R Point        // Commitment point (r*G)
	S FieldElement // Response scalar (r + e*x)
}

// generateSchnorrPoKDLProof generates a Schnorr proof for knowledge of a secret `x`
// such that `P = x*G`.
// secret: The prover's secret scalar `x`.
// G: The generator point `G`.
// challenge: The verifier's challenge scalar `e`.
func generateSchnorrPoKDLProof(secret FieldElement, G Point, challenge FieldElement) SchnorrPoKDLProof {
	r := generateRandomScalar() // Prover's ephemeral randomness (nonce)
	R := pointScalarMult(G, r)  // Commitment: R = r*G
	s := fieldAdd(r, fieldMul(challenge, secret)) // Response: s = r + e*x
	return SchnorrPoKDLProof{R: R, S: s}
}

// verifySchnorrPoKDLProof verifies a Schnorr proof.
// proof: The proof to verify (R, S).
// G: The generator point `G`.
// P: The public key point `P` (where `P = x*G`).
// challenge: The verifier's challenge scalar `e`.
// Returns true if `S*G == R + e*P`, false otherwise.
func verifySchnorrPoKDLProof(proof *SchnorrPoKDLProof, G, P Point, challenge FieldElement) bool {
	left := pointScalarMult(G, proof.S)                // S*G
	right := pointAdd(proof.R, pointScalarMult(P, challenge)) // R + e*P
	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

// --- III. Application Specific Structures & Protocol ---

// EligibilityProof combines all components of the aggregate proof for eligibility.
type EligibilityProof struct {
	// LicensePoKDL proves knowledge of the license secret.
	LicensePoKDL SchnorrPoKDLProof
	// DataIDPoKDL proves knowledge of the data identifier secret.
	DataIDPoKDL SchnorrPoKDLProof
	// CombinedChallenge ties both individual proofs together.
	CombinedChallenge FieldElement
}

// ProverContext holds the prover's secret credentials and data.
type ProverContext struct {
	LicenseSecret        FieldElement // Secret scalar associated with the medical license.
	PatientData          []byte       // The actual sensitive patient data (kept private).
	DataIdentifierScalar FieldElement // Secret scalar derived from patientData.
}

// VerifierContext holds public parameters and expected policy identifiers.
type VerifierContext struct {
	G_lic                       Point // Generator used for license proofs.
	PublicKey_LicenseCredential Point // Public point representing the Prover's license credential.
	G_data                      Point // Generator used for data identifier proofs.
	ExpectedDataIdentifierPoint Point // Public point representing the expected data identifier.
}

// computeCombinedChallenge generates a deterministic challenge for the aggregated proof.
// It incorporates all public parameters and the commitment points (R values) from the individual proofs
// to prevent replay attacks and securely link the proofs.
func computeCombinedChallenge(licProofCommitmentR, dataIDProofCommitmentR Point, verifierParams *VerifierContext) FieldElement {
	h := sha256.New()
	io.WriteString(h, "ZK_ELIGIBILITY_CHALLENGE_SEED") // Static seed for domain separation
	// Include all public parameters to ensure the challenge is unique to this context
	h.Write(verifierParams.G_lic.X.Bytes())
	h.Write(verifierParams.G_lic.Y.Bytes())
	h.Write(verifierParams.PublicKey_LicenseCredential.X.Bytes())
	h.Write(verifierParams.PublicKey_LicenseCredential.Y.Bytes())
	h.Write(verifierParams.G_data.X.Bytes())
	h.Write(verifierParams.G_data.Y.Bytes())
	h.Write(verifierParams.ExpectedDataIdentifierPoint.X.Bytes())
	h.Write(verifierParams.ExpectedDataIdentifierPoint.Y.Bytes())
	// Include the commitment points from the prover's side to make the challenge dependent on them
	h.Write(licProofCommitmentR.X.Bytes())
	h.Write(licProofCommitmentR.Y.Bytes())
	h.Write(dataIDProofCommitmentR.X.Bytes())
	h.Write(dataIDProofCommitmentR.Y.Bytes())
	return hashToField(h.Sum(nil))
}

// generateEligibilityProof is the main function for the Prover to generate the combined ZKP.
// It takes the Prover's secret context and the Verifier's public parameters.
// Returns an EligibilityProof struct or an error if proof generation fails.
func generateEligibilityProof(prover *ProverContext, verifierParams *VerifierContext) (*EligibilityProof, error) {
	// 1. Generate ephemeral randomness for each sub-proof (nonce)
	r_lic := generateRandomScalar()
	r_data := generateRandomScalar()

	// 2. Compute commitments (R values) for each sub-proof
	R_lic := pointScalarMult(verifierParams.G_lic, r_lic)
	R_data := pointScalarMult(verifierParams.G_data, r_data)

	// 3. Compute the combined challenge based on all public data and commitments
	challenge := computeCombinedChallenge(R_lic, R_data, verifierParams)

	// 4. Generate individual Schnorr responses (S values) using the combined challenge
	s_lic := fieldAdd(r_lic, fieldMul(challenge, prover.LicenseSecret))
	s_data := fieldAdd(r_data, fieldMul(challenge, prover.DataIdentifierScalar))

	return &EligibilityProof{
		LicensePoKDL: SchnorrPoKDLProof{
			R: R_lic,
			S: s_lic,
		},
		DataIDPoKDL: SchnorrPoKDLProof{
			R: R_data,
			S: s_data,
		},
		CombinedChallenge: challenge,
	}, nil
}

// verifyEligibilityProof is the main function for the Verifier to verify the combined ZKP.
// It takes the generated EligibilityProof and the Verifier's public parameters.
// Returns true if all proofs are valid, false otherwise, along with an error for failure details.
func verifyEligibilityProof(proof *EligibilityProof, verifierParams *VerifierContext) (bool, error) {
	// 1. Recompute the combined challenge using the R values from the proof
	recomputedChallenge := computeCombinedChallenge(proof.LicensePoKDL.R, proof.DataIDPoKDL.R, verifierParams)

	// 2. Verify that the recomputed challenge matches the one provided in the proof.
	// This step is crucial for security, linking the proof components.
	if recomputedChallenge.val.Cmp(proof.CombinedChallenge.val) != 0 {
		return false, fmt.Errorf("challenge mismatch: recomputed challenge does not match proof's challenge")
	}

	// 3. Verify Professional Credential PoKDL: Checks if the Prover knows 'licenseSecret'
	// such that PublicKey_LicenseCredential = licenseSecret * G_lic.
	licVerified := verifySchnorrPoKDLProof(
		&proof.LicensePoKDL,
		verifierParams.G_lic,
		verifierParams.PublicKey_LicenseCredential,
		proof.CombinedChallenge,
	)
	if !licVerified {
		return false, fmt.Errorf("professional credential proof failed")
	}

	// 4. Verify Data Identifier PoKDL: Checks if the Prover knows 'dataIdentifierScalar'
	// such that ExpectedDataIdentifierPoint = dataIdentifierScalar * G_data.
	dataIDVerified := verifySchnorrPoKDLProof(
		&proof.DataIDPoKDL,
		verifierParams.G_data,
		verifierParams.ExpectedDataIdentifierPoint,
		proof.CombinedChallenge,
	)
	if !dataIDVerified {
		return false, fmt.Errorf("data identifier proof failed")
	}

	return true, nil
}

// simulateLicenseCredentialSetup simulates the issuance of a license credential by a trusted authority.
// In a real system, an Issuer would generate `licenseSecret` and provide its public point
// (`licenseSecret * G_lic`) to the Prover and potentially publish it for Verifiers.
// This function returns the public point derived from the license secret.
func simulateLicenseCredentialSetup(licenseSecret FieldElement, G_lic Point) Point {
	return pointScalarMult(G_lic, licenseSecret)
}

// deriveDataIdentifierScalar computes a secret scalar from sensitive patient data.
// This scalar acts as the "identifier" for the data's schema compliance.
// In a real-world scenario, this might involve hashing specific, anonymized fields
// of the patient data in a prescribed manner to derive a unique, privacy-preserving scalar.
// For this simulation, we simply hash the entire patient data.
func deriveDataIdentifierScalar(patientData []byte) FieldElement {
	return hashToField(patientData)
}

// createExpectedDataIdentifierPoint computes the public point representing the
// expected data identifier. This is derived from a public, approved data schema specification.
// The `expectedDataIdentifierScalar` would be known to the Verifier (e.g., hash of an approved schema).
func createExpectedDataIdentifierPoint(expectedDataIdentifierScalar FieldElement, G_data Point) Point {
	return pointScalarMult(G_data, expectedDataIdentifierScalar)
}

func main() {
	fmt.Println("Starting ZK-Verified Data Processing Eligibility Proof simulation...")

	// --- 0. Global Setup ---
	// Setup global generators G and H for the curve. These are public.
	G, H := setupGenerators()

	// For this application, G_lic and G_data represent the specific generators
	// used for the license credential proofs and data identifier proofs, respectively.
	// They could be G, H, or other distinct points. Here, we use G and H for clarity.
	G_lic := G
	G_data := H

	// --- 1. Prover Setup (Secrets) ---
	fmt.Println("\n--- Prover Setup (Secrets) ---")

	// Prover's secret license ID scalar. This is a private value known only to the prover,
	// derived from their actual medical license details.
	proverLicenseSecret := generateRandomScalar()
	fmt.Printf("Prover's private License Secret (partial hash for display): %s...\n", proverLicenseSecret.val.String()[:10])

	// Prover's sensitive patient data. This is the private input the prover wishes to process.
	proverPatientData := []byte(`{"patientID":"anon_patient_123","diagnosis":"hypertension","medications":["lisinopril"],"lab_results":{"cholesterol":"normal"}}`)
	fmt.Printf("Prover's private Patient Data (sensitive, not revealed): %s (length %d)\n", proverPatientData, len(proverPatientData))

	// Prover derives a secret scalar identifier from their patient data.
	// This scalar represents the adherence of the patient data to a privacy-preserving schema.
	proverDataIdentifierScalar := deriveDataIdentifierScalar(proverPatientData)
	fmt.Printf("Prover's derived Data Identifier Scalar (private): %s...\n", proverDataIdentifierScalar.val.String()[:10])

	proverContext := &ProverContext{
		LicenseSecret:        proverLicenseSecret,
		PatientData:          proverPatientData, // The actual data is not part of the proof, only its derived scalar.
		DataIdentifierScalar: proverDataIdentifierScalar,
	}

	// --- 2. Verifier Setup (Public Parameters & Expectations) ---
	fmt.Println("\n--- Verifier Setup (Public Parameters & Expectations) ---")

	// Simulate License Credential issuance:
	// A trusted Issuer generates `publicKeyLicenseCredential` using the Prover's secret.
	// This public key is then shared with the Prover and is publicly known to the Verifier.
	publicKeyLicenseCredential := simulateLicenseCredentialSetup(proverLicenseSecret, G_lic)
	fmt.Printf("Public Key for License Credential: (%s..., %s...)\n", publicKeyLicenseCredential.X.String()[:10], publicKeyLicenseCredential.Y.String()[:10])

	// Verifier defines the expected data schema identifier:
	// This scalar is derived from a publicly approved, privacy-preserving data schema.
	// The Prover must demonstrate that their private data leads to this same scalar.
	expectedPatientDataForSchemaCompliance := []byte(`{"patientID":"anon_approved","diagnosis":"approved_category","medications":[],"lab_results":{"cholesterol":"any_value"}}`)
	expectedDataIdentifierScalar := deriveDataIdentifierScalar(expectedPatientDataForSchemaCompliance)
	expectedDataIdentifierPoint := createExpectedDataIdentifierPoint(expectedDataIdentifierScalar, G_data)
	fmt.Printf("Verifier's Expected Data Identifier Scalar (from approved schema): %s...\n", expectedDataIdentifierScalar.val.String()[:10])
	fmt.Printf("Verifier's Expected Data Identifier Point: (%s..., %s...)\n", expectedDataIdentifierPoint.X.String()[:10], expectedDataIdentifierPoint.Y.String()[:10])

	verifierContext := &VerifierContext{
		G_lic:                       G_lic,
		PublicKey_LicenseCredential: publicKeyLicenseCredential,
		G_data:                      G_data,
		ExpectedDataIdentifierPoint: expectedDataIdentifierPoint,
	}

	// --- 3. Prover Generates ZKP ---
	fmt.Println("\n--- Prover Generating Proof ---")
	eligibilityProof, err := generateEligibilityProof(proverContext, verifierContext)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}
	fmt.Println("Proof generated successfully. Prover does not reveal secrets.")
	// The `eligibilityProof` is what the Prover sends to the Verifier.
	// `proverLicenseSecret`, `proverPatientData`, `proverDataIdentifierScalar` remain private.

	// --- 4. Verifier Verifies ZKP ---
	fmt.Println("\n--- Verifier Verifying Proof ---")
	isVerified, err := verifyEligibilityProof(eligibilityProof, verifierContext)
	if err != nil {
		fmt.Printf("Proof verification failed: %v\n", err)
	} else if isVerified {
		fmt.Println("✅ SUCCESS: Eligibility Proof Verified! Prover is eligible to access the AI service.")
	} else {
		fmt.Println("❌ FAILURE: Eligibility Proof Failed! Prover is NOT eligible to access the AI service.")
	}

	// --- 5. Negative Test Case 1: Invalid Data ---
	fmt.Println("\n--- Negative Test Case 1: Invalid Data ---")
	// Scenario: Prover attempts to use patient data that does NOT conform to the expected schema.
	invalidPatientData := []byte(`{"patientID":"anon_evil","diagnosis":"confidential_info","medications":["unapproved_drug"],"secret_field":"very_sensitive"}`)
	invalidDataIdentifierScalar := deriveDataIdentifierScalar(invalidPatientData)

	invalidProverContextData := &ProverContext{
		LicenseSecret:        proverLicenseSecret, // License is still valid
		PatientData:          invalidPatientData,
		DataIdentifierScalar: invalidDataIdentifierScalar, // This scalar will not match Verifier's expectation
	}

	fmt.Println("Prover attempts to generate proof with invalid patient data (different schema identifier)...")
	invalidEligibilityProofData, err := generateEligibilityProof(invalidProverContextData, verifierContext)
	if err != nil {
		fmt.Printf("Error generating invalid data proof: %v\n", err)
		return
	}

	fmt.Println("Verifier attempts to verify proof with invalid patient data...")
	isInvalidVerifiedData, err := verifyEligibilityProof(invalidEligibilityProofData, verifierContext)
	if err != nil {
		fmt.Printf("✅ SUCCESS: Proof verification correctly failed for invalid data: %v\n", err)
	} else if isInvalidVerifiedData {
		fmt.Println("❌ FAILURE: Invalid data proof was unexpectedly Verified!")
	} else {
		fmt.Println("✅ SUCCESS: Invalid data proof was correctly NOT Verified.")
	}

	// --- 6. Negative Test Case 2: Invalid License ---
	fmt.Println("\n--- Negative Test Case 2: Invalid License ---")
	// Scenario: Prover has an invalid license (i.e., they don't know the secret corresponding to the public license key).
	invalidLicenseSecret := generateRandomScalar() // A random, different secret
	invalidProverContextLicense := &ProverContext{
		LicenseSecret:        invalidLicenseSecret, // Invalid license secret
		PatientData:          proverPatientData,    // Data is valid but doesn't matter without valid license
		DataIdentifierScalar: proverDataIdentifierScalar,
	}

	fmt.Println("Prover attempts to generate proof with invalid license secret...")
	invalidEligibilityProofLicense, err := generateEligibilityProof(invalidProverContextLicense, verifierContext)
	if err != nil {
		fmt.Printf("Error generating invalid license proof: %v\n", err)
		return
	}

	fmt.Println("Verifier attempts to verify proof with invalid license...")
	isInvalidVerifiedLicense, err := verifyEligibilityProof(invalidEligibilityProofLicense, verifierContext)
	if err != nil {
		fmt.Printf("✅ SUCCESS: Proof verification correctly failed for invalid license: %v\n", err)
	} else if isInvalidVerifiedLicense {
		fmt.Println("❌ FAILURE: Invalid license proof was unexpectedly Verified!")
	} else {
		fmt.Println("✅ SUCCESS: Invalid license proof was correctly NOT Verified.")
	}
}
```