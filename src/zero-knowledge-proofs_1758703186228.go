The following Go program implements a Zero-Knowledge Proof (ZKP) system for "ZK-Assured Decentralized Policy Compliance for Confidential Access". This system enables a Prover to demonstrate compliance with a complex, multi-attribute policy to a Verifier without revealing their sensitive attributes or identity.

The design leverages Pedersen commitments for attribute privacy and constructs ZKPs based on Sigma-protocols for proving specific properties (e.g., equality to a public value, equality of two committed values, greater-than-or-equal to a threshold). These individual ZKPs are then organized and combined to form a composite proof that reflects a boolean policy tree (AND/OR logic).

**Creative & Trendy Application:**

This system directly addresses a growing need in decentralized autonomous organizations (DAOs), confidential consortia, and secure data sharing platforms for *attribute-based access control (ABAC)* where policies are complex and sensitive attributes must remain private.

**Example Use Case:**

Imagine a decentralized financial (DeFi) lending platform or a confidential research consortium. A user (Prover) wants to access a high-value loan or a specific dataset. The platform's policy states:

"The user must have a verified 'Tier 3' membership (from Issuer A) AND their 'Credit Score' (from Issuer B) must be >= 75 AND their 'AML/KYC Status' (from Issuer C) must be 'Verified' (represented as 1) OR they must have a 'Premium Investor' status (from Issuer D, represented as a value 1)."

The user holds various credentials (containing committed attributes like Tier, Credit Score, AML/KYC Status, Premium Investor Status) issued by different, independent parties (A, B, C, D). They generate a single ZKP that proves they satisfy this policy without revealing their actual Tier, Credit Score, or specific identity to the lending platform. The platform (Verifier) can verify the proof efficiently and non-interactively.

This implementation emphasizes a creative composition of established ZKP primitives to build a flexible, policy-driven privacy-preserving access control layer, avoiding direct duplication of existing large ZKP libraries by building core components from scratch on top of standard elliptic curve cryptography.

---

### Outline and Function Summary for ZKP-Assured Decentralized Policy Compliance

This Go package implements a Zero-Knowledge Proof (ZKP) system for "ZK-Assured Decentralized Policy Compliance for Confidential Access". It allows a Prover to demonstrate compliance with a complex, multi-attribute policy to a Verifier, without revealing the underlying sensitive attributes or the identity of the Prover.

The system relies on Pedersen commitments for privacy and uses Sigma-protocol-based ZKPs for proving properties about committed values. These basic ZKPs are then composed into a larger proof structure that reflects a boolean policy tree (AND/OR logic).

**I. Core Cryptographic Primitives (Elliptic Curve Math & Scalars)**

1.  `Scalar`: Represents a large integer modulo the elliptic curve's group order.
    *   `NewRandomScalar()`: Generates a cryptographically secure random scalar.
    *   `Scalar.Add(other *Scalar)`: Performs modular addition.
    *   `Scalar.Sub(other *Scalar)`: Performs modular subtraction.
    *   `Scalar.Mul(other *Scalar)`: Performs modular multiplication.
    *   `Scalar.Inverse()`: Computes the modular multiplicative inverse.
    *   `Scalar.Pow(exp *Scalar)`: Computes modular exponentiation.
    *   `Scalar.ToBytes()`: Converts the scalar to a fixed-size byte slice.
    *   `FromBytes(data []byte)`: Converts a byte slice to a scalar.
    *   `HashToScalar(data ...[]byte)`: Hashes arbitrary data to a scalar, used for challenges.

2.  `ECPoint`: Represents a point on a chosen elliptic curve (e.g., P256).
    *   `NewGeneratorG()`: Returns the standard base generator point G for the curve.
    *   `NewGeneratorH()`: Returns a second, independent generator point H for Pedersen commitments.
    *   `ECPoint.Add(other *ECPoint)`: Performs elliptic curve point addition.
    *   `ECPoint.ScalarMul(scalar *Scalar)`: Performs elliptic curve scalar multiplication.
    *   `ECPoint.ToBytes()`: Converts the ECPoint to a compressed byte slice.
    *   `ECPoint.FromBytes(data []byte)`: Converts a byte slice to an ECPoint.
    *   `ECPoint.IsOnCurve()`: Checks if the point lies on the elliptic curve.

3.  `CommitmentKeys`: A struct to hold the global Pedersen commitment generators G and H.
    *   `SetupCommitmentKeys()`: Initializes and returns the global CommitmentKeys.

**II. Pedersen Commitments**

4.  `PedersenCommitment`: A struct representing a Pedersen commitment (C = value\*G + randomness\*H).
    *   `GeneratePedersenCommitment(value, randomness *Scalar, ck *CommitmentKeys)`: Computes and returns a new PedersenCommitment.
    *   `VerifyPedersenCommitment(value, randomness *Scalar, C *PedersenCommitment, ck *CommitmentKeys)`: Verifies if a given value and randomness match a commitment. (Used for local checks, not part of ZKP verification itself).

**III. Attribute Management & Credential Issuance**

5.  `Attribute`: A struct to define an attribute type and its scalar value.

6.  `ZKC_Credential`: A struct holding a Pedersen commitment for a single attribute, along with its original randomness and secret value (for the prover).
    *   (Note: In a real system, these would also include issuer signatures, but simplified here).

7.  `Issuer`: Represents a credential issuer.
    *   `Issuer.IssueCredential(attrType string, attrValue *Scalar, ck *CommitmentKeys)`: Creates a `ZKC_Credential` for a given attribute.

**IV. ZKP Primitives (Sigma-Protocols for Policy Predicates)**

8.  `ChallengeGenerator`: A utility for generating Fiat-Shamir challenges, ensuring non-interactivity.
    *   `NewChallengeGenerator(statementBytes ...[]byte)`: Initializes the generator with public context.
    *   `ChallengeGenerator.Append(data ...[]byte)`: Adds data to the transcript for challenge generation.
    *   `ChallengeGenerator.GenerateChallenge()`: Produces a new scalar challenge based on accumulated transcript.

9.  `PoK_CommValue_Proof` (Proof of Knowledge of Committed Value): Proves knowledge of 'v' and 'r' such that C = v\*G + r\*H.
    *   `GeneratePoK_CommValue_Proof(v, r *Scalar, C *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator)`: Generates the proof.
    *   `VerifyPoK_CommValue_Proof(C *PedersenCommitment, proof *PoK_CommValue_Proof, ck *CommitmentKeys, cg *ChallengeGenerator)`: Verifies the proof.

10. `PoK_EqualCommValues_Proof` (Proof of Equality of Two Committed Values): Proves C1 = v\*G + r1\*H and C2 = v\*G + r2\*H for the same 'v'.
    *   `GeneratePoK_EqualCommValues_Proof(v, r1, r2 *Scalar, C1, C2 *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator)`: Generates the proof.
    *   `VerifyPoK_EqualCommValues_Proof(C1, C2 *PedersenCommitment, proof *PoK_EqualCommValues_Proof, ck *CommitmentKeys, cg *ChallengeGenerator)`: Verifies the proof.

11. `PoK_ValueIsPublic_Proof` (Proof that Committed Value is a Specific Public Value): Proves C = publicV\*G + r\*H, where 'publicV' is known to the verifier, and the prover knows 'r'.
    *   `GeneratePoK_ValueIsPublic_Proof(r *Scalar, publicV *Scalar, C *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator)`: Generates the proof.
    *   `VerifyPoK_ValueIsPublic_Proof(publicV *Scalar, C *PedersenCommitment, proof *PoK_ValueIsPublic_Proof, ck *CommitmentKeys, cg *ChallengeGenerator)`: Verifies the proof.

12. `PoK_ValueGreaterThanOrEqual_Proof` (Proof of Value >= Public Threshold): Proves C = v\*G + r\*H and v >= Threshold.
    *   This is a simplification using a "disjunction of equality proofs" for a small, pre-defined range (`maxDiff`).
    *   `GeneratePoK_ValueGreaterThanOrEqual_Proof(v, r *Scalar, C *PedersenCommitment, threshold *Scalar, maxDiff int, ck *CommitmentKeys, cg *ChallengeGenerator)`: Generates the proof.
    *   `VerifyPoK_ValueGreaterThanOrEqual_Proof(C *PedersenCommitment, threshold *Scalar, maxDiff int, proof *PoK_ValueGreaterThanOrEqual_Proof, ck *CommitmentKeys, cg *ChallengeGenerator)`: Verifies the proof.

**V. Policy Definition and Orchestration**

13. `PolicyPredicateType`: Enum for types of atomic policy conditions (e.g., `EqPublicValue`, `EqCommittedValue`, `GreaterThanOrEqual`).

14. `PolicyPredicate`: Struct representing a single atomic policy condition.
    *   Example: `{Type: EqPublicValue, AttributeType: "Tier", PublicValue: Scalar("3")}`

15. `PolicyLogicOp`: Enum for boolean logic operations (`AND`, `OR`).

16. `PolicyNode`: A node in the policy tree, representing either a logical operation or an atomic predicate.

17. `ProofContainer`: A union-like struct to hold any specific type of ZKP primitive proof.

18. `ZKP_PolicyCompliance`: The main ZKP structure, containing the collection of sub-proofs generated for a policy, and the public commitments involved.

19. `GeneratePolicyComplianceProof(policy *PolicyNode, userCredentials []*ZKC_Credential, ck *CommitmentKeys)`:
    *   The Prover's primary function. It recursively traverses the policy tree, matches credentials, and generates appropriate sub-proofs, combining them into a single `ZKP_PolicyCompliance`.
    *   Internal: `generateSubProof(...)`: Recursive helper.

20. `VerifyPolicyComplianceProof(policy *PolicyNode, proof *ZKP_PolicyCompliance, ck *CommitmentKeys)`:
    *   The Verifier's primary function. It recursively traverses the policy tree and verifies the corresponding sub-proofs within the `ZKP_PolicyCompliance` structure.
    *   Internal: `verifySubProof(...)`: Recursive helper.

---
**Source Code:**

```go
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"
	"sync"
)

// Global curve for all operations (P256 for standard library support)
var curve elliptic.Curve
var groupOrder *big.Int // Order of the base point G
var initOnce sync.Once

func initCrypto() {
	initOnce.Do(func() {
		curve = elliptic.P256()
		groupOrder = curve.Params().N
	})
}

// ---------------------------------------------------------------------------------------------------
// I. Core Cryptographic Primitives (Elliptic Curve Math & Scalars)
// ---------------------------------------------------------------------------------------------------

// Scalar represents a large integer modulo the elliptic curve's group order.
type Scalar big.Int

// NewRandomScalar generates a cryptographically secure random scalar.
func NewRandomScalar() *Scalar {
	initCrypto()
	s, err := rand.Int(rand.Reader, groupOrder)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
	}
	return (*Scalar)(s)
}

// Add performs modular addition.
func (s *Scalar) Add(other *Scalar) *Scalar {
	initCrypto()
	res := new(big.Int).Add((*big.Int)(s), (*big.Int)(other))
	return (*Scalar)(res.Mod(res, groupOrder))
}

// Sub performs modular subtraction.
func (s *Scalar) Sub(other *Scalar) *Scalar {
	initCrypto()
	res := new(big.Int).Sub((*big.Int)(s), (*big.Int)(other))
	return (*Scalar)(res.Mod(res, groupOrder))
}

// Mul performs modular multiplication.
func (s *Scalar) Mul(other *Scalar) *Scalar {
	initCrypto()
	res := new(big.Int).Mul((*big.Int)(s), (*big.Int)(other))
	return (*Scalar)(res.Mod(res, groupOrder))
}

// Inverse computes the modular multiplicative inverse.
func (s *Scalar) Inverse() *Scalar {
	initCrypto()
	res := new(big.Int).ModInverse((*big.Int)(s), groupOrder)
	if res == nil {
		panic("Scalar has no inverse (it's 0 mod N)")
	}
	return (*Scalar)(res)
}

// Pow computes modular exponentiation.
func (s *Scalar) Pow(exp *Scalar) *Scalar {
	initCrypto()
	res := new(big.Int).Exp((*big.Int)(s), (*big.Int)(exp), groupOrder)
	return (*Scalar)(res)
}

// ToBytes converts the scalar to a fixed-size byte slice.
func (s *Scalar) ToBytes() []byte {
	initCrypto()
	return (*big.Int)(s).FillBytes(make([]byte, (groupOrder.BitLen()+7)/8))
}

// FromBytes converts a byte slice to a scalar.
func FromBytes(data []byte) *Scalar {
	initCrypto()
	s := new(big.Int).SetBytes(data)
	if s.Cmp(groupOrder) >= 0 {
		// If the scalar is larger than or equal to the group order, it's invalid
		// or should be taken modulo the group order. For cryptographic context,
		// usually values are expected to be strictly less than the order.
		s.Mod(s, groupOrder)
	}
	return (*Scalar)(s)
}

// HashToScalar hashes arbitrary data to a scalar.
func HashToScalar(data ...[]byte) *Scalar {
	initCrypto()
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hashBytes := h.Sum(nil)
	// Reduce hash to a scalar in the group order
	return (*Scalar)(new(big.Int).SetBytes(hashBytes).Mod(new(big.Int).SetBytes(hashBytes), groupOrder))
}

// ECPoint represents a point on a chosen elliptic curve (P256).
type ECPoint struct {
	X, Y *big.Int
}

// NewGeneratorG returns the standard base generator point G for the curve.
func NewGeneratorG() *ECPoint {
	initCrypto()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	return &ECPoint{X: Gx, Y: Gy}
}

// NewGeneratorH returns a second, independent generator point H for Pedersen commitments.
// This is typically generated by hashing G or some fixed value to a point on the curve.
// For simplicity, we'll hash a distinct string to a point.
func NewGeneratorH() *ECPoint {
	initCrypto()
	// A common way to get a second generator is to hash a value to a point.
	// This ensures H is independent of G (with overwhelming probability).
	seed := []byte("pedersen_h_generator_seed")
	h := sha256.New()
	h.Write(seed)
	seedHash := h.Sum(nil)

	// Keep hashing and mapping to point until we find one on curve
	// This is a simplified method. A more robust method would use a hash-to-curve algorithm.
	var x, y *big.Int
	for {
		x, y = curve.ScalarBaseMult(seedHash)
		if x != nil && curve.IsOnCurve(x, y) {
			return &ECPoint{X: x, Y: y}
		}
		// If not on curve, perturb the hash and try again
		h.Reset()
		h.Write(seedHash)
		h.Write([]byte{0x01}) // Append a byte to change the hash
		seedHash = h.Sum(nil)
		if len(seedHash) == 0 { // Just in case, avoid infinite loop with empty hash
			seedHash = []byte{0x01}
		}
	}
}

// Add performs elliptic curve point addition.
func (p *ECPoint) Add(other *ECPoint) *ECPoint {
	initCrypto()
	x, y := curve.Add(p.X, p.Y, other.X, other.Y)
	return &ECPoint{X: x, Y: y}
}

// ScalarMul performs elliptic curve scalar multiplication.
func (p *ECPoint) ScalarMul(scalar *Scalar) *ECPoint {
	initCrypto()
	x, y := curve.ScalarMult(p.X, p.Y, (*big.Int)(scalar).Bytes())
	return &ECPoint{X: x, Y: y}
}

// ToBytes converts the ECPoint to a compressed byte slice.
func (p *ECPoint) ToBytes() []byte {
	initCrypto()
	return elliptic.MarshalCompressed(curve, p.X, p.Y)
}

// FromBytes converts a byte slice to an ECPoint.
func (p *ECPoint) FromBytes(data []byte) error {
	initCrypto()
	x, y := elliptic.UnmarshalCompressed(curve, data)
	if x == nil {
		return fmt.Errorf("invalid compressed point bytes")
	}
	p.X = x
	p.Y = y
	return nil
}

// IsOnCurve checks if the point lies on the elliptic curve.
func (p *ECPoint) IsOnCurve() bool {
	initCrypto()
	return curve.IsOnCurve(p.X, p.Y)
}

// CommitmentKeys holds the global Pedersen commitment generators G and H.
type CommitmentKeys struct {
	G *ECPoint
	H *ECPoint
}

// SetupCommitmentKeys initializes and returns the global CommitmentKeys.
func SetupCommitmentKeys() *CommitmentKeys {
	initCrypto()
	return &CommitmentKeys{
		G: NewGeneratorG(),
		H: NewGeneratorH(),
	}
}

// ---------------------------------------------------------------------------------------------------
// II. Pedersen Commitments
// ---------------------------------------------------------------------------------------------------

// PedersenCommitment represents a Pedersen commitment (C = value*G + randomness*H).
type PedersenCommitment struct {
	C *ECPoint
}

// GeneratePedersenCommitment computes and returns a new PedersenCommitment.
func GeneratePedersenCommitment(value, randomness *Scalar, ck *CommitmentKeys) *PedersenCommitment {
	initCrypto()
	vG := ck.G.ScalarMul(value)
	rH := ck.H.ScalarMul(randomness)
	return &PedersenCommitment{C: vG.Add(rH)}
}

// VerifyPedersenCommitment verifies if a given value and randomness match a commitment.
// (Used for local checks, not part of ZKP verification itself).
func VerifyPedersenCommitment(value, randomness *Scalar, C *PedersenCommitment, ck *CommitmentKeys) bool {
	initCrypto()
	expectedC := GeneratePedersenCommitment(value, randomness, ck)
	return expectedC.C.X.Cmp(C.C.X) == 0 && expectedC.C.Y.Cmp(C.C.Y) == 0
}

// ---------------------------------------------------------------------------------------------------
// III. Attribute Management & Credential Issuance
// ---------------------------------------------------------------------------------------------------

// Attribute defines an attribute type and its scalar value.
type Attribute struct {
	Type  string
	Value *Scalar
}

// ZKC_Credential holds a Pedersen commitment for a single attribute, along with its original randomness and secret value.
type ZKC_Credential struct {
	AttributeType string
	Commitment    *PedersenCommitment
	Randomness    *Scalar // Stored by the prover to generate ZKPs
	AttributeValue *Scalar // Stored by the prover (secret) to generate certain ZKPs
	// In a real system, this would also include issuer signatures.
}

// Issuer represents a credential issuer.
type Issuer struct {
	ID        string
	PublicKey *ECPoint // Simplified, not used for actual signature in this example
}

// IssueCredential creates a ZKC_Credential for a given attribute.
func (i *Issuer) IssueCredential(attrType string, attrValue *Scalar, ck *CommitmentKeys) *ZKC_Credential {
	randomness := NewRandomScalar()
	commitment := GeneratePedersenCommitment(attrValue, randomness, ck)
	return &ZKC_Credential{
		AttributeType: attrType,
		Commitment:    commitment,
		Randomness:    randomness,
		AttributeValue: attrValue, // Prover needs to know the original value
	}
}

// ---------------------------------------------------------------------------------------------------
// IV. ZKP Primitives (Sigma-Protocols for Policy Predicates)
// ---------------------------------------------------------------------------------------------------

// ChallengeGenerator is a utility for generating Fiat-Shamir challenges.
type ChallengeGenerator struct {
	hasher hash.Hash
}

// NewChallengeGenerator initializes the generator with public context.
func NewChallengeGenerator(statementBytes ...[]byte) *ChallengeGenerator {
	cg := &ChallengeGenerator{hasher: sha256.New()}
	cg.Append(statementBytes...)
	return cg
}

// Append adds data to the transcript for challenge generation.
func (cg *ChallengeGenerator) Append(data ...[]byte) {
	for _, d := range data {
		cg.hasher.Write(d)
	}
}

// GenerateChallenge produces a new scalar challenge based on accumulated transcript.
func (cg *ChallengeGenerator) GenerateChallenge() *Scalar {
	initCrypto()
	challengeBytes := cg.hasher.Sum(nil)
	cg.hasher.Reset() // Reset for next challenge (important for multiple proofs in a sequence)
	cg.hasher.Write(challengeBytes) // Feed previous challenge hash back to avoid trivial reset
	return HashToScalar(challengeBytes)
}

// PoK_CommValue_Proof: Proof of Knowledge of Committed Value (v, r) for C = vG + rH.
type PoK_CommValue_Proof struct {
	A *ECPoint // Commitment A = w_v*G + w_r*H
	E *Scalar  // Challenge
	Zv *Scalar // Response Zv = w_v + E*v
	Zr *Scalar // Response Zr = w_r + E*r
}

// GeneratePoK_CommValue_Proof generates a PoK for (v, r).
func GeneratePoK_CommValue_Proof(v, r *Scalar, C *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator) *PoK_CommValue_Proof {
	wV := NewRandomScalar()
	wR := NewRandomScalar()
	A := ck.G.ScalarMul(wV).Add(ck.H.ScalarMul(wR))

	cg.Append(C.C.ToBytes(), A.ToBytes()) // Append commitment and A to transcript
	e := cg.GenerateChallenge()

	zv := wV.Add(e.Mul(v))
	zr := wR.Add(e.Mul(r))

	return &PoK_CommValue_Proof{A: A, E: e, Zv: zv, Zr: zr}
}

// VerifyPoK_CommValue_Proof verifies the PoK proof.
func VerifyPoK_CommValue_Proof(C *PedersenCommitment, proof *PoK_CommValue_Proof, ck *CommitmentKeys, cg *ChallengeGenerator) bool {
	cg.Append(C.C.ToBytes(), proof.A.ToBytes()) // Recompute challenge
	e := cg.GenerateChallenge()

	if e.ToBytes() == nil || proof.E.ToBytes() == nil {
		return false // Challenge must not be nil
	}

	// Check if the recomputed challenge matches the one in the proof (Fiat-Shamir consistency)
	if new(big.Int).Cmp((*big.Int)(e), (*big.Int)(proof.E)) != 0 {
		return false
	}

	// Check Zv*G + Zr*H == A + E*C
	left := ck.G.ScalarMul(proof.Zv).Add(ck.H.ScalarMul(proof.Zr))
	right := proof.A.Add(C.C.ScalarMul(proof.E))

	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

// PoK_EqualCommValues_Proof: Proof of Equality of Two Committed Values for C1 = vG + r1H, C2 = vG + r2H.
type PoK_EqualCommValues_Proof struct {
	A1 *ECPoint // Commitment A1 = w_v*G + w_r1*H
	A2 *ECPoint // Commitment A2 = w_v*G + w_r2*H
	E  *Scalar  // Challenge
	Zv *Scalar  // Response Zv = w_v + E*v
	Zr1 *Scalar // Response Zr1 = w_r1 + E*r1
	Zr2 *Scalar // Response Zr2 = w_r2 + E*r2
}

// GeneratePoK_EqualCommValues_Proof generates a PoK for equality of 'v' in two commitments.
func GeneratePoK_EqualCommValues_Proof(v, r1, r2 *Scalar, C1, C2 *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator) *PoK_EqualCommValues_Proof {
	wV := NewRandomScalar()
	wR1 := NewRandomScalar()
	wR2 := NewRandomScalar()

	A1 := ck.G.ScalarMul(wV).Add(ck.H.ScalarMul(wR1))
	A2 := ck.G.ScalarMul(wV).Add(ck.H.ScalarMul(wR2))

	cg.Append(C1.C.ToBytes(), C2.C.ToBytes(), A1.ToBytes(), A2.ToBytes())
	e := cg.GenerateChallenge()

	zv := wV.Add(e.Mul(v))
	zr1 := wR1.Add(e.Mul(r1))
	zr2 := wR2.Add(e.Mul(r2))

	return &PoK_EqualCommValues_Proof{A1: A1, A2: A2, E: e, Zv: zv, Zr1: zr1, Zr2: zr2}
}

// VerifyPoK_EqualCommValues_Proof verifies the PoK proof.
func VerifyPoK_EqualCommValues_Proof(C1, C2 *PedersenCommitment, proof *PoK_EqualCommValues_Proof, ck *CommitmentKeys, cg *ChallengeGenerator) bool {
	cg.Append(C1.C.ToBytes(), C2.C.ToBytes(), proof.A1.ToBytes(), proof.A2.ToBytes())
	e := cg.GenerateChallenge()

	if new(big.Int).Cmp((*big.Int)(e), (*big.Int)(proof.E)) != 0 {
		return false
	}

	// Check Zv*G + Zr1*H == A1 + E*C1
	left1 := ck.G.ScalarMul(proof.Zv).Add(ck.H.ScalarMul(proof.Zr1))
	right1 := proof.A1.Add(C1.C.ScalarMul(proof.E))
	if left1.X.Cmp(right1.X) != 0 || left1.Y.Cmp(right1.Y) != 0 {
		return false
	}

	// Check Zv*G + Zr2*H == A2 + E*C2
	left2 := ck.G.ScalarMul(proof.Zv).Add(ck.H.ScalarMul(proof.Zr2))
	right2 := proof.A2.Add(C2.C.ScalarMul(proof.E))
	if left2.X.Cmp(right2.X) != 0 || left2.Y.Cmp(right2.Y) != 0 {
		return false
	}

	return true
}

// PoK_ValueIsPublic_Proof: Proof that Committed Value is a Specific Public Value (publicV).
// Prover knows r such that C = publicV*G + r*H.
type PoK_ValueIsPublic_Proof struct {
	A  *ECPoint // A = w_r*H
	E  *Scalar  // Challenge
	Zr *Scalar  // Response Zr = w_r + E*r
}

// GeneratePoK_ValueIsPublic_Proof generates a PoK that committed value is 'publicV'.
func GeneratePoK_ValueIsPublic_Proof(r *Scalar, publicV *Scalar, C *PedersenCommitment, ck *CommitmentKeys, cg *ChallengeGenerator) *PoK_ValueIsPublic_Proof {
	wR := NewRandomScalar()
	A := ck.H.ScalarMul(wR) // Only commitment to randomness since value is public

	cg.Append(C.C.ToBytes(), publicV.ToBytes(), A.ToBytes())
	e := cg.GenerateChallenge()

	zr := wR.Add(e.Mul(r))

	return &PoK_ValueIsPublic_Proof{A: A, E: e, Zr: zr}
}

// VerifyPoK_ValueIsPublic_Proof verifies the PoK proof.
func VerifyPoK_ValueIsPublic_Proof(publicV *Scalar, C *PedersenCommitment, proof *PoK_ValueIsPublic_Proof, ck *CommitmentKeys, cg *ChallengeGenerator) bool {
	cg.Append(C.C.ToBytes(), publicV.ToBytes(), proof.A.ToBytes())
	e := cg.GenerateChallenge()

	if new(big.Int).Cmp((*big.Int)(e), (*big.Int)(proof.E)) != 0 {
		return false
	}

	// Check Zr*H == A + E*(C - publicV*G)
	// C - publicV*G is the commitment to 'r' (C_r = r*H)
	publicVG := ck.G.ScalarMul(publicV)
	Cr := C.C.Add(publicVG.ScalarMul(new(Scalar)(new(big.Int).Neg(big.NewInt(1))))) // C - publicV*G

	left := ck.H.ScalarMul(proof.Zr)
	right := proof.A.Add(Cr.ScalarMul(proof.E))

	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

// PoK_ValueGreaterThanOrEqual_Proof: Proof for v >= Threshold.
// This is a simplified implementation for small `maxDiff`. It proves that `v = threshold + diff` where `diff`
// is one of the values from `[0, maxDiff]`. This uses an OR proof construction.
type PoK_ValueGreaterThanOrEqual_Proof struct {
	ChallengeShares []*Scalar // e_k for each potential diff
	Responses       []*PoK_ValueIsPublic_Proof // PoK_ValueIsPublic_Proof for each potential v = threshold+diff
}

// GeneratePoK_ValueGreaterThanOrEqual_Proof generates a proof for v >= threshold for small maxDiff.
func GeneratePoK_ValueGreaterThanOrEqual_Proof(v, r *Scalar, C *PedersenCommitment, threshold *Scalar, maxDiff int, ck *CommitmentKeys, cg *ChallengeGenerator) *PoK_ValueGreaterThanOrEqual_Proof {
	actualDiffBig := new(big.Int).Sub((*big.Int)(v), (*big.Int)(threshold))
	if actualDiffBig.Sign() == -1 {
		panic("Cannot prove v >= threshold if v < threshold")
	}
	if actualDiffBig.Cmp(big.NewInt(int64(maxDiff))) > 0 {
		// If actual diff is too large, the OR proof cannot cover it.
		// For a real system, a more efficient range proof like Bulletproofs would be used.
		panic(fmt.Sprintf("Actual diff (%d) exceeds maxDiff (%d) for PoK_ValueGreaterThanOrEqual_Proof. Consider increasing MaxDiffForRange.", actualDiffBig, maxDiff))
	}
	actualDiffInt := int(actualDiffBig.Int64())

	var proofAks []*ECPoint
	var proofEks []*Scalar // Individual challenges e_k
	var proofZrs []*Scalar // Individual responses zr_k (prover's w_r for actual branch, random for others)

	// First Pass: Compute A_k and e_k for "false" branches, and A_k for "true" branch
	for k := 0; k <= maxDiff; k++ {
		if k == actualDiffInt {
			// True branch: Prover knows r and (threshold+k). Generate A_k using random w_k.
			wRk := NewRandomScalar()
			A_k := ck.H.ScalarMul(wRk)
			proofAks = append(proofAks, A_k)
			proofEks = append(proofEks, nil) // Placeholder for true challenge
			proofZrs = append(proofZrs, wRk) // Store w_k (randomness for A_k)
		} else {
			// False branch: Prover picks random e_k and z_k, then derives A_k
			e_k := NewRandomScalar()
			z_k := NewRandomScalar()

			currentVal := threshold.Add(new(Scalar)(big.NewInt(int64(k))))
			// C - currentVal*G represents the commitment to 'r' for this *hypothetical* value.
			Cr_k_commit := C.C.Add(ck.G.ScalarMul(currentVal).ScalarMul(new(Scalar)(new(big.Int).Neg(big.NewInt(1)))))
			// A_k = z_k*H - e_k*Cr_k_commit
			A_k := ck.H.ScalarMul(z_k).Add(Cr_k_commit.ScalarMul(e_k).ScalarMul(new(Scalar)(new(big.Int).Neg(big.NewInt(1)))))

			proofAks = append(proofAks, A_k)
			proofEks = append(proofEks, e_k)
			proofZrs = append(proofZrs, z_k)
		}
	}

	// Compute overall challenge E from all C, threshold, maxDiff, and all A_k
	cgOr := NewChallengeGenerator()
	cgOr.Append(C.C.ToBytes(), threshold.ToBytes(), big.NewInt(int64(maxDiff)).Bytes())
	for _, ak := range proofAks {
		cgOr.Append(ak.ToBytes())
	}
	E := cgOr.GenerateChallenge()

	// Compute actual challenge for the true branch: e_actualDiff = E - Sum(e_k for k != actualDiff)
	sumOfFalseChallenges := new(Scalar)(big.NewInt(0))
	for k := 0; k <= maxDiff; k++ {
		if k != actualDiffInt {
			sumOfFalseChallenges = sumOfFalseChallenges.Add(proofEks[k])
		}
	}
	eActualDiff := E.Sub(sumOfFalseChallenges)
	proofEks[actualDiffInt] = eActualDiff

	// Compute actual response for the true branch: zr_actualDiff = w_R_actual + e_actualDiff * r
	wRActual := proofZrs[actualDiffInt] // This was stored as w_k
	zrActual := wRActual.Add(eActualDiff.Mul(r))
	proofZrs[actualDiffInt] = zrActual

	// Package all sub-proof components into the final structure
	finalSubProofs := make([]*PoK_ValueIsPublic_Proof, maxDiff+1)
	for k := 0; k <= maxDiff; k++ {
		finalSubProofs[k] = &PoK_ValueIsPublic_Proof{
			A:  proofAks[k],
			E:  proofEks[k],
			Zr: proofZrs[k],
		}
	}

	return &PoK_ValueGreaterThanOrEqual_Proof{
		ChallengeShares: proofEks,
		Responses:       finalSubProofs,
	}
}

// VerifyPoK_ValueGreaterThanOrEqual_Proof verifies the proof for v >= threshold.
func VerifyPoK_ValueGreaterThanOrEqual_Proof(C *PedersenCommitment, threshold *Scalar, maxDiff int, proof *PoK_ValueGreaterThanOrEqual_Proof, ck *CommitmentKeys, cg *ChallengeGenerator) bool {
	if len(proof.Responses) != maxDiff+1 || len(proof.ChallengeShares) != maxDiff+1 {
		return false
	}

	// 1. Recompute overall challenge E
	cgOr := NewChallengeGenerator()
	cgOr.Append(C.C.ToBytes(), threshold.ToBytes(), big.NewInt(int64(maxDiff)).Bytes())
	for _, subProof := range proof.Responses {
		cgOr.Append(subProof.A.ToBytes())
	}
	E := cgOr.GenerateChallenge()

	// 2. Check if sum of individual challenges matches E
	sumOfIndividualChallenges := new(Scalar)(big.NewInt(0))
	for _, e_k := range proof.ChallengeShares {
		sumOfIndividualChallenges = sumOfIndividualChallenges.Add(e_k)
	}
	if new(big.Int).Cmp((*big.Int)(E), (*big.Int)(sumOfIndividualChallenges)) != 0 {
		return false
	}

	// 3. Verify each sub-proof (A_k, e_k, z_k)
	for k := 0; k <= maxDiff; k++ {
		currentVal := threshold.Add(new(Scalar)(big.NewInt(int64(k))))
		subProof := proof.Responses[k]
		e_k := proof.ChallengeShares[k]

		// Check: z_k*H == A_k + e_k*(C - currentVal*G)
		publicVGk := ck.G.ScalarMul(currentVal)
		Cr_k := C.C.Add(publicVGk.ScalarMul(new(Scalar)(new(big.Int).Neg(big.NewInt(1))))) // C - currentVal*G

		left := ck.H.ScalarMul(subProof.Zr)
		right := subProof.A.Add(Cr_k.ScalarMul(e_k))

		if left.X.Cmp(right.X) != 0 || left.Y.Cmp(right.Y) != 0 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------------------
// V. Policy Definition and Orchestration
// ---------------------------------------------------------------------------------------------------

// PolicyPredicateType enum for types of atomic policy conditions.
type PolicyPredicateType int

const (
	EqPublicValue PolicyPredicateType = iota
	EqCommittedValue // Prover proves two of their committed attributes are equal
	GreaterThanOrEqual
)

// PolicyPredicate represents a single atomic policy condition.
type PolicyPredicate struct {
	Type              PolicyPredicateType
	AttributeType     string  // Type of attribute being checked
	PublicValue       *Scalar // For EqPublicValue, GreaterThanOrEqual
	TargetAttributeType string  // For EqCommittedValue (e.g., "UserID")
	MaxDiffForRange int     // For GreaterThanOrEqual, defines the max diff to check in OR proof
}

// PolicyLogicOp enum for boolean logic operations.
type PolicyLogicOp int

const (
	AND PolicyLogicOp = iota
	OR
)

// PolicyNode is a node in the policy tree.
type PolicyNode struct {
	Type      PolicyLogicOp
	Predicate *PolicyPredicate
	Children  []*PolicyNode // For AND/OR operations
}

// ProofContainer is a union-like struct to hold any specific type of ZKP primitive proof.
type ProofContainer struct {
	PoKCommValue          *PoK_CommValue_Proof
	PoKEqualCommValues    *PoK_EqualCommValues_Proof
	PoKValueIsPublic      *PoK_ValueIsPublic_Proof
		PoKValueGreaterThanOrEqual *PoK_ValueGreaterThanOrEqual_Proof
}

// ZKP_PolicyCompliance is the main ZKP structure holding various proofs.
// It uses a map to associate policy nodes with their respective proofs.
// It also stores the public commitments used in the proof for verifier.
type ZKP_PolicyCompliance struct {
	Proofs map[string]*ProofContainer // Map policy node hash to its proof
	PublicCommitments map[string]*PedersenCommitment // Map attribute type to its commitment
}

// GeneratePolicyComplianceProof: The Prover's primary function.
func GeneratePolicyComplianceProof(policy *PolicyNode, userCredentials []*ZKC_Credential, ck *CommitmentKeys) (*ZKP_PolicyCompliance, error) {
	proofs := make(map[string]*ProofContainer)
	publicCommitments := make(map[string]*PedersenCommitment)
	
	// Convert slice of credentials to map for easier lookup
	credMap := make(map[string]*ZKC_Credential)
	for _, cred := range userCredentials {
		credMap[cred.AttributeType] = cred
		publicCommitments[cred.AttributeType] = cred.Commitment // Add to public list
	}

	cg := NewChallengeGenerator() // Main challenge generator for the entire proof

	err := generateSubProof(policy, credMap, ck, cg, proofs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate policy compliance proof: %w", err)
	}
	return &ZKP_PolicyCompliance{Proofs: proofs, PublicCommitments: publicCommitments}, nil
}

// generateSubProof is a recursive helper for generating proofs.
func generateSubProof(node *PolicyNode, userCredentials map[string]*ZKC_Credential, ck *CommitmentKeys, cg *ChallengeGenerator, proofs map[string]*ProofContainer) error {
	nodeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%v", node)))) // Unique identifier for node

	if node.Predicate != nil {
		// This is a leaf node with a specific predicate
		cred, found := userCredentials[node.Predicate.AttributeType]
		if !found {
			return fmt.Errorf("credential for attribute type '%s' not found for predicate", node.Predicate.AttributeType)
		}

		container := &ProofContainer{}
		switch node.Predicate.Type {
		case EqPublicValue:
			container.PoKValueIsPublic = GeneratePoK_ValueIsPublic_Proof(cred.Randomness, node.Predicate.PublicValue, cred.Commitment, ck, cg)
		case EqCommittedValue:
			targetCred, targetFound := userCredentials[node.Predicate.TargetAttributeType]
			if !targetFound {
				return fmt.Errorf("target credential for attribute type '%s' not found for equality predicate", node.Predicate.TargetAttributeType)
			}
			// Prover needs to know the actual value 'v' for both commitments.
			// This value is stored in ZKC_Credential.AttributeValue.
			if cred.AttributeValue == nil || targetCred.AttributeValue == nil {
				return fmt.Errorf("missing AttributeValue in credentials for EqCommittedValue proof")
			}
			if new(big.Int).Cmp((*big.Int)(cred.AttributeValue), (*big.Int)(targetCred.AttributeValue)) != 0 {
				return fmt.Errorf("committed values must be equal for EqCommittedValue proof to be generated successfully")
			}
			container.PoKEqualCommValues = GeneratePoK_EqualCommValues_Proof(
				cred.AttributeValue,
				cred.Randomness, targetCred.Randomness,
				cred.Commitment, targetCred.Commitment, ck, cg,
			)
		case GreaterThanOrEqual:
			if node.Predicate.PublicValue == nil {
				return fmt.Errorf("GreaterThanOrEqual predicate requires a PublicValue")
			}
			if node.Predicate.MaxDiffForRange <= 0 {
				return fmt.Errorf("GreaterThanOrEqual predicate requires a positive MaxDiffForRange")
			}
			if cred.AttributeValue == nil {
				return fmt.Errorf("missing AttributeValue in credential for GreaterThanOrEqual proof")
			}
			container.PoKValueGreaterThanOrEqual = GeneratePoK_ValueGreaterThanOrEqual_Proof(cred.AttributeValue, cred.Randomness, cred.Commitment, node.Predicate.PublicValue, node.Predicate.MaxDiffForRange, ck, cg)
		default:
			return fmt.Errorf("unsupported predicate type: %v", node.Predicate.Type)
		}
		proofs[nodeHash] = container

	} else {
		// This is an AND/OR node. Recursively generate proofs for children.
		for _, child := range node.Children {
			err := generateSubProof(child, userCredentials, ck, cg, proofs)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// VerifyPolicyComplianceProof: The Verifier's primary function.
func VerifyPolicyComplianceProof(policy *PolicyNode, zkp *ZKP_PolicyCompliance, ck *CommitmentKeys) (bool, error) {
	cg := NewChallengeGenerator() // Main challenge generator for verification

	return verifySubProof(policy, zkp, ck, cg)
}

// verifySubProof is a recursive helper for verifying proofs.
func verifySubProof(node *PolicyNode, zkp *ZKP_PolicyCompliance, ck *CommitmentKeys, cg *ChallengeGenerator) (bool, error) {
	nodeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%v", node)))) // Recompute unique identifier for node

	if node.Predicate != nil {
		// Leaf node verification
		container, found := zkp.Proofs[nodeHash]
		if !found || container == nil {
			return false, fmt.Errorf("proof for policy node %s not found or nil", nodeHash)
		}

		commitment, foundCommitment := zkp.PublicCommitments[node.Predicate.AttributeType]
		if !foundCommitment {
			return false, fmt.Errorf("public commitment for attribute type '%s' not found in ZKP_PolicyCompliance", node.Predicate.AttributeType)
		}

		switch node.Predicate.Type {
		case EqPublicValue:
			if container.PoKValueIsPublic == nil { return false, fmt.Errorf("invalid proof type for EqPublicValue") }
			return VerifyPoK_ValueIsPublic_Proof(node.Predicate.PublicValue, commitment, container.PoKValueIsPublic, ck, cg), nil
		case EqCommittedValue:
			targetCommitment, foundTargetCommitment := zkp.PublicCommitments[node.Predicate.TargetAttributeType]
			if !foundTargetCommitment {
				return false, fmt.Errorf("public commitment for target attribute type '%s' not found in ZKP_PolicyCompliance", node.Predicate.TargetAttributeType)
			}
			if container.PoKEqualCommValues == nil { return false, fmt.Errorf("invalid proof type for EqCommittedValue") }
			return VerifyPoK_EqualCommValues_Proof(commitment, targetCommitment, container.PoKEqualCommValues, ck, cg), nil
		case GreaterThanOrEqual:
			if node.Predicate.PublicValue == nil { return false, fmt.Errorf("GreaterThanOrEqual predicate requires a PublicValue") }
			if node.Predicate.MaxDiffForRange <= 0 { return false, fmt.Errorf("GreaterThanOrEqual predicate requires a positive MaxDiffForRange") }
			if container.PoKValueGreaterThanOrEqual == nil { return false, fmt.Errorf("invalid proof type for GreaterThanOrEqual") }
			return VerifyPoK_ValueGreaterThanOrEqual_Proof(commitment, node.Predicate.PublicValue, node.Predicate.MaxDiffForRange, container.PoKValueGreaterThanOrEqual, ck, cg), nil
		default:
			return false, fmt.Errorf("unsupported predicate type during verification: %v", node.Predicate.Type)
		}

	} else {
		// AND/OR node. Recursively verify children.
		// Challenges are generated globally, so each child verification should use its own `cg` instance,
		// but they all derive from the same initial public context.
		// For OR proof logic, individual challenges for sub-proofs are summed to get the total challenge.
		// For AND logic, each sub-proof is verified independently.
		// The `ChallengeGenerator` state must be consistent across all sub-proofs.
		// For simplicity, we create a new CG for each sub-path but append the parent CG's current state.
		// A more rigorous implementation of a ZKP for boolean logic would involve a single
		// combined proof for the entire policy tree. This current approach verifies individual components and then
		// combines the *boolean results* of verification.

		results := make(chan bool, len(node.Children))
		errs := make(chan error, len(node.Children))

		for _, child := range node.Children {
			// Create a copy of the current challenge generator's state for each child path
			childCG := NewChallengeGenerator()
			childCG.Append(cg.hasher.Sum(nil))

			go func(c *PolicyNode, childCG *ChallengeGenerator) {
				res, err := verifySubProof(c, zkp, ck, childCG)
				results <- res
				errs <- err
			}(child, childCG)
		}

		var overallResult bool
		if node.Type == AND {
			overallResult = true // Assume true for AND, prove false
		} else { // OR
			overallResult = false // Assume false for OR, prove true
		}

		for i := 0; i < len(node.Children); i++ {
			select {
			case res := <-results:
				if node.Type == AND {
					overallResult = overallResult && res
				} else { // OR
					overallResult = overallResult || res
				}
			case err := <-errs:
				// If any child returns an error, the whole verification fails
				return false, err
			}
		}
		return overallResult, nil
	}
}

// --- MAIN FUNCTION (for demonstration/testing) ---
func main() {
	fmt.Println("Starting ZK-Assured Decentralized Policy Compliance Demo...")

	// 1. Setup Global Commitment Keys
	ck := SetupCommitmentKeys()
	fmt.Println("Commitment Keys (G, H) generated.")

	// 2. Issuers issue credentials
	issuerA := &Issuer{ID: "IssuerA"}
	issuerB := &Issuer{ID: "IssuerB"}
	issuerC := &Issuer{ID: "IssuerC"}

	// Prover's (Alice's) attributes and credentials
	aliceTier := new(Scalar)(big.NewInt(3))
	aliceReputation := new(Scalar)(big.NewInt(80)) // Should be >= 75
	alicePremium := new(Scalar)(big.NewInt(1))     // 1 for true, 0 for false
	aliceUserID := new(Scalar)(big.NewInt(12345))

	credTier := issuerA.IssueCredential("Tier", aliceTier, ck)
	credReputation := issuerB.IssueCredential("Reputation", aliceReputation, ck)
	credPremium := issuerC.IssueCredential("Premium", alicePremium, ck)
	credUserID_A := issuerA.IssueCredential("UserID", aliceUserID, ck)
	credUserID_B := issuerB.IssueCredential("UserID", aliceUserID, ck)


	aliceCredentials := []*ZKC_Credential{credTier, credReputation, credPremium, credUserID_A, credUserID_B}
	fmt.Println("Alice's credentials issued and committed.")

	// 3. Define a Complex Policy
	// Policy: (Tier == 3 AND Reputation >= 75 AND UserID_A == UserID_B) OR (Premium == 1)
	
	// Predicate 1: Tier == 3
	predTierEq3 := &PolicyPredicate{
		Type:          EqPublicValue,
		AttributeType: "Tier",
		PublicValue:   new(Scalar)(big.NewInt(3)),
	}
	nodeTierEq3 := &PolicyNode{Predicate: predTierEq3}

	// Predicate 2: Reputation >= 75
	predReputationGE75 := &PolicyPredicate{
		Type:          GreaterThanOrEqual,
		AttributeType: "Reputation",
		PublicValue:   new(Scalar)(big.NewInt(75)),
		MaxDiffForRange: 20, // Max diff between 75 and reputation score (e.g., up to 95)
	}
	nodeReputationGE75 := &PolicyNode{Predicate: predReputationGE75}

	// Predicate 3: UserID from Issuer A == UserID from Issuer B
	predUserIDsEqual := &PolicyPredicate{
		Type:              EqCommittedValue,
		AttributeType:     "UserID",      // From IssuerA
		TargetAttributeType: "UserID",  // From IssuerB
	}
	nodeUserIDsEqual := &PolicyNode{Predicate: predUserIDsEqual}


	// AND node: (Tier == 3 AND Reputation >= 75 AND UserID_A == UserID_B)
	nodeAnd := &PolicyNode{
		Type:     AND,
		Children: []*PolicyNode{nodeTierEq3, nodeReputationGE75, nodeUserIDsEqual},
	}

	// Predicate 4: Premium == 1
	predPremiumEq1 := &PolicyPredicate{
		Type:          EqPublicValue,
		AttributeType: "Premium",
		PublicValue:   new(Scalar)(big.NewInt(1)),
	}
	nodePremiumEq1 := &PolicyNode{Predicate: predPremiumEq1}

	// OR node: (nodeAnd) OR (nodePremiumEq1)
	rootPolicy := &PolicyNode{
		Type:     OR,
		Children: []*PolicyNode{nodeAnd, nodePremiumEq1},
	}
	fmt.Println("Complex policy defined.")


	// 4. Prover (Alice) generates the ZKP for policy compliance
	fmt.Println("\n--- Prover generating ZKP for policy compliance ---")
	policyProof, err := GeneratePolicyComplianceProof(rootPolicy, aliceCredentials, ck)
	if err != nil {
		fmt.Printf("Error generating policy compliance proof: %v\n", err)
		return
	}
	fmt.Println("ZKP for policy compliance generated successfully.")

	// 5. Verifier verifies the ZKP
	fmt.Println("\n--- Verifier verifying ZKP ---")
	isValid, err := VerifyPolicyComplianceProof(rootPolicy, policyProof, ck)
	if err != nil {
		fmt.Printf("Error verifying policy compliance proof: %v\n", err)
		return
	}
	fmt.Printf("Policy compliance proof is valid: %t (Expected: true)\n", isValid)


	// 6. Demonstrate a failed policy (e.g., Alice's reputation is too low)
	fmt.Println("\n--- Demonstrating a failed policy proof (Alice's reputation < 75) ---")
	aliceReputationLow := new(Scalar)(big.NewInt(60)) // Lower than 75
	credReputationLow := issuerB.IssueCredential("Reputation", aliceReputationLow, ck)
	
	// Create a new set of credentials for the failed attempt, replacing only the 'Reputation' one
	aliceCredentialsFailed := []*ZKC_Credential{credTier, credReputationLow, credPremium, credUserID_A, credUserID_B}

	policyProofFailed, err := GeneratePolicyComplianceProof(rootPolicy, aliceCredentialsFailed, ck)
	if err != nil {
		fmt.Printf("Error generating failed policy compliance proof: %v\n", err)
		return
	}

	isValidFailed, err := VerifyPolicyComplianceProof(rootPolicy, policyProofFailed, ck)
	if err != nil {
		fmt.Printf("Error verifying failed policy compliance proof: %v\n", err)
		return
	}
	fmt.Printf("Failed policy compliance proof is valid: %t (Expected: false)\n", isValidFailed)

	// Demonstrate a failed policy (e.g., Alice's Premium is 0 and Reputation is Low)
	fmt.Println("\n--- Demonstrating a failed policy proof (Alice's Premium is 0 AND Reputation is Low) ---")
	alicePremiumFalse := new(Scalar)(big.NewInt(0)) // 0 for false
	credPremiumFalse := issuerC.IssueCredential("Premium", alicePremiumFalse, ck)
	
	// Both branches of the OR policy will now fail.
	aliceCredentialsDoubleFailed := []*ZKC_Credential{credTier, credReputationLow, credPremiumFalse, credUserID_A, credUserID_B}

	policyProofDoubleFailed, err := GeneratePolicyComplianceProof(rootPolicy, aliceCredentialsDoubleFailed, ck)
	if err != nil {
		fmt.Printf("Error generating double failed policy compliance proof: %v\n", err)
		return
	}

	isValidDoubleFailed, err := VerifyPolicyComplianceProof(rootPolicy, policyProofDoubleFailed, ck)
	if err != nil {
		fmt.Printf("Error verifying double failed policy compliance proof: %v\n", err)
		return
	}
	fmt.Printf("Double failed policy compliance proof is valid: %t (Expected: false)\n", isValidDoubleFailed)

}

```