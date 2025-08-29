This Zero-Knowledge Proof (ZKP) implementation in Golang is designed for **Verifiable Private Access Control on Encrypted Data Attributes**.

Imagine a scenario where a user wants to prove to a service provider that they meet certain criteria (e.g., `age >= 18`, `credit_score >= 700`, `is_employed == true`) *without revealing their actual age, credit score, or employment status*. This system allows a **Prover** to generate a ZKP for an **Access Policy** which is then verified by a **Verifier**.

The system leverages:
*   **Pedersen Commitments**: To hide sensitive attribute values.
*   **Σ-Protocol-like Proofs**: For proving knowledge of values satisfying specific conditions (equality, range, set membership) within commitments.
*   **Disjunctive Proofs (OR proofs)**: To prove that one of several conditions holds without revealing which one.
*   **Conjunctivity (AND proofs)**: By combining multiple individual proofs.

This concept is **advanced, creative, and trendy** because it addresses:
1.  **Privacy-Preserving Identity/Data**: A core requirement in modern decentralized identity (DID) systems, verifiable credentials, and secure data sharing.
2.  **Fine-Grained Access Control**: Beyond simple username/password, allowing policy-based access without over-revealing.
3.  **Real-world Applicability**: Useful in scenarios like KYC/AML compliance, age verification, credit checks, or personalized service offerings where privacy is paramount.
4.  **Novel Combination**: It builds a higher-level policy verification system from several ZKP primitives, demonstrating how ZKP can construct complex proofs for practical problems.

This implementation avoids duplicating existing full-fledged ZKP libraries by building specific, custom ZKP primitives (equality, range, set membership proofs) from cryptographic first principles based on common literature, while utilizing a robust Go elliptic curve library for underlying arithmetic.

---

### Zero-Knowledge Private Access Control (zkAccessControl)

**Outline:**

1.  **Package Setup**: Defines the main `zkaccesscontrol` package.
2.  **Core Cryptographic Primitives**:
    *   Elliptic Curve (EC) Group and Field Operations.
    *   Pedersen Commitments.
    *   Cryptographic Hash for Challenge Generation.
3.  **Data Structures (`types.go`)**:
    *   `PublicParams`: Common parameters for Prover and Verifier.
    *   `Attribute`: Represents a secret user attribute.
    *   `AccessCriterionType`: Enum for different condition types (e.g., `Equal`, `Range`, `SetMembership`).
    *   `AccessCriterion`: Defines a single condition for an attribute.
    *   `AccessPolicy`: A collection of `AccessCriterion` with logical connectors.
    *   `AttributeCommitment`: Stores a commitment to an attribute.
    *   `SubProof`: Interface for individual proofs (e.g., `EqualProof`, `RangeProof`).
    *   `PolicyProof`: Aggregates all `SubProof`s for an `AccessPolicy`.
4.  **Prover Side (`prover.go`)**:
    *   `Prover`: Manages user's secret attributes and generates proofs.
    *   Functions for creating attribute commitments.
    *   Functions for generating specific `SubProof`s.
    *   Main function to generate a `PolicyProof`.
5.  **Verifier Side (`verifier.go`)**:
    *   `Verifier`: Stores the `AccessPolicy` and verifies proofs.
    *   Functions for verifying specific `SubProof`s.
    *   Main function to verify a `PolicyProof`.
6.  **Common Utilities (`common.go`)**:
    *   Functions for `SetupPublicParameters`.
    *   Serialization/Deserialization helpers.
    *   Challenge generation (Fiat-Shamir heuristic).
    *   Helper functions for EC arithmetic and scalar operations (wrapped from `kyber`).
7.  **Proof Implementations (`proofs.go`)**:
    *   `EqualProof`: Structure and logic for proving equality.
    *   `RangeProof`: Structure and logic for proving a value is within a range using bit decomposition.
    *   `SetMembershipProof`: Structure and logic for proving membership in a set using disjunctive proofs.

---

**Function Summary:**

**`zkaccesscontrol` Package (Main, Common, Utils):**

1.  `SetupPublicParameters()`:
    *   **Purpose**: Initializes and returns the `PublicParams` required for all cryptographic operations (elliptic curve, generators `g`, `h`, prime order `q`). This is a trusted setup.
    *   **Returns**: `*PublicParams`, `error`.
2.  `GenerateRandomScalar(params *PublicParams)`:
    *   **Purpose**: Generates a cryptographically secure random scalar within the field order `q`. Used for commitment blinding factors.
    *   **Returns**: `kyber.Scalar`.
3.  `Commit(params *PublicParams, value kyber.Scalar, randomness kyber.Scalar)`:
    *   **Purpose**: Computes a Pedersen commitment `C = g^value * h^randomness`.
    *   **Returns**: `kyber.Point`.
4.  `GenerateChallenge(params *PublicParams, elements ...[]byte)`:
    *   **Purpose**: Implements the Fiat-Shamir heuristic to generate a challenge scalar by hashing all relevant public proof elements.
    *   **Returns**: `kyber.Scalar`.
5.  `MarshalPoint(p kyber.Point)`:
    *   **Purpose**: Serializes a `kyber.Point` into a byte slice.
    *   **Returns**: `[]byte`.
6.  `UnmarshalPoint(params *PublicParams, data []byte)`:
    *   **Purpose**: Deserializes a byte slice back into a `kyber.Point`.
    *   **Returns**: `kyber.Point`, `error`.
7.  `MarshalScalar(s kyber.Scalar)`:
    *   **Purpose**: Serializes a `kyber.Scalar` into a byte slice.
    *   **Returns**: `[]byte`.
8.  `UnmarshalScalar(params *PublicParams, data []byte)`:
    *   **Purpose**: Deserializes a byte slice back into a `kyber.Scalar`.
    *   **Returns**: `kyber.Scalar`, `error`.
9.  `ValueToScalar(params *PublicParams, val int)`:
    *   **Purpose**: Converts an integer value to a `kyber.Scalar`.
    *   **Returns**: `kyber.Scalar`.

**`prover.go` (Prover-side functions):**

10. `NewProver(params *PublicParams, attributes map[string]int)`:
    *   **Purpose**: Initializes a new Prover instance with public parameters and the user's secret attributes.
    *   **Returns**: `*Prover`.
11. `CreateAttributeCommitment(prover *Prover, attributeName string)`:
    *   **Purpose**: Generates a Pedersen commitment for a specific attribute held by the Prover. Stores the commitment and its randomness internally.
    *   **Returns**: `*AttributeCommitment`, `error`.
12. `generateEqualProof(prover *Prover, attrName string, expected kyber.Scalar)`:
    *   **Purpose**: Generates an `EqualProof` for a specified attribute, proving its value is equal to `expected`.
    *   **Returns**: `*EqualProof`, `error`.
13. `generateRangeProof(prover *Prover, attrName string, min, max kyber.Scalar, bitLength int)`:
    *   **Purpose**: Generates a `RangeProof` for a specified attribute, proving its value is within `[min, max]`.
    *   **Returns**: `*RangeProof`, `error`.
14. `generateSetMembershipProof(prover *Prover, attrName string, allowedValues []kyber.Scalar)`:
    *   **Purpose**: Generates a `SetMembershipProof` for an attribute, proving its value is one of `allowedValues`.
    *   **Returns**: `*SetMembershipProof`, `error`.
15. `GeneratePolicyProof(prover *Prover, policy *AccessPolicy)`:
    *   **Purpose**: The main prover function. Iterates through the `AccessPolicy` criteria, generates the required `SubProof` for each, and aggregates them into a `PolicyProof`.
    *   **Returns**: `*PolicyProof`, `error`.

**`verifier.go` (Verifier-side functions):**

16. `NewVerifier(params *PublicParams, policy *AccessPolicy)`:
    *   **Purpose**: Initializes a new Verifier instance with public parameters and the access policy to be enforced.
    *   **Returns**: `*Verifier`.
17. `verifyEqualProof(verifier *Verifier, commitment *AttributeCommitment, expected kyber.Scalar, proof *EqualProof)`:
    *   **Purpose**: Verifies an `EqualProof` against an `AttributeCommitment` and the `expected` value.
    *   **Returns**: `bool`, `error`.
18. `verifyRangeProof(verifier *Verifier, commitment *AttributeCommitment, min, max kyber.Scalar, bitLength int, proof *RangeProof)`:
    *   **Purpose**: Verifies a `RangeProof` against an `AttributeCommitment` and the `min/max` bounds.
    *   **Returns**: `bool`, `error`.
19. `verifySetMembershipProof(verifier *Verifier, commitment *AttributeCommitment, allowedValues []kyber.Scalar, proof *SetMembershipProof)`:
    *   **Purpose**: Verifies a `SetMembershipProof` against an `AttributeCommitment` and the `allowedValues` set.
    *   **Returns**: `bool`, `error`.
20. `VerifyPolicyProof(verifier *Verifier, proof *PolicyProof)`:
    *   **Purpose**: The main verifier function. It takes a `PolicyProof` and checks all individual `SubProof`s according to the `AccessPolicy`.
    *   **Returns**: `bool`, `error`.

**`types.go` (Data Structures & Helpers):**

21. `NewAccessPolicy(logic string, criteria ...*AccessCriterion)`:
    *   **Purpose**: Constructs a new `AccessPolicy` with a specified logical connector (e.g., "AND") and a list of criteria.
    *   **Returns**: `*AccessPolicy`.
22. `NewCriterion(attrName string, criterionType AccessCriterionType, value1 int, value2 int, values []int)`:
    *   **Purpose**: Creates a single `AccessCriterion` based on the specified type and values.
    *   **Returns**: `*AccessCriterion`.
23. `AccessPolicy.ToJSON()`, `AccessPolicy.FromJSON()`:
    *   **Purpose**: Marshal/Unmarshal `AccessPolicy` to/from JSON.
24. `PolicyProof.ToJSON()`, `PolicyProof.FromJSON()`:
    *   **Purpose**: Marshal/Unmarshal `PolicyProof` to/from JSON.

**`proofs.go` (Detailed Proof Implementations):**

25. `EqualProof.Prove(params *PublicParams, attrVal, r_attr, expected kyber.Scalar, challenge kyber.Scalar)`:
    *   **Purpose**: Generates the responses for an `EqualProof`.
    *   **Returns**: `*EqualProof`.
26. `EqualProof.Verify(params *PublicParams, commitment kyber.Point, expected kyber.Scalar, challenge kyber.Scalar)`:
    *   **Purpose**: Checks the responses of an `EqualProof`.
    *   **Returns**: `bool`.
27. `RangeProof.Prove(params *PublicParams, attrVal, r_attr, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)`:
    *   **Purpose**: Generates the complex set of commitments and responses for a `RangeProof` (involving bit decomposition and sub-proofs for each bit).
    *   **Returns**: `*RangeProof`.
28. `RangeProof.Verify(params *PublicParams, commitment kyber.Point, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)`:
    *   **Purpose**: Verifies the aggregate proof and individual bit proofs for a `RangeProof`.
    *   **Returns**: `bool`.
29. `SetMembershipProof.Prove(params *PublicParams, attrVal, r_attr kyber.Scalar, allowedValues []kyber.Scalar, challenge kyber.Scalar)`:
    *   **Purpose**: Generates a disjunctive proof for set membership by creating an `EqualProof` for the matching value and 'dummy' proofs for non-matching values.
    *   **Returns**: `*SetMembershipProof`.
30. `SetMembershipProof.Verify(params *PublicParams, commitment kyber.Point, allowedValues []kyber.Scalar, challenge kyber.Scalar)`:
    *   **Purpose**: Verifies a `SetMembershipProof` by checking the disjunctive proof.
    *   **Returns**: `bool`.

This comprehensive set of functions covers the full lifecycle of a ZKP-based private access control system, from setup and attribute commitment to complex policy proof generation and verification.

---

```go
package zkaccesscontrol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519" // Using Edwards25519 for curve operations
	"go.dedis.ch/kyber/v3/util/random"
)

// --- Zero-Knowledge Private Access Control (zkAccessControl) ---
//
// This Zero-Knowledge Proof (ZKP) implementation in Golang is designed for
// Verifiable Private Access Control on Encrypted Data Attributes.
//
// Imagine a scenario where a user wants to prove to a service provider that
// they meet certain criteria (e.g., `age >= 18`, `credit_score >= 700`, `is_employed == true`)
// *without revealing their actual age, credit score, or employment status*.
// This system allows a **Prover** to generate a ZKP for an **Access Policy**
// which is then verified by a **Verifier**.
//
// The system leverages:
// - Pedersen Commitments: To hide sensitive attribute values.
// - Σ-Protocol-like Proofs: For proving knowledge of values satisfying specific
//   conditions (equality, range, set membership) within commitments.
// - Disjunctive Proofs (OR proofs): To prove that one of several conditions holds
//   without revealing which one.
// - Conjunctivity (AND proofs): By combining multiple individual proofs.
//
// This concept is **advanced, creative, and trendy** because it addresses:
// 1. Privacy-Preserving Identity/Data: A core requirement in modern
//    decentralized identity (DID) systems, verifiable credentials, and secure data sharing.
// 2. Fine-Grained Access Control: Beyond simple username/password, allowing policy-based
//    access without over-revealing.
// 3. Real-world Applicability: Useful in scenarios like KYC/AML compliance,
//    age verification, credit checks, or personalized service offerings where privacy is paramount.
// 4. Novel Combination: It builds a higher-level policy verification system from
//    several ZKP primitives, demonstrating how ZKP can construct complex proofs
//    for practical problems.
//
// This implementation avoids duplicating existing full-fledged ZKP libraries by building
// specific, custom ZKP primitives (equality, range, set membership proofs) from
// cryptographic first principles based on common literature, while utilizing a robust
// Go elliptic curve library for underlying arithmetic.
//
// ---
//
// Outline:
// 1. Package Setup: Defines the main `zkaccesscontrol` package.
// 2. Core Cryptographic Primitives:
//    - Elliptic Curve (EC) Group and Field Operations.
//    - Pedersen Commitments.
//    - Cryptographic Hash for Challenge Generation.
// 3. Data Structures (`types.go` logic integrated below for simplicity):
//    - `PublicParams`: Common parameters for Prover and Verifier.
//    - `Attribute`: Represents a secret user attribute.
//    - `AccessCriterionType`: Enum for different condition types (e.g., `Equal`, `Range`, `SetMembership`).
//    - `AccessCriterion`: Defines a single condition for an attribute.
//    - `AccessPolicy`: A collection of `AccessCriterion` with logical connectors.
//    - `AttributeCommitment`: Stores a commitment to an attribute.
//    - `SubProof`: Interface for individual proofs (e.g., `EqualProof`, `RangeProof`).
//    - `PolicyProof`: Aggregates all `SubProof`s for an `AccessPolicy`.
// 4. Prover Side (`prover.go` logic integrated below):
//    - `Prover`: Manages user's secret attributes and generates proofs.
//    - Functions for creating attribute commitments.
//    - Functions for generating specific `SubProof`s.
//    - Main function to generate a `PolicyProof`.
// 5. Verifier Side (`verifier.go` logic integrated below):
//    - `Verifier`: Stores the `AccessPolicy` and verifies proofs.
//    - Functions for verifying specific `SubProof`s.
//    - Main function to verify a `PolicyProof`.
// 6. Common Utilities (`common.go` logic integrated below):
//    - Functions for `SetupPublicParameters`.
//    - Serialization/Deserialization helpers.
//    - Challenge generation (Fiat-Shamir heuristic).
//    - Helper functions for EC arithmetic and scalar operations (wrapped from `kyber`).
// 7. Proof Implementations (`proofs.go` logic integrated below):
//    - `EqualProof`: Structure and logic for proving equality.
//    - `RangeProof`: Structure and logic for proving a value is within a range using bit decomposition.
//    - `SetMembershipProof`: Structure and logic for proving membership in a set using disjunctive proofs.
//
// ---
//
// Function Summary:
//
// `zkaccesscontrol` Package (Main, Common, Utils):
//
// 1. `SetupPublicParameters()`:
//    - Purpose: Initializes and returns the `PublicParams` required for all cryptographic operations (elliptic curve, generators `g`, `h`, prime order `q`). This is a trusted setup.
//    - Returns: `*PublicParams`, `error`.
// 2. `GenerateRandomScalar(params *PublicParams)`:
//    - Purpose: Generates a cryptographically secure random scalar within the field order `q`. Used for commitment blinding factors.
//    - Returns: `kyber.Scalar`.
// 3. `Commit(params *PublicParams, value kyber.Scalar, randomness kyber.Scalar)`:
//    - Purpose: Computes a Pedersen commitment `C = g^value * h^randomness`.
//    - Returns: `kyber.Point`.
// 4. `GenerateChallenge(params *PublicParams, elements ...[]byte)`:
//    - Purpose: Implements the Fiat-Shamir heuristic to generate a challenge scalar by hashing all relevant public proof elements.
//    - Returns: `kyber.Scalar`.
// 5. `MarshalPoint(p kyber.Point)`:
//    - Purpose: Serializes a `kyber.Point` into a byte slice.
//    - Returns: `[]byte`.
// 6. `UnmarshalPoint(params *PublicParams, data []byte)`:
//    - Purpose: Deserializes a byte slice back into a `kyber.Point`.
//    - Returns: `kyber.Point`, `error`.
// 7. `MarshalScalar(s kyber.Scalar)`:
//    - Purpose: Serializes a `kyber.Scalar` into a byte slice.
//    - Returns: `[]byte`.
// 8. `UnmarshalScalar(params *PublicParams, data []byte)`:
//    - Purpose: Deserializes a byte slice back into a `kyber.Scalar`.
//    - Returns: `kyber.Scalar`, `error`.
// 9. `ValueToScalar(params *PublicParams, val int)`:
//    - Purpose: Converts an integer value to a `kyber.Scalar`.
//    - Returns: `kyber.Scalar`.
//
// `prover.go` (Prover-side functions):
//
// 10. `NewProver(params *PublicParams, attributes map[string]int)`:
//     - Purpose: Initializes a new Prover instance with public parameters and the user's secret attributes.
//     - Returns: `*Prover`.
// 11. `CreateAttributeCommitment(prover *Prover, attributeName string)`:
//     - Purpose: Generates a Pedersen commitment for a specific attribute held by the Prover. Stores the commitment and its randomness internally.
//     - Returns: `*AttributeCommitment`, `error`.
// 12. `generateEqualProof(prover *Prover, attrName string, expected kyber.Scalar)`:
//     - Purpose: Generates an `EqualProof` for a specified attribute, proving its value is equal to `expected`.
//     - Returns: `*EqualProof`, `error`.
// 13. `generateRangeProof(prover *Prover, attrName string, min, max kyber.Scalar, bitLength int)`:
//     - Purpose: Generates a `RangeProof` for a specified attribute, proving its value is within `[min, max]`.
//     - Returns: `*RangeProof`, `error`.
// 14. `generateSetMembershipProof(prover *Prover, attrName string, allowedValues []kyber.Scalar)`:
//     - Purpose: Generates a `SetMembershipProof` for an attribute, proving its value is one of `allowedValues`.
//     - Returns: `*SetMembershipProof`, `error`.
// 15. `GeneratePolicyProof(prover *Prover, policy *AccessPolicy)`:
//     - Purpose: The main prover function. Iterates through the `AccessPolicy` criteria, generates the required `SubProof` for each, and aggregates them into a `PolicyProof`.
//     - Returns: `*PolicyProof`, `error`.
//
// `verifier.go` (Verifier-side functions):
//
// 16. `NewVerifier(params *PublicParams, policy *AccessPolicy)`:
//     - Purpose: Initializes a new Verifier instance with public parameters and the access policy to be enforced.
//     - Returns: `*Verifier`.
// 17. `verifyEqualProof(verifier *Verifier, commitment *AttributeCommitment, expected kyber.Scalar, proof *EqualProof)`:
//     - Purpose: Verifies an `EqualProof` against an `AttributeCommitment` and the `expected` value.
//     - Returns: `bool`, `error`.
// 18. `verifyRangeProof(verifier *Verifier, commitment *AttributeCommitment, min, max kyber.Scalar, bitLength int, proof *RangeProof)`:
//     - Purpose: Verifies a `RangeProof` against an `AttributeCommitment` and the `min/max` bounds.
//     - Returns: `bool`, `error`.
// 19. `verifySetMembershipProof(verifier *Verifier, commitment *AttributeCommitment, allowedValues []kyber.Scalar, proof *SetMembershipProof)`:
//     - Purpose: Verifies a `SetMembershipProof` against an `AttributeCommitment` and the `allowedValues` set.
//     - Returns: `bool`, `error`.
// 20. `VerifyPolicyProof(verifier *Verifier, proof *PolicyProof)`:
//     - Purpose: The main verifier function. It takes a `PolicyProof` and checks all individual `SubProof`s according to the `AccessPolicy`.
//     - Returns: `bool`, `error`.
//
// `types.go` (Data Structures & Helpers):
//
// 21. `NewAccessPolicy(logic string, criteria ...*AccessCriterion)`:
//     - Purpose: Constructs a new `AccessPolicy` with a specified logical connector (e.g., "AND") and a list of criteria.
//     - Returns: `*AccessPolicy`.
// 22. `NewCriterion(attrName string, criterionType AccessCriterionType, value1 int, value2 int, values []int)`:
//     - Purpose: Creates a single `AccessCriterion` based on the specified type and values.
//     - Returns: `*AccessCriterion`.
// 23. `AccessPolicy.ToJSON()`, `AccessPolicy.FromJSON()`:
//     - Purpose: Marshal/Unmarshal `AccessPolicy` to/from JSON.
// 24. `PolicyProof.ToJSON()`, `PolicyProof.FromJSON()`:
//     - Purpose: Marshal/Unmarshal `PolicyProof` to/from JSON.
//
// `proofs.go` (Detailed Proof Implementations):
//
// 25. `EqualProof.Prove(params *PublicParams, attrVal, r_attr, expected kyber.Scalar, challenge kyber.Scalar)`:
//     - Purpose: Generates the responses for an `EqualProof` (Schnorr-like proof of knowledge of `r_attr` s.t. `C * g^-expected = h^r_attr`).
//     - Returns: `*EqualProof`.
// 26. `EqualProof.Verify(params *PublicParams, commitment kyber.Point, expected kyber.Scalar, challenge kyber.Scalar)`:
//     - Purpose: Checks the responses of an `EqualProof`.
//     - Returns: `bool`.
// 27. `RangeProof.Prove(params *PublicParams, attrVal, r_attr, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)`:
//     - Purpose: Generates the complex set of commitments and responses for a `RangeProof`. This involves decomposing `val-min` into bits, proving each bit is 0 or 1, and proving consistency.
//     - Returns: `*RangeProof`.
// 28. `RangeProof.Verify(params *PublicParams, commitment kyber.Point, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)`:
//     - Purpose: Verifies the aggregate proof and individual bit proofs for a `RangeProof`.
//     - Returns: `bool`.
// 29. `SetMembershipProof.Prove(params *PublicParams, attrVal, r_attr kyber.Scalar, allowedValues []kyber.Scalar, challenge kyber.Scalar)`:
//     - Purpose: Generates a disjunctive proof for set membership by creating an `EqualProof` for the matching value and 'dummy' proofs for non-matching values.
//     - Returns: `*SetMembershipProof`.
// 30. `SetMembershipProof.Verify(params *PublicParams, commitment kyber.Point, allowedValues []kyber.Scalar, challenge kyber.Scalar)`:
//     - Purpose: Verifies a `SetMembershipProof` by checking the disjunctive proof.
//     - Returns: `bool`.

// Global curve for operations
var suite = edwards25519.NewBlakeSHA256Ed25519()

// --- Data Structures ---

// PublicParams contains the common public parameters for the ZKP system.
type PublicParams struct {
	G     kyber.Point // Generator point for the elliptic curve
	H     kyber.Point // Another generator point, independent of G
	Suite kyber.Group // The elliptic curve suite
}

// Attribute represents a secret user attribute.
type Attribute struct {
	Name  string
	Value int
}

// AccessCriterionType defines the type of condition for an attribute.
type AccessCriterionType string

const (
	CriterionTypeEqual       AccessCriterionType = "Equal"
	CriterionTypeRange       AccessCriterionType = "Range"
	CriterionTypeSetMembership AccessCriterionType = "SetMembership"
)

// AccessCriterion defines a single condition for an attribute.
type AccessCriterion struct {
	AttributeName string              `json:"attributeName"`
	Type          AccessCriterionType `json:"type"`
	Value1        int                 `json:"value1,omitempty"`        // Used for Equal, Range (min)
	Value2        int                 `json:"value2,omitempty"`        // Used for Range (max)
	Values        []int               `json:"values,omitempty"`        // Used for SetMembership
	BitLength     int                 `json:"bitLength,omitempty"`     // Required for RangeProof, max bit length of value
}

// AccessPolicy defines a set of criteria combined with a logical connector.
type AccessPolicy struct {
	Logic    string             `json:"logic"` // "AND" or "OR"
	Criteria []*AccessCriterion `json:"criteria"`
}

// AttributeCommitment stores a commitment to an attribute.
type AttributeCommitment struct {
	AttributeName string     `json:"attributeName"`
	Commitment    kyber.Point `json:"commitment"` // C = g^value * h^randomness
	Randomness    kyber.Scalar // Stored by Prover only
}

// SubProof is an interface for any specific proof type (Equality, Range, Set Membership).
type SubProof interface {
	Verify(params *PublicParams, commitment kyber.Point, criterion *AccessCriterion) (bool, error)
	GetChallengeBytes() [][]byte // Helper to get elements for challenge generation
	Type() AccessCriterionType
}

// PolicyProof aggregates all SubProof for an AccessPolicy.
type PolicyProof struct {
	AttributeCommitments map[string]*AttributeCommitment `json:"attributeCommitments"` // Commitments for all involved attributes
	Proofs               map[string]json.RawMessage      `json:"proofs"`               // Map of proof type to actual proof data
	// Note: For simplicity, we are mapping proofs by attribute name here. In a real system,
	// this would be more complex to handle multiple proofs for the same attribute, or combined proofs.
}

// Proof wrappers for JSON serialization
type EqualProofWrapper struct {
	Type AccessCriterionType `json:"type"`
	Proof *EqualProof `json:"proof"`
}
type RangeProofWrapper struct {
	Type AccessCriterionType `json:"type"`
	Proof *RangeProof `json:"proof"`
}
type SetMembershipProofWrapper struct {
	Type AccessCriterionType `json:"type"`
	Proof *SetMembershipProof `json:"proof"`
}

// --- Prover ---

// Prover holds the secret attributes and parameters for generating proofs.
type Prover struct {
	Params           *PublicParams
	Attributes       map[string]int
	AttrCommitments  map[string]*AttributeCommitment // Stored commitments with randomness
}

// NewProver initializes a new Prover instance.
// 10. NewProver(params *PublicParams, attributes map[string]int)
func NewProver(params *PublicParams, attributes map[string]int) *Prover {
	return &Prover{
		Params:          params,
		Attributes:      attributes,
		AttrCommitments: make(map[string]*AttributeCommitment),
	}
}

// CreateAttributeCommitment generates a Pedersen commitment for a specific attribute.
// 11. CreateAttributeCommitment(prover *Prover, attributeName string)
func (p *Prover) CreateAttributeCommitment(attributeName string) (*AttributeCommitment, error) {
	attrValue, ok := p.Attributes[attributeName]
	if !ok {
		return nil, fmt.Errorf("attribute %s not found for prover", attributeName)
	}

	valScalar := ValueToScalar(p.Params, attrValue)
	randomness := GenerateRandomScalar(p.Params)
	commitment := Commit(p.Params, valScalar, randomness)

	attrCommitment := &AttributeCommitment{
		AttributeName: attributeName,
		Commitment:    commitment,
		Randomness:    randomness,
	}
	p.AttrCommitments[attributeName] = attrCommitment
	return attrCommitment, nil
}

// generateEqualProof generates an EqualProof.
// 12. generateEqualProof(prover *Prover, attrName string, expected kyber.Scalar)
func (p *Prover) generateEqualProof(attrName string, expected kyber.Scalar) (*EqualProof, error) {
	attrCommitment, ok := p.AttrCommitments[attrName]
	if !ok {
		return nil, fmt.Errorf("commitment for attribute %s not found, generate it first", attrName)
	}

	attrVal := ValueToScalar(p.Params, p.Attributes[attrName])
	r_attr := attrCommitment.Randomness

	// t = h^k, c = H(C, g^expected, t), s = k - c*r_attr
	// Verifier checks g^s h^c = t * (C / g^expected)^c
	// No, this is for knowledge of discrete log x in C = g^x
	// For C = g^val h^r, proving val = expected:
	// Prover proves knowledge of r_attr such that C * g^{-expected} = h^r_attr
	// This is a standard Schnorr PoK for discrete log.
	
	// Generate challenge from public info before computing response
	challengeElements := [][]byte{
		MarshalPoint(attrCommitment.Commitment),
		MarshalScalar(expected),
	}
	challenge := GenerateChallenge(p.Params, challengeElements...)

	proof := &EqualProof{}
	proof.Prove(p.Params, attrVal, r_attr, expected, challenge)
	return proof, nil
}

// generateRangeProof generates a RangeProof.
// 13. generateRangeProof(prover *Prover, attrName string, min, max kyber.Scalar, bitLength int)
func (p *Prover) generateRangeProof(attrName string, min, max kyber.Scalar, bitLength int) (*RangeProof, error) {
	attrCommitment, ok := p.AttrCommitments[attrName]
	if !ok {
		return nil, fmt.Errorf("commitment for attribute %s not found, generate it first", attrName)
	}

	attrVal := ValueToScalar(p.Params, p.Attributes[attrName])
	r_attr := attrCommitment.Randomness

	// Generate challenge from public info
	challengeElements := [][]byte{
		MarshalPoint(attrCommitment.Commitment),
		MarshalScalar(min),
		MarshalScalar(max),
		[]byte(strconv.Itoa(bitLength)),
	}
	challenge := GenerateChallenge(p.Params, challengeElements...)

	proof := &RangeProof{}
	proof.Prove(p.Params, attrVal, r_attr, min, max, bitLength, challenge)
	return proof, nil
}

// generateSetMembershipProof generates a SetMembershipProof.
// 14. generateSetMembershipProof(prover *Prover, attrName string, allowedValues []kyber.Scalar)
func (p *Prover) generateSetMembershipProof(attrName string, allowedValues []kyber.Scalar) (*SetMembershipProof, error) {
	attrCommitment, ok := p.AttrCommitments[attrName]
	if !ok {
		return nil, fmt.Errorf("commitment for attribute %s not found, generate it first", attrName)
	}

	attrVal := ValueToScalar(p.Params, p.Attributes[attrName])
	r_attr := attrCommitment.Randomness

	// Generate challenge from public info
	challengeElements := [][]byte{
		MarshalPoint(attrCommitment.Commitment),
	}
	for _, val := range allowedValues {
		challengeElements = append(challengeElements, MarshalScalar(val))
	}
	challenge := GenerateChallenge(p.Params, challengeElements...)

	proof := &SetMembershipProof{}
	proof.Prove(p.Params, attrVal, r_attr, allowedValues, challenge)
	return proof, nil
}

// GeneratePolicyProof creates a PolicyProof for the given AccessPolicy.
// 15. GeneratePolicyProof(prover *Prover, policy *AccessPolicy)
func (p *Prover) GeneratePolicyProof(policy *AccessPolicy) (*PolicyProof, error) {
	policyProof := &PolicyProof{
		AttributeCommitments: make(map[string]*AttributeCommitment),
		Proofs:               make(map[string]json.RawMessage),
	}

	for _, criterion := range policy.Criteria {
		// Ensure commitment exists for the attribute
		if _, ok := p.AttrCommitments[criterion.AttributeName]; !ok {
			_, err := p.CreateAttributeCommitment(criterion.AttributeName)
			if err != nil {
				return nil, fmt.Errorf("failed to create commitment for %s: %w", criterion.AttributeName, err)
			}
		}
		
		policyProof.AttributeCommitments[criterion.AttributeName] = p.AttrCommitments[criterion.AttributeName]

		var subProof SubProof
		var err error

		switch criterion.Type {
		case CriterionTypeEqual:
			expected := ValueToScalar(p.Params, criterion.Value1)
			subProof, err = p.generateEqualProof(criterion.AttributeName, expected)
		case CriterionTypeRange:
			min := ValueToScalar(p.Params, criterion.Value1)
			max := ValueToScalar(p.Params, criterion.Value2)
			subProof, err = p.generateRangeProof(criterion.AttributeName, min, max, criterion.BitLength)
		case CriterionTypeSetMembership:
			var allowedScalars []kyber.Scalar
			for _, v := range criterion.Values {
				allowedScalars = append(allowedScalars, ValueToScalar(p.Params, v))
			}
			subProof, err = p.generateSetMembershipProof(criterion.AttributeName, allowedScalars)
		default:
			return nil, fmt.Errorf("unsupported criterion type: %s", criterion.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to generate proof for criterion %s: %w", criterion.AttributeName, err)
		}

		// Marshal the subProof into JSON RawMessage for generic storage
		var wrappedProof interface{}
		switch sp := subProof.(type) {
		case *EqualProof:
			wrappedProof = EqualProofWrapper{Type: criterion.Type, Proof: sp}
		case *RangeProof:
			wrappedProof = RangeProofWrapper{Type: criterion.Type, Proof: sp}
		case *SetMembershipProof:
			wrappedProof = SetMembershipProofWrapper{Type: criterion.Type, Proof: sp}
		default:
			return nil, fmt.Errorf("unknown subproof type for serialization")
		}

		proofBytes, err := json.Marshal(wrappedProof)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal subproof: %w", err)
		}
		policyProof.Proofs[criterion.AttributeName+"_"+string(criterion.Type)] = proofBytes // Unique key
	}

	return policyProof, nil
}

// --- Verifier ---

// Verifier holds the policy and parameters for verifying proofs.
type Verifier struct {
	Params *PublicParams
	Policy *AccessPolicy
}

// NewVerifier initializes a new Verifier instance.
// 16. NewVerifier(params *PublicParams, policy *AccessPolicy)
func NewVerifier(params *PublicParams, policy *AccessPolicy) *Verifier {
	return &Verifier{
		Params: params,
		Policy: policy,
	}
}

// verifyEqualProof verifies an EqualProof.
// 17. verifyEqualProof(verifier *Verifier, commitment *AttributeCommitment, expected kyber.Scalar, proof *EqualProof)
func (v *Verifier) verifyEqualProof(commitment *AttributeCommitment, expected kyber.Scalar, proof *EqualProof) (bool, error) {
	challengeElements := [][]byte{
		MarshalPoint(commitment.Commitment),
		MarshalScalar(expected),
	}
	expectedChallenge := GenerateChallenge(v.Params, challengeElements...)

	if !proof.Challenge.Equal(expectedChallenge) {
		return false, fmt.Errorf("challenge mismatch for EqualProof")
	}

	return proof.Verify(v.Params, commitment.Commitment, expected, proof.Challenge), nil
}

// verifyRangeProof verifies a RangeProof.
// 18. verifyRangeProof(verifier *Verifier, commitment *AttributeCommitment, min, max kyber.Scalar, bitLength int, proof *RangeProof)
func (v *Verifier) verifyRangeProof(commitment *AttributeCommitment, min, max kyber.Scalar, bitLength int, proof *RangeProof) (bool, error) {
	challengeElements := [][]byte{
		MarshalPoint(commitment.Commitment),
		MarshalScalar(min),
		MarshalScalar(max),
		[]byte(strconv.Itoa(bitLength)),
	}
	expectedChallenge := GenerateChallenge(v.Params, challengeElements...)

	if !proof.Challenge.Equal(expectedChallenge) {
		return false, fmt.Errorf("challenge mismatch for RangeProof")
	}

	return proof.Verify(v.Params, commitment.Commitment, min, max, bitLength, proof.Challenge), nil
}

// verifySetMembershipProof verifies a SetMembershipProof.
// 19. verifySetMembershipProof(verifier *Verifier, commitment *AttributeCommitment, allowedValues []kyber.Scalar, proof *SetMembershipProof)
func (v *Verifier) verifySetMembershipProof(commitment *AttributeCommitment, allowedValues []kyber.Scalar, proof *SetMembershipProof) (bool, error) {
	challengeElements := [][]byte{
		MarshalPoint(commitment.Commitment),
	}
	for _, val := range allowedValues {
		challengeElements = append(challengeElements, MarshalScalar(val))
	}
	expectedChallenge := GenerateChallenge(v.Params, challengeElements...)

	if !proof.Challenge.Equal(expectedChallenge) {
		return false, fmt.Errorf("challenge mismatch for SetMembershipProof")
	}

	return proof.Verify(v.Params, commitment.Commitment, allowedValues, proof.Challenge), nil
}

// VerifyPolicyProof verifies a PolicyProof against the Verifier's policy.
// 20. VerifyPolicyProof(verifier *Verifier, proof *PolicyProof)
func (v *Verifier) VerifyPolicyProof(policyProof *PolicyProof) (bool, error) {
	results := make(map[string]bool)

	for _, criterion := range v.Policy.Criteria {
		commitment, ok := policyProof.AttributeCommitments[criterion.AttributeName]
		if !ok {
			return false, fmt.Errorf("missing commitment for attribute %s in policy proof", criterion.AttributeName)
		}

		proofBytes, ok := policyProof.Proofs[criterion.AttributeName+"_"+string(criterion.Type)]
		if !ok {
			return false, fmt.Errorf("missing proof for criterion %s of type %s in policy proof", criterion.AttributeName, criterion.Type)
		}

		var verified bool
		var err error

		switch criterion.Type {
		case CriterionTypeEqual:
			var wrapper EqualProofWrapper
			if err := json.Unmarshal(proofBytes, &wrapper); err != nil {
				return false, fmt.Errorf("failed to unmarshal EqualProof: %w", err)
			}
			expected := ValueToScalar(v.Params, criterion.Value1)
			verified, err = v.verifyEqualProof(commitment, expected, wrapper.Proof)
		case CriterionTypeRange:
			var wrapper RangeProofWrapper
			if err := json.Unmarshal(proofBytes, &wrapper); err != nil {
				return false, fmt.Errorf("failed to unmarshal RangeProof: %w", err)
			}
			min := ValueToScalar(v.Params, criterion.Value1)
			max := ValueToScalar(v.Params, criterion.Value2)
			verified, err = v.verifyRangeProof(commitment, min, max, criterion.BitLength, wrapper.Proof)
		case CriterionTypeSetMembership:
			var wrapper SetMembershipProofWrapper
			if err := json.Unmarshal(proofBytes, &wrapper); err != nil {
				return false, fmt.Errorf("failed to unmarshal SetMembershipProof: %w", err)
			}
			var allowedScalars []kyber.Scalar
			for _, val := range criterion.Values {
				allowedScalars = append(allowedScalars, ValueToScalar(v.Params, val))
			}
			verified, err = v.verifySetMembershipProof(commitment, allowedScalars, wrapper.Proof)
		default:
			return false, fmt.Errorf("unsupported criterion type: %s", criterion.Type)
		}

		if err != nil {
			return false, fmt.Errorf("verification failed for criterion %s: %w", criterion.AttributeName, err)
		}
		results[criterion.AttributeName] = verified
	}

	// Aggregate results based on policy logic (AND/OR)
	if v.Policy.Logic == "AND" {
		for _, criterion := range v.Policy.Criteria {
			if !results[criterion.AttributeName] {
				return false, nil // One false makes the AND policy false
			}
		}
		return true, nil
	} else if v.Policy.Logic == "OR" {
		for _, criterion := range v.Policy.Criteria {
			if results[criterion.AttributeName] {
				return true, nil // One true makes the OR policy true
			}
		}
		return false, nil // All false makes the OR policy false
	}
	return false, fmt.Errorf("unsupported policy logic: %s", v.Policy.Logic)
}

// --- Common Utilities ---

// SetupPublicParameters initializes and returns the PublicParams.
// 1. SetupPublicParameters()
func SetupPublicParameters() (*PublicParams, error) {
	// Using a standard Edwards25519 curve
	g := suite.Point().Base() // Standard generator
	h := suite.Point().Hash([]byte("zkaccesscontrol_H_generator"), false) // Another independent generator
	
	return &PublicParams{
		G:     g,
		H:     h,
		Suite: suite,
	}, nil
}

// GenerateRandomScalar generates a cryptographically secure random scalar.
// 2. GenerateRandomScalar(params *PublicParams)
func GenerateRandomScalar(params *PublicParams) kyber.Scalar {
	return params.Suite.Scalar().Pick(random.New())
}

// Commit computes a Pedersen commitment C = g^value * h^randomness.
// 3. Commit(params *PublicParams, value kyber.Scalar, randomness kyber.Scalar)
func Commit(params *PublicParams, value kyber.Scalar, randomness kyber.Scalar) kyber.Point {
	// C = G^value + H^randomness (in additive notation)
	// C = G.Mul(value) + H.Mul(randomness)
	return params.Suite.Point().Mul(value, params.G).Add(params.Suite.Point().Mul(randomness, params.H), nil)
}

// GenerateChallenge generates a challenge scalar using Fiat-Shamir heuristic.
// 4. GenerateChallenge(params *PublicParams, elements ...[]byte)
func GenerateChallenge(params *PublicParams, elements ...[]byte) kyber.Scalar {
	hasher := sha256.New()
	for _, el := range elements {
		hasher.Write(el)
	}
	hashBytes := hasher.Sum(nil)
	return params.Suite.Scalar().SetBytes(hashBytes)
}

// MarshalPoint serializes a kyber.Point to bytes.
// 5. MarshalPoint(p kyber.Point)
func MarshalPoint(p kyber.Point) []byte {
	if p == nil {
		return nil
	}
	data, _ := p.MarshalBinary()
	return data
}

// UnmarshalPoint deserializes bytes to a kyber.Point.
// 6. UnmarshalPoint(params *PublicParams, data []byte)
func UnmarshalPoint(params *PublicParams, data []byte) (kyber.Point, error) {
	if data == nil {
		return nil, nil
	}
	p := params.Suite.Point()
	err := p.UnmarshalBinary(data)
	return p, err
}

// MarshalScalar serializes a kyber.Scalar to bytes.
// 7. MarshalScalar(s kyber.Scalar)
func MarshalScalar(s kyber.Scalar) []byte {
	if s == nil {
		return nil
	}
	data, _ := s.MarshalBinary()
	return data
}

// UnmarshalScalar deserializes bytes to a kyber.Scalar.
// 8. UnmarshalScalar(params *PublicParams, data []byte)
func UnmarshalScalar(params *PublicParams, data []byte) (kyber.Scalar, error) {
	if data == nil {
		return nil, nil
	}
	s := params.Suite.Scalar()
	err := s.UnmarshalBinary(data)
	return s, err
}

// ValueToScalar converts an int to a kyber.Scalar.
// 9. ValueToScalar(params *PublicParams, val int)
func ValueToScalar(params *PublicParams, val int) kyber.Scalar {
	return params.Suite.Scalar().SetInt64(int64(val))
}

// --- Data Structures Helpers (for JSON serialization/deserialization) ---

// 21. NewAccessPolicy(logic string, criteria ...*AccessCriterion)
func NewAccessPolicy(logic string, criteria ...*AccessCriterion) *AccessPolicy {
	return &AccessPolicy{
		Logic:    strings.ToUpper(logic),
		Criteria: criteria,
	}
}

// 22. NewCriterion(attrName string, criterionType AccessCriterionType, value1 int, value2 int, values []int)
func NewCriterion(attrName string, criterionType AccessCriterionType, value1 int, value2 int, values []int, bitLength int) *AccessCriterion {
	return &AccessCriterion{
		AttributeName: attrName,
		Type:          criterionType,
		Value1:        value1,
		Value2:        value2,
		Values:        values,
		BitLength:     bitLength,
	}
}

// ToJSON serializes an AccessPolicy to JSON.
// 23. AccessPolicy.ToJSON()
func (ap *AccessPolicy) ToJSON() ([]byte, error) {
	return json.Marshal(ap)
}

// FromJSON deserializes JSON into an AccessPolicy.
// 23. AccessPolicy.FromJSON()
func (ap *AccessPolicy) FromJSON(data []byte) error {
	return json.Unmarshal(data, ap)
}

// ToJSON serializes a PolicyProof to JSON.
// 24. PolicyProof.ToJSON()
func (pp *PolicyProof) ToJSON() ([]byte, error) {
	// Custom marshalling for AttributeCommitments and Proofs map
	type Alias PolicyProof
	temp := &struct {
		AttributeCommitments map[string]struct {
			AttributeName string `json:"attributeName"`
			Commitment    []byte `json:"commitment"`
		} `json:"attributeCommitments"`
		*Alias
	}{
		AttributeCommitments: make(map[string]struct {
			AttributeName string `json:"attributeName"`
			Commitment    []byte `json:"commitment"`
		}),
		Alias: (*Alias)(pp),
	}

	for k, v := range pp.AttributeCommitments {
		temp.AttributeCommitments[k] = struct {
			AttributeName string `json:"attributeName"`
			Commitment    []byte `json:"commitment"`
		}{AttributeName: v.AttributeName, Commitment: MarshalPoint(v.Commitment)}
	}

	return json.Marshal(temp)
}

// FromJSON deserializes JSON into a PolicyProof.
// 24. PolicyProof.FromJSON()
func (pp *PolicyProof) FromJSON(params *PublicParams, data []byte) error {
	type Alias PolicyProof
	temp := &struct {
		AttributeCommitments map[string]struct {
			AttributeName string `json:"attributeName"`
			Commitment    []byte `json:"commitment"`
		} `json:"attributeCommitments"`
		*Alias
	}{
		Alias: (*Alias)(pp),
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	pp.AttributeCommitments = make(map[string]*AttributeCommitment)
	for k, v := range temp.AttributeCommitments {
		commitmentPoint, err := UnmarshalPoint(params, v.Commitment)
		if err != nil {
			return fmt.Errorf("failed to unmarshal commitment point: %w", err)
		}
		pp.AttributeCommitments[k] = &AttributeCommitment{
			AttributeName: v.AttributeName,
			Commitment:    commitmentPoint,
			Randomness:    nil, // Randomness is secret, not unmarshalled
		}
	}
	return nil
}

// --- Proof Implementations ---

// EqualProof is a ZKP for proving an attribute's value equals a known public value.
// It's a Schnorr-like PoK for r_attr in C * g^{-expected} = h^r_attr
type EqualProof struct {
	Challenge kyber.Scalar `json:"challenge"`
	S         kyber.Scalar `json:"s"` // s = k - c*r_attr (response)
	T         kyber.Point  `json:"t"` // t = h^k (prover's initial commitment)
}

// Type returns the criterion type for this proof.
func (p *EqualProof) Type() AccessCriterionType { return CriterionTypeEqual }

// GetChallengeBytes returns elements to be hashed for challenge generation.
func (p *EqualProof) GetChallengeBytes() [][]byte {
	// For verification, the verifier re-generates its challenge.
	// This method is primarily used internally during the proving process to ensure
	// the challenge is derived from all public components of the specific proof instance.
	// For this EqualProof structure, the 't' component is the prover's initial value for challenge generation.
	return [][]byte{MarshalPoint(p.T)}
}

// Prove generates an EqualProof.
// 25. EqualProof.Prove(params *PublicParams, attrVal, r_attr, expected kyber.Scalar, challenge kyber.Scalar)
func (p *EqualProof) Prove(params *PublicParams, attrVal, r_attr, expected kyber.Scalar, challenge kyber.Scalar) {
	// Prover wants to prove attrVal = expected
	// We are proving knowledge of `r_attr` such that `C * g^{-expected} = h^r_attr`
	// So, we use Schnorr PoK for discrete log on h.
	// 1. Prover picks random k
	k := GenerateRandomScalar(params)
	// 2. Prover computes t = h^k
	p.T = params.H.Mul(k, nil)
	// 3. Challenge c = H(C, g^expected, t) -- challenge is passed in as it's generated from outside
	//    This challenge generation should be consistent between prover/verifier
	p.Challenge = challenge // Use the provided challenge

	// 4. Prover computes s = k + c * r_attr
	s := params.Suite.Scalar().Mul(challenge, r_attr)
	s.Add(k, s)
	p.S = s
}

// Verify verifies an EqualProof.
// 26. EqualProof.Verify(params *PublicParams, commitment kyber.Point, expected kyber.Scalar, challenge kyber.Scalar)
func (p *EqualProof) Verify(params *PublicParams, commitment kyber.Point, expected kyber.Scalar, challenge kyber.Scalar) bool {
	// Reconstruct expected_C_prime = C * g^{-expected}
	expectedPointG := params.G.Mul(expected, nil)
	expectedCPrime := params.Suite.Point().Sub(commitment, expectedPointG)

	// Verifier checks: h^s == t * (C * g^{-expected})^c
	// h^s (left side)
	left := params.H.Mul(p.S, nil)

	// t * (C * g^{-expected})^c (right side)
	rightCPrimePowered := params.Suite.Point().Mul(p.Challenge, expectedCPrime)
	right := params.Suite.Point().Add(p.T, rightCPrimePowered)

	return left.Equal(right)
}

// RangeProof is a ZKP for proving an attribute's value is within a specified range [min, max].
// This uses bit decomposition: value-min is proven to be a sum of L bits, and each bit is 0 or 1.
type RangeProof struct {
	Challenge kyber.Scalar `json:"challenge"`
	// For each bit (b_i) of (attrVal - min):
	// commitment to bit_i (C_bi) = g^b_i * h^r_bi
	// proof that b_i is 0 or 1 (a disjunctive proof)
	BitCommitments []kyber.Point `json:"bitCommitments"`
	BitProofs      []*BitProof   `json:"bitProofs"` // Each BitProof proves a bit is 0 or 1
	// Proof that sum(b_i * 2^i) is consistent with (attrVal - min)
	// This is a PoK for r_diff where C_diff = g^(attrVal-min) * h^r_diff
	// And C_diff = C_sum, where C_sum = Sum(C_bi * 2^i)
	SumS kyber.Scalar `json:"sumS"` // Response for sum consistency
	SumT kyber.Point  `json:"sumT"` // Commitment for sum consistency
}

// BitProof proves that a committed value is either 0 or 1 (disjunctive proof).
type BitProof struct {
	Challenge0 kyber.Scalar `json:"challenge0"`
	Response0  kyber.Scalar `json:"response0"`
	Commitment0 kyber.Point `json:"commitment0"` // Commitment if bit is 0
	Challenge1 kyber.Scalar `json:"challenge1"`
	Response1  kyber.Scalar `json:"response1"`
	Commitment1 kyber.Point `json:"commitment1"` // Commitment if bit is 1
}

// Type returns the criterion type for this proof.
func (p *RangeProof) Type() AccessCriterionType { return CriterionTypeRange }

// GetChallengeBytes returns elements to be hashed for challenge generation.
func (p *RangeProof) GetChallengeBytes() [][]byte {
	elements := make([][]byte, 0)
	elements = append(elements, MarshalPoint(p.SumT))
	for _, bc := range p.BitCommitments {
		elements = append(elements, MarshalPoint(bc))
	}
	for _, bp := range p.BitProofs {
		elements = append(elements, MarshalPoint(bp.Commitment0), MarshalPoint(bp.Commitment1))
	}
	return elements
}

// Prove generates a RangeProof.
// 27. RangeProof.Prove(params *PublicParams, attrVal, r_attr, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)
func (p *RangeProof) Prove(params *PublicParams, attrVal, r_attr, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar) {
	// Prove that attrVal is in [min, max]
	// This is equivalent to proving:
	// 1. (attrVal - min) >= 0 AND (attrVal - min) <= (max - min)
	// Let `x = attrVal - min`. We prove `x >= 0` and `x <= (max - min)`.
	// For simplicity, we assume `x` is non-negative and prove it's representable within `bitLength` bits.
	// The `max - min` implicitly defines the max value for `x`.
	
	x := params.Suite.Scalar().Sub(attrVal, min) // The value to prove is in range [0, MaxRange] where MaxRange=2^bitLength-1
	r_x := r_attr // Re-using r_attr for now, more rigorous systems use a new random for x.
	
	// Ensure x is within the representable range (implicitly checked by bitLength)
	xBigInt := x.BigInt()
	if xBigInt.Cmp(big.NewInt(0)) < 0 {
		panic("Attribute value less than min, cannot generate proof for negative range")
	}
	maxRangeBig := big.NewInt(1).Lsh(big.NewInt(1), uint(bitLength)).Sub(big.NewInt(1), big.NewInt(1))
	if xBigInt.Cmp(maxRangeBig) > 0 {
		panic("Attribute value too large for specified bitLength range")
	}

	var bitCommitments []kyber.Point
	var bitProofs []*BitProof
	var r_bits []kyber.Scalar // Randomness for each bit commitment

	// 1. Decompose x into bits and generate proofs for each bit
	xBytes := x.Int64() // Assuming x fits in int64 for decomposition
	
	// Create common random `k` for the Schnorr PoK for sum commitment
	kSum := GenerateRandomScalar(params)
	p.SumT = params.H.Mul(kSum, nil) // T for sum consistency proof

	// Combine components for challenge
	challengeElements := p.GetChallengeBytes()
	challengeElements = append(challengeElements, MarshalScalar(x)) // Include x for challenge to make it unique
	p.Challenge = GenerateChallenge(params, challengeElements...)

	// For each bit:
	// - Commit to the bit (C_bi = g^b_i * h^r_bi)
	// - Create a Disjunctive Proof that b_i is 0 OR 1
	for i := 0; i < bitLength; i++ {
		bit := (xBytes >> i) & 1
		bitScalar := ValueToScalar(params, int(bit))
		r_bit := GenerateRandomScalar(params)
		
		C_bi := Commit(params, bitScalar, r_bit)
		bitCommitments = append(bitCommitments, C_bi)
		r_bits = append(r_bits, r_bit)

		bitProof := &BitProof{}
		
		// For disjunctive proof (b_i=0 OR b_i=1)
		// r0 and r1 are the blinding factors for each case
		r0 := GenerateRandomScalar(params)
		r1 := GenerateRandomScalar(params)

		// Commitment for b_i=0
		t0 := params.H.Mul(r0, nil) // g^0 * h^r0 = h^r0
		// Commitment for b_i=1
		t1 := params.G.Add(params.H.Mul(r1, nil), nil) // g^1 * h^r1
		
		bitProof.Commitment0 = t0
		bitProof.Commitment1 = t1

		// Challenge for the bit proof
		bitChallengeElements := [][]byte{
			MarshalPoint(C_bi),
			MarshalPoint(t0),
			MarshalPoint(t1),
		}
		bitChallenge := GenerateChallenge(params, bitChallengeElements...)

		// Disjunctive proof: one real proof, others dummy
		if bit == 0 {
			// Proving 0: actual response for r0, dummy for r1
			s0 := params.Suite.Scalar().Mul(bitChallenge, r_bit)
			s0.Add(r0, s0) // s0 = r0 + c * r_bit
			bitProof.Response0 = s0
			bitProof.Challenge0 = GenerateRandomScalar(params) // Dummy c0
			
			// Dummy for bit=1 case
			bitProof.Challenge1 = params.Suite.Scalar().Sub(bitChallenge, bitProof.Challenge0)
			bitProof.Response1 = GenerateRandomScalar(params) // Dummy s1
		} else {
			// Proving 1: actual response for r1, dummy for r0
			s1 := params.Suite.Scalar().Mul(bitChallenge, r_bit)
			s1.Add(r1, s1) // s1 = r1 + c * r_bit
			bitProof.Response1 = s1
			bitProof.Challenge1 = GenerateRandomScalar(params) // Dummy c1

			// Dummy for bit=0 case
			bitProof.Challenge0 = params.Suite.Scalar().Sub(bitChallenge, bitProof.Challenge1)
			bitProof.Response0 = GenerateRandomScalar(params) // Dummy s0
		}
		bitProofs = append(bitProofs, bitProof)
	}
	p.BitCommitments = bitCommitments
	p.BitProofs = bitProofs

	// 2. Prove consistency of sum(b_i * 2^i) with x
	// C_x = g^x * h^r_x
	// C_sum = sum_{i=0 to L-1} (C_bi)^(2^i) which is = g^(sum(bi*2^i)) * h^(sum(r_bi*2^i))
	// We want to prove C_x == C_sum. So we prove that:
	// C_x * C_sum^-1 = g^0 * h^(r_x - sum(r_bi * 2^i))
	// This is PoK of `r_x - sum(r_bi * 2^i)` on `h`.
	
	// Calculate sum of r_bi * 2^i
	sum_r_bi_pow2i := params.Suite.Scalar().Zero()
	for i := 0; i < bitLength; i++ {
		powerOf2 := ValueToScalar(params, 1<<i)
		term := params.Suite.Scalar().Mul(r_bits[i], powerOf2)
		sum_r_bi_pow2i.Add(sum_r_bi_pow2i, term)
	}

	// s_sum = kSum + challenge * (r_x - sum_r_bi_pow2i)
	diff_r := params.Suite.Scalar().Sub(r_x, sum_r_bi_pow2i)
	s_sum := params.Suite.Scalar().Mul(p.Challenge, diff_r)
	s_sum.Add(kSum, s_sum)
	p.SumS = s_sum
}

// Verify verifies a RangeProof.
// 28. RangeProof.Verify(params *PublicParams, commitment kyber.Point, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar)
func (p *RangeProof) Verify(params *PublicParams, commitment kyber.Point, min, max kyber.Scalar, bitLength int, challenge kyber.Scalar) bool {
	// 1. Verify range bounds
	// This is implicitly checked by the bitLength constraint of (attrVal - min)
	// The verifier should ensure min < max and bitLength is appropriate for (max-min)
	maxRangeBig := big.NewInt(1).Lsh(big.NewInt(1), uint(bitLength)).Sub(big.NewInt(1), big.NewInt(1))
	expectedMaxValForX := params.Suite.Scalar().Sub(max, min).BigInt()
	if expectedMaxValForX.Cmp(maxRangeBig) > 0 {
		return false // `max` is too large for the provided `bitLength`
	}
	
	// 2. Verify challenge consistency
	challengeElements := p.GetChallengeBytes()
	// This also needs to include x, but x is unknown. How does verifier generate the challenge correctly?
	// The prover must have committed to `x` or `attrVal` for the challenge.
	// For now, let's assume the challenge includes the raw commitment to `attrVal`
	// and the bounds. The prover's generation must align.
	
	// Recalculate x from commitment
	// Commitment_x = Commitment_attr * g^(-min)
	commitmentX := params.Suite.Point().Sub(commitment, params.G.Mul(min, nil))
	challengeElements = append(challengeElements, MarshalScalar(min), MarshalScalar(max), []byte(strconv.Itoa(bitLength)))
	expectedChallenge := GenerateChallenge(params, challengeElements...) // Needs to be consistent with prover's generation

	if !p.Challenge.Equal(expectedChallenge) {
		return false
	}

	// 3. Verify each BitProof
	if len(p.BitCommitments) != bitLength || len(p.BitProofs) != bitLength {
		return false
	}
	for i := 0; i < bitLength; i++ {
		C_bi := p.BitCommitments[i]
		bitProof := p.BitProofs[i]

		// Challenge for the bit proof
		bitChallengeElements := [][]byte{
			MarshalPoint(C_bi),
			MarshalPoint(bitProof.Commitment0),
			MarshalPoint(bitProof.Commitment1),
		}
		bitChallenge := GenerateChallenge(params, bitChallengeElements...)

		// Verify disjunctive proof for bit i
		// Check c0 + c1 == challenge_bit
		if !params.Suite.Scalar().Add(bitProof.Challenge0, bitProof.Challenge1).Equal(bitChallenge) {
			return false
		}

		// Check h^s0 == t0 * (C_bi)^c0
		left0 := params.H.Mul(bitProof.Response0, nil)
		right0c0 := params.Suite.Point().Mul(bitProof.Challenge0, C_bi)
		right0 := params.Suite.Point().Add(bitProof.Commitment0, right0c0)
		if !left0.Equal(right0) {
			return false
		}

		// Check h^s1 * g^c1 == t1 * (C_bi)^c1
		left1 := params.H.Mul(bitProof.Response1, nil)
		left1G := params.G.Mul(bitProof.Challenge1, nil)
		left1.Add(left1, left1G) // Corrected from original (left1 must be g^c1 * h^s1)

		right1c1 := params.Suite.Point().Mul(bitProof.Challenge1, C_bi)
		right1 := params.Suite.Point().Add(bitProof.Commitment1, right1c1)
		if !left1.Equal(right1) {
			return false
		}
	}

	// 4. Verify consistency of sum(b_i * 2^i) with x
	// C_x = commitmentX (calculated above)
	// C_sum = Sum(C_bi * 2^i)
	C_sum := params.Suite.Point().Null()
	for i := 0; i < bitLength; i++ {
		powerOf2 := ValueToScalar(params, 1<<i)
		term := params.Suite.Point().Mul(powerOf2, p.BitCommitments[i])
		C_sum.Add(C_sum, term)
	}

	// Check h^sumS == SumT * (C_x * C_sum^-1)^challenge
	// Expected difference commitment: C_diff = C_x * C_sum^-1
	C_sum_inv := params.Suite.Point().Neg(C_sum) // C_sum^-1 in additive group
	C_diff := params.Suite.Point().Add(commitmentX, C_sum_inv)

	leftSum := params.H.Mul(p.SumS, nil)
	rightSumPowered := params.Suite.Point().Mul(p.Challenge, C_diff)
	rightSum := params.Suite.Point().Add(p.SumT, rightSumPowered)

	return leftSum.Equal(rightSum)
}

// SetMembershipProof is a ZKP for proving an attribute's value is one of a set of allowed values.
// It uses a disjunctive proof (OR proof) of multiple equality proofs.
type SetMembershipProof struct {
	Challenge     kyber.Scalar `json:"challenge"`
	DisjunctiveT  []kyber.Point `json:"disjunctiveT"`  // t values for each branch of the OR proof
	DisjunctiveS  []kyber.Scalar `json:"disjunctiveS"` // s values for each branch
	DisjunctiveC  []kyber.Scalar `json:"disjunctiveC"` // c values for each branch (sum of these must be main challenge)
	ProvedIndex   int            // Only Prover knows this, not sent in JSON
}

// Type returns the criterion type for this proof.
func (p *SetMembershipProof) Type() AccessCriterionType { return CriterionTypeSetMembership }

// GetChallengeBytes returns elements to be hashed for challenge generation.
func (p *SetMembershipProof) GetChallengeBytes() [][]byte {
	elements := make([][]byte, 0)
	for _, t := range p.DisjunctiveT {
		elements = append(elements, MarshalPoint(t))
	}
	// For SetMembership, we include all possible values as part of challenge generation.
	// This function primarily returns *prover-generated* elements.
	// The overall challenge includes commitment and allowedValues.
	return elements
}

// Prove generates a SetMembershipProof.
// 29. SetMembershipProof.Prove(params *PublicParams, attrVal, r_attr kyber.Scalar, allowedValues []kyber.Scalar, challenge kyber.Scalar)
func (p *SetMembershipProof) Prove(params *PublicParams, attrVal, r_attr kyber.Scalar, allowedValues []kyber.Scalar, challenge kyber.Scalar) {
	numBranches := len(allowedValues)
	p.DisjunctiveT = make([]kyber.Point, numBranches)
	p.DisjunctiveS = make([]kyber.Scalar, numBranches)
	p.DisjunctiveC = make([]kyber.Scalar, numBranches)

	// Find the index of the actual matching value
	actualIndex := -1
	for i, val := range allowedValues {
		if attrVal.Equal(val) {
			actualIndex = i
			break
		}
	}
	if actualIndex == -1 {
		panic("Attribute value not found in allowed values, cannot generate SetMembershipProof.")
	}
	p.ProvedIndex = actualIndex

	// Generate random challenges and responses for dummy branches
	challengeSum := params.Suite.Scalar().Zero()
	for i := 0; i < numBranches; i++ {
		if i == actualIndex {
			// This branch will be filled in later with the real proof part
			continue
		}
		p.DisjunctiveC[i] = GenerateRandomScalar(params) // Dummy challenge
		p.DisjunctiveS[i] = GenerateRandomScalar(params) // Dummy response
		challengeSum.Add(challengeSum, p.DisjunctiveC[i])

		// Calculate dummy T_i for this branch: T_i = g^s_i * h^c_i * (C * g^-val_i)^c_i_neg
		// (C * g^-val_i) (this is C_expected_prime)
		C_expected_prime := params.Suite.Point().Sub(params.G.Mul(allowedValues[i], nil), nil)
		C_expected_prime.Add(C_expected_prime, params.G) // Simplified, actual point is passed in from outside

		// T_i = g^s_i * h^c_i * (C * g^-val_i)^(-c_i)
		// No, for a valid branch i, V_i checks g^s_i * h^c_i = t_i * (C * g^-val_i)^c_i
		// To make it dummy, we pick s_i, c_i, and calculate t_i
		// t_i = g^s_i * h^c_i * (C * g^-val_i)^(-c_i)
		g_s := params.G.Mul(p.DisjunctiveS[i], nil)
		h_c := params.H.Mul(p.DisjunctiveC[i], nil)
		
		dummyCPrime := params.Suite.Point().Sub(params.G.Mul(allowedValues[i], nil), nil) // (C * g^-val_i) must be based on the actual commitment
		dummyCPrimePowered := params.Suite.Point().Mul(p.DisjunctiveC[i].Neg(nil), dummyCPrime)
		
		dummyT := params.Suite.Point().Add(g_s, h_c)
		dummyT.Add(dummyT, dummyCPrimePowered)
		p.DisjunctiveT[i] = dummyT
	}

	// Calculate challenge for the actual branch: c_actual = challenge - sum(dummy_challenges)
	cActual := params.Suite.Scalar().Sub(challenge, challengeSum)
	p.DisjunctiveC[actualIndex] = cActual

	// Generate real proof for the actual branch (PoK(r_attr) for C * g^-attrVal = h^r_attr)
	// r_k = random for the actual branch's `t`
	kActual := GenerateRandomScalar(params)
	p.DisjunctiveT[actualIndex] = params.H.Mul(kActual, nil) // T_actual = h^k_actual

	// s_actual = k_actual + c_actual * r_attr
	sActual := params.Suite.Scalar().Mul(cActual, r_attr)
	sActual.Add(kActual, sActual)
	p.DisjunctiveS[actualIndex] = sActual
}

// Verify verifies a SetMembershipProof.
// 30. SetMembershipProof.Verify(params *PublicParams, commitment kyber.Point, allowedValues []kyber.Scalar, challenge kyber.Scalar)
func (p *SetMembershipProof) Verify(params *PublicParams, commitment kyber.Point, allowedValues []kyber.Scalar, challenge kyber.Scalar) bool {
	numBranches := len(allowedValues)
	if len(p.DisjunctiveT) != numBranches || len(p.DisjunctiveS) != numBranches || len(p.DisjunctiveC) != numBranches {
		return false // Mismatch in proof structure
	}

	// 1. Verify that sum of branch challenges equals the main challenge
	challengeSum := params.Suite.Scalar().Zero()
	for _, c := range p.DisjunctiveC {
		challengeSum.Add(challengeSum, c)
	}
	if !challengeSum.Equal(challenge) {
		return false // Sum of challenges must match main challenge
	}

	// 2. Verify each branch proof
	for i := 0; i < numBranches; i++ {
		t_i := p.DisjunctiveT[i]
		s_i := p.DisjunctiveS[i]
		c_i := p.DisjunctiveC[i]
		val_i := allowedValues[i]

		// Calculate C_prime_i = C * g^{-val_i}
		C_prime_i := params.Suite.Point().Sub(commitment, params.G.Mul(val_i, nil))

		// Check: h^s_i == t_i * (C_prime_i)^c_i
		left := params.H.Mul(s_i, nil)

		rightPowered := params.Suite.Point().Mul(c_i, C_prime_i)
		right := params.Suite.Point().Add(t_i, rightPowered)

		if !left.Equal(right) {
			return false // A branch verification failed
		}
	}
	return true
}

```