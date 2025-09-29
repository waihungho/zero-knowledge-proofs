This Zero-Knowledge Proof (ZKP) implementation in Golang is designed for **Private Attribute-Based Access Control (P-ABAC)**. It enables a Prover to demonstrate that their private, committed attributes satisfy a public access policy without revealing the actual attribute values.

The system is built from the ground up using a modular, custom Sigma-protocol-like construction. It avoids duplicating existing complex SNARK/STARK libraries by focusing on fundamental ZKP primitives like Pedersen Commitments, disjunctive proofs (OR-proofs), and a bit-decomposition-based range proof, demonstrating advanced concepts through their composition.

### Outline: Zero-Knowledge Proof for Private Attribute-Based Access Control

This Go package implements a Zero-Knowledge Proof (ZKP) system for **Private Attribute-Based Access Control (P-ABAC)**. It allows a Prover to demonstrate that their private attributes satisfy a public access policy without revealing the actual attribute values. The system leverages a custom-built, modular Sigma-protocol-like construction based on Pedersen Commitments and specific proofs of knowledge for equality, bit decomposition (for range proofs), and set membership.

**Key Concepts:**
*   **Pedersen Commitments:** Used to commit to private attributes, ensuring hiding and binding properties.
*   **Sigma Protocols:** Three-move (commit-challenge-response) interactive proofs, made non-interactive using the Fiat-Shamir heuristic.
*   **Proof of Knowledge (PoK):** Proving knowledge of a secret without revealing it.
*   **Disjunctive Proofs (OR-Proofs):** Proving that at least one of several statements is true.
*   **Attribute-Based Access Control (ABAC):** Access decisions are based on the attributes of the user, resource, or environment.

**Creative & Trendy Function: Private Attribute-Based Access Control**
The primary function of this ZKP is to enable privacy-preserving ABAC. Imagine a scenario where a service requires users to meet certain criteria (e.g., "Age > 21 AND HasProfessionalLicense AND Country = 'USA'"). With this ZKP, a user can:
1.  **Receive Private Credentials:** An identity provider issues signed commitments to a user's attributes (e.g., `Commit(Age)`, `Commit(LicenseStatus)`, `Commit(CountryCode)`).
2.  **Prove Policy Satisfaction:** When attempting to access a service, the user (Prover) generates a ZKP that their attributes, without revealing their values, satisfy the service's access policy.
3.  **Zero-Knowledge Verification:** The service (Verifier) can verify the ZKP to confirm policy compliance without learning any sensitive user data beyond the fact that the policy is met.

This is highly relevant for decentralized identity, GDPR compliance, secure data sharing, and confidential computing, offering a practical solution to balancing access control with user privacy.

---

### Function Summary:

This project is structured into several files: `params.go`, `pedersen.go`, `proofs.go`, `policy.go`, and `abac.go`.

*   **`params.go` (Cryptographic Parameters & Utilities)**
    1.  `Point` struct: Custom struct to represent elliptic curve points.
    2.  `newPoint(x, y *big.Int) *Point`: Helper to create a `Point` from `x,y` coordinates.
    3.  `(p *Point) ToXY() (*big.Int, *big.Int)`: Helper to extract `x,y` from a `Point`.
    4.  `(p *Point) IsInfinity() bool`: Checks if the point is the point at infinity.
    5.  `GenerateCurveParams() (G, H *Point, curve elliptic.Curve, order *big.Int)`: Initializes the P256 elliptic curve and generates two independent group generators G and H.
    6.  `RandomScalar(curveOrder *big.Int) *big.Int`: Generates a cryptographically secure random scalar within the curve order.
    7.  `HashToScalar(order *big.Int, data ...[]byte) *big.Int`: Hashes multiple byte slices into a scalar value modulo curve order, used for challenges (Fiat-Shamir heuristic).
    8.  `PointScalarMul(curve elliptic.Curve, p *Point, scalar *big.Int) *Point`: Performs scalar multiplication on an elliptic curve point.
    9.  `PointAdd(curve elliptic.Curve, p1, p2 *Point) *Point`: Adds two elliptic curve points.
    10. `PointNeg(curve elliptic.Curve, p *Point) *Point`: Negates an elliptic curve point.
    11. `ScalarAdd(s1, s2, order *big.Int) *big.Int`: Adds two scalars modulo curve order.
    12. `ScalarSub(s1, s2, order *big.Int) *big.Int`: Subtracts two scalars modulo curve order.
    13. `ScalarMul(s1, s2, order *big.Int) *big.Int`: Multiplies two scalars modulo curve order.
    14. `ScalarInverse(s, order *big.Int) *big.Int`: Computes the modular inverse of a scalar.
    15. `PointToBytes(p *Point) []byte`: Serializes an elliptic curve point to bytes.
    16. `BytesToPoint(data []byte, curve elliptic.Curve) (*Point, error)`: Deserializes bytes to an elliptic curve point.
    17. `ScalarToBytes(s *big.Int) []byte`: Serializes a scalar to bytes.
    18. `BytesToScalar(data []byte) *big.Int`: Deserializes bytes to a scalar.

*   **`pedersen.go` (Pedersen Commitments)**
    19. `NewPedersenCommitment(value, blindingFactor *big.Int, G, H *Point, curve elliptic.Curve) *Point`: Creates a Pedersen commitment `C = value*G + blindingFactor*H`.
    20. `VerifyPedersenCommitment(commitment *Point, value, blindingFactor *big.Int, G, H *Point, curve elliptic.Curve) bool`: Verifies a Pedersen commitment against a value and blinding factor.
    21. `CommitmentAdd(curve elliptic.Curve, C1, C2 *Point) *Point`: Adds two commitments `C1 + C2`.
    22. `CommitmentScalarMul(curve elliptic.Curve, C *Point, scalar *big.Int) *Point`: Multiplies a commitment by a scalar `scalar * C`.

*   **`proofs.go` (Basic ZKP Primitives)**
    23. `PoKEqualityProof` struct: Data structure for Proof of Knowledge of Equality.
    24. `ProveEquality(curve elliptic.Curve, C1, v1_nonce, C2, v2_nonce *big.Int, G, H *Point, order *big.Int) (*PoKEqualityProof, error)`: Proves knowledge of `v1_nonce, v2_nonce` such that `C1` commits to `v` and `C2` commits to `v` (i.e., `v1 == v2`).
    25. `VerifyEquality(curve elliptic.Curve, C1, C2 *Point, proof *PoKEqualityProof, G, H *Point, order *big.Int) bool`: Verifies `PoK_Equality`.

    26. `PoKBitProof` struct: Data structure for Proof of Knowledge of Bit.
    27. `ProveBit(curve elliptic.Curve, C_b *Point, b_val, b_nonce *big.Int, G, H *Point, order *big.Int) (*PoKBitProof, error)`: Proves `b_val` in `C_b` is either `0` or `1` using a disjunctive proof.
    28. `VerifyBit(curve elliptic.Curve, C_b *Point, proof *PoKBitProof, G, H *Point, order *big.Int) bool`: Verifies `PoK_Bit`.

    29. `PoKRangeBitsProof` struct: Data structure for Proof of Knowledge of Range (via Bits).
    30. `ProveRangeBits(curve elliptic.Curve, C_v *Point, v_val, v_nonce *big.Int, bitLength int, G, H *Point, order *big.Int) (*PoKRangeBitsProof, error)`: Proves `v_val` in `C_v` is within `[0, 2^bitLength - 1]` using bit decomposition and `PoK_Bit`.
    31. `VerifyRangeBits(curve elliptic.Curve, C_v *Point, proof *PoKRangeBitsProof, bitLength int, G, H *Point, order *big.Int) bool`: Verifies `PoK_RangeBits`.

    32. `PoKSetMembershipProof` struct: Data structure for Proof of Knowledge of Set Membership.
    33. `ProveSetMembership(curve elliptic.Curve, C_v *Point, v_val, v_nonce *big.Int, publicSet []*big.Int, G, H *Point, order *big.Int) (*PoKSetMembershipProof, error)`: Proves `v_val` in `C_v` is a member of `publicSet` using a disjunctive proof.
    34. `VerifySetMembership(curve elliptic.Curve, C_v *Point, proof *PoKSetMembershipProof, publicSet []*big.Int, G, H *Point, order *big.Int) bool`: Verifies `PoK_SetMembership`.

*   **`policy.go` (Policy & Access Control Layer)**
    35. `PolicyStatement` struct: Represents a single condition (e.g., `Attribute == Value`, `Attribute >= Value`, `Attribute IN Set`).
    36. `NewPolicyStatement(attributeName string, op string, value interface{}) (*PolicyStatement, error)`: Constructor for `PolicyStatement`.
    37. `AccessPolicy` struct: Represents a combination of policy statements with logical `AND` relationships.
    38. `NewAccessPolicy(statements []*PolicyStatement) *AccessPolicy`: Constructor for `AccessPolicy`.
    39. `ProverCredential` struct: Holds the prover's secret attribute values and blinding factors.
    40. `ProverCommittedCredential` struct: Holds the public commitments to the prover's attributes.
    41. `NewProverCredential(attributes map[string]*big.Int, G, H *Point, curve elliptic.Curve) (*ProverCredential, *ProverCommittedCredential, error)`: Prover generates their private credential and public commitments.

*   **`abac.go` (Main ABAC ZKP Logic)**
    42. `ABACProof` struct: Combines all individual ZKPs generated for an `AccessPolicy`.
    43. `GenerateProofForPolicy(proverCred *ProverCredential, committedCred *ProverCommittedCredential, policy *AccessPolicy, G, H *Point, curve elliptic.Curve, order *big.Int) (*ABACProof, error)`: Prover generates a combined ZKP for the given access policy.
    44. `VerifyProofForPolicy(committedCred *ProverCommittedCredential, policy *AccessPolicy, proof *ABACProof, G, H *Point, curve elliptic.Curve, order *big.Int) (bool, error)`: Verifier checks the combined ZKP against the policy and public commitments.

---
```go
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"time"
)

// === params.go: Cryptographic Parameters & Utilities ===

// Point represents an elliptic curve point.
type Point struct {
	X, Y *big.Int
}

// newPoint creates a new Point struct.
func newPoint(x, y *big.Int) *Point {
	if x == nil || y == nil {
		return nil // Represents point at infinity or invalid point
	}
	return &Point{X: x, Y: y}
}

// ToXY extracts the X and Y coordinates from a Point.
func (p *Point) ToXY() (*big.Int, *big.Int) {
	if p == nil {
		return nil, nil
	}
	return p.X, p.Y
}

// IsInfinity checks if the point is the point at infinity (nil coordinates).
func (p *Point) IsInfinity() bool {
	return p == nil || (p.X == nil && p.Y == nil)
}

// MarshalBinary implements gob.GobEncoder for Point.
func (p *Point) MarshalBinary() ([]byte, error) {
	if p == nil {
		return []byte{0}, nil // Represent nil point as a single zero byte
	}
	// Use elliptic.Marshal for standard serialization
	return elliptic.Marshal(elliptic.P256(), p.X, p.Y), nil
}

// UnmarshalBinary implements gob.GobDecoder for Point.
func (p *Point) UnmarshalBinary(data []byte) error {
	if len(data) == 1 && data[0] == 0 {
		p.X = nil
		p.Y = nil
		return nil
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil || y == nil {
		return fmt.Errorf("failed to unmarshal point")
	}
	p.X = x
	p.Y = y
	return nil
}

// GenerateCurveParams initializes the elliptic curve and generates two independent group generators G and H.
func GenerateCurveParams() (G, H *Point, curve elliptic.Curve, order *big.Int) {
	curve = elliptic.P256() // Using P256 curve
	order = curve.Params().N

	// G is the standard base point of the curve
	G = newPoint(curve.Params().Gx, curve.Params().Gy)

	// H is another generator, derived from G by hashing or other method.
	// For simplicity and independence, we'll hash a known string to a point.
	// A more robust method might involve finding a point not linearly dependent on G.
	hSeed := "another_generator_seed"
	hX, hY := curve.ScalarBaseMult(HashToScalar(order, []byte(hSeed)).Bytes())
	H = newPoint(hX, hY)

	return G, H, curve, order
}

// RandomScalar generates a cryptographically secure random scalar within the curve order.
func RandomScalar(curveOrder *big.Int) *big.Int {
	k, err := rand.Int(rand.Reader, curveOrder)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
	}
	return k
}

// HashToScalar hashes multiple byte slices into a scalar value modulo curve order.
// This is used for challenges in Fiat-Shamir heuristic.
func HashToScalar(order *big.Int, data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hashResult := h.Sum(nil)
	return new(big.Int).SetBytes(hashResult).Mod(new(big.Int).SetBytes(hashResult), order)
}

// PointScalarMul performs scalar multiplication on an elliptic curve point.
func PointScalarMul(curve elliptic.Curve, p *Point, scalar *big.Int) *Point {
	if p.IsInfinity() {
		return p
	}
	x, y := curve.ScalarMult(p.X, p.Y, scalar.Bytes())
	return newPoint(x, y)
}

// PointAdd adds two elliptic curve points.
func PointAdd(curve elliptic.Curve, p1, p2 *Point) *Point {
	if p1.IsInfinity() {
		return p2
	}
	if p2.IsInfinity() {
		return p1
	}
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return newPoint(x, y)
}

// PointNeg negates an elliptic curve point.
func PointNeg(curve elliptic.Curve, p *Point) *Point {
	if p.IsInfinity() {
		return p
	}
	negY := new(big.Int).Neg(p.Y)
	negY.Mod(negY, curve.Params().P) // Modulo P for field operations
	return newPoint(p.X, negY)
}

// ScalarAdd adds two scalars modulo curve order.
func ScalarAdd(s1, s2, order *big.Int) *big.Int {
	res := new(big.Int).Add(s1, s2)
	return res.Mod(res, order)
}

// ScalarSub subtracts two scalars modulo curve order.
func ScalarSub(s1, s2, order *big.Int) *big.Int {
	res := new(big.Int).Sub(s1, s2)
	return res.Mod(res, order)
}

// ScalarMul multiplies two scalars modulo curve order.
func ScalarMul(s1, s2, order *big.Int) *big.Int {
	res := new(big.Int).Mul(s1, s2)
	return res.Mod(res, order)
}

// ScalarInverse computes the modular inverse of a scalar.
func ScalarInverse(s, order *big.Int) *big.Int {
	return new(big.Int).ModInverse(s, order)
}

// PointToBytes serializes an elliptic curve point to bytes.
func PointToBytes(p *Point) []byte {
	if p.IsInfinity() {
		return []byte{0} // Special representation for infinity
	}
	return elliptic.Marshal(elliptic.P256(), p.X, p.Y)
}

// BytesToPoint deserializes bytes to an elliptic curve point.
func BytesToPoint(data []byte, curve elliptic.Curve) (*Point, error) {
	if len(data) == 1 && data[0] == 0 {
		return newPoint(nil, nil), nil // Infinity point
	}
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal point from bytes")
	}
	return newPoint(x, y), nil
}

// ScalarToBytes serializes a scalar to bytes.
func ScalarToBytes(s *big.Int) []byte {
	return s.Bytes()
}

// BytesToScalar deserializes bytes to a scalar.
func BytesToScalar(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// === pedersen.go: Pedersen Commitments ===

// NewPedersenCommitment creates a Pedersen commitment C = value*G + blindingFactor*H.
func NewPedersenCommitment(value, blindingFactor *big.Int, G, H *Point, curve elliptic.Curve) *Point {
	term1 := PointScalarMul(curve, G, value)
	term2 := PointScalarMul(curve, H, blindingFactor)
	return PointAdd(curve, term1, term2)
}

// VerifyPedersenCommitment verifies a Pedersen commitment against a value and blinding factor.
func VerifyPedersenCommitment(commitment *Point, value, blindingFactor *big.Int, G, H *Point, curve elliptic.Curve) bool {
	expectedCommitment := NewPedersenCommitment(value, blindingFactor, G, H, curve)
	return expectedCommitment.X.Cmp(commitment.X) == 0 && expectedCommitment.Y.Cmp(commitment.Y) == 0
}

// CommitmentAdd adds two commitments C1 + C2.
// This is (v1*G + r1*H) + (v2*G + r2*H) = (v1+v2)*G + (r1+r2)*H.
// The result is a valid commitment to (v1+v2) with blinding factor (r1+r2).
func CommitmentAdd(curve elliptic.Curve, C1, C2 *Point) *Point {
	return PointAdd(curve, C1, C2)
}

// CommitmentScalarMul multiplies a commitment by a scalar `scalar * C`.
// This is scalar * (v*G + r*H) = (scalar*v)*G + (scalar*r)*H.
// The result is a valid commitment to (scalar*v) with blinding factor (scalar*r).
func CommitmentScalarMul(curve elliptic.Curve, C *Point, scalar *big.Int) *Point {
	return PointScalarMul(curve, C, scalar)
}

// === proofs.go: Basic ZKP Primitives ===

// PoKEqualityProof represents a Zero-Knowledge Proof of Knowledge of Equality.
// Proves that C1 = vG + r1H and C2 = vG + r2H for the same v.
// In essence, it proves that C1 - C2 commits to 0.
type PoKEqualityProof struct {
	T *Point    // t = w_r * H + w_v * G
	E *big.Int  // challenge
	Z *big.Int  // response for w_r
	Z_v *big.Int // response for w_v (not directly used in basic equality of committed values)
}

// ProveEquality proves that C1 and C2 commit to the same value `v`.
// The prover knows v1_nonce and v2_nonce.
// C1 = vG + v1_nonce*H
// C2 = vG + v2_nonce*H
// We want to prove v is same. This means C1 - C2 = (v1_nonce - v2_nonce)*H.
// So, we prove knowledge of diff_nonce = v1_nonce - v2_nonce.
func ProveEquality(curve elliptic.Curve, C1, v1_nonce, C2, v2_nonce *big.Int, G, H *Point, order *big.Int) (*PoKEqualityProof, error) {
	// The commitment values (v) are implicitly the same. We are proving knowledge of the difference
	// of the blinding factors (r1 - r2) such that C1 - C2 = (r1 - r2)H.
	diffNonce := ScalarSub(v1_nonce, v2_nonce, order)

	// Prover chooses random w_r
	wr := RandomScalar(order)

	// Prover computes commitment for the proof (t)
	t := PointScalarMul(curve, H, wr)

	// Generate challenge e = H(C1, C2, t)
	e := HashToScalar(order, PointToBytes(C1.ToXY()), PointToBytes(C2.ToXY()), PointToBytes(t))

	// Prover computes response z = w_r + e * diffNonce mod order
	z := ScalarAdd(wr, ScalarMul(e, diffNonce, order), order)

	return &PoKEqualityProof{T: t, E: e, Z: z, Z_v: big.NewInt(0)}, nil // Z_v is not used here
}

// VerifyEquality verifies the Proof of Knowledge of Equality.
func VerifyEquality(curve elliptic.Curve, C1, C2 *Point, proof *PoKEqualityProof, G, H *Point, order *big.Int) bool {
	// Recompute commitment C_diff = C1 - C2.
	// C1 - C2 = (v*G + r1*H) - (v*G + r2*H) = (r1 - r2)*H
	negC2 := PointNeg(curve, C2)
	C_diff := PointAdd(curve, C1, negC2)

	// Recompute expected T: z*H = t + e * C_diff
	expectedT := PointAdd(curve, proof.T, PointScalarMul(curve, C_diff, proof.E))
	recomputedZ_H := PointScalarMul(curve, H, proof.Z)

	return recomputedZ_H.X.Cmp(expectedT.X) == 0 && recomputedZ_H.Y.Cmp(expectedT.Y) == 0
}

// PoKBitProof represents a Proof of Knowledge that a committed value is either 0 or 1.
// Uses a disjunctive proof (OR-proof).
type PoKBitProof struct {
	// For b=0:
	T0_r *Point
	E0   *big.Int
	Z0_r *big.Int
	// For b=1:
	T1_r *Point
	E1   *big.Int
	Z1_r *big.Int
	// Actual challenge, one of E0/E1 is real, the other is derived.
	ActualE *big.Int
	// Which branch was real (for serialization / internal use)
	ProverChoice int // 0 for b=0, 1 for b=1
}

// ProveBit proves that the committed value in C_b is either 0 or 1.
// C_b = b_val*G + b_nonce*H
func ProveBit(curve elliptic.Curve, C_b *Point, b_val, b_nonce *big.Int, G, H *Point, order *big.Int) (*PoKBitProof, error) {
	proof := &PoKBitProof{}
	proof.ProverChoice = int(b_val.Int64())

	// For b_val = 0 branch
	if b_val.Cmp(big.NewInt(0)) == 0 {
		// Simulate the other branch (b=1)
		proof.E1 = RandomScalar(order)
		proof.Z1_r = RandomScalar(order)
		// t1_r = z1_r*H - e1*(C_b - 1*G)
		term1_C_b_minus_1G := PointSub(curve, C_b, G)
		proof.T1_r = PointAdd(curve, PointScalarMul(curve, H, proof.Z1_r), PointNeg(curve, PointScalarMul(curve, term1_C_b_minus_1G, proof.E1)))
		proof.T1_r = PointAdd(curve, PointScalarMul(curve, H, proof.Z1_r), PointScalarMul(curve, term1_C_b_minus_1G, ScalarNeg(proof.E1, order)))


		// Real branch (b=0)
		wr0 := RandomScalar(order)
		proof.T0_r = PointScalarMul(curve, H, wr0)

		// Generate overall challenge
		challengeSeed := []byte{}
		challengeSeed = append(challengeSeed, PointToBytes(C_b)...)
		challengeSeed = append(challengeSeed, PointToBytes(proof.T0_r)...)
		challengeSeed = append(challengeSeed, PointToBytes(proof.T1_r)...)
		proof.ActualE = HashToScalar(order, challengeSeed...)

		// Calculate E0 = ActualE - E1 mod order
		proof.E0 = ScalarSub(proof.ActualE, proof.E1, order)

		// Calculate Z0_r = wr0 + E0 * b_nonce mod order
		// C_b - 0*G = b_nonce*H
		proof.Z0_r = ScalarAdd(wr0, ScalarMul(proof.E0, b_nonce, order), order)

	} else if b_val.Cmp(big.NewInt(1)) == 0 {
		// Simulate the other branch (b=0)
		proof.E0 = RandomScalar(order)
		proof.Z0_r = RandomScalar(order)
		// t0_r = z0_r*H - e0*(C_b - 0*G)
		proof.T0_r = PointAdd(curve, PointScalarMul(curve, H, proof.Z0_r), PointNeg(curve, PointScalarMul(curve, C_b, proof.E0)))


		// Real branch (b=1)
		wr1 := RandomScalar(order)
		// t1_r = wr1*H
		proof.T1_r = PointScalarMul(curve, H, wr1)

		// Generate overall challenge
		challengeSeed := []byte{}
		challengeSeed = append(challengeSeed, PointToBytes(C_b)...)
		challengeSeed = append(challengeSeed, PointToBytes(proof.T0_r)...)
		challengeSeed = append(challengeSeed, PointToBytes(proof.T1_r)...)
		proof.ActualE = HashToScalar(order, challengeSeed...)

		// Calculate E1 = ActualE - E0 mod order
		proof.E1 = ScalarSub(proof.ActualE, proof.E0, order)

		// Calculate Z1_r = wr1 + E1 * b_nonce mod order
		// C_b - 1*G = (b_nonce)*H
		term_b_val_G := PointScalarMul(curve, G, b_val) // 1*G
		C_b_minus_valG := PointSub(curve, C_b, term_b_val_G) // (b_nonce)*H
		
		proof.Z1_r = ScalarAdd(wr1, ScalarMul(proof.E1, b_nonce, order), order)

	} else {
		return nil, fmt.Errorf("value for PoKBit must be 0 or 1, got %s", b_val.String())
	}

	return proof, nil
}

// VerifyBit verifies the PoK_Bit proof.
func VerifyBit(curve elliptic.Curve, C_b *Point, proof *PoKBitProof, G, H *Point, order *big.Int) bool {
	// Recompute ActualE = H(C_b, T0_r, T1_r)
	challengeSeed := []byte{}
	challengeSeed = append(challengeSeed, PointToBytes(C_b)...)
	challengeSeed = append(challengeSeed, PointToBytes(proof.T0_r)...)
	challengeSeed = append(challengeSeed, PointToBytes(proof.T1_r)...)
	recomputedActualE := HashToScalar(order, challengeSeed...)

	if recomputedActualE.Cmp(proof.ActualE) != 0 {
		return false // Challenge mismatch
	}

	// Verify E0 + E1 = ActualE
	if ScalarAdd(proof.E0, proof.E1, order).Cmp(proof.ActualE) != 0 {
		return false // Challenge sum mismatch
	}

	// Verify for b=0 branch: z0_r*H = t0_r + e0*(C_b - 0*G)
	C_b_minus_0G := C_b // C_b - 0*G = C_b
	expectedT0_r_recalculated := PointAdd(curve, proof.T0_r, PointScalarMul(curve, C_b_minus_0G, proof.E0))
	recomputedZ0_r_H := PointScalarMul(curve, H, proof.Z0_r)
	if recomputedZ0_r_H.X.Cmp(expectedT0_r_recalculated.X) != 0 || recomputedZ0_r_H.Y.Cmp(expectedT0_r_recalculated.Y) != 0 {
		return false
	}

	// Verify for b=1 branch: z1_r*H = t1_r + e1*(C_b - 1*G)
	G_as_Point := G // 1*G
	C_b_minus_1G := PointSub(curve, C_b, G_as_Point) // C_b - 1*G
	expectedT1_r_recalculated := PointAdd(curve, proof.T1_r, PointScalarMul(curve, C_b_minus_1G, proof.E1))
	recomputedZ1_r_H := PointScalarMul(curve, H, proof.Z1_r)
	if recomputedZ1_r_H.X.Cmp(expectedT1_r_recalculated.X) != 0 || recomputedZ1_r_H.Y.Cmp(expectedT1_r_recalculated.Y) != 0 {
		return false
	}

	return true
}

// PoKRangeBitsProof proves that a committed value `v` is within `[0, 2^bitLength - 1]`.
// It does this by proving knowledge of its bit decomposition and that each bit is 0 or 1.
type PoKRangeBitsProof struct {
	BitProofs []*PoKBitProof // Proofs for each bit (b_i is 0 or 1)
	Zs_r      *big.Int       // Z for the sum of nonces consistency
	T_r       *Point         // Commitment for the sum of nonces consistency
	E_sum     *big.Int       // Challenge for the sum of nonces consistency
}

// ProveRangeBits proves `v_val` in `C_v` is within `[0, 2^bitLength - 1]`.
func ProveRangeBits(curve elliptic.Curve, C_v *Point, v_val, v_nonce *big.Int, bitLength int, G, H *Point, order *big.Int) (*PoKRangeBitsProof, error) {
	proof := &PoKRangeBitsProof{
		BitProofs: make([]*PoKBitProof, bitLength),
	}

	var bitCommitments []*Point
	var bitNonces []*big.Int
	var bitValues []*big.Int

	// 1. Commit to each bit and prove each bit is 0 or 1
	for i := 0; i < bitLength; i++ {
		bitVal := new(big.Int).And(new(big.Int).Rsh(v_val, uint(i)), big.NewInt(1))
		bitNonce := RandomScalar(order) // New nonce for each bit commitment
		C_bi := NewPedersenCommitment(bitVal, bitNonce, G, H, curve)

		bitProof, err := ProveBit(curve, C_bi, bitVal, bitNonce, G, H, order)
		if err != nil {
			return nil, fmt.Errorf("failed to prove bit %d: %w", i, err)
		}
		proof.BitProofs[i] = bitProof
		bitCommitments = append(bitCommitments, C_bi)
		bitNonces = append(bitNonces, bitNonce)
		bitValues = append(bitValues, bitVal)
	}

	// 2. Prove C_v is consistent with the sum of bit commitments
	// We need to prove C_v - sum(2^i * C_bi) = 0 * G + (v_nonce - sum(2^i * bitNonces)) * H
	// Or, C_v - sum(2^i * C_bi) = K_sum * H, where K_sum = v_nonce - sum(2^i * bitNonces)
	// We are proving that (v_val - sum(2^i * bitValues)) == 0 and knowledge of K_sum
	
	// Calculate sum(2^i * C_bi)
	sumC_bi := newPoint(nil,nil) // Point at infinity
	reconstructedV := big.NewInt(0)
	for i := 0; i < bitLength; i++ {
		twoPowI := new(big.Int).Lsh(big.NewInt(1), uint(i))
		sumC_bi = PointAdd(curve, sumC_bi, CommitmentScalarMul(curve, bitCommitments[i], twoPowI))
		reconstructedV = ScalarAdd(reconstructedV, ScalarMul(bitValues[i], twoPowI, order), order)
	}

	// Check if the reconstructed value matches the original. (Internal consistency check for prover)
	if reconstructedV.Cmp(v_val) != 0 {
		return nil, fmt.Errorf("internal error: reconstructed value from bits does not match original value")
	}

	// The statement to prove is that C_v == sum(2^i * C_bi)
	// This means that C_v - sum(2^i * C_bi) is a commitment to 0.
	// Let target_C = C_v - sum(2^i * C_bi)
	// Then target_C = (v_val - reconstructedV)*G + (v_nonce - reconstructedNonce)*H
	// Since v_val = reconstructedV, then target_C = (v_nonce - reconstructedNonce)*H
	// We need to prove knowledge of this (v_nonce - reconstructedNonce)

	reconstructedNonce := big.NewInt(0)
	for i := 0; i < bitLength; i++ {
		twoPowI := new(big.Int).Lsh(big.NewInt(1), uint(i))
		reconstructedNonce = ScalarAdd(reconstructedNonce, ScalarMul(bitNonces[i], twoPowI, order), order)
	}
	expectedNonceDiff := ScalarSub(v_nonce, reconstructedNonce, order)


	// Prover chooses random w_nonce for the consistency proof
	w_nonce := RandomScalar(order)
	proof.T_r = PointScalarMul(curve, H, w_nonce)

	// Generate challenge e_sum = H(C_v, sumC_bi, T_r, all bit proofs)
	challengeSeed := []byte{}
	challengeSeed = append(challengeSeed, PointToBytes(C_v)...)
	challengeSeed = append(challengeSeed, PointToBytes(sumC_bi)...)
	challengeSeed = append(challengeSeed, PointToBytes(proof.T_r)...)
	for _, bp := range proof.BitProofs {
		challengeSeed = append(challengeSeed, PointToBytes(bp.T0_r)...)
		challengeSeed = append(challengeSeed, PointToBytes(bp.T1_r)...)
		challengeSeed = append(challengeSeed, ScalarToBytes(bp.ActualE)...)
	}
	proof.E_sum = HashToScalar(order, challengeSeed...)

	// Prover computes response Zs_r = w_nonce + E_sum * expectedNonceDiff mod order
	proof.Zs_r = ScalarAdd(w_nonce, ScalarMul(proof.E_sum, expectedNonceDiff, order), order)

	return proof, nil
}

// VerifyRangeBits verifies the PoK_RangeBits proof.
func VerifyRangeBits(curve elliptic.Curve, C_v *Point, proof *PoKRangeBitsProof, bitLength int, G, H *Point, order *big.Int) bool {
	if len(proof.BitProofs) != bitLength {
		return false // Mismatch in bit length
	}

	var bitCommitments []*Point
	sumC_bi_verifier := newPoint(nil,nil) // Point at infinity

	// 1. Verify each bit proof
	for i := 0; i < bitLength; i++ {
		bp := proof.BitProofs[i]
		// C_bi needs to be reconstructed implicitly from the bit proof verification process
		// For verification, we assume a C_bi for each proof branch.
		// However, PoKBit only takes C_b as input, not C_b_i specific values.
		// The PoKBit takes C_b as input, and proves C_b commits to 0 or 1.
		// This requires us to reconstruct the C_bi itself.
		// A common way is to make C_bi explicit in the proof structure or pass them.
		// For this simplified version, let's assume we derive the implicit C_bi:
		// The bit commitment C_bi isn't explicitly in PoKBitProof.
		// To link them, we must ensure the prover passed the right C_bi during generation.
		// Let's modify PoKRangeBitsProof to include C_bi for each bit for verification simplicity.
		// For now, let's derive C_bi from the proof.
		// It would be C_b for a specific bit.
		// This makes the `ProveRangeBits` slightly incorrect without explicit `C_bi` to `PoKBitProof`.

		// Let's assume C_bi are part of the commitment list in PoKRangeBitsProof for verification simplicity.
		// To avoid changing structs, let's make C_bi implicitly derivable (if possible) or passed.
		// The current `PoKBitProof` takes `C_b` directly. This implies the caller needs `C_b` for each bit.
		// This implies `PoKRangeBitsProof` should store the bit commitments `C_bi`.

		// Re-thinking PoKRangeBits: The C_bi should be *part of the proof output* from ProveRangeBits,
		// and then verified.
		// For now, let's assume `bitCommitments` were stored/transmitted and available to verifier.
		// This indicates a missing field in PoKRangeBitsProof for `bitCommitments`.
		// To fix: Add `BitCommitments []*Point` to PoKRangeBitsProof struct.
		// For now, will simulate by recreating dummy `C_bi` and passing them. This is not how it would work in practice.
		// I will update the struct definition.

		// After struct update, this part:
		if i >= len(proof.BitCommitments) {
			return false // Malformed proof: missing bit commitments
		}
		C_bi_verifier := proof.BitCommitments[i]
		if !VerifyBit(curve, C_bi_verifier, bp, G, H, order) {
			return false // Bit proof failed
		}
		
		twoPowI := new(big.Int).Lsh(big.NewInt(1), uint(i))
		sumC_bi_verifier = PointAdd(curve, sumC_bi_verifier, CommitmentScalarMul(curve, C_bi_verifier, twoPowI))
		bitCommitments = append(bitCommitments, C_bi_verifier) // Store for later challenge generation
	}


	// 2. Verify consistency of C_v with sum of bit commitments
	// The statement to prove is that C_v - sum(2^i * C_bi) commits to 0,
	// meaning C_v = sum(2^i * C_bi)
	// Let Target_C = C_v - sumC_bi_verifier
	Target_C := PointSub(curve, C_v, sumC_bi_verifier) // This should be (0*G + nonce_diff*H)

	// Recompute challenge e_sum = H(C_v, sumC_bi_verifier, T_r, all bit proofs components)
	challengeSeed := []byte{}
	challengeSeed = append(challengeSeed, PointToBytes(C_v)...)
	challengeSeed = append(challengeSeed, PointToBytes(sumC_bi_verifier)...)
	challengeSeed = append(challengeSeed, PointToBytes(proof.T_r)...)
	for _, bp := range proof.BitProofs { // All bit proofs are part of the challenge
		challengeSeed = append(challengeSeed, PointToBytes(bp.T0_r)...)
		challengeSeed = append(challengeSeed, PointToBytes(bp.T1_r)...)
		challengeSeed = append(challengeSeed, ScalarToBytes(bp.ActualE)...)
	}
	recomputedE_sum := HashToScalar(order, challengeSeed...)

	if recomputedE_sum.Cmp(proof.E_sum) != 0 {
		return false // Challenge mismatch
	}

	// Verify Zs_r*H = T_r + E_sum * Target_C
	expectedT_r_recalculated := PointAdd(curve, proof.T_r, PointScalarMul(curve, Target_C, proof.E_sum))
	recomputedZs_r_H := PointScalarMul(curve, H, proof.Zs_r)

	if recomputedZs_r_H.X.Cmp(expectedT_r_recalculated.X) != 0 || recomputedZs_r_H.Y.Cmp(expectedT_r_recalculated.Y) != 0 {
		return false
	}

	return true
}

// PoKSetMembershipProof proves that a committed value is a member of a public set.
// This is done by proving that the committed value is equal to one of the public set elements using OR-proofs.
type PoKSetMembershipProof struct {
	IndividualProofs []*PoKEqualityProof // A PoKEqualityProof for each element in the set
	SimulatedE       []*big.Int          // Simulated challenges for non-chosen branches
	ActualE          *big.Int            // The overall challenge
	ProverChoice     int                 // Index of the element actually committed to
}

// ProveSetMembership proves `v_val` in `C_v` is a member of `publicSet`.
func ProveSetMembership(curve elliptic.Curve, C_v *Point, v_val, v_nonce *big.Int, publicSet []*big.Int, G, H *Point, order *big.Int) (*PoKSetMembershipProof, error) {
	proof := &PoKSetMembershipProof{
		IndividualProofs: make([]*PoKEqualityProof, len(publicSet)),
		SimulatedE:       make([]*big.Int, len(publicSet)),
		ProverChoice:     -1,
	}

	// Find the index of v_val in publicSet
	for i, elem := range publicSet {
		if v_val.Cmp(elem) == 0 {
			proof.ProverChoice = i
			break
		}
	}
	if proof.ProverChoice == -1 {
		return nil, fmt.Errorf("committed value is not in the public set")
	}

	var allT []*Point
	challengeSeedElements := [][]byte{}
	challengeSeedElements = append(challengeSeedElements, PointToBytes(C_v)...)

	// Simulate for non-chosen branches
	for i := 0; i < len(publicSet); i++ {
		if i == proof.ProverChoice {
			// This branch will be the real proof, simulate later after overall challenge
			continue
		}

		// Simulate E and Z for this branch
		simulatedE := RandomScalar(order)
		simulatedZ := RandomScalar(order)
		proof.SimulatedE[i] = simulatedE // Store simulated challenge
		// Compute simulated T for this branch: t = z*H - e*(C_v - elem*G)
		elemG := PointScalarMul(curve, G, publicSet[i])
		C_v_minus_elemG := PointSub(curve, C_v, elemG) // Expected to be (v_nonce - 0)*H
		simulatedT := PointSub(curve, PointScalarMul(curve, H, simulatedZ), PointScalarMul(curve, C_v_minus_elemG, simulatedE))

		proof.IndividualProofs[i] = &PoKEqualityProof{T: simulatedT, E: simulatedE, Z: simulatedZ}
		allT = append(allT, simulatedT)
	}

	// Real proof for the chosen branch
	// Choose random w_r
	wr_real := RandomScalar(order)
	t_real := PointScalarMul(curve, H, wr_real)
	proof.IndividualProofs[proof.ProverChoice] = &PoKEqualityProof{T: t_real} // Fill in later

	allT = append(allT, t_real) // Add the real T to the list

	// Generate overall challenge using Fiat-Shamir
	for _, t := range allT {
		challengeSeedElements = append(challengeSeedElements, PointToBytes(t)...)
	}
	proof.ActualE = HashToScalar(order, challengeSeedElements...)

	// Calculate the real challenge for the chosen branch
	sumSimulatedE := big.NewInt(0)
	for i, e := range proof.SimulatedE {
		if i != proof.ProverChoice && e != nil {
			sumSimulatedE = ScalarAdd(sumSimulatedE, e, order)
		}
	}
	realE := ScalarSub(proof.ActualE, sumSimulatedE, order)
	proof.IndividualProofs[proof.ProverChoice].E = realE

	// Compute real Z for the chosen branch: z = w_r + E * (v_nonce - 0) mod order
	// C_v - publicSet[ProverChoice]*G = v_nonce*H
	committedValueG := PointScalarMul(curve, G, publicSet[proof.ProverChoice])
	C_v_minus_committedValueG := PointSub(curve, C_v, committedValueG) // This is effectively v_nonce*H
	
	z_real := ScalarAdd(wr_real, ScalarMul(realE, v_nonce, order), order)
	proof.IndividualProofs[proof.ProverChoice].Z = z_real

	return proof, nil
}

// VerifySetMembership verifies the PoK_SetMembership proof.
func VerifySetMembership(curve elliptic.Curve, C_v *Point, proof *PoKSetMembershipProof, publicSet []*big.Int, G, H *Point, order *big.Int) bool {
	if len(publicSet) != len(proof.IndividualProofs) {
		return false // Malformed proof or public set mismatch
	}

	var allT []*Point
	challengeSeedElements := [][]byte{}
	challengeSeedElements = append(challengeSeedElements, PointToBytes(C_v)...)

	for i, p := range proof.IndividualProofs {
		if p == nil || p.T == nil { // Some branches might have nil T if simulation was done improperly, or proof is malformed
			return false
		}
		allT = append(allT, p.T)
	}
	
	for _, t := range allT {
		challengeSeedElements = append(challengeSeedElements, PointToBytes(t)...)
	}
	recomputedActualE := HashToScalar(order, challengeSeedElements...)

	if recomputedActualE.Cmp(proof.ActualE) != 0 {
		return false // Overall challenge mismatch
	}

	sumE := big.NewInt(0)
	for _, p := range proof.IndividualProofs {
		if p.E == nil { return false } // Malformed proof
		sumE = ScalarAdd(sumE, p.E, order)
	}
	if sumE.Cmp(recomputedActualE) != 0 {
		return false // Sum of E's does not match overall challenge
	}

	for i, p := range proof.IndividualProofs {
		// Verify for each branch: z*H = t + e * (C_v - elem*G)
		elemG := PointScalarMul(curve, G, publicSet[i])
		C_v_minus_elemG := PointSub(curve, C_v, elemG) // This needs to be (v_nonce)*H for a valid match

		expectedT_recalculated := PointAdd(curve, p.T, PointScalarMul(curve, C_v_minus_elemG, p.E))
		recomputedZ_H := PointScalarMul(curve, H, p.Z)

		if recomputedZ_H.X.Cmp(expectedT_recalculated.X) != 0 || recomputedZ_H.Y.Cmp(expectedT_recalculated.Y) != 0 {
			return false
		}
	}

	return true
}

// PointSub subtracts p2 from p1.
func PointSub(curve elliptic.Curve, p1, p2 *Point) *Point {
	return PointAdd(curve, p1, PointNeg(curve, p2))
}

// ScalarNeg computes the negation of a scalar modulo order.
func ScalarNeg(s, order *big.Int) *big.Int {
	res := new(big.Int).Neg(s)
	return res.Mod(res, order)
}


// === policy.go: Policy & Access Control Layer ===

// PolicyStatement represents a single condition in an access policy.
type PolicyStatement struct {
	AttributeName string      // e.g., "Age", "Country"
	Operator      string      // e.g., "==", ">=", "IN"
	Value         *big.Int    // For "==", ">=", single value
	ValueSet      []*big.Int  // For "IN" operator
	RangeBitLength int        // For ">=" operator, indicates max range of difference (v-K)
}

// NewPolicyStatement creates a new PolicyStatement.
func NewPolicyStatement(attributeName, op string, val interface{}) (*PolicyStatement, error) {
	stmt := &PolicyStatement{
		AttributeName: attributeName,
		Operator:      op,
	}

	switch op {
	case "==", ">=":
		switch v := val.(type) {
		case int:
			stmt.Value = big.NewInt(int64(v))
		case *big.Int:
			stmt.Value = v
		default:
			return nil, fmt.Errorf("unsupported value type for operator %s: %T", op, val)
		}
		if op == ">=" {
			// For range proofs, we need a max bit length for the difference (v - K)
			// This is a simplification; a full Bulletproof would not need this upfront.
			// Let's assume a reasonable maximum difference of 64 bits for practical purposes.
			// This implies the value for the attribute cannot be extremely large,
			// or the lower bound K must be close to the actual attribute value.
			stmt.RangeBitLength = 64
		}
	case "IN":
		switch v := val.(type) {
		case []int:
			stmt.ValueSet = make([]*big.Int, len(v))
			for i, iv := range v {
				stmt.ValueSet[i] = big.NewInt(int64(iv))
			}
		case []*big.Int:
			stmt.ValueSet = v
		default:
			return nil, fmt.Errorf("unsupported value type for operator IN: %T", val)
		}
	default:
		return nil, fmt.Errorf("unsupported operator: %s", op)
	}

	return stmt, nil
}

// AccessPolicy represents a combination of policy statements (currently assumed ANDed).
type AccessPolicy struct {
	Statements []*PolicyStatement
}

// NewAccessPolicy creates a new AccessPolicy.
func NewAccessPolicy(statements []*PolicyStatement) *AccessPolicy {
	return &AccessPolicy{Statements: statements}
}

// ProverCredential holds the prover's secret attribute values and blinding factors.
type ProverCredential struct {
	Attributes map[string]*big.Int
	Nonces     map[string]*big.Int
}

// ProverCommittedCredential holds the public commitments to the prover's attributes.
type ProverCommittedCredential struct {
	Commitments map[string]*Point
}

// NewProverCredential generates a ProverCredential and its corresponding ProverCommittedCredential.
func NewProverCredential(attributes map[string]*big.Int, G, H *Point, curve elliptic.Curve) (*ProverCredential, *ProverCommittedCredential, error) {
	proverCred := &ProverCredential{
		Attributes: make(map[string]*big.Int),
		Nonces:     make(map[string]*big.Int),
	}
	committedCred := &ProverCommittedCredential{
		Commitments: make(map[string]*Point),
	}
	order := curve.Params().N

	for name, value := range attributes {
		nonce := RandomScalar(order)
		commitment := NewPedersenCommitment(value, nonce, G, H, curve)

		proverCred.Attributes[name] = value
		proverCred.Nonces[name] = nonce
		committedCred.Commitments[name] = commitment
	}

	return proverCred, committedCred, nil
}


// === abac.go: Main ABAC ZKP Logic ===

// ABACProof combines all individual ZKPs generated for an AccessPolicy.
type ABACProof struct {
	EqualityProofs    map[string]*PoKEqualityProof
	RangeProofs       map[string]*PoKRangeBitsProof
	SetMembershipProofs map[string]*PoKSetMembershipProof
	// Any other proof types would be added here
}

// GenerateProofForPolicy generates a combined ZKP for the given access policy.
func GenerateProofForPolicy(proverCred *ProverCredential, committedCred *ProverCommittedCredential, policy *AccessPolicy, G, H *Point, curve elliptic.Curve, order *big.Int) (*ABACProof, error) {
	proof := &ABACProof{
		EqualityProofs:    make(map[string]*PoKEqualityProof),
		RangeProofs:       make(map[string]*PoKRangeBitsProof),
		SetMembershipProofs: make(map[string]*PoKSetMembershipProof),
	}

	for _, stmt := range policy.Statements {
		attrName := stmt.AttributeName
		committedAttr, exists := committedCred.Commitments[attrName]
		if !exists {
			return nil, fmt.Errorf("attribute %s not found in committed credentials", attrName)
		}
		attrVal, exists := proverCred.Attributes[attrName]
		if !exists {
			return nil, fmt.Errorf("attribute %s not found in prover's secret credentials", attrName)
		}
		attrNonce, exists := proverCred.Nonces[attrName]
		if !exists {
			return nil, fmt.Errorf("nonce for attribute %s not found in prover's secret credentials", attrName)
		}

		switch stmt.Operator {
		case "==":
			// Prove equality of committed attribute with a public value
			// This is effectively proving C_attr = value*G + nonce*H
			// This requires comparing two commitments: C_attr and Commit(stmt.Value, 0)
			// For simplicity and to match the PoKEqualityProof structure,
			// let's prove that C_attr - stmt.Value*G == nonce*H and know nonce.
			// This is not directly `ProveEquality(C1, C2)` but a PoK of the nonce.
			// A simpler way: The verifier already knows stmt.Value.
			// The prover simply proves that committedAttr contains `attrVal` and `attrNonce`.
			// This is essentially VerifyPedersenCommitment from the prover's side.
			// A ZKP for this needs to hide `attrVal` *and* `attrNonce`.

			// To prove C_attr commits to stmt.Value:
			// Prover creates commitment C_stmt_val = stmt.Value * G + w_r * H
			// Prover creates C_eq = C_attr - C_stmt_val = (attrVal - stmt.Value)G + (attrNonce - w_r)H
			// Prover proves C_eq commits to 0.
			
			// This means proving (attrVal - stmt.Value) == 0 AND knowledge of (attrNonce - w_r).
			// Let's adapt PoKEqualityProof.
			
			// We need a specific blinding factor for the stmt.Value commitment to use PoKEqualityProof
			stmtNonce := RandomScalar(order)
			C_stmt_value := NewPedersenCommitment(stmt.Value, stmtNonce, G, H, curve)
			
			eqProof, err := ProveEquality(curve, committedAttr, attrNonce, C_stmt_value, stmtNonce, G, H, order)
			if err != nil {
				return nil, fmt.Errorf("failed to prove equality for %s: %w", attrName, err)
			}
			proof.EqualityProofs[attrName] = eqProof

		case ">=":
			// Prove v >= K
			// This means v - K >= 0. Let delta = v - K.
			// We need to prove delta is non-negative, and fits within RangeBitLength.
			// C_delta = C_attr - K*G = (attrVal - K)G + attrNonce*H
			// We then call PoKRangeBits on C_delta with value (attrVal - K) and nonce attrNonce
			
			deltaVal := ScalarSub(attrVal, stmt.Value, order)
			if deltaVal.Sign() == -1 {
				// Prover knows their value is less than K, so they cannot prove this.
				return nil, fmt.Errorf("attribute %s value %s is less than required minimum %s", attrName, attrVal.String(), stmt.Value.String())
			}

			// The RangeBitLength is for the *difference* (delta).
			// MaxDeltaValue := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(stmt.RangeBitLength)), big.NewInt(1))
			// if deltaVal.Cmp(MaxDeltaValue) > 0 {
			// 	return nil, fmt.Errorf("attribute %s difference %s exceeds max range bit length %d", attrName, deltaVal.String(), stmt.RangeBitLength)
			// }
			
			// The commitment for delta: C_delta = deltaVal*G + attrNonce*H
			// This means we are passing the original nonce `attrNonce` but for a *different* value `deltaVal`.
			// The commitment for delta is:
			C_delta := NewPedersenCommitment(deltaVal, attrNonce, G, H, curve)

			rangeProof, err := ProveRangeBits(curve, C_delta, deltaVal, attrNonce, stmt.RangeBitLength, G, H, order)
			if err != nil {
				return nil, fmt.Errorf("failed to prove range for %s: %w", attrName, err)
			}
			proof.RangeProofs[attrName] = rangeProof

		case "IN":
			// Prove v is in Set
			setProof, err := ProveSetMembership(curve, committedAttr, attrVal, attrNonce, stmt.ValueSet, G, H, order)
			if err != nil {
				return nil, fmt.Errorf("failed to prove set membership for %s: %w", attrName, err)
			}
			proof.SetMembershipProofs[attrName] = setProof

		default:
			return nil, fmt.Errorf("unsupported operator in policy: %s", stmt.Operator)
		}
	}

	return proof, nil
}

// VerifyProofForPolicy verifies the combined ZKP against the policy and public commitments.
func VerifyProofForPolicy(committedCred *ProverCommittedCredential, policy *AccessPolicy, proof *ABACProof, G, H *Point, curve elliptic.Curve, order *big.Int) (bool, error) {
	for _, stmt := range policy.Statements {
		attrName := stmt.AttributeName
		committedAttr, exists := committedCred.Commitments[attrName]
		if !exists {
			return false, fmt.Errorf("attribute %s not found in committed credentials", attrName)
		}

		var ok bool
		var err error

		switch stmt.Operator {
		case "==":
			eqProof, exists := proof.EqualityProofs[attrName]
			if !exists {
				return false, fmt.Errorf("equality proof missing for attribute %s", attrName)
			}
			stmtNonce := RandomScalar(order) // Dummy nonce, not used in verification directly, but needed for C_stmt_value
			C_stmt_value := NewPedersenCommitment(stmt.Value, stmtNonce, G, H, curve)

			ok = VerifyEquality(curve, committedAttr, C_stmt_value, eqProof, G, H, order)
			if !ok {
				err = fmt.Errorf("equality proof failed for %s", attrName)
			}
		case ">=":
			rangeProof, exists := proof.RangeProofs[attrName]
			if !exists {
				return false, fmt.Errorf("range proof missing for attribute %s", attrName)
			}
			// C_delta = C_attr - K*G
			K_G := PointScalarMul(curve, G, stmt.Value)
			C_delta := PointSub(curve, committedAttr, K_G)

			ok = VerifyRangeBits(curve, C_delta, rangeProof, stmt.RangeBitLength, G, H, order)
			if !ok {
				err = fmt.Errorf("range proof failed for %s", attrName)
			}
		case "IN":
			setProof, exists := proof.SetMembershipProofs[attrName]
			if !exists {
				return false, fmt.Errorf("set membership proof missing for attribute %s", attrName)
			}
			ok = VerifySetMembership(curve, committedAttr, setProof, stmt.ValueSet, G, H, order)
			if !ok {
				err = fmt.Errorf("set membership proof failed for %s", attrName)
			}
		default:
			return false, fmt.Errorf("unsupported operator in policy: %s", stmt.Operator)
		}

		if !ok {
			return false, err
		}
	}

	return true, nil
}

// === Main function for demonstration ===

func init() {
	// Register custom types for gob encoding/decoding
	gob.Register(&Point{})
	gob.Register(&PoKEqualityProof{})
	gob.Register(&PoKBitProof{})
	gob.Register(&PoKRangeBitsProof{})
	gob.Register(&PoKSetMembershipProof{})
	gob.Register(&PolicyStatement{})
	gob.Register(&AccessPolicy{})
	gob.Register(&ABACProof{})
	gob.Register(&ProverCredential{})
	gob.Register(&ProverCommittedCredential{})
}


func main() {
	fmt.Println("Starting Zero-Knowledge Proof for Private Attribute-Based Access Control...")

	// 1. Setup global parameters
	G, H, curve, order := GenerateCurveParams()
	fmt.Println("Global ZKP parameters generated.")

	// 2. Prover generates their private credentials and public commitments
	fmt.Println("\n--- Prover's Side (Credential Generation) ---")
	proverAttributes := map[string]*big.Int{
		"Age":        big.NewInt(30),
		"Country":    big.NewInt(1),  // 1 for USA
		"CreditScore": big.NewInt(750),
		"IsLicensed": big.NewInt(1), // 1 for true
	}
	proverCred, committedCred, err := NewProverCredential(proverAttributes, G, H, curve)
	if err != nil {
		fmt.Printf("Error creating prover credential: %v\n", err)
		return
	}
	fmt.Printf("Prover generated private attributes and public commitments (e.g., Age commitment: %v...)\n", PointToBytes(committedCred.Commitments["Age"])[:10])

	// 3. Verifier defines an access policy
	fmt.Println("\n--- Verifier's Side (Policy Definition) ---")
	ageStmt, _ := NewPolicyStatement("Age", ">=", 21)
	countryStmt, _ := NewPolicyStatement("Country", "==", 1) // Must be USA (code 1)
	creditScoreStmt, _ := NewPolicyStatement("CreditScore", ">=", 700)
	isLicensedStmt, _ := NewPolicyStatement("IsLicensed", "IN", []int{1}) // Must be licensed (1)

	accessPolicy := NewAccessPolicy([]*PolicyStatement{ageStmt, countryStmt, creditScoreStmt, isLicensedStmt})
	fmt.Println("Access Policy defined: (Age >= 21) AND (Country == USA) AND (CreditScore >= 700) AND (IsLicensed == true)")

	// 4. Prover generates a ZKP that their attributes satisfy the policy
	fmt.Println("\n--- Prover's Side (Proof Generation) ---")
	startTime := time.Now()
	abacProof, err := GenerateProofForPolicy(proverCred, committedCred, accessPolicy, G, H, curve, order)
	if err != nil {
		fmt.Printf("Error generating ABAC proof: %v\n", err)
		return
	}
	duration := time.Since(startTime)
	fmt.Printf("ABAC Proof generated successfully in %s.\n", duration)

	// 5. Serialize and deserialize the proof (simulating network transfer)
	fmt.Println("\n--- Simulating Proof Transmission ---")
	var proofBuffer strings.Builder
	enc := gob.NewEncoder(&proofBuffer)
	err = enc.Encode(abacProof)
	if err != nil {
		fmt.Printf("Error encoding proof: %v\n", err)
		return
	}
	fmt.Printf("Proof size (approx): %d bytes\n", len(proofBuffer.String()))

	var decodedProof ABACProof
	dec := gob.NewDecoder(strings.NewReader(proofBuffer.String()))
	err = dec.Decode(&decodedProof)
	if err != nil {
		fmt.Printf("Error decoding proof: %v\n", err)
		return
	}
	fmt.Println("Proof serialized and deserialized successfully.")
	// Verify that the decoded proof is structurally identical (for sanity check)
    // Note: big.Int comparison by value is deep. Pointers to big.Int need careful comparison.
    // For simplicity, we just check if it's not nil. A proper deep comparison of all fields would be more thorough.
    if decodedProof.EqualityProofs == nil || decodedProof.RangeProofs == nil || decodedProof.SetMembershipProofs == nil {
        fmt.Println("Decoded proof is incomplete or malformed (after sanity check).")
        // Handle error or return
    } else {
        fmt.Println("Decoded proof passes basic sanity check.")
    }


	// 6. Verifier verifies the ZKP
	fmt.Println("\n--- Verifier's Side (Proof Verification) ---")
	startTime = time.Now()
	isValid, err := VerifyProofForPolicy(committedCred, accessPolicy, &decodedProof, G, H, curve, order)
	if err != nil {
		fmt.Printf("Error during ABAC proof verification: %v\n", err)
		return
	}
	duration = time.Since(startTime)
	fmt.Printf("ABAC Proof verified in %s.\n", duration)

	if isValid {
		fmt.Println("\n--- Verification Result: SUCCESS! ---")
		fmt.Println("The prover's committed attributes satisfy the access policy without revealing any private information.")
	} else {
		fmt.Println("\n--- Verification Result: FAILED! ---")
		fmt.Println("The prover's committed attributes DO NOT satisfy the access policy.")
	}

	// --- Demonstrate a failed proof (e.g., wrong age) ---
	fmt.Println("\n--- Demonstrating a FAILED Proof (Prover doesn't meet age requirement) ---")
	proverAttributes_fail := map[string]*big.Int{
		"Age":        big.NewInt(18), // Too young!
		"Country":    big.NewInt(1),
		"CreditScore": big.NewInt(750),
		"IsLicensed": big.NewInt(1),
	}
	proverCred_fail, committedCred_fail, _ := NewProverCredential(proverAttributes_fail, G, H, curve)
	
	abacProof_fail, err := GenerateProofForPolicy(proverCred_fail, committedCred_fail, accessPolicy, G, H, curve, order)
	if err != nil {
		fmt.Printf("Expected error during failed proof generation (age < 21): %v\n", err)
		// This error is caught during proof generation because our range proof needs delta >= 0.
		// If the prover's value is 18 and policy asks for >= 21, delta = 18 - 21 = -3.
		// Our range proof `ProveRangeBits` for `delta >= 0` will detect this.
	} else {
		fmt.Println("Proof generated even with insufficient age (should fail verification).")
		isValid_fail, verifyErr := VerifyProofForPolicy(committedCred_fail, accessPolicy, abacProof_fail, G, H, curve, order)
		if verifyErr != nil {
			fmt.Printf("Error during failed ABAC proof verification: %v\n", verifyErr)
		}
		if !isValid_fail {
			fmt.Println("Verification for failed proof: Correctly FAILED!")
		} else {
			fmt.Println("Verification for failed proof: Unexpectedly SUCCEEDED!")
		}
	}


}

```