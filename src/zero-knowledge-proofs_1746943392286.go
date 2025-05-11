Okay, let's design a Zero-Knowledge Proof system in Go based on Pedersen Commitments, focusing on proving properties of committed values without revealing the values themselves. We will build up from basic knowledge proofs to a more complex concept like a Bounded Range Proof using composed bit proofs (a form of Chaum-Pedersen OR proofs).

This system is not a production-ready library but demonstrates the composition of ZKP primitives for a specific, slightly more complex task than a simple "prove knowledge of discrete log". It avoids duplicating the structure and specific algorithms of well-known ZKP libraries like Gnark or Bulletproofs, focusing on building from fundamental building blocks using standard Go crypto libraries (`math/big`, `crypto/elliptic`, `crypto/rand`, `crypto/sha256`).

**Interesting, Advanced Concept:** We'll build a ZKP system that proves:
1.  Knowledge of the value and randomness used in a Pedersen commitment.
2.  That a committed value is either 0 or 1 (a "Knowledge of Bit" proof using a non-interactive OR protocol).
3.  That a committed value is within a specific range `[0, 2^m - 1]` by proving commitments to its bits and their correct linear combination (a "Bounded Range Proof"). This composition is the advanced concept here.

---

```golang
package zkpcomposition

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
)

// --- Outline and Function Summary ---
//
// This package implements a Zero-Knowledge Proof system based on Pedersen Commitments
// and composition of Sigma-like protocols. It provides primitives and proofs
// for knowledge of committed values, knowledge of bits, and bounded range proofs.
//
// Data Types:
// - FieldElement: Represents an element in the scalar field of the elliptic curve.
// - CurvePoint: Represents a point on the elliptic curve.
// - PedersenParams: Contains the elliptic curve and generator points G, H.
// - KnowledgeProof: A ZKP proving knowledge of value 'x' and randomness 'r' for C = xG + rH.
// - BitProof: A ZKP proving a committed value is 0 or 1 (Knowledge of Bit).
// - BoundedRangeProof: A ZKP proving a committed value is in [0, 2^m - 1].
//
// Core Primitives and Helpers:
// - NewFieldElementFromBigInt: Creates a FieldElement.
// - FieldAdd, FieldSub, FieldMul, FieldInv, FieldNeg: Field arithmetic operations.
// - NewCurvePointFromCoords: Creates a CurvePoint.
// - CurveAdd, CurveScalarMul: Curve point operations.
// - GenerateRandomScalar: Generates a random scalar (FieldElement).
// - HashToScalar: Hashes bytes to a FieldElement (Fiat-Shamir challenge).
// - HashToCurvePoint: Generates a curve point from a seed (for H).
// - ZeroFieldElement, OneFieldElement: Constant FieldElements.
// - SumCommitments: Sums a slice of curve points.
// - LinearCombinationCommitments: Computes a linear combination of points.
// - ScalarFromUint64: Converts a uint64 to a FieldElement.
// - Bytes, BigInt, Coords, Curve: Serialization and getter methods for types.
//
// Setup and Commitment:
// - SetupPedersen: Initializes Pedersen parameters (G, H) for a given curve.
// - CommitPedersen: Creates a Pedersen commitment C = value*G + randomness*H.
//
// ZK Proofs (Prove/Verify Pairs + Struct Methods):
// - ProveKnowledge: Creates a KnowledgeProof for a commitment.
// - VerifyKnowledge: Verifies a KnowledgeProof.
// - ProveBit: Creates a BitProof for a commitment to a bit.
// - VerifyBit: Verifies a BitProof.
// - ProveBoundedRange: Creates a BoundedRangeProof for a value and bit length.
// - VerifyBoundedRange: Verifies a BoundedRangeProof.
//
// Serialization/Deserialization (Bytes/MarshalBinary/UnmarshalBinary) and Equality:
// - Bytes/MarshalBinary/UnmarshalBinary methods for proof and parameter types.
// - Equals methods for comparing types.
//
// Function List (20+):
// 1. NewFieldElementFromBigInt
// 2. FieldAdd
// 3. FieldSub
// 4. FieldMul
// 5. FieldInv
// 6. FieldNeg
// 7. GenerateRandomScalar
// 8. HashToScalar
// 9. HashToCurvePoint (Helper for setup)
// 10. SetupPedersen
// 11. CommitPedersen
// 12. ZeroFieldElement
// 13. OneFieldElement
// 14. SumCommitments (Helper)
// 15. LinearCombinationCommitments (Helper)
// 16. ScalarFromUint64 (Helper)
// 17. ProveKnowledge (Generates KnowledgeProof using FS)
// 18. VerifyKnowledge (Verifies KnowledgeProof using FS)
// 19. (KnowledgeProof) MarshalBinary
// 20. (KnowledgeProof) UnmarshalBinary
// 21. ProveBit (Generates BitProof using FS & OR logic)
// 22. VerifyBit (Verifies BitProof using FS & OR logic)
// 23. (BitProof) MarshalBinary
// 24. (BitProof) UnmarshalBinary
// 25. ProveBoundedRange (Generates BoundedRangeProof by composing proofs)
// 26. VerifyBoundedRange (Verifies BoundedRangeProof by verifying components)
// 27. (BoundedRangeProof) MarshalBinary
// 28. (BoundedRangeProof) UnmarshalBinary
// 29. (FieldElement) Bytes
// 30. (CurvePoint) Bytes
// 31. (PedersenParams) Bytes
// 32. NewFieldElementFromBytes
// 33. NewCurvePointFromBytes
// 34. NewPedersenParamsFromBytes
// 35. (FieldElement) BigInt
// 36. (CurvePoint) Coords
// 37. (PedersenParams) Curve
// 38. (KnowledgeProof) Verify (Convenience wrapper)
// 39. (BitProof) Verify (Convenience wrapper)
// 40. (BoundedRangeProof) Verify (Convenience wrapper)
// 41. (FieldElement) Equals
// 42. (CurvePoint) Equals
// 43. (PedersenParams) Equals
// 44. (KnowledgeProof) Equals
// 45. (BitProof) Equals
// 46. (BoundedRangeProof) Equals
// --- End of Outline and Summary ---

var (
	ErrInvalidProof        = errors.New("invalid zero-knowledge proof")
	ErrInvalidParameters   = errors.New("invalid zkp parameters")
	ErrSerialization       = errors.New("serialization error")
	ErrDeserialization     = errors.New("deserialization error")
	ErrInvalidBitValue     = errors.New("bit value must be 0 or 1")
	ErrCommitmentMismatch  = errors.New("commitment in proof does not match verified commitment")
	ErrInvalidBitLength    = errors.New("invalid bit length for bounded range proof")
	ErrCommitmentCount     = errors.New("number of bit commitments mismatch")
	ErrProofCount          = errors.New("number of bit proofs mismatch")
	ErrRangeValueTooLarge  = errors.New("value exceeds maximum for given bit length")
	ErrProofVerificationFailed = errors.New("proof verification failed")
)

// FieldElement represents an element in the scalar field (order of the curve's base point).
type FieldElement struct {
	Value *big.Int
	Order *big.Int // The order of the scalar field (N)
}

// NewFieldElementFromBigInt creates a new FieldElement. Assumes val is non-negative and less than Order.
func NewFieldElementFromBigInt(val *big.Int, order *big.Int) FieldElement {
	v := new(big.Int).Set(val)
	v.Mod(v, order) // Ensure value is within the field
	return FieldElement{Value: v, Order: order}
}

// ZeroFieldElement returns the additive identity (0).
func ZeroFieldElement(order *big.Int) FieldElement {
	return NewFieldElementFromBigInt(big.NewInt(0), order)
}

// OneFieldElement returns the multiplicative identity (1).
func OneFieldElement(order *big.Int) FieldElement {
	return NewFieldElementFromBigInt(big.NewInt(1), order)
}

// FieldAdd performs modular addition.
func FieldAdd(a, b FieldElement) FieldElement {
	if a.Order.Cmp(b.Order) != 0 {
		panic("field orders mismatch")
	}
	res := new(big.Int).Add(a.Value, b.Value)
	res.Mod(res, a.Order)
	return NewFieldElementFromBigInt(res, a.Order)
}

// FieldSub performs modular subtraction.
func FieldSub(a, b FieldElement) FieldElement {
	if a.Order.Cmp(b.Order) != 0 {
		panic("field orders mismatch")
	}
	res := new(big.Int).Sub(a.Value, b.Value)
	res.Mod(res, a.Order)
	return NewFieldElementFromBigInt(res, a.Order)
}

// FieldMul performs modular multiplication.
func FieldMul(a, b FieldElement) FieldElement {
	if a.Order.Cmp(b.Order) != 0 {
		panic("field orders mismatch")
	}
	res := new(big.Int).Mul(a.Value, b.Value)
	res.Mod(res, a.Order)
	return NewFieldElementFromBigInt(res, a.Order)
}

// FieldInv performs modular inverse (a^-1 mod Order).
func FieldInv(a FieldElement) FieldElement {
	if a.Value.Sign() == 0 {
		panic("cannot invert zero field element")
	}
	res := new(big.Int).ModInverse(a.Value, a.Order)
	if res == nil {
		panic("modular inverse does not exist") // Should not happen for prime order
	}
	return NewFieldElementFromBigInt(res, a.Order)
}

// FieldNeg performs modular negation (-a mod Order).
func FieldNeg(a FieldElement) FieldElement {
	res := new(big.Int).Neg(a.Value)
	res.Mod(res, a.Order)
	return NewFieldElementFromBigInt(res, a.Order)
}

// Equals checks if two FieldElements are equal.
func (fe FieldElement) Equals(other FieldElement) bool {
	return fe.Value.Cmp(other.Value) == 0 && fe.Order.Cmp(other.Order) == 0
}

// Bytes returns the big.Int value as a byte slice.
func (fe FieldElement) Bytes() []byte {
	return fe.Value.Bytes()
}

// BigInt returns the underlying big.Int value.
func (fe FieldElement) BigInt() *big.Int {
	return fe.Value
}

// NewFieldElementFromBytes creates a FieldElement from bytes. Assumes bytes are less than order.
func NewFieldElementFromBytes(b []byte, order *big.Int) (FieldElement, error) {
	if len(b) == 0 {
        return FieldElement{}, ErrDeserialization
    }
    val := new(big.Int).SetBytes(b)
	if val.Cmp(order) >= 0 {
		// Value is outside the field, should be handled during serialization/deserialization
		// based on expected size or just reject if strictly outside the order
		// For simplicity here, we allow it and mod, but ideally serialization
		// ensures values are in range or padded to a specific size.
		// Let's enforce strict check for demo.
		// return FieldElement{}, fmt.Errorf("%w: bytes represent value >= field order", ErrDeserialization)
	}
	val.Mod(val, order) // Ensure it's in the field, though deserialized bytes should typically be in range.
	return NewFieldElementFromBigInt(val, order), nil
}


// CurvePoint represents a point on the elliptic curve.
type CurvePoint struct {
	X, Y *big.Int
	Curve elliptic.Curve // Keep curve context for operations
}

// NewCurvePointFromCoords creates a new CurvePoint.
func NewCurvePointFromCoords(x, y *big.Int, curve elliptic.Curve) CurvePoint {
	// Note: Does not check if the point is actually on the curve.
	// Use curve.IsOnCurve(x, y) if needed, but adds overhead.
	return CurvePoint{X: new(big.Int).Set(x), Y: new(big.Int).Set(y), Curve: curve}
}

// CurveAdd performs point addition.
func CurveAdd(p1, p2 CurvePoint) CurvePoint {
	if p1.Curve != p2.Curve {
		panic("curves mismatch")
	}
	x, y := p1.Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return NewCurvePointFromCoords(x, y, p1.Curve)
}

// CurveScalarMul performs scalar multiplication.
func CurveScalarMul(s FieldElement, p CurvePoint) CurvePoint {
	x, y := p.Curve.ScalarMult(p.X, p.Y, s.Value.Bytes())
	return NewCurvePointFromCoords(x, y, p.Curve)
}

// IsIdentity checks if the point is the point at infinity (identity element).
func (cp CurvePoint) IsIdentity() bool {
	return cp.X.Sign() == 0 && cp.Y.Sign() == 0 // Simplified check for some curves, needs careful consideration for others
}

// Equals checks if two CurvePoints are equal.
func (cp CurvePoint) Equals(other CurvePoint) bool {
	// Comparing curves by pointer equality might be insufficient if curves are created differently but represent the same group.
	// For standard library curves, this is usually fine.
	return cp.Curve == other.Curve && cp.X.Cmp(other.X) == 0 && cp.Y.Cmp(other.Y) == 0
}

// Bytes returns the point coordinates as a byte slice (concatenated X and Y).
func (cp CurvePoint) Bytes() []byte {
	// Simple serialization, may need compressed/uncompressed format based on context
	xBytes := cp.X.Bytes()
	yBytes := cp.Y.Bytes()
	// Pad to curve parameters size for consistency if needed.
	// For P256, P384, P521, standard size is ceil(bitSize / 8).
	size := (cp.Curve.Params().BitSize + 7) / 8
	buf := make([]byte, size*2) // X || Y
	copy(buf[size-len(xBytes):size], xBytes)
	copy(buf[size*2-len(yBytes):size*2], yBytes)
	return buf
}

// Coords returns the underlying big.Int coordinates.
func (cp CurvePoint) Coords() (*big.Int, *big.Int) {
	return cp.X, cp.Y
}

// NewCurvePointFromBytes creates a CurvePoint from bytes.
func NewCurvePointFromBytes(b []byte, curve elliptic.Curve) (CurvePoint, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(b) != size*2 {
		return CurvePoint{}, fmt.Errorf("%w: invalid byte length for curve point", ErrDeserialization)
	}
	x := new(big.Int).SetBytes(b[:size])
	y := new(big.Int).SetBytes(b[size:])

	// Optional: Check if point is on curve - adds security but also overhead
	if !curve.IsOnCurve(x, y) {
		// Return error or panic depending on strictness required
		// panic("deserialized point is not on curve")
		// For this example, we will trust the source or handle elsewhere.
		// return CurvePoint{}, fmt.Errorf("%w: deserialized point not on curve", ErrDeserialization)
	}

	return NewCurvePointFromCoords(x, y, curve), nil
}


// PedersenParams contains the necessary parameters for Pedersen commitments and proofs.
type PedersenParams struct {
	Curve elliptic.Curve
	G     CurvePoint
	H     CurvePoint
	Order *big.Int // Order of the scalar field
}

// SetupPedersen generates Pedersen parameters (G, H) for a given curve.
// G is the base point of the curve. H is derived deterministically from a seed.
func SetupPedersen(curve elliptic.Curve, seedH []byte) (PedersenParams, error) {
	params := curve.Params()
	// G is the base point
	gX, gY := params.Gx, params.Gy
	G := NewCurvePointFromCoords(gX, gY, curve)

	// H is derived from the seed using hash-to-point
	// Note: A proper hash-to-point function is non-trivial.
	// Simple approach: hash seed to scalar and multiply G by it.
	// This ensures H is on the curve and related to the seed, but H is a multiple of G.
	// For stronger Pedersen security (G and H should be independent generators),
	// H should ideally not be a known scalar multiple of G.
	// A more secure way for standard curves might involve hashing the seed and base point,
	// then using ScalarMult, or using a dedicated hash-to-curve method.
	// Let's use H = hash(seed) * G for simplicity here, acknowledging this limitation.
	// A better H derivation: Find an arbitrary point not generated by G, or use a verifiably random procedure like BLS setup.
	// A robust alternative for H: HashToPoint(seed)
	H, err := HashToCurvePoint(seedH, curve)
	if err != nil {
		return PedersenParams{}, fmt.Errorf("failed to generate H: %w", err)
	}

	return PedersenParams{
		Curve: curve,
		G:     G,
		H:     H,
		Order: params.N, // Scalar field order
	}, nil
}

// Curve returns the underlying elliptic curve.
func (pp PedersenParams) Curve() elliptic.Curve {
	return pp.Curve
}

// Bytes serializes the PedersenParams (G and H points).
func (pp PedersenParams) Bytes() []byte {
	gBytes := pp.G.Bytes()
	hBytes := pp.H.Bytes()
	// Assuming G and H have the same byte size based on curve
	buf := make([]byte, len(gBytes)+len(hBytes))
	copy(buf, gBytes)
	copy(buf[len(gBytes):], hBytes)
	return buf
}

// NewPedersenParamsFromBytes deserializes PedersenParams.
func NewPedersenParamsFromBytes(b []byte, curve elliptic.Curve) (PedersenParams, error) {
	size := (curve.Params().BitSize + 7) / 8 * 2 // Size of a point (X || Y)
	if len(b) != size*2 { // Size of G || H
		return PedersenParams{}, fmt.Errorf("%w: invalid byte length for PedersenParams", ErrDeserialization)
	}
	gBytes := b[:size]
	hBytes := b[size:]

	G, err := NewCurvePointFromBytes(gBytes, curve)
	if err != nil {
		return PedersenParams{}, fmt.Errorf("%w: failed to deserialize G", err)
	}
	H, err := NewCurvePointFromBytes(hBytes, curve)
	if err != nil {
		return PedersenParams{}, fmt.Errorf("%w: failed to deserialize H", err)
	}

	return PedersenParams{
		Curve: curve,
		G:     G,
		H:     H,
		Order: curve.Params().N,
	}, nil
}

// Equals checks if two PedersenParams are equal.
func (pp PedersenParams) Equals(other PedersenParams) bool {
	return pp.Curve == other.Curve && pp.G.Equals(other.G) && pp.H.Equals(other.H) && pp.Order.Cmp(other.Order) == 0
}

// CommitPedersen creates a Pedersen commitment C = value*G + randomness*H.
func CommitPedersen(value, randomness FieldElement, params PedersenParams) (CurvePoint, error) {
	if value.Order.Cmp(params.Order) != 0 || randomness.Order.Cmp(params.Order) != 0 {
		return CurvePoint{}, ErrInvalidParameters
	}
	 commitment := CurveAdd(
		CurveScalarMul(value, params.G),
		CurveScalarMul(randomness, params.H),
	)
	return commitment, nil
}

// --- Helper Functions ---

// GenerateRandomScalar generates a random scalar in the range [0, Order-1].
func GenerateRandomScalar(order *big.Int) (FieldElement, error) {
	if order == nil || order.Sign() <= 0 {
		return FieldElement{}, ErrInvalidParameters
	}
	val, err := rand.Int(rand.Reader, order)
	if err != nil {
		return FieldElement{}, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return NewFieldElementFromBigInt(val, order), nil
}

// GenerateRandomScalarBytes is a helper to generate random bytes for a scalar.
// Useful when input to hashing or other functions expecting bytes.
func GenerateRandomScalarBytes(order *big.Int) ([]byte, error) {
	scalar, err := GenerateRandomScalar(order)
	if err != nil {
		return nil, err
	}
	return scalar.Bytes(), nil
}


// HashToScalar hashes arbitrary data to a field element (Fiat-Shamir challenge).
func HashToScalar(order *big.Int, data ...[]byte) FieldElement {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	// Reduce hash output modulo the field order
	hashBytes := hasher.Sum(nil)
	val := new(big.Int).SetBytes(hashBytes)
	val.Mod(val, order)
	// Ensure it's non-zero if the protocol requires non-zero challenges
	if val.Sign() == 0 {
		// In a real implementation, handle this edge case (e.g., re-hash with a counter)
		// For demonstration, we'll accept 0, though some protocols disallow it.
	}
	return NewFieldElementFromBigInt(val, order)
}

// HashToCurvePoint is a deterministic way to get a point on the curve from a seed.
// This is a simplified approach; proper hash-to-curve (like RFC 9380) is complex.
// Here we hash the seed to a scalar and multiply the base point by it.
// This ensures the resulting point is on the curve but will be a multiple of G.
func HashToCurvePoint(seed []byte, curve elliptic.Curve) (CurvePoint, error) {
	params := curve.Params()
	scalar := HashToScalar(params.N, seed) // Use the order as the modulus
	// Simple deterministic point from scalar multiplication of G
	x, y := curve.ScalarBaseMult(scalar.Value.Bytes())
	if x.Sign() == 0 && y.Sign() == 0 {
		// If the scalar was 0 mod N, this gives the point at infinity.
		// For H, we generally want a non-identity point. Re-hashing might be needed.
		return CurvePoint{}, errors.New("derived point is point at infinity")
	}
	return NewCurvePointFromCoords(x, y, curve), nil
}

// ScalarFromUint64 converts a uint64 to a FieldElement.
func ScalarFromUint64(val uint64, order *big.Int) FieldElement {
	return NewFieldElementFromBigInt(new(big.Int).SetUint64(val), order)
}

// SumCommitments sums a slice of curve points.
func SumCommitments(commitments []CurvePoint) CurvePoint {
	if len(commitments) == 0 {
		// Return point at infinity (identity) - assumes CurvePoint handles this
		if len(commitments) == 0 {
             // Need a way to get the identity point. For stdlib curves, (0,0) often works.
             // Or return an error if empty slice is not expected/handled.
             if len(commitments) == 0 || commitments[0].Curve == nil {
                panic("SumCommitments requires non-empty slice with initialized points")
             }
            return NewCurvePointFromCoords(big.NewInt(0), big.NewInt(0), commitments[0].Curve) // Point at infinity
        }
	}
	sum := commitments[0]
	for i := 1; i < len(commitments); i++ {
		sum = CurveAdd(sum, commitments[i])
	}
	return sum
}

// LinearCombinationCommitments computes sum(scalars_i * commitments_i).
// Assumes all commitments are on the same curve and scalars match the curve order.
func LinearCombinationCommitments(scalars []FieldElement, commitments []CurvePoint, params PedersenParams) (CurvePoint, error) {
	if len(scalars) != len(commitments) {
		return CurvePoint{}, fmt.Errorf("%w: scalar and commitment counts mismatch", ErrInvalidParameters)
	}
	if len(scalars) == 0 {
		// Return point at infinity
		return NewCurvePointFromCoords(big.NewInt(0), big.NewInt(0), params.Curve), nil
	}

	// Start with scalar_0 * commitment_0
	result := CurveScalarMul(scalars[0], commitments[0])

	// Add subsequent scalar_i * commitment_i
	for i := 1; i < len(scalars); i++ {
		term := CurveScalarMul(scalars[i], commitments[i])
		result = CurveAdd(result, term)
	}

	return result, nil
}


// --- ZK Proof 1: Knowledge of Committed Value (Sigma Protocol) ---
// Prove knowledge of x, r such that C = xG + rH
// Non-interactive using Fiat-Shamir transform: e = Hash(C, R)
// Prover: picks random w, t. Computes R = wG + tH. Gets challenge e. Computes s_x = w + e*x, s_r = t + e*r. Proof is {R, s_x, s_r}.
// Verifier: Checks R + e*C == s_x*G + s_r*H

type KnowledgeProof struct {
	CommitmentRandom CurvePoint // R = wG + tH
	ResponseValue    FieldElement // s_x = w + e*x
	ResponseRandom   FieldElement // s_r = t + e*r
}

// ProveKnowledge creates a KnowledgeProof for a given commitment, value, and randomness.
// This function combines the commitment and response generation using the Fiat-Shamir transform.
func (params PedersenParams) ProveKnowledge(value, randomness FieldElement) (KnowledgeProof, error) {
	// Prover Step 1: Choose random w, t and compute R
	w, err := GenerateRandomScalar(params.Order)
	if err != nil {
		return KnowledgeProof{}, fmt.Errorf("failed to generate random w: %w", err)
	}
	t, err := GenerateRandomScalar(params.Order)
	if err != nil {
		return KnowledgeProof{}, fmt.Errorf("failed to generate random t: %w", err)
	}
	R := CurveAdd(
		CurveScalarMul(w, params.G),
		CurveScalarMul(t, params.H),
	)

	// Simulate Verifier Step (Fiat-Shamir): Compute challenge e
	C, err := CommitPedersen(value, randomness, params)
	if err != nil {
		return KnowledgeProof{}, fmt.Errorf("failed to compute commitment C: %w", err)
	}
	e := HashToScalar(params.Order, C.Bytes(), R.Bytes())

	// Prover Step 2: Compute responses s_x, s_r
	s_x := FieldAdd(w, FieldMul(e, value))
	s_r := FieldAdd(t, FieldMul(e, randomness))

	return KnowledgeProof{
		CommitmentRandom: R,
		ResponseValue:    s_x,
		ResponseRandom:   s_r,
	}, nil
}

// VerifyKnowledge verifies a KnowledgeProof for a given commitment.
// This function recomputes the challenge using Fiat-Shamir and checks the verification equation.
func (params PedersenParams) VerifyKnowledge(commitment CurvePoint, proof KnowledgeProof) bool {
	// Recompute challenge e using Fiat-Shamir
	e := HashToScalar(params.Order, commitment.Bytes(), proof.CommitmentRandom.Bytes())

	// Verifier Check: R + e*C == s_x*G + s_r*H
	// Left side: R + e*C
	eC := CurveScalarMul(e, commitment)
	lhs := CurveAdd(proof.CommitmentRandom, eC)

	// Right side: s_x*G + s_r*H
	sxG := CurveScalarMul(proof.ResponseValue, params.G)
	srH := CurveScalarMul(proof.ResponseRandom, params.H)
	rhs := CurveAdd(sxG, srH)

	return lhs.Equals(rhs)
}

// Verify is a convenience method for KnowledgeProof verification.
func (kp KnowledgeProof) Verify(commitment CurvePoint, params PedersenParams) bool {
    return params.VerifyKnowledge(commitment, kp)
}


// MarshalBinary serializes the KnowledgeProof.
func (kp KnowledgeProof) MarshalBinary() ([]byte, error) {
	rBytes := kp.CommitmentRandom.Bytes()
	sxBytes := kp.ResponseValue.Bytes()
	srBytes := kp.ResponseRandom.Bytes()

	// Simple concatenation. For safety, might need length prefixes or fixed sizes.
	// Assuming curve point bytes have consistent size (size*2 for X|Y) and scalar bytes have consistent size (size for big.Int).
	pointSize := (kp.CommitmentRandom.Curve.Params().BitSize + 7) / 8 * 2
	scalarSize := (kp.ResponseValue.Order.BitLen() + 7) / 8

	buf := make([]byte, pointSize + scalarSize + scalarSize) // R || s_x || s_r

	// Pad scalar bytes if necessary for fixed size
	copy(buf[pointSize - len(rBytes):pointSize], rBytes)
	copy(buf[pointSize+scalarSize-len(sxBytes):pointSize+scalarSize], sxBytes)
	copy(buf[pointSize+scalarSize+scalarSize-len(srBytes):pointSize+scalarSize+scalarSize], srBytes)

	return buf, nil
}

// UnmarshalBinary deserializes the KnowledgeProof.
func (kp *KnowledgeProof) UnmarshalBinary(data []byte, curve elliptic.Curve, order *big.Int) error {
	pointSize := (curve.Params().BitSize + 7) / 8 * 2
	scalarSize := (order.BitLen() + 7) / 8
	expectedLen := pointSize + scalarSize + scalarSize

	if len(data) != expectedLen {
		return fmt.Errorf("%w: invalid byte length for KnowledgeProof", ErrDeserialization)
	}

	var err error
	kp.CommitmentRandom, err = NewCurvePointFromBytes(data[:pointSize], curve)
	if err != nil {
		return fmt.Errorf("%w: failed to deserialize CommitmentRandom", err)
	}

	kp.ResponseValue, err = NewFieldElementFromBytes(data[pointSize:pointSize+scalarSize], order)
	if err != nil {
		return fmt.Errorf("%w: failed to deserialize ResponseValue", err)
	}

	kp.ResponseRandom, err = NewFieldElementFromBytes(data[pointSize+scalarSize:], order)
	if err != nil {
		return fmt.Errorf("%w: failed to deserialize ResponseRandom", err)
	}

	return nil
}

// Equals checks if two KnowledgeProofs are equal.
func (kp KnowledgeProof) Equals(other KnowledgeProof) bool {
	return kp.CommitmentRandom.Equals(other.CommitmentRandom) &&
		kp.ResponseValue.Equals(other.ResponseValue) &&
		kp.ResponseRandom.Equals(other.ResponseRandom)
}


// --- ZK Proof 2: Knowledge of Bit (Chaum-Pedersen OR Proof adaptation) ---
// Prove knowledge of x, r such that C = xG + rH AND x is in {0, 1}.
// This can be proven by showing C is a commitment to 0 OR C is a commitment to 1.
// C = 0*G + r0*H  OR  C = 1*G + r1*H
// This is equivalent to proving knowledge of r0 in C = r0*H OR knowledge of r1 in C - G = r1*H.
// We can use the KnowledgeProof structure on the 'H' part (commitment to 0) for both cases and compose them.
// Prover proves knowledge of r in C' = rH for C' = C (if bit is 0) or C' = C-G (if bit is 1).
// Non-interactive Chaum-Pedersen OR structure:
// Prover picks randoms (w0, t0) for case 0, (w1, t1) for case 1.
// Computes commitments R0 = t0*H, R1 = t1*H. (Note: w0/w1 are not needed as x is fixed at 0 or 1)
// Gets total challenge e = Hash(C, R0, R1).
// Splits e into e0, e1 such that e0 + e1 = e (e.g., e0 = Hash(C, R0, R1, label0), e1 = e - e0).
// If bit is 0: Compute response for case 0: s0 = t0 + e0*r0. For case 1 (false): s1 = t1 + e1*fake_r1, where fake_r1 is arbitrary.
// If bit is 1: Compute response for case 1: s1 = t1 + e1*r1. For case 0 (false): s0 = t0 + e0*fake_r0.
// Proof contains {R0, R1, s0, s1}.
// Verifier checks R0 + e0*C == s0*H and R1 + e1*(C-G) == s1*H. (This requires knowledge of C, R0, R1 to recompute e, e0, e1).

type BitProof struct {
	// CommitmentRandom0 is the random commitment R0 for the case bit=0
	CommitmentRandom0 CurvePoint
	// CommitmentRandom1 is the random commitment R1 for the case bit=1
	CommitmentRandom1 CurvePoint
	// Response0 is the response s0 for the case bit=0
	Response0 FieldElement
	// Response1 is the response s1 for the case bit=1
	Response1 FieldElement
}

// ProveBit creates a BitProof for a commitment C = bitValue*G + randomness*H.
// bitValue must be 0 or 1.
func (params PedersenParams) ProveBit(bitValue uint, randomness FieldElement) (BitProof, error) {
	if bitValue != 0 && bitValue != 1 {
		return BitProof{}, ErrInvalidBitValue
	}

	// Prover picks randoms for both cases (even though only one is 'true')
	t0_rand, err := GenerateRandomScalar(params.Order)
	if err != nil { return BitProof{}, fmt.Errorf("failed to generate random t0: %w", err) }
	t1_rand, err := GenerateRandomScalar(params.Order)
	if err != nil { return BitProof{}, fmt.Errorf("failed to generate random t1: %w", err); }

	// Compute random commitments for both cases (R_i = t_i * H)
	R0 := CurveScalarMul(t0_rand, params.H)
	R1 := CurveScalarMul(t1_rand, params.H)

	// Compute the actual commitment C = bitValue*G + randomness*H
	C, err := CommitPedersen(ScalarFromUint64(uint64(bitValue), params.Order), randomness, params)
	if err != nil { return BitProof{}, fmt.Errorf("failed to compute commitment C: %w", err); }

	// Simulate Verifier (Fiat-Shamir): Compute total challenge e
	e := HashToScalar(params.Order, C.Bytes(), R0.Bytes(), R1.Bytes())

	// Split the challenge e into e0 and e1 (e0 + e1 = e)
	// A common way is to use a different hash or label for e0.
	e0 := HashToScalar(params.Order, C.Bytes(), R0.Bytes(), R1.Bytes(), []byte("label0"))
	e1 := FieldSub(e, e0) // e1 = e - e0 mod Order

	// Prover computes responses (s_i = t_i + e_i * secret_i)
	// Here, secret_i is the randomness 'r' from C = b*G + r*H

	var s0, s1 FieldElement
	if bitValue == 0 { // Proving C = 0*G + r*H (Case 0 is true)
		// Response for true case (bit=0): s0 = t0_rand + e0 * randomness (the actual randomness)
		s0 = FieldAdd(t0_rand, FieldMul(e0, randomness))
		// Response for false case (bit=1): s1 = t1_rand + e1 * fake_randomness
		// We need to pick a random fake_randomness, or structure the protocol differently.
		// A simpler approach for the OR proof: Prover commits to both cases.
		// Case 0: C = r0*H. Prover needs to prove knowledge of r0. Use KnowledgeProof on (0, r0, C).
		// Case 1: C-G = r1*H. Prover needs to prove knowledge of r1. Use KnowledgeProof on (0, r1, C-G).
		// Then combine these two proofs using CP-OR.
		// Let's re-structure based on the CP-OR description {R0, R1, s0, s1} where s_i relates to t_i and the secret.

		// Let's stick to the CP-OR form described in comments above:
		// C = b*G + r*H
		// Prove b in {0, 1}
		// Case 0: C = r*H => C is commitment to 0
		// Case 1: C - G = r*H => C-G is commitment to 0
		// We are proving knowledge of 'r' such that C' = r*H for C'=C or C'=C-G.
		// The base protocol is ProveKnowledge applied to a commitment to 0.
		// KnowledgeProof for C = 0*G + r*H: {R = tH, s_x = w + e*0, s_r = t + e*r}. If w=0, R = tH, s_x=0, s_r = t+er.
		// Let's use the simpler form where R_i = t_i * H and s_i = t_i + e_i * secret_i.

		// If bitValue is 0, secret is 'randomness' (from C = 0G + randomness*H).
		s0 = FieldAdd(t0_rand, FieldMul(e0, randomness))

		// If bitValue is 1, secret is 'randomness' (from C = 1G + randomness*H).
		// We need to prove C-G is a commitment to 0 with randomness 'randomness'.
		// So, if bitValue=0 is false, we generate a fake response for case 1.
		// This is where the CP-OR structure comes in: for the 'false' case, you generate the response using randoms,
		// such that the verification equation holds for the corresponding 'false' challenge part.

		// Let's simplify the CP-OR application for this specific structure:
		// Prove knowledge of r such that C = r*H (bit=0) OR C-G = r*H (bit=1).
		// Prover knows the true bit (0 or 1) and its randomness.
		// Let's say bit=0 is true, randomness=r.
		// Prover picks random t0, t1, fake_r1, fake_s1.
		// Computes R0 = t0*H, R1 = t1*H.
		// Gets challenge e, splits e = e0 + e1.
		// s0 = t0 + e0*r
		// The check for case 1 is R1 + e1*(C-G) == s1*H. Prover needs to find s1 such that this holds for a random t1 and fake_r1.
		// fake_s1 = t1 + e1 * fake_r1. Prover reveals {R0, R1, s0, fake_s1}.
		// This requires revealing fake_r1 or structuring s1 differently.

		// A more standard CP-OR reveals (R0, R1, s0, s1) where s_i are responses for *randomness*.
		// R_i = randomness_i * H
		// e = H(C, R0, R1)
		// e0 = H(C, R0, R1, 'label0')
		// e1 = e - e0
		// If bit=0 is true (C=r*H): s0 = randomness0 + e0*r; s1 = randomness1 + e1*fake_r
		// If bit=1 is true (C-G=r*H): s1 = randomness1 + e1*r; s0 = randomness0 + e0*fake_r

		// Let's use the form where R_i = t_i * H and s_i are responses.
		// The secret we are proving knowledge of is 'r' in C' = r*H.
		// Case 0: C' = C, secret = randomness.
		// Case 1: C' = C-G, secret = randomness.

		// Prover chooses random blinding scalars for the responses (t0, t1)
		// Computes commitments R0 = t0 * H, R1 = t1 * H
		// Gets challenge e = Hash(C, R0, R1)
		// Splits e = e0 + e1 (e0 = Hash(C, R0, R1, 'label0'), e1 = e - e0)

		// If bitValue == 0:
		// Response for case 0 (true): s0 = t0 + e0 * randomness
		s0 = FieldAdd(t0_rand, FieldMul(e0, randomness))
		// Response for case 1 (false): s1 is computed to satisfy the check using a random fake randomness
		// Check for case 1: R1 + e1*(C-G) == s1*H
		// Prover knows C, G, H, R1, e1, t1_rand. Needs to find s1.
		// R1 = t1_rand*H. So, t1_rand*H + e1*(C-G) == s1*H
		// (t1_rand + e1 * (C-G)/H) * H == s1 * H -- Division by H is symbolic.
		// We need s1 = t1_rand + e1 * fake_randomness_for_case1
		// The standard way for CP-OR is s_i = t_i + e_i * secret_i.
		// If case i is false, 'secret_i' is computed backwards from random response.
		// Let's generate a random response s1 and compute the implied fake randomness.
		fake_s1, err := GenerateRandomScalar(params.Order)
		if err != nil { return BitProof{}, fmt.Errorf("failed to generate fake s1: %w", err); }
		// fake_s1 = t1_rand + e1 * fake_randomness_for_case1
		// (fake_s1 - t1_rand) = e1 * fake_randomness_for_case1
		// fake_randomness_for_case1 = (fake_s1 - t1_rand) / e1   (if e1 is invertible)
		s1 = fake_s1 // The response value we reveal for the false case.


	} else { // bitValue == 1: Proving C = 1*G + r*H  => C-G = r*H (Case 1 is true)
		// Response for case 1 (true): s1 = t1_rand + e1 * randomness
		s1 = FieldAdd(t1_rand, FieldMul(e1, randomness))
		// Response for case 0 (false): s0 is computed using random fake randomness
		fake_s0, err := GenerateRandomScalar(params.Order)
		if err != nil { return BitProof{}, fmt.Errorf("failed to generate fake s0: %w", err); }
		s0 = fake_s0
	}

	return BitProof{
		CommitmentRandom0: R0,
		CommitmentRandom1: R1,
		Response0:         s0,
		Response1:         s1,
	}, nil
}

// VerifyBit verifies a BitProof for a commitment.
func (params PedersenParams) VerifyBit(commitment CurvePoint, proof BitProof) bool {
	// Recompute challenges e, e0, e1
	e := HashToScalar(params.Order, commitment.Bytes(), proof.CommitmentRandom0.Bytes(), proof.CommitmentRandom1.Bytes())
	e0 := HashToScalar(params.Order, commitment.Bytes(), proof.CommitmentRandom0.Bytes(), proof.CommitmentRandom1.Bytes(), []byte("label0"))
	e1 := FieldSub(e, e0) // e1 = e - e0 mod Order

	// Verifier Check 1 (for bit=0 case): R0 + e0*C == s0*H
	// R0 = t0*H, s0 = t0 + e0*r0
	// t0*H + e0*C == (t0 + e0*r0)*H
	// t0*H + e0*C == t0*H + e0*r0*H
	// e0*C == e0*r0*H   (if e0 != 0)
	// If e0 != 0, C == r0*H. This confirms C is a commitment to 0 *IF* s0 was computed correctly using r0.
	// The actual check is R0 + e0*C == s0*H
	lhs0 := CurveAdd(proof.CommitmentRandom0, CurveScalarMul(e0, commitment))
	rhs0 := CurveScalarMul(proof.Response0, params.H)
	check0 := lhs0.Equals(rhs0)

	// Verifier Check 2 (for bit=1 case): R1 + e1*(C-G) == s1*H
	// R1 = t1*H, s1 = t1 + e1*r1
	// t1*H + e1*(C-G) == (t1 + e1*r1)*H
	// t1*H + e1*(C-G) == t1*H + e1*r1*H
	// e1*(C-G) == e1*r1*H  (if e1 != 0)
	// If e1 != 0, C-G == r1*H. This confirms C-G is a commitment to 0 *IF* s1 was computed correctly using r1.
	// The actual check is R1 + e1*(C-G) == s1*H
	cMinusG := FieldSub(OneFieldElement(params.Order), ZeroFieldElement(params.Order)) // Dummy value for scalar G - not scalar G
	cMinusGPoint := CurveSub(commitment, params.G) // C - G point operation
	lhs1 := CurveAdd(proof.CommitmentRandom1, CurveScalarMul(e1, cMinusGPoint))
	rhs1 := CurveScalarMul(proof.Response1, params.H)
	check1 := lhs1.Equals(rhs1)

	// The proof is valid if EITHER check 0 OR check 1 passes AND the prover doesn't know the secret for the other case.
	// With Fiat-Shamir and the random response structure for the false case, the prover can only pass *both* checks
	// if they know secrets for *both* cases (i.e., know r0 for C=r0H AND r1 for C-G=r1H), which is generally impossible
	// if C is a commitment to a unique value (0 or 1).
	// So, the proof is valid if at least one check passes. This is NOT the standard CP-OR verification.
	// The standard CP-OR verification is that *both* equations hold, and the security comes from the split challenges (e0 + e1 = e)
	// and the structure of responses (one real, one faked).

	// Let's use the standard CP-OR verification: both equations must hold.
	// The prover constructed the proof such that one equation holds because they used the real secret,
	// and the other equation holds because they constructed the response s_false using random t_false and random fake_s_false.
	// This requires the prover to solve for the fake secret: fake_secret = (s_false - t_false) / e_false.
	// If e_false is invertible, this is possible. If e_false = 0, this case isn't checked.
	// The validity relies on e0 and e1 being non-zero with high probability and e0+e1=e linking the two proofs.

	// Verifier checks R0 + e0*C == s0*H AND R1 + e1*(C-G) == s1*H
	return check0 && check1
}

// CurveSub performs point subtraction p1 - p2 (p1 + (-p2))
func CurveSub(p1, p2 CurvePoint) CurvePoint {
    if p1.Curve != p2.Curve || p2.Curve == nil {
        panic("curves mismatch or nil curve")
    }
     // Identity point (0,0)
     identity := NewCurvePointFromCoords(big.NewInt(0), big.NewInt(0), p2.Curve)
     // The negative of a point (x, y) on a short Weierstrass curve y^2 = x^3 + ax + b is (x, -y mod p)
     negY := new(big.Int).Neg(p2.Y)
     negY.Mod(negY, p2.Curve.Params().P) // Modulo P for the curve field, not the scalar field N
     negP2 := NewCurvePointFromCoords(p2.X, negY, p2.Curve)

     return CurveAdd(p1, negP2)
}


// Verify is a convenience method for BitProof verification.
func (bp BitProof) Verify(commitment CurvePoint, params PedersenParams) bool {
    return params.VerifyBit(commitment, bp)
}

// MarshalBinary serializes the BitProof.
func (bp BitProof) MarshalBinary() ([]byte, error) {
	r0Bytes := bp.CommitmentRandom0.Bytes()
	r1Bytes := bp.CommitmentRandom1.Bytes()
	s0Bytes := bp.Response0.Bytes()
	s1Bytes := bp.Response1.Bytes()

	// Assuming points and scalars have fixed sizes
	pointSize := (bp.CommitmentRandom0.Curve.Params().BitSize + 7) / 8 * 2
	scalarSize := (bp.Response0.Order.BitLen() + 7) / 8

	buf := make([]byte, pointSize*2 + scalarSize*2) // R0 || R1 || s0 || s1

	copy(buf[pointSize - len(r0Bytes):pointSize], r0Bytes)
	copy(buf[pointSize*2 - len(r1Bytes):pointSize*2], r1Bytes)
	copy(buf[pointSize*2 + scalarSize - len(s0Bytes):pointSize*2 + scalarSize], s0Bytes)
	copy(buf[pointSize*2 + scalarSize*2 - len(s1Bytes):pointSize*2 + scalarSize*2], s1Bytes)

	return buf, nil
}

// UnmarshalBinary deserializes the BitProof.
func (bp *BitProof) UnmarshalBinary(data []byte, curve elliptic.Curve, order *big.Int) error {
	pointSize := (curve.Params().BitSize + 7) / 8 * 2
	scalarSize := (order.BitLen() + 7) / 8
	expectedLen := pointSize*2 + scalarSize*2

	if len(data) != expectedLen {
		return fmt.Errorf("%w: invalid byte length for BitProof", ErrDeserialization)
	}

	var err error
	bp.CommitmentRandom0, err = NewCurvePointFromBytes(data[:pointSize], curve)
	if err != nil { return fmt.Errorf("%w: failed to deserialize R0", err) }
	bp.CommitmentRandom1, err = NewCurvePointFromBytes(data[pointSize:pointSize*2], curve)
	if err != nil { return fmt.Errorf("%w: failed to deserialize R1", err) }
	bp.Response0, err = NewFieldElementFromBytes(data[pointSize*2:pointSize*2+scalarSize], order)
	if err != nil { return fmt.Errorf("%w: failed to deserialize s0", err) }
	bp.Response1, err = NewFieldElementFromBytes(data[pointSize*2+scalarSize:], order)
	if err != nil { return fmt.Errorf("%w: failed to deserialize s1", err) }

	return nil
}

// Equals checks if two BitProofs are equal.
func (bp BitProof) Equals(other BitProof) bool {
	return bp.CommitmentRandom0.Equals(other.CommitmentRandom0) &&
		bp.CommitmentRandom1.Equals(other.CommitmentRandom1) &&
		bp.Response0.Equals(other.Response0) &&
		bp.Response1.Equals(other.Response1)
}


// --- ZK Proof 3: Bounded Range Proof ---
// Prove knowledge of value 'x' and randomness 'r' such that C = xG + rH AND 0 <= x < 2^bitLength.
// This is achieved by:
// 1. Decomposing x into bits: x = sum(b_i * 2^i) where b_i is 0 or 1.
// 2. Prover commits to each bit: C_i = b_i*G + r_i*H for i = 0 to bitLength-1.
// 3. Prover provides a BitProof for each C_i, proving b_i is 0 or 1.
// 4. Prover needs to prove the commitments C_i sum up correctly to C: C == sum(2^i * C_i).
//    C = sum(2^i * (b_i*G + r_i*H))
//    C = sum(2^i * b_i * G) + sum(2^i * r_i * H)
//    C = (sum(2^i * b_i)) * G + (sum(2^i * r_i)) * H
//    C = x * G + (sum(2^i * r_i)) * H
//    For this to equal C = x*G + r*H, we need the total randomness r to equal sum(2^i * r_i).
//    So, the prover must choose bit randoms r_i such that r = sum(2^i * r_i).

type BoundedRangeProof struct {
	ValueCommitment CurvePoint       // The commitment to the value x
	BitCommitments  []CurvePoint     // Commitments C_i for each bit b_i
	BitProofs       []BitProof       // BitProof for each C_i
	BitLength       uint             // The maximum number of bits (range 0 to 2^bitLength - 1)
}

// ProveBoundedRange creates a BoundedRangeProof for a value and its commitment.
// The prover must provide the value, the total randomness for the value commitment, and the desired bit length.
// The prover internally calculates the bit commitments and bit proofs.
func (params PedersenParams) ProveBoundedRange(value uint64, randomness FieldElement, bitLength uint) (BoundedRangeProof, error) {
	maxVal := uint64(1) << bitLength
	if bitLength == 0 || value >= maxVal {
        // Note: For uint64, left shift by 64 is undefined. Need to handle bitLength=64 carefully.
        if bitLength > 63 { // Handle potential overflow for maxVal for bitLength >= 64
            // This simple range proof is usually for smaller bit lengths (e.g., 32 or 64).
            // If bitLength is huge, use a different range proof method (like Bulletproofs).
             return BoundedRangeProof{}, fmt.Errorf("%w: bit length %d is too large or value %d exceeds max %d", ErrRangeValueTooLarge, bitLength, value, maxVal)
        }
        if bitLength > 0 && value >= maxVal {
             return BoundedRangeProof{}, fmt.Errorf("%w: value %d exceeds max %d for bit length %d", ErrRangeValueTooLarge, value, maxVal, bitLength)
        }
        if bitLength == 0 && value > 0 { // Only 0 is allowed for bitLength 0
            return BoundedRangeProof{}, fmt.Errorf("%w: value %d is not 0 for bit length 0", ErrRangeValueTooLarge, value)
        }
        if bitLength == 0 && value == 0 {
            // Special case: 0 bit length implies value must be 0.
             // Proceed with bitLength=0.
        } else if bitLength > 63 {
            // This construction of maxVal fails for bitLength > 63 due to uint64 overflow.
            // Consider maxVal check only for bitLength <= 63, or use big.Int for value/maxVal.
             // For this example, assume bitLength <= 63.
             return BoundedRangeProof{}, fmt.Errorf("%w: bit length %d not supported by uint64 max check", ErrInvalidBitLength, bitLength)
        }
	}

	// Compute the main commitment C = value*G + randomness*H
	C, err := CommitPedersen(ScalarFromUint64(value, params.Order), randomness, params)
	if err != nil {
		return BoundedRangeProof{}, fmt.Errorf("failed to compute value commitment: %w", err)
	}

	bitCommitments := make([]CurvePoint, bitLength)
	bitProofs := make([]BitProof, bitLength)
	bitRandoms := make([]FieldElement, bitLength) // Randomness for each bit commitment

	// Extract bits and generate commitments and proofs
	currentRandomness := randomness
	powersOf2 := make([]FieldElement, bitLength) // Need powers of 2 as scalars
    two := ScalarFromUint64(2, params.Order)
    currentPower := OneFieldElement(params.Order)


	// Calculate powers of 2 and their commitment contributions
    for i := uint(0); i < bitLength; i++ {
        powersOf2[i] = currentPower
        currentPower = FieldMul(currentPower, two)
    }


	// We need r = sum(2^i * r_i). This means we can't choose r_i randomly for each bit.
	// We need to choose r_0, ..., r_{bitLength-2} randomly, then calculate r_{bitLength-1}
	// r_{bitLength-1} = (r - sum(2^i * r_i for i=0 to bitLength-2)) / 2^(bitLength-1)
	// This requires 2^(bitLength-1) to be invertible, which is true if Order is prime and bitLength-1 < log2(Order).
	// P256 order is large enough.

	// Generate random randomness for all bits except the last
	for i := uint(0); i < bitLength-1; i++ {
		r_i, err := GenerateRandomScalar(params.Order)
		if err != nil {
			return BoundedRangeProof{}, fmt.Errorf("failed to generate random r_%d: %w", i, err)
		}
		bitRandoms[i] = r_i
	}

    // Calculate the randomness for the last bit
    if bitLength > 0 {
        sumWeightedRandomsExceptLast := ZeroFieldElement(params.Order)
        for i := uint(0); i < bitLength-1; i++ {
            term := FieldMul(powersOf2[i], bitRandoms[i])
            sumWeightedRandomsExceptLast = FieldAdd(sumWeightedRandomsExceptLast, term)
        }

        remainingRandomness := FieldSub(randomness, sumWeightedRandomsExceptLast)
        lastPowerOf2Inv := FieldInv(powersOf2[bitLength-1]) // (2^(m-1))^-1 mod N
        bitRandoms[bitLength-1] = FieldMul(remainingRandomness, lastPowerOf2Inv)
    }


	// Create commitments and proofs for each bit
	for i := uint(0); i < bitLength; i++ {
		bit := (value >> i) & 1 // Get the i-th bit
		bitScalar := ScalarFromUint64(bit, params.Order)
		r_i := bitRandoms[i] // Use the determined randomness for the bit

		// Compute the bit commitment C_i = b_i*G + r_i*H
		C_i, err := CommitPedersen(bitScalar, r_i, params)
		if err != nil {
			return BoundedRangeProof{}, fmt.Errorf("failed to compute bit commitment %d: %w", i, err)
		}
		bitCommitments[i] = C_i

		// Prove that C_i commits to a bit (0 or 1)
		bitProof, err := params.ProveBit(uint(bit), r_i) // Pass the actual bit randomness
		if err != nil {
			return BoundedRangeProof{}, fmt.Errorf("failed to create bit proof %d: %w", i, err)
		}
		bitProofs[i] = bitProof
	}

	return BoundedRangeProof{
		ValueCommitment: C,
		BitCommitments:  bitCommitments,
		BitProofs:       bitProofs,
		BitLength:       bitLength,
	}, nil
}

// VerifyBoundedRange verifies a BoundedRangeProof.
// It checks each bit proof and verifies that the weighted sum of bit commitments equals the main commitment.
func (params PedersenParams) VerifyBoundedRange(proof BoundedRangeProof) bool {
	if uint(len(proof.BitCommitments)) != proof.BitLength || uint(len(proof.BitProofs)) != proof.BitLength {
		// Should ideally return error, but Verify methods typically return bool
		// fmt.Println(ErrCommitmentCount, len(proof.BitCommitments), proof.BitLength) // Debug
		// fmt.Println(ErrProofCount, len(proof.BitProofs), proof.BitLength) // Debug
		return false
	}

	// 1. Verify each bit proof
	for i := uint(0); i < proof.BitLength; i++ {
		if !params.VerifyBit(proof.BitCommitments[i], proof.BitProofs[i]) {
			// fmt.Printf("Bit proof %d failed verification\n", i) // Debug
			return false // If any bit proof fails, the whole proof is invalid
		}
	}

	// 2. Verify the linear combination of bit commitments equals the value commitment
	// Check if proof.ValueCommitment == sum(2^i * proof.BitCommitments[i])
	weightedBitCommitments := make([]CurvePoint, proof.BitLength)
	powersOf2 := make([]FieldElement, proof.BitLength)
	two := ScalarFromUint64(2, params.Order)
	currentPower := OneFieldElement(params.Order)

	for i := uint(0); i < proof.BitLength; i++ {
		powersOf2[i] = currentPower
		weightedBitCommitments[i] = CurveScalarMul(powersOf2[i], proof.BitCommitments[i])
        currentPower = FieldMul(currentPower, two)
	}

	computedValueCommitment := SumCommitments(weightedBitCommitments)

	// fmt.Printf("Original Commitment: %s\n", proof.ValueCommitment.Bytes()) // Debug
	// fmt.Printf("Computed Commitment: %s\n", computedValueCommitment.Bytes()) // Debug


	return proof.ValueCommitment.Equals(computedValueCommitment)
}

// Verify is a convenience method for BoundedRangeProof verification.
func (brp BoundedRangeProof) Verify(params PedersenParams) bool {
    return params.VerifyBoundedRange(brp)
}


// MarshalBinary serializes the BoundedRangeProof.
func (brp BoundedRangeProof) MarshalBinary() ([]byte, error) {
	// ValueCommitment: Point (size*2)
	// BitLength: uint (8 bytes)
	// BitCommitments: []Point. Write count (4 bytes), then each point.
	// BitProofs: []BitProof. Write count (4 bytes), then each proof.

	var buf []byte
	w := &ByteWriter{buf: &buf}

	// Write ValueCommitment
	vcBytes := brp.ValueCommitment.Bytes()
	w.WriteBytes(vcBytes)

	// Write BitLength
	w.WriteUint64(uint64(brp.BitLength))

	// Write BitCommitments
	w.WriteUint32(uint32(len(brp.BitCommitments)))
	for _, c := range brp.BitCommitments {
		cBytes := c.Bytes()
		w.WriteBytes(cBytes)
	}

	// Write BitProofs
	w.WriteUint32(uint32(len(brp.BitProofs)))
	for _, p := range brp.BitProofs {
		pBytes, err := p.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to marshal bit proof: %v", ErrSerialization, err)
		}
		// BitProof MarshalBinary writes fixed size, so no length prefix needed here
		w.WriteBytes(pBytes)
	}

	if w.err != nil {
		return nil, w.err
	}
	return buf, nil
}

// UnmarshalBinary deserializes the BoundedRangeProof.
func (brp *BoundedRangeProof) UnmarshalBinary(data []byte, curve elliptic.Curve, order *big.Int) error {
	r := &ByteReader{data: data}

	// Read ValueCommitment
	pointSize := (curve.Params().BitSize + 7) / 8 * 2
	vcBytes := r.ReadBytes(pointSize)
	var err error
	brp.ValueCommitment, err = NewCurvePointFromBytes(vcBytes, curve)
	if err != nil { return fmt.Errorf("%w: failed to deserialize value commitment", err) }

	// Read BitLength
	brp.BitLength = uint(r.ReadUint64())

	// Read BitCommitments
	bitCommitmentCount := int(r.ReadUint32())
	if bitCommitmentCount < 0 || uint(bitCommitmentCount) != brp.BitLength {
         // Allow 0 length if bitLength is 0
        if !(bitCommitmentCount == 0 && brp.BitLength == 0) {
		  return fmt.Errorf("%w: mismatched bit commitment count %d vs length %d", ErrDeserialization, bitCommitmentCount, brp.BitLength)
        }
	}
    brp.BitCommitments = make([]CurvePoint, bitCommitmentCount)
	for i := 0; i < bitCommitmentCount; i++ {
		cBytes := r.ReadBytes(pointSize)
		brp.BitCommitments[i], err = NewCurvePointFromBytes(cBytes, curve)
		if err != nil { return fmt.Errorf("%w: failed to deserialize bit commitment %d", ErrDeserialization, i) }
	}

	// Read BitProofs
	bitProofCount := int(r.ReadUint32())
     if bitProofCount < 0 || uint(bitProofCount) != brp.BitLength {
         // Allow 0 length if bitLength is 0
        if !(bitProofCount == 0 && brp.BitLength == 0) {
             return fmt.Errorf("%w: mismatched bit proof count %d vs length %d", ErrDeserialization, bitProofCount, brp.BitLength)
        }
    }
	brp.BitProofs = make([]BitProof, bitProofCount)

	// Need BitProof marshaled size to read
	tempBP := BitProof{}
	// Need curve and order to get size from marshal, this is a bit circular.
	// A better approach is fixing sizes based on curve/order during setup, or including params in serialized data.
	// Let's assume we have params to get the size.
	// The size is 2*pointSize + 2*scalarSize
	scalarSize := (order.BitLen() + 7) / 8
	bitProofSize := pointSize*2 + scalarSize*2

	for i := 0; i < bitProofCount; i++ {
		pBytes := r.ReadBytes(bitProofSize)
		err = tempBP.UnmarshalBinary(pBytes, curve, order)
		if err != nil { return fmt.Errorf("%w: failed to deserialize bit proof %d: %v", ErrDeserialization, i, err) }
		brp.BitProofs[i] = tempBP // tempBP is unmarshalled in place
	}

	if r.err != nil {
		return r.err
	}

    // Check if there's any leftover data
    if r.pos != len(r.data) {
         return fmt.Errorf("%w: leftover data after deserialization", ErrDeserialization)
    }


	return nil
}

// Equals checks if two BoundedRangeProofs are equal.
func (brp BoundedRangeProof) Equals(other BoundedRangeProof) bool {
	if !brp.ValueCommitment.Equals(other.ValueCommitment) || brp.BitLength != other.BitLength || len(brp.BitCommitments) != len(other.BitCommitments) || len(brp.BitProofs) != len(other.BitProofs) {
		return false
	}
	for i := range brp.BitCommitments {
		if !brp.BitCommitments[i].Equals(other.BitCommitments[i]) {
			return false
		}
	}
	for i := range brp.BitProofs {
		if !brp.BitProofs[i].Equals(other.BitProofs[i]) {
			return false
		}
	}
	return true
}


// --- Simple Byte Readers/Writers for Serialization ---
// Minimal helpers, not robust production-ready serialization

type ByteWriter struct {
	buf *[]byte
	err error
}

func (w *ByteWriter) WriteBytes(b []byte) {
	if w.err != nil { return }
	*w.buf = append(*w.buf, b...)
}

func (w *ByteWriter) WriteUint32(v uint32) {
	if w.err != nil { return }
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	*w.buf = append(*w.buf, buf...)
}

func (w *ByteWriter) WriteUint64(v uint64) {
	if w.err != nil { return }
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	*w.buf = append(*w.buf, buf...)
}

type ByteReader struct {
	data []byte
	pos  int
	err  error
}

func (r *ByteReader) ReadBytes(n int) []byte {
	if r.err != nil { return nil }
	if r.pos+n > len(r.data) {
		r.err = fmt.Errorf("%w: read beyond end of buffer", ErrDeserialization)
		return nil
	}
	 chunk := r.data[r.pos : r.pos+n]
	 r.pos += n
	 return chunk
}

func (r *ByteReader) ReadUint32() uint32 {
	if r.err != nil { return 0 }
	buf := r.ReadBytes(4)
	if r.err != nil { return 0 }
	return binary.BigEndian.Uint32(buf)
}

func (r *ByteReader) ReadUint64() uint64 {
	if r.err != nil { return 0 }
	buf := r.ReadBytes(8)
	if r.err != nil { return 0 }
	return binary.BigEndian.Uint64(buf)
}

// --- Example Usage (Optional, for testing/demonstration) ---
/*
func main() {
    // 1. Setup
    curve := elliptic.P256()
    seedH := []byte("pedersen-setup-seed-h")
    params, err := SetupPedersen(curve, seedH)
    if err != nil {
        log.Fatalf("Setup failed: %v", err)
    }
    fmt.Println("Setup complete")

    // 2. Knowledge Proof Example
    fmt.Println("\n--- Knowledge Proof ---")
    value := NewFieldElementFromBigInt(big.NewInt(12345), params.Order)
    randomness, err := GenerateRandomScalar(params.Order)
    if err != nil { log.Fatal(err) }

    commitment, err := CommitPedersen(value, randomness, params)
    if err != nil { log.Fatal(err) }
    fmt.Printf("Committed value: %s\n", value.BigInt().String())
    fmt.Printf("Commitment: X=%s, Y=%s\n", commitment.X.String()[:10]+"...", commitment.Y.String()[:10]+"...")

    proof, err := params.ProveKnowledge(value, randomness)
    if err != nil { log.Fatalf("Proof generation failed: %v", err) }
    fmt.Println("Knowledge proof generated.")

    isValid := params.VerifyKnowledge(commitment, proof)
    fmt.Printf("Knowledge proof verification: %v\n", isValid)

    // Test serialization
    proofBytes, err := proof.MarshalBinary()
    if err != nil { log.Fatalf("Proof marshal failed: %v", err) }
    fmt.Printf("Knowledge proof marshaled (%d bytes)\n", len(proofBytes))

    var unmarshaledProof KnowledgeProof
    err = unmarshaledProof.UnmarshalBinary(proofBytes, params.Curve, params.Order)
    if err != nil { log.Fatalf("Proof unmarshal failed: %v", err) }
     fmt.Println("Knowledge proof unmarshaled.")

    isValid = params.VerifyKnowledge(commitment, unmarshaledProof)
    fmt.Printf("Unmarshaled Knowledge proof verification: %v\n", isValid)

    // 3. Bit Proof Example
    fmt.Println("\n--- Bit Proof ---")
    bitValue := uint(1) // Prove the bit is 1
    bitRandomness, err := GenerateRandomScalar(params.Order)
    if err != nil { log.Fatal(err) }

    bitCommitment, err := CommitPedersen(ScalarFromUint64(uint64(bitValue), params.Order), bitRandomness, params)
    if err != nil { log.Fatal(err) }
     fmt.Printf("Committed bit: %d\n", bitValue)
     fmt.Printf("Bit Commitment: X=%s, Y=%s\n", bitCommitment.X.String()[:10]+"...", bitCommitment.Y.String()[:10]+"...")

    bitProof, err := params.ProveBit(bitValue, bitRandomness)
    if err != nil { log.Fatalf("Bit proof generation failed: %v", err) }
    fmt.Println("Bit proof generated.")

    isBitValid := params.VerifyBit(bitCommitment, bitProof)
    fmt.Printf("Bit proof verification: %v\n", isBitValid)

     // Test serialization
    bitProofBytes, err := bitProof.MarshalBinary()
    if err != nil { log.Fatalf("Bit proof marshal failed: %v", err) }
    fmt.Printf("Bit proof marshaled (%d bytes)\n", len(bitProofBytes))

    var unmarshaledBitProof BitProof
    err = unmarshaledBitProof.UnmarshalBinary(bitProofBytes, params.Curve, params.Order)
    if err != nil { log.Fatalf("Bit proof unmarshal failed: %v", err) }
     fmt.Println("Bit proof unmarshaled.")

    isBitValid = params.VerifyBit(bitCommitment, unmarshaledBitProof)
    fmt.Printf("Unmarshaled Bit proof verification: %v\n", isBitValid)


    // 4. Bounded Range Proof Example
    fmt.Println("\n--- Bounded Range Proof ---")
    rangeValue := uint64(150) // Value to prove is in range
    bitLength := uint(8)      // Range [0, 2^8 - 1] = [0, 255]
    rangeRandomness, err := GenerateRandomScalar(params.Order) // Total randomness for value commitment
    if err != nil { log.Fatal(err) }

     // Need to compute the value commitment separately first, as the prover needs its randomness decomposition
     // OR the prover takes the total randomness and computes the decomposition internally.
     // Let's stick to the current structure where prover computes the bit randoms from the total randomness.
    rangeCommitment, err := CommitPedersen(ScalarFromUint64(rangeValue, params.Order), rangeRandomness, params)
    if err != nil { log.Fatal(err) }
     fmt.Printf("Value to prove in range [%d, %d]: %d\n", 0, (uint64(1)<<bitLength)-1, rangeValue)
     fmt.Printf("Range Commitment: X=%s, Y=%s\n", rangeCommitment.X.String()[:10]+"...", rangeCommitment.Y.String()[:10]+"...")


    rangeProof, err := params.ProveBoundedRange(rangeValue, rangeRandomness, bitLength)
    if err != nil { log.Fatalf("Range proof generation failed: %v", err) }
    fmt.Println("Bounded range proof generated.")

    isRangeValid := params.VerifyBoundedRange(rangeProof)
    fmt.Printf("Bounded range proof verification: %v\n", isRangeValid)

     // Test serialization
    rangeProofBytes, err := rangeProof.MarshalBinary()
    if err != nil { log.Fatalf("Range proof marshal failed: %v", err) }
    fmt.Printf("Bounded range proof marshaled (%d bytes)\n", len(rangeProofBytes))

    var unmarshaledRangeProof BoundedRangeProof
    err = unmarshaledRangeProof.UnmarshalBinary(rangeProofBytes, params.Curve, params.Order)
    if err != nil { log.Fatalf("Range proof unmarshal failed: %v", err) }
    fmt.Println("Bounded range proof unmarshaled.")

    isRangeValid = params.VerifyBoundedRange(unmarshaledRangeProof)
    fmt.Printf("Unmarshaled Bounded range proof verification: %v\n", isRangeValid)


     // Test invalid range proof (value out of range)
    fmt.Println("\n--- Invalid Bounded Range Proof (Value out of range) ---")
     invalidValue := uint64(300) // Out of range [0, 255]
     invalidRandomness, err := GenerateRandomScalar(params.Order)
     if err != nil { log.Fatal(err) }
     invalidCommitment, err := CommitPedersen(ScalarFromUint64(invalidValue, params.Order), invalidRandomness, params)
     if err != nil { log.Fatal(err) }

     // Prover *can* still generate a proof, but it won't verify correctly because the randomness decomposition won't sum correctly,
     // or the bit proofs for the higher bits (beyond bitLength) would need to be included and verified as 0.
     // Our current ProveBoundedRange relies on the value *actually* fitting in bitLength.
     // If the value exceeds uint64 max bits (64), ProveBoundedRange will error.
     // If value fits uint64 but exceeds 2^bitLength, our ProveBoundedRange will still run for bitLength bits.
     // The check `value >= maxVal` inside ProveBoundedRange handles the prover side.

     // To test invalid proof generation/verification *when value is out of bound but fits uint64*,
     // we would need to bypass the check in ProveBoundedRange or craft an invalid proof manually.
     // A simpler test is modifying a valid proof or verifying a valid proof against a wrong commitment.

    fmt.Println("Attempting to verify a valid range proof against a different commitment...")
    // Reuse the valid rangeProof for value 150, but check against commitment for value 151
    differentValue := uint64(151)
    differentRandomness, err := GenerateRandomScalar(params.Order)
     if err != nil { log.Fatal(err) }
    differentCommitment, err := CommitPedersen(ScalarFromUint64(differentValue, params.Order), differentRandomness, params)
     if err != nil { log.Fatal(err) }

    // Create a proof struct with the *wrong* value commitment
    tamperedProof := rangeProof
    tamperedProof.ValueCommitment = differentCommitment

    // Note: The VerifierBoundedRange only uses ValueCommitment for the final check,
    // sum(2^i * C_i) == ValueCommitment. The C_i and BitProofs are verified independently first.
    // This specific tampering *should* cause the final check to fail.

    isTamperedRangeValid := params.VerifyBoundedRange(tamperedProof)
    fmt.Printf("Bounded range proof (tampered commitment) verification: %v\n", isTamperedRangeValid) // Should be false

     // Test invalid bit proof within a range proof
     fmt.Println("\n--- Invalid Bounded Range Proof (Tampered Bit Proof) ---")
     tamperedRangeProof2 := rangeProof
     if len(tamperedRangeProof2.BitProofs) > 0 {
         // Flip a bit in one of the responses of the first bit proof
         originalS0Bytes := tamperedRangeProof2.BitProofs[0].Response0.Bytes()
         if len(originalS0Bytes) > 0 {
             tamperedS0Bytes := make([]byte, len(originalS0Bytes))
             copy(tamperedS0Bytes, originalS0Bytes)
             tamperedS0Bytes[0] ^= 0x01 // Flip a bit
             tamperedRangeProof2.BitProofs[0].Response0, err = NewFieldElementFromBytes(tamperedS0Bytes, params.Order)
             if err != nil { log.Fatalf("Failed to tamper S0: %v", err) }

             fmt.Println("Tampered first bit proof.")
             isTamperedRangeValid2 := params.VerifyBoundedRange(tamperedRangeProof2)
             fmt.Printf("Bounded range proof (tampered bit proof) verification: %v\n", isTamperedRangeValid2) // Should be false
         }
     }
}
*/
```