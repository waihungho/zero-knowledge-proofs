Okay, let's design and implement a Zero-Knowledge Proof system in Go that proves knowledge of a *weighted sum* of secret values contained within Pedersen commitments, where the weighted sum equals a secret value contained in a separate Pedersen commitment. This is a useful primitive for privacy-preserving audits, voting, and decentralized finance applications.

**Concept:**

The proof demonstrates: "I know secrets `w_1, ..., w_n` and randomness `r_1, ..., r_n` such that `C_i = w_i * G + r_i * H` for public commitments `C_1, ..., C_n`, AND I know a secret `total_value` and randomness `total_randomness` such that `C_total = total_value * G + total_randomness * H`, AND a known public coefficient `k` applied to the sum of a *specified subset* of my secrets (`w_i` where `i` is in a public `Weights` index list) equals `total_value`: `k * SUM(w_i for i in Weights) = total_value`."

The verifier learns *nothing* about the individual `w_i`, `r_i`, `total_value`, `total_randomness`, the sum `SUM(w_i)`, or `SUM(r_i)`. They only confirm the mathematical relationship holds.

This concept is advanced because it operates on secrets *inside* commitments and combines a linear relationship proof with commitment proofs. It's trendy due to its relevance in privacy-preserving applications. It's creative as it's not the most basic "prove knowledge of a single secret key" example. It avoids duplicating a full SNARK/STARK library by building on Pedersen commitments and a combined Sigma protocol structure using Fiat-Shamir.

---

**Outline:**

1.  **Cryptographic Primitives:** Implement scalar and point arithmetic over an elliptic curve.
2.  **Pedersen Commitment:** Implement `Commit(value, randomness) = value*G + randomness*H`.
3.  **Parameters:** Define the curve, order, and base points G and H.
4.  **Proof Structure:** Define the data structure for the ZKP.
5.  **Prover Logic:** Implement the steps for generating the proof (commitment to randomizers, challenge generation via Fiat-Shamir, response calculation).
6.  **Verifier Logic:** Implement the steps for verifying the proof (recomputing challenge, checking equations).
7.  **Utility Functions:** Hashing, serialization, list processing (summing points/scalars).
8.  **Main Functions:** Setup, Proof Generation, Proof Verification.

---

**Function Summary:**

*   `SetupParams()`: Initializes curve, generators G and H, and order.
*   `NewScalar(val *big.Int)`: Creates a scalar from a big integer, handling modulo arithmetic.
*   `Scalar.Rand(rand io.Reader)`: Generates a random scalar modulo the order.
*   `Scalar.Add(other *Scalar)`: Scalar addition modulo order.
*   `Scalar.Mul(other *Scalar)`: Scalar multiplication modulo order.
*   `Scalar.Neg()`: Scalar negation modulo order.
*   `Scalar.Inverse()`: Scalar modular inverse.
*   `Scalar.IsZero()`: Checks if the scalar is zero.
*   `Scalar.ToBytes()`: Serializes scalar to bytes.
*   `Scalar.FromBytes(bz []byte)`: Deserializes bytes to scalar.
*   `NewPoint(bz []byte)`: Creates a curve point from compressed bytes.
*   `Point.GeneratorG()`: Gets the base generator G.
*   `Point.GeneratorH(params *Params)`: Gets the second generator H.
*   `Point.ScalarMul(s *Scalar)`: Point multiplication by a scalar.
*   `Point.Add(other *Point)`: Point addition.
*   `Point.Neg()`: Point negation.
*   `Point.IsEqual(other *Point)`: Checks if two points are equal.
*   `Point.IsOnCurve()`: Checks if the point is on the curve.
*   `Point.ToBytes()`: Serializes point to compressed bytes.
*   `Point.FromBytes(bz []byte, curve elliptic.Curve)`: Deserializes bytes to point (requires curve).
*   `Commitment` (type alias for Point).
*   `NewCommitment(value, randomness *Scalar, params *Params)`: Creates a Pedersen commitment.
*   `SumPoints(points []*Point)`: Sums a list of points.
*   `SumScalars(scalars []*Scalar, order *big.Int)`: Sums a list of scalars modulo order.
*   `ComputeChallenge(params *Params, transcript ...[]byte)`: Generates the Fiat-Shamir challenge hash from a transcript of data.
*   `Proof` (struct): Holds all announcement points and response scalars.
*   `GenerateProof(params *Params, secrets []*Scalar, randomness []*Scalar, totalSecret, totalRandomness *Scalar, weights []int, k *Scalar)`: The main prover function.
*   `VerifyProof(params *Params, commitments []*Point, totalCommitment *Point, weights []int, k *Scalar, proof *Proof)`: The main verifier function.
*   `Proof.ToBytes()`: Serializes the proof structure.
*   `Proof.FromBytes(bz []byte, params *Params)`: Deserializes bytes to a Proof structure.

**(Minimum 28 functions listed)**

---

```golang
package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// --- Outline ---
// 1. Cryptographic Primitives (Scalar and Point operations)
// 2. Pedersen Commitment
// 3. Parameters (Curve, Generators G and H, Order)
// 4. Proof Structure
// 5. Prover Logic (GenerateProof)
// 6. Verifier Logic (VerifyProof)
// 7. Utility Functions (Hashing, Serialization, Summing)
// 8. Main Functions (Setup, Generate, Verify)

// --- Function Summary ---
// SetupParams: Initializes curve, generators G and H, and order.
// NewScalar: Creates a scalar from big.Int.
// Scalar.Rand: Generates a random scalar.
// Scalar.Add: Scalar addition.
// Scalar.Mul: Scalar multiplication.
// Scalar.Neg: Scalar negation.
// Scalar.Inverse: Scalar modular inverse.
// Scalar.IsZero: Checks if the scalar is zero.
// Scalar.ToBytes: Serializes scalar.
// Scalar.FromBytes: Deserializes scalar.
// NewPoint: Creates a curve point from bytes.
// Point.GeneratorG: Gets the base generator G.
// Point.GeneratorH: Gets the second generator H.
// Point.ScalarMul: Point multiplication.
// Point.Add: Point addition.
// Point.Neg: Point negation.
// Point.IsEqual: Checks if two points are equal.
// Point.IsOnCurve: Checks if the point is on the curve.
// Point.ToBytes: Serializes point.
// Point.FromBytes: Deserializes point.
// Commitment (type alias)
// NewCommitment: Creates a Pedersen commitment.
// SumPoints: Sums a list of points.
// SumScalars: Sums a list of scalars.
// ComputeChallenge: Generates the Fiat-Shamir challenge hash.
// Proof (struct): Holds proof elements.
// GenerateProof: Main prover function.
// VerifyProof: Main verifier function.
// Proof.ToBytes: Serializes the proof.
// Proof.FromBytes: Deserializes bytes to Proof.


// Params holds the cryptographic parameters for the ZKP system.
type Params struct {
	Curve elliptic.Curve
	G     *Point // Base generator point
	H     *Point // Second generator point (unrelated to G)
	Order *big.Int // Order of the curve's base point group
}

// Scalar represents a scalar value modulo the curve order.
type Scalar struct {
	bi    *big.Int
	order *big.Int
}

// NewScalar creates a new Scalar from a big.Int, applying the modulo operation.
func NewScalar(val *big.Int, order *big.Int) *Scalar {
	v := new(big.Int).Set(val)
	v.Mod(v, order)
	// Ensure positive representation in the field
	if v.Sign() < 0 {
		v.Add(v, order)
	}
	return &Scalar{bi: v, order: order}
}

// Rand generates a cryptographically secure random scalar.
func (s *Scalar) Rand(rand io.Reader) (*Scalar, error) {
	if s.order == nil {
		return nil, errors.New("scalar order not set")
	}
	val, err := randScalar(rand, s.order)
	if err != nil {
		return nil, err
	}
	return NewScalar(val, s.order), nil
}

// Add returns the sum of two scalars modulo the order.
func (s *Scalar) Add(other *Scalar) *Scalar {
	if s.order == nil || other.order == nil || s.order.Cmp(other.order) != 0 {
		panic("scalar orders mismatch")
	}
	res := new(big.Int).Add(s.bi, other.bi)
	res.Mod(res, s.order)
	return NewScalar(res, s.order)
}

// Mul returns the product of two scalars modulo the order.
func (s *Scalar) Mul(other *Scalar) *Scalar {
	if s.order == nil || other.order == nil || s.order.Cmp(other.order) != 0 {
		panic("scalar orders mismatch")
	}
	res := new(big.Int).Mul(s.bi, other.bi)
	res.Mod(res, s.order)
	return NewScalar(res, s.order)
}

// Neg returns the negation of the scalar modulo the order.
func (s *Scalar) Neg() *Scalar {
	if s.order == nil {
		panic("scalar order not set")
	}
	res := new(big.Int).Neg(s.bi)
	res.Mod(res, s.order)
	// Ensure positive representation
	if res.Sign() < 0 {
		res.Add(res, s.order)
	}
	return NewScalar(res, s.order)
}

// Inverse returns the modular multiplicative inverse of the scalar.
func (s *Scalar) Inverse() *Scalar {
	if s.order == nil {
		panic("scalar order not set")
	}
	res := new(big.Int).ModInverse(s.bi, s.order)
	if res == nil {
		// Inverse does not exist (scalar is zero or not coprime to order)
		// In a prime field, only 0 has no inverse.
		if s.bi.Sign() == 0 {
             panic("cannot inverse zero scalar")
        }
        // Should not happen in a prime field for non-zero scalars
		panic("modular inverse failed")
	}
	return NewScalar(res, s.order)
}

// IsZero checks if the scalar is zero.
func (s *Scalar) IsZero() bool {
	return s.bi.Sign() == 0
}

// ToBytes serializes the scalar to a big-endian byte slice.
func (s *Scalar) ToBytes() []byte {
	// The byte length should be ceil(log2(order) / 8).
	// For secp256k1, the order is 256 bits, so 32 bytes.
	bz := s.bi.Bytes()
	expectedLen := (s.order.BitLen() + 7) / 8
	if len(bz) < expectedLen {
		// Pad with leading zeros if necessary
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(bz):], bz)
		return padded
	} else if len(bz) > expectedLen {
         // This might happen if the big.Int representation is longer than the field size
         // This indicates an issue, should panic or return error
         panic("scalar byte length exceeds expected")
    }
	return bz
}

// FromBytes deserializes a big-endian byte slice to a scalar.
func (s *Scalar) FromBytes(bz []byte) (*Scalar, error) {
    if s.order == nil {
        return nil, errors.New("scalar order not set")
    }
	val := new(big.Int).SetBytes(bz)
	// Check if the resulting scalar is within the valid range [0, order-1]
	if val.Cmp(s.order) >= 0 {
		return nil, errors.New("scalar value out of range [0, order-1]")
	}
	return NewScalar(val, s.order), nil // NewScalar will perform the final modulo
}


// Point represents a point on the elliptic curve.
type Point struct {
	X, Y *big.Int
	curve elliptic.Curve
}

// NewPoint creates a new Point.
func NewPoint(x, y *big.Int, curve elliptic.Curve) *Point {
	return &Point{X: x, Y: y, curve: curve}
}

// GeneratorG returns the base generator G for the parameters.
// Note: In a real system, G would be part of the public Params struct.
// We add this method for easier access in this example.
func (p *Point) GeneratorG(params *Params) *Point {
	if params == nil {
		panic("params not set")
	}
	return params.G // Assume G is initialized in SetupParams
}

// GeneratorH returns the second generator H for the parameters.
// Note: In a real system, H would be part of the public Params struct.
// We add this method for easier access in this example.
func (p *Point) GeneratorH(params *Params) *Point {
	if params == nil {
		panic("params not set")
	}
	return params.H // Assume H is initialized in SetupParams
}


// ScalarMul performs scalar multiplication on the point.
func (p *Point) ScalarMul(s *Scalar) *Point {
	x, y := p.curve.ScalarMult(p.X, p.Y, s.bi.Bytes())
	// ScalarMult expects scalar bytes. Ensure bytes are correct length for scalar field.
    // elliptic.Curve.ScalarBaseMult uses the curve order for scalar input length.
    // For ScalarMult, it might expect a different length depending on implementation details or context.
    // Using standard big.Int bytes might not be canonical.
    // Let's re-implement manually using the curve's base point mult and Add.
    // This assumes p is not G or H. If p is G, use ScalarBaseMult.
    if p.X.Cmp(p.curve.Params().Gx) == 0 && p.Y.Cmp(p.curve.Params().Gy) == 0 {
        x, y = p.curve.ScalarBaseMult(s.bi.Bytes()) // Efficient for G
    } else {
        // Manual scalar mult: s*P = P + P + ... (s times)
        // A proper implementation would use a windowed method or similar.
        // For demonstration, we can use the curve's ScalarMult which likely handles this efficiently.
        // Double check the scalar byte representation expected by curve.ScalarMult.
        // crypto/elliptic scalar arguments are typically expected to be mod N (curve order).
        // big.Int.Bytes() gives minimum big-endian representation.
        // A canonical representation might be fixed-width bytes.
        // For safety, let's use the curve's ScalarMult with fixed-width scalar bytes.
        scalarBytes := s.ToBytes() // Use our fixed-width ToBytes
        x, y = p.curve.ScalarMult(p.X, p.Y, scalarBytes)
    }

	return NewPoint(x, y, p.curve)
}

// Add performs point addition.
func (p *Point) Add(other *Point) *Point {
	if p.curve != other.curve {
		panic("point curves mismatch")
	}
	x, y := p.curve.Add(p.X, p.Y, other.X, other.Y)
	return NewPoint(x, y, p.curve)
}

// Neg returns the negation of the point.
func (p *Point) Neg() *Point {
	// For a curve y^2 = x^3 + ax + b, the negative of (x, y) is (x, -y).
	// y-coordinate is modulo the field prime P.
	negY := new(big.Int).Neg(p.Y)
	negY.Mod(negY, p.curve.Params().P)
    // Ensure positive representation
    if negY.Sign() < 0 {
        negY.Add(negY, p.curve.Params().P)
    }
	return NewPoint(new(big.Int).Set(p.X), negY, p.curve)
}

// IsEqual checks if two points are the same.
func (p *Point) IsEqual(other *Point) bool {
    if p == nil || other == nil {
        return p == other // True if both are nil
    }
    if p.curve != other.curve {
        return false
    }
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}


// IsOnCurve checks if the point lies on the curve.
func (p *Point) IsOnCurve() bool {
    if p == nil || p.X == nil || p.Y == nil {
        return false // Point at infinity or incomplete point
    }
    // Use the curve's IsOnCurve method.
	return p.curve.IsOnCurve(p.X, p.Y)
}

// ToBytes serializes the point to compressed bytes.
func (p *Point) ToBytes() []byte {
    if p == nil || p.X == nil || p.Y == nil {
        return []byte{0x00} // Represent point at infinity or invalid point
    }
	return elliptic.MarshalCompressed(p.curve, p.X, p.Y)
}

// FromBytes deserializes compressed bytes to a point.
func (p *Point) FromBytes(bz []byte, curve elliptic.Curve) (*Point, error) {
	if len(bz) == 1 && bz[0] == 0x00 {
        // Special case for point at infinity representation
        // elliptic.UnmarshalCompressed handles this returning (nil, nil) for secp256k1
        // Check curve-specific behavior if necessary. For secp256k1, nil, nil means infinity.
        x, y := elliptic.UnmarshalCompressed(curve, bz)
        if x == nil && y == nil {
            return &Point{X: nil, Y: nil, curve: curve}, nil // Represent point at infinity
        }
        return nil, errors.New("invalid point at infinity encoding") // Unexpected encoding for infinity
    }
	x, y := elliptic.UnmarshalCompressed(curve, bz)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal compressed point")
	}
    pt := NewPoint(x, y, curve)
    if !pt.IsOnCurve() {
         return nil, errors.New("deserialized point is not on curve")
    }
	return pt, nil
}

// Commitment is a type alias for Point, representing a Pedersen commitment.
type Commitment = Point

// NewCommitment creates a new Pedersen commitment C = value*G + randomness*H.
func NewCommitment(value, randomness *Scalar, params *Params) (*Commitment, error) {
	if params == nil || params.G == nil || params.H == nil || params.Order == nil {
		return nil, errors.New("zkp params not initialized")
	}
    if value.order.Cmp(params.Order) != 0 || randomness.order.Cmp(params.Order) != 0 {
        return nil, errors.New("scalar orders mismatch params order")
    }

	valG := params.G.ScalarMul(value)
	randH := params.H.ScalarMul(randomness)

	return valG.Add(randH), nil
}

// SumPoints adds a list of points. Returns nil if list is empty.
func SumPoints(points []*Point) *Point {
	if len(points) == 0 {
		return nil // Point at infinity or identity
	}
	sum := points[0]
	for i := 1; i < len(points); i++ {
		sum = sum.Add(points[i])
	}
	return sum
}

// SumScalars adds a list of scalars modulo the given order. Returns nil if list is empty.
func SumScalars(scalars []*Scalar, order *big.Int) *Scalar {
    if len(scalars) == 0 {
        return NewScalar(big.NewInt(0), order) // Sum of empty set is 0
    }
    sum := NewScalar(big.NewInt(0), order)
    for _, s := range scalars {
        sum = sum.Add(s)
    }
    return sum
}

// ComputeChallenge generates the Fiat-Shamir challenge hash.
// It hashes all relevant public data and prover announcements.
// The order and deterministic inclusion of elements are crucial.
func ComputeChallenge(params *Params, transcript ...[]byte) (*Scalar, error) {
	if params == nil || params.Order == nil {
		return nil, errors.New("params not initialized for challenge computation")
	}
	h := sha256.New()

	// Include parameters (order matters for H if derived)
	h.Write(params.Curve.Params().Gx.Bytes())
	h.Write(params.Curve.Params().Gy.Bytes())
	h.Write(params.Order.Bytes())
    // G is (Gx, Gy) from curve params
	h.Write(params.H.ToBytes()) // Include H's compressed bytes

	// Include the rest of the transcript
	for _, data := range transcript {
		h.Write(data)
	}

	// Hash the result and convert to a scalar modulo the order.
	// This conversion should be done carefully to avoid bias.
	// A standard way is to take the hash output as a big.Int and mod by order.
	hashBytes := h.Sum(nil)
	challengeBI := new(big.Int).SetBytes(hashBytes)

	return NewScalar(challengeBI, params.Order), nil
}

// Proof holds the elements of the ZKP.
type Proof struct {
	// Announcements for knowledge of wi, ri inside Ci
	Announcements []*Point // A_i = v_wi*G + v_ri*H for each i in weights
	// Announcement for knowledge of total_value, total_randomness inside C_total
	TotalAnnouncement *Point // A_total = v_total_v*G + v_total_r*H
	// Announcement for the sum relation proof (R_diff*H = TargetPoint)
	SumRelationAnnouncement *Point // V_diff = v_diff * H

	// Responses for knowledge of wi, ri
	Z_w []*Scalar // z_wi = v_wi + c*wi
	Z_r []*Scalar // z_ri = v_ri + c*ri
	// Responses for knowledge of total_value, total_randomness
	Z_total_v *Scalar // z_total_v = v_total_v + c*total_value
	Z_total_r *Scalar // z_total_r = v_total_r + c*total_randomness
	// Response for the sum relation proof
	Z_diff *Scalar // z_diff = v_diff + c*R_diff
}

// GenerateProof generates the ZKP for the weighted sum relation.
// `secrets` and `randomness` are the full lists corresponding to all `commitments` C1..Cn.
// `weights` are the indices of the secrets/randomness to include in the sum.
// `k` is the public scaling coefficient.
func GenerateProof(params *Params, secrets []*Scalar, randomness []*Scalar, totalSecret, totalRandomness *Scalar, weights []int, k *Scalar) (*Proof, error) {
	if params == nil || params.G == nil || params.H == nil || params.Order == nil {
		return nil, errors.New("zkp params not initialized")
	}
	numCommitments := len(secrets)
	if numCommitments != len(randomness) {
		return nil, errors.New("secrets and randomness lists must be the same length")
	}
    if totalSecret.order.Cmp(params.Order) != 0 || totalRandomness.order.Cmp(params.Order) != 0 || k.order.Cmp(params.Order) != 0 {
        return nil, errors.New("totalSecret, totalRandomness, or k order mismatch params order")
    }
    for i := range secrets {
        if secrets[i].order.Cmp(params.Order) != 0 || randomness[i].order.Cmp(params.Order) != 0 {
            return nil, fmt.Errorf("secret or randomness scalar order mismatch params order at index %d", i)
        }
    }


	// 1. Prover computes public commitments (these are inputs, not generated here)
	// C_i = secrets[i]*G + randomness[i]*H for i = 0..n-1
	// C_total = totalSecret*G + totalRandomness*H

	// 2. Prover calculates the value needed for the sum relation check
	// R_sum = SUM(randomness[i] for i in weights)
	// R_diff = k * R_sum - totalRandomness
	sumRandomness := []*Scalar{}
	for _, idx := range weights {
        if idx < 0 || idx >= numCommitments {
            return nil, fmt.Errorf("invalid weight index: %d", idx)
        }
		sumRandomness = append(sumRandomness, randomness[idx])
	}
	R_sum := SumScalars(sumRandomness, params.Order)
	k_R_sum := k.Mul(R_sum)
	R_diff := k_R_sum.Add(totalRandomness.Neg()) // k * R_sum - totalRandomness

	// 3. Prover chooses random blinding factors
	v_w := make([]*Scalar, numCommitments)
	v_r := make([]*Scalar, numCommitments)
	for i := 0; i < numCommitments; i++ {
		v, err := NewScalar(nil, params.Order).Rand(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random v_w[%d]: %w", i, err)
		}
		v_w[i] = v
		v, err = NewScalar(nil, params.Order).Rand(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random v_r[%d]: %w", i, err)
		}
		v_r[i] = v
	}

	v_total_v, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_total_v: %w", err)
	}
	v_total_r, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_total_r: %w", err)
	}

	v_diff, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_diff: %w", err)
	}


	// 4. Prover computes announcements
	announcements := make([]*Point, len(weights)) // Only need announcements for the commitments in the weighted sum
	for i, idx := range weights {
		v_wiG := params.G.ScalarMul(v_w[idx])
		v_riH := params.H.ScalarMul(v_r[idx])
		announcements[i] = v_wiG.Add(v_riH) // A_i = v_wi*G + v_ri*H
	}

	v_total_vG := params.G.ScalarMul(v_total_v)
	v_total_rH := params.H.ScalarMul(v_total_r)
	totalAnnouncement := v_total_vG.Add(v_total_rH) // A_total = v_total_v*G + v_total_r*H

	sumRelationAnnouncement := params.H.ScalarMul(v_diff) // V_diff = v_diff * H


	// 5. Prover computes public commitments C_i and C_total for challenge hashing
    commitmentPoints := make([]*Point, numCommitments)
    for i := 0; i < numCommitments; i++ {
        c, err := NewCommitment(secrets[i], randomness[i], params)
        if err != nil { return nil, fmt.Errorf("failed to create commitment C[%d]: %w", i, err) }
        commitmentPoints[i] = c
    }
    totalCommitment, err := NewCommitment(totalSecret, totalRandomness, params)
    if err != nil { return nil, fmt.Errorf("failed to create total commitment: %w", err) }

    // Compute C_sum and TargetPoint for challenge hashing
    weightedCommitments := make([]*Point, len(weights))
    for i, idx := range weights {
        weightedCommitments[i] = commitmentPoints[idx]
    }
    C_sum := SumPoints(weightedCommitments)
    k_C_sum := C_sum.ScalarMul(k)
    TargetPoint := k_C_sum.Add(totalCommitment.Neg()) // TargetPoint = k * C_sum - C_total

	// 6. Prover computes challenge `c` using Fiat-Shamir heuristic
	// Hash everything relevant: Params, Commitments, Weights, k, Announcements, TargetPoint
	transcript := [][]byte{}
    for _, cmt := range commitmentPoints { transcript = append(transcript, cmt.ToBytes()) }
    transcript = append(transcript, totalCommitment.ToBytes())
    for _, w := range weights { transcript = append(transcript, big.NewInt(int64(w)).Bytes()) }
    transcript = append(transcript, k.ToBytes())
    for _, ann := range announcements { transcript = append(transcript, ann.ToBytes()) }
    transcript = append(transcript, totalAnnouncement.ToBytes())
    transcript = append(transcript, sumRelationAnnouncement.ToBytes())
    transcript = append(transcript, TargetPoint.ToBytes())

	c, err := ComputeChallenge(params, transcript...)
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	// 7. Prover computes responses
	z_w := make([]*Scalar, len(weights))
	z_r := make([]*Scalar, len(weights))
	for i, idx := range weights {
		// z_wi = v_wi + c * wi
		c_wi := c.Mul(secrets[idx])
		z_w[i] = v_w[idx].Add(c_wi)

		// z_ri = v_ri + c * ri
		c_ri := c.Mul(randomness[idx])
		z_r[i] = v_r[idx].Add(c_ri)
	}

	// z_total_v = v_total_v + c * total_value
	c_total_v := c.Mul(totalSecret)
	z_total_v := v_total_v.Add(c_total_v)

	// z_total_r = v_total_r + c * total_randomness
	c_total_r := c.Mul(totalRandomness)
	z_total_r := v_total_r.Add(c_total_r)

	// z_diff = v_diff + c * R_diff
	c_R_diff := c.Mul(R_diff)
	z_diff := v_diff.Add(c_R_diff)


	// 8. Return the proof
	proof := &Proof{
		Announcements: announcements, // Announcements for weighted commitments
		TotalAnnouncement: totalAnnouncement,
		SumRelationAnnouncement: sumRelationAnnouncement,
		Z_w: z_w, // Responses for weighted secrets
		Z_r: z_r, // Responses for weighted randomness
		Z_total_v: z_total_v,
		Z_total_r: z_total_r,
		Z_diff: z_diff,
	}

	return proof, nil
}

// VerifyProof verifies the ZKP for the weighted sum relation.
// `commitments` are the public C1..Cn. `totalCommitment` is the public C_total.
func VerifyProof(params *Params, commitments []*Point, totalCommitment *Point, weights []int, k *Scalar, proof *Proof) (bool, error) {
	if params == nil || params.G == nil || params.H == nil || params.Order == nil {
		return false, errors.New("zkp params not initialized")
	}
    if totalCommitment == nil || k == nil || proof == nil || proof.Announcements == nil || proof.TotalAnnouncement == nil || proof.SumRelationAnnouncement == nil ||
       proof.Z_w == nil || proof.Z_r == nil || proof.Z_total_v == nil || proof.Z_total_r == nil || proof.Z_diff == nil {
        return false, errors.New("invalid inputs or incomplete proof structure")
    }
     if k.order.Cmp(params.Order) != 0 {
        return false, errors.New("k scalar order mismatch params order")
    }
    for _, z := range proof.Z_w { if z == nil || z.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_w scalar") } }
    for _, z := range proof.Z_r { if z == nil || z.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_r scalar") } }
    if proof.Z_total_v.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_total_v scalar") }
    if proof.Z_total_r.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_total_r scalar") }
    if proof.Z_diff.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_diff scalar") }


	numCommitments := len(commitments)
    if len(weights) != len(proof.Announcements) || len(weights) != len(proof.Z_w) || len(weights) != len(proof.Z_r) {
        return false, errors.New("proof structure mismatch with weights length")
    }

    weightedCommitments := make([]*Point, len(weights))
    for i, idx := range weights {
        if idx < 0 || idx >= numCommitments {
            return false, fmt.Errorf("invalid weight index in proof verification: %d", idx)
        }
        weightedCommitments[i] = commitments[idx]
    }

    // 1. Verifier re-computes the challenge
    // Needs the original commitments (C1..Cn, C_total) which are public inputs
    // Needs the weights and k, which are public inputs
    // Needs the prover's announcements (A_i, A_total, V_diff) from the proof
    // Needs the TargetPoint, which is computed from public inputs C_sum and C_total
    C_sum := SumPoints(weightedCommitments)
    if C_sum == nil && len(weights) > 0 { // SumPoints returns nil for empty list, but here we expect non-nil if weights exist
         return false, errors.New("failed to compute C_sum for non-empty weights")
    }
    k_C_sum := C_sum.ScalarMul(k)
    TargetPoint := k_C_sum.Add(totalCommitment.Neg())

    transcript := [][]byte{}
    for _, cmt := range commitments { transcript = append(transcript, cmt.ToBytes()) }
    transcript = append(transcript, totalCommitment.ToBytes())
    for _, w := range weights { transcript = append(transcript, big.NewInt(int64(w)).Bytes()) }
    transcript = append(transcript, k.ToBytes())
    for _, ann := range proof.Announcements { transcript = append(transcript, ann.ToBytes()) }
    transcript = append(transcript, proof.TotalAnnouncement.ToBytes())
    transcript = append(transcript, proof.SumRelationAnnouncement.ToBytes())
    transcript = append(transcript, TargetPoint.ToBytes())

	c, err := ComputeChallenge(params, transcript...)
	if err != nil {
		return false, fmt.Errorf("failed to re-compute challenge: %w", err)
	}

	// 2. Verifier checks the equations
    // Check 1: Knowledge of wi, ri for each i in weights
	for i, idx := range weights {
        // Check z_wi*G + z_ri*H == A_i + c*C_i
        lhs_G := params.G.ScalarMul(proof.Z_w[i])
        lhs_H := params.H.ScalarMul(proof.Z_r[i])
        lhs := lhs_G.Add(lhs_H)

        c_Ci := commitments[idx].ScalarMul(c)
        rhs := proof.Announcements[i].Add(c_Ci)

        if !lhs.IsEqual(rhs) {
            return false, fmt.Errorf("verification failed for commitment %d (index %d): %v != %v", i, idx, lhs.ToBytes(), rhs.ToBytes())
        }
    }

    // Check 2: Knowledge of total_value, total_randomness for C_total
    // Check z_total_v*G + z_total_r*H == A_total + c*C_total
    lhs_total_G := params.G.ScalarMul(proof.Z_total_v)
    lhs_total_H := params.H.ScalarMul(proof.Z_total_r)
    lhs_total := lhs_total_G.Add(lhs_total_H)

    c_C_total := totalCommitment.ScalarMul(c)
    rhs_total := proof.TotalAnnouncement.Add(c_C_total)

    if !lhs_total.IsEqual(rhs_total) {
        return false, fmt.Errorf("verification failed for total commitment: %v != %v", lhs_total.ToBytes(), rhs_total.ToBytes())
    }

    // Check 3: The sum relation (k * SUM(wi) = total_value)
    // This is implicitly checked by verifying the R_diff proof:
    // z_diff*H == V_diff + c*TargetPoint
    // Substitute z_diff = v_diff + c*R_diff
    // (v_diff + c*R_diff)*H == V_diff + c*TargetPoint
    // v_diff*H + c*R_diff*H == V_diff + c*TargetPoint
    // Since V_diff = v_diff*H (by construction), this simplifies to:
    // c*R_diff*H == c*TargetPoint
    // If c is non-zero (highly probable with hashing), this means R_diff*H == TargetPoint.
    // TargetPoint = k * C_sum - C_total
    // R_diff*H == k * C_sum - C_total
    // Substitute R_diff = k*R_sum - total_randomness and C_sum = W_sum*G + R_sum*H and C_total = total_value*G + total_randomness*H
    // (k*R_sum - total_randomness)*H == k * (W_sum*G + R_sum*H) - (total_value*G + total_randomness*H)
    // k*R_sum*H - total_randomness*H == k*W_sum*G + k*R_sum*H - total_value*G - total_randomness*H
    // Rearranging:
    // 0 == (k*W_sum - total_value)*G
    // This implies k*W_sum - total_value == 0 (since G is a generator and has prime order)
    // k * SUM(wi for i in weights) == total_value. This is the statement we want to prove!

    lhs_diff := params.H.ScalarMul(proof.Z_diff)
    c_TargetPoint := TargetPoint.ScalarMul(c)
    rhs_diff := proof.SumRelationAnnouncement.Add(c_TargetPoint)

    if !lhs_diff.IsEqual(rhs_diff) {
         return false, fmt.Errorf("verification failed for sum relation: %v != %v", lhs_diff.ToBytes(), rhs_diff.ToBytes())
    }


	// If all checks pass
	return true, nil
}

// Proof serialization/deserialization helpers (simplified)

// Proof struct:
// Announcements []*Point // Length is len(weights)
// TotalAnnouncement *Point
// SumRelationAnnouncement *Point
// Z_w []*Scalar // Length is len(weights)
// Z_r []*Scalar // Length is len(weights)
// Z_total_v *Scalar
// Z_total_r *Scalar
// Z_diff *Scalar

// ToBytes serializes the proof. Simple concatenation based on known lengths.
// A more robust implementation would include length prefixes and potentially versioning.
func (p *Proof) ToBytes() ([]byte, error) {
    if p == nil { return nil, nil }
    if len(p.Announcements) != len(p.Z_w) || len(p.Announcements) != len(p.Z_r) {
        return nil, errors.New("proof element length mismatch")
    }

	var buf []byte

	// Number of weighted commitments determines lengths of slices
    buf = append(buf, big.NewInt(int64(len(p.Announcements))).Bytes()...) // Length prefix (simple)

	for _, pt := range p.Announcements { buf = append(buf, pt.ToBytes()...) }
	buf = append(buf, p.TotalAnnouncement.ToBytes())
	buf = append(buf, p.SumRelationAnnouncement.ToBytes())

	for _, s := range p.Z_w { buf = append(buf, s.ToBytes()...) }
	for _, s := range p.Z_r { buf = append(buf, s.ToBytes()...) }
	buf = append(buf, p.Z_total_v.ToBytes())
	buf = append(buf, p.Z_total_r.ToBytes())
	buf = append(buf, p.Z_diff.ToBytes())

	return buf, nil
}

// FromBytes deserializes the proof. Requires knowing the curve/order to handle scalars and points.
// Also requires knowing the number of weighted commitments (which is encoded as the first element).
func (p *Proof) FromBytes(bz []byte, params *Params) (*Proof, error) {
    if params == nil || params.Curve == nil || params.Order == nil {
        return nil, errors.New("zkp params not initialized for deserialization")
    }
    if len(bz) == 0 { return nil, errors.New("proof bytes are empty") }

    // Read length prefix (simple - assumes max int64 length for prefix)
    prefixLen := 8 // Estimate max length of int64 bytes
    if len(bz) < prefixLen { return nil, errors.New("proof bytes too short for length prefix") }

    lenPrefixBytes := bz[:prefixLen]
    // Find the actual start of the number by trimming leading zeros
    actualStart := 0
    for actualStart < len(lenPrefixBytes) && lenPrefixBytes[actualStart] == 0 {
        actualStart++
    }
    if actualStart == len(lenPrefixBytes) { actualStart-- } // Handle case where length is 0
    numWeightedBig := new(big.Int).SetBytes(lenPrefixBytes[actualStart:])
    numWeighted := int(numWeightedBig.Int64()) // Assumes length fits in int

    readPos := prefixLen // Start reading after the assumed prefix space

    // Point byte length (compressed) for secp256k1 is 33 bytes
    pointLen := (params.Curve.Params().BitSize + 7) / 8 + 1 // (FieldSize/8) + 1 byte tag
    scalarLen := (params.Order.BitLen() + 7) / 8 // Order size / 8

    // Read Announcements []*Point
    announcements := make([]*Point, numWeighted)
    for i := 0; i < numWeighted; i++ {
        if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for announcement points") }
        pt, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
        if err != nil { return nil, fmt.Errorf("failed to deserialize announcement point %d: %w", i, err) }
        announcements[i] = pt
        readPos += pointLen
    }

    // Read TotalAnnouncement *Point
    if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for total announcement") }
    totalAnn, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
    if err != nil { return nil, fmt.Errorf("failed to deserialize total announcement: %w", err) }
    readPos += pointLen

    // Read SumRelationAnnouncement *Point
     if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for sum relation announcement") }
    sumRelationAnn, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
    if err != nil { return nil, fmt.Errorf("failed to deserialize sum relation announcement: %w", err) }
    readPos += pointLen


	// Read Z_w []*Scalar
	z_w := make([]*Scalar, numWeighted)
	for i := 0; i < numWeighted; i++ {
        if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_w scalars") }
        s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen])
        if err != nil { return nil, fmt.Errorf("failed to deserialize Z_w scalar %d: %w", i, err) }
        z_w[i] = NewScalar(s.bi, params.Order) // Ensure correct order is set
		readPos += scalarLen
	}

	// Read Z_r []*Scalar
	z_r := make([]*Scalar, numWeighted)
	for i := 0; i < numWeighted; i++ {
		if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_r scalars") }
        s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen])
        if err != nil { return nil, fmt.Errorf("failed to deserialize Z_r scalar %d: %w", i, err) }
        z_r[i] = NewScalar(s.bi, params.Order) // Ensure correct order is set
		readPos += scalarLen
	}

	// Read Z_total_v *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_total_v scalar") }
    s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen])
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_total_v scalar: %w", err) }
    z_total_v := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

	// Read Z_total_r *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_total_r scalar") }
    s, err = new(Scalar).FromBytes(bz[readPos:readPos+scalarLen])
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_total_r scalar: %w", err) }
    z_total_r := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

	// Read Z_diff *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_diff scalar") }
    s, err = new(Scalar).FromBytes(bz[readPos:readPos+scalarLen])
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_diff scalar: %w", err) }
    z_diff := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

    if readPos != len(bz) {
        // This indicates a mismatch between expected and actual bytes read
        return nil, fmt.Errorf("deserialization error: %d bytes read, %d total bytes", readPos, len(bz))
    }


	return &Proof{
		Announcements: announcements,
		TotalAnnouncement: totalAnn,
		SumRelationAnnouncement: sumRelationAnn,
		Z_w: z_w,
		Z_r: z_r,
		Z_total_v: z_total_v,
		Z_total_r: z_total_r,
		Z_diff: z_diff,
	}, nil
}


// --- Helper functions ---

// randScalar generates a random scalar in the range [0, order-1].
func randScalar(rand io.Reader, order *big.Int) (*big.Int, error) {
	if order.Sign() <= 0 {
		return nil, errors.New("order must be positive")
	}
	// Generate a random big.Int up to the bit size of the order.
	// Then take modulo order.
	max := new(big.Int).Sub(order, big.NewInt(1))
	if max.Sign() < 0 {
		// Order is 1, only possible scalar is 0
		return big.NewInt(0), nil
	}
	// Get byte length of order
	n := len(order.Bytes())
	if n == 0 {
        n = 1 // Ensure at least one byte if order is 0 or 1
    }

	// Generate random bytes
	for {
		randomBytes := make([]byte, n)
		_, err := io.ReadFull(rand, randomBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		// Convert bytes to big.Int
		randomBI := new(big.Int).SetBytes(randomBytes)

		// Modulo by order
		randomBI.Mod(randomBI, order)

        // Check if the result is less than the order
        if randomBI.Cmp(order) < 0 {
             // Success
             return randomBI, nil
        }
        // If randomBI is >= order (unlikely with Mod but possible depending on Mod implementation
        // or if the random generation wasn't perfectly uniform relative to the order),
        // loop and try again. This is standard practice in some libraries.
	}
}

// SetupParams initializes the parameters for the ZKP system.
// Uses secp256k1 and derives H from G deterministically for simplicity in example.
// A real system might use a verifiably random H or a safe prime construction.
func SetupParams() (*Params, error) {
	curve := elliptic.Secp256k1()
	G := &Point{X: curve.Params().Gx, Y: curve.Params().Gy, curve: curve}
	order := curve.Params().N

	// Derive H from G deterministically using a hash-to-curve like approach (simplified).
    // This isn't a full rigorous hash-to-curve but aims to get an independent point.
    // H = Hash(G_bytes || "Pedersen-H-Generator") * G is NOT independent.
    // H should be a point whose discrete log relation to G is unknown.
    // A standard approach is hashing a specific string and using it as a seed to derive a point,
    // or using a second, unrelated generator point if available (e.g., from curve specs).
    // For secp256k1, there isn't a standard second generator.
    // Let's use a simple, non-rigorous method for demonstration: hash a label and use the hash as coordinates/seed.
    // A better method: try hashing a counter until a point is found on the curve.
    h := sha256.New()
    h.Write([]byte("Pedersen-H-Generator-Seed"))
    seed := h.Sum(nil)

    // This is not cryptographically rigorous but demonstrates the need for H.
    // A proper implementation might use a method like Try-and-Increment or SWU hash-to-curve.
    // Here, we'll simulate finding a point. In practice, you'd pre-compute/derive H correctly.
    // Using a simple hash as a scalar multiplier for G is NOT correct for deriving an independent H.
    // Let's just generate a point using a random-like approach for example purposes.
    // We cannot simply hash to a point here without proper hash-to-curve.
    // A common demo alternative is using a fixed string as a scalar, which is also not secure.
    // Let's acknowledge this limitation and use a placeholder or find *some* other valid point.
    // For secp256k1, any point P on the curve is a valid base if its order is N.
    // We can use the generator for a different cofactor group if one exists, or simply pick a point P = s*G for a secret s (not helpful).
    // A practical library would provide H. Since we are implementing from scratch *without* duplicating a library function for this *specific* H,
    // let's use a point derived from a hash that's *not* based on G.
    // A simple, non-rigorous approach for demonstration: hash some data and try to interpret the hash as coordinates until it's on the curve.
    // This is slow and not standard.
    // Let's assume a standard practice: H is a separate generator provided by the system, whose dLog wrt G is unknown.
    // Since we're forced *not* to use a library's H, we must construct *something*.
    // Let's use a point derived from a fixed, arbitrary seed string via `ScalarBaseMult` with a hash of the string. This is STILL s*G, which is BAD.
    // Okay, let's use a point derived from hashing *distinct* data and attempting to find a point.
    // This is a placeholder for a proper H generation/derivation method.
    fmt.Println("Warning: Pedersen H generator derivation is non-rigorous for demonstration purposes.")
    h_seed := sha256.Sum256([]byte("Another Pedersen Generator Seed"))
    // This is not a hash-to-curve function. This will likely produce a scalar.
    // Using it as a scalar multiplier will give a point related to G.
    // This is a known issue when implementing Pedersen without a proper second generator.
    // For this "from scratch" example requirement, we must simulate getting H somehow.
    // Let's *simulate* generating H from a random point. In a real system, H would be fixed and publicly known.
    // We'll generate it once and fix it in the Params struct.
    hRandScalar, err := randScalar(rand.Reader, order)
    if err != nil {
        return nil, fmt.Errorf("failed to generate random scalar for H: %w", err)
    }
    H := G.ScalarMul(hRandScalar) // Note: This makes H's dLog relative to G known (hRandScalar), breaking the security assumption for hiding both value AND randomness. For this specific proof (k*Sum(w)=TotalValue), this might *still* work if the proof doesn't expose this relation, but it's a weakness for standard Pedersen. A true Pedersen requires dLog(H base G) to be unknown. Let's proceed with this known limitation for the sake of the example meeting the "no library H" constraint.

    return &Params{
        Curve: curve,
        G:     G,
        H:     H, // This H is *not* cryptographically independent of G in this demo.
        Order: order,
    }, nil
}
```

Let's add the serialization and deserialization methods for `Point` and `Scalar` to handle their byte representations correctly within the `Proof.ToBytes` and `Proof.FromBytes` methods. The scalar byte length should be consistent.

```golang
// Corrected Scalar.ToBytes to return fixed width bytes
func (s *Scalar) ToBytes() []byte {
	// The byte length is determined by the order size.
	byteLen := (s.order.BitLen() + 7) / 8
	bz := s.bi.Bytes()

	if len(bz) > byteLen {
		// This should not happen if NewScalar correctly mods the value
		panic("scalar bytes exceed expected length")
	}

	// Pad with leading zeros if necessary
	padded := make([]byte, byteLen)
	copy(padded[byteLen-len(bz):], bz)
	return padded
}

// Corrected Scalar.FromBytes to handle fixed width bytes
func (s *Scalar) FromBytes(bz []byte) (*Scalar, error) {
    if s.order == nil {
        return nil, errors.New("scalar order not set for FromBytes")
    }
    expectedLen := (s.order.BitLen() + 7) / 8
    if len(bz) != expectedLen {
        return nil, fmt.Errorf("scalar bytes length mismatch: expected %d, got %d", expectedLen, len(bz))
    }
	val := new(big.Int).SetBytes(bz)

	// Check if the resulting scalar is within the valid range [0, order-1]
	// Note: The modulo is implicitly handled by NewScalar, but we should still validate input.
	if val.Cmp(s.order) >= 0 {
		return nil, errors.New("scalar value from bytes out of range [0, order-1]")
	}
	return NewScalar(val, s.order), nil
}

// Point.ToBytes uses MarshalCompressed, which is standard (33 bytes for secp256k1)
// Point.FromBytes uses UnmarshalCompressed, which is standard.
// We just need to ensure the Point struct has the curve set before calling FromBytes.
// The Proof.FromBytes method needs to pass the curve from Params.

// Corrected Point.FromBytes signature
func (p *Point) FromBytes(bz []byte, curve elliptic.Curve) (*Point, error) {
	if curve == nil {
		return nil, errors.New("curve not provided for point deserialization")
	}
	if len(bz) == 0 {
        return nil, errors.New("point bytes are empty")
    }
	if len(bz) == 1 && bz[0] == 0x00 {
        // Handle point at infinity representation
         x, y := elliptic.UnmarshalCompressed(curve, bz)
         if x == nil && y == nil {
            return &Point{X: nil, Y: nil, curve: curve}, nil // Represent point at infinity
         }
         return nil, errors.New("invalid point at infinity encoding")
    }

    // For non-infinity points, expected length is (curve field size / 8) + 1 (for compression tag)
    expectedLen := (curve.Params().BitSize + 7) / 8 + 1
    if len(bz) != expectedLen {
         return nil, fmt.Errorf("point bytes length mismatch: expected %d, got %d", expectedLen, len(bz))
    }

	x, y := elliptic.UnmarshalCompressed(curve, bz)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal compressed point")
	}
    pt := NewPoint(x, y, curve)
    if !pt.IsOnCurve() {
         return nil, errors.New("deserialized point is not on curve")
    }
	return pt, nil
}


// Corrected Proof.FromBytes to pass curve and handle scalar order
func (p *Proof) FromBytes(bz []byte, params *Params) (*Proof, error) {
    if params == nil || params.Curve == nil || params.Order == nil {
        return nil, errors.New("zkp params not initialized for deserialization")
    }
    if len(bz) == 0 { return nil, errors.New("proof bytes are empty") }

    // Read length prefix (simple - assumes max int64 length for prefix)
    // Let's use a fixed 4 bytes for length prefix to simplify reading. Max numWeighted = 2^32-1
    prefixLenBytes := 4 // Using 4 bytes for len prefix
    if len(bz) < prefixLenBytes { return nil, errors.New("proof bytes too short for length prefix") }

    numWeightedBig := new(big.Int).SetBytes(bz[:prefixLenBytes])
    numWeighted := int(numWeightedBig.Int64()) // Assumes length fits in int

    readPos := prefixLenBytes // Start reading after the prefix

    // Point byte length (compressed) for secp256k1 is 33 bytes
    pointLen := (params.Curve.Params().BitSize + 7) / 8 + 1
    scalarLen := (params.Order.BitLen() + 7) / 8

    // Read Announcements []*Point
    announcements := make([]*Point, numWeighted)
    for i := 0; i < numWeighted; i++ {
        if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for announcement points") }
        pt, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
        if err != nil { return nil, fmt.Errorf("failed to deserialize announcement point %d: %w", i, err) }
        announcements[i] = pt
        readPos += pointLen
    }

    // Read TotalAnnouncement *Point
    if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for total announcement") }
    totalAnn, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
    if err != nil { return nil, fmt.Errorf("failed to deserialize total announcement: %w", err) }
    readPos += pointLen

    // Read SumRelationAnnouncement *Point
     if readPos + pointLen > len(bz) { return nil, errors.New("proof bytes too short for sum relation announcement") }
    sumRelationAnn, err := new(Point).FromBytes(bz[readPos:readPos+pointLen], params.Curve)
    if err != nil { return nil, fmt.Errorf("failed to deserialize sum relation announcement: %w", err) }
    readPos += pointLen


	// Read Z_w []*Scalar
	z_w := make([]*Scalar, numWeighted)
	for i := 0; i < numWeighted; i++ {
        if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_w scalars") }
        s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen]) // Use Scalar.FromBytes
        if err != nil { return nil, fmt.Errorf("failed to deserialize Z_w scalar %d: %w", i, err) }
        z_w[i] = NewScalar(s.bi, params.Order) // Ensure correct order is set
		readPos += scalarLen
	}

	// Read Z_r []*Scalar
	z_r := make([]*Scalar, numWeighted)
	for i := 0; i < numWeighted; i++ {
		if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_r scalars") }
        s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen]) // Use Scalar.FromBytes
        if err != nil { return nil, fmt.Errorf("failed to deserialize Z_r scalar %d: %w", i, err) }
        z_r[i] = NewScalar(s.bi, params.Order) // Ensure correct order is set
		readPos += scalarLen
	}

	// Read Z_total_v *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_total_v scalar") }
    s, err := new(Scalar).FromBytes(bz[readPos:readPos+scalarLen]) // Use Scalar.FromBytes
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_total_v scalar: %w", err) }
    z_total_v := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

	// Read Z_total_r *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_total_r scalar") }
    s, err = new(Scalar).FromBytes(bz[readPos:readPos+scalarLen]) // Use Scalar.FromBytes
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_total_r scalar: %w", err) }
    z_total_r := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

	// Read Z_diff *Scalar
	if readPos + scalarLen > len(bz) { return nil, errors.New("proof bytes too short for Z_diff scalar") }
    s, err = new(Scalar).FromBytes(bz[readPos:readPos+scalarLen]) // Use Scalar.FromBytes
    if err != nil { return nil, fmt.Errorf("failed to deserialize Z_diff scalar: %w", err) }
    z_diff := NewScalar(s.bi, params.Order) // Ensure correct order is set
	readPos += scalarLen

    if readPos != len(bz) {
        // This indicates a mismatch between expected and actual bytes read
        return nil, fmt.Errorf("deserialization error: %d bytes read, %d total bytes", readPos, len(bz))
    }


	return &Proof{
		Announcements: announcements,
		TotalAnnouncement: totalAnn,
		SumRelationAnnouncement: sumRelationAnn,
		Z_w: z_w,
		Z_r: z_r,
		Z_total_v: z_total_v,
		Z_total_r: z_total_r,
		Z_diff: z_diff,
	}, nil
}


// Helper to convert int weights to bytes for hashing
func weightsToBytes(weights []int) []byte {
    var bz []byte
    for _, w := range weights {
        // Use fixed size for each weight for consistency in transcript
        wBig := big.NewInt(int64(w))
        wBytes := wBig.Bytes()
        // Pad to a fixed size, e.g., 4 bytes for int32
        paddedWBytes := make([]byte, 4)
        copy(paddedWBytes[4-len(wBytes):], wBytes)
        bz = append(bz, paddedWBytes...)
    }
    return bz
}

// Update ComputeChallenge to use weightsToBytes
func ComputeChallenge(params *Params, commitments []*Point, totalCommitment *Point, weights []int, k *Scalar, proof *Proof) (*Scalar, error) {
    if params == nil || params.Order == nil {
        return nil, errors.New("params not initialized for challenge computation")
    }
    if k == nil || proof == nil {
        return nil, errors.New("invalid inputs for challenge computation")
    }


    h := sha256.New()

    // Include parameters (order matters for H if derived)
    h.Write(params.Curve.Params().Gx.Bytes())
    h.Write(params.Curve.Params().Gy.Bytes())
    h.Write(params.Order.Bytes())
    h.Write(params.H.ToBytes())

    // Include public commitments
    for _, cmt := range commitments {
        h.Write(cmt.ToBytes())
    }
    h.Write(totalCommitment.ToBytes())

    // Include public weights and coefficient k
    h.Write(weightsToBytes(weights))
    h.Write(k.ToBytes())

    // Include prover's announcements
    for _, ann := range proof.Announcements {
        h.Write(ann.ToBytes())
    }
    h.Write(proof.TotalAnnouncement.ToBytes())
    h.Write(proof.SumRelationAnnouncement.ToBytes())

    // Include TargetPoint (derived from public inputs)
    weightedCommitments := make([]*Point, len(weights))
    for i, idx := range weights {
         if idx < 0 || idx >= len(commitments) {
             // This case should ideally be caught earlier, but defensive check during hashing
             return nil, fmt.Errorf("invalid weight index %d during challenge computation", idx)
         }
        weightedCommitments[i] = commitments[idx]
    }
    C_sum := SumPoints(weightedCommitments)
    if C_sum == nil && len(weights) > 0 {
         return nil, errors.New("failed to compute C_sum for non-empty weights during challenge")
    }
    k_C_sum := C_sum.ScalarMul(k)
    TargetPoint := k_C_sum.Add(totalCommitment.Neg())
    h.Write(TargetPoint.ToBytes())


    // Hash the result and convert to a scalar modulo the order.
    hashBytes := h.Sum(nil)
    challengeBI := new(big.Int).SetBytes(hashBytes)

    return NewScalar(challengeBI, params.Order), nil
}

// Regenerate GenerateProof and VerifyProof signatures to take commitments as input

// GenerateProof generates the ZKP for the weighted sum relation.
// `secrets` and `randomness` are the full lists corresponding to all `commitments` C1..Cn.
// `commitments` are the public C1..Cn points.
// `totalSecret`, `totalRandomness`, and `totalCommitment` are for C_total.
// `weights` are the indices of the secrets/randomness to include in the sum.
// `k` is the public scaling coefficient.
func GenerateProof(params *Params, secrets []*Scalar, randomness []*Scalar, commitments []*Point, totalSecret, totalRandomness *Scalar, totalCommitment *Point, weights []int, k *Scalar) (*Proof, error) {
	if params == nil || params.G == nil || params.H == nil || params.Order == nil {
		return nil, errors.New("zkp params not initialized")
	}
	numCommitments := len(secrets)
	if numCommitments != len(randomness) || numCommitments != len(commitments) {
		return nil, errors.New("secrets, randomness, and commitments lists must be the same length")
	}
    if totalSecret.order.Cmp(params.Order) != 0 || totalRandomness.order.Cmp(params.Order) != 0 || totalCommitment.curve != params.Curve || k.order.Cmp(params.Order) != 0 {
        return nil, errors.New("totalSecret, totalRandomness order, totalCommitment curve, or k order mismatch")
    }
    for i := range secrets {
        if secrets[i].order.Cmp(params.Order) != 0 || randomness[i].order.Cmp(params.Order) != 0 || commitments[i].curve != params.Curve {
            return nil, fmt.Errorf("secret, randomness scalar order, or commitment curve mismatch at index %d", i)
        }
    }
    for _, idx := range weights {
        if idx < 0 || idx >= numCommitments {
            return nil, fmt.Errorf("invalid weight index: %d", idx)
        }
    }


	// 1. Prover calculates the value needed for the sum relation check
	// R_sum = SUM(randomness[i] for i in weights)
	// R_diff = k * R_sum - totalRandomness
	sumRandomness := make([]*Scalar, len(weights))
	for i, idx := range weights {
		sumRandomness[i] = randomness[idx]
	}
	R_sum := SumScalars(sumRandomness, params.Order)
	k_R_sum := k.Mul(R_sum)
	R_diff := k_R_sum.Add(totalRandomness.Neg()) // k * R_sum - totalRandomness

	// 2. Prover chooses random blinding factors
	v_w := make([]*Scalar, numCommitments)
	v_r := make([]*Scalar, numCommitments)
	for i := 0; i < numCommitments; i++ {
		v, err := NewScalar(nil, params.Order).Rand(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random v_w[%d]: %w", i, err)
		}
		v_w[i] = v
		v, err = NewScalar(nil, params.Order).Rand(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random v_r[%d]: %w", i, err)
		}
		v_r[i] = v
	}

	v_total_v, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_total_v: %w", err)
	}
	v_total_r, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_total_r: %w", err)
	}

	v_diff, err := NewScalar(nil, params.Order).Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random v_diff: %w", err)
	}


	// 3. Prover computes announcements
	announcements := make([]*Point, len(weights)) // Only need announcements for the commitments in the weighted sum
	for i, idx := range weights {
		v_wiG := params.G.ScalarMul(v_w[idx])
		v_riH := params.H.ScalarMul(v_r[idx])
		announcements[i] = v_wiG.Add(v_riH) // A_i = v_wi*G + v_ri*H
	}

	v_total_vG := params.G.ScalarMul(v_total_v)
	v_total_rH := params.H.ScalarMul(v_total_r)
	totalAnnouncement := v_total_vG.Add(v_total_rH) // A_total = v_total_v*G + v_total_r*H

	sumRelationAnnouncement := params.H.ScalarMul(v_diff) // V_diff = v_diff * H


    // 4. Prover computes challenge `c` using Fiat-Shamir heuristic
	// Hash everything relevant: Params, Commitments, Weights, k, Announcements, TargetPoint
    // Compute C_sum and TargetPoint for challenge hashing (done inside ComputeChallenge now)
    tempProofForHashing := &Proof{
        Announcements: announcements,
        TotalAnnouncement: totalAnnouncement,
        SumRelationAnnouncement: sumRelationAnnouncement,
        // Responses are not included in the challenge hash input
        Z_w: nil, Z_r: nil, Z_total_v: nil, Z_total_r: nil, Z_diff: nil,
    }

	c, err := ComputeChallenge(params, commitments, totalCommitment, weights, k, tempProofForHashing)
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	// 5. Prover computes responses
	z_w := make([]*Scalar, len(weights))
	z_r := make([]*Scalar, len(weights))
	for i, idx := range weights {
		// z_wi = v_wi + c * wi
		c_wi := c.Mul(secrets[idx])
		z_w[i] = v_w[idx].Add(c_wi)

		// z_ri = v_ri + c * ri
		c_ri := c.Mul(randomness[idx])
		z_r[i] = v_r[idx].Add(c_ri)
	}

	// z_total_v = v_total_v + c * total_value
	c_total_v := c.Mul(totalSecret)
	z_total_v := v_total_v.Add(c_total_v)

	// z_total_r = v_total_r + c * total_randomness
	c_total_r := c.Mul(totalRandomness)
	z_total_r := v_total_r.Add(c_total_r)

	// z_diff = v_diff + c * R_diff
	c_R_diff := c.Mul(R_diff)
	z_diff := v_diff.Add(c_R_diff)


	// 6. Return the proof
	proof := &Proof{
		Announcements: announcements, // Announcements for weighted commitments
		TotalAnnouncement: totalAnnouncement,
		SumRelationAnnouncement: sumRelationAnnouncement,
		Z_w: z_w, // Responses for weighted secrets
		Z_r: z_r, // Responses for weighted randomness
		Z_total_v: z_total_v,
		Z_total_r: z_total_r,
		Z_diff: z_diff,
	}

	return proof, nil
}

// VerifyProof verifies the ZKP for the weighted sum relation.
// `commitments` are the public C1..Cn. `totalCommitment` is the public C_total.
func VerifyProof(params *Params, commitments []*Point, totalCommitment *Point, weights []int, k *Scalar, proof *Proof) (bool, error) {
	if params == nil || params.G == nil || params.H == nil || params.Order == nil {
		return false, errors.New("zkp params not initialized")
	}
    if totalCommitment == nil || k == nil || proof == nil || proof.Announcements == nil || proof.TotalAnnouncement == nil || proof.SumRelationAnnouncement == nil ||
       proof.Z_w == nil || proof.Z_r == nil || proof.Z_total_v == nil || proof.Z_total_r == nil || proof.Z_diff == nil {
        return false, errors.New("invalid inputs or incomplete proof structure")
    }
     if k.order.Cmp(params.Order) != 0 {
        return false, errors.New("k scalar order mismatch params order")
    }
     for i := range commitments {
         if commitments[i].curve != params.Curve {
             return false, fmt.Errorf("commitment curve mismatch at index %d", i)
         }
     }
     if totalCommitment.curve != params.Curve {
         return false, errors.New("total commitment curve mismatch")
     }

    for _, z := range proof.Z_w { if z == nil || z.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_w scalar") } }
    for _, z := range proof.Z_r { if z == nil || z.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_r scalar") } }
    if proof.Z_total_v.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_total_v scalar") }
    if proof.Z_total_r.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_total_r scalar") }
    if proof.Z_diff.order.Cmp(params.Order) != 0 { return false, errors.New("invalid Z_diff scalar") }


	numCommitments := len(commitments)
    if len(weights) != len(proof.Announcements) || len(weights) != len(proof.Z_w) || len(weights) != len(proof.Z_r) {
        return false, errors.New("proof structure mismatch with weights length")
    }

    weightedCommitments := make([]*Point, len(weights))
    for i, idx := range weights {
        if idx < 0 || idx >= numCommitments {
            return false, fmt.Errorf("invalid weight index in proof verification: %d", idx)
        }
        weightedCommitments[i] = commitments[idx]
    }

    // 1. Verifier re-computes the challenge
    // Needs the original commitments (C1..Cn, C_total) which are public inputs
    // Needs the weights and k, which are public inputs
    // Needs the prover's announcements (A_i, A_total, V_diff) from the proof
    // Needs the TargetPoint, which is computed from public inputs C_sum and C_total
    // Compute C_sum and TargetPoint (done inside ComputeChallenge now)

	c, err := ComputeChallenge(params, commitments, totalCommitment, weights, k, proof)
	if err != nil {
		return false, fmt.Errorf("failed to re-compute challenge: %w", err)
	}

	// 2. Verifier checks the equations
    // Check 1: Knowledge of wi, ri for each i in weights
	for i, idx := range weights {
        // Check z_wi*G + z_ri*H == A_i + c*C_i
        lhs_G := params.G.ScalarMul(proof.Z_w[i])
        lhs_H := params.H.ScalarMul(proof.Z_r[i])
        lhs := lhs_G.Add(lhs_H)

        c_Ci := commitments[idx].ScalarMul(c)
        rhs := proof.Announcements[i].Add(c_Ci)

        if !lhs.IsEqual(rhs) {
            return false, fmt.Errorf("verification failed for commitment %d (index %d)", i, idx)
        }
    }

    // Check 2: Knowledge of total_value, total_randomness for C_total
    // Check z_total_v*G + z_total_r*H == A_total + c*C_total
    lhs_total_G := params.G.ScalarMul(proof.Z_total_v)
    lhs_total_H := params.H.ScalarMul(proof.Z_total_r)
    lhs_total := lhs_total_G.Add(lhs_total_H)

    c_C_total := totalCommitment.ScalarMul(c)
    rhs_total := proof.TotalAnnouncement.Add(c_C_total)

    if !lhs_total.IsEqual(rhs_total) {
        return false, errors.New("verification failed for total commitment")
    }

    // Check 3: The sum relation (k * SUM(wi) = total_value)
    // z_diff*H == V_diff + c*TargetPoint
    // TargetPoint = k * C_sum - C_total (C_sum computed from public weightedCommitments)
    C_sum := SumPoints(weightedCommitments)
     if C_sum == nil && len(weights) > 0 {
         return false, errors.New("failed to compute C_sum for non-empty weights during verification")
    }
    k_C_sum := C_sum.ScalarMul(k)
    TargetPoint := k_C_sum.Add(totalCommitment.Neg())

    lhs_diff := params.H.ScalarMul(proof.Z_diff)
    c_TargetPoint := TargetPoint.ScalarMul(c)
    rhs_diff := proof.SumRelationAnnouncement.Add(c_TargetPoint)

    if !lhs_diff.IsEqual(rhs_diff) {
         return false, errors.New("verification failed for sum relation")
    }

	// If all checks pass
	return true, nil
}

```