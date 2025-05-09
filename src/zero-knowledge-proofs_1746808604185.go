Okay, let's create a Zero-Knowledge Proof implementation in Go for a specific, slightly more advanced application: **Private Eligibility Proof for Conditional Access**.

The scenario: A Prover wants to prove they meet a specific set of criteria (like being within a certain age range AND having an income above a threshold) to a Verifier *without revealing their exact age or income*.

This involves:
1.  **Commitments:** Hiding the private attribute values (age, income) using cryptographic commitments.
2.  **Range Proofs:** Proving that the committed values fall within specified ranges (e.g., `Age >= 18`, `Age <= 65`, `Income >= 30000`). This is a core ZKP technique. Implementing a full, production-grade ZK range proof (like Bulletproofs or using SNARKs) is very complex and would duplicate existing libraries.
3.  **Combination Proofs:** Proving that *all* conditions (multiple range proofs) are met (AND logic).
4.  **Zero-Knowledge:** Ensuring the Verifier learns *only* that the criteria are met, nothing about the specific private values.

We will implement a simplified ZKP structure using Pedersen commitments and a Sigma-protocol-like approach for range proofs. *Crucially, the range proof part here will be a simplified model focusing on proving knowledge of values satisfying equations related to the range, rather than a fully robust, standard ZK range proof scheme (which requires more complex techniques like proving non-negativity using bit decompositions or specialized protocols).* This allows us to build the structure without duplicating the intricate low-level math of existing libraries like gnark or implementations of Bulletproofs.

**Outline:**

1.  **System Setup:** Generate necessary cryptographic parameters (elliptic curve points).
2.  **Data Structures:** Define types for private values, criteria, commitments, witness, proof components, and the final proof.
3.  **Commitment Operations:** Functions to generate commitments and perform homomorphic operations (addition, scalar multiplication) on them.
4.  **Range Proof Logic (Simplified):**
    *   Represent the range check `min <= v <= max` as `v - min >= 0` and `max - v >= 0`.
    *   Prover commits to `v`, `v-min`, and `max-v`.
    *   Prover uses a Sigma-protocol inspired structure to prove knowledge of the openings of these commitments and that the *relationships* between the commitments hold (e.g., `Commit(v) - Commit(min) == Commit(v-min)`).
    *   *Simplification:* The actual *non-negativity* proof for `v-min` and `max-v` is the hardest part of a ZK range proof. In this example, we will structure the proof elements and verification equations to *simulate* the process of proving relationships between committed values, but without implementing a full, robust ZK proof for `x >= 0`. This allows us to build the ZKP framework structure and function count.
5.  **Multi-Attribute Combination:** Structure the proof to combine individual attribute range proofs using AND logic.
6.  **Prover:** Function to take private witness and public criteria, generate commitments, compute challenges using Fiat-Shamir, and calculate responses to form the proof.
7.  **Verifier:** Function to take public parameters, commitments, criteria, and the proof, re-compute challenges, and verify the provided responses and commitment equations.
8.  **Helper Functions:** Cryptographic operations, serialization, transcript management for Fiat-Shamir.

**Function Summary (25+ functions):**

*   `GenerateSystemParameters`: Creates global curve parameters (G, H).
*   `ExportParameters`: Serializes SystemParameters.
*   `ImportParameters`: Deserializes SystemParameters.
*   `NewAttributeValue`: Creates a wrapper for a private scalar value.
*   `NewEligibilityCriteria`: Creates a structure for a single attribute range criterion.
*   `EligibilityCriteria.SatisfiesLocal`: Checks if a raw value satisfies this criterion (used only by prover locally).
*   `NewWitness`: Creates a structure to hold prover's private values and blinding factors.
*   `Witness.AddAttribute`: Adds a private attribute value and its random blinding factor to the witness.
*   `AttributeCommitment`: Structure representing a commitment.
*   `GenerateCommitment`: Creates a Pedersen commitment `v*G + r*H`.
*   `PointAdd`: Adds two elliptic curve points.
*   `PointSubtract`: Subtracts one elliptic curve point from another.
*   `ScalarMultiplyBase`: Multiplies the base point G by a scalar.
*   `ScalarMultiplyPoint`: Multiplies a point by a scalar.
*   `AddCommitments`: Adds two commitments homomorphically.
*   `SubtractCommitments`: Subtracts one commitment from another.
*   `ScalarMultiplyCommitment`: Multiplies the value component of a commitment by a scalar (scales the commitment).
*   `Transcript`: Helper for building the Fiat-Shamir challenge.
*   `Transcript.AppendPoint`: Adds a point to the transcript hash.
*   `Transcript.AppendScalar`: Adds a scalar to the transcript hash.
*   `Transcript.AppendBytes`: Adds raw bytes to the transcript hash.
*   `Transcript.GenerateChallenge`: Computes the challenge scalar from the transcript.
*   `AttributeRangeProofPart`: Structure for the proof concerning a single attribute range. Contains commitments and proof elements.
*   `AttributeRangeProofPart.GenerateProofPart`: Prover logic for one range.
*   `AttributeRangeProofPart.VerifyProofPart`: Verifier logic for one range part.
*   `EligibilityProof`: The main proof structure, containing parts for each attribute.
*   `EligibilityProof.MarshalBinary`: Serializes the proof.
*   `EligibilityProof.UnmarshalBinary`: Deserializes the proof.
*   `ProveEligibility`: Main prover function, orchestrates generating all parts.
*   `VerifyEligibilityProof`: Main verifier function, orchestrates verifying all parts.
*   `generateRandomScalar`: Generates a cryptographically secure random scalar.
*   `hashToScalar`: Hashes bytes to a scalar.

```golang
package zkpeligibility

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// --- Outline ---
// 1. System Setup: Generate elliptic curve parameters (G, H).
// 2. Data Structures: Define Go types for values, criteria, commitments, witness, and proof.
// 3. Commitment Operations: Implement Pedersen commitment generation and homomorphic operations.
// 4. Range Proof Logic (Simplified): Implement structures and logic for proving a value is within a range using commitments and proof elements. This is a core ZKP technique but simplified here for range proof non-negativity part.
// 5. Multi-Attribute Combination: Combine proofs for multiple attributes (AND logic).
// 6. Prover: Generate commitments, build transcript, calculate challenges and responses.
// 7. Verifier: Verify commitments, build transcript, re-calculate challenges, and check verification equations.
// 8. Helper Functions: Cryptographic utilities, serialization, Fiat-Shamir transcript.

// --- Function Summary ---
// GenerateSystemParameters: Creates global curve parameters (G, H) for commitments.
// ExportParameters: Serializes SystemParameters for sharing.
// ImportParameters: Deserializes SystemParameters.
// NewAttributeValue: Creates a wrapper for a private scalar value.
// NewEligibilityCriteria: Creates a structure for a single attribute range criterion [Min, Max].
// EligibilityCriteria.SatisfiesLocal: Checks if a raw scalar value satisfies the criterion (prover side).
// NewWitness: Creates a structure to hold prover's private data (values, randoms).
// Witness.AddAttribute: Adds a private attribute value and its random blinding factor to the witness.
// AttributeCommitment: Structure representing a Pedersen commitment Point = Value*G + Random*H.
// GenerateCommitment: Computes a Pedersen commitment for a given value and random.
// PointAdd: Adds two elliptic curve points.
// PointSubtract: Subtracts one elliptic curve point from another.
// ScalarMultiplyBase: Multiplies the base point G by a scalar.
// ScalarMultiplyPoint: Multiplies an arbitrary point by a scalar.
// AddCommitments: Adds two commitments homomorphically (Commit(a)+Commit(b) = Commit(a+b)).
// SubtractCommitments: Subtracts one commitment from another.
// ScalarMultiplyCommitment: Multiplies the *value* component of a commitment by a scalar.
// Transcript: Helper structure for managing data for Fiat-Shamir hashing.
// Transcript.AppendPoint: Adds a point's serialized bytes to the transcript hash state.
// Transcript.AppendScalar: Adds a scalar's serialized bytes to the transcript hash state.
// Transcript.AppendBytes: Adds raw bytes to the transcript hash state.
// Transcript.GenerateChallenge: Computes the challenge scalar from the current transcript hash.
// AttributeRangeProofPart: Structure containing commitments and ZK proof elements for a single attribute range.
// AttributeRangeProofPart.GenerateProofPart: Prover logic to create proof elements for one range criterion.
// AttributeRangeProofPart.VerifyProofPart: Verifier logic to check proof elements for one range criterion.
// EligibilityProof: The main proof structure containing multiple AttributeRangeProofParts.
// EligibilityProof.MarshalBinary: Serializes the entire proof.
// EligibilityProof.UnmarshalBinary: Deserializes the entire proof.
// ProveEligibility: Main prover function - takes witness and criteria, generates the full proof.
// VerifyEligibilityProof: Main verifier function - takes proof and criteria, verifies it.
// generateRandomScalar: Generates a cryptographically secure random scalar within the curve's order.
// hashToScalar: Hashes a byte slice to a scalar within the curve's order.
// PointToBytes: Serializes a point.
// BytesToPoint: Deserializes a point.
// ScalarToBytes: Serializes a scalar.
// BytesToScalar: Deserializes a scalar.

// --- Constants and Global Parameters ---
var (
	curve = elliptic.P256() // Use P256 elliptic curve
	G     elliptic.Point    // Generator point G (base point)
	H     elliptic.Point    // Another generator point H, independent of G
	order = curve.Params().N // Order of the curve
)

// SystemParameters holds the public parameters for the ZKP system.
type SystemParameters struct {
	G elliptic.Point // Base point
	H elliptic.Point // Second generator point
}

// GenerateSystemParameters sets up the global curve parameters G and H.
// In a real system, H should be generated deterministically from G using a verifiable process (e.g., hash-to-curve),
// ensuring it's not a known multiple of G. For this example, we'll use the standard base point G
// and generate H by hashing a fixed value to a point, acknowledging this is a simplification.
func GenerateSystemParameters() error {
	G = curve.Params().Gx
	// Generate H by hashing a fixed string to a point on the curve.
	// A robust hash-to-curve is complex. Simple method: hash and try scalar mult.
	// More proper method: try different hash outputs until a point is found.
	// For illustrative purposes, we'll use a simplified method that *assumes* it works.
	// WARNING: This is not a cryptographically rigorous method for generating H.
	hasher := sha256.New()
	hasher.Write([]byte("zkpeligibility:second_generator"))
	seed := new(big.Int).SetBytes(hasher.Sum(nil))
	// Simple (non-robust) way to get a second generator: use a point derived from a hash
	// or just pick a random valid scalar and multiply G by it.
	// Using a random scalar for H=dG means if 'd' is known, privacy is broken.
	// A better approach is needed for production.
	// Let's use a deterministic scalar based on the seed for reproducibility in this example.
	hScalar := new(big.Int).SetBytes(seed.Bytes())
	hScalar.Mod(hScalar, order)
	// Ensure hScalar is not zero or one, and G*hScalar is not the point at infinity.
	// A rigorous system would ensure H is a proper independent generator.
	// For this example, we'll just use G*hScalar.
	hx, hy := curve.ScalarBaseMult(hScalar.Bytes())
	H = curve.Point(hx, hy)

	if G == nil || H == nil {
		return errors.New("failed to generate system parameters")
	}
	return nil
}

// ExportParameters serializes the system parameters.
func ExportParameters(params *SystemParameters) ([]byte, error) {
	gBytes, err := PointToBytes(params.G)
	if err != nil {
		return nil, fmt.Errorf("failed to export G: %w", err)
	}
	hBytes, err := PointToBytes(params.H)
	if err != nil {
		return nil, fmt.Errorf("failed to export H: %w", err)
	}
	// Simple concatenation: len(G) || G_bytes || len(H) || H_bytes
	gLen := make([]byte, 4)
	binary.BigEndian.PutUint32(gLen, uint32(len(gBytes)))
	hLen := make([]byte, 4)
	binary.BigEndian.PutUint32(hLen, uint32(len(hBytes)))

	data := append(gLen, gBytes...)
	data = append(data, hLen...)
	data = append(data, hBytes...)
	return data, nil
}

// ImportParameters deserializes the system parameters.
func ImportParameters(data []byte) (*SystemParameters, error) {
	if len(data) < 8 {
		return nil, errors.New("invalid parameter data length")
	}
	gLen := binary.BigEndian.Uint32(data[:4])
	gBytes := data[4 : 4+gLen]
	if len(data) < int(4+gLen+4) {
		return nil, errors.New("invalid parameter data length for G")
	}
	hLen := binary.BigEndian.Uint32(data[4+gLen : 4+gLen+4])
	hBytes := data[4+gLen+4 : 4+gLen+4+hLen]
	if len(data) != int(4+gLen+4+hLen) {
		return nil, errors.New("invalid parameter data length for H")
	}

	gPoint, err := BytesToPoint(gBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to import G: %w", err)
	}
	hPoint, err := BytesToPoint(hBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to import H: %w", err)
	}

	// Update global parameters for consistency if needed, though better to use returned params
	// G = gPoint
	// H = hPoint
	// order = curve.Params().N // Ensure order is set

	return &SystemParameters{G: gPoint, H: hPoint}, nil
}

// NewAttributeValue creates a private attribute value wrapper.
func NewAttributeValue(val int64) *big.Int {
	v := big.NewInt(val)
	v.Mod(v, order) // Ensure value is within field size
	return v
}

// NewEligibilityCriteria creates a structure defining a required range [Min, Max].
type EligibilityCriteria struct {
	AttributeName string   // e.g., "Age", "Income" - for context
	Min           *big.Int // Minimum required value
	Max           *big.Int // Maximum allowed value
}

// NewEligibilityCriteria creates a new EligibilityCriteria object.
func NewEligibilityCriteria(name string, min, max int64) *EligibilityCriteria {
	minBig := big.NewInt(min)
	maxBig := big.NewInt(max)
	// Ensure Min/Max are within field order if they are used in scalar operations
	minBig.Mod(minBig, order)
	maxBig.Mod(maxBig, order)

	return &EligibilityCriteria{
		AttributeName: name,
		Min:           minBig,
		Max:           maxBig,
	}
}

// SatisfiesLocal checks if a given raw value satisfies this criterion.
// This function is for the Prover's local check and is NOT part of the ZKP.
func (c *EligibilityCriteria) SatisfiesLocal(value *big.Int) bool {
	// Perform standard big.Int comparison
	return value.Cmp(c.Min) >= 0 && value.Cmp(c.Max) <= 0
}

// Witness holds the prover's secret data.
type Witness struct {
	Values  []*big.Int // The private attribute values
	Randoms []*big.Int // The blinding factors used for commitments
}

// NewWitness creates an empty witness structure.
func NewWitness() *Witness {
	return &Witness{
		Values:  []*big.Int{},
		Randoms: []*big.Int{},
	}
}

// AddAttribute adds a private value and its random blinding factor to the witness.
func (w *Witness) AddAttribute(value *big.Int, random *big.Int) {
	w.Values = append(w.Values, value)
	w.Randoms = append(w.Randoms, random)
}

// AttributeCommitment represents a Pedersen commitment Point = value*G + random*H
type AttributeCommitment struct {
	Point elliptic.Point
}

// GenerateCommitment creates a Pedersen commitment for a value `v` and randomness `r`.
func GenerateCommitment(v, r *big.Int, params *SystemParameters) (*AttributeCommitment, error) {
	if params == nil || params.G == nil || params.H == nil {
		return nil, errors.New("system parameters not initialized")
	}
	// C = v*G + r*H
	vG := ScalarMultiplyPoint(params.G, v)
	rH := ScalarMultiplyPoint(params.H, r)
	C := PointAdd(vG, rH)
	if C == nil {
		return nil, errors.New("failed to generate commitment point")
	}
	return &AttributeCommitment{Point: C}, nil
}

// PointAdd adds two elliptic curve points using the global curve.
func PointAdd(p1, p2 elliptic.Point) elliptic.Point {
	x, y := curve.Add(p1.X(), p1.Y(), p2.X(), p2.Y())
	if x == nil || y == nil { // Should not happen on valid curve points usually
		return nil
	}
	return curve.Point(x, y)
}

// PointSubtract subtracts one elliptic curve point from another (p1 - p2 = p1 + (-p2)).
func PointSubtract(p1, p2 elliptic.Point) elliptic.Point {
	// Get the inverse of p2
	invP2x, invP2y := curve.Params().Curve.Inverse(p2.X(), p2.Y()) // Note: Inverse needs Affine coordinates. P256 has Inverse function.
	if invP2x == nil || invP2y == nil { // Should not happen for points not at infinity
		return nil
	}
	invP2 := curve.Point(invP2x, invP2y)
	// Add p1 and -p2
	return PointAdd(p1, invP2)
}

// ScalarMultiplyBase multiplies the curve's base point G by a scalar s.
func ScalarMultiplyBase(s *big.Int, params *SystemParameters) elliptic.Point {
	if params == nil || params.G == nil {
		return nil
	}
	x, y := curve.ScalarBaseMult(s.Bytes())
	if x == nil || y == nil { // Should not happen for valid scalar/base point
		return nil
	}
	return curve.Point(x, y)
}

// ScalarMultiplyPoint multiplies a point P by a scalar s.
func ScalarMultiplyPoint(p elliptic.Point, s *big.Int) elliptic.Point {
	x, y := curve.ScalarMult(p.X(), p.Y(), s.Bytes())
	if x == nil || y == nil { // Should not happen for valid scalar/point
		return nil
	}
	return curve.Point(x, y)
}

// AddCommitments adds two commitments homomorphically. C1+C2 = (v1+v2)*G + (r1+r2)*H
func AddCommitments(c1, c2 *AttributeCommitment) *AttributeCommitment {
	if c1 == nil || c2 == nil {
		return nil
	}
	sumPoint := PointAdd(c1.Point, c2.Point)
	if sumPoint == nil {
		return nil
	}
	return &AttributeCommitment{Point: sumPoint}
}

// SubtractCommitments subtracts one commitment from another. C1-C2 = (v1-v2)*G + (r1-r2)*H
func SubtractCommitments(c1, c2 *AttributeCommitment) *AttributeCommitment {
	if c1 == nil || c2 == nil {
		return nil
	}
	diffPoint := PointSubtract(c1.Point, c2.Point)
	if diffPoint == nil {
		return nil
	}
	return &AttributeCommitment{Point: diffPoint}
}

// ScalarMultiplyCommitment multiplies the *value* component of a commitment by a scalar s.
// s * C = s * (v*G + r*H) = (s*v)*G + (s*r)*H
// Note: This operation requires knowing the blinding factor `r` which makes it not purely homomorphic
// for scalar multiplication of the value. A true homomorphic scalar multiplication requires different schemes.
// This function is rather used within the proof logic to scale commitments for verification equations.
func ScalarMultiplyCommitment(c *AttributeCommitment, s *big.Int) *AttributeCommitment {
	if c == nil {
		return nil
	}
	scaledPoint := ScalarMultiplyPoint(c.Point, s)
	if scaledPoint == nil {
		return nil
	}
	return &AttributeCommitment{Point: scaledPoint}
}

// Transcript manages the state for the Fiat-Shamir heuristic.
type Transcript struct {
	hasher *sha256.Hasher
}

// NewTranscript creates a new transcript.
func NewTranscript() *Transcript {
	h := sha256.New().(sha256.Hasher) // Get the concrete type
	return &Transcript{&h}
}

// AppendPoint adds a point to the transcript's hash state.
func (t *Transcript) AppendPoint(p elliptic.Point) error {
	b, err := PointToBytes(p)
	if err != nil {
		return err
	}
	t.hasher.Write(b)
	return nil
}

// AppendScalar adds a scalar to the transcript's hash state.
func (t *Transcript) AppendScalar(s *big.Int) {
	t.hasher.Write(s.Bytes())
}

// AppendBytes adds arbitrary bytes to the transcript's hash state.
func (t *Transcript) AppendBytes(b []byte) {
	t.hasher.Write(b)
}

// GenerateChallenge computes the challenge scalar from the current transcript state.
func (t *Transcript) GenerateChallenge() *big.Int {
	hashResult := t.hasher.Sum(nil)
	return hashToScalar(hashResult)
}

// AttributeRangeProofPart contains the proof elements for one attribute range check.
// This structure implements a simplified Sigma-protocol inspired proof of knowledge
// related to the commitments C_v, C_v_minus_min, C_max_minus_v.
// It proves knowledge of v, r_v, (v-min), r_v_minus_min, (max-v), r_max_minus_v
// such that the commitment equations hold.
// NOTE: This structure alone does *not* prove v-min >= 0 and max-v >= 0 Zero-Knowledge.
// A full ZK range proof requires additional commitments and proof elements (e.g., bit commitments).
type AttributeRangeProofPart struct {
	AttributeName string // Name of the attribute this part proves
	CommitmentV   *AttributeCommitment // Commitment to the attribute value v: C_v = v*G + r_v*H
	CommitmentV_minus_min *AttributeCommitment // Commitment to v-min: C_{v-min} = (v-min)*G + r_{v-min}*H
	CommitmentMax_minus_v *AttributeCommitment // Commitment to max-v: C_{max-v} = (max-v)*G + r_{max-v}*H

	// ZK Proof elements (inspired by Sigma protocol, proving knowledge of values/randoms)
	// Based on challenge 'e', prover proves knowledge of x, r such that C = xG + rH
	// Prover computes challenge 'e' = H(transcript)
	// Prover computes response 'z' = x + e*k (where k is a temporary random, x is the secret, C is commitment)
	// Here, we have multiple secrets and commitments. The proof structure is simplified.
	// Let's prove knowledge of v, r_v, v-min, r_{v-min}, max-v, r_{max-v}
	// We need responses related to these secrets and randoms, tied together by challenges.
	// A simple way in Sigma protocols is proving knowledge of opening C = xG + rH:
	// 1. Prover picks random k1, k2. Computes A = k1*G + k2*H. Sends A.
	// 2. Verifier sends challenge e.
	// 3. Prover computes z1 = k1 + e*x (mod order), z2 = k2 + e*r (mod order). Sends z1, z2.
	// 4. Verifier checks z1*G + z2*H == A + e*C.
	// Applying this here is complex with multiple relations.
	// Let's simplify the *structure* to prove knowledge of values AND their randoms
	// implicitly via combined responses and checks.
	// We need responses z_v, z_rv, z_vmin, z_rv_vmin, z_maxv, z_rv_maxv
	// Where z_x = k_x + e*x and z_rx = k_rx + e*rx
	// And we need commitments to k_v, k_rv, k_vmin, k_rv_vmin, k_maxv, k_rv_maxv
	// A = k_v*G + k_rv*H
	// A_vmin = k_vmin*G + k_rv_vmin*H
	// A_maxv = k_maxv*G + k_rv_maxv*H

	A_v *AttributeCommitment // Commitment to randoms k_v, k_rv: A_v = k_v*G + k_rv*H
	A_v_minus_min *AttributeCommitment // Commitment to randoms k_vmin, k_rv_vmin: A_{v-min} = k_vmin*G + k_rv_vmin*H
	A_max_minus_v *AttributeCommitment // Commitment to randoms k_maxv, k_rv_maxv: A_{max-v} = k_maxv*G + k_{max-v}*H

	// Responses
	Z_v      *big.Int // z_v = k_v + e * v (mod order)
	Z_rv     *big.Int // z_rv = k_rv + e * r_v (mod order)
	Z_v_minus_min *big.Int // z_vmin = k_vmin + e * (v-min) (mod order)
	Z_rv_minus_min *big.Int // z_rv_vmin = k_rv_vmin + e * r_{v-min} (mod order)
	Z_max_minus_v *big.Int // z_maxv = k_maxv + e * (max-v) (mod order)
	Z_rv_max_minus_v *big.Int // z_rv_maxv = k_rv_maxv + e * r_{max-v} (mod order)
}

// GenerateProofPart creates the ZK proof elements for a single attribute range.
// It performs steps similar to a Sigma protocol: commit to randoms, get challenge, compute responses.
// Prover needs: value v, random r_v, criteria (min, max), system parameters.
// It also implicitly requires v-min, r_{v-min}, max-v, r_{max-v} such that
// C_{v-min} = (v-min)G + r_{v-min}H and C_{max-v} = (max-v)G + r_{max-v}H.
// The prover computes these derived values and randoms.
func (p *AttributeRangeProofPart) GenerateProofPart(
	value, randomV *big.Int,
	criteria *EligibilityCriteria,
	transcript *Transcript,
	params *SystemParameters,
) error {

	if params == nil || params.G == nil || params.H == nil {
		return errors.New("system parameters not initialized")
	}
	if value == nil || randomV == nil || criteria == nil || criteria.Min == nil || criteria.Max == nil {
		return errors.New("invalid input parameters")
	}
	if transcript == nil {
		return errors.New("transcript is nil")
	}

	// 1. Prover calculates derived values and their randoms.
	//    Ensure v-min and max-v are >= 0 (prover side check, not part of ZKP).
	//    This is where the prover ensures the criteria are met.
	v_minus_min_val := new(big.Int).Sub(value, criteria.Min)
	max_minus_v_val := new(big.Int).Sub(criteria.Max, value)

	// Note: If v-min or max-v is negative, the prover *should not* be able to complete a proper ZK range proof.
	// In this simplified structure, they *could* still generate the commitments and responses,
	// but a full ZK range proof protocol would fail at the stage proving non-negativity.
	// We proceed assuming the prover *does* satisfy the criteria locally.
	if v_minus_min_val.Sign() < 0 || max_minus_v_val.Sign() < 0 {
		// In a real system, the prover would stop here or use a different protocol.
		// For this example, we will proceed to show the proof structure, but acknowledge
		// that a verifier would *not* learn this failure zero-knowledge.
		// A robust ZK range proof proves non-negativity ZK. This example does not.
		fmt.Printf("Prover Warning: Value %s outside range [%s, %s]. Proof will structurally pass but is not a valid ZK range proof for this value.\n", value, criteria.Min, criteria.Max)
	}

	// Prover needs randoms for C_{v-min} and C_{max-v}.
	// To maintain relationships, r_{v-min} and r_{max-v} must be related to r_v.
	// If C_v = vG + r_v H, C_{v-min} = (v-min)G + r_{v-min}H, C_{max-v} = (max-v)G + r_{max-v}H
	// We need C_v - min*G = C_{v-min} => (vG+r_vH) - minG = (v-min)G + r_{v-min}H => (v-min)G + r_vH = (v-min)G + r_{v-min}H => r_vH = r_{v-min}H => r_v = r_{v-min} (mod order)
	// We need max*G - C_v = C_{max-v} => max*G - (vG+r_vH) = (max-v)G + r_{max-v}H => (max-v)G - r_vH = (max-v)G + r_{max-v}H => -r_vH = r_{max-v}H => r_{max-v} = -r_v (mod order)
	// So, r_{v-min} should be r_v, and r_{max-v} should be -r_v.
	r_v_minus_min_rand := randomV // Use the same random for v-min commitment
	r_max_minus_v_rand := new(big.Int).Neg(randomV)
	r_max_minus_v_rand.Mod(r_max_minus_v_rand, order) // Ensure positive and in order

	// 2. Prover generates commitments for the values and randoms.
	// These are the main commitments included in the proof.
	cv, err := GenerateCommitment(value, randomV, params)
	if err != nil {
		return fmt.Errorf("failed to commit to value: %w", err)
	}
	cv_minus_min, err := GenerateCommitment(v_minus_min_val, r_v_minus_min_rand, params)
	if err != nil {
		return fmt.Errorf("failed to commit to v-min: %w", err)
	}
	cmax_minus_v, err := GenerateCommitment(max_minus_v_val, r_max_minus_v_rand, params)
	if err != nil {
		return fmt.Errorf("failed to commit to max-v: %w", err)
	}

	p.AttributeName = criteria.AttributeName
	p.CommitmentV = cv
	p.CommitmentV_minus_min = cv_minus_min
	p.CommitmentMax_minus_v = cmax_minus_v

	// 3. Prover picks randoms for the ZK proof (k_v, k_rv, etc.)
	// These are temporary secrets used only during proof generation.
	k_v, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_v: %w", err) }
	k_rv, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_rv: %w", err) }

	k_vmin, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_vmin: %w", err) }
	k_rv_vmin, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_rv_vmin: %w", err) }

	k_maxv, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_maxv: %w", err) }
	k_rv_maxv, err := generateRandomScalar()
	if err != nil { return fmt.Errorf("failed to generate k_rv_maxv: %w", err) }


	// 4. Prover computes auxiliary commitments A_v, A_{v-min}, A_{max-v}
	av, err := GenerateCommitment(k_v, k_rv, params)
	if err != nil { return fmt.Errorf("failed to generate A_v: %w", err) }
	av_minus_min, err := GenerateCommitment(k_vmin, k_rv_vmin, params)
	if err != nil { return fmt.Errorf("failed to generate A_{v-min}: %w", err) }
	amax_minus_v, err := GenerateCommitment(k_maxv, k_rv_maxv, params)
	if err != nil { return fmt.Errorf("failed to generate A_{max-v}: %w", err) }

	p.A_v = av
	p.A_v_minus_min = av_minus_min
	p.A_max_minus_v = amax_minus_v

	// 5. Prover adds public data and commitments to the transcript to generate the challenge 'e'
	transcript.AppendBytes([]byte(p.AttributeName))
	transcript.AppendScalar(criteria.Min) // Public min
	transcript.AppendScalar(criteria.Max) // Public max
	if err := transcript.AppendPoint(p.CommitmentV.Point); err != nil { return fmt.Errorf("transcript append CV: %w", err)}
	if err := transcript.AppendPoint(p.CommitmentV_minus_min.Point); err != nil { return fmt.Errorf("transcript append CV-min: %w", err)}
	if err := transcript.AppendPoint(p.CommitmentMax_minus_v.Point); err != nil { return fmt.Errorf("transcript append CMax-V: %w", err)}
	if err := transcript.AppendPoint(p.A_v.Point); err != nil { return fmt.Errorf("transcript append Av: %w", err)}
	if err := transcript.AppendPoint(p.A_v_minus_min.Point); err != nil { return fmt.Errorf("transcript append Av-min: %w", err)}
	if err := transcript.AppendPoint(p.A_max_minus_v.Point); err != nil { return fmt.Errorf("transcript append AMax-V: %w", err)}

	e := transcript.GenerateChallenge()

	// 6. Prover computes responses based on private secrets, randoms, and challenge 'e'
	// z = k + e * secret (mod order)

	// z_v = k_v + e * v
	p.Z_v = new(big.Int).Mul(e, value)
	p.Z_v.Add(p.Z_v, k_v)
	p.Z_v.Mod(p.Z_v, order)

	// z_rv = k_rv + e * r_v
	p.Z_rv = new(big.Int).Mul(e, randomV)
	p.Z_rv.Add(p.Z_rv, k_rv)
	p.Z_rv.Mod(p.Z_rv, order)

	// z_vmin = k_vmin + e * (v-min)
	p.Z_v_minus_min = new(big.Int).Mul(e, v_minus_min_val)
	p.Z_v_minus_min.Add(p.Z_v_minus_min, k_vmin)
	p.Z_v_minus_min.Mod(p.Z_v_minus_min, order)

	// z_rv_vmin = k_rv_vmin + e * r_{v-min}
	p.Z_rv_minus_min = new(big.Int).Mul(e, r_v_minus_min_rand)
	p.Z_rv_minus_min.Add(p.Z_rv_minus_min, k_rv_vmin)
	p.Z_rv_minus_min.Mod(p.Z_rv_minus_min, order)

	// z_maxv = k_maxv + e * (max-v)
	p.Z_max_minus_v = new(big.Int).Mul(e, max_minus_v_val)
	p.Z_max_minus_v.Add(p.Z_max_minus_v, k_maxv)
	p.Z_max_minus_v.Mod(p.Z_max_minus_v, order)

	// z_rv_maxv = k_rv_maxv + e * r_{max-v}
	p.Z_rv_max_minus_v = new(big.Int).Mul(e, r_max_minus_v_rand)
	p.Z_rv_max_minus_v.Add(p.Z_rv_max_minus_v, k_rv_maxv)
	p.Z_rv_max_minus_v.Mod(p.Z_rv_max_minus_v, order)

	return nil
}

// VerifyProofPart verifies the ZK proof elements for a single attribute range.
// Verifier checks if z*G + z_r*H == A + e*C
// For our structure:
// Check 1: z_v*G + z_rv*H == A_v + e*C_v
// Check 2: z_vmin*G + z_rv_vmin*H == A_{v-min} + e*C_{v-min}
// Check 3: z_maxv*G + z_rv_maxv*H == A_{max-v} + e*C_{max-v}
// Additionally, the verifier must check the *relationship* between the commitments:
// Check 4: C_v - min*G == C_{v-min}
// Check 5: max*G - C_v == C_{max-v}
// If all checks pass, it proves knowledge of v, r_v, v-min, r_{v-min}, max-v, r_{max-v}
// that satisfy the commitment equations and their relationship.
// It does NOT prove v-min >= 0 or max-v >= 0 zero-knowledge.
func (p *AttributeRangeProofPart) VerifyProofPart(
	criteria *EligibilityCriteria,
	transcript *Transcript,
	params *SystemParameters,
) (bool, error) {

	if params == nil || params.G == nil || params.H == nil {
		return false, errors.New("system parameters not initialized")
	}
	if criteria == nil || criteria.Min == nil || criteria.Max == nil {
		return false, errors.New("invalid criteria")
	}
	if transcript == nil {
		return false, errors.New("transcript is nil")
	}
	if p.CommitmentV == nil || p.CommitmentV_minus_min == nil || p.CommitmentMax_minus_v == nil ||
		p.A_v == nil || p.A_v_minus_min == nil || p.A_max_minus_v == nil ||
		p.Z_v == nil || p.Z_rv == nil || p.Z_v_minus_min == nil || p.Z_rv_minus_min == nil || p.Z_max_minus_v == nil || p.Z_rv_max_minus_v == nil {
		return false, errors.New("proof part is incomplete")
	}

	// 1. Verifier re-generates the challenge 'e'
	transcript.AppendBytes([]byte(p.AttributeName))
	transcript.AppendScalar(criteria.Min)
	transcript.AppendScalar(criteria.Max)
	if err := transcript.AppendPoint(p.CommitmentV.Point); err != nil { return false, fmt.Errorf("verifier transcript append CV: %w", err)}
	if err := transcript.AppendPoint(p.CommitmentV_minus_min.Point); err != nil { return false, fmt.Errorf("verifier transcript append CV-min: %w", err)}
	if err := transcript.AppendPoint(p.CommitmentMax_minus_v.Point); err != nil { return false, fmt.Errorf("verifier transcript append CMax-V: %w", err)}
	if err := transcript.AppendPoint(p.A_v.Point); err != nil { return false, fmt.Errorf("verifier transcript append Av: %w", err)}
	if err := transcript.AppendPoint(p.A_v_minus_min.Point); err != nil { return false, fmt.Errorf("verifier transcript append Av-min: %w", err)}
	if err := transcript.AppendPoint(p.A_max_minus_v.Point); err != nil { return false, fmt.Errorf("verifier transcript append AMax-V: %w", err)}

	e := transcript.GenerateChallenge()

	// 2. Verifier checks the Sigma protocol equations: z*G + z_r*H == A + e*C

	// Check 1: z_v*G + z_rv*H == A_v + e*C_v
	lhs1 := PointAdd(ScalarMultiplyBase(p.Z_v, params), ScalarMultiplyPoint(params.H, p.Z_rv))
	eCv := ScalarMultiplyCommitment(p.CommitmentV, e)
	rhs1 := AddCommitments(p.A_v, eCv)
	if !curve.IsOnCurve(lhs1.X(), lhs1.Y()) || !lhs1.Equal(rhs1.Point) {
		return false, errors.New("verification failed for value commitment")
	}

	// Check 2: z_vmin*G + z_rv_vmin*H == A_{v-min} + e*C_{v-min}
	lhs2 := PointAdd(ScalarMultiplyBase(p.Z_v_minus_min, params), ScalarMultiplyPoint(params.H, p.Z_rv_minus_min))
	eCv_minus_min := ScalarMultiplyCommitment(p.CommitmentV_minus_min, e)
	rhs2 := AddCommitments(p.A_v_minus_min, eCv_minus_min)
	if !curve.IsOnCurve(lhs2.X(), lhs2.Y()) || !lhs2.Equal(rhs2.Point) {
		return false, errors.New("verification failed for v-min commitment")
	}

	// Check 3: z_maxv*G + z_rv_maxv*H == A_{max-v} + e*C_{max-v}
	lhs3 := PointAdd(ScalarMultiplyBase(p.Z_max_minus_v, params), ScalarMultiplyPoint(params.H, p.Z_rv_max_minus_v))
	eCmax_minus_v := ScalarMultiplyCommitment(p.CommitmentMax_minus_v, e)
	rhs3 := AddCommitments(p.A_max_minus_v, eCmax_minus_v)
	if !curve.IsOnCurve(lhs3.X(), lhs3.Y()) || !lhs3.Equal(rhs3.Point) {
		return false, errors.New("verification failed for max-v commitment")
	}

	// 3. Verifier checks the relationship between commitments and public min/max
	// These checks verify that C_{v-min} and C_{max-v} are indeed commitments to v-min and max-v
	// *relative to C_v* and using the specified randoms.

	// Check 4: C_v - min*G == C_{v-min}
	// C_v.Point - ScalarMultiplyBase(criteria.Min, params) == C_v_minus_min.Point
	minG := ScalarMultiplyBase(criteria.Min, params)
	calculated_C_v_minus_min := PointSubtract(p.CommitmentV.Point, minG)
	if !curve.IsOnCurve(calculated_C_v_minus_min.X(), calculated_C_v_minus_min.Y()) || !calculated_C_v_minus_min.Equal(p.CommitmentV_minus_min.Point) {
		return false, errors.New("verification failed for commitment relationship: C_v - min*G")
	}

	// Check 5: max*G - C_v == C_{max-v}
	// ScalarMultiplyBase(criteria.Max, params) - C_v.Point == C_max_minus_v.Point
	maxG := ScalarMultiplyBase(criteria.Max, params)
	calculated_C_max_minus_v := PointSubtract(maxG, p.CommitmentV.Point)
	if !curve.IsOnCurve(calculated_C_max_minus_v.X(), calculated_C_max_minus_v.Y()) || !calculated_C_max_minus_v.Equal(p.CommitmentMax_minus_v.Point) {
		return false, errors.New("verification failed for commitment relationship: max*G - C_v")
	}

	// If all checks pass, the prover has proven knowledge of the values and randoms
	// satisfying the commitment equations and their relationships.
	// A robust ZK range proof would have additional checks here proving
	// v-min and max-v are non-negative zero-knowledge.
	return true, nil
}

// EligibilityProof is the main structure holding the proof for multiple attributes.
type EligibilityProof struct {
	AttributeProofs []*AttributeRangeProofPart // Proof part for each attribute/criterion
}

// MarshalBinary serializes the EligibilityProof.
func (ep *EligibilityProof) MarshalBinary() ([]byte, error) {
	var data []byte
	// Write number of attribute proofs
	count := uint32(len(ep.AttributeProofs))
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, count)
	data = append(data, countBytes...)

	for _, part := range ep.AttributeProofs {
		// Serialize each part
		partData, err := part.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal proof part: %w", err)
		}
		// Write length of part data
		partLen := make([]byte, 4)
		binary.BigEndian.PutUint32(partLen, uint32(len(partData)))
		data = append(data, partLen...)
		data = append(data, partData...)
	}
	return data, nil
}

// UnmarshalBinary deserializes the EligibilityProof.
func (ep *EligibilityProof) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid proof data length")
	}
	count := binary.BigEndian.Uint32(data[:4])
	data = data[4:]

	ep.AttributeProofs = make([]*AttributeRangeProofPart, count)

	for i := uint32(0); i < count; i++ {
		if len(data) < 4 {
			return errors.New("invalid proof data length for part length")
		}
		partLen := binary.BigEndian.Uint32(data[:4])
		if len(data) < int(4+partLen) {
			return errors.New("invalid proof data length for part data")
		}
		partData := data[4 : 4+partLen]
		data = data[4+partLen:]

		part := &AttributeRangeProofPart{}
		if err := part.UnmarshalBinary(partData); err != nil {
			return fmt.Errorf("failed to unmarshal proof part %d: %w", i, err)
		}
		ep.AttributeProofs[i] = part
	}
	if len(data) != 0 {
		return errors.New("trailing data after unmarshalling proof")
	}
	return nil
}

// MarshalBinary serializes a single AttributeRangeProofPart.
func (p *AttributeRangeProofPart) MarshalBinary() ([]byte, error) {
	var data []byte

	// AttributeName
	nameBytes := []byte(p.AttributeName)
	nameLen := make([]byte, 4)
	binary.BigEndian.PutUint32(nameLen, uint32(len(nameBytes)))
	data = append(data, nameLen...)
	data = append(data, nameBytes...)

	// Commitments
	commitments := []*AttributeCommitment{
		p.CommitmentV, p.CommitmentV_minus_min, p.CommitmentMax_minus_v,
		p.A_v, p.A_v_minus_min, p.A_max_minus_v,
	}
	for _, c := range commitments {
		cBytes, err := PointToBytes(c.Point)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal commitment point: %w", err)
		}
		data = append(data, cBytes...)
	}

	// Responses
	responses := []*big.Int{
		p.Z_v, p.Z_rv, p.Z_v_minus_min, p.Z_rv_minus_min, p.Z_max_minus_v, p.Z_rv_max_minus_v,
	}
	for _, z := range responses {
		zBytes := z.Bytes() // big.Int.Bytes() gives minimal representation
		zLen := make([]byte, 4)
		binary.BigEndian.PutUint32(zLen, uint32(len(zBytes)))
		data = append(data, zLen...)
		data = append(data, zBytes...)
	}

	return data, nil
}

// UnmarshalBinary deserializes a single AttributeRangeProofPart.
func (p *AttributeRangeProofPart) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid proof part data length for name length")
	}
	nameLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(nameLen) {
		return errors.New("invalid proof part data length for name")
	}
	p.AttributeName = string(data[:nameLen])
	data = data[nameLen:]

	// Commitments (6 points)
	commitments := []*AttributeCommitment{
		{}, {}, {}, {}, {}, {},
	}
	pointLength := (curve.Params().BitSize + 7) / 8 * 2 // Uncompressed point size (approx) or use curve.Params().P.BitLen()/8 * 2 + 1 for compressed
	// Use a more reliable way based on point serialization standard
	// Let's use the standard EC point encoding (like Marshal)
	// P256 uncompressed is 1 + (256/8)*2 = 1 + 32*2 = 65 bytes.
	// Let's assume uncompressed for simplicity of fixed size reading.
	// A proper implementation should handle compressed/uncompressed flags and variable sizes.
	// For P-256, uncompressed is 65 bytes (0x04 || X || Y)
	pointSize := 65 // Assuming uncompressed form

	for i := 0; i < len(commitments); i++ {
		if len(data) < pointSize {
			return fmt.Errorf("invalid proof part data length for commitment %d", i)
		}
		pointBytes := data[:pointSize]
		data = data[pointSize:]

		point, err := BytesToPoint(pointBytes)
		if err != nil {
			return fmt.Errorf("failed to unmarshal commitment point %d: %w", i, err)
		}
		commitments[i].Point = point
	}

	p.CommitmentV = commitments[0]
	p.CommitmentV_minus_min = commitments[1]
	p.CommitmentMax_minus_v = commitments[2]
	p.A_v = commitments[3]
	p.A_v_minus_min = commitments[4]
	p.A_max_minus_v = commitments[5]

	// Responses (6 scalars)
	responses := []*big.Int{
		{}, {}, {}, {}, {}, {},
	}
	for i := 0; i < len(responses); i++ {
		if len(data) < 4 {
			return fmt.Errorf("invalid proof part data length for response %d length", i)
		}
		zLen := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		if len(data) < int(zLen) {
			return fmt.Errorf("invalid proof part data length for response %d data", i)
		}
		zBytes := data[:zLen]
		data = data[zLen:]

		responses[i] = new(big.Int).SetBytes(zBytes)
	}

	p.Z_v = responses[0]
	p.Z_rv = responses[1]
	p.Z_v_minus_min = responses[2]
	p.Z_rv_minus_min = responses[3]
	p.Z_max_minus_v = responses[4]
	p.Z_rv_max_minus_v = responses[5]

	if len(data) != 0 {
		return errors.New("trailing data after unmarshalling proof part")
	}

	return nil
}


// ProveEligibility generates the zero-knowledge proof that the prover's attributes
// satisfy all provided criteria ranges.
func ProveEligibility(
	witness *Witness,
	criteriaList []*EligibilityCriteria,
	params *SystemParameters,
) (*EligibilityProof, error) {

	if params == nil || params.G == nil || params.H == nil {
		return nil, errors.New("system parameters not initialized")
	}
	if witness == nil || len(witness.Values) != len(witness.Randoms) {
		return nil, errors.New("invalid witness")
	}
	if len(witness.Values) != len(criteriaList) {
		return nil, errors.New("number of witness attributes must match number of criteria")
	}

	// Prover first checks locally if criteria are satisfied.
	// If not, they cannot generate a valid range proof (specifically, proving non-negativity ZK).
	// Our simplified model doesn't have a robust non-negativity proof, but in principle
	// the prover would fail the process here.
	for i, criterion := range criteriaList {
		if !criterion.SatisfiesLocal(witness.Values[i]) {
			// In a real ZKP, the prover cannot produce a proof if they don't satisfy the statement.
			// We'll allow it structurally in this example for demonstration, but print a warning.
			fmt.Printf("Prover Warning: Witness value for %s (%s) does not satisfy criterion [%s, %s].\n",
				criterion.AttributeName, witness.Values[i], criterion.Min, criterion.Max)
			// return nil, fmt.Errorf("witness does not satisfy criterion for %s", criterion.AttributeName)
		}
	}

	proof := &EligibilityProof{}
	transcript := NewTranscript() // Initialize transcript for Fiat-Shamir

	for i := range witness.Values {
		part := &AttributeRangeProofPart{}
		// Generate proof part for the i-th attribute and criterion
		err := part.GenerateProofPart(
			witness.Values[i],
			witness.Randoms[i],
			criteriaList[i],
			transcript, // Pass the same transcript for all parts
			params,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate proof part for %s: %w", criteriaList[i].AttributeName, err)
		}
		proof.AttributeProofs = append(proof.AttributeProofs, part)
	}

	return proof, nil
}

// VerifyEligibilityProof verifies the zero-knowledge proof against the provided criteria.
func VerifyEligibilityProof(
	proof *EligibilityProof,
	criteriaList []*EligibilityCriteria,
	params *SystemParameters,
) (bool, error) {

	if params == nil || params.G == nil || params.H == nil {
		return false, errors.New("system parameters not initialized")
	}
	if proof == nil {
		return false, errors.New("proof is nil")
	}
	if len(proof.AttributeProofs) != len(criteriaList) {
		return false, errors.New("number of proof parts must match number of criteria")
	}

	transcript := NewTranscript() // Initialize transcript (must be same process as prover)

	for i := range proof.AttributeProofs {
		part := proof.AttributeProofs[i]
		criterion := criteriaList[i]

		// Verify proof part for the i-th attribute and criterion
		ok, err := part.VerifyProofPart(
			criterion,
			transcript, // Pass the same transcript for all parts
			params,
		)
		if err != nil {
			return false, fmt.Errorf("failed to verify proof part for %s: %w", criterion.AttributeName, err)
		}
		if !ok {
			return false, fmt.Errorf("verification failed for proof part %s", criterion.AttributeName)
		}
	}

	// If all individual parts verify, the overall proof is valid.
	// The AND logic is implicitly enforced because the verifier checks *all* parts.
	return true, nil
}

// --- Helper Cryptographic Functions ---

// generateRandomScalar generates a random scalar in the range [0, order-1].
func generateRandomScalar() (*big.Int, error) {
	// Generate a random big integer and reduce it modulo the curve order
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return k, nil
}

// hashToScalar hashes a byte slice to a scalar in the range [0, order-1].
func hashToScalar(data []byte) *big.Int {
	hasher := sha256.New()
	hasher.Write(data)
	hashBytes := hasher.Sum(nil)
	// Convert hash output to a big.Int and reduce modulo the curve order
	s := new(big.Int).SetBytes(hashBytes)
	s.Mod(s, order)
	return s
}

// PointToBytes serializes an elliptic curve point using Marshal.
func PointToBytes(p elliptic.Point) ([]byte, error) {
	if p == nil || p.X() == nil || p.Y() == nil {
		// Represent point at infinity or invalid point
		// Standard encoding for point at infinity is 0x00
		if p == nil { // Or check p.X == nil && p.Y == nil for Point at infinity
			return []byte{0x00}, nil
		}
		// For non-infinity points, Marshal handles validity
	}
	// Use standard EC point encoding (uncompressed form starts with 0x04)
	return elliptic.Marshal(curve, p.X(), p.Y()), nil
}

// BytesToPoint deserializes bytes back into an elliptic curve point.
func BytesToPoint(b []byte) (elliptic.Point, error) {
	if len(b) == 1 && b[0] == 0x00 {
		// This might represent the point at infinity depending on context/standard.
		// P256 doesn't typically return point at infinity from operations unless inputs are invalid.
		// Handle if necessary, otherwise rely on Unmarshal validation.
		return nil, errors.New("point at infinity not expected in this context")
	}
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal point")
	}
	// Unmarshal returns nil,nil for invalid points. Check IsOnCurve explicitly for safety.
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("unmarshalled point is not on curve")
	}
	return curve.Point(x, y), nil
}

// ScalarToBytes serializes a big.Int scalar.
func ScalarToBytes(s *big.Int) []byte {
	// Use ModBytes for fixed size representation if needed,
	// but simple Bytes() is often sufficient, just need length prefix for deserialization.
	return s.Bytes()
}

// BytesToScalar deserializes bytes back into a big.Int scalar.
func BytesToScalar(b []byte) *big.Int {
	// big.Int.SetBytes handles leading zeros correctly.
	return new(big.Int).SetBytes(b)
}

// --- Main Example Usage (optional, can be in a separate file) ---
/*
func main() {
	// 1. Setup System Parameters
	err := GenerateSystemParameters()
	if err != nil {
		fmt.Printf("Error generating system parameters: %v\n", err)
		return
	}
	fmt.Println("System Parameters Generated.")

	// Optional: Export/Import parameters
	params := &SystemParameters{G: G, H: H}
	paramBytes, err := ExportParameters(params)
	if err != nil { fmt.Printf("Export error: %v\n", err); return }
	importedParams, err := ImportParameters(paramBytes)
	if err != nil { fmt.Printf("Import error: %v\n", err); return }
	// Use importedParams from now on if desired

	// 2. Prover side: Define Witness and Criteria
	proverWitness := NewWitness()

	// Prover's actual private data
	proverAgeValue := NewAttributeValue(35)
	proverIncomeValue := NewAttributeValue(75000)

	// Generate random blinding factors for commitments
	proverAgeRandom, err := generateRandomScalar()
	if err != nil { fmt.Printf("Error generating random: %v\n", err); return }
	proverIncomeRandom, err := generateRandomScalar()
	if err != nil { fmt.Printf("Error generating random: %v\n", err); return }

	proverWitness.AddAttribute(proverAgeValue, proverAgeRandom)
	proverWitness.AddAttribute(proverIncomeValue, proverIncomeRandom)

	// Criteria defined by the Verifier (public)
	verifierCriteria := []*EligibilityCriteria{
		NewEligibilityCriteria("Age", 18, 65),
		NewEligibilityCriteria("Income", 50000, 150000), // Example: Needs income between 50k and 150k
	}

	fmt.Printf("Prover's Age: %v\n", proverAgeValue) // Prover knows this
	fmt.Printf("Prover's Income: %v\n", proverIncomeValue) // Prover knows this

	// Prover checks locally if they meet criteria
	allSatisfiedLocal := true
	for i, criterion := range verifierCriteria {
		if !criterion.SatisfiesLocal(proverWitness.Values[i]) {
			fmt.Printf("Prover local check failed for %s: %v is not in [%v, %v]\n", criterion.AttributeName, proverWitness.Values[i], criterion.Min, criterion.Max)
			allSatisfiedLocal = false
		} else {
			fmt.Printf("Prover local check passed for %s: %v is in [%v, %v]\n", criterion.AttributeName, proverWitness.Values[i], criterion.Min, criterion.Max)
		}
	}

	if !allSatisfiedLocal {
		fmt.Println("Prover does not meet criteria locally. Cannot generate valid proof.")
		// In a real system, prover would stop here or use a different protocol
		// For this example, we'll generate the proof anyway to show structure, but expect verification failure
		fmt.Println("Generating proof anyway for structural demonstration...")
	}


	// 3. Prover generates the ZKP
	fmt.Println("Prover is generating proof...")
	proof, err := ProveEligibility(proverWitness, verifierCriteria, importedParams) // Or use params
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}
	fmt.Println("Proof generated successfully.")

	// Optional: Serialize/Deserialize proof
	proofBytes, err := proof.MarshalBinary()
	if err != nil { fmt.Printf("Proof Marshal error: %v\n", err); return }
	fmt.Printf("Proof size: %d bytes\n", len(proofBytes))
	unmarshaledProof := &EligibilityProof{}
	err = unmarshaledProof.UnmarshalBinary(proofBytes)
	if err != nil { fmt.Printf("Proof Unmarshal error: %v\n", err); return }
	fmt.Println("Proof serialized and deserialized successfully.")
	proof = unmarshaledProof // Use the unmarshaled proof for verification

	// 4. Verifier side: Receives Proof and uses public Criteria and Parameters

	// Verifier verifies the ZKP
	fmt.Println("Verifier is verifying proof...")
	isValid, err := VerifyEligibilityProof(proof, verifierCriteria, importedParams) // Or use params
	if err != nil {
		fmt.Printf("Error verifying proof: %v\n", err)
	} else {
		fmt.Printf("Proof is valid: %v\n", isValid)
	}

	// Example with a value that does NOT meet the criteria (e.g., Age 15)
	fmt.Println("\n--- Testing with failing proof ---")
	failingWitness := NewWitness()
	failingAgeValue := NewAttributeValue(15) // Too young
	failingIncomeValue := NewAttributeValue(75000) // Still valid

	failingAgeRandom, err := generateRandomScalar()
	if err != nil { fmt.Printf("Error generating random: %v\n", err); return }
	failingIncomeRandom, err := generateRandomScalar()
	if err != nil { fmt.Printf("Error generating random: %v\n", err); return }

	failingWitness.AddAttribute(failingAgeValue, failingAgeRandom)
	failingWitness.AddAttribute(failingIncomeValue, failingIncomeRandom)

	fmt.Printf("Prover's Age: %v (should fail age check)\n", failingAgeValue)
	fmt.Printf("Prover's Income: %v\n", failingIncomeValue)

	failingAllSatisfiedLocal := true
	for i, criterion := range verifierCriteria {
		if !criterion.SatisfiesLocal(failingWitness.Values[i]) {
			fmt.Printf("Prover local check failed for %s: %v is not in [%v, %v]\n", criterion.AttributeName, failingWitness.Values[i], criterion.Min, criterion.Max)
			failingAllSatisfiedLocal = false
		} else {
			fmt.Printf("Prover local check passed for %s: %v is in [%v, %v]\n", criterion.AttributeName, failingWitness.Values[i], criterion.Min, criterion.Max)
		}
	}
	if failingAllSatisfiedLocal { // Should not happen with Age 15
		fmt.Println("Prover unexpectedly meets criteria locally?")
	}

	fmt.Println("Prover is generating failing proof...")
	failingProof, err := ProveEligibility(failingWitness, verifierCriteria, importedParams)
	if err != nil {
		fmt.Printf("Error generating failing proof: %v\n", err)
		// Continue to verify it if generated anyway due to the warning
	} else {
		fmt.Println("Failing proof generated successfully.")

		fmt.Println("Verifier is verifying failing proof...")
		isFailingValid, err := VerifyEligibilityProof(failingProof, verifierCriteria, importedParams)
		if err != nil {
			fmt.Printf("Error verifying failing proof: %v\n", err) // Expect an error here if verification fails correctly
		} else {
			fmt.Printf("Failing proof is valid: %v\n", isFailingValid) // Should be false
		}
	}

}
*/
```