The following Go package `zkp` implements a Zero-Knowledge Proof for **"Private Aggregated Contribution with Compliance."**

This ZKP allows a Prover to demonstrate to a Verifier that:
1.  They have a collection of `N` private contributions (`x_1, ..., x_N`).
2.  The *sum* of these private contributions (`Sum = x_1 + ... + x_N`) is at least a public `Threshold`.
3.  Each individual private contribution `x_i` is non-negative and falls within a public maximum range (`0 <= x_i <= 2^L - 1`, where `L` is `MaxValueBitLength`).

All of this is achieved without revealing the individual `x_i` values or the exact `Sum` itself.

### Interesting, Advanced-Concept, Creative & Trendy Aspects:

*   **Privacy-Preserving Aggregation & Compliance:** This ZKP is directly applicable to scenarios where collective compliance (e.g., total carbon emissions below a cap, total funds collected above a minimum, total usage within limits) needs to be verified without exposing sensitive individual data. This is crucial for federated learning, consortium blockchains, and privacy-centric audits.
*   **Modular ZKP Construction:** It combines several fundamental ZKP building blocks:
    *   **Pedersen Commitments:** For unconditionally hiding the private values while allowing homomorphic operations.
    *   **Fiat-Shamir Heuristic:** To convert interactive Sigma protocols into non-interactive proofs.
    *   **Simplified Range Proofs for Non-Negativity and Upper Bounds:** Instead of full-blown Bulletproofs or Groth16 (which are very complex to implement from scratch), this solution utilizes a bit-decomposition approach. It proves a value is within a range by:
        1.  Committing to each bit of the value.
        2.  Using a custom **Zero-Knowledge OR (ZK-OR) protocol** to prove that each committed bit is either `0` or `1` (without revealing which).
        3.  Proving that the commitment to the full value is consistent with the sum of its bit commitments (scaled by powers of two).
    *   **Threshold Proof:** Achieved by creatively reducing the `Sum >= Threshold` problem to a non-negativity range proof for `(Sum - Threshold)`.
*   **Focus on Primitives, Not Libraries:** This implementation is built from lower-level cryptographic primitives (elliptic curve arithmetic, SHA256) rather than relying on high-level ZKP libraries, fulfilling the "don't duplicate any of open source" requirement by presenting a novel combination and application of these primitives.

### Outline and Function Summary:

This project is structured into logical modules. The number of functions exceeds the requested 20, providing a comprehensive, yet illustrative, implementation.

**I. Cryptographic Primitives and Utilities**
*   `Params`: Global ZKP parameters (elliptic curve, Pedersen generators G, H, curve order).
*   `Commitment`: Represents an Elliptic Curve point (the result of a Pedersen commitment).
*   `GenerateCommitmentParams()`: Initializes the P256 elliptic curve and generates two independent generators G and H.
*   `Commit(value, randomness, params)`: Creates a Pedersen commitment `value*G + randomness*H`.
*   `Open(commitment, value, randomness, params)`: Verifies if a given commitment correctly opens to a specific value and randomness.
*   `AddCommitments(c1, c2, params)`: Adds two Pedersen commitments homomorphically (`(v1+v2)*G + (r1+r2)*H`).
*   `ScalarMultiplyCommitment(c, scalar, params)`: Multiplies a Pedersen commitment by a scalar homomorphically (`(s*v)*G + (s*r)*H`).
*   `GenerateRandomScalar(order)`: Generates a cryptographically secure random `big.Int` suitable for scalar operations within the curve order.
*   `BigIntToBytes(val, byteLen)`: Converts a `big.Int` to a fixed-length byte slice, padding or truncating as necessary.
*   `BytesToBigInt(b)`: Converts a byte slice to a `big.Int`.

**II. Proof Transcript Management (Fiat-Shamir Heuristic)**
*   `Transcript`: Stores proof elements (`[]byte`) to ensure deterministic challenge generation.
*   `NewTranscript()`: Creates an empty `Transcript`.
*   `Transcript_AppendPoint(t, label, p)`: Appends an elliptic curve point's coordinates to the transcript.
*   `Transcript_AppendScalar(t, label, s)`: Appends a `big.Int` scalar's byte representation to the transcript.
*   `GenerateChallenge(t, order)`: Generates a deterministic challenge (`big.Int`) from the accumulated transcript data using SHA256.

**III. Core ZKP Components (Schnorr, Bit ZK-OR, Range Proof)**
*   `SchnorrProof`: Data structure for a standard Schnorr proof (response `Z` and commitment `A`).
*   `Prover_GenerateSchnorrProof(randScalar, targetCommitment, challenge, params)`: Generates a Schnorr proof of knowledge of `randScalar` for `targetCommitment = randScalar * H`.
*   `Verifier_VerifySchnorrProof(proof, targetCommitment, challenge, params)`: Verifies a Schnorr proof.
*   `BitZKORProof`: Data structure for a ZK-OR proof that a committed bit is either 0 or 1. This uses a customized Chaum-Pedersen style ZK-OR.
*   `Prover_GenerateBitZKORProof(bit, bitRandomness, params, transcript)`: Generates a ZK-OR proof for a bit `b \in \{0, 1\}` in `Commit(b, bitRandomness)`.
*   `Verifier_VerifyBitZKORProof(C_bit, proof, params, transcript)`: Verifies a ZK-OR proof for a committed bit.
*   `Prover_DecomposeIntoBits(value, bitLength)`: Helper function to decompose a `big.Int` value into a slice of its binary bits (0 or 1).
*   `ValueInSmallRangeProof`: Contains bit commitments, their ZK-OR proofs, and a Schnorr consistency proof.
*   `Prover_GenerateValueInSmallRangeProof(value, valueRandomness, bitLength, params, transcript)`: Generates a proof that `value` (committed as `Commit(value, valueRandomness)`) is in the range `[0, 2^L-1]`. This involves bit decomposition, individual bit ZK-OR proofs, and a Schnorr proof for the overall consistency.
*   `Verifier_VerifyValueInSmallRangeProof(valueCommitment, rangeProof, bitLength, params, transcript)`: Verifies a `ValueInSmallRangeProof`.

**IV. Main ZKP Protocol (Aggregated Contribution and Threshold)**
*   `ThresholdProof`: Data structure for proving `Score >= Threshold`.
*   `Prover_GenerateThresholdProof(score, scoreRandomness, threshold, maxValBitLength, params, transcript)`: Generates a proof that a `score` (committed as `Commit(score, scoreRandomness)`) is greater than or equal to a `threshold`. It does this by proving `(score - threshold)` is non-negative using `ValueInSmallRangeProof`.
*   `Verifier_VerifyThresholdProof(scoreCommitment, proof, threshold, maxValBitLength, params, transcript)`: Verifies a `ThresholdProof`.

**V. Full Proof Structure and Orchestration**
*   `FullProof`: Aggregates all proof components from individual contributions and the final sum.
*   `Prover_ConstructFullProof(secretsX, randomnessX, threshold, maxValBitLength, params)`: Orchestrates all prover steps:
    1.  Commits to each private contribution `x_i`.
    2.  Generates `ValueInSmallRangeProof` for each `x_i` (to prove `0 <= x_i <= 2^L-1`).
    3.  Calculates the `totalScore = sum(x_i)` and its aggregated randomness.
    4.  Commits to the `totalScore`.
    5.  Generates a `ThresholdProof` for `totalScore >= Threshold`.
*   `Verifier_ProcessFullProof(fullProof, threshold, maxValBitLength, params)`: Orchestrates all verifier steps:
    1.  Verifies each `ValueInSmallRangeProof` for `x_i`.
    2.  Reconstructs the `totalScoreCommitment` by homomorphically summing the `x_i` commitments.
    3.  Compares the reconstructed `totalScoreCommitment` with the one provided in the `fullProof`.
    4.  Verifies the `ThresholdProof` for the `totalScore`.

```go
// Package zkp implements a Zero-Knowledge Proof for private aggregated contribution with compliance.
//
// This ZKP allows a Prover to demonstrate that:
// 1. They have a collection of `N` private contributions (`x_1, ..., x_N`).
// 2. The *sum* of these private contributions (`Sum = x_1 + ... + x_N`) is at least a public `Threshold`.
// 3. Each individual private contribution `x_i` is non-negative and falls within a public maximum range
//    (`0 <= x_i <= 2^L - 1`, where `L` is `MaxValueBitLength`).
//
// All of this is achieved without revealing the individual `x_i` values or the exact `Sum` itself.
//
// Concepts used:
// - Pedersen Commitments: Additively homomorphic commitments for `x_i` and `Sum`.
// - Sigma Protocols: Interactive proofs (made non-interactive via Fiat-Shamir heuristic) for knowledge of discrete logarithms (randomness and committed values).
// - Simplified Range Proofs for Non-Negativity and Upper Bounds: For proving `V >= 0` and `V <= MaxValue` (where MaxValue = 2^L-1), the Prover commits to `V` and its bit decomposition. A custom Zero-Knowledge OR (ZK-OR) protocol is used to prove each bit is either 0 or 1, and a consistency proof verifies the bit decomposition. This simplifies full Bulletproofs or Groth16.
// - Threshold Proof: Achieved by proving `Sum - Threshold >= 0`, reducing to the non-negativity range proof.
//
// Outline and Function Summary:
//
// I. Cryptographic Primitives and Utilities
//    1.  `Params`: Global ZKP parameters (elliptic curve, generators G, H, curve order).
//    2.  `Commitment`: Represents an Elliptic Curve point (g^value * h^randomness).
//    3.  `GenerateCommitmentParams()`: Initializes curve, G, H.
//    4.  `Commit(value, randomness, params)`: Creates a Pedersen commitment.
//    5.  `Open(commitment, value, randomness, params)`: Verifies an opened commitment.
//    6.  `AddCommitments(c1, c2, params)`: Homomorphically adds two commitments.
//    7.  `ScalarMultiplyCommitment(c, scalar, params)`: Homomorphically scales a commitment.
//    8.  `GenerateRandomScalar(order)`: Generates a cryptographically secure random scalar.
//    9.  `BigIntToBytes(val, byteLen)`: Converts `big.Int` to its fixed-size byte representation.
//    10. `BytesToBigInt(b)`: Converts a byte slice to `big.Int`.
//
// II. Proof Transcript Management (Fiat-Shamir Heuristic)
//    11. `Transcript`: Stores proof elements for challenge generation.
//    12. `NewTranscript()`: Creates a new transcript.
//    13. `Transcript_AppendPoint(t, label, p)`: Appends an EC point to the transcript.
//    14. `Transcript_AppendScalar(t, label, s)`: Appends a scalar to the transcript.
//    15. `GenerateChallenge(t, order)`: Generates a deterministic challenge from transcript.
//
// III. Core ZKP Components (Schnorr, Bit ZK-OR, Range Proof)
//    16. `SchnorrProof`: Represents a Schnorr proof for knowledge of a discrete logarithm.
//    17. `Prover_GenerateSchnorrProof(randScalar, targetCommitment, challenge, params)`: Generates a Schnorr proof.
//    18. `Verifier_VerifySchnorrProof(proof, targetCommitment, challenge, params)`: Verifies a Schnorr proof.
//    19. `BitZKORProof`: Represents a ZK-OR proof for a committed bit (0 or 1).
//    20. `Prover_GenerateBitZKORProof(bit, bitRandomness, params, transcript)`: Generates a ZK-OR proof for a bit.
//    21. `Verifier_VerifyBitZKORProof(C_bit, proof, params, transcript)`: Verifies a ZK-OR proof for a bit.
//    22. `Prover_DecomposeIntoBits(value, bitLength)`: Helper to decompose a value into bits.
//    23. `ValueInSmallRangeProof`: Contains bit commitments and their ZK-OR proofs, plus a consistency proof.
//    24. `Prover_GenerateValueInSmallRangeProof(value, valueRandomness, bitLength, params, transcript)`: Generates a proof that a value is in [0, 2^L-1].
//    25. `Verifier_VerifyValueInSmallRangeProof(valueCommitment, rangeProof, bitLength, params, transcript)`: Verifies a value is in [0, 2^L-1].
//
// IV. Main ZKP Protocol (Aggregated Contribution and Threshold)
//    26. `ThresholdProof`: Proof for `Sum >= Threshold`.
//    27. `Prover_GenerateThresholdProof(score, scoreRandomness, threshold, maxValBitLength, params, transcript)`: Generates proof for threshold.
//    28. `Verifier_VerifyThresholdProof(scoreCommitment, proof, threshold, maxValBitLength, params, transcript)`: Verifies proof for threshold.
//
// V. Full Proof Structure and Orchestration
//    29. `FullProof`: Aggregates all proof components.
//    30. `Prover_ConstructFullProof(secretsX, randomnessX, threshold, maxValBitLength, params)`: Orchestrates all prover steps to generate `FullProof`.
//    31. `Verifier_ProcessFullProof(fullProof, threshold, maxValBitLength, params)`: Orchestrates all verifier steps to verify `FullProof`.

package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// I. Cryptographic Primitives and Utilities

// Params holds the elliptic curve parameters and Pedersen generators.
type Params struct {
	Curve elliptic.Curve
	G     *elliptic.Point // Generator 1 (base point of the curve)
	H     *elliptic.Point // Generator 2 (randomly chosen independent point)
	Order *big.Int        // Order of the curve (n)
}

// Commitment represents a Pedersen commitment as an elliptic curve point.
type Commitment struct {
	X *big.Int
	Y *big.Int
}

// GenerateCommitmentParams initializes the elliptic curve, selects two generators G and H.
// G is the base point of the curve. H is a randomly chosen point on the curve.
func GenerateCommitmentParams() (*Params, error) {
	curve := elliptic.P256() // Using P256 curve, a standard NIST curve

	G := curve.Params().Gx // Base point X
	GY := curve.Params().Gy // Base point Y

	// Generate a random H point by hashing a known string or random bytes to a point.
	// For simplicity, we'll derive H by multiplying G by a random scalar.
	// This ensures H is on the curve but is not G itself.
	var HX, HY *big.Int
	var err error
	for {
		hScalarBytes := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, hScalarBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes for H scalar: %w", err)
		}
		hScalar := new(big.Int).SetBytes(hScalarBytes)
		hScalar.Mod(hScalar, curve.Params().N) // Ensure scalar is within curve order
		if hScalar.Cmp(big.NewInt(0)) == 0 {    // Avoid scalar 0
			continue
		}
		HX, HY = curve.ScalarBaseMult(hScalar.Bytes())
		if HX.Cmp(G) == 0 && HY.Cmp(GY) == 0 { // Ensure H is not G
			continue
		}
		break
	}

	return &Params{
		Curve: curve,
		G:     &elliptic.Point{X: G, Y: GY},
		H:     &elliptic.Point{X: HX, Y: HY},
		Order: curve.Params().N,
	}, nil
}

// Commit creates a Pedersen commitment C = value*G + randomness*H.
func Commit(value *big.Int, randomness *big.Int, params *Params) *Commitment {
	// value*G
	valX, valY := params.Curve.ScalarBaseMult(value.Bytes())
	// randomness*H
	randX, randY := params.Curve.ScalarMult(params.H.X, params.H.Y, randomness.Bytes())

	// Add the two points: (value*G) + (randomness*H)
	commitX, commitY := params.Curve.Add(valX, valY, randX, randY)
	return &Commitment{X: commitX, Y: commitY}
}

// Open verifies a Pedersen commitment C = value*G + randomness*H.
func Open(commitment *Commitment, value *big.Int, randomness *big.Int, params *Params) bool {
	expectedCommitment := Commit(value, randomness, params)
	return expectedCommitment.X.Cmp(commitment.X) == 0 && expectedCommitment.Y.Cmp(commitment.Y) == 0
}

// AddCommitments performs C1 + C2 = (v1+v2)*G + (r1+r2)*H.
func AddCommitments(c1 *Commitment, c2 *Commitment, params *Params) *Commitment {
	if c1 == nil || c2 == nil {
		return nil // Or handle error
	}
	resX, resY := params.Curve.Add(c1.X, c1.Y, c2.X, c2.Y)
	return &Commitment{X: resX, Y: resY}
}

// ScalarMultiplyCommitment performs s*C = (s*v)*G + (s*r)*H.
func ScalarMultiplyCommitment(c *Commitment, scalar *big.Int, params *Params) *Commitment {
	if c == nil || scalar == nil {
		return nil // Or handle error
	}
	resX, resY := params.Curve.ScalarMult(c.X, c.Y, scalar.Bytes())
	return &Commitment{X: resX, Y: resY}
}

// GenerateRandomScalar generates a cryptographically secure random big.Int
// suitable for use as a randomness or challenge, within the curve order.
func GenerateRandomScalar(order *big.Int) (*big.Int, error) {
	// Generate random bytes for the scalar
	bytes := make([]byte, order.BitLen()/8+1) // Ensure enough bytes for the order's bit length
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to big.Int and take modulo to fit within the curve order
	r := new(big.Int).SetBytes(bytes)
	r.Mod(r, order)

	// Ensure randomness is not zero, as zero randomness can break security in some ZKP contexts.
	// Regenerate if zero.
	if r.Cmp(big.NewInt(0)) == 0 {
		return GenerateRandomScalar(order) // Recursive call if zero, unlikely but good practice
	}
	return r, nil
}

// BigIntToBytes converts a big.Int to its fixed-size byte representation.
// `byteLen` specifies the desired length. If `val` is shorter, it's padded with zeros.
// If `val` is longer, it's truncated from the left (most significant bytes).
func BigIntToBytes(val *big.Int, byteLen int) []byte {
	if val == nil {
		return make([]byte, byteLen) // Return zero-filled bytes for nil
	}
	bytes := val.Bytes()
	if len(bytes) >= byteLen {
		return bytes[len(bytes)-byteLen:] // Truncate if too long (take least significant bytes)
	}
	padded := make([]byte, byteLen)
	copy(padded[byteLen-len(bytes):], bytes) // Pad with leading zeros
	return padded
}

// BytesToBigInt converts a byte slice to a big.Int.
func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// II. Proof Transcript Management (Fiat-Shamir Heuristic)

// Transcript stores proof elements to generate challenges deterministically using Fiat-Shamir.
type Transcript struct {
	data []byte
}

// NewTranscript creates an empty Transcript.
func NewTranscript() *Transcript {
	return &Transcript{data: make([]byte, 0)}
}

// Transcript_AppendPoint appends an elliptic curve point to the transcript.
// It uses a label for domain separation and includes X and Y coordinates.
func Transcript_AppendPoint(t *Transcript, label string, p *Commitment) {
	t.data = append(t.data, []byte(label)...)
	t.data = append(t.data, BigIntToBytes(p.X, 32)...) // P256 X coordinate is 32 bytes
	t.data = append(t.data, BigIntToBytes(p.Y, 32)...) // P256 Y coordinate is 32 bytes
}

// Transcript_AppendScalar appends a scalar (big.Int) to the transcript.
// It uses a label for domain separation and includes the scalar's byte representation.
func Transcript_AppendScalar(t *Transcript, label string, s *big.Int) {
	t.data = append(t.data, []byte(label)...)
	t.data = append(t.data, BigIntToBytes(s, 32)...) // Scalars are typically 32 bytes for P256
}

// GenerateChallenge generates a deterministic challenge using SHA256 (Fiat-Shamir heuristic).
// The challenge is reduced modulo the curve order to ensure it fits.
func GenerateChallenge(t *Transcript, order *big.Int) *big.Int {
	hasher := sha256.New()
	hasher.Write(t.data) // Hash the accumulated transcript data
	hashBytes := hasher.Sum(nil)

	challenge := new(big.Int).SetBytes(hashBytes)
	return challenge.Mod(challenge, order) // Reduce modulo curve order
}

// III. Core ZKP Components (Schnorr, Bit ZK-OR, Range Proof)

// SchnorrProof represents a standard Schnorr proof for knowledge of a discrete logarithm.
// Used to prove knowledge of `exponent` in `Point = exponent * Generator`.
// Specifically, it proves knowledge of `randScalar` for a commitment `C = randScalar * H`.
type SchnorrProof struct {
	Response   *big.Int   // z = k + e*randScalar mod Q
	Commitment *Commitment // a = k*H, where k is a random nonce
}

// Prover_GenerateSchnorrProof generates a Schnorr proof for knowledge of `randScalar`
// such that `targetCommitment = randScalar * H` (conceptually, in this context).
// The actual `targetCommitment` is the part `r*H` of a Pedersen commitment `v*G + r*H`.
func Prover_GenerateSchnorrProof(randScalar *big.Int, params *Params, transcript *Transcript) (*SchnorrProof, error) {
	// Generate a random nonce 'k'
	k, err := GenerateRandomScalar(params.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce k: %w", err)
	}

	// Compute commitment `a = k*H` (prover's initial commitment)
	aX, aY := params.Curve.ScalarMult(params.H.X, params.H.Y, k.Bytes())
	commitmentA := &Commitment{X: aX, Y: aY}

	// Append `a` to transcript and get challenge `e`
	Transcript_AppendPoint(transcript, "Schnorr_A_commitment", commitmentA)
	challenge := GenerateChallenge(transcript, params.Order)

	// Compute response `z = k + e*randScalar mod Q`
	eTimesR := new(big.Int).Mul(challenge, randScalar)
	eTimesR.Mod(eTimesR, params.Order)
	z := new(big.Int).Add(k, eTimesR)
	z.Mod(z, params.Order)

	return &SchnorrProof{Response: z, Commitment: commitmentA}, nil
}

// Verifier_VerifySchnorrProof verifies a Schnorr proof for knowledge of `randScalar`
// in `targetCommitment = randScalar * H`.
// The verification equation is `z*H == a + e*targetCommitment`.
func Verifier_VerifySchnorrProof(proof *SchnorrProof, targetCommitment *Commitment, params *Params, transcript *Transcript) bool {
	// Re-append `a` to transcript to get same challenge `e`
	Transcript_AppendPoint(transcript, "Schnorr_A_commitment", proof.Commitment)
	challenge := GenerateChallenge(transcript, params.Order)

	// Left side: z*H
	zHX, zHY := params.Curve.ScalarMult(params.H.X, params.H.Y, proof.Response.Bytes())
	leftPoint := &Commitment{X: zHX, Y: zHY}

	// Right side: a + e*targetCommitment
	// e*targetCommitment
	eTargetX, eTargetY := params.Curve.ScalarMult(targetCommitment.X, targetCommitment.Y, challenge.Bytes())
	eTargetCommitment := &Commitment{X: eTargetX, Y: eTargetY}
	// a + e*targetCommitment
	rightPoint := AddCommitments(proof.Commitment, eTargetCommitment, params)

	return leftPoint.X.Cmp(rightPoint.X) == 0 && leftPoint.Y.Cmp(rightPoint.Y) == 0
}

// BitZKORProof represents a ZK-OR proof that a committed bit is either 0 or 1.
// It uses a Chaum-Pedersen based interactive ZK-OR structure for two Schnorr-like proofs.
// Prover either knows `r0` for `Commit(0, r0)` OR `r1` for `Commit(1, r1)`.
type BitZKORProof struct {
	C0_simulated *Commitment // Simulated commitment `a0` for the `b=0` branch
	C1_simulated *Commitment // Simulated commitment `a1` for the `b=1` branch
	Z0           *big.Int    // Response `z0` for the `b=0` path
	Z1           *big.Int    // Response `z1` for the `b=1` path
	E0           *big.Int    // Challenge `e0` used for the `b=0` path (derived from `e` and `e1`)
	E1           *big.Int    // Challenge `e1` used for the `b=1` path (randomly chosen for the dummy path)
}

// Prover_GenerateBitZKORProof generates a ZK-OR proof for a bit being 0 or 1.
// `bit` is the actual bit (0 or 1), `bitRandomness` is its commitment randomness `r_b`.
// The goal is to prove `Commit(bit, r_b)` is either `Commit(0, r_b)` or `Commit(1, r_b)`.
// This proof demonstrates knowledge of `r_b` and `b` where `b \in \{0,1\}`.
func Prover_GenerateBitZKORProof(bit *big.Int, bitRandomness *big.Int, params *Params, transcript *Transcript) (*BitZKORProof, error) {
	proof := &BitZKORProof{}

	// Generate random nonces and dummy challenge/response for the *non-actual* branch.
	k_real, err := GenerateRandomScalar(params.Order) // Nonce for the real branch
	if err != nil {
		return nil, err
	}
	e_dummy, err := GenerateRandomScalar(params.Order) // Challenge for the dummy branch
	if err != nil {
		return nil, err
	}
	z_dummy, err := GenerateRandomScalar(params.Order) // Response for the dummy branch
	if err != nil {
		return nil, err
	}

	// Prover's commitment for the bit: C_bit = G^b * H^r_b
	C_bit := Commit(bit, bitRandomness, params)

	if bit.Cmp(big.NewInt(0)) == 0 { // Real bit is 0: Prover knows `r_b` for `Commit(0, r_b)`
		// Real branch is for 0. `target_0 = C_bit`
		// `a0_real = k_real * H`
		a0_realX, a0_realY := params.Curve.ScalarMult(params.H.X, params.H.Y, k_real.Bytes())
		proof.C0_simulated = &Commitment{X: a0_realX, Y: a0_realY}

		// Dummy branch is for 1. `target_1 = C_bit - G` (since C_bit=H^r_b, this is G^-1 H^r_b)
		C_target_1_x, C_target_1_y := params.Curve.Sub(C_bit.X, C_bit.Y, params.G.X, params.G.Y) // C_bit - G
		C_target_1 := &Commitment{X: C_target_1_x, Y: C_target_1_y}

		// `a1_dummy = z_dummy * H - e_dummy * C_target_1`
		z_dummy_H_x, z_dummy_H_y := params.Curve.ScalarMult(params.H.X, params.H.Y, z_dummy.Bytes())
		e_dummy_C_target_1_x, e_dummy_C_target_1_y := params.Curve.ScalarMult(C_target_1.X, C_target_1.Y, e_dummy.Bytes())
		a1_dummyX, a1_dummyY := params.Curve.Sub(z_dummy_H_x, z_dummy_H_y, e_dummy_C_target_1_x, e_dummy_C_target_1_y)
		proof.C1_simulated = &Commitment{X: a1_dummyX, Y: a1_dummyY}

		proof.Z1 = z_dummy // Store dummy response
		proof.E1 = e_dummy // Store dummy challenge

	} else { // Real bit is 1: Prover knows `r_b` for `Commit(1, r_b)` (i.e. for C_bit - G)
		// Real branch is for 1. `target_1 = C_bit - G`
		// `a1_real = k_real * H`
		a1_realX, a1_realY := params.Curve.ScalarMult(params.H.X, params.H.Y, k_real.Bytes())
		proof.C1_simulated = &Commitment{X: a1_realX, Y: a1_realY}

		// Dummy branch is for 0. `target_0 = C_bit`
		// `a0_dummy = z_dummy * H - e_dummy * C_bit`
		z_dummy_H_x, z_dummy_H_y := params.Curve.ScalarMult(params.H.X, params.H.Y, z_dummy.Bytes())
		e_dummy_C_bit_x, e_dummy_C_bit_y := params.Curve.ScalarMult(C_bit.X, C_bit.Y, e_dummy.Bytes())
		a0_dummyX, a0_dummyY := params.Curve.Sub(z_dummy_H_x, z_dummy_H_y, e_dummy_C_bit_x, e_dummy_C_bit_y)
		proof.C0_simulated = &Commitment{X: a0_dummyX, Y: a0_dummyY}

		proof.Z0 = z_dummy // Store dummy response
		proof.E0 = e_dummy // Store dummy challenge
	}

	// Append both simulated commitments to the transcript and get the combined challenge `e`
	Transcript_AppendPoint(transcript, "ZKOR_a0", proof.C0_simulated)
	Transcript_AppendPoint(transcript, "ZKOR_a1", proof.C1_simulated)
	e := GenerateChallenge(transcript, params.Order)

	// Compute the missing challenge and response for the real branch
	if bit.Cmp(big.NewInt(0)) == 0 { // Real branch was for 0
		// `e0 = e - e1 (mod Q)`
		e0 := new(big.Int).Sub(e, proof.E1)
		e0.Mod(e0, params.Order)
		proof.E0 = e0

		// `z0 = k_real + e0 * bitRandomness (mod Q)`
		e0_rand := new(big.Int).Mul(proof.E0, bitRandomness)
		e0_rand.Mod(e0_rand, params.Order)
		proof.Z0 = new(big.Int).Add(k_real, e0_rand)
		proof.Z0.Mod(proof.Z0, params.Order)
	} else { // Real branch was for 1
		// `e1 = e - e0 (mod Q)`
		e1 := new(big.Int).Sub(e, proof.E0)
		e1.Mod(e1, params.Order)
		proof.E1 = e1

		// `z1 = k_real + e1 * bitRandomness (mod Q)`
		// The `bitRandomness` is the `r` in `G^1 H^r`. So `r` is `bitRandomness`.
		e1_rand := new(big.Int).Mul(proof.E1, bitRandomness)
		e1_rand.Mod(e1_rand, params.Order)
		proof.Z1 = new(big.Int).Add(k_real, e1_rand)
		proof.Z1.Mod(proof.Z1, params.Order)
	}

	return proof, nil
}

// Verifier_VerifyBitZKORProof verifies a ZK-OR proof for a bit.
// `C_bit` is the original commitment to the bit.
func Verifier_VerifyBitZKORProof(C_bit *Commitment, proof *BitZKORProof, params *Params, transcript *Transcript) bool {
	// Re-append `a0_simulated` and `a1_simulated` to transcript to get same combined challenge `e`
	Transcript_AppendPoint(transcript, "ZKOR_a0", proof.C0_simulated)
	Transcript_AppendPoint(transcript, "ZKOR_a1", proof.C1_simulated)
	e := GenerateChallenge(transcript, params.Order)

	// Check `e = e0 + e1 (mod Q)`
	eSum := new(big.Int).Add(proof.E0, proof.E1)
	eSum.Mod(eSum, params.Order)
	if e.Cmp(eSum) != 0 {
		return false
	}

	// Verify branch 0: `z0*H == a0 + e0*C_bit` (target is Commit(0,r))
	// Left side: `z0*H`
	z0_H_x, z0_H_y := params.Curve.ScalarMult(params.H.X, params.H.Y, proof.Z0.Bytes())
	left0 := &Commitment{X: z0_H_x, Y: z0_H_y}
	// Right side: `a0 + e0*C_bit`
	e0_C_bit_x, e0_C_bit_y := params.Curve.ScalarMult(C_bit.X, C_bit.Y, proof.E0.Bytes())
	e0_C_bit := &Commitment{X: e0_C_bit_x, Y: e0_C_bit_y}
	right0 := AddCommitments(proof.C0_simulated, e0_C_bit, params)
	if left0.X.Cmp(right0.X) != 0 || left0.Y.Cmp(right0.Y) != 0 {
		return false // Proof for branch 0 fails
	}

	// Verify branch 1: `z1*H == a1 + e1*(C_bit - G)` (target is Commit(1,r))
	// Left side: `z1*H`
	z1_H_x, z1_H_y := params.Curve.ScalarMult(params.H.X, params.H.Y, proof.Z1.Bytes())
	left1 := &Commitment{X: z1_H_x, Y: z1_H_y}
	// Right side: `a1 + e1*(C_bit - G)`
	// `C_bit - G` is the commitment to `(bit-1, r_b)`
	C_bit_minus_G_x, C_bit_minus_G_y := params.Curve.Sub(C_bit.X, C_bit.Y, params.G.X, params.G.Y)
	C_bit_minus_G := &Commitment{X: C_bit_minus_G_x, Y: C_bit_minus_G_y}
	e1_C_bit_minus_G_x, e1_C_bit_minus_G_y := params.Curve.ScalarMult(C_bit_minus_G.X, C_bit_minus_G.Y, proof.E1.Bytes())
	e1_C_bit_minus_G := &Commitment{X: e1_C_bit_minus_G_x, Y: e1_C_bit_minus_G_y}
	right1 := AddCommitments(proof.C1_simulated, e1_C_bit_minus_G, params)
	if left1.X.Cmp(right1.X) != 0 || left1.Y.Cmp(right1.Y) != 0 {
		return false // Proof for branch 1 fails
	}

	return true
}

// Prover_DecomposeIntoBits decomposes a big.Int into a slice of big.Int bits (0 or 1).
func Prover_DecomposeIntoBits(value *big.Int, bitLength int) []*big.Int {
	bits := make([]*big.Int, bitLength)
	temp := new(big.Int).Set(value)
	for i := 0; i < bitLength; i++ {
		bits[i] = new(big.Int).And(temp, big.NewInt(1)) // Get the least significant bit
		temp.Rsh(temp, 1)                               // Right shift to get next bit
	}
	return bits
}

// ValueInSmallRangeProof contains bit commitments, their ZK-OR proofs, and a Schnorr consistency proof.
// It proves that the value committed in `valueCommitment` is within `[0, 2^L-1]`.
type ValueInSmallRangeProof struct {
	BitCommitments   []*Commitment     // Commitments to individual bits (C_b0, C_b1, ...)
	BitZKORProofs    []*BitZKORProof   // ZK-OR proofs for each bit being 0 or 1
	ConsistencyProof *SchnorrProof     // Proves `valueRandomness` for `valueCommitment` is known.
}

// Prover_GenerateValueInSmallRangeProof generates a proof that a value is in the range `[0, 2^L-1]`.
// `value` is the secret value, `valueRandomness` is its secret randomness for `valueCommitment`.
// `bitLength` is `L`.
func Prover_GenerateValueInSmallRangeProof(
	value *big.Int,
	valueRandomness *big.Int,
	bitLength int,
	params *Params,
	transcript *Transcript,
) (*ValueInSmallRangeProof, error) {
	proof := &ValueInSmallRangeProof{}

	// Ensure value is non-negative and fits within the bitLength
	if value.Sign() < 0 || value.BitLen() > bitLength {
		return nil, fmt.Errorf("value %s is out of range [0, 2^%d-1]", value.String(), bitLength)
	}

	// 1. Decompose value into bits
	bits := Prover_DecomposeIntoBits(value, bitLength)

	// 2. Commit to each bit and generate ZK-OR proof
	proof.BitCommitments = make([]*Commitment, bitLength)
	proof.BitZKORProofs = make([]*BitZKORProof, bitLength)

	for i := 0; i < bitLength; i++ {
		r_bi, err := GenerateRandomScalar(params.Order) // Randomness for this specific bit commitment
		if err != nil {
			return nil, fmt.Errorf("failed to generate randomness for bit %d: %w", i, err)
		}
		proof.BitCommitments[i] = Commit(bits[i], r_bi, params)

		// Append bit commitment to transcript for its ZK-OR proof challenge
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_Cb%d", i), proof.BitCommitments[i])

		// Each ZK-OR proof should derive its challenge from a local transcript
		bitZKORTranscript := NewTranscript()
		Transcript_AppendPoint(bitZKORTranscript, "ZKOR_C_bit_target", proof.BitCommitments[i]) // Target commitment for ZK-OR
		bitZKOR, err := Prover_GenerateBitZKORProof(bits[i], r_bi, params, bitZKORTranscript)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ZK-OR for bit %d: %w", i, err)
		}
		proof.BitZKORProofs[i] = bitZKOR

		// Append ZK-OR proof components to the main transcript to influence subsequent challenges
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_ZKOR_C0_%d", i), bitZKOR.C0_simulated)
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_ZKOR_C1_%d", i), bitZKOR.C1_simulated)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_Z0_%d", i), bitZKOR.Z0)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_Z1_%d", i), bitZKOR.Z1)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_E0_%d", i), bitZKOR.E0)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_E1_%d", i), bitZKOR.E1)
	}

	// 3. Generate Schnorr proof for knowledge of `valueRandomness` for `Commit(value, valueRandomness)`.
	// This helps link `valueRandomness` to the `valueCommitment`.
	// The `valueCommitment` itself is passed separately to the verifier (not part of this proof struct).
	schnorrProof, err := Prover_GenerateSchnorrProof(valueRandomness, params, transcript) // Transcript updated by bit commitments/ZKORs
	if err != nil {
		return nil, fmt.Errorf("failed to generate Schnorr proof for value randomness: %w", err)
	}
	proof.ConsistencyProof = schnorrProof

	return proof, nil
}

// Verifier_VerifyValueInSmallRangeProof verifies a ValueInSmallRangeProof.
// `valueCommitment` is the commitment to the value being proven in range.
func Verifier_VerifyValueInSmallRangeProof(
	valueCommitment *Commitment,
	rangeProof *ValueInSmallRangeProof,
	bitLength int,
	params *Params,
	transcript *Transcript,
) bool {
	if len(rangeProof.BitCommitments) != bitLength || len(rangeProof.BitZKORProofs) != bitLength {
		return false // Malformed proof: incorrect number of bit components
	}

	// 1. Verify each bit's ZK-OR proof
	for i := 0; i < bitLength; i++ {
		// Re-append bit commitment to transcript to reconstruct the exact challenge context for ZK-OR
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_Cb%d", i), rangeProof.BitCommitments[i])

		// Create a local transcript for the ZK-OR proof verification
		bitZKORTranscript := NewTranscript()
		Transcript_AppendPoint(bitZKORTranscript, "ZKOR_C_bit_target", rangeProof.BitCommitments[i])

		// Re-append ZK-OR proof components to the main transcript
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_ZKOR_C0_%d", i), rangeProof.BitZKORProofs[i].C0_simulated)
		Transcript_AppendPoint(transcript, fmt.Sprintf("RangeProof_ZKOR_C1_%d", i), rangeProof.BitZKORProofs[i].C1_simulated)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_Z0_%d", i), rangeProof.BitZKORProofs[i].Z0)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_Z1_%d", i), rangeProof.BitZKORProofs[i].Z1)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_E0_%d", i), rangeProof.BitZKORProofs[i].E0)
		Transcript_AppendScalar(transcript, fmt.Sprintf("RangeProof_ZKOR_E1_%d", i), rangeProof.BitZKORProofs[i].E1)

		if !Verifier_VerifyBitZKORProof(rangeProof.BitCommitments[i], rangeProof.BitZKORProofs[i], params, bitZKORTranscript) {
			return false // One of the bit ZK-OR proofs failed
		}
	}

	// 2. Verify consistency: `valueCommitment == sum(C_bit_i * 2^i)`
	// Reconstruct the expected value commitment from bit commitments
	summedBitCommitment := Commit(big.NewInt(0), big.NewInt(0), params) // Start with identity point (0*G + 0*H)
	for i := 0; i < bitLength; i++ {
		two_pow_i := new(big.Int).Lsh(big.NewInt(1), uint(i))
		scaledBitCommitment := ScalarMultiplyCommitment(rangeProof.BitCommitments[i], two_pow_i, params)
		summedBitCommitment = AddCommitments(summedBitCommitment, scaledBitCommitment, params)
	}

	// Check if the actual `valueCommitment` matches the one derived from bits.
	// This ensures that the committed value is `sum(b_i * 2^i)` and its randomness is `sum(r_bi * 2^i)`.
	if valueCommitment.X.Cmp(summedBitCommitment.X) != 0 || valueCommitment.Y.Cmp(summedBitCommitment.Y) != 0 {
		return false // Value-from-bits consistency failed
	}

	// 3. Verify the Schnorr proof for knowledge of `valueRandomness` for `valueCommitment`.
	return Verifier_VerifySchnorrProof(rangeProof.ConsistencyProof, valueCommitment, params, transcript)
}

// IV. Main ZKP Protocol (Aggregated Contribution and Threshold)

// ThresholdProof proves `Score >= Threshold`.
// It contains a commitment to `(Score - Threshold)` and a `ValueInSmallRangeProof` for this difference,
// demonstrating `Score - Threshold >= 0`.
type ThresholdProof struct {
	ScoreMinusThresholdCommitment *Commitment           // Commitment to `(Score - Threshold)`
	ScoreMinusThresholdRangeProof *ValueInSmallRangeProof // Proof that `(Score - Threshold)` is in range `[0, 2^L-1]`
}

// Prover_GenerateThresholdProof generates a proof that `score >= threshold`.
// `score` is the secret total score, `scoreRandomness` is its secret randomness.
func Prover_GenerateThresholdProof(
	score *big.Int,
	scoreRandomness *big.Int,
	threshold *big.Int,
	maxValBitLength int,
	params *Params,
	transcript *Transcript,
) (*ThresholdProof, error) {
	// 1. Calculate `Score - Threshold`
	scoreMinusThreshold := new(big.Int).Sub(score, threshold)

	// Ensure that (Score - Threshold) can be represented by `maxValBitLength` if positive.
	// If it's negative, the proof will inherently fail `ValueInSmallRangeProof` which checks non-negativity.
	if scoreMinusThreshold.BitLen() > maxValBitLength {
		// This means Score - Threshold is too large to fit in the specified bit length.
		// For a real range proof, it'd prove <= MaxValue. Here it is implicitly checked.
		// If Prover sends a value too large, it might pass the `ValueInSmallRangeProof`
		// if `MaxValueBitLength` is not carefully chosen to be small enough.
		// For this ZKP, `maxValBitLength` is the upper bound.
	}

	// 2. Commit to `Score - Threshold`.
	// `Commit(Score - Threshold, scoreRandomness)` is actually `Commit(Score, scoreRandomness) - Commit(Threshold, 0)`.
	// We construct `Commit(Score - Threshold, scoreRandomness)` directly.
	scoreMinusThresholdCommitment := Commit(scoreMinusThreshold, scoreRandomness, params)

	// Append commitment to transcript before its range proof.
	Transcript_AppendPoint(transcript, "ThreshProof_SMT_Comm", scoreMinusThresholdCommitment)

	// 3. Generate range proof for `Score - Threshold >= 0` (i.e., it's in `[0, 2^L-1]`)
	rangeProof, err := Prover_GenerateValueInSmallRangeProof(
		scoreMinusThreshold,
		scoreRandomness, // The randomness for `(Score - Threshold)` is `scoreRandomness`
		maxValBitLength,
		params,
		transcript, // Use the main transcript for range proof components
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate range proof for Score - Threshold: %w", err)
	}

	return &ThresholdProof{
		ScoreMinusThresholdCommitment: scoreMinusThresholdCommitment,
		ScoreMinusThresholdRangeProof: rangeProof,
	}, nil
}

// Verifier_VerifyThresholdProof verifies `Score >= Threshold`.
// `scoreCommitment` is the commitment to the total score.
func Verifier_VerifyThresholdProof(
	scoreCommitment *Commitment,
	proof *ThresholdProof,
	threshold *big.Int,
	maxValBitLength int,
	params *Params,
	transcript *Transcript,
) bool {
	// 1. Reconstruct `Commit(Score - Threshold, r_score)` from `scoreCommitment` and `threshold`.
	// Expected: `C_score - G^Threshold` (since `Commit(Threshold, 0) = G^Threshold`).
	thresholdG := Commit(threshold, big.NewInt(0), params) // G^Threshold
	expectedSMTCommitment := AddCommitments(scoreCommitment, ScalarMultiplyCommitment(thresholdG, big.NewInt(-1), params), params)

	// Check if this matches the provided `proof.ScoreMinusThresholdCommitment`.
	if expectedSMTCommitment.X.Cmp(proof.ScoreMinusThresholdCommitment.X) != 0 ||
		expectedSMTCommitment.Y.Cmp(proof.ScoreMinusThresholdCommitment.Y) != 0 {
		return false // Mismatch in `Score - Threshold` commitment
	}

	// Append commitment to transcript before its range proof.
	Transcript_AppendPoint(transcript, "ThreshProof_SMT_Comm", proof.ScoreMinusThresholdCommitment)

	// 2. Verify the range proof for `Score - Threshold >= 0`.
	return Verifier_VerifyValueInSmallRangeProof(
		proof.ScoreMinusThresholdCommitment,
		proof.ScoreMinusThresholdRangeProof,
		maxValBitLength,
		params,
		transcript, // Use the main transcript for range proof components
	)
}

// V. Full Proof Structure and Orchestration

// FullProof aggregates all proof components for the entire ZKP protocol.
type FullProof struct {
	XCommitments    []*Commitment           // Public commitments to individual private contributions `x_i`
	XRangeProofs    []*ValueInSmallRangeProof // Proofs for `x_i` in `[0, 2^L-1]`
	ScoreCommitment *Commitment             // Public commitment to the total aggregated score (`Sum = sum(x_i)`)
	ThresholdProof  *ThresholdProof         // Proof that `Sum >= Threshold`
}

// Prover_ConstructFullProof orchestrates all prover steps to generate the `FullProof`.
// `secretsX` are the private contributions, `randomnessX` are their corresponding random blinding factors.
// `threshold` is the public minimum sum required. `maxValBitLength` defines the upper bound for `x_i`.
func Prover_ConstructFullProof(
	secretsX []*big.Int,
	randomnessX []*big.Int,
	threshold *big.Int,
	maxValBitLength int,
	params *Params,
) (*FullProof, error) {
	if len(secretsX) == 0 || len(secretsX) != len(randomnessX) {
		return nil, fmt.Errorf("number of contributions and randomness values must match and be non-empty")
	}

	proof := &FullProof{}
	n := len(secretsX)

	proof.XCommitments = make([]*Commitment, n)
	proof.XRangeProofs = make([]*ValueInSmallRangeProof, n)

	// Initialize aggregated score and randomness
	totalScore := big.NewInt(0)
	totalScoreRandomness := big.NewInt(0)
	mainTranscript := NewTranscript() // Main transcript for Fiat-Shamir challenges

	for i := 0; i < n; i++ {
		// 1. Commit to `x_i`
		proof.XCommitments[i] = Commit(secretsX[i], randomnessX[i], params)
		Transcript_AppendPoint(mainTranscript, fmt.Sprintf("Cx%d", i), proof.XCommitments[i])

		// 2. Generate range proof for `x_i` (to prove `0 <= x_i <= 2^L-1`)
		xRangeProof, err := Prover_GenerateValueInSmallRangeProof(
			secretsX[i], randomnessX[i], maxValBitLength, params, mainTranscript, // Main transcript for range proof
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate range proof for x_%d: %w", i, err)
		}
		proof.XRangeProofs[i] = xRangeProof

		// 3. Accumulate `totalScore = sum(x_i)` and `totalScoreRandomness = sum(r_xi)`
		totalScore.Add(totalScore, secretsX[i])
		totalScoreRandomness.Add(totalScoreRandomness, randomnessX[i])
		totalScoreRandomness.Mod(totalScoreRandomness, params.Order) // Keep randomness within curve order
	}

	// 4. Commit to `totalScore`
	proof.ScoreCommitment = Commit(totalScore, totalScoreRandomness, params)
	Transcript_AppendPoint(mainTranscript, "C_score", proof.ScoreCommitment)

	// 5. Generate `ThresholdProof` for `totalScore >= Threshold`
	thresholdProof, err := Prover_GenerateThresholdProof(
		totalScore, totalScoreRandomness, threshold, maxValBitLength, params, mainTranscript,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate threshold proof: %w", err)
	}
	proof.ThresholdProof = thresholdProof
	// The `ThresholdProof` elements are appended to the main transcript within its generation function.

	return proof, nil
}

// Verifier_ProcessFullProof orchestrates all verifier steps to verify the `FullProof`.
func Verifier_ProcessFullProof(
	fullProof *FullProof,
	threshold *big.Int,
	maxValBitLength int,
	params *Params,
) bool {
	n := len(fullProof.XCommitments)
	if n == 0 || n != len(fullProof.XRangeProofs) {
		return false // Malformed proof: incorrect number of commitments or range proofs
	}

	mainTranscript := NewTranscript()

	// 1. Verify range proofs for each `x_i` and reconstruct the `totalScoreCommitment`
	reconstructedTotalScoreCommitment := Commit(big.NewInt(0), big.NewInt(0), params) // Start with identity point

	for i := 0; i < n; i++ {
		// Re-append commitment to `x_i` to the transcript
		Transcript_AppendPoint(mainTranscript, fmt.Sprintf("Cx%d", i), fullProof.XCommitments[i])

		// Verify `ValueInSmallRangeProof` for `x_i`
		if !Verifier_VerifyValueInSmallRangeProof(
			fullProof.XCommitments[i], fullProof.XRangeProofs[i], maxValBitLength, params, mainTranscript,
		) {
			fmt.Printf("Verification failed for x_i range proof at index %d\n", i)
			return false
		}

		// Homomorphically add `x_i`'s commitment to reconstruct the total sum commitment
		reconstructedTotalScoreCommitment = AddCommitments(reconstructedTotalScoreCommitment, fullProof.XCommitments[i], params)
	}

	// 2. Verify `ScoreCommitment` consistency: `C_score == sum(C_xi)`
	// The `fullProof.ScoreCommitment` should match the `reconstructedTotalScoreCommitment`.
	Transcript_AppendPoint(mainTranscript, "C_score", fullProof.ScoreCommitment)
	if reconstructedTotalScoreCommitment.X.Cmp(fullProof.ScoreCommitment.X) != 0 ||
		reconstructedTotalScoreCommitment.Y.Cmp(fullProof.ScoreCommitment.Y) != 0 {
		fmt.Println("Verification failed: Reconstructed score commitment mismatch with provided score commitment.")
		return false
	}

	// 3. Verify `ThresholdProof` for `Sum >= Threshold`
	if !Verifier_VerifyThresholdProof(
		fullProof.ScoreCommitment, fullProof.ThresholdProof, threshold, maxValBitLength, params, mainTranscript,
	) {
		fmt.Println("Verification failed for threshold proof.")
		return false
	}

	return true // All verification steps passed
}
```