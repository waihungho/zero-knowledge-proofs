Okay, let's design and implement a Zero-Knowledge Range Proof in Go. Instead of a simple "prove you know x such that C=xG", we will implement a more advanced and applicable concept: **Proving that a secret value `x`, for which a Pedersen Commitment `C = x*G + r*H` is known, lies within a specified range `[min, max]`, without revealing `x` or the randomness `r`.**

This is a core building block for privacy-preserving applications like confidential transactions (showing amounts are non-negative or within limits) or private identity verification (showing age is within a range without revealing age).

We will construct this proof using standard elliptic curve cryptography and Sigma protocols, combining:
1.  **Pedersen Commitments:** For binding to the value and randomness.
2.  **Bit Decomposition:** Representing the value `v >= 0` as a sum of bits `v = \sum b_i 2^i`.
3.  **ZK Proof of Knowledge of Discrete Log (Sigma KDL):** To prove the commitment relates to the bit commitments correctly.
4.  **ZK Proof of OR (Sigma OR):** To prove each bit commitment commits to either 0 or 1.

The overall proof `min <= x <= max` is achieved by proving `x - min >= 0` and `max - x >= 0`. Both non-negativity proofs are instances of proving a value is in `[0, 2^N]` for a sufficient `N`.

This approach avoids directly duplicating complex SNARK/STARK libraries and focuses on building a specific, useful ZKP from cryptographic primitives.

---

## Outline & Function Summary

```golang
// Package zkrange implements a Zero-Knowledge Proof system for proving a secret
// committed value lies within a specified range [min, max].
// It utilizes Pedersen commitments, bit decomposition, Sigma protocol for Knowledge
// of Discrete Log (KDL), and a Sigma protocol for ZK-OR proofs.

/*
Outline:
1.  Elliptic Curve Point Helpers: Basic operations on curve points.
2.  Scalar Helpers: Basic operations on big.Int scalars.
3.  Hashing Utilities: For Fiat-Shamir challenges and generating curve points.
4.  Parameters: Public parameters (G, H, curve).
5.  Pedersen Commitment: Struct and methods for commitments.
6.  ZK-OR Proof for Bit: Sigma protocol to prove a commitment is to 0 OR 1.
7.  Sigma Proof for KDL: Sigma protocol to prove knowledge of 's' in Y = s*P.
8.  Range Proof [0, 2^N]: Proof structure and logic to prove a committed value 'v' is in [0, 2^N] by decomposing 'v' into bits and proving properties of bit commitments.
    -   Sum Check Proof: Prove C - sum(C_i * 2^i) relates correctly to randomness.
    -   Bit Proofs: Prove each C_i commits to 0 or 1.
9.  Range Proof [min, max]: Overall proof structure and logic to prove 'x' is in [min, max] using two [0, 2^N] proofs for (x - min) and (max - x).
10. Serialization: Methods to marshal/unmarshal proof components and parameters.
*/

/*
Function Summary:

// Elliptic Curve Point Helpers
func pointMarshal(p *ec.Point) []byte
func pointUnmarshal(curve elliptic.Curve, data []byte) (*ec.Point, error)
func pointAdd(p1, p2 *ec.Point) *ec.Point
func pointSub(p1, p2 *ec.Point) *ec.Point
func scalarMult(p *ec.Point, s *big.Int) *ec.Point
func scalarBaseMult(curve elliptic.Curve, s *big.Int) *ec.Point
func hashToCurvePoint(curve elliptic.Curve, seed string) (*ec.Point, error)

// Scalar Helpers
func generateRandomScalar(curve elliptic.Curve) (*big.Int, error)
func bigIntToBytes(i *big.Int) []byte
func bytesToBigInt(b []byte) *big.Int
func safeBigInt(i *big.Int, max *big.Int) *big.Int // Ensures scalar is within curve order

// Hashing Utilities
func hashFiatShamir(inputs ...[]byte) *big.Int // Generates challenge from transcript

// Parameters
type Params struct { ... }
func Setup(curve elliptic.Curve, seed string) (*Params, error) // Generates G, H

// Pedersen Commitment
type PedersenCommitment struct { ... }
func NewPedersenCommitment(params *Params, value, randomness *big.Int) (*PedersenCommitment, error)
func (pc *PedersenCommitment) Point() *ec.Point
func (pc *PedersenCommitment) MarshalBinary() ([]byte, error)
func (pc *PedersenCommitment) UnmarshalBinary(params *Params, data []byte) error
func (pc *PedersenCommitment) Add(other *PedersenCommitment) *PedersenCommitment // Homomorphic Add
func (pc *PedersenCommitment) Subtract(other *PedersenCommitment) *PedersenCommitment // Homomorphic Subtract
func (pc *PedersenCommitment) ScalarMult(s *big.Int) *PedersenCommitment // Homomorphic ScalarMult (value*s, randomness*s)
func commitmentFromPoint(params *Params, p *ec.Point) *PedersenCommitment // Internal helper

// ZK-OR Proof for Bit (0 or 1)
type ZKORBitProof struct { ... } // Represents (c0, s0_G, s0_H), (c1, s1_G, s1_H)
func proveBitZKOR(params *Params, C_bit *PedersenCommitment, bit, randomness *big.Int, transcript *Transcript) (*ZKORBitProof, error) // Proves C_bit commits to 'bit' using 'randomness'
func verifyBitZKOR(params *Params, C_bit *PedersenCommitment, proof *ZKORBitProof, transcript *Transcript) error

// Sigma Proof for KDL (Knowledge of Discrete Log)
type SigmaKDLProof struct { ... } // Represents T, s
func proveKDL(params *Params, point *ec.Point, scalar *big.Int, transcript *Transcript) (*SigmaKDLProof, error) // Proves knowledge of 'scalar' such that point = scalar * H
func verifyKDL(params *Params, point *ec.Point, proof *SigmaKDLProof, transcript *Transcript) error

// Range Proof [0, 2^N] (Internal)
type RangeProofN struct { ... } // Contains C_i's, SumCheckProof, BitProofs
func deriveBitLength(maxValue *big.Int) uint // Calculates N for [0, 2^N]
func proveRangeN(params *Params, C *PedersenCommitment, value, randomness *big.Int, n uint, transcript *Transcript) (*RangeProofN, error)
func verifyRangeN(params *Params, C *PedersenCommitment, proof *RangeProofN, n uint, transcript *Transcript) error

// Range Proof [min, max] (Public Interface)
type RangeProofMinMax struct { ... } // Contains C_x, Proof for C_y, Proof for C_z
func ProveRangeMinMax(params *Params, C_x *PedersenCommitment, x_value, r_randomness *big.Int, min, max *big.Int) (*RangeProofMinMax, error)
func VerifyRangeMinMax(params *Params, C_x *PedersenCommitment, proof *RangeProofMinMax, min, max *big.Int) error

// Serialization methods for Proof structs (Marshal/UnmarshalBinary)
func (p *ZKORBitProof) MarshalBinary() ([]byte, error)
func (p *ZKORBitProof) UnmarshalBinary(data []byte) error
func (p *SigmaKDLProof) MarshalBinary() ([]byte, error)
func (p *SigmaKDLProof) UnmarshalBinary(data []byte) error
func (p *RangeProofN) MarshalBinary() ([]byte, error) // Requires marshaling sub-proofs/commitments
func (p *RangeProofN) UnmarshalBinary(params *Params, data []byte) error // Requires unmarshaling sub-proofs/commitments
func (p *RangeProofMinMax) MarshalBinary() ([]byte, error) // Requires marshaling sub-proofs/commitments
func (p *RangeProofMinMax) UnmarshalBinary(params *Params, data []byte) error // Requires unmarshaling sub-proofs/commitments

// Transcript struct for Fiat-Shamir
type Transcript struct { ... }
func NewTranscript(label string) *Transcript
func (t *Transcript) Append(label string, data []byte) error
func (t *Transcript) Challenge(label string) *big.Int
*/
```

---

```golang
package zkrange

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	ErrInvalidProof      = errors.New("invalid proof")
	ErrSerialization     = errors.New("serialization error")
	ErrDeserialization   = errors.New("deserialization error")
	ErrInvalidChallenge  = errors.New("invalid challenge")
	ErrInvalidParameters = errors.New("invalid parameters")
)

// --- Elliptic Curve Point Helpers ---

// pointMarshal serializes an elliptic curve point.
func pointMarshal(p *ec.Point) []byte {
	if p == nil || p.IsInfinity() {
		return []byte{0x00} // Represent infinity with a single byte
	}
	return elliptic.Marshal(p.Curve, p.X, p.Y)
}

// pointUnmarshal deserializes an elliptic curve point.
func pointUnmarshal(curve elliptic.Curve, data []byte) (*ec.Point, error) {
	if len(data) == 0 {
		return nil, ErrDeserialization
	}
	if len(data) == 1 && data[0] == 0x00 {
		// Representing infinity
		return &ec.Point{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)}, nil // Standard way to represent infinity point in crypto/elliptic internal code
	}
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil { // Unmarshal failed
		return nil, ErrDeserialization
	}
	return &ec.Point{Curve: curve, X: x, Y: y}, nil
}

// pointAdd performs point addition on the curve. Handles nil/infinity.
func pointAdd(p1, p2 *ec.Point) *ec.Point {
	if p1 == nil || p1.IsInfinity() {
		return p2
	}
	if p2 == nil || p2.IsInfinity() {
		return p1
	}
	x, y := p1.Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return &ec.Point{Curve: p1.Curve, X: x, Y: y}
}

// pointSub performs point subtraction on the curve (p1 - p2). Handles nil/infinity.
func pointSub(p1, p2 *ec.Point) *ec.Point {
	if p2 == nil || p2.IsInfinity() {
		return p1 // p1 - infinity = p1
	}
	// p1 - p2 = p1 + (-p2)
	negP2 := &ec.Point{Curve: p2.Curve, X: p2.X, Y: new(big.Int).Neg(p2.Y)}
	return pointAdd(p1, negP2)
}

// scalarMult performs scalar multiplication s * p. Handles nil point.
func scalarMult(p *ec.Point, s *big.Int) *ec.Point {
	if p == nil || p.IsInfinity() || isScalarZero(s) {
		return &ec.Point{Curve: p.Curve, X: big.NewInt(0), Y: big.NewInt(0)} // Infinity
	}
	x, y := p.Curve.ScalarMult(p.X, p.Y, s.Bytes())
	return &ec.Point{Curve: p.Curve, X: x, Y: y}
}

// scalarBaseMult performs scalar multiplication s * G (base point).
func scalarBaseMult(curve elliptic.Curve, s *big.Int) *ec.Point {
	if isScalarZero(s) {
		return &ec.Point{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)} // Infinity
	}
	x, y := curve.ScalarBaseMult(s.Bytes())
	return &ec.Point{Curve: curve, X: x, Y: y}
}

// hashToCurvePoint attempts to deterministically map a seed to a point on the curve.
// Note: This is a simplified approach. Proper hash-to-curve is more complex.
// This version hashes the seed and uses the result as a scalar to multiply H.
func hashToCurvePoint(curve elliptic.Curve, seed string) (*ec.Point, error) {
	// A proper implementation would use a standard like RFC 9380.
	// For this example, we'll hash and multiply the base point or H if H is available.
	// Let's hash and multiply the base point G for parameter generation.
	digest := sha256.Sum256([]byte(seed))
	s := new(big.Int).SetBytes(digest[:])
	// Ensure scalar is within curve order
	s = safeBigInt(s, curve.Params().N)
	return scalarBaseMult(curve, s), nil
}

// --- Scalar Helpers ---

// generateRandomScalar generates a cryptographically secure random scalar within the curve order [1, N-1].
func generateRandomScalar(curve elliptic.Curve) (*big.Int, error) {
	n := curve.Params().N
	if n == nil {
		return nil, ErrInvalidParameters
	}
	// Generate a random number < n
	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	// Ensure it's not zero
	if k.Sign() == 0 {
		return generateRandomScalar(curve) // Retry
	}
	return k, nil
}

// bigIntToBytes converts big.Int to fixed-size byte slice based on curve order size.
func bigIntToBytes(i *big.Int) []byte {
	if i == nil {
		return nil // Or a fixed zero-value representation
	}
	// Calculate byte length needed for the curve order (e.g., 32 bytes for P256)
	// Use the coordinate size for consistent length, assuming scalars fit.
	byteLen := (elliptic.P256().Params().BitSize + 7) / 8
	b := i.Bytes()
	// Pad or truncate to byteLen
	if len(b) > byteLen {
		// This shouldn't happen if scalar is < curve order
		b = b[len(b)-byteLen:]
	} else if len(b) < byteLen {
		paddedB := make([]byte, byteLen)
		copy(paddedB[byteLen-len(b):], b)
		b = paddedB
	}
	return b
}

// bytesToBigInt converts byte slice to big.Int.
func bytesToBigInt(b []byte) *big.Int {
	if len(b) == 0 {
		return big.NewInt(0) // Or handle as error/nil depending on convention
	}
	return new(big.Int).SetBytes(b)
}

// safeBigInt ensures a scalar is within the range [0, max).
func safeBigInt(i *big.Int, max *big.Int) *big.Int {
	if i == nil {
		return big.NewInt(0)
	}
	mod := new(big.Int).Mod(i, max)
	if mod.Sign() < 0 { // Handle negative results from Mod if any
		mod.Add(mod, max)
	}
	return mod
}

// isScalarZero checks if a big.Int is zero.
func isScalarZero(s *big.Int) bool {
	return s == nil || s.Sign() == 0
}

// --- Hashing Utilities (Fiat-Shamir Transcript) ---

// Transcript manages the state for Fiat-Shamir challenge generation.
type Transcript struct {
	hasher io.Writer // Use a hash function as the writer
}

// NewTranscript creates a new transcript initialized with a label.
func NewTranscript(label string) *Transcript {
	h := sha256.New()
	h.Write([]byte(label)) // Domain separation
	return &Transcript{hasher: h}
}

// Append adds data to the transcript.
func (t *Transcript) Append(label string, data []byte) error {
	// Append label length + label, then data length + data
	// This prevents collision attacks where different concatenations of data yield the same hash
	labelLen := big.NewInt(int64(len(label)))
	dataLen := big.NewInt(int64(len(data)))

	// Simple length prefixing for demo. More robust: use varint encoding or fixed size.
	// Using fixed 4 bytes for length for simplicity here.
	lenBytes := make([]byte, 4)

	labelLenBytes := bigIntToBytes(labelLen)[:4] // Assume length fits in 4 bytes
	copy(lenBytes, labelLenBytes)
	if _, err := t.hasher.Write(lenBytes); err != nil { return err }
	if _, err := t.hasher.Write([]byte(label)); err != nil { return err }

	dataLenBytes := bigIntToBytes(dataLen)[:4] // Assume length fits in 4 bytes
	copy(lenBytes, dataLenBytes)
	if _, err := t.hasher.Write(lenBytes); err != nil { return err }
	if _, err := t.hasher.Write(data); err != nil { return err }

	return nil
}

// Challenge generates a challenge scalar from the current transcript state.
func (t *Transcript) Challenge(label string) *big.Int {
	// Append label before generating challenge
	if err := t.Append(label, []byte{}); err != nil {
		// Should not happen with standard hashers, but handle defensively
		panic(fmt.Sprintf("transcript append failed: %v", err))
	}

	// Get hash sum
	h := t.hasher.(sha256.Hash) // Cast back to get the sum
	hashBytes := h.Sum(nil)

	// Create a new hasher with the current state for the next challenge
	newState := sha256.New()
	newState.Write(hashBytes) // Initialize new state with the output of the last step
	t.hasher = newState

	// Convert hash bytes to a scalar within the curve order N
	curveOrder := elliptic.P256().Params().N // Assume P256 for challenge range
	challenge := new(big.Int).SetBytes(hashBytes)

	return safeBigInt(challenge, curveOrder)
}


// --- Parameters ---

// Params holds the public parameters for the ZK range proof.
type Params struct {
	Curve elliptic.Curve // The elliptic curve in use
	G     *ec.Point      // The standard base point
	H     *ec.Point      // A secondary base point, derived deterministically but not a simple multiple of G
}

// Setup generates the public parameters (G and H) for the proof system.
// H is generated by hashing a seed to a point.
func Setup(curve elliptic.Curve, seed string) (*Params, error) {
	// G is the standard base point of the curve
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	G := &ec.Point{Curve: curve, X: Gx, Y: Gy}

	// H is derived from a seed. Must not be G or a simple multiple of G.
	// Hashing a known seed and multiplying G is one way.
	// A better way is using a verifiable random function or hashing to a point method.
	// For simplicity, let's use hashing the seed and multiplying G. We need to be sure
	// it's not a small multiple. Using a different seed string helps.
	H, err := hashToCurvePoint(curve, seed+"-zkrangeproof-H")
	if err != nil {
		return nil, fmt.Errorf("failed to generate H point: %w", err)
	}
	if H.IsInfinity() {
		return nil, fmt.Errorf("generated H point is at infinity")
	}

	return &Params{Curve: curve, G: G, H: H}, nil
}

// MarshalBinary serializes the Params.
func (p *Params) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// Curve is implicit if we fix to P256, or needs identifier
	// For now, assume P256 based on the implementation
	buf.Write(pointMarshal(p.G)) // G is usually fixed, but included for completeness
	buf.Write(pointMarshal(p.H))
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the Params. Assumes P256 curve.
func (p *Params) UnmarshalBinary(data []byte) error {
	if p.Curve == nil {
		p.Curve = elliptic.P256() // Default to P256 if not set
	}

	// G size (P256: 33 bytes compressed, 65 uncompressed + 1 type byte)
	// Let's find the expected point size based on the curve
	pointByteSize := (p.Curve.Params().BitSize+7)/8 + 1 // +1 for type byte (0x02, 0x03, 0x04) or infinity byte (0x00)

	// Need to handle variable-length point marshaling if infinity marker is used
	// If using fixed-size marshaling (like UnmarshalCompressed/Uncompressed), need different logic.
	// Using standard elliptic.Marshal/Unmarshal includes type byte.
	// Point Marshal: 0x04 | X | Y (uncompressed) or 0x02/0x03 | X (compressed)
	// Point Unmarshal: expects this format.
	// Our pointMarshal uses elliptic.Marshal directly for non-infinity, 0x00 for infinity.
	// Let's read points sequentially.

	reader := bytes.NewReader(data)

	// Read G
	// A robust approach would read length prefixes, but let's try reading point bytes directly
	// and rely on elliptic.Unmarshal to consume the correct amount.
	// This requires a peek or careful reading. Let's simplify for this example
	// and assume standard marshal output sizes or read sequentially.
	// With pointMarshal using elliptic.Marshal for non-infinity, it writes X and Y.
	// X and Y are big-endian fixed size (curve bit size / 8).
	// Let's use a simple separator or fixed structure.
	// Simpler: Assume fixed order G, H and read sequentially based on curve size.
	// We need to distinguish infinity (1 byte 0x00) from standard points.

	gBytes, err := readPrefixedBytes(reader)
	if err != nil { return fmt.Errorf("failed to read G bytes: %w", err) }
	p.G, err = pointUnmarshal(p.Curve, gBytes)
	if err != nil { return fmt.Errorf("failed to unmarshal G point: %w", err) }

	hBytes, err := readPrefixedBytes(reader)
	if err != nil { return fmt.Errorf("failed to read H bytes: %w", err) }
	p.H, err = pointUnmarshal(p.Curve, hBytes)
	if err != nil { return fmt.Errorf("failed to unmarshal H point: %w", err) }

	// Basic validation
	if p.G.IsInfinity() || p.H.IsInfinity() {
		return ErrInvalidParameters // G and H cannot be infinity
	}

	return nil
}

// writePrefixedBytes writes data preceded by its length (as 4-byte big-endian)
func writePrefixedBytes(writer *bytes.Buffer, data []byte) error {
	lenBytes := bigIntToBytes(big.NewInt(int64(len(data))))[:4] // Use first 4 bytes for length
	if _, err := writer.Write(lenBytes); err != nil { return err }
	if _, err := writer.Write(data); err != nil { return err }
	return nil
}

// readPrefixedBytes reads data preceded by its length (as 4-byte big-endian)
func readPrefixedBytes(reader *bytes.Reader) ([]byte, error) {
	lenBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, lenBytes); err != nil {
		if err == io.EOF { return nil, io.ErrUnexpectedEOF }
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}
	dataLen := int(bytesToBigInt(lenBytes).Int64())
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(reader, data); err != nil {
		if err == io.EOF { return nil, io.ErrUnexpectedEOF }
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return data, nil
}


// --- Pedersen Commitment ---

// PedersenCommitment represents a commitment C = value*G + randomness*H
type PedersenCommitment struct {
	P *ec.Point // The resulting elliptic curve point
	params *Params // Reference to parameters for context
}

// NewPedersenCommitment creates a new Pedersen commitment.
func NewPedersenCommitment(params *Params, value, randomness *big.Int) (*PedersenCommitment, error) {
	if params == nil || params.G == nil || params.H == nil {
		return nil, ErrInvalidParameters
	}
	curve := params.Curve

	// C = value*G + randomness*H
	valueG := scalarBaseMult(curve, safeBigInt(value, curve.Params().N)) // Use G (base point) for value
	randomnessH := scalarMult(params.H, safeBigInt(randomness, curve.Params().N)) // Use H for randomness

	P := pointAdd(valueG, randomnessH)
	return &PedersenCommitment{P: P, params: params}, nil
}

// commitmentFromPoint creates a PedersenCommitment struct from a point. Internal use.
func commitmentFromPoint(params *Params, p *ec.Point) *PedersenCommitment {
	if p == nil {
		p = &ec.Point{Curve: params.Curve, X: big.NewInt(0), Y: big.NewInt(0)} // Infinity
	}
	return &PedersenCommitment{P: p, params: params}
}


// Point returns the elliptic curve point of the commitment.
func (pc *PedersenCommitment) Point() *ec.Point {
	if pc == nil {
		return nil // Or return infinity point based on convention
	}
	return pc.P
}

// Add performs homomorphic addition of two commitments: C1 + C2 = (v1+v2)G + (r1+r2)H
func (pc *PedersenCommitment) Add(other *PedersenCommitment) *PedersenCommitment {
	if pc == nil || other == nil || pc.params == nil || other.params == nil || pc.params.Curve != other.params.Curve {
		// Handle error or return nil/identity commitment
		return nil // Or new(PedersenCommitment) initialized to infinity
	}
	sumPoint := pointAdd(pc.P, other.P)
	return &PedersenCommitment{P: sumPoint, params: pc.params}
}

// Subtract performs homomorphic subtraction: C1 - C2 = (v1-v2)G + (r1-r2)H
func (pc *PedersenCommitment) Subtract(other *PedersenCommitment) *PedersenCommitment {
	if pc == nil || other == nil || pc.params == nil || other.params == nil || pc.params.Curve != other.params.Curve {
		// Handle error
		return nil
	}
	subPoint := pointSub(pc.P, other.P)
	return &PedersenCommitment{P: subPoint, params: pc.params}
}

// ScalarMult performs homomorphic scalar multiplication: s * C = (s*v)G + (s*r)H
func (pc *PedersenCommitment) ScalarMult(s *big.Int) *PedersenCommitment {
	if pc == nil || pc.params == nil {
		// Handle error
		return nil
	}
	sPoint := scalarMult(pc.P, safeBigInt(s, pc.params.Curve.Params().N))
	return &PedersenCommitment{P: sPoint, params: pc.params}
}


// MarshalBinary serializes the Pedersen Commitment.
func (pc *PedersenCommitment) MarshalBinary() ([]byte, error) {
	if pc == nil || pc.P == nil {
		return nil, ErrSerialization
	}
	// Only the point needs to be serialized
	return pointMarshal(pc.P), nil
}

// UnmarshalBinary deserializes the Pedersen Commitment. Requires params to set the curve.
func (pc *PedersenCommitment) UnmarshalBinary(params *Params, data []byte) error {
	if params == nil || params.Curve == nil {
		return ErrInvalidParameters
	}
	p, err := pointUnmarshal(params.Curve, data)
	if err != nil {
		return fmt.Errorf("%w: failed to unmarshal commitment point", err)
	}
	pc.P = p
	pc.params = params // Link back to parameters
	return nil
}

// --- ZK-OR Proof for Bit (0 or 1) ---

// ZKORBitProof represents the proof data for C = b*G + r*H commits to b=0 OR b=1.
// This follows a standard Sigma OR structure with challenge splitting.
type ZKORBitProof struct {
	// For case b=0: c0, s0_G, s0_H
	C0 *big.Int
	S0G *big.Int
	S0H *big.Int
	// For case b=1: c1, s1_G, s1_H
	C1 *big.Int
	S1G *big.Int
	S1H *big.Int
}

// proveBitZKOR generates a ZK proof that C_bit commits to 'bit' (0 or 1).
// transcript is used for Fiat-Shamir.
func proveBitZKOR(params *Params, C_bit *PedersenCommitment, bit, randomness *big.Int, transcript *Transcript) (*ZKORBitProof, error) {
	curve := params.Curve
	N := curve.Params().N // Curve order
	bitVal := safeBigInt(bit, big.NewInt(2)) // Ensure bit is 0 or 1
	rVal := safeBigInt(randomness, N)

	// --- Prover's turn ---
	// Generate randomness for both branches
	a0, err := generateRandomScalar(curve) ; if err != nil { return nil, err }
	b0, err := generateRandomScalar(curve) ; if err != nil { return nil, err }
	a1, err := generateRandomScalar(curve) ; if err != nil { return nil, err }
	b1, err := generateRandomScalar(curve) ; if err != nil { return nil, err }

	// Generate commitments for both branches
	// A_i = a_i*G + b_i*H
	A0 := pointAdd(scalarBaseMult(curve, a0), scalarMult(params.H, b0))
	A1 := pointAdd(scalarBaseMult(curve, a1), scalarMult(params.H, b1))

	// Append commitments to transcript
	if err := transcript.Append("A0", pointMarshal(A0)); err != nil { return nil, err }
	if err := transcript.Append("A1", pointMarshal(A1)); err != nil { return nil, err }

	// Get challenge 'c' from Verifier (Fiat-Shamir)
	c := transcript.Challenge("bit_proof_challenge")

	// Split challenge c = c0 + c1. Prover chooses one c_other randomly.
	// The actual challenge c_k is derived c - c_other.
	var c0, c1 *big.Int

	// Compute responses based on the actual bit value
	if bitVal.Cmp(big.NewInt(0)) == 0 { // Actual bit is 0 (Case 0)
		// Generate random challenge for Case 1
		c1, err = generateRandomScalar(curve) ; if err != nil { return nil, err }
		c1 = safeBigInt(c1, N)
		// Derive challenge for Case 0: c0 = c - c1 (mod N)
		c0 = new(big.Int).Sub(c, c1)
		c0 = safeBigInt(c0, N)

		// Compute real responses for Case 0 (v=0, r=rVal)
		// s0_G = a0 + c0*v0 (mod N) where v0=0
		// s0_H = b0 + c0*r0 (mod N) where r0=rVal
		s0_G := a0 // a0 + c0*0
		s0_H := new(big.Int).Mul(c0, rVal)
		s0_H = new(big.Int).Add(b0, s0_H)
		s0_H = safeBigInt(s0_H, N)

		// Compute fake responses for Case 1 (v=1) using the random c1
		// A1 = s1_G*G + s1_H*H - c1*C_bit
		// s1_G = a1 + c1*v1 => a1 = s1_G - c1*v1 (mod N) where v1=1
		// s1_H = b1 + c1*r1 => b1 = s1_H - c1*r1 (mod N) where r1 is unknown (randomly generated for the fake proof)
		// To compute fake A1 that verifies: A1 = (s1_G - c1*1)*G + (s1_H - c1*r1)*H + c1*C_bit
		// We need to ensure A1 = a1 G + b1 H.
		// The ZK-OR logic is often: pick random s_other_G, s_other_H, compute A_other = s_other_G*G + s_other_H*H - c_other*C.
		// Let's re-align with standard ZK-OR structure.
		// Prover knows k. Random: (a_k, b_k), c_other. Derived: c_k = c - c_other.
		// Real responses: s_k_G = a_k + c_k*v_k, s_k_H = b_k + c_k*r_k
		// Fake A_other: A_other = s_other_G*G + s_other_H*H - c_other*C
		// Need s_other_G, s_other_H to be random.
		// Let's try again:
		// If bitVal = 0 (case 0 is true):
		// Randoms: a0, b0 (real), s1_G, s1_H (fake responses for case 1)
		// Commitments:
		// A0 = a0*G + b0*H (real commitment for case 0)
		// A1 = s1_G*G + s1_H*H - c1*C_bit (fake commitment for case 1, where c1 is random)
		// Verifier sends c.
		// Prover derives c0 = c - c1.
		// Real responses for case 0: s0_G = a0 + c0*0 = a0, s0_H = b0 + c0*rVal.
		// Send (c0, s0_G, s0_H) and (c1, s1_G, s1_H).

		// Let's implement this standard approach:
		s1_G, err := generateRandomScalar(curve); if err != nil { return nil, err }
		s1_G = safeBigInt(s1_G, N)
		s1_H, err := generateRandomScalar(curve); if err != nil { return nil, err }
		s1_H = safeBigInt(s1_H, N)
		c1, err = generateRandomScalar(curve); if err != nil { return nil, err } // c1 is random
		c1 = safeBigInt(c1, N)

		// Compute fake A1: A1 = s1_G*G + s1_H*H - c1*C_bit
		s1GG_s1HH := pointAdd(scalarBaseMult(curve, s1_G), scalarMult(params.H, s1_H))
		c1Cbit := scalarMult(C_bit.Point(), c1)
		A1 = pointSub(s1GG_s1HH, c1Cbit) // This A1 is sent

		// Compute real A0: A0 = a0*G + b0*H
		// We don't know a0, b0 *yet* in this flow if we start with random s and c.
		// The ZK-OR should be:
		// For each case i (0 or 1): Prover computes Ti = ai*G + bi*H. Sends T0, T1.
		// Verifier sends c.
		// Prover splits c into c0, c1 such that c0+c1=c. One c_i is random, other is c-random.
		// Prover computes si_G = ai + ci*vi and si_H = bi + ci*ri for the real case.
		// For the fake case, prover sets si_G, si_H randomly, and computes Ti = si_G*G + si_H*H - ci*C.
		// Let's rename T to A for consistency with previous attempt.

		// Case 0 is true (bitVal = 0):
		// Random: a0, b0 (real commitment), s1_G, s1_H (fake responses), c1 (random challenge)
		// A0 = a0*G + b0*H (compute and send)
		// A1 = s1_G*G + s1_H*H - c1*C_bit (compute and send)
		// Verifier sends c.
		// Derive c0 = c - c1 (mod N).
		// Real responses for case 0: s0_G = a0 + c0*0 = a0. s0_H = b0 + c0*rVal.

		a0, err = generateRandomScalar(curve); if err != nil { return nil, err }
		a0 = safeBigInt(a0, N)
		b0, err = generateRandomScalar(curve); if err != nil { return nil, err }
		b0 = safeBigInt(b0, N)
		A0 = pointAdd(scalarBaseMult(curve, a0), scalarMult(params.H, b0)) // Real A0

		s1_G, err = generateRandomScalar(curve); if err != nil { return nil, err }
		s1_G = safeBigInt(s1_G, N)
		s1_H, err = generateRandomScalar(curve); if err != nil { return nil, err }
		s1_H = safeBigInt(s1_H, N)
		c1, err = generateRandomScalar(curve); if err != nil { return nil, err } // c1 random
		c1 = safeBigInt(c1, N)
		// Compute A1: A1 = s1_G*G + s1_H*H - c1*C_bit
		s1GG := scalarBaseMult(curve, s1_G)
		s1HH := scalarMult(params.H, s1_H)
		s1GG_s1HH := pointAdd(s1GG, s1HH)
		c1Cbit := scalarMult(C_bit.Point(), c1)
		A1 = pointSub(s1GG_s1HH, c1Cbit) // Fake A1

		// Append A0, A1 *to the main RangeProofN transcript* BEFORE generating the challenge 'c'
		// The ZKOR proof structure needs to be integrated into the main Fiat-Shamir flow.
		// The commitments A0, A1 are part of the range proof message.
		// The challenge 'c' is for the whole range proof.
		// Then THIS proveBitZKOR receives the *specific* challenge *for this bit*.
		// Let's adjust. The RangeProofN prover will generate the challenge 'c' for ALL bit proofs.

		// For now, let's assume 'c' is provided *to* this function,
		// and this function manages the internal challenge splitting.
		// This means the A0, A1 must be included in the transcript that generated 'c'.
		// The RangeProofN will manage the overall transcript. This function just uses it.

		// Let's retry with 'c' being the overall challenge passed in.
		// Prover knows bitVal, rVal. C_bit = bitVal*G + rVal*H.
		// Goal: Prove C_bit commits to 0 OR 1.
		// Use a standard ZK-OR structure:
		// Prover commits to (a_i, b_i) for each case i=0, 1: A_i = a_i*G + b_i*H.
		// Sends A0, A1. Verifier sends challenge `c`.
		// Prover computes responses s_i_G, s_i_H for i=0, 1 s.t. s_i_G = a_i + c_i*v_i, s_i_H = b_i + c_i*r_i, with c0+c1=c.
		// The ZK magic is how c0, c1 are chosen/derived. One must be random.

		// Let's use the standard Schnorr-based ZK-OR where Prover knows *one* witness (bitVal, rVal).
		// Prover knows `k` such that v_k is the true value.
		// Choose random `a_k, b_k`. Compute real commitment: `A_k = a_k*G + b_k*H`.
		// Choose random `c_other`. Choose random `s_other_G, s_other_H`.
		// Compute fake commitment for the other case: `A_other = s_other_G*G + s_other_H*H - c_other*C_bit`.
		// Send A0, A1. Get overall challenge `c`.
		// Derive `c_k = c - c_other` (mod N).
		// Compute real responses: `s_k_G = a_k + c_k * v_k` (mod N), `s_k_H = b_k + c_k * r_k` (mod N).
		// Send all (c0, s0_G, s0_H) and (c1, s1_G, s1_H).

		// So, A0, A1 are commitments. The challenges c0, c1 are *part of the proof response*, not inputs.
		// This means the Fiat-Shamir challenge 'c' must be generated *after* A0 and A1 are in the transcript.
		// The `proveBitZKOR` function should accept the transcript and compute/append A0, A1 before challenging.

		var aK, bK, sOtherG, sOtherH, cOther *big.Int // Real commitment randomness, fake responses, random challenge for other case
		var vK *big.Int // The actual bit value (0 or 1)

		if bitVal.Cmp(big.NewInt(0)) == 0 { // Case 0 is true (bit is 0)
			vK = big.NewInt(0)
			aK, err = generateRandomScalar(curve); if err != nil { return nil, err }
			bK, err = generateRandomScalar(curve); if err != nil { return nil, err }
			sOtherG, err = generateRandomScalar(curve); if err != nil { return nil, err } // Fake s1_G
			sOtherH, err = generateRandomScalar(curve); if err != nil { return nil, err } // Fake s1_H
			cOther, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random c1
		} else { // Case 1 is true (bit is 1)
			vK = big.NewInt(1)
			aK, err = generateRandomScalar(curve); if err != nil { return nil, err }
			bK, err = generateRandomScalar(curve); if err != nil { return nil, err }
			sOtherG, err = generateRandomScalar(curve); if err != nil { return nil, err } // Fake s0_G
			sOtherH, err = generateRandomScalar(curve); if err != nil { return nil, err } // Fake s0_H
			cOther, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random c0
		}

		aK = safeBigInt(aK, N); bK = safeBigInt(bK, N)
		sOtherG = safeBigInt(sOtherG, N); sOtherH = safeBigInt(sOtherH, N)
		cOther = safeBigInt(cOther, N)

		// Compute commitments A0, A1
		var A0, A1 *ec.Point

		if bitVal.Cmp(big.NewInt(0)) == 0 { // Case 0 is true
			// A0 is real
			A0 = pointAdd(scalarBaseMult(curve, aK), scalarMult(params.H, bK))
			// A1 is fake
			sOtherGG := scalarBaseMult(curve, sOtherG) // s1_G*G
			sOtherHH := scalarMult(params.H, sOtherH) // s1_H*H
			sOtherSum := pointAdd(sOtherGG, sOtherHH)
			cOtherCbit := scalarMult(C_bit.Point(), cOther) // c1*C_bit
			A1 = pointSub(sOtherSum, cOtherCbit) // A1 = s1_G*G + s1_H*H - c1*C_bit
		} else { // Case 1 is true
			// A1 is real
			A1 = pointAdd(scalarBaseMult(curve, aK), scalarMult(params.H, bK))
			// A0 is fake
			sOtherGG := scalarBaseMult(curve, sOtherG) // s0_G*G
			sOtherHH := scalarMult(params.H, sOtherH) // s0_H*H
			sOtherSum := pointAdd(sOtherGG, sOtherHH)
			cOtherCbit := scalarMult(C_bit.Point(), cOther) // c0*C_bit
			A0 = pointSub(sOtherSum, cOtherCbit) // A0 = s0_G*G + s0_H*H - c0*C_bit
		}

		// Append A0, A1 to the transcript
		if err := transcript.Append("ZKOR_A0", pointMarshal(A0)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_A1", pointMarshal(A1)); err != nil { return nil, err }

		// Get overall challenge 'c' (managed by the caller - RangeProofN)
		// The range proof N prover calls this, appends A0, A1, THEN calls transcript.Challenge.
		// Let's assume the challenge `c` is passed *into* this function.
		// Okay, need to refactor: This function should *not* generate the challenge internally.
		// It should receive the challenge. The A0, A1 should be passed OUT or appended by the caller.

		// New approach: proveBitZKOR prepares the commitments A0, A1 and returns them.
		// The caller appends them to the transcript, gets the challenge, then calls *another* function
		// proveBitZKOR_response to get the responses.
		// Or, simpler: `proveBitZKOR` takes the transcript, appends its stuff, gets challenge, computes responses, returns proof.
		// This requires the transcript to be passed *by pointer* and shared.

		// Let's stick to the plan: `proveBitZKOR` generates A0, A1, appends, gets challenge, computes responses.
		// This implies a nested Fiat-Shamir. The challenge `c` generated here is specific to this ZK-OR proof.
		// The overall range proof transcript will include challenges from these sub-proofs.

		// Revert to internal challenge generation for this sub-proof:
		// Prover commits A0, A1. Verifier sends c (Fiat-Shamir).
		// Prover computes responses based on which bit is true.
		// Let's make it work with `c` being the challenge for this specific ZK-OR.

		// Randoms based on which bit is true
		var a, b *big.Int // Randomness for the real commitment
		var v *big.Int    // The actual bit value
		var cOtherVal *big.Int // The random challenge for the other case
		var sOtherGVal, sOtherHVal *big.Int // The random responses for the other case

		if bitVal.Cmp(big.NewInt(0)) == 0 { // Bit is 0
			v = big.NewInt(0)
			a, err = generateRandomScalar(curve); if err != nil { return nil, err }
			b, err = generateRandomScalar(curve); if err != nil { return nil, err }
			sOtherGVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random s1G
			sOtherHVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random s1H
			cOtherVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random c1
		} else { // Bit is 1
			v = big.NewInt(1)
			a, err = generateRandomScalar(curve); if err != nil { return nil, err }
			b, err = generateRandomScalar(curve); if err != nil { return nil, err }
			sOtherGVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random s0G
			sOtherHVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random s0H
			cOtherVal, err = generateRandomScalar(curve); if err != nil { return nil, err } // Random c0
		}
		a = safeBigInt(a, N); b = safeBigInt(b, N)
		sOtherGVal = safeBigInt(sOtherGVal, N); sOtherHVal = safeBigInt(sOtherHVal, N)
		cOtherVal = safeBigInt(cOtherVal, N)

		// Compute A0 and A1 to send
		var proverA0, proverA1 *ec.Point

		if v.Cmp(big.NewInt(0)) == 0 { // Proving bit 0
			// A0 is real: A0 = a*G + b*H
			proverA0 = pointAdd(scalarBaseMult(curve, a), scalarMult(params.H, b))
			// A1 is fake: A1 = s1G*G + s1H*H - c1*C_bit
			s1GG := scalarBaseMult(curve, sOtherGVal)
			s1HH := scalarMult(params.H, sOtherHVal)
			s1Sum := pointAdd(s1GG, s1HH)
			c1Cbit := scalarMult(C_bit.Point(), cOtherVal)
			proverA1 = pointSub(s1Sum, c1Cbit)
		} else { // Proving bit 1
			// A1 is real: A1 = a*G + b*H
			proverA1 = pointAdd(scalarBaseMult(curve, a), scalarMult(params.H, b))
			// A0 is fake: A0 = s0G*G + s0H*H - c0*C_bit
			s0GG := scalarBaseMult(curve, sOtherGVal)
			s0HH := scalarMult(params.H, sOtherHVal)
			s0Sum := pointAdd(s0GG, s0HH)
			c0Cbit := scalarMult(C_bit.Point(), cOtherVal)
			proverA0 = pointSub(s0Sum, c0Cbit)
		}

		// Append A0, A1 to the transcript for THIS ZK-OR sub-proof
		subTranscript := NewTranscript("bit_zkor")
		if err := subTranscript.Append("A0", pointMarshal(proverA0)); err != nil { return nil, err }
		if err := subTranscript.Append("A1", pointMarshal(proverA1)); err != nil { return nil, err }

		// Get challenge `c` for THIS ZK-OR sub-proof
		c := subTranscript.Challenge("challenge")

		// Compute c0, c1 based on the true bit
		var c0, c1 *big.Int
		if v.Cmp(big.NewInt(0)) == 0 { // Bit is 0 (case 0 is true)
			c1 = cOtherVal // c1 was random
			c0 = new(big.Int).Sub(c, c1) // c0 = c - c1
			c0 = safeBigInt(c0, N)
		} else { // Bit is 1 (case 1 is true)
			c0 = cOtherVal // c0 was random
			c1 = new(big.Int).Sub(c, c0) // c1 = c - c0
			c1 = safeBigInt(c1, N)
		}

		// Compute responses s0_G, s0_H, s1_G, s1_H
		var s0_G, s0_H, s1_G, s1_H *big.Int

		if v.Cmp(big.NewInt(0)) == 0 { // Bit is 0 (case 0 is true)
			// Real responses for case 0: s0_G = a + c0*0, s0_H = b + c0*rVal
			s0_G = a // aK (from case 0 randoms)
			term := new(big.Int).Mul(c0, rVal)
			s0_H = new(big.Int).Add(b, term) // bK (from case 0 randoms)
			s0_H = safeBigInt(s0_H, N)

			// Fake responses for case 1: s1_G, s1_H were random (sOtherGVal, sOtherHVal)
			s1_G = sOtherGVal
			s1_H = sOtherHVal

		} else { // Bit is 1 (case 1 is true)
			// Fake responses for case 0: s0_G, s0_H were random (sOtherGVal, sOtherHVal)
			s0_G = sOtherGVal
			s0_H = sOtherHVal

			// Real responses for case 1: s1_G = a + c1*1, s1_H = b + c1*rVal
			termG := new(big.Int).Mul(c1, big.NewInt(1))
			s1_G = new(big.Int).Add(a, termG) // aK (from case 1 randoms)
			s1_G = safeBigInt(s1_G, N)
			termH := new(big.Int).Mul(c1, rVal)
			s1_H = new(big.Int).Add(b, termH) // bK (from case 1 randoms)
			s1_H = safeBigInt(s1_H, N)
		}

		proof := &ZKORBitProof{
			C0: c0, S0G: s0_G, S0H: s0_H,
			C1: c1, S1G: s1_G, S1H: s1_H,
		}

		// Append the proof elements to the *main* transcript for the calling RangeProofN
		if err := transcript.Append("ZKOR_C0", bigIntToBytes(proof.C0)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_S0G", bigIntToBytes(proof.S0G)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_S0H", bigIntToBytes(proof.S0H)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_C1", bigIntToBytes(proof.C1)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_S1G", bigIntToBytes(proof.S1G)); err != nil { return nil, err }
		if err := transcript.Append("ZKOR_S1H", bigIntToBytes(proof.S1H)); err != nil { return nil, err }


		return proof, nil
}


// verifyBitZKOR verifies a ZK proof that C_bit commits to 0 or 1.
// transcript is used for Fiat-Shamir (must be same state as prover).
func verifyBitZKOR(params *Params, C_bit *PedersenCommitment, proof *ZKORBitProof, transcript *Transcript) error {
	if proof == nil || C_bit == nil || C_bit.P == nil || params == nil {
		return ErrInvalidProof
	}
	curve := params.Curve
	N := curve.Params().N

	// Recompute A0, A1 using the proof responses and challenges
	// A_i = s_i_G*G + s_i_H*H - c_i*C_bit

	// For case 0 (v=0):
	// s0_G*G + s0_H*H
	term0 := pointAdd(scalarBaseMult(curve, safeBigInt(proof.S0G, N)), scalarMult(params.H, safeBigInt(proof.S0H, N)))
	// c0*C_bit
	c0Cbit := scalarMult(C_bit.Point(), safeBigInt(proof.C0, N))
	// Computed A0 = term0 - c0*C_bit
	computedA0 := pointSub(term0, c0Cbit)

	// For case 1 (v=1):
	// s1_G*G + s1_H*H
	term1 := pointAdd(scalarBaseMult(curve, safeBigInt(proof.S1G, N)), scalarMult(params.H, safeBigInt(proof.S1H, N)))
	// c1*C_bit
	c1Cbit := scalarMult(C_bit.Point(), safeBigInt(proof.C1, N))
	// Computed A1 = term1 - c1*C_bit
	computedA1 := pointSub(term1, c1Cbit)

	// Append the computed A0, A1 to a *sub-transcript* to derive the challenge `c`
	// This sub-transcript must mirror the prover's sub-transcript state.
	subTranscript := NewTranscript("bit_zkor")
	if err := subTranscript.Append("A0", pointMarshal(computedA0)); err != nil { return fmt.Errorf("%w: verify append A0 failed", err) }
	if err := subTranscript.Append("A1", pointMarshal(computedA1)); err != nil { return fmt.Errorf("%w: verify append A1 failed", err) }

	// Get the challenge 'c' that the prover used for this sub-proof
	c := subTranscript.Challenge("challenge")

	// Check if the challenge split is correct: c0 + c1 = c (mod N)
	c0plusc1 := new(big.Int).Add(proof.C0, proof.C1)
	c0plusc1 = safeBigInt(c0plusc1, N)

	if c0plusc1.Cmp(c) != 0 {
		return fmt.Errorf("%w: challenge split mismatch (c0+c1 != c)", ErrInvalidProof)
	}

	// Append the proof elements to the *main* transcript for the calling RangeProofN verification
	if err := transcript.Append("ZKOR_C0", bigIntToBytes(proof.C0)); err != nil { return fmt.Errorf("%w: verify append C0 failed", err) }
	if err := transcript.Append("ZKOR_S0G", bigIntToBytes(proof.S0G)); err != nil { return fmt.Errorf("%w: verify append S0G failed", err) }
	if err := transcript.Append("ZKOR_S0H", bigIntToBytes(proof.S0H)); err != nil { return fmt.Errorf("%w: verify append S0H failed", err) }
	if err := transcript.Append("ZKOR_C1", bigIntToBytes(proof.C1)); err != nil { return fmt.Errorf("%w: verify append C1 failed", err) }
	if err := transcript.Append("ZKOR_S1G", bigIntToBytes(proof.S1G)); err != nil { return fmt.Errorf("%w: verify append S1G failed", err) }
	if err := transcript.Append("ZKOR_S1H", bigIntToBytes(proof.S1H)); err != nil { return fmt.Errorf("%w: verify append S1H failed", err) }


	// If we reached here, the checks passed. The proof is valid.
	return nil
}


// MarshalBinary serializes the ZKORBitProof.
func (p *ZKORBitProof) MarshalBinary() ([]byte, error) {
	if p == nil { return nil, nil } // Or return error for nil proof

	var buf bytes.Buffer
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.C0)); err != nil { return nil, fmt.Errorf("%w: marshal C0", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.S0G)); err != nil { return nil, fmt.Errorf("%w: marshal S0G", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.S0H)); err != nil { return nil, fmt.Errorf("%w: marshal S0H", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.C1)); err != nil { return nil, fmt đẹp("%w: marshal C1", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.S1G)); err != nil { return nil, fmt.Errorf("%w: marshal S1G", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.S1H)); err != nil { return nil, fmt.Errorf("%w: marshal S1H", err)}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the ZKORBitProof.
func (p *ZKORBitProof) UnmarshalBinary(data []byte) error {
	if p == nil { return ErrDeserialization } // Cannot unmarshal into nil receiver

	reader := bytes.NewReader(data)
	var err error

	c0Bytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal C0", err)}
	p.C0 = bytesToBigInt(c0Bytes)

	s0gBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal S0G", err)}
	p.S0G = bytesToBigInt(s0gBytes)

	s0hBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal S0H", err)}
	p.S0H = bytesToBigInt(s0hBytes)

	c1Bytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal C1", err)}
	p.C1 = bytesToBigInt(c1Bytes)

	s1gBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal S1G", err)}
	p.S1G = bytesToBigInt(s1gBytes)

	s1hBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal S1H", err)}
	p.S1H = bytesToBigInt(s1hBytes)

	// Ensure no leftover data
	if reader.Len() > 0 {
		return fmt.Errorf("%w: leftover data after unmarshaling", ErrDeserialization)
	}

	return nil
}


// --- Sigma Proof for KDL (Knowledge of Discrete Log) ---

// SigmaKDLProof represents the proof data for proving knowledge of 's' in Y = s*P.
// We use this to prove knowledge of R_total in (C - sum Ci*2^i) = R_total*H.
type SigmaKDLProof struct {
	T *ec.Point // Commitment point T = t*H
	S *big.Int  // Response s = t + c*scalar (mod N)
}

// proveKDL generates a Sigma proof for knowledge of `scalar` such that `point` = `scalar` * `params.H`.
// `point` here corresponds to `C - sum(Ci*2^i)`. `scalar` corresponds to `R_total`.
func proveKDL(params *Params, point *ec.Point, scalar *big.Int, transcript *Transcript) (*SigmaKDLProof, error) {
	if point == nil || point.IsInfinity() || scalar == nil || params == nil {
		// This case should ideally not happen if point is C - sum(Ci*2^i) and scalar is R_total
		// unless R_total is 0 and the resulting point is infinity.
		// We *can* prove knowledge of 0.
		if scalar.Sign() == 0 && (point == nil || point.IsInfinity()) {
			// Handle knowledge of 0 proof? A simplified KDL proof for scalar 0 might be just T=infinity, s=0.
			// But let's assume the standard protocol for non-zero knowledge.
			// If scalar is 0, point must be infinity. T must be infinity. c=Hash(...), s=0+c*0=0.
			// Verifier checks T + c*point = s*H => infinity + c*infinity = 0*H => infinity = infinity. This works.
			return &SigmaKDLProof{T: &ec.Point{Curve: params.Curve, X: big.NewInt(0), Y: big.NewInt(0)}, S: big.NewInt(0)}, nil
		}
		return nil, fmt.Errorf("%w: invalid inputs for KDL proof", ErrInvalidParameters)
	}

	curve := params.Curve
	N := curve.Params().N
	scalarVal := safeBigInt(scalar, N)

	// Prover chooses random t
	t, err := generateRandomScalar(curve)
	if err != nil { return nil, err }
	t = safeBigInt(t, N)

	// Prover computes commitment T = t * H
	T := scalarMult(params.H, t)

	// Append T to the transcript
	if err := transcript.Append("KDL_T", pointMarshal(T)); err != nil { return nil, err }

	// Get challenge 'c' from Verifier (Fiat-Shamir)
	c := transcript.Challenge("kdl_challenge")

	// Prover computes response s = t + c * scalar (mod N)
	term := new(big.Int).Mul(c, scalarVal)
	s := new(big.Int).Add(t, term)
	s = safeBigInt(s, N)

	proof := &SigmaKDLProof{T: T, S: s}

	// Append s to the transcript
	if err := transcript.Append("KDL_S", bigIntToBytes(proof.S)); err != nil { return nil, err }

	return proof, nil
}

// verifyKDL verifies a Sigma proof for knowledge of `scalar` such that `point` = `scalar` * `params.H`.
func verifyKDL(params *Params, point *ec.Point, proof *SigmaKDLProof, transcript *Transcript) error {
	if proof == nil || proof.T == nil || proof.S == nil || params == nil || params.H == nil {
		return ErrInvalidProof
	}

	curve := params.Curve
	N := curve.Params().N
	sVal := safeBigInt(proof.S, N)

	// Append T from the proof to the transcript (before challenge generation)
	if err := transcript.Append("KDL_T", pointMarshal(proof.T)); err != nil { return fmt.Errorf("%w: verify append T failed", err) }

	// Regenerate challenge 'c' from the transcript
	c := transcript.Challenge("kdl_challenge")
	cVal := safeBigInt(c, N)

	// Append s from the proof to the transcript (after challenge generation)
	if err := transcript.Append("KDL_S", bigIntToBytes(proof.S)); err != nil { return fmt.Errorf("%w: verify append S failed", err) }


	// Verifier checks: s * H == T + c * point
	// Left side: s * H
	left := scalarMult(params.H, sVal)

	// Right side: T + c * point
	cPoint := scalarMult(point, cVal)
	right := pointAdd(proof.T, cPoint)

	if left.X.Cmp(right.X) != 0 || left.Y.Cmp(right.Y) != 0 {
		return fmt.Errorf("%w: KDL verification failed (s*H != T + c*point)", ErrInvalidProof)
	}

	return nil
}

// MarshalBinary serializes the SigmaKDLProof.
func (p *SigmaKDLProof) MarshalBinary() ([]byte, error) {
	if p == nil { return nil, nil }

	var buf bytes.Buffer
	if err := writePrefixedBytes(&buf, pointMarshal(p.T)); err != nil { return nil, fmt.Errorf("%w: marshal T", err)}
	if err := writePrefixedBytes(&buf, bigIntToBytes(p.S)); err != nil { return nil, fmt.Errorf("%w: marshal S", err)}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the SigmaKDLProof. Requires params for the curve.
func (p *SigmaKDLProof) UnmarshalBinary(params *Params, data []byte) error {
	if p == nil { return ErrDeserialization }

	reader := bytes.NewReader(data)
	var err error

	tBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal T", err)}
	p.T, err = pointUnmarshal(params.Curve, tBytes)
	if err != nil { return fmt.Errorf("%w: unmarshal T point", err)}

	sBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal S", err)}
	p.S = bytesToBigInt(sBytes)

	if reader.Len() > 0 {
		return fmt.Errorf("%w: leftover data after unmarshaling", ErrDeserialization)
	}

	return nil
}

// --- Range Proof [0, 2^N] (Internal Component) ---

// RangeProofN represents the proof data that a committed value is in [0, 2^N].
type RangeProofN struct {
	N uint // The bit length N

	BitCommitments []*PedersenCommitment // C_i for each bit i
	SumCheckProof  *SigmaKDLProof        // Proof that C - sum(Ci*2^i) = R_total*H
	BitProofs      []*ZKORBitProof       // Proofs that each Ci commits to 0 or 1
}

// deriveBitLength calculates the minimum number of bits N needed to represent a value up to maxValue.
// Range [0, maxValue] requires N bits if 2^(N-1) <= maxValue < 2^N. Max value is 2^N - 1.
// So, we need N bits if maxValue <= 2^N - 1.
// N is the smallest integer such that 2^N > maxValue.
// log2(maxValue) < N. N = floor(log2(maxValue)) + 1.
// If maxValue is 0, range is [0,0], need 1 bit for 0.
func deriveBitLength(maxValue *big.Int) uint {
	if maxValue == nil || maxValue.Sign() < 0 {
		return 0 // Invalid or negative range
	}
	if maxValue.Sign() == 0 {
		return 1 // Range [0, 0] needs 1 bit (for 0)
	}
	// Calculate smallest N such that 2^N > maxValue
	// This is equivalent to N = bits required to represent maxValue + 1 (if maxValue is power of 2 minus 1)
	// Or simply, N = number of bits in binary representation of maxValue + 1 if maxValue is not 2^k-1
	// Go's big.Int.BitLen() gives minimum bits to represent the number (most significant bit position + 1).
	// E.g., 7 (111) is 3 bits, 8 (1000) is 4 bits.
	// To represent values up to M, we need ceil(log2(M+1)) bits.
	// e.g. M=7 (0..7): ceil(log2(8))=3 bits (000..111).
	// e.g. M=8 (0..8): ceil(log2(9))=4 bits (0000..1000).
	// The max value representable by N bits is 2^N - 1.
	// So if we need to represent values up to M, we need N bits where M <= 2^N - 1.
	// 2^N >= M + 1. N >= log2(M+1).
	// Smallest integer N is ceil(log2(M+1)).
	// This is effectively (M+1).BitLen().
	return uint(new(big.Int).Add(maxValue, big.NewInt(1)).BitLen())
}


// proveRangeN generates a proof that C commits to a value `v` in [0, 2^N].
func proveRangeN(params *Params, C *PedersenCommitment, value, randomness *big.Int, n uint, transcript *Transcript) (*RangeProofN, error) {
	if params == nil || C == nil || value == nil || randomness == nil || n == 0 {
		return nil, ErrInvalidParameters
	}

	curve := params.Curve
	N_curve := curve.Params().N // Curve order

	// 1. Decompose value into bits: v = sum(b_i * 2^i)
	valueVal := safeBigInt(value, N_curve)
	rVal := safeBigInt(randomness, N_curve) // Randomness for C

	bits := make([]*big.Int, n)
	bitRandomness := make([]*big.Int, n)
	bitCommitments := make([]*PedersenCommitment, n)

	// Calculate sum of randomness for bits scaled by 2^i
	sumBitRandomnessScaled := big.NewInt(0)

	// 2. Commit to each bit: C_i = b_i*G + r_i*H
	for i := uint(0); i < n; i++ {
		bit := new(big.Int).Rsh(valueVal, i).And(big.NewInt(1)) // Get the i-th bit

		rand_i, err := generateRandomScalar(curve)
		if err != nil { return nil, fmt.Errorf("failed to generate randomness for bit %d: %w", err) }
		rand_i = safeBigInt(rand_i, N_curve)
		bitRandomness[i] = rand_i

		Ci, err := NewPedersenCommitment(params, bit, rand_i)
		if err != nil { return nil, fmt.Errorf("failed to create commitment for bit %d: %w", err) }
		bitCommitments[i] = Ci

		// Update sumBitRandomnessScaled
		pow2i := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil) // 2^i
		term := new(big.Int).Mul(rand_i, pow2i)
		sumBitRandomnessScaled.Add(sumBitRandomnessScaled, term)
		sumBitRandomnessScaled = safeBigInt(sumBitRandomnessScaled, N_curve) // Keep it within N

		// Append bit commitment to transcript
		if err := transcript.Append(fmt.Sprintf("Ci_%d", i), Ci.MarshalBinary()); err != nil { return nil, err }
	}

	// 3. Sum Check Proof: Prove C - sum(Ci*2^i) = R_total*H
	// Prover knows R_total = r_randomness - sum(r_i * 2^i) (mod N)
	R_total := new(big.Int).Sub(rVal, sumBitRandomnessScaled)
	R_total = safeBigInt(R_total, N_curve)

	// The point we need to prove knowledge of discrete log for is C - sum(Ci*2^i)
	// sum(Ci*2^i) = sum((b_i*G + r_i*H)*2^i) = (sum b_i*2^i)*G + (sum r_i*2^i)*H
	//              = v*G + (sum r_i*2^i)*H
	// C = v*G + r*H
	// C - sum(Ci*2^i) = (v*G + r*H) - (v*G + (sum r_i*2^i)*H)
	//                 = (r - sum r_i*2^i)*H
	// This is exactly R_total*H.
	// So the 'point' for proveKDL is C.Point() - sum(Ci*2^i).Points()
	sumCiScaledPoint := &ec.Point{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)} // Infinity (identity)
	for i := uint(0); i < n; i++ {
		pow2i := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), N_curve) // 2^i mod N
		CiScaled := scalarMult(bitCommitments[i].Point(), pow2i)
		sumCiScaledPoint = pointAdd(sumCiScaledPoint, CiScaled)
	}
	sumCheckPoint := pointSub(C.Point(), sumCiScaledPoint)

	sumCheckProof, err := proveKDL(params, sumCheckPoint, R_total, transcript)
	if err != nil { return nil, fmt.Errorf("failed to generate sum check proof: %w", err) }

	// 4. Bit Proofs: Prove each C_i commits to 0 or 1
	bitProofs := make([]*ZKORBitProof, n)
	for i := uint(0); i < n; i++ {
		bitVal := new(big.Int).Rsh(valueVal, i).And(big.NewInt(1)) // The i-th bit
		bitRand := bitRandomness[i] // Randomness used for C_i

		bitProof, err := proveBitZKOR(params, bitCommitments[i], bitVal, bitRand, transcript)
		if err != nil { return nil, fmt.Errorf("failed to generate ZKOR proof for bit %d: %w", err) }
		bitProofs[i] = bitProof
	}


	return &RangeProofN{
		N:              n,
		BitCommitments: bitCommitments,
		SumCheckProof:  sumCheckProof,
		BitProofs:      bitProofs,
	}, nil
}

// verifyRangeN verifies a proof that C commits to a value in [0, 2^N].
func verifyRangeN(params *Params, C *PedersenCommitment, proof *RangeProofN, n uint, transcript *Transcript) error {
	if params == nil || C == nil || C.P == nil || proof == nil || proof.SumCheckProof == nil || proof.BitProofs == nil || proof.N != n {
		return fmt.Errorf("%w: invalid inputs for verifyRangeN", ErrInvalidProof)
	}
	if uint(len(proof.BitCommitments)) != n || uint(len(proof.BitProofs)) != n {
		return fmt.Errorf("%w: inconsistent proof lengths for N=%d", ErrInvalidProof, n)
	}

	curve := params.Curve
	N_curve := curve.Params().N

	// 1. Append bit commitments to transcript (must match prover's order)
	for i := uint(0); i < n; i++ {
		if err := transcript.Append(fmt.Sprintf("Ci_%d", i), proof.BitCommitments[i].MarshalBinary()); err != nil { return fmt.Errorf("%w: verify append Ci failed for bit %d", err, i) }
	}

	// 2. Verify Sum Check Proof: C - sum(Ci*2^i) == R_total*H
	// Recompute the point for the KDL check: C - sum(Ci*2^i)
	sumCiScaledPoint := &ec.Point{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)} // Infinity
	for i := uint(0); i < n; i++ {
		if proof.BitCommitments[i] == nil || proof.BitCommitments[i].P == nil {
			return fmt.Errorf("%w: invalid bit commitment point for bit %d", ErrInvalidProof, i)
		}
		pow2i := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), N_curve) // 2^i mod N
		CiScaled := scalarMult(proof.BitCommitments[i].Point(), pow2i)
		sumCiScaledPoint = pointAdd(sumCiScaledPoint, CiScaled)
	}
	sumCheckPoint := pointSub(C.Point(), sumCiScaledPoint)

	if err := verifyKDL(params, sumCheckPoint, proof.SumCheckProof, transcript); err != nil {
		return fmt.Errorf("%w: sum check verification failed: %v", ErrInvalidProof, err)
	}

	// 3. Verify Bit Proofs: Each C_i commits to 0 or 1
	for i := uint(0); i < n; i++ {
		if err := verifyBitZKOR(params, proof.BitCommitments[i], proof.BitProofs[i], transcript); err != nil {
			return fmt.Errorf("%w: ZKOR verification failed for bit %d: %v", ErrInvalidProof, err, err)
		}
	}

	// If all checks pass, the value committed in C is in [0, 2^N]
	return nil
}

// MarshalBinary serializes RangeProofN. Requires params for point/scalar sizes.
func (p *RangeProofN) MarshalBinary() ([]byte, error) {
	if p == nil { return nil, nil }

	var buf bytes.Buffer
	// N (as 4 bytes)
	nBytes := make([]byte, 4)
	big.NewInt(int64(p.N)).FillBytes(nBytes)
	buf.Write(nBytes)

	// Number of bit commitments/proofs (should equal N, but write length)
	numBits := uint32(len(p.BitCommitments)) // Use fixed size for length
	numBitsBytes := make([]byte, 4)
	big.NewInt(int64(numBits)).FillBytes(numBitsBytes)
	buf.Write(numBitsBytes)

	// Bit Commitments (list)
	for _, comm := range p.BitCommitments {
		commBytes, err := comm.MarshalBinary()
		if err != nil { return nil, fmt.Errorf("%w: marshal bit commitment", err)}
		if err := writePrefixedBytes(&buf, commBytes); err != nil { return nil, fmt.Errorf("%w: marshal bit commitment prefixed", err)}
	}

	// Sum Check Proof
	sumCheckBytes, err := p.SumCheckProof.MarshalBinary()
	if err != nil { return nil, fmt.Errorf("%w: marshal sum check proof", err)}
	if err := writePrefixedBytes(&buf, sumCheckBytes); err != nil { return nil, fmt.Errorf("%w: marshal sum check proof prefixed", err)}

	// Bit Proofs (list)
	for _, bitProof := range p.BitProofs {
		bpBytes, err := bitProof.MarshalBinary()
		if err != nil { return nil, fmt.Errorf("%w: marshal bit proof", err)}
		if err := writePrefixedBytes(&buf, bpBytes); err != nil { return nil, fmt.Errorf("%w: marshal bit proof prefixed", err)}
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes RangeProofN. Requires params for point/scalar sizes.
func (p *RangeProofN) UnmarshalBinary(params *Params, data []byte) error {
	if p == nil { return ErrDeserialization }

	reader := bytes.NewReader(data)
	var err error

	// N (4 bytes)
	nBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, nBytes); err != nil { return fmt.Errorf("%w: unmarshal N length", err)}
	p.N = uint(bytesToBigInt(nBytes).Int64())

	// Number of bit commitments/proofs (4 bytes)
	numBitsBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, numBitsBytes); err != nil { return fmt.Errorf("%w: unmarshal numBits length", err)}
	numBits := uint(bytesToBigInt(numBitsBytes).Int64())

	if numBits != p.N {
		return fmt.Errorf("%w: numBits in data (%d) does not match N (%d)", ErrDeserialization, numBits, p.N)
	}

	// Bit Commitments (list)
	p.BitCommitments = make([]*PedersenCommitment, numBits)
	for i := uint(0); i < numBits; i++ {
		commBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal bit commitment prefixed %d", err, i)}
		p.BitCommitments[i] = new(PedersenCommitment)
		if err := p.BitCommitments[i].UnmarshalBinary(params, commBytes); err != nil { return fmt.Errorf("%w: unmarshal bit commitment %d", err, i)}
	}

	// Sum Check Proof
	sumCheckBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal sum check proof prefixed", err)}
	p.SumCheckProof = new(SigmaKDLProof)
	if err := p.SumCheckProof.UnmarshalBinary(params, sumCheckBytes); err != nil { return fmt.Errorf("%w: unmarshal sum check proof", err)}

	// Bit Proofs (list)
	p.BitProofs = make([]*ZKORBitProof, numBits)
	for i := uint(0); i < numBits; i++ {
		bpBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal bit proof prefixed %d", err, i)}
		p.BitProofs[i] = new(ZKORBitProof)
		if err := p.BitProofs[i].UnmarshalBinary(bpBytes); err != nil { return fmt.Errorf("%w: unmarshal bit proof %d", err, i)}
	}

	if reader.Len() > 0 {
		return fmt.Errorf("%w: leftover data after unmarshaling", ErrDeserialization)
	}

	return nil
}


// --- Range Proof [min, max] (Public Interface) ---

// RangeProofMinMax represents the proof that a committed value is in [min, max].
// It consists of two RangeProofN instances: one for value-min >= 0, and one for max-value >= 0.
type RangeProofMinMax struct {
	C_x *PedersenCommitment // The original commitment C_x = x*G + r*H (included for verifier)

	// Proof that C_y = C_x - min*G commits to y = x - min >= 0
	// This proof is on C_y, showing it's in [0, 2^N_y]
	Proof_Cy_NonNegative *RangeProofN

	// Proof that C_z = max*G - C_x commits to z = max - x >= 0
	// This proof is on C_z, showing it's in [0, 2^N_z]
	Proof_Cz_NonNegative *RangeProofN
}

// ProveRangeMinMax generates a ZK proof that the secret value `x` committed in `C_x`
// is within the range [min, max]. Prover must provide `x_value` and `r_randomness`.
func ProveRangeMinMax(params *Params, C_x *PedersenCommitment, x_value, r_randomness *big.Int, min, max *big.Int) (*RangeProofMinMax, error) {
	if params == nil || C_x == nil || x_value == nil || r_randomness == nil || min == nil || max == nil {
		return nil, ErrInvalidParameters
	}
	if min.Cmp(max) > 0 {
		return nil, fmt.Errorf("%w: min value cannot be greater than max value", ErrInvalidParameters)
	}

	N_curve := params.Curve.Params().N
	xVal := safeBigInt(x_value, N_curve)
	rVal := safeBigInt(r_randomness, N_curve)
	minVal := safeBigInt(min, N_curve)
	maxVal := safeBigInt(max, N_curve)


	// Check if the commitment C_x is indeed for (x_value, r_randomness)
	// This is a sanity check for the prover code, not part of the ZKP itself.
	expectedCx, err := NewPedersenCommitment(params, xVal, rVal)
	if err != nil { return nil, fmt.Errorf("prover failed to compute expected C_x: %w", err) }
	if C_x.Point().X.Cmp(expectedCx.Point().X) != 0 || C_x.Point().Y.Cmp(expectedCx.Point().Y) != 0 {
		// This indicates the provided secret does not match the public commitment.
		// In a real system, the prover should not be able to get to this point with incorrect secrets.
		// For a library function, maybe return an error or panic?
		return nil, fmt.Errorf("%w: provided x_value and r_randomness do not match commitment C_x", ErrInvalidProof)
	}

	// 1. Proof for x - min >= 0
	// Let y = x - min. Need to prove y >= 0.
	// C_y = Commit(y) = Commit(x - min)
	// C_y = (x - min)*G + r*H = x*G - min*G + r*H = (x*G + r*H) - min*G = C_x - min*G
	// The randomness for C_y is the same randomness `r` used for C_x.
	yValue := new(big.Int).Sub(xVal, minVal) // y = x - min
	// We need to prove y >= 0, which means y is in [0, MaxPossibleY] where MaxPossibleY = max - min.
	// The range proof [0, 2^N] is used. N_y must be sufficient to cover [0, max - min].
	// N_y = ceil(log2((max-min)+1))
	maxPossibleY := new(big.Int).Sub(maxVal, minVal)
	N_y := deriveBitLength(maxPossibleY) // Bit length needed for values up to max-min

	// C_y commitment derived from C_x
	minG := scalarBaseMult(params.Curve, minVal)
	C_y_point := pointSub(C_x.Point(), minG)
	C_y := commitmentFromPoint(params, C_y_point)

	// Generate RangeProofN for C_y proving y is in [0, 2^N_y] using the actual yValue and rVal
	// Start a new transcript for the overall proof
	transcript := NewTranscript("range_min_max")
	if err := transcript.Append("Cx", C_x.MarshalBinary()); err != nil { return nil, err }
	if err := transcript.Append("min", bigIntToBytes(min)); err != nil { return nil, err }
	if err := transcript.Append("max", bigIntToBytes(max)); err != nil { return nil, err }
	if err := transcript.Append("Cy", C_y.MarshalBinary()); err != nil { return nil, err } // Append derived Cy

	proof_Cy_NonNegative, err := proveRangeN(params, C_y, yValue, rVal, N_y, transcript) // Prove y >= 0
	if err != nil { return nil, fmt.Errorf("failed to generate proof for x-min >= 0: %w", err) }


	// 2. Proof for max - x >= 0
	// Let z = max - x. Need to prove z >= 0.
	// C_z = Commit(z) = Commit(max - x)
	// C_z = (max - x)*G + r'*H for *some* randomness r'.
	// We can relate C_z to C_x:
	// C_z = max*G - x*G + r'*H
	// C_x = x*G + r*H
	// max*G - C_x = max*G - (x*G + r*H) = (max - x)G - r*H. This is a commitment to (max-x) with randomness -r.
	// So C_z can be (max - x)G + (-r)H, which equals max*G - C_x. The randomness is -r.
	zValue := new(big.Int).Sub(maxVal, xVal) // z = max - x
	// We need to prove z >= 0, which means z is in [0, MaxPossibleZ] where MaxPossibleZ = max - min.
	// N_z must be sufficient to cover [0, max - min].
	// N_z = ceil(log2((max-min)+1)) -> N_z is the same as N_y
	N_z := deriveBitLength(maxPossibleY) // Bit length needed for values up to max-min

	// C_z commitment derived from C_x using randomness -r
	maxG := scalarBaseMult(params.Curve, maxVal)
	C_z_point := pointSub(maxG, C_x.Point()) // C_z = max*G - C_x
	C_z := commitmentFromPoint(params, C_z_point)
	zRandomness := new(big.Int).Neg(rVal) // Randomness for C_z is -r
	zRandomness = safeBigInt(zRandomness, N_curve)

	if err := transcript.Append("Cz", C_z.MarshalBinary()); err != nil { return nil, err } // Append derived Cz

	proof_Cz_NonNegative, err := proveRangeN(params, C_z, zValue, zRandomness, N_z, transcript) // Prove z >= 0
	if err != nil { return nil, fmt.Errorf("failed to generate proof for max-x >= 0: %w", err) }

	proof := &RangeProofMinMax{
		C_x:                  C_x, // Include original commitment in proof
		Proof_Cy_NonNegative: proof_Cy_NonNegative,
		Proof_Cz_NonNegative: proof_Cz_NonNegative,
	}

	return proof, nil
}


// VerifyRangeMinMax verifies a ZK proof that the value committed in C_x
// is within the range [min, max].
func VerifyRangeMinMax(params *Params, C_x *PedersenCommitment, proof *RangeProofMinMax, min, max *big.Int) error {
	if params == nil || C_x == nil || C_x.P == nil || proof == nil || min == nil || max == nil {
		return ErrInvalidProof
	}
	if proof.Proof_Cy_NonNegative == nil || proof.Proof_Cz_NonNegative == nil {
		return fmt.Errorf("%w: missing sub-proofs", ErrInvalidProof)
	}
	if min.Cmp(max) > 0 {
		return fmt.Errorf("%w: min value cannot be greater than max value during verification", ErrInvalidParameters)
	}
	if C_x.params == nil {
		// Ensure the commitment has params linked, especially for unmarshaled ones
		C_x.params = params
	}


	curve := params.Curve
	N_curve := curve.Params().N
	minVal := safeBigInt(min, N_curve)
	maxVal := safeBigInt(max, N_curve)

	// Calculate expected derived commitments
	minG := scalarBaseMult(params.Curve, minVal)
	C_y_expected_point := pointSub(C_x.Point(), minG)
	C_y_expected := commitmentFromPoint(params, C_y_expected_point)

	maxG := scalarBaseMult(params.Curve, maxVal)
	C_z_expected_point := pointSub(maxG, C_x.Point())
	C_z_expected := commitmentFromPoint(params, C_z_expected_point)

	// Determine the expected bit length N for the range [0, max-min]
	maxPossibleValue := new(big.Int).Sub(maxVal, minVal)
	N_expected := deriveBitLength(maxPossibleValue)

	// Verify the bit lengths in the proofs match expectations
	if proof.Proof_Cy_NonNegative.N != N_expected || proof.Proof_Cz_NonNegative.N != N_expected {
		return fmt.Errorf("%w: sub-proof bit lengths mismatch expected N (%d)", ErrInvalidProof, N_expected)
	}
	if uint(len(proof.Proof_Cy_NonNegative.BitCommitments)) != N_expected || uint(len(proof.Proof_Cy_NonNegative.BitProofs)) != N_expected {
		return fmt.Errorf("%w: sub-proof Cy has inconsistent lengths for N=%d", ErrInvalidProof, N_expected)
	}
	if uint(len(proof.Proof_Cz_NonNegative.BitCommitments)) != N_expected || uint(len(proof.Proof_Cz_NonNegative.BitProofs)) != N_expected {
		return fmt.Errorf("%w: sub-proof Cz has inconsistent lengths for N=%d", ErrInvalidProof, N_expected)
	}


	// Start a new transcript for verification, mirroring the prover's initial appends
	transcript := NewTranscript("range_min_max")
	if err := transcript.Append("Cx", C_x.MarshalBinary()); err != nil { return fmt.Errorf("%w: verify append Cx failed", err) }
	if err := transcript.Append("min", bigIntToBytes(min)); err != nil { return fmt.Errorf("%w: verify append min failed", err) }
	if err := transcript.Append("max", bigIntToBytes(max)); err != nil { return fmt.Errorf("%w: verify append max failed", err) }
	if err := transcript.Append("Cy", C_y_expected.MarshalBinary()); err != nil { return fmt.Errorf("%w: verify append Cy failed", err) } // Append *derived* Cy

	// Verify the first RangeProofN (x - min >= 0) on C_y
	err := verifyRangeN(params, C_y_expected, proof.Proof_Cy_NonNegative, N_expected, transcript)
	if err != nil {
		return fmt.Errorf("%w: verification failed for x-min >= 0: %v", ErrInvalidProof, err)
	}

	if err := transcript.Append("Cz", C_z_expected.MarshalBinary()); err != nil { return fmt.Errorf("%w: verify append Cz failed", err) } // Append *derived* Cz

	// Verify the second RangeProofN (max - x >= 0) on C_z
	err = verifyRangeN(params, C_z_expected, proof.Proof_Cz_NonNegative, N_expected, transcript)
	if err != nil {
		return fmt.Errorf("%w: verification failed for max-x >= 0: %v", ErrInvalidProof, err)
	}

	// If both sub-proofs pass, the overall range proof is valid.
	return nil
}

// MarshalBinary serializes RangeProofMinMax. Requires params for serialization of nested proofs.
func (p *RangeProofMinMax) MarshalBinary() ([]byte, error) {
	if p == nil { return nil, nil }

	var buf bytes.Buffer

	// C_x (original commitment)
	cxBytes, err := p.C_x.MarshalBinary()
	if err != nil { return nil, fmt.Errorf("%w: marshal C_x", err)}
	if err := writePrefixedBytes(&buf, cxBytes); err != nil { return nil, fmt.Errorf("%w: marshal C_x prefixed", err)}

	// Proof_Cy_NonNegative
	cyProofBytes, err := p.Proof_Cy_NonNegative.MarshalBinary()
	if err != nil { return nil, fmt.Errorf("%w: marshal Cy proof", err)}
	if err := writePrefixedBytes(&buf, cyProofBytes); err != nil { return nil, fmt.Errorf("%w: marshal Cy proof prefixed", err)}

	// Proof_Cz_NonNegative
	czProofBytes, err := p.Proof_Cz_NonNegative.MarshalBinary()
	if err != nil { return nil, fmt.Errorf("%w: marshal Cz proof", err)}
	if err := writePrefixedBytes(&buf, czProofBytes); err != nil { return nil, fmt.Errorf("%w: marshal Cz proof prefixed", err)}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes RangeProofMinMax. Requires params for deserialization of nested proofs/commitments.
func (p *RangeProofMinMax) UnmarshalBinary(params *Params, data []byte) error {
	if p == nil { return ErrDeserialization }

	reader := bytes.NewReader(data)
	var err error

	// C_x
	cxBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal C_x prefixed", err)}
	p.C_x = new(PedersenCommitment)
	if err := p.C_x.UnmarshalBinary(params, cxBytes); err != nil { return fmt.Errorf("%w: unmarshal C_x", err)}

	// Proof_Cy_NonNegative
	cyProofBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal Cy proof prefixed", err)}
	p.Proof_Cy_NonNegative = new(RangeProofN)
	if err := p.Proof_Cy_NonNegative.UnmarshalBinary(params, cyProofBytes); err != nil { return fmt.Errorf("%w: unmarshal Cy proof", err)}

	// Proof_Cz_NonNegative
	czProofBytes, err := readPrefixedBytes(reader); if err != nil { return fmt.Errorf("%w: unmarshal Cz proof prefixed", err)}
	p.Proof_Cz_NonNegative = new(RangeProofN)
	if err := p.Proof_Cz_NonNegative.UnmarshalBinary(params, czProofBytes); err != nil { return fmt.Errorf("%w: unmarshal Cz proof", err)}

	if reader.Len() > 0 {
		return fmt.Errorf("%w: leftover data after unmarshaling", ErrDeserialization)
	}

	return nil
}
```