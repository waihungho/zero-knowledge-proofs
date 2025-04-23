```go
// Package customzkp implements a Zero-Knowledge Proof system in Go.
// It focuses on proving knowledge of secrets related to elliptic curve discrete logs,
// specifically extending the Schnorr protocol to handle multiple related secrets.
// This is not intended as a production-ready library but demonstrates
// the core concepts and provides a structure for building more complex ZKPs.
// It avoids relying on existing high-level ZKP frameworks, implementing
// the core logic using Go's standard big.Int and crypto/elliptic packages.
//
// Outline:
// 1. Elliptic Curve and Scalar Operations: Basic building blocks.
// 2. Parameter and Key Management: Setup of curve, generators, keys.
// 3. Basic Schnorr ZKP (Single Secret): Implementation of the core protocol steps.
// 4. Multi-Secret ZKP (Extended Schnorr): Proving knowledge of two secrets related to a public value.
// 5. Data Structures: Representation of proofs, contexts, etc.
// 6. Serialization/Deserialization: Converting data structures to bytes.
// 7. Utility Functions: Hashing, random number generation, input validation.
// 8. Proof Orchestration: Functions to manage interactive or non-interactive proof flow.
//
// Function Summary (at least 20 functions):
// ECC_GenerateCurveParameters: Initializes elliptic curve parameters (P-256).
// ECC_GetGeneratorG: Returns the standard base point G of the curve.
// ECC_GetRandomGeneratorH: Returns a potentially different, random generator point H for multi-secret proofs.
// ECC_PointMultiply: Performs scalar multiplication on an elliptic curve point (k * P).
// ECC_PointAdd: Performs point addition on an elliptic curve (P + Q).
// ECC_PointSerialize: Serializes an elliptic curve point to bytes.
// ECC_PointDeserialize: Deserializes bytes into an elliptic curve point.
// Scalar_Add: Performs modular addition of two scalars (a + b mod n).
// Scalar_Multiply: Performs modular multiplication of two scalars (a * b mod n).
// Scalar_HashToScalar: Hashes arbitrary data to produce a scalar modulo the curve order.
// GenerateRandomScalar: Generates a cryptographically secure random scalar within the curve order.
// GenerateProverSecret: Generates a random secret scalar for the prover.
// GenerateProverCommitmentKey: Computes the public commitment key C = w * G for a secret w.
// NewProverContext: Creates a context for the single-secret prover.
// ProverGenerateCommitment: Generates the prover's commitment R = r * G for a random nonce r.
// VerifierGenerateChallenge: Generates a random challenge scalar e for interactive proofs.
// HashToChallenge: Deterministically generates a challenge scalar using Fiat-Shamir heuristic.
// ProverComputeResponse: Computes the prover's response s = r + e * w mod n.
// NewSingleSecretProof: Creates a structure to hold the single-secret proof (R, s).
// ProverCreateSingleSecretProof: Combines commitment and response into a proof structure.
// NewVerifierContext: Creates a context for the single-secret verifier.
// VerifierVerifySingleSecretProof: Verifies a single-secret proof (checks s*G == R + e*C).
// GenerateMultiSecretCommitmentKey: Computes the public commitment key C = w1*G + w2*H for secrets w1, w2.
// NewProverContextMulti: Creates a context for the multi-secret prover.
// ProverGenerateCommitmentMulti: Generates the prover's commitment R = r1*G + r2*H for nonces r1, r2.
// ProverComputeResponseMulti: Computes responses s1 = r1 + e*w1 and s2 = r2 + e*w2.
// NewMultiSecretProof: Creates a structure to hold the multi-secret proof (R, s1, s2).
// ProverCreateMultiSecretProof: Combines commitment and responses into a multi-secret proof structure.
// NewVerifierContextMulti: Creates a context for the multi-secret verifier.
// VerifierVerifyMultiSecretProof: Verifies a multi-secret proof (checks s1*G + s2*H == R + e*C).
// VerifyPointOnCurve: Checks if a deserialized point lies on the curve.
// RunInteractiveProofSessionSingle: Orchestrates an interactive single-secret proof exchange.
// RunFiatShamirProofSessionSingle: Orchestrates a non-interactive single-secret proof using Fiat-Shamir.
// RunInteractiveProofSessionMulti: Orchestrates an interactive multi-secret proof exchange.
// RunFiatShamirProofSessionMulti: Orchestrates a non-interactive multi-secret proof using Fiat-Shamir.

package customzkp

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

var (
	curve elliptic.Curve
	G     *big.Int // Base point Gx
	Gy    *big.Int // Base point Gy
	n     *big.Int // Curve order

	ErrInvalidScalar     = errors.New("invalid scalar value")
	ErrInvalidPoint      = errors.New("invalid point on curve")
	ErrProofVerification = errors.New("proof verification failed")
	ErrSerialization     = errors.New("serialization failed")
	ErrDeserialization   = errors.New("deserialization failed")
)

// ECC_GenerateCurveParameters initializes the elliptic curve (P-256) and its parameters.
func ECC_GenerateCurveParameters() {
	curve = elliptic.P256()
	G, Gy = curve.Params().Gx, curve.Params().Gy
	n = curve.Params().N
}

// ECC_GetGeneratorG returns the standard base point G.
func ECC_GetGeneratorG() (x, y *big.Int) {
	// Ensure parameters are initialized
	if curve == nil {
		ECC_GenerateCurveParameters()
	}
	return G, Gy
}

// ECC_GetRandomGeneratorH returns a random generator point H != G.
// In a real system, H should be derived from G using a verifiably random process
// like hashing G to a point, or using a dedicated different curve parameter.
// This simple implementation picks a random scalar k and computes k*G.
// It's crucial that H is fixed and publicly known for the system to be secure.
func ECC_GetRandomGeneratorH() (x, y *big.Int, err error) {
	// Ensure parameters are initialized
	if curve == nil {
		ECC_GenerateCurveParameters()
	}
	// Generate a random non-zero scalar
	k, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random scalar for H: %w", err)
	}
	// Compute k*G
	Hx, Hy := curve.ScalarBaseMult(k.Bytes())

	// Ensure H is not the point at infinity or G (unlikely with random k but good practice)
	// Note: comparing H to G is not strictly necessary if k is random and non-zero mod n,
	// but checking against the point at infinity is important.
	if Hx.Cmp(big.NewInt(0)) == 0 && Hy.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, errors.New("generated random generator H is the point at infinity")
	}

	return Hx, Hy, nil
}

// ECC_PointMultiply performs scalar multiplication k * P.
func ECC_PointMultiply(Px, Py *big.Int, k *big.Int) (Qx, Qy *big.Int, err error) {
	if curve == nil {
		return nil, nil, errors.New("curve parameters not initialized")
	}
	if k == nil || k.Sign() < 0 || k.Cmp(n) >= 0 {
		return nil, nil, ErrInvalidScalar
	}
	if Px == nil || Py == nil || !curve.IsOnCurve(Px, Py) {
		// Handle the point at infinity (0,0) which is technically on the curve but often needs special handling.
		// For P256, (0,0) isn't on the standard curve. Let's check standard on-curve.
		if Px.Cmp(big.NewInt(0)) == 0 && Py.Cmp(big.NewInt(0)) == 0 {
             // If P is point at infinity, k*P is point at infinity
             return big.NewInt(0), big.NewInt(0), nil
        }
		return nil, nil, ErrInvalidPoint
	}

	Qx, Qy = curve.ScalarMult(Px, Py, k.Bytes())
	return Qx, Qy, nil
}

// ECC_PointAdd performs point addition P + Q.
func ECC_PointAdd(P1x, P1y, P2x, P2y *big.Int) (Qx, Qy *big.Int, err error) {
	if curve == nil {
		return nil, nil, errors.New("curve parameters not initialized")
	}
	// Handle point at infinity scenarios
	p1IsInf := P1x.Cmp(big.NewInt(0)) == 0 && P1y.Cmp(big.NewInt(0)) == 0
	p2IsInf := P2x.Cmp(big.NewInt(0)) == 0 && P2y.Cmp(big.NewInt(0)) == 0

	if p1IsInf && p2IsInf {
		return big.NewInt(0), big.NewInt(0), nil // infinity + infinity = infinity
	}
	if p1IsInf {
		if !curve.IsOnCurve(P2x, P2y) { return nil, nil, ErrInvalidPoint }
		return new(big.Int).Set(P2x), new(big.Int).Set(P2y), nil // infinity + Q = Q
	}
	if p2IsInf {
		if !curve.IsOnCurve(P1x, P1y) { return nil, nil, ErrInvalidPoint }
		return new(big.Int).Set(P1x), new(big.Int).Set(P1y), nil // P + infinity = P
	}

	// Standard point addition
	if !curve.IsOnCurve(P1x, P1y) || !curve.IsOnCurve(P2x, P2y) {
		return nil, nil, ErrInvalidPoint
	}

	Qx, Qy = curve.Add(P1x, P1y, P2x, P2y)
	return Qx, Qy, nil
}

// ECC_PointSerialize serializes an elliptic curve point (Px, Py) to bytes
// using the uncompressed point format (0x04 || Px || Py).
// Returns an error if the point is invalid or serialization fails.
func ECC_PointSerialize(Px, Py *big.Int) ([]byte, error) {
	if curve == nil {
		return nil, errors.New("curve parameters not initialized")
	}
    // Handle point at infinity (serialize as 0x00 or other agreed format)
    if Px.Cmp(big.NewInt(0)) == 0 && Py.Cmp(big.NewInt(0)) == 0 {
        // Let's define point at infinity as a single zero byte for simplicity in this example
        return []byte{0x00}, nil
    }

	// Check if the point is on the curve before serializing
	if !curve.IsOnCurve(Px, Py) {
		return nil, ErrInvalidPoint
	}

	// Using standard Uncompressed format: 0x04 || X || Y
	// X and Y are padded to the curve size (32 bytes for P256)
	pointBytes := elliptic.Marshal(curve, Px, Py)
	if pointBytes == nil {
		return nil, ErrSerialization
	}
	return pointBytes, nil
}

// ECC_PointDeserialize deserializes bytes into an elliptic curve point (Px, Py).
// Returns an error if deserialization fails or the point is not on the curve.
func ECC_PointDeserialize(data []byte) (Px, Py *big.Int, err error) {
	if curve == nil {
		return nil, nil, errors.New("curve parameters not initialized")
	}
    // Handle point at infinity deserialization
    if len(data) == 1 && data[0] == 0x00 {
        return big.NewInt(0), big.NewInt(0), nil
    }

	Px, Py = elliptic.Unmarshal(curve, data)
	if Px == nil || Py == nil {
		return nil, nil, ErrDeserialization
	}

	// Verify the point is on the curve after deserialization
	if !curve.IsOnCurve(Px, Py) {
		return nil, nil, ErrInvalidPoint
	}

	return Px, Py, nil
}

// Scalar_Add performs modular addition (a + b) mod n.
func Scalar_Add(a, b *big.Int) *big.Int {
	if n == nil {
		ECC_GenerateCurveParameters() // Ensure n is initialized
	}
	res := new(big.Int).Add(a, b)
	res.Mod(res, n)
	return res
}

// Scalar_Multiply performs modular multiplication (a * b) mod n.
func Scalar_Multiply(a, b *big.Int) *big.Int {
	if n == nil {
		ECC_GenerateCurveParameters() // Ensure n is initialized
	}
	res := new(big.Int).Mul(a, b)
	res.Mod(res, n)
	return res
}

// Scalar_HashToScalar hashes arbitrary data to produce a scalar modulo n.
func Scalar_HashToScalar(data ...[]byte) *big.Int {
	if n == nil {
		ECC_GenerateCurveParameters() // Ensure n is initialized
	}
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	hashBytes := hasher.Sum(nil)

	// Convert hash bytes to a big.Int and take modulo n
	hashInt := new(big.Int).SetBytes(hashBytes)
	return hashInt.Mod(hashInt, n)
}

// GenerateRandomScalar generates a cryptographically secure random scalar in [1, n-1].
func GenerateRandomScalar() (*big.Int, error) {
	if n == nil {
		ECC_GenerateCurveParameters() // Ensure n is initialized
	}
	// Generate a random number less than n
	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	// Ensure the scalar is not zero (private keys/nonces should be non-zero)
	if k.Sign() == 0 {
		// Very low probability, but recurse if it happens
		return GenerateRandomScalar()
	}
	return k, nil
}

// VerifyScalarRange checks if a scalar s is within the valid range [1, n-1].
func VerifyScalarRange(s *big.Int) error {
	if n == nil {
		ECC_GenerateCurveParameters() // Ensure n is initialized
	}
	if s == nil || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return ErrInvalidScalar
	}
	return nil
}

// VerifyPointOnCurve checks if a point (Px, Py) is on the curve.
func VerifyPointOnCurve(Px, Py *big.Int) error {
	if curve == nil {
		return errors.New("curve parameters not initialized")
	}
    // Allow point at infinity as a valid "point" in some contexts, though technically not on the curve equation
     if Px.Cmp(big.NewInt(0)) == 0 && Py.Cmp(big.NewInt(0)) == 0 {
        return nil // Point at infinity is valid
     }
	if Px == nil || Py == nil || !curve.IsOnCurve(Px, Py) {
		return ErrInvalidPoint
	}
	return nil
}

// --- Single Secret Schnorr ZKP Functions ---

// ProverContext holds the state for the single-secret prover.
type ProverContext struct {
	secretW *big.Int // The secret witness w
	nonceR  *big.Int // The random nonce r generated for the current proof attempt
}

// SingleSecretProof holds the components of a single-secret proof.
type SingleSecretProof struct {
	CommitmentR_x *big.Int // R = r * G, X-coordinate
	CommitmentR_y *big.Int // R = r * G, Y-coordinate
	ResponseS     *big.Int // s = r + e * w (mod n)
}

// NewProverContext creates a context for the single-secret prover.
func NewProverContext(secretW *big.Int) (*ProverContext, error) {
	if err := VerifyScalarRange(secretW); err != nil {
		return nil, fmt.Errorf("invalid prover secret: %w", err)
	}
	return &ProverContext{secretW: secretW}, nil
}

// GenerateProverSecret generates a random secret scalar for the prover.
func GenerateProverSecret() (*big.Int, error) {
	return GenerateRandomScalar()
}

// GenerateProverCommitmentKey computes the public commitment key C = w * G.
func GenerateProverCommitmentKey(secretW *big.Int) (Cx, Cy *big.Int, err error) {
	if err := VerifyScalarRange(secretW); err != nil {
		return nil, nil, fmt.Errorf("invalid prover secret for commitment key: %w", err)
	}
	Gx, Gy := ECC_GetGeneratorG()
	Cx, Cy, err = ECC_PointMultiply(Gx, Gy, secretW)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute commitment key: %w", err)
	}
	return Cx, Cy, nil
}

// ProverGenerateCommitment generates the prover's commitment R = r * G for a random nonce r.
func (pc *ProverContext) ProverGenerateCommitment() (Rx, Ry *big.Int, err error) {
	// Generate a fresh random nonce r for each proof attempt
	r, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	pc.nonceR = r

	Gx, Gy := ECC_GetGeneratorG()
	Rx, Ry, err = ECC_PointMultiply(Gx, Gy, pc.nonceR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute commitment: %w", err)
	}
	return Rx, Ry, nil
}

// ProverComputeResponse computes the prover's response s = r + e * w (mod n).
func (pc *ProverContext) ProverComputeResponse(challengeE *big.Int) (*big.Int, error) {
	if pc.nonceR == nil {
		return nil, errors.New("nonce not generated, call ProverGenerateCommitment first")
	}
	if err := VerifyScalarRange(challengeE); err != nil {
		// Challenge can be 0 in interactive, but not Fiat-Shamir.
		// Let's allow 0 for robustness here, but verify against n.
		if challengeE == nil || challengeE.Sign() < 0 || challengeE.Cmp(n) >= 0 {
             return nil, fmt.Errorf("invalid challenge scalar: %w", ErrInvalidScalar)
        }
	}

	// s = r + e * w (mod n)
	eTimesW := Scalar_Multiply(challengeE, pc.secretW)
	s := Scalar_Add(pc.nonceR, eTimesW)

	// Clear the nonce after computing the response (use it only once)
	pc.nonceR = nil // nil out the nonce to prevent reuse

	return s, nil
}

// NewSingleSecretProof creates a structure to hold the single-secret proof.
func NewSingleSecretProof(Rx, Ry, s *big.Int) *SingleSecretProof {
	return &SingleSecretProof{
		CommitmentR_x: Rx,
		CommitmentR_y: Ry,
		ResponseS:     s,
	}
}

// ProverCreateSingleSecretProof combines commitment and response into a proof structure.
func (pc *ProverContext) ProverCreateSingleSecretProof(Rx, Ry, s *big.Int) (*SingleSecretProof, error) {
	// Basic validation
	if err := VerifyPointOnCurve(Rx, Ry); err != nil {
		return nil, fmt.Errorf("invalid commitment point: %w", err)
	}
	if err := VerifyScalarRange(s); err != nil {
         // Response 's' can be 0 in very rare cases (e.g., if r = -e*w mod n).
         // The range check should just be 0 <= s < n.
         if s == nil || s.Sign() < 0 || s.Cmp(n) >= 0 {
             return nil, fmt.Errorf("invalid response scalar: %w", ErrInvalidScalar)
         }
	}
	return NewSingleSecretProof(Rx, Ry, s), nil
}


// VerifierContext holds the public values needed for verification.
type VerifierContext struct {
	CommitmentKeyCx *big.Int // Prover's public commitment key C = w * G, X-coord
	CommitmentKeyCy *big.Int // Prover's public commitment key C = w * G, Y-coord
}

// NewVerifierContext creates a context for the single-secret verifier.
func NewVerifierContext(Cx, Cy *big.Int) (*VerifierContext, error) {
	if err := VerifyPointOnCurve(Cx, Cy); err != nil {
		return nil, fmt.Errorf("invalid commitment key point: %w", err)
	}
	return &VerifierContext{CommitmentKeyCx: Cx, CommitmentKeyCy: Cy}, nil
}

// VerifierGenerateChallenge generates a random challenge scalar e for interactive proofs.
func VerifierGenerateChallenge() (*big.Int, error) {
	// In an interactive proof, the challenge is random and generated by the verifier.
	// In Fiat-Shamir (non-interactive), it's a hash of the public data.
	// This function is for the interactive case.
	return GenerateRandomScalar() // Generates a random scalar in [1, n-1]
}

// HashToChallenge deterministically generates a challenge scalar e using the Fiat-Shamir heuristic.
// It hashes the public parameters and the prover's commitment.
func HashToChallenge(Cx, Cy, Rx, Ry *big.Int) (*big.Int, error) {
	cxBytes, err := ECC_PointSerialize(Cx, Cy)
	if err != nil { return nil, fmt.Errorf("failed to serialize commitment key for hashing: %w", err) }
	rxBytes, err := ECC_PointSerialize(Rx, Ry)
	if err != nil { return nil, fmt.Errorf("failed to serialize commitment for hashing: %w", err) }

	Gx, Gy := ECC_GetGeneratorG()
    gxBytes, err := ECC_PointSerialize(Gx, Gy)
    if err != nil { return nil, fmt.Errorf("failed to serialize generator G for hashing: %w", err) }


	// Hash G, C, R to get the challenge scalar
	return Scalar_HashToScalar(gxBytes, cxBytes, rxBytes), nil
}

// VerifierVerifySingleSecretProof verifies a single-secret proof (R, s) against the public key C.
// It checks if s * G == R + e * C.
func (vc *VerifierContext) VerifierVerifySingleSecretProof(proof *SingleSecretProof, challengeE *big.Int) (bool, error) {
	if proof == nil {
		return false, errors.New("nil proof provided")
	}
	if err := VerifyPointOnCurve(proof.CommitmentR_x, proof.CommitmentR_y); err != nil {
		return false, fmt.Errorf("invalid commitment point in proof: %w", err)
	}
	// Response 's' must be in [0, n-1]
	if proof.ResponseS == nil || proof.ResponseS.Sign() < 0 || proof.ResponseS.Cmp(n) >= 0 {
		return false, fmt.Errorf("invalid response scalar in proof: %w", ErrInvalidScalar)
	}
    // Challenge 'e' must be in [0, n-1] (can be 0 from hashing, but not <0 or >=n)
    if challengeE == nil || challengeE.Sign() < 0 || challengeE.Cmp(n) >= 0 {
         return false, fmt.Errorf("invalid challenge scalar: %w", ErrInvalidScalar)
    }


	Gx, Gy := ECC_GetGeneratorG()

	// Calculate left side: s * G
	sGx, sGy, err := ECC_PointMultiply(Gx, Gy, proof.ResponseS)
	if err != nil {
		return false, fmt.Errorf("failed to compute s*G: %w", err)
	}

	// Calculate right side: e * C
	eCx, eCy, err := ECC_PointMultiply(vc.CommitmentKeyCx, vc.CommitmentKeyCy, challengeE)
	if err != nil {
		return false, fmt.Errorf("failed to compute e*C: %w", err)
	}

	// Calculate R + e * C
	sumRx, sumRy, err := ECC_PointAdd(proof.CommitmentR_x, proof.CommitmentR_y, eCx, eCy)
	if err != nil {
		return false, fmt.Errorf("failed to compute R + e*C: %w", err)
	}

	// Check if s * G == R + e * C
	if sGx.Cmp(sumRx) == 0 && sGy.Cmp(sumRy) == 0 {
		return true, nil // Verification successful
	}

	return false, ErrProofVerification // Verification failed
}

// SingleSecretProof_Serialize serializes a SingleSecretProof to bytes.
// Format: Len(R_x) || R_x || Len(R_y) || R_y || Len(s) || s (Length prefixes as 4-byte big-endian unsigned int)
// Note: Using ECC_PointSerialize for R_x, R_y handles their length internally.
func SingleSecretProof_Serialize(proof *SingleSecretProof) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("nil proof provided for serialization")
	}

	// Serialize commitment R
	rBytes, err := ECC_PointSerialize(proof.CommitmentR_x, proof.CommitmentR_y)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize commitment R: %w", err)
	}

	// Serialize response s
	sBytes := proof.ResponseS.Bytes()

	// Combine bytes: R || s
	// In a more robust format, you might include length prefixes or use a structured encoding.
	// For simplicity here, assuming fixed-size elements based on curve parameters.
	// A safer way is to include length prefixes.
	// Let's use a simple prefix: 4 bytes for len(R_bytes) | R_bytes | 4 bytes for len(s_bytes) | s_bytes
	var buf []byte

	// Length of R bytes (typically 65 for P-256 uncompressed + type byte)
	rLen := uint32(len(rBytes))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, rLen)
	buf = append(buf, lenBuf...)
	buf = append(buf, rBytes...)

	// Length of s bytes (variable, up to 32 for P-256 scalar)
	sLen := uint32(len(sBytes))
	binary.BigEndian.PutUint32(lenBuf, sLen)
	buf = append(buf, lenBuf...)
	buf = append(buf, sBytes...)

	return buf, nil
}

// SingleSecretProof_Deserialize deserializes bytes into a SingleSecretProof.
func SingleSecretProof_Deserialize(data []byte) (*SingleSecretProof, error) {
	if len(data) < 8 { // Need at least 4 bytes for rLen + 4 bytes for sLen
		return nil, ErrDeserialization
	}

	// Read R length
	rLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(rLen) {
		return nil, ErrDeserialization
	}
	rBytes := data[:rLen]
	data = data[rLen:]

	// Read s length
	if len(data) < 4 {
		return nil, ErrDeserialization
	}
	sLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(sLen) {
		return nil, ErrDeserialization
	}
	sBytes := data[:sLen]
	// data = data[sLen:] // No more data expected after s

	// Deserialize R
	Rx, Ry, err := ECC_PointDeserialize(rBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize commitment R: %w", err)
	}

	// Deserialize s
	s := new(big.Int).SetBytes(sBytes)

	// Basic validation on s
	if s.Sign() < 0 || s.Cmp(n) >= 0 {
		// Should be 0 <= s < n
        return nil, fmt.Errorf("deserialized scalar s is out of range: %w", ErrDeserialization)
	}

	return NewSingleSecretProof(Rx, Ry, s), nil
}


// --- Multi-Secret Schnorr-like ZKP Functions ---

// MultiSecretProverContext holds the state for the multi-secret prover.
type MultiSecretProverContext struct {
	secretW1 *big.Int // First secret witness w1
	secretW2 *big.Int // Second secret witness w2
	nonceR1  *big.Int // First random nonce r1
	nonceR2  *big.Int // Second random nonce r2
	Hx, Hy   *big.Int // Public generator H
}

// MultiSecretProof holds the components of a multi-secret proof.
type MultiSecretProof struct {
	CommitmentR_x *big.Int // R = r1*G + r2*H, X-coordinate
	CommitmentR_y *big.Int // R = r1*G + r2*H, Y-coordinate
	ResponseS1    *big.Int // s1 = r1 + e * w1 (mod n)
	ResponseS2    *big.Int // s2 = r2 + e * w2 (mod n)
}

// NewProverContextMulti creates a context for the multi-secret prover.
func NewProverContextMulti(secretW1, secretW2, Hx, Hy *big.Int) (*MultiSecretProverContext, error) {
	if err := VerifyScalarRange(secretW1); err != nil {
		return nil, fmt.Errorf("invalid first secret: %w", err)
	}
	if err := VerifyScalarRange(secretW2); err != nil {
		return nil, fmt.Errorf("invalid second secret: %w", err)
	}
	if err := VerifyPointOnCurve(Hx, Hy); err != nil {
		return nil, fmt.Errorf("invalid generator H point: %w", err)
	}
    Gx, Gy := ECC_GetGeneratorG()
    if Hx.Cmp(Gx) == 0 && Hy.Cmp(Gy) == 0 {
        return nil, errors.New("generator H cannot be the same as G")
    }

	return &MultiSecretProverContext{
		secretW1: secretW1,
		secretW2: secretW2,
		Hx:       Hx,
		Hy:       Hy,
	}, nil
}

// GenerateMultiSecretCommitmentKey computes the public commitment key C = w1*G + w2*H.
func GenerateMultiSecretCommitmentKey(secretW1, secretW2, Hx, Hy *big.Int) (Cx, Cy *big.Int, err error) {
	if err := VerifyScalarRange(secretW1); err != nil {
		return nil, nil, fmt.Errorf("invalid first secret for commitment key: %w", err)
	}
	if err := VerifyScalarRange(secretW2); err != nil {
		return nil, nil, fmt.Errorf("invalid second secret for commitment key: %w", err)
	}
	if err := VerifyPointOnCurve(Hx, Hy); err != nil {
		return nil, nil, fmt.Errorf("invalid generator H for commitment key: %w", err)
	}
     Gx, Gy := ECC_GetGeneratorG()
     if Hx.Cmp(Gx) == 0 && Hy.Cmp(Gy) == 0 {
        return nil, nil, errors.New("generator H cannot be the same as G for commitment key")
    }


	// Compute w1*G
	w1Gx, w1Gy, err := ECC_PointMultiply(Gx, Gy, secretW1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute w1*G: %w", err)
	}

	// Compute w2*H
	w2Hx, w2Hy, err := ECC_PointMultiply(Hx, Hy, secretW2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute w2*H: %w", err)
	}

	// Compute C = w1*G + w2*H
	Cx, Cy, err = ECC_PointAdd(w1Gx, w1Gy, w2Hx, w2Hy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute w1*G + w2*H: %w", err)
	}

	return Cx, Cy, nil
}

// ProverGenerateCommitmentMulti generates the prover's commitment R = r1*G + r2*H.
func (pc *MultiSecretProverContext) ProverGenerateCommitmentMulti() (Rx, Ry *big.Int, err error) {
	// Generate fresh random nonces r1, r2
	r1, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce r1: %w", err)
	}
	r2, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce r2: %w", err)
	}
	pc.nonceR1 = r1
	pc.nonceR2 = r2

	Gx, Gy := ECC_GetGeneratorG()

	// Compute r1*G
	r1Gx, r1Gy, err := ECC_PointMultiply(Gx, Gy, pc.nonceR1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute r1*G: %w", err)
	}

	// Compute r2*H
	r2Hx, r2Hy, err := ECC_PointMultiply(pc.Hx, pc.Hy, pc.nonceR2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute r2*H: %w", err)
	}

	// Compute R = r1*G + r2*H
	Rx, Ry, err = ECC_PointAdd(r1Gx, r1Gy, r2Hx, r2Hy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute commitment R: %w", err)
	}

	return Rx, Ry, nil
}

// ProverComputeResponseMulti computes responses s1 = r1 + e*w1 and s2 = r2 + e*w2.
func (pc *MultiSecretProverContext) ProverComputeResponseMulti(challengeE *big.Int) (s1, s2 *big.Int, err error) {
	if pc.nonceR1 == nil || pc.nonceR2 == nil {
		return nil, nil, errors.New("nonces not generated, call ProverGenerateCommitmentMulti first")
	}
	if challengeE == nil || challengeE.Sign() < 0 || challengeE.Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("invalid challenge scalar: %w", ErrInvalidScalar)
	}

	// s1 = r1 + e * w1 (mod n)
	eTimesW1 := Scalar_Multiply(challengeE, pc.secretW1)
	s1 = Scalar_Add(pc.nonceR1, eTimesW1)

	// s2 = r2 + e * w2 (mod n)
	eTimesW2 := Scalar_Multiply(challengeE, pc.secretW2)
	s2 = Scalar_Add(pc.nonceR2, eTimesW2)

	// Clear nonces
	pc.nonceR1 = nil
	pc.nonceR2 = nil

	return s1, s2, nil
}

// NewMultiSecretProof creates a structure to hold the multi-secret proof.
func NewMultiSecretProof(Rx, Ry, s1, s2 *big.Int) *MultiSecretProof {
	return &MultiSecretProof{
		CommitmentR_x: Rx,
		CommitmentR_y: Ry,
		ResponseS1:    s1,
		ResponseS2:    s2,
	}
}

// ProverCreateMultiSecretProof combines commitment and responses into a multi-secret proof structure.
func (pc *MultiSecretProverContext) ProverCreateMultiSecretProof(Rx, Ry, s1, s2 *big.Int) (*MultiSecretProof, error) {
	// Basic validation
	if err := VerifyPointOnCurve(Rx, Ry); err != nil {
		return nil, fmt.Errorf("invalid commitment point: %w", err)
	}
	// Responses s1, s2 must be in [0, n-1]
	if s1 == nil || s1.Sign() < 0 || s1.Cmp(n) >= 0 || s2 == nil || s2.Sign() < 0 || s2.Cmp(n) >= 0 {
		return nil, fmt.Errorf("invalid response scalar in proof: %w", ErrInvalidScalar)
	}
	return NewMultiSecretProof(Rx, Ry, s1, s2), nil
}


// VerifierContextMulti holds the public values needed for multi-secret verification.
type VerifierContextMulti struct {
	CommitmentKeyCx *big.Int // C = w1*G + w2*H, X-coord
	CommitmentKeyCy *big.Int // C = w1*G + w2*H, Y-coord
	Hx, Hy          *big.Int // Public generator H
}

// NewVerifierContextMulti creates a context for the multi-secret verifier.
func NewVerifierContextMulti(Cx, Cy, Hx, Hy *big.Int) (*VerifierContextMulti, error) {
	if err := VerifyPointOnCurve(Cx, Cy); err != nil {
		return nil, fmt.Errorf("invalid commitment key point: %w", err)
	}
	if err := VerifyPointOnCurve(Hx, Hy); err != nil {
		return nil, fmt.Errorf("invalid generator H point: %w", err)
	}
     Gx, Gy := ECC_GetGeneratorG()
     if Hx.Cmp(Gx) == 0 && Hy.Cmp(Gy) == 0 {
        return nil, errors.New("generator H cannot be the same as G for verifier context")
    }
	return &VerifierContextMulti{
		CommitmentKeyCx: Cx,
		CommitmentKeyCy: Cy,
		Hx:              Hx,
		Hy:              Hy,
	}, nil
}

// VerifierVerifyMultiSecretProof verifies a multi-secret proof (R, s1, s2) against the public key C.
// It checks if s1*G + s2*H == R + e * C.
func (vc *VerifierContextMulti) VerifierVerifyMultiSecretProof(proof *MultiSecretProof, challengeE *big.Int) (bool, error) {
	if proof == nil {
		return false, errors.New("nil multi-secret proof provided")
	}
	if err := VerifyPointOnCurve(proof.CommitmentR_x, proof.CommitmentR_y); err != nil {
		return false, fmt.Errorf("invalid commitment point in proof: %w", err)
	}
	// Responses s1, s2 must be in [0, n-1]
	if proof.ResponseS1 == nil || proof.ResponseS1.Sign() < 0 || proof.ResponseS1.Cmp(n) >= 0 ||
		proof.ResponseS2 == nil || proof.ResponseS2.Sign() < 0 || proof.ResponseS2.Cmp(n) >= 0 {
		return false, fmt.Errorf("invalid response scalar in proof: %w", ErrInvalidScalar)
	}
    // Challenge 'e' must be in [0, n-1]
    if challengeE == nil || challengeE.Sign() < 0 || challengeE.Cmp(n) >= 0 {
         return false, fmt.Errorf("invalid challenge scalar: %w", ErrInvalidScalar)
    }


	Gx, Gy := ECC_GetGeneratorG()

	// Calculate left side: s1 * G + s2 * H
	s1Gx, s1Gy, err := ECC_PointMultiply(Gx, Gy, proof.ResponseS1)
	if err != nil {
		return false, fmt.Errorf("failed to compute s1*G: %w", err)
	}
	s2Hx, s2Hy, err := ECC_PointMultiply(vc.Hx, vc.Hy, proof.ResponseS2)
	if err != nil {
		return false, fmt.Errorf("failed to compute s2*H: %w", err)
	}
	lhsX, lhsY, err := ECC_PointAdd(s1Gx, s1Gy, s2Hx, s2Hy)
	if err != nil {
		return false, fmt.Errorf("failed to compute s1*G + s2*H: %w", err)
	}

	// Calculate right side: R + e * C
	eCx, eCy, err := ECC_PointMultiply(vc.CommitmentKeyCx, vc.CommitmentKeyCy, challengeE)
	if err != nil {
		return false, fmt.Errorf("failed to compute e*C: %w", err)
	}
	rhsX, rhsY, err := ECC_PointAdd(proof.CommitmentR_x, proof.CommitmentR_y, eCx, eCy)
	if err != nil {
		return false, fmt.Errorf("failed to compute R + e*C: %w", err)
	}

	// Check if s1 * G + s2 * H == R + e * C
	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		return true, nil // Verification successful
	}

	return false, ErrProofVerification // Verification failed
}

// MultiSecretProof_Serialize serializes a MultiSecretProof to bytes.
// Format: Len(R_bytes) | R_bytes | Len(s1_bytes) | s1_bytes | Len(s2_bytes) | s2_bytes (Length prefixes as 4-byte big-endian unsigned int)
func MultiSecretProof_Serialize(proof *MultiSecretProof) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("nil proof provided for serialization")
	}

	rBytes, err := ECC_PointSerialize(proof.CommitmentR_x, proof.CommitmentR_y)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize commitment R: %w", err)
	}

	s1Bytes := proof.ResponseS1.Bytes()
	s2Bytes := proof.ResponseS2.Bytes()

	var buf []byte

	lenBuf := make([]byte, 4)

	// Length of R bytes
	rLen := uint32(len(rBytes))
	binary.BigEndian.PutUint32(lenBuf, rLen)
	buf = append(buf, lenBuf...)
	buf = append(buf, rBytes...)

	// Length of s1 bytes
	s1Len := uint32(len(s1Bytes))
	binary.BigEndian.PutUint32(lenBuf, s1Len)
	buf = append(buf, lenBuf...)
	buf = append(buf, s1Bytes...)

	// Length of s2 bytes
	s2Len := uint32(len(s2Bytes))
	binary.BigEndian.PutUint32(lenBuf, s2Len)
	buf = append(buf, lenBuf...)
	buf = append(buf, s2Bytes...)

	return buf, nil
}

// MultiSecretProof_Deserialize deserializes bytes into a MultiSecretProof.
func MultiSecretProof_Deserialize(data []byte) (*MultiSecretProof, error) {
	if len(data) < 12 { // Need at least 4 bytes for rLen + 4 bytes for s1Len + 4 bytes for s2Len
		return nil, ErrDeserialization
	}

	// Read R length
	rLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(rLen) {
		return nil, ErrDeserialization
	}
	rBytes := data[:rLen]
	data = data[rLen:]

	// Read s1 length
	if len(data) < 4 {
		return nil, ErrDeserialization
	}
	s1Len := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(s1Len) {
		return nil, ErrDeserialization
	}
	s1Bytes := data[:s1Len]
	data = data[s1Len:]

	// Read s2 length
	if len(data) < 4 {
		return nil, ErrDeserialization
	}
	s2Len := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if len(data) < int(s2Len) {
		return nil, ErrDeserialization
	}
	s2Bytes := data[:s2Len]
	// data = data[s2Len:] // No more data expected

	// Deserialize R
	Rx, Ry, err := ECC_PointDeserialize(rBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize commitment R: %w", err)
	}

	// Deserialize s1
	s1 := new(big.Int).SetBytes(s1Bytes)
	// Deserialize s2
	s2 := new(big.Int).SetBytes(s2Bytes)

    // Basic validation on s1, s2
	if s1.Sign() < 0 || s1.Cmp(n) >= 0 || s2.Sign() < 0 || s2.Cmp(n) >= 0 {
		// Should be 0 <= s < n
        return nil, fmt.Errorf("deserialized scalar s1 or s2 is out of range: %w", ErrDeserialization)
	}


	return NewMultiSecretProof(Rx, Ry, s1, s2), nil
}


// --- Proof Orchestration Examples ---
// These functions demonstrate how a prover and verifier would interact
// or how a non-interactive proof would be generated and verified.

// RunInteractiveProofSessionSingle simulates an interactive single-secret ZKP exchange.
// Prover has secretW, Verifier knows public key C = w*G.
func RunInteractiveProofSessionSingle(secretW *big.Int) (bool, error) {
	fmt.Println("--- Running Interactive Single-Secret Proof Session ---")

	// 1. Setup (outside the interactive loop, often done once)
	ECC_GenerateCurveParameters()
	Gx, Gy := ECC_GetGeneratorG()

	// Prover generates public key C
	Cx, Cy, err := GenerateProverCommitmentKey(secretW)
	if err != nil {
		return false, fmt.Errorf("setup error: %w", err)
	}
	fmt.Printf("Prover's public key C: (%s, %s)\n", Cx.Text(16), Cy.Text(16))

	// Create Prover and Verifier contexts
	proverCtx, err := NewProverContext(secretW)
	if err != nil {
		return false, fmt.Errorf("prover context error: %w", err)
	}
	verifierCtx, err := NewVerifierContext(Cx, Cy)
	if err != nil {
		return false, fmt.Errorf("verifier context error: %w", err)
	}
	fmt.Println("Prover and Verifier contexts initialized.")

	// 2. Prover sends Commitment (R) to Verifier
	Rx, Ry, err := proverCtx.ProverGenerateCommitment()
	if err != nil {
		return false, fmt.Errorf("prover commitment error: %w", err)
	}
	fmt.Printf("Prover commits R: (%s, %s)\n", Rx.Text(16), Ry.Text(16))
	// In a real interactive protocol, R is sent over a channel.

	// 3. Verifier generates and sends Challenge (e) to Prover
	challengeE, err := VerifierGenerateChallenge() // Random challenge
	if err != nil {
		return false, fmt.Errorf("verifier challenge error: %w", err)
	}
	fmt.Printf("Verifier challenges with e: %s\n", challengeE.Text(16))
	// In a real interactive protocol, e is sent over a channel.

	// 4. Prover computes and sends Response (s) to Verifier
	responseS, err := proverCtx.ProverComputeResponse(challengeE)
	if err != nil {
		return false, fmt.Errorf("prover response error: %w", err)
	}
	fmt.Printf("Prover responds with s: %s\n", responseS.Text(16))
	// In a real interactive protocol, s is sent over a channel.

	// Prover creates the final proof structure (optional in interactive, but good for serialization example)
	proof := NewSingleSecretProof(Rx, Ry, responseS)

	// 5. Verifier verifies the Proof (R, s) using e and C
	fmt.Println("Verifier starts verification...")
	isVerified, err := verifierCtx.VerifierVerifySingleSecretProof(proof, challengeE)
	if err != nil {
		return false, fmt.Errorf("verifier verification error: %w", err)
	}

	if isVerified {
		fmt.Println("Verification successful: Prover knows the secret w for C.")
	} else {
		fmt.Println("Verification failed: Prover does NOT know the secret w for C.")
	}

	return isVerified, nil
}


// RunFiatShamirProofSessionSingle simulates a non-interactive single-secret ZKP session.
// Prover has secretW, Verifier knows public key C = w*G.
func RunFiatShamirProofSessionSingle(secretW *big.Int) (bool, error) {
	fmt.Println("\n--- Running Fiat-Shamir Single-Secret Proof Session (Non-Interactive) ---")

	// 1. Setup
	ECC_GenerateCurveParameters()
	Gx, Gy := ECC_GetGeneratorG()

	// Prover generates public key C
	Cx, Cy, err := GenerateProverCommitmentKey(secretW)
	if err != nil {
		return false, fmt.Errorf("setup error: %w", err)
	}
	fmt.Printf("Prover's public key C: (%s, %s)\n", Cx.Text(16), Cy.Text(16))

	// Create Prover context
	proverCtx, err := NewProverContext(secretW)
	if err != nil {
		return false, fmt.Errorf("prover context error: %w", err)
	}
	fmt.Println("Prover context initialized.")

	// 2. Prover generates Commitment (R)
	Rx, Ry, err := proverCtx.ProverGenerateCommitment()
	if err != nil {
		return false, fmt.Errorf("prover commitment error: %w", err)
	}
	fmt.Printf("Prover commits R: (%s, %s)\n", Rx.Text(16), Ry.Text(16))

	// 3. Prover computes Challenge (e) using Fiat-Shamir (hash of public data + commitment)
	// The prover and verifier MUST use the same public data and hashing algorithm.
	challengeE, err := HashToChallenge(Cx, Cy, Rx, Ry)
	if err != nil {
		return false, fmt.Errorf("prover hashing challenge error: %w", err)
	}
	fmt.Printf("Prover computes challenge e (Fiat-Shamir): %s\n", challengeE.Text(16))

	// 4. Prover computes Response (s) using the hashed challenge
	responseS, err := proverCtx.ProverComputeResponse(challengeE)
	if err != nil {
		return false, fmt.Errorf("prover response error: %w", err)
	}
	fmt.Printf("Prover responds with s: %s\n", responseS.Text(16))

	// 5. Prover creates the non-interactive proof structure (R, s)
	proof := NewSingleSecretProof(Rx, Ry, responseS)
	fmt.Println("Prover creates proof structure.")

	// --- Verification (done by the Verifier) ---

	// Verifier has the public key C and receives the proof (R, s).
	// Verifier needs to re-compute the challenge e using the same Fiat-Shamir method.
	fmt.Println("\nVerifier receives proof and starts verification...")

	// Create Verifier context using the public key C
	verifierCtx, err := NewVerifierContext(Cx, Cy)
	if err != nil {
		return false, fmt.Errorf("verifier context error: %w", err)
	}
	fmt.Println("Verifier context initialized.")

	// Verifier re-computes the challenge e from received R and known C (and G)
	verifierChallengeE, err := HashToChallenge(verifierCtx.CommitmentKeyCx, verifierCtx.CommitmentKeyCy, proof.CommitmentR_x, proof.CommitmentR_y)
	if err != nil {
		return false, fmt.Errorf("verifier hashing challenge error: %w", err)
	}
	fmt.Printf("Verifier re-computes challenge e: %s\n", verifierChallengeE.Text(16))
	// The challenge must match the one the prover used!

	// 6. Verifier verifies the Proof (R, s) using the re-computed e and C
	isVerified, err := verifierCtx.VerifierVerifySingleSecretProof(proof, verifierChallengeE)
	if err != nil {
		return false, fmt.Errorf("verifier verification error: %w", err)
	}

	if isVerified {
		fmt.Println("Verification successful: Non-interactive proof validates.")
	} else {
		fmt.Println("Verification failed: Non-interactive proof invalid.")
	}

	return isVerified, nil
}


// RunFiatShamirProofSessionMulti simulates a non-interactive multi-secret ZKP session.
// Prover has secrets w1, w2. Verifier knows public key C = w1*G + w2*H.
func RunFiatShamirProofSessionMulti(secretW1, secretW2 *big.Int) (bool, error) {
	fmt.Println("\n--- Running Fiat-Shamir Multi-Secret Proof Session (Non-Interactive) ---")

	// 1. Setup
	ECC_GenerateCurveParameters()
	Gx, Gy := ECC_GetGeneratorG()
	// Get or generate a public generator H (must be known to both prover and verifier)
	Hx, Hy, err := ECC_GetRandomGeneratorH() // Use a fixed, known H in a real system!
	if err != nil {
		return false, fmt.Errorf("setup error: %w", err)
	}
	fmt.Printf("Public Generator G: (%s, %s)\n", Gx.Text(16), Gy.Text(16))
	fmt.Printf("Public Generator H: (%s, %s)\n", Hx.Text(16), Hy.Text(16))


	// Prover generates public key C = w1*G + w2*H
	Cx, Cy, err := GenerateMultiSecretCommitmentKey(secretW1, secretW2, Hx, Hy)
	if err != nil {
		return false, fmt.Errorf("setup error: %w", err)
	}
	fmt.Printf("Prover's public key C: (%s, %s)\n", Cx.Text(16), Cy.Text(16))

	// Create Prover context
	proverCtx, err := NewProverContextMulti(secretW1, secretW2, Hx, Hy)
	if err != nil {
		return false, fmt.Errorf("prover context error: %w", err)
	}
	fmt.Println("Prover context initialized.")

	// 2. Prover generates Commitment (R = r1*G + r2*H)
	Rx, Ry, err := proverCtx.ProverGenerateCommitmentMulti()
	if err != nil {
		return false, fmt.Errorf("prover commitment error: %w", err)
	}
	fmt.Printf("Prover commits R: (%s, %s)\n", Rx.Text(16), Ry.Text(16))

	// 3. Prover computes Challenge (e) using Fiat-Shamir (hash of public data + commitment)
	// Public data includes G, H, and C.
	gxBytes, err := ECC_PointSerialize(Gx, Gy)
    if err != nil { return false, fmt.Errorf("failed to serialize G for challenge hash: %w", err) }
	hxBytes, err := ECC_PointSerialize(Hx, Hy)
    if err != nil { return false, fmt.Errorf("failed to serialize H for challenge hash: %w", err) }
	cxBytes, err := ECC_PointSerialize(Cx, Cy)
    if err != nil { return false, fmt.Errorf("failed to serialize C for challenge hash: %w", err) }
	rxBytes, err := ECC_PointSerialize(Rx, Ry)
    if err != nil { return false, fmt.Errorf("failed to serialize R for challenge hash: %w", err) }

	challengeE := Scalar_HashToScalar(gxBytes, hxBytes, cxBytes, rxBytes)

	fmt.Printf("Prover computes challenge e (Fiat-Shamir): %s\n", challengeE.Text(16))

	// 4. Prover computes Responses (s1, s2) using the hashed challenge
	responseS1, responseS2, err := proverCtx.ProverComputeResponseMulti(challengeE)
	if err != nil {
		return false, fmt.Errorf("prover response error: %w", err)
	}
	fmt.Printf("Prover responds with s1: %s, s2: %s\n", responseS1.Text(16), responseS2.Text(16))

	// 5. Prover creates the non-interactive proof structure (R, s1, s2)
	proof := NewMultiSecretProof(Rx, Ry, responseS1, responseS2)
	fmt.Println("Prover creates proof structure.")

	// --- Verification (done by the Verifier) ---

	// Verifier has public keys C, H and receives the proof (R, s1, s2).
	// Verifier needs to re-compute the challenge e using the same Fiat-Shamir method.
	fmt.Println("\nVerifier receives proof and starts verification...")

	// Create Verifier context using the public keys C and H
	verifierCtx, err := NewVerifierContextMulti(Cx, Cy, Hx, Hy)
	if err != nil {
		return false, fmt.Errorf("verifier context error: %w", err)
	}
	fmt.Println("Verifier context initialized.")

	// Verifier re-computes the challenge e from received R and known C, H (and G)
	verifierGx, verifierGy := ECC_GetGeneratorG()
    verifierGxBytes, err := ECC_PointSerialize(verifierGx, verifierGy)
    if err != nil { return false, fmt.Errorf("failed to serialize G for challenge hash: %w", err) }
	verifierHxBytes, err := ECC_PointSerialize(verifierCtx.Hx, verifierCtx.Hy)
    if err != nil { return false, fmt.Errorf("failed to serialize H for challenge hash: %w", err) }
	verifierCxBytes, err := ECC_PointSerialize(verifierCtx.CommitmentKeyCx, verifierCtx.CommitmentKeyCy)
    if err != nil { return false, fmt.Errorf("failed to serialize C for challenge hash: %w", err) }
	verifierRxBytes, err := ECC_PointSerialize(proof.CommitmentR_x, proof.CommitmentR_y)
    if err != nil { return false, fmt.Errorf("failed to serialize R for challenge hash: %w", err) }


	verifierChallengeE := Scalar_HashToScalar(verifierGxBytes, verifierHxBytes, verifierCxBytes, verifierRxBytes)

	fmt.Printf("Verifier re-computes challenge e: %s\n", verifierChallengeE.Text(16))
	// The challenge must match the one the prover used!

	// 6. Verifier verifies the Proof (R, s1, s2) using the re-computed e and C, H
	isVerified, err := verifierCtx.VerifierVerifyMultiSecretProof(proof, verifierChallengeE)
	if err != nil {
		return false, fmt.Errorf("verifier verification error: %w", err)
	}

	if isVerified {
		fmt.Println("Verification successful: Non-interactive multi-secret proof validates.")
	} else {
		fmt.Println("Verification failed: Non-interactive multi-secret proof invalid.")
	}

	return isVerified, nil
}

```