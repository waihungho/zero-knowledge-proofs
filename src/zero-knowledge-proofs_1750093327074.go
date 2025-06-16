Okay, let's design and implement a Zero-Knowledge Proof (ZKP) system in Go for a specific, somewhat creative scenario: **Proving Knowledge of a Secret that Evaluates a Public Polynomial to a Specific Public Value**, framed as an "Attribute Token" verification system.

This system is *not* a full-fledged zk-SNARK or zk-STARK library. It's a custom, simplified Sigma-like protocol tailored to this polynomial evaluation problem. This allows us to implement the core ZKP concepts (Commitment, Challenge, Response, Fiat-Shamir) and related cryptographic primitives using Go's standard libraries (`crypto/elliptic`, `math/big`, `crypto/rand`, etc.) without directly duplicating the complex internal workings of major ZKP frameworks.

The "advanced concept" here is the use of polynomial evaluation within the ZKP statement and linking it to a verifiable attribute. The "creative/trendy" aspect is the specific application scenario.

**Disclaimer:** This implementation is for educational and conceptual purposes. The specific ZKP protocol used here (a simplified Sigma-like structure checking `P(z) == A + c*y`) is *not* a standard, universally secure proof for arbitrary polynomials over finite fields using only field arithmetic checks. Production-grade ZKP systems use more complex polynomial commitment schemes and verification checks often involving elliptic curve pairings or FRI. This code focuses on demonstrating the *structure* of a ZKP and its components.

---

**Outline and Function Summary:**

This Go package `zkpolyattr` implements a simplified Zero-Knowledge Proof system.

**Package:** `zkpolyattr`

**Concepts Demonstrated:**
*   Finite Field Arithmetic (using `math/big`)
*   Elliptic Curve Point Arithmetic (using `crypto/elliptic`)
*   Polynomial Evaluation over a Finite Field
*   Pedersen Commitment Scheme (as a building block)
*   Sigma Protocol Structure (Commitment, Challenge, Response)
*   Fiat-Shamir Transform (to make interactive protocol non-interactive)
*   Application: Proving Knowledge of a Secret `s` such that `P(s) = y`, where `P` and `y` are public. This is framed as verifying an "Attribute Token".

**Structure:**
1.  **Types:** Define structures for Scalars, Points, Polynomials, Public Parameters, Private Witness, and the Proof.
2.  **Constants & Helpers:** Initialize curve parameters, implement basic scalar and point operations.
3.  **Setup:** Function to generate public parameters.
4.  **Polynomial Operations:** Function for polynomial evaluation.
5.  **Commitment:** Function for Pedersen scalar commitment (demonstration/building block).
6.  **Fiat-Shamir:** Function to compute the challenge.
7.  **Application Logic (Attribute Token):** Simulate token creation.
8.  **ZKP Protocol:** Implement the Prover and Verifier logic, broken into phases.

**Function Summary (Total: 25+):**

*   **Type Converters/Wrappers (3):**
    *   `ScalarFromBigInt(*big.Int) Scalar`: Wrap *big.Int as Scalar.
    *   `ScalarToBigInt(Scalar) *big.Int`: Unwrap Scalar to *big.Int.
    *   `PointFromCoords(*big.Int, *big.Int) (Point, error)`: Create Point from coordinates.
*   **Scalar Arithmetic (5):**
    *   `ScalarAdd(Scalar, Scalar, *big.Int) Scalar`: Modular addition.
    *   `ScalarSub(Scalar, Scalar, *big.Int) Scalar`: Modular subtraction.
    *   `ScalarMul(Scalar, Scalar, *big.Int) Scalar`: Modular multiplication.
    *   `ScalarInverse(Scalar, *big.Int) (Scalar, error)`: Modular inverse.
    *   `ScalarNegate(Scalar, *big.Int) Scalar`: Modular negation.
*   **Point Arithmetic (2):**
    *   `PointAdd(Point, Point) Point`: Elliptic curve point addition.
    *   `PointScalarMul(Point, Scalar) Point`: Elliptic curve scalar multiplication.
*   **Randomness (1):**
    *   `GenerateRandomScalar(*big.Int) (Scalar, error)`: Securely generate a random scalar.
*   **Setup (1):**
    *   `SetupParameters() (*PublicParams, error)`: Generate public parameters (curve, field modulus, generators G, H).
*   **Polynomial Operations (1):**
    *   `PolynomialEval(Polynomial, Scalar, *big.Int) Scalar`: Evaluate polynomial `P(x)` at `x`.
*   **Commitment (1):**
    *   `CommitScalarPedersen(Scalar, Scalar, Point, Point) Point`: Compute Pedersen commitment `value*G + randomness*H`.
*   **Fiat-Shamir (1):**
    *   `ComputeChallenge(Scalar, Scalar, Polynomial, *PublicParams) Scalar`: Compute challenge `c` from hash of protocol elements.
*   **Application Simulation (1):**
    *   `CreateAttributeToken(Polynomial, Scalar, *PublicParams) (Scalar, *PrivateWitness)`: Simulate generating a witness `s` and corresponding public attribute value `y=P(s)`.
*   **Prover (5):**
    *   `ProveAttributeKnowledge_Phase1_CommitA(Polynomial, Scalar, *PublicParams) (Scalar, Scalar, error)`: Prover's first phase: Choose random `k`, compute `A=P(k)`. Returns `A` and `k`.
    *   `ProveAttributeKnowledge_Phase2_ComputeZ(Scalar, Scalar, Scalar, *PublicParams) Scalar`: Prover's second phase: Compute response `z = k + c*s`. Returns `z`.
    *   `ProveAttributeKnowledge(Polynomial, Scalar, Scalar, *PublicParams) (*Proof, error)`: Orchestrates prover phases, takes `s`, returns `Proof`.
    *   `NewPrivateWitness(Scalar) *PrivateWitness`: Constructor for private witness.
    *   `NewProof(Scalar, Scalar) *Proof`: Constructor for proof structure.
*   **Verifier (5):**
    *   `VerifyAttributeProof_Phase1_ComputeChallenge(Scalar, Scalar, Polynomial, *PublicParams) Scalar`: Verifier re-computes the challenge `c`.
    *   `VerifyAttributeProof_Phase2_CheckEquality(Scalar, Scalar, Scalar, Polynomial, *PublicParams) bool`: Verifier checks the core equation `P(z) == A + c*y`.
    *   `VerifyAttributeProof(Polynomial, Scalar, *Proof, *PublicParams) (bool, error)`: Orchestrates verifier phases, takes `Proof`, returns verification status.
    *   `NewPublicParameters(*big.Int, Point, Point) *PublicParams`: Constructor for public parameters.
    *   `CheckPointOnCurve(Point) bool`: Helper to check if a point is on the curve.

---

```golang
package zkpolyattr

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// --- Constants and Global Parameters ---

// We'll use P256 curve, it has a suitable prime order N for scalar field.
var curve = elliptic.P256()
var scalarModulus = curve.Params().N // The order of the base point, used as the scalar field modulus

// --- Type Definitions ---

// Scalar represents an element in the finite field (scalars for curve points).
type Scalar struct {
	// Using big.Int to handle large integers and modular arithmetic
	Value *big.Int
}

// Point represents a point on the elliptic curve.
type Point struct {
	X *big.Int
	Y *big.Int
}

// Polynomial represents a polynomial with Scalar coefficients.
// P(x) = Coeffs[0] + Coeffs[1]*x + Coeffs[2]*x^2 + ...
type Polynomial []Scalar

// PublicParams holds the system's public parameters.
type PublicParams struct {
	Curve         elliptic.Curve // The elliptic curve
	ScalarModulus *big.Int       // The order of the curve's base point (scalar field modulus)
	G             Point          // A base point on the curve
	H             Point          // Another base point, not a known multiple of G (for Pedersen)
}

// PrivateWitness holds the prover's secret information.
type PrivateWitness struct {
	S Scalar // The secret value the prover knows (e.g., the attribute token secret)
}

// Proof holds the data generated by the prover.
type Proof struct {
	A Scalar // Prover's commitment-like value (P(k))
	Z Scalar // Prover's response (k + c*s)
}

// --- Type Converters/Wrappers ---

// ScalarFromBigInt wraps a *big.Int into a Scalar.
func ScalarFromBigInt(val *big.Int) Scalar {
	return Scalar{Value: new(big.Int).Set(val)}
}

// ScalarToBigInt unwraps a Scalar to a *big.Int.
func ScalarToBigInt(s Scalar) *big.Int {
	return new(big.Int).Set(s.Value)
}

// PointFromCoords creates a Point from X and Y coordinates.
// Checks if the point is on the curve.
func PointFromCoords(x, y *big.Int) (Point, error) {
	p := Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
	if !curve.IsOnCurve(p.X, p.Y) {
		return Point{}, fmt.Errorf("point %v,%v is not on curve", x, y)
	}
	return p, nil
}

// CheckPointOnCurve checks if a given Point is on the curve.
func CheckPointOnCurve(p Point) bool {
	return curve.IsOnCurve(p.X, p.Y)
}

// --- Scalar Arithmetic (Modular arithmetic) ---

// ScalarAdd performs modular addition: (a + b) mod N.
func ScalarAdd(a, b Scalar, N *big.Int) Scalar {
	res := new(big.Int).Add(a.Value, b.Value)
	res.Mod(res, N)
	return ScalarFromBigInt(res)
}

// ScalarSub performs modular subtraction: (a - b) mod N.
func ScalarSub(a, b Scalar, N *big.Int) Scalar {
	res := new(big.Int).Sub(a.Value, b.Value)
	res.Mod(res, N)
	// Handle negative results of Mod for consistency
	if res.Sign() < 0 {
		res.Add(res, N)
	}
	return ScalarFromBigInt(res)
}

// ScalarMul performs modular multiplication: (a * b) mod N.
func ScalarMul(a, b Scalar, N *big.Int) Scalar {
	res := new(big.Int).Mul(a.Value, b.Value)
	res.Mod(res, N)
	return ScalarFromBigInt(res)
}

// ScalarInverse performs modular inverse: a^(-1) mod N.
func ScalarInverse(a Scalar, N *big.Int) (Scalar, error) {
	if a.Value.Sign() == 0 {
		return Scalar{}, fmt.Errorf("cannot invert zero scalar")
	}
	res := new(big.Int).ModInverse(a.Value, N)
	if res == nil {
		return Scalar{}, fmt.Errorf("no modular inverse for %v mod %v", a.Value, N)
	}
	return ScalarFromBigInt(res), nil
}

// ScalarNegate performs modular negation: -a mod N.
func ScalarNegate(a Scalar, N *big.Int) Scalar {
	res := new(big.Int).Neg(a.Value)
	res.Mod(res, N)
	// Handle negative results of Mod for consistency
	if res.Sign() < 0 {
		res.Add(res, N)
	}
	return ScalarFromBigInt(res)
}

// --- Point Arithmetic (Elliptic Curve) ---

// PointAdd performs elliptic curve point addition.
func PointAdd(p1, p2 Point) Point {
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return Point{X: x, Y: y}
}

// PointScalarMul performs elliptic curve scalar multiplication.
func PointScalarMul(p Point, s Scalar) Point {
	x, y := curve.ScalarMult(p.X, p.Y, s.Value.Bytes())
	return Point{X: x, Y: y}
}

// --- Randomness ---

// GenerateRandomScalar generates a cryptographically secure random scalar in [1, N-1].
func GenerateRandomScalar(N *big.Int) (Scalar, error) {
	// Generate a random big.Int in [0, N-1]
	k, err := rand.Int(rand.Reader, N)
	if err != nil {
		return Scalar{}, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	// Ensure scalar is not zero
	if k.Sign() == 0 {
		// This is highly unlikely but possible with tiny N or faulty RNG
		return GenerateRandomScalar(N) // Retry
	}
	return ScalarFromBigInt(k), nil
}

// --- Setup ---

// SetupParameters generates the public parameters for the system.
func SetupParameters() (*PublicParams, error) {
	G_x, G_y := curve.Params().Gx, curve.Params().Gy
	G := Point{X: G_x, Y: G_y}

	// Generate a random scalar h_scalar and derive H = h_scalar * G.
	// In a real system, H would be derived from a trusted setup or other process
	// to ensure the prover doesn't know h_scalar. For this example,
	// we generate it randomly and assume the setup is trusted.
	h_scalar_bi, err := rand.Int(rand.Reader, scalarModulus)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random h_scalar for H: %w", err)
	}
	H_x, H_y := curve.ScalarBaseMult(h_scalar_bi.Bytes())
	H := Point{X: H_x, Y: H_y}

	return &PublicParams{
		Curve:         curve,
		ScalarModulus: scalarModulus,
		G:             G,
		H:             H,
	}, nil
}

// --- Polynomial Operations ---

// PolynomialEval evaluates the polynomial P(x) at the given scalar x modulo N.
// P(x) = c_0 + c_1*x + c_2*x^2 + ...
func PolynomialEval(P Polynomial, x Scalar, N *big.Int) Scalar {
	if len(P) == 0 {
		return ScalarFromBigInt(big.NewInt(0)) // Evaluate to 0 for empty polynomial
	}

	result := ScalarFromBigInt(big.NewInt(0))
	x_power := ScalarFromBigInt(big.NewInt(1)) // x^0

	for _, coeff := range P {
		// term = coeff * x_power
		term := ScalarMul(coeff, x_power, N)
		// result = result + term
		result = ScalarAdd(result, term, N)

		// x_power = x_power * x for next iteration
		x_power = ScalarMul(x_power, x, N)
	}

	return result
}

// --- Commitment Scheme (Pedersen - as a building block) ---

// CommitScalarPedersen computes a Pedersen commitment C = value*G + randomness*H.
// Note: This function is provided as an example building block.
// The core ZKP in this system uses scalar evaluation and Fiat-Shamir,
// not point commitments in the final check equation.
func CommitScalarPedersen(value Scalar, randomness Scalar, G, H Point) Point {
	term1 := PointScalarMul(G, value)
	term2 := PointScalarMul(H, randomness)
	return PointAdd(term1, term2)
}

// --- Fiat-Shamir Transform ---

// ComputeChallenge calculates the challenge scalar 'c' using a cryptographic hash function.
// It serializes relevant protocol elements (A, y, P coefficients, public params)
// into a deterministic byte string before hashing.
func ComputeChallenge(A Scalar, y Scalar, P Polynomial, pubParams *PublicParams) Scalar {
	h := sha256.New()

	// Write elements deterministically to the hash
	writeScalar(h, A)
	writeScalar(h, y)
	writePolynomial(h, P)
	writePublicParams(h, pubParams)

	// Get hash output and convert to a scalar modulo N
	hashBytes := h.Sum(nil)
	c := new(big.Int).SetBytes(hashBytes)
	c.Mod(c, pubParams.ScalarModulus)

	return ScalarFromBigInt(c)
}

// Helper to write a Scalar to a hash interface.
func writeScalar(w io.Writer, s Scalar) {
	if s.Value != nil {
		w.Write(s.Value.Bytes())
	} else {
		// Write a zero scalar representation or a fixed placeholder
		w.Write(big.NewInt(0).Bytes())
	}
}

// Helper to write a Polynomial (coefficients) to a hash interface.
func writePolynomial(w io.Writer, P Polynomial) {
	for _, coeff := range P {
		writeScalar(w, coeff)
	}
}

// Helper to write PublicParams to a hash interface.
func writePublicParams(w io.Writer, pp *PublicParams) {
	if pp == nil {
		return
	}
	writeScalar(w, ScalarFromBigInt(pp.ScalarModulus))
	if pp.G.X != nil && pp.G.Y != nil {
		w.Write(pp.G.X.Bytes())
		w.Write(pp.G.Y.Bytes())
	}
	if pp.H.X != nil && pp.H.Y != nil {
		w.Write(pp.H.X.Bytes())
		w.Write(pp.H.Y.Bytes())
	}
	// Curve parameters could also be included for stricter determinism
}

// --- Application Simulation (Attribute Token) ---

// CreateAttributeToken simulates the creation of an attribute token.
// Given a public polynomial P and a secret 's', it computes the
// corresponding public value y = P(s). The user keeps 's' (private witness)
// and the system or a third party publishes P and y.
func CreateAttributeToken(P Polynomial, s Scalar, pubParams *PublicParams) (Scalar, *PrivateWitness) {
	// Compute y = P(s)
	y := PolynomialEval(P, s, pubParams.ScalarModulus)

	// s is the private witness
	witness := NewPrivateWitness(s)

	return y, witness
}

// --- ZKP Protocol (Simplified Sigma-like for P(s)=y) ---

// ProveAttributeKnowledge orchestrates the prover's steps to generate a ZKP.
// Statement: I know 's' such that P(s) = y.
// Witness: s
func ProveAttributeKnowledge(P Polynomial, y Scalar, witness *PrivateWitness, pubParams *PublicParams) (*Proof, error) {
	s := witness.S

	// Phase 1: Prover chooses random 'k' and computes A = P(k)
	k, err := ProveAttributeKnowledge_Phase1_CommitA(P, s, pubParams) // Note: k is also returned
	if err != nil {
		return nil, fmt.Errorf("prover phase 1 failed: %w", err)
	}
	A := PolynomialEval(P, k, pubParams.ScalarModulus) // Recompute A for clarity

	// Phase 2 (Fiat-Shamir): Prover computes challenge c = Hash(A, y, P, pubParams)
	c := VerifyAttributeProof_Phase1_ComputeChallenge(A, y, P, pubParams) // Prover computes challenge same way Verifier will

	// Phase 3: Prover computes response z = k + c*s
	z := ProveAttributeKnowledge_Phase2_ComputeZ(k, c, s, pubParams)

	// The proof consists of (A, z)
	return NewProof(A, z), nil
}

// ProveAttributeKnowledge_Phase1_CommitA is Prover Step 1: Choose random k, compute A = P(k).
// Returns A and the random k chosen.
func ProveAttributeKnowledge_Phase1_CommitA(P Polynomial, s Scalar, pubParams *PublicParams) (Scalar, Scalar, error) {
	// Prover chooses a random scalar k
	k, err := GenerateRandomScalar(pubParams.ScalarModulus)
	if err != nil {
		return Scalar{}, Scalar{}, fmt.Errorf("failed to generate random k: %w", err)
	}

	// Compute A = P(k)
	A := PolynomialEval(P, k, pubParams.ScalarModulus)

	return A, k, nil // Return A and k
}

// ProveAttributeKnowledge_Phase2_ComputeZ is Prover Step 3: Compute response z = k + c*s.
func ProveAttributeKnowledge_Phase2_ComputeZ(k Scalar, c Scalar, s Scalar, pubParams *PublicParams) Scalar {
	// Compute c * s
	cs := ScalarMul(c, s, pubParams.ScalarModulus)
	// Compute z = k + (c*s) mod N
	z := ScalarAdd(k, cs, pubParams.ScalarModulus)
	return z
}

// VerifyAttributeProof orchestrates the verifier's steps.
// Statement: I verify that the prover knows 's' such that P(s) = y, given Proof(A, z).
func VerifyAttributeProof(P Polynomial, y Scalar, proof *Proof, pubParams *PublicParams) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("proof is nil")
	}

	// Phase 1 (Fiat-Shamir): Verifier re-computes challenge c = Hash(A, y, P, pubParams)
	c := VerifyAttributeProof_Phase1_ComputeChallenge(proof.A, y, P, pubParams)

	// Phase 2: Verifier checks if P(z) == A + c*y
	isValid := VerifyAttributeProof_Phase2_CheckEquality(proof.A, proof.Z, y, P, pubParams)

	return isValid, nil
}

// VerifyAttributeProof_Phase1_ComputeChallenge is Verifier Step 1 (Fiat-Shamir): Recompute c.
func VerifyAttributeProof_Phase1_ComputeChallenge(A Scalar, y Scalar, P Polynomial, pubParams *PublicParams) Scalar {
	// Verifier computes challenge c = Hash(A, y, P, pubParams)
	// This is the same function as used by the prover for Fiat-Shamir transform.
	return ComputeChallenge(A, y, P, pubParams)
}

// VerifyAttributeProof_Phase2_CheckEquality is Verifier Step 2: Check if P(z) == A + c*y.
// This check is the core of this specific simplified protocol.
// Note: As mentioned in the disclaimer, this specific check is NOT a universally
// secure ZKP check for arbitrary polynomials using only field arithmetic.
// Secure systems involve more complex checks often over elliptic curve points/pairings.
func VerifyAttributeProof_Phase2_CheckEquality(A Scalar, z Scalar, y Scalar, P Polynomial, pubParams *PublicParams) bool {
	// Compute Left Hand Side: P(z) mod N
	lhs := PolynomialEval(P, z, pubParams.ScalarModulus)

	// Compute Right Hand Side: (A + c*y) mod N
	// First, re-compute challenge c (this step is logically part of Phase 1 but computed here for the check)
	c := VerifyAttributeProof_Phase1_ComputeChallenge(A, y, P, pubParams)
	cy := ScalarMul(c, y, pubParams.ScalarModulus)
	rhs := ScalarAdd(A, cy, pubParams.ScalarModulus)

	// Check if LHS == RHS
	return lhs.Value.Cmp(rhs.Value) == 0
}

// --- Constructors ---

// NewPrivateWitness creates a new PrivateWitness instance.
func NewPrivateWitness(s Scalar) *PrivateWitness {
	return &PrivateWitness{S: s}
}

// NewProof creates a new Proof instance.
func NewProof(A, z Scalar) *Proof {
	return &Proof{A: A, Z: z}
}

// NewPublicParameters creates a new PublicParameters instance.
func NewPublicParameters(N *big.Int, G, H Point) *PublicParams {
	return &PublicParams{
		Curve:         curve, // Use the package global curve
		ScalarModulus: new(big.Int).Set(N),
		G:             G,
		H:             H,
	}
}

// --- Helper functions for printing/debugging ---

func (s Scalar) String() string {
	if s.Value == nil {
		return "Scalar<nil>"
	}
	return fmt.Sprintf("Scalar<%v>", s.Value)
}

func (p Point) String() string {
	if p.X == nil || p.Y == nil {
		return "Point<nil>"
	}
	return fmt.Sprintf("Point<%v, %v>", p.X, p.Y)
}

func (P Polynomial) String() string {
	s := "Polynomial["
	for i, coeff := range P {
		s += coeff.String()
		if i < len(P)-1 {
			s += ", "
		}
	}
	s += "]"
	return s
}

func (pp *PublicParams) String() string {
	if pp == nil {
		return "PublicParams<nil>"
	}
	return fmt.Sprintf("PublicParams{Modulus:%v, G:%s, H:%s}", pp.ScalarModulus, pp.G, pp.H)
}

func (pw *PrivateWitness) String() string {
	if pw == nil {
		return "PrivateWitness<nil>"
	}
	return fmt.Sprintf("PrivateWitness{S:%s}", pw.S)
}

func (proof *Proof) String() string {
	if proof == nil {
		return "Proof<nil>"
	}
	return fmt.Sprintf("Proof{A:%s, Z:%s}", proof.A, proof.Z)
}

// PointToBytes serializes a Point to bytes. (Simple hex encoding for demonstration)
func PointToBytes(p Point) []byte {
	// Note: In production, use compressed/uncompressed point encoding standardized methods.
	if p.X == nil || p.Y == nil {
		return nil
	}
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	// Pad with leading zeros if necessary to ensure fixed length based on curve size
	paddedX := make([]byte, 32) // P256 coordinates are up to 32 bytes
	paddedY := make([]byte, 32)
	copy(paddedX[32-len(xBytes):], xBytes)
	copy(paddedY[32-len(yBytes):], yBytes)

	bytes := append(paddedX, paddedY...)
	return []byte(hex.EncodeToString(bytes)) // Hex encode for simple string representation
}

// BytesToPoint deserializes bytes back to a Point. (Simple hex decoding for demonstration)
func BytesToPoint(b []byte) (Point, error) {
	// Note: In production, use compressed/uncompressed point encoding standardized methods.
	hexStr := string(b)
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Point{}, fmt.Errorf("failed to decode hex: %w", err)
	}
	if len(bytes) != 64 { // 32 bytes for X, 32 for Y
		return Point{}, fmt.Errorf("invalid point byte length: %d", len(bytes))
	}
	x := new(big.Int).SetBytes(bytes[:32])
	y := new(big.Int).SetBytes(bytes[32:])

	p := Point{X: x, Y: y}
	if !CheckPointOnCurve(p) {
		return Point{}, fmt.Errorf("decoded point %s is not on curve", hexStr)
	}
	return p, nil
}

// ScalarToBytes serializes a Scalar to bytes. (Simple hex encoding for demonstration)
func ScalarToBytes(s Scalar) []byte {
	if s.Value == nil {
		return big.NewInt(0).Bytes() // Return zero bytes for nil scalar
	}
	return []byte(hex.EncodeToString(s.Value.Bytes())) // Hex encode
}

// BytesToScalar deserializes bytes back to a Scalar. (Simple hex decoding for demonstration)
func BytesToScalar(b []byte, N *big.Int) (Scalar, error) {
	hexStr := string(b)
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Scalar{}, fmt.Errorf("failed to decode hex: %w", err)
	}
	s := new(big.Int).SetBytes(bytes)
	// Ensure the scalar is within the field [0, N-1]
	s.Mod(s, N)
	return ScalarFromBigInt(s), nil
}

// ComputePolynomialValue is a helper/utility function to compute P(s)
// This is the same logic as PolynomialEval but maybe useful as a separate
// "public" function to show how the expected value 'y' is derived.
func ComputePolynomialValue(P Polynomial, s Scalar, pubParams *PublicParams) Scalar {
	return PolynomialEval(P, s, pubParams.ScalarModulus)
}
```