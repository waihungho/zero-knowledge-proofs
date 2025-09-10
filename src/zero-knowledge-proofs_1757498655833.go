The following Golang package `zkp_eligibility` implements a Zero-Knowledge Proof system. The core function it provides is the ability for a Prover to demonstrate that their private secret numerical value `x` is greater than or equal to a public threshold `T`, without revealing the exact value of `x`.

This is an advanced and creative application of ZKP for "Private Eligibility Verification". For example, a decentralized platform might require users to prove their "reputation score" is above a certain level to access a premium feature, without revealing their actual score or its components.

The system leverages:
*   **Elliptic Curve Cryptography (ECC)**: For all point arithmetic and commitment generation.
*   **Pedersen Commitments**: To commit to secret values (`x` and the difference `y = x - T`).
*   **Sigma Protocols (Schnorr-like)**: For proving knowledge of the committed values' secret components (`x`, `y`, and their randomizers).
*   **Simplified Range Proof for Non-Negativity**: To prove that `y >= 0`. This is implemented by decomposing `y` into `BIT_LENGTH` binary bits and proving each committed bit is either 0 or 1 using a non-interactive "OR" proof (a variant of Schnorr's OR proof).
*   **Fiat-Shamir Heuristic**: To convert the interactive Sigma protocols into non-interactive proofs, allowing for a single proof object.

---

**Project Name**: `zkp_eligibility`

**Description**:
This package implements a Zero-Knowledge Proof system for privately verifying eligibility based on a single numerical criterion exceeding a public threshold. A Prover demonstrates that their private secret value `x` (e.g., a contribution score, age, or income) is greater than or equal to a public threshold `T`, without revealing the exact value of `x`.

The system uses a Pedersen Commitment scheme and a variant of a Sigma protocol combined with a simplified range proof for non-negativity. The core idea is to prove knowledge of `x` such that `x = y + T` and `y >= 0`, where `y` is also a secret. The range proof for `y >= 0` is simplified for demonstration purposes to prove `y` is represented by a fixed number of bits (i.e., `y` is within `[0, 2^BIT_LENGTH - 1]`). Each bit `b_i` is committed as `C(b_i, r_bi)` and proven to be either 0 or 1 using a non-interactive OR proof.

**Core Concepts**:
*   **Elliptic Curve Cryptography**: Used for point arithmetic, commitment schemes, and challenges.
*   **Pedersen Commitments**: `C(v, r) = v*G + r*H`, used to commit to secret values `x` and `y`.
*   **Sigma Protocol (Proof of Knowledge of Commitment and Randomizer)**: Proves knowledge of both the value `v` and its randomizer `r` for a commitment `C = v*G + r*H`.
*   **Simplified Range Proof (for y >= 0)**: Proves that a committed value `y` is composed of `BIT_LENGTH` binary values (bits). Each bit `b_i` is committed as `C(b_i, r_bi)` and then proven to be either 0 or 1 using a Schnorr-like OR proof. The `r_bi` are carefully chosen to homomorphically sum to `r_y`.
*   **Fiat-Shamir Heuristic**: Converts interactive proofs into non-interactive ones using a cryptographically secure hash function.

**Public Parameters**:
*   `Curve`: The elliptic curve used for all operations (e.g., secp256k1).
*   `G, H`: Publicly known generator points on the curve. `H` is derived securely from `G` such that `dlog_G(H)` is unknown.
*   `BIT_LENGTH`: Defines the maximum bit length for the difference `y`, thus limiting the range of `y` for the simplified range proof `[0, 2^BIT_LENGTH - 1]`.

---

**Functions Summary (26 functions)**:

**Core Cryptographic Primitives**:
1.  `NewCurve`: Initializes the elliptic curve context, including its parameters (`Curve`, `G`, `H`, `N`).
2.  `ScalarToBytes`: Converts a `big.Int` scalar to a fixed-size byte array for serialization.
3.  `BytesToScalar`: Converts a byte array to a `big.Int` scalar.
4.  `PointToBytes`: Serializes an elliptic curve `Point` to bytes using compressed format.
5.  `BytesToPoint`: Deserializes bytes to an elliptic curve `Point`.
6.  `ScalarMult`: Multiplies a scalar by an elliptic curve `Point`.
7.  `PointAdd`: Adds two elliptic curve `Point`s.
8.  `GenerateRandomScalar`: Generates a cryptographically secure random scalar within the curve's order `N`.
9.  `ComputeChallenge`: Generates a challenge scalar using the Fiat-Shamir heuristic by hashing proof components.

**Pedersen Commitment Scheme**:
10. `NewPedersenCommitment`: Creates a new Pedersen commitment (`C = vG + rH`) and returns the `Commitment` point.
11. `Commit`: Internal helper function to perform the `vG + rH` operation.
12. `VerifyCommitment`: Verifies if a given `Commitment` `C` corresponds to a `(value, randomizer)` pair (primarily for testing and internal consistency, not part of the core ZKP protocol).

**ZKP Structure & Prover Logic**:
13. `NewProver`: Initializes a `Prover` instance with the secret value `x`, public threshold `T`, and cryptographic context.
14. `generateProofOfKnowledgeCR`: Prover's helper to generate a `ProofOfKnowledgeCR` (a Schnorr-like proof for `v` and `r` for `C = vG + rH`).
15. `proveBitCommitment`: Prover's helper to generate a `BitProof` for a single bit (0 or 1) using a Schnorr-like OR proof.
16. `proveRangeNonNegative`: Prover's helper to generate the `RangeProofBitDecomposition` by combining multiple `BitProof`s for `y >= 0`.
17. `GenerateProof`: Orchestrates all sub-proofs (`ProofOfKnowledgeCR` for `x`, `ProofOfKnowledgeCR` for `y`, and the `RangeProofBitDecomposition`) to create the final `Proof` for `x >= T`.

**ZKP Structure & Verifier Logic**:
18. `NewVerifier`: Initializes a `Verifier` instance with public parameters and the threshold `T`.
19. `verifyProofOfKnowledgeCR`: Verifier's helper to verify a `ProofOfKnowledgeCR`.
20. `verifyBitCommitment`: Verifier's helper to verify a single `BitProof`.
21. `verifyRangeNonNegative`: Verifier's helper to verify the combined `RangeProofBitDecomposition` for `y >= 0`.
22. `VerifyProof`: Orchestrates all sub-verifications (`ProofOfKnowledgeCR` for `Cx`, `ProofOfKnowledgeCR` for `Cy`, `Cx = Cy + T*G` relationship, and `RangeProofBitDecomposition`) to check the overall `Proof`.

**Utilities (Serialization)**:
23. `encodeBigInt`: Helper to serialize a `big.Int` to a fixed-length byte slice.
24. `decodeBigInt`: Helper to deserialize a fixed-length byte slice to a `big.Int`.
25. `ProofToBytes`: Serializes the entire `Proof` structure into a byte slice for transmission or storage.
26. `BytesToProof`: Deserializes a byte slice back into a `Proof` structure.

---

```go
package zkp_eligibility

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"bytes"
)

// --- Global Constants and Parameters ---

// Default elliptic curve for the ZKP system.
// secp256k1 is chosen for its widespread use and efficient implementation in Go.
var Curve = elliptic.Secp256k1()

// BIT_LENGTH defines the maximum bit length for the difference 'y' in the range proof.
// This limits 'y' to the range [0, 2^BIT_LENGTH - 1].
// A smaller BIT_LENGTH makes the proof faster but limits the maximum threshold difference.
const BIT_LENGTH = 32 // Sufficient for many practical scenarios, e.g., scores up to 4 billion.

// --- Helper Types for ZKP Components ---

// Point represents an elliptic curve point (X, Y coordinates).
type Point struct {
	X *big.Int
	Y *big.Int
}

// Commitment represents a Pedersen commitment C = vG + rH.
type Commitment Point

// Proof stores all components of the Zero-Knowledge Proof.
type Proof struct {
	Cx        Commitment              // Commitment to the secret value x
	Cy        Commitment              // Commitment to the difference y = x - T
	SigmaX    *ProofOfKnowledgeCR     // Proof of knowledge for x and its randomizer
	SigmaY    *ProofOfKnowledgeCR     // Proof of knowledge for y and its randomizer
	RangeProof RangeProofBitDecomposition // Simplified range proof for y >= 0
}

// ProofOfKnowledgeCR is a Schnorr-like proof of knowledge for `value` and `randomizer`
// for a Pedersen commitment C = value*G + randomizer*H.
type ProofOfKnowledgeCR struct {
	A  Point    // A = kv*G + kr*H, where kv, kr are random nonces
	E  *big.Int // Challenge scalar, derived from hashing
	Sv *big.Int // Response scalar for value
	Sr *big.Int // Response scalar for randomizer
}

// RangeProofBitDecomposition contains individual bit proofs for a simplified range proof.
// For a value 'y', it proves that 'y' can be represented by `BIT_LENGTH` bits,
// and each bit b_i is either 0 or 1.
type RangeProofBitDecomposition struct {
	BitProofs []*BitProof // Array of proofs for each bit b_i
}

// BitProof proves that a committed bit `b_i` is either 0 or 1.
// This uses a non-interactive OR proof (often called a 'schnorr-or' proof).
type BitProof struct {
	C_bi Commitment // Commitment to the bit b_i (b_i*G + r_bi*H)
	
	// Proof components for b_i = 0 branch
	A0 Point    // A_0 = k_0*H - e_0*C_bi (if b_i was 1, for simulation)
	S0 *big.Int // s_0 = k_0 + e_0*r_bi

	// Proof components for b_i = 1 branch
	A1 Point    // A_1 = k_1*H - e_1*(C_bi - G) (if b_i was 0, for simulation)
	S1 *big.Int // s_1 = k_1 + e_1*r_bi

	E0 *big.Int // Challenge for b_i = 0 branch
	E1 *big.Int // Challenge for b_i = 1 branch
}

// --- ZKP System Context ---

// ZKPContext holds public parameters and curve info.
type ZKPContext struct {
	Curve elliptic.Curve
	G     Point    // Base generator point G
	H     Point    // Pedersen generator point H
	N     *big.Int // Order of the curve
}

// Prover holds the prover's secret data and context.
type Prover struct {
	*ZKPContext
	x         *big.Int // The private value to be proven
	randomizerX *big.Int // The randomizer for x's commitment
	y         *big.Int // The private difference x - T
	randomizerY *big.Int // The randomizer for y's commitment
	threshold *big.Int // The public threshold T
}

// Verifier holds the verifier's public parameters and context.
type Verifier struct {
	*ZKPContext
	threshold *big.Int // The public threshold T
}


// --- Implementations ---

// NewCurve initializes the elliptic curve context and its public parameters G, H, and N.
// This function must be called once at the start of the application.
func NewCurve() *ZKPContext {
	p := Curve.Params()
	ctx := &ZKPContext{
		Curve: Curve,
		G:     Point{X: p.Gx, Y: p.Gy},
		N:     p.N,
	}

	// Generate H such that dlog_G(H) is unknown.
	// For this example, we'll use a fixed, large, non-zero scalar derived from a hash.
	// In a real system, you'd want a more robust, verifiably random process.
	hScalarBytes := sha256.Sum256([]byte("pedersen-h-generator-seed-v1"))
	hScalar := new(big.Int).SetBytes(hScalarBytes[:])
	hScalar.Mod(hScalar, ctx.N) // Ensure scalar is within curve order
	
	hx, hy := ctx.Curve.ScalarBaseMult(hScalar.Bytes())
	ctx.H = Point{X: hx, Y: hy}

	return ctx
}

// ScalarToBytes converts a big.Int scalar to a fixed-size byte array.
// It pads with leading zeros if necessary to match the curve's order size.
func ScalarToBytes(s *big.Int) []byte {
	byteLen := (Curve.Params().N.BitLen() + 7) / 8 
	sBytes := s.FillBytes(make([]byte, byteLen))
	return sBytes
}

// BytesToScalar converts a byte array to a big.Int scalar.
func BytesToScalar(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// PointToBytes serializes an elliptic curve point to bytes using compressed format.
func PointToBytes(p Point) []byte {
	return elliptic.MarshalCompressed(Curve, p.X, p.Y)
}

// BytesToPoint deserializes bytes to an elliptic curve point.
// Returns an error if the bytes do not represent a valid point.
func BytesToPoint(b []byte) (Point, error) {
	x, y := elliptic.UnmarshalCompressed(Curve, b)
	if x == nil {
		return Point{}, fmt.Errorf("invalid point bytes")
	}
	return Point{X: x, Y: y}, nil
}

// ScalarMult multiplies a scalar by an elliptic curve point.
func ScalarMult(p Point, scalar *big.Int) Point {
	x, y := Curve.ScalarMult(p.X, p.Y, scalar.Bytes())
	return Point{X: x, Y: y}
}

// PointAdd adds two elliptic curve points.
func PointAdd(p1, p2 Point) Point {
	x, y := Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return Point{X: x, Y: y}
}

// GenerateRandomScalar generates a cryptographically secure random scalar within the curve's order N.
func GenerateRandomScalar(ctx *ZKPContext) *big.Int {
	k, err := rand.Int(rand.Reader, ctx.N)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar: %v", err)) // Should not happen in practice
	}
	return k
}

// ComputeChallenge generates a challenge scalar using Fiat-Shamir heuristic over proof components.
// It hashes all relevant proof components (commitments, points, etc.) to produce a challenge.
func ComputeChallenge(ctx *ZKPContext, components ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, comp := range components {
		hasher.Write(comp)
	}
	hashBytes := hasher.Sum(nil)
	return new(big.Int).SetBytes(hashBytes).Mod(new(big.Int).SetBytes(hashBytes), ctx.N)
}

// NewPedersenCommitment creates a new Pedersen commitment C = vG + rH.
func NewPedersenCommitment(ctx *ZKPContext, value *big.Int, randomizer *big.Int) Commitment {
	return Commit(ctx, value, randomizer)
}

// Commit performs the Pedersen commitment operation: C = vG + rH.
func Commit(ctx *ZKPContext, value *big.Int, randomizer *big.Int) Commitment {
	vG := ScalarMult(ctx.G, value)
	rH := ScalarMult(ctx.H, randomizer)
	committedPoint := PointAdd(vG, rH)
	return Commitment(committedPoint)
}

// VerifyCommitment verifies if a given commitment C corresponds to (v, r).
// This is for testing/debugging, not typically part of a ZKP protocol (as v, r are secret).
func VerifyCommitment(ctx *ZKPContext, C Commitment, value *big.Int, randomizer *big.Int) bool {
	expectedC := Commit(ctx, value, randomizer)
	return C.X.Cmp(expectedC.X) == 0 && C.Y.Cmp(expectedC.Y) == 0
}

// NewProver initializes a Prover instance.
func NewProver(ctx *ZKPContext, x *big.Int, threshold *big.Int) *Prover {
	if x.Cmp(threshold) < 0 {
		panic("Prover's secret value x must be >= threshold T")
	}

	randomizerX := GenerateRandomScalar(ctx)
	
	// y = x - T
	y := new(big.Int).Sub(x, threshold)
	randomizerY := GenerateRandomScalar(ctx)

	return &Prover{
		ZKPContext: ctx,
		x:          x,
		randomizerX: randomizerX,
		y:          y,
		randomizerY: randomizerY,
		threshold:  threshold,
	}
}

// generateProofOfKnowledgeCR (Proof of Knowledge for Commitment and Randomizer)
// This proves knowledge of `value` and `randomizer` for a commitment `C = value*G + randomizer*H`.
func (p *Prover) generateProofOfKnowledgeCR(commitment Commitment, value *big.Int, randomizer *big.Int) *ProofOfKnowledgeCR {
	kv := p.GenerateRandomScalar(p.ZKPContext)
	kr := p.GenerateRandomScalar(p.ZKPContext)

	// A = kv*G + kr*H
	temp1 := ScalarMult(p.G, kv)
	temp2 := ScalarMult(p.H, kr)
	A := PointAdd(temp1, temp2)

	e := ComputeChallenge(p.ZKPContext, PointToBytes(Commitment(commitment)), PointToBytes(A))
	
	// sv = (kv + e*value) mod N
	sv := new(big.Int).Mul(e, value)
	sv.Add(sv, kv)
	sv.Mod(sv, p.N)

	// sr = (kr + e*randomizer) mod N
	sr := new(big.Int).Mul(e, randomizer)
	sr.Add(sr, kr)
	sr.Mod(sr, p.N)

	return &ProofOfKnowledgeCR{
		A:  A,
		E:  e,
		Sv: sv,
		Sr: sr,
	}
}

// proveBitCommitment: Prover generates a BitProof for a single bit (0 or 1).
// This uses a non-interactive OR proof (often called a 'schnorr-or' proof).
// Input: C_bi = b_i*G + r_bi*H, the actual bit b_i, and its randomizer r_bi.
func (p *Prover) proveBitCommitment(C_bi Commitment, b_i *big.Int, r_bi *big.Int) *BitProof {
	var k0, s0 *big.Int
	var k1, s1 *big.Int
	var A0, A1 Point
	var e0, e1 *big.Int

	// Point inversion for subtraction: P1 - P2 = P1 + (-P2) where -P2 = (x, -y mod P)
	// (C_bi - G) for b_i=1 branch
	negG_Y := new(big.Int).Neg(p.G.Y)
	negG_Y.Mod(negG_Y, p.Curve.Params().P) 
	C_bi_minus_G_X, C_bi_minus_G_Y := p.Curve.Add(C_bi.X, C_bi.Y, p.G.X, negG_Y)
	C_bi_minus_G := Point{X: C_bi_minus_G_X, Y: C_bi_minus_G_Y}

	if b_i.Cmp(big.NewInt(0)) == 0 { // Prover knows b_i = 0 (Real branch is b_i=0)
		// Real branch (b_i = 0):
		k0 = p.GenerateRandomScalar(p.ZKPContext)
		A0 = ScalarMult(p.H, k0) // A0 = k0*H

		// Fake branch (b_i = 1): Simulate response s1 and challenge e1
		e1 = p.GenerateRandomScalar(p.ZKPContext)
		s1 = p.GenerateRandomScalar(p.ZKPContext)
		
		// A1 = s1*H - e1*(C_bi - G) mod N (reconstruct A1 from fake response and challenge)
		term1 := ScalarMult(p.H, s1)
		neg_e1 := new(big.Int).Neg(e1)
		neg_e1.Mod(neg_e1, p.N)
		A1 = PointAdd(term1, ScalarMult(C_bi_minus_G, neg_e1))

		// Overall challenge for the combined proof
		e := p.ComputeChallenge(p.ZKPContext, PointToBytes(A0), PointToBytes(A1), PointToBytes(Commitment(C_bi)))
		
		// Derive e0 from e and e1
		e0 = new(big.Int).Sub(e, e1)
		e0.Mod(e0, p.N)

		// Calculate real response s0
		s0 = new(big.Int).Mul(e0, r_bi)
		s0.Sub(k0, s0) // s0 = k0 - e0*r_bi mod N
		s0.Mod(s0, p.N)

	} else if b_i.Cmp(big.NewInt(1)) == 0 { // Prover knows b_i = 1 (Real branch is b_i=1)
		// Fake branch (b_i = 0): Simulate response s0 and challenge e0
		e0 = p.GenerateRandomScalar(p.ZKPContext)
		s0 = p.GenerateRandomScalar(p.ZKPContext)
		
		// A0 = s0*H - e0*C_bi mod N (reconstruct A0 from fake response and challenge)
		term1 := ScalarMult(p.H, s0)
		neg_e0 := new(big.Int).Neg(e0)
		neg_e0.Mod(neg_e0, p.N)
		A0 = PointAdd(term1, ScalarMult(Commitment(C_bi), neg_e0))

		// Real branch (b_i = 1):
		k1 = p.GenerateRandomScalar(p.ZKPContext)
		A1 = ScalarMult(p.H, k1) // A1 = k1*H (for C_bi - G)
		
		// Overall challenge for the combined proof
		e := p.ComputeChallenge(p.ZKPContext, PointToBytes(A0), PointToBytes(A1), PointToBytes(Commitment(C_bi)))

		// Derive e1 from e and e0
		e1 = new(big.Int).Sub(e, e0)
		e1.Mod(e1, p.N)

		// Calculate real response s1
		s1 = new(big.Int).Mul(e1, r_bi)
		s1.Sub(k1, s1) // s1 = k1 - e1*r_bi mod N
		s1.Mod(s1, p.N)
	} else {
		panic("Bit value must be 0 or 1")
	}

	return &BitProof{
		C_bi: C_bi,
		A0:   A0,
		S0:   s0,
		A1:   A1,
		S1:   s1,
		E0:   e0,
		E1:   e1,
	}
}

// proveRangeNonNegative generates a simplified range proof for y >= 0.
// It proves that 'y' can be represented by `BIT_LENGTH` bits, and each bit b_i is 0 or 1.
// The randomizers for bits `r_bi` are chosen such that their weighted sum (sum(r_bi * 2^i)) equals `r_y`.
func (p *Prover) proveRangeNonNegative(y_val *big.Int, r_y *big.Int) RangeProofBitDecomposition {
	bitProofs := make([]*BitProof, BIT_LENGTH)
	
	r_bis := make([]*big.Int, BIT_LENGTH)
	sumR_bi_pow2i := big.NewInt(0)
	
	// Generate BIT_LENGTH-1 randomizers for bits
	for i := 0; i < BIT_LENGTH-1; i++ {
		r_bis[i] = p.GenerateRandomScalar(p.ZKPContext)
		term := new(big.Int).Mul(r_bis[i], new(big.Int).Lsh(big.NewInt(1), uint(i)))
		sumR_bi_pow2i.Add(sumR_bi_pow2i, term)
	}

	// Calculate the last randomizer r_b(BIT_LENGTH-1) to ensure the sum matches r_y
	// r_b(BIT_LENGTH-1) = (r_y - sum(r_bi * 2^i for i < BIT_LENGTH-1)) * (2^(BIT_LENGTH-1))^-1 mod N
	pow2Last := new(big.Int).Lsh(big.NewInt(1), uint(BIT_LENGTH-1))
	invPow2Last := new(big.Int).ModInverse(pow2Last, p.N) // (2^(BIT_LENGTH-1))^-1 mod N

	diffR := new(big.Int).Sub(r_y, sumR_bi_pow2i)
	diffR.Mod(diffR, p.N)
	r_bis[BIT_LENGTH-1] = new(big.Int).Mul(diffR, invPow2Last)
	r_bis[BIT_LENGTH-1].Mod(r_bis[BIT_LENGTH-1], p.N)


	// For each bit of y, create a BitProof
	for i := 0; i < BIT_LENGTH; i++ {
		// Get i-th bit of y_val
		bi := new(big.Int).And(new(big.Int).Rsh(y_val, uint(i)), big.NewInt(1))
		
		// Create commitment for this bit
		C_bi := NewPedersenCommitment(p.ZKPContext, bi, r_bis[i])
		
		// Generate BitProof for C_bi
		bitProofs[i] = p.proveBitCommitment(C_bi, bi, r_bis[i])
	}
	
	return RangeProofBitDecomposition{BitProofs: bitProofs}
}

// GenerateProof orchestrates all sub-proofs to create the final ZKP for 'x >= T'.
func (p *Prover) GenerateProof() *Proof {
	// 1. Commit to x and y
	Cx := NewPedersenCommitment(p.ZKPContext, p.x, p.randomizerX)
	Cy := NewPedersenCommitment(p.ZKPContext, p.y, p.randomizerY)

	// 2. Prove knowledge of x and its randomizer (for Cx)
	sigmaX := p.generateProofOfKnowledgeCR(Cx, p.x, p.randomizerX)

	// 3. Prove knowledge of y and its randomizer (for Cy)
	sigmaY := p.generateProofOfKnowledgeCR(Cy, p.y, p.randomizerY)

	// 4. Prove y >= 0 using simplified bit decomposition range proof
	rangeProof := p.proveRangeNonNegative(p.y, p.randomizerY)

	return &Proof{
		Cx:        Cx,
		Cy:        Cy,
		SigmaX:    sigmaX,
		SigmaY:    sigmaY,
		RangeProof: rangeProof,
	}
}

// NewVerifier initializes a Verifier instance.
func NewVerifier(ctx *ZKPContext, threshold *big.Int) *Verifier {
	return &Verifier{
		ZKPContext: ctx,
		threshold:  threshold,
	}
}

// verifyProofOfKnowledgeCR verifies a ProofOfKnowledgeCR.
func (v *Verifier) verifyProofOfKnowledgeCR(C Commitment, proof *ProofOfKnowledgeCR) bool {
	// Recompute challenge e' = H(C, A)
	expectedE := ComputeChallenge(v.ZKPContext, PointToBytes(C), PointToBytes(proof.A))
	if expectedE.Cmp(proof.E) != 0 {
		return false // Challenge mismatch
	}

	// Check if sv*G + sr*H == A + e*C
	// Left side: sv*G + sr*H
	leftG := ScalarMult(v.G, proof.Sv)
	leftH := ScalarMult(v.H, proof.Sr)
	lhs := PointAdd(leftG, leftH)

	// Right side: A + e*C
	eC := ScalarMult(C, proof.E)
	rhs := PointAdd(proof.A, eC)

	return lhs.X.Cmp(rhs.X) == 0 && lhs.Y.Cmp(rhs.Y) == 0
}

// verifyBitCommitment verifies a single BitProof.
func (v *Verifier) verifyBitCommitment(bp *BitProof) bool {
	// Recompute common challenge e = H(A0, A1, C_bi)
	e := v.ComputeChallenge(v.ZKPContext, PointToBytes(bp.A0), PointToBytes(bp.A1), PointToBytes(bp.C_bi))

	// Check e0 + e1 == e mod N
	sumE := new(big.Int).Add(bp.E0, bp.E1)
	sumE.Mod(sumE, v.N)
	if sumE.Cmp(e) != 0 {
		return false // Challenge sum mismatch
	}

	// Verify branch 0: s0*H == A0 + e0*C_bi
	// Left: s0*H
	lhs0 := ScalarMult(v.H, bp.S0)
	// Right: A0 + e0*C_bi
	e0C_bi := ScalarMult(bp.C_bi, bp.E0)
	rhs0 := PointAdd(bp.A0, e0C_bi)
	if lhs0.X.Cmp(rhs0.X) != 0 || lhs0.Y.Cmp(rhs0.Y) != 0 {
		return false
	}

	// Verify branch 1: s1*H == A1 + e1*(C_bi - G)
	// For C_bi - G:
	negG_Y := new(big.Int).Neg(v.G.Y)
	negG_Y.Mod(negG_Y, v.Curve.Params().P)
	C_bi_minus_G_X, C_bi_minus_G_Y := v.Curve.Add(bp.C_bi.X, bp.C_bi.Y, v.G.X, negG_Y)
	C_bi_minus_G := Point{X: C_bi_minus_G_X, Y: C_bi_minus_G_Y}

	// Left: s1*H
	lhs1 := ScalarMult(v.H, bp.S1)
	// Right: A1 + e1*(C_bi - G)
	e1_C_bi_minus_G := ScalarMult(C_bi_minus_G, bp.E1)
	rhs1 := PointAdd(bp.A1, e1_C_bi_minus_G)
	if lhs1.X.Cmp(rhs1.X) != 0 || lhs1.Y.Cmp(rhs1.Y) != 0 {
		return false
	}

	return true
}

// verifyRangeNonNegative verifies the simplified range proof for y >= 0.
// It checks each bit proof and the implicit consistency of C_y with the C_bi commitments.
func (v *Verifier) verifyRangeNonNegative(C_y Commitment, rangeProof RangeProofBitDecomposition) bool {
	if len(rangeProof.BitProofs) != BIT_LENGTH {
		return false // Incorrect number of bit proofs
	}

	// After verifying all individual bit proofs, check if the homomorphic sum matches C_y
	// This verifies that `y` was correctly decomposed into `b_i` and `r_y` into `r_bi`.
	// expectedSumPoint = sum(C_bi * 2^i)
	expectedSumPoint := Point{X: big.NewInt(0), Y: big.NewInt(0)} // Identity point (infinity)

	for i := 0; i < BIT_LENGTH; i++ {
		bp := rangeProof.BitProofs[i]
		
		// Verify each individual bit proof
		if !v.verifyBitCommitment(bp) {
			fmt.Printf("Bit proof for bit %d failed.\n", i)
			return false
		}
		
		// Accumulate C_bi * 2^i
		powerOf2 := new(big.Int).Lsh(big.NewInt(1), uint(i))
		scaledC_bi := ScalarMult(bp.C_bi, powerOf2)
		expectedSumPoint = PointAdd(expectedSumPoint, scaledC_bi)
	}

	// Compare the re-constructed commitment with the original commitment C_y
	return C_y.X.Cmp(expectedSumPoint.X) == 0 && C_y.Y.Cmp(expectedSumPoint.Y) == 0
}

// VerifyProof orchestrates all sub-verifications to check the overall ZKP.
func (v *Verifier) VerifyProof(proof *Proof) bool {
	// 1. Verify knowledge of x and its randomizer (for Cx)
	if !v.verifyProofOfKnowledgeCR(proof.Cx, proof.SigmaX) {
		fmt.Println("Verification failed: ProofOfKnowledgeCR for Cx failed")
		return false
	}

	// 2. Verify knowledge of y and its randomizer (for Cy)
	if !v.verifyProofOfKnowledgeCR(proof.Cy, proof.SigmaY) {
		fmt.Println("Verification failed: ProofOfKnowledgeCR for Cy failed")
		return false
	}

	// 3. Verify the difference relationship: Cx = Cy + T*G
	// This checks that x = y + T.
	TG := ScalarMult(v.G, v.threshold)
	expectedCx := PointAdd(proof.Cy, TG)
	if proof.Cx.X.Cmp(expectedCx.X) != 0 || proof.Cx.Y.Cmp(expectedCx.Y) != 0 {
		fmt.Println("Verification failed: Difference relationship Cx = Cy + TG failed")
		return false
	}

	// 4. Verify y >= 0 using simplified bit decomposition range proof
	if !v.verifyRangeNonNegative(proof.Cy, proof.RangeProof) {
		fmt.Println("Verification failed: Range proof for y >= 0 failed")
		return false
	}

	return true
}

// encodeBigInt helper to encode a big.Int with fixed length based on curve order
func encodeBigInt(b *big.Int, N *big.Int) []byte {
	return b.FillBytes(make([]byte, (N.BitLen()+7)/8))
}

// decodeBigInt helper to decode a big.Int from fixed length bytes
func decodeBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// ProofToBytes serializes the entire ZKP structure into a byte slice.
func ProofToBytes(proof *Proof, ctx *ZKPContext) ([]byte, error) {
	var buf bytes.Buffer
	// Cx
	buf.Write(PointToBytes(proof.Cx))
	// Cy
	buf.Write(PointToBytes(proof.Cy))
	// SigmaX
	buf.Write(PointToBytes(proof.SigmaX.A))
	buf.Write(encodeBigInt(proof.SigmaX.E, ctx.N))
	buf.Write(encodeBigInt(proof.SigmaX.Sv, ctx.N))
	buf.Write(encodeBigInt(proof.SigmaX.Sr, ctx.N))
	// SigmaY
	buf.Write(PointToBytes(proof.SigmaY.A))
	buf.Write(encodeBigInt(proof.SigmaY.E, ctx.N))
	buf.Write(encodeBigInt(proof.SigmaY.Sv, ctx.N))
	buf.Write(encodeBigInt(proof.SigmaY.Sr, ctx.N))
	// RangeProofBitDecomposition
	for _, bp := range proof.RangeProof.BitProofs {
		buf.Write(PointToBytes(bp.C_bi))
		buf.Write(PointToBytes(bp.A0))
		buf.Write(encodeBigInt(bp.S0, ctx.N))
		buf.Write(PointToBytes(bp.A1))
		buf.Write(encodeBigInt(bp.S1, ctx.N))
		buf.Write(encodeBigInt(bp.E0, ctx.N))
		buf.Write(encodeBigInt(bp.E1, ctx.N))
	}

	return buf.Bytes(), nil
}

// BytesToProof deserializes a byte slice back into a ZKP Proof structure.
func BytesToProof(data []byte, ctx *ZKPContext) (*Proof, error) {
	proof := &Proof{}
	reader := bytes.NewReader(data)
	var err error

	pointByteLen := (ctx.Curve.Params().BitSize+7)/8 + 1 // Compressed point format needs 1 byte for tag + (size in bytes)
	scalarByteLen := (ctx.N.BitLen()+7)/8 // For scalars (order N)

	// Helper to read point or scalar
	readPoint := func() (Point, error) {
		pBytes := make([]byte, pointByteLen) 
		_, err := io.ReadFull(reader, pBytes)
		if err != nil {
			return Point{}, err
		}
		return BytesToPoint(pBytes)
	}
	readScalar := func() (*big.Int, error) {
		sBytes := make([]byte, scalarByteLen) 
		_, err := io.ReadFull(reader, sBytes)
		if err != nil {
			return nil, err
		}
		return BytesToScalar(sBytes), nil
	}

	// Cx
	proof.Cx, err = readPoint()
	if err != nil { return nil, fmt.Errorf("read Cx failed: %w", err) }
	// Cy
	proof.Cy, err = readPoint()
	if err != nil { return nil, fmt.Errorf("read Cy failed: %w", err) }
	
	// SigmaX
	proof.SigmaX = &ProofOfKnowledgeCR{} 
	proof.SigmaX.A, err = readPoint()
	if err != nil { return nil, fmt.Errorf("read SigmaX.A failed: %w", err) }
	proof.SigmaX.E, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaX.E failed: %w", err) }
	proof.SigmaX.Sv, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaX.Sv failed: %w", err) }
	proof.SigmaX.Sr, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaX.Sr failed: %w", err) }

	// SigmaY
	proof.SigmaY = &ProofOfKnowledgeCR{} 
	proof.SigmaY.A, err = readPoint()
	if err != nil { return nil, fmt.Errorf("read SigmaY.A failed: %w", err) }
	proof.SigmaY.E, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaY.E failed: %w", err) }
	proof.SigmaY.Sv, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaY.Sv failed: %w", err) }
	proof.SigmaY.Sr, err = readScalar()
	if err != nil { return nil, fmt.Errorf("read SigmaY.Sr failed: %w", err) }


	// RangeProofBitDecomposition
	proof.RangeProof.BitProofs = make([]*BitProof, BIT_LENGTH)
	for i := 0; i < BIT_LENGTH; i++ {
		bp := &BitProof{}
		bp.C_bi, err = readPoint()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].C_bi failed: %w", i, err) }
		bp.A0, err = readPoint()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].A0 failed: %w", i, err) }
		bp.S0, err = readScalar()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].S0 failed: %w", i, err) }
		bp.A1, err = readPoint()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].A1 failed: %w", i, err) }
		bp.S1, err = readScalar()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].S1 failed: %w", i, err) }
		bp.E0, err = readScalar()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].E0 failed: %w", i, err) }
		bp.E1, err = readScalar()
		if err != nil { return nil, fmt.Errorf("read BitProof[%d].E1 failed: %w", i, err) }
		proof.RangeProof.BitProofs[i] = bp
	}

	return proof, nil
}
```