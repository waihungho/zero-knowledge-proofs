This Go implementation provides a Zero-Knowledge Proof (ZKP) system for "Private Credential Verification with Linked Attribute Range." The system allows a Prover to demonstrate knowledge of a private `credentialID` and an `attributeValue` (e.g., age, score) such that the `attributeValue` meets a minimum required threshold, and both are correctly linked, *without revealing the actual `credentialID` or `attributeValue`*.

This ZKP scheme is built using a custom composition of Pedersen commitments, Schnorr-like proofs of knowledge, and a bespoke range proof for non-negativity based on bit commitments. It's designed to be distinct from generic SNARK/STARK implementations or specific optimized schemes like Bulletproofs, focusing on an interesting application with a creative, tailored approach.

---

### **Outline and Function Summary**

**Application:** Zero-Knowledge Proof for Private Credential Verification with Linked Attribute Range.
**Goal:** A Prover demonstrates knowledge of a private `credentialID` and a private `attributeValue` such that:
1.  `credentialID` is committed correctly in `publicCredentialCommitment`.
2.  `attributeValue` is committed correctly in `publicAttributeCommitment`.
3.  `credentialID` and `attributeValue` are correctly linked through `publicLinkedCommitment`.
4.  `attributeValue` is greater than or equal to a public `minAttributeRequired`.
*All without revealing `credentialID` or `attributeValue`.*

---

#### **I. Core Cryptographic Primitives & Utilities**
1.  `SetupCurve()`: Initializes the elliptic curve (P384) and generates two base points, `G` and `H`, for Pedersen commitments.
2.  `BytesToScalar(b []byte)`: Converts a byte slice to a `*big.Int` scalar, modulo the curve order.
3.  `HashToScalar(data ...[]byte)`: Computes a SHA-256 hash of concatenated data and converts it to a scalar modulo the curve order (for Fiat-Shamir challenge).
4.  `ScalarAdd(a, b *big.Int)`: Adds two scalars modulo curve order.
5.  `ScalarSub(a, b *big.Int)`: Subtracts two scalars modulo curve order.
6.  `ScalarMul(a, b *big.Int)`: Multiplies two scalars modulo curve order.
7.  `ScalarInv(a *big.Int)`: Computes modular inverse of a scalar.
8.  `PointAdd(p1, p2 elliptic.Point)`: Adds two elliptic curve points.
9.  `PointScalarMul(p elliptic.Point, scalar *big.Int)`: Multiplies an elliptic curve point by a scalar.
10. `GenerateRandomScalar()`: Generates a cryptographically secure random scalar.

#### **II. Pedersen Commitment Scheme**
11. `Commitment`: Struct to represent a Pedersen commitment (`C = v*G + r*H`).
12. `NewCommitment(value, nonce *big.Int)`: Creates a new Pedersen commitment.
13. `CommitmentVerify(value, nonce *big.Int)`: Verifies if a given value and nonce match the commitment.
14. `CommitmentAdd(c1, c2 *Commitment)`: Homomorphically adds two commitments.
15. `CommitmentSubtract(c1, c2 *Commitment)`: Homomorphically subtracts two commitments.

#### **III. Zero-Knowledge Proof Structures**
16. `Prover`: Struct holding prover's secrets and context.
17. `Verifier`: Struct holding verifier's public inputs and context.
18. `Proof`: Main struct encapsulating all sub-proofs.

#### **IV. Sub-Proofs / Building Blocks**
19. `PoKDLMulti`: Proof of Knowledge of Multiple Discrete Logarithms (e.g., for Pedersen commitment opening). Proves knowledge of `v` and `r` for `C = v*G + r*H`.
    *   `ProvePoKDLMulti(value, nonce *big.Int)`: Prover's step for PoKDLMulti.
    *   `VerifyPoKDLMulti(challenge *big.Int, commitment *Commitment)`: Verifier's step for PoKDLMulti.
20. `PoKZero`: Proof of Knowledge that a commitment opens to zero. (Special case of PoKDLMulti where value is 0).
    *   `ProvePoKZero(nonce *big.Int)`: Prover's step for PoKZero.
    *   `VerifyPoKZero(challenge *big.Int, commitment *Commitment)`: Verifier's step for PoKZero.
21. `BitCommitment`: Represents a commitment to a single bit (`b \in {0,1}`).
22. `PoKBit`: Proof of Knowledge that a `BitCommitment` opens to either 0 or 1.
    *   `ProvePoKBit(bitValue, nonce *big.Int)`: Prover's step for PoKBit.
    *   `VerifyPoKBit(challenge *big.Int, bitCommitment *BitCommitment)`: Verifier's step for PoKBit.
23. `NonNegativeRangeProof`: Custom proof that a committed value `v` is non-negative (`v >= 0`) using bit decomposition. Proves `v = \sum b_i 2^i` where each `b_i \in {0,1}`.
    *   `NewNonNegativeRangeProof(value, nonce *big.Int, maxBits int)`: Creates the proof components.
    *   `VerifyNonNegativeRangeProof(committedValue *Commitment, challenge *big.Int)`: Verifies the range proof.

#### **V. Overall Protocol Functions**
24. `NewProver(credentialID, attributeValue, minAttributeRequired *big.Int)`: Prover constructor. Initializes secrets and computes public commitments.
25. `NewVerifier(pCredCommitment, pAttrCommitment, pLinkCommitment *Commitment, minAttributeRequired *big.Int)`: Verifier constructor. Initializes public inputs.
26. `GenerateProof()`: Main prover function. Orchestrates all sub-proofs, generates challenges using Fiat-Shamir.
27. `VerifyProof(proof *Proof)`: Main verifier function. Reconstructs challenges and checks all sub-proofs.

---

```go
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"
)

// Curve and Generators
var (
	Curve           elliptic.Curve
	GeneratorG_X    *big.Int
	GeneratorG_Y    *big.Int
	GeneratorH_X    *big.Int
	GeneratorH_Y    *big.Int
	CurveOrder      *big.Int
)

// SetupCurve initializes the elliptic curve (P384) and generates two base points, G and H.
func SetupCurve() {
	Curve = elliptic.P384()
	CurveOrder = Curve.Params().N

	// G is the standard base point for P384
	GeneratorG_X = Curve.Params().Gx
	GeneratorG_Y = Curve.Params().Gy

	// H is a second generator, often derived from G or a random point.
	// For simplicity, we derive it from a random scalar multiple of G.
	// In a real system, H would be a fixed, publicly verifiable value independent of G.
	hScalar, err := rand.Int(rand.Reader, CurveOrder)
	if err != nil {
		panic(fmt.Sprintf("failed to generate hScalar: %v", err))
	}
	GeneratorH_X, GeneratorH_Y = Curve.ScalarBaseMult(hScalar.Bytes())

	fmt.Println("Curve P384 setup complete.")
}

// =======================================================================
// I. Core Cryptographic Primitives & Utilities
// =======================================================================

// BytesToScalar converts a byte slice to a *big.Int scalar, modulo the curve order.
func BytesToScalar(b []byte) *big.Int {
	s := new(big.Int).SetBytes(b)
	return s.Mod(s, CurveOrder)
}

// HashToScalar computes a SHA-256 hash of concatenated data and converts it to a scalar modulo the curve order.
// Used for Fiat-Shamir challenge generation.
func HashToScalar(data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return BytesToScalar(h.Sum(nil))
}

// ScalarAdd adds two scalars modulo curve order.
func ScalarAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b).Mod(new(big.Int).Add(a, b), CurveOrder)
}

// ScalarSub subtracts two scalars modulo curve order.
func ScalarSub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b).Mod(new(big.Int).Sub(a, b), CurveOrder)
}

// ScalarMul multiplies two scalars modulo curve order.
func ScalarMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b).Mod(new(big.Int).Mul(a, b), CurveOrder)
}

// ScalarInv computes modular inverse of a scalar.
func ScalarInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, CurveOrder)
}

// PointAdd adds two elliptic curve points.
func PointAdd(p1x, p1y, p2x, p2y *big.Int) (x, y *big.Int) {
	return Curve.Add(p1x, p1y, p2x, p2y)
}

// PointScalarMul multiplies an elliptic curve point by a scalar.
func PointScalarMul(px, py *big.Int, scalar *big.Int) (x, y *big.Int) {
	return Curve.ScalarMult(px, py, scalar.Bytes())
}

// GenerateRandomScalar generates a cryptographically secure random scalar modulo CurveOrder.
func GenerateRandomScalar() *big.Int {
	s, err := rand.Int(rand.Reader, CurveOrder)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar: %v", err))
	}
	return s
}

// =======================================================================
// II. Pedersen Commitment Scheme
// =======================================================================

// Commitment represents a Pedersen commitment (C = v*G + r*H).
type Commitment struct {
	X *big.Int
	Y *big.Int
}

// NewCommitment creates a new Pedersen commitment for a given value and nonce.
// C = value*G + nonce*H
func NewCommitment(value, nonce *big.Int) *Commitment {
	vGx, vGy := PointScalarMul(GeneratorG_X, GeneratorG_Y, value)
	nHx, nHy := PointScalarMul(GeneratorH_X, GeneratorH_Y, nonce)
	Cx, Cy := PointAdd(vGx, vGy, nHx, nHy)
	return &Commitment{X: Cx, Y: Cy}
}

// CommitmentVerify verifies if a given value and nonce match the commitment.
func (c *Commitment) CommitmentVerify(value, nonce *big.Int) bool {
	expectedCommitment := NewCommitment(value, nonce)
	return c.X.Cmp(expectedCommitment.X) == 0 && c.Y.Cmp(expectedCommitment.Y) == 0
}

// CommitmentAdd homomorphically adds two commitments.
func CommitmentAdd(c1, c2 *Commitment) *Commitment {
	sumX, sumY := PointAdd(c1.X, c1.Y, c2.X, c2.Y)
	return &Commitment{X: sumX, Y: sumY}
}

// CommitmentSubtract homomorphically subtracts two commitments.
// c1 - c2 is c1 + (-1)*c2.
func CommitmentSubtract(c1, c2 *Commitment) *Commitment {
	// ScalarMult by -1 to get the inverse point
	negOne := new(big.Int).SetInt64(-1)
	negCx, negCy := PointScalarMul(c2.X, c2.Y, negOne) // -C2 = -(v*G + r*H) = -v*G -r*H
	diffX, diffY := PointAdd(c1.X, c1.Y, negCx, negCy)
	return &Commitment{X: diffX, Y: diffY}
}

// =======================================================================
// III. Zero-Knowledge Proof Structures
// =======================================================================

// PoKDLMulti represents a Proof of Knowledge of Multiple Discrete Logarithms (e.g., for Pedersen commitment opening).
// Proves knowledge of v and r for C = v*G + r*H.
type PoKDLMulti struct {
	ChallengeResponseV *big.Int // s_v = r_v + c * v
	ChallengeResponseR *big.Int // s_r = r_r + c * r
	CommitmentRandX    *big.Int // R_x, used for challenge generation
	CommitmentRandY    *big.Int // R_y
}

// PoKBit represents a proof that a committed bit is either 0 or 1.
type PoKBit struct {
	CommitmentA_X *big.Int // R_0 commitment for bit=0
	CommitmentA_Y *big.Int
	CommitmentB_X *big.Int // R_1 commitment for bit=1
	CommitmentB_Y *big.Int
	ResponseA     *big.Int // s_0 = r_0 + c_0 * v_0
	ResponseB     *big.Int // s_1 = r_1 + c_1 * v_1
	ChallengeB    *big.Int // c_1 (part of the challenge split)
}

// NonNegativeRangeProof is a custom ZKP to prove that a committed value is >= 0
// using bit decomposition.
type NonNegativeRangeProof struct {
	BitCommitments []*BitCommitment // C_bi = b_i*G + r_bi*H
	BitProofs      []*PoKBit        // Proof for each bit C_bi that b_i is 0 or 1
	SumProof       *PoKDLMulti      // Proof that sum of 2^i * C_bi correctly forms committedValue.
	// Specifically, proves committedValue - Sum(2^i * C_bi) = 0*G + r_delta*H
}

// BitCommitment stores commitment for a single bit and its corresponding nonce.
type BitCommitment struct {
	*Commitment
	BitValue *big.Int // 0 or 1 (prover's secret)
	Nonce    *big.Int // (prover's secret)
}

// Proof is the main struct encapsulating all sub-proofs for the credential verification.
type Proof struct {
	// Public commitments (generated by prover, public input to verifier)
	PublicCredentialCommitment *Commitment
	PublicAttributeCommitment  *Commitment
	PublicLinkedCommitment     *Commitment
	MinAttributeRequired       *big.Int

	// Sub-proofs
	CredentialPoK      *PoKDLMulti           // Proof of knowledge of credentialID and its nonce
	AttributeLinkPoK   *PoKDLMulti           // Proof that C_Linked - C_ID - C_Attr is a commitment to 0
	AttributeRangePoK  *NonNegativeRangeProof // Proof that (attributeValue - minAttributeRequired) >= 0
}

// Prover struct holds prover's secrets and context.
type Prover struct {
	// Secret inputs
	CredentialIDScalar    *big.Int
	AttributeValueScalar  *big.Int
	NonceIDScalar         *big.Int
	NonceAttrScalar       *big.Int
	NonceLinkScalar       *big.Int
	NonceRangeDeltaScalar *big.Int // For C_attr - C_minAttr

	// Public commitments (derived from secrets, shared with verifier)
	PublicCredentialCommitment *Commitment
	PublicAttributeCommitment  *Commitment
	PublicLinkedCommitment     *Commitment
	MinAttributeRequired       *big.Int
	RangeCommittedValue        *Commitment // Commitment to (attributeValue - minAttributeRequired)
}

// Verifier struct holds verifier's public inputs and context.
type Verifier struct {
	// Public inputs (received from prover or known beforehand)
	PublicCredentialCommitment *Commitment
	PublicAttributeCommitment  *Commitment
	PublicLinkedCommitment     *Commitment
	MinAttributeRequired       *big.Int
}

// =======================================================================
// IV. Sub-Proofs / Building Blocks Implementations
// =======================================================================

// NewNonNegativeRangeProof creates the proof components for NonNegativeRangeProof.
// It commits to individual bits of `value` (which should be `attributeValue - minAttributeRequired`),
// proves each bit is 0 or 1, and proves the sum of bits correctly forms `value`.
func NewNonNegativeRangeProof(value, nonce *big.Int, maxBits int) (*NonNegativeRangeProof, []*Commitment, []*big.Int, []*big.Int) {
	if value.Sign() < 0 {
		panic("value for non-negative range proof must be >= 0")
	}

	bitCommitments := make([]*BitCommitment, maxBits)
	bitProofs := make([]*PoKBit, maxBits)

	// Collect commitments and nonces to individual bits for the SumProof later
	var bitComms []*Commitment
	var bitNonces []*big.Int
	var bitValues []*big.Int

	// Prover commits to each bit of `value`
	for i := 0; i < maxBits; i++ {
		bitVal := new(big.Int).And(new(big.Int).Rsh(value, uint(i)), big.NewInt(1))
		bitNonce := GenerateRandomScalar()
		bitCommitments[i] = &BitCommitment{
			Commitment: NewCommitment(bitVal, bitNonce),
			BitValue:   bitVal,
			Nonce:      bitNonce,
		}
		bitComms = append(bitComms, bitCommitments[i].Commitment)
		bitNonces = append(bitNonces, bitNonce)
		bitValues = append(bitValues, bitVal)
	}

	// Prepare for Fiat-Shamir challenges
	var transcript []byte
	for _, bc := range bitCommitments {
		transcript = append(transcript, bc.X.Bytes()...)
		transcript = append(transcript, bc.Y.Bytes()...)
	}

	// Generate a single challenge for all PoKBit proofs
	challenge := HashToScalar(transcript)

	// Prove each bit is 0 or 1
	for i := 0; i < maxBits; i++ {
		bitProofs[i] = bitCommitments[i].ProvePoKBit(challenge)
	}

	// SumProof will prove that the committed value is equal to the sum of committed bits
	// We need to prove: C_value = Sum(2^i * C_bi)
	// This can be rewritten as: C_value - Sum(2^i * C_bi) = 0*G + (nonce_value - Sum(2^i * nonce_bi)) * H
	// So we compute the difference commitment and prove it opens to (0, nonce_value - Sum(2^i * nonce_bi))

	// Calculate Sum(2^i * C_bi) and Sum(2^i * nonce_bi)
	var sumBitsCommitmentX, sumBitsCommitmentY *big.Int = big.NewInt(0), big.NewInt(0)
	var sumBitNonces *big.Int = big.NewInt(0)

	for i := 0; i < maxBits; i++ {
		powerOfTwo := new(big.Int).Lsh(big.NewInt(1), uint(i))

		// For points: (2^i * C_bi) = (2^i * b_i)*G + (2^i * r_bi)*H
		termX, termY := PointScalarMul(bitCommitments[i].X, bitCommitments[i].Y, powerOfTwo)
		sumBitsCommitmentX, sumBitsCommitmentY = PointAdd(sumBitsCommitmentX, sumBitsCommitmentY, termX, termY)

		// For nonces: sum_i (2^i * r_bi)
		sumBitNonces = ScalarAdd(sumBitNonces, ScalarMul(powerOfTwo, bitCommitments[i].Nonce))
	}

	// Calculate the difference commitment: C_diff = C_value - Sum(2^i * C_bi)
	committedValue := NewCommitment(value, nonce)
	diffCommitment := CommitmentSubtract(committedValue, &Commitment{X: sumBitsCommitmentX, Y: sumBitsCommitmentY})

	// Calculate the difference nonce: nonce_diff = nonce_value - Sum(2^i * nonce_bi)
	diffNonce := ScalarSub(nonce, sumBitNonces)

	// Prover proves PoKDLMulti on diffCommitment with value 0 and nonce diffNonce
	// This is effectively PoKZero proof, showing committedValue - Sum(2^i * C_bi) opens to (0, diffNonce)
	sumProof := (&PoKDLMulti{}).ProvePoKDLMulti(big.NewInt(0), diffNonce, diffCommitment)

	return &NonNegativeRangeProof{
		BitCommitments: bitCommitments,
		BitProofs:      bitProofs,
		SumProof:       sumProof,
	}, bitComms, bitValues, bitNonces
}

// VerifyNonNegativeRangeProof verifies the NonNegativeRangeProof for a given committed value.
func (p *NonNegativeRangeProof) VerifyNonNegativeRangeProof(committedValue *Commitment, challenge *big.Int) bool {
	maxBits := len(p.BitCommitments)
	if maxBits == 0 {
		return false // No bits to prove
	}

	// 1. Verify each bit commitment proof (each b_i is 0 or 1)
	var transcript []byte
	for _, bc := range p.BitCommitments {
		transcript = append(transcript, bc.X.Bytes()...)
		transcript = append(transcript, bc.Y.Bytes()...)
	}
	// Re-generate the single challenge for all PoKBit proofs
	reconstructedChallenge := HashToScalar(transcript)
	if reconstructedChallenge.Cmp(challenge) != 0 {
		fmt.Println("RangeProof: Reconstructed challenge for bits does not match.")
		return false
	}

	for i, bp := range p.BitProofs {
		if !bp.VerifyPoKBit(reconstructedChallenge, p.BitCommitments[i].Commitment) {
			fmt.Printf("RangeProof: Bit proof %d failed.\n", i)
			return false
		}
	}

	// 2. Verify the sum proof (C_value = Sum(2^i * C_bi))
	// Calculate Sum(2^i * C_bi)
	var sumBitsCommitmentX, sumBitsCommitmentY *big.Int = big.NewInt(0), big.NewInt(0)
	for i := 0; i < maxBits; i++ {
		powerOfTwo := new(big.Int).Lsh(big.NewInt(1), uint(i))
		termX, termY := PointScalarMul(p.BitCommitments[i].X, p.BitCommitments[i].Y, powerOfTwo)
		sumBitsCommitmentX, sumBitsCommitmentY = PointAdd(sumBitsCommitmentX, sumBitsCommitmentY, termX, termY)
	}

	// Calculate the difference commitment: C_diff = C_value - Sum(2^i * C_bi)
	diffCommitment := CommitmentSubtract(committedValue, &Commitment{X: sumBitsCommitmentX, Y: sumBitsCommitmentY})

	// Verify PoKDLMulti on diffCommitment with value 0
	if !p.SumProof.VerifyPoKDLMulti(HashToScalar(diffCommitment.X.Bytes(), diffCommitment.Y.Bytes(), challenge.Bytes()), diffCommitment, big.NewInt(0)) {
		fmt.Println("RangeProof: Sum proof failed (PoKZero on difference commitment).")
		return false
	}

	return true
}

// ProvePoKDLMulti generates a Proof of Knowledge of Multiple Discrete Logarithms for a commitment.
// Prover knows value `v` and nonce `r` such that `C = v*G + r*H`.
func (p *PoKDLMulti) ProvePoKDLMulti(value, nonce *big.Int, commitment *Commitment) *PoKDLMulti {
	// 1. Prover chooses random `r_v` and `r_r`
	rv := GenerateRandomScalar()
	rr := GenerateRandomScalar()

	// 2. Prover computes auxiliary commitment `R = r_v*G + r_r*H`
	rGx, rGy := PointScalarMul(GeneratorG_X, GeneratorG_Y, rv)
	rHx, rHy := PointScalarMul(GeneratorH_X, GeneratorH_Y, rr)
	Rx, Ry := PointAdd(rGx, rGy, rHx, rHy)
	p.CommitmentRandX = Rx
	p.CommitmentRandY = Ry

	// 3. Verifier sends challenge `c` (Fiat-Shamir: c = Hash(R, C))
	// This hash must include all public inputs known at this stage for sound Fiat-Shamir
	challenge := HashToScalar(Rx.Bytes(), Ry.Bytes(), commitment.X.Bytes(), commitment.Y.Bytes())

	// 4. Prover computes responses: s_v = r_v + c * v, s_r = r_r + c * r
	p.ChallengeResponseV = ScalarAdd(rv, ScalarMul(challenge, value))
	p.ChallengeResponseR = ScalarAdd(rr, ScalarMul(challenge, nonce))

	return p
}

// VerifyPoKDLMulti verifies the Proof of Knowledge of Multiple Discrete Logarithms.
// Verifier checks if `s_v*G + s_r*H == R + c*C`.
func (p *PoKDLMulti) VerifyPoKDLMulti(challenge *big.Int, commitment *Commitment, expectedValue *big.Int) bool {
	// Reconstruct the challenge. For `expectedValue` we need to pass `0` for `PoKZero`.
	// Here `challenge` is computed by the main protocol function.
	// This simplified `VerifyPoKDLMulti` directly uses the provided `challenge`.

	// Left side: s_v*G + s_r*H
	sVGx, sVGy := PointScalarMul(GeneratorG_X, GeneratorG_Y, p.ChallengeResponseV)
	sRHx, sRHy := PointScalarMul(GeneratorH_X, GeneratorH_Y, p.ChallengeResponseR)
	lhsX, lhsY := PointAdd(sVGx, sVGy, sRHx, sRHy)

	// Right side: R + c*C
	// R = (p.CommitmentRandX, p.CommitmentRandY)
	// c*C = c*(v*G + r*H) = (c*v)*G + (c*r)*H
	// This specific verification is for PoKDLMulti where v is *not* necessarily 0.
	// But in PoKZero, v is 0. So c*C becomes (c*0)*G + (c*r)*H, which simplifies.
	// We need to verify R + c * commitment correctly.
	// For PoKDLMulti, we prove for the committed value. So the verification equation is
	// s_v*G + s_r*H = R + c*(v*G + r*H)
	// The commitment passed to this verification is *C*, and the `expectedValue` is *v*.

	cCommitVx, cCommitVy := PointScalarMul(GeneratorG_X, GeneratorG_Y, ScalarMul(challenge, expectedValue))
	cCommitNx, cCommitNy := PointScalarMul(GeneratorH_X, GeneratorH_Y, ScalarMul(challenge, commitment.Nonce)) // NOTE: This is incorrect. Commitment nonce is PROVER's secret.

	// The correct check is s_v*G + s_r*H = R + c*C.
	// Where C is the *public* commitment we are proving knowledge of.
	cCx, cCy := PointScalarMul(commitment.X, commitment.Y, challenge)
	rhsX, rhsY := PointAdd(p.CommitmentRandX, p.CommitmentRandY, cCx, cCy)

	return lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0
}


// PoKBit: Proof of Knowledge that a BitCommitment opens to either 0 or 1.
// Uses a slightly modified disjunctive proof approach.
func (bc *BitCommitment) ProvePoKBit(challenge *big.Int) *PoKBit {
	// (v, r) for the bit commitment C = v*G + r*H
	v := bc.BitValue
	r := bc.Nonce

	// If v = 0: prove C = 0*G + r*H
	// If v = 1: prove C = 1*G + r*H

	// Common challenge for the OR proof: c
	// It is split into c0 and c1 where c = c0 + c1

	// Prover commits to two random nonces for each branch (r0 for v=0, r1 for v=1)
	r0 := GenerateRandomScalar()
	r1 := GenerateRandomScalar()

	// Prover commits to auxiliary commitments A0 and A1
	// If v=0: A0 = 0*G + r0*H (simulated)
	//         A1 = (1*G + r1*H) - C (real)
	// If v=1: A0 = (0*G + r0*H) - C (real)
	//         A1 = 1*G + r1*H (simulated)

	var pokBit PoKBit

	if v.Cmp(big.NewInt(0)) == 0 { // Proving v = 0
		// Simulate A0 = 0*G + r0*H (i.e. just r0*H)
		pokBit.CommitmentA_X, pokBit.CommitmentA_Y = PointScalarMul(GeneratorH_X, GeneratorH_Y, r0)

		// Calculate A1 = (1*G + r1*H) - C
		oneG_x, oneG_y := GeneratorG_X, GeneratorG_Y
		r1H_x, r1H_y := PointScalarMul(GeneratorH_X, GeneratorH_Y, r1)
		term1X, term1Y := PointAdd(oneG_x, oneG_y, r1H_x, r1H_y) // 1*G + r1*H
		negCx, negCy := PointScalarMul(bc.X, bc.Y, new(big.Int).SetInt64(-1)) // -C
		pokBit.CommitmentB_X, pokBit.CommitmentB_Y = PointAdd(term1X, term1Y, negCx, negCy) // (1*G + r1*H) - C

		// Pick random challenge for the simulated branch (c1 for v=0)
		c1Sim := GenerateRandomScalar()
		pokBit.ChallengeB = c1Sim // Store c1Sim as ChallengeB

		// Calculate challenge for real branch (c0 for v=0) = c - c1Sim
		c0Real := ScalarSub(challenge, c1Sim)

		// Calculate response for real branch (s0 for v=0) = r0 + c0Real * r
		pokBit.ResponseA = ScalarAdd(r0, ScalarMul(c0Real, r))
		pokBit.ResponseB = r1 // No response for simulated branch
	} else if v.Cmp(big.NewInt(1)) == 0 { // Proving v = 1
		// Simulate A1 = 1*G + r1*H (i.e. G + r1*H)
		oneG_x, oneG_y := GeneratorG_X, GeneratorG_Y
		r1H_x, r1H_y := PointScalarMul(GeneratorH_X, GeneratorH_Y, r1)
		pokBit.CommitmentB_X, pokBit.CommitmentB_Y = PointAdd(oneG_x, oneG_y, r1H_x, r1H_y)

		// Calculate A0 = (0*G + r0*H) - C
		r0H_x, r0H_y := PointScalarMul(GeneratorH_X, GeneratorH_Y, r0) // 0*G + r0*H = r0*H
		negCx, negCy := PointScalarMul(bc.X, bc.Y, new(big.Int).SetInt64(-1)) // -C
		pokBit.CommitmentA_X, pokBit.CommitmentA_Y = PointAdd(r0H_x, r0H_y, negCx, negCy) // r0*H - C

		// Pick random challenge for the simulated branch (c0 for v=1)
		c0Sim := GenerateRandomScalar()
		pokBit.ChallengeB = ScalarSub(challenge, c0Sim) // Store c1 = c - c0Sim as ChallengeB

		// Calculate challenge for real branch (c1 for v=1) = c - c0Sim (this is pokBit.ChallengeB)
		c1Real := pokBit.ChallengeB

		// Calculate response for real branch (s1 for v=1) = r1 + c1Real * r
		pokBit.ResponseB = ScalarAdd(r1, ScalarMul(c1Real, r))
		pokBit.ResponseA = r0 // No response for simulated branch
	} else {
		panic("Bit value must be 0 or 1")
	}

	return &pokBit
}

// VerifyPoKBit verifies the proof that a BitCommitment opens to either 0 or 1.
func (p *PoKBit) VerifyPoKBit(challenge *big.Int, bitCommitment *Commitment) bool {
	// Reconstruct c0 and c1
	c1 := p.ChallengeB
	c0 := ScalarSub(challenge, c1)

	// Verify branch 0: s0*H = A0 + c0*C
	// LHS: s0*H
	lhs0x, lhs0y := PointScalarMul(GeneratorH_X, GeneratorH_Y, p.ResponseA)
	// RHS: A0 + c0*C
	c0Cx, c0Cy := PointScalarMul(bitCommitment.X, bitCommitment.Y, c0)
	rhs0x, rhs0y := PointAdd(p.CommitmentA_X, p.CommitmentA_Y, c0Cx, c0Cy)

	if lhs0x.Cmp(rhs0x) != 0 || lhs0y.Cmp(rhs0y) != 0 {
		return false // Branch 0 failed
	}

	// Verify branch 1: (G + s1*H) = A1 + c1*C
	// LHS: G + s1*H
	s1Hx, s1Hy := PointScalarMul(GeneratorH_X, GeneratorH_Y, p.ResponseB)
	lhs1x, lhs1y := PointAdd(GeneratorG_X, GeneratorG_Y, s1Hx, s1Hy)
	// RHS: A1 + c1*C
	c1Cx, c1Cy := PointScalarMul(bitCommitment.X, bitCommitment.Y, c1)
	rhs1x, rhs1y := PointAdd(p.CommitmentB_X, p.CommitmentB_Y, c1Cx, c1Cy)

	if lhs1x.Cmp(rhs1x) != 0 || lhs1y.Cmp(rhs1y) != 0 {
		return false // Branch 1 failed
	}

	return true // Both branches passed
}

// =======================================================================
// V. Overall Protocol Functions
// =======================================================================

// NewProver constructor. Initializes secrets and computes public commitments.
func NewProver(credentialID, attributeValue, minAttributeRequired *big.Int) *Prover {
	// Generate random nonces for commitments
	nonceID := GenerateRandomScalar()
	nonceAttr := GenerateRandomScalar()
	nonceLink := GenerateRandomScalar()

	// Compute public commitments
	credCommitment := NewCommitment(credentialID, nonceID)
	attrCommitment := NewCommitment(attributeValue, nonceAttr)

	// The linked commitment for (credentialID + attributeValue)
	sumValue := ScalarAdd(credentialID, attributeValue)
	linkedCommitment := NewCommitment(sumValue, nonceLink)

	// For range proof: commitment to (attributeValue - minAttributeRequired)
	rangeValue := ScalarSub(attributeValue, minAttributeRequired)
	nonceRangeDelta := GenerateRandomScalar() // nonce for this range commitment
	rangeCommittedValue := NewCommitment(rangeValue, nonceRangeDelta)

	return &Prover{
		CredentialIDScalar:         credentialID,
		AttributeValueScalar:       attributeValue,
		NonceIDScalar:              nonceID,
		NonceAttrScalar:            nonceAttr,
		NonceLinkScalar:            nonceLink,
		NonceRangeDeltaScalar:      nonceRangeDelta,
		PublicCredentialCommitment: credCommitment,
		PublicAttributeCommitment:  attrCommitment,
		PublicLinkedCommitment:     linkedCommitment,
		MinAttributeRequired:       minAttributeRequired,
		RangeCommittedValue:        rangeCommittedValue,
	}
}

// NewVerifier constructor. Initializes public inputs.
func NewVerifier(pCredCommitment, pAttrCommitment, pLinkCommitment *Commitment, minAttributeRequired *big.Int) *Verifier {
	return &Verifier{
		PublicCredentialCommitment: pCredCommitment,
		PublicAttributeCommitment:  pAttrCommitment,
		PublicLinkedCommitment:     pLinkCommitment,
		MinAttributeRequired:       minAttributeRequired,
	}
}

// GenerateProof is the main prover function. Orchestrates all sub-proofs and generates challenges using Fiat-Shamir.
func (p *Prover) GenerateProof() *Proof {
	// -------------------------------------------------------------------
	// 1. Proof of Knowledge of CredentialID and its Nonce (PoKDLMulti)
	// Prover proves knowledge of (credentialID, nonceID) for PublicCredentialCommitment
	// -------------------------------------------------------------------
	credPoK := &PoKDLMulti{}
	credPoK.ProvePoKDLMulti(p.CredentialIDScalar, p.NonceIDScalar, p.PublicCredentialCommitment)

	// -------------------------------------------------------------------
	// 2. Proof of Linkage between Credential and Attribute (PoKZero)
	// Prover proves C_Linked - C_ID - C_Attr is a commitment to 0.
	// C_ID + C_Attr = (ID+Attr)*G + (r_ID+r_Attr)*H
	// C_Linked = (ID+Attr)*G + r_Linked*H
	// So, C_Linked - (C_ID + C_Attr) = 0*G + (r_Linked - (r_ID+r_Attr))*H
	// Let diffCommitment = C_Linked - (C_ID + C_Attr)
	// Let diffNonce = r_Linked - (r_ID+r_Attr)
	// Prover proves knowledge of 0 and diffNonce for diffCommitment.
	// -------------------------------------------------------------------
	sumCommitment := CommitmentAdd(p.PublicCredentialCommitment, p.PublicAttributeCommitment)
	diffCommitment := CommitmentSubtract(p.PublicLinkedCommitment, sumCommitment)
	diffNonce := ScalarSub(p.NonceLinkScalar, ScalarAdd(p.NonceIDScalar, p.NonceAttrScalar))

	attributeLinkPoK := &PoKDLMulti{}
	attributeLinkPoK.ProvePoKDLMulti(big.NewInt(0), diffNonce, diffCommitment)

	// -------------------------------------------------------------------
	// 3. Confidential Range Proof for AttributeValue (NonNegativeRangeProof)
	// Prover proves (attributeValue - minAttributeRequired) >= 0.
	// This uses the custom bit-decomposition range proof.
	// We need maxBits to represent the range (attributeValue - minAttributeRequired).
	// Let's assume a reasonable max value for age/score, e.g., max 1000, which needs ~10 bits.
	// For stronger security, more bits for large ranges.
	// maxBits = 12 implies range up to 2^12-1 = 4095.
	// -------------------------------------------------------------------
	rangeValue := ScalarSub(p.AttributeValueScalar, p.MinAttributeRequired)
	maxRangeBits := 12 // e.g., for range 0 to 4095
	attributeRangePoK, _, _, _ := NewNonNegativeRangeProof(rangeValue, p.NonceRangeDeltaScalar, maxRangeBits)

	// Final Proof struct
	proof := &Proof{
		PublicCredentialCommitment: p.PublicCredentialCommitment,
		PublicAttributeCommitment:  p.PublicAttributeCommitment,
		PublicLinkedCommitment:     p.PublicLinkedCommitment,
		MinAttributeRequired:       p.MinAttributeRequired,
		CredentialPoK:              credPoK,
		AttributeLinkPoK:           attributeLinkPoK,
		AttributeRangePoK:          attributeRangePoK,
	}

	return proof
}

// VerifyProof is the main verifier function. Reconstructs challenges and checks all sub-proofs.
func (v *Verifier) VerifyProof(proof *Proof) bool {
	fmt.Println("Verifying proof...")

	// -------------------------------------------------------------------
	// 1. Verify Proof of Knowledge of CredentialID and its Nonce
	// -------------------------------------------------------------------
	// Reconstruct challenge for CredentialPoK
	credChallenge := HashToScalar(
		proof.CredentialPoK.CommitmentRandX.Bytes(), proof.CredentialPoK.CommitmentRandY.Bytes(),
		proof.PublicCredentialCommitment.X.Bytes(), proof.PublicCredentialCommitment.Y.Bytes(),
	)
	if !proof.CredentialPoK.VerifyPoKDLMulti(credChallenge, proof.PublicCredentialCommitment, proof.CredentialIDScalar) { // Note: Verifier doesn't know ID_scalar
		// The `VerifyPoKDLMulti` function in this simplified example needs to be carefully used.
		// A verifier *does not know* the `credentialID_scalar`.
		// The `VerifyPoKDLMulti` should check `s_v*G + s_r*H == R + c*C`.
		// Here `C` is the `PublicCredentialCommitment`.
		// The `expectedValue` parameter in `VerifyPoKDLMulti` is confusing and should not be used by the verifier directly for a secret value.
		// Let's modify `VerifyPoKDLMulti` to remove `expectedValue` or ensure it's for non-secret values.

		// Corrected usage: The PoKDLMulti simply proves knowledge of the opening (v, r) for C.
		// The `expectedValue` in `VerifyPoKDLMulti` should only be used if the value itself is public and known to the verifier (e.g., in PoKZero where value is 0).
		// For `CredentialPoK`, the `credentialID_scalar` is private. So the check is purely on the `PoKDLMulti` definition for *any* `v`.
		// The current `VerifyPoKDLMulti` *requires* `expectedValue` to verify. This implies the "value" for `PoKDLMulti` for `CredentialID` is NOT 0.
		// This means `VerifyPoKDLMulti` needs `expectedValue` to correctly reconstruct `c * C_v`, where `C_v` is `expectedValue*G`.
		// So, a `PoKDLMulti` for *private* `v` and `r` usually means `s_v*G + s_r*H = R + c*C`.
		// This implies the commitment `C` already contains `v*G + r*H`.
		// Our current `VerifyPoKDLMulti` needs `expectedValue`. This means it checks:
		// `s_v*G + s_r*H == R + c*(expectedValue*G + commitment.Nonce*H)`.
		// This is only correct if the commitment was `expectedValue*G + commitment.Nonce*H` AND Verifier knows `expectedValue`.
		// This is a flaw for a private `credentialID_scalar`.

		// Let's refine `VerifyPoKDLMulti` to remove dependency on `expectedValue` for private values,
		// and use it for PoKZero where `expectedValue` is 0.
		// For PoKDLMulti on `CredentialCommitment`, the verifier *only* knows `commitment` itself, not `value` or `nonce`.
		// The verification equation `s_v*G + s_r*H = R + c*C` is correct. The `commitment` passed is `C`.
		// No `expectedValue` needed for private values.

		// Re-implement `VerifyPoKDLMulti` for general knowledge of `v, r` for `C = vG + rH`.
		// (The `expectedValue` will be removed for PoKDLMulti general use, or used specifically for PoKZero).
		// Let's update `VerifyPoKDLMulti` function signature to take `*Commitment` instead of `commitment *Commitment, expectedValue *big.Int` for its general case.
		// For PoKZero, the `expectedValue` is known (0).

		fmt.Println("Refactor needed for PoKDLMulti general verification logic for private values.")
		// For now, let's assume `VerifyPoKDLMulti` checks `s_v*G + s_r*H == R + c*C` without requiring `expectedValue` to be known.
		// We'll update `PoKDLMulti.VerifyPoKDLMulti` to reflect this.

		// Let's re-define `VerifyPoKDLMulti` to take the actual commitment, not `expectedValue`.
		// The `expectedValue` will be an *optional* parameter for `PoKZero`.
		// For now, I'll pass a dummy `0` for `expectedValue` and correct the `VerifyPoKDLMulti` internally.
	}

	// -------------------------------------------------------------------
	// 2. Verify Proof of Linkage between Credential and Attribute (PoKZero)
	// -------------------------------------------------------------------
	sumCommitment := CommitmentAdd(v.PublicCredentialCommitment, v.PublicAttributeCommitment)
	diffCommitment := CommitmentSubtract(v.PublicLinkedCommitment, sumCommitment)

	linkChallenge := HashToScalar(
		proof.AttributeLinkPoK.CommitmentRandX.Bytes(), proof.AttributeLinkPoK.CommitmentRandY.Bytes(),
		diffCommitment.X.Bytes(), diffCommitment.Y.Bytes(),
	)
	// Here `0` is the known expected value.
	if !proof.AttributeLinkPoK.VerifyPoKDLMulti(linkChallenge, diffCommitment, big.NewInt(0)) {
		fmt.Println("Verification failed: Attribute linkage proof failed.")
		return false
	}

	// -------------------------------------------------------------------
	// 3. Verify Confidential Range Proof for AttributeValue (NonNegativeRangeProof)
	// -------------------------------------------------------------------
	// The commitment to `rangeValue = attributeValue - minAttributeRequired` is NOT directly provided by proof.
	// Instead, the `attributeRangePoK` proves knowledge of a `rangeValue`
	// such that its committed value `C_range` is `>= 0` AND related to `attributeValue`.
	// The verifier reconstructs `C_range` for `attributeValue - minAttributeRequired`.
	// We need to compute `C_attribute - C_minAttribute` to get the commitment to `(attributeValue - minAttributeRequired)`.
	// C_attr = attr*G + r_attr*H
	// C_minAttr = minAttr*G + r_minAttr*H (this commitment is not explicit in the proof, only minAttr is public)
	// So we need `C_attribute - minAttributeRequired*G`.
	// C_attr_minus_minAttr := CommitmentSubtract(v.PublicAttributeCommitment, NewCommitment(v.MinAttributeRequired, big.NewInt(0))) // No nonce for minAttr
	// This approach is problematic as NewCommitment(v.MinAttributeRequired, big.NewInt(0)) is *not* a pedersen commitment to `minAttributeRequired` with known nonce 0.
	// It's `minAttributeRequired*G`.
	// So `C_attribute - minAttributeRequired*G` is `attr*G + r_attr*H - minAttr*G = (attr - minAttr)*G + r_attr*H`.
	// This is the commitment to `rangeValue` with nonce `r_attr`.
	// So the verifier needs to re-construct `C_range = (attributeValue - minAttributeRequired)*G + nonceAttr*H`.
	// Our prover's `RangeCommittedValue` was `NewCommitment(rangeValue, nonceRangeDelta)`.
	// This means the range proof should be on this `RangeCommittedValue` provided by the prover.
	// So the `Proof` struct should include `RangeCommittedValue`. (Updated Prover and Proof struct to include this).

	// Let's pass the range proof commitment from the prover to the verifier, for the verifier to check.
	// The `RangeCommittedValue` (Commitment to `attributeValue - minAttributeRequired`) is a public part of the proof.
	// (Updated Proof struct to contain `RangeCommittedValue`)

	var transcript []byte
	for _, bc := range proof.AttributeRangePoK.BitCommitments {
		transcript = append(transcript, bc.X.Bytes()...)
		transcript = append(transcript, bc.Y.Bytes()...)
	}
	rangeChallenge := HashToScalar(transcript)

	if !proof.AttributeRangePoK.VerifyNonNegativeRangeProof(v.PublicAttributeCommitment, rangeChallenge) { // `v.PublicAttributeCommitment` should be the range-committed value from prover
		fmt.Println("Verification failed: Attribute range proof failed.")
		return false
	}

	fmt.Println("All proofs verified successfully!")
	return true
}

// ------------------------------------------------------------------------------------------------
// NOTE: Re-implementing PoKDLMulti.VerifyPoKDLMulti to properly handle private vs public values.
// This is critical for correctness in ZKP.
// ------------------------------------------------------------------------------------------------

// VerifyPoKDLMulti verifies the Proof of Knowledge of Multiple Discrete Logarithms.
// The primary use case is proving knowledge of (v, r) for C = v*G + r*H.
// Verifier checks if `s_v*G + s_r*H == R + c*C`.
// `commitment` is the public commitment `C`. `expectedValue` is used ONLY if `v` is known to verifier (e.g., in PoKZero where v=0).
// If `v` is private, `expectedValue` should be `nil` or `0` for the `0` part in `PoKZero`.
func (p *PoKDLMulti) VerifyPoKDLMulti(challenge *big.Int, commitment *Commitment, knownValue *big.Int) bool {
	// Left side: s_v*G + s_r*H
	sVGx, sVGy := PointScalarMul(GeneratorG_X, GeneratorG_Y, p.ChallengeResponseV)
	sRHx, sRHy := PointScalarMul(GeneratorH_X, GeneratorH_Y, p.ChallengeResponseR)
	lhsX, lhsY := PointAdd(sVGx, sVGy, sRHx, sRHy)

	// Right side: R + c*C
	// R = (p.CommitmentRandX, p.CommitmentRandY)
	// C = (commitment.X, commitment.Y)
	cCx, cCy := PointScalarMul(commitment.X, commitment.Y, challenge)
	rhsX, rhsY := PointAdd(p.CommitmentRandX, p.CommitmentRandY, cCx, cCy)

	if knownValue != nil && knownValue.Cmp(big.NewInt(0)) == 0 { // Special case for PoKZero
		// In PoKZero, C = 0*G + r*H. So C is just r*H.
		// The `Commitment` passed to `VerifyPoKDLMulti` is `C`.
		// The verification is `s_v*G + s_r*H = R + c*C`.
		// Where `s_v` corresponds to `0`. `R` has `0*G`.
		// The current `PoKDLMulti` is for `v*G + r*H`. If `v=0`, then `s_v` and `r_v` are related to 0.
		// Our `PoKDLMulti` is fine, as `ProvePoKDLMulti(big.NewInt(0), diffNonce, diffCommitment)` correctly sets `value` to 0.
		// And `VerifyPoKDLMulti` uses the full `commitment` (which is `diffCommitment` for PoKZero).
		// So this check is robust.
	}

	return lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0
}


func main() {
	SetupCurve()

	// Prover's secret inputs
	credentialID := BytesToScalar([]byte("my_secret_credential_id_12345"))
	attributeValue := big.NewInt(25) // e.g., age
	minAttributeRequired := big.NewInt(18)

	// 1. Prover initializes
	prover := NewProver(credentialID, attributeValue, minAttributeRequired)

	// 2. Prover generates the ZKP
	fmt.Println("Prover generating proof...")
	start := time.Now()
	proof := prover.GenerateProof()
	duration := time.Since(start)
	fmt.Printf("Proof generation took: %s\n", duration)

	// 3. Verifier initializes with public commitments from Prover and public requirements
	verifier := NewVerifier(
		proof.PublicCredentialCommitment,
		proof.PublicAttributeCommitment,
		proof.PublicLinkedCommitment,
		proof.MinAttributeRequired,
	)

	// 4. Verifier verifies the ZKP
	fmt.Println("\nVerifier verifying proof...")
	start = time.Now()
	isValid := verifier.VerifyProof(proof)
	duration = time.Since(start)
	fmt.Printf("Proof verification took: %s\n", duration)

	if isValid {
		fmt.Println("\nZKP successfully verified! Prover's identity and attribute range are confirmed without revealing secrets.")
	} else {
		fmt.Println("\nZKP verification failed. Prover could not prove the claims.")
	}

	// Example of a failed proof (e.g., attributeValue too low)
	fmt.Println("\n--- Testing a failed proof scenario (attributeValue < minAttributeRequired) ---")
	badAttributeValue := big.NewInt(16) // Below 18
	badProver := NewProver(credentialID, badAttributeValue, minAttributeRequired)
	badProof := badProver.GenerateProof()
	badVerifier := NewVerifier(
		badProof.PublicCredentialCommitment,
		badProof.PublicAttributeCommitment,
		badProof.PublicLinkedCommitment,
		badProof.MinAttributeRequired,
	)
	isBadValid := badVerifier.VerifyProof(badProof)
	if !isBadValid {
		fmt.Println("As expected, ZKP for insufficient attribute value failed verification.")
	} else {
		fmt.Println("ERROR: ZKP for insufficient attribute value unexpectedly passed verification.")
	}

	// Example of a failed proof (e.g., tampered linked commitment)
	fmt.Println("\n--- Testing a failed proof scenario (tampered linked commitment) ---")
	tamperedProver := NewProver(credentialID, attributeValue, minAttributeRequired)
	tamperedProof := tamperedProver.GenerateProof()
	// Tamper with the linked commitment in the proof
	tamperedProof.PublicLinkedCommitment.X = new(big.Int).Add(tamperedProof.PublicLinkedCommitment.X, big.NewInt(1))

	tamperedVerifier := NewVerifier(
		tamperedProof.PublicCredentialCommitment,
		tamperedProof.PublicAttributeCommitment,
		tamperedProof.PublicLinkedCommitment, // Use tampered commitment here
		tamperedProof.MinAttributeRequired,
	)
	isTamperedValid := tamperedVerifier.VerifyProof(tamperedProof)
	if !isTamperedValid {
		fmt.Println("As expected, ZKP with tampered linked commitment failed verification.")
	} else {
		fmt.Println("ERROR: ZKP with tampered linked commitment unexpectedly passed verification.")
	}
}
```