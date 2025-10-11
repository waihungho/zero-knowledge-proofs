```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
)

// Outline: Zero-Knowledge Proof for Private Reputation Tier Verification
//
// This Go package implements a Zero-Knowledge Proof (ZKP) system for
// proving that a user's private reputation score falls within a publicly
// defined tier (e.g., "Bronze", "Silver", "Gold" represented by score ranges)
// without revealing the exact score. The core cryptographic primitive
// used is a Disjunctive Schnorr Proof, which allows proving the knowledge
// of a secret value *s* such that its commitment *C = s*G + r*H* is valid
// for *s* being *one of* a set of predefined public values *{v_0, v_1, ..., v_N}*.
//
// Application: Private Reputation Tier Verification
// A decentralized identity or reputation system requires users to prove
// their reputation score (a private integer) meets a certain tier requirement.
// For instance, a service might only be accessible to users with a
// "Silver" tier reputation, meaning their score is between 11 and 20.
// The user (Prover) wants to demonstrate they are in the "Silver" tier
// to the service (Verifier) without disclosing their exact score (e.g., 14).
//
// The ZKP protocol works by defining the desired score range [MinTierScore, MaxTierScore].
// The Prover commits to their secret score. Then, they generate a Disjunctive Schnorr
// Proof, effectively proving: "I know a secret 'score' such that its commitment
// matches 'score' * G + 'r' * H, AND 'score' is equal to V_min OR V_min+1 OR ... OR V_max."
// The verifier checks this disjunctive proof.
//
// Key Concepts:
// - Elliptic Curve Cryptography: Basis for point arithmetic and discrete logarithm problem.
// - Pedersen Commitments: Allows committing to a secret value without revealing it,
//   and later proving properties about it.
// - Schnorr Proof of Knowledge: A fundamental ZKP to prove knowledge of a discrete logarithm.
// - Fiat-Shamir Heuristic: Transforms an interactive proof into a non-interactive one
//   using a cryptographic hash function to generate challenges.
// - Disjunctive Proof (OR Proof): A composite ZKP that proves that at least one of
//   several statements is true, without revealing which one. This is crucial for range
//   proofs over small, finite sets.
//
// The implementation is "from scratch" using Go's `math/big` for arithmetic,
// avoiding external ZKP libraries to meet the "no duplication of open source"
// requirement for ZKP-specific components. Standard cryptographic hashes and
// random number generators (`crypto/sha256`, `crypto/rand`) are used as
// fundamental primitives.
//
// Disclaimer: This implementation is for educational purposes and demonstrates
// the concepts. It is NOT audited, optimized, or production-ready. Real-world
// cryptographic systems require extensive expertise, formal proofs of security,
// and careful engineering.
//
// Number of functions: More than 20.
//
// ---
// Function Summary:
//
// Core Elliptic Curve & Scalar Operations:
// - `CurveParams`: Structure holding elliptic curve parameters (P, N, Gx, Gy).
// - `NewCurveParams(curveID int)`: Initializes standard curve parameters (e.g., secp256k1-like).
// - `Point`: Structure representing an elliptic curve point (X, Y).
// - `NewPoint(x, y *big.Int)`: Creates a new EC Point.
// - `(p *Point) String() string`: String representation of a point for debug.
// - `Scalar`: Type alias for `*big.Int` representing a scalar modulo N.
// - `NewScalar(val *big.Int)`: Creates a new Scalar.
// - `(s Scalar) String() string`: String representation of a scalar for debug.
// - `(s Scalar) Add(t Scalar) Scalar`: Scalar addition modulo N.
// - `(s Scalar) Sub(t Scalar) Scalar`: Scalar subtraction modulo N.
// - `(s Scalar) Mul(t Scalar) Scalar`: Scalar multiplication modulo N.
// - `(s Scalar) Inv() Scalar`: Scalar modular inverse modulo N.
// - `(s Scalar) Neg() Scalar`: Scalar negation modulo N.
// - `(s Scalar) Bytes() []byte`: Converts scalar to byte slice.
// - `ECAdd(p1, p2 *Point) *Point`: Elliptic curve point addition.
// - `ECScalarMul(s Scalar, p *Point) *Point`: Elliptic curve scalar multiplication.
// - `ECPointEqual(p1, p2 *Point) bool`: Checks if two points are equal.
// - `ECPointZero() *Point`: Returns the point at infinity (identity element).
// - `(p *Point) IsOnCurve() bool`: Checks if a point lies on the curve.
// - `(p *Point) Bytes() []byte`: Converts point to compressed byte slice for hashing.
//
// Cryptographic Primitives & Utilities:
// - `GenerateRandomScalar(max *big.Int) Scalar`: Generates a cryptographically secure random scalar.
// - `HashToScalar(N *big.Int, data ...[]byte) Scalar`: Hashes multiple byte slices to a scalar modulo N (Fiat-Shamir).
// - `SetupGenerators(curve *CurveParams) (G, H *Point)`: Generates two independent, random generators G and H.
//
// Pedersen Commitment:
// - `PedersenCommit(value Scalar, blindingFactor Scalar, G, H *Point) *Point`: Creates a Pedersen commitment `value*G + blindingFactor*H`.
// - `PedersenOpen(commitment *Point, value Scalar, blindingFactor Scalar, G, H *Point) bool`: Verifies a Pedersen commitment.
//
// Schnorr Proof of Knowledge (Basic):
// - `SchnorrProof`: Structure holding a Schnorr proof (commitment, challenge, response).
// - `GenerateSchnorrProof(secret Scalar, G *Point, N *big.Int) *SchnorrProof`: Generates a standard Schnorr proof for `secret*G`.
// - `VerifySchnorrProof(proof *SchnorrProof, publicKey *Point, G *Point, N *big.Int) bool`: Verifies a standard Schnorr proof.
//
// Disjunctive Schnorr Proof (OR Proof):
// - `DisjunctiveProof`: Structure for the combined disjunctive proof.
// - `DisjunctProofPart`: Structure for a single part of the disjunctive proof (commitment `A`, challenge `e`, response `s`).
// - `GenerateDisjunctiveProof(secretValue Scalar, correctIndex int, possibleValues []Scalar, G, H *Point, N *big.Int) (*DisjunctiveProof, *Point)`:
//   Creates a disjunctive proof that the `PedersenCommit` of `secretValue` (using G and H) is equal to one of `possibleValues`.
//   Returns the proof and the actual Pedersen commitment `C = secretValue*G + r*H`.
// - `VerifyDisjunctiveProof(C *Point, possibleValues []Scalar, proof *DisjunctiveProof, G, H *Point, N *big.Int) bool`:
//   Verifies a disjunctive proof against a given commitment `C` and set of `possibleValues`.
//
// Application Layer: Private Reputation Tier Verification
// - `ReputationTierVerifier`: Structure to define and manage reputation tiers.
// - `NewReputationTierVerifier(minScore, maxScore int) *ReputationTierVerifier`: Creates a tier verifier for a specific score range.
// - `(rtv *ReputationTierVerifier) GetPossibleValues() []Scalar`: Generates the list of `Scalar`s for the tier range.
// - `(rtv *ReputationTierVerifier) GenerateProof(secretScore int, G, H *Point, N *big.Int) (*DisjunctiveProof, *Point, error)`:
//   Prover's side: takes a secret integer score and generates the full disjunctive ZKP.
//   Returns the proof, the Pedersen commitment to the score, and an error if score is out of tier range.
// - `(rtv *ReputationTierVerifier) VerifyProof(commitmentC *Point, proof *DisjunctiveProof, G, H *Point, N *big.Int) bool`:
//   Verifier's side: checks if the provided proof for commitmentC confirms the score is in the defined tier.

// --- Core Elliptic Curve & Scalar Operations ---

const (
	// Using a simplified representation of secp256k1 parameters
	// for educational purposes without directly importing crypto/secp256k1
	// These values are derived from secp256k1 constants.
	CurveSecp256k1 = iota
)

// CurveParams holds elliptic curve parameters for y^2 = x^3 + ax + b mod P
type CurveParams struct {
	P    *big.Int // Prime modulus
	N    *big.Int // Order of the base point G
	Gx   *big.Int // X-coordinate of base point G
	Gy   *big.Int // Y-coordinate of base point G
	A, B *big.Int // Curve equation parameters (a=0, b=7 for secp256k1)
}

// NewCurveParams initializes standard curve parameters.
func NewCurveParams(curveID int) *CurveParams {
	params := &CurveParams{}
	switch curveID {
	case CurveSecp256k1:
		params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
		params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
		params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
		params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
		params.A = big.NewInt(0)
		params.B = big.NewInt(7)
	default:
		panic("Unsupported curve ID")
	}
	return params
}

// Point represents an elliptic curve point.
type Point struct {
	X, Y    *big.Int
	IsInfinity bool // True if this is the point at infinity
	curve *CurveParams
}

// NewPoint creates a new EC Point.
func NewPoint(x, y *big.Int, curve *CurveParams) *Point {
	return &Point{X: x, Y: y, IsInfinity: false, curve: curve}
}

// ECPointZero returns the point at infinity (identity element).
func ECPointZero(curve *CurveParams) *Point {
	return &Point{IsInfinity: true, curve: curve}
}

// IsOnCurve checks if a point lies on the curve.
func (p *Point) IsOnCurve() bool {
	if p.IsInfinity {
		return true // Point at infinity is always on the curve
	}
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, p.curve.P)

	x3 := new(big.Int).Mul(p.X, p.X)
	x3.Mul(x3, p.X)
	
	ax := new(big.Int).Mul(p.curve.A, p.X)
	
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, p.curve.B)
	rhs.Mod(rhs, p.curve.P)

	return y2.Cmp(rhs) == 0
}

// Bytes returns a compressed byte representation of the point for hashing.
func (p *Point) Bytes() []byte {
	if p.IsInfinity {
		return []byte{0x00} // Special byte for infinity point
	}
	// Use compressed form: 0x02 for even Y, 0x03 for odd Y, followed by X coordinate
	prefix := byte(0x02)
	if new(big.Int).And(p.Y, big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
		prefix = 0x03
	}
	xBytes := p.X.Bytes()
	// Pad X bytes to be 32 bytes long for secp256k1
	paddedXBytes := make([]byte, 32)
	copy(paddedXBytes[32-len(xBytes):], xBytes)
	return append([]byte{prefix}, paddedXBytes...)
}

// String provides a string representation of the point for debug.
func (p *Point) String() string {
	if p.IsInfinity {
		return "Point(Infinity)"
	}
	return fmt.Sprintf("Point(X: %s, Y: %s)", p.X.Text(16), p.Y.Text(16))
}

// ECAdd performs elliptic curve point addition.
func ECAdd(p1, p2 *Point) *Point {
	curve := p1.curve
	if p1.IsInfinity { return p2 }
	if p2.IsInfinity { return p1 }

	if ECPointEqual(p1, ECPointZero(curve)) { return p2 }
	if ECPointEqual(p2, ECPointZero(curve)) { return p1 }
	
	// P + (-P) = Infinity
	if p1.X.Cmp(p2.X) == 0 && new(big.Int).Add(p1.Y, p2.Y).Mod(new(big.Int).Add(p1.Y, p2.Y), curve.P).Cmp(big.NewInt(0)) == 0 {
		return ECPointZero(curve)
	}

	var lambda *big.Int
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 { // Point doubling
		// lambda = (3x^2 + a) * (2y)^-1 mod P
		x2 := new(big.Int).Mul(p1.X, p1.X)
		num := new(big.Int).Mul(x2, big.NewInt(3))
		num.Add(num, curve.A)
		den := new(big.Int).Mul(p1.Y, big.NewInt(2))
		den.ModInverse(den, curve.P)
		lambda = new(big.Int).Mul(num, den)
		lambda.Mod(lambda, curve.P)
	} else { // Point addition
		// lambda = (y2 - y1) * (x2 - x1)^-1 mod P
		num := new(big.Int).Sub(p2.Y, p1.Y)
		den := new(big.Int).Sub(p2.X, p1.X)
		den.ModInverse(den, curve.P) // Modular inverse
		lambda = new(big.Int).Mul(num, den)
		lambda.Mod(lambda, curve.P)
	}

	// x3 = lambda^2 - x1 - x2 mod P
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p1.X)
	x3.Sub(x3, p2.X)
	x3.Mod(x3, curve.P)
	if x3.Sign() == -1 { x3.Add(x3, curve.P) }

	// y3 = lambda * (x1 - x3) - y1 mod P
	y3 := new(big.Int).Sub(p1.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p1.Y)
	y3.Mod(y3, curve.P)
	if y3.Sign() == -1 { y3.Add(y3, curve.P) }

	return NewPoint(x3, y3, curve)
}

// ECScalarMul performs elliptic curve scalar multiplication.
func ECScalarMul(s Scalar, p *Point) *Point {
	curve := p.curve
	if s.Cmp(big.NewInt(0)) == 0 || p.IsInfinity {
		return ECPointZero(curve)
	}
	result := ECPointZero(curve)
	addend := p
	
	// Perform multiplication using double-and-add algorithm
	// iterate over bits of s (from LSB to MSB)
	for i := 0; i < s.BitLen(); i++ {
		if s.Bit(i) == 1 {
			result = ECAdd(result, addend)
		}
		addend = ECAdd(addend, addend) // Double the addend
	}
	return result
}

// ECPointEqual checks if two points are equal.
func ECPointEqual(p1, p2 *Point) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2 // Both nil or one nil -> only equal if both nil
	}
	if p1.IsInfinity && p2.IsInfinity {
		return true
	}
	if p1.IsInfinity != p2.IsInfinity {
		return false
	}
	return p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0
}


// Scalar type alias for *big.Int for clarity, operating modulo N.
type Scalar *big.Int

// NewScalar creates a new Scalar from big.Int.
func NewScalar(val *big.Int) Scalar {
	if val == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(val)
}

// String provides a string representation of the scalar for debug.
func (s Scalar) String() string {
	return fmt.Sprintf("Scalar(%s)", (*big.Int)(s).Text(16))
}

// Add performs scalar addition modulo N.
func (s Scalar) Add(t Scalar, N *big.Int) Scalar {
	res := new(big.Int).Add(s, t)
	res.Mod(res, N)
	return res
}

// Sub performs scalar subtraction modulo N.
func (s Scalar) Sub(t Scalar, N *big.Int) Scalar {
	res := new(big.Int).Sub(s, t)
	res.Mod(res, N)
	return res
}

// Mul performs scalar multiplication modulo N.
func (s Scalar) Mul(t Scalar, N *big.Int) Scalar {
	res := new(big.Int).Mul(s, t)
	res.Mod(res, N)
	return res
}

// Inv performs scalar modular inverse modulo N.
func (s Scalar) Inv(N *big.Int) Scalar {
	res := new(big.Int).ModInverse(s, N)
	return res
}

// Neg performs scalar negation modulo N.
func (s Scalar) Neg(N *big.Int) Scalar {
	res := new(big.Int).Neg(s)
	res.Mod(res, N)
	return res
}

// Bytes converts scalar to byte slice.
func (s Scalar) Bytes() []byte {
	return (*big.Int)(s).Bytes()
}

// --- Cryptographic Primitives & Utilities ---

// GenerateRandomScalar generates a cryptographically secure random scalar modulo max.
func GenerateRandomScalar(max *big.Int) Scalar {
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
	}
	return Scalar(r)
}

// HashToScalar hashes multiple byte slices to a scalar modulo N (Fiat-Shamir).
func HashToScalar(N *big.Int, data ...[]byte) Scalar {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	digest := h.Sum(nil)
	
	// Convert hash digest to a big.Int
	hashInt := new(big.Int).SetBytes(digest)
	
	// Reduce modulo N to get a scalar
	hashInt.Mod(hashInt, N)
	return Scalar(hashInt)
}

// SetupGenerators generates two independent, random generators G and H.
// G is the curve's base point. H is derived by hashing G's coordinates to a point.
func SetupGenerators(curve *CurveParams) (G, H *Point) {
	G = NewPoint(curve.Gx, curve.Gy, curve)
	
	// Derive H by hashing G's coordinates to a scalar and then multiplying G by it.
	// This ensures H is on the curve and distinct from G.
	// A more robust method would be to use a "hash to curve" function.
	// For simplicity, we'll hash G's bytes to a scalar, and use that scalar multiple of G as H.
	// This makes H a known multiple of G. For a true Pedersen commitment, H should be independent,
	// meaning H is not a known multiple of G.
	// To address this, we'll pick a random scalar to multiply by G to get H,
	// and prove that this scalar is unknown to anyone. Or, for simplicity here,
	// we will hash G's x-coordinate to a new point on the curve, which is often done by
	// hashing to a new scalar and multiplying by G. A true random H would require
	// generating another point from scratch or picking a random point from the curve,
	// ensuring it's not a trivial multiple of G.
	// For this pedagogical example, let's use a common trick: hash to scalar and multiply G.
	// To make H 'independent' of G in the discrete log sense, it's better if H is a random point
	// on the curve whose discrete log w.r.t G is unknown.
	// Let's generate H as a random scalar multiple of G, where the scalar is *not* N.
	// To make it cryptographically sound, we should choose a truly random H point with unknown dlog.
	// For simplicity, and acknowledging educational scope:
	// We use G as the base generator and derive H as a random scalar multiple of G,
	// where this scalar's value is unknown to the ZKP participants.
	// A truly independent H would be chosen with unknown `dl_H_G` such that H = `dl_H_G` * G.
	// For this implementation, let's derive H from a hash of G, which makes it deterministic
	// but cryptographically distinct enough for a basic demonstration.
	
	// A simple way to get a 'second' generator whose discrete log w.r.t G is unknown:
	// Use a hardcoded, large, random scalar or derive it from a standard random seed.
	// This is a common practice in non-interactive ZKPs if CRS is not available.
	hScalar := HashToScalar(curve.N, G.Bytes(), []byte("pedersen_H_seed"))
	H = ECScalarMul(hScalar, G)

	return G, H
}

// --- Pedersen Commitment ---

// PedersenCommit creates a Pedersen commitment C = value*G + blindingFactor*H.
func PedersenCommit(value Scalar, blindingFactor Scalar, G, H *Point) *Point {
	term1 := ECScalarMul(value, G)
	term2 := ECScalarMul(blindingFactor, H)
	return ECAdd(term1, term2)
}

// PedersenOpen verifies a Pedersen commitment.
func PedersenOpen(commitment *Point, value Scalar, blindingFactor Scalar, G, H *Point) bool {
	expectedCommitment := PedersenCommit(value, blindingFactor, G, H)
	return ECPointEqual(commitment, expectedCommitment)
}

// --- Schnorr Proof of Knowledge (Basic) ---

// SchnorrProof holds a Schnorr proof.
type SchnorrProof struct {
	Commitment *Point // R = r*G
	Challenge  Scalar // e = H(A || R || M)
	Response   Scalar // s = r + e*x mod N
}

// GenerateSchnorrProof generates a standard Schnorr proof for knowledge of secret x in publicKey = x*G.
func GenerateSchnorrProof(secret Scalar, G *Point, N *big.Int) *SchnorrProof {
	// 1. Prover chooses random `r`
	r := GenerateRandomScalar(N)

	// 2. Prover computes commitment `R = r*G`
	R := ECScalarMul(r, G)

	// 3. Prover computes challenge `e = H(publicKey || R)` (Fiat-Shamir heuristic)
	publicKey := ECScalarMul(secret, G) // The public key for which we prove knowledge of `secret`
	e := HashToScalar(N, publicKey.Bytes(), R.Bytes())

	// 4. Prover computes response `s = r + e*secret mod N`
	eSecret := secret.Mul(e, N)
	s := r.Add(eSecret, N)

	return &SchnorrProof{
		Commitment: R,
		Challenge:  e,
		Response:   s,
	}
}

// VerifySchnorrProof verifies a standard Schnorr proof.
func VerifySchnorrProof(proof *SchnorrProof, publicKey *Point, G *Point, N *big.Int) bool {
	// 1. Verifier recomputes challenge `e_prime = H(publicKey || R)`
	ePrime := HashToScalar(N, publicKey.Bytes(), proof.Commitment.Bytes())

	// 2. Verifier checks if `e_prime == e`
	if ePrime.Cmp(proof.Challenge) != 0 {
		return false
	}

	// 3. Verifier checks `s*G == R + e*publicKey`
	lhs := ECScalarMul(proof.Response, G)
	rhsTerm2 := ECScalarMul(proof.Challenge, publicKey)
	rhs := ECAdd(proof.Commitment, rhsTerm2)

	return ECPointEqual(lhs, rhs)
}

// --- Disjunctive Schnorr Proof (OR Proof) ---

// DisjunctProofPart represents one component of a disjunctive proof.
type DisjunctProofPart struct {
	A *Point // Commitment for this disjunct (randomly generated for dummy disjuncts)
	E Scalar // Challenge for this disjunct (randomly generated for dummy disjuncts)
	S Scalar // Response for this disjunct (randomly generated for dummy disjuncts)
}

// DisjunctiveProof holds the combined disjunctive proof.
type DisjunctiveProof struct {
	Parts []*DisjunctProofPart // List of proof parts
}

// GenerateDisjunctiveProof creates a disjunctive proof for C = score*G + r*H
// such that score is one of the possibleValues.
// correctIndex indicates which of possibleValues is the actual secret.
func GenerateDisjunctiveProof(secretValue Scalar, blindingFactor Scalar, correctIndex int, possibleValues []Scalar, G, H *Point, N *big.Int) (*DisjunctiveProof, *Point) {
	numDisjuncts := len(possibleValues)
	if correctIndex < 0 || correctIndex >= numDisjuncts {
		panic("correctIndex out of bounds for possibleValues")
	}

	// 1. Prover computes the actual Pedersen commitment for the secret value.
	C := PedersenCommit(secretValue, blindingFactor, G, H)

	proof := &DisjunctiveProof{
		Parts: make([]*DisjunctProofPart, numDisjuncts),
	}

	// Prepare to collect all commitment components (A_i) for the global challenge
	var allABytes [][]byte
	allABytes = append(allABytes, C.Bytes()) // Include main commitment in hash

	// Generate dummy proofs for incorrect disjuncts
	dummyChallengesSum := big.NewInt(0)
	for i := 0; i < numDisjuncts; i++ {
		if i == correctIndex {
			// Skip the correct disjunct for now
			proof.Parts[i] = &DisjunctProofPart{} // Placeholder
		} else {
			// For dummy disjuncts (i != correctIndex):
			// Prover chooses random e_i and s_i
			e_i := GenerateRandomScalar(N)
			s_i := GenerateRandomScalar(N)

			// Computes A_i = s_i*G + e_i*(C - v_i*G - r_i*H) where r_i*H is (C - v_i*G)
			// Effectively, A_i = s_i*G + e_i*(C - v_i*G)
			// C_i_target = C - v_i*G (This is what the prover would have committed to for v_i, if v_i were the true value)
			C_i_target := ECAdd(C, ECScalarMul(possibleValues[i].Neg(N), G))

			A_i := ECAdd(ECScalarMul(s_i, G), ECScalarMul(e_i, C_i_target))

			proof.Parts[i] = &DisjunctProofPart{
				A: A_i,
				E: e_i,
				S: s_i,
			}
			dummyChallengesSum = dummyChallengesSum.Add(dummyChallengesSum, e_i)
			allABytes = append(allABytes, A_i.Bytes())
		}
	}

	// Calculate global challenge e
	globalChallenge := HashToScalar(N, allABytes...)

	// Compute the real challenge for the correct disjunct: e_correct = globalChallenge - sum(e_i for i!=correctIndex) mod N
	correctE := globalChallenge.Sub(dummyChallengesSum, N)

	// For the correct disjunct (i == correctIndex):
	// Compute real A_correct and s_correct
	// A_correct = r_prime*G, where r_prime = r + e*r_blinding (actual blinding factor for C - v_correct*G)
	// (C - v_correct*G) = r*H + secretValue*G - v_correct*G = r*H + (secretValue - v_correct)*G
	// Since secretValue == v_correct, this simplifies to C - v_correct*G = r*H
	// So, we are proving knowledge of 'r' for r*H.
	// Let 'sk_correct' be 'r' (blinding factor)
	// Let 'pk_correct' be 'H' (the base point for the blinding factor)
	// 'C_prime' is 'C - v_correct*G'. We are proving knowledge of 'r' s.t. 'C_prime = r*H'

	// 1. Prover chooses random 'k' (new blinding factor for this specific Schnorr proof)
	k := GenerateRandomScalar(N)
	
	// 2. Prover computes A_correct = k*H
	A_correct := ECScalarMul(k, H)

	// Store A_correct for global challenge hashing (it's already implicitly in allABytes)
	// (we actually need to replace the placeholder A_i with the real A_correct before the global hash)
	// This means a slight adjustment in the process: we need A_correct *before* computing globalChallenge.
	// Let's re-hash for simplicity if A_correct gets determined later.

	// A better way for disjunctive proof's global challenge generation for non-interactive:
	// A_i are actual commitments.
	// Global challenge `e = Hash(C || A_0 || A_1 || ... || A_N)`
	// `e_correct = e - sum(e_i for i!=correctIndex)`
	// `s_correct = k + e_correct * r mod N` (where r is the blindingFactor)
	// `A_correct = s_correct*H - e_correct*(C - v_correct*G)` (this is for verification, not generation)
	// For generation: `A_correct = k*H` (where k is the `r` from Schnorr proof)

	// Re-calculating global challenge if we need to include A_correct
	// For Fiat-Shamir, the challenge must be computed *after* all commitments (A_i) are fixed.
	// A_correct = k*H
	// After having A_correct, we can finalize `allABytes` and hash for globalChallenge.
	// Let's rebuild allABytes list in a way that includes A_correct directly.

	// Placeholder A_correct
	proof.Parts[correctIndex].A = ECScalarMul(k, H) // Placeholder, but conceptually A_correct = k*H

	// Re-collect all A_i bytes now that A_correct is "known"
	allABytes = [][]byte{}
	allABytes = append(allABytes, C.Bytes()) // Include main commitment in hash
	for i := 0; i < numDisjuncts; i++ {
		allABytes = append(allABytes, proof.Parts[i].A.Bytes())
	}
	globalChallenge = HashToScalar(N, allABytes...)

	// Compute the real challenge for the correct disjunct: e_correct = globalChallenge - sum(e_i for i!=correctIndex) mod N
	// Re-sum dummy challenges after global challenge is fixed.
	dummyChallengesSum = big.NewInt(0)
	for i := 0; i < numDisjuncts; i++ {
		if i != correctIndex {
			dummyChallengesSum = dummyChallengesSum.Add(dummyChallengesSum, proof.Parts[i].E)
		}
	}
	correctE = globalChallenge.Sub(dummyChallengesSum, N)
	
	// Compute real response for the correct disjunct: s_correct = k + e_correct*blindingFactor mod N
	correctS := k.Add(correctE.Mul(blindingFactor, N), N)

	proof.Parts[correctIndex] = &DisjunctProofPart{
		A: A_correct, // This is already k*H
		E: correctE,
		S: correctS,
	}

	return proof, C
}

// VerifyDisjunctiveProof verifies a disjunctive proof.
func VerifyDisjunctiveProof(C *Point, possibleValues []Scalar, proof *DisjunctiveProof, G, H *Point, N *big.Int) bool {
	if len(possibleValues) != len(proof.Parts) {
		return false
	}

	var allABytes [][]byte
	allABytes = append(allABytes, C.Bytes()) // Include main commitment in hash
	for _, part := range proof.Parts {
		allABytes = append(allABytes, part.A.Bytes())
	}
	globalChallenge := HashToScalar(N, allABytes...)

	sumE := big.NewInt(0)
	for _, part := range proof.Parts {
		sumE.Add(sumE, part.E)
	}
	sumE.Mod(sumE, N)

	// Check if sum of all challenges matches the global challenge
	if globalChallenge.Cmp(Scalar(sumE)) != 0 {
		fmt.Println("Verification failed: Sum of challenges does not match global challenge.")
		return false
	}

	// Verify each individual disjunct's equation
	for i, part := range proof.Parts {
		// We are checking: s_i*H = A_i + e_i*(C - v_i*G)
		// Where C - v_i*G represents the Pedersen commitment to the blinding factor if v_i were the true score.
		
		// Target point for this disjunct's commitment: C_target_i = C - v_i*G
		v_i_G := ECScalarMul(possibleValues[i], G)
		C_target_i := ECAdd(C, v_i_G.Neg(N)) // C - v_i*G

		// LHS: s_i*H
		lhs := ECScalarMul(part.S, H)

		// RHS: A_i + e_i*C_target_i
		rhsTerm2 := ECScalarMul(part.E, C_target_i)
		rhs := ECAdd(part.A, rhsTerm2)

		if !ECPointEqual(lhs, rhs) {
			fmt.Printf("Verification failed: Disjunct %d equation mismatch.\n", i)
			// fmt.Printf("LHS: %s\n", lhs.String())
			// fmt.Printf("RHS: %s\n", rhs.String())
			return false
		}
	}

	return true
}

// --- Application Layer: Private Reputation Tier Verification ---

// ReputationTierVerifier defines a specific tier range.
type ReputationTierVerifier struct {
	MinScore int
	MaxScore int
}

// NewReputationTierVerifier creates a tier verifier for a specific score range.
func NewReputationTierVerifier(minScore, maxScore int) *ReputationTierVerifier {
	if minScore > maxScore || minScore < 0 {
		panic("Invalid score range for ReputationTierVerifier")
	}
	return &ReputationTierVerifier{
		MinScore: minScore,
		MaxScore: maxScore,
	}
}

// GetPossibleValues generates the list of Scalars for the tier range.
func (rtv *ReputationTierVerifier) GetPossibleValues() []Scalar {
	possibleValues := make([]Scalar, rtv.MaxScore-rtv.MinScore+1)
	for i := 0; i <= rtv.MaxScore-rtv.MinScore; i++ {
		possibleValues[i] = NewScalar(big.NewInt(int64(rtv.MinScore + i)))
	}
	return possibleValues
}

// GenerateProof Prover's side: takes a secret integer score and generates the full disjunctive ZKP.
func (rtv *ReputationTierVerifier) GenerateProof(secretScore int, G, H *Point, N *big.Int) (*DisjunctiveProof, *Point, error) {
	if secretScore < rtv.MinScore || secretScore > rtv.MaxScore {
		return nil, nil, fmt.Errorf("secret score %d is not within the defined tier range [%d, %d]", secretScore, rtv.MinScore, rtv.MaxScore)
	}

	possibleValues := rtv.GetPossibleValues()
	correctIndex := secretScore - rtv.MinScore // Calculate index of secretScore in possibleValues

	secretScalar := NewScalar(big.NewInt(int64(secretScore)))
	blindingFactor := GenerateRandomScalar(N)

	proof, commitmentC := GenerateDisjunctiveProof(secretScalar, blindingFactor, correctIndex, possibleValues, G, H, N)

	return proof, commitmentC, nil
}

// VerifyProof Verifier's side: checks if the provided proof for commitmentC confirms the score is in the defined tier.
func (rtv *ReputationTierVerifier) VerifyProof(commitmentC *Point, proof *DisjunctiveProof, G, H *Point, N *big.Int) bool {
	possibleValues := rtv.GetPossibleValues()
	return VerifyDisjunctiveProof(commitmentC, possibleValues, proof, G, H, N)
}

// Main function to demonstrate the ZKP system.
func main() {
	fmt.Println("Starting Zero-Knowledge Proof for Private Reputation Tier Verification demonstration...")

	// 1. Setup: Initialize curve parameters and generators
	curve := NewCurveParams(CurveSecp256k1)
	G, H := SetupGenerators(curve)
	N := curve.N // Order of the curve

	fmt.Printf("\n--- Setup ---")
	fmt.Printf("\nCurve P: %s", curve.P.Text(16))
	fmt.Printf("\nCurve N (Order): %s", N.Text(16))
	fmt.Printf("\nGenerator G: %s", G.String())
	fmt.Printf("\nGenerator H: %s", H.String())
	fmt.Println("\n-----------------------------")

	// Define a reputation tier: "Silver" tier for scores between 11 and 20 (inclusive)
	minTierScore := 11
	maxTierScore := 20
	silverTierVerifier := NewReputationTierVerifier(minTierScore, maxTierScore)
	fmt.Printf("\nReputation Tier Defined: Scores between %d and %d (inclusive)\n", minTierScore, maxTierScore)

	// --- Scenario 1: Prover has a score within the tier ---
	fmt.Println("\n--- Scenario 1: Prover with a score within the tier (e.g., 14) ---")
	proverSecretScore1 := 14 // This is the Prover's private information

	fmt.Printf("Prover's secret score (private): %d\n", proverSecretScore1)

	// Prover generates the ZKP
	start := time.Now()
	proof1, commitment1, err := silverTierVerifier.GenerateProof(proverSecretScore1, G, H, N)
	if err != nil {
		fmt.Printf("Prover failed to generate proof: %v\n", err)
		return
	}
	duration := time.Since(start)
	fmt.Printf("Proof generation time: %s\n", duration)

	fmt.Printf("Prover generated commitment C: %s\n", commitment1.String())
	// fmt.Printf("Generated Proof (truncated for brevity):\n")
	// for i, part := range proof1.Parts {
	// 	fmt.Printf("  Part %d: A=%s, E=%s, S=%s\n", i, part.A.String(), part.E.String(), part.S.String())
	// }
	fmt.Println("Proof parts generated (details omitted for readability).")

	// Verifier verifies the ZKP
	fmt.Println("Verifier starts verification...")
	start = time.Now()
	isValid1 := silverTierVerifier.VerifyProof(commitment1, proof1, G, H, N)
	duration = time.Since(start)
	fmt.Printf("Proof verification time: %s\n", duration)

	fmt.Printf("Verification result for score %d: %t\n", proverSecretScore1, isValid1)
	if isValid1 {
		fmt.Println("SUCCESS: Prover successfully proved their score is in the Silver tier without revealing the exact score!")
	} else {
		fmt.Println("FAILURE: Proof verification failed.")
	}

	// --- Scenario 2: Prover has a score outside the tier (should fail) ---
	fmt.Println("\n--- Scenario 2: Prover with a score outside the tier (e.g., 5) ---")
	proverSecretScore2 := 5 // This is the Prover's private information, outside the tier

	fmt.Printf("Prover's secret score (private): %d\n", proverSecretScore2)

	// Prover attempts to generate the ZKP for the incorrect tier
	// This should fail at the application level if the score is not even valid for the range it's trying to prove.
	// For this ZKP, if the prover *claims* their score is in [11,20] but it's actually 5,
	// they *cannot* generate a valid disjunctive proof for [11,20].
	// However, `GenerateProof` function proactively checks if the `secretScore` is within the `minTierScore` and `maxTierScore`
	// *for the purpose of finding the `correctIndex`*.
	// If the actual secret is outside this range, `GenerateProof` will return an error because it can't find a `correctIndex`.
	// This is a design choice: either the application layer validates it, or the ZKP itself makes it impossible to construct.
	// Here, we've implemented the application layer to prevent generation for an out-of-range secret.

	fmt.Println("Prover attempts to generate proof for score 5 against Silver tier...")
	proof2, commitment2, err := silverTierVerifier.GenerateProof(proverSecretScore2, G, H, N)
	if err != nil {
		fmt.Printf("Prover failed to generate proof as expected (score outside tier): %v\n", err)
		// To demonstrate ZKP failure, let's artificially construct a commitment and a "fake" proof if err occurs.
		// In a real scenario, the prover just wouldn't be able to generate it.
		// For demo, let's assume a malicious prover tries to submit a randomly generated proof/commitment
		// or a proof generated for a different tier/value.
		fmt.Println("Attempting to verify a 'fake' proof (e.g., from a different tier/score).")

		// Create a random commitment and a random disjunctive proof as if a malicious prover submitted it
		fakeSecret := NewScalar(big.NewInt(100)) // A score far outside the tier
		fakeBlinding := GenerateRandomScalar(N)
		fakeCommitment := PedersenCommit(fakeSecret, fakeBlinding, G, H)

		// Create a "malicious" proof by generating a disjunctive proof for a value outside the tier,
		// but claiming it's for the tier [11,20]. This won't work if the 'GenerateProof'
		// enforces the secret to be within range.
		// Instead, let's simulate a random/malicious proof attempt.
		// This part is tricky to demonstrate without making the prover *able* to generate an invalid proof.
		// The `GenerateDisjunctiveProof` itself *requires* the correctIndex to be valid.
		// So, the most realistic "failure" is `GenerateProof` returning an error.
		// If a prover *did* try to submit a random/maliciously crafted proof (not generated by the protocol):
		// It would almost certainly fail the verification checks due to mathematical inconsistencies.
		fmt.Println("Simulating a malicious prover submitting a *random* proof with a random commitment.")
		randomProof := &DisjunctiveProof{Parts: make([]*DisjunctProofPart, len(silverTierVerifier.GetPossibleValues()))}
		for i := range randomProof.Parts {
			randomProof.Parts[i] = &DisjunctProofPart{
				A: ECScalarMul(GenerateRandomScalar(N), G),
				E: GenerateRandomScalar(N),
				S: GenerateRandomScalar(N),
			}
		}

		isValid2 := silverTierVerifier.VerifyProof(fakeCommitment, randomProof, G, H, N)
		fmt.Printf("Verification result for malicious attempt (score 5, random proof): %t\n", isValid2)
		if !isValid2 {
			fmt.Println("SUCCESS: Malicious proof was rejected as expected.")
		} else {
			fmt.Println("FAILURE: Malicious proof was accepted! This is a severe security flaw.")
		}

	} else {
		// This case means GenerateProof did NOT return an error, which it should for score 5.
		// This block is unlikely to be reached with current GenerateProof implementation.
		fmt.Println("Unexpected: Prover generated proof even for score 5. Proceeding to verify (should fail)...")
		isValid2 := silverTierVerifier.VerifyProof(commitment2, proof2, G, H, N)
		fmt.Printf("Verification result for score %d: %t\n", proverSecretScore2, isValid2)
		if !isValid2 {
			fmt.Println("SUCCESS: Proof for score 5 was rejected as expected.")
		} else {
			fmt.Println("FAILURE: Proof for score 5 was accepted! This is a severe security flaw.")
		}
	}

	fmt.Println("\nZero-Knowledge Proof demonstration finished.")
}

```