Okay, here is a Golang implementation of a Zero-Knowledge Proof scheme.

Instead of a basic "prove knowledge of a secret value", we will implement a **Selective Credential Proof** based on a Disjunction of Schnorr proofs (OR-Proof). This is a more advanced concept where the prover proves they know a secret key (`x_i`) corresponding to *one* public key (`Y_i = g^{x_i}`) within a public list of potential keys (`Y_0, Y_1, ..., Y_{k-1}`), without revealing *which* key they know.

This is useful for scenarios like:
*   Proving membership in a group without revealing your specific identifier.
*   Proving possession of an attribute credential from a list of accepted credentials.
*   Simplified revocation checking (proving you *don't* know a key from a revoked list).

We will use elliptic curve cryptography (`crypto/elliptic`, `math/big`) and the Fiat-Shamir heuristic to make the proof non-interactive. We will avoid using large external ZKP libraries to meet the "don't duplicate open source" constraint (relative to full frameworks), implementing the core logic ourselves on top of standard Go crypto primitives.

**Outline:**

1.  **Parameters Setup:** Define the elliptic curve and generator point (`g`).
2.  **Key Generation:** Create secret/public key pairs (`x`, `Y=g^x`).
3.  **Eligibility List:** A public list of potential public keys (`Y_0, ..., Y_{k-1}`).
4.  **Prover's Secret:** The prover holds one specific secret key (`x_i`) and its corresponding public key (`Y_i`) from the eligibility list.
5.  **Proof Structure:** The data the prover sends to the verifier.
6.  **Proving Algorithm:** Steps the prover takes to construct the proof.
7.  **Verification Algorithm:** Steps the verifier takes to check the proof.
8.  **Serialization/Deserialization:** Functions to convert data structures to/from bytes.
9.  **Helper Functions:** Cryptographic utilities (hashing, point operations, scalar arithmetic).

**Function Summary (20+ functions):**

1.  `GenerateParams()`: Creates cryptographic parameters (curve, generator).
2.  `GenerateAttributeKey(params)`: Generates a new random secret `x` and public `Y = g^x`.
3.  `CreateEligibilityList(publicKeys)`: Creates a public list of `Y` points.
4.  `NewProverSecret(secretKey, publicKey)`: Creates a struct holding the prover's specific known key pair.
5.  `NewProof()`: Initializes an empty proof structure.
6.  `ProveKnowledge(params, eligibilityList, proverSecret)`: The main function to generate the non-interactive ZKP.
7.  `VerifyProof(params, eligibilityList, proof)`: The main function to verify the ZKP.
8.  `computeFiatShamirChallenge(params, commitmentsA)`: Computes the challenge hash from commitments.
9.  `pointToBytes(point)`: Converts an elliptic curve point to compressed bytes.
10. `bytesToPoint(params, b)`: Converts compressed bytes back to an elliptic curve point.
11. `scalarToBytes(scalar)`: Converts a big.Int scalar to bytes.
12. `bytesToScalar(params, b)`: Converts bytes back to a big.Int scalar (checking bounds).
13. `addScalars(params, s1, s2)`: Adds two scalars modulo curve order.
14. `subScalars(params, s1, s2)`: Subtracts s2 from s1 modulo curve order.
15. `mulScalars(params, s1, s2)`: Multiplies two scalars modulo curve order.
16. `modInverse(params, s)`: Computes the modular multiplicative inverse of a scalar.
17. `pointNeg(params, point)`: Computes the negation of a point.
18. `scalarPointMul(params, scalar, point)`: Scalar multiplication of a point.
19. `scalarBaseMul(params, scalar)`: Scalar multiplication of the base point G.
20. `addPoints(params, p1, p2)`: Adds two points.
21. `Proof.MarshalBinary()`: Serializes the proof struct using Gob.
22. `Proof.UnmarshalBinary(data)`: Deserializes the proof struct using Gob.
23. `Params.MarshalBinary()`: Serializes params.
24. `Params.UnmarshalBinary(data)`: Deserializes params.
25. `EligibilityList.MarshalBinary()`: Serializes eligibility list.
26. `EligibilityList.UnmarshalBinary(data)`: Deserializes eligibility list.
27. `ProverSecret.MarshalBinary()`: Serializes prover secret.
28. `ProverSecret.UnmarshalBinary(data)`: Deserializes prover secret.
29. `hashBigInt(i)`: Hashes a big.Int.
30. `hashBytes(b)`: Hashes bytes.
31. `hashPoints(points)`: Hashes a list of points.

```golang
package selectivezkp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
)

// --- Data Structures ---

// Params holds the cryptographic parameters for the ZKP scheme.
// Uses P-256 elliptic curve.
type Params struct {
	Curve elliptic.Curve
	G     *elliptic.Point // Base point (generator)
	Order *big.Int        // Order of the curve subgroup
}

// EligibilityList holds the list of public keys (Y_i) that the prover might know a secret key for.
type EligibilityList struct {
	PublicKeys []*elliptic.Point
}

// ProverSecret holds the specific secret key (x_i) and its corresponding public key (Y_i) the prover possesses.
type ProverSecret struct {
	SecretKey *big.Int
	PublicKey *elliptic.Point
}

// Proof holds the zero-knowledge proof data for the selective credential proof.
// This structure contains elements derived from the disjunction of Schnorr proofs.
// A_j: Commitment points for each possible public key in the EligibilityList.
// s_j: Response scalars for each possible public key.
// c_j: Challenge scalars for each possible public key.
// Note: Only k-1 of the c_j values are randomly chosen; one is derived.
// The proof contains *all* A_j, *all* s_j, and *all* c_j for verifier convenience,
// ensuring sum(c_j) == FiatShamirHash(A_j).
type Proof struct {
	A []*elliptic.Point
	S []*big.Int
	C []*big.Int
}

// --- Core ZKP Functions ---

// GenerateParams creates and returns the common cryptographic parameters.
// Uses the P256 curve.
func GenerateParams() (*Params, error) {
	curve := elliptic.P256()
	// ScalarBaseMult returns G = g^1
	gx, gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	g := elliptic.NewPoint(gx, gy)
	order := curve.Params().N // The order of the base point G

	if g.X == nil || g.Y == nil || order == nil {
		return nil, fmt.Errorf("failed to generate curve parameters or base point")
	}

	return &Params{
		Curve: curve,
		G:     g,
		Order: order,
	}, nil
}

// GenerateAttributeKey creates a new random secret key (scalar) and its corresponding public key (point).
// Y = g^x
func GenerateAttributeKey(params *Params) (*big.Int, *elliptic.Point, error) {
	// Generate random secret key x (a scalar)
	x, err := rand.Int(rand.Reader, params.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate secret key: %v", err)
	}

	// Compute public key Y = g^x
	Y := scalarBaseMul(params, x)
	if Y.X == nil || Y.Y == nil {
		return nil, nil, fmt.Errorf("failed to compute public key")
	}

	return x, Y, nil
}

// CreateEligibilityList creates a new EligibilityList struct from a slice of public keys.
func CreateEligibilityList(publicKeys []*elliptic.Point) *EligibilityList {
	// Defensive copy of the slice to prevent external modification
	keyList := make([]*elliptic.Point, len(publicKeys))
	copy(keyList, publicKeys)
	return &EligibilityList{PublicKeys: keyList}
}

// NewProverSecret creates a ProverSecret struct.
func NewProverSecret(secretKey *big.Int, publicKey *elliptic.Point) *ProverSecret {
	return &ProverSecret{
		SecretKey: new(big.Int).Set(secretKey), // Defensive copy
		PublicKey: elliptic.NewPoint(publicKey.X, publicKey.Y), // Defensive copy
	}
}

// NewProof creates an empty Proof struct.
func NewProof() *Proof {
	return &Proof{
		A: []*elliptic.Point{},
		S: []*big.Int{},
		C: []*big.Int{},
	}
}

// ProveKnowledge generates a non-interactive zero-knowledge proof
// that the prover knows a secret key for one of the public keys in the eligibility list,
// without revealing which one. This implements a Fiat-Shamir transformed OR-Proof (Disjunction of Schnorr proofs).
// The prover must know the secretKey for *one* of the PublicKeys in the EligibilityList.
func ProveKnowledge(params *Params, eligibilityList *EligibilityList, proverSecret *ProverSecret) (*Proof, error) {
	k := len(eligibilityList.PublicKeys)
	if k == 0 {
		return nil, fmt.Errorf("eligibility list cannot be empty")
	}

	// 1. Find the index `i` of the prover's known public key in the eligibility list.
	//    This index is needed internally by the prover but *not* revealed in the proof.
	knownIndex := -1
	for i := 0; i < k; i++ {
		if eligibilityList.PublicKeys[i].X.Cmp(proverSecret.PublicKey.X) == 0 &&
			eligibilityList.PublicKeys[i].Y.Cmp(proverSecret.PublicKey.Y) == 0 {
			knownIndex = i
			break
		}
	}
	if knownIndex == -1 {
		return nil, fmt.Errorf("prover's public key not found in eligibility list")
	}

	A := make([]*elliptic.Point, k)
	s := make([]*big.Int, k)
	cAll := make([]*big.Int, k) // This slice will hold all c_j values (k-1 random, 1 derived)

	// Store fake challenges (k-1 random c_j for j != knownIndex) to sum them later
	fakeChallengesSum := big.NewInt(0)
	fakeChallenges := make([]*big.Int, 0, k-1) // Store only the *randomly chosen* challenges

	// 2. For each index j in 0..k-1:
	//    If j is the known index (i), compute the commitment A_i normally using a random nonce r_i.
	//    If j is not the known index (j != i), pick random challenge c_j and response s_j,
	//    and compute A_j such that g^{s_j} == A_j * Y_j^{c_j} holds *by construction*.
	var rKnown *big.Int // Store the random nonce for the true proof part

	for j := 0; j < k; j++ {
		if j == knownIndex {
			// True proof part (index i)
			var err error
			rKnown, err = rand.Int(rand.Reader, params.Order)
			if err != nil {
				return nil, fmt.Errorf("failed to generate nonce r for known key: %v", err)
			}
			A[j] = scalarBaseMul(params, rKnown) // A_i = g^{r_i}
		} else {
			// Fake proof parts (index j != i)
			var err error
			// Choose random c_j and s_j
			cRandom, err := rand.Int(rand.Reader, params.Order)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random challenge c_%d: %v", j, err)
			}
			sRandom, err := rand.Int(rand.Reader, params.Order)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random response s_%d: %v", j, err)
			}

			// Compute A_j such that g^{s_j} == A_j * Y_j^{c_j}
			// A_j = g^{s_j} * Y_j^{-c_j}
			// Y_j^{-c_j} = Y_j^{order - c_j} (point exponentiation with negative scalar is point multiplication by scalar and negation)
			cYj := scalarPointMul(params, cRandom, eligibilityList.PublicKeys[j]) // c_j * Y_j
			cYjNeg := pointNeg(params, cYj)                                       // -(c_j * Y_j)

			A[j] = addPoints(params, scalarBaseMul(params, sRandom), cYjNeg) // A_j = s_j * G - c_j * Y_j  <-- simplified notation

			s[j] = sRandom
			cAll[j] = cRandom // Temporarily store the random challenge here
			fakeChallengesSum = addScalars(params, fakeChallengesSum, cRandom)
			fakeChallenges = append(fakeChallenges, cRandom) // Store the random challenge
		}
	}

	// 3. Compute the Fiat-Shamir challenge 'c' from all commitments A_j.
	cTotal := computeFiatShamirChallenge(params, A)

	// 4. Compute the true challenge c_i for the known index: c_i = c - sum(c_j for j != i).
	// Need to ensure c_Total >= fakeChallengesSum before subtraction, or use modular arithmetic directly.
	// Since we're working modulo Order, subtraction is just adding the modular inverse.
	cKnown := subScalars(params, cTotal, fakeChallengesSum)
	cAll[knownIndex] = cKnown // Store the derived challenge in the main challenge slice

	// 5. Compute the true response s_i for the known index: s_i = r_i + c_i * x_i.
	// Note: s_j for j != i were already set in step 2.
	cxKnown := mulScalars(params, cKnown, proverSecret.SecretKey) // c_i * x_i
	sKnown := addScalars(params, rKnown, cxKnown)                  // r_i + c_i * x_i
	s[knownIndex] = sKnown // Store the derived response

	// 6. The proof consists of all A_j, all s_j, and all c_j.
	// We need to ensure the c_j list sent in the proof can be verified against the total hash.
	// A standard approach includes all c_j in the proof.
	// The verifier checks sum(c_j) == Hash(A_j) and g^{s_j} == A_j * Y_j^{c_j} for ALL j.
	// The 'fake' components (j != i) will satisfy the equation by construction using the included c_j and s_j.
	// The 'true' component (j == i) will satisfy the equation because s_i and c_i were derived correctly from the known x_i and r_i.

	// Ensure cAll has exactly k elements summing to cTotal.
	// We already stored the derived cKnown at cAll[knownIndex] and random cRandoms at cAll[j] for j!=knownIndex.
	// Now, collect the cAll values into a new slice to be stored in the Proof struct.
	cProof := make([]*big.Int, k)
	copy(cProof, cAll)

	proof := &Proof{
		A: A,       // Commitments
		S: s,       // Responses
		C: cProof,  // Challenges (k-1 random + 1 derived)
	}

	return proof, nil
}

// VerifyProof verifies the zero-knowledge proof that the prover knows a secret key
// for one of the public keys in the eligibility list.
func VerifyProof(params *Params, eligibilityList *EligibilityList, proof *Proof) (bool, error) {
	k := len(eligibilityList.PublicKeys)
	if k == 0 {
		return false, fmt.Errorf("eligibility list cannot be empty")
	}
	if len(proof.A) != k || len(proof.S) != k || len(proof.C) != k {
		return false, fmt.Errorf("proof dimensions mismatch: expected %d elements, got A:%d, S:%d, C:%d", k, len(proof.A), len(proof.S), len(proof.C))
	}

	// 1. Recompute the Fiat-Shamir challenge 'c' from the commitments A_j provided in the proof.
	cExpected := computeFiatShamirChallenge(params, proof.A)

	// 2. Check if the sum of challenges c_j provided in the proof equals the recomputed Fiat-Shamir challenge.
	cSumActual := big.NewInt(0)
	for _, cj := range proof.C {
		if cj == nil { // Should not happen with proper marshalling, but defensive
			return false, fmt.Errorf("nil challenge in proof C list")
		}
		cSumActual = addScalars(params, cSumActual, cj)
	}

	if cSumActual.Cmp(cExpected) != 0 {
		// fmt.Printf("Challenge sum mismatch: Expected %s, Got %s\n", cExpected.String(), cSumActual.String()) // Debug
		return false, fmt.Errorf("challenge sum mismatch")
	}

	// 3. For each index j in 0..k-1, check if the Schnorr equation holds: g^{s_j} == A_j * Y_j^{c_j}.
	// g^{s_j} is computed using scalarBaseMul(s_j).
	// A_j * Y_j^{c_j} is computed using addPoints(A_j, scalarPointMul(c_j, Y_j)).
	for j := 0; j < k; j++ {
		Yj := eligibilityList.PublicKeys[j]
		Aj := proof.A[j]
		sj := proof.S[j]
		cj := proof.C[j]

		if Yj == nil || Aj == nil || sj == nil || cj == nil { // Should not happen with proper marshalling
			return false, fmt.Errorf("nil element in proof or eligibility list at index %d", j)
		}

		// Left side of the equation: g^{s_j}
		leftSide := scalarBaseMul(params, sj)
		if leftSide.X == nil || leftSide.Y == nil {
			// fmt.Printf("Verification failed: failed to compute g^s_%d\n", j) // Debug
			return false, fmt.Errorf("verification failed: failed to compute g^s_%d", j)
		}

		// Right side of the equation: A_j * Y_j^{c_j}
		cYj := scalarPointMul(params, cj, Yj) // c_j * Y_j
		rightSide := addPoints(params, Aj, cYj) // A_j + (c_j * Y_j)
		if rightSide.X == nil || rightSide.Y == nil {
			// fmt.Printf("Verification failed: failed to compute A_%d + c_%d*Y_%d\n", j, j, j) // Debug
			return false, fmt.Errorf("verification failed: failed to compute A_%d + c_%d*Y_%d", j, j, j)
		}

		// Check if leftSide == rightSide
		if leftSide.X.Cmp(rightSide.X) != 0 || leftSide.Y.Cmp(rightSide.Y) != 0 {
			// fmt.Printf("Verification failed: equation check failed for index %d\n", j) // Debug
			return false, fmt.Errorf("verification failed: equation check failed for index %d", j)
		}
	}

	// If all checks passed, the proof is valid.
	return true, nil
}

// computeFiatShamirChallenge computes the hash used as the challenge in the Fiat-Shamir transformation.
// It hashes the concatenation of the byte representations of all commitment points.
func computeFiatShamirChallenge(params *Params, commitmentsA []*elliptic.Point) *big.Int {
	h := sha256.New()
	for _, p := range commitmentsA {
		h.Write(pointToBytes(p)) // Use compressed point representation
	}
	hashBytes := h.Sum(nil)

	// Convert hash to a scalar modulo the curve order
	// Need to handle potential edge case where hash >= order
	challenge := new(big.Int).SetBytes(hashBytes)
	return challenge.Mod(challenge, params.Order)
}

// --- Helper Cryptographic Functions ---

// pointToBytes converts an elliptic curve point to its compressed byte representation.
func pointToBytes(point *elliptic.Point) []byte {
	// Use Marshal which produces compressed points for P256 by default unless uncompressed is needed
	// Uncompressed: 0x04 || x || y
	// Compressed: 0x02 || x (if y is even) or 0x03 || x (if y is odd)
	// We need to handle the case of the point at infinity (often represented as (0,0))
	if point == nil || point.X == nil || point.Y == nil {
		// Represent point at infinity? Depends on curve implementation, but (0,0) is common.
		// P256 Marshal handles (0,0) as infinity and returns a specific byte.
		// For robustness, let's explicitly check if it's the point at infinity (usually (0,0))
		// P256's Marshal handles (0,0) correctly as the identity.
		if point.X != nil && point.Y != nil && point.X.Sign() == 0 && point.Y.Sign() == 0 {
			// Point at infinity bytes for P256 according to crypto/elliptic Marshal spec?
			// Check if Marshal(0,0) gives expected identity byte (often 0).
			// Let's just use Marshal directly and trust it handles (0,0) if it's the identity.
			// If point is genuinely nil, return empty or error placeholder. Empty bytes seem reasonable for nil point.
			return []byte{} // Or handle error appropriately
		}
		// Otherwise, marshal the point
		return elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y)
	}
	return elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y)
}

// bytesToPoint converts a compressed byte representation back to an elliptic curve point.
func bytesToPoint(params *Params, b []byte) *elliptic.Point {
	if len(b) == 0 {
		// Handle empty bytes potentially representing point at infinity or error
		// For P256, MarshalCompressed(0,0) returns 1 byte (0x00), Unmarshal will succeed with (0,0).
		// An empty byte slice likely represents an error during serialization.
		// Return point at infinity (0,0) or nil based on desired behavior. Nil seems safer if empty means error.
		return nil // Or elliptic.NewPoint(big.NewInt(0), big.NewInt(0)) if 0 bytes means identity
	}
	x, y := elliptic.UnmarshalCompressed(params.Curve, b)
	if x == nil || y == nil {
		// Unmarshalling failed
		return nil
	}
	// Check if the point is actually on the curve. UnmarshalCompressed does NOT guarantee this for all inputs.
	if !params.Curve.IsOnCurve(x, y) {
		// fmt.Printf("Warning: Decoded point is not on curve: %v, %v\n", x, y) // Debug
		return nil // Not on curve
	}
	return elliptic.NewPoint(x, y)
}

// scalarToBytes converts a big.Int scalar to a fixed-width byte slice (32 bytes for P256).
func scalarToBytes(scalar *big.Int) []byte {
	// Pad or truncate to the size needed for the curve order.
	// P256 order fits in 32 bytes (256 bits).
	// big.Int.Bytes() gives minimum big-endian representation.
	// Pad with leading zeros if less than 32 bytes.
	scalarBytes := scalar.Bytes()
	bytesLen := (elliptic.P256().Params().BitSize + 7) / 8 // Should be 32
	if len(scalarBytes) > bytesLen {
		// This shouldn't happen if scalar is always modulo Order,
		// but clip if it does or return error. Clipping might lose information.
		// Returning error might be safer in a real system.
		// For this example, let's panic or return error if it's oversized.
		// Simpler: just pad if too short.
		// If scalar is zero, Bytes() returns nil slice. Handle this.
		if len(scalarBytes) == 0 && scalar.Sign() == 0 {
			scalarBytes = []byte{0} // Canonical representation of zero
		}
	}

	paddedBytes := make([]byte, bytesLen)
	copy(paddedBytes[bytesLen-len(scalarBytes):], scalarBytes)
	return paddedBytes
}

// bytesToScalar converts a fixed-width byte slice (32 bytes) to a big.Int scalar.
// It also checks if the scalar is within the valid range [0, Order-1].
func bytesToScalar(params *Params, b []byte) *big.Int {
	bytesLen := (params.Curve.Params().BitSize + 7) / 8 // Should be 32
	if len(b) != bytesLen {
		// fmt.Printf("Warning: Input byte slice has incorrect length for scalar: expected %d, got %d\n", bytesLen, len(b)) // Debug
		return nil // Incorrect length
	}
	scalar := new(big.Int).SetBytes(b)
	// Check if scalar is in the valid range [0, Order-1]
	if scalar.Sign() < 0 || scalar.Cmp(params.Order) >= 0 {
		// fmt.Printf("Warning: Decoded scalar is out of range [0, Order-1]: %v\n", scalar) // Debug
		return nil // Out of range
	}
	return scalar
}

// addScalars adds two scalars modulo the curve order.
func addScalars(params *Params, s1, s2 *big.Int) *big.Int {
	return new(big.Int).Add(s1, s2).Mod(new(big.Int), params.Order)
}

// subScalars subtracts s2 from s1 modulo the curve order.
func subScalars(params *Params, s1, s2 *big.Int) *big.Int {
	// (s1 - s2) mod N = (s1 + (N - s2)) mod N
	s2Neg := new(big.Int).Sub(params.Order, s2) // This is Order - s2, which is -s2 mod Order
	return addScalars(params, s1, s2Neg)
}

// mulScalars multiplies two scalars modulo the curve order.
func mulScalars(params *Params, s1, s2 *big.Int) *big.Int {
	return new(big.Int).Mul(s1, s2).Mod(new(big.Int), params.Order)
}

// modInverse computes the modular multiplicative inverse of a scalar modulo the curve order.
func modInverse(params *Params, s *big.Int) *big.Int {
	// Use Fermat's Little Theorem: s^(Order-2) mod Order
	// Or use the built-in big.Int.ModInverse
	if s.Sign() == 0 {
		// Inverse of 0 is undefined
		return nil
	}
	return new(big.Int).ModInverse(s, params.Order)
}

// pointNeg computes the negation of a point P(x, y) as P(x, -y mod p).
func pointNeg(params *Params, point *elliptic.Point) *elliptic.Point {
	if point == nil || point.X == nil || point.Y == nil {
		return nil // Handle nil point
	}
	// The y-coordinate in affine coordinates is negated modulo the field prime p
	// P256 uses a prime field. The y-coordinate negation is P.Y = curve.Params().P - point.Y
	negY := new(big.Int).Sub(params.Curve.Params().P, point.Y)
	// The point at infinity (0,0) is its own negation.
	if point.X.Sign() == 0 && point.Y.Sign() == 0 {
		return elliptic.NewPoint(big.NewInt(0), big.NewInt(0))
	}
	// Verify the new point is on the curve (it should be if point was on curve)
	if !params.Curve.IsOnCurve(point.X, negY) {
		// This should not happen for a point on curve (unless point was point at infinity, handled above)
		// fmt.Printf("Warning: Negated point is not on curve: %v, %v\n", point.X, negY) // Debug
		return nil // Should not return nil if point was valid
	}
	return elliptic.NewPoint(point.X, negY)
}


// scalarPointMul multiplies a scalar by a point.
// Alias for elliptic.Curve.ScalarMult, ensuring use of curve from params.
func scalarPointMul(params *Params, scalar *big.Int, point *elliptic.Point) *elliptic.Point {
	if point == nil || point.X == nil || point.Y == nil || scalar == nil {
		// Treat scalar*nil or nil*point as nil? Elliptic spec often treats P+0=P, P*0=0, P*1=P.
		// Let's align with ScalarMult which can handle nil inputs and returns identity (0,0) for scalar 0.
		// If point is nil and scalar is not 0, the result is undefined unless it's point at infinity.
		// Use the underlying curve method which handles edge cases.
		x, y := params.Curve.ScalarMult(point.X, point.Y, scalar.Bytes())
		return elliptic.NewPoint(x, y)
	}
	x, y := params.Curve.ScalarMult(point.X, point.Y, scalar.Bytes())
	return elliptic.NewPoint(x, y)
}

// scalarBaseMul multiplies a scalar by the base point G.
// Alias for elliptic.Curve.ScalarBaseMult, ensuring use of curve from params.
func scalarBaseMul(params *Params, scalar *big.Int) *elliptic.Point {
	if scalar == nil {
		// scalar 0 gives point at infinity (0,0)
		// ScalarBaseMult(nil) returns (0,0)
		x, y := params.Curve.ScalarBaseMult(nil)
		return elliptic.NewPoint(x, y)
	}
	x, y := params.Curve.ScalarBaseMult(scalar.Bytes())
	return elliptic.NewPoint(x, y)
}

// addPoints adds two points on the curve.
// Alias for elliptic.Curve.Add, ensuring use of curve from params.
func addPoints(params *Params, p1, p2 *elliptic.Point) *elliptic.Point {
	// Add handles nil points correctly (P + 0 = P)
	if p1 == nil || p1.X == nil || p1.Y == nil { // Treat as point at infinity if X or Y is nil
		p1 = elliptic.NewPoint(big.NewInt(0), big.NewInt(0))
	}
	if p2 == nil || p2.X == nil || p2.Y == nil { // Treat as point at infinity if X or Y is nil
		p2 = elliptic.NewPoint(big.NewInt(0), big.NewInt(0))
	}

	x, y := params.Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return elliptic.NewPoint(x, y)
}

// hashBigInt hashes a big.Int scalar.
func hashBigInt(i *big.Int) []byte {
	h := sha256.New()
	if i != nil {
		h.Write(i.Bytes())
	}
	return h.Sum(nil)
}

// hashBytes hashes a byte slice.
func hashBytes(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

// hashPoints hashes a list of points by hashing their concatenated byte representations.
func hashPoints(points []*elliptic.Point) []byte {
	h := sha256.New()
	for _, p := range points {
		h.Write(pointToBytes(p))
	}
	return h.Sum(nil)
}


// --- Serialization (using encoding/gob) ---

// Gob requires types to be registered if they are interfaces or not concrete types known at compile time.
// elliptic.Curve is an interface. elliptic.Point struct fields X, Y are *big.Int.
// We need to register the concrete curve implementation (P256) and big.Int.
// It's also safer/more compatible to serialize points and scalars as bytes.

// Register P256 curve for gob encoding (though we serialize points/scalars as bytes, good practice)
func init() {
	gob.Register(elliptic.P256()) // Register the curve interface implementation
	gob.Register(&elliptic.Point{}) // Register the concrete point type
	gob.Register(&big.Int{}) // Register big.Int
}

// pointGobHelper is a helper struct for gob encoding/decoding points as bytes.
type pointGobHelper struct {
	Bytes []byte
}

func (p *elliptic.Point) GobEncode() ([]byte, error) {
	if p == nil || p.X == nil || p.Y == nil {
		return nil, nil // Encode nil point as nil bytes
	}
	return pointToBytes(p), nil
}

func (p *elliptic.Point) GobDecode(data []byte) error {
	if len(data) == 0 {
		// Represents a nil point
		p.X = nil
		p.Y = nil
		return nil
	}
	curve := elliptic.P256() // Assuming P256 as the standard curve for this scheme
	x, y := elliptic.UnmarshalCompressed(curve, data)
	if x == nil || y == nil {
		return fmt.Errorf("gobDecode: failed to unmarshal point bytes")
	}
	if !curve.IsOnCurve(x, y) {
		return fmt.Errorf("gobDecode: decoded point is not on curve")
	}
	p.X = x
	p.Y = y
	return nil
}

// scalarGobHelper is a helper struct for gob encoding/decoding scalars as bytes.
type scalarGobHelper struct {
	Bytes []byte
}

func (s *big.Int) GobEncode() ([]byte, error) {
	if s == nil {
		return nil, nil // Encode nil scalar as nil bytes
	}
	return scalarToBytes(s), nil
}

func (s *big.Int) GobDecode(data []byte) error {
	if len(data) == 0 {
		// Represents a nil or zero scalar (need to distinguish)
		// Standard scalarToBytes encodes zero as non-empty, so empty means nil/error
		s.SetInt64(0) // Default to zero if nil representation is intended? Or return error?
		// Let's stick to scalarToBytes encoding zero as bytes. Empty means error/nil.
		return fmt.Errorf("gobDecode: received empty data for scalar")
	}
	params, err := GenerateParams() // Need curve order to validate scalar range
	if err != nil {
		return fmt.Errorf("gobDecode: failed to get params for scalar validation: %v", err)
	}
	scalar := bytesToScalar(params, data)
	if scalar == nil {
		return fmt.Errorf("gobDecode: failed to unmarshal scalar bytes or scalar out of range")
	}
	s.Set(scalar)
	return nil
}


// Proof.MarshalBinary serializes the Proof struct using Gob.
func (p *Proof) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	// Gob will use the custom GobEncode/GobDecode methods for Points and big.Ints
	err := enc.Encode(p)
	if err != nil {
		return nil, fmt.Errorf("failed to gob encode proof: %v", err)
	}
	return buf.Bytes(), nil
}

// Proof.UnmarshalBinary deserializes the Proof struct using Gob.
func (p *Proof) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	// Gob will use the custom GobEncode/GobDecode methods for Points and big.Ints
	err := dec.Decode(p)
	if err != nil {
		return fmt.Errorf("failed to gob decode proof: %v", err)
	}
	// Post-decoding validation could go here (e.g., point validity)
	// Our GobDecode for point checks IsOnCurve, so this is implicitly done.
	return nil
}


// Params.MarshalBinary serializes the Params struct.
// Note: We cannot gob encode the curve interface directly reliably across different executions.
// We will only encode the base point (which implies the curve if it's a standard one like P256)
// and the order. The verifier must reconstruct the curve object based on the public parameters.
// A better approach would be to encode a curve identifier (e.g., "P256").
// For this example, we'll assume the verifier is configured with P256.
// Let's just encode the G point and Order, and the unmarshaller will assume P256.
type paramsGobHelper struct {
	GB []byte // G point as bytes
	Order *big.Int
}

func (p *Params) MarshalBinary() ([]byte, error) {
	if p == nil || p.G == nil || p.Order == nil {
		return nil, fmt.Errorf("cannot marshal nil or incomplete params")
	}
	helper := paramsGobHelper{
		GB: pointToBytes(p.G),
		Order: p.Order, // Gob will use big.Int's custom encoding
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(helper)
	if err != nil {
		return nil, fmt.Errorf("failed to gob encode params helper: %v", err)
	}
	return buf.Bytes(), nil
}

func (p *Params) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot unmarshal empty params data")
	}
	var helper paramsGobHelper
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&helper)
	if err != nil {
		return fmt.Errorf("failed to gob decode params helper: %v", err)
	}

	// Reconstruct Params assuming P256 curve
	curve := elliptic.P256()
	g := bytesToPoint(&Params{Curve: curve, Order: helper.Order}, helper.GB) // Temporarily pass params for point decoding
	if g == nil {
		return fmt.Errorf("failed to unmarshal G point from bytes")
	}
	if helper.Order == nil { // Should not happen with big.Int GobDecode
		return fmt.Errorf("failed to unmarshal Order")
	}

	p.Curve = curve
	p.G = g
	p.Order = helper.Order
	return nil
}

// EligibilityList.MarshalBinary serializes the EligibilityList.
type eligibilityListGobHelper struct {
	PublicKeysBytes [][]byte // Public keys as bytes
}

func (el *EligibilityList) MarshalBinary() ([]byte, error) {
	if el == nil || el.PublicKeys == nil {
		return nil, fmt.Errorf("cannot marshal nil or incomplete eligibility list")
	}
	helper := eligibilityListGobHelper{
		PublicKeysBytes: make([][]byte, len(el.PublicKeys)),
	}
	for i, pk := range el.PublicKeys {
		helper.PublicKeysBytes[i] = pointToBytes(pk)
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(helper)
	if err != nil {
		return nil, fmt.Errorf("failed to gob encode eligibility list helper: %v", err)
	}
	return buf.Bytes(), nil
}

func (el *EligibilityList) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot unmarshal empty eligibility list data")
	}
	var helper eligibilityListGobHelper
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&helper)
	if err != nil {
		return fmt.Errorf("failed to gob decode eligibility list helper: %v", err)
	}

	// Reconstruct EligibilityList assuming P256 curve (need params for bytesToPoint)
	// This is a dependency issue - Unmarshal needs params. A better design might pass params to Unmarshal,
	// or encode curve info. For simplicity here, let's generate default params just for point decoding.
	// Note: The *actual* params used for verification must match the params used for proof generation.
	// In a real system, params would be a well-known global or part of a configuration.
	// Here, we'll create temporary params just for point decoding - this is *fragile* if the curve wasn't P256.
	// A more robust solution would be to unmarshal params first, then use them for list/proof unmarshalling.
	tempParams, err := GenerateParams() // This might generate different G point depending on crypto/rand state if curve isn't fixed
	if err != nil {
		return fmt.Errorf("failed to generate temp params for list unmarshalling: %v", err)
	}
	el.PublicKeys = make([]*elliptic.Point, len(helper.PublicKeysBytes))
	for i, pb := range helper.PublicKeysBytes {
		el.PublicKeys[i] = bytesToPoint(tempParams, pb) // Use temp params for point decoding
		if el.PublicKeys[i] == nil {
			return fmt.Errorf("failed to unmarshal public key point %d", i)
		}
	}
	return nil
}

// ProverSecret.MarshalBinary serializes the ProverSecret.
type proverSecretGobHelper struct {
	SecretKey *big.Int // Gob will use big.Int's custom encoding
	PublicKeyBytes []byte // Public key as bytes
}

func (ps *ProverSecret) MarshalBinary() ([]byte, error) {
	if ps == nil || ps.SecretKey == nil || ps.PublicKey == nil {
		return nil, fmt.Errorf("cannot marshal nil or incomplete prover secret")
	}
	helper := proverSecretGobHelper{
		SecretKey: ps.SecretKey,
		PublicKeyBytes: pointToBytes(ps.PublicKey),
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(helper)
	if err != nil {
		return nil, fmt.Errorf("failed to gob encode prover secret helper: %v", err)
	}
	return buf.Bytes(), nil
}

func (ps *ProverSecret) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot unmarshal empty prover secret data")
	}
	var helper proverSecretGobHelper
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&helper)
	if err != nil {
		return fmt.Errorf("failed to gob decode prover secret helper: %v", err)
	}

	// Reconstruct ProverSecret (need params for bytesToPoint and scalar validation)
	// Again, fragility here if curve isn't P256.
	tempParams, err := GenerateParams() // Temp params for decoding
	if err != nil {
		return fmt.Errorf("failed to generate temp params for secret unmarshalling: %v", err)
	}
	ps.SecretKey = helper.SecretKey // GobDecode handles scalar validation internally via big.Int.GobDecode
	if ps.SecretKey == nil {
		return fmt.Errorf("failed to unmarshal secret key")
	}
	ps.PublicKey = bytesToPoint(tempParams, helper.PublicKeyBytes) // Use temp params for point decoding
	if ps.PublicKey == nil {
		return fmt.Errorf("failed to unmarshal public key point")
	}

	return nil
}

```