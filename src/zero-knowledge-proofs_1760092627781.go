This Go implementation provides a Zero-Knowledge Proof system focusing on a **Disjunctive Schnorr Proof (Proof of OR)**. This advanced concept enables a prover to demonstrate knowledge of a secret (discrete logarithm) corresponding to *one* public key from a predefined set of public keys, *without revealing which public key it is, nor the secret itself*.

### Outline and Function Summary

This ZKP system is designed around a practical application: **ZKP-Enabled Anonymous Whitelist/Membership Verification**.
Imagine a scenario where a service or decentralized autonomous organization (DAO) needs to verify if a user is part of a specific group (e.g., "premium member," "verified contributor") without:
1.  Revealing the user's specific identity or underlying secret.
2.  Revealing which particular member of the group they are.
3.  Requiring the service to store sensitive user data.

The system works as follows:
*   A "Group Manager" generates a set of unique secret keys (`s_i`) and their corresponding public keys (`P_i = s_i * G`, where `G` is a known generator point on an elliptic curve). This set `{P_1, ..., P_N}` forms the public "whitelist".
*   Each whitelisted user is securely given one specific secret key `s_k` and its public key `P_k`.
*   When a user needs to prove their membership, they use their `s_k` and `P_k` to construct a Disjunctive Schnorr Proof. This proof demonstrates that `P_k` is indeed one of the public keys in the `P_set`, and that they know the discrete logarithm (`s_k`) for `P_k`.

---

**Core ZKP Components:**

**A. Elliptic Curve & Math Utilities (Handles NIST P-256 curve operations and `big.Int` arithmetic)**
*   **01. `InitCurve()`:** Initializes the elliptic curve (P256) and its parameters (order `N`, base point `G`).
*   **02. `GetCurveParams()`:** Returns the initialized curve, its order `N`, and the base point `G`.
*   **03. `NewScalar(val interface{}) (*big.Int, error)`:** Converts an input (`*big.Int` or `[]byte`) into a scalar modulo `N`. If `val` is `nil`, it generates a random scalar.
*   **04. `ScalarAdd(s1, s2 *big.Int) *big.Int`:** Adds two scalars modulo `N`.
*   **05. `ScalarSub(s1, s2 *big.Int) *big.Int`:** Subtracts `s2` from `s1` modulo `N`.
*   **06. `ScalarMul(s1, s2 *big.Int) *big.Int`:** Multiplies two scalars modulo `N`.
*   **07. `ScalarInverse(s *big.Int) *big.Int`:** Computes the modular multiplicative inverse of a scalar modulo `N`.
*   **08. `ScalarNeg(s *big.Int) *big.Int`:** Computes the negative of a scalar modulo `N`.
*   **09. `PointAdd(p1, p2 *ECCPoint) *ECCPoint`:** Adds two elliptic curve points.
*   **10. `PointMulScalar(p *ECCPoint, s *big.Int) *ECCPoint`:** Multiplies an elliptic curve point by a scalar.
*   **11. `HashToScalar(data ...interface{}) (*big.Int, error)`:** Hashes arbitrary data (scalars, points, bytes, strings) using SHA256 and converts the result to a scalar modulo `N`.
*   **12. `GenerateRandomScalar() (*big.Int, error)`:** Generates a cryptographically secure random scalar in `[1, N-1]`.
*   **13. `(*ECCPoint).Equal(p2 *ECCPoint) bool`:** Compares two `ECCPoint`s for equality.

**B. Core Schnorr Protocol Building Blocks (Functions for a single Schnorr Proof)**
*   **14. `SchnorrCommitment() (*ECCPoint, *big.Int, error)`:** Generates a Schnorr commitment `R = k*G`, returning `R` and the random nonce `k`.
*   **15. `SchnorrChallenge(P, R *ECCPoint) (*big.Int, error)`:** Computes the challenge `e` as `H(G, P, R)`.
*   **16. `SchnorrResponse(k, s, e *big.Int) *big.Int`:** Computes the prover's response `z = k + e*s` modulo `N`.
*   **17. `VerifySchnorrResponse(P, R *ECCPoint, e, z *big.Int) bool`:** Verifies a single Schnorr proof: checks if `z*G == R + e*P`.

**C. Disjunctive Schnorr Proof (Proof of OR) - Core Logic**
*   **18. `DisjunctiveProof` (struct):** Represents the structure of a complete Disjunctive Schnorr Proof, containing arrays of commitments (`Rs`), challenges (`Es`), and responses (`Zs`) for each element in the public key set.
*   **19. `GenerateDisjunctiveProof(s_k *big.Int, P_k *ECCPoint, P_set []*ECCPoint) (*DisjunctiveProof, error)`:** The main prover function. It takes the prover's secret key `s_k`, their public key `P_k`, and the full set of public keys `P_set`, then constructs and returns the disjunctive proof.
*   **20. `VerifyDisjunctiveProof(proof *DisjunctiveProof, P_set []*ECCPoint) (bool, error)`:** The main verifier function. It takes a `DisjunctiveProof` and the `P_set`, recomputes the global challenge, checks the sum of challenges, and verifies each individual Schnorr equation to determine the proof's validity.

**D. Application Layer: ZKP-Enabled Anonymous Whitelist/Membership Verification**
*   **21. `GroupManager` (struct):** Manages the generation and storage of whitelisted `UserIdentity` objects and publishes the public `P_set`.
*   **22. `NewGroupManager() *GroupManager`:** Constructor for `GroupManager`.
*   **23. `AddMember() (*UserIdentity, error)`:** A `GroupManager` function to generate a new secret/public key pair for a member, add it to the whitelist, and return the `UserIdentity` to the new member.
*   **24. `GetWhitelist() []*ECCPoint`:** A `GroupManager` function that returns a copy of the publicly known set of all whitelisted public keys.
*   **25. `UserIdentity` (struct):** Represents a single user's assigned secret key (`s_k`) and their corresponding public key (`P_k`).
*   **26. `(*UserIdentity).GenerateMembershipProof(P_set []*ECCPoint) (*DisjunctiveProof, error)`:** A method for a `UserIdentity` to create a disjunctive proof of their membership using their secret key and the public whitelist.
*   **27. `VerifyUserMembership(proof *DisjunctiveProof, P_set []*ECCPoint) (bool, error)`:** A high-level verifier-side function that wraps `VerifyDisjunctiveProof` to check if a user's proof is valid against a given public whitelist.

---

```go
package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
)

// --- Outline and Function Summary ---
// This ZKP implementation focuses on a "Disjunctive Schnorr Proof" (Proof of OR).
// It allows a prover to demonstrate knowledge of a secret (discrete logarithm 's')
// corresponding to one public key 'P_k' from a predefined set of public keys '{P_1, ..., P_N}',
// without revealing 's' or which 'P_k' they know the discrete logarithm for.
//
// Application: ZKP-Enhanced Anonymous Whitelist/Membership Verification
// A "Group Manager" creates a set of public keys {P_i} corresponding to secret keys {s_i}.
// Each whitelisted user receives one pair (s_k, P_k).
// Users can then prove their membership in the group to a verifier without revealing
// their secret 's_k' or their specific identity (i.e., which P_k they correspond to).
//
// -----------------------------------------------------------------------------------
// Core ZKP Components:
// -----------------------------------------------------------------------------------
// A. Elliptic Curve & Math Utilities (Handles P256 curve operations and big.Int arithmetic)
// 01. InitCurve: Initializes the elliptic curve parameters.
// 02. GetCurveParams: Returns the initialized curve parameters.
// 03. NewScalar: Creates a scalar (big.Int modulo N) from an input or generates a random one.
// 04. ScalarAdd: Adds two scalars modulo N.
// 05. ScalarSub: Subtracts two scalars modulo N.
// 06. ScalarMul: Multiplies two scalars modulo N.
// 07. ScalarInverse: Computes the modular multiplicative inverse of a scalar.
// 08. ScalarNeg: Computes the negative of a scalar modulo N.
// 09. PointAdd: Adds two elliptic curve points.
// 10. PointMulScalar: Multiplies an elliptic curve point by a scalar.
// 11. HashToScalar: Hashes a slice of byte arrays, big.Ints, or ECCPoints to a scalar modulo N.
// 12. GenerateRandomScalar: Generates a cryptographically secure random scalar modulo N.
// 13. (*ECCPoint).Equal: Compares two ECCPoint structures for equality.
//
// B. Core Schnorr Protocol Building Blocks (Functions for a single Schnorr Proof)
// 14. SchnorrCommitment: Generates a Schnorr commitment (R = k*G).
// 15. SchnorrChallenge: Computes the challenge 'e' for a Schnorr proof (e = H(G, P, R)).
// 16. SchnorrResponse: Computes the response 'z' for a Schnorr proof (z = k + e*s).
// 17. VerifySchnorrResponse: Verifies a single Schnorr proof (z*G == R + e*P).
//
// C. Disjunctive Schnorr Proof (Proof of OR) - Core Logic
// 18. DisjunctiveProof: Structure representing the entire disjunctive proof.
// 19. GenerateDisjunctiveProof: Main prover function to create a Disjunctive Schnorr Proof.
// 20. VerifyDisjunctiveProof: Main verifier function to verify a Disjunctive Schnorr Proof.
//
// D. Application Layer: ZKP-Enabled Anonymous Whitelist/Membership Verification
// 21. GroupManager: Manages the set of whitelisted public keys.
// 22. NewGroupManager: Constructor for GroupManager.
// 23. AddMember: Group manager adds a new member, generating their secret and public key.
// 24. GetWhitelist: Returns the public keys forming the whitelist.
// 25. UserIdentity: Structure representing a user's secret and public key pair.
// 26. (*UserIdentity).GenerateMembershipProof: User-side function to create membership proof.
// 27. VerifyUserMembership: Verifier-side function to check membership proof.
// -----------------------------------------------------------------------------------

// Globals for P256 curve parameters
var (
	curve elliptic.Curve
	N     *big.Int   // The order of the base point G
	G_x   *big.Int   // X-coordinate of the base point G
	G_y   *big.Int   // Y-coordinate of the base point G
	G     *ECCPoint  // Base point G
	once  sync.Once  // Ensures curve initialization happens only once
)

// ECCPoint represents an elliptic curve point (x, y)
type ECCPoint struct {
	X, Y *big.Int
}

// InitCurve initializes the P256 curve parameters.
// This function uses sync.Once to ensure thread-safe, single initialization.
func InitCurve() {
	once.Do(func() {
		curve = elliptic.P256()
		N = curve.Params().N
		G_x = curve.Params().Gx
		G_y = curve.Params().Gy
		G = &ECCPoint{X: G_x, Y: G_y}
	})
}

// GetCurveParams returns the initialized curve, its base point order N, and the base point G.
func GetCurveParams() (elliptic.Curve, *big.Int, *ECCPoint) {
	InitCurve() // Ensure curve is initialized
	return curve, N, G
}

// NewScalar creates a new scalar (big.Int modulo N) from a given big.Int or byte slice.
// If input is nil, it calls GenerateRandomScalar to get a new random scalar.
func NewScalar(val interface{}) (*big.Int, error) {
	InitCurve()
	var s *big.Int
	switch v := val.(type) {
	case *big.Int:
		s = new(big.Int).Mod(v, N)
	case []byte:
		s = new(big.Int).SetBytes(v)
		s.Mod(s, N)
	case nil: // Generate random scalar
		return GenerateRandomScalar()
	default:
		return nil, fmt.Errorf("unsupported type for scalar: %T", val)
	}
	return s, nil
}

// ScalarAdd adds two scalars modulo N.
func ScalarAdd(s1, s2 *big.Int) *big.Int {
	InitCurve()
	return new(big.Int).Add(s1, s2).Mod(N, N) // Optimized: (s1+s2) % N
}

// ScalarSub subtracts s2 from s1 modulo N.
func ScalarSub(s1, s2 *big.Int) *big.Int {
	InitCurve()
	return new(big.Int).Sub(s1, s2).Mod(N, N) // Optimized: (s1-s2) % N
}

// ScalarMul multiplies two scalars modulo N.
func ScalarMul(s1, s2 *big.Int) *big.Int {
	InitCurve()
	return new(big.Int).Mul(s1, s2).Mod(N, N) // Optimized: (s1*s2) % N
}

// ScalarInverse computes the modular multiplicative inverse of a scalar.
func ScalarInverse(s *big.Int) *big.Int {
	InitCurve()
	// Ensure s is not zero before computing inverse
	if s.Cmp(big.NewInt(0)) == 0 {
		return nil // Or handle as an error
	}
	return new(big.Int).ModInverse(s, N)
}

// ScalarNeg computes the negative of a scalar modulo N.
func ScalarNeg(s *big.Int) *big.Int {
	InitCurve()
	return new(big.Int).Neg(s).Mod(N, N) // Optimized: (-s) % N
}

// PointAdd adds two elliptic curve points.
func PointAdd(p1, p2 *ECCPoint) *ECCPoint {
	InitCurve()
	x, y := curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return &ECCPoint{X: x, Y: y}
}

// PointMulScalar multiplies an elliptic curve point by a scalar.
func PointMulScalar(p *ECCPoint, s *big.Int) *ECCPoint {
	InitCurve()
	x, y := curve.ScalarMult(p.X, p.Y, s.Bytes())
	return &ECCPoint{X: x, Y: y}
}

// HashToScalar hashes arbitrary data to a scalar modulo N.
// The data can be a mix of big.Ints, byte slices, ECCPoints, or strings.
func HashToScalar(data ...interface{}) (*big.Int, error) {
	InitCurve()
	h := sha256.New()
	for _, d := range data {
		var b []byte
		switch v := d.(type) {
		case *big.Int:
			b = v.Bytes()
		case []byte:
			b = v
		case *ECCPoint:
			// Ensure points are serialized consistently for hashing
			b = append(v.X.Bytes(), v.Y.Bytes()...)
		case string:
			b = []byte(v)
		default:
			return nil, fmt.Errorf("unsupported type for hashing: %T", d)
		}
		if _, err := h.Write(b); err != nil {
			return nil, err
		}
	}
	hashBytes := h.Sum(nil)
	return new(big.Int).SetBytes(hashBytes).Mod(N, N), nil // Modulo N
}

// GenerateRandomScalar generates a cryptographically secure random scalar modulo N.
// The scalar is in the range [1, N-1].
func GenerateRandomScalar() (*big.Int, error) {
	InitCurve()
	// Generate a random big.Int in the range [1, N-1]
	// crypto/rand.Int generates in [0, max-1] so we use N-1 and add 1.
	max := new(big.Int).Sub(N, big.NewInt(1)) // N-1
	k, err := rand.Int(rand.Reader, max)      // k in [0, N-2]
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(k, big.NewInt(1)), nil // k+1 in [1, N-1]
}

// Equal checks if two ECCPoint objects represent the same point.
func (p1 *ECCPoint) Equal(p2 *ECCPoint) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2 // Both nil or one nil and one not
	}
	return p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0
}

// SchnorrCommitment generates a Schnorr commitment R = k*G, where k is a random nonce.
// It returns the commitment R and the nonce k.
func SchnorrCommitment() (*ECCPoint, *big.Int, error) {
	InitCurve()
	k, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, err
	}
	R := PointMulScalar(G, k)
	return R, k, nil
}

// SchnorrChallenge computes the challenge 'e' for a Schnorr proof.
// e = H(G, P, R). G is the base point, P is the public key, R is the commitment.
func SchnorrChallenge(P, R *ECCPoint) (*big.Int, error) {
	InitCurve()
	return HashToScalar(G, P, R)
}

// SchnorrResponse computes the response 'z' for a Schnorr proof: z = k + e*s (mod N).
// s is the secret key (discrete logarithm).
func SchnorrResponse(k, s, e *big.Int) *big.Int {
	InitCurve()
	// z = k + e*s mod N
	eS := ScalarMul(e, s)
	z := ScalarAdd(k, eS)
	return z
}

// VerifySchnorrResponse verifies a single Schnorr proof.
// Checks if z*G == R + e*P (mod N).
func VerifySchnorrResponse(P, R *ECCPoint, e, z *big.Int) bool {
	InitCurve()
	// Check z*G
	lhs := PointMulScalar(G, z)

	// Check R + e*P
	eP := PointMulScalar(P, e)
	rhs := PointAdd(R, eP)

	return lhs.Equal(rhs)
}

// DisjunctiveProof holds the components of a Disjunctive Schnorr Proof.
type DisjunctiveProof struct {
	Rs []*ECCPoint  // R_i commitments for each P_i
	Es []*big.Int   // e_i challenges for each P_i
	Zs []*big.Int   // z_i responses for each P_i
}

// GenerateDisjunctiveProof creates a Disjunctive Schnorr Proof.
// s_k is the secret key known by the prover.
// P_k is the public key corresponding to s_k.
// P_set is the full set of public keys {P_1, ..., P_N} including P_k.
// The prover proves they know s_k for one P_k in P_set without revealing s_k or k.
func GenerateDisjunctiveProof(s_k *big.Int, P_k *ECCPoint, P_set []*ECCPoint) (*DisjunctiveProof, error) {
	InitCurve()
	N_size := len(P_set)
	if N_size == 0 {
		return nil, fmt.Errorf("P_set cannot be empty")
	}

	// Find the index of P_k in P_set
	k_idx := -1
	for i, P := range P_set {
		if P_k.Equal(P) {
			k_idx = i
			break
		}
	}
	if k_idx == -1 {
		return nil, fmt.Errorf("P_k not found in P_set")
	}

	// 1. Prover (Commitment Phase) and fake challenges/responses
	Rs := make([]*ECCPoint, N_size)
	Es_fake := make([]*big.Int, N_size) // Storing fake challenges for non-target P_i
	Zs_fake := make([]*big.Int, N_size) // Storing fake responses for non-target P_i

	// For the actual target P_k (index k_idx):
	// Choose random k_k. Compute R_k = k_k * G. Store k_k for later.
	real_k, err := GenerateRandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar for real k: %w", err)
	}
	Rs[k_idx] = PointMulScalar(G, real_k)

	// For all other P_i (i != k_idx):
	// Choose random e_i (challenge) and z_i (response).
	// Compute R_i = z_i * G - e_i * P_i. This constructs a valid (R_i, e_i, z_i) triplet
	// for an arbitrary (unknown) secret, making it look like a valid Schnorr proof.
	for i := 0; i < N_size; i++ {
		if i == k_idx {
			continue // Skip the real target
		}
		e_i, err := GenerateRandomScalar() // Random fake challenge
		if err != nil {
			return nil, fmt.Errorf("failed to generate random scalar for fake e[%d]: %w", i, err)
		}
		z_i, err := GenerateRandomScalar() // Random fake response
		if err != nil {
			return nil, fmt.Errorf("failed to generate random scalar for fake z[%d]: %w", i, err)
		}

		// R_i = z_i * G - e_i * P_i (mod N)
		z_i_G := PointMulScalar(G, z_i)
		e_i_P_i := PointMulScalar(P_set[i], e_i)
		neg_e_i_P_i := PointMulScalar(e_i_P_i, ScalarNeg(big.NewInt(1))) // -e_i*P_i
		Rs[i] = PointAdd(z_i_G, neg_e_i_P_i)                             // (z_i * G) + (-e_i * P_i)

		Es_fake[i] = e_i
		Zs_fake[i] = z_i
	}

	// 2. Verifier (Challenge Phase - simulated by prover for global challenge)
	// Global challenge E = H(G, P_1, ..., P_N, R_1, ..., R_N)
	// Prepare data for hashing: G, all P_i, all R_i
	hashData := make([]interface{}, 1+N_size*2)
	hashData[0] = G
	for i := 0; i < N_size; i++ {
		hashData[1+i] = P_set[i]
		hashData[1+N_size+i] = Rs[i]
	}

	E_total, err := HashToScalar(hashData...)
	if err != nil {
		return nil, fmt.Errorf("failed to hash for total challenge: %w", err)
	}

	// 3. Prover (Response Phase)
	// Calculate sum of fake challenges
	E_fake_sum := big.NewInt(0)
	for i := 0; i < N_size; i++ {
		if i == k_idx {
			continue
		}
		E_fake_sum = ScalarAdd(E_fake_sum, Es_fake[i])
	}

	// Calculate real challenge e_k for P_k: e_k = E_total - E_fake_sum (mod N)
	real_e := ScalarSub(E_total, E_fake_sum)

	// Calculate real response z_k for P_k: z_k = real_k + real_e * s_k (mod N)
	real_z := SchnorrResponse(real_k, s_k, real_e)

	// Assemble final proof: combine real and fake parts
	final_Es := make([]*big.Int, N_size)
	final_Zs := make([]*big.Int, N_size)

	for i := 0; i < N_size; i++ {
		if i == k_idx {
			final_Es[i] = real_e
			final_Zs[i] = real_z
		} else {
			final_Es[i] = Es_fake[i]
			final_Zs[i] = Zs_fake[i]
		}
	}

	return &DisjunctiveProof{
		Rs: Rs,
		Es: final_Es,
		Zs: final_Zs,
	}, nil
}

// VerifyDisjunctiveProof verifies a Disjunctive Schnorr Proof.
// Takes the proof and the set of public keys P_set.
func VerifyDisjunctiveProof(proof *DisjunctiveProof, P_set []*ECCPoint) (bool, error) {
	InitCurve()
	N_size := len(P_set)
	if N_size == 0 || len(proof.Rs) != N_size || len(proof.Es) != N_size || len(proof.Zs) != N_size {
		return false, fmt.Errorf("invalid proof or P_set size mismatch")
	}

	// 1. Verifier (Challenge Phase) - Recompute global challenge E_total
	hashData := make([]interface{}, 1+N_size*2)
	hashData[0] = G
	for i := 0; i < N_size; i++ {
		hashData[1+i] = P_set[i]
		hashData[1+N_size+i] = proof.Rs[i]
	}

	E_total, err := HashToScalar(hashData...)
	if err != nil {
		return false, fmt.Errorf("failed to hash for total challenge during verification: %w", err)
	}

	// 2. Verify sum of challenges
	E_sum_from_proof := big.NewInt(0)
	for _, e_i := range proof.Es {
		E_sum_from_proof = ScalarAdd(E_sum_from_proof, e_i)
	}
	if E_total.Cmp(E_sum_from_proof) != 0 {
		return false, fmt.Errorf("total challenge mismatch: expected %s, got %s", E_total.String(), E_sum_from_proof.String())
	}

	// 3. Verify each individual Schnorr equation: z_i * G == R_i + e_i * P_i
	for i := 0; i < N_size; i++ {
		if !VerifySchnorrResponse(P_set[i], proof.Rs[i], proof.Es[i], proof.Zs[i]) {
			return false, fmt.Errorf("individual Schnorr verification failed for index %d", i)
		}
	}

	return true, nil
}

// GroupManager manages the set of whitelisted public keys.
type GroupManager struct {
	members []*UserIdentity // Stores the identities (s_k, P_k) of whitelisted members
	P_set   []*ECCPoint     // Publicly known set of public keys {P_1, ..., P_N}
	lock    sync.Mutex      // To protect concurrent access to internal state
}

// UserIdentity represents a user's secret key and their corresponding public key.
type UserIdentity struct {
	SecretKey *big.Int  // s_k
	PublicKey *ECCPoint // P_k = s_k * G
}

// NewGroupManager creates and initializes a new GroupManager.
func NewGroupManager() *GroupManager {
	InitCurve()
	return &GroupManager{
		members: make([]*UserIdentity, 0),
		P_set:   make([]*ECCPoint, 0),
	}
}

// AddMember adds a new whitelisted member to the group.
// It generates a new secret key s_k and its public key P_k,
// adds them to the manager's internal lists, and returns the UserIdentity to the user.
func (gm *GroupManager) AddMember() (*UserIdentity, error) {
	gm.lock.Lock()
	defer gm.lock.Unlock()

	InitCurve()
	s_k, err := GenerateRandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret key for new member: %w", err)
	}
	P_k := PointMulScalar(G, s_k)

	user := &UserIdentity{
		SecretKey: s_k,
		PublicKey: P_k,
	}

	gm.members = append(gm.members, user)
	gm.P_set = append(gm.P_set, P_k)

	return user, nil
}

// GetWhitelist returns the publicly known set of all whitelisted public keys.
// A copy is returned to prevent external modification of the internal state.
func (gm *GroupManager) GetWhitelist() []*ECCPoint {
	gm.lock.Lock()
	defer gm.lock.Unlock()
	whitelistCopy := make([]*ECCPoint, len(gm.P_set))
	copy(whitelistCopy, gm.P_set)
	return whitelistCopy
}

// GenerateMembershipProof allows a user to generate a proof that they are a member
// of the group, given their secret key s_k, public key P_k, and the full P_set.
// This is a method on UserIdentity, implying the user uses their own secret.
func (ui *UserIdentity) GenerateMembershipProof(P_set []*ECCPoint) (*DisjunctiveProof, error) {
	return GenerateDisjunctiveProof(ui.SecretKey, ui.PublicKey, P_set)
}

// VerifyUserMembership verifies a user's membership proof against the public whitelist.
// This function would typically be called by a service provider or verifier.
func VerifyUserMembership(proof *DisjunctiveProof, P_set []*ECCPoint) (bool, error) {
	return VerifyDisjunctiveProof(proof, P_set)
}
```