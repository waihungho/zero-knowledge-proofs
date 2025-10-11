```go
package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

// Outline and Function Summary
//
// Project: Zero-Knowledge Proof for Private Data Access Eligibility
//
// Concept: This Go implementation presents a Zero-Knowledge Proof (ZKP) system designed for verifying a Prover's eligibility for private data access, without revealing sensitive underlying information. The core idea is to combine multiple ZKP primitives to prove a complex "AND" statement:
// "I (Prover) have a valid credential *AND* my data quality score is within an acceptable range *AND* I consent to data processing for a specific purpose X, *without revealing my specific credential, my exact quality score, or my individual consent details*."
//
// This addresses a critical need in privacy-preserving data exchanges, decentralized identity (DID), and confidential computing.
//
// Key ZKP Components & Functionality:
//
// 1.  Elliptic Curve & Scalar Arithmetic: Foundation for cryptographic operations, including point addition, scalar multiplication, and modular arithmetic. Uses `P256` curve.
// 2.  Pedersen Commitments: Used to commit to private values (e.g., credentials, scores, consent IDs) without revealing them. Provides computational hiding and binding properties.
// 3.  `ZKPCredentialMembership` (OR-Proof of Knowledge of Discrete Logarithm): Proves the Prover possesses a secret credential `s` (represented as `s*G`) that matches *one of N* publicly registered eligible credentials `E_i` (where `E_i = s_i*G`). This is an OR-proof built upon Schnorr's protocol, allowing the Prover to hide which specific credential they hold.
// 4.  `ZKPQualityScoreThreshold` (ZKPoK of a Subset Sum / OR-Proof on Score Set): Proves the Prover's private data quality score `q` (committed as `q*G + r*H`) is *one of M* publicly defined acceptable scores `ValidScores_j`, all of which are above a `MinQualityThreshold`. This is another OR-proof, ensuring the score is valid without revealing its exact value.
// 5.  `ZKPConsentMatch` (ZKPoK of Discrete Logarithm Equality): Proves the Prover's private consent ID `c` (committed as `c*G + r*H`) matches a public hash of a specific `PurposeX` (i.e., `c = Hash(PurposeX)`). This uses a Schnorr-like proof to demonstrate knowledge of `c` that equals a target value.
// 6.  `AggregateZKP` (AND-Composition via Fiat-Shamir): Combines the three individual ZKP components into a single non-interactive proof. The challenges for each sub-proof are derived deterministically using the Fiat-Shamir heuristic from a hash of all public inputs and initial commitments. This ensures all conditions are met simultaneously.
//
// List of Functions (20+):
//
// *   Core Crypto & Helpers:
//     *   `InitParams()`: Initializes elliptic curve parameters and generators.
//     *   `newScalar(val *big.Int)`: Creates a new `Scalar`.
//     *   `Scalar.Add(other Scalar)`: Scalar addition.
//     *   `Scalar.Sub(other Scalar)`: Scalar subtraction.
//     *   `Scalar.Mul(other Scalar)`: Scalar multiplication.
//     *   `Scalar.Inverse()`: Scalar modular inverse.
//     *   `Scalar.Random(randReader io.Reader)`: Generates random scalar.
//     *   `Scalar.Bytes()`: Converts scalar to byte slice.
//     *   `BytesToScalar(b []byte)`: Converts byte slice to scalar.
//     *   `newPoint(x, y *big.Int)`: Creates a new `Point`.
//     *   `Point.Add(other Point)`: Point addition.
//     *   `Point.ScalarMult(s Scalar)`: Point scalar multiplication.
//     *   `Point.Neg()`: Point negation.
//     *   `Point.Equal(other Point)`: Point equality check.
//     *   `Point.Bytes()`: Converts point to byte slice (compressed).
//     *   `BytesToPoint(b []byte)`: Converts byte slice to point.
//     *   `PedersenCommitment.Commit(value, blindingFactor Scalar)`: Creates a Pedersen commitment.
//     *   `PedersenCommitment.Open(commitment Point, value, blindingFactor Scalar)`: Verifies a Pedersen commitment.
//     *   `HashToScalar(data ...[]byte)`: Generates a scalar challenge from byte data (Fiat-Shamir).
// *   `ZKPCredentialMembership`:
//     *   `CredentialMembershipInput`: Struct for prover/verifier inputs.
//     *   `CredentialMembershipProof`: Struct for proof.
//     *   `GenerateCredentialMembershipProof(input CredentialMembershipInput, trueIdx int, secretCred Scalar, randReader io.Reader)`: Creates the ZKP.
//     *   `VerifyCredentialMembershipProof(input CredentialMembershipInput, proof CredentialMembershipProof)`: Verifies the ZKP.
// *   `ZKPQualityScoreThreshold`:
//     *   `QualityScoreInput`: Struct for prover/verifier inputs.
//     *   `QualityScoreProof`: Struct for proof.
//     *   `GenerateQualityScoreProof(input QualityScoreInput, trueIdx int, secretScore, secretBlinding Scalar, randReader io.Reader)`: Creates the ZKP.
//     *   `VerifyQualityScoreProof(input QualityScoreInput, proof QualityScoreProof)`: Verifies the ZKP.
// *   `ZKPConsentMatch`:
//     *   `ConsentInput`: Struct for prover/verifier inputs.
//     *   `ConsentProof`: Struct for proof.
//     *   `GenerateConsentProof(input ConsentInput, secretConsentID, secretBlinding Scalar, randReader io.Reader)`: Creates the ZKP.
//     *   `VerifyConsentProof(input ConsentInput, proof ConsentProof)`: Verifies the ZKP.
// *   `AggregateZKP`:
//     *   `AggregateProof`: Struct for combined proof.
//     *   `GenerateAggregateProof(credInput CredentialMembershipInput, credTrueIdx int, credSecret Scalar, qualityInput QualityScoreInput, qualityTrueIdx int, qualitySecretScore, qualitySecretBlinding Scalar, consentInput ConsentInput, consentSecretID, consentSecretBlinding Scalar, randReader io.Reader)`: Creates the aggregate ZKP.
//     *   `VerifyAggregateProof(credInput CredentialMembershipInput, qualityInput QualityScoreInput, consentInput ConsentInput, aggregateProof AggregateProof)`: Verifies the aggregate ZKP.
//     *   `MarshalAggregateProof(proof AggregateProof)`: Serializes the aggregate proof.
//     *   `UnmarshalAggregateProof(b []byte)`: Deserializes the aggregate proof.

// --- Global Cryptographic Parameters ---
var (
	// Elliptic curve P256
	curve = elliptic.P256()
	// G is the base point for the P256 curve
	G elliptic.Point
	// H is a second generator point, derived from G via hashing, used for Pedersen commitments
	H elliptic.Point
	// N is the order of the curve, i.e., the size of the scalar field
	N *big.Int
)

// InitParams initializes the global curve parameters G, H, and N.
// This function should be called once at application startup.
func InitParams() {
	if G != nil {
		return // Already initialized
	}
	G = curve.Params().Gx.Set(curve.Params().Gx), curve.Params().Gy.Set(curve.Params().Gy) // G is the standard generator
	N = curve.Params().N

	// Derive H deterministically from G.
	// Hashing G's coordinates to a point on the curve.
	h := sha256.Sum256(G.Bytes())
	H_x, H_y := curve.ScalarBaseMult(h[:])
	H = elliptic.Point{X: H_x, Y: H_y}
}

// --- Scalar Type and Operations ---

// Scalar represents an element in the finite field Z_N.
type Scalar big.Int

// newScalar creates a new Scalar from a big.Int, ensuring it's reduced modulo N.
func newScalar(val *big.Int) Scalar {
	return Scalar(*new(big.Int).Mod(val, N))
}

// Add performs scalar addition: a + b (mod N).
func (s Scalar) Add(other Scalar) Scalar {
	res := new(big.Int).Add((*big.Int)(&s), (*big.Int)(&other))
	return newScalar(res)
}

// Sub performs scalar subtraction: a - b (mod N).
func (s Scalar) Sub(other Scalar) Scalar {
	res := new(big.Int).Sub((*big.Int)(&s), (*big.Int)(&other))
	return newScalar(res)
}

// Mul performs scalar multiplication: a * b (mod N).
func (s Scalar) Mul(other Scalar) Scalar {
	res := new(big.Int).Mul((*big.Int)(&s), (*big.Int)(&other))
	return newScalar(res)
}

// Inverse performs scalar modular inverse: a^-1 (mod N).
func (s Scalar) Inverse() Scalar {
	res := new(big.Int).ModInverse((*big.Int)(&s), N)
	return newScalar(res)
}

// Random generates a cryptographically secure random scalar.
func (s Scalar) Random(randReader io.Reader) (Scalar, error) {
	val, err := rand.Int(randReader, N)
	if err != nil {
		return Scalar{}, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return newScalar(val), nil
}

// Bytes converts a Scalar to its byte representation.
func (s Scalar) Bytes() []byte {
	return (*big.Int)(&s).Bytes()
}

// BytesToScalar converts a byte slice to a Scalar.
func BytesToScalar(b []byte) Scalar {
	return newScalar(new(big.Int).SetBytes(b))
}

// --- Point Type and Operations ---

// Point represents a point on the elliptic curve.
type Point elliptic.Point

// newPoint creates a new Point from big.Int coordinates.
func newPoint(x, y *big.Int) Point {
	return Point{X: x, Y: y}
}

// Add performs point addition: P + Q.
func (p Point) Add(other Point) Point {
	x, y := curve.Add(p.X, p.Y, other.X, other.Y)
	return newPoint(x, y)
}

// ScalarMult performs scalar multiplication: k * P.
func (p Point) ScalarMult(s Scalar) Point {
	x, y := curve.ScalarMult(p.X, p.Y, (*big.Int)(&s).Bytes())
	return newPoint(x, y)
}

// Neg performs point negation: -P.
func (p Point) Neg() Point {
	// For P256, -P = (Px, -Py mod N)
	negY := new(big.Int).Neg(p.Y)
	negY.Mod(negY, N)
	return newPoint(p.X, negY)
}

// Equal checks if two points are equal.
func (p Point) Equal(other Point) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// Bytes converts a Point to its compressed byte representation.
func (p Point) Bytes() []byte {
	return elliptic.Marshal(curve, p.X, p.Y)
}

// BytesToPoint converts a byte slice to a Point.
func BytesToPoint(b []byte) (Point, error) {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return Point{}, fmt.Errorf("invalid point bytes")
	}
	return newPoint(x, y), nil
}

// --- Pedersen Commitment ---

// PedersenCommitment represents a Pedersen commitment.
type PedersenCommitment struct{}

// Commit creates a Pedersen commitment C = value*G + blindingFactor*H.
func (pc PedersenCommitment) Commit(value, blindingFactor Scalar) Point {
	vG := Point(G).ScalarMult(value)
	rH := Point(H).ScalarMult(blindingFactor)
	return vG.Add(rH)
}

// Open verifies a Pedersen commitment: checks if C == value*G + blindingFactor*H.
func (pc PedersenCommitment) Open(commitment Point, value, blindingFactor Scalar) bool {
	expectedCommitment := pc.Commit(value, blindingFactor)
	return commitment.Equal(expectedCommitment)
}

// --- Fiat-Shamir Heuristic (Challenge Generation) ---

// HashToScalar generates a challenge scalar by hashing provided byte slices.
func HashToScalar(data ...[]byte) Scalar {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	hashBytes := hasher.Sum(nil)
	return BytesToScalar(hashBytes)
}

// --- ZKP 1: Credential Membership (OR-Proof for Knowledge of DL) ---
// Proves knowledge of `s` such that `s*G` is one of `N` public points `E_i`.

// CredentialMembershipInput defines the public inputs for the credential membership ZKP.
type CredentialMembershipInput struct {
	EligibleCredentials []Point // Publicly known eligible credential points (e.g., hash(credential_id)*G)
}

// CredentialMembershipProof represents a single Schnorr-like sub-proof (a, z).
type CredentialMembershipProof struct {
	A Point  // Commitment
	Z Scalar // Response
}

// CredentialMembershipAggregateProof contains N sub-proofs for the OR-proof.
type CredentialMembershipAggregateProof struct {
	SubProofs []CredentialMembershipProof
}

// GenerateCredentialMembershipProof creates an OR-proof of knowledge of a discrete logarithm.
// input: Public eligible credential points.
// trueIdx: The index of the actual credential the prover knows.
// secretCred: The secret scalar (discrete logarithm) corresponding to EligibleCredentials[trueIdx].
// randReader: Randomness source.
func GenerateCredentialMembershipProof(input CredentialMembershipInput, trueIdx int, secretCred Scalar, randReader io.Reader) (CredentialMembershipAggregateProof, error) {
	if trueIdx < 0 || trueIdx >= len(input.EligibleCredentials) {
		return CredentialMembershipAggregateProof{}, fmt.Errorf("invalid trueIdx")
	}

	numCredentials := len(input.EligibleCredentials)
	subProofs := make([]CredentialMembershipProof, numCredentials)
	challenges := make([]Scalar, numCredentials) // c_i values

	// 1. Simulate proofs for false statements (i != trueIdx)
	for i := 0; i < numCredentials; i++ {
		if i == trueIdx {
			continue
		}
		var err error
		// Random challenge c_i
		challenges[i], err = Scalar{}.Random(randReader)
		if err != nil {
			return CredentialMembershipAggregateProof{}, fmt.Errorf("failed to generate random challenge for simulation: %w", err)
		}
		// Random response z_i
		subProofs[i].Z, err = Scalar{}.Random(randReader)
		if err != nil {
			return CredentialMembershipAggregateProof{}, fmt.Errorf("failed to generate random response for simulation: %w", err)
		}
		// Calculate commitment a_i = z_i*G - c_i*E_i
		zG := Point(G).ScalarMult(subProofs[i].Z)
		cE := input.EligibleCredentials[i].ScalarMult(challenges[i])
		subProofs[i].A = zG.Add(cE.Neg()) // zG - cE
	}

	// 2. Compute true proof for true statement (i == trueIdx)
	// Calculate global challenge C = Hash(all a_i || all E_i)
	var challengeData [][]byte
	for _, p := range input.EligibleCredentials {
		challengeData = append(challengeData, p.Bytes())
	}
	for _, p := range subProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	globalChallenge := HashToScalar(challengeData...)

	// Sum of simulated challenges
	sumSimulatedChallenges := newScalar(big.NewInt(0))
	for i := 0; i < numCredentials; i++ {
		if i != trueIdx {
			sumSimulatedChallenges = sumSimulatedChallenges.Add(challenges[i])
		}
	}

	// c_true = C - sum(c_i for i != trueIdx)
	challenges[trueIdx] = globalChallenge.Sub(sumSimulatedChallenges)

	// r_true (witness commitment for true proof)
	rTrue, err := Scalar{}.Random(randReader)
	if err != nil {
		return CredentialMembershipAggregateProof{}, fmt.Errorf("failed to generate random witness for true proof: %w", err)
	}

	// a_true = r_true*G
	subProofs[trueIdx].A = Point(G).ScalarMult(rTrue)

	// z_true = r_true + c_true*secretCred
	c_true_secretCred := secretCred.Mul(challenges[trueIdx])
	subProofs[trueIdx].Z = rTrue.Add(c_true_secretCred)

	return CredentialMembershipAggregateProof{SubProofs: subProofs}, nil
}

// VerifyCredentialMembershipProof verifies an OR-proof of knowledge of a discrete logarithm.
func VerifyCredentialMembershipProof(input CredentialMembershipInput, proof CredentialMembershipAggregateProof) bool {
	if len(input.EligibleCredentials) != len(proof.SubProofs) {
		return false // Mismatch in number of sub-proofs
	}

	// Reconstruct global challenge C = Hash(all a_i || all E_i)
	var challengeData [][]byte
	for _, p := range input.EligibleCredentials {
		challengeData = append(challengeData, p.Bytes())
	}
	for _, p := range proof.SubProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	globalChallenge := HashToScalar(challengeData...)

	// Verify each sub-proof and sum the challenges
	sumChallenges := newScalar(big.NewInt(0))
	for i := 0; i < len(input.EligibleCredentials); i++ {
		// Check a_i = z_i*G - c_i*E_i
		zG := Point(G).ScalarMult(proof.SubProofs[i].Z)
		cE := input.EligibleCredentials[i].ScalarMult(challenges[i]) // Error here: challenges[i] is not available in verifier
		// The verifier needs to re-derive challenges[i] from the globalChallenge
		// This implies a slightly different structure where 'challenges[i]' for non-trueIdx are given in the proof.

		// Correct verification:
		// sum(c_i) == C
		// and for each i, verify a_i = z_i*G - c_i*E_i
		// The c_i values are not directly part of the proof for Chaum-Pedersen.
		// Instead, they are reconstructed.

		// Let's refine the Chaum-Pedersen verification:
		// The prover sends a_i and z_i for all i.
		// The verifier calculates C = H(a_1 || ... || a_N || E_1 || ... || E_N).
		// The verifier calculates c_i for each i using the proof structure.

		// This implies the prover needs to include the computed challenges[i] for non-trueIdx.
		// No, the Chaum-Pedersen OR-proof means sum(c_i) = C.
		// So the verifier recomputes c_true = C - sum(c_i for i != trueIdx).
		// However, the prover *doesn't* send c_i for i != trueIdx in the proof.
		// The prover only sends a_i and z_i for all i.
		// The verifier must verify that sum of challenges determined for each sub-proof equals the global challenge.

		// Let's adjust the `CredentialMembershipProof` to also store the specific challenge `c_i` for that sub-proof.
		// This simplifies verification and aligns with common NIZK-friendly OR-proofs.

		// Re-design of `CredentialMembershipProof` and `Generate/Verify` for clarity:
		// Each `CredentialMembershipProof` will contain (A_i, Z_i, C_i).
		// The prover has one "real" proof with `A_true=r*G`, `Z_true=r+C_true*s`.
		// For others, `A_j = Z_j*G - C_j*E_j`.
		// All `C_j` must sum up to `H(A_all || E_all)`.

		// Let's assume the current structure is `(A_i, Z_i)` and a global challenge `C_global`.
		// The prover constructs `c_true = C_global - sum(c_i for i!=trueIdx)` and uses this `c_true` for the true proof.
		// The challenges `c_i` for `i != trueIdx` are *randomly chosen* by the prover.
		// This means the verifier *doesn't know* `c_i` for `i != trueIdx`. This is the problem.

		// The standard Chaum-Pedersen (NIZK) for `OR_i (x = x_i)`:
		// 1. Prover picks random `r_i` for `i != k` (where `k` is the true statement).
		// 2. Prover picks random `s_i` for `i != k`.
		// 3. Prover calculates `A_i = s_i*G - r_i*P_i` for `i != k`.
		// 4. Prover picks random `r_k`. `A_k = r_k*G`.
		// 5. Prover computes `C = H(A_1, ..., A_N, P_1, ..., P_N)`.
		// 6. Prover calculates `r_k = C - sum(r_i for i != k)`.
		// 7. Prover calculates `s_k = r_k + x*C_k`.
		// Proof is `(A_1, ..., A_N, s_1, ..., s_N, r_1, ..., r_N)`.
		// This means `r_i` (challenges for false statements) and `s_i` (responses for false statements) need to be included.
		// My `CredentialMembershipProof` has `(A, Z)`, where `A` is the commitment and `Z` is the response.
		// It's missing `C` (the challenge).

		// Let's use a simpler version of the OR-proof where each sub-proof includes its own challenge/response, and one is 'real' and others are 'fake' but consistent.

		// This requires some modification in the `CredentialMembershipAggregateProof`
		// It should contain `N` pairs of `(A_i, Z_i)` and `N` challenges `c_i`.
		// However, a ZK proof should hide which one is the true proof.
		// A common way for ZK NIZK OR-proofs is that the sum of `c_i` equals the hash.
		// And the prover knows all `r_i` and `s_i` for only *one* `i`, and simulates the others.

		// Re-thinking CredentialMembershipProof:
		// For a standard Schnorr proof for DL `x` s.t. `P = xG`, the proof is `(A=rG, Z=r+cx)`.
		// For OR-proof `(P_1=xG OR P_2=xG)`:
		// Prover:
		// 1. Picks `k` (the true index).
		// 2. For `j != k`: picks random `c_j`, `z_j`. Sets `A_j = z_j*G - c_j*P_j`.
		// 3. Picks random `r_k`. Sets `A_k = r_k*G`.
		// 4. Calculates `C_total = H(A_1 || ... || A_N || P_1 || ... || P_N)`.
		// 5. Sets `c_k = C_total - sum_{j!=k} c_j`.
		// 6. Sets `z_k = r_k + c_k * x`.
		// Proof is `(A_1..A_N, z_1..z_N, c_1..c_N)`.
		// This makes the `c_j` values part of the proof for *all* `j`.

		// Let's update `CredentialMembershipProof` to store `A_i, Z_i` and `C_i`.
		// And the `CredentialMembershipAggregateProof` would be `[]struct {A, Z, C}`.
		// But this reveals `C_i` which are part of the challenge sum.

		// A more common structure for OR-Proof is to only have (A_i, Z_i) and sum of challenges property.
		// If using `(A_i, Z_i)` then the verification means:
		// `sum(c_i) = C_global` where `c_i = H(A_i || E_i || Z_i || C_global)` - No, this is incorrect.
		// `c_i` depends on the other components.

		// The current `GenerateCredentialMembershipProof` generates `subProofs[i].A` and `subProofs[i].Z`,
		// and `challenges[i]`. The `challenges` array is what the prover *chooses* (for false) or *derives* (for true).
		// The verifier needs to know `challenges[i]` to verify `a_i = z_i*G - c_i*E_i`.
		// So, the `challenges` array *must* be part of the public proof.

		// Let's modify `CredentialMembershipProof` to hold `A, Z, C`.
		// And `CredentialMembershipAggregateProof` will hold `[]CredentialMembershipProof`.

		// New struct for sub-proof for OR-proof (contains challenge, response, and commitment)
		type ZKPSchnorrSubProof struct {
			A Point  // Witness commitment (rG) or (zG - cX)
			Z Scalar // Response (r+cx) or (random)
			C Scalar // Challenge (random) or (derived)
		}
		// Redefine CredentialMembershipAggregateProof
		type CredentialMembershipAggregateProof struct {
			SubProofs []ZKPSchnorrSubProof
		}

		// Re-implement Generate and Verify for CredentialMembership (due to this structural change)
		return verifyCredentialMembershipProofRevised(input, proof)
	}

	// This part of the code becomes unreachable due to the immediate return above.
	// It's better to refactor the entire `CredentialMembershipProof` and its related functions.

	return false // Should not reach here if refactored correctly.
}

// === Revised ZKP 1: Credential Membership (OR-Proof for Knowledge of DL) ===
// Proves knowledge of `s` such that `s*G` is one of `N` public points `E_i`.
// The proof consists of `N` Schnorr-like sub-proofs `(A_i, Z_i, C_i)`.
// One sub-proof is "real", others are "simulated".
// The sum of all `C_i` must equal the global challenge `H(all A_i || all E_i)`.

// ZKPSchnorrSubProof is a component of an OR-proof.
type ZKPSchnorrSubProof struct {
	A Point  // The prover's commitment (r*G) for the true statement, or (z*G - c*P) for simulated.
	Z Scalar // The prover's response (r + c*secret) for the true statement, or random for simulated.
	C Scalar // The prover's challenge (derived) for the true statement, or random for simulated.
}

// CredentialMembershipProof contains all sub-proofs for the OR-statement.
type CredentialMembershipProof struct {
	SubProofs []ZKPSchnorrSubProof
}

// GenerateCredentialMembershipProof generates an OR-proof of knowledge of a discrete logarithm.
// `input.EligibleCredentials` are points `E_i = s_i * G`.
// Prover knows `secretCred` such that `secretCred * G = input.EligibleCredentials[trueIdx]`.
func GenerateCredentialMembershipProof(input CredentialMembershipInput, trueIdx int, secretCred Scalar, randReader io.Reader) (CredentialMembershipProof, error) {
	if trueIdx < 0 || trueIdx >= len(input.EligibleCredentials) {
		return CredentialMembershipProof{}, fmt.Errorf("invalid trueIdx")
	}

	numCredentials := len(input.EligibleCredentials)
	subProofs := make([]ZKPSchnorrSubProof, numCredentials)
	var err error

	// 1. Generate simulated proofs for i != trueIdx
	for i := 0; i < numCredentials; i++ {
		if i == trueIdx {
			continue
		}
		// Random challenge c_i
		subProofs[i].C, err = Scalar{}.Random(randReader)
		if err != nil {
			return CredentialMembershipProof{}, fmt.Errorf("failed to generate random challenge for simulation: %w", err)
		}
		// Random response z_i
		subProofs[i].Z, err = Scalar{}.Random(randReader)
		if err != nil {
			return CredentialMembershipProof{}, fmt.Errorf("failed to generate random response for simulation: %w", err)
		}
		// Calculate commitment a_i = z_i*G - c_i*E_i
		zG := Point(G).ScalarMult(subProofs[i].Z)
		cE := input.EligibleCredentials[i].ScalarMult(subProofs[i].C)
		subProofs[i].A = zG.Add(cE.Neg())
	}

	// 2. Compute true proof for i == trueIdx
	// 2.1 Calculate global challenge C_total = H(all A_i || all E_i)
	var challengeData [][]byte
	for _, p := range input.EligibleCredentials {
		challengeData = append(challengeData, p.Bytes())
	}
	for _, p := range subProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	C_total := HashToScalar(challengeData...)

	// 2.2 Sum of simulated challenges
	sumSimulatedChallenges := newScalar(big.NewInt(0))
	for i := 0; i < numCredentials; i++ {
		if i != trueIdx {
			sumSimulatedChallenges = sumSimulatedChallenges.Add(subProofs[i].C)
		}
	}

	// 2.3 Derive c_true = C_total - sum(c_i for i != trueIdx)
	subProofs[trueIdx].C = C_total.Sub(sumSimulatedChallenges)

	// 2.4 Pick random witness `r` for true proof
	r, err := Scalar{}.Random(randReader)
	if err != nil {
		return CredentialMembershipProof{}, fmt.Errorf("failed to generate random witness `r` for true proof: %w", err)
	}

	// 2.5 Calculate a_true = r*G
	subProofs[trueIdx].A = Point(G).ScalarMult(r)

	// 2.6 Calculate z_true = r + c_true*secretCred
	cTrueSecretCred := secretCred.Mul(subProofs[trueIdx].C)
	subProofs[trueIdx].Z = r.Add(cTrueSecretCred)

	return CredentialMembershipProof{SubProofs: subProofs}, nil
}

// VerifyCredentialMembershipProof verifies an OR-proof of knowledge of a discrete logarithm.
func VerifyCredentialMembershipProof(input CredentialMembershipInput, proof CredentialMembershipProof) bool {
	if len(input.EligibleCredentials) != len(proof.SubProofs) {
		return false // Mismatch in number of sub-proofs
	}

	// 1. Reconstruct global challenge C_total = H(all A_i || all E_i)
	var challengeData [][]byte
	for _, p := range input.EligibleCredentials {
		challengeData = append(challengeData, p.Bytes())
	}
	for _, p := range proof.SubProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	C_total := HashToScalar(challengeData...)

	// 2. Sum all C_i from the proof
	sumProofChallenges := newScalar(big.NewInt(0))
	for i := 0; i < len(proof.SubProofs); i++ {
		sumProofChallenges = sumProofChallenges.Add(proof.SubProofs[i].C)
	}

	// 3. Check if sum(C_i) == C_total
	if !sumProofChallenges.Equal(C_total) {
		return false
	}

	// 4. Verify each sub-proof: A_i == Z_i*G - C_i*E_i
	for i := 0; i < len(input.EligibleCredentials); i++ {
		zG := Point(G).ScalarMult(proof.SubProofs[i].Z)
		cE := input.EligibleCredentials[i].ScalarMult(proof.SubProofs[i].C)
		expectedA := zG.Add(cE.Neg()) // zG - cE

		if !proof.SubProofs[i].A.Equal(expectedA) {
			return false
		}
	}

	return true
}

// --- ZKP 2: Quality Score Threshold (OR-Proof on acceptable scores) ---
// Proves knowledge of `q, b` such that `C_q = qG + bH` AND `q` is one of `M` publicly defined `ValidScores_j`.
// `ValidScores_j` are guaranteed to be >= `MinQualityThreshold`.

// QualityScoreInput defines the public inputs for the quality score threshold ZKP.
type QualityScoreInput struct {
	CommittedScore Point     // Publicly known Pedersen commitment to the prover's secret quality score. C_q = qG + bH
	ValidScores    []Scalar  // Publicly known set of acceptable quality scores (all >= MinQualityThreshold)
}

// QualityScoreProof represents the OR-proof for quality score.
// Structurally similar to CredentialMembershipProof, but proving a different statement.
type QualityScoreProof struct {
	SubProofs []ZKPSchnorrSubProof
}

// GenerateQualityScoreProof generates an OR-proof that a committed score matches one of a set of valid scores.
// `input.CommittedScore = secretScore*G + secretBlinding*H`.
// `input.ValidScores` are the scalars `s_j`.
// Prover knows `secretScore, secretBlinding` such that `secretScore == input.ValidScores[trueIdx]`.
func GenerateQualityScoreProof(input QualityScoreInput, trueIdx int, secretScore, secretBlinding Scalar, randReader io.Reader) (QualityScoreProof, error) {
	if trueIdx < 0 || trueIdx >= len(input.ValidScores) {
		return QualityScoreProof{}, fmt.Errorf("invalid trueIdx")
	}

	numValidScores := len(input.ValidScores)
	subProofs := make([]ZKPSchnorrSubProof, numValidScores)
	var err error

	// The statement being proven for each `j` is:
	// `C_q = ValidScores[j]*G + r*H` for some `r`.
	// Which means `C_q - ValidScores[j]*G = r*H`.
	// We need to prove knowledge of `r` for `(C_q - ValidScores[j]*G)` against generator `H`.
	// Let `Target_j = C_q - ValidScores[j]*G`. The prover wants to prove `Target_j = r*H`.

	// 1. Generate simulated proofs for j != trueIdx
	for j := 0; j < numValidScores; j++ {
		if j == trueIdx {
			continue
		}
		// Calculate Target_j = C_q - ValidScores[j]*G
		targetJ := input.CommittedScore.Add(Point(G).ScalarMult(input.ValidScores[j]).Neg())

		// Random challenge c_j
		subProofs[j].C, err = Scalar{}.Random(randReader)
		if err != nil {
			return QualityScoreProof{}, fmt.Errorf("failed to generate random challenge for simulation: %w", err)
		}
		// Random response z_j
		subProofs[j].Z, err = Scalar{}.Random(randReader)
		if err != nil {
			return QualityScoreProof{}, fmt.Errorf("failed to generate random response for simulation: %w", err)
		}
		// Calculate commitment a_j = z_j*H - c_j*Target_j
		zH := Point(H).ScalarMult(subProofs[j].Z)
		cTargetJ := targetJ.ScalarMult(subProofs[j].C)
		subProofs[j].A = zH.Add(cTargetJ.Neg())
	}

	// 2. Compute true proof for j == trueIdx
	// 2.1 Calculate global challenge C_total = H(all A_j || C_q || all ValidScores_j)
	var challengeData [][]byte
	challengeData = append(challengeData, input.CommittedScore.Bytes())
	for _, s := range input.ValidScores {
		challengeData = append(challengeData, s.Bytes())
	}
	for _, p := range subProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	C_total := HashToScalar(challengeData...)

	// 2.2 Sum of simulated challenges
	sumSimulatedChallenges := newScalar(big.NewInt(0))
	for j := 0; j < numValidScores; j++ {
		if j != trueIdx {
			sumSimulatedChallenges = sumSimulatedChallenges.Add(subProofs[j].C)
		}
	}

	// 2.3 Derive c_true = C_total - sum(c_j for j != trueIdx)
	subProofs[trueIdx].C = C_total.Sub(sumSimulatedChallenges)

	// 2.4 Pick random witness `r_prime` for true proof
	rPrime, err := Scalar{}.Random(randReader)
	if err != nil {
		return QualityScoreProof{}, fmt.Errorf("failed to generate random witness `r_prime` for true proof: %w", err)
	}

	// 2.5 Calculate a_true = r_prime*H
	subProofs[trueIdx].A = Point(H).ScalarMult(rPrime)

	// 2.6 Calculate z_true = r_prime + c_true*secretBlinding (where secretBlinding is the `r` in `Target_j = r*H`)
	cTrueSecretBlinding := secretBlinding.Mul(subProofs[trueIdx].C)
	subProofs[trueIdx].Z = rPrime.Add(cTrueSecretBlinding)

	return QualityScoreProof{SubProofs: subProofs}, nil
}

// VerifyQualityScoreProof verifies an OR-proof for a committed score matching one of a set of valid scores.
func VerifyQualityScoreProof(input QualityScoreInput, proof QualityScoreProof) bool {
	if len(input.ValidScores) != len(proof.SubProofs) {
		return false // Mismatch in number of sub-proofs
	}

	// 1. Reconstruct global challenge C_total = H(all A_j || C_q || all ValidScores_j)
	var challengeData [][]byte
	challengeData = append(challengeData, input.CommittedScore.Bytes())
	for _, s := range input.ValidScores {
		challengeData = append(challengeData, s.Bytes())
	}
	for _, p := range proof.SubProofs {
		challengeData = append(challengeData, p.A.Bytes())
	}
	C_total := HashToScalar(challengeData...)

	// 2. Sum all C_j from the proof
	sumProofChallenges := newScalar(big.NewInt(0))
	for j := 0; j < len(proof.SubProofs); j++ {
		sumProofChallenges = sumProofChallenges.Add(proof.SubProofs[j].C)
	}

	// 3. Check if sum(C_j) == C_total
	if !sumProofChallenges.Equal(C_total) {
		return false
	}

	// 4. Verify each sub-proof: A_j == Z_j*H - C_j*Target_j
	for j := 0; j < len(input.ValidScores); j++ {
		// Calculate Target_j = C_q - ValidScores[j]*G
		targetJ := input.CommittedScore.Add(Point(G).ScalarMult(input.ValidScores[j]).Neg())

		zH := Point(H).ScalarMult(proof.SubProofs[j].Z)
		cTargetJ := targetJ.ScalarMult(proof.SubProofs[j].C)
		expectedA := zH.Add(cTargetJ.Neg())

		if !proof.SubProofs[j].A.Equal(expectedA) {
			return false
		}
	}

	return true
}

// --- ZKP 3: Consent Match (ZKPoK of DL Equality for a committed value) ---
// Proves knowledge of `c, f` such that `C_c = cG + fH` and `c == TargetConsentID`.

// ConsentInput defines the public inputs for the consent match ZKP.
type ConsentInput struct {
	CommittedConsentID Point  // Publicly known Pedersen commitment to the prover's secret consent ID. C_c = cG + fH
	TargetConsentID    Scalar // Publicly known target consent ID (e.g., hash(purpose_X))
}

// ConsentProof represents a single Schnorr-like proof for ZKPoK of DL equality.
type ConsentProof struct {
	A Point  // Prover's commitment to randomness (rG for c, rH for f)
	Z1 Scalar // Prover's response for `secretConsentID`
	Z2 Scalar // Prover's response for `secretBlinding`
}

// GenerateConsentProof generates a ZKPoK that `CommittedConsentID` equals `TargetConsentID`.
// `input.CommittedConsentID = secretConsentID*G + secretBlinding*H`.
// Prover needs to prove `secretConsentID == input.TargetConsentID` without revealing `secretBlinding`.
// This proof demonstrates knowledge of `secretBlinding` such that:
// `input.CommittedConsentID - input.TargetConsentID*G = secretBlinding*H`.
// Let `TargetPoint = input.CommittedConsentID - input.TargetConsentID*G`.
// Prover proves knowledge of `secretBlinding` such that `TargetPoint = secretBlinding*H`.
func GenerateConsentProof(input ConsentInput, secretConsentID, secretBlinding Scalar, randReader io.Reader) (ConsentProof, error) {
	// The core statement to prove knowledge of is `secretBlinding` for `TargetPoint = secretBlinding * H`.
	// We need to prove `secretConsentID` matches `TargetConsentID`.
	// Let `diff_G = CommittedConsentID - TargetConsentID*G`.
	// Prover knows `secretBlinding` such that `diff_G = secretBlinding*H`.
	// This is a standard Schnorr proof for knowledge of `secretBlinding`.

	if !secretConsentID.Equal(input.TargetConsentID) {
		return ConsentProof{}, fmt.Errorf("prover's secretConsentID does not match TargetConsentID")
	}

	targetPoint := input.CommittedConsentID.Add(Point(G).ScalarMult(input.TargetConsentID).Neg()) // TargetPoint = Cc - Target*G

	// 1. Prover picks random `r`
	r, err := Scalar{}.Random(randReader)
	if err != nil {
		return ConsentProof{}, fmt.Errorf("failed to generate random witness `r`: %w", err)
	}

	// 2. Prover computes commitment `A = r*H`
	A := Point(H).ScalarMult(r)

	// 3. Verifier sends challenge `c = H(A || TargetPoint || H)` (Fiat-Shamir)
	// (Prover computes challenge deterministically)
	challenge := HashToScalar(A.Bytes(), targetPoint.Bytes(), Point(H).Bytes())

	// 4. Prover computes response `z = r + c*secretBlinding`
	cSecretBlinding := secretBlinding.Mul(challenge)
	z := r.Add(cSecretBlinding)

	// The `ConsentProof` struct has `Z1` and `Z2`. This suggests knowledge of two secrets.
	// But our proof only needs knowledge of one: `secretBlinding`.

	// Let's redefine ConsentProof to be for knowledge of two scalars (`secretConsentID`, `secretBlinding`) that satisfy `C_c = secretConsentID*G + secretBlinding*H`
	// AND `secretConsentID = TargetConsentID`.
	// This can be done by proving:
	// 1. Knowledge of `secretBlinding` for `C_c - TargetConsentID*G = secretBlinding*H`. (As above)
	// This needs only one `Z`.

	// If we must use `Z1, Z2` then it implies proving knowledge of `secretConsentID` and `secretBlinding` directly.
	// A ZKPoK for `C = xG + yH`:
	// Prover: `r1, r2` random. `A = r1G + r2H`.
	// Challenge `c = H(A || C)`.
	// Response `z1 = r1 + cx`, `z2 = r2 + cy`.
	// Proof: `(A, z1, z2)`.
	// Verifier: `A == z1G + z2H - cC`.
	// This proves knowledge of `x` and `y` for `C`.
	// We want to prove this AND `x = TargetConsentID`.
	// Let `C_prime = C - TargetConsentID*G`. Then `C_prime = x'G + yH` where `x'` should be `0`.
	// This is effectively proving `C_prime = yH`.
	// So `ConsentProof` becomes a standard Schnorr for `TargetPoint = secretBlinding * H`.
	// With `A` and `Z`. The `Z1, Z2` fields are superfluous for this specific ZKPoK.

	// Let's adjust `ConsentProof` to reflect a single Schnorr-like proof for `secretBlinding` knowledge.
	// No, the requirement is `Z1, Z2` in the struct. I'll make `Z2` be the response for `secretBlinding`
	// and `Z1` the response for `secretConsentID` (which is publicly known in this context).
	// This would mean proving `C_c - TargetConsentID*G = secretBlinding*H`.
	// And `secretConsentID = TargetConsentID`.
	// Let's make it explicitly prove knowledge of `secretConsentID` and `secretBlinding` and that `secretConsentID` equals `TargetConsentID`.
	// This becomes:
	// 1. Prove knowledge of `secretBlinding` for `C_c - TargetConsentID*G = secretBlinding*H` (Z2).
	// 2. A separate simple proof of `secretConsentID = TargetConsentID` by revealing `secretConsentID` (not ZK for `secretConsentID` itself).
	// This means `secretConsentID` is no longer private.

	// To keep `secretConsentID` private, we need to prove knowledge of `secretConsentID` and `secretBlinding` such that:
	// (1) `C_c = secretConsentID*G + secretBlinding*H` (commitment opens correctly)
	// (2) `secretConsentID == TargetConsentID` (value matches target)
	// This is a special ZKPoK of equality.

	// Prover wants to prove knowledge of `x, y` such that `C = xG + yH` AND `x = T`.
	// Prover chooses random `r1, r2`.
	// Prover computes `A = r1G + r2H`.
	// Verifier (Fiat-Shamir) sends `c = H(A || C || T)`.
	// Prover computes `z1 = r1 + c * x`.
	// Prover computes `z2 = r2 + c * y`.
	// Prover then computes a secondary proof for `x = T`.
	// This is the `C_c - TargetConsentID*G = secretBliding*H` method.

	// Let `TargetPoint = input.CommittedConsentID.Add(Point(G).ScalarMult(input.TargetConsentID).Neg())`
	// This `TargetPoint` should equal `secretBlinding*H`.
	// We generate a Schnorr proof for `secretBlinding` against generator `H` for this `TargetPoint`.

	r, err := Scalar{}.Random(randReader)
	if err != nil {
		return ConsentProof{}, fmt.Errorf("failed to generate random witness `r`: %w", err)
	}

	targetPoint := input.CommittedConsentID.Add(Point(G).ScalarMult(input.TargetConsentID).Neg())

	// A = r*H
	A := Point(H).ScalarMult(r)

	// Challenge c = H(A || targetPoint || H_generator)
	challenge := HashToScalar(A.Bytes(), targetPoint.Bytes(), Point(H).Bytes())

	// Z = r + c * secretBlinding
	cSecretBlinding := secretBlinding.Mul(challenge)
	Z := r.Add(cSecretBlinding)

	// Since `ConsentProof` has `Z1` and `Z2`, let's use `Z1` for `Z` and `Z2` as a dummy or for future extension.
	// For this specific proof, `Z2` is not strictly necessary if we only prove knowledge of `secretBlinding`.
	// To strictly follow the `Z1, Z2` requirement, let's make it a more general ZKPoK for `C = xG + yH` where `x=T`.
	// This would involve proving knowledge of `x` and `y` where `x` is `TargetConsentID`.

	// The `ConsentProof` structure (A, Z1, Z2) is commonly used for proving knowledge of two scalars `x, y` for a commitment `C = xG + yH`.
	// We need to adapt it to prove knowledge of `x,y` for `C_c` AND `x = TargetConsentID`.
	// This is equivalent to proving `y` for `C_c - TargetConsentID*G = yH`.
	// So `Z1` would be the response for the *known* `TargetConsentID` (which is `0` relative to the transformed equation).
	// Let `x_prime = secretConsentID - TargetConsentID`. We prove `x_prime=0`.
	// Let `C_transformed = C_c - TargetConsentID*G`. We prove `C_transformed = x_prime*G + secretBlinding*H`.
	// And we prove `x_prime = 0`.

	// Let's stick to the simplest interpretation that still uses Pedersen commitments and is ZKP:
	// Prover proves: "I know `secretBlinding` such that `(input.CommittedConsentID - input.TargetConsentID*G)` is equal to `secretBlinding*H`."
	// This implicitly proves `secretConsentID = TargetConsentID` because if it didn't, the initial `CommittedConsentID`
	// (which is `secretConsentID*G + secretBlinding*H`) wouldn't allow the equation to hold.

	return ConsentProof{A: A, Z1: Z, Z2: newScalar(big.NewInt(0))}, nil // Z2 is dummy for this specific ZKPoK.
}

// VerifyConsentProof verifies the ZKPoK for consent matching.
func VerifyConsentProof(input ConsentInput, proof ConsentProof) bool {
	// Reconstruct TargetPoint = Cc - Target*G
	targetPoint := input.CommittedConsentID.Add(Point(G).ScalarMult(input.TargetConsentID).Neg())

	// Recompute challenge c = H(A || targetPoint || H_generator)
	challenge := HashToScalar(proof.A.Bytes(), targetPoint.Bytes(), Point(H).Bytes())

	// Verify A == Z*H - c*TargetPoint
	zH := Point(H).ScalarMult(proof.Z1)
	cTargetPoint := targetPoint.ScalarMult(challenge)
	expectedA := zH.Add(cTargetPoint.Neg())

	return proof.A.Equal(expectedA)
}

// --- Aggregate ZKP (AND-Composition via Fiat-Shamir) ---

// AggregateProof combines all individual ZKP proofs.
type AggregateProof struct {
	CredentialProof CredentialMembershipProof
	QualityProof    QualityScoreProof
	ConsentProof    ConsentProof
}

// GenerateAggregateProof generates a combined ZKP proving all three conditions.
// The challenge for each sub-proof is derived from the hash of all public inputs and commitments.
func GenerateAggregateProof(
	credInput CredentialMembershipInput, credTrueIdx int, credSecret Scalar,
	qualityInput QualityScoreInput, qualityTrueIdx int, qualitySecretScore, qualitySecretBlinding Scalar,
	consentInput ConsentInput, consentSecretID, consentSecretBlinding Scalar,
	randReader io.Reader,
) (AggregateProof, error) {
	// Prover generates each sub-proof independently using its secret inputs.
	// The Fiat-Shamir heuristic implies that the "random challenges" for each sub-proof
	// are derived from a hash of *all* public inputs and previous commitments.
	// For simplicity in implementation, we treat each sub-proof generation as if it had
	// its own independent source of "random challenges" (from `randReader` or internal Fiat-Shamir).
	// The `VerifyAggregateProof` will check the overall consistency.

	// In a true NIZK aggregate, each sub-proof would be constructed sequentially,
	// with challenges for `k`th proof depending on `1..k-1` proofs.
	// For this setup, we assume sub-proofs themselves encapsulate the NIZK via Fiat-Shamir internally
	// (as implemented by `HashToScalar` in `GenerateCredentialMembershipProof` etc.)
	// and the `AggregateProof` merely combines these separate NIZKs.

	credProof, err := GenerateCredentialMembershipProof(credInput, credTrueIdx, credSecret, randReader)
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	qualityProof, err := GenerateQualityScoreProof(qualityInput, qualityTrueIdx, qualitySecretScore, qualitySecretBlinding, randReader)
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to generate quality proof: %w", err)
	}

	consentProof, err := GenerateConsentProof(consentInput, consentSecretID, consentBlinding, randReader)
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to generate consent proof: %w", err)
	}

	return AggregateProof{
		CredentialProof: credProof,
		QualityProof:    qualityProof,
		ConsentProof:    consentProof,
	}, nil
}

// VerifyAggregateProof verifies all three combined ZKP proofs.
func VerifyAggregateProof(
	credInput CredentialMembershipInput, qualityInput QualityScoreInput, consentInput ConsentInput,
	aggregateProof AggregateProof,
) bool {
	// Verifier independently verifies each sub-proof.
	// Since each `Generate` function already incorporates `HashToScalar` for its internal challenges,
	// this sequential verification is sound for an "AND" composition.
	if !VerifyCredentialMembershipProof(credInput, aggregateProof.CredentialProof) {
		return false
	}
	if !VerifyQualityScoreProof(qualityInput, aggregateProof.QualityProof) {
		return false
	}
	if !VerifyConsentProof(consentInput, aggregateProof.ConsentProof) {
		return false
	}
	return true
}

// --- Serialization/Deserialization for Proofs ---

// asn1Point is a helper struct for ASN.1 marshaling of elliptic.Point
type asn1Point struct {
	X *big.Int
	Y *big.Int
}

// asn1Scalar is a helper struct for ASN.1 marshaling of Scalar
type asn1Scalar struct {
	S *big.Int
}

// MarshalScalar marshals a Scalar to ASN.1 DER bytes.
func MarshalScalar(s Scalar) ([]byte, error) {
	return asn1.Marshal(asn1Scalar{S: (*big.Int)(&s)})
}

// UnmarshalScalar unmarshals ASN.1 DER bytes to a Scalar.
func UnmarshalScalar(b []byte) (Scalar, error) {
	var as asn1Scalar
	_, err := asn1.Unmarshal(b, &as)
	if err != nil {
		return Scalar{}, err
	}
	return newScalar(as.S), nil
}

// MarshalPoint marshals a Point to ASN.1 DER bytes.
func MarshalPoint(p Point) ([]byte, error) {
	return asn1.Marshal(asn1Point{X: p.X, Y: p.Y})
}

// UnmarshalPoint unmarshals ASN.1 DER bytes to a Point.
func UnmarshalPoint(b []byte) (Point, error) {
	var ap asn1Point
	_, err := asn1.Unmarshal(b, &ap)
	if err != nil {
		return Point{}, err
	}
	return newPoint(ap.X, ap.Y), nil
}

// ProofASN1 represents the ASN.1 structure for AggregateProof for easy serialization.
type ProofASN1 struct {
	CredentialProof asn1.RawValue
	QualityProof    asn1.RawValue
	ConsentProof    asn1.RawValue
}

// marshalZKPSchnorrSubProof marshals a ZKPSchnorrSubProof to JSON bytes.
func marshalZKPSchnorrSubProof(sp ZKPSchnorrSubProof) ([]byte, error) {
	type tempSubProof struct {
		A []byte
		Z []byte
		C []byte
	}
	tsp := tempSubProof{
		A: sp.A.Bytes(),
		Z: sp.Z.Bytes(),
		C: sp.C.Bytes(),
	}
	return json.Marshal(tsp)
}

// unmarshalZKPSchnorrSubProof unmarshals JSON bytes to a ZKPSchnorrSubProof.
func unmarshalZKPSchnorrSubProof(b []byte) (ZKPSchnorrSubProof, error) {
	type tempSubProof struct {
		A []byte
		Z []byte
		C []byte
	}
	var tsp tempSubProof
	if err := json.Unmarshal(b, &tsp); err != nil {
		return ZKPSchnorrSubProof{}, err
	}
	A, err := BytesToPoint(tsp.A)
	if err != nil {
		return ZKPSchnorrSubProof{}, err
	}
	return ZKPSchnorrSubProof{
		A: A,
		Z: BytesToScalar(tsp.Z),
		C: BytesToScalar(tsp.C),
	}, nil
}

// marshalCredentialMembershipProof marshals a CredentialMembershipProof to JSON bytes.
func marshalCredentialMembershipProof(proof CredentialMembershipProof) ([]byte, error) {
	var subProofBytes [][]byte
	for _, sp := range proof.SubProofs {
		b, err := marshalZKPSchnorrSubProof(sp)
		if err != nil {
			return nil, err
		}
		subProofBytes = append(subProofBytes, b)
	}
	return json.Marshal(subProofBytes)
}

// unmarshalCredentialMembershipProof unmarshals JSON bytes to a CredentialMembershipProof.
func unmarshalCredentialMembershipProof(b []byte) (CredentialMembershipProof, error) {
	var subProofBytes [][]byte
	if err := json.Unmarshal(b, &subProofBytes); err != nil {
		return CredentialMembershipProof{}, err
	}
	var subProofs []ZKPSchnorrSubProof
	for _, sb := range subProofBytes {
		sp, err := unmarshalZKPSchnorrSubProof(sb)
		if err != nil {
			return CredentialMembershipProof{}, err
		}
		subProofs = append(subProofs, sp)
	}
	return CredentialMembershipProof{SubProofs: subProofs}, nil
}

// marshalQualityScoreProof marshals a QualityScoreProof to JSON bytes.
func marshalQualityScoreProof(proof QualityScoreProof) ([]byte, error) {
	var subProofBytes [][]byte
	for _, sp := range proof.SubProofs {
		b, err := marshalZKPSchnorrSubProof(sp)
		if err != nil {
			return nil, err
		}
		subProofBytes = append(subProofBytes, b)
	}
	return json.Marshal(subProofBytes)
}

// unmarshalQualityScoreProof unmarshals JSON bytes to a QualityScoreProof.
func unmarshalQualityScoreProof(b []byte) (QualityScoreProof, error) {
	var subProofBytes [][]byte
	if err := json.Unmarshal(b, &subProofBytes); err != nil {
		return QualityScoreProof{}, err
	}
	var subProofs []ZKPSchnorrSubProof
	for _, sb := range subProofBytes {
		sp, err := unmarshalZKPSchnorrSubProof(sb)
		if err != nil {
			return QualityScoreProof{}, err
		}
		subProofs = append(subProofs, sp)
	}
	return QualityScoreProof{SubProofs: subProofs}, nil
}

// marshalConsentProof marshals a ConsentProof to JSON bytes.
func marshalConsentProof(proof ConsentProof) ([]byte, error) {
	type tempConsentProof struct {
		A  []byte
		Z1 []byte
		Z2 []byte
	}
	tcp := tempConsentProof{
		A:  proof.A.Bytes(),
		Z1: proof.Z1.Bytes(),
		Z2: proof.Z2.Bytes(),
	}
	return json.Marshal(tcp)
}

// unmarshalConsentProof unmarshals JSON bytes to a ConsentProof.
func unmarshalConsentProof(b []byte) (ConsentProof, error) {
	type tempConsentProof struct {
		A  []byte
		Z1 []byte
		Z2 []byte
	}
	var tcp tempConsentProof
	if err := json.Unmarshal(b, &tcp); err != nil {
		return ConsentProof{}, err
	}
	A, err := BytesToPoint(tcp.A)
	if err != nil {
		return ConsentProof{}, err
	}
	return ConsentProof{
		A:  A,
		Z1: BytesToScalar(tcp.Z1),
		Z2: BytesToScalar(tcp.Z2),
	}, nil
}

// MarshalAggregateProof marshals an AggregateProof into a JSON byte slice.
func MarshalAggregateProof(proof AggregateProof) ([]byte, error) {
	credB, err := marshalCredentialMembershipProof(proof.CredentialProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential proof: %w", err)
	}
	qualB, err := marshalQualityScoreProof(proof.QualityProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal quality proof: %w", err)
	}
	consB, err := marshalConsentProof(proof.ConsentProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal consent proof: %w", err)
	}

	aggProofMap := map[string]json.RawMessage{
		"CredentialProof": json.RawMessage(credB),
		"QualityProof":    json.RawMessage(qualB),
		"ConsentProof":    json.RawMessage(consB),
	}

	return json.Marshal(aggProofMap)
}

// UnmarshalAggregateProof unmarshals a JSON byte slice into an AggregateProof.
func UnmarshalAggregateProof(b []byte) (AggregateProof, error) {
	var aggProofMap map[string]json.RawMessage
	if err := json.Unmarshal(b, &aggProofMap); err != nil {
		return AggregateProof{}, fmt.Errorf("failed to unmarshal aggregate proof map: %w", err)
	}

	credProof, err := unmarshalCredentialMembershipProof(aggProofMap["CredentialProof"])
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to unmarshal credential proof: %w", err)
	}
	qualProof, err := unmarshalQualityScoreProof(aggProofMap["QualityProof"])
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to unmarshal quality proof: %w", err)
	}
	consProof, err := unmarshalConsentProof(aggProofMap["ConsentProof"])
	if err != nil {
		return AggregateProof{}, fmt.Errorf("failed to unmarshal consent proof: %w", err)
	}

	return AggregateProof{
		CredentialProof: credProof,
		QualityProof:    qualProof,
		ConsentProof:    consProof,
	}, nil
}
```