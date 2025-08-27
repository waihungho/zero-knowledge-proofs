```go
package zkpshare

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// Outline and Function Summary
//
// This Zero-Knowledge Proof (ZKP) implementation in Golang focuses on a creative and trendy application:
// "Verifiable Secret Share in Distributed Key Generation (DKG)".
// In DKG, participants generate shares of a master private key. It's crucial that these shares are valid
// and that their corresponding public key shares are correctly derived. This ZKP allows a participant
// to prove knowledge of their secret share and its consistency with public values, without revealing the share itself.
//
// The system implements a custom, non-interactive, Fiat-Shamir transformed Proof of Knowledge (PoK)
// that simultaneously proves:
// 1. Knowledge of a secret scalar `s` (the private key share).
// 2. That a public elliptic curve point `P_pub` is correctly derived from `s` (i.e., `P_pub = s * G`, where `G` is the curve generator).
// 3. That a public Pedersen commitment `C_s` (i.e., `C_s = s * G + r * H`, where `r` is a blinding factor and `H` is another generator)
//    is consistent with the same secret `s` and a secret `r`.
//
// This combined proof is a foundational building block for many advanced cryptographic protocols,
// ensuring the integrity of distributed computations involving secret values.
// The "range" aspect of the share is handled conceptually by the prover ensuring their share falls within a
// valid range before generating the proof; the ZKP itself proves the *consistency* of the share,
// not its specific bounds in a zero-knowledge manner (a full zero-knowledge range proof like Bulletproofs
// would be significantly more complex and outside the scope of "20 functions" without duplication).
//
// Function Summary:
//
// I. Core Cryptographic Primitives (Elliptic Curve & Finite Field)
//    1.  `FieldScalar`: struct wrapping *big.Int for finite field elements.
//    2.  `NewFieldScalar(val *big.Int, order *big.Int) *FieldScalar`: Creates a new FieldScalar, reducing value mod order.
//    3.  `FieldScalar.Add(a, b *FieldScalar) *FieldScalar`: Field addition (a + b) mod order.
//    4.  `FieldScalar.Sub(a, b *FieldScalar) *FieldScalar`: Field subtraction (a - b) mod order.
//    5.  `FieldScalar.Mul(a, b *FieldScalar) *FieldScalar`: Field multiplication (a * b) mod order.
//    6.  `FieldScalar.Inv(a *FieldScalar) *FieldScalar`: Modular multiplicative inverse of a FieldScalar.
//    7.  `FieldScalar.Equal(other *FieldScalar) bool`: Checks if two FieldScalars are equal.
//    8.  `FieldScalar.Bytes() []byte`: Converts FieldScalar to its big-endian byte representation.
//    9.  `FieldScalar.FromBytes(b []byte, order *big.Int) *FieldScalar`: Converts a byte slice to a FieldScalar.
//    10. `RandFieldScalar(randSource io.Reader, order *big.Int) *FieldScalar`: Generates a random FieldScalar in [0, order-1].
//    11. `ECPoint`: struct wrapping elliptic.Curve and *big.Int for X, Y coordinates.
//    12. `NewECPoint(x, y *big.Int, curve elliptic.Curve) *ECPoint`: Creates a new ECPoint.
//    13. `ECPoint.Add(p1, p2 *ECPoint) *ECPoint`: Performs elliptic curve point addition p1 + p2.
//    14. `ECPoint.ScalarMul(p *ECPoint, s *FieldScalar) *ECPoint`: Performs scalar multiplication p * s.
//    15. `ECPoint.Equal(p1, p2 *ECPoint) bool`: Checks if two ECPoints are equal.
//    16. `ECParams`: struct holding elliptic curve parameters (Curve, G_Base, H_Commit).
//    17. `DefaultECParams() *ECParams`: Initializes default curve parameters (secp256k1) and generators.
//    18. `HashToECPoint(data []byte, params *ECParams) *ECPoint`: Deterministically maps data to an ECPoint on the curve.
//    19. `HashToFieldScalar(data ...[]byte) *FieldScalar`: Deterministically hashes data to a FieldScalar (Fiat-Shamir challenge).
//    20. `PointMarshalBinary(p *ECPoint) ([]byte, error)`: Serializes an ECPoint to its compressed binary form.
//    21. `PointUnmarshalBinary(b []byte, curve elliptic.Curve) (*ECPoint, error)`: Deserializes an ECPoint from binary.
//
// II. Pedersen Commitment (Basic)
//    22. `PedersenCommitment(value *FieldScalar, blinding *FieldScalar, G, H *ECPoint) *ECPoint`: Computes C = value*G + blinding*H.
//    23. `VerifyPedersenCommitment(C *ECPoint, value *FieldScalar, blinding *FieldScalar, G, H *ECPoint) bool`: Verifies a Pedersen commitment opening.
//
// III. Proof of Knowledge for DKG Share and Consistency Proof (Custom ZKP)
//    24. `DKGShareProof`: struct storing the proof components (A_s, A_r, Z_s, Z_r).
//    25. `GenerateDKGShareProof(secretShare *FieldScalar, blindingFactor *FieldScalar, params *ECParams) (*DKGShareProof, *ECPoint, *ECPoint)`:
//        Prover's main function. Generates the ZKP, the public key share (P = sG), and the commitment (C = sG + rH).
//    26. `VerifyDKGShareProof(proof *DKGShareProof, publicKeyShare *ECPoint, commitment *ECPoint, params *ECParams) bool`:
//        Verifier's main function. Verifies the DKGShareProof against public key share and commitment.
//
// IV. Application-Specific Utilities for DKG (Helpers for Prover/Simulation)
//    27. `IsScalarInBounds(s *FieldScalar, min, max *FieldScalar) bool`: Checks if a scalar is within a given range (prover-side validation).
//    28. `GenerateRandomShare(randSource io.Reader, maxShareValue *FieldScalar, order *big.Int) *FieldScalar`:
//        Generates a random FieldScalar within a specified bound, suitable for a DKG share.
//    29. `DKGMessage`: struct to encapsulate a participant's public DKG contribution (Public Key Share, Commitment, Proof).
//    30. `NewDKGParticipant(id int, maxShareVal *FieldScalar, params *ECParams) (secretShare *FieldScalar, blindingFactor *FieldScalar, dkgMsg *DKGMessage)`:
//        Simulates a DKG participant generating their secret share, blinding factor, public key, commitment, and proof,
//        packaging it into a `DKGMessage` for broadcast.
//

// I. Core Cryptographic Primitives (Elliptic Curve & Finite Field)

// FieldScalar represents an element in the finite field Z_N where N is the order of the curve.
type FieldScalar struct {
	val   *big.Int
	order *big.Int // The order of the scalar field (e.g., N for elliptic curves)
}

// 1. NewFieldScalar creates a new FieldScalar, reducing the value modulo the curve order.
func NewFieldScalar(val *big.Int, order *big.Int) *FieldScalar {
	v := new(big.Int).Set(val)
	return &FieldScalar{val: v.Mod(v, order), order: order}
}

// 2. FieldScalar.Add performs field addition (a + b) mod N.
func (fs *FieldScalar) Add(a, b *FieldScalar) *FieldScalar {
	res := new(big.Int).Add(a.val, b.val)
	return NewFieldScalar(res, fs.order)
}

// 3. FieldScalar.Sub performs field subtraction (a - b) mod N.
func (fs *FieldScalar) Sub(a, b *FieldScalar) *FieldScalar {
	res := new(big.Int).Sub(a.val, b.val)
	return NewFieldScalar(res, fs.order)
}

// 4. FieldScalar.Mul performs field multiplication (a * b) mod N.
func (fs *FieldScalar) Mul(a, b *FieldScalar) *FieldScalar {
	res := new(big.Int).Mul(a.val, b.val)
	return NewFieldScalar(res, fs.order)
}

// 5. FieldScalar.Inv computes the modular inverse of a FieldScalar (a^-1) mod N.
func (fs *FieldScalar) Inv(a *FieldScalar) *FieldScalar {
	res := new(big.Int).ModInverse(a.val, fs.order)
	if res == nil {
		panic("Modular inverse does not exist (element is not coprime to order)")
	}
	return NewFieldScalar(res, fs.order)
}

// 6. FieldScalar.Equal checks if two FieldScalars are equal.
func (fs *FieldScalar) Equal(other *FieldScalar) bool {
	if fs == nil || other == nil {
		return fs == other // Both nil, or one nil
	}
	return fs.val.Cmp(other.val) == 0 && fs.order.Cmp(other.order) == 0
}

// 7. FieldScalar.Bytes converts the FieldScalar to a byte slice.
func (fs *FieldScalar) Bytes() []byte {
	return fs.val.Bytes()
}

// 8. FieldScalar.FromBytes converts a byte slice to a FieldScalar.
func (fs *FieldScalar) FromBytes(b []byte, order *big.Int) *FieldScalar {
	val := new(big.Int).SetBytes(b)
	return NewFieldScalar(val, order)
}

// 9. RandFieldScalar generates a random FieldScalar in [0, order-1].
func RandFieldScalar(randSource io.Reader, order *big.Int) *FieldScalar {
	val, err := rand.Int(randSource, order)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random FieldScalar: %v", err))
	}
	return NewFieldScalar(val, order)
}

// ECPoint represents an elliptic curve point.
type ECPoint struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

// 10. NewECPoint creates a new ECPoint.
func NewECPoint(x, y *big.Int, curve elliptic.Curve) *ECPoint {
	if !curve.IsOnCurve(x, y) {
		// Allow point at infinity (0,0) as a special case, otherwise panic for invalid points.
		if !(x.Cmp(big.NewInt(0)) == 0 && y.Cmp(big.NewInt(0)) == 0) {
			panic("NewECPoint: Point not on curve")
		}
	}
	return &ECPoint{X: x, Y: y, Curve: curve}
}

// 11. ECPoint.Add performs elliptic curve point addition p1 + p2.
func (p *ECPoint) Add(p1, p2 *ECPoint) *ECPoint {
	x, y := p.Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	return NewECPoint(x, y, p.Curve)
}

// 12. ECPoint.ScalarMul performs scalar multiplication p * s.
func (p *ECPoint) ScalarMul(point *ECPoint, s *FieldScalar) *ECPoint {
	x, y := p.Curve.ScalarMult(point.X, point.Y, s.val.Bytes())
	return NewECPoint(x, y, p.Curve)
}

// 13. ECPoint.Equal checks if two ECPoints are equal.
func (p *ECPoint) Equal(p1, p2 *ECPoint) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2 // Both nil, or one nil
	}
	return p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0
}

// ECParams holds elliptic curve parameters including generators.
type ECParams struct {
	Curve    elliptic.Curve
	G_Base   *ECPoint // Base generator point
	H_Commit *ECPoint // Second generator for Pedersen commitments, distinct from G_Base
}

// 14. DefaultECParams initializes default curve parameters (secp256k1).
func DefaultECParams() *ECParams {
	curve := elliptic.P256() // Using P256 for this example for general availability

	// G_Base
	Gx, Gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	gBase := NewECPoint(Gx, Gy, curve)

	params := &ECParams{
		Curve:  curve,
		G_Base: gBase,
	}

	// 15. HashToECPoint (called internally by DefaultECParams to generate H_Commit)
	// Now generate H_Commit using HashToECPoint.
	hCommitData := []byte("ZKPSHARE_H_COMMIT_GENERATOR_SEED")
	params.H_Commit = HashToECPoint(hCommitData, params)

	return params
}

// 16. HashToECPoint deterministically maps data to an ECPoint.
// This uses a method of hashing the seed to a scalar and then multiplying G by that scalar.
// This ensures the resulting point is on the curve and distinct.
func HashToECPoint(data []byte, params *ECParams) *ECPoint {
	hasher := sha256.New()
	hasher.Write(data)
	hashBytes := hasher.Sum(nil)

	// Multiply G_Base by the hash as a scalar.
	// Ensure the scalar is not zero.
	hScalar := NewFieldScalar(new(big.Int).SetBytes(hashBytes), params.Curve.Params().N)
	if hScalar.val.Cmp(big.NewInt(0)) == 0 {
		// If the hash results in zero, add a fixed offset to avoid point at infinity or G=H.
		hScalar = NewFieldScalar(big.NewInt(1), params.Curve.Params().N).Add(hScalar, NewFieldScalar(big.NewInt(1), params.Curve.Params().N))
	}
	// To ensure H is distinct from G, we can add a small constant if hScalar happens to be 1.
	if hScalar.val.Cmp(big.NewInt(1)) == 0 {
		hScalar = hScalar.Add(hScalar, NewFieldScalar(big.NewInt(1), params.Curve.Params().N)) // hScalar = 2
	}

	return params.G_Base.ScalarMul(params.G_Base, hScalar)
}

// 17. HashToFieldScalar deterministically hashes data to a FieldScalar (Fiat-Shamir).
func HashToFieldScalar(data ...[]byte) *FieldScalar {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	hashBytes := hasher.Sum(nil)
	// We need the curve order to create the FieldScalar correctly.
	curve := elliptic.P256() // Default curve for challenge generation
	return NewFieldScalar(new(big.Int).SetBytes(hashBytes), curve.Params().N)
}

// 18. PointMarshalBinary serializes an ECPoint to binary.
func PointMarshalBinary(p *ECPoint) ([]byte, error) {
	if p == nil || p.X == nil || p.Y == nil {
		// Treat point at infinity (0,0) as a valid case for marshalling if needed,
		// but typically it means an uninitialized point.
		if p != nil && p.X.Cmp(big.NewInt(0)) == 0 && p.Y.Cmp(big.NewInt(0)) == 0 {
			// Specific handling for point at infinity, e.g., return a fixed small byte slice
			return []byte{0}, nil 
		}
		return nil, fmt.Errorf("cannot marshal nil or uninitialized ECPoint coordinates")
	}
	return elliptic.Marshal(p.Curve, p.X, p.Y), nil
}

// 19. PointUnmarshalBinary deserializes an ECPoint from binary.
func PointUnmarshalBinary(b []byte, curve elliptic.Curve) (*ECPoint, error) {
	if len(b) == 1 && b[0] == 0 { // Special case for point at infinity
		return NewECPoint(big.NewInt(0), big.NewInt(0), curve), nil
	}
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal ECPoint: invalid byte slice")
	}
	return NewECPoint(x, y, curve), nil
}

// II. Pedersen Commitment (Basic)

// 20. PedersenCommitment computes C = value*G + blinding*H.
func PedersenCommitment(value *FieldScalar, blinding *FieldScalar, G, H *ECPoint) *ECPoint {
	sG := G.ScalarMul(G, value)
	rH := H.ScalarMul(H, blinding)
	return G.Add(sG, rH)
}

// 21. VerifyPedersenCommitment verifies a Pedersen commitment opening.
func VerifyPedersenCommitment(C *ECPoint, value *FieldScalar, blinding *FieldScalar, G, H *ECPoint) bool {
	expectedC := PedersenCommitment(value, blinding, G, H)
	return C.Equal(C, expectedC)
}

// III. Proof of Knowledge for DKG Share and Consistency Proof (Custom ZKP)

// 22. DKGShareProof stores the components of the ZKP.
type DKGShareProof struct {
	A_s *ECPoint   // Commitment to random nonce for s*G (rho_s * G)
	A_r *ECPoint   // Commitment to random nonce for s*G + r*H (rho_s * G + rho_r * H)
	Z_s *FieldScalar // Response for s (rho_s + c * s)
	Z_r *FieldScalar // Response for r (rho_r + c * r)
}

// 23. GenerateDKGShareProof is the prover's main function.
// It generates the ZKP, the public key share (P = sG), and the commitment (C = sG + rH).
func GenerateDKGShareProof(secretShare *FieldScalar, blindingFactor *FieldScalar, params *ECParams) (*DKGShareProof, *ECPoint, *ECPoint) {
	// Compute public key share P = sG
	publicKeyShare := params.G_Base.ScalarMul(params.G_Base, secretShare)

	// Compute commitment C = sG + rH
	commitment := PedersenCommitment(secretShare, blindingFactor, params.G_Base, params.H_Commit)

	// Generate random nonces rho_s, rho_r in Z_N
	rho_s := RandFieldScalar(rand.Reader, params.Curve.Params().N)
	rho_r := RandFieldScalar(rand.Reader, params.Curve.Params().N)

	// Compute challenge commitments A_s, A_r
	A_s := params.G_Base.ScalarMul(params.G_Base, rho_s)
	A_r_commit := PedersenCommitment(rho_s, rho_r, params.G_Base, params.H_Commit)

	// Compute challenge 'c' using Fiat-Shamir transform
	// Concatenate all public values to ensure soundness
	pkBytes, _ := PointMarshalBinary(publicKeyShare)
	cmBytes, _ := PointMarshalBinary(commitment)
	asBytes, _ := PointMarshalBinary(A_s)
	arBytes, _ := PointMarshalBinary(A_r_commit)

	challenge := HashToFieldScalar(pkBytes, cmBytes, asBytes, arBytes)

	// Compute responses Z_s, Z_r
	// Z_s = rho_s + c * s
	c_s := secretShare.Mul(challenge, secretShare)
	Z_s := rho_s.Add(rho_s, c_s)

	// Z_r = rho_r + c * r
	c_r := blindingFactor.Mul(challenge, blindingFactor)
	Z_r := rho_r.Add(rho_r, c_r)

	proof := &DKGShareProof{
		A_s: A_s,
		A_r: A_r_commit,
		Z_s: Z_s,
		Z_r: Z_r,
	}

	return proof, publicKeyShare, commitment
}

// 24. VerifyDKGShareProof is the verifier's main function.
// It verifies the DKGShareProof against public key share and commitment.
func VerifyDKGShareProof(proof *DKGShareProof, publicKeyShare *ECPoint, commitment *ECPoint, params *ECParams) bool {
	// Recompute challenge 'c' using Fiat-Shamir transform
	pkBytes, _ := PointMarshalBinary(publicKeyShare)
	cmBytes, _ := PointMarshalBinary(commitment)
	asBytes, _ := PointMarshalBinary(proof.A_s)
	arBytes, _ := PointMarshalBinary(proof.A_r)

	challenge := HashToFieldScalar(pkBytes, cmBytes, asBytes, arBytes)

	// Check Equation 1: Z_s * G == A_s + c * P_pub
	left1 := params.G_Base.ScalarMul(params.G_Base, proof.Z_s)
	c_P_pub := publicKeyShare.ScalarMul(publicKeyShare, challenge)
	right1 := proof.A_s.Add(proof.A_s, c_P_pub)
	if !left1.Equal(left1, right1) {
		return false
	}

	// Check Equation 2: Z_s * G + Z_r * H == A_r + c * C_s
	Z_s_G := params.G_Base.ScalarMul(params.G_Base, proof.Z_s)
	Z_r_H := params.H_Commit.ScalarMul(params.H_Commit, proof.Z_r)
	left2 := Z_s_G.Add(Z_s_G, Z_r_H)

	c_C_s := commitment.ScalarMul(commitment, challenge)
	right2 := proof.A_r.Add(proof.A_r, c_C_s)

	if !left2.Equal(left2, right2) {
		return false
	}

	return true // Both equations hold, proof is valid
}

// IV. Application-Specific Utilities for DKG (Helpers for Prover/Simulation)

// 25. IsScalarInBounds checks if a scalar is within a given range (prover-side validation).
// This is not a zero-knowledge proof itself but a utility function a prover would use
// to ensure their secret share satisfies application-specific constraints before proving.
func IsScalarInBounds(s *FieldScalar, min, max *FieldScalar) bool {
	if s == nil || min == nil || max == nil {
		return false
	}
	// Check s >= min and s <= max
	return s.val.Cmp(min.val) >= 0 && s.val.Cmp(max.val) <= 0
}

// 26. GenerateRandomShare generates a random FieldScalar within a specified bound,
// suitable for a DKG share. The share will be > 0 and <= maxShareValue.
func GenerateRandomShare(randSource io.Reader, maxShareValue *FieldScalar, order *big.Int) *FieldScalar {
	zeroScalar := NewFieldScalar(big.NewInt(0), order)
	for {
		// Generate a random scalar up to the order of the curve.
		candidate := RandFieldScalar(randSource, order)
		
		// Check if share is > 0 and <= maxShareValue
		// maxShareValue.val is an exclusive upper bound, so we check if candidate.val is less than or equal.
		if candidate.val.Cmp(zeroScalar.val) > 0 && candidate.val.Cmp(maxShareValue.val) <= 0 {
			return candidate
		}
	}
}

// 27. DKGMessage encapsulates a participant's public DKG contribution.
type DKGMessage struct {
	ParticipantID  int
	PublicKeyShare *ECPoint
	Commitment     *ECPoint
	Proof          *DKGShareProof
}

// 28. NewDKGParticipant simulates a DKG participant.
// It generates their secret share, blinding factor, public key, commitment, and proof,
// packaging it into a `DKGMessage` for broadcast.
func NewDKGParticipant(id int, maxShareVal *FieldScalar, params *ECParams) (secretShare *FieldScalar, blindingFactor *FieldScalar, dkgMsg *DKGMessage) {
	// Generate a valid secret share
	s := GenerateRandomShare(rand.Reader, maxShareVal, params.Curve.Params().N)

	// Generate a random blinding factor
	r := RandFieldScalar(rand.Reader, params.Curve.Params().N)

	// Generate the DKG proof
	proof, pkShare, commit := GenerateDKGShareProof(s, r, params)

	dkgMsg = &DKGMessage{
		ParticipantID:  id,
		PublicKeyShare: pkShare,
		Commitment:     commit,
		Proof:          proof,
	}

	return s, r, dkgMsg
}
```