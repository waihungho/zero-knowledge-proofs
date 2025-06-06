```go
// Package zkpattribute provides a non-interactive Zero-Knowledge Proof (ZKP) system
// for proving statements about committed attributes using Pedersen commitments
// and a composed Fiat-Shamir protocol.
//
// This implementation focuses on proving knowledge of commitment openings,
// equality between committed attribute values, and knowledge of the preimage
// of a public point under scalar multiplication (a form of Discrete Log).
//
// It orchestrates multiple such proofs over a set of committed attributes
// into a single, non-interactive proof using a shared transcript and the
// Fiat-Shamir heuristic. This enables proving complex statements like:
// "I know the values of attributes 'age' and 'salary', the committed 'age'
// is greater than 18 (using equality/DL proof relating to a derived point),
// and my 'salary' committed value equals my 'income' committed value".
//
// This is an advanced concept combining multiple basic ZKP building blocks
// and their composition for a specific application (verifiable attributes)
// without directly replicating a full, standard ZK-SNARK/STARK library,
// focusing on Pedersen and Schnorr-like components.
//
// Outline:
// 1.  Elliptic Curve and Scalar Arithmetic Helpers
// 2.  Transcript Management for Fiat-Shamir
// 3.  Pedersen Commitment Structure and Functions
// 4.  Attribute Data Structures (Commitment, Witness, Statement, Request, Proof)
// 5.  Core ZKP Component Implementations (Prove/Verify Knowledge of Opening, Equality, Discrete Log)
// 6.  Composite Proof Logic (ProveAttributes, VerifyAttributes)
// 7.  Utility and Marshalling Functions
//
// Function Summary:
// - Scalar arithmetic (Add, Mul, IsZero, IsEqual, etc. modulo curve order)
// - Point arithmetic (Add, ScalarMul, IsOnCurve, etc.)
// - HashToScalar: Deterministically map data to a scalar.
// - SetupPedersen: Initialize public parameters (G, H).
// - Commit, CommitWithRandomness: Create Pedersen commitments.
// - Transcript methods (AppendPoint, AppendScalar, GenerateChallenge): Build Fiat-Shamir challenge.
// - Attribute data structures (NewAttributeCommitment, NewAttributeWitness, NewAttributeStatement, etc.)
// - ProveOpeningPhase1/2, VerifyOpeningComponent: ZKP of knowledge of commitment opening.
// - ProveEqualityPhase1/2, VerifyEqualityComponent: ZKP of equality of committed values.
// - ProveDiscreteLogPhase1/2, VerifyDiscreteLogComponent: ZKP of knowledge of discrete log (preimage point).
// - ProveAttributes: The main prover function, combines individual proofs using a shared transcript.
// - VerifyAttributes: The main verifier function, verifies combined proof against shared challenge.
// - Marshalling/Unmarshalling: Convert structures to/from bytes for serialization (e.g., ProofToBytes, BytesToProof).
// - Utility functions (CheckProofRequestConsistency, CheckProofConsistency).

package zkpattribute

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// Using P256 for simplicity. Could use other curves like secp256k1.
var curve = elliptic.P256()
var order = curve.Params().N
var G = curve.Params().G

// --- 1. Elliptic Curve and Scalar Arithmetic Helpers ---

// GenerateRandomScalar returns a cryptographically secure random scalar [1, order-1].
func GenerateRandomScalar() (*big.Int, error) {
	// rand.Int returns [0, max-1], we need [1, order-1]
	// Generate a random number in the range [0, order-1]
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	// Ensure scalar is not zero, regenerate if necessary (highly improbable)
	for k.Sign() == 0 {
		k, err = rand.Int(rand.Reader, order)
		if err != nil {
			return nil, fmt.Errorf("failed to generate non-zero random scalar: %w", err)
		}
	}
	return k, nil
}

// ScalarAdd returns a + b mod order.
func ScalarAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b).Mod(order, order)
}

// ScalarSub returns a - b mod order.
func ScalarSub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b).Mod(order, order)
}

// ScalarMul returns a * b mod order.
func ScalarMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b).Mod(order, order)
}

// ScalarNeg returns -a mod order.
func ScalarNeg(a *big.Int) *big.Int {
	return new(big.Int).Neg(a).Mod(order, order)
}

// PointScalarMul performs scalar multiplication s * P.
func PointScalarMul(s *big.Int, Px, Py *big.Int) (x, y *big.Int) {
	return curve.ScalarMult(Px, Py, s.Bytes())
}

// PointAdd performs point addition P + Q.
func PointAdd(Px, Py, Qx, Qy *big.Int) (x, y *big.Int) {
	return curve.Add(Px, Py, Qx, Qy)
}

// HashToScalar hashes arbitrary data and maps the result to a scalar modulo order.
// This is a standard technique for deriving challenges or group elements.
// Uses SHA256 and reduces the hash output modulo the curve order.
func HashToScalar(data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hashBytes := h.Sum(nil)
	// Map hash output to a scalar in [0, order-1]
	return new(big.Int).SetBytes(hashBytes).Mod(order, order)
}

// --- 2. Transcript Management for Fiat-Shamir ---

// Transcript manages the state for deterministic challenge generation.
type Transcript struct {
	state []byte
}

// NewTranscript creates a new empty transcript.
func NewTranscript() *Transcript {
	// Initialize with a unique domain separation tag for this protocol
	initialState := sha256.Sum256([]byte("ZKPAttributeProofTranscript"))
	return &Transcript{state: initialState[:]}
}

// AppendPoint adds a point to the transcript state.
func (t *Transcript) AppendPoint(label string, x, y *big.Int) error {
	// Use Marshal to get a standard byte representation of the point
	pointBytes := elliptic.Marshal(curve, x, y)
	if pointBytes == nil {
		return fmt.Errorf("failed to marshal point for transcript")
	}
	h := sha256.New()
	h.Write(t.state)
	h.Write([]byte(label)) // Domain separation for different appended data types
	h.Write(pointBytes)
	t.state = h.Sum(nil)
	return nil
}

// AppendScalar adds a scalar to the transcript state.
func (t *Transcript) AppendScalar(label string, s *big.Int) {
	h := sha256.New()
	h.Write(t.state)
	h.Write([]byte(label)) // Domain separation
	// Use Bytes() which returns big-endian byte representation.
	// Pad to order length if needed, but Mod() ensures it's within range.
	// For robustness, pad to the byte length of the curve order.
	scalarBytes := s.Bytes()
	paddedScalarBytes := make([]byte, (order.BitLen()+7)/8)
	copy(paddedScalarBytes[len(paddedScalarBytes)-len(scalarBytes):], scalarBytes)

	h.Write(paddedScalarBytes)
	t.state = h.Sum(nil)
}

// AppendBytes adds arbitrary bytes to the transcript state.
func (t *Transcript) AppendBytes(label string, b []byte) {
	h := sha256.New()
	h.Write(t.state)
	h.Write([]byte(label)) // Domain separation
	h.Write(b)
	t.state = h.Sum(nil)
}

// GenerateChallenge generates a challenge scalar from the current transcript state.
// The label helps provide domain separation if multiple challenges are needed from one transcript (less common in simple FS).
func (t *Transcript) GenerateChallenge(label string) *big.Int {
	h := sha256.New()
	h.Write(t.state)
	h.Write([]byte(label)) // Domain separation for this specific challenge
	challengeBytes := h.Sum(nil)
	// Map hash output to a scalar in [0, order-1]
	return new(big.Int).SetBytes(challengeBytes).Mod(order, order)
}

// --- 3. Pedersen Commitment Structure and Functions ---

// PedersenParams holds the public parameters for Pedersen commitments.
type PedersenParams struct {
	Gx, Gy *big.Int // Base point G of the curve (usually curve.Params().G)
	Hx, Hy *big.Int // Second base point H, random and not a multiple of G (ideally)
	Curve  elliptic.Curve
	Order  *big.Int
}

// SetupPedersen generates the public parameters for Pedersen commitments.
// In a real-world setup, H should be chosen carefully, e.g., hashing G with a unique label.
// For this example, we select H = s*G for a secret random s, and discard s.
func SetupPedersen() (*PedersenParams, error) {
	// Choose a random scalar s
	s, err := GenerateRandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate scalar for H: %w", err)
	}

	// Compute H = s * G
	Hx, Hy := PointScalarMul(s, Gx, Gy)

	return &PedersenParams{
		Gx:    Gx,
		Gy:    Gy,
		Hx:    Hx,
		Hy:    Hy,
		Curve: curve,
		Order: order,
	}, nil
}

// Commit computes a Pedersen commitment: C = value*G + blindingFactor*H
func (p *PedersenParams) Commit(value, blindingFactor *big.Int) (Cx, Cy *big.Int, err error) {
	if value == nil || blindingFactor == nil {
		return nil, nil, fmt.Errorf("value and blindingFactor must be non-nil")
	}
	if value.Cmp(p.Order) >= 0 || value.Sign() < 0 || blindingFactor.Cmp(p.Order) >= 0 || blindingFactor.Sign() < 0 {
		// Strictly speaking, values and blinding factors can be any integers and then reduced mod order,
		// but for ZKP witnesses it's standard practice they are in [0, order-1].
		// Let's allow any big.Int and reduce.
		value = new(big.Int).Mod(value, p.Order)
		blindingFactor = new(big.Int).Mod(blindingFactor, p.Order)
	}


	// value * G
	vGx, vGy := PointScalarMul(value, p.Gx, p.Gy)

	// blindingFactor * H
	rHx, rHy := PointScalarMul(blindingFactor, p.Hx, p.Hy)

	// Add points: (vG) + (rH)
	Cx, Cy = PointAdd(vGx, vGy, rHx, rHy)

	// Check if the resulting point is the point at infinity or invalid
	if Cx == nil || Cy == nil || !p.Curve.IsOnCurve(Cx, Cy) {
		return nil, nil, fmt.Errorf("generated commitment point is invalid")
	}

	return Cx, Cy, nil
}

// CommitWithRandomness generates a random blinding factor and computes the commitment.
func (p *PedersenParams) CommitWithRandomness(value *big.Int) (Cx, Cy *big.Int, blindingFactor *big.Int, err error) {
	r, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate random blinding factor: %w", err)
	}

	Cx, Cy, err = p.Commit(value, r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	return Cx, Cy, r, nil
}

// --- 4. Attribute Data Structures ---

// AttributeCommitment holds the public commitment to an attribute.
type AttributeCommitment struct {
	AttributeName string
	Cx, Cy        *big.Int
}

// NewAttributeCommitment creates a new attribute commitment struct.
func NewAttributeCommitment(name string, cx, cy *big.Int) *AttributeCommitment {
	return &AttributeCommitment{
		AttributeName: name,
		Cx:            cx,
		Cy:            cy,
	}
}

// AttributeWitness holds the secret value and blinding factor for an attribute.
type AttributeWitness struct {
	AttributeName   string
	Value           *big.Int
	BlindingFactor *big.Int
}

// NewAttributeWitness creates a new attribute witness struct.
func NewAttributeWitness(name string, value, blindingFactor *big.Int) *AttributeWitness {
	return &AttributeWitness{
		AttributeName:   name,
		Value:           value,
		BlindingFactor: blindingFactor,
	}
}

// AttributeStatementType defines the type of ZKP statement being made.
type AttributeStatementType int

const (
	TypeKnowledgeOfOpening AttributeStatementType = iota // Prove knowledge of value and blinding factor in a commitment.
	TypeEquality                                       // Prove two commitments hide the same value.
	TypeDiscreteLog                                    // Prove knowledge of x such that x*G = Y (Y is public). Can be used to prove value = Hash(secret_preimage).
	// Add more advanced types here, e.g., TypeRange (value is in [a,b]), TypeLessThan (value < public_k), TypeRelation (f(v1, v2) = 0).
	// Implementing these complex types (like range proofs) from scratch is substantial and might duplicate existing libraries.
	// We focus on the composition framework using the basic types.
)

// AttributeStatement defines a single statement to be proven about committed attributes.
// It refers to attributes by their names defined in the commitments and witnesses.
type AttributeStatement struct {
	Type AttributeStatementType
	// Specifies the attributes involved in the statement.
	// e.g., for TypeKnowledgeOfOpening, this is the name of the attribute being opened.
	// e.g., for TypeEquality, this might be two attribute names.
	// e.g., for TypeDiscreteLog, this might be an attribute name whose value is the discrete log.
	AttributeNames []string
	// Public data relevant to the statement (e.g., a public point for TypeDiscreteLog, a threshold for comparisons).
	PublicData map[string]*big.Int
}

// NewAttributeStatement creates a new statement struct.
func NewAttributeStatement(stmtType AttributeStatementType, names []string, publicData map[string]*big.Int) *AttributeStatement {
	return &AttributeStatement{
		Type:           stmtType,
		AttributeNames: names,
		PublicData:     publicData,
	}
}

// AttributeProofRequest defines a list of statements to be proven.
type AttributeProofRequest struct {
	Statements []*AttributeStatement
}

// NewAttributeProofRequest creates a new proof request.
func NewAttributeProofRequest(statements ...*AttributeStatement) *AttributeProofRequest {
	return &AttributeProofRequest{
		Statements: statements,
	}
}

// Proof components for different statement types

// ProofOpeningComponent holds the proof data for TypeKnowledgeOfOpening.
type ProofOpeningComponent struct {
	AttributeName string
	Tx, Ty        *big.Int // T = rv*G + rr*H
	Zv, Zr        *big.Int // zv = rv + c*v, zr = rr + c*r
}

// ProofEqualityComponent holds the proof data for TypeEquality.
type ProofEqualityComponent struct {
	AttributeName1 string // Names of the two attributes being compared
	AttributeName2 string
	T1x, T1y       *big.Int // T1 = rv*G + rr1*H
	T2x, T2y       *big.Int // T2 = rv*G + rr2*H
	Zv             *big.Int // zv = rv + c*v (v is the common value)
	Zr1            *big.Int // zr1 = rr1 + c*r1
	Zr2            *big.Int // zr2 = rr2 + c*r2
}

// ProofDiscreteLogComponent holds the proof data for TypeDiscreteLog.
type ProofDiscreteLogComponent struct {
	AttributeName string // Name of the attribute whose value is the discrete log
	Tx, Ty        *big.Int // T = r*G
	Z             *big.Int // z = r + c*x (x is the discrete log / secret value)
}

// AttributeProof holds the combined ZKP data for all statements in a request.
type AttributeProof struct {
	OpeningProofs []*ProofOpeningComponent
	EqualityProofs []*ProofEqualityComponent
	DiscreteLogProofs []*ProofDiscreteLogComponent
	// Add fields for other proof types here
}

// NewAttributeProof creates a new empty attribute proof struct.
func NewAttributeProof() *AttributeProof {
	return &AttributeProof{
		OpeningProofs: make([]*ProofOpeningComponent, 0),
		EqualityProofs: make([]*ProofEqualityComponent, 0),
		DiscreteLogProofs: make([]*ProofDiscreteLogComponent, 0),
	}
}

// --- 5. Core ZKP Component Implementations (Helpers for Composite Proof) ---

// Phase 1: Prover computes commitments (T values) and adds them to the transcript.
// These functions are internal helpers used by ProveAttributes.

func proveOpeningPhase1(params *PedersenParams, witness *AttributeWitness, transcript *Transcript) (*ProofOpeningComponent, *big.Int, *big.Int, error) {
	// Choose random values rv, rr
	rv, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening proof phase1: failed to generate random rv: %w", err)
	}
	rr, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening proof phase1: failed to generate random rr: %w", err)
	}

	// Compute T = rv*G + rr*H
	rvGx, rvGy := PointScalarMul(rv, params.Gx, params.Gy)
	rrHx, rrHy := PointScalarMul(rr, params.Hx, params.Hy)
	Tx, Ty := PointAdd(rvGx, rvGy, rrHx, rrHy)

	if Tx == nil || Ty == nil || !params.Curve.IsOnCurve(Tx, Ty) {
		return nil, nil, nil, fmt.Errorf("opening proof phase1: generated T point is invalid")
	}

	// Add T to the transcript
	err = transcript.AppendPoint(fmt.Sprintf("T_opening_%s", witness.AttributeName), Tx, Ty)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening proof phase1: failed to append T to transcript: %w", err)
	}

	// Return the T point and the randoms (rv, rr) needed for phase 2
	comp := &ProofOpeningComponent{AttributeName: witness.AttributeName, Tx: Tx, Ty: Ty}
	return comp, rv, rr, nil
}

func proveEqualityPhase1(params *PedersenParams, witness1, witness2 *AttributeWitness, transcript *Transcript) (*ProofEqualityComponent, *big.Int, *big.Int, *big.Int, error) {
	// Ensure witnesses are for the same value (prover side assertion)
	if witness1.Value.Cmp(witness2.Value) != 0 {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: witnesses must hide the same value")
	}

	// Choose random values rv, rr1, rr2
	rv, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: failed to generate random rv: %w", err)
	}
	rr1, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: failed to generate random rr1: %w", err)
	}
	rr2, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: failed to generate random rr2: %w", err)
	}

	// Compute T1 = rv*G + rr1*H and T2 = rv*G + rr2*H (same rv, different rrs)
	rvGx, rvGy := PointScalarMul(rv, params.Gx, params.Gy)
	rr1Hx, rr1Hy := PointScalarMul(rr1, params.Hx, params.Hy)
	rr2Hx, rr2Hy := PointScalarMul(rr2, params.Hx, params.Hy)

	T1x, T1y := PointAdd(rvGx, rvGy, rr1Hx, rr1Hy)
	T2x, T2y := PointAdd(rvGx, rvGy, rr2Hx, rr2Hy)

	if T1x == nil || T1y == nil || !params.Curve.IsOnCurve(T1x, T1y) || T2x == nil || T2y == nil || !params.Curve.IsOnCurve(T2x, T2y) {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: generated T points are invalid")
	}


	// Add T1 and T2 to the transcript
	err = transcript.AppendPoint(fmt.Sprintf("T1_equality_%s_%s", witness1.AttributeName, witness2.AttributeName), T1x, T1y)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: failed to append T1 to transcript: %w", err)
	}
	err = transcript.AppendPoint(fmt.Sprintf("T2_equality_%s_%s", witness1.AttributeName, witness2.AttributeName), T2x, T2y)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("equality proof phase1: failed to append T2 to transcript: %w", err)
	}

	// Return the T points and the randoms needed for phase 2
	comp := &ProofEqualityComponent{
		AttributeName1: witness1.AttributeName, AttributeName2: witness2.AttributeName,
		T1x: T1x, T1y: T1y, T2x: T2x, T2y: T2y,
	}
	return comp, rv, rr1, rr2, nil
}

func proveDiscreteLogPhase1(params *PedersenParams, witness *AttributeWitness, publicPointX, publicPointY *big.Int, transcript *Transcript) (*ProofDiscreteLogComponent, *big.Int, error) {
	// Statement: Prove knowledge of witness.Value (x) such that x*G = (publicPointX, publicPointY)
	// Prover needs to know witness.Value (x). Prover *does not* use the blinding factor or H in this proof.

	// Choose random r
	r, err := GenerateRandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("discrete log proof phase1: failed to generate random r: %w", err)
	}

	// Compute T = r*G
	Tx, Ty := PointScalarMul(r, params.Gx, params.Gy)

	if Tx == nil || Ty == nil || !params.Curve.IsOnCurve(Tx, Ty) {
		return nil, nil, fmt.Errorf("discrete log proof phase1: generated T point is invalid")
	}

	// Add public point Y and T to the transcript
	err = transcript.AppendPoint(fmt.Sprintf("PublicPoint_dl_%s", witness.AttributeName), publicPointX, publicPointY)
	if err != nil {
		return nil, nil, fmt.Errorf("discrete log proof phase1: failed to append PublicPoint to transcript: %w", err)
	}
	err = transcript.AppendPoint(fmt.Sprintf("T_dl_%s", witness.AttributeName), Tx, Ty)
	if err != nil {
		return nil, nil, fmt.Errorf("discrete log proof phase1: failed to append T to transcript: %w", err)
	}


	// Return the T point and the random r needed for phase 2
	comp := &ProofDiscreteLogComponent{AttributeName: witness.AttributeName, Tx: Tx, Ty: Ty}
	return comp, r, nil
}


// Phase 2: Prover computes responses (z values) using the challenge.
// These functions are internal helpers used by ProveAttributes.

func proveOpeningPhase2(params *PedersenParams, witness *AttributeWitness, rv, rr, challenge *big.Int, comp *ProofOpeningComponent) error {
	// Compute responses: zv = rv + c*v, zr = rr + c*r
	c_v := ScalarMul(challenge, witness.Value)
	c_r := ScalarMul(challenge, witness.BlindingFactor)

	comp.Zv = ScalarAdd(rv, c_v)
	comp.Zr = ScalarAdd(rr, c_r)

	return nil
}

func proveEqualityPhase2(params *PedersenParams, witness1, witness2 *AttributeWitness, rv, rr1, rr2, challenge *big.Int, comp *ProofEqualityComponent) error {
	// Compute responses: zv = rv + c*v, zr1 = rr1 + c*r1, zr2 = rr2 + c*r2
	// v is the common value: witness1.Value (or witness2.Value)
	c_v := ScalarMul(challenge, witness1.Value) // Use witness1.Value as v

	comp.Zv = ScalarAdd(rv, c_v)
	comp.Zr1 = ScalarAdd(rr1, ScalarMul(challenge, witness1.BlindingFactor))
	comp.Zr2 = ScalarAdd(rr2, ScalarMul(challenge, witness2.BlindingFactor))

	return nil
}

func proveDiscreteLogPhase2(params *PedersenParams, witness *AttributeWitness, r, challenge *big.Int, comp *ProofDiscreteLogComponent) error {
	// Compute response: z = r + c*x
	// x is witness.Value
	c_x := ScalarMul(challenge, witness.Value)
	comp.Z = ScalarAdd(r, c_x)

	return nil
}

// --- 6. Composite Proof Logic ---

// ProveAttributes creates a single ZKP for a set of statements about committed attributes.
// It uses the Fiat-Shamir heuristic to make the interactive protocol non-interactive.
func ProveAttributes(params *PedersenParams, commitments map[string]*AttributeCommitment, witnesses map[string]*AttributeWitness, request *AttributeProofRequest) (*AttributeProof, error) {

	if err := CheckProofRequestConsistency(request, commitments, witnesses); err != nil {
		return nil, fmt.Errorf("proof request inconsistency: %w", err)
	}

	transcript := NewTranscript()
	proof := NewAttributeProof()

	// Store randoms generated in Phase 1 to use in Phase 2 after challenge is known
	openingRandoms := make(map[string]struct{ rv, rr *big.Int })
	equalityRandoms := make(map[string]struct{ rv, rr1, rr2 *big.Int }) // Key is name1_name2
	discreteLogRandoms := make(map[string]*big.Int) // Key is attribute name

	// Phase 1: Prover computes T values for each statement and adds public information to the transcript.
	// Commitment points (Cx, Cy) for all involved attributes are added implicitly by the structure
	// of the individual proof components' transcript additions in phase1 helpers.
	// For robustness, explicitly add all *relevant* commitment points to the transcript upfront.
	// This ensures the challenge depends on all commitments the proof is *about*.
	relevantCommitmentNames := make(map[string]bool)
	for _, stmt := range request.Statements {
		for _, name := range stmt.AttributeNames {
			relevantCommitmentNames[name] = true
		}
		// For DL proofs, the public point is also part of the public info.
		// Added within proveDiscreteLogPhase1 to associate it with the specific statement.
	}

	for name := range relevantCommitmentNames {
		comm, ok := commitments[name]
		if !ok {
			return nil, fmt.Errorf("commitment for attribute '%s' not found", name)
		}
		err := transcript.AppendPoint(fmt.Sprintf("Commitment_%s", name), comm.Cx, comm.Cy)
		if err != nil {
			return nil, fmt.Errorf("failed to append commitment '%s' to transcript: %w", name, err)
		}
	}


	for i, stmt := range request.Statements {
		switch stmt.Type {
		case TypeKnowledgeOfOpening:
			if len(stmt.AttributeNames) != 1 {
				return nil, fmt.Errorf("statement %d: TypeKnowledgeOfOpening requires exactly one attribute name", i)
			}
			name := stmt.AttributeNames[0]
			witness := witnesses[name] // Already checked existence in CheckProofRequestConsistency

			comp, rv, rr, err := proveOpeningPhase1(params, witness, transcript)
			if err != nil {
				return nil, fmt.Errorf("statement %d opening proof phase 1 failed: %w", i, err)
			}
			proof.OpeningProofs = append(proof.OpeningProofs, comp)
			openingRandoms[name] = struct{ rv, rr *big.Int }{rv, rr}

		case TypeEquality:
			if len(stmt.AttributeNames) != 2 {
				return nil, fmt.Errorf("statement %d: TypeEquality requires exactly two attribute names", i)
			}
			name1 := stmt.AttributeNames[0]
			name2 := stmt.AttributeNames[1]
			witness1 := witnesses[name1]
			witness2 := witnesses[name2]

			comp, rv, rr1, rr2, err := proveEqualityPhase1(params, witness1, witness2, transcript)
			if err != nil {
				return nil, fmt.Errorf("statement %d equality proof phase 1 failed: %w", i, err)
			}
			proof.EqualityProofs = append(proof.EqualityProofs, comp)
			equalityRandoms[fmt.Sprintf("%s_%s", name1, name2)] = struct{ rv, rr1, rr2 *big.Int }{rv, rr1, rr2}

		case TypeDiscreteLog:
			if len(stmt.AttributeNames) != 1 {
				return nil, fmt.Errorf("statement %d: TypeDiscreteLog requires exactly one attribute name", i)
			}
			if stmt.PublicData == nil || stmt.PublicData["Px"] == nil || stmt.PublicData["Py"] == nil {
				return nil, fmt.Errorf("statement %d: TypeDiscreteLog requires PublicData with Px and Py", i)
			}
			name := stmt.AttributeNames[0]
			witness := witnesses[name]
			publicPointX := stmt.PublicData["Px"]
			publicPointY := stmt.PublicData["Py"]

			// Check if public point is on the curve
			if !params.Curve.IsOnCurve(publicPointX, publicPointY) {
				return nil, fmt.Errorf("statement %d discrete log proof phase 1: public point is not on curve", i)
			}

			comp, r, err := proveDiscreteLogPhase1(params, witness, publicPointX, publicPointY, transcript)
			if err != nil {
				return nil, fmt.Errorf("statement %d discrete log proof phase 1 failed: %w", i, err)
			}
			proof.DiscreteLogProofs = append(proof.DiscreteLogProofs, comp)
			discreteLogRandoms[name] = r

		default:
			return nil, fmt.Errorf("unsupported statement type: %v", stmt.Type)
		}
	}

	// Generate the shared challenge using the full transcript state
	challenge := transcript.GenerateChallenge("final_challenge")

	// Phase 2: Prover computes responses using the challenge and fills the proof struct.
	for _, comp := range proof.OpeningProofs {
		witness := witnesses[comp.AttributeName]
		randoms := openingRandoms[comp.AttributeName]
		if err := proveOpeningPhase2(params, witness, randoms.rv, randoms.rr, challenge, comp); err != nil {
			return nil, fmt.Errorf("opening proof phase 2 failed for '%s': %w", comp.AttributeName, err)
		}
	}

	for _, comp := range proof.EqualityProofs {
		witness1 := witnesses[comp.AttributeName1]
		witness2 := witnesses[comp.AttributeName2]
		key := fmt.Sprintf("%s_%s", comp.AttributeName1, comp.AttributeName2) // Match key used in Phase 1
		randoms := equalityRandoms[key]
		if err := proveEqualityPhase2(params, witness1, witness2, randoms.rv, randoms.rr1, randoms.rr2, challenge, comp); err != nil {
			return nil, fmt.Errorf("equality proof phase 2 failed for '%s' and '%s': %w", comp.AttributeName1, comp.AttributeName2, err)
		}
	}

	for _, comp := range proof.DiscreteLogProofs {
		witness := witnesses[comp.AttributeName]
		r := discreteLogRandoms[comp.AttributeName]
		if err := proveDiscreteLogPhase2(params, witness, r, challenge, comp); err != nil {
			return nil, fmt.Errorf("discrete log proof phase 2 failed for '%s': %w", comp.AttributeName, err)
		}
	}

	return proof, nil
}

// VerifyAttributes verifies a ZKP for a set of statements about committed attributes.
func VerifyAttributes(params *PedersenParams, commitments map[string]*AttributeCommitment, request *AttributeProofRequest, proof *AttributeProof) (bool, error) {

	if err := CheckProofConsistency(request, commitments, proof); err != nil {
		return false, fmt.Errorf("proof inconsistency: %w", err)
	}

	transcript := NewTranscript()

	// Add all relevant commitment points to the transcript first, same as prover.
	relevantCommitmentNames := make(map[string]bool)
	for _, stmt := range request.Statements {
		for _, name := range stmt.AttributeNames {
			relevantCommitmentNames[name] = true
		}
		// For DL proofs, the public point is also part of the public info.
		// Added within verifyDiscreteLogComponent to associate it with the specific statement.
	}

	for name := range relevantCommitmentNames {
		comm, ok := commitments[name]
		if !ok {
			// This shouldn't happen if CheckProofConsistency passed, but double-check
			return false, fmt.Errorf("commitment for attribute '%s' not found during verification setup", name)
		}
		err := transcript.AppendPoint(fmt.Sprintf("Commitment_%s", name), comm.Cx, comm.Cy)
		if err != nil {
			return false, fmt.Errorf("failed to append commitment '%s' to transcript during verification setup: %w", name, err)
		}
	}


	// Reconstruct the transcript state by adding public commitments (Cx, Cy) and prover's T values.
	// We must add T values in the *same order* as the prover did during Phase 1.
	// The simplest way is to iterate through the *request statements* and pull the corresponding Ts from the proof.

	openingProofIndex := 0
	equalityProofIndex := 0
	discreteLogProofIndex := 0

	for i, stmt := range request.Statements {
		switch stmt.Type {
		case TypeKnowledgeOfOpening:
			if openingProofIndex >= len(proof.OpeningProofs) {
				return false, fmt.Errorf("malformed proof: not enough opening proofs")
			}
			comp := proof.OpeningProofs[openingProofIndex]

			// Check if the component matches the statement
			if len(stmt.AttributeNames) != 1 || stmt.AttributeNames[0] != comp.AttributeName {
				return false, fmt.Errorf("malformed proof: opening proof component name mismatch for statement %d", i)
			}

			// Add T to the transcript
			err := transcript.AppendPoint(fmt.Sprintf("T_opening_%s", comp.AttributeName), comp.Tx, comp.Ty)
			if err != nil {
				return false, fmt.Errorf("statement %d opening proof verification: failed to append T to transcript: %w", i, err)
			}
			openingProofIndex++

		case TypeEquality:
			if equalityProofIndex >= len(proof.EqualityProofs) {
				return false, fmt.Errorf("malformed proof: not enough equality proofs")
			}
			comp := proof.EqualityProofs[equalityProofIndex]

			// Check if the component matches the statement (order matters for transcript)
			if len(stmt.AttributeNames) != 2 || stmt.AttributeNames[0] != comp.AttributeName1 || stmt.AttributeNames[1] != comp.AttributeName2 {
				// If names are swapped in the proof component but statement uses them in request order,
				// this check fails. Prover must ensure order matches request.
				return false, fmt.Errorf("malformed proof: equality proof component name mismatch or order for statement %d", i)
			}

			// Add T1 and T2 to the transcript (in correct order)
			err := transcript.AppendPoint(fmt.Sprintf("T1_equality_%s_%s", comp.AttributeName1, comp.AttributeName2), comp.T1x, comp.T1y)
			if err != nil {
				return false, fmt.Errorf("statement %d equality proof verification: failed to append T1 to transcript: %w", i, err)
			}
			err = transcript.AppendPoint(fmt.Sprintf("T2_equality_%s_%s", comp.AttributeName1, comp.AttributeName2), comp.T2x, comp.T2y)
			if err != nil {
				return false, fmt.Errorf("statement %d equality proof verification: failed to append T2 to transcript: %w", i, err)
			}
			equalityProofIndex++

		case TypeDiscreteLog:
			if discreteLogProofIndex >= len(proof.DiscreteLogProofs) {
				return false, fmt.Errorf("malformed proof: not enough discrete log proofs")
			}
			comp := proof.DiscreteLogProofs[discreteLogProofIndex]

			// Check if the component matches the statement
			if len(stmt.AttributeNames) != 1 || stmt.AttributeNames[0] != comp.AttributeName {
				return false, fmt.Errorf("malformed proof: discrete log proof component name mismatch for statement %d", i)
			}
			if stmt.PublicData == nil || stmt.PublicData["Px"] == nil || stmt.PublicData["Py"] == nil {
				return false, fmt.Errorf("statement %d: TypeDiscreteLog requires PublicData with Px and Py during verification", i)
			}
			publicPointX := stmt.PublicData["Px"]
			publicPointY := stmt.PublicData["Py"]

			// Check if public point is on the curve
			if !params.Curve.IsOnCurve(publicPointX, publicPointY) {
				return false, fmt.Errorf("statement %d discrete log proof verification: public point is not on curve", i)