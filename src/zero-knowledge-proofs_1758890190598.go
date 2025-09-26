This Go application implements a Zero-Knowledge Proof (ZKP) system for privacy-preserving anomaly detection in time-series sensor data.

---

### **Outline of the Zero-Knowledge Proof System for Private Anomaly Detection**

This application demonstrates a Zero-Knowledge Proof (ZKP) system for privacy-preserving anomaly detection in time-series sensor data.

**Scenario:** An IoT device (Prover) collects sensitive sensor readings. A monitoring station (Verifier) defines an anomaly as a situation where the sum of any 'M' consecutive sensor readings exceeds a public threshold 'T'. The Prover wants to prove to the Verifier that an anomaly *has occurred* according to this rule, without revealing any of its individual sensor readings.

The system leverages zk-SNARKs (specifically Groth16 via `gnark`) to construct and verify the proof.

---

### **Function Summary**

**1. `main.go`**
   -   `main()`: The entry point and orchestrator. It simulates the entire process: trusted setup, sensor data generation (with or without anomaly), proof generation by the Prover, and proof verification by the Verifier.

**2. `anomalycircuit/circuit.go`**
   -   `AnomalyCircuit` (struct): Defines the arithmetic circuit for anomaly detection. It holds both private (sensor readings, anomaly flag) and public (threshold, window size, total readings, whether anomaly occurred) inputs.
   -   `newAnomalyCircuit(N, M int)`: A constructor function that initializes an `AnomalyCircuit` with the total number of readings (`N`) and the window size (`M`).
   -   `Define(api frontend.API)`: Implements the core ZKP logic. This method translates the anomaly detection rule into R1CS constraints:
       -   It iterates through all possible `M`-length sliding windows within the `N` sensor readings.
       -   For each window, it calculates the sum of readings using `makeWindowSum`.
       -   It compares each window sum against the public threshold `T` using ZKP-friendly comparison (`cmp.IsLessOrEqual`).
       -   It aggregates these comparisons to determine if *any* window sum exceeded `T` using `api.Or`.
       -   It asserts that the `HasAnomaly` public output matches the computed anomaly state.
   -   `makeWindowSum(api frontend.API, readings []frontend.Variable, startIndex int, windowSize int)`: A helper function used within `Define` to calculate the sum of `windowSize` consecutive sensor readings starting from `startIndex`.

**3. `zkp/gnark_handler.go`**
   -   `SetupKeys` (struct): A container to hold the `ProvingKey` and `VerifyingKey` generated during the trusted setup.
   -   `TrustedSetup(circuit r1cs.R1CS)`: Performs the cryptographic trusted setup. It generates a `ProvingKey` (used by the Prover) and a `VerifyingKey` (used by the Verifier) for the specified circuit.
   -   `CreateProof(pk groth16.ProvingKey, circuit r1cs.R1CS, assignment frontend.Circuit)`: Generates a Zero-Knowledge Proof. The Prover provides its private inputs (as part of `assignment`) and the circuit definition, and this function computes the proof.
   -   `VerifyProof(vk groth16.VerifyingKey, proof groth16.Proof, publicInput frontend.Circuit)`: Verifies a Zero-Knowledge Proof. The Verifier provides the `VerifyingKey`, the `proof`, and the public inputs (as part of `publicInput`), and this function returns `true` if the proof is valid.
   -   `ExportVerifyingKey(vk groth16.VerifyingKey, filename string)`: Serializes the `VerifyingKey` and saves it to a file, allowing it to be shared with the Verifier.
   -   `ImportVerifyingKey(filename string) (groth16.VerifyingKey, error)`: Deserializes and loads a `VerifyingKey` from a specified file.
   -   `ExportProof(proof groth16.Proof, filename string)`: Serializes the generated `Proof` and saves it to a file, for transmission from Prover to Verifier.
   -   `ImportProof(filename string) (groth16.Proof, error)`: Deserializes and loads a `Proof` from a specified file.

**4. `sensors/generator.go`**
   -   `SensorData` (struct): A simple struct to encapsulate a slice of `float64` sensor readings.
   -   `GenerateSensorReadings(N int, min, max float64, introduceAnomaly bool, anomalyWindowStart, anomalyMagnitude int)`: Generates a slice of `N` simulated `float64` sensor readings. It can optionally inject an anomaly by increasing readings within a specified window.
   -   `ComputeWindowSums(readings []float64, windowSize int)`: A utility function (not part of the ZKP circuit) that calculates all sliding window sums for a given set of `float64` readings. Useful for debugging and validating the anomaly generation.

**5. `utils/helpers.go`**
   -   `FloatToBigInt(f float64) *big.Int`: Converts a `float64` to a `*big.Int` suitable for `gnark` circuits. It applies a `SCALING_FACTOR` to maintain decimal precision, as ZKP operates on integers within a finite field.
   -   `BigIntToFloat(i *big.Int) float64`: Converts a `*big.Int` (field element) back to a `float64` by reversing the scaling factor.
   -   `Log(format string, args ...interface{})`: A simple logging utility for consistent output formatting.
   -   `SaveToFile(data interface{}, filename string)`: A generic helper to serialize (using `gob` encoding) and save any data structure to a specified file.
   -   `LoadFromFile(data interface{}, filename string)`: A generic helper to load and deserialize data from a file into a provided data structure.

---

```go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/your-username/zkp-anomaly-detection/anomalycircuit"
	"github.com/your-username/zkp-anomaly-detection/sensors"
	"github.com/your-username/zkp-anomaly-detection/utils"
	"github.com/your-username/zkp-anomaly-detection/zkp"

	"gnark.dev/gnark/backend/groth16"
	"gnark.dev/gnark/constraint"
)

// Application-specific constants
// SCALING_FACTOR is used to convert float64 sensor readings to big.Int for ZKP,
// as ZKP circuits operate on finite field elements (integers).
// A factor of 1000 means 3 decimal places are preserved.
const SCALING_FACTOR = 1000.0
const MAX_READING_VALUE = 200.0 // Max expected sensor reading (before scaling)
const MAX_WINDOW_SIZE = 10      // Max number of readings in a window
const MAX_NUM_READINGS = 100    // Max total number of readings

const (
	circuitFilename string = "anomaly_detection_circuit.r1cs"
	pkFilename      string = "proving_key.key"
	vkFilename      string = "verifying_key.key"
	proofFilename   string = "anomaly_proof.gz"
)

func main() {
	utils.Log("Starting Zero-Knowledge Proof for Private Anomaly Detection...")

	// --- 1. Circuit Definition & Compilation ---
	utils.Log("\n[STEP 1] Defining and compiling the ZKP circuit...")
	const N_READINGS = 50 // Total number of sensor readings
	const M_WINDOW_SIZE = 5 // Window size for anomaly detection
	const ANOMALY_THRESHOLD = 500.0 // Threshold for a window sum to be anomalous
	
	// Ensure ANOMALY_THRESHOLD is consistent with SCALING_FACTOR
	scaledThreshold := utils.FloatToBigInt(ANOMALY_THRESHOLD * SCALING_FACTOR)

	circuit := anomalycircuit.NewAnomalyCircuit(N_READINGS, M_WINDOW_SIZE)
	circuit.Threshold = scaledThreshold
	circuit.N = N_READINGS
	circuit.M = M_WINDOW_SIZE

	// Compile the circuit
	r1cs, err := circuit.Compile(rand.Reader)
	if err != nil {
		utils.Log("Error compiling circuit: %v", err)
		os.Exit(1)
	}
	utils.Log("Circuit compiled successfully. Number of constraints: %d", r1cs.Get //NumConstraints())

	// Save compiled circuit to a file (optional, for persistence/re-use)
	if err := utils.SaveToFile(r1cs, circuitFilename); err != nil {
		utils.Log("Error saving compiled circuit: %v", err)
		os.Exit(1)
	}
	utils.Log("Compiled circuit saved to %s", circuitFilename)

	// --- 2. Trusted Setup (Prover and Verifier collaboration) ---
	utils.Log("\n[STEP 2] Performing trusted setup to generate proving and verifying keys...")
	setupStart := time.Now()
	setupKeys, err := zkp.TrustedSetup(r1cs)
	if err != nil {
		utils.Log("Error during trusted setup: %v", err)
		os.Exit(1)
	}
	utils.Log("Trusted setup completed in %s", time.Since(setupStart))

	// Export keys for sharing
	if err := utils.SaveToFile(setupKeys.ProvingKey, pkFilename); err != nil {
		utils.Log("Error saving proving key: %v", err)
		os.Exit(1)
	}
	if err := zkp.ExportVerifyingKey(setupKeys.VerifyingKey, vkFilename); err != nil {
		utils.Log("Error saving verifying key: %v", err)
		os.Exit(1)
	}
	utils.Log("Proving key saved to %s, Verifying key saved to %s", pkFilename, vkFilename)

	// --- 3. Prover's Side: Generate Sensor Data and Create Proof ---
	utils.Log("\n[STEP 3] Prover's side: Generating sensor data and creating proof...")

	// Scenario 1: No anomaly
	// sensorReadings := sensors.GenerateSensorReadings(N_READINGS, 80.0, 110.0, false, 0, 0)
	// expectedAnomaly := false

	// Scenario 2: With anomaly
	anomalyStartIdx := 10                                     // Anomaly starts at index 10
	anomalyMagnitude := 120                                   // Extra value for anomaly window readings
	sensorReadings := sensors.GenerateSensorReadings(N_READINGS, 80.0, 110.0, true, anomalyStartIdx, anomalyMagnitude)
	expectedAnomaly := true // For verification, Prover claims there is an anomaly

	utils.Log("Generated %d sensor readings (anomaly present: %t)", N_READINGS, expectedAnomaly)

	// Compute actual window sums for validation/debugging
	actualWindowSums := sensors.ComputeWindowSums(sensorReadings.Readings, M_WINDOW_SIZE)
	detectedAnomalyInRawData := false
	for i, sum := range actualWindowSums {
		if sum > ANOMALY_THRESHOLD {
			detectedAnomalyInRawData = true
			utils.Log("DEBUG: Anomaly detected in raw data (window %d sum: %.2f > %.2f)", i, sum, ANOMALY_THRESHOLD)
			break
		}
	}
	utils.Log("DEBUG: Raw data check - Anomaly detected: %t (Expected: %t)", detectedAnomalyInRawData, expectedAnomaly)
	if detectedAnomalyInRawData != expectedAnomaly {
		utils.Log("WARNING: Discrepancy between generated data anomaly and expected anomaly flag.")
	}

	// Prepare Prover's assignment (private and public inputs)
	proverAssignment := anomalycircuit.NewAnomalyCircuit(N_READINGS, M_WINDOW_SIZE)
	proverAssignment.Threshold = scaledThreshold
	proverAssignment.N = N_READINGS
	proverAssignment.M = M_WINDOW_SIZE
	proverAssignment.HasAnomaly = expectedAnomaly // Prover's claim about anomaly presence

	scaledReadings := make([]*big.Int, N_READINGS)
	for i, r := range sensorReadings.Readings {
		scaledReadings[i] = utils.FloatToBigInt(r * SCALING_FACTOR)
	}
	proverAssignment.SensorReadings = scaledReadings

	proofStart := time.Now()
	proof, err := zkp.CreateProof(setupKeys.ProvingKey, r1cs, proverAssignment)
	if err != nil {
		utils.Log("Error creating proof: %v", err)
		os.Exit(1)
	}
	utils.Log("Proof created successfully in %s", time.Since(proofStart))

	// Export proof for transmission to Verifier
	if err := zkp.ExportProof(proof, proofFilename); err != nil {
		utils.Log("Error saving proof: %v", err)
		os.Exit(1)
	}
	utils.Log("Proof saved to %s", proofFilename)

	// --- 4. Verifier's Side: Verify Proof ---
	utils.Log("\n[STEP 4] Verifier's side: Verifying the proof...")

	// Verifier loads the verifying key and proof (simulated here)
	verifierVK, err := zkp.ImportVerifyingKey(vkFilename)
	if err != nil {
		utils.Log("Error loading verifying key for Verifier: %v", err)
		os.Exit(1)
	}
	verifierProof, err := zkp.ImportProof(proofFilename)
	if err != nil {
		utils.Log("Error loading proof for Verifier: %v", err)
		os.Exit(1)
	}

	// Prepare Verifier's public inputs
	verifierPublicAssignment := anomalycircuit.NewAnomalyCircuit(N_READINGS, M_WINDOW_SIZE)
	verifierPublicAssignment.Threshold = scaledThreshold
	verifierPublicAssignment.N = N_READINGS
	verifierPublicAssignment.M = M_WINDOW_SIZE
	verifierPublicAssignment.HasAnomaly = expectedAnomaly // Verifier checks this claim

	verifyStart := time.Now()
	err = zkp.VerifyProof(verifierVK, verifierProof, verifierPublicAssignment)
	if err != nil {
		utils.Log("Proof verification FAILED: %v", err)
	} else {
		utils.Log("Proof verification SUCCESS! The Prover successfully demonstrated an anomaly without revealing sensor data.")
	}
	utils.Log("Proof verification completed in %s", time.Since(verifyStart))

	utils.Log("\nZero-Knowledge Proof system for Private Anomaly Detection finished.")
}
```