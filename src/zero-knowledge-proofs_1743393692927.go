```go
/*
Outline and Function Summary:

Package: zkp_supplychain

This package implements a Zero-Knowledge Proof (ZKP) system for verifying properties of items in a supply chain without revealing sensitive details.
It focuses on demonstrating various ZKP concepts through practical supply chain scenarios.

Function Summary:

1.  GenerateProductHash(productData string) string:
    - Generates a cryptographic hash of product data to represent a unique product ID.

2.  CommitToProductOrigin(origin string) (commitment string, secret string):
    - Prover commits to the product origin using a commitment scheme (e.g., hashing with a salt).

3.  RevealProductOrigin(secret string) string:
    - Prover reveals the secret used in the commitment to open the commitment.

4.  VerifyOriginCommitment(commitment string, revealedOrigin string, secret string) bool:
    - Verifier checks if the revealed origin and secret match the initial commitment.

5.  ProveProductBatchNumberRange(batchNumber int, minRange int, maxRange int) (proof string):
    - Prover generates a ZKP to prove that the batch number is within a specific range without revealing the exact batch number. (Simplified range proof concept).

6.  VerifyProductBatchNumberRangeProof(proof string, minRange int, maxRange int) bool:
    - Verifier checks the proof to confirm the batch number is within the specified range.

7.  ProveProductManufactureDateBefore(manufactureDate string, thresholdDate string) (proof string):
    - Prover proves that the manufacture date is before a certain threshold date without revealing the exact date. (Simplified comparison proof).

8.  VerifyProductManufactureDateBeforeProof(proof string, thresholdDate string) bool:
    - Verifier checks the proof to confirm the manufacture date is before the threshold.

9.  ProveProductNameInSet(productName string, allowedNames []string) (proof string):
    - Prover proves that the product name belongs to a predefined set of allowed names without revealing the exact name. (Set membership proof concept).

10. VerifyProductNameInSetProof(proof string, allowedNames []string) bool:
    - Verifier checks the proof to confirm the product name is in the allowed set.

11. ProveProductWeightAboveThreshold(weight float64, thresholdWeight float64) (proof string):
    - Prover proves that the product weight is above a certain threshold without revealing the precise weight. (Threshold proof).

12. VerifyProductWeightAboveThresholdProof(proof string, thresholdWeight float64) bool:
    - Verifier checks the proof to confirm the weight is above the threshold.

13. ProveProductColorNotBlack(color string) (proof string):
    - Prover proves that the product color is NOT black without revealing the actual color (Negation proof).

14. VerifyProductColorNotBlackProof(proof string) bool:
    - Verifier checks the proof to confirm the color is not black.

15. ProveProductMaterialIsRecycled(materialCode string, recycledMaterialCodes []string) (proof string):
    - Prover proves the material is recycled by showing its code is in a list of recycled material codes without revealing the specific code (Set membership for recycled materials).

16. VerifyProductMaterialIsRecycledProof(proof string, recycledMaterialCodes []string) bool:
    - Verifier checks the proof to confirm the material is recycled.

17. ProveProductSupplierLocationRegion(locationData string, regionHash string) (proof string, witness string):
    - Prover proves the supplier location is within a specific region (represented by a region hash) without revealing the exact location details.  Introduces a witness concept.

18. VerifyProductSupplierLocationRegionProof(proof string, regionHash string, witness string) bool:
    - Verifier checks the proof and witness against the region hash to confirm the location is within the region.

19. ProveProductCompliesWithStandard(complianceData string, standardHash string) (proof string):
    - Prover proves product compliance with a standard represented by a hash without revealing the detailed compliance data.

20. VerifyProductCompliesWithStandardProof(proof string, standardHash string) bool:
    - Verifier checks the proof against the standard hash to confirm compliance.

21. ProveTwoProductsSameBatch(productHash1 string, productHash2 string, batchSecret string) (proof string):
    - Prover proves two product hashes belong to the same batch using a shared secret without revealing the secret or the batch directly. (Relation proof).

22. VerifyTwoProductsSameBatchProof(proof string, productHash1 string, productHash2 string) bool:
    - Verifier checks the proof to confirm that the two products belong to the same batch.

Note: These functions are simplified demonstrations of ZKP concepts and do not use advanced cryptographic libraries for efficiency or robustness.
They are intended to illustrate the *idea* of Zero-Knowledge Proofs in various supply chain verification scenarios.
For real-world secure ZKP applications, established cryptographic libraries and protocols should be used.
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// --- Function 1: GenerateProductHash ---
// Generates a cryptographic hash of product data to represent a unique product ID.
func GenerateProductHash(productData string) string {
	hasher := sha256.New()
	hasher.Write([]byte(productData))
	hashedBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashedBytes)
}

// --- Function 2: CommitToProductOrigin ---
// Prover commits to the product origin using a commitment scheme (e.g., hashing with a salt).
func CommitToProductOrigin(origin string) (commitment string, secret string) {
	rand.Seed(time.Now().UnixNano())
	salt := strconv.Itoa(rand.Int()) // Simple salt
	secret = salt + ":" + origin
	hasher := sha256.New()
	hasher.Write([]byte(secret))
	commitment = hex.EncodeToString(hasher.Sum(nil))
	return commitment, secret
}

// --- Function 3: RevealProductOrigin ---
// Prover reveals the secret used in the commitment to open the commitment.
func RevealProductOrigin(secret string) string {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) == 2 {
		return parts[1] // Return the origin part of the secret
	}
	return "" // Or handle error appropriately
}

// --- Function 4: VerifyOriginCommitment ---
// Verifier checks if the revealed origin and secret match the initial commitment.
func VerifyOriginCommitment(commitment string, revealedOrigin string, secret string) bool {
	reconstructedSecret := strings.SplitN(secret, ":", 2)[0] + ":" + revealedOrigin // Reconstruct secret format
	hasher := sha256.New()
	hasher.Write([]byte(reconstructedSecret))
	recalculatedCommitment := hex.EncodeToString(hasher.Sum(nil))
	return commitment == recalculatedCommitment
}

// --- Function 5: ProveProductBatchNumberRange ---
// Prover generates a ZKP to prove that the batch number is within a specific range without revealing the exact batch number. (Simplified range proof concept).
func ProveProductBatchNumberRange(batchNumber int, minRange int, maxRange int) (proof string) {
	if batchNumber >= minRange && batchNumber <= maxRange {
		// In a real ZKP, this would be a more complex proof. Here, we just create a simple "yes" proof.
		proof = "BatchNumberInRangeProof"
	} else {
		proof = "BatchNumberOutOfRangeProof" // Indicate out of range (verifier will reject this)
	}
	return proof
}

// --- Function 6: VerifyProductBatchNumberRangeProof ---
// Verifier checks the proof to confirm the batch number is within the specified range.
func VerifyProductBatchNumberRangeProof(proof string, minRange int, maxRange int) bool {
	return proof == "BatchNumberInRangeProof" // Simplistic verification
}

// --- Function 7: ProveProductManufactureDateBefore ---
// Prover proves that the manufacture date is before a certain threshold date without revealing the exact date. (Simplified comparison proof).
func ProveProductManufactureDateBefore(manufactureDate string, thresholdDate string) (proof string) {
	layout := "2006-01-02" // Date format
	mDate, _ := time.Parse(layout, manufactureDate)
	tDate, _ := time.Parse(layout, thresholdDate)

	if mDate.Before(tDate) {
		proof = "ManufactureDateBeforeThresholdProof"
	} else {
		proof = "ManufactureDateAfterThresholdProof" // Indicate not before (verifier will reject)
	}
	return proof
}

// --- Function 8: VerifyProductManufactureDateBeforeProof ---
// Verifier checks the proof to confirm the manufacture date is before the threshold.
func VerifyProductManufactureDateBeforeProof(proof string, thresholdDate string) bool {
	return proof == "ManufactureDateBeforeThresholdProof" // Simplistic verification
}

// --- Function 9: ProveProductNameInSet ---
// Prover proves that the product name belongs to a predefined set of allowed names without revealing the exact name. (Set membership proof concept).
func ProveProductNameInSet(productName string, allowedNames []string) (proof string) {
	for _, name := range allowedNames {
		if name == productName {
			proof = "ProductNameInSetProof"
			return proof
		}
	}
	proof = "ProductNameNotInSetProof" // Indicate not in set (verifier will reject)
	return proof
}

// --- Function 10: VerifyProductNameInSetProof ---
// Verifier checks the proof to confirm the product name is in the allowed set.
func VerifyProductNameInSetProof(proof string, allowedNames []string) bool {
	return proof == "ProductNameInSetProof" // Simplistic verification
}

// --- Function 11: ProveProductWeightAboveThreshold ---
// Prover proves that the product weight is above a certain threshold without revealing the precise weight. (Threshold proof).
func ProveProductWeightAboveThreshold(weight float64, thresholdWeight float64) (proof string) {
	if weight > thresholdWeight {
		proof = "ProductWeightAboveThresholdProof"
	} else {
		proof = "ProductWeightBelowThresholdProof" // Indicate below threshold (verifier will reject)
	}
	return proof
}

// --- Function 12: VerifyProductWeightAboveThresholdProof ---
// Verifier checks the proof to confirm the weight is above the threshold.
func VerifyProductWeightAboveThresholdProof(proof string, thresholdWeight float64) bool {
	return proof == "ProductWeightAboveThresholdProof" // Simplistic verification
}

// --- Function 13: ProveProductColorNotBlack ---
// Prover proves that the product color is NOT black without revealing the actual color (Negation proof).
func ProveProductColorNotBlack(color string) (proof string) {
	if strings.ToLower(color) != "black" {
		proof = "ProductColorNotBlackProof"
	} else {
		proof = "ProductColorIsBlackProof" // Indicate color is black (verifier will reject)
	}
	return proof
}

// --- Function 14: VerifyProductColorNotBlackProof ---
// Verifier checks the proof to confirm the color is not black.
func VerifyProductColorNotBlackProof(proof string) bool {
	return proof == "ProductColorNotBlackProof" // Simplistic verification
}

// --- Function 15: ProveProductMaterialIsRecycled ---
// Prover proves the material is recycled by showing its code is in a list of recycled material codes without revealing the specific code (Set membership for recycled materials).
func ProveProductMaterialIsRecycled(materialCode string, recycledMaterialCodes []string) (proof string) {
	for _, code := range recycledMaterialCodes {
		if code == materialCode {
			proof = "ProductMaterialIsRecycledProof"
			return proof
		}
	}
	proof = "ProductMaterialIsNotRecycledProof" // Indicate not recycled (verifier will reject)
	return proof
}

// --- Function 16: VerifyProductMaterialIsRecycledProof ---
// Verifier checks the proof to confirm the material is recycled.
func VerifyProductMaterialIsRecycledProof(proof string, recycledMaterialCodes []string) bool {
	return proof == "ProductMaterialIsRecycledProof" // Simplistic verification
}

// --- Function 17: ProveProductSupplierLocationRegion ---
// Prover proves the supplier location is within a specific region (represented by a region hash) without revealing the exact location details.  Introduces a witness concept.
func ProveProductSupplierLocationRegion(locationData string, regionHash string) (proof string, witness string) {
	// In a real system, regionHash would be derived from some region definition.
	// Here, we just hash the locationData and compare to regionHash for simplicity.
	hasher := sha256.New()
	hasher.Write([]byte(locationData))
	locationHash := hex.EncodeToString(hasher.Sum(nil))

	if locationHash == regionHash {
		proof = "ProductLocationInRegionProof"
		witness = locationData // Witness is the location data (for demonstration - in real ZKP, witness would be different)
	} else {
		proof = "ProductLocationNotInRegionProof" // Indicate not in region (verifier will reject)
		witness = ""
	}
	return proof, witness
}

// --- Function 18: VerifyProductSupplierLocationRegionProof ---
// Verifier checks the proof and witness against the region hash to confirm the location is within the region.
func VerifyProductSupplierLocationRegionProof(proof string, regionHash string, witness string) bool {
	if proof == "ProductLocationInRegionProof" {
		hasher := sha256.New()
		hasher.Write([]byte(witness))
		witnessHash := hex.EncodeToString(hasher.Sum(nil))
		return witnessHash == regionHash // Verify witness against region hash
	}
	return false // Proof failed
}

// --- Function 19: ProveProductCompliesWithStandard ---
// Prover proves product compliance with a standard represented by a hash without revealing the detailed compliance data.
func ProveProductCompliesWithStandard(complianceData string, standardHash string) (proof string) {
	hasher := sha256.New()
	hasher.Write([]byte(complianceData))
	complianceHash := hex.EncodeToString(hasher.Sum(nil))

	if complianceHash == standardHash {
		proof = "ProductCompliesWithStandardProof"
	} else {
		proof = "ProductDoesNotComplyWithStandardProof" // Indicate non-compliance (verifier will reject)
	}
	return proof
}

// --- Function 20: VerifyProductCompliesWithStandardProof ---
// Verifier checks the proof against the standard hash to confirm compliance.
func VerifyProductCompliesWithStandardProof(proof string, standardHash string) bool {
	return proof == "ProductCompliesWithStandardProof" // Simplistic verification
}

// --- Function 21: ProveTwoProductsSameBatch ---
// Prover proves two product hashes belong to the same batch using a shared secret without revealing the secret or the batch directly. (Relation proof).
func ProveTwoProductsSameBatch(productHash1 string, productHash2 string, batchSecret string) (proof string) {
	combinedData := productHash1 + ":" + productHash2 + ":" + batchSecret
	hasher := sha256.New()
	hasher.Write([]byte(combinedData))
	batchProofHash := hex.EncodeToString(hasher.Sum(nil))
	proof = batchProofHash // Proof is the hash of combined data including the secret
	return proof
}

// --- Function 22: VerifyTwoProductsSameBatchProof ---
// Verifier checks the proof to confirm that the two products belong to the same batch.
func VerifyTwoProductsSameBatchProof(proof string, productHash1 string, productHash2 string) bool {
	// Verifier would need to know the valid batch secrets or have a way to verify them (not implemented in this simplified example).
	// For demonstration, we assume the verifier knows a potential batch secret and tries it.
	potentialBatchSecrets := []string{"batchSecret123", "anotherBatchSecret"} // Example secrets - in real system, this is more complex

	for _, secret := range potentialBatchSecrets {
		combinedData := productHash1 + ":" + productHash2 + ":" + secret
		hasher := sha256.New()
		hasher.Write([]byte(combinedData))
		recalculatedProofHash := hex.EncodeToString(hasher.Sum(nil))
		if proof == recalculatedProofHash {
			return true // Proof verified with this secret (meaning they are in the same batch)
		}
	}
	return false // No secret verified the proof - products are likely not in the same batch
}

func main() {
	fmt.Println("Zero-Knowledge Proof Demonstration for Supply Chain:")

	// --- Example 1: Product Origin Verification ---
	fmt.Println("\n--- Product Origin Verification ---")
	origin := "Factory in Country X"
	commitment, secret := CommitToProductOrigin(origin)
	fmt.Println("Commitment:", commitment)

	// ... later, Verifier receives commitment and proof request ...
	revealedOrigin := RevealProductOrigin(secret)
	isValidOrigin := VerifyOriginCommitment(commitment, revealedOrigin, secret)
	fmt.Println("Revealed Origin:", revealedOrigin)
	fmt.Println("Origin Commitment Verified:", isValidOrigin) // Should be true

	// --- Example 2: Batch Number Range Verification ---
	fmt.Println("\n--- Batch Number Range Verification ---")
	batchNumber := 150
	minRange := 100
	maxRange := 200
	batchRangeProof := ProveProductBatchNumberRange(batchNumber, minRange, maxRange)
	isBatchInRange := VerifyProductBatchNumberRangeProof(batchRangeProof, minRange, maxRange)
	fmt.Println("Batch Number Range Proof:", batchRangeProof)
	fmt.Println("Batch Number In Range Verified:", isBatchInRange) // Should be true

	// --- Example 3: Product Name Set Membership Verification ---
	fmt.Println("\n--- Product Name Set Membership Verification ---")
	productName := "EcoFriendly T-Shirt"
	allowedProductNames := []string{"Basic T-Shirt", "EcoFriendly T-Shirt", "Premium Jeans"}
	nameSetProof := ProveProductNameInSet(productName, allowedProductNames)
	isNameInSet := VerifyProductNameInSetProof(nameSetProof, allowedProductNames)
	fmt.Println("Product Name Set Proof:", nameSetProof)
	fmt.Println("Product Name In Set Verified:", isNameInSet) // Should be true

	// --- Example 4: Product Material Recycled Verification ---
	fmt.Println("\n--- Product Material Recycled Verification ---")
	materialCode := "RECYCLED_PET"
	recycledCodes := []string{"RECYCLED_PET", "RECYCLED_ALUMINUM", "RECYCLED_PAPER"}
	recycledProof := ProveProductMaterialIsRecycled(materialCode, recycledCodes)
	isRecycled := VerifyProductMaterialIsRecycledProof(recycledProof, recycledCodes)
	fmt.Println("Recycled Material Proof:", recycledProof)
	fmt.Println("Material Is Recycled Verified:", isRecycled) // Should be true

	// --- Example 5: Product Supplier Location Region Verification ---
	fmt.Println("\n--- Product Supplier Location Region Verification ---")
	locationData := "Supplier Warehouse in Region Alpha"
	regionHash := GenerateProductHash("Region Alpha Definition") // Example region hash
	locationProof, witness := ProveProductSupplierLocationRegion(locationData, regionHash)
	isLocationInRegion := VerifyProductSupplierLocationRegionProof(locationProof, regionHash, witness)
	fmt.Println("Location Region Proof:", locationProof)
	fmt.Println("Location In Region Verified:", isLocationInRegion) // Should be true

	// --- Example 6: Two Products Same Batch Verification ---
	fmt.Println("\n--- Two Products Same Batch Verification ---")
	productData1 := "Product A - Batch XYZ"
	productData2 := "Product B - Batch XYZ"
	productHash1 := GenerateProductHash(productData1)
	productHash2 := GenerateProductHash(productData2)
	batchSecret := "batchSecretXYZ" // Shared secret for batch XYZ
	sameBatchProof := ProveTwoProductsSameBatch(productHash1, productHash2, batchSecret)
	areSameBatch := VerifyTwoProductsSameBatchProof(sameBatchProof, productHash1, productHash2)
	fmt.Println("Same Batch Proof:", sameBatchProof)
	fmt.Println("Products In Same Batch Verified:", areSameBatch) // Should be true (if batchSecretXYZ is in potentialBatchSecrets)

	fmt.Println("\n--- End of Zero-Knowledge Proof Demonstration ---")
}
```