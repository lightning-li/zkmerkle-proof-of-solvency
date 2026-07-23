package circuit

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/klauspost/compress/s2"
)

func ConstructR1csAndWitness(provingSystem string, assetCountsTier int, userOpsPerBatch int) (constraint.ConstraintSystem, witness.Witness, error) {
	solver.RegisterHint(IntegerDivision)
	totalAssetsCount := utils.AssetCounts

	emptyUserCircuit := NewBatchCreateUserCircuit(uint32(assetCountsTier), uint32(totalAssetsCount), uint32(userOpsPerBatch))
	s := time.Now()
	var builder frontend.NewBuilder
	if provingSystem == "plonk" {
		builder = scs.NewBuilder
	} else if provingSystem == "groth16" {
		builder = r1cs.NewBuilder
	} else {
		return nil, nil, fmt.Errorf("invalid proving system")
	}
	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, emptyUserCircuit)
	if err != nil {
		return nil, nil, err
	}
	et := time.Now()
	fmt.Println("compile time is ", et.Sub(s))
	fmt.Println("batch create user constraints number is ", oR1cs.GetNbConstraints())

	userCircuit := ConstructValidBatch(assetCountsTier, totalAssetsCount, userOpsPerBatch)

	witness, e := frontend.NewWitness(userCircuit, ecc.BN254.ScalarField())
	if witness == nil {
		return nil, nil, e
	}
	return oR1cs, witness, nil
}

func TestBatchCreateUserCircuit(t *testing.T) {
	for _, assetCountsTier := range utils.AssetCountsTiers {
		userOpsPerBatch := 2
		t.Run(fmt.Sprintf("assets_%d_users_%d", assetCountsTier, userOpsPerBatch), func(t *testing.T) {
			oR1cs, witness, err := ConstructR1csAndWitness("groth16", assetCountsTier, userOpsPerBatch)
			if err != nil {
				t.Fatal(err)
			}
			err = oR1cs.IsSolved(witness)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// compileConstraintsForBatch compiles the circuit for a given asset tier and
// user-per-batch count, returning only the number of r1cs constraints. It does
// not build a witness, so it is much cheaper than ConstructR1csAndWitness and
// safe to call repeatedly while probing constraint growth.
func compileConstraintsForBatch(assetCountsTier int, userOpsPerBatch int) (int, error) {
	emptyUserCircuit := NewBatchCreateUserCircuit(uint32(assetCountsTier), uint32(utils.AssetCounts), uint32(userOpsPerBatch))
	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, emptyUserCircuit)
	if err != nil {
		return 0, err
	}
	return oR1cs.GetNbConstraints(), nil
}

// TestEstimateUserCapacityPerTier estimates, for every asset tier, how many
// users a single batch circuit can hold under a target constraint budget
// (default 2^26, overridable via ZKPOR_CONSTRAINT_BUDGET).
//
// The circuit's constraint count is affine in the number of users:
//
//	constraints(n) = base + perUser * n
//
//	- base:    constraints that do NOT scale with users (cex asset setup,
//	           tier-ratio lookup tables, commitments, etc.)
//	- perUser: constraints added by each additional user
//
// We recover both by compiling the circuit for n = 1..probeMax users and taking
// a linear fit. Probing up to 4 (matching the manual procedure) lets us verify
// the growth is actually linear rather than trusting a single delta. The
// capacity is then floor((budget - base) / perUser).
//
// This test only COMPILES circuits (no setup/prove), but large tiers still take
// a while, so run it with a generous timeout, e.g.:
//
//	go test ./circuit/ -run '^TestEstimateUserCapacityPerTier$' -v -timeout 2h
func TestEstimateUserCapacityPerTier(t *testing.T) {
	// constraint budget: 2^26 by default, overridable for experimentation.
	budget := int64(1) << 26
	if env := os.Getenv("ZKPOR_CONSTRAINT_BUDGET"); env != "" {
		parsed, err := strconv.ParseInt(env, 10, 64)
		if err != nil {
			t.Fatalf("invalid ZKPOR_CONSTRAINT_BUDGET %q: %v", env, err)
		}
		budget = parsed
	}

	// number of users to probe per tier (1..probeMax). probeMax >= 2 is
	// required to fit a line; >= 3 lets us sanity-check linearity.
	probeMax := 4
	if env := os.Getenv("ZKPOR_PROBE_MAX"); env != "" {
		parsed, err := strconv.Atoi(env)
		if err != nil || parsed < 2 {
			t.Fatalf("invalid ZKPOR_PROBE_MAX %q (must be integer >= 2): %v", env, err)
		}
		probeMax = parsed
	}

	type tierResult struct {
		tier        int
		counts      []int // constraints for n = 1..probeMax users
		base        int   // constraints not scaling with users
		perUser     int   // constraints added per user (average slope)
		maxDelta    int   // largest deviation of a single-step delta from perUser
		capacity    int64 // floor((budget - base) / perUser)
		linearityOK bool
	}

	results := make([]tierResult, 0, len(utils.AssetCountsTiers))

	for _, tier := range utils.AssetCountsTiers {
		counts := make([]int, 0, probeMax)
		for n := 1; n <= probeMax; n++ {
			c, err := compileConstraintsForBatch(tier, n)
			if err != nil {
				t.Fatalf("compile failed for tier=%d users=%d: %v", tier, n, err)
			}
			fmt.Printf("[tier=%d] users=%d constraints=%d\n", tier, n, c)
			counts = append(counts, c)
		}

		// perUser is the constraint delta between consecutive user counts.
		// With a perfectly affine circuit all deltas are identical, but gnark
		// compilation introduces a few constraints of jitter, so we take the
		// average slope over the whole probe range (counts[last]-counts[0])/(n-1)
		// as the estimate — this averages out the per-step noise.
		deltas := make([]int, 0, probeMax-1)
		for i := 1; i < len(counts); i++ {
			deltas = append(deltas, counts[i]-counts[i-1])
		}
		perUser := (counts[len(counts)-1] - counts[0]) / (len(counts) - 1)

		// Record the largest deviation of any single-step delta from the
		// average slope, as a linearity sanity check.
		maxDelta := 0
		for _, d := range deltas {
			diff := d - perUser
			if diff < 0 {
				diff = -diff
			}
			if diff > maxDelta {
				maxDelta = diff
			}
		}

		// base = constraints(n) - perUser*n, using n=1 measurement.
		base := counts[0] - perUser

		var capacity int64
		if perUser > 0 {
			capacity = (budget - int64(base)) / int64(perUser)
			if capacity < 0 {
				capacity = 0
			}
		}

		// Treat growth as linear if the worst single-step deviation is tiny
		// relative to the per-user slope (< 1%). Anything larger suggests the
		// affine model does not hold and the estimate should not be trusted.
		linearityOK := perUser > 0 && maxDelta*100 < perUser

		results = append(results, tierResult{
			tier:        tier,
			counts:      counts,
			base:        base,
			perUser:     perUser,
			maxDelta:    maxDelta,
			capacity:    capacity,
			linearityOK: linearityOK,
		})
	}

	// summary report
	fmt.Println()
	fmt.Println("================ user capacity per asset tier ================")
	fmt.Printf("constraint budget            : %d (2^%.0f)\n", budget, logBase2(budget))
	fmt.Printf("users probed per tier        : 1..%d\n", probeMax)
	fmt.Println("-------------------------------------------------------------")
	for _, r := range results {
		fmt.Printf("asset tier                   : %d\n", r.tier)
		fmt.Printf("  measured constraints (n=1..%d): %v\n", probeMax, r.counts)
		fmt.Printf("  base constraints (fixed)     : %d\n", r.base)
		fmt.Printf("  per-user constraints         : %d\n", r.perUser)
		if r.linearityOK {
			fmt.Printf("  linearity check              : OK (max step deviation = %d, within noise)\n", r.maxDelta)
		} else {
			fmt.Printf("  linearity check              : WARN max step deviation = %d vs per-user %d (growth not affine, estimate unreliable)\n", r.maxDelta, r.perUser)
		}
		fmt.Printf("  => max users per batch       : %d\n", r.capacity)
		fmt.Printf("     (uses %d constraints, budget %d)\n", int64(r.base)+r.capacity*int64(r.perUser), budget)
		fmt.Println("-------------------------------------------------------------")
	}
}

// logBase2 returns log2(x) for reporting; x is expected to be a positive power
// of two but any positive value works for display purposes.
func logBase2(x int64) float64 {
	l := 0.0
	for x > 1 {
		x >>= 1
		l++
	}
	return l
}

func TestBatchCreateUserCircuitFromKeySetup(t *testing.T) {
	oR1cs, witness, err := ConstructR1csAndWitness("groth16", 50, 1)
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(oR1cs)
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	startTime := time.Now()
	proof, err := groth16.Prove(oR1cs, pk, witness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	endTime := time.Now()
	fmt.Println("prove time is ", endTime.Sub(startTime))
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}

func TestBatchCreateUserCircuitFromPlonkKeySetup(t *testing.T) {
	oScs, witness, err := ConstructR1csAndWitness("plonk", 50, 1)
	if err != nil {
		t.Fatal(err)
	}
	srs, srsLang, err := unsafekzg.NewSRS(oScs)
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(oScs, srs, srsLang)
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	startTime := time.Now()
	proof, err := plonk.Prove(oScs, pk, witness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	endTime := time.Now()
	fmt.Println("prove time is ", endTime.Sub(startTime))
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}

func TestBatchCreateUserCircuitFromKeyFiles(t *testing.T) {
	oR1cs, witness, err := ConstructR1csAndWitness("groth16", 50, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := time.Now()
	r1csFromFile, err := os.ReadFile("../src/keygen/zkpor50_1.r1cs")
	if err != nil {
		panic(err)
	}
	buf := bytes.NewBuffer(r1csFromFile)
	newR1CS := groth16.NewCS(ecc.BN254)
	_, _ = newR1CS.ReadFrom(buf)
	et := time.Now()
	fmt.Println("read r1cs time is ", et.Sub(s))

	s = time.Now()
	pkFromFile, err := os.ReadFile("../src/keygen/zkpor50_1.pk")
	if err != nil {
		panic(err)
	}
	buf = bytes.NewBuffer(pkFromFile)
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.UnsafeReadFrom(buf)
	et = time.Now()
	fmt.Println("read pk time is ", et.Sub(s))

	s = time.Now()
	vkFromFile, err := os.ReadFile("../src/keygen/zkpor50_1.vk")
	if err != nil {
		panic(err)
	}
	buf = bytes.NewBuffer(vkFromFile)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, _ = vk.ReadFrom(buf)
	et = time.Now()
	fmt.Println("read vk time is ", et.Sub(s))

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	startTime := time.Now()
	proof, err := groth16.Prove(oR1cs, pk, witness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	endTime := time.Now()
	fmt.Println("prove time is ", endTime.Sub(startTime))
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}

func TestBatchCreateUserCircuitFromWitnessFile(t *testing.T) {
	targetAssetCounts := 30
	totalAssetsCount := 500
	userOpsPerBatch := 2
	targetCircuitAssetCounts := 0
	for _, v := range utils.AssetCountsTiers {
		if targetAssetCounts <= v {
			targetCircuitAssetCounts = v
			break
		}
	}
	fmt.Println("targetCircuitAssetCounts is ", targetCircuitAssetCounts)
	fmt.Println("totalAssetsCount is ", totalAssetsCount)
	fmt.Println("userOpsPerBatch is ", userOpsPerBatch)
	userCircuit := NewBatchCreateUserCircuit(uint32(targetCircuitAssetCounts), uint32(totalAssetsCount), uint32(userOpsPerBatch))
	s := time.Now()
	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, userCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	et := time.Now()
	fmt.Println("compile time is ", et.Sub(s))
	fmt.Println("batch create user constraints number is ", oR1cs.GetNbConstraints())

	// the witness.log can be generated by dbtool query_witness_data subcommand
	userCircuit = ConstructBatchFromFile("witness.log")
	solver.RegisterHint(IntegerDivision)
	witness, e := frontend.NewWitness(userCircuit, ecc.BN254.ScalarField())
	if witness == nil {
		t.Fatal(e)
		t.Fatal("witness is nil")
	}
	// err = oR1cs.IsSolved(witness)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	pk, vk, err := groth16.Setup(oR1cs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	startTime := time.Now()
	proof, err := groth16.Prove(oR1cs, pk, witness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	endTime := time.Now()
	fmt.Println("prove time is ", endTime.Sub(startTime))
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}

func ConstructBatchFromFile(fileName string) (witness *BatchCreateUserCircuit) {
	witnessFile, err := os.ReadFile(fileName)
	if err != nil {
		panic(err.Error())
	}
	witnessData := make([]byte, hex.DecodedLen(len(witnessFile)))
	n, err := hex.Decode(witnessData, witnessFile)
	if err != nil {
		panic(err.Error())
	}
	witnessData = witnessData[:n]

	witnessForCircuit := utils.DecodeBatchWitness(string(witnessData[:]))
	circuitWitness, _ := SetBatchCreateUserCircuitWitness(witnessForCircuit)
	return circuitWitness
}

func ConstructValidBatch(assetsCount int, totalAssetsCount int, userOpsPerBatch int) (witness *BatchCreateUserCircuit) {
	// construct cex assets
	cexAssets := make([]utils.CexAssetInfo, totalAssetsCount)
	for i := 0; i < totalAssetsCount; i++ {
		u := utils.CexAssetInfo{
			BasePrice: 1,
			Index:     uint32(i),
		}
		avgRatio := 100 / utils.TierCount
		for j := 0; j < utils.TierCount; j++ {
			u.LoanRatios[j] = utils.TierRatio{
				BoundaryValue:    new(big.Int).SetInt64(int64(100 * (j + 1))),
				Ratio:            uint8(100 - avgRatio*j),
				PrecomputedValue: new(big.Int).SetInt64(0),
			}
			u.MarginRatios[j] = utils.TierRatio{
				BoundaryValue:    new(big.Int).SetInt64(int64(100 * (j + 1))),
				Ratio:            uint8(100 - avgRatio*j),
				PrecomputedValue: new(big.Int).SetInt64(0),
			}
			u.PortfolioMarginRatios[j] = utils.TierRatio{
				BoundaryValue:    new(big.Int).SetInt64(int64(100 * (j + 1))),
				Ratio:            uint8(100 - avgRatio*j),
				PrecomputedValue: new(big.Int).SetInt64(0),
			}
		}
		utils.CalculatePrecomputedValue(u.LoanRatios[:])
		utils.CalculatePrecomputedValue(u.MarginRatios[:])
		utils.CalculatePrecomputedValue(u.PortfolioMarginRatios[:])
		cexAssets[i] = u
	}

	gap := totalAssetsCount / assetsCount
	// construct accounts
	accounts := make([]utils.AccountInfo, userOpsPerBatch)

	batchCreateUserWit := &utils.BatchCreateUserWitness{
		BeforeCexAssets: make([]utils.CexAssetInfo, totalAssetsCount),
		CreateUserOps:   make([]utils.CreateUserOperation, userOpsPerBatch),
	}
	for i := 0; i < totalAssetsCount; i++ {
		batchCreateUserWit.BeforeCexAssets[i] = cexAssets[i]
	}
	batchCreateUserWit.BeforeCEXAssetsCommitment = utils.ComputeCexAssetsCommitment(batchCreateUserWit.BeforeCexAssets)

	for i := 0; i < len(accounts); i++ {
		accounts[i] = utils.AccountInfo{
			AccountIndex: uint32(i),
			AccountId:    make([]byte, 32),
		}
		rand.Read(accounts[i].AccountId)
		accounts[i].AccountId = new(fr.Element).SetBytes(accounts[i].AccountId).Marshal()
		accounts[i].Assets = make([]utils.AccountAsset, assetsCount)
		totalEquity := new(big.Int).SetInt64(0)
		totalDebt := new(big.Int).SetInt64(0)
		totalCollateral := new(big.Int).SetInt64(0)

		for j := 0; j < len(accounts[i].Assets); j++ {
			accounts[i].Assets[j].Index = uint16(gap * j)
			assetPrice := new(big.Int).SetUint64(cexAssets[accounts[i].Assets[j].Index].BasePrice)
			accounts[i].Assets[j].Loan = uint64(rand.Intn(1000)) + 1
			accounts[i].Assets[j].Margin = uint64(rand.Intn(1000)) + 1
			accounts[i].Assets[j].PortfolioMargin = uint64(rand.Intn(1000)) + 1
			totalValue := accounts[i].Assets[j].Loan + accounts[i].Assets[j].Margin + accounts[i].Assets[j].PortfolioMargin
			collateralValue := utils.CalculateAssetValueForCollateral(accounts[i].Assets[j].Loan,
				accounts[i].Assets[j].Margin,
				accounts[i].Assets[j].PortfolioMargin,
				&cexAssets[accounts[i].Assets[j].Index])
			totalCollateral.Add(totalCollateral, collateralValue)
			collateralValue.Div(collateralValue, assetPrice)
			accounts[i].Assets[j].Debt = uint64(rand.Intn(int(collateralValue.Int64()))) + 1
			accounts[i].Assets[j].Equity = uint64(rand.Intn(1000)) + totalValue
			debtBigInt := new(big.Int).SetUint64(accounts[i].Assets[j].Debt)
			equityBigInt := new(big.Int).SetUint64(accounts[i].Assets[j].Equity)
			debtBigInt.Mul(debtBigInt, assetPrice)
			totalDebt.Add(totalDebt, debtBigInt)
			equityBigInt.Mul(equityBigInt, assetPrice)
			totalEquity.Add(totalEquity, equityBigInt)
			// update cexAssets
			cexAssets[accounts[i].Assets[j].Index].TotalEquity += accounts[i].Assets[j].Equity
			cexAssets[accounts[i].Assets[j].Index].TotalDebt += accounts[i].Assets[j].Debt
			cexAssets[accounts[i].Assets[j].Index].LoanCollateral += accounts[i].Assets[j].Loan
			cexAssets[accounts[i].Assets[j].Index].MarginCollateral += accounts[i].Assets[j].Margin
			cexAssets[accounts[i].Assets[j].Index].PortfolioMarginCollateral += accounts[i].Assets[j].PortfolioMargin
		}
		accounts[i].TotalEquity = totalEquity
		accounts[i].TotalDebt = totalDebt
		accounts[i].TotalCollateral = totalCollateral
	}

	// Build the account tree using the two-phase approach
	accountTree, err := utils.NewAccountTree(userOpsPerBatch)
	if err != nil {
		panic(err.Error())
	}
	for i := 0; i < len(accounts); i++ {
		poseidonHasher := poseidon.NewPoseidon()
		accountHash := utils.AccountInfoToHash(&accounts[i], &poseidonHasher)
		accountTree.Set(accounts[i].AccountIndex, accountHash)
	}
	accountTree.Build()

	// Get proofs from the built tree
	for i := 0; i < len(accounts); i++ {
		accountProof, err := accountTree.GetProof(accounts[i].AccountIndex)
		if err != nil {
			panic(err.Error())
		}
		batchCreateUserWit.CreateUserOps[i] = utils.CreateUserOperation{
			Assets:        accounts[i].Assets,
			AccountIndex:  accounts[i].AccountIndex,
			AccountIdHash: accounts[i].AccountId,
		}
		copy(batchCreateUserWit.CreateUserOps[i].AccountProof[:], accountProof[:])
	}

	batchCreateUserWit.AccountTreeRoot = accountTree.Root()
	batchCreateUserWit.AfterCEXAssetsCommitment = utils.ComputeCexAssetsCommitment(cexAssets)
	batchCreateUserWit.MinAccountIndex = accounts[0].AccountIndex
	batchCreateUserWit.MaxAccountIndex = accounts[len(accounts)-1].AccountIndex
	minBytes := new(big.Int).SetUint64(uint64(batchCreateUserWit.MinAccountIndex)).Bytes()
	if len(minBytes) == 0 {
		minBytes = []byte{0}
	}
	maxBytes := new(big.Int).SetUint64(uint64(batchCreateUserWit.MaxAccountIndex)).Bytes()
	if len(maxBytes) == 0 {
		maxBytes = []byte{0}
	}
	batchCreateUserWit.BatchCommitment = poseidon.PoseidonBytes(
		batchCreateUserWit.AccountTreeRoot,
		batchCreateUserWit.BeforeCEXAssetsCommitment,
		batchCreateUserWit.AfterCEXAssetsCommitment,
		minBytes,
		maxBytes)
	var serializeBuf bytes.Buffer
	enc := gob.NewEncoder(&serializeBuf)
	err = enc.Encode(batchCreateUserWit)
	if err != nil {
		panic(err.Error())
	}
	buf := serializeBuf.Bytes()
	compressedBuf := s2.Encode(nil, buf)
	witnessDataStr := base64.StdEncoding.EncodeToString(compressedBuf)
	witnessForCircuit := utils.DecodeBatchWitness(witnessDataStr)
	circuitWitness, _ := SetBatchCreateUserCircuitWitness(witnessForCircuit)
	return circuitWitness
}

func TestSetBatchCreateUserCircuitWitness(t *testing.T) {
	targetAssetCounts := 50
	userOpsPerBatch := 1
	circuitWitness := ConstructValidBatch(targetAssetCounts, utils.AssetCounts, userOpsPerBatch)
	for i := 0; i < len(circuitWitness.CreateUserOps); i++ {
		if len(circuitWitness.CreateUserOps[i].Assets) != targetAssetCounts {
			t.Fatal("asset counts not match")
		}
	}
	fmt.Println("assets info ", circuitWitness.CreateUserOps[0].Assets[0].LoanCollateralIndex)
	fmt.Println("assets info ", circuitWitness.CreateUserOps[0].Assets[0].MarginCollateralIndex)
	fmt.Println("assets info ", circuitWitness.CreateUserOps[0].Assets[0].PortfolioMarginCollateralIndex)
}
