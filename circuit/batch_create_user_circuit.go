package circuit

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark/std/hash/poseidon"
	"github.com/consensys/gnark/std/rangecheck"
)

type BatchCreateUserCircuit struct {
	BatchCommitment           Variable `gnark:",public"`
	BeforeAccountTreeRoot     Variable
	AfterAccountTreeRoot      Variable
	BeforeCEXAssetsCommitment Variable
	AfterCEXAssetsCommitment  Variable
	BeforeCexAssets           []CexAssetInfo
	CreateUserOps             []CreateUserOperation
}

func NewVerifyBatchCreateUserCircuit(commitment []byte) *BatchCreateUserCircuit {
	var v BatchCreateUserCircuit
	v.BatchCommitment = commitment
	return &v
}

func NewBatchCreateUserCircuit(assetCounts uint32, batchCounts uint32) *BatchCreateUserCircuit {
	var circuit BatchCreateUserCircuit
	circuit.BatchCommitment = 0
	circuit.BeforeAccountTreeRoot = 0
	circuit.AfterAccountTreeRoot = 0
	circuit.BeforeCEXAssetsCommitment = 0
	circuit.AfterCEXAssetsCommitment = 0
	circuit.BeforeCexAssets = make([]CexAssetInfo, assetCounts)
	for i := uint32(0); i < assetCounts; i++ {
		circuit.BeforeCexAssets[i] = CexAssetInfo{
			TotalEquity: 0,
			TotalDebt:   0,
			BasePrice:   0,
			VipLoanCollateral: 0,
			MarginCollateral: 0,
			PortfolioMarginCollateral: 0,
			VipLoanRatios: make([]TierRatio, utils.TierCount),
			MarginRatios: make([]TierRatio, utils.TierCount),
			PortfolioMarginRatios: make([]TierRatio, utils.TierCount),
		}
	}
	circuit.CreateUserOps = make([]CreateUserOperation, batchCounts)
	for i := uint32(0); i < batchCounts; i++ {
		circuit.CreateUserOps[i] = CreateUserOperation{
			BeforeAccountTreeRoot: 0,
			AfterAccountTreeRoot:  0,
			Assets:                make([]UserAssetInfo, assetCounts),
			AccountIndex:          0,
			AccountProof:          [utils.AccountTreeDepth]Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		}
		for j := uint32(0); j < assetCounts; j++ {
			circuit.CreateUserOps[i].Assets[j].Debt = 0
			circuit.CreateUserOps[i].Assets[j].Equity = 0
			circuit.CreateUserOps[i].Assets[j].VipLoanCollateral = 0
			circuit.CreateUserOps[i].Assets[j].MarginCollateral = 0
			circuit.CreateUserOps[i].Assets[j].PortfolioMarginCollateral = 0
		}
	}
	return &circuit
}

func (b BatchCreateUserCircuit) Define(api API) error {
	// verify whether BatchCommitment is computed correctly
	actualBatchCommitment := poseidon.Poseidon(api, b.BeforeAccountTreeRoot, b.AfterAccountTreeRoot, b.BeforeCEXAssetsCommitment, b.AfterCEXAssetsCommitment)
	api.AssertIsEqual(b.BatchCommitment, actualBatchCommitment)
	countOfCexAsset := GetVariableCountOfCexAsset(b.BeforeCexAssets[0])
	cexAssets := make([]Variable, len(b.BeforeCexAssets) * countOfCexAsset)
	afterCexAssets := make([]CexAssetInfo, len(b.BeforeCexAssets))

	r := rangecheck.New(api)
	// verify whether beforeCexAssetsCommitment is computed correctly
	for i := 0; i < len(b.BeforeCexAssets); i++ {
		r.Check(b.BeforeCexAssets[i].TotalEquity, 64)
		r.Check(b.BeforeCexAssets[i].TotalDebt, 64)
		r.Check(b.BeforeCexAssets[i].BasePrice, 64)
		r.Check(b.BeforeCexAssets[i].VipLoanCollateral, 64)
		r.Check(b.BeforeCexAssets[i].MarginCollateral, 64)
		r.Check(b.BeforeCexAssets[i].PortfolioMarginCollateral, 64)
		
		FillCexAssetCommitment(api, b.BeforeCexAssets[i], i, cexAssets)
		GenerateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].VipLoanRatios)
		GenerateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].MarginRatios)
		GenerateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].PortfolioMarginRatios)
		afterCexAssets[i] = b.BeforeCexAssets[i]
	}
	actualCexAssetsCommitment := poseidon.Poseidon(api, cexAssets...)
	api.AssertIsEqual(b.BeforeCEXAssetsCommitment, actualCexAssetsCommitment)

	api.AssertIsEqual(b.BeforeAccountTreeRoot, b.CreateUserOps[0].BeforeAccountTreeRoot)
	api.AssertIsEqual(b.AfterAccountTreeRoot, b.CreateUserOps[len(b.CreateUserOps)-1].AfterAccountTreeRoot)

	t := ConstructTierRatiosLookupTable(api, b.BeforeCexAssets)

	for i := 0; i < len(b.CreateUserOps); i++ {
		accountIndexHelper := AccountIdToMerkleHelper(api, b.CreateUserOps[i].AccountIndex)
		VerifyMerkleProof(api, b.CreateUserOps[i].BeforeAccountTreeRoot, EmptyAccountLeafNodeHash, b.CreateUserOps[i].AccountProof[:], accountIndexHelper)
		var totalUserEquity Variable = 0
		var totalUserDebt Variable = 0
		userAssets := b.CreateUserOps[i].Assets
		var totalUserCollateralRealValue Variable = 0
		
		for j := 0; j < len(userAssets); j++ {
			r.Check(userAssets[j].Debt, 64)
			r.Check(userAssets[j].Equity, 64)
			r.Check(userAssets[j].VipLoanCollateral, 64)
			r.Check(userAssets[j].MarginCollateral, 64)
			r.Check(userAssets[j].PortfolioMarginCollateral, 64)
			
			assetTotalCollateral := api.Add(userAssets[j].VipLoanCollateral, userAssets[j].MarginCollateral, userAssets[j].PortfolioMarginCollateral)
			r.Check(assetTotalCollateral, 64)
			api.AssertIsLessOrEqualNOp(assetTotalCollateral, userAssets[j].Equity, 64, true)
			
			collateralValues := GetAndCheckTierRatiosQueryResults(api, r, t, j, userAssets[j], b.BeforeCexAssets[j].BasePrice, 
											3*(len(b.BeforeCexAssets[j].VipLoanRatios)+1), 
											3*(len(b.BeforeCexAssets[j].MarginRatios)+1),
											3*(len(b.BeforeCexAssets[j].PortfolioMarginRatios)+1))
			vipLoanRealValue := collateralValues[0]
			marginRealValue := collateralValues[1]
			portfolioMarginRealValue := collateralValues[2]

			totalUserCollateralRealValue = api.Add(totalUserCollateralRealValue, vipLoanRealValue, marginRealValue, portfolioMarginRealValue)
			
			totalUserEquity = api.Add(totalUserEquity, api.Mul(userAssets[j].Equity, b.BeforeCexAssets[j].BasePrice))
			totalUserDebt = api.Add(totalUserDebt, api.Mul(userAssets[j].Debt, b.BeforeCexAssets[j].BasePrice))

			afterCexAssets[j].TotalEquity = api.Add(afterCexAssets[j].TotalEquity, userAssets[j].Equity)
			afterCexAssets[j].TotalDebt = api.Add(afterCexAssets[j].TotalDebt, userAssets[j].Debt)
			afterCexAssets[j].VipLoanCollateral = api.Add(afterCexAssets[j].VipLoanCollateral, userAssets[j].VipLoanCollateral)
			afterCexAssets[j].MarginCollateral = api.Add(afterCexAssets[j].MarginCollateral, userAssets[j].MarginCollateral)
			afterCexAssets[j].PortfolioMarginCollateral = api.Add(afterCexAssets[j].PortfolioMarginCollateral, userAssets[j].PortfolioMarginCollateral)
		}
		// make sure user's total Debt is less or equal than total collateral
		api.AssertIsLessOrEqualNOp(totalUserDebt, totalUserCollateralRealValue, 128)

		userAssetsCommitment := ComputeUserAssetsCommitment(api, userAssets)
		accountHash := poseidon.Poseidon(api, b.CreateUserOps[i].AccountIdHash, totalUserEquity, totalUserDebt, userAssetsCommitment)
		actualAccountTreeRoot := UpdateMerkleProof(api, accountHash, b.CreateUserOps[i].AccountProof[:], accountIndexHelper)
		api.AssertIsEqual(actualAccountTreeRoot, b.CreateUserOps[i].AfterAccountTreeRoot)

	}

	tempAfterCexAssets := make([]Variable, len(b.BeforeCexAssets) * countOfCexAsset)
	for j := 0; j < len(b.BeforeCexAssets); j++ {
		r.Check(afterCexAssets[j].TotalEquity, 64)
		r.Check(afterCexAssets[j].TotalDebt, 64)
		r.Check(afterCexAssets[j].VipLoanCollateral, 64)
		r.Check(afterCexAssets[j].MarginCollateral, 64)
		r.Check(afterCexAssets[j].PortfolioMarginCollateral, 64)

		FillCexAssetCommitment(api, afterCexAssets[j], j, tempAfterCexAssets)
	}

	// verify AfterCEXAssetsCommitment is computed correctly
	actualAfterCEXAssetsCommitment := poseidon.Poseidon(api, tempAfterCexAssets...)
	api.AssertIsEqual(actualAfterCEXAssetsCommitment, b.AfterCEXAssetsCommitment)

	for i := 0; i < len(b.CreateUserOps)-1; i++ {
		api.AssertIsEqual(b.CreateUserOps[i].AfterAccountTreeRoot, b.CreateUserOps[i+1].BeforeAccountTreeRoot)
	}

	return nil
}

func copyTierRatios(dst []TierRatio, src []utils.TierRatio) {
	for i := 0; i < len(dst); i++ {
		dst[i].BoundaryValue = src[i].BoundaryValue
		dst[i].Ratio = src[i].Ratio
		dst[i].PrecomputedValue = src[i].PrecomputedValue
	}

}

func SetBatchCreateUserCircuitWitness(batchWitness *utils.BatchCreateUserWitness) (witness *BatchCreateUserCircuit, err error) {
	witness = &BatchCreateUserCircuit{
		BatchCommitment:           batchWitness.BatchCommitment,
		BeforeAccountTreeRoot:     batchWitness.BeforeAccountTreeRoot,
		AfterAccountTreeRoot:      batchWitness.AfterAccountTreeRoot,
		BeforeCEXAssetsCommitment: batchWitness.BeforeCEXAssetsCommitment,
		AfterCEXAssetsCommitment:  batchWitness.AfterCEXAssetsCommitment,
		BeforeCexAssets:           make([]CexAssetInfo, len(batchWitness.BeforeCexAssets)),
		CreateUserOps:             make([]CreateUserOperation, len(batchWitness.CreateUserOps)),
	}

	for i := 0; i < len(witness.BeforeCexAssets); i++ {
		witness.BeforeCexAssets[i].TotalEquity = batchWitness.BeforeCexAssets[i].TotalEquity
		witness.BeforeCexAssets[i].TotalDebt = batchWitness.BeforeCexAssets[i].TotalDebt
		witness.BeforeCexAssets[i].BasePrice = batchWitness.BeforeCexAssets[i].BasePrice
		witness.BeforeCexAssets[i].VipLoanCollateral = batchWitness.BeforeCexAssets[i].VipLoanCollateral
		witness.BeforeCexAssets[i].MarginCollateral = batchWitness.BeforeCexAssets[i].MarginCollateral
		witness.BeforeCexAssets[i].PortfolioMarginCollateral = batchWitness.BeforeCexAssets[i].PortfolioMarginCollateral
		witness.BeforeCexAssets[i].VipLoanRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].VipLoanRatios))
		copyTierRatios(witness.BeforeCexAssets[i].VipLoanRatios, batchWitness.BeforeCexAssets[i].VipLoanRatios[:])
		witness.BeforeCexAssets[i].MarginRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].MarginRatios))
		copyTierRatios(witness.BeforeCexAssets[i].MarginRatios, batchWitness.BeforeCexAssets[i].MarginRatios[:])
		witness.BeforeCexAssets[i].PortfolioMarginRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].PortfolioMarginRatios))
		copyTierRatios(witness.BeforeCexAssets[i].PortfolioMarginRatios, batchWitness.BeforeCexAssets[i].PortfolioMarginRatios[:])
	}

	for i := 0; i < len(witness.CreateUserOps); i++ {
		witness.CreateUserOps[i].BeforeAccountTreeRoot = batchWitness.CreateUserOps[i].BeforeAccountTreeRoot
		witness.CreateUserOps[i].AfterAccountTreeRoot = batchWitness.CreateUserOps[i].AfterAccountTreeRoot
		witness.CreateUserOps[i].Assets = make([]UserAssetInfo, len(batchWitness.CreateUserOps[i].Assets))
		for j := 0; j < len(batchWitness.CreateUserOps[i].Assets); j++ {
			var userAsset UserAssetInfo
			userAsset.Equity = batchWitness.CreateUserOps[i].Assets[j].Equity
			userAsset.Debt = batchWitness.CreateUserOps[i].Assets[j].Debt
			userAsset.VipLoanCollateral = batchWitness.CreateUserOps[i].Assets[j].VipLoan
			userAsset.MarginCollateral = batchWitness.CreateUserOps[i].Assets[j].Margin
			userAsset.PortfolioMarginCollateral = batchWitness.CreateUserOps[i].Assets[j].PortfolioMargin

			witness.CreateUserOps[i].Assets[j] = userAsset
		}
		witness.CreateUserOps[i].AccountIdHash = batchWitness.CreateUserOps[i].AccountIdHash
		witness.CreateUserOps[i].AccountIndex = batchWitness.CreateUserOps[i].AccountIndex
		for j := 0; j < len(witness.CreateUserOps[i].AccountProof); j++ {
			witness.CreateUserOps[i].AccountProof[j] = batchWitness.CreateUserOps[i].AccountProof[j]
		}
	}
	return witness, nil
}
