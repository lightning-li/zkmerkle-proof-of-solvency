package circuit

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark/std/hash/poseidon"
)

func VerifyMerkleProof(api API, merkleRoot Variable, node Variable, proofSet, helper []Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = poseidon.Poseidon(api, d1, d2)
	}
	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(merkleRoot, node)
}

func UpdateMerkleProof(api API, node Variable, proofSet, helper []Variable) (root Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = poseidon.Poseidon(api, d1, d2)
	}
	root = node
	return root
}

func AccountIdToMerkleHelper(api API, accountId Variable) []Variable {
	merkleHelpers := api.ToBinary(accountId, utils.AccountTreeDepth)
	return merkleHelpers
}

// check value is in [0, 2^64-1] range
func CheckValueInRange(api API, value Variable) {
	api.ToBinary(value, 64)
}

func ComputeUserAssetsCommitment(api API, assets []UserAssetInfo) Variable {
	nEles := (len(assets)*2 + 2) / 3
	tmpUserAssets := make([]Variable, nEles)
	flattenAssets := make([]Variable, nEles*3)
	for i := 0; i < len(assets); i++ {
		flattenAssets[2*i] = assets[i].Equity
		flattenAssets[2*i+1] = assets[i].Debt
	}
	for i := len(assets) * 2; i < len(flattenAssets); i++ {
		flattenAssets[i] = 0
	}
	for i := 0; i < len(tmpUserAssets); i++ {
		tmpUserAssets[i] = api.Add(api.Mul(flattenAssets[3*i], utils.Uint64MaxValueFrSquare),
			api.Mul(flattenAssets[3*i+1], utils.Uint64MaxValueFr), flattenAssets[3*i+2])
	}
	commitment := poseidon.Poseidon(api, tmpUserAssets...)
	return commitment
}

// one variable: TotalEquity + TotalDebt + BasePrice
// one variable: VipLoanCollateral + MarginCollateral + PortfolioMarginCollateral
// one variable contain two TierRatios and the length of TierRatios is even
func GetVariableCountOfCexAsset(cexAsset CexAssetInfo) int {
	res := 2 
	res += len(cexAsset.VipLoanRatios) / 2
	res += len(cexAsset.MarginRatios) / 2
	res += len(cexAsset.PortfolioMarginRatios) / 2
	return res
}

func ConvertTierRatiosToVariables(api API, ratios []TierRatio, res []Variable) {
	for i := 0; i < len(ratios); i += 2 {
		v := api.Add(ratios[i].Ratio, api.Mul(ratios[i].BoundaryValue, utils.Uint8MaxValueFr))
		v1 := api.Add(api.Mul(ratios[i+1].Ratio, utils.Uint126MaxValueFr), api.Mul(ratios[i+1].BoundaryValue, utils.Uint134MaxValueFr))
		res[i/2] = api.Add(v, v1)
	}
}

func FillCexAssetCommitment(api API, asset CexAssetInfo, currentIndex int, commitments []Variable) {
	counts := GetVariableCountOfCexAsset(asset)
	
	commitments[currentIndex*counts] = api.Add(api.Mul(asset.TotalEquity, utils.Uint64MaxValueFrSquare),
			api.Mul(asset.TotalDebt, utils.Uint64MaxValueFr), asset.BasePrice)
	
	commitments[currentIndex*counts+1] = api.Add(api.Mul(asset.VipLoanCollateral, utils.Uint64MaxValueFrSquare),
			api.Mul(asset.MarginCollateral, utils.Uint64MaxValueFr), asset.PortfolioMarginCollateral)

	ConvertTierRatiosToVariables(api, asset.VipLoanRatios, commitments[currentIndex*counts+2:])
	ConvertTierRatiosToVariables(api, asset.MarginRatios, commitments[currentIndex*counts+2+len(asset.VipLoanRatios)/2:])
	ConvertTierRatiosToVariables(api, asset.PortfolioMarginRatios, commitments[currentIndex*counts+2+len(asset.VipLoanRatios)/2+len(asset.MarginRatios)/2:])
}

func GenerateRapidArithmeticForCollateral(api API, tierRatios []TierRatio) {
	
	tierRatios[0].PrecomputedValue = api.Div(api.Mul(tierRatios[0].BoundaryValue, tierRatios[0].Ratio), utils.PercentageMultiplierFr)
	for i := 1; i < len(tierRatios); i++ {
		// constraint number: 2230 => 1876 => 389
		api.AssertIsLessOrEqualNOp(tierRatios[i-1].BoundaryValue, tierRatios[i].BoundaryValue, 128)
		// constraint number: 607
		api.AssertIsLessOrEqualNOp(tierRatios[i].Ratio, utils.PercentageMultiplierFr, 7)
		// constraint number: 480
		api.AssertIsLessOrEqualNOp(tierRatios[i].BoundaryValue, utils.MaxTierBoundaryValueFr, 128)
		diffBoundary := api.Sub(tierRatios[i].BoundaryValue, tierRatios[i-1].BoundaryValue)
		current := api.Div(api.Mul(diffBoundary, tierRatios[i].Ratio), utils.PercentageMultiplierFr)
		tierRatios[i].PrecomputedValue = api.Add(tierRatios[i-1].PrecomputedValue, current)
	}
}

// func FindTierRatioIndex(_ *big.Int, in []*big.Int, out []*big.Int) error {
// 	// in[0] is collateral
// 	// in[1..] is tierRatios
// 	// out[0] is the index of the tierRatios which boundary value is greater than collateral
// 	// out[1] is the flag to indicate whether there is a boundary value which is greater than collateral
// 	collateral := in[0]
// 	tierRatios := in[1:]
// 	for i := 0; i < len(tierRatios); i++ {
// 		if tierRatios[i].Cmp(collateral) > 0 {
// 			out[0] = big.NewInt(int64(i))
// 			out[1] = big.NewInt(1)
// 			return nil
// 		}
// 	}
// 	out[0] = big.NewInt(int64(len(tierRatios)))
// 	out[1] = big.NewInt(0)
// 	return nil
// }

func ComputeCollateral(api API, collateral Variable, tierRatios []TierRatio) Variable {
	var res Variable
	var firstFlag Variable = 0

	compareRes := api.CmpNOp(tierRatios[0].BoundaryValue, collateral, 128, true)
	flag := api.IsZero(api.Sub(compareRes, 1))
	firstFlag = api.Xor(firstFlag, flag)
	res = api.Select(firstFlag, api.Mul(collateral, tierRatios[0].Ratio), tierRatios[0].PrecomputedValue)
	
	for i := 1; i < len(tierRatios); i++ {
		compareRes = api.CmpNOp(tierRatios[i].BoundaryValue, collateral, 128, true)
		// flag is true if tierRatios[i].BoundaryValue > collateral
		// flag is false if tierRatios[i].BoundaryValue <= collateral
		flag = api.IsZero(api.Sub(compareRes, 1))
		// Only the first time that boundary value is greater than collateral, 
		// the firstFlag to 1. Otherwise, the firstFlag is 0.
		firstFlag = api.Xor(firstFlag, flag)
		
		v := api.Select(firstFlag, tierRatios[i-1].PrecomputedValue, 0)
		res = api.Add(res, v)

		v1 := api.Select(firstFlag, api.Sub(collateral, tierRatios[i-1].BoundaryValue), 0)
		v1 = api.Div(api.Mul(v1, tierRatios[i].Ratio), utils.PercentageMultiplierFr)
		res = api.Add(res, v1)
		firstFlag = api.Select(flag, 1, 0)
	}
	// The last tier boundary value is less or equal than collateral
	res = api.Select(firstFlag, res, tierRatios[len(tierRatios)-1].PrecomputedValue)
	return res
}