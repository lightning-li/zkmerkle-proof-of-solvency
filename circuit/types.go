package circuit

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark/frontend"
)

type (
	Variable = frontend.Variable
	API      = frontend.API
)

// Consider using variable or constant
type TierRatio struct {
	BoundaryValue      Variable
	Ratio         	   Variable
	PrecomputedValue   Variable
}

type CexAssetInfo struct {
	TotalEquity Variable
	TotalDebt   Variable
	BasePrice   Variable

	VipLoanCollateral     		Variable
	MarginCollateral      		Variable
	PortfolioMarginCollateral   Variable

	VipLoanRatios               []TierRatio
	MarginRatios                []TierRatio
	PortfolioMarginRatios	    []TierRatio
}

type UserAssetInfo struct {
	Equity Variable
	Debt   Variable
	VipLoanCollateral     		Variable
	MarginCollateral      		Variable
	PortfolioMarginCollateral   Variable
}

type CreateUserOperation struct {
	BeforeAccountTreeRoot Variable
	AfterAccountTreeRoot  Variable
	Assets                []UserAssetInfo
	AccountIndex          Variable
	AccountIdHash         Variable
	AccountProof          [utils.AccountTreeDepth]Variable
}
