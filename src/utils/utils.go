package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/shopspring/decimal"
)

func ConvertTierRatiosToBytes(tiersRatio []TierRatio) [][]byte {
	res := make([][]byte, 0, len(tiersRatio)/2)
	resBigInt := new(big.Int).SetUint64(0)
	aBigInt := new(big.Int).SetUint64(0)
	bBigInt := new(big.Int).SetUint64(0)
	cBigInt := new(big.Int).SetUint64(0)
	dBigInt := new(big.Int).SetUint64(0)
	for i := 0; i < len(tiersRatio); i+=2 {
		resBigInt.SetUint64(0)
		aBigInt.SetUint64(uint64(tiersRatio[i].Ratio))
		bBigInt.Set(tiersRatio[i].BoundaryValue)
		bBigInt.Mul(bBigInt, Uint8MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)

		cBigInt.SetUint64(uint64(tiersRatio[i+1].Ratio))
		cBigInt.Mul(cBigInt, Uint126MaxValueBigInt)
		dBigInt.Set(tiersRatio[i+1].BoundaryValue)
		dBigInt.Mul(dBigInt, Uint134MaxValueBigInt)
		cBigInt.Add(cBigInt, dBigInt)

		resBigInt.Add(aBigInt, cBigInt)
		res = append(res, resBigInt.Bytes())

	}
	return res
}

func ConvertAssetInfoToBytes(value any) [][]byte {
	switch t := value.(type) {
	case CexAssetInfo:
		res := make([][]byte, 0, 10)
		aBigInt := new(big.Int).SetUint64(t.TotalEquity)
		bBigInt := new(big.Int).SetUint64(t.TotalDebt)
		cBigInt := new(big.Int).SetUint64(t.BasePrice)
		aBigInt.Mul(aBigInt, Uint64MaxValueBigIntSquare)
		bBigInt.Mul(bBigInt, Uint64MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)
		resBigInt := new(big.Int).Add(aBigInt, cBigInt)
		res = append(res, resBigInt.Bytes())

		resBigInt.SetUint64(0)
		aBigInt.SetUint64(t.VipLoanCollateral)
		bBigInt.SetUint64(t.MarginCollateral)
		cBigInt.SetUint64(t.PortfolioMarginCollateral)
		aBigInt.Mul(aBigInt, Uint64MaxValueBigIntSquare)
		bBigInt.Mul(bBigInt, Uint64MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)
		resBigInt.Add(cBigInt, aBigInt)
		res = append(res, resBigInt.Bytes())

		// one tier ratio: boundaryValue take 118 bits, ratio take 8 bits = 126 bits
		// so two tier ratio take 252 bits, can be stored in one circuit Variable
		tempRes := ConvertTierRatiosToBytes(t.VipLoanRatios[:])
		res = append(res, tempRes...)
		tempRes = ConvertTierRatiosToBytes(t.MarginRatios[:])
		res = append(res, tempRes...)
		tempRes = ConvertTierRatiosToBytes(t.PortfolioMarginRatios[:])
		res = append(res, tempRes...)
		return res
	default:
		panic("not supported type")
	}
}

func SelectAssetValue(expectAssetIndex int, flag int, currentAssetPosition int, assets []AccountAsset) (*big.Int, bool) {
	if currentAssetPosition >= len(assets) {
		return ZeroBigInt, false
	}
	if int(assets[currentAssetPosition].Index) > expectAssetIndex {
		return ZeroBigInt, false
	} else {
		if flag == 0 {
			return new(big.Int).SetUint64(assets[currentAssetPosition].Equity), false
		} else if flag == 1 {
			return new(big.Int).SetUint64(assets[currentAssetPosition].Debt), false
		} else if flag == 2 {
			return new(big.Int).SetUint64(assets[currentAssetPosition].VipLoan), false
		} else if flag == 3 {
			return new(big.Int).SetUint64(assets[currentAssetPosition].Margin), false
		} else {
			return new(big.Int).SetUint64(assets[currentAssetPosition].PortfolioMargin), true
		}
	}
}

func ComputeUserAssetsCommitment(hasher *hash.Hash, assets []AccountAsset) []byte {
	(*hasher).Reset()
	nEles := (AssetCounts*5 + 2) / 3
	currentAssetPosition := 0
	for i := 0; i < nEles; i++ {
		expectAssetIndex := (3 * i) / 5
		flag := (3 * i) % 5
		aBigInt, positionChange := SelectAssetValue(expectAssetIndex, flag, currentAssetPosition, assets)
		if positionChange {
			currentAssetPosition += 1
		}

		expectAssetIndex = ((3 * i) + 1) / 5
		flag = ((3 * i) + 1) % 5
		bBigInt, positionChange := SelectAssetValue(expectAssetIndex, flag, currentAssetPosition, assets)
		if positionChange {
			currentAssetPosition += 1
		}

		expectAssetIndex = ((3 * i) + 2) / 5
		flag = ((3 * i) + 2) % 5
		cBigInt, positionChange := SelectAssetValue(expectAssetIndex, flag, currentAssetPosition, assets)
		if positionChange {
			currentAssetPosition += 1
		}

		sumBigIntBytes := new(big.Int).Add(new(big.Int).Add(
			new(big.Int).Mul(aBigInt, Uint64MaxValueBigIntSquare),
			new(big.Int).Mul(bBigInt, Uint64MaxValueBigInt)),
			cBigInt).Bytes()
		(*hasher).Write(sumBigIntBytes)
	}

	return (*hasher).Sum(nil)
}

func ParseUserDataSet(dirname string) ([]AccountInfo, []CexAssetInfo, error) {
	const CEX_ASSET_INFO_FILE string = "cex_assets_info.csv"
	userFiles, err := os.ReadDir(dirname)
	if err != nil {
		return nil, nil, err
	}
	var accountInfo []AccountInfo
	var cexAssetInfo []CexAssetInfo

	workersNum := 8
	userFileNames := make([]string, 0)

	type UserParseRes struct {
		accounts []AccountInfo
	}
	results := make([]chan UserParseRes, workersNum)
	for i := 0; i < workersNum; i++ {
		results[i] = make(chan UserParseRes, 1)
	}

	for _, userFile := range userFiles {
		if !strings.Contains(userFile.Name(), ".csv") {
			continue
		}
		if userFile.Name() == CEX_ASSET_INFO_FILE {
			continue
		}

		userFileNames = append(userFileNames, filepath.Join(dirname, userFile.Name()))
	}
	assetIndexes, err := ParseAssetIndexFromUserFile(userFileNames[0])
	if err != nil {
		return nil, nil, err
	}

	cexAssetInfo, err = ParseCexAssetInfoFromFile(filepath.Join(dirname, CEX_ASSET_INFO_FILE), assetIndexes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < workersNum; i++ {
		go func(workerId int) {
			for j := workerId; j < len(userFileNames); j += workersNum {
				if j >= len(userFileNames) {
					break
				}
				tmpAccountInfo, err := ReadUserDataFromCsvFile(userFileNames[j], cexAssetInfo)
				if err != nil {
					panic(err.Error())
				}
				results[workerId] <- UserParseRes{
					accounts: tmpAccountInfo,
				}
			}
		}(i)
	}

	gcQuitChan := make(chan bool)
	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
				runtime.GC()
			case <-gcQuitChan:
				return
			}
		}
	}()

	quit := make(chan bool)
	go func() {
		for i := 0; i < len(userFileNames); i++ {
			res := <-results[i%workersNum]
			if i != 0 {
				for j := 0; j < len(res.accounts); j++ {
					res.accounts[j].AccountIndex += uint32(len(accountInfo))
				}
			}
			accountInfo = append(accountInfo, res.accounts...)
		}
		quit <- true
	}()
	<-quit
	gcQuitChan <- true
	return accountInfo, cexAssetInfo, nil
}

func SafeAdd(a uint64, b uint64) (c uint64) {
	c = a + b
	if c < a {
		panic("overflow for balance")
	}
	return c
}

func ParseAssetIndexFromUserFile(userFilename string) ([]string, error) {
	f, err := os.Open(userFilename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.Read()
	if err != nil {
		return nil, err
	}
	// 3: rn, id, total_net_balance
	// 6: equity_assetA, debt_assetA, assetA, assetA_viploan, assetA_margin, assetA_portfolio_margin
	assetCounts := (len(data) - 3) / 6
	cexAssetsList := make([]string, assetCounts)
	
	for i := 0; i < assetCounts; i++ {
		cexAssetsList[i] = data[i*6+4]
	}
	return cexAssetsList, nil
}

func PaddingTierRatios(tiersRatio []TierRatio) (res [TierCount]TierRatio) {
	if len(tiersRatio) > TierCount {
		panic("the length of tiers ratio is bigger than TierCount")
	}
	for i := 0; i < TierCount; i++ {
		if i < len(tiersRatio) {
			res[i] = tiersRatio[i]
		} else {
			precomputedValue := new(big.Int).SetUint64(0)
			if len(tiersRatio) > 0 {
				precomputedValue.Set(tiersRatio[len(tiersRatio)-1].PrecomputedValue)
			}
			
			res[i] = TierRatio{
				BoundaryValue: new(big.Int).Set(MaxTierBoundaryValue),
				Ratio:         0,
				PrecomputedValue: precomputedValue,
			}
		}
	}
	return res
}

func ParseTiersRatioFromStr(tiersRatioEnc string) ([TierCount]TierRatio, error) {
	// tiersRatioEnc = strings.Trim(tiersRatioEnc, "[]")
	if len(tiersRatioEnc) == 0 {
		return PaddingTierRatios([]TierRatio{}), nil
	}
	tiersRatioStrs := strings.Split(tiersRatioEnc, ",")
	tiersRatio := make([]TierRatio, 0, 10)
	valueMultiplier := new(big.Int).SetUint64(10000000000000000)
	precomputedValue := new(big.Int).SetUint64(0)
	for i := 0; i < len(tiersRatioStrs); i += 1 {
		tmpTierRatio := strings.Split(tiersRatioStrs[i], ":")
		rangeValues := strings.Split(tmpTierRatio[0], "-")
		if len(tmpTierRatio) != 2 || len(rangeValues) != 2 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers ratio data wrong")
		}
		lowBoundaryValue, err := ConvertFloatStrToUint64(rangeValues[0], 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}
		boundaryValue, err := ConvertFloatStrToUint64(rangeValues[1], 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}
		
		ratio, err := ConvertFloatStrToUint64(tmpTierRatio[1], 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}
		
		boundaryValueBigInt := new(big.Int).SetUint64(boundaryValue)
		boundaryValueBigInt.Mul(boundaryValueBigInt, valueMultiplier)
		lowBoundaryValueBigInt := new(big.Int).SetUint64(lowBoundaryValue)
		lowBoundaryValueBigInt.Mul(lowBoundaryValueBigInt, valueMultiplier)

		if boundaryValueBigInt.Cmp(lowBoundaryValueBigInt) < 0 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers boundry value data wrong")
		}
		
		diffValue := new(big.Int).Sub(boundaryValueBigInt, lowBoundaryValueBigInt)

		precomputedValue.Add(precomputedValue, diffValue.Mul(diffValue, new(big.Int).SetUint64(ratio)).Div(diffValue, PercentageMultiplier))
		
		tiersRatio = append(tiersRatio, TierRatio{
			BoundaryValue: boundaryValueBigInt,
			Ratio:         uint8(ratio),
			PrecomputedValue: new(big.Int).Set(precomputedValue),
		})
	}
	return PaddingTierRatios(tiersRatio), nil

}

func ParseCexAssetInfoFromFile(name string, assetIndexes []string) ([]CexAssetInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	cexAssets2Info := make(map[string]CexAssetInfo)
	data = data[1:]
	for i := 0; i < len(data); i++ {
		if len(data[i]) != 5 {
			fmt.Println("cex asset data wrong:", data[i])
			return nil, errors.New("cex asset data wrong")
		}
		tmpCexAssetInfo := CexAssetInfo {
			Symbol: data[i][0],
		}
		multiplier := int64(100000000)
		if AssetTypeForTwoDigits[tmpCexAssetInfo.Symbol] {
			multiplier = 100000000000000
		}
		tmpCexAssetInfo.BasePrice, err = ConvertFloatStrToUint64(data[i][1], multiplier)
		if err != nil {
			fmt.Println("asset data wrong:", data[i][0], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.VipLoanRatios, err = ParseTiersRatioFromStr(data[i][2])
		if err != nil {
			fmt.Println("parse viploan tiers ratio failed:", data[i][2], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.MarginRatios, err = ParseTiersRatioFromStr(data[i][3])
		if err != nil {
			fmt.Println("parse margin tiers ratio failed:", data[i][3], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.PortfolioMarginRatios, err = ParseTiersRatioFromStr(data[i][4])
		if err != nil {
			fmt.Println("parse portfolio margin tiers ratio failed:", data[i][4], err.Error())
			return nil, err
		}
		
		cexAssets2Info[tmpCexAssetInfo.Symbol] = tmpCexAssetInfo
	}
	
	cexAssetsInfo := make([]CexAssetInfo, len(assetIndexes))

	if len(assetIndexes) != len(cexAssets2Info) {
		fmt.Println("the length of asset indexes is not equal to the length of cex assets info")
		return nil, errors.New("cex asset data wrong")
	}
	for i := 0; i < len(assetIndexes); i++ {
		cexAssetsInfo[i] = cexAssets2Info[assetIndexes[i]]
		cexAssetsInfo[i].Index = uint32(i)
	}

	return cexAssetsInfo, nil

}

func ReadUserDataFromCsvFile(name string, cexAssetsInfo []CexAssetInfo) ([]AccountInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	accountIndex := 0
	accounts := make([]AccountInfo, len(data)-1)
	// rn, id,
	// equity_assetA, debt_assetA, assetA, assetA_viploan, assetA_margin, assetA_portfolio_margin,
	// equity_assetB, debt_assetB, assetB, assetB_viploan, assetB_margin, assetA_portfolio_margin,
	// ......
	assetCounts := (len(data[0]) - 3) / 6
	data = data[1:]
	invalidCounts := 0
	for i := 0; i < len(data); i++ {
		invalidAccountFlag := false
		var account AccountInfo
		assets := make([]AccountAsset, 0, 8)
		account.TotalEquity = new(big.Int).SetInt64(0)
		account.TotalDebt = new(big.Int).SetInt64(0)
		account.TotalCollateral = new(big.Int).SetInt64(0)
		// first element of data[i] is ID. we use accountIndex instead
		account.AccountIndex = uint32(accountIndex)
		accountId, err := hex.DecodeString(data[i][1])
		if err != nil || len(accountId) != 32 {
			panic("accountId is invalid: " + data[i][1])
		}
		account.AccountId = new(fr.Element).SetBytes(accountId).Marshal()
		var tmpAsset AccountAsset
		for j := 0; j < assetCounts; j++ {
			multiplier := int64(100000000)
			if AssetTypeForTwoDigits[cexAssetsInfo[j].Symbol] {
				multiplier = 100
			}
			equity, err := ConvertFloatStrToUint64(data[i][j*6+2], multiplier)
			if err != nil {
				fmt.Println("the symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "equity data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			debt, err := ConvertFloatStrToUint64(data[i][j*6+3], multiplier)
			if err != nil {
				fmt.Println("the debt symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "debt data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}
			
			viploan, err := ConvertFloatStrToUint64(data[i][j*6+5], multiplier)
			if err != nil {
				fmt.Println("the viploan symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "viploan data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			margin, err := ConvertFloatStrToUint64(data[i][j*6+6], multiplier)
			if err != nil {
				fmt.Println("the margin symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "margin data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			portfolioMargin, err := ConvertFloatStrToUint64(data[i][j*6+7], multiplier)
			if err != nil {
				fmt.Println("the portfolio margin symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "portfolio margin data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			if equity != 0 || debt != 0 {
				tmpAsset.Index = uint16(j)
				tmpAsset.Equity = equity
				tmpAsset.Debt = debt
				tmpAsset.VipLoan = viploan
				tmpAsset.Margin = margin
				tmpAsset.PortfolioMargin = portfolioMargin
				assets = append(assets, tmpAsset)
				assetTotalCollateral := SafeAdd(tmpAsset.VipLoan, tmpAsset.Margin)
				assetTotalCollateral = SafeAdd(assetTotalCollateral, tmpAsset.PortfolioMargin)
				if assetTotalCollateral > tmpAsset.Equity {
					fmt.Println("account", data[i][1], "data wrong: total collateral is bigger than equity")
					invalidCounts += 1
					invalidAccountFlag = true
					break
				}

				account.TotalEquity = account.TotalEquity.Add(account.TotalEquity,
					new(big.Int).Mul(new(big.Int).SetUint64(tmpAsset.Equity), new(big.Int).SetUint64(cexAssetsInfo[j].BasePrice)))
				account.TotalDebt = account.TotalDebt.Add(account.TotalDebt,
					new(big.Int).Mul(new(big.Int).SetUint64(tmpAsset.Debt), new(big.Int).SetUint64(cexAssetsInfo[j].BasePrice)))
				
				account.TotalCollateral = account.TotalCollateral.Add(account.TotalCollateral, 
					CalculateAssetValueForCollateral(viploan, margin, portfolioMargin, &cexAssetsInfo[j]))
			}
		}

		if !invalidAccountFlag {
			account.Assets = assets
			if account.TotalCollateral.Cmp(account.TotalDebt) >= 0 {
				accounts[accountIndex] = account
				accountIndex += 1
			} else {
				invalidCounts += 1
				fmt.Println("account", data[i][1], "data wrong: total debt is bigger than collateral:", account.TotalDebt, account.TotalCollateral)
			}
		}
		if i%100000 == 0 {
			runtime.GC()
		}
	}
	accounts = accounts[:accountIndex]
	fmt.Println("The invalid accounts number is ", invalidCounts)
	fmt.Println("The valid accounts number is ", len(accounts))
	return accounts, nil
}

func CalculateAssetValueForCollateral(viploan uint64, margin uint64, portfolioMargin uint64, cexAssetInfo *CexAssetInfo) *big.Int {
	assetPrice := new(big.Int).SetUint64(cexAssetInfo.BasePrice)
	viploanValue := new(big.Int).SetUint64(viploan)
	viploanValue.Mul(viploanValue, assetPrice)
	viploanValue = CalculateAssetValueViaTiersRatio(viploanValue, cexAssetInfo.VipLoanRatios[:])
	
	marginValue := new(big.Int).SetUint64(margin)
	marginValue.Mul(marginValue, assetPrice)
	marginValue = CalculateAssetValueViaTiersRatio(marginValue, cexAssetInfo.MarginRatios[:])
	
	portfolioMarginValue := new(big.Int).SetUint64(portfolioMargin)
	portfolioMarginValue.Mul(portfolioMarginValue, assetPrice)
	portfolioMarginValue = CalculateAssetValueViaTiersRatio(portfolioMarginValue, cexAssetInfo.PortfolioMarginRatios[:])
	// fmt.Println("viploanValue", viploanValue.String())
	// fmt.Println("marginValue", marginValue.String())
	// fmt.Println("portfolioMarginValue", portfolioMarginValue.String())
	return viploanValue.Add(viploanValue, marginValue).Add(viploanValue, portfolioMarginValue)
}

func CalculateAssetValueViaTiersRatio(collateralValue *big.Int, tiersRatio []TierRatio) *big.Int {
	if len(tiersRatio) == 0 {
		return ZeroBigInt
	}
	var res *big.Int

	for i := 0; i < len(tiersRatio); i++ {
		if collateralValue.Cmp(tiersRatio[i].BoundaryValue) <= 0 {
			if i != 0 {
				collateralValue.Sub(collateralValue, tiersRatio[i-1].BoundaryValue)
			}
			res = new(big.Int).Mul(collateralValue, new(big.Int).SetUint64(uint64(tiersRatio[i].Ratio)))
			res.Div(res, PercentageMultiplier)
			if i != 0 {
				res.Add(res, tiersRatio[i-1].PrecomputedValue)
			}
			return res
		}
	}
	res = new(big.Int).Set(tiersRatio[len(tiersRatio)-1].PrecomputedValue)
	return res
}

func ConvertFloatStrToUint64(f string, multiplier int64) (uint64, error) {
	if f == "0.0" {
		return 0, nil
	}
	numFloat, err := decimal.NewFromString(f)
	if err != nil {
		return 0, err
	}
	numFloat = numFloat.Mul(decimal.NewFromInt(multiplier))
	numBigInt := numFloat.BigInt()
	if !numBigInt.IsUint64() {
		return 0, errors.New("overflow uint64")
	}
	num := numBigInt.Uint64()
	return num, nil
}

func DecodeBatchWitness(data string) *BatchCreateUserWitness {
	var witnessForCircuit BatchCreateUserWitness
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Println("deserialize batch witness failed: ", err.Error())
		return nil
	}
	unserializeBuf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(unserializeBuf)
	err = dec.Decode(&witnessForCircuit)
	if err != nil {
		fmt.Println("unmarshal batch witness failed: ", err.Error())
		return nil
	}
	for i := 0; i < len(witnessForCircuit.CreateUserOps); i++ {
		userAssets := make([]AccountAsset, AssetCounts)
		storeUserAssets := witnessForCircuit.CreateUserOps[i].Assets
		for p := 0; p < len(storeUserAssets); p++ {
			userAssets[storeUserAssets[p].Index] = storeUserAssets[p]
		}
		witnessForCircuit.CreateUserOps[i].Assets = userAssets
	}
	return &witnessForCircuit
}

func AccountInfoToHash(account *AccountInfo, hasher *hash.Hash) []byte {
	assetCommitment := ComputeUserAssetsCommitment(hasher, account.Assets)
	(*hasher).Reset()
	// compute new account leaf node hash
	accountHash := poseidon.PoseidonBytes(account.AccountId, account.TotalEquity.Bytes(), account.TotalDebt.Bytes(), assetCommitment)
	return accountHash
}

func RecoverAfterCexAssets(witness *BatchCreateUserWitness) []CexAssetInfo {
	cexAssets := witness.BeforeCexAssets
	for i := 0; i < len(witness.CreateUserOps); i++ {
		for j := 0; j < len(witness.CreateUserOps[i].Assets); j++ {
			asset := &witness.CreateUserOps[i].Assets[j]
			cexAssets[asset.Index].TotalEquity = SafeAdd(cexAssets[asset.Index].TotalEquity, asset.Equity)
			cexAssets[asset.Index].TotalDebt = SafeAdd(cexAssets[asset.Index].TotalDebt, asset.Debt)
		}
	}
	// sanity check
	hasher := poseidon.NewPoseidon()
	for i := 0; i < len(cexAssets); i++ {
		commitments := ConvertAssetInfoToBytes(cexAssets[i])
		for j := 0; j < len(commitments); j++ {
			hasher.Write(commitments[j])
		}
	}
	cexCommitment := hasher.Sum(nil)
	if string(cexCommitment) != string(witness.AfterCEXAssetsCommitment) {
		panic("after cex commitment verify failed")
	}
	return cexAssets
}

func ComputeCexAssetsCommitment(cexAssetsInfo []CexAssetInfo) []byte {
	hasher := poseidon.NewPoseidon()
	emptyCexAssets := make([]CexAssetInfo, AssetCounts-len(cexAssetsInfo))
	cexAssetsInfo = append(cexAssetsInfo, emptyCexAssets...)
	for i := 0; i < len(cexAssetsInfo); i++ {
		commitments := ConvertAssetInfoToBytes(cexAssetsInfo[i])
		for j := 0; j < len(commitments); j++ {
			hasher.Write(commitments[j])
		}
	}
	return hasher.Sum(nil)
}
