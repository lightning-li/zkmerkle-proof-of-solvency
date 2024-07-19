package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

const (
	BatchCreateUserOpsCounts = 864
	AccountTreeDepth         = 28
	AssetCounts              = 350
	// TierCount: must be even number, the cex assets commitment will depend on the TierCount/2 parts
	TierCount				 = 10
	RedisLockKey             = "prover_mutex_key"
	R1csBatchSize            = 1000000
)

var (
	ZeroBigInt                    = new(big.Int).SetInt64(0)
	OneBigInt                     = new(big.Int).SetInt64(1)
	PercentageMultiplier          = new(big.Int).SetUint64(100)
	MaxTierBoundaryValue, _       = new(big.Int).SetString("340282366920938463463374607431768211455", 10) // (pow(2,128)-1)
	Uint64MaxValueBigInt, _       = new(big.Int).SetString("18446744073709551616", 10)
	Uint64MaxValueBigIntSquare, _ = new(big.Int).SetString("340282366920938463463374607431768211456", 10)
	Uint8MaxValueBigInt, _        = new(big.Int).SetString("256", 10)
	Uint126MaxValueBigInt, _      = new(big.Int).SetString("85070591730234615865843651857942052864", 10)
	Uint134MaxValueBigInt, _      = new(big.Int).SetString("21778071482940061661655974875633165533184", 10)
	Uint64MaxValueFr              = new(fr.Element).SetBigInt(Uint64MaxValueBigInt)
	Uint64MaxValueFrSquare        = new(fr.Element).SetBigInt(Uint64MaxValueBigIntSquare)
	Uint8MaxValueFr               = new(fr.Element).SetBigInt(Uint8MaxValueBigInt)
	Uint126MaxValueFr             = new(fr.Element).SetBigInt(Uint126MaxValueBigInt)
	Uint134MaxValueFr             = new(fr.Element).SetBigInt(Uint134MaxValueBigInt)
	MaxTierBoundaryValueFr		  = new(fr.Element).SetBigInt(MaxTierBoundaryValue)
	PercentageMultiplierFr     	  = new(fr.Element).SetBigInt(PercentageMultiplier)

	AssetTypeForTwoDigits         = map[string]bool{
		"BTTC":  true,
		"SHIB":  true,
		"LUNC":  true,
		"XEC":   true,
		"WIN":   true,
		"BIDR":  true,
		"SPELL": true,
		"HOT":   true,
		"DOGE":  true,
        "PEPE":  true,
	}
)
