package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type MockCollateralCircuit struct {
	Collateral             Variable  `gnark:",public"`
	CollateralTierRatio    []TierRatio

	ExpectedCollateral      Variable `gnark:",public"`
}

func (circuit MockCollateralCircuit) Define(api API) error {
	// GenerateRapidArithmeticForCollateral(api, circuit.CollateralTierRatio)
	actualCollateral := ComputeCollateral(api, circuit.Collateral, circuit.CollateralTierRatio)
	api.AssertIsEqual(circuit.ExpectedCollateral, actualCollateral)
	// a := api.ToBinary(circuit.Collateral)
	// api.AssertIsBoolean(a[0])
	// api.Cmp(circuit.Collateral, circuit.ExpectedCollateral)
	return nil
}

func TestMockCollateralCircuit(t *testing.T) {
	var circuit MockCollateralCircuit
	circuit.Collateral = 110
	circuit.CollateralTierRatio = []TierRatio{
		{BoundaryValue: 100, Ratio: 100},
		{BoundaryValue: 200, Ratio: 90},
		{BoundaryValue: 300, Ratio: 80},
		{BoundaryValue: 400, Ratio: 70},
		{BoundaryValue: 500, Ratio: 60},
		{BoundaryValue: 600, Ratio: 50},
		{BoundaryValue: 700, Ratio: 40},
		{BoundaryValue: 800, Ratio: 30},
		{BoundaryValue: 900, Ratio: 20},
		{BoundaryValue: 1000, Ratio: 10},
	}
	circuit.ExpectedCollateral = 108

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints number is ", oR1cs.GetNbConstraints())
	// oR1cs.IsSolved()
}