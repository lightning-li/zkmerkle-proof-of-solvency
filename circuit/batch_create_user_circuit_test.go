package circuit

import (
	"fmt"
	"testing"

	// "github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)


func TestBatchCreateUserCircuit(t *testing.T) {
	userCircuit := NewBatchCreateUserCircuit(350, 2)
	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, userCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("batch create user constraints number is ", oR1cs.GetNbConstraints())
}