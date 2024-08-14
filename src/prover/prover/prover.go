package prover

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/circuit"
	"github.com/binance/zkmerkle-proof-of-solvency/src/prover/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/witness"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/zeromicro/go-zero/core/stores/redis"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func WithRedis(redisType string, redisPass string) redis.Option {
	return func(p *redis.Redis) {
		p.Type = redisType
		p.Pass = redisPass
	}
}

type Prover struct {
	witnessModel witness.WitnessModel
	proofModel   ProofModel
	redisConn    *redis.Redis

	VerifyingKeys groth16.VerifyingKey
	ProvingKeys   groth16.ProvingKey
	SessionName   string
	R1cs          constraint.ConstraintSystem
}

func NewProver(config *config.Config) *Prover {
	redisConn := redis.New(config.Redis.Host, WithRedis(config.Redis.Type, config.Redis.Password))
	db, err := gorm.Open(mysql.Open(config.MysqlDataSource))
	if err != nil {
		panic(err.Error())
	}
	prover := Prover{
		witnessModel: witness.NewWitnessModel(db, config.DbSuffix),
		proofModel:   NewProofModel(db, config.DbSuffix),
		redisConn:    redisConn,
		SessionName:  config.ZkKeyName,
	}

	// std.RegisterHints()
	solver.RegisterHint(circuit.IntegerDivision)
	s := time.Now()
	fmt.Println("begin loading r1cs...")
	loadR1csChan := make(chan bool)
	go func() {
		for {

			select {
			case <-loadR1csChan:
				fmt.Println("load r1cs finished...... quit")
				return
			case <-time.After(time.Second * 10):
				runtime.GC()
			}
		}
	}()

	prover.R1cs = groth16.NewCS(ecc.BN254)
	r1csFromFile, err := os.ReadFile(config.ZkKeyName + ".r1cs")
	if err != nil {
		panic("r1cs file load error..." + err.Error())
	}
	buf := bytes.NewBuffer(r1csFromFile)
	n, err := prover.R1cs.ReadFrom(buf)
	if err != nil {
		panic("r1cs read error..." + err.Error())
	}
	fmt.Println("r1cs read size is ", n)
	// circuit := circuit.NewBatchCreateUserCircuit(utils.AssetCounts, utils.BatchCreateUserOpsCounts)
	// prover.R1cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(0))
	loadR1csChan <- true
	runtime.GC()
	et := time.Now()
	fmt.Println("finish loading r1cs.... the time cost is ", et.Sub(s))
	// read proving and verifying keys
	fmt.Println("begin loading proving key...")
	s = time.Now()
	pkFromFile, err := os.ReadFile(config.ZkKeyName + ".pk")
	if err != nil {
		panic("provingKey file load error:" + err.Error())
	}
	buf = bytes.NewBuffer(pkFromFile)
	prover.ProvingKeys = groth16.NewProvingKey(ecc.BN254)
	n, err = prover.ProvingKeys.UnsafeReadFrom(buf)
	if err != nil {
		panic("provingKey loading error:" + err.Error())
	}
	fmt.Println("proving key read size is ", n)
	et = time.Now()
	fmt.Println("finish loading proving key... the time cost is ", et.Sub(s))
	
	fmt.Println("begin loading verifying key...")
	s = time.Now()
	vkFromFile, err := os.ReadFile(config.ZkKeyName + ".vk")
	buf = bytes.NewBuffer(vkFromFile)
	prover.VerifyingKeys = groth16.NewVerifyingKey(ecc.BN254)
	n, err = prover.VerifyingKeys.ReadFrom(buf)
	if err != nil {
		panic("verifyingKey loading error:" + err.Error())
	}
	fmt.Println("verifying key read size is ", n)
	et = time.Now()
	fmt.Println("finish loading verifying key.. the time cost is ", et.Sub(s))
	return &prover
}

func (p *Prover) Run(flag bool) {
	p.proofModel.CreateProofTable()
	batchWitnessFetch := func() (*witness.BatchWitness, error) {
		lock := utils.GetRedisLockByKey(p.redisConn, utils.RedisLockKey)
		err := utils.TryAcquireLock(lock)
		if err != nil {
			return nil, utils.GetRedisLockFailed
		}
		//nolint:errcheck
		defer lock.Release()

		// Fetch unproved block witness.
		blockWitness, err := p.witnessModel.GetLatestBatchWitnessByStatus(witness.StatusPublished)
		if err != nil {
			return nil, err
		}
		// Update status of block witness.
		err = p.witnessModel.UpdateBatchWitnessStatus(blockWitness, witness.StatusReceived)
		if err != nil {
			return nil, err
		}
		return blockWitness, nil
	}

	batchWitnessFetchForRerun := func() (*witness.BatchWitness, error) {
		blockWitness, err := p.witnessModel.GetLatestBatchWitnessByStatus(witness.StatusReceived)
		if err != nil {
			return nil, err
		}
		return blockWitness, nil
	}

	for {
		var batchWitness *witness.BatchWitness
		var err error
		if !flag {
			batchWitness, err = batchWitnessFetch()
			if errors.Is(err, utils.GetRedisLockFailed) {
				fmt.Println("get redis lock failed")
				continue
			}
			if errors.Is(err, utils.DbErrNotFound) {
				fmt.Println("there is no published status witness in db, so quit")
				fmt.Println("prover run finish...")
				return
			}
			if err != nil {
				fmt.Println("get batch witness failed: ", err.Error())
				return
			}
		} else {
			batchWitness, err = batchWitnessFetchForRerun()
			if errors.Is(err, utils.DbErrNotFound) {
				fmt.Println("there is no received status witness in db, so quit")
				fmt.Println("prover rerun finish...")
				return
			}
			if err != nil {
				fmt.Println("something wrong happened, err is ", err.Error())
				return
			}
		}

		witnessForCircuit := utils.DecodeBatchWitness(batchWitness.WitnessData)
		cexAssetListCommitments := make([][]byte, 2)
		cexAssetListCommitments[0] = witnessForCircuit.BeforeCEXAssetsCommitment
		cexAssetListCommitments[1] = witnessForCircuit.AfterCEXAssetsCommitment
		accountTreeRoots := make([][]byte, 2)
		accountTreeRoots[0] = witnessForCircuit.BeforeAccountTreeRoot
		accountTreeRoots[1] = witnessForCircuit.AfterAccountTreeRoot
		cexAssetListCommitmentsSerial, err := json.Marshal(cexAssetListCommitments)
		if err != nil {
			fmt.Println("marshal cex asset list failed: ", err.Error())
			return
		}
		accountTreeRootsSerial, err := json.Marshal(accountTreeRoots)
		if err != nil {
			fmt.Println("marshal account tree root failed: ", err.Error())
			return
		}
		proof, err := GenerateAndVerifyProof(p.R1cs, p.ProvingKeys, p.VerifyingKeys, witnessForCircuit, p.SessionName, batchWitness.Height)
		if err != nil {
			fmt.Println("generate and verify proof error:", err.Error())
		}
		var buf bytes.Buffer
		_, err = proof.WriteRawTo(&buf)
		if err != nil {
			fmt.Println("proof serialize failed")
			return
		}
		proofBytes := buf.Bytes()
		//formateProof, _ := FormatProof(proof, witnessForCircuit.BatchCommitment)
		//proofBytes, err := json.Marshal(formateProof)
		//if err != nil {
		//	fmt.Println("marshal batch proof failed: ", err.Error())
		//	return
		//}

		// Check the existence of block proof.
		_, err = p.proofModel.GetProofByBatchNumber(batchWitness.Height)
		if err == nil {
			fmt.Printf("blockProof of height %d exists\n", batchWitness.Height)
			err = p.witnessModel.UpdateBatchWitnessStatus(batchWitness, witness.StatusFinished)
			if err != nil {
				fmt.Println("update witness error:", err.Error())
			}
			continue
		}

		var row = &Proof{
			ProofInfo:               base64.StdEncoding.EncodeToString(proofBytes),
			BatchNumber:             batchWitness.Height,
			CexAssetListCommitments: string(cexAssetListCommitmentsSerial),
			AccountTreeRoots:        string(accountTreeRootsSerial),
			BatchCommitment:         base64.StdEncoding.EncodeToString(witnessForCircuit.BatchCommitment),
		}
		err = p.proofModel.CreateProof(row)
		if err != nil {
			fmt.Printf("create blockProof of height %d failed\n", batchWitness.Height)
			return
		}
		err = p.witnessModel.UpdateBatchWitnessStatus(batchWitness, witness.StatusFinished)
		if err != nil {
			fmt.Println("update witness error:", err.Error())
		}
	}
}

// func LoadR1CSLen(filename string) (nbConstraints int, err error) {
// 	f, err := os.Open(filename)
// 	if err != nil {
// 		return -1, fmt.Errorf("read file error")
// 	}
// 	defer f.Close()

// 	var value int
// 	_, err = fmt.Fscanf(f, "%d", &value)
// 	if err != nil {
// 		return -1, err
// 	}

// 	return value, nil
// }

// func LoadProvingKey(filepath string) (pks []groth16.ProvingKey, err error) {
// 	logx.Info("start reading proving key")
// 	return groth16.ReadSegmentProveKey(ecc.BN254, filepath)
// }

// func LoadVerifyingKey(filepath string) (verifyingKey groth16.VerifyingKey, err error) {
// 	verifyingKey = groth16.NewVerifyingKey(ecc.BN254)
// 	f, _ := os.Open(filepath + ".vk.save")
// 	_, err = verifyingKey.ReadFrom(f)
// 	if err != nil {
// 		return verifyingKey, fmt.Errorf("read file error")
// 	}
// 	f.Close()
// 	return verifyingKey, nil
// }

func GenerateAndVerifyProof(r1cs constraint.ConstraintSystem,
	provingKey   groth16.ProvingKey,
	verifyingKey groth16.VerifyingKey,
	batchWitness *utils.BatchCreateUserWitness,
	zkKeyName string,
	batchNumber int64,
) (proof groth16.Proof, err error) {
	startTime := time.Now().UnixMilli()
	fmt.Println("begin to generate proof for batch: ", batchNumber)
	circuitWitness, _ := circuit.SetBatchCreateUserCircuitWitness(batchWitness)
	verifyWitness := circuit.NewVerifyBatchCreateUserCircuit(batchWitness.BatchCommitment)
	witness, err := frontend.NewWitness(circuitWitness, ecc.BN254.ScalarField())
	if err != nil {
		return proof, err
	}

	vWitness, err := frontend.NewWitness(verifyWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return proof, err
	}
	proof, err = groth16.Prove(r1cs, provingKey, witness)
	if err != nil {
		return proof, err
	}
	endTime := time.Now().UnixMilli()
	fmt.Println("proof generation cost ", endTime-startTime, " ms")

	err = groth16.Verify(proof, verifyingKey, vWitness)
	if err != nil {
		return proof, err
	}
	endTime2 := time.Now().UnixMilli()
	fmt.Println("proof verification cost ", endTime2-endTime, " ms")
	return proof, nil
}
