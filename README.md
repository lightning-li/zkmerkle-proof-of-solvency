# zkmerkle-proof-of-solvency
## Circuit Design

See the [technical blog](https://gusty-radon-13b.notion.site/Proof-of-solvency-61414c3f7c1e46c5baec32b9491b2b3d) for more details about background and circuit design
## How to run

### Run third-party services
This project needs following third party services:
- mysql: used to store `witness`, `userproof`, `proof` table;
- redis: provide distributed lock for multi provers;
- kvrocks: used to store account tree

We can use docker to run these services:

```shell
docker run -d --name zkpos-redis -p 6379:6379 redis

docker run -d --name zkpos-mysql -p 3306:3306  -v /server/docker_data/mysql_data:/var/lib/mysql -e MYSQL_USER=zkpos -e MYSQL_PASSWORD=zkpos@123 -e MYSQL_DATABASE=zkpos  -e MYSQL_ROOT_PASSWORD=zkpos@123 mysql

docker run -d --name zkpos-kvrocks -p 6666:6666 -v /server/docker_data/kvrocksdata:/kvrocksdata apache/kvrocks --dir /kvrocksdata
```

where `/server/docker_data/` is directory in the host machine which is used to persist mysql and kvrocks docker data.


### Generate zk keys

The `keygen` service is for generating zk related keys which are used to generate and verify zk proof. The updated PoR solution now supports multi-tier circuits based on the counts of asset types a user owns. The `BatchCreateUserOpsCountsTiers` constant in the utils package represents the multi-tier circuit configuration that defines how many users can be created in one batch for each specific tier.

Run the following commands to start `keygen` service:
```
// make sure the BatchCreateUserOpsCounts in utils/constants.go is expected

cd src/keygen; go run main.go
```

After `keygen` service finishes running, there will be several key files generated in the current directory, like the following:
```shell
-rw-r--r--. 1 root root  524 Aug 19 09:46 zkpor350_128.vk
-rw-r--r--. 1 root root  12G Aug 19 09:46 zkpor350_128.pk
-rw-r--r--. 1 root root 7.5G Aug 19 09:47 zkpor350_128.r1cs
-rw-r--r--. 1 root root  524 Aug 19 10:38 zkpor50_580.vk
-rw-r--r--. 1 root root  12G Aug 19 10:38 zkpor50_580.pk
-rw-r--r--. 1 root root  12G Aug 19 10:39 zkpor50_580.r1cs
```

### Generate witness

The `witness` service is used to generate witness for `prover` service. 

`witness/config/config.json` is the config file `witness` service use. The sample file is as follows:
```json
{
  "MysqlDataSource" : "zkpos:zkpos@123@tcp(127.0.0.1:3306)/zkpos?parseTime=true",
  "UserDataFile": "/server/data/20230118",
  "DbSuffix": "0",
  "TreeDB": {
    "Driver": "redis",
    "Option": {
      "Addr": "127.0.0.1:6666"
    }
  }
}
```

Where

- `MysqlDataSource`: this is the mysql config;
- `UserDataFile`: the directory which contains all users balance sheet files;
- `DbSuffix`: this suffix will be appended to the ending of table name, such as `proof0`, `witness0` table;
- `TreeDB`:
  - `Driver`: `redis` means account tree use kvrocks as its storage engine;
  - `Option`:
    - `Addr`: `kvrocks` service listen address


Run the following command to start `witness` service:
```shell
cd witness; go run main.go
```

The `witness` service supports recovery from unexpected crash. After `witness` service finish running, we can see `witness` from `witness` table.

One witness batch contains 460 users whose assets number is larger than 50, and 92 users whose assets number is less or equal than 50.

### Generate zk proof

The `prover` service is used to generate zk proof and supports running in parallel. It reads witness from `witness` table generated by `witness` service.

`prover/config/config.json` is the config file `prover` service uses. The sample file is as follows:
```json
{
  "MysqlDataSource" : "zkpos:zkpos@123@tcp(127.0.0.1:3306)/zkpos?parseTime=true",
  "DbSuffix": "0",
  "Redis": {
    "Host": "127.0.0.1:6379",
    "Type": "node"
  },
  "ZkKeyName": ["/server/zkmerkle-proof-of-solvency/src/keygen/zkpor50_580", "/server/zkmerkle-proof-of-solvency/src/keygen/zkpor350_128"],
  "AssetsCountTiers": [50, 350]
}
```

Where

- `MysqlDataSource`: this is the mysql config;
- `DbSuffix`: this suffix will be appended to the ending of table name, such as `proof0`, `witness0` table;
- `Redis`:
  - `Host`: `redis` service listen addr;
  - `Type`: only support `node` type
- `ZkKeyName`: the list of key names generated by `keygen` service
- `AssetsCountTiers`: The list of asset count tiers, each corresponding to a key name in `ZkKeyName` 

Run the following command to start `prover` service:
```shell
cd prover; go run main.go
```

To run `prover` service in parallel, just repeat executing above commands.

**Note: After all prover service finishes running, We should use `go run main.go -rerun` command to regenerate proof for unfinished batch**

After the whole `prover` service finished, we can see batch zk proof in `proof` table.

### Generate user proof

The `userproof` service is used to generate and persist user merkle proof. It uses `userproof/config/config.json` as config file, and the sample config is as follows:
```json
{
  "MysqlDataSource" : "zkpos:zkpos@123@tcp(127.0.0.1:3306)/zkpos?parseTime=true",
  "UserDataFile": "/server/data/20230118",
  "DbSuffix": "0",
  "TreeDB": {
    "Driver": "redis",
    "Option": {
      "Addr": "127.0.0.1:6666"
    }
  }
}
```

Where

- `MysqlDataSource`: this is the mysql config;
- `UserDataFile`: the directory which contains all users balance sheet files;
- `DbSuffix`: this suffix will be appended to the ending of table name, such as `proof0`, `witness0` table;
- `TreeDB`:
  - `Driver`: `redis` means account tree use kvrocks as its storage engine;
  - `Option`:
    - `Addr`: `kvrocks` service listen address

Run the following command to run `userproof` service:
```shell
cd userproof; go run main.go
```

After `userproof` service finishes running, we can see every user proof from `userproof` table.

The performance: about 10k users proof generation per second in a 128GB memory and 32 core virtual machine.

### Verifier

The `verifier` service is used to verify batch proof and single user proof.

#### Verify batch proof
The service use `config.json` as its config file, and the sample config is as follows:
```json
{
  "ProofTable": "config/proof.csv",
  "ZkKeyName": ["config/zkpor50_580", "config/zkpor350_128"],
  "AssetsCountTiers": [50, 350],
  "CexAssetsInfo": [{"TotalEquity":219971568487,"TotalDebt":9789219,"BasePrice":24620000000},{"TotalEquity":8664493444,"TotalDebt":122580,"BasePrice":1682628000000},{"TotalEquity":67463930749983,"TotalDebt":16127314913,"BasePrice":100000000},{"TotalEquity":68358645578,"TotalDebt":130187,"BasePrice":121377000000},{"TotalEquity":590353015932,"TotalDebt":0,"BasePrice":598900000},{"TotalEquity":255845425858,"TotalDebt":13839361,"BasePrice":6541000000},{"TotalEquity":0,"TotalDebt":0,"BasePrice":99991478},{"TotalEquity":267958065914051,"TotalDebt":501899265949,"BasePrice":100000000},{"TotalEquity":124934670143615,"TotalDebt":1422964747,"BasePrice":34500000}]
}
```
Where
- `ProofTable`: this is proof csv file which can be exported by `proof` table;
- `ZkKeyName`: the key name generated by `keygen` service;
- `AssetsCountTiers`: The list of asset count tiers, each corresponding to a key name in `ZkKeyName`;
- `CexAssetsInfo`: this is published by CEX, it represents CEX's liability;

You can get `CexAssetsInfo` using `dbtool` command after `witness` service run finished. Run the following command to verify batch proof:
```shell
cd verifier; go run main.go
```

#### Verify user proof
The service use `user_config.json` as its config file, and the sample config is as follows:
```json
{"AccountIndex":9,"AccountIdHash":"000000000000000000000000000000000000000000000000000000000000006d","TotalEquity":107595993240612342000000,"TotalDebt":4812541145779934000000,"TotalCollateral":4861152676874104600000,"Assets":[{"Index":0,"Equity":14571647457,"Debt":184812783,"VipLoan":7285823729,"Margin":3642911864,"PortfolioMargin":1821455932},{"Index":1,"Equity":25424316291,"Debt":3323064077,"VipLoan":12712158145,"Margin":6356079073,"PortfolioMargin":3178039536},{"Index":2,"Equity":57834282404,"Debt":19716095367,"VipLoan":28917141202,"Margin":14458570601,"PortfolioMargin":7229285300},{"Index":3,"Equity":25100,"Debt":669524367015,"VipLoan":12550,"Margin":6275,"PortfolioMargin":3138}],"Root":"1a4940fecdbf2f7d8fe9c4f16083ceb587f69f0b9af0d02d528235757536668f","Proof":["EerEdgizAIY2QB/1c7e3vogBKXoD3Q3WN+wDO/hx/HY=","Kj6yinCJObEjIDqK3KPiXqGUetaaHdYoP6WRVWRyubE=","JxQCfxGWwtk0XQi2UkU4GUjHZKmW5uCQw0Unqf6nJUI=","CfqgZ96f0N0RUyd4IQ1sEdsm2Yq+4WRCq7awff2P1q8=","LvSjy7ocJKqWPpjRr17niwhgtmqNFMNuLS8lVLRWLbo=","EWnMgwIncL2h5IMqlObRbaa0hD2DMWcbNPuSLrb+LwY=","HiOSZAFdHtBMxcPB4yWGPY9dTuHSLMCzAOsoh4qt+VI=","EcAo/cipNXN6IeLHoQ+V9ZDX23KqZhF7lp65zJoo7MU=","EXs4mjwX3UpfJxC8Kbyey3JEyxilg8FXXUGabXvApac=","DBGelh5dqSIf/6qrFwCud4VSt77d0MMdmq41g78dmwc=","I4HkTsZT2BLXNzJCXW15MbQ8MDtzXjbbfJsZ15ZczS0=","FmFiP3/04HxlH5/MJeRG1SbSzu9OQVzJM49uQO10w1o=","C28Jko6/+VPAikr9oK2vf9jbCVhVDjWG6r699bHv+Vk=","Jm8aL9AJ54lAZRMbySEmEH8oAKiEp7jlOI2wOnu4KRo=","GdbpvwyPyQb6/HOZs17w6AMncy/htlh4R/dXIdyJv5w=","IeDs6wpjmp+DbYopQmas2GMl8CZpA+sqr9/+lzRvBZQ=","AD+yl4nRexwrClLzFeHozdiNJCcn/I1+RYKAHwWjS1k=","GdGGEDCn9AHLU8bC6QsDzqCF0F6FrVGq/DbA0jdsdHg=","JOxehD0Ia2qECvgPvgPIKzre8/cQHN9MO2g4fp1yR/k=","G/rWV3lgtPIpEYF5YPJKfzOsHOIGjaMkj+Jl5+W/Vs4=","FkShbCYN5Dmq5ePg/edPHJsgCkDWa5sbttdOntkfrs8=","Fw4CMs3uC4DLmXzr+1Z8YL5nifrZ28ERj7PJmKOAyjc=","G7sBVubhUFfBP7dPh1j5pJHUQKgIt8Urv8uKSlmDIfw=","H68ykCMipvlmIvsqggAZdTN2sVuURSsZjT62jaC7yw4=","L+fBG2iAWzztMIp9v/FVKvmA32J5y/xyK+Gkfk6/7oc=","IHcZ3Kq0U/3YtilfJZnfL3lBZZ7vF6UXDWC+YQjx9bw=","BOc4UULtPNPKmGuvrWUC5oQcEw1UoytqQRbtqRg/+E0=","F/aouPJyLNduMVnva1aMSV04QPRc0MhDhgTP2/L0ZKs="]}
```

Where

- `AccountIndex`: account index used to verify;
- `AccountIdHash`: account hash id which contains user info
- `Root`: account tree root published by cex;
- `Assets`: all user assets info;
- `Proof`: user merkle proof which uses `base64` encoding;
- `TotalEquity`: user total equity which is calculated by all the assets equity multipy its corresponding price
- `TotalDebt`: user total debt which is calculated by all the assets debt multipy its corresponding price
- `VipLoan/Margin/PortfolioMargin`: user collateral value

Run the following command to verify single user proof:
```shell
cd verifier; go run main.go -user
```

### dbtool command

Run the following command to remove only kvrocks data:
```shell
cd src/dbtool; go run main.go -only_delete_kvrocks
```

Run the following command to delete kvrocks data and mysql:
```shell
cd src/dbtool; go run main.go -delete_all
```

Run the following command to get cex assets info in json format:
```shell
cd src/dbtool; go run main.go -query_cex_assets
```

Run the following command to query user config which is used in verifier:
```shell
cd src/dbtool; go run main.go -query_account_data 9
```

Run the following command to query witness data which is the input of circuit:
```shell
cd src/dbtool; go run main.go -query_witness_data 9
```

### Check data correctness

#### check account tree construct correctness
`userproof` service provides a command flag `-memory_tree` which can construct account tree in memory
using user balance sheet.

Run the following command:
```shell
cd userproof; go run main.go -memory_tree
```

Compare the account tree root in the output log with the account tree root by `witness` service, if matches, then the account tree is correctly constructed.

**Note: when `userproof` service runs in the `-memory_tree` mode, its performance is about 75k per minute, so 3000w accounts will take about ~7 hours**
