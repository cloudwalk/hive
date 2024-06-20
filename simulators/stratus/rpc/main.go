package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/hive/hivesim"
	"time"

	"math/big"
	"strings"
)

var (
	// parameters used for signing transactions
	chainID  = big.NewInt(7)
	gasPrice = big.NewInt(30 * params.GWei)

	// would be nice to use a networkID that's different from chainID,
	// but some clients don't support the distinction properly.
	networkID = big.NewInt(7)
)

var clientEnv = hivesim.Params{
	"HIVE_NODETYPE":       "full",
	"HIVE_NETWORK_ID":     networkID.String(),
	"HIVE_CHAIN_ID":       chainID.String(),
	"HIVE_FORK_HOMESTEAD": "0",
	"HIVE_FORK_TANGERINE": "0",
	"HIVE_FORK_SPURIOUS":  "0",

	// All tests use clique PoA to mine new blocks.
	"HIVE_CLIQUE_PERIOD":                    "1",
	"HIVE_CLIQUE_PRIVATEKEY":                "9c647b8b7c4e7c3490668fb6c11473619db80c93704c70893d3813af4090c39c",
	"HIVE_MINER":                            "658bdf435d810c91414ec09147daa6db62406379",
	"HIVE_TERMINAL_TOTAL_DIFFICULTY_PASSED": "0",
}

var files = map[string]string{
	"/genesis.json": "./init/genesis.json",
}

type testSpec struct {
	Name  string
	About string
	Run   func(*TestEnv)
}

var tests = []testSpec{
	// HTTP RPC tests.
	{Name: "http/BalanceAndNonceAt", Run: balanceAndNonceAtTest},
	{Name: "http/CanonicalChain", Run: canonicalChainTest},
	{Name: "http/CodeAt", Run: CodeAtTest},
	{Name: "http/ContractDeployment", Run: deployContractTest},
	//{Name: "http/ContractDeploymentOutOfGas", Run: deployContractOutOfGasTest},
	{Name: "http/EstimateGas", Run: estimateGasTest},
	//{Name: "http/GenesisBlockByHash", Run: genesisBlockByHashTest},
	//{Name: "http/GenesisBlockByNumber", Run: genesisBlockByNumberTest},
	//{Name: "http/GenesisHeaderByHash", Run: genesisHeaderByHashTest},
	//{Name: "http/GenesisHeaderByNumber", Run: genesisHeaderByNumberTest},
	{Name: "http/Receipt", Run: receiptTest},
	{Name: "http/SyncProgress", Run: syncProgressTest},
	{Name: "http/TransactionCount", Run: transactionCountTest}, //method eth_getBlockTransactionCountByHash not found - it is needed!!!
	{Name: "http/TransactionInBlock", Run: transactionInBlockTest},
	{Name: "http/TransactionReceipt", Run: TransactionReceiptTest},

	// HTTP ABI tests.
	{Name: "http/ABICall", Run: callContractTest},
	{Name: "http/ABITransact", Run: transactContractTest},

	{Name: "ws/BalanceAndNonceAt", Run: balanceAndNonceAtTest},
	{Name: "ws/CanonicalChain", Run: canonicalChainTest},
	{Name: "ws/CodeAt", Run: CodeAtTest},
	{Name: "ws/ContractDeployment", Run: deployContractTest},
	//{Name: "ws/ContractDeploymentOutOfGas", Run: deployContractOutOfGasTest},
	{Name: "ws/EstimateGas", Run: estimateGasTest},
	//{Name: "ws/GenesisBlockByHash", Run: genesisBlockByHashTest},
	//{Name: "ws/GenesisBlockByNumber", Run: genesisBlockByNumberTest},
	//{Name: "ws/GenesisHeaderByHash", Run: genesisHeaderByHashTest},
	//{Name: "ws/GenesisHeaderByNumber", Run: genesisHeaderByNumberTest},
	{Name: "ws/Receipt", Run: receiptTest},
	//{Name: "ws/SyncProgress", Run: syncProgressTest},
	{Name: "ws/TransactionCount", Run: transactionCountTest},
	{Name: "ws/TransactionInBlock", Run: transactionInBlockTest},
	{Name: "ws/TransactionReceipt", Run: TransactionReceiptTest},

	// WebSocket subscription tests.
	{Name: "ws/NewHeadSubscription", Run: newHeadSubscriptionTest},
	{Name: "ws/LogSubscription", Run: logSubscriptionTest},
	//{Name: "ws/TransactionInBlockSubscription", Run: transactionInBlockSubscriptionTest},

	// WebSocket ABI tests.
	{Name: "ws/ABICall", Run: callContractTest},
	{Name: "ws/ABITransact", Run: transactContractTest},
}

func main() {
	//client, _ := ethclient.DialContext(context.Background(), "https://eth-sepolia.g.alchemy.com/v2/JSpouDMyD5PzFXEU63caxbH9hx90FO-l")
	////addr := types.By([]byte{0x1})
	////client.SendTransaction()
	//sender := common.BytesToAddress([]byte{0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266})
	//to := common.BytesToAddress([]byte{0x0000000000000000000000000000000000000000})
	//rawTx := types.NewTransaction(0, to, new(big.Int), 0, big.NewInt(32*params.GWei), msg.Data)
	//types.SignTx(rawTx, sender, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	//
	//tx, err := t.Vault.signTransaction(sender, rawTx)
	//if err != nil {
	//	t.Fatalf("Could not sign transaction: %v", err)
	//}

	suite := hivesim.Suite{
		Name: "rpc",
		Description: `
The RPC test suite runs a set of RPC related tests against a running node. It tests
several real-world scenarios such as sending value transactions, deploying a contract or
interacting with one.`[1:],
	}

	// Add tests for full nodes.
	suite.Add(&hivesim.ClientTestSpec{
		Role:        "eth1",
		Name:        "client launch",
		Description: `This test launches the client and collects its logs.`,
		Parameters:  clientEnv,
		Files:       files,
		Run:         func(t *hivesim.T, c *hivesim.Client) { runAllTests(t, c, c.Type) },
		AlwaysRun:   true,
	})

	// Add tests to launch LES servers.
	serverParams := clientEnv.Set("HIVE_LES_SERVER", "1")
	suite.Add(hivesim.ClientTestSpec{
		Role:        "eth1_les_server",
		Name:        "CLIENT as LES server",
		Description: "This test launches an LES server.",
		Parameters:  serverParams,
		Files:       files,
		Run:         func(t *hivesim.T, srv *hivesim.Client) { runLESTests(t, srv) },
		AlwaysRun:   true,
	})

	sim := hivesim.New()
	hivesim.MustRunSuite(sim, suite)
}

func runLESTests(t *hivesim.T, serverNode *hivesim.Client) {
	// Configure LES client.
	clientParams := clientEnv.Set("HIVE_NODETYPE", "light")
	// Disable mining.
	clientParams = clientParams.Set("HIVE_MINER", "")
	clientParams = clientParams.Set("HIVE_CLIQUE_PRIVATEKEY", "")

	enode, err := serverNode.EnodeURL()
	if err != nil {
		t.Fatal("can't get node peer-to-peer endpoint:", enode)
	}

	// Sync all sink nodes against the source.
	t.RunAllClients(hivesim.ClientTestSpec{
		Role:        "eth1_les_client",
		Name:        "CLIENT as LES client",
		Description: "This runs the RPC tests against an LES client.",
		Parameters:  clientParams,
		Files:       files,
		AlwaysRun:   true,
		Run: func(t *hivesim.T, client *hivesim.Client) {
			err := client.RPC().Call(nil, "admin_addPeer", enode)
			if err != nil {
				t.Fatalf("connection failed:", err)
			}
			waitSynced(client.RPC())
			runAllTests(t, client, client.Type+" LES")
		},
	})
}

// runAllTests runs the tests against a client instance.
// Most tests simply wait for tx inclusion in a block so we can run many tests concurrently.
func runAllTests(t *hivesim.T, c *hivesim.Client, clientName string) {
	vault := newVault()

	time.Sleep(5 * time.Second)

	newTestName := "http/createContracts2"
	newTestAbout := "Create contracts base"

	func() {
		t.Run(hivesim.TestSpec{
			Name:        fmt.Sprintf("%s (%s)", newTestName, clientName),
			Description: newTestAbout,
			Run: func(t *hivesim.T) {
				createContractsExec(t, c, vault)
			},
		})
	}()

	//s := newSemaphore(16)
	for _, test := range tests {
		test := test
		//s.get()
		func() {
			time.Sleep(1 * time.Second)
			//defer s.put()
			t.Run(hivesim.TestSpec{
				Name:        fmt.Sprintf("%s (%s)", test.Name, clientName),
				Description: test.About,
				Run: func(t *hivesim.T) {
					switch test.Name[:strings.IndexByte(test.Name, '/')] {
					case "http":
						runHTTP(t, c, vault, test.Run)
					case "ws":
						runWS(t, c, vault, test.Run)
					default:
						panic("bad test prefix in name " + test.Name)
					}
				},
			})
		}()
	}
	//s.drain()
}

func createContractsExec(t *hivesim.T, c *hivesim.Client, v *vault) {
	t.Log("createContractsExec BEGIN (sleep 60)")
	time.Sleep(5 * time.Second)
	res, err := c.Exec("createcontracts.sh", "127.0.0.1")
	if err != nil {
		t.Fatal("createcontracts.sh")
		t.Fatal(err)
	}

	t.Log(res.Stdout)
	t.Log(res.Stderr)
	t.Log(res.ExitCode)
	t.Log("createContractsExec END")
}

type semaphore chan struct{}

func newSemaphore(n int) semaphore {
	s := make(semaphore, n)
	for i := 0; i < n; i++ {
		s <- struct{}{}
	}
	return s
}

func (s semaphore) get() { <-s }
func (s semaphore) put() { s <- struct{}{} }

func (s semaphore) drain() {
	for i := 0; i < cap(s); i++ {
		<-s
	}
}
