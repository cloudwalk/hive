package main

import (
	"bytes"
	"math/big"
	"math/rand"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var (
	contractCode = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.16;

contract Test {
    event E0();
    event E1(uint);
    event E2(uint indexed);
    event E3(address);
    event E4(address indexed);
    event E5(uint, address) anonymous;

    uint public ui;
    mapping(address => uint) map;

    constructor(uint ui_) {
        ui = ui_;
        map[msg.sender] = ui_;
    }

    function events(uint ui_, address addr_) public {
        emit E0();
        emit E1(ui_);
        emit E2(ui_);
        emit E3(addr_);
        emit E4(addr_);
        emit E5(ui_, addr_);
    }

    function constFunc(uint a, uint b, uint c) public returns(uint, uint, uint)  {
        return (a, b, c);
    }

    function getFromMap(address addr) public returns(uint) {
        return map[addr];
    }

    function addToMap(address addr, uint value) public {
        map[addr] = value;
    }
}`
	// test contract deploy code, will deploy the contract with 1234 as argument
	deployCode = common.Hex2Bytes("6060604052346100005760405160208061048c833981016040528080519060200190919050505b8060008190555080600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b505b610409806100836000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063abd1a0cf1461008d578063abfced1d146100d4578063e05c914a14610110578063e6768b451461014c575b610000565b346100005761007761019d565b6040518082815260200191505060405180910390f35b34610000576100be600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506101a3565b6040518082815260200191505060405180910390f35b346100005761010e600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919080359060200190919050506101ed565b005b346100005761014a600480803590602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610236565b005b346100005761017960048080359060200190919080359060200190919080359060200190919050506103c4565b60405180848152602001838152602001828152602001935050505060405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490505b919050565b80600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b5050565b7f6031a8d62d7c95988fa262657cd92107d90ed96e08d8f867d32f26edfe85502260405180905060405180910390a17f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda66450826040518082815260200191505060405180910390a1817fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e2960405180905060405180910390a27f7890603b316f3509577afd111710f9ebeefa15e12f72347d9dffd0d65ae3bade81604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a18073ffffffffffffffffffffffffffffffffffffffff167f7efef9ea3f60ddc038e50cccec621f86a0195894dc0520482abf8b5c6b659e4160405180905060405180910390a28181604051808381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a05b5050565b6000600060008585859250925092505b935093509390505600a165627a7a72305820aaf842d0d0c35c45622c5263cbb54813d2974d3999c8c38551d7c613ea2bc117002900000000000000000000000000000000000000000000000000000000000004d2")
	// test contract code as deployed
	runtimeCode = common.Hex2Bytes("60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063abd1a0cf1461008d578063abfced1d146100d4578063e05c914a14610110578063e6768b451461014c575b610000565b346100005761007761019d565b6040518082815260200191505060405180910390f35b34610000576100be600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506101a3565b6040518082815260200191505060405180910390f35b346100005761010e600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919080359060200190919050506101ed565b005b346100005761014a600480803590602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610236565b005b346100005761017960048080359060200190919080359060200190919080359060200190919050506103c4565b60405180848152602001838152602001828152602001935050505060405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490505b919050565b80600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b5050565b7f6031a8d62d7c95988fa262657cd92107d90ed96e08d8f867d32f26edfe85502260405180905060405180910390a17f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda66450826040518082815260200191505060405180910390a1817fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e2960405180905060405180910390a27f7890603b316f3509577afd111710f9ebeefa15e12f72347d9dffd0d65ae3bade81604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a18073ffffffffffffffffffffffffffffffffffffffff167f7efef9ea3f60ddc038e50cccec621f86a0195894dc0520482abf8b5c6b659e4160405180905060405180910390a28181604051808381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a05b5050565b6000600060008585859250925092505b935093509390505600a165627a7a72305820aaf842d0d0c35c45622c5263cbb54813d2974d3999c8c38551d7c613ea2bc1170029")

	preDeployedCode        = common.Hex2Bytes("0x608060405234801561001057600080fd5b506040516106b43803806106b4833981810160405281019061003291906100be565b8060008190555080600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550506100eb565b600080fd5b6000819050919050565b61009b81610088565b81146100a657600080fd5b50565b6000815190506100b881610092565b92915050565b6000602082840312156100d4576100d3610083565b5b60006100e2848285016100a9565b91505092915050565b6105ba806100fa6000396000f3fe60806040526004361061005e5760003560e01c8063abfced1d11610043578063abfced1d146100d2578063e05c914a146100fb578063e6768b451461012457610065565b8063a223e05d1461006a578063abd1a0cf1461009557610065565b3661006557005b600080fd5b34801561007657600080fd5b5061007f610163565b60405161008c9190610350565b60405180910390f35b3480156100a157600080fd5b506100bc60048036038101906100b791906103ce565b610169565b6040516100c99190610350565b60405180910390f35b3480156100de57600080fd5b506100f960048036038101906100f49190610427565b6101b2565b005b34801561010757600080fd5b50610122600480360381019061011d9190610467565b6101fa565b005b34801561013057600080fd5b5061014b600480360381019061014691906104a7565b610320565b60405161015a939291906104fa565b60405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b80600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050565b7f6031a8d62d7c95988fa262657cd92107d90ed96e08d8f867d32f26edfe85502260405160405180910390a17f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda66450826040516102559190610350565b60405180910390a1817fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e2960405160405180910390a27f7890603b316f3509577afd111710f9ebeefa15e12f72347d9dffd0d65ae3bade816040516102b99190610540565b60405180910390a18073ffffffffffffffffffffffffffffffffffffffff167f7efef9ea3f60ddc038e50cccec621f86a0195894dc0520482abf8b5c6b659e4160405160405180910390a2818160405161031492919061055b565b60405180910390a05050565b600080600085858592509250925093509350939050565b6000819050919050565b61034a81610337565b82525050565b60006020820190506103656000830184610341565b92915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061039b82610370565b9050919050565b6103ab81610390565b81146103b657600080fd5b50565b6000813590506103c8816103a2565b92915050565b6000602082840312156103e4576103e361036b565b5b60006103f2848285016103b9565b91505092915050565b61040481610337565b811461040f57600080fd5b50565b600081359050610421816103fb565b92915050565b6000806040838503121561043e5761043d61036b565b5b600061044c858286016103b9565b925050602061045d85828601610412565b9150509250929050565b6000806040838503121561047e5761047d61036b565b5b600061048c85828601610412565b925050602061049d858286016103b9565b9150509250929050565b6000806000606084860312156104c0576104bf61036b565b5b60006104ce86828701610412565b93505060206104df86828701610412565b92505060406104f086828701610412565b9150509250925092565b600060608201905061050f6000830186610341565b61051c6020830185610341565b6105296040830184610341565b949350505050565b61053a81610390565b82525050565b60006020820190506105556000830184610531565b92915050565b60006040820190506105706000830185610341565b61057d6020830184610531565b939250505056fea2646970667358221220de5c90f8aa63d90e946f8702fd31aa225f69db1e4987cc52db2b0c7f26edb61e64736f6c6343000810003300000000000000000000000000000000000000000000000000000000000004d2")
	preDeployedRuntimeCode = common.Hex2Bytes("60806040526004361061005e5760003560e01c8063abfced1d11610043578063abfced1d146100d2578063e05c914a146100fb578063e6768b451461012457610065565b8063a223e05d1461006a578063abd1a0cf1461009557610065565b3661006557005b600080fd5b34801561007657600080fd5b5061007f610163565b60405161008c9190610350565b60405180910390f35b3480156100a157600080fd5b506100bc60048036038101906100b791906103ce565b610169565b6040516100c99190610350565b60405180910390f35b3480156100de57600080fd5b506100f960048036038101906100f49190610427565b6101b2565b005b34801561010757600080fd5b50610122600480360381019061011d9190610467565b6101fa565b005b34801561013057600080fd5b5061014b600480360381019061014691906104a7565b610320565b60405161015a939291906104fa565b60405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b80600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050565b7f6031a8d62d7c95988fa262657cd92107d90ed96e08d8f867d32f26edfe85502260405160405180910390a17f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda66450826040516102559190610350565b60405180910390a1817fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e2960405160405180910390a27f7890603b316f3509577afd111710f9ebeefa15e12f72347d9dffd0d65ae3bade816040516102b99190610540565b60405180910390a18073ffffffffffffffffffffffffffffffffffffffff167f7efef9ea3f60ddc038e50cccec621f86a0195894dc0520482abf8b5c6b659e4160405160405180910390a2818160405161031492919061055b565b60405180910390a05050565b600080600085858592509250925093509350939050565b6000819050919050565b61034a81610337565b82525050565b60006020820190506103656000830184610341565b92915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061039b82610370565b9050919050565b6103ab81610390565b81146103b657600080fd5b50565b6000813590506103c8816103a2565b92915050565b6000602082840312156103e4576103e361036b565b5b60006103f2848285016103b9565b91505092915050565b61040481610337565b811461040f57600080fd5b50565b600081359050610421816103fb565b92915050565b6000806040838503121561043e5761043d61036b565b5b600061044c858286016103b9565b925050602061045d85828601610412565b9150509250929050565b6000806040838503121561047e5761047d61036b565b5b600061048c85828601610412565b925050602061049d858286016103b9565b9150509250929050565b6000806000606084860312156104c0576104bf61036b565b5b60006104ce86828701610412565b93505060206104df86828701610412565b92505060406104f086828701610412565b9150509250925092565b600060608201905061050f6000830186610341565b61051c6020830185610341565b6105296040830184610341565b949350505050565b61053a81610390565b82525050565b60006020820190506105556000830184610531565b92915050565b60006040820190506105706000830185610341565b61057d6020830184610531565b939250505056fea2646970667358221220de5c90f8aa63d90e946f8702fd31aa225f69db1e4987cc52db2b0c7f26edb61e64736f6c63430008100033000000000000000000000000000000000000000000000000000000000000000000")

	// contractSrc is predeploy on the following address in the genesis block.
	predeployedContractAddr = common.HexToAddress("e7f1725E7734CE288F8367e1Bb143E90bb3F0512")
	// contractSrc is pre-deployed with the following address in the genesis block.
	predeployedContractWithAddress = common.HexToAddress("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	// holds the pre-deployed contract ABI
	predeployedContractABI = `[
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "ui_",
          "type": "uint256"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": false,
      "inputs": [],
      "name": "E0",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "E1",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "E2",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "E3",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "E4",
      "type": "event"
    },
    {
      "anonymous": true,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "E5",
      "type": "event"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "addr",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "value",
          "type": "uint256"
        }
      ],
      "name": "addToMap",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "a",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "b",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "c",
          "type": "uint256"
        }
      ],
      "name": "constFunc",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "ui_",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "addr_",
          "type": "address"
        }
      ],
      "name": "events",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "addr",
          "type": "address"
        }
      ],
      "name": "getFromMap",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "ui",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "stateMutability": "payable",
      "type": "receive"
    }
  ]`
)

var (
	big0 = new(big.Int)
	big1 = big.NewInt(1)
)

// CodeAtTest tests the code for the pre-deployed contract.
func CodeAtTest(t *TestEnv) {
	code, err := t.Eth.CodeAt(t.Ctx(), predeployedContractAddr, nil)
	if err != nil {
		t.Fatalf("Could not fetch code for predeployed contract: %v", err)
	}
	if bytes.Compare(preDeployedRuntimeCode, code) != 0 {
		t.Fatalf("Unexpected code, want %x, got %x", runtimeCode, code)
	}
}

// estimateGasTest fetches the estimated gas usage for a call to the events method.
func estimateGasTest(t *TestEnv) {
	var (
		address        = t.Vault.createAccount(t, big.NewInt(params.Ether))
		contractABI, _ = abi.JSON(strings.NewReader(predeployedContractABI))
		intArg         = big.NewInt(rand.Int63())
	)

	payload, err := contractABI.Pack("events", intArg, address)
	if err != nil {
		t.Fatalf("Unable to prepare tx payload: %v", err)
	}
	msg := ethereum.CallMsg{
		From: address,
		To:   &predeployedContractAddr,
		Data: payload,
	}
	estimated, err := t.Eth.EstimateGas(t.Ctx(), msg)
	if err != nil {
		t.Fatalf("Could not estimate gas: %v", err)
	}

	// send the actual tx and test gas usage
	txGas := estimated + 100000
	rawTx := types.NewTransaction(0, *msg.To, msg.Value, txGas, big.NewInt(32*params.GWei), msg.Data)
	tx, err := t.Vault.signTransaction(address, rawTx)
	if err != nil {
		t.Fatalf("Could not sign transaction: %v", err)
	}

	if err := t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
		t.Fatalf("Could not send tx: %v", err)
	}

	receipt, err := waitForTxConfirmations(t, tx.Hash(), 1)
	if err != nil {
		t.Fatalf("Could not wait for confirmations: %v", err)
	}

	// test lower bound
	if estimated < receipt.GasUsed {
		t.Fatalf("Estimated gas too low, want %d >= %d", estimated, receipt.GasUsed)
	}
	// test upper bound
	if receipt.GasUsed+5000 < estimated {
		t.Fatalf("Estimated gas too high, estimated: %d, used: %d", estimated, receipt.GasUsed)
	}
}

// balanceAndNonceAtTest creates a new account and transfers funds to it.
// It then tests if the balance and nonce of the sender and receiver
// address are updated correct.
func balanceAndNonceAtTest(t *TestEnv) {
	var (
		sourceAddr  = t.Vault.createAccount(t, big.NewInt(params.Ether))
		sourceNonce = uint64(0)
		targetAddr  = t.Vault.createAccount(t, nil)
	)

	// Get current balance
	sourceAddressBalanceBefore, err := t.Eth.BalanceAt(t.Ctx(), sourceAddr, nil)
	if err != nil {
		t.Fatalf("Unable to retrieve balance: %v", err)
	}

	expected := big.NewInt(params.Ether)
	if sourceAddressBalanceBefore.Cmp(expected) != 0 {
		t.Errorf("Expected balance %d, got %d", expected, sourceAddressBalanceBefore)
	}

	nonceBefore, err := t.Eth.NonceAt(t.Ctx(), sourceAddr, nil)
	if err != nil {
		t.Fatalf("Unable to determine nonce: %v", err)
	}
	if nonceBefore != sourceNonce {
		t.Fatalf("Invalid nonce, want %d, got %d", sourceNonce, nonceBefore)
	}

	// send 1234 wei to target account and verify balances and nonces are updated
	var (
		amount   = big.NewInt(1234)
		gasLimit = uint64(50000)
	)
	rawTx := types.NewTransaction(sourceNonce, targetAddr, amount, gasLimit, gasPrice, nil)
	valueTx, err := t.Vault.signTransaction(sourceAddr, rawTx)
	if err != nil {
		t.Fatalf("Unable to sign value tx: %v", err)
	}
	sourceNonce++

	t.Logf("BalanceAt: send %d wei from 0x%x to 0x%x in 0x%x", valueTx.Value(), sourceAddr, targetAddr, valueTx.Hash())
	if err := t.Eth.SendTransaction(t.Ctx(), valueTx); err != nil {
		t.Fatalf("Unable to send transaction: %v", err)
	}

	var receipt *types.Receipt
	for {
		receipt, err = t.Eth.TransactionReceipt(t.Ctx(), valueTx.Hash())
		if receipt != nil {
			break
		}
		if err != ethereum.NotFound {
			t.Fatalf("Could not fetch receipt for 0x%x: %v", valueTx.Hash(), err)
		}
		time.Sleep(time.Second)
	}

	// ensure balances have been updated
	accountBalanceAfter, err := t.Eth.BalanceAt(t.Ctx(), sourceAddr, nil)
	if err != nil {
		t.Fatalf("Unable to retrieve balance: %v", err)
	}
	balanceTargetAccountAfter, err := t.Eth.BalanceAt(t.Ctx(), targetAddr, nil)
	if err != nil {
		t.Fatalf("Unable to retrieve balance: %v", err)
	}

	// expected balance is previous balance - tx amount - tx fee (gasUsed * gasPrice)
	exp := new(big.Int).Set(sourceAddressBalanceBefore)
	exp.Sub(exp, amount)
	//sub gas fee - not necessary for Stratus
	//exp.Sub(exp, new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), valueTx.GasPrice()))

	if exp.Cmp(accountBalanceAfter) != 0 {
		t.Errorf("Expected sender account to have a balance of %d, got %d", exp, accountBalanceAfter)
	}
	if balanceTargetAccountAfter.Cmp(amount) != 0 {
		t.Errorf("Expected new account to have a balance of %d, got %d", valueTx.Value(), balanceTargetAccountAfter)
	}

	// ensure nonce is incremented by 1
	nonceAfter, err := t.Eth.NonceAt(t.Ctx(), sourceAddr, nil)
	if err != nil {
		t.Fatalf("Unable to determine nonce: %v", err)
	}
	expectedNonce := nonceBefore + 1
	if expectedNonce != nonceAfter {
		t.Fatalf("Invalid nonce, want %d, got %d", expectedNonce, nonceAfter)
	}
}

// genesisByHash fetches the known genesis header and compares
// it against the genesis file to determine if block fields are
// returned correct.
func genesisHeaderByHashTest(t *TestEnv) {
	gblock := loadGenesis()

	headerByHash, err := t.Eth.HeaderByHash(t.Ctx(), gblock.Hash())
	if err != nil {
		t.Fatalf("Unable to fetch block %x: %v", gblock.Hash(), err)
	}
	if d := diff(gblock.Header(), headerByHash); d != "" {
		t.Fatal("genesis header reported by node differs from expected header:\n", d)
	}
}

// headerByNumberTest fetched the known genesis header and compares
// it against the genesis file to determine if block fields are
// returned correct.
func genesisHeaderByNumberTest(t *TestEnv) {
	gblock := loadGenesis()

	headerByNum, err := t.Eth.HeaderByNumber(t.Ctx(), big0)
	if err != nil {
		t.Fatalf("Unable to fetch genesis block: %v", err)
	}
	if d := diff(gblock.Header(), headerByNum); d != "" {
		t.Fatal("genesis header reported by node differs from expected header:\n", d)
	}
}

// genesisBlockByHashTest fetched the known genesis block and compares it against
// the genesis file to determine if block fields are returned correct.
func genesisBlockByHashTest(t *TestEnv) {
	gblock := loadGenesis()

	blockByHash, err := t.Eth.BlockByHash(t.Ctx(), gblock.Hash())
	if err != nil {
		t.Fatalf("Unable to fetch block %x: %v", gblock.Hash(), err)
	}
	if d := diff(gblock.Header(), blockByHash.Header()); d != "" {
		t.Fatal("genesis header reported by node differs from expected header:\n", d)
	}
}

// genesisBlockByNumberTest retrieves block 0 since that is the only block
// that is known through the genesis.json file and tests if block
// fields matches the fields defined in the genesis file.
func genesisBlockByNumberTest(t *TestEnv) {
	gblock := loadGenesis()

	blockByNum, err := t.Eth.BlockByNumber(t.Ctx(), big0)
	if err != nil {
		t.Fatalf("Unable to fetch genesis block: %v", err)
	}
	if d := diff(gblock.Header(), blockByNum.Header()); d != "" {
		t.Fatal("genesis header reported by node differs from expected header:\n", d)
	}
}

// canonicalChainTest loops over 10 blocks and does some basic validations
// to ensure the chain form a valid canonical chain and resources like uncles,
// transactions and receipts can be fetched and provide a consistent view.
func canonicalChainTest(t *TestEnv) {
	// wait a bit so there is actually a chain with enough height
	for {
		latestBlock, err := t.Eth.BlockByNumber(t.Ctx(), nil)
		if err != nil {
			t.Fatalf("Unable to fetch latest block")
		}
		if latestBlock.NumberU64() >= 20 {
			break
		}
		time.Sleep(time.Second)
	}

	var childBlock *types.Block
	for i := 10; i >= 0; i-- {
		block, err := t.Eth.BlockByNumber(t.Ctx(), big.NewInt(int64(i)))
		if err != nil {
			t.Fatalf("Unable to fetch block #%d", i)
		}
		if childBlock != nil {
			if childBlock.ParentHash() != block.Hash() {
				t.Errorf("Canonical chain broken on %d-%d / %x-%x", block.NumberU64(), childBlock.NumberU64(), block.Hash(), childBlock.Hash())
			}
		}

		// try to fetch all txs and receipts and do some basic validation on them
		// to check if the fetched chain is consistent.
		for _, tx := range block.Transactions() {
			fetchedTx, _, err := t.Eth.TransactionByHash(t.Ctx(), tx.Hash())
			if err != nil {
				t.Fatalf("Unable to fetch transaction %x from block %x: %v", tx.Hash(), block.Hash(), err)
			}
			if fetchedTx == nil {
				t.Fatalf("Transaction %x could not be found but was included in block %x", tx.Hash(), block.Hash())
			}
			receipt, err := t.Eth.TransactionReceipt(t.Ctx(), fetchedTx.Hash())
			if err != nil {
				t.Fatalf("Unable to fetch receipt for %x from block %x: %v", fetchedTx.Hash(), block.Hash(), err)
			}
			if receipt == nil {
				t.Fatalf("Receipt for %x could not be found but was included in block %x", fetchedTx.Hash(), block.Hash())
			}
			if receipt.TxHash != fetchedTx.Hash() {
				t.Fatalf("Receipt has an invalid tx, expected %x, got %x", fetchedTx.Hash(), receipt.TxHash)
			}
		}

		// make sure all uncles can be fetched
		for _, uncle := range block.Uncles() {
			uBlock, err := t.Eth.HeaderByHash(t.Ctx(), uncle.Hash())
			if err != nil {
				t.Fatalf("Unable to fetch uncle block: %v", err)
			}
			if uBlock == nil {
				t.Logf("Could not fetch uncle block %x", uncle.Hash())
			}
		}

		childBlock = block
	}
}

// deployContractTest deploys `contractSrc` and tests if the code and state
// on the contract address contain the expected values (as set in the ctor).
func deployContractTest(t *TestEnv) {
	var (
		address = t.Vault.createAccount(t, big.NewInt(params.Ether))
		nonce   = uint64(0)

		expectedContractAddress = crypto.CreateAddress(address, nonce)
		gasLimit                = uint64(1200000)
	)

	rawTx := types.NewContractCreation(nonce, big0, gasLimit, gasPrice, deployCode)
	deployTx, err := t.Vault.signTransaction(address, rawTx)
	if err != nil {
		t.Fatalf("Unable to sign deploy tx: %v", err)
	}

	// deploy contract
	if err := t.Eth.SendTransaction(t.Ctx(), deployTx); err != nil {
		t.Fatalf("Unable to send transaction: %v", err)
	}

	t.Logf("Deploy transaction: 0x%x", deployTx.Hash())

	// fetch transaction receipt for contract address
	//var contractAddress common.Address
	receipt, err := waitForTxConfirmations(t, deployTx.Hash(), 5)
	if err != nil {
		t.Fatalf("Unable to retrieve receipt: %v", err)
	}

	// ensure receipt has the expected address
	if expectedContractAddress != receipt.ContractAddress {
		t.Fatalf("Contract deploy on different address, expected %x, got %x", expectedContractAddress, receipt.ContractAddress)
	}

	// test deployed code matches runtime code
	code, err := t.Eth.CodeAt(t.Ctx(), receipt.ContractAddress, nil)
	if err != nil {
		t.Fatalf("Unable to fetch contract code: %v", err)
	}
	if bytes.Compare(runtimeCode, code) != 0 {
		t.Errorf("Deployed code doesn't match, expected %x, got %x", runtimeCode, code)
	}

	// test contract state, pos 0 must be 1234
	value, err := t.Eth.StorageAt(t.Ctx(), receipt.ContractAddress, common.Hash{}, nil)
	if err == nil {
		v := new(big.Int).SetBytes(value)
		if v.Uint64() != 1234 {
			t.Errorf("Unexpected value on %x:0x01, expected 1234, got %d", receipt.ContractAddress, v)
		}
	} else {
		t.Errorf("Unable to retrieve storage pos 0x01 on address %x: %v", receipt.ContractAddress, err)
	}

	// test contract state, map on pos 1 with key myAccount must be 1234
	storageKey := make([]byte, 64)
	copy(storageKey[12:32], address.Bytes())
	storageKey[63] = 1
	storageKey = crypto.Keccak256(storageKey)

	value, err = t.Eth.StorageAt(t.Ctx(), receipt.ContractAddress, common.BytesToHash(storageKey), nil)
	if err == nil {
		v := new(big.Int).SetBytes(value)
		if v.Uint64() != 1234 {
			t.Errorf("Unexpected value in map, expected 1234, got %d", v)
		}
	} else {
		t.Fatalf("Unable to retrieve value in map: %v", err)
	}
}

// deployContractOutOfGasTest tries to deploy `contractSrc` with insufficient gas. It
// checks the receipts reflects the "out of gas" event and code / state isn't created in
// the contract address.
func deployContractOutOfGasTest(t *TestEnv) {
	var (
		address         = t.Vault.createAccount(t, big.NewInt(params.Ether))
		nonce           = uint64(0)
		contractAddress = crypto.CreateAddress(address, nonce)
		gasLimit        = uint64(18446744073709551614) // insufficient gas
	)
	t.Logf("calculated contract address: %x", contractAddress)

	// Deploy the contract.
	rawTx := types.NewContractCreation(nonce, big0, gasLimit, gasPrice, deployCode)
	deployTx, err := t.Vault.signTransaction(address, rawTx)
	if err != nil {
		t.Fatalf("unable to sign deploy tx: %v", err)
	}
	t.Logf("out of gas tx: %x", deployTx.Hash())
	if err := t.Eth.SendTransaction(t.Ctx(), deployTx); err != nil {
		t.Fatalf("unable to send transaction: %v", err)
	}

	// Wait for the transaction receipt.
	receipt, err := waitForTxConfirmations(t, deployTx.Hash(), 5)
	if err != nil {
		t.Fatalf("unable to fetch tx receipt: %v", err)
	}
	// Check receipt fields.
	if receipt.Status != types.ReceiptStatusFailed {
		t.Errorf("receipt has status %d, want %d", receipt.Status, types.ReceiptStatusFailed)
	}
	if receipt.GasUsed != gasLimit {
		t.Errorf("receipt has gasUsed %d, want %d", receipt.GasUsed, gasLimit)
	}
	if receipt.ContractAddress != contractAddress {
		t.Errorf("receipt has contract address %x, want %x", receipt.ContractAddress, contractAddress)
	}
	if receipt.BlockHash == (common.Hash{}) {
		t.Errorf("receipt has empty block hash", receipt.BlockHash)
	}
	// Check that nothing is deployed at the contract address.
	code, err := t.Eth.CodeAt(t.Ctx(), contractAddress, nil)
	if err != nil {
		t.Fatalf("unable to fetch code: %v", err)
	}
	if len(code) != 0 {
		t.Errorf("expected no code deployed but got %x", code)
	}
}

// receiptTest tests whether the created receipt is correct by calling the `events` method
// on the pre-deployed contract.
func receiptTest(t *TestEnv) {
	var (
		contractABI, _ = abi.JSON(strings.NewReader(predeployedContractABI))
		address        = t.Vault.createAccount(t, big.NewInt(params.Ether))
		nonce          = uint64(0)

		intArg = big.NewInt(rand.Int63())
	)

	payload, err := contractABI.Pack("events", intArg, address)
	if err != nil {
		t.Fatalf("Unable to prepare tx payload: %v", err)
	}

	rawTx := types.NewTransaction(nonce, predeployedContractAddr, big0, 500000, gasPrice, payload)
	tx, err := t.Vault.signTransaction(address, rawTx)
	if err != nil {
		t.Fatalf("Unable to sign deploy tx: %v", err)
	}

	if err := t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
		t.Fatalf("Unable to send transaction: %v", err)
	}

	// wait for transaction
	receipt, err := waitForTxConfirmations(t, tx.Hash(), 0)
	if err != nil {
		t.Fatalf("Unable to retrieve tx receipt: %v", err)
	}
	// validate receipt fields
	if receipt.TxHash != tx.Hash() {
		t.Errorf("Receipt contains invalid tx hash, want %x, got %x", tx.Hash(), receipt.TxHash)
	}
	if receipt.ContractAddress != (common.Address{}) {
		t.Errorf("Receipt contains invalid contract address, want empty address got %x", receipt.ContractAddress)
	}
	bloom := types.CreateBloom(types.Receipts{receipt})
	if receipt.Bloom != bloom {
		t.Errorf("Receipt contains invalid bloom, want %x, got %x", bloom, receipt.Bloom)
	}

	var (
		intArgBytes  = common.LeftPadBytes(intArg.Bytes(), 32)
		addrArgBytes = common.LeftPadBytes(address.Bytes(), 32)
	)

	if len(receipt.Logs) != 6 {
		t.Fatalf("Want 6 logs, got %d", len(receipt.Logs))
	}

	validateLog(t, tx, *receipt.Logs[0], predeployedContractAddr, receipt.Logs[0].Index+0, contractABI.Events["E0"], nil)
	validateLog(t, tx, *receipt.Logs[1], predeployedContractAddr, receipt.Logs[0].Index+1, contractABI.Events["E1"], intArgBytes)
	validateLog(t, tx, *receipt.Logs[2], predeployedContractAddr, receipt.Logs[0].Index+2, contractABI.Events["E2"], intArgBytes)
	validateLog(t, tx, *receipt.Logs[3], predeployedContractAddr, receipt.Logs[0].Index+3, contractABI.Events["E3"], addrArgBytes)
	validateLog(t, tx, *receipt.Logs[4], predeployedContractAddr, receipt.Logs[0].Index+4, contractABI.Events["E4"], addrArgBytes)
	validateLog(t, tx, *receipt.Logs[5], predeployedContractAddr, receipt.Logs[0].Index+5, contractABI.Events["E5"], intArgBytes, addrArgBytes)
}

// validateLog is a helper method that tests if the given set of logs are valid when the events method on the
// standard contract is called with argData.
func validateLog(t *TestEnv, tx *types.Transaction, log types.Log, contractAddress common.Address, index uint, ev abi.Event, argData ...[]byte) {
	if log.Address != contractAddress {
		t.Errorf("Log[%d] contains invalid address, want 0x%x, got 0x%x [tx=0x%x]", index, contractAddress, log.Address, tx.Hash())
	}
	if log.TxHash != tx.Hash() {
		t.Errorf("Log[%d] contains invalid hash, want 0x%x, got 0x%x [tx=0x%x]", index, tx.Hash(), log.TxHash, tx.Hash())
	}
	if log.Index != index {
		t.Errorf("Log[%d] has invalid index, want %d, got %d [tx=0x%x]", index, index, log.Index, tx.Hash())
	}

	// assemble expected topics and log data
	var (
		topics []common.Hash
		data   []byte
	)
	if !ev.Anonymous {
		topics = append(topics, ev.ID)
	}
	for i, arg := range ev.Inputs {
		if arg.Indexed {
			topics = append(topics, common.BytesToHash(argData[i]))
		} else {
			data = append(data, argData[i]...)
		}
	}

	if len(log.Topics) != len(topics) {
		t.Errorf("Log[%d] contains invalid number of topics, want %d, got %d [tx=0x%x]", index, len(topics), len(log.Topics), tx.Hash())
	} else {
		for i, topic := range topics {
			if topics[i] != topic {
				t.Errorf("Log[%d] contains invalid topic, want 0x%x, got 0x%x [tx=0x%x]", index, topics[i], topic, tx.Hash())
			}
		}
	}
	if !bytes.Equal(log.Data, data) {
		t.Errorf("Log[%d] contains invalid data, want 0x%x, got 0x%x [tx=0x%x]", index, data, log.Data, tx.Hash())
	}
}

// syncProgressTest only tests if this function is supported by the node.
func syncProgressTest(t *TestEnv) {
	_, err := t.Eth.SyncProgress(t.Ctx())
	if err != nil {
		t.Fatalf("Unable to determine sync progress: %v", err)
	}
}

// transactionInBlockTest will wait for a new block with transaction
// and retrieves transaction details by block hash and position.
func transactionInBlockTest(t *TestEnv) {
	var (
		key         = t.Vault.createAccount(t, big.NewInt(params.Ether))
		nonce       = uint64(0)
		blockNumber = new(big.Int)
	)

	for {
		blockNumber.Add(blockNumber, big1)

		block, err := t.Eth.BlockByNumber(t.Ctx(), blockNumber)
		if err == ethereum.NotFound { // end of chain
			rawTx := types.NewTransaction(nonce, predeployedVaultAddr, big1, 100000, gasPrice, nil)
			nonce++

			tx, err := t.Vault.signTransaction(key, rawTx)
			if err != nil {
				t.Fatalf("Unable to sign deploy tx: %v", err)
			}
			if err = t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
				t.Fatalf("Unable to send transaction: %v", err)
			}
			time.Sleep(time.Second)
			continue
		}
		if err != nil {
			t.Fatalf("Unable to fetch latest block: %v", err)
			t.Fatalf("blocknumber: %d", blockNumber)
		}
		if len(block.Transactions()) == 0 {
			continue
		}
		for i := 0; i < len(block.Transactions()); i++ {
			_, err := t.Eth.TransactionInBlock(t.Ctx(), block.Hash(), uint(i))
			if err != nil {
				t.Fatalf("Unable to fetch transaction by block hash and index: %v", err)
			}
		}
		return
	}
}

// transactionInBlockSubscriptionTest will wait for a new block with transaction
// and retrieves transaction details by block hash and position.
func transactionInBlockSubscriptionTest(t *TestEnv) {
	var heads = make(chan *types.Header, 100)

	sub, err := t.Eth.SubscribeNewHead(t.Ctx(), heads)
	if err != nil {
		t.Fatalf("Unable to subscribe to new heads: %v", err)
	}

	key := t.Vault.createAccount(t, big.NewInt(params.Ether))
	for i := 0; i < 5; i++ {
		rawTx := types.NewTransaction(uint64(i), predeployedVaultAddr, big1, 100000, gasPrice, nil)
		tx, err := t.Vault.signTransaction(key, rawTx)
		if err != nil {
			t.Fatalf("Unable to sign deploy tx: %v", err)
		}
		if err = t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
			t.Fatalf("Unable to send transaction: %v", err)
		}
	}

	// wait until transaction
	defer sub.Unsubscribe()
	for {
		head := <-heads

		block, err := t.Eth.BlockByHash(t.Ctx(), head.Hash())
		if err != nil {
			t.Fatalf("Unable to retrieve block %x: %v", head.Hash(), err)
		}
		if len(block.Transactions()) == 0 {
			continue
		}
		for i := 0; i < len(block.Transactions()); i++ {
			_, err = t.Eth.TransactionInBlock(t.Ctx(), head.Hash(), uint(i))
			if err != nil {
				t.Fatalf("Unable to fetch transaction by block hash and index: %v", err)
			}
		}
		return
	}
}

// newHeadSubscriptionTest tests whether
func newHeadSubscriptionTest(t *TestEnv) {
	var (
		heads = make(chan *types.Header)
	)

	sub, err := t.Eth.SubscribeNewHead(t.Ctx(), heads)
	if err != nil {
		t.Fatalf("Unable to subscribe to new heads: %v", err)
	}

	defer sub.Unsubscribe()
	for i := 0; i < 10; i++ {
		select {
		case newHead := <-heads:
			header, err := t.Eth.HeaderByHash(t.Ctx(), newHead.Hash())
			if err != nil {
				t.Fatalf("Unable to fetch header: %v", err)
			}
			if header == nil {
				t.Fatalf("Unable to fetch header %s", newHead.Hash())
			}
		case err := <-sub.Err():
			t.Fatalf("Received errors: %v", err)
		}
	}
}

func logSubscriptionTest(t *TestEnv) {
	var (
		criteria = ethereum.FilterQuery{
			Addresses: []common.Address{predeployedContractAddr},
			Topics:    [][]common.Hash{},
		}
		logs = make(chan types.Log)
	)

	sub, err := t.Eth.SubscribeFilterLogs(t.Ctx(), criteria, logs)
	if err != nil {
		t.Fatalf("Unable to create log subscription: %v", err)
	}
	defer sub.Unsubscribe()

	var (
		contractABI, _ = abi.JSON(strings.NewReader(predeployedContractABI))
		address        = t.Vault.createAccount(t, big.NewInt(params.Ether))
		nonce          = uint64(0)

		arg0 = big.NewInt(rand.Int63())
		arg1 = address
	)

	payload, _ := contractABI.Pack("events", arg0, arg1)
	rawTx := types.NewTransaction(nonce, predeployedContractAddr, big0, 500000, gasPrice, payload)
	tx, err := t.Vault.signTransaction(address, rawTx)
	if err != nil {
		t.Fatalf("Unable to sign deploy tx: %v", err)
	}

	if err = t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
		t.Fatalf("Unable to send transaction: %v", err)
	}

	t.Logf("Wait for logs generated for transaction: %x", tx.Hash())
	var (
		expectedLogs = 6
		currentLogs  = 0
		fetchedLogs  []types.Log
		deadline     = time.NewTimer(30 * time.Second)
	)

	// ensure we receive all logs that are generated by our transaction.
	// log fields are in depth verified in another test.
	for len(fetchedLogs) < expectedLogs {
		select {
		case log := <-logs:
			// other tests also send transaction to the predeployed
			// contract ensure these logs are from "our" transaction.
			if log.TxHash != tx.Hash() {
				continue
			}
			fetchedLogs = append(fetchedLogs, log)
		case err := <-sub.Err():
			t.Fatalf("Log subscription returned error: %v", err)
		case <-deadline.C:
			t.Fatalf("Only received %d/%d logs", currentLogs, expectedLogs)
		}
	}

	validatePredeployContractLogs(t, tx, fetchedLogs, arg0, arg1)
}

// validatePredeployContractLogs tests wether the given logs are expected when
// the event function was called on the predeployed test contract was called
// with the given args. The event function raises the following events:
// event E0();
// event E1(uint);
// event E2(uint indexed);
// event E3(address);
// event E4(address indexed);
// event E5(uint, address) anonymous;
func validatePredeployContractLogs(t *TestEnv, tx *types.Transaction, logs []types.Log, intArg *big.Int, addrArg common.Address) {
	if len(logs) != 6 {
		t.Fatalf("Unexpected log count, want 6, got %d", len(logs))
	}

	var (
		contractABI, _ = abi.JSON(strings.NewReader(predeployedContractABI))
		intArgBytes    = common.LeftPadBytes(intArg.Bytes(), 32)
		addrArgBytes   = common.LeftPadBytes(addrArg.Bytes(), 32)
	)

	validateLog(t, tx, logs[0], predeployedContractAddr, logs[0].Index+0, contractABI.Events["E0"], nil)
	validateLog(t, tx, logs[1], predeployedContractAddr, logs[0].Index+1, contractABI.Events["E1"], intArgBytes)
	validateLog(t, tx, logs[2], predeployedContractAddr, logs[0].Index+2, contractABI.Events["E2"], intArgBytes)
	validateLog(t, tx, logs[3], predeployedContractAddr, logs[0].Index+3, contractABI.Events["E3"], addrArgBytes)
	validateLog(t, tx, logs[4], predeployedContractAddr, logs[0].Index+4, contractABI.Events["E4"], addrArgBytes)
	validateLog(t, tx, logs[5], predeployedContractAddr, logs[0].Index+5, contractABI.Events["E5"], intArgBytes, addrArgBytes)
}

func transactionCountTest(t *TestEnv) {
	var (
		key = t.Vault.createAccount(t, big.NewInt(params.Ether))
	)

	for i := 0; i < 60; i++ {
		rawTx := types.NewTransaction(uint64(i), predeployedVaultAddr, big1, 100000, gasPrice, nil)
		tx, err := t.Vault.signTransaction(key, rawTx)
		if err != nil {
			t.Fatalf("Unable to sign deploy tx: %v", err)
		}

		if err = t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
			t.Fatalf("Unable to send transaction: %v", err)
		}
		block, err := t.Eth.BlockByNumber(t.Ctx(), nil)
		if err != nil {
			t.Fatalf("Unable to retrieve latest block: %v", err)
		}

		if len(block.Transactions()) > 0 {
			count, err := t.Eth.TransactionCount(t.Ctx(), block.Hash())
			if err != nil {
				t.Fatalf("Unable to retrieve block transaction count: %v", err)
			}
			if count != uint(len(block.Transactions())) {
				t.Fatalf("Invalid block tx count, want %d, got %d", len(block.Transactions()), count)
			}
			return
		}

		time.Sleep(time.Second)
	}
}

// TransactionReceiptTest sends a transaction and tests the receipt fields.
func TransactionReceiptTest(t *TestEnv) {
	var (
		key = t.Vault.createAccount(t, big.NewInt(params.Ether))
	)

	rawTx := types.NewTransaction(uint64(0), common.Address{}, big1, 100000, gasPrice, nil)
	tx, err := t.Vault.signTransaction(key, rawTx)
	if err != nil {
		t.Fatalf("Unable to sign deploy tx: %v", err)
	}

	if err = t.Eth.SendTransaction(t.Ctx(), tx); err != nil {
		t.Fatalf("Unable to send transaction: %v", err)
	}

	for i := 0; i < 60; i++ {
		receipt, err := t.Eth.TransactionReceipt(t.Ctx(), tx.Hash())
		if err == ethereum.NotFound {
			time.Sleep(time.Second)
			continue
		}

		if err != nil {
			t.Errorf("Unable to fetch receipt: %v", err)
		}
		if receipt.TxHash != tx.Hash() {
			t.Errorf("Receipt [tx=%x] contains invalid tx hash, want %x, got %x", tx.Hash(), receipt.TxHash)
		}
		if receipt.ContractAddress != (common.Address{}) {
			t.Errorf("Receipt [tx=%x] contains invalid contract address, expected empty address but got %x", tx.Hash(), receipt.ContractAddress)
		}
		if receipt.Bloom.Big().Cmp(big0) != 0 {
			t.Errorf("Receipt [tx=%x] bloom not empty, %x", tx.Hash(), receipt.Bloom)
		}
		if receipt.GasUsed != params.TxGas {
			t.Errorf("Receipt [tx=%x] has invalid gas used, want %d, got %d", tx.Hash(), params.TxGas, receipt.GasUsed)
		}
		if len(receipt.Logs) != 0 {
			t.Errorf("Receipt [tx=%x] should not contain logs but got %d logs", tx.Hash(), len(receipt.Logs))
		}
		return
	}
}
