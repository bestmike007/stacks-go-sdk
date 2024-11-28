package transaction_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/icon-project/stacks-go-sdk/pkg/clarity"
	"github.com/icon-project/stacks-go-sdk/pkg/crypto"
	"github.com/icon-project/stacks-go-sdk/pkg/stacks"
	"github.com/icon-project/stacks-go-sdk/pkg/transaction"
	"github.com/stretchr/testify/require"
)

func TestBroadcastSTXTokenTransferTransaction(t *testing.T) {
	mnemonic := "vapor unhappy gather snap project ball gain puzzle comic error avocado bounce letter anxiety wheel provide canyon promote sniff improve figure daughter mansion baby"
	privateKey, err := crypto.DeriveStxPrivateKey(mnemonic, 0)
	if err != nil {
		t.Fatalf("Failed to derive private key: %v", err)
	}

	senderAddress := "ST15C893XJFJ6FSKM020P9JQDB5T7X6MQTXMBPAVH"
	senderPublicKey := crypto.GetPublicKeyFromPrivate(privateKey)
	var signerArray [20]byte
	copy(signerArray[:], crypto.Hash160(senderPublicKey))

	recipient := "ST3YJD5Y1WTMC8R09ZKR3HJF562R3NM8HHXW2S2R9"
	amount := big.NewInt(1000000) // 1 STX
	memo := "Test transfer"
	network := stacks.NewStacksTestnet()
	nonce, err := transaction.GetNextNonce(senderAddress, *network)
	require.NoError(t, err, "Failed to get nonce")
	// skip 4 nonce to ensure it never get settled
	nonce = nonce.Add(nonce, big.NewInt(4))
	tx, err := transaction.MakeSTXTokenTransfer(recipient, *amount, memo, *network, senderAddress, privateKey, nil, nonce)
	if err != nil {
		t.Fatalf("Failed to create transaction: %v", err)
	}

	err = transaction.SignTransaction(tx, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	txID, err := transaction.BroadcastTransaction(tx, network)
	if err != nil {
		t.Fatalf("Failed to broadcast transaction: %v", err)
	}

	fmt.Printf("Transaction broadcasted successfully. TxID: %s\n", txID)
}

func TestBroadcastContractCallTransaction(t *testing.T) {
	mnemonic := "vapor unhappy gather snap project ball gain puzzle comic error avocado bounce letter anxiety wheel provide canyon promote sniff improve figure daughter mansion baby"
	privateKey, err := crypto.DeriveStxPrivateKey(mnemonic, 0)
	if err != nil {
		t.Fatalf("Failed to derive private key: %v", err)
	}

	senderAddress := "ST15C893XJFJ6FSKM020P9JQDB5T7X6MQTXMBPAVH"
	senderPublicKey := crypto.GetPublicKeyFromPrivate(privateKey)
	var signerArray [20]byte
	copy(signerArray[:], crypto.Hash160(senderPublicKey))

	contractAddress := "ST15C893XJFJ6FSKM020P9JQDB5T7X6MQTXMBPAVH"
	contractName := "contract_name"
	functionName := "address-string-to-principal"

	strArg, err := clarity.NewStringASCII("test")
	require.NoError(t, err, "Failed to create string argument")

	functionArgs := []clarity.ClarityValue{
		strArg,
	}

	network := stacks.NewStacksTestnet()
	nonce, err := transaction.GetNextNonce(senderAddress, *network)
	require.NoError(t, err, "Failed to get nonce")
	// skip 5 nonce to ensure it never get settled
	nonce = nonce.Add(nonce, big.NewInt(5))
	tx, err := transaction.MakeContractCall(contractAddress, contractName, functionName, functionArgs, *network, senderAddress, privateKey, nil, nonce, stacks.PostConditionModeAllow, []transaction.PostCondition{})
	if err != nil {
		t.Fatalf("Failed to create transaction: %v", err)
	}

	err = transaction.SignTransaction(tx, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	txID, err := transaction.BroadcastTransaction(tx, network)
	if err != nil {
		t.Fatalf("Failed to broadcast transaction: %v", err)
	}

	fmt.Printf("Transaction broadcasted successfully. TxID: %s\n", txID)
}

func TestBroadcastContractDeployTransaction(t *testing.T) {
	mnemonic := "vapor unhappy gather snap project ball gain puzzle comic error avocado bounce letter anxiety wheel provide canyon promote sniff improve figure daughter mansion baby"
	privateKey, err := crypto.DeriveStxPrivateKey(mnemonic, 0)
	if err != nil {
		t.Fatalf("Failed to derive private key: %v", err)
	}

	senderAddress := "ST15C893XJFJ6FSKM020P9JQDB5T7X6MQTXMBPAVH"
	senderPublicKey := crypto.GetPublicKeyFromPrivate(privateKey)
	var signerArray [20]byte
	copy(signerArray[:], crypto.Hash160(senderPublicKey))

	// Define the contract name and Clarity code
	contractName := "my-counter"
	codeBody := `(define-data-var counter int 0)

(define-public (increment)
    (begin
        (var-set counter (+ (var-get counter) 1))
        (ok (var-get counter))))

(define-public (decrement)
    (begin
        (var-set counter (- (var-get counter) 1))
        (ok (var-get counter))))

(define-read-only (get-counter)
    (ok (var-get counter)))`

	network := stacks.NewStacksTestnet()
	nonce, err := transaction.GetNextNonce(senderAddress, *network)
	require.NoError(t, err, "Failed to get nonce")
	// skip 6 nonce to ensure it never get settled
	nonce = nonce.Add(nonce, big.NewInt(6))
	tx, err := transaction.MakeContractDeploy(
		// make sure the contract name is unique
		contractName+"-"+nonce.Text(36),
		codeBody,
		stacks.ClarityVersionUnspecified,
		*network,
		senderAddress,
		privateKey,
		nil, // Auto-estimate fee
		nil, // Auto-estimate nonce
		stacks.PostConditionModeAllow,
		[]transaction.PostCondition{},
	)
	if err != nil {
		t.Fatalf("Failed to create contract deploy transaction: %v", err)
	}

	err = transaction.SignTransaction(tx, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	txID, err := transaction.BroadcastTransaction(tx, network)
	if err != nil {
		t.Fatalf("Failed to broadcast transaction: %v", err)
	}

	fmt.Printf("Contract deploy transaction broadcasted successfully. TxID: %s\n", txID)
	fmt.Printf("Contract will be deployed as: %s.%s\n", senderAddress, contractName)
}
