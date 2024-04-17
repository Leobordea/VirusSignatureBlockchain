package chaincode_test

import (
	"chaincode"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode/mocks"
	"github.com/stretchr/testify/require"
)

//go:generate counterfeiter -o mocks/transaction.go -fake-name TransactionContext . transactionContext
type transactionContext interface {
	contractapi.TransactionContextInterface
}

//go:generate counterfeiter -o mocks/chaincodestub.go -fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

//go:generate counterfeiter -o mocks/statequeryiterator.go -fake-name StateQueryIterator . stateQueryIterator
type stateQueryIterator interface {
	shim.StateQueryIteratorInterface
}

func TestInitLedger(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	signatureTransfer := chaincode.VirusChaincode{}
	err := signatureTransfer.InitLedger(transactionContext)
	require.NoError(t, err)

	chaincodeStub.PutStateReturns(fmt.Errorf("failed inserting key"))
	err = signatureTransfer.InitLedger(transactionContext)
	require.EqualError(t, err, "failed to put to world state. failed inserting key")
}

func TestCreateSignature(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	signatureTransfer := chaincode.VirusChaincode{}
	err := signatureTransfer.UploadSignature(transactionContext, "", "", "", "")
	require.NoError(t, err)

	chaincodeStub.GetStateReturns([]byte{}, nil)
	err = signatureTransfer.UploadSignature(transactionContext, "", "virus1", "", "")
	require.EqualError(t, err, "the signature virus1 already exists")

	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve signature"))
	err = signatureTransfer.UploadSignature(transactionContext, "", "virus1", "", "")
	require.EqualError(t, err, "failed to read from world state: unable to retrieve signature")
}

func TestReadSignature(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	expectedsignature := &chaincode.VirusSignature{SignatureID: "virus1"}
	bytes, err := json.Marshal(expectedsignature)
	require.NoError(t, err)

	chaincodeStub.GetStateReturns(bytes, nil)
	signatureTransfer := chaincode.VirusChaincode{}
	signature, err := signatureTransfer.GetSignature(transactionContext, "")
	require.NoError(t, err)
	require.Equal(t, expectedsignature, signature)

	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve signature"))
	_, err = signatureTransfer.GetSignature(transactionContext, "")
	require.EqualError(t, err, "failed to read from world state: unable to retrieve signature")

	chaincodeStub.GetStateReturns(nil, nil)
	signature, err = signatureTransfer.GetSignature(transactionContext, "virus1")
	require.EqualError(t, err, "Virus signature with ID virus1 not found")
	require.Nil(t, signature)
}

func TestUpdateSignature(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	expectedsignature := &chaincode.VirusSignature{SignatureID: "virus1"}
	bytes, err := json.Marshal(expectedsignature)
	require.NoError(t, err)

	chaincodeStub.GetStateReturns(bytes, nil)
	signatureTransfer := chaincode.VirusChaincode{}
	err = signatureTransfer.UpdateSignature(transactionContext, "", "", "", "")
	require.NoError(t, err)

	chaincodeStub.GetStateReturns(nil, nil)
	err = signatureTransfer.UpdateSignature(transactionContext, "", "virus1", "", "")
	require.EqualError(t, err, "virus signature with ID virus1 does not exist")

	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve signature"))
	err = signatureTransfer.UpdateSignature(transactionContext, "virus1", "", "", "")
	require.EqualError(t, err, "failed to read from world state: unable to retrieve signature")
}

func TestDeleteSignature(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	signature := &chaincode.VirusSignature{SignatureID: "virus1"}
	bytes, err := json.Marshal(signature)
	require.NoError(t, err)

	chaincodeStub.GetStateReturns(bytes, nil)
	chaincodeStub.DelStateReturns(nil)
	signatureTransfer := chaincode.VirusChaincode{}
	err = signatureTransfer.DeleteSignature(transactionContext, "")
	require.NoError(t, err)

	chaincodeStub.GetStateReturns(nil, nil)
	err = signatureTransfer.DeleteSignature(transactionContext, "virus1")
	require.EqualError(t, err, "virus signature with ID virus1 does not exist")

	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve signature"))
	err = signatureTransfer.DeleteSignature(transactionContext, "")
	require.EqualError(t, err, "failed to read virus signature from ledger: unable to retrieve signature")
}

func TestGetAllSignatures(t *testing.T) {
	signature := &chaincode.VirusSignature{SignatureID: "virus1"}
	bytes, err := json.Marshal(signature)
	require.NoError(t, err)

	iterator := &mocks.StateQueryIterator{}
	iterator.HasNextReturnsOnCall(0, true)
	iterator.HasNextReturnsOnCall(1, false)
	iterator.NextReturns(&queryresult.KV{Value: bytes}, nil)

	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	chaincodeStub.GetStateByRangeReturns(iterator, nil)
	signatureTransfer := &chaincode.VirusChaincode{}
	signatures, err := signatureTransfer.GetAllSignatures(transactionContext)
	require.NoError(t, err)
	require.Equal(t, []*chaincode.VirusSignature{signature}, signatures)

	iterator.HasNextReturns(true)
	iterator.NextReturns(nil, fmt.Errorf("failed retrieving next item"))
	signatures, err = signatureTransfer.GetAllSignatures(transactionContext)
	require.EqualError(t, err, "failed retrieving next item")
	require.Nil(t, signatures)

	chaincodeStub.GetStateByRangeReturns(nil, fmt.Errorf("failed retrieving all signatures"))
	signatures, err = signatureTransfer.GetAllSignatures(transactionContext)
	require.EqualError(t, err, "failed retrieving all signatures")
	require.Nil(t, signatures)
}
