package chaincode

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"time"
)

// SmartContract provides functions for managing an signature
type VirusChaincode struct {
	contractapi.Contract
}

// signature describes basic details of what makes up a simple signature
// Insert struct field in alphabetic order => to achieve determinism accross languages
// golang keeps the order when marshal to json but doesn't order automatically
type VirusSignature struct {
	IPFSHash    string `json:"IPFSHash"`
	SignatureID string `json:"SignatureID"`
	Timestamp   int64  `json:"Timestamp"`
	Uploader    string `json:"Uploader"`
	VirusName   string `json:"VirusName"`
}

func (t *VirusChaincode) InitLedger(ctx contractapi.TransactionContextInterface) error {
	virusSignatures := []VirusSignature{
		{SignatureID: "1", VirusName: "SampleVirus1", IPFSHash: "QmZQHmuXvF1AifghrGnNH4uey5iF1hzeRZvfevF2kg19nV", Uploader: "Org1", Timestamp: time.Now().Unix()},
		{SignatureID: "2", VirusName: "SampleVirus2", IPFSHash: "QmZQHmuXvF1AifghrGnNH4uey5iF1hzeRZvfevF2kg19nW", Uploader: "Org2", Timestamp: time.Now().Unix()},
		// Add more sample virus signatures as needed
	}

	for _, signature := range virusSignatures {
		virusJSON, err := json.Marshal(signature)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(signature.SignatureID, virusJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}
func (t *VirusChaincode) UploadSignature(ctx contractapi.TransactionContextInterface, ipfsHash string, signatureID string, uploader string, virusName string) error {
	exists, err := t.SignatureExists(ctx, signatureID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the signature %s already exists", signatureID)
	}
	signature := VirusSignature{
		IPFSHash:    ipfsHash,
		SignatureID: signatureID,
		Timestamp:   time.Now().Unix(),
		Uploader:    uploader,
		VirusName:   virusName,
	}

	virusJSON, err := json.Marshal(signature)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(signatureID, virusJSON)
}

func (t *VirusChaincode) GetSignature(ctx contractapi.TransactionContextInterface, signatureID string) (*VirusSignature, error) {
	virusJSON, err := ctx.GetStub().GetState(signatureID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if virusJSON == nil {
		return nil, fmt.Errorf("Virus signature with ID %s not found", signatureID)
	}

	var signature VirusSignature
	err = json.Unmarshal(virusJSON, &signature)
	if err != nil {
		return nil, err
	}

	return &signature, nil
}
func (t *VirusChaincode) UpdateSignature(ctx contractapi.TransactionContextInterface, newIPFSHash string, signatureID string, uploader string, newVirusName string) error {
	// Retrieve the existing virus signature from the ledger
	exists, err := t.SignatureExists(ctx, signatureID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("virus signature with ID %s does not exist", signatureID)
	}

	signature := VirusSignature{
		IPFSHash:    newIPFSHash,
		SignatureID: signatureID,
		Timestamp:   time.Now().Unix(),
		Uploader:    uploader,
		VirusName:   newVirusName,
	}

	virusJSON, err := json.Marshal(signature)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(signatureID, virusJSON)
}
func (t *VirusChaincode) DeleteSignature(ctx contractapi.TransactionContextInterface, signatureID string) error {
	// Check if the virus signature exists
	virusJSON, err := ctx.GetStub().GetState(signatureID)
	if err != nil {
		return fmt.Errorf("failed to read virus signature from ledger: %v", err)
	}
	if virusJSON == nil {
		return fmt.Errorf("virus signature with ID %s does not exist", signatureID)
	}

	// Delete the virus signature from the ledger
	err = ctx.GetStub().DelState(signatureID)
	if err != nil {
		return fmt.Errorf("failed to delete virus signature from ledger: %v", err)
	}

	return nil
}

func (t *VirusChaincode) SignatureExists(ctx contractapi.TransactionContextInterface, signatureID string) (bool, error) {
	// Check if the virus signature exists
	virusJSON, err := ctx.GetStub().GetState(signatureID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return virusJSON != nil, nil
}

func (t *VirusChaincode) GetAllSignatures(ctx contractapi.TransactionContextInterface) ([]*VirusSignature, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var signatures []*VirusSignature
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var signature VirusSignature
		err = json.Unmarshal(queryResponse.Value, &signature)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, &signature)
	}

	return signatures, nil
}

func main() {
	virusChaincode := new(VirusChaincode)
	contractAPI, err := contractapi.NewChaincode(virusChaincode)
	if err != nil {
		log.Fatal("Error creating virus chaincode: ", err)
	}

	if err := contractAPI.Start(); err != nil {
		log.Fatal("Error starting virus chaincode: ", err)
	}
}
