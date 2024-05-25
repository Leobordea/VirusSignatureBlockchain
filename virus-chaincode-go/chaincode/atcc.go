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
	SigName   string `json:"SigName"`
}

func (t *VirusChaincode) InitLedger(ctx contractapi.TransactionContextInterface) error {
	virusSignatures := []VirusSignature{
		{SignatureID: "1", SigName: "MD5", IPFSHash: "QmZQHmuXvF1AifghrGnNH4uey5iF1hzeRZvfevF2kg19nV", Uploader: "Org1", Timestamp: time.Now().Unix()},
		{SignatureID: "2", SigName: "SHA1", IPFSHash: "91d81538ae5ec6166e6192c768b40d7b622781467f3836", Uploader: "Org2", Timestamp: time.Now().Unix()},
		{SignatureID: "3", SigName: "SHA256", IPFSHash: "9e83e05bbf9b5db17ac0deec3b7ce6cba983f6dc50531c", Uploader: "Org1", Timestamp: time.Now().Unix()},
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
