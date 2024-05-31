package chaincode

import (
	"encoding/json"
	"fmt"
	"log"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an signature
type VirusChaincode struct {
	contractapi.Contract
}

// signature describes basic details of what makes up a simple signature
// Insert struct field in alphabetic order => to achieve determinism accross languages
// golang keeps the order when marshal to json but doesn't order automatically
type VirusSignature struct {
	IPFS_CID    string `json:"IPFS_CID"`
	SignatureID string `json:"SignatureID"`
	Timestamp   int64  `json:"Timestamp"`
	Uploader    string `json:"Uploader"`
	SigName     string `json:"SigName"`
}

func (t *VirusChaincode) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

func (t *VirusChaincode) GetAllSignatures(ctx contractapi.TransactionContextInterface) ([]*VirusSignature, error) {
	virusSignatures := []*VirusSignature{
		{SignatureID: "1", SigName: "hypatia-md5-bloom", IPFS_CID: "QmYCX7WLMbMZh5sNpbHQJzv3fGc5aePGErdCDjQAkJkrC2", Uploader: "Divested-Mobile", Timestamp: 1717174878},
		{SignatureID: "2", SigName: "hypatia-sha1-bloom", IPFS_CID: "QmamKMWmLDxBWBz5pdSwDCtmmXRyzzTB58FbTqU578S49c", Uploader: "Divested-Mobile", Timestamp: 1717174878},
		{SignatureID: "3", SigName: "hypatia-sha256-bloom", IPFS_CID: "QmWEyhH59qQxfLiexBaU45Td9nTkzYBZw8noRDXBcuYw3y", Uploader: "Divested-Mobile", Timestamp: 1717174878},
	}
	return virusSignatures, nil
}

// Vote structure to hold vote details
type Vote struct {
	Org     string `json:"org"`
	Approve bool   `json:"approve"`
}

// Vote allows an organization to cast a vote if they haven't voted before
func (s *VirusChaincode) Vote(ctx contractapi.TransactionContextInterface, approve bool) error {
	// Get the MSP ID of the invoking organization
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	// Check if the organization has already voted
	voteAsBytes, err := ctx.GetStub().GetState(clientMSPID)
	if err != nil {
		return fmt.Errorf("failed to read vote from world state: %v", err)
	}
	if voteAsBytes != nil {
		return fmt.Errorf("organization %s has already voted", clientMSPID)
	}

	// Create a new vote
	vote := Vote{
		Org:     clientMSPID,
		Approve: approve,
	}
	voteJSON, err := json.Marshal(vote)
	if err != nil {
		return fmt.Errorf("failed to marshal vote: %v", err)
	}

	// Store the vote in the world state with the organization's MSP ID as the key
	return ctx.GetStub().PutState(clientMSPID, voteJSON)
}

// GetVote retrieves the vote for an organization
func (s *VirusChaincode) GetVote(ctx contractapi.TransactionContextInterface, org string) (*Vote, error) {
	voteAsBytes, err := ctx.GetStub().GetState(org)
	if err != nil {
		return nil, fmt.Errorf("failed to read vote from world state: %v", err)
	}
	if voteAsBytes == nil {
		return nil, fmt.Errorf("vote for org %s does not exist", org)
	}

	var vote Vote
	err = json.Unmarshal(voteAsBytes, &vote)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vote: %v", err)
	}

	return &vote, nil
}

// CountVotes counts the votes for approval and disapproval
func (s *VirusChaincode) CountVotes(ctx contractapi.TransactionContextInterface) (map[string]int, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get state by range: %v", err)
	}
	defer resultsIterator.Close()

	voteCounts := map[string]int{"approve": 0, "disapprove": 0}
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate over results: %v", err)
		}

		var vote Vote
		err = json.Unmarshal(queryResponse.Value, &vote)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal vote: %v", err)
		}

		if vote.Approve {
			voteCounts["approve"]++
		} else {
			voteCounts["disapprove"]++
		}
	}

	return voteCounts, nil
}

// ListOrgsVoted lists all organizations that have voted along with their votes
func (s *VirusChaincode) ListOrgsVoted(ctx contractapi.TransactionContextInterface) ([]Vote, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get state by range: %v", err)
	}
	defer resultsIterator.Close()

	var orgVotes []Vote
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate over results: %v", err)
		}

		var vote Vote
		err = json.Unmarshal(queryResponse.Value, &vote)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal vote: %v", err)
		}

		orgVote := Vote{
			Org:     vote.Org,
			Approve: vote.Approve,
		}
		orgVotes = append(orgVotes, orgVote)
	}

	return orgVotes, nil
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
