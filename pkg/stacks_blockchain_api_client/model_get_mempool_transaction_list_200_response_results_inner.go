/*
Stacks Blockchain API

Welcome to the API reference overview for the [Stacks Blockchain API](https://docs.hiro.so/stacks-blockchain-api).        [Download Postman collection](https://hirosystems.github.io/stacks-blockchain-api/collection.json)

API version: v8.1.2
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package stacks_blockchain_api_client

import (
	"encoding/json"
	"fmt"
)


// GetMempoolTransactionList200ResponseResultsInner struct for GetMempoolTransactionList200ResponseResultsInner
type GetMempoolTransactionList200ResponseResultsInner struct {
	CoinbaseMempoolTransaction1 *CoinbaseMempoolTransaction1
	ContractCallMempoolTransaction1 *ContractCallMempoolTransaction1
	PoisonMicroblockMempoolTransaction1 *PoisonMicroblockMempoolTransaction1
	SmartContractMempoolTransaction1 *SmartContractMempoolTransaction1
	TenureChangeMempoolTransaction1 *TenureChangeMempoolTransaction1
	TokenTransferMempoolTransaction1 *TokenTransferMempoolTransaction1
}

// Unmarshal JSON data into any of the pointers in the struct
func (dst *GetMempoolTransactionList200ResponseResultsInner) UnmarshalJSON(data []byte) error {
	var err error
	// try to unmarshal JSON data into CoinbaseMempoolTransaction1
	err = json.Unmarshal(data, &dst.CoinbaseMempoolTransaction1);
	if err == nil {
		jsonCoinbaseMempoolTransaction1, _ := json.Marshal(dst.CoinbaseMempoolTransaction1)
		if string(jsonCoinbaseMempoolTransaction1) == "{}" { // empty struct
			dst.CoinbaseMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.CoinbaseMempoolTransaction1, return on the first match
		}
	} else {
		dst.CoinbaseMempoolTransaction1 = nil
	}

	// try to unmarshal JSON data into ContractCallMempoolTransaction1
	err = json.Unmarshal(data, &dst.ContractCallMempoolTransaction1);
	if err == nil {
		jsonContractCallMempoolTransaction1, _ := json.Marshal(dst.ContractCallMempoolTransaction1)
		if string(jsonContractCallMempoolTransaction1) == "{}" { // empty struct
			dst.ContractCallMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.ContractCallMempoolTransaction1, return on the first match
		}
	} else {
		dst.ContractCallMempoolTransaction1 = nil
	}

	// try to unmarshal JSON data into PoisonMicroblockMempoolTransaction1
	err = json.Unmarshal(data, &dst.PoisonMicroblockMempoolTransaction1);
	if err == nil {
		jsonPoisonMicroblockMempoolTransaction1, _ := json.Marshal(dst.PoisonMicroblockMempoolTransaction1)
		if string(jsonPoisonMicroblockMempoolTransaction1) == "{}" { // empty struct
			dst.PoisonMicroblockMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.PoisonMicroblockMempoolTransaction1, return on the first match
		}
	} else {
		dst.PoisonMicroblockMempoolTransaction1 = nil
	}

	// try to unmarshal JSON data into SmartContractMempoolTransaction1
	err = json.Unmarshal(data, &dst.SmartContractMempoolTransaction1);
	if err == nil {
		jsonSmartContractMempoolTransaction1, _ := json.Marshal(dst.SmartContractMempoolTransaction1)
		if string(jsonSmartContractMempoolTransaction1) == "{}" { // empty struct
			dst.SmartContractMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.SmartContractMempoolTransaction1, return on the first match
		}
	} else {
		dst.SmartContractMempoolTransaction1 = nil
	}

	// try to unmarshal JSON data into TenureChangeMempoolTransaction1
	err = json.Unmarshal(data, &dst.TenureChangeMempoolTransaction1);
	if err == nil {
		jsonTenureChangeMempoolTransaction1, _ := json.Marshal(dst.TenureChangeMempoolTransaction1)
		if string(jsonTenureChangeMempoolTransaction1) == "{}" { // empty struct
			dst.TenureChangeMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.TenureChangeMempoolTransaction1, return on the first match
		}
	} else {
		dst.TenureChangeMempoolTransaction1 = nil
	}

	// try to unmarshal JSON data into TokenTransferMempoolTransaction1
	err = json.Unmarshal(data, &dst.TokenTransferMempoolTransaction1);
	if err == nil {
		jsonTokenTransferMempoolTransaction1, _ := json.Marshal(dst.TokenTransferMempoolTransaction1)
		if string(jsonTokenTransferMempoolTransaction1) == "{}" { // empty struct
			dst.TokenTransferMempoolTransaction1 = nil
		} else {
			return nil // data stored in dst.TokenTransferMempoolTransaction1, return on the first match
		}
	} else {
		dst.TokenTransferMempoolTransaction1 = nil
	}

	return fmt.Errorf("data failed to match schemas in anyOf(GetMempoolTransactionList200ResponseResultsInner)")
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src *GetMempoolTransactionList200ResponseResultsInner) MarshalJSON() ([]byte, error) {
	if src.CoinbaseMempoolTransaction1 != nil {
		return json.Marshal(&src.CoinbaseMempoolTransaction1)
	}

	if src.ContractCallMempoolTransaction1 != nil {
		return json.Marshal(&src.ContractCallMempoolTransaction1)
	}

	if src.PoisonMicroblockMempoolTransaction1 != nil {
		return json.Marshal(&src.PoisonMicroblockMempoolTransaction1)
	}

	if src.SmartContractMempoolTransaction1 != nil {
		return json.Marshal(&src.SmartContractMempoolTransaction1)
	}

	if src.TenureChangeMempoolTransaction1 != nil {
		return json.Marshal(&src.TenureChangeMempoolTransaction1)
	}

	if src.TokenTransferMempoolTransaction1 != nil {
		return json.Marshal(&src.TokenTransferMempoolTransaction1)
	}

	return nil, nil // no data in anyOf schemas
}


type NullableGetMempoolTransactionList200ResponseResultsInner struct {
	value *GetMempoolTransactionList200ResponseResultsInner
	isSet bool
}

func (v NullableGetMempoolTransactionList200ResponseResultsInner) Get() *GetMempoolTransactionList200ResponseResultsInner {
	return v.value
}

func (v *NullableGetMempoolTransactionList200ResponseResultsInner) Set(val *GetMempoolTransactionList200ResponseResultsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableGetMempoolTransactionList200ResponseResultsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableGetMempoolTransactionList200ResponseResultsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetMempoolTransactionList200ResponseResultsInner(val *GetMempoolTransactionList200ResponseResultsInner) *NullableGetMempoolTransactionList200ResponseResultsInner {
	return &NullableGetMempoolTransactionList200ResponseResultsInner{value: val, isSet: true}
}

func (v NullableGetMempoolTransactionList200ResponseResultsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetMempoolTransactionList200ResponseResultsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


