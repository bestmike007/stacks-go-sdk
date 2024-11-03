/*
Stacks Blockchain API

Welcome to the API reference overview for the [Stacks Blockchain API](https://docs.hiro.so/stacks-blockchain-api).        [Download Postman collection](https://hirosystems.github.io/stacks-blockchain-api/collection.json)

API version: v7.14.1
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package stacks_blockchain_api_client

import (
	"encoding/json"
	"fmt"
)


// TokenTransferTransactionPostConditionsInner struct for TokenTransferTransactionPostConditionsInner
type TokenTransferTransactionPostConditionsInner struct {
	TokenTransferTransactionPostConditionsInnerAnyOf *TokenTransferTransactionPostConditionsInnerAnyOf
	TokenTransferTransactionPostConditionsInnerAnyOf1 *TokenTransferTransactionPostConditionsInnerAnyOf1
	TokenTransferTransactionPostConditionsInnerAnyOf2 *TokenTransferTransactionPostConditionsInnerAnyOf2
}

// Unmarshal JSON data into any of the pointers in the struct
func (dst *TokenTransferTransactionPostConditionsInner) UnmarshalJSON(data []byte) error {
	var err error
	// try to unmarshal JSON data into TokenTransferTransactionPostConditionsInnerAnyOf
	err = json.Unmarshal(data, &dst.TokenTransferTransactionPostConditionsInnerAnyOf);
	if err == nil {
		jsonTokenTransferTransactionPostConditionsInnerAnyOf, _ := json.Marshal(dst.TokenTransferTransactionPostConditionsInnerAnyOf)
		if string(jsonTokenTransferTransactionPostConditionsInnerAnyOf) == "{}" { // empty struct
			dst.TokenTransferTransactionPostConditionsInnerAnyOf = nil
		} else {
			return nil // data stored in dst.TokenTransferTransactionPostConditionsInnerAnyOf, return on the first match
		}
	} else {
		dst.TokenTransferTransactionPostConditionsInnerAnyOf = nil
	}

	// try to unmarshal JSON data into TokenTransferTransactionPostConditionsInnerAnyOf1
	err = json.Unmarshal(data, &dst.TokenTransferTransactionPostConditionsInnerAnyOf1);
	if err == nil {
		jsonTokenTransferTransactionPostConditionsInnerAnyOf1, _ := json.Marshal(dst.TokenTransferTransactionPostConditionsInnerAnyOf1)
		if string(jsonTokenTransferTransactionPostConditionsInnerAnyOf1) == "{}" { // empty struct
			dst.TokenTransferTransactionPostConditionsInnerAnyOf1 = nil
		} else {
			return nil // data stored in dst.TokenTransferTransactionPostConditionsInnerAnyOf1, return on the first match
		}
	} else {
		dst.TokenTransferTransactionPostConditionsInnerAnyOf1 = nil
	}

	// try to unmarshal JSON data into TokenTransferTransactionPostConditionsInnerAnyOf2
	err = json.Unmarshal(data, &dst.TokenTransferTransactionPostConditionsInnerAnyOf2);
	if err == nil {
		jsonTokenTransferTransactionPostConditionsInnerAnyOf2, _ := json.Marshal(dst.TokenTransferTransactionPostConditionsInnerAnyOf2)
		if string(jsonTokenTransferTransactionPostConditionsInnerAnyOf2) == "{}" { // empty struct
			dst.TokenTransferTransactionPostConditionsInnerAnyOf2 = nil
		} else {
			return nil // data stored in dst.TokenTransferTransactionPostConditionsInnerAnyOf2, return on the first match
		}
	} else {
		dst.TokenTransferTransactionPostConditionsInnerAnyOf2 = nil
	}

	return fmt.Errorf("data failed to match schemas in anyOf(TokenTransferTransactionPostConditionsInner)")
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src *TokenTransferTransactionPostConditionsInner) MarshalJSON() ([]byte, error) {
	if src.TokenTransferTransactionPostConditionsInnerAnyOf != nil {
		return json.Marshal(&src.TokenTransferTransactionPostConditionsInnerAnyOf)
	}

	if src.TokenTransferTransactionPostConditionsInnerAnyOf1 != nil {
		return json.Marshal(&src.TokenTransferTransactionPostConditionsInnerAnyOf1)
	}

	if src.TokenTransferTransactionPostConditionsInnerAnyOf2 != nil {
		return json.Marshal(&src.TokenTransferTransactionPostConditionsInnerAnyOf2)
	}

	return nil, nil // no data in anyOf schemas
}


type NullableTokenTransferTransactionPostConditionsInner struct {
	value *TokenTransferTransactionPostConditionsInner
	isSet bool
}

func (v NullableTokenTransferTransactionPostConditionsInner) Get() *TokenTransferTransactionPostConditionsInner {
	return v.value
}

func (v *NullableTokenTransferTransactionPostConditionsInner) Set(val *TokenTransferTransactionPostConditionsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableTokenTransferTransactionPostConditionsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableTokenTransferTransactionPostConditionsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTokenTransferTransactionPostConditionsInner(val *TokenTransferTransactionPostConditionsInner) *NullableTokenTransferTransactionPostConditionsInner {
	return &NullableTokenTransferTransactionPostConditionsInner{value: val, isSet: true}
}

func (v NullableTokenTransferTransactionPostConditionsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTokenTransferTransactionPostConditionsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

