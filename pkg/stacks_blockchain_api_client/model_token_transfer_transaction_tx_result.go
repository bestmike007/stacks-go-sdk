/*
Stacks Blockchain API

Welcome to the API reference overview for the [Stacks Blockchain API](https://docs.hiro.so/stacks-blockchain-api).        [Download Postman collection](https://hirosystems.github.io/stacks-blockchain-api/collection.json)

API version: v8.1.2
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package stacks_blockchain_api_client

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the TokenTransferTransactionTxResult type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &TokenTransferTransactionTxResult{}

// TokenTransferTransactionTxResult Result of the transaction. For contract calls, this will show the value returned by the call. For other transaction types, this will return a boolean indicating the success of the transaction.
type TokenTransferTransactionTxResult struct {
	// Hex string representing the value fo the transaction result
	Hex string `json:"hex"`
	// Readable string of the transaction result
	Repr string `json:"repr"`
}

type _TokenTransferTransactionTxResult TokenTransferTransactionTxResult

// NewTokenTransferTransactionTxResult instantiates a new TokenTransferTransactionTxResult object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTokenTransferTransactionTxResult(hex string, repr string) *TokenTransferTransactionTxResult {
	this := TokenTransferTransactionTxResult{}
	this.Hex = hex
	this.Repr = repr
	return &this
}

// NewTokenTransferTransactionTxResultWithDefaults instantiates a new TokenTransferTransactionTxResult object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTokenTransferTransactionTxResultWithDefaults() *TokenTransferTransactionTxResult {
	this := TokenTransferTransactionTxResult{}
	return &this
}

// GetHex returns the Hex field value
func (o *TokenTransferTransactionTxResult) GetHex() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Hex
}

// GetHexOk returns a tuple with the Hex field value
// and a boolean to check if the value has been set.
func (o *TokenTransferTransactionTxResult) GetHexOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Hex, true
}

// SetHex sets field value
func (o *TokenTransferTransactionTxResult) SetHex(v string) {
	o.Hex = v
}

// GetRepr returns the Repr field value
func (o *TokenTransferTransactionTxResult) GetRepr() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Repr
}

// GetReprOk returns a tuple with the Repr field value
// and a boolean to check if the value has been set.
func (o *TokenTransferTransactionTxResult) GetReprOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Repr, true
}

// SetRepr sets field value
func (o *TokenTransferTransactionTxResult) SetRepr(v string) {
	o.Repr = v
}

func (o TokenTransferTransactionTxResult) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o TokenTransferTransactionTxResult) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["hex"] = o.Hex
	toSerialize["repr"] = o.Repr
	return toSerialize, nil
}

func (o *TokenTransferTransactionTxResult) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"hex",
		"repr",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varTokenTransferTransactionTxResult := _TokenTransferTransactionTxResult{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varTokenTransferTransactionTxResult)

	if err != nil {
		return err
	}

	*o = TokenTransferTransactionTxResult(varTokenTransferTransactionTxResult)

	return err
}

type NullableTokenTransferTransactionTxResult struct {
	value *TokenTransferTransactionTxResult
	isSet bool
}

func (v NullableTokenTransferTransactionTxResult) Get() *TokenTransferTransactionTxResult {
	return v.value
}

func (v *NullableTokenTransferTransactionTxResult) Set(val *TokenTransferTransactionTxResult) {
	v.value = val
	v.isSet = true
}

func (v NullableTokenTransferTransactionTxResult) IsSet() bool {
	return v.isSet
}

func (v *NullableTokenTransferTransactionTxResult) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTokenTransferTransactionTxResult(val *TokenTransferTransactionTxResult) *NullableTokenTransferTransactionTxResult {
	return &NullableTokenTransferTransactionTxResult{value: val, isSet: true}
}

func (v NullableTokenTransferTransactionTxResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTokenTransferTransactionTxResult) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


