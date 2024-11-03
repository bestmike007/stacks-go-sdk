/*
Stacks Blockchain API

Welcome to the API reference overview for the [Stacks Blockchain API](https://docs.hiro.so/stacks-blockchain-api).        [Download Postman collection](https://hirosystems.github.io/stacks-blockchain-api/collection.json)

API version: v7.14.1
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package stacks_blockchain_api_client

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the TransactionNotFound type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &TransactionNotFound{}

// TransactionNotFound This object returns the id for not found transaction
type TransactionNotFound struct {
	Found bool `json:"found"`
	Result TransactionNotFoundResult `json:"result"`
}

type _TransactionNotFound TransactionNotFound

// NewTransactionNotFound instantiates a new TransactionNotFound object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTransactionNotFound(found bool, result TransactionNotFoundResult) *TransactionNotFound {
	this := TransactionNotFound{}
	this.Found = found
	this.Result = result
	return &this
}

// NewTransactionNotFoundWithDefaults instantiates a new TransactionNotFound object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTransactionNotFoundWithDefaults() *TransactionNotFound {
	this := TransactionNotFound{}
	return &this
}

// GetFound returns the Found field value
func (o *TransactionNotFound) GetFound() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.Found
}

// GetFoundOk returns a tuple with the Found field value
// and a boolean to check if the value has been set.
func (o *TransactionNotFound) GetFoundOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Found, true
}

// SetFound sets field value
func (o *TransactionNotFound) SetFound(v bool) {
	o.Found = v
}

// GetResult returns the Result field value
func (o *TransactionNotFound) GetResult() TransactionNotFoundResult {
	if o == nil {
		var ret TransactionNotFoundResult
		return ret
	}

	return o.Result
}

// GetResultOk returns a tuple with the Result field value
// and a boolean to check if the value has been set.
func (o *TransactionNotFound) GetResultOk() (*TransactionNotFoundResult, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Result, true
}

// SetResult sets field value
func (o *TransactionNotFound) SetResult(v TransactionNotFoundResult) {
	o.Result = v
}

func (o TransactionNotFound) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o TransactionNotFound) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["found"] = o.Found
	toSerialize["result"] = o.Result
	return toSerialize, nil
}

func (o *TransactionNotFound) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"found",
		"result",
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

	varTransactionNotFound := _TransactionNotFound{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varTransactionNotFound)

	if err != nil {
		return err
	}

	*o = TransactionNotFound(varTransactionNotFound)

	return err
}

type NullableTransactionNotFound struct {
	value *TransactionNotFound
	isSet bool
}

func (v NullableTransactionNotFound) Get() *TransactionNotFound {
	return v.value
}

func (v *NullableTransactionNotFound) Set(val *TransactionNotFound) {
	v.value = val
	v.isSet = true
}

func (v NullableTransactionNotFound) IsSet() bool {
	return v.isSet
}

func (v *NullableTransactionNotFound) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTransactionNotFound(val *TransactionNotFound) *NullableTransactionNotFound {
	return &NullableTransactionNotFound{value: val, isSet: true}
}

func (v NullableTransactionNotFound) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTransactionNotFound) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

