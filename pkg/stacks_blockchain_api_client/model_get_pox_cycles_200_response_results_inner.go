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

// checks if the GetPoxCycles200ResponseResultsInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &GetPoxCycles200ResponseResultsInner{}

// GetPoxCycles200ResponseResultsInner struct for GetPoxCycles200ResponseResultsInner
type GetPoxCycles200ResponseResultsInner struct {
	BlockHeight int32 `json:"block_height"`
	IndexBlockHash string `json:"index_block_hash"`
	CycleNumber int32 `json:"cycle_number"`
	TotalWeight int32 `json:"total_weight"`
	TotalStackedAmount string `json:"total_stacked_amount"`
	TotalSigners int32 `json:"total_signers"`
}

type _GetPoxCycles200ResponseResultsInner GetPoxCycles200ResponseResultsInner

// NewGetPoxCycles200ResponseResultsInner instantiates a new GetPoxCycles200ResponseResultsInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetPoxCycles200ResponseResultsInner(blockHeight int32, indexBlockHash string, cycleNumber int32, totalWeight int32, totalStackedAmount string, totalSigners int32) *GetPoxCycles200ResponseResultsInner {
	this := GetPoxCycles200ResponseResultsInner{}
	this.BlockHeight = blockHeight
	this.IndexBlockHash = indexBlockHash
	this.CycleNumber = cycleNumber
	this.TotalWeight = totalWeight
	this.TotalStackedAmount = totalStackedAmount
	this.TotalSigners = totalSigners
	return &this
}

// NewGetPoxCycles200ResponseResultsInnerWithDefaults instantiates a new GetPoxCycles200ResponseResultsInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetPoxCycles200ResponseResultsInnerWithDefaults() *GetPoxCycles200ResponseResultsInner {
	this := GetPoxCycles200ResponseResultsInner{}
	return &this
}

// GetBlockHeight returns the BlockHeight field value
func (o *GetPoxCycles200ResponseResultsInner) GetBlockHeight() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.BlockHeight
}

// GetBlockHeightOk returns a tuple with the BlockHeight field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetBlockHeightOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.BlockHeight, true
}

// SetBlockHeight sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetBlockHeight(v int32) {
	o.BlockHeight = v
}

// GetIndexBlockHash returns the IndexBlockHash field value
func (o *GetPoxCycles200ResponseResultsInner) GetIndexBlockHash() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.IndexBlockHash
}

// GetIndexBlockHashOk returns a tuple with the IndexBlockHash field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetIndexBlockHashOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.IndexBlockHash, true
}

// SetIndexBlockHash sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetIndexBlockHash(v string) {
	o.IndexBlockHash = v
}

// GetCycleNumber returns the CycleNumber field value
func (o *GetPoxCycles200ResponseResultsInner) GetCycleNumber() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.CycleNumber
}

// GetCycleNumberOk returns a tuple with the CycleNumber field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetCycleNumberOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CycleNumber, true
}

// SetCycleNumber sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetCycleNumber(v int32) {
	o.CycleNumber = v
}

// GetTotalWeight returns the TotalWeight field value
func (o *GetPoxCycles200ResponseResultsInner) GetTotalWeight() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.TotalWeight
}

// GetTotalWeightOk returns a tuple with the TotalWeight field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetTotalWeightOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TotalWeight, true
}

// SetTotalWeight sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetTotalWeight(v int32) {
	o.TotalWeight = v
}

// GetTotalStackedAmount returns the TotalStackedAmount field value
func (o *GetPoxCycles200ResponseResultsInner) GetTotalStackedAmount() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.TotalStackedAmount
}

// GetTotalStackedAmountOk returns a tuple with the TotalStackedAmount field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetTotalStackedAmountOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TotalStackedAmount, true
}

// SetTotalStackedAmount sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetTotalStackedAmount(v string) {
	o.TotalStackedAmount = v
}

// GetTotalSigners returns the TotalSigners field value
func (o *GetPoxCycles200ResponseResultsInner) GetTotalSigners() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.TotalSigners
}

// GetTotalSignersOk returns a tuple with the TotalSigners field value
// and a boolean to check if the value has been set.
func (o *GetPoxCycles200ResponseResultsInner) GetTotalSignersOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TotalSigners, true
}

// SetTotalSigners sets field value
func (o *GetPoxCycles200ResponseResultsInner) SetTotalSigners(v int32) {
	o.TotalSigners = v
}

func (o GetPoxCycles200ResponseResultsInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o GetPoxCycles200ResponseResultsInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["block_height"] = o.BlockHeight
	toSerialize["index_block_hash"] = o.IndexBlockHash
	toSerialize["cycle_number"] = o.CycleNumber
	toSerialize["total_weight"] = o.TotalWeight
	toSerialize["total_stacked_amount"] = o.TotalStackedAmount
	toSerialize["total_signers"] = o.TotalSigners
	return toSerialize, nil
}

func (o *GetPoxCycles200ResponseResultsInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"block_height",
		"index_block_hash",
		"cycle_number",
		"total_weight",
		"total_stacked_amount",
		"total_signers",
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

	varGetPoxCycles200ResponseResultsInner := _GetPoxCycles200ResponseResultsInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varGetPoxCycles200ResponseResultsInner)

	if err != nil {
		return err
	}

	*o = GetPoxCycles200ResponseResultsInner(varGetPoxCycles200ResponseResultsInner)

	return err
}

type NullableGetPoxCycles200ResponseResultsInner struct {
	value *GetPoxCycles200ResponseResultsInner
	isSet bool
}

func (v NullableGetPoxCycles200ResponseResultsInner) Get() *GetPoxCycles200ResponseResultsInner {
	return v.value
}

func (v *NullableGetPoxCycles200ResponseResultsInner) Set(val *GetPoxCycles200ResponseResultsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableGetPoxCycles200ResponseResultsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableGetPoxCycles200ResponseResultsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetPoxCycles200ResponseResultsInner(val *GetPoxCycles200ResponseResultsInner) *NullableGetPoxCycles200ResponseResultsInner {
	return &NullableGetPoxCycles200ResponseResultsInner{value: val, isSet: true}
}

func (v NullableGetPoxCycles200ResponseResultsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetPoxCycles200ResponseResultsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

