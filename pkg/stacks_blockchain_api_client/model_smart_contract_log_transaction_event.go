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

// checks if the SmartContractLogTransactionEvent type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SmartContractLogTransactionEvent{}

// SmartContractLogTransactionEvent Only present in `smart_contract` and `contract_call` tx types.
type SmartContractLogTransactionEvent struct {
	EventIndex int32 `json:"event_index"`
	EventType string `json:"event_type"`
	TxId string `json:"tx_id"`
	ContractLog SmartContractLogTransactionEventAllOfContractLog `json:"contract_log"`
}

type _SmartContractLogTransactionEvent SmartContractLogTransactionEvent

// NewSmartContractLogTransactionEvent instantiates a new SmartContractLogTransactionEvent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSmartContractLogTransactionEvent(eventIndex int32, eventType string, txId string, contractLog SmartContractLogTransactionEventAllOfContractLog) *SmartContractLogTransactionEvent {
	this := SmartContractLogTransactionEvent{}
	this.EventIndex = eventIndex
	this.EventType = eventType
	this.TxId = txId
	this.ContractLog = contractLog
	return &this
}

// NewSmartContractLogTransactionEventWithDefaults instantiates a new SmartContractLogTransactionEvent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSmartContractLogTransactionEventWithDefaults() *SmartContractLogTransactionEvent {
	this := SmartContractLogTransactionEvent{}
	return &this
}

// GetEventIndex returns the EventIndex field value
func (o *SmartContractLogTransactionEvent) GetEventIndex() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.EventIndex
}

// GetEventIndexOk returns a tuple with the EventIndex field value
// and a boolean to check if the value has been set.
func (o *SmartContractLogTransactionEvent) GetEventIndexOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.EventIndex, true
}

// SetEventIndex sets field value
func (o *SmartContractLogTransactionEvent) SetEventIndex(v int32) {
	o.EventIndex = v
}

// GetEventType returns the EventType field value
func (o *SmartContractLogTransactionEvent) GetEventType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.EventType
}

// GetEventTypeOk returns a tuple with the EventType field value
// and a boolean to check if the value has been set.
func (o *SmartContractLogTransactionEvent) GetEventTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.EventType, true
}

// SetEventType sets field value
func (o *SmartContractLogTransactionEvent) SetEventType(v string) {
	o.EventType = v
}

// GetTxId returns the TxId field value
func (o *SmartContractLogTransactionEvent) GetTxId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.TxId
}

// GetTxIdOk returns a tuple with the TxId field value
// and a boolean to check if the value has been set.
func (o *SmartContractLogTransactionEvent) GetTxIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TxId, true
}

// SetTxId sets field value
func (o *SmartContractLogTransactionEvent) SetTxId(v string) {
	o.TxId = v
}

// GetContractLog returns the ContractLog field value
func (o *SmartContractLogTransactionEvent) GetContractLog() SmartContractLogTransactionEventAllOfContractLog {
	if o == nil {
		var ret SmartContractLogTransactionEventAllOfContractLog
		return ret
	}

	return o.ContractLog
}

// GetContractLogOk returns a tuple with the ContractLog field value
// and a boolean to check if the value has been set.
func (o *SmartContractLogTransactionEvent) GetContractLogOk() (*SmartContractLogTransactionEventAllOfContractLog, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ContractLog, true
}

// SetContractLog sets field value
func (o *SmartContractLogTransactionEvent) SetContractLog(v SmartContractLogTransactionEventAllOfContractLog) {
	o.ContractLog = v
}

func (o SmartContractLogTransactionEvent) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SmartContractLogTransactionEvent) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["event_index"] = o.EventIndex
	toSerialize["event_type"] = o.EventType
	toSerialize["tx_id"] = o.TxId
	toSerialize["contract_log"] = o.ContractLog
	return toSerialize, nil
}

func (o *SmartContractLogTransactionEvent) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"event_index",
		"event_type",
		"tx_id",
		"contract_log",
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

	varSmartContractLogTransactionEvent := _SmartContractLogTransactionEvent{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varSmartContractLogTransactionEvent)

	if err != nil {
		return err
	}

	*o = SmartContractLogTransactionEvent(varSmartContractLogTransactionEvent)

	return err
}

type NullableSmartContractLogTransactionEvent struct {
	value *SmartContractLogTransactionEvent
	isSet bool
}

func (v NullableSmartContractLogTransactionEvent) Get() *SmartContractLogTransactionEvent {
	return v.value
}

func (v *NullableSmartContractLogTransactionEvent) Set(val *SmartContractLogTransactionEvent) {
	v.value = val
	v.isSet = true
}

func (v NullableSmartContractLogTransactionEvent) IsSet() bool {
	return v.isSet
}

func (v *NullableSmartContractLogTransactionEvent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSmartContractLogTransactionEvent(val *SmartContractLogTransactionEvent) *NullableSmartContractLogTransactionEvent {
	return &NullableSmartContractLogTransactionEvent{value: val, isSet: true}
}

func (v NullableSmartContractLogTransactionEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSmartContractLogTransactionEvent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

