/*
Stacks 2.0+ RPC API

This is the documentation for the `stacks-node` RPC interface. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package rpc_client

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the PostCallReadOnlyFnschema type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PostCallReadOnlyFnschema{}

// PostCallReadOnlyFnschema GET request to get contract source
type PostCallReadOnlyFnschema struct {
	Okay bool `json:"okay"`
	Result *string `json:"result,omitempty"`
	Cause *string `json:"cause,omitempty"`
}

type _PostCallReadOnlyFnschema PostCallReadOnlyFnschema

// NewPostCallReadOnlyFnschema instantiates a new PostCallReadOnlyFnschema object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPostCallReadOnlyFnschema(okay bool) *PostCallReadOnlyFnschema {
	this := PostCallReadOnlyFnschema{}
	this.Okay = okay
	return &this
}

// NewPostCallReadOnlyFnschemaWithDefaults instantiates a new PostCallReadOnlyFnschema object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPostCallReadOnlyFnschemaWithDefaults() *PostCallReadOnlyFnschema {
	this := PostCallReadOnlyFnschema{}
	return &this
}

// GetOkay returns the Okay field value
func (o *PostCallReadOnlyFnschema) GetOkay() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.Okay
}

// GetOkayOk returns a tuple with the Okay field value
// and a boolean to check if the value has been set.
func (o *PostCallReadOnlyFnschema) GetOkayOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Okay, true
}

// SetOkay sets field value
func (o *PostCallReadOnlyFnschema) SetOkay(v bool) {
	o.Okay = v
}

// GetResult returns the Result field value if set, zero value otherwise.
func (o *PostCallReadOnlyFnschema) GetResult() string {
	if o == nil || IsNil(o.Result) {
		var ret string
		return ret
	}
	return *o.Result
}

// GetResultOk returns a tuple with the Result field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PostCallReadOnlyFnschema) GetResultOk() (*string, bool) {
	if o == nil || IsNil(o.Result) {
		return nil, false
	}
	return o.Result, true
}

// HasResult returns a boolean if a field has been set.
func (o *PostCallReadOnlyFnschema) HasResult() bool {
	if o != nil && !IsNil(o.Result) {
		return true
	}

	return false
}

// SetResult gets a reference to the given string and assigns it to the Result field.
func (o *PostCallReadOnlyFnschema) SetResult(v string) {
	o.Result = &v
}

// GetCause returns the Cause field value if set, zero value otherwise.
func (o *PostCallReadOnlyFnschema) GetCause() string {
	if o == nil || IsNil(o.Cause) {
		var ret string
		return ret
	}
	return *o.Cause
}

// GetCauseOk returns a tuple with the Cause field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PostCallReadOnlyFnschema) GetCauseOk() (*string, bool) {
	if o == nil || IsNil(o.Cause) {
		return nil, false
	}
	return o.Cause, true
}

// HasCause returns a boolean if a field has been set.
func (o *PostCallReadOnlyFnschema) HasCause() bool {
	if o != nil && !IsNil(o.Cause) {
		return true
	}

	return false
}

// SetCause gets a reference to the given string and assigns it to the Cause field.
func (o *PostCallReadOnlyFnschema) SetCause(v string) {
	o.Cause = &v
}

func (o PostCallReadOnlyFnschema) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PostCallReadOnlyFnschema) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["okay"] = o.Okay
	if !IsNil(o.Result) {
		toSerialize["result"] = o.Result
	}
	if !IsNil(o.Cause) {
		toSerialize["cause"] = o.Cause
	}
	return toSerialize, nil
}

func (o *PostCallReadOnlyFnschema) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"okay",
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

	varPostCallReadOnlyFnschema := _PostCallReadOnlyFnschema{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varPostCallReadOnlyFnschema)

	if err != nil {
		return err
	}

	*o = PostCallReadOnlyFnschema(varPostCallReadOnlyFnschema)

	return err
}

type NullablePostCallReadOnlyFnschema struct {
	value *PostCallReadOnlyFnschema
	isSet bool
}

func (v NullablePostCallReadOnlyFnschema) Get() *PostCallReadOnlyFnschema {
	return v.value
}

func (v *NullablePostCallReadOnlyFnschema) Set(val *PostCallReadOnlyFnschema) {
	v.value = val
	v.isSet = true
}

func (v NullablePostCallReadOnlyFnschema) IsSet() bool {
	return v.isSet
}

func (v *NullablePostCallReadOnlyFnschema) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePostCallReadOnlyFnschema(val *PostCallReadOnlyFnschema) *NullablePostCallReadOnlyFnschema {
	return &NullablePostCallReadOnlyFnschema{value: val, isSet: true}
}

func (v NullablePostCallReadOnlyFnschema) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePostCallReadOnlyFnschema) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

