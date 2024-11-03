/*
Stacks Blockchain API

Testing StackingAPIService

*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech);

package stacks_blockchain_api_client

import (
	"context"
	"testing"

	"github.com/icon-project/stacks-go-sdk/pkg/stacks_blockchain_api_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_stacks_blockchain_api_client_StackingAPIService(t *testing.T) {

	configuration := stacks_blockchain_api_client.NewConfiguration()
	apiClient := stacks_blockchain_api_client.NewAPIClient(configuration)

	t.Run("Test StackingAPIService ExtendedV1PoxEventsGet", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var pox stacks_blockchain_api_client.ExtendedV1PoxEventsGetPoxParameter

		httpRes, err := apiClient.StackingAPI.ExtendedV1PoxEventsGet(context.Background(), pox).Execute()

		require.Nil(t, err)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test StackingAPIService ExtendedV1PoxStackerPrincipalGet", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var pox stacks_blockchain_api_client.ExtendedV1PoxEventsGetPoxParameter
		var principal stacks_blockchain_api_client.GetFilteredEventsAddressParameter

		httpRes, err := apiClient.StackingAPI.ExtendedV1PoxStackerPrincipalGet(context.Background(), pox, principal).Execute()

		require.Nil(t, err)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test StackingAPIService ExtendedV1PoxTxTxIdGet", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var pox stacks_blockchain_api_client.ExtendedV1PoxEventsGetPoxParameter
		var txId string

		httpRes, err := apiClient.StackingAPI.ExtendedV1PoxTxTxIdGet(context.Background(), pox, txId).Execute()

		require.Nil(t, err)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test StackingAPIService GetPoolDelegations", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var pox stacks_blockchain_api_client.ExtendedV1PoxEventsGetPoxParameter
		var poolPrincipal string

		resp, httpRes, err := apiClient.StackingAPI.GetPoolDelegations(context.Background(), pox, poolPrincipal).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

}