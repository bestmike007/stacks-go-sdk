/*
Stacks Blockchain API

Testing MicroblocksAPIService

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

func Test_stacks_blockchain_api_client_MicroblocksAPIService(t *testing.T) {

	configuration := stacks_blockchain_api_client.NewConfiguration()
	apiClient := stacks_blockchain_api_client.NewAPIClient(configuration)

	t.Run("Test MicroblocksAPIService GetMicroblockByHash", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var hash string

		resp, httpRes, err := apiClient.MicroblocksAPI.GetMicroblockByHash(context.Background(), hash).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test MicroblocksAPIService GetMicroblockList", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		resp, httpRes, err := apiClient.MicroblocksAPI.GetMicroblockList(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test MicroblocksAPIService GetUnanchoredTxs", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		resp, httpRes, err := apiClient.MicroblocksAPI.GetUnanchoredTxs(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

}