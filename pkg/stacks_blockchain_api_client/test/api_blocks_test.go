/*
Stacks Blockchain API

Testing BlocksAPIService

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

func Test_stacks_blockchain_api_client_BlocksAPIService(t *testing.T) {

	configuration := stacks_blockchain_api_client.NewConfiguration()
	configuration.Servers = stacks_blockchain_api_client.ServerConfigurations{configuration.Servers[0]}
	apiClient := stacks_blockchain_api_client.NewAPIClient(configuration)
	height := uint64(1234)
	heightOrHash := stacks_blockchain_api_client.GetBlockHeightOrHashParameter{
		Uint64: &height,
	}

	t.Run("Test BlocksAPIService GetAverageBlockTimes", func(t *testing.T) {
		resp, httpRes, err := apiClient.BlocksAPI.GetAverageBlockTimes(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlock", func(t *testing.T) {
		resp, httpRes, err := apiClient.BlocksAPI.GetBlock(context.Background(), heightOrHash).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlockByBurnBlockHash", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var burnBlockHash string

		resp, httpRes, err := apiClient.BlocksAPI.GetBlockByBurnBlockHash(context.Background(), burnBlockHash).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlockByBurnBlockHeight", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var burnBlockHeight int32

		resp, httpRes, err := apiClient.BlocksAPI.GetBlockByBurnBlockHeight(context.Background(), burnBlockHeight).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlockByHash", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var hash string

		resp, httpRes, err := apiClient.BlocksAPI.GetBlockByHash(context.Background(), hash).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlockByHeight", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		var height int32

		resp, httpRes, err := apiClient.BlocksAPI.GetBlockByHeight(context.Background(), height).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlockList", func(t *testing.T) {

		t.Skip("skip test") // remove to run test

		resp, httpRes, err := apiClient.BlocksAPI.GetBlockList(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test BlocksAPIService GetBlocks", func(t *testing.T) {
		resp, httpRes, err := apiClient.BlocksAPI.GetBlocks(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

}
