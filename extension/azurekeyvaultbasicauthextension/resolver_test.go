// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvaultbasicauthextension

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKVClient struct {
	value string
	err   error
}

func (m *mockKVClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	if m.err != nil {
		return azsecrets.GetSecretResponse{}, m.err
	}
	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{Value: &m.value},
	}, nil
}

func newAZMockOutput(username, password string) string {
	data, _ := json.Marshal(map[string]string{"username": username, "password": password})
	return string(data)
}

func TestAzureResolver_Resolve(t *testing.T) {
	val := newAZMockOutput("alice", "s3cr3t")
	r := &azureSecretResolver{
		client:      &mockKVClient{value: val},
		secretName:  "my-creds",
		usernameKey: "username",
		passwordKey: "password",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "alice", username)
	assert.Equal(t, "s3cr3t", password)
}

func TestAzureResolver_CustomKeys(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"user": "bob", "pass": "hunter2"})
	r := &azureSecretResolver{
		client:      &mockKVClient{value: string(data)},
		secretName:  "my-creds",
		usernameKey: "user",
		passwordKey: "pass",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "bob", username)
	assert.Equal(t, "hunter2", password)
}

func TestAzureResolver_APIError(t *testing.T) {
	r := &azureSecretResolver{
		client:      &mockKVClient{err: errors.New("access denied")},
		secretName:  "my-creds",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetSecret")
}

func TestAzureResolver_NilValue(t *testing.T) {
	r := &azureSecretResolver{
		client:      &mockKVClient{}, // value is empty string, but we need nil Value
		secretName:  "my-creds",
		usernameKey: "username",
		passwordKey: "password",
	}
	// Override with a mock that returns nil Value
	r.client = &nilValueKVClient{}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

func TestAzureResolver_InvalidJSON(t *testing.T) {
	r := &azureSecretResolver{
		client:      &mockKVClient{value: "not-json"},
		secretName:  "my-creds",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestAzureResolver_MissingKey(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"username": "alice"})
	r := &azureSecretResolver{
		client:      &mockKVClient{value: string(data)},
		secretName:  "my-creds",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"password"`)
}

// nilValueKVClient returns a response with nil Value.
type nilValueKVClient struct{}

func (m *nilValueKVClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{Value: nil},
	}, nil
}
