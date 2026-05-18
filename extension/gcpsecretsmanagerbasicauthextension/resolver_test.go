// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gcpsecretsmanagerbasicauthextension

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGCPClient struct {
	payload []byte
	err     error
}

func (m *mockGCPClient) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: m.payload},
	}, nil
}

func newGCPMockOutput(username, password string) []byte {
	data, _ := json.Marshal(map[string]string{"username": username, "password": password})
	return data
}

func TestGCPResolver_Resolve(t *testing.T) {
	r := &gcpSecretResolver{
		client:      &mockGCPClient{payload: newGCPMockOutput("alice", "s3cr3t")},
		secretName:  "projects/my-project/secrets/my-creds/versions/latest",
		usernameKey: "username",
		passwordKey: "password",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "alice", username)
	assert.Equal(t, "s3cr3t", password)
}

func TestGCPResolver_CustomKeys(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"user": "bob", "pass": "hunter2"})
	r := &gcpSecretResolver{
		client:      &mockGCPClient{payload: data},
		secretName:  "projects/my-project/secrets/my-creds/versions/latest",
		usernameKey: "user",
		passwordKey: "pass",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "bob", username)
	assert.Equal(t, "hunter2", password)
}

func TestGCPResolver_APIError(t *testing.T) {
	r := &gcpSecretResolver{
		client:      &mockGCPClient{err: errors.New("permission denied")},
		secretName:  "projects/my-project/secrets/my-creds/versions/latest",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessSecretVersion")
}

func TestGCPResolver_InvalidJSON(t *testing.T) {
	r := &gcpSecretResolver{
		client:      &mockGCPClient{payload: []byte("not-json")},
		secretName:  "projects/my-project/secrets/my-creds/versions/latest",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestGCPResolver_MissingKey(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"username": "alice"})
	r := &gcpSecretResolver{
		client:      &mockGCPClient{payload: data},
		secretName:  "projects/my-project/secrets/my-creds/versions/latest",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"password"`)
}
