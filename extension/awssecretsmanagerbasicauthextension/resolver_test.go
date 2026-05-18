// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awssecretsmanagerbasicauthextension

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSMClient struct {
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (m *mockSMClient) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.output, m.err
}

func newMockOutput(username, password string) *secretsmanager.GetSecretValueOutput {
	data, _ := json.Marshal(map[string]string{"username": username, "password": password})
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(string(data))}
}

func TestAWSResolver_Resolve(t *testing.T) {
	r := &awsSecretResolver{
		client:      &mockSMClient{output: newMockOutput("alice", "s3cr3t")},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "alice", username)
	assert.Equal(t, "s3cr3t", password)
}

func TestAWSResolver_CustomKeys(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"user": "bob", "pass": "hunter2"})
	r := &awsSecretResolver{
		client:      &mockSMClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(string(data))}},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "user",
		passwordKey: "pass",
	}
	username, password, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "bob", username)
	assert.Equal(t, "hunter2", password)
}

func TestAWSResolver_SDKError(t *testing.T) {
	r := &awsSecretResolver{
		client:      &mockSMClient{err: errors.New("access denied")},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetSecretValue")
}

func TestAWSResolver_NilSecretString(t *testing.T) {
	r := &awsSecretResolver{
		client:      &mockSMClient{output: &secretsmanager.GetSecretValueOutput{SecretString: nil}},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no string value")
}

func TestAWSResolver_MissingKey(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"username": "alice"})
	r := &awsSecretResolver{
		client:      &mockSMClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(string(data))}},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"password"`)
}

func TestAWSResolver_InvalidJSON(t *testing.T) {
	r := &awsSecretResolver{
		client:      &mockSMClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("not-json")}},
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	_, _, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}
