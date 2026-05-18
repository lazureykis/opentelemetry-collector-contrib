// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awssecretsmanagerbasicauthextension

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.uber.org/zap/zaptest"

	internalsm "github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/secretsmanager"
)

func newExtensionWithPoller(t *testing.T, username, password string) *awsSecretsManagerBasicAuth {
	t.Helper()
	mock := &mockSMClient{output: newMockOutput(username, password)}
	resolver := &awsSecretResolver{
		client:      mock,
		secretARN:   "arn:aws:secretsmanager:us-east-1:123:secret:test",
		usernameKey: "username",
		passwordKey: "password",
	}
	poller := internalsm.NewCredentialPoller(resolver, time.Hour, zaptest.NewLogger(t))
	require.NoError(t, poller.Start(context.Background()))
	t.Cleanup(poller.Shutdown)

	return &awsSecretsManagerBasicAuth{
		cfg:    &Config{SecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:test"},
		poller: poller,
		logger: zaptest.NewLogger(t),
	}
}

func TestExtension_RoundTripper(t *testing.T) {
	ext := newExtensionWithPoller(t, "alice", "s3cr3t")
	rt, err := ext.RoundTripper(http.DefaultTransport)
	require.NoError(t, err)
	require.NotNil(t, rt)
}

func TestExtension_PerRPCCredentials(t *testing.T) {
	ext := newExtensionWithPoller(t, "alice", "s3cr3t")
	creds, err := ext.PerRPCCredentials()
	require.NoError(t, err)
	require.NotNil(t, creds)
}

func TestExtension_AuthMethodsBeforeStart(t *testing.T) {
	ext := newExtension(&Config{SecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:test"}, zaptest.NewLogger(t))
	_, err := ext.RoundTripper(http.DefaultTransport)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not started")

	_, err = ext.PerRPCCredentials()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestExtension_ShutdownBeforeStart(t *testing.T) {
	ext := newExtension(&Config{SecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:test"}, zaptest.NewLogger(t))
	assert.NoError(t, ext.Shutdown(context.Background()))
}

func TestFactory_DefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NotNil(t, cfg)
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestFactory_CreateExtension(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.SecretARN = "arn:aws:secretsmanager:us-east-1:123:secret:test"
	ext, err := factory.Create(context.Background(), extensiontest.NewNopSettings(factory.Type()), cfg)
	require.NoError(t, err)
	require.NotNil(t, ext)
}
