// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvaultbasicauthextension

import (
	"context"
	"errors"
	"net/http"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	grpccreds "google.golang.org/grpc/credentials"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/basicauth"
	internalsm "github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/secretsmanager"
)

var (
	_ extension.Extension      = (*azureKeyVaultBasicAuth)(nil)
	_ extensionauth.HTTPClient = (*azureKeyVaultBasicAuth)(nil)
	_ extensionauth.GRPCClient = (*azureKeyVaultBasicAuth)(nil)
)

type azureKeyVaultBasicAuth struct {
	cfg    *Config
	poller *internalsm.CredentialPoller
	logger *zap.Logger
}

func newExtension(cfg *Config, logger *zap.Logger) *azureKeyVaultBasicAuth {
	return &azureKeyVaultBasicAuth{cfg: cfg, logger: logger}
}

func (e *azureKeyVaultBasicAuth) Start(ctx context.Context, _ component.Host) error {
	resolver, err := newAzureSecretResolver(
		e.cfg.VaultURL,
		e.cfg.SecretName,
		e.cfg.SecretVersion,
		e.cfg.usernameKey(),
		e.cfg.passwordKey(),
	)
	if err != nil {
		return err
	}
	e.poller = internalsm.NewCredentialPoller(resolver, e.cfg.refreshInterval(), e.logger)
	return e.poller.Start(ctx)
}

func (e *azureKeyVaultBasicAuth) Shutdown(_ context.Context) error {
	if e.poller != nil {
		e.poller.Shutdown()
	}
	return nil
}

func (e *azureKeyVaultBasicAuth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	if e.poller == nil {
		return nil, errors.New("extension not started")
	}
	return basicauth.NewRoundTripper(base, e.poller)
}

func (e *azureKeyVaultBasicAuth) PerRPCCredentials() (grpccreds.PerRPCCredentials, error) {
	if e.poller == nil {
		return nil, errors.New("extension not started")
	}
	return basicauth.NewPerRPCCredentials(e.poller)
}
