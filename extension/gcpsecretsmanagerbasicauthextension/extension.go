// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gcpsecretsmanagerbasicauthextension

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
	_ extension.Extension      = (*gcpSecretsManagerBasicAuth)(nil)
	_ extensionauth.HTTPClient = (*gcpSecretsManagerBasicAuth)(nil)
	_ extensionauth.GRPCClient = (*gcpSecretsManagerBasicAuth)(nil)
)

type gcpSecretsManagerBasicAuth struct {
	cfg    *Config
	poller *internalsm.CredentialPoller
	logger *zap.Logger
}

func newExtension(cfg *Config, logger *zap.Logger) *gcpSecretsManagerBasicAuth {
	return &gcpSecretsManagerBasicAuth{cfg: cfg, logger: logger}
}

func (e *gcpSecretsManagerBasicAuth) Start(ctx context.Context, _ component.Host) error {
	resolver, err := newGCPSecretResolver(ctx, e.cfg.SecretName, e.cfg.usernameKey(), e.cfg.passwordKey())
	if err != nil {
		return err
	}
	e.poller = internalsm.NewCredentialPoller(resolver, e.cfg.refreshInterval(), e.logger)
	return e.poller.Start(ctx)
}

func (e *gcpSecretsManagerBasicAuth) Shutdown(_ context.Context) error {
	if e.poller != nil {
		e.poller.Shutdown()
	}
	return nil
}

func (e *gcpSecretsManagerBasicAuth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	if e.poller == nil {
		return nil, errors.New("extension not started")
	}
	return basicauth.NewRoundTripper(base, e.poller)
}

func (e *gcpSecretsManagerBasicAuth) PerRPCCredentials() (grpccreds.PerRPCCredentials, error) {
	if e.poller == nil {
		return nil, errors.New("extension not started")
	}
	return basicauth.NewPerRPCCredentials(e.poller)
}
