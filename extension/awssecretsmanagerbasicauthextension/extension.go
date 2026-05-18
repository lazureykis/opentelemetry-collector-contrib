// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awssecretsmanagerbasicauthextension

import (
	"context"
	"fmt"
	"net/http"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	grpccreds "google.golang.org/grpc/credentials"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/basicauth"
	internalsm "github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/secretsmanager"
)

var (
	_ extension.Extension      = (*awsSecretsManagerBasicAuth)(nil)
	_ extensionauth.HTTPClient = (*awsSecretsManagerBasicAuth)(nil)
	_ extensionauth.GRPCClient = (*awsSecretsManagerBasicAuth)(nil)
)

type awsSecretsManagerBasicAuth struct {
	cfg    *Config
	poller *internalsm.CredentialPoller
	logger *zap.Logger
}

func newExtension(cfg *Config, logger *zap.Logger) *awsSecretsManagerBasicAuth {
	return &awsSecretsManagerBasicAuth{cfg: cfg, logger: logger}
}

func (e *awsSecretsManagerBasicAuth) Start(ctx context.Context, _ component.Host) error {
	opts := []func(*awsconfig.LoadOptions) error{}
	if e.cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(e.cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	resolver := &awsSecretResolver{
		client:      awssm.NewFromConfig(awsCfg),
		secretARN:   e.cfg.SecretARN,
		usernameKey: e.cfg.usernameKey(),
		passwordKey: e.cfg.passwordKey(),
	}
	e.poller = internalsm.NewCredentialPoller(resolver, e.cfg.refreshInterval(), e.logger)
	return e.poller.Start(ctx)
}

func (e *awsSecretsManagerBasicAuth) Shutdown(_ context.Context) error {
	if e.poller != nil {
		e.poller.Shutdown()
	}
	return nil
}

func (e *awsSecretsManagerBasicAuth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	return basicauth.NewRoundTripper(base, e.poller)
}

func (e *awsSecretsManagerBasicAuth) PerRPCCredentials() (grpccreds.PerRPCCredentials, error) {
	return basicauth.NewPerRPCCredentials(e.poller)
}
