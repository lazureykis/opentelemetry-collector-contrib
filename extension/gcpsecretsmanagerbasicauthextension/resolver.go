// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gcpsecretsmanagerbasicauthextension

import (
	"context"
	"encoding/json"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// gcpSMClient is the testable subset — adapter hides the variadic gax.CallOption.
type gcpSMClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

// realClientAdapter wraps *secretmanager.Client to satisfy gcpSMClient.
type realClientAdapter struct {
	c *secretmanager.Client
}

func (a *realClientAdapter) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return a.c.AccessSecretVersion(ctx, req)
}

type gcpSecretResolver struct {
	client      gcpSMClient
	secretName  string
	usernameKey string
	passwordKey string
}

func newGCPSecretResolver(ctx context.Context, secretName, usernameKey, passwordKey string) (*gcpSecretResolver, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Secret Manager client: %w", err)
	}
	return &gcpSecretResolver{
		client:      &realClientAdapter{c: client},
		secretName:  secretName,
		usernameKey: usernameKey,
		passwordKey: passwordKey,
	}, nil
}

func (r *gcpSecretResolver) Resolve(ctx context.Context) (string, string, error) {
	resp, err := r.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: r.secretName,
	})
	if err != nil {
		return "", "", fmt.Errorf("AccessSecretVersion: %w", err)
	}

	var fields map[string]string
	if err := json.Unmarshal(resp.Payload.Data, &fields); err != nil {
		return "", "", fmt.Errorf("unmarshal secret JSON: %w", err)
	}

	username, ok := fields[r.usernameKey]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", r.usernameKey, r.secretName)
	}
	password, ok := fields[r.passwordKey]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", r.passwordKey, r.secretName)
	}
	return username, password, nil
}
