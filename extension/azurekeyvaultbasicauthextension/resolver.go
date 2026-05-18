// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvaultbasicauthextension

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type kvClient interface {
	GetSecret(ctx context.Context, secretName string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

type azureSecretResolver struct {
	client        kvClient
	secretName    string
	secretVersion string
	usernameKey   string
	passwordKey   string
}

func newAzureSecretResolver(vaultURL, secretName, secretVersion, usernameKey, passwordKey string) (*azureSecretResolver, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create Key Vault client: %w", err)
	}
	return &azureSecretResolver{
		client:        client,
		secretName:    secretName,
		secretVersion: secretVersion,
		usernameKey:   usernameKey,
		passwordKey:   passwordKey,
	}, nil
}

func (r *azureSecretResolver) Resolve(ctx context.Context) (string, string, error) {
	resp, err := r.client.GetSecret(ctx, r.secretName, r.secretVersion, nil)
	if err != nil {
		return "", "", fmt.Errorf("GetSecret: %w", err)
	}
	if resp.Value == nil {
		return "", "", fmt.Errorf("secret %q has no value", r.secretName)
	}

	var fields map[string]string
	if err := json.Unmarshal([]byte(*resp.Value), &fields); err != nil {
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
