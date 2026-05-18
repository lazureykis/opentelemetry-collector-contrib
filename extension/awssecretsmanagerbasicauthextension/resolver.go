// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awssecretsmanagerbasicauthextension

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type smClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type awsSecretResolver struct {
	client      smClient
	secretARN   string
	usernameKey string
	passwordKey string
}

func (r *awsSecretResolver) Resolve(ctx context.Context) (string, string, error) {
	resp, err := r.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(r.secretARN),
	})
	if err != nil {
		return "", "", fmt.Errorf("GetSecretValue: %w", err)
	}
	if resp.SecretString == nil {
		return "", "", fmt.Errorf("secret %q has no string value", r.secretARN)
	}

	var fields map[string]string
	if err := json.Unmarshal([]byte(*resp.SecretString), &fields); err != nil {
		return "", "", fmt.Errorf("unmarshal secret JSON: %w", err)
	}

	username, ok := fields[r.usernameKey]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", r.usernameKey, r.secretARN)
	}
	password, ok := fields[r.passwordKey]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", r.passwordKey, r.secretARN)
	}
	return username, password, nil
}
