// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awssecretsmanagerbasicauthextension

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

const defaultRefreshInterval = time.Hour

var _ component.Config = (*Config)(nil)

type Config struct {
	SecretARN       string        `mapstructure:"secret_arn"`
	Region          string        `mapstructure:"region"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
	UsernameKey     string        `mapstructure:"username_key"`
	PasswordKey     string        `mapstructure:"password_key"`
}

func (c *Config) Validate() error {
	if c.SecretARN == "" {
		return errors.New("secret_arn is required")
	}
	return nil
}

func (c *Config) usernameKey() string {
	if c.UsernameKey != "" {
		return c.UsernameKey
	}
	return "username"
}

func (c *Config) passwordKey() string {
	if c.PasswordKey != "" {
		return c.PasswordKey
	}
	return "password"
}

func (c *Config) refreshInterval() time.Duration {
	if c.RefreshInterval > 0 {
		return c.RefreshInterval
	}
	return defaultRefreshInterval
}
