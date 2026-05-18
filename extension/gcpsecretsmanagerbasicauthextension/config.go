// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gcpsecretsmanagerbasicauthextension

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

const defaultRefreshInterval = time.Hour

var _ component.Config = (*Config)(nil)

type Config struct {
	SecretName      string        `mapstructure:"secret_name"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
	UsernameKey     string        `mapstructure:"username_key"`
	PasswordKey     string        `mapstructure:"password_key"`
}

func (c *Config) Validate() error {
	if c.SecretName == "" {
		return errors.New("secret_name is required")
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
