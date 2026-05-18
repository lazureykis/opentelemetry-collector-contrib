// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package secretsmanager provides a polling-based credential rotation mechanism
// for sourcing Basic Auth credentials from cloud secret stores.
package secretsmanager // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/secretsmanager"

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// SecretResolver fetches a username/password pair from a cloud secret store.
// Implementations are provided by each cloud-specific auth extension.
type SecretResolver interface {
	Resolve(ctx context.Context) (username, password string, err error)
}

type credentials struct {
	username string
	password string
}

// CredentialPoller polls a SecretResolver at a fixed interval and exposes the
// latest credentials via Username() and Password(). It satisfies the
// basicauth.CredentialProvider interface without importing that package.
type CredentialPoller struct {
	resolver        SecretResolver
	refreshInterval time.Duration
	creds           atomic.Pointer[credentials]
	shutdownCh      chan struct{}
	doneCh          chan struct{}
	logger          *zap.Logger
}

// NewCredentialPoller creates a CredentialPoller. Call Start to begin polling.
func NewCredentialPoller(resolver SecretResolver, refreshInterval time.Duration, logger *zap.Logger) *CredentialPoller {
	return &CredentialPoller{
		resolver:        resolver,
		refreshInterval: refreshInterval,
		logger:          logger,
	}
}

// Start performs the initial secret fetch (failing fast on error) then launches
// the background polling goroutine.
func (p *CredentialPoller) Start(ctx context.Context) error {
	if p.refreshInterval <= 0 {
		return fmt.Errorf("refreshInterval must be positive, got %v", p.refreshInterval)
	}
	if p.shutdownCh != nil {
		return fmt.Errorf("CredentialPoller already started")
	}
	username, password, err := p.resolver.Resolve(ctx)
	if err != nil {
		return fmt.Errorf("initial secret fetch failed: %w", err)
	}
	p.creds.Store(&credentials{username: username, password: password})

	p.shutdownCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	go p.poll()
	return nil
}

// Shutdown stops the polling goroutine and waits for it to exit.
func (p *CredentialPoller) Shutdown() {
	if p.shutdownCh == nil {
		return
	}
	select {
	case <-p.shutdownCh:
		// already closed
	default:
		close(p.shutdownCh)
	}
	<-p.doneCh
}

// Username returns the current username. Safe for concurrent use.
func (p *CredentialPoller) Username() string {
	if c := p.creds.Load(); c != nil {
		return c.username
	}
	return ""
}

// Password returns the current password. Safe for concurrent use.
func (p *CredentialPoller) Password() string {
	if c := p.creds.Load(); c != nil {
		return c.password
	}
	return ""
}

func (p *CredentialPoller) poll() {
	defer close(p.doneCh)

	// Cancel in-flight Resolve calls when shutdown is requested.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-p.shutdownCh
		cancel()
	}()

	ticker := time.NewTicker(p.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.shutdownCh:
			return
		case <-ticker.C:
			username, password, err := p.resolver.Resolve(ctx)
			if err != nil {
				p.logger.Warn("failed to refresh credentials, keeping last known values", zap.Error(err))
				continue
			}
			old := p.creds.Load()
			if old != nil && old.username == username && old.password == password {
				continue
			}
			p.creds.Store(&credentials{username: username, password: password})
		}
	}
}
