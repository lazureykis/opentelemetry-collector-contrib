// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanager

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// staticResolver always returns the same credentials.
type staticResolver struct {
	username string
	password string
}

func (r *staticResolver) Resolve(_ context.Context) (string, string, error) {
	return r.username, r.password, nil
}

// rotatingResolver alternates between two sets of credentials on each call.
type rotatingResolver struct {
	call    atomic.Int32
	first   [2]string
	second  [2]string
}

func (r *rotatingResolver) Resolve(_ context.Context) (string, string, error) {
	if r.call.Add(1)%2 == 1 {
		return r.first[0], r.first[1], nil
	}
	return r.second[0], r.second[1], nil
}

// errorResolver fails after n successful calls.
type errorResolver struct {
	call    atomic.Int32
	succeed int32
}

func (r *errorResolver) Resolve(_ context.Context) (string, string, error) {
	if r.call.Add(1) <= r.succeed {
		return "user", "pass", nil
	}
	return "", "", errors.New("secret unavailable")
}

func newTestPoller(t *testing.T, resolver SecretResolver, interval time.Duration) *CredentialPoller {
	t.Helper()
	return NewCredentialPoller(resolver, interval, zaptest.NewLogger(t))
}

func TestCredentialPoller_InitialFetch(t *testing.T) {
	p := newTestPoller(t, &staticResolver{"alice", "secret"}, time.Hour)
	require.NoError(t, p.Start(t.Context()))
	defer p.Shutdown()

	assert.Equal(t, "alice", p.Username())
	assert.Equal(t, "secret", p.Password())
}

func TestCredentialPoller_InitialFetchFailure(t *testing.T) {
	resolver := &errorResolver{succeed: 0}
	p := newTestPoller(t, resolver, time.Hour)
	err := p.Start(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initial secret fetch failed")
}

func TestCredentialPoller_RotatesCredentials(t *testing.T) {
	resolver := &rotatingResolver{
		first:  [2]string{"alice", "pass1"},
		second: [2]string{"alice", "pass2"},
	}
	p := newTestPoller(t, resolver, 10*time.Millisecond)
	require.NoError(t, p.Start(t.Context()))
	defer p.Shutdown()

	assert.Eventually(t, func() bool {
		return p.Password() == "pass2"
	}, 2*time.Second, 5*time.Millisecond)
}

func TestCredentialPoller_ErrorResiliency(t *testing.T) {
	// Succeeds on first call (Start), then fails on all polls.
	resolver := &errorResolver{succeed: 1}
	p := newTestPoller(t, resolver, 10*time.Millisecond)
	require.NoError(t, p.Start(t.Context()))
	defer p.Shutdown()

	time.Sleep(50 * time.Millisecond)
	// Credentials from the initial fetch must be retained.
	assert.Equal(t, "user", p.Username())
	assert.Equal(t, "pass", p.Password())
}

func TestCredentialPoller_AtomicPair(t *testing.T) {
	resolver := &rotatingResolver{
		first:  [2]string{"alice", "pass1"},
		second: [2]string{"alice", "pass2"},
	}
	p := newTestPoller(t, resolver, 5*time.Millisecond)
	require.NoError(t, p.Start(t.Context()))
	defer p.Shutdown()

	for range 1000 {
		c := p.creds.Load()
		if c == nil {
			continue
		}
		assert.True(t,
			(c.username == "alice" && c.password == "pass1") ||
				(c.username == "alice" && c.password == "pass2"),
			"torn pair: %q / %q", c.username, c.password)
	}
}

func TestCredentialPoller_InvalidRefreshInterval(t *testing.T) {
	p := newTestPoller(t, &staticResolver{"u", "p"}, 0)
	err := p.Start(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refreshInterval must be positive")
}

func TestCredentialPoller_DoubleStart(t *testing.T) {
	p := newTestPoller(t, &staticResolver{"u", "p"}, time.Hour)
	require.NoError(t, p.Start(t.Context()))
	defer p.Shutdown()
	err := p.Start(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
}

func TestCredentialPoller_ShutdownIsIdempotent(t *testing.T) {
	p := newTestPoller(t, &staticResolver{"u", "p"}, time.Hour)
	require.NoError(t, p.Start(t.Context()))
	p.Shutdown()
	p.Shutdown() // must not panic
}
