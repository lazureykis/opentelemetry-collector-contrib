// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Evidence for PR #46659 review (not for upstream merge).
//
// Demonstrates that the new top-level fail_on_missing_metadata flag, because it is
// passed verbatim to every configured detector, turns a benign multi-detector config
// into a hard startup failure. Detectors for a platform the collector is NOT running on
// (e.g. azure/ecs/lambda/eks when on a different cloud) cannot tell "not on this platform"
// apart from "metadata temporarily unreachable" — the PR's own README admits ECS/Lambda/EKS
// "return an error ... (not running on X)". errors.Join then propagates that single error
// through Refresh (prev == nil on first Start, so the keep-previous-snapshot guard is skipped)
// up to Start, which fails the component — and the whole collector — even though the detector
// for the cloud the collector IS on succeeded.

package internal

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

// healthyDetector models the cloud the collector IS running on: it always succeeds.
type healthyDetector struct{}

func (healthyDetector) Detect(_ context.Context, _ bool) (pcommon.Resource, string, error) {
	res := pcommon.NewResource()
	res.Attributes().PutStr("cloud.provider", "the-cloud-i-am-on")
	return res, "https://opentelemetry.io/schemas/1.6.1", nil
}

// notOnPlatformDetector models a detector for a platform the collector is NOT running on
// (azure/ecs/lambda/eks, etc.). With the flag off it returns an empty resource and no error
// (the historical "silently not on this cloud" behavior). With the flag on it returns an
// error — exactly what azure.go / ecs.go / lambda.go / eks detector.go now do.
type notOnPlatformDetector struct{}

func (notOnPlatformDetector) Detect(_ context.Context, failOnMissingMetadata bool) (pcommon.Resource, string, error) {
	if failOnMissingMetadata {
		return pcommon.NewResource(), "", errors.New("not running on this platform: metadata unavailable")
	}
	return pcommon.NewResource(), "", nil
}

func TestEvidence_FailOnMissingMetadata_MultiDetector_BreaksStartup(t *testing.T) {
	// Short client timeout bounds detectResource's retry/backoff loop so the failing
	// case returns promptly instead of retrying for the full default window.
	client := &http.Client{Timeout: 200 * time.Millisecond}

	t.Run("flag OFF: non-active-platform detector stays silent, collector starts", func(t *testing.T) {
		p := NewResourceProvider(zap.NewNop(), time.Second, false, healthyDetector{}, notOnPlatformDetector{})

		// Refresh is what Start() calls; a nil return means Start() succeeds.
		err := p.Refresh(t.Context(), client)
		require.NoError(t, err, "with the flag off, an inactive-platform detector must not break startup")

		res, _, getErr := p.Get(t.Context(), client)
		require.NoError(t, getErr)
		v, ok := res.Attributes().Get("cloud.provider")
		require.True(t, ok, "the active cloud must still be detected")
		assert.Equal(t, "the-cloud-i-am-on", v.Str())
	})

	t.Run("flag ON: same config now fails to start despite the active cloud succeeding", func(t *testing.T) {
		p := NewResourceProvider(zap.NewNop(), time.Second, true, healthyDetector{}, notOnPlatformDetector{})

		// Start() returns whatever Refresh() returns; a non-nil error here means the
		// component (and therefore the collector) fails to start.
		err := p.Refresh(t.Context(), client)
		require.Error(t, err, "regression: a detector for a platform we are not on fails the whole startup")
		assert.Contains(t, err.Error(), "not running on this platform")
	})
}
