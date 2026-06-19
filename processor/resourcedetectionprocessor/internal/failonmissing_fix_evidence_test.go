// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Fix verification for PR #46659 review (not for upstream merge).
//
// Companion to failonmissing_multidetector_evidence_test.go (which reproduced the bug). This
// proves the fix: a detector that cleanly determines it is NOT on its platform must return an
// empty resource with no error even when fail_on_missing_metadata is true, so it no longer
// tanks startup for a multi-detector config. Uses the *real* lambda detector (with
// AWS_LAMBDA_FUNCTION_NAME unset = not on Lambda) alongside a healthy detector for the cloud we
// are actually on; with the flag on, Refresh now succeeds and the active cloud is still detected.

package internal_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor/internal"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor/internal/aws/lambda"
)

// activeCloudDetector models the cloud the collector IS running on: always succeeds.
type activeCloudDetector struct{}

func (activeCloudDetector) Detect(_ context.Context, _ bool) (pcommon.Resource, string, error) {
	res := pcommon.NewResource()
	res.Attributes().PutStr("cloud.provider", "the-cloud-i-am-on")
	return res, "https://opentelemetry.io/schemas/1.6.1", nil
}

func TestEvidence_46659Fix_RealLambdaNotOnPlatform_DoesNotBreakStartup(t *testing.T) {
	// Guarantee we are not running on Lambda.
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	require.NoError(t, os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME"))

	lam, err := lambda.NewDetector(processortest.NewNopSettings(processortest.NopType), lambda.CreateDefaultConfig())
	require.NoError(t, err)

	// [active cloud, real lambda (not on Lambda)] with fail_on_missing_metadata = true.
	p := internal.NewResourceProvider(zap.NewNop(), time.Second, true, activeCloudDetector{}, lam)

	err = p.Refresh(t.Context(), &http.Client{Timeout: time.Second})
	require.NoError(t, err, "post-fix: lambda's not-on-platform negative must not fail startup with the flag on")

	res, _, getErr := p.Get(t.Context(), &http.Client{Timeout: time.Second})
	require.NoError(t, getErr)
	v, ok := res.Attributes().Get("cloud.provider")
	require.True(t, ok, "the active cloud must still be detected")
	assert.Equal(t, "the-cloud-i-am-on", v.Str())
}
