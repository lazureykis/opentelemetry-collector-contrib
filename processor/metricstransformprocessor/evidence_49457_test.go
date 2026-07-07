// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metricstransformprocessor

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/processor/processorhelper"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/metricstransformprocessor/internal/metadata"
)

// TestEvidence49457CombineDropsSummaryDatapoints documents that PR #49457, which adds a
// skip+warn guard for Summary metrics on the aggregate_labels / aggregate_label_values
// paths, leaves the identical silent data-loss bug on the `action: combine` path.
//
// A combine transform whose include-regex matches EXACTLY ONE Summary metric slips past the
// canBeCombined Summary guard (it only fires for len(metrics) > 1) and lands on
// groupMetrics -> aggregateutil.GroupDataPoints/MergeDataPoints, which have no
// MetricTypeSummary case. CopyMetricDetails builds an empty Summary and no datapoints are
// carried over -- the summary goes in with 2 datapoints and comes out with 0, no warning.
//
// This test PASSING (asserting 0 output datapoints) IS the silent data loss the PR's own
// changelog claims to fix, still present on the Combine path.
func TestEvidence49457CombineDropsSummaryDatapoints(t *testing.T) {
	in := metricBuilder(pmetric.MetricTypeSummary, "summary_metric", "label1").
		addSummaryDatapoint(1, 1, 10, 100, "value1").
		addSummaryDatapoint(1, 1, 20, 200, "value2").
		build()
	require.Equal(t, 2, in.Summary().DataPoints().Len(), "precondition: 2 input datapoints")

	transforms := []internalTransform{
		{
			MetricIncludeFilter: internalFilterRegexp{include: regexp.MustCompile("^summary_metric$")},
			Action:              Combine,
			NewName:             "combined",
		},
	}

	p := &metricsTransformProcessor{
		transforms: transforms,
		logger:     zap.NewExample(),
	}

	next := new(consumertest.MetricsSink)
	mtp, err := processorhelper.NewMetrics(
		t.Context(),
		processortest.NewNopSettings(metadata.Type),
		&Config{},
		next,
		p.processMetrics,
		processorhelper.WithCapabilities(consumerCapabilities))
	require.NoError(t, err)

	inMetrics := pmetric.NewMetrics()
	in.CopyTo(inMetrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty())

	require.NoError(t, mtp.ConsumeMetrics(t.Context(), inMetrics))

	got := next.AllMetrics()
	require.Len(t, got, 1)
	outMetrics := got[0].ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, outMetrics.Len())

	out := outMetrics.At(0)
	require.Equal(t, pmetric.MetricTypeSummary, out.Type())

	// SILENT DATA LOSS: 2 datapoints in, 0 out. This assertion PASSING documents the bug.
	assert.Equal(t, 0, out.Summary().DataPoints().Len(),
		"expected the Combine path to silently drop all Summary datapoints (the bug); "+
			"if this fails, the combine-path data loss has been fixed")
}
