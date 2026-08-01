// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tailsamplingprocessor

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/processor/processortest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor/internal/metadata"
)

// In the pebble tail storage backend, storage.Take's ONLY error return is
// db.DeleteRange(prefix, end, pebble.NoSync), and storage.Delete's only action
// is the same db.DeleteRange(prefix, end, pebble.NoSync) over the same range.
// So whatever makes Take fail makes the Delete inside dropTrace fail too.
//
// This test models that correlation, which the PR's own fake does not: it fails
// Take while leaving Delete succeeding, so the PR's
// "delete queue must be cleaned after Take failure" assertion is never exercised
// against the way the shipped backend actually fails.
func TestTakeErrorWithCorrelatedDeleteErrorStrandsDeleteQueue(t *testing.T) {
	enableTailStorageFeatureGateForTest(t)

	storageErr := errors.New("pebble DeleteRange error: pebble: closed")

	for _, tc := range []struct {
		name     string
		strategy samplingStrategy
		waitTick bool
	}{
		{name: "trace complete", strategy: samplingStrategyTraceComplete, waitTick: true},
		{name: "span ingest", strategy: samplingStrategySpanIngest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := newTestTSPController()
			sink := new(consumertest.TracesSink)

			cfg := Config{
				DecisionWait:     defaultTestDecisionWait,
				NumTraces:        defaultNumTraces,
				SamplingStrategy: tc.strategy,
				PolicyCfgs:       testPolicy,
				TailStorageID:    &testExtensionID,
				Options:          []Option{withTestController(controller)},
			}

			host := &extensionHost{
				extension: &extension{takeErr: storageErr, deleteErr: storageErr},
			}
			p, err := newTracesProcessor(t.Context(), processortest.NewNopSettings(metadata.Type), sink, cfg)
			require.NoError(t, err)
			require.NoError(t, p.Start(t.Context(), host))

			require.NoError(t, p.ConsumeTraces(t.Context(), simpleTraces()))
			if tc.waitTick {
				controller.waitForTick()
				controller.waitForTick()
			}

			require.NoError(t, p.Shutdown(t.Context()))

			tsp := p.(*tailSamplingSpanProcessor)
			assert.Positive(t, host.extension.takeCount, "tail storage Take must be exercised")
			assert.Positive(t, host.extension.deleteCount, "dropTrace must have re-issued the delete")
			assert.Empty(t, sink.AllTraces(), "trace must not be forwarded when tail storage Take fails")
			assert.Empty(t, tsp.idToTrace, "trace state must be dropped after Take failure")
			assert.Zero(t, tsp.deleteTraceQueue.Len(), "delete queue must be cleaned after Take failure")
		})
	}
}

// Under a sustained storage outage the stranded elements accumulate. dropTrace
// removes the idToTrace entry before its Delete fails, so len(idToTrace) never
// reaches NumTraces and waitForSpace -- the only path that reaps an orphaned
// queue element -- is never reached. deleteTraceQueue then grows without bound
// while idToTrace stays empty.
func TestTakeErrorWithCorrelatedDeleteErrorGrowsDeleteQueueUnbounded(t *testing.T) {
	enableTailStorageFeatureGateForTest(t)

	storageErr := errors.New("pebble DeleteRange error: pebble: closed")
	const traces = 500

	controller := newTestTSPController()
	sink := new(consumertest.TracesSink)

	cfg := Config{
		DecisionWait:     defaultTestDecisionWait,
		NumTraces:        defaultNumTraces,
		SamplingStrategy: samplingStrategySpanIngest,
		PolicyCfgs:       testPolicy,
		TailStorageID:    &testExtensionID,
		Options:          []Option{withTestController(controller)},
	}

	host := &extensionHost{
		extension: &extension{takeErr: storageErr, deleteErr: storageErr},
	}
	p, err := newTracesProcessor(t.Context(), processortest.NewNopSettings(metadata.Type), sink, cfg)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context(), host))

	for i := range traces {
		var id pcommon.TraceID
		id[0] = byte(i / 256)
		id[1] = byte(i % 256)
		id[15] = 1
		require.NoError(t, p.ConsumeTraces(t.Context(), simpleTracesWithID(id)))
	}

	require.NoError(t, p.Shutdown(t.Context()))

	tsp := p.(*tailSamplingSpanProcessor)
	t.Logf("NumTraces budget=%d idToTrace=%d deleteTraceQueue=%d",
		cfg.NumTraces, len(tsp.idToTrace), tsp.deleteTraceQueue.Len())
	assert.Empty(t, tsp.idToTrace, "memory budget stays empty, so overflow reaping never triggers")
	assert.Zero(t, tsp.deleteTraceQueue.Len(), "delete queue must not accumulate stranded elements")
}
