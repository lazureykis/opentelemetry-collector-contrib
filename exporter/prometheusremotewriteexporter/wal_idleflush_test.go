// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheusremotewriteexporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	remoteapi "github.com/prometheus/client_golang/exp/api/remote"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter/exportertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusremotewriteexporter/internal/metadata"
)

// TestExportWALFlushesBufferedDataWhenIdle reproduces the stall fixed by PR #49131.
//
// With BufferSize > 1, a number of buffered requests smaller than the buffer
// size never satisfies the size-based export condition
// (len(reqL) >= maxCountPerUpload) in continuallyPopWALThenExport. Such entries
// must therefore be flushed by the truncation timer. Before the fix,
// readPrompbFromWAL blocked indefinitely on rNotify once the WAL drained, so the
// loop never returned to evaluate the truncation timer — the buffered request
// was stuck until the next write arrived.
//
// Here we send exactly one metric with BufferSize=5, then let traffic go idle.
// The request must still be delivered (flushed by the timer) within a bounded
// time. On the pre-fix code this hangs and the assertion times out.
func TestExportWALFlushesBufferedDataWhenIdle(t *testing.T) {
	cfg := &Config{
		WAL: configoptional.Some(WALConfig{
			Directory: t.TempDir(),
			// > 1 so a single buffered request never hits the size-based
			// export condition and must rely on the truncation timer.
			BufferSize: 5,
			// Keep the test fast: readWaitTimeout is truncateFrequency/2.
			TruncateFrequency: 200 * time.Millisecond,
		}),
		RemoteWriteProtoMsg: remoteapi.WriteV1MessageType,
	}
	buildInfo := component.BuildInfo{
		Description: "OpenTelemetry Collector",
		Version:     "1.0",
	}
	set := exportertest.NewNopSettings(metadata.Type)
	set.BuildInfo = buildInfo

	requestsReceived := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requestsReceived.Add(1)
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.NotNil(t, body)
		writeReq := &prompb.WriteRequest{}
		var unzipped []byte
		dest, err := snappy.Decode(unzipped, body)
		assert.NoError(t, err)
		assert.NoError(t, proto.Unmarshal(dest, writeReq))
		assert.Len(t, writeReq.Timeseries, 1)
	}))
	defer server.Close()

	clientConfig := confighttp.NewDefaultClientConfig()
	clientConfig.Endpoint = server.URL
	cfg.ClientConfig = clientConfig

	require.NoError(t, cfg.Validate())

	prwe, err := newPRWExporter(cfg, set)
	require.NoError(t, err)
	require.NotNil(t, prwe)
	require.NoError(t, prwe.Start(t.Context(), componenttest.NewNopHost()))
	defer func() {
		require.NoError(t, prwe.Shutdown(t.Context()))
	}()

	metrics := map[string]*prompb.TimeSeries{
		"test_metric": {
			Labels:  []prompb.Label{{Name: "__name__", Value: "test_metric"}},
			Samples: []prompb.Sample{{Value: 1, Timestamp: 100}},
		},
	}
	require.NoError(t, prwe.handleExport(t.Context(), metrics, nil))

	// No further writes arrive. The single buffered request must still be
	// flushed by the truncation timer. Pre-fix, this never happens.
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Equal(t, int64(1), requestsReceived.Load())
	}, 3*time.Second, 20*time.Millisecond,
		"buffered WAL request was not flushed while idle (stall from #49130)")
}
