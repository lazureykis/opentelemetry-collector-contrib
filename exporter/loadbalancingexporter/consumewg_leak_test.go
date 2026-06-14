// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Reproduction for PR #48983 review: proves the traceID fast path leaks
// wrappedExporter.consumeWG when loadBalancer.exporterAndEndpoint errors partway
// through a batch (a backend that got consumeWG.Add(1) never gets Done()), so
// wrappedExporter.Shutdown -> consumeWG.Wait() hangs forever.
// Evidence branch only — not intended for upstream merge.

package loadbalancingexporter

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/loadbalancingexporter/internal/metadata"
)

type fakeTracesExp struct {
	component.StartFunc
	component.ShutdownFunc
}

func (fakeTracesExp) Capabilities() consumer.Capabilities                { return consumer.Capabilities{} }
func (fakeTracesExp) ConsumeTraces(context.Context, ptrace.Traces) error { return nil }

func findTID(t *testing.T, lb *loadBalancer, wantEndpoint string) pcommon.TraceID {
	t.Helper()
	for i := 0; i < 1_000_000; i++ {
		var tid [16]byte
		binary.BigEndian.PutUint64(tid[8:], uint64(i))
		if lb.ring.endpointFor(tid[:]) == wantEndpoint {
			return pcommon.TraceID(tid)
		}
	}
	t.Fatalf("no trace id routed to %q", wantEndpoint)
	return pcommon.TraceID{}
}

func makeTraces(tids ...pcommon.TraceID) ptrace.Traces {
	td := ptrace.NewTraces()
	ss := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
	for _, tid := range tids {
		ss.Spans().AppendEmpty().SetTraceID(tid)
	}
	return td
}

// waitCh returns a channel closed once wg.Wait() returns.
func waitCh(wg *sync.WaitGroup) chan struct{} {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	return done
}

func TestBug48983_ConsumeWGLeakOnResolveError(t *testing.T) {
	tb, err := metadata.NewTelemetryBuilder(componenttest.NewNopTelemetrySettings())
	require.NoError(t, err)

	// Ring knows two endpoints, but only "good" has a resolved exporter.
	// "missing" will make exporterAndEndpoint return an error.
	good := newWrappedExporter(fakeTracesExp{}, endpointWithPort("good"))
	lb := &loadBalancer{
		ring:      newHashRing([]string{"good", "missing"}),
		exporters: map[string]*wrappedExporter{endpointWithPort("good"): good},
	}
	e := &traceExporterImp{
		loadBalancer: lb,
		routingKey:   traceIDRouting,
		logger:       zap.NewNop(),
		telemetry:    tb,
	}

	tGood := findTID(t, lb, "good")
	tMissing := findTID(t, lb, "missing")

	// Control: both spans route to "good" -> Add(1) then Done() -> balanced,
	// so Wait() returns promptly.
	require.NoError(t, e.consumeTracesByID(context.Background(), makeTraces(tGood, tGood)))
	select {
	case <-waitCh(&good.consumeWG):
	case <-time.After(time.Second):
		t.Fatal("control: consumeWG should be balanced but Wait() blocked")
	}

	// Leak: "good" gets Add(1); then "missing" fails to resolve and the function
	// returns before the loop that calls Done() -> +1 leaked forever, so Shutdown's
	// consumeWG.Wait() would hang.
	err = e.consumeTracesByID(context.Background(), makeTraces(tGood, tMissing))
	require.Error(t, err)

	leaked := waitCh(&good.consumeWG)
	select {
	case <-leaked:
		t.Fatal("expected consumeWG to be leaked, but Wait() returned")
	case <-time.After(time.Second):
		// Still blocked after 1s == leaked. Bug proven.
	}

	// Cleanup: balance the leaked Add(1) so the helper goroutine exits (otherwise
	// goleak flags it — which is itself the Shutdown-hang this test demonstrates).
	good.consumeWG.Done()
	<-leaked
}
