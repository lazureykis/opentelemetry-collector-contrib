// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcp

// Repro for contrib PR #49199 (avoid emitting partial log after read error in
// tcp OneLogPerPacket mode).
//
// `io.Copy(&buf, conn)` blocks accumulating bytes and only returns when the
// connection terminates. A peer that closes with RST instead of FIN (e.g.
// SO_LINGER=0, load balancers, abrupt disconnect-after-send) makes io.Copy
// return an error even though `buf` already holds every byte the peer sent.
//
// PR #49199 discards the buffer on any read error, so a COMPLETE log from an
// RST-closing sender is silently dropped — not just "partial/corrupt" data.
//
// This test sends a complete payload, syncs so the server's io.Copy has read
// it, then RST-closes. It asserts the intact log is emitted, so it PASSES on
// main and FAILS on PR head e07f3aab.

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component/componenttest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/entry"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/testutil"
)

func TestTCPInput_OneLogPerPacket_CompleteLogRSTClose(t *testing.T) {
	const payload = "this is a complete log line"

	cfg := NewConfigWithID("test_id")
	cfg.ListenAddress = ":0"
	cfg.OneLogPerPacket = true

	set := componenttest.NewNopTelemetrySettings()
	op, err := cfg.Build(set)
	require.NoError(t, err)

	mockOutput := testutil.Operator{}
	tcpInput := op.(*Input)
	tcpInput.OutputOperators = []operator.Operator{&mockOutput}

	entryChan := make(chan *entry.Entry, 1)
	mockOutput.On("Process", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		entryChan <- args.Get(1).(*entry.Entry)
	}).Return(nil)

	require.NoError(t, tcpInput.Start(testutil.NewUnscopedMockPersister()))
	defer func() { require.NoError(t, tcpInput.Stop()) }()

	conn, err := net.Dial("tcp", tcpInput.listener.Addr().String())
	require.NoError(t, err)

	_, err = conn.Write([]byte(payload))
	require.NoError(t, err)

	// Let the server's io.Copy read the full payload into its buffer before the
	// RST arrives, so this is unambiguously a complete message, not a partial read.
	time.Sleep(250 * time.Millisecond)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		require.NoError(t, tcpConn.SetLinger(0)) // forces RST instead of FIN on close
	}
	require.NoError(t, conn.Close())

	select {
	case e := <-entryChan:
		require.Equal(t, payload, e.Body, "the complete log should be emitted intact")
	case <-time.After(2 * time.Second):
		t.Fatal("complete log was silently dropped after RST close (PR #49199 discards it)")
	}
}
