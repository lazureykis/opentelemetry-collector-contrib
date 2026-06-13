// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Reproduction for PR #48479 review: proves the hardcoded 64Ki element cap
// rejects a legitimate batch that is well within max_packed_forward_bytes, and
// that the rejection tears down the whole connection (no event delivered).
// Evidence branch only — not intended for upstream merge.

package fluentforwardreceiver

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/fluentforwardreceiver/internal/metadata"
)

// buildForwardMessage builds a valid Forward-mode message:
//
//	[ tag, [ [ts, {"log":"x"}], ... ] ]
//
// Every entry is well-formed and small — this is legitimate traffic, not a
// forged header.
func buildForwardMessage(tag string, numEntries int) []byte {
	var b []byte
	b = msgp.AppendArrayHeader(b, 2)
	b = msgp.AppendString(b, tag)
	b = msgp.AppendArrayHeader(b, uint32(numEntries))
	for i := 0; i < numEntries; i++ {
		b = msgp.AppendArrayHeader(b, 2)
		b = msgp.AppendInt64(b, 0)
		b = msgp.AppendMapHeader(b, 1)
		b = msgp.AppendString(b, "log")
		b = msgp.AppendString(b, "x")
	}
	return b
}

// Bug 1: the two limits contradict each other. A legitimate batch that fits
// comfortably inside the configured max_packed_forward_bytes (16 MiB) is still
// rejected, because the hardcoded 64Ki element cap rejects it first.
func TestBug48479_LegitBatchWithinByteLimitIsRejected(t *testing.T) {
	// Control: a batch at exactly the element cap decodes fine.
	okPayload := buildForwardMessage("my.tag", maxMsgpackElements)
	var ok forwardEventLogRecords
	require.NoError(t, ok.DecodeMsg(msgp.NewReader(bytes.NewReader(okPayload))))
	require.Equal(t, maxMsgpackElements, ok.LogRecordSlice.Len())

	// One more entry — still legitimate, still well-formed, still far under the
	// 16 MiB raw-byte budget the PR itself allows.
	payload := buildForwardMessage("my.tag", maxMsgpackElements+1)
	require.Less(t, len(payload), maxMsgpackRawBytes,
		"batch is within the configured max_packed_forward_bytes")

	// ...yet it is rejected.
	var fe forwardEventLogRecords
	err := fe.DecodeMsg(msgp.NewReader(bytes.NewReader(payload)))
	require.ErrorIs(t, err, msgp.ErrLimitExceeded)

	t.Logf("REJECTED legit batch: %d entries, payload=%.2f MiB, but raw limit=%d MiB (element cap=%d)",
		maxMsgpackElements+1, float64(len(payload))/(1024*1024),
		maxMsgpackRawBytes/(1024*1024), maxMsgpackElements)
}

// Bug 2: rejection tears down the entire connection — the whole batch is
// dropped (not skipped), and no event is delivered. handleConnections then
// conn.Close()s and the chunk is never acked, so a real sender resends the same
// batch -> reconnect/wedge loop with persistent data loss.
func TestBug48479_OversizedBatchTearsDownWholeConnection(t *testing.T) {
	tb, err := metadata.NewTelemetryBuilder(componenttest.NewNopTelemetrySettings())
	require.NoError(t, err)

	outCh := make(chan event, 1)
	s := newServer(outCh, zap.NewNop(), tb, maxMsgpackRawBytes)

	client, srv := net.Pipe()
	payload := buildForwardMessage("my.tag", maxMsgpackElements+1)
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = client.Write(payload)
	}()

	herr := s.handleConn(context.Background(), srv)

	require.Error(t, herr, "the whole connection handler aborts")
	require.ErrorIs(t, herr, msgp.ErrLimitExceeded)

	select {
	case <-outCh:
		t.Fatal("expected no event delivered: the entire batch is dropped, not skipped")
	default:
	}

	_ = client.Close()
	_ = srv.Close()
}
