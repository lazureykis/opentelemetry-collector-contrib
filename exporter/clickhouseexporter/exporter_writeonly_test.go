// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clickhouseexporter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

// countingBatch records each successful Send (i.e. a delivered INSERT batch).
type countingBatch struct{ sends *atomic.Int32 }

func (countingBatch) Abort() error                    { return nil }
func (countingBatch) Append(...any) error             { return nil }
func (countingBatch) AppendStruct(any) error          { return nil }
func (countingBatch) Column(int) driver.BatchColumn   { return nil }
func (countingBatch) Flush() error                    { return nil }
func (b countingBatch) Send() error                   { b.sends.Add(1); return nil }
func (countingBatch) IsSent() bool                    { return false }
func (countingBatch) Rows() int                       { return 0 }
func (countingBatch) Columns() []column.Interface     { return nil }
func (countingBatch) Close() error                    { return nil }

// writeOnlyConn models a least-privilege ClickHouse ingestion user: INSERT is
// granted (PrepareBatch + Send succeed) but SELECT/SHOW is denied, so the
// startup DESC TABLE probe (internal.GetTableColumns -> db.Query) fails
// permanently. This is a standard, recommended write-only grant for an
// ingestion pipeline.
type writeOnlyConn struct{ sends *atomic.Int32 }

var _ driver.Conn = writeOnlyConn{}

func (writeOnlyConn) Contributors() []string                        { return nil }
func (writeOnlyConn) ServerVersion() (*driver.ServerVersion, error) { return nil, nil }
func (writeOnlyConn) Select(context.Context, any, string, ...any) error {
	return errors.New("code: 497, message: not enough privileges: SELECT denied")
}
func (writeOnlyConn) Query(context.Context, string, ...any) (driver.Rows, error) {
	return nil, errors.New("code: 497, message: not enough privileges: SHOW COLUMNS denied")
}
func (writeOnlyConn) QueryRow(context.Context, string, ...any) driver.Row { return nil }
func (c writeOnlyConn) PrepareBatch(context.Context, string, ...driver.PrepareBatchOption) (driver.Batch, error) {
	return countingBatch{sends: c.sends}, nil
}
func (writeOnlyConn) Exec(context.Context, string, ...any) error              { return nil }
func (writeOnlyConn) AsyncInsert(context.Context, string, bool, ...any) error { return nil }
func (writeOnlyConn) Ping(context.Context) error                             { return nil }
func (writeOnlyConn) Stats() driver.Stats                                    { return driver.Stats{} }
func (writeOnlyConn) Close() error                                           { return nil }

func writeOnlyTestLogs() plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "svc")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.LogRecords().AppendEmpty().Body().SetStr("hello")
	return ld
}

// TestLogsExporter_WriteOnlyUserNeverDelivers demonstrates the regression in
// #48902 for a write-only ClickHouse user (INSERT granted, DESC/SELECT denied).
//
// The DESC failure is permanent (a privilege grant, not a transient outage), but
// the PR classifies every detection failure as a plain retryable error with no
// transient/permanent distinction. So every push defers, the INSERT is never
// rendered, and NOT ONE batch is ever delivered — the collector looks healthy
// and only emits a Debug log. With retry_on_failure (the recommended setting)
// each batch retries until max_elapsed_time, then drops: silent total data loss.
//
// Before this PR, start() rendered the (degraded) INSERT unconditionally even
// when DESC failed, so the same user kept delivering rows (without the optional
// columns). See exporter_logs.go start() on main:
//
//	err = e.detectSchemaFeatures(ctx)     // DESC fails, logged, ignored
//	if err := e.renderInsertLogsSQL(); ...  // INSERT rendered anyway -> writes
func TestLogsExporter_WriteOnlyUserNeverDelivers(t *testing.T) {
	cfg := withDefaultConfig()
	cfg.Endpoint = defaultEndpoint
	cfg.CreateSchema = false

	var sends atomic.Int32
	exp := newLogsExporter(zaptest.NewLogger(t), cfg)
	exp.db = writeOnlyConn{sends: &sends}

	ld := writeOnlyTestLogs()

	const batches = 50
	for i := range batches {
		err := exp.pushLogsData(t.Context(), ld)
		require.Errorf(t, err, "push %d: write-only user should keep deferring", i)
		require.Contains(t, err.Error(), "schema detection deferred")
	}

	require.Equal(t, int32(0), sends.Load(),
		"write-only user: not a single batch delivered after %d pushes (was degraded-but-delivered before #48902)", batches)
	require.Equal(t, schemaUnknown, schemaDetectionState(exp.detector.state.Load()))
	require.Empty(t, exp.insertSQL, "INSERT never rendered -> nothing can ever be written")
}
