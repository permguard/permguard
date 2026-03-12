// Copyright 2024 Nitro Agility S.r.l.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package centralstorage

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/telemetry"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// CleanupStaleTransactions cleans up stale pending transactions older than maxAge.
// Returns the number of transactions cleaned and total objects deleted.
func (s SQLiteCentralStoragePAP) CleanupStaleTransactions(ctx context.Context, maxAge time.Duration) (int, int64, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.CleanupStaleTransactions")
	defer span.End()
	telemetry.CleanupRunsTotal.Add(ctx, 1)
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return 0, 0, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	threshold := time.Now().Add(-maxAge)
	staleTxs, err := s.sqlRepo.FetchStaleTransactions(ctx, db, threshold)
	if err != nil {
		return 0, 0, err
	}
	if len(staleTxs) == 0 {
		return 0, 0, nil
	}
	cleaned := 0
	var totalDeleted int64
	for _, staleTx := range staleTxs {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return cleaned, totalDeleted, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
		}
		deleted, err := s.sqlRepo.DeleteKeyValuesByTxID(ctx, tx, staleTx.ZoneID, staleTx.TxID)
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				s.ctx.Logger().Warn("Cleanup: rollback failed after delete error",
					zap.String("txid", staleTx.TxID),
					zap.Int64("zone_id", staleTx.ZoneID),
					zap.Error(rbErr))
			}
			logger := s.ctx.Logger()
			logger.Error("Cleanup: failed to delete objects",
				zap.String("txid", staleTx.TxID),
				zap.Int64("zone_id", staleTx.ZoneID),
				zap.Error(err))
			continue
		}
		if err := s.sqlRepo.UpdateTransactionStatus(ctx, tx, staleTx.TxID, azrepos.TxStatusFailed); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				s.ctx.Logger().Warn("Cleanup: rollback failed after status update error",
					zap.String("txid", staleTx.TxID),
					zap.Int64("zone_id", staleTx.ZoneID),
					zap.Error(rbErr))
			}
			logger := s.ctx.Logger()
			logger.Error("Cleanup: failed to mark transaction as failed",
				zap.String("txid", staleTx.TxID),
				zap.Int64("zone_id", staleTx.ZoneID),
				zap.Error(err))
			continue
		}
		if err := tx.Commit(); err != nil {
			logger := s.ctx.Logger()
			logger.Error("Cleanup: failed to commit cleanup",
				zap.String("txid", staleTx.TxID),
				zap.Int64("zone_id", staleTx.ZoneID),
				zap.Error(err))
			continue
		}
		cleaned++
		totalDeleted += deleted
	}
	telemetry.CleanupTxCleanedTotal.Add(ctx, int64(cleaned))
	telemetry.CleanupObjDeletedTotal.Add(ctx, totalDeleted)
	span.SetAttributes(attribute.Int("cleaned", cleaned), attribute.Int64("deleted", totalDeleted))
	return cleaned, totalDeleted, nil
}
