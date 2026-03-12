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
	"database/sql"
	"errors"
	"fmt"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// rollback attempts to rollback a transaction and joins any rollback error with the original error.
func rollback(tx *sql.Tx, origErr error) error {
	if rbErr := tx.Rollback(); rbErr != nil {
		return errors.Join(origErr, fmt.Errorf("storage: rollback failed: %w", rbErr))
	}
	return origErr
}

// PushAdvertise handles the push advertise step.
// On success (no conflicts, not up-to-date), it generates a txid and creates a pending push transaction.
func (s SQLiteCentralStoragePAP) PushAdvertise(ctx context.Context, req *pap.PushAdvertiseRequest) (*pap.PushAdvertiseResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("storage: nil request: %w", azstorage.ErrInvalidInput)
	}
	if req.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid zone id: %w", azstorage.ErrInvalidInput)
	}
	if req.RefCommit == "" || req.RefPrevCommit == "" {
		return nil, fmt.Errorf("storage: invalid ref commit: %w", azstorage.ErrInvalidInput)
	}
	ledger, err := s.readLedger(ctx, req.ZoneID, req.LedgerID)
	if err != nil {
		return nil, err
	}
	headCommitID := ledger.Ref
	hasConflicts := false
	isUpToDate := false
	if headCommitID != objects.ZeroOID && headCommitID != req.RefPrevCommit {
		objMng, err := objects.NewObjectManager()
		if err != nil {
			return nil, err
		}
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
		}
		hasMatch, history, err := objMng.BuildCommitHistory(headCommitID, req.RefPrevCommit, false, func(oid string) (*objects.Object, error) {
			keyValue, errkey := s.sqlRepo.KeyValue(ctx, db, req.ZoneID, oid)
			if errkey != nil || keyValue == nil || keyValue.Value == nil {
				return nil, nil
			}
			return objects.NewObject(keyValue.Value)
		})
		if err != nil {
			return nil, err
		}
		hasConflicts = hasMatch && len(history) > 1
		if headCommitID != objects.ZeroOID && req.RefPrevCommit == objects.ZeroOID {
			hasConflicts = true
		}
		isUpToDate = headCommitID == req.RefCommit
	}

	// If push is allowed (no conflicts and not up-to-date), create a push transaction.
	var txid string
	if !hasConflicts && !isUpToDate {
		txid = azrepos.GenerateUUID()
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
		}
		pushTx := &azrepos.PushTransaction{
			TxID:     txid,
			LedgerID: req.LedgerID,
			ZoneID:   req.ZoneID,
		}
		if err := s.sqlRepo.CreatePushTransaction(ctx, tx, pushTx); err != nil {
			return nil, rollback(tx, err)
		}
		if err := tx.Commit(); err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
		}
		logger := s.ctx.Logger()
		logger.Info(fmt.Sprintf("Push session started (txid: %s, ledger: %s, zone: %d)", txid, req.LedgerID, req.ZoneID))
	}

	return &pap.PushAdvertiseResponse{
		TxID:         txid,
		ServerCommit: headCommitID,
		HasConflicts: hasConflicts,
		IsUpToDate:   isUpToDate,
	}, nil
}

// markPushFailed marks a push transaction as failed. It is best-effort and logs errors.
func (s SQLiteCentralStoragePAP) markPushFailed(ctx context.Context, txid string) {
	if txid == "" {
		return
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return
	}
	_ = s.sqlRepo.UpdatePushTransactionStatusNoTx(ctx, db, txid, azrepos.PushTxStatusFailed)
	logger := s.ctx.Logger()
	logger.Info(fmt.Sprintf("Push session failed (txid: %s)", txid))
}

// PushTransfer handles the push transfer step.
func (s SQLiteCentralStoragePAP) PushTransfer(ctx context.Context, req *pap.PushTransferRequest) (*pap.PushTransferResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("storage: nil request: %w", azstorage.ErrInvalidInput)
	}
	if req.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid zone id: %w", azstorage.ErrInvalidInput)
	}
	if req.TxID == "" {
		return nil, fmt.Errorf("storage: txid is required: %w", azstorage.ErrInvalidInput)
	}

	// Validate the push transaction exists and is pending.
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	pushTx, err := s.sqlRepo.GetPushTransaction(ctx, db, req.TxID)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid push transaction (txid: %s): %w", req.TxID, azstorage.ErrInvalidInput)
	}
	if pushTx.Status != azrepos.PushTxStatusPending {
		return nil, fmt.Errorf("storage: push transaction is not pending (txid: %s, status: %s): %w", req.TxID, pushTx.Status, azstorage.ErrInvalidInput)
	}

	// Validate transfer rate limits.
	var totalSize int64
	for _, obj := range req.Objects {
		totalSize += int64(len(obj.Content))
	}
	if err := objects.ValidateTransferLimits(len(req.Objects), totalSize, 0, 0); err != nil {
		s.markPushFailed(ctx, req.TxID)
		return nil, fmt.Errorf("storage: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		s.markPushFailed(ctx, req.TxID)
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	for _, obj := range req.Objects {
		if err := objects.VerifyOID(obj.OID, obj.Content); err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, fmt.Errorf("storage: received corrupted object %s: %w", obj.OID, err))
		}
		if err := objects.ValidateObjectSize(obj.Content, objects.DefaultMaxObjectSize); err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, fmt.Errorf("storage: received oversized object %s: %w", obj.OID, err))
		}
		keyValue := &azrepos.KeyValue{
			ZoneID: req.ZoneID,
			Key:    obj.OID,
			Value:  obj.Content,
		}
		_, err = s.sqlRepo.UpsertKeyValue(ctx, tx, keyValue, req.TxID)
		if err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, err)
		}
	}
	committed := false
	if req.IsLast {
		if req.ExpectedServerCommit == "" {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, fmt.Errorf("storage: expected server commit is required for final transfer: %w", azstorage.ErrInvalidInput))
		}
		// Verify graph integrity of the final commit before updating the ledger ref.
		objMng, err := objects.NewObjectManager()
		if err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, err)
		}
		if err := objMng.VerifyCommitGraphIntegrity(req.RemoteCommitID, func(oid string) (*objects.Object, error) {
			return s.readObjectTx(ctx, tx, req.ZoneID, oid)
		}); err != nil {
			_ = rollback(tx, nil)
			s.markPushFailed(ctx, req.TxID)
			return nil, fmt.Errorf("storage: graph integrity check failed: %w", err)
		}
		// Atomic commit: update key_values ref, update ledger ref+txid, mark push committed.
		err = s.sqlRepo.UpdateLedgerRef(ctx, tx, req.ZoneID, req.LedgerID, req.ExpectedServerCommit, req.RemoteCommitID, req.TxID)
		if err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err))
		}
		if err := s.sqlRepo.UpdatePushTransactionStatus(ctx, tx, req.TxID, azrepos.PushTxStatusCommitted); err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, rollback(tx, err)
		}
		if err := tx.Commit(); err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
		}
		committed = true
		logger := s.ctx.Logger()
		logger.Info(fmt.Sprintf("Push session committed (txid: %s, ledger: %s, zone: %d)", req.TxID, req.LedgerID, req.ZoneID))
	} else {
		if err := tx.Commit(); err != nil {
			s.markPushFailed(ctx, req.TxID)
			return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
		}
	}
	return &pap.PushTransferResponse{
		Committed: committed,
	}, nil
}
