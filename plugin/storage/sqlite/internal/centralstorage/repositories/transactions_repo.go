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

package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // SQLite driver

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// CreateTransaction inserts a new transaction with status pending.
func (r *Repository) CreateTransaction(ctx context.Context, tx *sql.Tx, txn *Transaction) error {
	if txn == nil || txn.TxID == "" {
		return fmt.Errorf("storage: invalid transaction: %w", azstorage.ErrInvalidInput)
	}
	_, err := tx.ExecContext(ctx,
		"INSERT INTO transactions (txid, ledger_id, zone_id, status) VALUES (?, ?, ?, ?)",
		txn.TxID, txn.LedgerID, txn.ZoneID, TxStatusPending,
	)
	if err != nil {
		return WrapSqliteError("failed to create transaction", err)
	}
	return nil
}

// UpdateTransactionStatus updates the status of a transaction.
func (r *Repository) UpdateTransactionStatus(ctx context.Context, tx *sql.Tx, txid string, status string) error {
	if txid == "" {
		return fmt.Errorf("storage: invalid txid: %w", azstorage.ErrInvalidInput)
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE transactions SET status = ? WHERE txid = ?",
		status, txid,
	)
	if err != nil {
		return WrapSqliteError("failed to update transaction status", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return WrapSqliteError("failed to get rows affected for transaction status update", err)
	}
	if rows != 1 {
		return fmt.Errorf("transaction not found (txid: %s): %w", txid, azstorage.ErrNotFound)
	}
	return nil
}

// UpdateTransactionStatusNoTx updates the status of a transaction without a transaction.
func (r *Repository) UpdateTransactionStatusNoTx(ctx context.Context, db *sqlx.DB, txid string, status string) error {
	if txid == "" {
		return fmt.Errorf("storage: invalid txid: %w", azstorage.ErrInvalidInput)
	}
	result, err := db.ExecContext(ctx,
		"UPDATE transactions SET status = ? WHERE txid = ?",
		status, txid,
	)
	if err != nil {
		return WrapSqliteError("failed to update transaction status", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return WrapSqliteError("failed to get rows affected for transaction status update", err)
	}
	if rows != 1 {
		return fmt.Errorf("transaction not found (txid: %s): %w", txid, azstorage.ErrNotFound)
	}
	return nil
}

// GetTransaction retrieves a transaction by txid.
func (r *Repository) GetTransaction(ctx context.Context, db *sqlx.DB, txid string) (*Transaction, error) {
	if txid == "" {
		return nil, fmt.Errorf("storage: invalid txid: %w", azstorage.ErrInvalidInput)
	}
	var txn Transaction
	err := db.QueryRowContext(ctx,
		"SELECT txid, ledger_id, zone_id, started_at, status FROM transactions WHERE txid = ?",
		txid,
	).Scan(&txn.TxID, &txn.LedgerID, &txn.ZoneID, &txn.StartedAt, &txn.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("transaction not found (txid: %s): %w", txid, azstorage.ErrNotFound)
		}
		return nil, WrapSqliteError("failed to retrieve transaction", err)
	}
	return &txn, nil
}

// FetchStaleTransactions retrieves pending transactions older than the given threshold.
func (r *Repository) FetchStaleTransactions(ctx context.Context, db *sqlx.DB, olderThan time.Time) ([]Transaction, error) {
	var txs []Transaction
	err := db.SelectContext(ctx, &txs,
		"SELECT txid, ledger_id, zone_id, started_at, status FROM transactions WHERE status = ? AND started_at < ?",
		TxStatusPending, olderThan,
	)
	if err != nil {
		return nil, WrapSqliteError("failed to fetch stale transactions", err)
	}
	return txs, nil
}

// DeleteKeyValuesByTxID deletes all key-value pairs associated with the given txid and zone.
func (r *Repository) DeleteKeyValuesByTxID(ctx context.Context, tx *sql.Tx, zoneID int64, txid string) (int64, error) {
	if txid == "" {
		return 0, fmt.Errorf("storage: invalid txid: %w", azstorage.ErrInvalidInput)
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM key_values WHERE zone_id = ? AND txid = ?",
		zoneID, txid,
	)
	if err != nil {
		return 0, WrapSqliteError("failed to delete key values by txid", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, WrapSqliteError("failed to get rows affected for key values delete", err)
	}
	return rows, nil
}
