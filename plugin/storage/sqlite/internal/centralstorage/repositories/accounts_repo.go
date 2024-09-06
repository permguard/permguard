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
	"database/sql"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// GenerateAccountID generates a random account id.
func GenerateAccountID() int64 {
	const base = 100000000000
	const maxRange = 900000000000
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Int63n(maxRange)
	accountID := base + randomNumber
	return accountID
}

// UpsertAccount creates or updates an account.
func (r *Repo) UpsertAccount(tx *sql.Tx, isCreate bool, account *Account) (*Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - account data is missing or malformed (%s)", LogAccountEntry(account)))
	}
	if !isCreate && azvalidators.ValidateAccountID("account", account.AccountID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - account id is not valid (%s)", LogAccountEntry(account)))
	}
	if err := azvalidators.ValidateName("account", account.Name); err != nil {
		errorMessage := "storage: invalid client input - account name is not valid (%s)"
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogAccountEntry(account)))
	}

	accountID := account.AccountID
	accountName := account.Name
	var result sql.Result
	var err error
	if isCreate {
		accountID = GenerateAccountID()
		result, err = tx.Exec("INSERT INTO accounts (account_id, name) VALUES (?, ?)", accountID, accountName)
	} else {
		result, err = tx.Exec("UPDATE accounts SET name = ? WHERE account_id = ?", accountName, accountID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to %s account - operation '%s-account' encountered an issue (%s)", action, action, LogAccountEntry(account)), err)
	}

	var dbAccount Account
	err = tx.QueryRow("SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = ?", accountID).Scan(
		&dbAccount.AccountID,
		&dbAccount.CreatedAt,
		&dbAccount.UpdatedAt,
		&dbAccount.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve account - operation 'retrieve-created-account' encountered an issue (%s)", LogAccountEntry(account)), err)
	}
	return &dbAccount, nil
}

// DeleteAccount deletes an account.
func (r *Repo) DeleteAccount(tx *sql.Tx, accountID int64) (*Account, error) {
	if err := azvalidators.ValidateAccountID("account", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - account id is not valid (id: %d)", accountID))
	}

	var dbAccount Account
	err := tx.QueryRow("SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = ?", accountID).Scan(
		&dbAccount.AccountID,
		&dbAccount.CreatedAt,
		&dbAccount.UpdatedAt,
		&dbAccount.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - account id is not valid (id: %d)", accountID), err)
	}
	res, err := tx.Exec("DELETE FROM accounts WHERE account_id = ?", accountID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete account - operation 'delete-account' encountered an issue (id: %d)", accountID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete account - operation 'delete-account' encountered an issue (id: %d)", accountID), err)
	}
	return &dbAccount, nil
}

// FetchAccounts retrieves accounts.
func (r *Repo) FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]Account, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	var dbAccounts []Account

	baseQuery := "SELECT * FROM accounts"
	var conditions []string
	var args []interface{}

	if filterID != nil {
		accountID := *filterID
		if err := azvalidators.ValidateAccountID("account", accountID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - account id is not valid (id: %d)", accountID))
		}
		conditions = append(conditions, "account_id = ?")
		args = append(args, accountID)
	}

	if filterName != nil {
		accountName := *filterName
		if err := azvalidators.ValidateName("account", accountName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - account name is not valid (name: %s)", accountName))
		}
		accountName = "%" + accountName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, accountName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY account_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbAccounts, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve accounts - operation 'retrieve-accounts' encountered an issue with parameters %v", args), err)
	}

	return dbAccounts, nil
}
