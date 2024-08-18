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

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azivalidators "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/validators"
)

// generateAccountID generates a random account id.
func generateAccountID() int64 {
	const base = 100000000000
	const maxRange = 900000000000
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Int63n(maxRange)
	accountID := base + randomNumber
	return accountID
}

// UpsertAccount creates or updates an account.
func UpsertAccount(tx *sql.Tx, isCreate bool, account *Account) (*Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: account is nil.")
	}
	if !isCreate {
		if err := azivalidators.ValidateAccountID("account", account.AccountID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", account.AccountID))
		}
	}
	if err := azivalidators.ValidateName("account", account.Name); err != nil {
		if account.AccountID == 0 {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s (it is required to be lower case).", account.Name))
		} else {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s for account id %d (it is required to be lower case).", account.Name, account.AccountID))
		}
	}
	var accountID int64
	if isCreate {
		accountID = generateAccountID()
		accountName := account.Name
		result, err := tx.Exec("INSERT INTO accounts (account_id, name) VALUES (?, ?)", accountID, accountName)
		if err != nil || result == nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be created.")
		}
	} else {
		accountID = account.AccountID
		accountName := account.Name
		result, err := tx.Exec("UPDATE accounts SET name = ? WHERE account_id = ?", accountName, accountID)
		if err != nil || result == nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be updated.")
		}
	}
	var dbAccount Account
	err := tx.QueryRow("SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = ?", accountID).Scan(
		&dbAccount.AccountID,
		&dbAccount.CreatedAt,
		&dbAccount.UpdatedAt,
		&dbAccount.Name,
	)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account upsert has failed.")

	}
	return &dbAccount, nil
}

// DeleteAccount deletes an account.
func DeleteAccount(db *sqlx.DB, accountID int64) (*Account, error) {
	if err := azivalidators.ValidateAccountID("account", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", accountID))
	}
	var dbAccount Account
	err := db.Get(&dbAccount, "SELECT * FROM accounts WHERE account_id = ?", accountID)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account to be deleted was not found.")
	}
	res, err := db.Exec("DELETE FROM accounts WHERE account_id = ?", accountID)
	if err != nil || res == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be deleted.")
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be deleted.")
	}
	return &dbAccount, nil
}

// FetchAccounts retrieves accounts.
func FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]Account, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, "storage: invalid page or page size.")
	}
	var dbAccounts []Account

	baseQuery := "SELECT * FROM accounts"
	var conditions []string
	var args []interface{}

	if filterID != nil {
		accountID := *filterID
		if err := azivalidators.ValidateAccountID("account", accountID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", accountID))
		}
		conditions = append(conditions, "account_id = ?")
		args = append(args, accountID)
	}

	if filterName != nil {
		accountName := *filterName
		if err := azivalidators.ValidateName("account", accountName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s (it is required to be lower case).", accountName))
		}
		accountName = "%" + accountName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, accountName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY account_id"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbAccounts, baseQuery, args...)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be retrieved.")
	}

	return dbAccounts, nil
}
