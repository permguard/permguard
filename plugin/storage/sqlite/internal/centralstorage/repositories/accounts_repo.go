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
func UpsertAccount(db *sql.Tx, isCreate bool, account *Account) (*Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrInvalidInputParameter, "storage: account is nil.")
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
	// var dbAccount Account
	// var result *sqlx.DB
	// if isCreate {
	// 	dbAccount = Account{
	// 		AccountID: generateAccountID(),
	// 		Name:      account.Name,
	// 	}
	// 	result = db.Omit("CreatedAt", "UpdatedAt").Create(&dbAccount)
	// 	if result.RowsAffected == 0 || result.Error != nil {
	// 		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be created.")
	// 	}
	// } else {
	// 	result = db.Where("account_id = ?", account.AccountID).First(&dbAccount)
	// 	if result.RowsAffected == 0 {
	// 		return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be retrieved.")
	// 	}
	// 	dbAccount.Name = account.Name
	// 	result = db.Omit("CreatedAt", "UpdatedAt").Where("account_id = ?", account.AccountID).Updates(account)
	// 	if result.RowsAffected == 0 || result.Error != nil {
	// 		return nil, azerrors.WrapSystemError(azerrors.ErrStorageGeneric, "storage: account cannot be updated.")
	// 	}
	// }
	// return &dbAccount, nil
	return nil, nil
}

// DeleteAccount deletes an account.
func DeleteAccount(db *sqlx.DB, accountID int64) (*Account, error) {
	// if err := azivalidators.ValidateAccountID("account", accountID); err != nil {
	// 	return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", accountID))
	// }
	// var dbAccount Account
	// result := db.Where("account_id = ?", accountID).First(&dbAccount)
	// if result.RowsAffected == 0 {
	// 	return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be retrieved.")
	// }
	// result = db.Delete(dbAccount)
	// if result.RowsAffected == 0 || result.Error != nil {
	// 	return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be deleted.")
	// }
	// return &dbAccount, nil
	return nil, nil
}

// FetchAccounts retrieves accounts.
func FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]Account, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, "storage: invalid page or page size.")
	}
	var dbAccounts []Account

	limit := pageSize
	offset := (page - 1) * pageSize

	query := "SELECT * FROM accounts LIMIT ? OFFSET ?"
	err := db.Select(&dbAccounts, query, limit, offset)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be retrieved.")
	}

	return dbAccounts, nil
	// query := db
	// if filterID != nil {
	// 	accountID := *filterID
	// 	if err := azivalidators.ValidateAccountID("account", accountID); err != nil {
	// 		return nil, azerrors.WrapSystemError(azerrors.ErrClientAccountID, fmt.Sprintf("storage: invalid account id %d.", accountID))
	// 	}
	// 	query = query.Where("account_id = ?", accountID)
	// }
	// if filterName != nil {
	// 	accountName := *filterName
	// 	if err := azivalidators.ValidateName("account", accountName); err != nil {
	// 		return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid account name %s (it is required to be lower case).", accountName))
	// 	}
	// 	accountName = "%" + accountName + "%"
	// 	query = query.Where("name LIKE ?", accountName)
	// }
	// size := int(pageSize)
	// offset := int((page - 1) * pageSize)
	// result := query.Order("account_id asc").Limit(size).Offset(offset).Find(&dbAccounts)
	// if result.Error != nil {
	// 	return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, "storage: account cannot be retrieved.")
	// }
	// return dbAccounts, nil
}
