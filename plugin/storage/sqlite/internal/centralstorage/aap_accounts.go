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
	"database/sql"
	"fmt"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// CreateAccount creates a new account.
func (s SQLiteCentralStorageAAP) CreateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - account is nil.")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error("cannot connect.", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error("cannot open the transaction.", err)
	}
	dbInAccount := &azirepos.Account{
		AccountID: account.AccountID,
		Name:      account.Name,
	}
	dbOutaccount, err := s.sqlRepo.UpsertAccount(tx, true, dbInAccount)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error("cannot commit the transaction.", err)
	}
	return mapAccountToAgentAccount(dbOutaccount)
}

// UpdateAccount updates an account.
func (s SQLiteCentralStorageAAP) UpdateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - account is nil.")
	}
	execFunc := func(tx *sql.Tx, param interface{}) (interface{}, error) {
		inAccount, _ := param.(*azmodels.Account)
		dbaccount := &azirepos.Account{
			AccountID: inAccount.AccountID,
			Name:      inAccount.Name,
		}
		dbaccount, err := s.sqlRepo.UpsertAccount(tx, false, dbaccount)
		if err != nil {
			return nil, err
		}
		return mapAccountToAgentAccount(dbaccount)
	}
	result, err := s.sqlExec.ExecuteWithTransaction(s.ctx, s.sqliteConnector, execFunc, account)
	if err != nil {
		return nil, err
	}
	return result.(*azmodels.Account), nil
}

// DeleteAccount deletes an account.
func (s SQLiteCentralStorageAAP) DeleteAccount(accountID int64) (*azmodels.Account, error) {
	execFunc := func(tx *sql.Tx, param interface{}) (interface{}, error) {
		inAccountID, _ := param.(int64)
		dbaccount, err := s.sqlRepo.DeleteAccount(tx, inAccountID)
		if err != nil {
			return nil, err
		}
		return mapAccountToAgentAccount(dbaccount)
	}
	result, err := s.sqlExec.ExecuteWithTransaction(s.ctx, s.sqliteConnector, execFunc, accountID)
	if err != nil {
		return nil, err
	}
	return result.(*azmodels.Account), nil
}

// FetchAccounts returns all accounts.
func (s SQLiteCentralStorageAAP) FetchAccounts(page int32, pageSize int32, fields map[string]any) ([]azmodels.Account, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *int64
	if _, ok := fields[azmodels.FieldAccountAccountID]; ok {
		accountID, ok := fields[azmodels.FieldAccountAccountID].(int64)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - account id is not valid (account id: %d).", accountID))
		}
		filterID = &accountID
	}
	var filterName *string
	if _, ok := fields[azmodels.FieldAccountName]; ok {
		accountName, ok := fields[azmodels.FieldAccountName].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - account name is not valid (account name: %s).", accountName))
		}
		filterName = &accountName
	}
	dbAccounts, err := s.sqlRepo.FetchAccounts(db, page, pageSize, filterID, filterName)
	if err != nil {
		return nil, err
	}
	accounts := make([]azmodels.Account, len(dbAccounts))
	for i, a := range dbAccounts {
		account, err := mapAccountToAgentAccount(&a)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageEntityMapping, fmt.Sprintf("storage: failed to convert account entity (%s).", azirepos.LogAccountEntry(&a)))
		}
		accounts[i] = *account
	}
	return accounts, nil
}
