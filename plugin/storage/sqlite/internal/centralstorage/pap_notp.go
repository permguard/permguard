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
	"strconv"

	"github.com/jmoiron/sqlx"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"

	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpagstatemachines "github.com/permguard/permguard/internal/agents/notp/statemachines"
)

const (
	// LocalCommitIDKey is the local commit id key.
	LocalCommitIDKey = "local-commit-id"
	// RemoteCommitIDKey is the remote commit id key.
	RemoteCommitIDKey = "remote-commit-id"
	// TerminationKey is the termination key.
	TerminationKey = "termination"
	// DiffCommitIDsKey represents the diff commit ids key.
	DiffCommitIDsKey = "diff-commit-ids"
	// DiffCommitIDCursorKey represents the diff commit id cursor key.
	DiffCommitIDCursorKey = "diff-commit-id-cursor"
)

// getFromHandlerContext gets the value from the handler context.
func getFromHandlerContext[T any](ctx *notpstatemachines.HandlerContext, key string) (T, bool) {
	value, ok := ctx.Get(key)
	if !ok {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	if !ok {
		var zero T
		return zero, false
	}
	return typedValue, true
}

// GetObjectForType gets the object for the type.
func GetObjectForType[T any](objMng *azlangobjs.ObjectManager, obj *azlangobjs.Object) (*T, error) {
	objInfo, err := objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	instance := objInfo.GetInstance()
	value, ok := instance.(*T)
	if !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "storage: invalid object type")
	}
	return value, nil
}

// readObject reads the object.
func (s SQLiteCentralStoragePAP) readObject(db *sqlx.DB, oid string) (*azlangobjs.Object, error) {
	keyValue, errkey := s.sqlRepo.GetKeyValue(db, oid)
	if errkey != nil || keyValue == nil || keyValue.Value == nil {
		return nil, nil
	}
	obj, err := azlangobjs.NewObject(keyValue.Value)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// extractMetaData extracts the meta data.
func (s SQLiteCentralStoragePAP) extractMetaData(ctx *notpstatemachines.HandlerContext) (int64, string) {
	applicationIDStr, _ := getFromHandlerContext[string](ctx, notpagstatemachines.ApplicationIDKey)
	applicationID, err := strconv.ParseInt(applicationIDStr, 10, 64)
	if err != nil {
		return 0, ""
	}
	repoID, _ := getFromHandlerContext[string](ctx, notpagstatemachines.LedgerIDKey)
	return applicationID, repoID
}

// readLedgerFromHandlerContext reads the ledger from the handler context.
func (s SQLiteCentralStoragePAP) readLedgerFromHandlerContext(handlerCtx *notpstatemachines.HandlerContext) (*azmodels.Ledger, error) {
	applicationID, repoID := s.extractMetaData(handlerCtx)
	fields := map[string]any{
		azmodels.FieldLedgerLedgerID: repoID,
	}
	ledgers, err := s.FetchLedgers(1, 1, applicationID, fields)
	if err != nil {
		return nil, err
	}
	if len(ledgers) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: ledger not found.")
	}
	return &ledgers[0], nil
}
