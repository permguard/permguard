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
	"fmt"
	"strconv"

	"github.com/jmoiron/sqlx"

	"github.com/permguard/permguard/pkg/transport/models/pap"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"

	notpagstatemachines "github.com/permguard/permguard/internal/transport/notp/statemachines"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
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
	value, ok := ctx.Value(key)
	if !ok {
		var zero T
		return zero, false
	}

	switch v := value.(type) {
	case string:
		var zero T
		switch any(zero).(type) {
		case int:
			if num, err := strconv.Atoi(v); err == nil {
				return any(num).(T), true
			}
		case int64:
			if num, err := strconv.ParseInt(v, 10, 64); err == nil {
				return any(num).(T), true
			}
		default:
			if any(zero) == "" {
				return any(v).(T), true
			}
		}
	case T:
		return v, true
	}
	var zero T
	return zero, false
}

// GetObjectForType gets the object for the type.
func GetObjectForType[T any](objMng *objects.ObjectManager, obj *objects.Object) (*T, error) {
	objInfo, err := objMng.ObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	instance := objInfo.Instance()
	value, ok := instance.(*T)
	if !ok {
		return nil, fmt.Errorf("storage: invalid object type")
	}
	return value, nil
}

// readObject reads the object.
func (s SQLiteCentralStoragePAP) readObject(db *sqlx.DB, zoneID int64, oid string) (*objects.Object, error) {
	keyValue, errkey := s.sqlRepo.KeyValue(db, zoneID, oid)
	if errkey != nil || keyValue == nil || keyValue.Value == nil {
		return nil, nil
	}
	obj, err := objects.NewObject(keyValue.Value)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// extractMetaData extracts the meta data.
func (s SQLiteCentralStoragePAP) extractMetaData(ctx *notpstatemachines.HandlerContext) (int64, string) {
	zoneIDStr, _ := getFromHandlerContext[string](ctx, notpagstatemachines.ZoneIDKey)
	zoneID, err := strconv.ParseInt(zoneIDStr, 10, 64)
	if err != nil {
		return 0, ""
	}
	ledgerID, _ := getFromHandlerContext[string](ctx, notpagstatemachines.LedgerIDKey)
	return zoneID, ledgerID
}

// readLedgerFromHandlerContext reads the ledger from the handler context.
func (s SQLiteCentralStoragePAP) readLedgerFromHandlerContext(handlerCtx *notpstatemachines.HandlerContext) (*pap.Ledger, error) {
	zoneID, ledgerID := s.extractMetaData(handlerCtx)
	fields := map[string]any{
		pap.FieldLedgerLedgerID: ledgerID,
	}
	ledgers, err := s.FetchLedgers(1, 1, zoneID, fields)
	if err != nil {
		return nil, err
	}
	if len(ledgers) == 0 {
		return nil, fmt.Errorf("storage: ledger not found")
	}
	return &ledgers[0], nil
}
