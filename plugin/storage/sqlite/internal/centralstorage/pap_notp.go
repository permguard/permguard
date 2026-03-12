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
	"fmt"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/attribute"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// GetObjectForType gets the object for the type.
func GetObjectForType[T any](objMng *objects.ObjectManager, obj *objects.Object) (*T, error) {
	objInfo, err := objMng.ObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	instance := objInfo.Instance()
	value, ok := instance.(*T)
	if !ok {
		return nil, fmt.Errorf("storage: invalid object type: %w", azstorage.ErrInternal)
	}
	return value, nil
}

// readObject reads the object and verifies OID integrity.
func (s SQLiteCentralStoragePAP) readObject(ctx context.Context, db *sqlx.DB, zoneID int64, oid string) (*objects.Object, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.ReadObject")
	defer span.End()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("oid", oid))
	keyValue, errkey := s.sqlRepo.KeyValue(ctx, db, zoneID, oid)
	if errkey != nil || keyValue == nil || keyValue.Value == nil {
		return nil, nil
	}
	if err := objects.VerifyOID(oid, keyValue.Value); err != nil {
		return nil, fmt.Errorf("storage: corrupted object %s: %w", oid, err)
	}
	obj, err := objects.NewObject(keyValue.Value)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// readObjectTx reads the object within a transaction and verifies OID integrity.
func (s SQLiteCentralStoragePAP) readObjectTx(ctx context.Context, tx *sql.Tx, zoneID int64, oid string) (*objects.Object, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.ReadObjectTx")
	defer span.End()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("oid", oid))
	keyValue, errkey := s.sqlRepo.KeyValueTx(ctx, tx, zoneID, oid)
	if errkey != nil || keyValue == nil || keyValue.Value == nil {
		return nil, nil
	}
	if err := objects.VerifyOID(oid, keyValue.Value); err != nil {
		return nil, fmt.Errorf("storage: corrupted object %s: %w", oid, err)
	}
	obj, err := objects.NewObject(keyValue.Value)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// readLedger reads the ledger by zone ID and ledger ID.
func (s SQLiteCentralStoragePAP) readLedger(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.ReadLedger")
	defer span.End()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("ledger_id", ledgerID))
	fields := map[string]any{
		pap.FieldLedgerLedgerID: ledgerID,
	}
	ledgers, err := s.FetchLedgers(ctx, 1, 1, zoneID, fields)
	if err != nil {
		return nil, err
	}
	if len(ledgers) == 0 {
		return nil, fmt.Errorf("storage: ledger not found: %w", azstorage.ErrNotFound)
	}
	return &ledgers[0], nil
}
