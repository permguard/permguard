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
	"fmt"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/attribute"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadKeyValue(ctx context.Context, s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) ([]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("storage: invalid database: %w", azstorage.ErrInternal)
	}
	if objMng == nil {
		return nil, fmt.Errorf("storage: invalid object manager: %w", azstorage.ErrInternal)
	}
	keyValue, err := s.sqlRepo.KeyValue(ctx, db, zoneID, key)
	if err != nil {
		return nil, err
	}
	if keyValue == nil {
		return nil, fmt.Errorf("storage: key value is nil: %w", azstorage.ErrNotFound)
	}
	return keyValue.Value, nil
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadBytes(ctx context.Context, s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) ([]byte, error) {
	value, err := authorizationCheckReadKeyValue(ctx, s, db, objMng, zoneID, key)
	if err != nil {
		return nil, err
	}
	object, err := objMng.DeserializeObjectFromBytes(value)
	if err != nil {
		return nil, err
	}
	_, instanceBytes, err := objMng.InstanceBytesFromBytes(object)
	return instanceBytes, err
}

// authorizationCheckReadTree reads the tree object for the authorization check.
func authorizationCheckReadTree(ctx context.Context, s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, commitID string) (*objects.Tree, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.ReadPolicyTree")
	defer span.End()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("commit_id", commitID))
	ocontent, err := authorizationCheckReadBytes(ctx, s, db, objMng, zoneID, commitID)
	if err != nil {
		return nil, err
	}
	commitObj, err := objMng.DeserializeCommit(ocontent)
	if err != nil {
		return nil, err
	}
	ocontent, err = authorizationCheckReadBytes(ctx, s, db, objMng, zoneID, commitObj.Tree().String())
	if err != nil {
		return nil, err
	}
	return objMng.DeserializeTree(ocontent)
}

// LoadPolicyStore loads the policy store for a given zone ID and store ID.
func (s SQLiteCentralStoragePDP) LoadPolicyStore(ctx context.Context, zoneID int64, storeID string) (*authzen.PolicyStore, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.LoadPolicyStore")
	defer span.End()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("store_id", storeID))
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}

	dbLedgers, err := s.sqlRepo.FetchLedgers(ctx, db, 1, 2, zoneID, &storeID, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: bad request for either zone id or policy store id: %w", err)
	}
	if len(dbLedgers) != 1 {
		return nil, fmt.Errorf("storage: bad request for either zone id or policy store id: %w", azstorage.ErrNotFound)
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == objects.ZeroOID {
		return nil, fmt.Errorf("storage: server couldn't validate the ledger reference: %w", azstorage.ErrInvalidInput)
	}

	authzPolicyStore := &authzen.PolicyStore{}
	authzPolicyStore.SetVersion(ledgerRef)

	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, fmt.Errorf("storage: server couldn't create the object manager: %w", azstorage.ErrInternal)
	}
	treeObj, err := authorizationCheckReadTree(ctx, &s, db, objMng, zoneID, ledgerRef)
	if err != nil {
		return nil, fmt.Errorf("storage: server couldn't read the tree: %w", err)
	}
	entries := treeObj.Entries()
	span.SetAttributes(attribute.Int("policy_entries", len(entries)))
	for _, entry := range entries {
		entryID := entry.OID()
		value, err2 := authorizationCheckReadKeyValue(ctx, &s, db, objMng, zoneID, entryID)
		if err2 != nil {
			return nil, fmt.Errorf("storage: server couldn't read the key %s: %w", entryID, err2)
		}
		obj, err3 := objMng.DeserializeObjectFromBytes(value)
		if err3 != nil {
			return nil, fmt.Errorf("storage: server couldn't deserialize the object from bytes: %w", err3)
		}
		objInfo, err4 := objMng.ObjectInfo(obj)
		if err4 != nil {
			return nil, fmt.Errorf("storage: server couldn't read object info: %w", err4)
		}
		objInfoHeader := objInfo.Header()
		oid := objInfo.OID()
		switch objInfoHeader.MetadataUint32(objects.MetaKeyCodeTypeID) {
		case types.ClassTypeSchemaID:
			authzPolicyStore.AddSchema(oid, objInfo)
		case types.ClassTypePolicyID:
			authzPolicyStore.AddPolicy(oid, objInfo)
		default:
			return nil, fmt.Errorf("storage: server couldn't process the code type id: %w", azstorage.ErrInternal)
		}
	}
	return authzPolicyStore, nil
}
