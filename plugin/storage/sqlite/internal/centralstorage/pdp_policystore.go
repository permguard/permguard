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
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadKeyValue(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) ([]byte, error) {
	if db == nil {
		return nil, errors.New("storage: invalid database")
	}
	if objMng == nil {
		return nil, errors.New("storage: invalid object manager")
	}
	keyValue, err := s.sqlRepo.KeyValue(db, zoneID, key)
	if err != nil {
		return nil, err
	}
	if keyValue == nil {
		return nil, errors.New("storage: key value is nil")
	}
	return keyValue.Value, nil
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadBytes(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) ([]byte, error) {
	value, err := authorizationCheckReadKeyValue(s, db, objMng, zoneID, key)
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
func authorizationCheckReadTree(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, commitID string) (*objects.Tree, error) {
	ocontent, err := authorizationCheckReadBytes(s, db, objMng, zoneID, commitID)
	if err != nil {
		return nil, err
	}
	commitObj, err := objMng.DeserializeCommit(ocontent)
	if err != nil {
		return nil, err
	}
	ocontent, err = authorizationCheckReadBytes(s, db, objMng, zoneID, commitObj.Tree())
	if err != nil {
		return nil, err
	}
	return objMng.DeserializeTree(ocontent)
}

// LoadPolicyStore loads the policy store for a given zone ID and store ID.
func (s SQLiteCentralStoragePDP) LoadPolicyStore(zoneID int64, storeID string) (*authzen.PolicyStore, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, errors.Join(errors.New("storage: server couldn't connect to the database"), err)
	}

	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, zoneID, &storeID, nil)
	if err != nil {
		return nil, errors.Join(errors.New("storage: bad request for either zone id or policy store id"), err)
	}
	if len(dbLedgers) != 1 {
		return nil, errors.Join(errors.New("storage: bad request for either zone id or policy store id"), err)
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == objects.ZeroOID {
		return nil, errors.Join(errors.New("storage: server couldn't validate the ledger reference"), err)
	}

	authzPolicyStore := &authzen.PolicyStore{}
	authzPolicyStore.SetVersion(ledgerRef)

	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, errors.Join(errors.New("storage: server couldn't create the object manager"), err)
	}
	treeObj, err := authorizationCheckReadTree(&s, db, objMng, zoneID, ledgerRef)
	if err != nil {
		return nil, errors.Join(errors.New("storage: server couldn't read the tree"), err)
	}
	for _, entry := range treeObj.Entries() {
		entryID := entry.OID()
		value, err2 := authorizationCheckReadKeyValue(&s, db, objMng, zoneID, entryID)
		if err2 != nil {
			return nil, errors.Join(fmt.Errorf("storage: server couldn't read the key %s", entryID), err2)
		}
		obj, err3 := objMng.DeserializeObjectFromBytes(value)
		if err3 != nil {
			return nil, errors.Join(errors.New("storage: server couldn't deserialize the object from bytes"), err3)
		}
		objInfo, err4 := objMng.ObjectInfo(obj)
		if err4 != nil {
			return nil, errors.Join(errors.New("storage: server couldn't read object info"), err4)
		}
		objInfoHeader := objInfo.Header()
		oid := objInfo.OID()
		switch objInfoHeader.CodeTypeID() {
		case types.ClassTypeSchemaID:
			authzPolicyStore.AddSchema(oid, objInfo)
		case types.ClassTypePolicyID:
			authzPolicyStore.AddPolicy(oid, objInfo)
		default:
			return nil, errors.New("storage: server couldn't process the code type id")
		}
	}
	return authzPolicyStore, nil
}
