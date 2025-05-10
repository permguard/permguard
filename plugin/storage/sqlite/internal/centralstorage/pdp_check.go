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

	"github.com/jmoiron/sqlx"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
	azplugincedar "github.com/permguard/permguard/plugin/languages/cedar"
	azauthzen "github.com/permguard/permguard/ztauthstar/pkg/authzen"
	azauthzlangtypes "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	azobjs "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// authorizationCheckBuildContextResponse builds the context response for the authorization check.
func authorizationCheckBuildContextResponse(authzDecision *azauthzen.AuthorizationDecision) *azmodelspdp.ContextResponse {
	ctxResponse := &azmodelspdp.ContextResponse{}
	ctxResponse.ID = authzDecision.GetID()

	adminError := authzDecision.GetAdminError()
	if adminError != nil {
		ctxResponse.ReasonAdmin = &azmodelspdp.ReasonResponse{
			Code:    adminError.GetCode(),
			Message: adminError.GetMessage(),
		}
	} else if authzDecision.GetDecision() == false {
		ctxResponse.ReasonAdmin = &azmodelspdp.ReasonResponse{
			Code:    azauthzen.AuthzErrInternalErrorCode,
			Message: azauthzen.AuthzErrInternalErrorMessage,
		}
	}

	userError := authzDecision.GetUserError()
	if userError != nil {
		ctxResponse.ReasonUser = &azmodelspdp.ReasonResponse{
			Code:    userError.GetCode(),
			Message: userError.GetMessage(),
		}
	} else if authzDecision.GetDecision() == false {
		ctxResponse.ReasonUser = &azmodelspdp.ReasonResponse{
			Code:    azauthzen.AuthzErrInternalErrorCode,
			Message: azauthzen.AuthzErrInternalErrorMessage,
		}
	}
	return ctxResponse
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadKeyValue(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azobjs.ObjectManager, zoneID int64, key string) ([]byte, error) {
	if db == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "invalid database")
	}
	if objMng == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "invalid object manager")
	}
	keyValue, err := s.sqlRepo.GetKeyValue(db, zoneID, key)
	if err != nil {
		return nil, err
	}
	if keyValue == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "key value is nil")
	}
	return keyValue.Value, nil
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadBytes(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azobjs.ObjectManager, zoneID int64, key string) (string, []byte, error) {
	value, err := authorizationCheckReadKeyValue(s, db, objMng, zoneID, key)
	if err != nil {
		return "", nil, err
	}
	object, err := objMng.DeserializeObjectFromBytes(value)
	if err != nil {
		return "", nil, err
	}
	objectType, instanceBytes, err := objMng.GetInstanceBytesFromBytes(object)
	return objectType, instanceBytes, err
}

// authorizationCheckReadTree reads the tree object for the authorization check.
func authorizationCheckReadTree(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azobjs.ObjectManager, zoneID int64, commitID string) (*azobjs.Tree, error) {
	_, ocontent, err := authorizationCheckReadBytes(s, db, objMng, zoneID, commitID)
	if err != nil {
		return nil, err
	}
	commitObj, err := objMng.DeserializeCommit(ocontent)
	if err != nil {
		return nil, err
	}
	_, ocontent, err = authorizationCheckReadBytes(s, db, objMng, zoneID, commitObj.GetTree())
	if err != nil {
		return nil, err
	}
	return objMng.DeserializeTree(ocontent)
}

// AuthorizationCheck performs the authorization check.
func (s SQLiteCentralStoragePDP) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckRequest) ([]azmodelspdp.EvaluationResponse, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrStorageGeneric, "server couldn't connect to the database", err)
	}

	authzCtx := request.AuthorizationModel
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, authzCtx.ZoneID, &authzCtx.PolicyStore.ID, nil)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguangeSemantic, "bad request for either zone id or policy store id", err)
	}
	if len(dbLedgers) != 1 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "bad request for either zone id or policy store id")
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == azobjs.ZeroOID {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't validate the ledger reference")
	}

	authzPolicyStore := azauthzen.PolicyStore{}
	authzPolicyStore.SetVersion(ledgerRef)

	objMng, err := azobjs.NewObjectManager()
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't create the object manager", err)
	}
	treeObj, err := authorizationCheckReadTree(&s, db, objMng, authzCtx.ZoneID, ledgerRef)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't read the tree", err)
	}
	for _, entry := range treeObj.GetEntries() {
		entryID := entry.GetOID()
		value, err := authorizationCheckReadKeyValue(&s, db, objMng, authzCtx.ZoneID, entryID)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, fmt.Sprintf("server couldn't read the key %s", entryID), err)
		}
		obj, err := objMng.DeserializeObjectFromBytes(value)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't deserialize the object from bytes", err)
		}
		objInfo, err := objMng.GetObjectInfo(obj)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't read object info", err)
		}
		objInfoHeader := objInfo.GetHeader()
		oid := objInfo.GetOID()
		if objInfoHeader.GetCodeTypeID() == azauthzlangtypes.ClassTypeSchemaID {
			authzPolicyStore.AddSchema(oid, objInfo)
		} else if objInfoHeader.GetCodeTypeID() == azauthzlangtypes.ClassTypePolicyID {
			authzPolicyStore.AddPolicy(oid, objInfo)
		} else {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't process the code type id")
		}
	}

	cedarLanguageAbs, err := azplugincedar.NewCedarLanguageAbstraction()
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrServerGeneric, "server couldn't validate the language abstraction layer", err)
	}

	evaluations := []azmodelspdp.EvaluationResponse{}
	for _, expandedRequest := range request.Evaluations {
		authzCtx := azauthzen.AuthorizationModel{}
		authzCtx.SetSubject(expandedRequest.Subject.Type, expandedRequest.Subject.ID, expandedRequest.Subject.Source, expandedRequest.Subject.Properties)
		authzCtx.SetResource(expandedRequest.Resource.Type, expandedRequest.Resource.ID, expandedRequest.Resource.Properties)
		authzCtx.SetAction(expandedRequest.Action.Name, expandedRequest.Action.Properties)
		authzCtx.SetContext(expandedRequest.Context)
		entities := request.AuthorizationModel.Entities
		if entities != nil {
			authzCtx.SetEntities(entities.Schema, entities.Items)
		}
		contextID := expandedRequest.ContextID
		//TODO: Fix manifest refactoring
		authzResponse, err := cedarLanguageAbs.AuthorizationCheck(nil, contextID, &authzPolicyStore, &authzCtx)
		if err != nil {
			evaluation := azmodelspdp.NewEvaluationErrorResponse(expandedRequest.RequestID, azauthzen.AuthzErrInternalErrorCode, err.Error(), azauthzen.AuthzErrInternalErrorMessage)
			evaluations = append(evaluations, *evaluation)
			continue
		}
		if authzResponse == nil {
			evaluation := azmodelspdp.NewEvaluationErrorResponse(expandedRequest.RequestID, azauthzen.AuthzErrInternalErrorCode, "because of a nil authz response", azauthzen.AuthzErrInternalErrorMessage)
			evaluations = append(evaluations, *evaluation)
			continue
		}
		evaluation := &azmodelspdp.EvaluationResponse{
			RequestID: expandedRequest.RequestID,
			Decision:  authzResponse.GetDecision(),
			Context:   authorizationCheckBuildContextResponse(authzResponse),
		}
		evaluations = append(evaluations, *evaluation)
	}
	return evaluations, nil
}
