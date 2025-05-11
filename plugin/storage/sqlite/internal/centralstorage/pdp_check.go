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

	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/plugin/languages/cedar"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// authorizationCheckBuildContextResponse builds the context response for the authorization check.
func authorizationCheckBuildContextResponse(authzDecision *authzen.AuthorizationDecision) *pdp.ContextResponse {
	ctxResponse := &pdp.ContextResponse{}
	ctxResponse.ID = authzDecision.GetID()

	adminError := authzDecision.GetAdminError()
	if adminError != nil {
		ctxResponse.ReasonAdmin = &pdp.ReasonResponse{
			Code:    adminError.GetCode(),
			Message: adminError.GetMessage(),
		}
	} else if !authzDecision.GetDecision() {
		ctxResponse.ReasonAdmin = &pdp.ReasonResponse{
			Code:    authzen.AuthzErrInternalErrorCode,
			Message: authzen.AuthzErrInternalErrorMessage,
		}
	}

	userError := authzDecision.GetUserError()
	if userError != nil {
		ctxResponse.ReasonUser = &pdp.ReasonResponse{
			Code:    userError.GetCode(),
			Message: userError.GetMessage(),
		}
	} else if !authzDecision.GetDecision() {
		ctxResponse.ReasonUser = &pdp.ReasonResponse{
			Code:    authzen.AuthzErrInternalErrorCode,
			Message: authzen.AuthzErrInternalErrorMessage,
		}
	}
	return ctxResponse
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadKeyValue(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) ([]byte, error) {
	if db == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrStorageGeneric, "invalid database")
	}
	if objMng == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrStorageGeneric, "invalid object manager")
	}
	keyValue, err := s.sqlRepo.GetKeyValue(db, zoneID, key)
	if err != nil {
		return nil, err
	}
	if keyValue == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrStorageGeneric, "key value is nil")
	}
	return keyValue.Value, nil
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadBytes(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, key string) (string, []byte, error) {
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
func authorizationCheckReadTree(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *objects.ObjectManager, zoneID int64, commitID string) (*objects.Tree, error) {
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
func (s SQLiteCentralStoragePDP) AuthorizationCheck(request *pdp.AuthorizationCheckRequest) ([]pdp.EvaluationResponse, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrStorageGeneric, "server couldn't connect to the database", err)
	}

	authzCtx := request.AuthorizationModel
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, authzCtx.ZoneID, &authzCtx.PolicyStore.ID, nil)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrLanguangeSemantic, "bad request for either zone id or policy store id", err)
	}
	if len(dbLedgers) != 1 {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrLanguangeSemantic, "bad request for either zone id or policy store id")
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == objects.ZeroOID {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't validate the ledger reference")
	}

	authzPolicyStore := authzen.PolicyStore{}
	authzPolicyStore.SetVersion(ledgerRef)

	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't create the object manager", err)
	}
	treeObj, err := authorizationCheckReadTree(&s, db, objMng, authzCtx.ZoneID, ledgerRef)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't read the tree", err)
	}
	for _, entry := range treeObj.GetEntries() {
		entryID := entry.GetOID()
		value, err2 := authorizationCheckReadKeyValue(&s, db, objMng, authzCtx.ZoneID, entryID)
		if err2 != nil {
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, fmt.Sprintf("server couldn't read the key %s", entryID), err)
		}
		obj, err3 := objMng.DeserializeObjectFromBytes(value)
		if err3 != nil {
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't deserialize the object from bytes", err)
		}
		objInfo, err4 := objMng.GetObjectInfo(obj)
		if err4 != nil {
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't read object info", err)
		}
		objInfoHeader := objInfo.GetHeader()
		oid := objInfo.GetOID()
		if objInfoHeader.GetCodeTypeID() == types.ClassTypeSchemaID {
			authzPolicyStore.AddSchema(oid, objInfo)
		} else if objInfoHeader.GetCodeTypeID() == types.ClassTypePolicyID {
			authzPolicyStore.AddPolicy(oid, objInfo)
		} else {
			return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't process the code type id")
		}
	}

	cedarLanguageAbs, err := cedar.NewCedarLanguageAbstraction()
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrServerGeneric, "server couldn't validate the language abstraction layer", err)
	}

	evaluations := []pdp.EvaluationResponse{}
	for _, expandedRequest := range request.Evaluations {
		authzCtx := authzen.AuthorizationModel{}
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
			evaluation := pdp.NewEvaluationErrorResponse(expandedRequest.RequestID, authzen.AuthzErrInternalErrorCode, err.Error(), authzen.AuthzErrInternalErrorMessage)
			evaluations = append(evaluations, *evaluation)
			continue
		}
		if authzResponse == nil {
			evaluation := pdp.NewEvaluationErrorResponse(expandedRequest.RequestID, authzen.AuthzErrInternalErrorCode, "because of a nil authz response", authzen.AuthzErrInternalErrorMessage)
			evaluations = append(evaluations, *evaluation)
			continue
		}
		evaluation := &pdp.EvaluationResponse{
			RequestID: expandedRequest.RequestID,
			Decision:  authzResponse.GetDecision(),
			Context:   authorizationCheckBuildContextResponse(authzResponse),
		}
		evaluations = append(evaluations, *evaluation)
	}
	return evaluations, nil
}
