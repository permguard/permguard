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
	"github.com/jmoiron/sqlx"

	azlangtypes "github.com/permguard/permguard-abs-language/pkg/languages/types"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azauthz "github.com/permguard/permguard/pkg/authorization"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
	azplangcedar "github.com/permguard/permguard/plugin/languages/cedar"
)

// authorizationCheckBuildContextResponse builds the context response for the authorization check.
func authorizationCheckBuildContextResponse(authzDecision *azauthz.AuthorizationDecision) *azmodelspdp.ContextResponse {
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
			Code:    azauthz.AuthzErrInternalErrorCode,
			Message: azauthz.AuthzErrInternalErrorMessage,
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
			Code:    azauthz.AuthzErrInternalErrorCode,
			Message: azauthz.AuthzErrInternalErrorMessage,
		}
	}
	return ctxResponse
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadKeyValue(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azlangobjs.ObjectManager, key string) ([]byte, error) {
	if db == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "invalid database")
	}
	if objMng == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "invalid object manager")
	}
	keyValue, err := s.sqlRepo.GetKeyValue(db, key)
	if err != nil {
		return nil, err
	}
	if keyValue == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "key value is nil")
	}
	return keyValue.Value, nil
}

// authorizationCheckReadBytes reads the key value for the authorization check.
func authorizationCheckReadBytes(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azlangobjs.ObjectManager, key string) (string, []byte, error) {
	value, err := authorizationCheckReadKeyValue(s, db, objMng, key)
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
func authorizationCheckReadTree(s *SQLiteCentralStoragePDP, db *sqlx.DB, objMng *azlangobjs.ObjectManager, commitID string) (*azlangobjs.Tree, error) {
	_, ocontent, err := authorizationCheckReadBytes(s, db, objMng, commitID)
	if err != nil {
		return nil, err
	}
	commitObj, err := objMng.DeserializeCommit(ocontent)
	if err != nil {
		return nil, err
	}
	_, ocontent, err = authorizationCheckReadBytes(s, db, objMng, commitObj.GetTree())
	if err != nil {
		return nil, err
	}
	return objMng.DeserializeTree(ocontent)
}

// AuthorizationCheck performs the authorization check.
func (s SQLiteCentralStoragePDP) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckRequest) (*azmodelspdp.AuthorizationCheckResponse, error) {
	authzCheckResponse := &azmodelspdp.AuthorizationCheckResponse{}
	authzCheckResponse.Decision = false
	authzCheckResponse.Context = &azmodelspdp.ContextResponse{}
	authzCheckResponse.Evaluations = []azmodelspdp.EvaluationResponse{}

	authzCtx := request.AuthorizationContext

	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}

	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, authzCtx.ApplicationID, &authzCtx.PolicyStore.ID, nil)
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	if len(dbLedgers) != 1 {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == azlangobjs.ZeroOID {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorMessage, azauthz.AuthzErrInternalErrorMessage), nil
	}

	authzPolicyStore := azauthz.PolicyStore{}
	authzPolicyStore.SetVersion(ledgerRef)

	objMng, err := azlangobjs.NewObjectManager()
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
	}
	treeObj, err := authorizationCheckReadTree(&s, db, objMng, ledgerRef)
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
	}
	for _, entry := range treeObj.GetEntries() {
		value, err := authorizationCheckReadKeyValue(&s, db, objMng, entry.GetOID())
		if err != nil {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
		}
		obj, err := objMng.DeserializeObjectFromBytes(value)
		if err != nil {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
		}
		objInfo, err := objMng.GetObjectInfo(obj)
		objInfoHeader := objInfo.GetHeader()
		oid := objInfo.GetOID()
		if objInfoHeader.GetCodeTypeID() == azlangtypes.ClassTypeSchemaID {
			authzPolicyStore.AddSchema(oid, objInfo)
		} else if objInfoHeader.GetCodeTypeID() == azlangtypes.ClassTypePolicyID {
			authzPolicyStore.AddPolicy(oid, objInfo)
		} else {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorMessage), nil
		}
	}

	cedarLanguageAbs, err := azplangcedar.NewCedarLanguageAbstraction()
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}

	for _, expandedRequest := range request.Evaluations {
		authzCtx := azauthz.AuthorizationContext{}
		authzCtx.SetSubject(expandedRequest.Subject.Type, expandedRequest.Subject.ID, expandedRequest.Subject.Source, expandedRequest.Subject.Properties)
		authzCtx.SetResource(expandedRequest.Resource.Type, expandedRequest.Resource.ID, expandedRequest.Resource.Properties)
		authzCtx.SetAction(expandedRequest.Action.Name, expandedRequest.Action.Properties)
		authzCtx.SetContext(expandedRequest.Context)
		entities := request.AuthorizationContext.Entities
		if entities != nil {
			authzCtx.SetEntities(entities.Schema, entities.Items)
		}
		authzResponse, err := cedarLanguageAbs.AuthorizationCheck(&authzPolicyStore, &authzCtx)
		if err != nil {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
		}
		if authzResponse == nil {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorMessage), nil
		}
		evaluationResponse := azmodelspdp.EvaluationResponse{
			Decision: authzResponse.GetDecision(),
			Context:  authorizationCheckBuildContextResponse(authzResponse),
		}
		authzCheckResponse.Evaluations = append(authzCheckResponse.Evaluations, evaluationResponse)
	}
	evaluations := authzCheckResponse.Evaluations
	if len(evaluations) > 0 {
		allTrue := true
		for _, evaluation := range authzCheckResponse.Evaluations {
			if !evaluation.Decision {
				allTrue = false
				break
			}
		}
		authzCheckResponse.Decision = allTrue
	}
	return authzCheckResponse, nil
}
