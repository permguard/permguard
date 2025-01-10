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
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azauthz "github.com/permguard/permguard/pkg/authorization"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
	azplangcedar "github.com/permguard/permguard/plugin/languages/cedar"
)

// authorizationCheckContextResponse creates an authorization check context response.
func authorizationCheckContextResponse(authzResponse *azauthz.AuthorizationDecision) *azmodelspdp.ContextResponse {
	response := &azmodelspdp.ContextResponse{}
	response.ID = authzResponse.GetID()
	if authzResponse.GetAdminError() != nil {
		response.ReasonAdmin = &azmodelspdp.ReasonResponse{
			Code:    authzResponse.GetAdminError().GetCode(),
			Message: authzResponse.GetAdminError().GetMessage(),
		}
	} else {
		response.ReasonAdmin = &azmodelspdp.ReasonResponse{
			Code:    azauthz.AuthzErrUnauthorizedCode,
			Message: azauthz.AuthzErrUnauthorizedMessage,
		}
	}
	if authzResponse.GetUserError() != nil {
		response.ReasonUser = &azmodelspdp.ReasonResponse{
			Code:    authzResponse.GetUserError().GetCode(),
			Message: authzResponse.GetUserError().GetMessage(),
		}
	} else {
		response.ReasonUser = &azmodelspdp.ReasonResponse{
			Code:    azauthz.AuthzErrUnauthorizedCode,
			Message: azauthz.AuthzErrUnauthorizedMessage,
		}
	}
	return response
}

// CreateLedger creates a new ledger.
func (s SQLiteCentralStoragePDP) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*azmodelspdp.AuthorizationCheckResponse, error) {
	authzCheckResponse := &azmodelspdp.AuthorizationCheckResponse{}
	authzCheckResponse.Decision = false
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	applicationID := request.AuthorizationContext.ApplicationID
	policyStore := request.AuthorizationContext.PolicyStore
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, applicationID, &policyStore.ID, nil)
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
	authzPolicyStore.AddPolicy("policyID", nil)
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
		evaluationResponse := azmodelspdp.EvaluationResponse{
			Decision: authzResponse.GetDecision(),
			Context:  authorizationCheckContextResponse(authzResponse),
		}
		authzCheckResponse.Evaluations = append(authzCheckResponse.Evaluations, evaluationResponse)
	}
	if len(authzCheckResponse.Evaluations) > 0 {
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
