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
	} else {
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
	} else {
		ctxResponse.ReasonUser = &azmodelspdp.ReasonResponse{
			Code:    azauthz.AuthzErrInternalErrorCode,
			Message: azauthz.AuthzErrInternalErrorMessage,
		}
	}
	return ctxResponse
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
	//TODO: Load policies
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
