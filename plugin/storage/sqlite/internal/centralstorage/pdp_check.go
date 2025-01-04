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
	"strings"

	azauthz "github.com/permguard/permguard/pkg/authorization"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
	azplangcedar "github.com/permguard/permguard/plugin/languages/cedar"
)

// expandedRequest represents the expanded request.
type expandedRequest struct {
	isRoot bool
	subject *azmodelspdp.Subject
	resource *azmodelspdp.Resource
	action *azmodelspdp.Action
	context map[string]any
}

// verify verifies the expanded request.
func (r *expandedRequest) verify() error {
	if r.subject == nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid input subject.")
	}
	if r.resource == nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid input resource.")
	}
	if r.action == nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid input action.")
	}
	return nil
}

// authorizationCheckExpandRequest expands the request.
func authorizationCheckExpandRequest(request *azmodelspdp.AuthorizationCheckRequest) ([]expandedRequest, error) {
	expandedRequests := []expandedRequest{}
	hasEvaluations := len(request.Evaluations) > 0
	if !hasEvaluations {
		expandedRequest := expandedRequest{
			isRoot: true,
			subject: request.Subject,
			resource: request.Resource,
			action: request.Action,
			context: request.Context,
		}
		expandedRequests = append(expandedRequests, expandedRequest)
	} else {
		for _, evaluation := range request.Evaluations {
			expandedRequest := expandedRequest{
				isRoot: false,
				subject: request.Subject,
				resource: request.Resource,
				action: request.Action,
				context: request.Context,
			}
			if evaluation.Subject != nil {
				expandedRequest.subject = evaluation.Subject
			}
			if evaluation.Resource != nil {
				expandedRequest.resource = evaluation.Resource
			}
			if evaluation.Action != nil {
				expandedRequest.action = evaluation.Action
			}
			expandedRequests = append(expandedRequests, expandedRequest)
		}
	}
	for _, expandedRequest := range expandedRequests {
		err := expandedRequest.verify()
		if err != nil {
			return nil, err
		}
	}
	return expandedRequests, nil
}

// authorizationCheckVerifyPrincipal verifies the principal.
func authorizationCheckVerifyPrincipal(principal *azmodelspdp.Principal, subject *azmodelspdp.Subject) bool {
	if principal == nil {
		return true
	}
	if principal.ID != subject.ID {
		return false
	} else if principal.Type != subject.Type {
		return false
	} else if principal.Source != subject.Source {
		return false
	}
	return true
}

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

// authorizationCheckErrorResponse creates an authorization check error response.
func authorizationCheckErrorResponse(authzCheckResponse *azmodelspdp.AuthorizationCheckResponse, erroCode string, adminReason  string, userReason string) *azmodelspdp.AuthorizationCheckResponse {
	authzCheckResponse.Context.ReasonAdmin = &azmodelspdp.ReasonResponse{
		Code:    erroCode,
		Message: adminReason,
	}
	authzCheckResponse.Context.ReasonUser = &azmodelspdp.ReasonResponse{
		Code:    erroCode,
		Message: userReason,
	}
	return authzCheckResponse
}

// CreateLedger creates a new ledger.
func (s SQLiteCentralStoragePDP) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckRequest) (*azmodelspdp.AuthorizationCheckResponse, error) {
	authzCheckResponse := &azmodelspdp.AuthorizationCheckResponse{}
	authzCheckResponse.Decision = false
	if request == nil || request.AuthorizationContext == nil || request.AuthorizationContext.PolicyStore == nil {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	expandedRequests, err := authorizationCheckExpandRequest(request)
	if err != nil {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	policyStore := request.AuthorizationContext.PolicyStore
	if strings.ToLower(policyStore.Type) != "ledger" {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	applicationID := request.AuthorizationContext.ApplicationID
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, 1, 2, applicationID, &policyStore.ID, nil)
	if err != nil {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	if len(dbLedgers) != 1 {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	ledger := dbLedgers[0]
	ledgerRef := ledger.Ref
	if ledgerRef == azlangobjs.ZeroOID {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, azauthz.AuthzErrInternalErrorMessage, azauthz.AuthzErrInternalErrorMessage), nil
	}
	authzPolicyStore := azauthz.PolicyStore{}
	authzPolicyStore.AddPolicy("policyID", nil)
	cedarLanguageAbs, err := azplangcedar.NewCedarLanguageAbstraction()
	if err != nil {
		return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	for _, expandedRequest := range expandedRequests {
		if !authorizationCheckVerifyPrincipal(request.AuthorizationContext.Principal, expandedRequest.subject) {
			return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrUnauthorizedCode, azauthz.AuthzErrUnauthorizedMessage, azauthz.AuthzErrUnauthorizedMessage), nil
		}
		authzCtx := azauthz.AuthorizationContext{}
		authzCtx.SetSubject(expandedRequest.subject.Type, expandedRequest.subject.ID, expandedRequest.subject.Source, expandedRequest.subject.Properties)
		authzCtx.SetResource(expandedRequest.resource.Type, expandedRequest.resource.ID, expandedRequest.resource.Properties)
		authzCtx.SetAction(expandedRequest.action.Name, expandedRequest.action.Properties)
		authzCtx.SetContext(expandedRequest.context)
		entities := request.AuthorizationContext.Entities
		if  entities != nil {
			authzCtx.SetEntities(entities.Schema, entities.Items)
		}
		authzResponse, err := cedarLanguageAbs.AuthorizationCheck(&authzPolicyStore, &authzCtx)
		if err != nil {
			return authorizationCheckErrorResponse(authzCheckResponse, azauthz.AuthzErrInternalErrorCode, err.Error(), azauthz.AuthzErrInternalErrorMessage), nil
		}
		if expandedRequest.isRoot {
			authzCheckResponse.Decision = authzResponse.GetDecision()
			authzCheckResponse.Context = authorizationCheckContextResponse(authzResponse)
		} else {
			evaluationResponse := azmodelspdp.EvaluationResponse{
				Decision: authzResponse.GetDecision(),
				Context:  authorizationCheckContextResponse(authzResponse),
			}
			authzCheckResponse.Evaluations = append(authzCheckResponse.Evaluations, evaluationResponse)
		}
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
