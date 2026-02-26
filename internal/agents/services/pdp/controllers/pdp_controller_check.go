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

package controllers

import (
	"github.com/permguard/permguard/common/pkg/extensions/ids"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
)

// authorizationCheckExpandAuthorizationCheckWithDefaults expands the authorization check with defaults.
func authorizationCheckExpandAuthorizationCheckWithDefaults(request *pdp.AuthorizationCheckWithDefaultsRequest) *pdp.AuthorizationCheckRequest {
	expReq := &pdp.AuthorizationCheckRequest{}
	expReq.AuthorizationModel = request.AuthorizationModel

	if len(request.Evaluations) == 0 {
		expRequest := pdp.EvaluationRequest{
			RequestID: request.RequestID,
			Subject:   request.Subject,
			Resource:  request.Resource,
			Action:    request.Action,
			Context:   request.Context,
			ContextID: ids.GenerateID(),
		}
		if expRequest.Context == nil {
			expRequest.Context = make(map[string]interface{})
		}
		expReq.Evaluations = []pdp.EvaluationRequest{expRequest}
	} else {
		requestID := request.RequestID
		expReq.Evaluations = []pdp.EvaluationRequest{}
		for _, evaluation := range request.Evaluations {
			expRequest := pdp.EvaluationRequest{
				RequestID: request.RequestID,
				Subject:   request.Subject,
				Resource:  request.Resource,
				Action:    request.Action,
				Context:   request.Context,
				ContextID: ids.GenerateID(),
			}
			if len(evaluation.RequestID) > 0 {
				expRequest.RequestID = evaluation.RequestID
			} else {
				expRequest.RequestID = requestID
			}
			if evaluation.Subject != nil {
				expRequest.Subject = evaluation.Subject
			}
			if evaluation.Resource != nil {
				expRequest.Resource = evaluation.Resource
			}
			if evaluation.Action != nil {
				expRequest.Action = evaluation.Action
			}
			if len(evaluation.Context) > 0 {
				expRequest.Context = evaluation.Context
			}
			if expRequest.Context == nil {
				expRequest.Context = make(map[string]interface{})
			}
			expReq.Evaluations = append(expReq.Evaluations, expRequest)
		}
	}
	return expReq
}

// authorizationCheckBuildContextResponse builds the context response for the authorization check.
func authorizationCheckBuildContextResponse(authzDecision *authzen.AuthorizationDecision) *pdp.ContextResponse {
	ctxResponse := &pdp.ContextResponse{}
	ctxResponse.ID = authzDecision.ID()

	adminError := authzDecision.AdminError()
	if adminError != nil {
		ctxResponse.ReasonAdmin = &pdp.ReasonResponse{
			Code:    adminError.Code(),
			Message: adminError.Message(),
		}
	} else if !authzDecision.Decision() {
		ctxResponse.ReasonAdmin = &pdp.ReasonResponse{
			Code:    authzen.AuthzErrInternalErrorCode,
			Message: authzen.AuthzErrInternalErrorMessage,
		}
	}

	userError := authzDecision.UserError()
	if userError != nil {
		ctxResponse.ReasonUser = &pdp.ReasonResponse{
			Code:    userError.Code(),
			Message: userError.Message(),
		}
	} else if !authzDecision.Decision() {
		ctxResponse.ReasonUser = &pdp.ReasonResponse{
			Code:    authzen.AuthzErrInternalErrorCode,
			Message: authzen.AuthzErrInternalErrorMessage,
		}
	}
	return ctxResponse
}
