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
	"fmt"
	"strings"

	azauthzen "github.com/permguard/permguard-ztauthstar/pkg/authzen"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

const (
	// LedgerKind is the kind of the policy store.
	LedgerKind = "ledger"
)

// PDPController is the controller for the PDP service.
type PDPController struct {
	ctx     *azservices.ServiceContext
	storage azStorage.PDPCentralStorage
}

// Setup initializes the service.
func (s PDPController) Setup() error {
	return nil
}

// NewPDPController creates a new PDP controller.
func NewPDPController(serviceContext *azservices.ServiceContext, storage azStorage.PDPCentralStorage) (*PDPController, error) {
	service := PDPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// AuthorizationCheck checks if the request is authorized.
func (s PDPController) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*azmodelspdp.AuthorizationCheckResponse, error) {
	if request == nil {
		errMsg := fmt.Sprintf("%s: received nil request", azauthzen.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, "", azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
	}
	requestID := request.RequestID
	if request.AuthorizationModel == nil {
		errMsg := fmt.Sprintf("%s: missing authorization model in request", azauthzen.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, requestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
	}
	if request.AuthorizationModel.PolicyStore == nil {
		errMsg := fmt.Sprintf("%s: missing policy store in authorization model", azauthzen.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, requestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
	}
	expReq, err := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	if err != nil {
		errMsg := fmt.Sprintf("%s: failed to expand authorization request with defaults", azauthzen.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, requestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
	}
	type evalItem struct {
		listID int
		value  *azmodelspdp.EvaluationResponse
	}
	evalItems := []evalItem{}
	reqEvaluations := []azmodelspdp.EvaluationRequest{}
	reqEvaluationsCounter := 0
	for _, evaluation := range expReq.Evaluations {
		if request.AuthorizationModel.ZoneID == 0 {
			errMsg := fmt.Sprintf("%s: invalid zone id", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		policyStore := request.AuthorizationModel.PolicyStore
		if len(policyStore.Kind) == 0 {
			policyStore.Kind = LedgerKind
		}
		if strings.ToLower(policyStore.Kind) != LedgerKind {
			errMsg := fmt.Sprintf("%s: invalid zone type", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(policyStore.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid policy store id", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		principal := request.AuthorizationModel.Principal
		if principal == nil {
			errMsg := fmt.Sprintf("%s: invalid principal", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(principal.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid the principal id", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !azmodelspdp.IsValidIdentiyType(principal.Type) {
			errMsg := fmt.Sprintf("%s: invalid the principal type", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Subject.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid subject id", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !azmodelspdp.IsValidIdentiyType(evaluation.Subject.Type) {
			errMsg := fmt.Sprintf("%s: invalid subject type", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !azmodelspdp.IsValidProperties(evaluation.Subject.Properties) {
			errMsg := fmt.Sprintf("%s: invalid  subject properties", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Resource.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid resource id", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Resource.Type)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid resource type", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !azmodelspdp.IsValidProperties(evaluation.Resource.Properties) {
			errMsg := fmt.Sprintf("%s: invalid resource properties", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Action.Name)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid action name", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !azmodelspdp.IsValidProperties(evaluation.Action.Properties) {
			errMsg := fmt.Sprintf("%s: invalid action properties", azauthzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: azmodelspdp.NewEvaluationErrorResponse(evaluation.RequestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage)})
			continue
		}
		evalItems = append(evalItems, evalItem{listID: reqEvaluationsCounter, value: nil})
		reqEvaluationsCounter++
		reqEvaluations = append(reqEvaluations, evaluation)
	}
	reqEvaluationsSize := len(reqEvaluations)
	expReq.Evaluations = reqEvaluations
	authzCheckEvaluations := []azmodelspdp.EvaluationResponse{}
	if reqEvaluationsSize > 0 {
		authzCheckEvaluations, err = s.storage.AuthorizationCheck(expReq)
		if err != nil {
			errMsg := fmt.Sprintf("%s: authorization check has failed %s", azauthzen.AuthzErrInternalErrorMessage, err.Error())
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, requestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
		}
		if len(authzCheckEvaluations) != reqEvaluationsSize {
			errMsg := fmt.Sprintf("%s: invalid authorization check response size for evaluations", azauthzen.AuthzErrInternalErrorMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, requestID, azauthzen.AuthzErrBadRequestCode, errMsg, azauthzen.AuthzErrBadRequestMessage), nil
		}
	}
	evaluations := []azmodelspdp.EvaluationResponse{}
	for i := range len(evalItems) {
		evalItem := evalItems[i]
		if evalItem.listID == -1 {
			evaluations = append(evaluations, *evalItems[i].value)
		} else {
			evaluations = append(evaluations, authzCheckEvaluations[evalItem.listID])
		}
	}
	authzCheckResp := &azmodelspdp.AuthorizationCheckResponse{
		RequestID:   request.RequestID,
		Evaluations: evaluations,
	}
	if len(authzCheckResp.Evaluations) == 1 {
		firstEval := authzCheckResp.Evaluations[0]
		authzCheckResp.RequestID = firstEval.RequestID
		authzCheckResp.Decision = firstEval.Decision
		authzCheckResp.Context = firstEval.Context
	}
	if len(authzCheckResp.Evaluations) > 0 {
		allTrue := true
		for _, evaluation := range authzCheckResp.Evaluations {
			if !evaluation.Decision {
				allTrue = false
				break
			}
		}
		authzCheckResp.Decision = allTrue
	}
	return authzCheckResp, nil
}
