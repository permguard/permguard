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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/core/files"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
)

const (
	// LedgerKind is the kind of the policy store.
	LedgerKind = "ledger"
)

// PDPController is the controller for the PDP service.
type PDPController struct {
	ctx     *services.ServiceContext
	storage storage.PDPCentralStorage
}

// Setup initializes the service.
func (s PDPController) Setup() error {
	return nil
}

// NewPDPController creates a new PDP controller.
func NewPDPController(serviceContext *services.ServiceContext, storage storage.PDPCentralStorage) (*PDPController, error) {
	service := PDPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// AuthorizationCheck checks if the request is authorized.
func (s PDPController) AuthorizationCheck(request *pdp.AuthorizationCheckWithDefaultsRequest) (*pdp.AuthorizationCheckResponse, error) {
	if request == nil {
		errMsg := fmt.Sprintf("%s: received nil request", authzen.AuthzErrBadRequestMessage)
		return pdp.NewAuthorizationCheckErrorResponse(nil, "", authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
	}
	requestID := request.RequestID
	if request.AuthorizationModel == nil {
		errMsg := fmt.Sprintf("%s: missing authorization model in request", authzen.AuthzErrBadRequestMessage)
		return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
	}
	if request.AuthorizationModel.PolicyStore == nil {
		errMsg := fmt.Sprintf("%s: missing policy store in authorization model", authzen.AuthzErrBadRequestMessage)
		return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
	}
	expReq, err := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	if err != nil {
		errMsg := fmt.Sprintf("%s: failed to expand authorization request with defaults", authzen.AuthzErrBadRequestMessage)
		return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
	}
	type evalItem struct {
		listID int
		value  *pdp.EvaluationResponse
	}
	evalItems := []evalItem{}
	reqEvaluations := []pdp.EvaluationRequest{}
	reqEvaluationsCounter := 0
	for _, evaluation := range expReq.Evaluations {
		if request.AuthorizationModel.ZoneID == 0 {
			errMsg := fmt.Sprintf("%s: invalid zone id", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		policyStore := request.AuthorizationModel.PolicyStore
		if len(policyStore.Kind) == 0 {
			policyStore.Kind = LedgerKind
		}
		if strings.ToLower(policyStore.Kind) != LedgerKind {
			errMsg := fmt.Sprintf("%s: invalid zone type", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(policyStore.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid policy store id", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		principal := request.AuthorizationModel.Principal
		if principal == nil {
			errMsg := fmt.Sprintf("%s: invalid principal", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(principal.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid the principal id", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !pdp.IsValidIdentiyType(principal.Type) {
			errMsg := fmt.Sprintf("%s: invalid the principal type", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Subject.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid subject id", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !pdp.IsValidIdentiyType(evaluation.Subject.Type) {
			errMsg := fmt.Sprintf("%s: invalid subject type", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !pdp.IsValidProperties(evaluation.Subject.Properties) {
			errMsg := fmt.Sprintf("%s: invalid  subject properties", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Resource.ID)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid resource id", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Resource.Type)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid resource type", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !pdp.IsValidProperties(evaluation.Resource.Properties) {
			errMsg := fmt.Sprintf("%s: invalid resource properties", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if len(strings.TrimSpace(evaluation.Action.Name)) == 0 {
			errMsg := fmt.Sprintf("%s: invalid action name", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		if !pdp.IsValidProperties(evaluation.Action.Properties) {
			errMsg := fmt.Sprintf("%s: invalid action properties", authzen.AuthzErrBadRequestMessage)
			evalItems = append(evalItems, evalItem{listID: -1, value: pdp.NewEvaluationErrorResponse(evaluation.RequestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)})
			continue
		}
		evalItems = append(evalItems, evalItem{listID: reqEvaluationsCounter, value: nil})
		reqEvaluationsCounter++
		reqEvaluations = append(reqEvaluations, evaluation)
	}
	reqEvaluationsSize := len(reqEvaluations)
	expReq.Evaluations = reqEvaluations
	authzCheckEvaluations := []pdp.EvaluationResponse{}
	if reqEvaluationsSize > 0 {
		authzCheckEvaluations, err = s.storage.AuthorizationCheck(expReq)
		if err != nil {
			errMsg := fmt.Sprintf("%s: authorization check has failed %s", authzen.AuthzErrInternalErrorMessage, err.Error())
			return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
		}
		if len(authzCheckEvaluations) != reqEvaluationsSize {
			errMsg := fmt.Sprintf("%s: invalid authorization check response size for evaluations", authzen.AuthzErrInternalErrorMessage)
			return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
		}
	}
	evaluations := []pdp.EvaluationResponse{}
	for i := range len(evalItems) {
		evalItem := evalItems[i]
		if evalItem.listID == -1 {
			evaluations = append(evaluations, *evalItems[i].value)
		} else {
			evaluations = append(evaluations, authzCheckEvaluations[evalItem.listID])
		}
	}
	authzCheckResp := &pdp.AuthorizationCheckResponse{
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
	reader, _ := s.ctx.GetHostConfigReader()
	appData := reader.GetAppData()
	decisionLogsPath := filepath.Join(appData, "decisions.log")
	decisionLogs := s.buildDecisionLogs(expReq, authzCheckResp)
	for _, decisionLog := range decisionLogs {
		decision, _ := json.Marshal(decisionLog)
		files.AppendToFile(decisionLogsPath, append(decision, '\n'), false)
	}
	return authzCheckResp, nil
}

// buildDecisionLogs builds the decision logs.
func (s PDPController) buildDecisionLogs(req *pdp.AuthorizationCheckRequest, resp *pdp.AuthorizationCheckResponse) ([]map[string]any) {
	decisionLogs := make([]map[string]any, len(req.Evaluations))
	for i := range req.Evaluations {
		reqVal := req.Evaluations[i]
		respVal := resp.Evaluations[i]
		decisionMap := map[string]any {}
		requestMap := map[string]any{}
		requestMap["authorization_model"] = req.AuthorizationModel
		requestMap["evaluation"] = reqVal
		decisionMap["request"] = requestMap
		decisionMap["response"] = respVal
		decisionLogs[i] = decisionMap
	}
	return decisionLogs
}
