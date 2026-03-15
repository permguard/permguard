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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/permguard/permguard/internal/agents/decisions"
	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	"github.com/permguard/permguard/pkg/core/files"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/plugin/languages/cedar"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
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
func (s PDPController) AuthorizationCheck(ctx context.Context, request *pdp.AuthorizationCheckWithDefaultsRequest) (_ *pdp.AuthorizationCheckResponse, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "pdp.AuthorizationCheck")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.AuthzCheckTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.AuthzCheckDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.StatusAttr(st))
	}()
	if request == nil {
		errMsg := fmt.Sprintf("%s: received nil request", authzen.AuthzErrBadRequestMessage)
		return pdp.NewAuthorizationCheckErrorResponse(nil, "", authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage), nil
	}
	cfgReader, err := s.ctx.ServiceConfigReader()
	if err != nil {
		return nil, errors.Join(errors.New("pdp-service: failed to get service config reader"), err)
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
	expReq := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	type evalItem struct {
		listID int
		value  *pdp.EvaluationResponse
	}
	evalItems := []evalItem{}
	reqEvaluations := []pdp.EvaluationRequest{}
	reqEvaluationsCounter := 0
	for _, evaluation := range expReq.Evaluations {
		input := buildEvaluationInput(request.AuthorizationModel, &evaluation)
		if errResp := validateEvaluation(evaluation.RequestID, input); errResp != nil {
			evalItems = append(evalItems, evalItem{listID: -1, value: errResp})
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
		authzModel := expReq.AuthorizationModel
		loadCtx, loadSpan := telemetry.Tracer().Start(ctx, "pdp.LoadPolicyStore",
			trace.WithAttributes(
				attribute.Int64("zone_id", authzModel.ZoneID),
				attribute.String("policy_store_id", authzModel.PolicyStore.ID)))
		authzPolicyStore, err2 := s.storage.LoadPolicyStore(loadCtx, authzModel.ZoneID, authzModel.PolicyStore.ID)
		loadSpan.End()
		telemetry.AuthzPolicyLoadTotal.Add(ctx, 1, telemetry.StatusAttr(telemetry.StatusFromErr(err2)))
		if err2 != nil {
			if logger := s.ctx.Logger(); logger != nil {
				logger.Error("Failed to load policy store for authorization check",
					zap.Int64("zone_id", authzModel.ZoneID),
					zap.String("policy_store_id", authzModel.PolicyStore.ID),
					zap.String("request_id", requestID),
					zap.Error(err2))
			}
			errMsg := fmt.Sprintf("%s: authorization check has failed", authzen.AuthzErrInternalErrorMessage)
			return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrInternalErrorCode, errMsg, authzen.AuthzErrInternalErrorMessage), nil
		}
		cedarLanguageAbs, err2 := cedar.NewCedarLanguageAbstraction()
		if err2 != nil {
			if logger := s.ctx.Logger(); logger != nil {
				logger.Error("Failed to create Cedar language abstraction",
					zap.Int64("zone_id", authzModel.ZoneID),
					zap.String("policy_store_id", authzModel.PolicyStore.ID),
					zap.String("request_id", requestID),
					zap.Error(err2))
			}
			errMsg := fmt.Sprintf("%s: authorization check has failed", authzen.AuthzErrInternalErrorMessage)
			return pdp.NewAuthorizationCheckErrorResponse(nil, requestID, authzen.AuthzErrInternalErrorCode, errMsg, authzen.AuthzErrInternalErrorMessage), nil
		}
		telemetry.AuthzEvaluationsCount.Record(ctx, int64(reqEvaluationsSize))
		_, evalSpan := telemetry.Tracer().Start(ctx, "pdp.PolicyEvaluations",
			trace.WithAttributes(attribute.Int("evaluations_count", reqEvaluationsSize)))
		authzCheckEvaluations = []pdp.EvaluationResponse{}
		for _, expandedRequest := range expReq.Evaluations {
			authzCtx := authzen.AuthorizationModel{}
			if err := authzCtx.SetSubject(expandedRequest.Subject.Type, expandedRequest.Subject.ID, expandedRequest.Subject.Source, expandedRequest.Subject.Properties); err != nil {
				if logger := s.ctx.Logger(); logger != nil {
					logger.Error("Failed to set authorization subject",
						zap.String("request_id", requestID),
						zap.Int64("zone_id", authzModel.ZoneID),
						zap.Error(err))
				}
				return nil, err
			}
			if err := authzCtx.SetResource(expandedRequest.Resource.Type, expandedRequest.Resource.ID, expandedRequest.Resource.Properties); err != nil {
				if logger := s.ctx.Logger(); logger != nil {
					logger.Error("Failed to set authorization resource",
						zap.String("request_id", requestID),
						zap.Int64("zone_id", authzModel.ZoneID),
						zap.Error(err))
				}
				return nil, err
			}
			if err := authzCtx.SetAction(expandedRequest.Action.Name, expandedRequest.Action.Properties); err != nil {
				if logger := s.ctx.Logger(); logger != nil {
					logger.Error("Failed to set authorization action",
						zap.String("request_id", requestID),
						zap.Int64("zone_id", authzModel.ZoneID),
						zap.Error(err))
				}
				return nil, err
			}
			if err := authzCtx.SetContext(expandedRequest.Context); err != nil {
				if logger := s.ctx.Logger(); logger != nil {
					logger.Error("Failed to set authorization context",
						zap.String("request_id", requestID),
						zap.Int64("zone_id", authzModel.ZoneID),
						zap.Error(err))
				}
				return nil, err
			}
			entities := expReq.AuthorizationModel.Entities
			if entities != nil {
				if err := authzCtx.SetEntities(entities.Schema, entities.Items); err != nil {
					if logger := s.ctx.Logger(); logger != nil {
						logger.Error("Failed to set authorization entities",
							zap.String("request_id", requestID),
							zap.Int64("zone_id", authzModel.ZoneID),
							zap.Error(err))
					}
					return nil, err
				}
			}
			contextID := expandedRequest.ContextID
			// TODO: Fix manifest refactoring
			authzResponse, err2 := cedarLanguageAbs.AuthorizationCheck(nil, contextID, authzPolicyStore, &authzCtx)
			if err2 != nil {
				evaluation := pdp.NewEvaluationErrorResponse(expandedRequest.RequestID, authzen.AuthzErrInternalErrorCode, err2.Error(), authzen.AuthzErrInternalErrorMessage)
				authzCheckEvaluations = append(authzCheckEvaluations, *evaluation)
				continue
			}
			if authzResponse == nil {
				evaluation := pdp.NewEvaluationErrorResponse(expandedRequest.RequestID, authzen.AuthzErrInternalErrorCode, "because of a nil authz response", authzen.AuthzErrInternalErrorMessage)
				authzCheckEvaluations = append(authzCheckEvaluations, *evaluation)
				continue
			}
			evaluation := &pdp.EvaluationResponse{
				RequestID: expandedRequest.RequestID,
				Decision:  authzResponse.Decision(),
				Context:   authorizationCheckBuildContextResponse(authzResponse),
			}
			authzCheckEvaluations = append(authzCheckEvaluations, *evaluation)
		}
		evalSpan.End()
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
	decision := "deny"
	if authzCheckResp.Decision {
		decision = "allow"
	}
	telemetry.AuthzDecisionTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("decision", decision)))
	span.SetAttributes(attribute.String("authz.decision", decision), attribute.Int("authz.evaluations", len(authzCheckResp.Evaluations)))
	decisionLog, err := runtime.GetTypedValue[string](cfgReader.Value, "decision-log")
	if err != nil {
		return nil, errors.Join(errors.New("pdp-service: failed to get decision logs configuration"), err)
	}
	if decisions.ShouldLogDecision(decisionLog) {
		var decisionLogsPath string
		decisionKind := decisions.DecisionLogKind(decisionLog)
		if decisionKind == decisions.DecisionLogFile {
			hostReader, err := s.ctx.HostConfigReader()
			if err != nil {
				return nil, errors.Join(errors.New("pdp-service: failed to get host config reader"), err)
			}
			decisionLogsPath = filepath.Join(hostReader.AppData(), "decisions.log")
		}
		decisionLogs := s.buildDecisionLogs(expReq, authzCheckResp)
		logger := s.ctx.Logger()
		for _, decisionLog := range decisionLogs {
			decision, err := json.Marshal(decisionLog)
			if err != nil {
				logger.Warn("Failed to marshal decision log entry",
					zap.String("request_id", requestID),
					zap.Error(err))
				continue
			}
			switch decisionKind {
			case decisions.DecisionLogFile:
				if _, err := files.AppendToFile(decisionLogsPath, append(decision, '\n'), false); err != nil {
					logger.Warn("Failed to write decision log to file",
						zap.String("path", decisionLogsPath),
						zap.String("request_id", requestID),
						zap.Error(err))
				}
			case decisions.DecisionLogStdOut:
				logger.Info("DECISION-LOG", zap.String("decision", string(decision)))
			}
		}
	}
	return authzCheckResp, nil
}

// buildDecisionLogs builds the decision logs.
func (s PDPController) buildDecisionLogs(req *pdp.AuthorizationCheckRequest, resp *pdp.AuthorizationCheckResponse) []map[string]any {
	decisionLogs := make([]map[string]any, len(req.Evaluations))
	for i := range req.Evaluations {
		reqVal := req.Evaluations[i]
		respVal := resp.Evaluations[i]
		decisionMap := map[string]any{}
		requestMap := map[string]any{}
		requestMap["authorization_model"] = req.AuthorizationModel
		requestMap["evaluation"] = reqVal
		decisionMap["request"] = requestMap
		decisionMap["response"] = respVal
		decisionLogs[i] = decisionMap
	}
	return decisionLogs
}
