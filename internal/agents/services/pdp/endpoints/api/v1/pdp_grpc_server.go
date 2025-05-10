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

package v1

import (
	"context"
	"encoding/json"

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
	azauthzen "github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"go.uber.org/zap"
)

// PDPService is the service for the PDP.
type PDPService interface {
	// AuthorizationCheck checks the authorization.
	AuthorizationCheck(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*azmodelspdp.AuthorizationCheckResponse, error)
}

// NewV1PDPServer creates a new PDP server.
func NewV1PDPServer(endpointCtx *azservices.EndpointContext, Service PDPService) (*V1PDPServer, error) {
	return &V1PDPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1PDPServer is the gRPC server for the PDP.
type V1PDPServer struct {
	UnimplementedV1PDPServiceServer
	ctx     *azservices.EndpointContext
	service PDPService
}

// AuthorizationCheck checks the authorization.
func (s *V1PDPServer) AuthorizationCheck(ctx context.Context, request *AuthorizationCheckRequest) (*AuthorizationCheckResponse, error) {
	logger := s.ctx.GetLogger()
	if request != nil {
		jsonData, err := json.MarshalIndent(request, "", "  ")
		if err == nil {
			logger.Debug("AuthorizationCheck request", zap.String("request", string(jsonData)))
		} else {
			logger.Error("AuthorizationCheck request", zap.String("request", err.Error()))
		}
	}
	req, err := MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest(request)
	if req == nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrClientParameter, "request cannot be nil", err)
	}
	authzResponse, err := s.service.AuthorizationCheck(req)
	if err != nil {
		authzResponse = &azmodelspdp.AuthorizationCheckResponse{
			RequestID: req.RequestID,
			Decision:  false,
		}
		for _, evaluation := range req.Evaluations {
			requestID := evaluation.RequestID
			if len(requestID) == 0 {
				requestID = req.RequestID
			}
			evalResponse := azmodelspdp.NewEvaluationErrorResponse(requestID, azauthzen.AuthzErrBadRequestCode, err.Error(), azauthzen.AuthzErrBadRequestMessage)
			authzResponse.Evaluations = append(authzResponse.Evaluations, *evalResponse)
		}
		if len(authzResponse.Evaluations) == 1 {
			firstEval := authzResponse.Evaluations[0]
			authzResponse.Context = firstEval.Context
		}
	}
	return MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse(authzResponse)
}
