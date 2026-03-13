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

	otelcodes "go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"go.uber.org/zap"
)

// PDPService is the service for the PDP.
type PDPService interface {
	// AuthorizationCheck checks the authorization.
	AuthorizationCheck(ctx context.Context, request *pdp.AuthorizationCheckWithDefaultsRequest) (*pdp.AuthorizationCheckResponse, error)
}

// NewPDPServer creates a new PDP server.
func NewPDPServer(endpointCtx *services.EndpointContext, service PDPService) (*PDPServer, error) {
	return &PDPServer{
		ctx:     endpointCtx,
		service: service,
	}, nil
}

// PDPServer is the gRPC server for the PDP.
type PDPServer struct {
	UnimplementedV1PDPServiceServer
	ctx     *services.EndpointContext
	service PDPService
}

// AuthorizationCheck checks the authorization.
func (s *PDPServer) AuthorizationCheck(ctx context.Context, request *AuthorizationCheckRequest) (_ *AuthorizationCheckResponse, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "grpc.pdp.AuthorizationCheck")
	defer span.End()
	defer func() {
		telemetry.GRPCRequestTotal.Add(ctx, 1, telemetry.MethodAttr("pdp.AuthorizationCheck"), telemetry.StatusAttr(telemetry.StatusFromErr(retErr)))
	}()
	logger := s.ctx.Logger()
	if request != nil {
		jsonData, err := json.MarshalIndent(request, "", "  ")
		if err == nil {
			logger.Debug("AuthorizationCheck request", zap.String("request", string(jsonData)))
		} else {
			logger.Error("Failed to marshal AuthorizationCheck request for logging", zap.Error(err))
		}
	}
	req, err := MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest(request)
	if req == nil {
		span.SetStatus(otelcodes.Error, "nil request")
		return nil, status.Errorf(codes.InvalidArgument, "pdp-endpoint: request cannot be nil: %v", err)
	}
	authzResponse, err := s.service.AuthorizationCheck(ctx, req)
	if err != nil {
		span.SetStatus(otelcodes.Error, err.Error())
		authzResponse = &pdp.AuthorizationCheckResponse{
			RequestID: req.RequestID,
			Decision:  false,
		}
		for _, evaluation := range req.Evaluations {
			requestID := evaluation.RequestID
			if len(requestID) == 0 {
				requestID = req.RequestID
			}
			evalResponse := pdp.NewEvaluationErrorResponse(requestID, authzen.AuthzErrBadRequestCode, err.Error(), authzen.AuthzErrBadRequestMessage)
			authzResponse.Evaluations = append(authzResponse.Evaluations, *evalResponse)
		}
		if len(authzResponse.Evaluations) == 1 {
			firstEval := authzResponse.Evaluations[0]
			authzResponse.Context = firstEval.Context
		}
	}
	resp, err := MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse(authzResponse)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pdp-endpoint: failed to map authorization check response: %v", err)
	}
	return resp, nil
}
