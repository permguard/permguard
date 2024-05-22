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
	"errors"

	azpermissions "github.com/permguard/permguard/pkg/accesscontrol/permissions"
	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// PDPService is the service for the PDP.
type PDPService interface {
	Setup() error
	GetPermissionsState(identityUUR azpolicies.UURString, settings ...azpermissions.PermissionsEngineOption) (*azpermissions.PermissionsState, error)
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

// GetPermissionsState gets the permissions state.
func (s V1PDPServer) GetPermissionsState(ctx context.Context, req *PermissionsStateRequest) (*PermissionsStateResponse, error) {
	identityUUR := azpolicies.UURString(req.Identity.Uur)
	isValid, err := identityUUR.IsValid(azpolicies.PolicyLatest)
	if err != nil {
		return nil, errors.Join(errors.New("pdp: invalid identity UUR"), err)
	}
	if !isValid {
		return nil, errors.New("pdp: invalid identity UUR")
	}
	var permState *azpermissions.PermissionsState
	if req.PermissionsEngine != nil {
		virtualState := req.PermissionsEngine.VirtualState
		virtualStateViewIsCombinded := virtualState.View == VirtualState_COMBINED
		settings := []azpermissions.PermissionsEngineOption{
			azpermissions.WithPermissionsEngineVirtualState(virtualState.Enabled),
			azpermissions.WithPermissionsEngineVirtualStateViewCombined(virtualStateViewIsCombinded),
		}
		permState, err = s.service.GetPermissionsState(identityUUR, settings[:]...)
	} else {
		permState, err = s.service.GetPermissionsState(identityUUR)
	}
	if err != nil {
		s.ctx.GetLogger().Fatal("Error while getting permissions state")
	}
	if permState == nil {
		return nil, errors.New("pdp: permission state cannot be built for the given identity")
	}
	return mapToPermissionsStateResponse(req.Identity.GetUur(), permState)
}

// EvaluatePermissions evaluates the permissions.
func (s V1PDPServer) EvaluatePermissions(ctx context.Context, req *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error) {
	permissionsEvaluation := &PermissionsEvaluationResponse{
		Identity: &Identity{
			Uur: req.Identity.GetUur(),
		},
		Evaluations: make([]*PermissionsEvaluationOutcome, len(req.Evaluations)),
		Permitted:   true,
	}
	for i, evaluation := range req.Evaluations {
		outcome := &PermissionsEvaluationOutcome{
			Evaluation: evaluation,
			Permitted:  false,
			Explanation: &PermissionsEvaluationOutcomeExplanation{
				IsExplicitlyForbidden: true,
				IsImplicitlyForbidden: false,
			},
		}
		permissionsEvaluation.Evaluations[i] = outcome
	}
	return permissionsEvaluation, nil
}
