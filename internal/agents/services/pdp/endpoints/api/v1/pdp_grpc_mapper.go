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
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

// MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest maps the gRPC authorization check request to the agent authorization check request.
func MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest(request *AuthorizationCheckRequest) (*azmodelspdp.AuthorizationCheckRequest, error) {
	req :=  &azmodelspdp.AuthorizationCheckRequest{}
	if request.AuthorizationContext != nil {

	}
	if request.Evaluations != nil {
		for _, evaluation := range request.Evaluations {
			if evaluation != nil {
			}
		}
	}
	return req, nil
}

// MapAgentAuthorizationCheckRequestToGrpcAuthorizationCheckRequest maps the agent authorization check request to the gRPC authorization check request.
func MapAgentAuthorizationCheckRequestToGrpcAuthorizationCheckRequest(request *azmodelspdp.AuthorizationCheckRequest) (*AuthorizationCheckRequest, error) {
	return &AuthorizationCheckRequest{
	}, nil
}

// MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse maps the agent authorization check response to the gRPC authorization check response.
func MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse(response *azmodelspdp.AuthorizationCheckResponse) (*AuthorizationCheckResponse, error) {
	return &AuthorizationCheckResponse{
	}, nil
}

// MapGrpcAuthorizationCheckResponseToAgentAuthorizationCheckResponse maps the gRPC authorization check response to the agent authorization check response.
func MapGrpcAuthorizationCheckResponseToAgentAuthorizationCheckResponse(response *AuthorizationCheckResponse) (*azmodelspdp.AuthorizationCheckResponse, error) {
	return &azmodelspdp.AuthorizationCheckResponse{
	}, nil
}
