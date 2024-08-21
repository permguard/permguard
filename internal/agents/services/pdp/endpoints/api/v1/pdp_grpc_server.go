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
	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// PDPService is the service for the PDP.
type PDPService interface {
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
