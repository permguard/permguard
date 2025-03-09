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

package clients

import (
	"context"

	azapiv1pdp "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
	azmodelpdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

// AuthorizationCheck checks the authorization request.
func (c *GrpcPDPClient) AuthorizationCheck(request *azmodelpdp.AuthorizationCheckWithDefaultsRequest) (*azmodelpdp.AuthorizationCheckResponse, error) {
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	req, err := azapiv1pdp.MapAgentAuthorizationCheckRequestToGrpcAuthorizationCheckRequest(request)
	response, err := client.AuthorizationCheck(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return azapiv1pdp.MapGrpcAuthorizationCheckResponseToAgentAuthorizationCheckResponse(response)
}
