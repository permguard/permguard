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
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pdpv1 "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
)

// GrpcPDPClient is a gRPC client for the PDP service.
type GrpcPDPClient struct {
	endpoint string
}

// NewGrpcPDPClient creates a new gRPC client for the PDP service.
func NewGrpcPDPClient(endpoint string) (*GrpcPDPClient, error) {
	if endpoint == "" {
		return nil, errors.New("client: endpoint is required")
	}
	return &GrpcPDPClient{
		endpoint: endpoint,
	}, nil
}

// createGRPCClient creates a new gRPC client.
func (c *GrpcPDPClient) createGRPCClient() (pdpv1.V1PDPServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(c.endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	client := pdpv1.NewV1PDPServiceClient(conn)
	return client, conn, nil
}
