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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	azapiv1pdp "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// GrpcPDPClient is a gRPC client for the PDP service.
type GrpcPDPClient struct {
	target string
}

// NewGrpcPDPClient creates a new gRPC client for the PDP service.
func NewGrpcPDPClient(target string) (*GrpcPDPClient, error) {
	if target == "" {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "target is required")
	}
	return &GrpcPDPClient{
		target: target,
	}, nil
}

// createGRPCClient creates a new gRPC client.
func (c *GrpcPDPClient) createGRPCClient() (azapiv1pdp.V1PDPServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(c.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	client := azapiv1pdp.NewV1PDPServiceClient(conn)
	return client, conn, nil
}
