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

	zapv1 "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
)

// GrpcZAPClient is a gRPC client for the ZAP service.
type GrpcZAPClient struct {
	target string
}

// NewGrpcZAPClient creates a new gRPC client for the ZAP service.
func NewGrpcZAPClient(target string) (*GrpcZAPClient, error) {
	if target == "" {
		return nil, errors.New("grpc-client: target is required")
	}
	return &GrpcZAPClient{
		target: target,
	}, nil
}

// createGRPCClient creates a new gRPC client.
func (c *GrpcZAPClient) createGRPCClient() (zapv1.V1ZAPServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(c.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	client := zapv1.NewV1ZAPServiceClient(conn)
	return client, conn, nil
}
