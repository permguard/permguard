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

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
)

// GrpcAAPClient is a gRPC client for the AAP service.
type GrpcAAPClient struct {
	target string
}

// NewGrpcAAPClient creates a new gRPC client for the AAP service.
func NewGrpcAAPClient(target string) (*GrpcAAPClient, error) {
	if target == "" {
		return nil, errors.New("client: target is required")
	}
	return &GrpcAAPClient{
		target: target,
	}, nil
}

// createGRPCClient creates a new gRPC client.
func (c *GrpcAAPClient) createGRPCClient() (azapiv1aap.V1AAPServiceClient, error) {
	conn, err := grpc.Dial(c.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := azapiv1aap.NewV1AAPServiceClient(conn)
	return client, nil
}
