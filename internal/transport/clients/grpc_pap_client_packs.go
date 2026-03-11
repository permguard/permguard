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
	"encoding/json"
	"fmt"
	"time"

	azpapv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

const (
	// grpcCallTimeout is the default timeout for gRPC unary calls.
	grpcCallTimeout = 30 * time.Second
)

// grpcContext returns a context with the default gRPC call timeout.
func grpcContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), grpcCallTimeout)
}

// marshalPackMessage marshals a request into a PackMessage.
func marshalPackMessage(req any) (*azpapv1.PackMessage, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("client: failed to marshal request: %w", err)
	}
	return &azpapv1.PackMessage{Data: data}, nil
}

// unmarshalPackMessage unmarshals a PackMessage into a response.
func unmarshalPackMessage[T any](msg *azpapv1.PackMessage) (*T, error) {
	var resp T
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("client: failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// PushAdvertise calls the PushAdvertise unary RPC.
func (s *GrpcPAPClientSession) PushAdvertise(req *pap.PushAdvertiseRequest) (*pap.PushAdvertiseResponse, error) {
	ctx, cancel := grpcContext()
	defer cancel()
	in, err := marshalPackMessage(req)
	if err != nil {
		return nil, err
	}
	out, err := s.client.PushAdvertise(ctx, in)
	if err != nil {
		return nil, err
	}
	return unmarshalPackMessage[pap.PushAdvertiseResponse](out)
}

// PushTransfer calls the PushTransfer unary RPC.
func (s *GrpcPAPClientSession) PushTransfer(req *pap.PushTransferRequest) (*pap.PushTransferResponse, error) {
	ctx, cancel := grpcContext()
	defer cancel()
	in, err := marshalPackMessage(req)
	if err != nil {
		return nil, err
	}
	out, err := s.client.PushTransfer(ctx, in)
	if err != nil {
		return nil, err
	}
	return unmarshalPackMessage[pap.PushTransferResponse](out)
}

// PullState calls the PullState unary RPC.
func (s *GrpcPAPClientSession) PullState(req *pap.PullStateRequest) (*pap.PullStateResponse, error) {
	ctx, cancel := grpcContext()
	defer cancel()
	in, err := marshalPackMessage(req)
	if err != nil {
		return nil, err
	}
	out, err := s.client.PullState(ctx, in)
	if err != nil {
		return nil, err
	}
	return unmarshalPackMessage[pap.PullStateResponse](out)
}

// PullNegotiate calls the PullNegotiate unary RPC.
func (s *GrpcPAPClientSession) PullNegotiate(req *pap.PullNegotiateRequest) (*pap.PullNegotiateResponse, error) {
	ctx, cancel := grpcContext()
	defer cancel()
	in, err := marshalPackMessage(req)
	if err != nil {
		return nil, err
	}
	out, err := s.client.PullNegotiate(ctx, in)
	if err != nil {
		return nil, err
	}
	return unmarshalPackMessage[pap.PullNegotiateResponse](out)
}

// PullObjects calls the PullObjects unary RPC.
func (s *GrpcPAPClientSession) PullObjects(req *pap.PullObjectsRequest) (*pap.PullObjectsResponse, error) {
	ctx, cancel := grpcContext()
	defer cancel()
	in, err := marshalPackMessage(req)
	if err != nil {
		return nil, err
	}
	out, err := s.client.PullObjects(ctx, in)
	if err != nil {
		return nil, err
	}
	return unmarshalPackMessage[pap.PullObjectsResponse](out)
}
