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
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	azpdpv1 "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/transport/grpctls"
)

// GrpcPDPClient is a gRPC client for the PDP service.
type GrpcPDPClient struct {
	endpoint     string
	creds        credentials.TransportCredentials
	spiffeCloser io.Closer
	mu           sync.Mutex
	conn         *grpc.ClientConn
	client       azpdpv1.V1PDPServiceClient
}

// NewGrpcPDPClient creates a new gRPC client for the PDP service.
func NewGrpcPDPClient(endpoint string, tlsCfg *grpctls.ClientConfig) (*GrpcPDPClient, error) {
	hostPort, useTLS, err := parseGrpcEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	var creds credentials.TransportCredentials
	var spiffeCloser io.Closer
	if useTLS && tlsCfg != nil && tlsCfg.Spiffe {
		creds, spiffeCloser, err = grpctls.NewSpiffeClientCredentials(context.Background(), tlsCfg.SpiffeSocketPath)
		if err != nil {
			return nil, err
		}
	} else if useTLS {
		creds, err = grpctls.NewClientCredentials(tlsCfg)
		if err != nil {
			return nil, err
		}
	}
	return &GrpcPDPClient{
		endpoint:     hostPort,
		creds:        creds,
		spiffeCloser: spiffeCloser,
	}, nil
}

// getClient returns a gRPC client, creating the connection on first use.
func (c *GrpcPDPClient) getClient() (azpdpv1.V1PDPServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.client, nil
	}
	var dialOpt grpc.DialOption
	if c.creds != nil {
		dialOpt = grpc.WithTransportCredentials(c.creds)
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	conn, err := grpc.NewClient(c.endpoint, dialOpt,
		grpc.WithUnaryInterceptor(tlsHintUnaryInterceptor()),
		grpc.WithStreamInterceptor(tlsHintStreamInterceptor()),
	)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.client = azpdpv1.NewV1PDPServiceClient(conn)
	return c.client, nil
}

// Close closes the persistent gRPC connection.
func (c *GrpcPDPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spiffeCloser != nil {
		_ = c.spiffeCloser.Close()
	}
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}
