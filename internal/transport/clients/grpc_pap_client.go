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
	"errors"
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	azpapv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/transport/grpctls"
)

// GrpcPAPClient is a gRPC client for the PAP service.
type GrpcPAPClient struct {
	endpoint        string
	displayEndpoint string
	collect         func(string)
	creds           credentials.TransportCredentials
	spiffeCloser    io.Closer
	mu              sync.Mutex
	conn            *grpc.ClientConn
	client          azpapv1.V1PAPServiceClient
}

// NewGrpcPAPClient creates a new gRPC client for the PAP service.
func NewGrpcPAPClient(endpoint string, tlsCfg *grpctls.ClientConfig, collect func(string)) (*GrpcPAPClient, error) {
	hostPort, useTLS, err := parseGrpcEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		if err = tlsCfg.Validate(); err != nil {
			return nil, err
		}
		if !useTLS && tlsCfg.HasTLS() {
			return nil, errors.New("cli: TLS flags (--tls-*) require the grpcs:// scheme")
		}
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
	return &GrpcPAPClient{
		endpoint:        hostPort,
		displayEndpoint: endpoint,
		collect:         collect,
		creds:           creds,
		spiffeCloser:    spiffeCloser,
	}, nil
}

// getClient returns a gRPC client, creating the connection on first use.
func (c *GrpcPAPClient) getClient() (azpapv1.V1PAPServiceClient, error) {
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
		grpc.WithChainUnaryInterceptor(verboseLoggingUnaryInterceptor(c.collect, c.displayEndpoint), tlsHintUnaryInterceptor()),
		grpc.WithChainStreamInterceptor(verboseLoggingStreamInterceptor(c.collect, c.displayEndpoint), tlsHintStreamInterceptor()),
	)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.client = azpapv1.NewV1PAPServiceClient(conn)
	return c.client, nil
}

// Close closes the persistent gRPC connection.
func (c *GrpcPAPClient) Close() error {
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

// GrpcPAPClientSession holds a reusable gRPC connection and client for multiple calls.
type GrpcPAPClientSession struct {
	client azpapv1.V1PAPServiceClient
	conn   *grpc.ClientConn
}

// Connect creates a new session with a reusable gRPC connection.
func (c *GrpcPAPClient) Connect() (*GrpcPAPClientSession, error) {
	client, err := c.getClient()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	return &GrpcPAPClientSession{client: client, conn: conn}, nil
}

// Close closes the session's gRPC connection.
func (s *GrpcPAPClientSession) Close() error {
	return s.conn.Close()
}
