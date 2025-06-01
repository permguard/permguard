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

package services

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// EndpointConfig represents the endpoint configuration.
type EndpointConfig struct {
	hostable         services.Hostable
	storageConnector *storage.StorageConnector
	service          services.ServiceKind
	port             int
	registration     func(*grpc.Server, *services.ServiceContext, *services.EndpointContext, *storage.StorageConnector) error
}

// newEndpointConfig creates a new endpoint configuration.
func newEndpointConfig(hostable services.Hostable, service services.ServiceKind, storageConnector *storage.StorageConnector, port int, registration func(*grpc.Server, *services.ServiceContext, *services.EndpointContext, *storage.StorageConnector) error) (*EndpointConfig, error) {
	return &EndpointConfig{
		hostable:         hostable,
		storageConnector: storageConnector,
		service:          service,
		port:             port,
		registration:     registration,
	}, nil
}

// Hostable returns the hostable.
func (c *EndpointConfig) Hostable() services.Hostable {
	return c.hostable
}

// StorageConnector returns the storage connector.
func (c *EndpointConfig) StorageConnector() *storage.StorageConnector {
	return c.storageConnector
}

// Service returns the service kind.
func (c *EndpointConfig) Service() services.ServiceKind {
	return c.service
}

// Port returns the port.
func (c *EndpointConfig) Port() int {
	return c.port
}

// Registration returns the registration function.
func (c *EndpointConfig) Registration() func(*grpc.Server, *services.ServiceContext, *services.EndpointContext, *storage.StorageConnector) error {
	return c.registration
}

// Endpoint represents the endpoint.
type Endpoint struct {
	config     *EndpointConfig
	ctx        *services.EndpointContext
	grpcServer *grpc.Server
}

// newEndpoint creates a new grpcendpoint.
func newEndpoint(endpointCfg *EndpointConfig, serviceCtx *services.ServiceContext) (*Endpoint, error) {
	grpcendpointCtx, err := services.NewEndpointContext(serviceCtx, endpointCfg.port)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		config: endpointCfg,
		ctx:    grpcendpointCtx,
	}, nil
}

// logger returns the logger.
func (e *Endpoint) logger() *zap.Logger {
	return e.ctx.Logger()
}

// Serve starts the grpcendpoint.
func (e *Endpoint) Serve(ctx context.Context, serviceCtx *services.ServiceContext) (bool, error) {
	logger := e.logger()
	logger.Debug("Endpoint is starting")
	grpcServer := grpc.NewServer(
		withServerUnaryInterceptor(e.ctx),
	)
	e.grpcServer = grpcServer
	port := e.config.Port()
	registration := e.config.Registration()
	err := registration(grpcServer, serviceCtx, e.ctx, e.config.StorageConnector())
	if err != nil {
		return false, err
	}
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Error("Endpoint cannot listen on port", zap.Error(err))
		return false, err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Endpoint generated a panic", zap.Any("panic", r))
				e.config.Hostable().Shutdown(context.Background())
			}
		}()
		lgr := serviceCtx.Logger()
		lgr.Info(serviceCtx.LogMessage(fmt.Sprintf("Service is serving on port: %d", port)))
		if err := grpcServer.Serve(lis); err != nil {
			lgr.Error(serviceCtx.LogMessage(fmt.Sprintf("Service failed to serve on port: %d", port)), zap.Error(err))
			e.config.Hostable().Shutdown(context.Background())
		}
	}()
	logger.Debug("Endpoint is started")
	return true, nil
}

// GracefulStop stops the grpcendpoint.
func (e *Endpoint) GracefulStop(ctx context.Context) (bool, error) {
	logger := e.logger()
	logger.Debug("Endpoint is stopping")
	e.grpcServer.GracefulStop()
	logger.Debug("Endpoint has stopped")
	return true, nil
}
