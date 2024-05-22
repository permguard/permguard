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

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// EndpointConfig represents the endpoint configuration.
type EndpointConfig struct {
	hostable         azservices.Hostable
	storageConnector *azstorage.StorageConnector
	service          azservices.ServiceKind
	port             int
	registration     func(*grpc.Server, *azservices.ServiceContext, *azservices.EndpointContext, *azstorage.StorageConnector) error
}

// newEndpointConfig creates a new endpoint configuration.
func newEndpointConfig(hostable azservices.Hostable, service azservices.ServiceKind, storageConnector *azstorage.StorageConnector, port int, registration func(*grpc.Server, *azservices.ServiceContext, *azservices.EndpointContext, *azstorage.StorageConnector) error) (*EndpointConfig, error) {
	return &EndpointConfig{
		hostable:         hostable,
		storageConnector: storageConnector,
		service:          service,
		port:             port,
		registration:     registration,
	}, nil
}

// GetHostable returns the hostable.
func (c *EndpointConfig) GetHostable() azservices.Hostable {
	return c.hostable
}

// GetStorageConnector returns the storage connector.
func (c *EndpointConfig) GetStorageConnector() *azstorage.StorageConnector {
	return c.storageConnector
}

// GetService returns the service kind.
func (c *EndpointConfig) GetService() azservices.ServiceKind {
	return c.service
}

// GetPort returns the port.
func (c *EndpointConfig) GetPort() int {
	return c.port
}

// GetRegistration returns the registration function.
func (c *EndpointConfig) GetRegistration() func(*grpc.Server, *azservices.ServiceContext, *azservices.EndpointContext, *azstorage.StorageConnector) error {
	return c.registration
}

// Endpoint represents the endpoint.
type Endpoint struct {
	config     *EndpointConfig
	ctx        *azservices.EndpointContext
	grpcServer *grpc.Server
}

// newEndpoint creates a new grpcendpoint.
func newEndpoint(endpointCfg *EndpointConfig, serviceCtx *azservices.ServiceContext) (*Endpoint, error) {
	grpcendpointCtx, err := azservices.NewEndpointContext(serviceCtx, endpointCfg.port)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		config: endpointCfg,
		ctx:    grpcendpointCtx,
	}, nil
}

// getLogger returns the logger.
func (e *Endpoint) getLogger() *zap.Logger {
	return e.ctx.GetLogger()
}

// Serve starts the grpcendpoint.
func (e *Endpoint) Serve(ctx context.Context, serviceCtx *azservices.ServiceContext) (bool, error) {
	logger := e.getLogger()
	logger.Debug("Endpoint is starting")
	grpcServer := grpc.NewServer(
		withServerUnaryInterceptor(e.ctx),
	)
	e.grpcServer = grpcServer
	port := e.config.GetPort()
	registration := e.config.GetRegistration()
	err := registration(grpcServer, serviceCtx, e.ctx, e.config.GetStorageConnector())
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
				e.config.GetHostable().Shutdown(context.Background())
			}
		}()
		logger := serviceCtx.GetLogger()
		logger.Info(serviceCtx.GetLogMessage(fmt.Sprintf("Service is serving on port: %d", port)))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error(serviceCtx.GetLogMessage(fmt.Sprintf("Service failed to serve on port: %d", port)), zap.Error(err))
			e.config.GetHostable().Shutdown(context.Background())
		}
	}()
	logger.Debug("Endpoint is started")
	return true, nil
}

// GracefulStop stops the grpcendpoint.
func (e *Endpoint) GracefulStop(ctx context.Context) (bool, error) {
	logger := e.getLogger()
	logger.Debug("Endpoint is stopping")
	e.grpcServer.GracefulStop()
	logger.Debug("Endpoint has stopped")
	return true, nil
}
