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
	"errors"

	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// ServiceConfig represents the service configuration.
type ServiceConfig struct {
	hostable         services.Hostable
	storageConnector *storage.Connector
	serviceable      services.Serviceable
}

// NewServiceConfig creates a new service configuration.
func newServiceConfig(hostable services.Hostable, storageConnector *storage.Connector, serviceable services.Serviceable) *ServiceConfig {
	return &ServiceConfig{
		hostable:         hostable,
		storageConnector: storageConnector,
		serviceable:      serviceable,
	}
}

// Hostable returns the hostable.
func (c *ServiceConfig) Hostable() services.Hostable {
	return c.hostable
}

// Connector returns the storage connector.
func (c *ServiceConfig) Connector() *storage.Connector {
	return c.storageConnector
}

// Serviceable returns the serviceable.
func (c *ServiceConfig) Serviceable() services.Serviceable {
	return c.serviceable
}

// Service represents the service.
type Service struct {
	config    *ServiceConfig
	ctx       *services.ServiceContext
	endpoints []*Endpoint
}

// newService creates a new service.
func newService(serviceCfg *ServiceConfig, hostContext *services.HostContext) (*Service, error) {
	svcCfgReader, err := serviceCfg.serviceable.ServiceConfigReader()
	if err != nil {
		return nil, errors.Join(errors.New("service: cannot get service config reader"), err)
	}
	serviceCtx, err := services.NewServiceContext(hostContext, serviceCfg.serviceable.Service(), svcCfgReader)
	if err != nil {
		return nil, err
	}
	return &Service{
		config: serviceCfg,
		ctx:    serviceCtx,
	}, nil
}

// logger returns the logger.
func (s *Service) logger() *zap.Logger {
	return s.ctx.Logger()
}

// Serve starts the service.
func (s *Service) Serve(ctx context.Context) (bool, error) {
	logger := s.logger()
	logger.Debug("Service is starting")
	edpts, err := s.config.serviceable.Endpoints()
	if err != nil {
		logger.Error("Service cannot retrieve endpoints", zap.Error(err))
		return false, err
	}
	endpoints := make([]*Endpoint, 0, len(edpts))
	for _, edpt := range edpts {
		endpointCfg := newEndpointConfig(s.config.Hostable(), edpt.Service(), s.config.Connector(), edpt.Port(), edpt.Registration())
		endpoint, err := newEndpoint(endpointCfg, s.ctx)
		if err != nil {
			logger.Error("Service cannot create endpoint", zap.Error(err))
			return false, err
		}
		endpoints = append(endpoints, endpoint)
	}
	s.endpoints = endpoints
	hasStarted := true
	for _, endpoint := range s.endpoints {
		started, err := endpoint.Serve(ctx, s.ctx)
		if err != nil {
			logger.Error("Service cannot start endpoint", zap.Error(err))
			return false, err
		}
		hasStarted = hasStarted && started
	}
	if hasStarted {
		logger.Debug("Service has started")
	} else {
		logger.Warn("Service has not fully started")
	}
	return hasStarted, nil
}

// GracefulStop stops the service.
func (s *Service) GracefulStop(ctx context.Context) (bool, error) {
	logger := s.logger()
	logger.Debug("Service is stopping")
	hasStopped := true
	for _, edpt := range s.endpoints {
		stop, err := edpt.GracefulStop(ctx)
		if err != nil {
			logger.Error("Service cannot stop endpoint", zap.Error(err))
			return false, err
		}
		hasStopped = hasStopped && stop
	}
	if hasStopped {
		logger.Debug("Service has stopped")
	} else {
		logger.Warn("Service has not fully stopped")
	}
	return hasStopped, nil
}
