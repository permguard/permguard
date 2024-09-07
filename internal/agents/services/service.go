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

	"go.uber.org/zap"

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ServiceConfig represents the service configuration.
type ServiceConfig struct {
	hostable         azservices.Hostable
	storageConnector *azstorage.StorageConnector
	serviceable      azservices.Serviceable
}

// NewServiceConfig creates a new service configuration.
func newServiceConfig(hostable azservices.Hostable, storageConnector *azstorage.StorageConnector, serviceable azservices.Serviceable) (*ServiceConfig, error) {
	return &ServiceConfig{
		hostable:         hostable,
		storageConnector: storageConnector,
		serviceable:      serviceable,
	}, nil
}

// GetHostable returns the hostable.
func (c *ServiceConfig) GetHostable() azservices.Hostable {
	return c.hostable
}

// GetStorageConnector returns the storage connector.
func (c *ServiceConfig) GetStorageConnector() *azstorage.StorageConnector {
	return c.storageConnector
}

// GetServiceable returns the serviceable.
func (c *ServiceConfig) GetServiceable() azservices.Serviceable {
	return c.serviceable
}

// Service represents the service.
type Service struct {
	config    *ServiceConfig
	ctx       *azservices.ServiceContext
	endpoints []*Endpoint
}

// newService creates a new service.
func newService(serviceCfg *ServiceConfig, hostContext *azservices.HostContext) (*Service, error) {
	svcCfgReader, err := serviceCfg.serviceable.GetServiceConfigReader()
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrConfigurationGeneric, "config: cannot get service config reader")
	}
	serviceCtx, err := azservices.NewServiceContext(hostContext, serviceCfg.serviceable.GetService(), svcCfgReader)
	if err != nil {
		return nil, err
	}
	return &Service{
		config: serviceCfg,
		ctx:    serviceCtx,
	}, nil
}

// getLogger returns the logger.
func (s *Service) getLogger() *zap.Logger {
	return s.ctx.GetLogger()
}

// Serve starts the service.
func (s *Service) Serve(ctx context.Context) (bool, error) {
	logger := s.getLogger()
	logger.Debug("Service is starting")
	edpts, err := s.config.serviceable.GetEndpoints()
	if err != nil {
		logger.Error("Service cannot retrieve endpoints", zap.Error(err))
		return false, err
	}
	endpoints := make([]*Endpoint, 0, len(edpts))
	for _, edpt := range edpts {
		endpointCfg, err := newEndpointConfig(s.config.GetHostable(), edpt.GetService(), s.config.GetStorageConnector(), edpt.GetPort(), edpt.GetRegistration())
		if err != nil {
			logger.Error("Service cannot create endpoint config", zap.Error(err))
			return false, err
		}
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
	logger := s.getLogger()
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
