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
	azcopier "github.com/permguard/permguard/pkg/extensions/copier"
)

// HostConfig represents the host configuration.
type HostConfig struct {
	logger            *zap.Logger
	host              azservices.HostKind
	hostable          azservices.Hostable
	storageConnector  *azstorage.StorageConnector
	services          []azservices.ServiceKind
	servicesFactories map[azservices.ServiceKind]azservices.ServiceFactoryProvider
	appData           string
}

// NewHostConfig creates a new host configuration.
func NewHostConfig(host azservices.HostKind, hostable azservices.Hostable, storageConnector *azstorage.StorageConnector,
	services []azservices.ServiceKind, servicesFactories map[azservices.ServiceKind]azservices.ServiceFactoryProvider, logger *zap.Logger, appData string,
) (*HostConfig, error) {
	return &HostConfig{
		logger:            logger,
		host:              host,
		hostable:          hostable,
		storageConnector:  storageConnector,
		services:          services,
		servicesFactories: servicesFactories,
		appData:           appData,
	}, nil
}

// GetHostable returns the hostable.
func (h *HostConfig) GetHostable() azservices.Hostable {
	return h.hostable
}

// GetStorageConnector returns the storage connector.
func (h *HostConfig) GetStorageConnector() *azstorage.StorageConnector {
	return h.storageConnector
}

// GetServicesFactories returns the services factories.
func (h *HostConfig) GetServicesFactories() map[azservices.ServiceKind]azservices.ServiceFactoryProvider {
	return azcopier.CopyMap(h.servicesFactories)
}

// GetAppData returns the app data.
func (h *HostConfig) GetAppData() string {
	return h.appData
}

// Host represents the host.
type Host struct {
	config   *HostConfig
	ctx      *azservices.HostContext
	services []*Service
}

// NewHost creates a new host.
func NewHost(hostCfg *HostConfig) (*Host, error) {
	hostCfgReader := azservices.NewHostConfiguration(hostCfg.GetAppData())
	hostCtx, err := azservices.NewHostContext(hostCfg.host, hostCfg.hostable, hostCfg.logger, hostCfgReader)
	if err != nil {
		return nil, err
	}
	return &Host{
		config: hostCfg,
		ctx:    hostCtx,
	}, nil
}

// getLogger returns the logger.
func (h *Host) getLogger() *zap.Logger {
	return h.ctx.GetLogger()
}

// buildServicesForServe builds the services for the host.
func buildServicesForServe(h *Host, factories []azservices.ServiceFactory, logger *zap.Logger) ([]*Service, bool, bool, error) {
	services := make([]*Service, len(h.config.GetServicesFactories()))
	for i, factory := range factories {
		svcable, err := factory.Create()
		if err != nil {
			logger.Error("Error creating the service from the factory", zap.Error(err))
			return nil, true, false, err
		}
		serviceCfg, err := newServiceConfig(h.config.GetHostable(), h.config.GetStorageConnector(), svcable)
		if err != nil {
			logger.Error("Error creating service config", zap.Error(err))
			return nil, true, false, err
		}
		service, err := newService(serviceCfg, h.ctx)
		if err != nil {
			logger.Error("Error creating service", zap.Error(err))
			return nil, true, false, err
		}
		services[i] = service
	}
	return services, false, false, nil
}

// Serve starts the host.
func (h *Host) Serve(ctx context.Context) (bool, error) {
	logger := h.getLogger()
	logger.Debug("Host is starting")
	factories := make([]azservices.ServiceFactory, len(h.config.GetServicesFactories()))
	count := 0
	for _, servicesFactory := range h.config.GetServicesFactories() {
		factory, err := servicesFactory.CreateFactory()
		if err != nil {
			logger.Error("Error creating the service factory", zap.Error(err))
			return false, err
		}
		factories[count] = factory
		count++
	}
	services, shouldReturn, returnValue, returnValue1 := buildServicesForServe(h, factories, logger)
	if shouldReturn {
		return returnValue, returnValue1
	}
	h.services = services
	hasStarted := true
	for _, service := range h.services {
		started, err := service.Serve(ctx)
		if err != nil {
			return false, err
		}
		hasStarted = hasStarted && started
	}
	if hasStarted {
		logger.Debug("Host has started")
	} else {
		logger.Warn("Host has not fully started")
	}
	return hasStarted, nil
}

// GracefulStop stops the host.
func (h *Host) GracefulStop(ctx context.Context) (bool, error) {
	logger := h.getLogger()
	logger.Debug("Host is stopping")
	hasStopped := true
	for _, service := range h.services {
		stopped, err := service.GracefulStop(ctx)
		if err != nil {
			return false, err
		}
		hasStopped = hasStopped && stopped
	}
	if hasStopped {
		logger.Debug("Host has stopped")
	} else {
		logger.Warn("Host has not fully stopped")
	}
	return hasStopped, nil
}
